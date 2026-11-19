// SPDX-License-Identifier: Apache-2.0
#include "store/arena.h"

#include "store/node_state.h"
#include "util/log.h"
#include "util/nonce_source.h"

#include <algorithm>
#include <bit>
#include <optional>
#include <string>

namespace miracache::store {
namespace {

using Sb = std::span<std::byte, proto::kSuperblockSize>;
using Csb = std::span<const std::byte, proto::kSuperblockSize>;

Sb sb_copy(std::span<std::byte> seg0, unsigned i) {
  return Sb(seg0.data() + i * proto::kSuperblockSize, proto::kSuperblockSize);
}

bool all_zero(std::span<const std::byte> b) {
  return std::all_of(b.begin(), b.end(), [](std::byte v) { return v == std::byte{0}; });
}

proto::SegmentMeta meta_for(const SegmentLayout& l, std::uint32_t seg, std::uint32_t epoch) {
  proto::SegmentMeta m;
  m.seg_id = seg;
  m.n_runs = l.n_runs;
  m.run_table_off = l.run_table_off;
  m.hdr_table_off = l.hdr_table_off;
  m.data_off = l.data_off;
  m.format_epoch = epoch;
  return m;
}

}  // namespace

Expected<std::unique_ptr<Arena>> Arena::open(const StoreConfig& cfg, std::unique_ptr<Backing> backing) {
  if (auto s = cfg.validate(); !s) return s.error();
  auto seg_layout = compute_segment_layout(cfg.segment_bytes, cfg.run_bytes);
  if (!seg_layout) return seg_layout.error();
  // A3.1: the persisted scope region. Auto: none for the volatile Anon backing, else one record per min_block of data
  // (a scope holds at least one block), capped at the spec's 4 Mi.
  std::uint32_t scope_records = cfg.scope_records;
  if (scope_records == 0 && cfg.backing != BackingKind::Anon) {
    const std::uint64_t data = std::uint64_t{cfg.n_segments} * seg_layout->n_runs * seg_layout->run_bytes;
    scope_records = static_cast<std::uint32_t>(
        std::clamp<std::uint64_t>(data / cfg.min_block_bytes, 64, proto::kDefaultMaxScopeRecords));
  }
  auto scope_layout = compute_scope_region(*seg_layout, scope_records);
  if (!scope_layout) return scope_layout.error();

  // r9b T02/T03: the state_dir is checked and locked before the store is mapped or touched: a second memory node on
  // the same state_dir stops here, before it can reformat anything.
  const bool use_file = !cfg.state_dir.empty();
  StateDirLock lock;
  if (use_file) {
    if (auto s = prepare_state_dir(cfg.state_dir); !s) return s.error();  // T03: our own dir, not group/world-writable
    auto lk = StateDirLock::acquire(cfg.state_dir);                        // T02: one memory node per state_dir
    if (!lk) return lk.error();
    lock = std::move(*lk);
  }
  std::unique_ptr<Arena> a(new Arena());
  a->lock_ = std::move(lock);
  a->cfg_ = cfg;
  a->layout_.seg = *seg_layout;
  a->layout_.n_segments = cfg.n_segments;
  a->layout_.scope = *scope_layout;
  a->backing_ = backing ? std::move(backing) : make_backing(cfg);

  for (std::uint32_t s = 0; s < cfg.n_segments; ++s) {
    auto m = a->backing_->map(s, cfg.segment_bytes);
    if (!m) return m.error();
    a->segs_.push_back(*m);
  }
  const auto seg0 = a->segs_[0];
  const auto& l = a->layout_.seg;

  // r9b T11: every segment's metadata is written by a format, so every segment is synced (seg 0 whole: superblocks).
  // r9c U03: segments 1..n first, segment 0 (the superblocks) last, so a power loss in between never leaves a valid
  // superblock over metadata that was not written yet.
  auto sync_meta = [&]() -> Status {
    for (std::uint32_t k = 1; k <= cfg.n_segments; ++k) {
      const std::uint32_t s = k % cfg.n_segments;
      const std::size_t n = s == 0 ? a->segs_[0].size() : std::min<std::size_t>(l.data_off, a->segs_[s].size());
      if (auto e = a->backing_->sync(s, 0, n); !e) return e;
    }
    return {};
  };
  // Zeroes the metadata of every segment (the store becomes blank) and syncs it.
  auto wipe_meta = [&]() -> Status {
    for (std::uint32_t s = 0; s < cfg.n_segments; ++s) {
      auto bytes = a->segs_[s];
      const std::size_t n = std::min<std::size_t>(l.data_off, bytes.size());
      std::fill(bytes.begin(), bytes.begin() + static_cast<std::ptrdiff_t>(n), std::byte{0});
    }
    return sync_meta();
  };

  // Review r9 S04 + r9b T01/T02: with a state_dir the node ID lives in <state_dir>/node-id, so a wiped or volatile store
  // keeps its identity. Without one (tests) it lives in the superblock only, as in plan 2C.
  //   node-id present                    -> that ID;
  //   node-id missing, `initialised` set -> the node was replaced: a new ID, the store is reformatted;
  //   node-id missing, never initialised -> upgrade path: adopt a persistent superblock ID if any, else draw.
  std::uint32_t file_id = 0;
  bool initialised = false, file_invalid = false;  // file_invalid: node-id existed but held no valid ID (r9c U04)
  if (use_file) {
    auto r = read_node_id_file(cfg.state_dir, &file_invalid);
    if (!r) return r.error();
    if (*r) file_id = **r;
    auto ini = state_dir_initialised(cfg.state_dir);
    if (!ini) return ini.error();
    initialised = *ini;
  }
  // A replaced node (T01): draws its new ID and writes it before the store is touched; a crash in between leaves
  // node-id holding the new ID, so the next start sees a store of another identity and reformats it.
  auto replace_id = [&](std::uint32_t prev_store_id) -> Status {
    auto id = random_nonzero_u32();
    if (!id) return id.error();
    file_id = *id;
    if (auto w = write_node_id_file(cfg.state_dir, file_id); !w) return w;
    log::write(log::Level::Warn, "store", "node replaced: new id",
               {{"id", std::to_string(file_id)}, {"store_id", std::to_string(prev_store_id)}, {"state_dir", cfg.state_dir},
                {"reason", file_invalid ? "invalid_file" : "missing_file"}});
    return {};
  };

  bool blank = all_zero(seg0.subspan(0, kSuperblockRegionBytes));
  std::optional<proto::Superblock> found;  // the newest valid superblock of a non-blank store
  if (!blank) {
    auto sb = proto::choose_superblock(Csb(sb_copy(seg0, 0)), Csb(sb_copy(seg0, 1)));
    if (!sb) return sb.error();
    found = *sb;
    if (use_file) {
      if (file_id == 0 && !initialised) {
        // Upgrade path: a store that has an ID but a state_dir that was never initialised. Adopt the store's ID.
        file_id = sb->node_id;
        if (auto w = write_node_id_file(cfg.state_dir, file_id); !w) return w.error();
        log::write(log::Level::Info, "store", "node id adopted from the store into the state file",
                   {{"id", std::to_string(file_id)}});
      } else if (file_id == 0 || sb->node_id != file_id) {
        if (file_id == 0) {
          // T01: node-id was deleted in an initialised dir = replacing the node. The old cache belongs to the old
          // identity: reformat under the new one.
          if (auto s = replace_id(sb->node_id); !s) return s.error();
        } else {
          // The store belongs to another identity (moved, or the state file was replaced). It is a cache:
          // reformat it as blank under the file's ID and start, never refuse.
          log::write(log::Level::Warn, "store", "store node id differs from the state file; reformatting the store",
                     {{"store_id", std::to_string(sb->node_id)}, {"state_id", std::to_string(file_id)}});
        }
        if (auto e = wipe_meta(); !e) return e.error();
        blank = true;
        found.reset();
      }
    }
  }
  // r9c U03: a valid superblock over a segment meta that does not decode (zeroed or torn: a reformat that lost power
  // between the syncs) is a half-formatted store, i.e. blank. A meta that decodes but differs from the config is
  // still refused below.
  if (!blank) {
    for (std::uint32_t s = 0; s < cfg.n_segments && !blank; ++s) {
      auto bytes = a->segs_[s];
      if (!proto::decode_segment_meta(std::span<const std::byte, proto::kSegmentMetaSize>(
              bytes.data() + kSegmentMetaOff, proto::kSegmentMetaSize))) {
        log::write(log::Level::Warn, "store", "segment meta unreadable under a valid superblock; reformatting the store",
                   {{"segment", std::to_string(s)}});
        if (auto e = wipe_meta(); !e) return e.error();
        blank = true;
        found.reset();
      }
    }
  }
  // s12 (tpu-sync cross-check C2): the restart scan infers each run's block size from min_block_bytes, so the value the
  // store was formatted with must be the one in force. A store from before s12 has 0 there (unknown): re-formatted
  // once, like a store without a scope region. Another value is a STATIC change: refused. Checked before the scope
  // region, whose computed default size depends on min_block_bytes (so the refusal names the real cause).
  const auto min_log2 = static_cast<std::uint8_t>(std::countr_zero(static_cast<std::uint64_t>(cfg.min_block_bytes)));
  if (!blank && found && found->min_block_log2 != min_log2) {
    if (found->min_block_log2 == 0) {
      log::write(log::Level::Warn, "store", "store does not record its minimum block size (written before s12); reformatting the store",
                 {{"state_dir", cfg.state_dir}});
      if (auto e = wipe_meta(); !e) return e.error();
      blank = true;
      found.reset();
    } else {
      return Error{ErrorCode::InvalidArgument, "arena: store.min_block_bytes differs from the formatted store (STATIC: "
                                               "drain and re-format the node)"};
    }
  }
  // A3.1: the scope region must be where this config puts it. A store without one (written before A3.1) cannot resume
  // its scopes, so it is re-formatted (a cold start, once); a region of another size is a STATIC change (refused,
  // like the geometry); a region header that does not decode loses every scope, so the store is blank.
  const auto& sl = a->layout_.scope;
  if (!blank && found && (found->scope_off != sl.off || found->scope_len != sl.len)) {
    if (found->scope_off == 0 && found->scope_len == 0) {
      log::write(log::Level::Warn, "store", "store has no scope region (written before warm restart); reformatting the store",
                 {{"state_dir", cfg.state_dir}});
      if (auto e = wipe_meta(); !e) return e.error();
      blank = true;
      found.reset();
    } else {
      return Error{ErrorCode::InvalidArgument, "arena: scope region differs from config (store.scope_records is STATIC)"};
    }
  }
  if (sl.records > 0) a->scopes_ = std::make_unique<ScopeTable>(a->segs_[0].subspan(sl.off, sl.len), sl.records);
  if (!blank && a->scopes_ && !a->scopes_->check_header()) {
    log::write(log::Level::Warn, "store", "scope region header unreadable; reformatting the store", {});
    if (auto e = wipe_meta(); !e) return e.error();
    blank = true;
    found.reset();
  }
  if (blank) {
    a->fresh_ = true;
    // A3.1: a blank store holds no block header and no scope record (a header slot is valid only from commit to
    // free, which is what the restart scan relies on), whatever the media held before. Check-before-write.
    for (std::uint32_t s = 0; s < cfg.n_segments; ++s) {
      auto bytes = a->segs_[s];
      for (std::uint64_t off = kRunTableOffMin; off < l.data_off && off < bytes.size(); off += kPage) {
        auto page = bytes.subspan(off, std::min<std::uint64_t>(kPage, std::min<std::uint64_t>(l.data_off, bytes.size()) - off));
        if (!all_zero(page)) std::fill(page.begin(), page.end(), std::byte{0});
      }
    }
    if (a->scopes_)
      if (auto e = a->scopes_->format(); !e) return e.error();
    a->sb_.scope_off = sl.off;
    a->sb_.scope_len = sl.len;
    a->sb_.format_epoch = 1;
    // Plan 2C: the ID is drawn here, once, for a blank store (cfg.node_id is only a test hook).
    // With a state file (S04) a blank store takes the file's ID, so a wiped hugetlbfs or a volatile (Anon)
    // store keeps its identity; a new ID is drawn only when node-id is missing (first start, or a replacement).
    // Without a state file (tests) a blank store gets a new ID: its cache is gone too.
    if (use_file) {
      if (file_id == 0) {
        if (initialised) {
          if (auto s = replace_id(0); !s) return s.error();
        } else {
          auto id = random_nonzero_u32();
          if (!id) return id.error();
          file_id = *id;
          if (auto w = write_node_id_file(cfg.state_dir, file_id); !w) return w.error();
        }
      }
      a->sb_.node_id = file_id;
    } else if (cfg.node_id != 0) {
      a->sb_.node_id = cfg.node_id;
    } else {
      auto id = random_nonzero_u32();
      if (!id) return id.error();
      a->sb_.node_id = *id;
    }
    a->sb_.segment_size = cfg.segment_bytes;
    a->sb_.n_segments = cfg.n_segments;
    a->sb_.min_block_log2 = min_log2;  // s12 C2
    a->sb_.sg_off = 0;  // the array is volatile heap memory, not part of the media
    a->sb_.sg_slots = a->layout_.sg_slots();
    // Two copies: seq 0 in copy 0, seq 1 in copy 1; later writes alternate (seq & 1).
    a->sb_.seq = 0;
    if (auto e = proto::encode(a->sb_, sb_copy(seg0, 0)); !e) return e.error();
    a->sb_.seq = 1;
    if (auto e = proto::encode(a->sb_, sb_copy(seg0, 1)); !e) return e.error();
    for (std::uint32_t s = 0; s < cfg.n_segments; ++s) {
      const auto m = meta_for(l, s, a->sb_.format_epoch);
      auto bytes = a->segs_[s];
      if (auto e = proto::encode(m, std::span<std::byte, proto::kSegmentMetaSize>(
                                         bytes.data() + kSegmentMetaOff, proto::kSegmentMetaSize));
          !e)
        return e.error();
    }
    if (auto e = sync_meta(); !e) return e.error();
  } else {
    a->sb_ = *found;
    if (a->sb_.segment_size != cfg.segment_bytes || a->sb_.n_segments != cfg.n_segments ||
        (!use_file && cfg.node_id != 0 && a->sb_.node_id != cfg.node_id))
      return Error{ErrorCode::InvalidArgument, "arena: superblock geometry differs from config"};
    for (std::uint32_t s = 0; s < cfg.n_segments; ++s) {
      auto bytes = a->segs_[s];
      auto m = proto::decode_segment_meta(std::span<const std::byte, proto::kSegmentMetaSize>(
          bytes.data() + kSegmentMetaOff, proto::kSegmentMetaSize));
      if (!m) return m.error();
      const auto want = meta_for(l, s, a->sb_.format_epoch);
      if (m->seg_id != s || m->n_runs != want.n_runs || m->run_table_off != want.run_table_off ||
          m->hdr_table_off != want.hdr_table_off || m->data_off != want.data_off ||
          m->format_epoch != want.format_epoch)
        return Error{ErrorCode::InvalidArgument, "arena: segment meta differs from config"};
    }
    a->was_clean_ = a->sb_.clean_shutdown == 1;
  }
  // T01: the directory holds an ID now; from here on a missing node-id means the node was replaced. Written after
  // node-id, so a crash in between only repeats the upgrade path with the ID that is already in the file.
  if (use_file && !initialised)
    if (auto m = mark_state_dir_initialised(cfg.state_dir); !m) return m.error();

  a->sg_ = std::make_unique<StateGenArray>(a->layout_.sg_slots());
  a->gens_ = std::make_unique<GenCounter>(a->sb_.gen_hwm, cfg.gen_chunk, &Arena::persist_hwm, a.get());

  // Mark the node owned and dirty until shutdown_clean().
  a->sb_.owner_pid = cfg.owner_pid;
  a->sb_.clean_shutdown = 0;
  if (auto e = a->write_superblock(); !e) return e.error();
  return a;
}

Status Arena::write_superblock() {
  ++sb_.seq;
  auto copy = sb_copy(segs_[0], static_cast<unsigned>(sb_.seq & 1));
  if (auto e = proto::encode(sb_, copy); !e) return e;
  return backing_->sync(0, (sb_.seq & 1) * proto::kSuperblockSize, proto::kSuperblockSize);
}

Status Arena::persist_hwm(void* self, std::uint64_t hwm) {
  auto* a = static_cast<Arena*>(self);
  a->sb_.gen_hwm = hwm;
  return a->write_superblock();
}

Status Arena::shutdown_clean() {
  sb_.clean_shutdown = 1;
  return write_superblock();
}

std::span<std::byte> Arena::block(std::uint32_t seg, std::uint64_t off, std::uint64_t len) const {
  const auto s = segs_.at(seg);
  MIRACACHE_CHECK(off <= s.size() && len <= s.size() - off);
  return s.subspan(off, len);
}

}  // namespace miracache::store
