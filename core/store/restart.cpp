// SPDX-License-Identifier: Apache-2.0
#include "store/restart.h"

#include <algorithm>
#include <cstring>
#include <deque>
#include <map>
#include <set>
#include <vector>

#include "proto/scope_record.h"
#include "proto/server_header.h"
#include "util/crc32c.h"

namespace miracache::store {
namespace {

constexpr std::uint8_t kHdrMagic[4] = {'M', 'I', 'R', 'H'};

bool all_zero(std::span<const std::byte> b) {
  return std::all_of(b.begin(), b.end(), [](std::byte v) { return v == std::byte{0}; });
}
void zero(std::span<std::byte> b) {
  if (!all_zero(b)) std::memset(b.data(), 0, b.size());
}

struct Cand {
  std::uint32_t seg = 0, run = 0, rid = 0, block = 0;
  std::uint64_t slot = 0;
  std::uint64_t cls = 0;
  proto::ServerHeader h;
  KeyHash key{}, parent{};  // parent: the 16 B prefix, zero-padded (zero = chain root)
};

using ScopeKey = std::pair<PrincipalId, ScopeId>;

}  // namespace

const char* discard_reason_name(DiscardReason r) {
  switch (r) {
    case DiscardReason::Header: return "header";
    case DiscardReason::Generation: return "generation";
    case DiscardReason::Geometry: return "geometry";
    case DiscardReason::Digest: return "digest";
    case DiscardReason::Scope: return "scope";
    case DiscardReason::Orphan: return "orphan";
    case DiscardReason::Duplicate: return "duplicate";
    case DiscardReason::SharedScopeId: return "shared_scope_id";
    case DiscardReason::TornRecord: return "torn_record";
  }
  return "unknown";
}

Expected<RestartReport> restart_scan(Arena& arena, SlabAllocator& slab, Store& store, const RestartOptions& opt) {
  RestartReport rep;
  if (arena.fresh()) return rep;
  rep.ran = true;
  rep.clean = arena.was_clean();
  const bool verify = !rep.clean || opt.verify_extents;
  rep.verified = verify;
  const StoreLayout& L = arena.layout();
  const SegmentLayout& sl = L.seg;
  // Every generation issued from now on is above this (GenCounter resumes one chunk above the persisted mark), so a
  // block whose header names a higher one cannot be ours: a torn or foreign header.
  const std::uint64_t gen_bound = arena.gens().last();

  auto crc_ok = [&](const Cand& c, std::uint64_t cls) {
    const std::uint64_t off = sl.run_data_off(c.run) + std::uint64_t{c.block} * cls;
    return crc32c(arena.block(c.seg, off, c.h.stored_len)) == c.h.payload_crc;
  };
  auto discard = [&](DiscardReason why, const Cand& c) {
    ++rep.discarded[static_cast<std::size_t>(why)];
    zero(slab.header_slot(c.seg, c.slot));
  };

  // ---- 1. Scope records (spec 6.1 step 5). Owners of a scope_id: every principal with an OPEN or DRAINING record, and
  // (best effort) the principal a torn record names. NOTHING is cleared here: the slots to release are collected in
  // `release_slots` and released only after step 2 has zeroed every header they could have vouched for (crash order).
  const std::int64_t off_ns = store.wall_offset_ns();
  auto to_ns = [off_ns](std::uint64_t ms) {
    // Garbage cannot overflow: ms * 1e6 and the offset subtraction saturate. (Times in the future are clamped to now
    // by Store::restore_scopes.)
    const std::uint64_t m = std::min<std::uint64_t>(ms, static_cast<std::uint64_t>(INT64_MAX / 1'000'000));
    const std::int64_t ns = static_cast<std::int64_t>(m) * 1'000'000;
    std::int64_t r = 0;
    if (__builtin_sub_overflow(ns, off_ns, &r)) r = off_ns < 0 ? INT64_MAX : INT64_MIN;
    return r;
  };
  std::map<ScopeId, std::map<PrincipalId, bool>> owners;  // -> open
  std::set<ScopeId> torn_scopes;                          // a record for it failed its CRC
  bool blind = false;                                     // a torn record whose principal / scope_id are unreadable
  std::map<ScopeKey, Store::RestoredScope> open;
  std::vector<std::uint32_t> release_slots;  // each slot at most once
  if (ScopeTable* t = arena.scope_table()) {
    rep.scope_records_corrupt = t->load(
        [&](std::uint32_t slot, const proto::ScopeRecord& r) {
          if (r.mode != proto::kScopeModeImplicit || (r.state != proto::kScopeOpen && r.state != proto::kScopeDraining)) {
            release_slots.push_back(slot);
            return true;
          }
          ScopeId s{};
          std::copy(r.scope_id.begin(), r.scope_id.end(), s.begin());
          const PrincipalId p = r.principal_id;
          owners[s][p] |= r.state == proto::kScopeOpen;
          if (r.state != proto::kScopeOpen) {
            ++rep.scopes_draining;
            release_slots.push_back(slot);  // not resumed; its blocks are discarded below
            return true;
          }
          Store::RestoredScope rs{p, s, to_ns(r.opened_at_ms), to_ns(r.last_used_ms), slot};
          auto [it, inserted] = open.emplace(ScopeKey{p, s}, rs);
          if (!inserted) {  // one scope twice (never written so): keep the later use
            if (rs.last_used_ns > it->second.last_used_ns) std::swap(it->second, rs);
            release_slots.push_back(rs.rec_slot);
          }
          return true;
        },
        [&](std::uint32_t slot, std::span<const std::byte> b) {
          // principal_id (u32 @0) and scope_id (@8) are rewritten with identical values on every update, so they are
          // intact after a torn time / CRC rewrite.
          PrincipalId p = 0;
          for (std::size_t i = 0; i < 4; ++i)
            p |= PrincipalId{std::to_integer<std::uint8_t>(b[proto::scr::principal_id + i])} << (8 * i);
          ScopeId s{};
          std::memcpy(s.data(), b.data() + proto::scr::scope_id, s.size());
          if (p == 0 || std::all_of(s.begin(), s.end(), [](std::uint8_t v) { return v == 0; })) {
            blind = true;  // H05: reported (blind_record_slots, TornRecord discards); the memory node logs it
            rep.blind_record_slots.push_back(slot);
          } else {
            owners[s].emplace(p, false);  // a not-open owner (an OPEN record for the same pair keeps its true)
            torn_scopes.insert(s);
          }
          release_slots.push_back(slot);
          return true;
        });
  }
  // A scope whose scope_id has another (or a draining, or a torn) owner is not resumed either: its blocks cannot be
  // attributed. Its OPEN record goes with the rest, after the header pass.
  for (auto it = open.begin(); it != open.end();) {
    const auto& o = owners.at(it->first.second);
    if (blind || o.size() != 1 || !o.begin()->second || torn_scopes.count(it->first.second)) {
      release_slots.push_back(it->second.rec_slot);
      it = open.erase(it);
    } else {
      ++it;
    }
  }
  rep.scopes_resumed = open.size();
  if (opt.stop_after && opt.stop_after(RestartOptions::Stage::RecordsLoaded))
    return Error{ErrorCode::Aborted, "restart scan: stopped after the scope records were loaded"};
  std::map<ScopeId, std::size_t> shared_idx;  // scope_id -> index in rep.shared_scopes

  // ---- 2. Header tables (step 4): candidates per run, the run's class, then per scope.
  std::map<ScopeKey, std::vector<Cand>> per_scope;
  for (std::uint32_t seg = 0; seg < L.n_segments; ++seg) {
    for (std::uint32_t run = 0; run < sl.n_runs; ++run) {
      const std::uint32_t rid = seg * sl.n_runs + run;
      if (slab.run_reserved(rid)) continue;
      std::vector<Cand> cs;
      for (std::uint32_t b = 0; b < proto::kSlotsPerRun; ++b) {
        Cand c;
        c.seg = seg, c.run = run, c.rid = rid, c.block = b;
        c.slot = L.gen_slot(seg, run, b);
        auto hs = slab.header_slot(seg, c.slot);
        ++rep.slots_scanned;
        if (std::memcmp(hs.data(), kHdrMagic, 4) != 0) {
          zero(hs);  // empty, or a clear cut short (the magic goes first)
          continue;
        }
        auto h = proto::decode_server_header(std::span<const std::byte, proto::kServerHeaderSize>(hs.data(), proto::kServerHeaderSize));
        if (!h || !proto::validate(*h, sl.run_bytes)) {
          discard(DiscardReason::Header, c);
          continue;
        }
        if (h->generation > gen_bound) {
          discard(DiscardReason::Generation, c);
          continue;
        }
        c.h = *h;
        std::memcpy(c.key.data(), h->key_hash, 32);
        std::memcpy(c.parent.data(), h->parent_hash, kParentHashBytes);
        cs.push_back(c);
      }
      if (cs.empty()) continue;
      // The run's class: every block of a class C has exact_len(stored_len) == C (an exact class) or
      // ladder_len(exact_len(stored_len)) == C (a rung class), and sits in a slot < per_run(C). The class most
      // blocks agree on wins; a tie (an exact length and its rung) is settled by the extent CRCs of blocks past slot 0
      // (their offsets differ), else the smaller class (for slot 0 alone both place the block identically).
      auto fits = [&](const Cand& c, std::uint64_t cls) {
        const std::uint64_t e = slab.exact_len(c.h.stored_len);
        return (e == cls || slab.ladder_len(e) == cls) && c.block < slab.per_run(cls) && c.h.stored_len <= cls;
      };
      std::set<std::uint64_t> classes;
      for (const auto& c : cs) {
        const std::uint64_t e = slab.exact_len(c.h.stored_len);
        classes.insert(e);
        classes.insert(slab.ladder_len(e));
      }
      std::map<std::uint64_t, std::size_t> score;
      std::size_t best_n = 0;
      for (std::uint64_t cls : classes) {
        std::size_t n = 0;
        for (const auto& c : cs) n += fits(c, cls) ? 1 : 0;
        score[cls] = n;
        best_n = std::max(best_n, n);
      }
      std::uint64_t best = 0;
      std::size_t best_crc = 0, n_top = 0;
      for (const auto& [cls, n] : score) n_top += n == best_n && n > 0;
      for (const auto& [cls, n] : score) {  // ascending: on a full tie the smaller class wins
        if (n != best_n || n == 0) continue;
        std::size_t m = 0, tried = 0;
        if (n_top > 1)
          for (const auto& c : cs)
            if (c.block > 0 && fits(c, cls) && tried < 4) ++tried, m += crc_ok(c, cls) ? 1 : 0;
        if (best == 0 || m > best_crc) best = cls, best_crc = m;
      }
      for (auto& c : cs) {
        if (best == 0 || !fits(c, best)) {
          discard(DiscardReason::Geometry, c);
          continue;
        }
        c.cls = best;
        ScopeId s{};
        std::memcpy(s.data(), c.h.scope_id, 32);
        auto o = owners.find(s);
        if (!blind && o != owners.end() && (o->second.size() > 1 || torn_scopes.count(s))) {
          // Two principals (or a torn record) share the scope_id and headers carry no principal: unattributable.
          discard(DiscardReason::SharedScopeId, c);
          auto [si, fresh] = shared_idx.emplace(s, rep.shared_scopes.size());
          if (fresh) {
            SharedScope sh;
            sh.scope = s;
            sh.torn_record = torn_scopes.count(s) != 0;
            for (const auto& [p, is_open] : o->second) sh.principals.push_back(p);
            rep.shared_scopes.push_back(std::move(sh));
          }
          ++rep.shared_scopes[si->second].blocks;
          rep.shared_scopes[si->second].bytes += c.cls;
          continue;
        }
        if (blind) {  // H05: a torn record with an unreadable owner: nothing on media can be attributed
          discard(DiscardReason::TornRecord, c);
          continue;
        }
        if (o == owners.end() || o->second.size() != 1 || !open.count(ScopeKey{o->second.begin()->first, s})) {
          discard(DiscardReason::Scope, c);
          continue;
        }
        if (verify && !crc_ok(c, best)) {  // after the scope check: an extent that is discarded anyway is not read
          discard(DiscardReason::Digest, c);
          continue;
        }
        per_scope[ScopeKey{o->second.begin()->first, s}].push_back(c);
      }
    }
    if (opt.progress) opt.progress(seg, rep);
  }
  // Every header of a scope that is not resumed is zero now: only then do its records (and the duplicates and torn
  // ones) go. A crash before this loop leaves the records, so the next scan reaches the same verdicts.
  if (opt.stop_after && opt.stop_after(RestartOptions::Stage::HeadersScanned))
    return Error{ErrorCode::Aborted, "restart scan: stopped after the header pass"};
  if (ScopeTable* t = arena.scope_table())
    for (auto slot : release_slots) t->release(slot);

  // ---- 3. Scopes, then their blocks: chains from their roots (the orphan sweep), parents first.
  std::vector<Store::RestoredScope> scopes;
  for (const auto& [k, rs] : open) scopes.push_back(rs);
  std::sort(scopes.begin(), scopes.end(), [](const auto& a, const auto& b) {
    return a.last_used_ns != b.last_used_ns ? a.last_used_ns < b.last_used_ns
                                            : std::make_pair(a.principal, a.scope) < std::make_pair(b.principal, b.scope);
  });
  store.restore_scopes(scopes);
  for (const auto& sc : scopes) {  // least recently used first: the block LRU follows the scope LRU
    auto ps = per_scope.find(ScopeKey{sc.principal, sc.scope});
    if (ps == per_scope.end()) continue;
    std::vector<Cand>& cs = ps->second;
    std::map<KeyHash, std::size_t> by_key;  // UniqueKey: the higher generation wins
    for (std::size_t i = 0; i < cs.size(); ++i) {
      auto [it, inserted] = by_key.emplace(cs[i].key, i);
      if (inserted) continue;
      if (cs[i].h.generation > cs[it->second].h.generation) {
        discard(DiscardReason::Duplicate, cs[it->second]);
        it->second = i;
      } else {
        discard(DiscardReason::Duplicate, cs[i]);
      }
    }
    std::map<KeyHash, std::vector<KeyHash>> with_prefix, children;  // own 16 B prefix -> keys; parent prefix -> keys
    for (const auto& [k, i] : by_key) {
      with_prefix[parent_prefix(k)].push_back(k);
      children[cs[i].parent].push_back(k);
    }
    // A parent resolves only when exactly one key has its prefix (as at commit); a cyclic index cannot loop (visited).
    std::vector<KeyHash> order;
    std::set<KeyHash> visited;
    if (auto r = children.find(KeyHash{}); r != children.end())
      for (const auto& k : r->second)
        if (visited.insert(k).second) order.push_back(k);
    for (std::size_t i = 0; i < order.size(); ++i) {
      const KeyHash pfx = parent_prefix(order[i]);
      if (with_prefix[pfx].size() != 1) continue;
      if (auto ch = children.find(pfx); ch != children.end())
        for (const auto& k : ch->second)
          if (visited.insert(k).second) order.push_back(k);
    }
    std::set<KeyHash> adopted;
    for (const KeyHash& k : order) {
      const Cand& c = cs[by_key.at(k)];
      if (!parent_is_root(c.parent) && !adopted.count(with_prefix.at(c.parent).front())) {
        discard(DiscardReason::Orphan, c);
        continue;
      }
      if (!slab.adopt_run(c.rid, c.cls, sc.principal)) {
        discard(DiscardReason::Geometry, c);
        continue;
      }
      const Extent e = slab.adopt_block(c.rid, c.block, c.h.generation);
      store.restore_block(sc.principal, sc.scope, k, c.parent, e, c.h.stored_len);
      adopted.insert(k);
      ++rep.adopted_blocks;
      rep.adopted_bytes += e.len;
    }
    for (const auto& [k, i] : by_key)
      if (!visited.count(k)) discard(DiscardReason::Orphan, cs[i]);
  }
  return rep;
}

}  // namespace miracache::store
