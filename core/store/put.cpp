// SPDX-License-Identifier: Apache-2.0
#include "store/put.h"

#include <algorithm>
#include <cstring>
#include <memory>

#include "proto/extent_header.h"
#include "proto/server_header.h"
#include "util/buggify.h"
#include "util/crc32c.h"

namespace miracache::store {

namespace {
constexpr std::uint32_t kRetryBusyMs = 50;
constexpr std::uint32_t kRetryQuotaMs = 1000;
constexpr std::uint32_t kRetryFullMs = 1000;  // arena full and no run can be freed
}  // namespace

PutPath::PutPath(Store& store, SlabAllocator& slab, MrManager& mrs, Arena& arena, const Clock& clock, Executor& exec,
                 PutDoneFn notify)
    : store_(store), slab_(slab), mrs_(mrs), arena_(arena), clock_(clock), exec_(exec), notify_(std::move(notify)),
      put_timeout_(arena.config().put_timeout) {}

std::uint64_t PutPath::header_off(const Extent& e) const {
  const auto& l = arena_.layout();
  return l.seg.hdr_table_off + (e.gen_slot - std::uint64_t{e.seg} * l.seg.slots()) * kHeaderSlotBytes;
}

std::span<std::byte> PutPath::extent_bytes(const Extent& e, std::uint64_t len) const {
  return arena_.block(e.seg, e.off, len);
}

bool PutPath::fence_all(std::vector<fabric::MemRegion>& mrs) {
  std::vector<fabric::MemRegion> left;
  for (const auto& m : mrs)
    if (!mrs_.fence(m)) left.push_back(m);
  mrs = std::move(left);
  return mrs.empty();
}

// Fence first, free second: an extent is never freed while a write MR can still reach it.
void PutPath::release(Rec& r) {
  const bool fenced = fence_all(r.mrs);
  if (fenced) {
    for (const auto& e : r.ext) slab_.free(e);
  } else {
    limbo_.push_back({std::move(r.mrs), std::move(r.ext)});
  }
  r.mrs.clear();
  r.ext.clear();
  // Only keys this put accepted: a SKIPped key belongs to another live put.
  for (std::size_t i = 0; i < r.keys.size(); ++i)
    if (r.ext_of[i] >= 0) inflight_.erase({r.principal, r.scope, r.keys[i].key});
}

void PutPath::end_put(std::map<PutId, Rec>::iterator it) {
  Rec& r = it->second;
  if (mx_ && !r.counted) {  // ended without a commit verdict: cancel, timeout, endpoint down, doomed
    for (std::size_t i = 0; i < r.keys.size(); ++i)
      if (r.ext_of[i] >= 0) count_put(PutResult::Aborted, r.keys[i].stored_len);
  }
  if (r.charged) store_.release_inflight(r.principal, r.charged);
  if (auto e = ep_puts_.find(r.ep); e != ep_puts_.end() && --e->second == 0) ep_puts_.erase(e);
  puts_.erase(it);
}

PutBeginAck PutPath::put_begin(fabric::EndpointId ep, const PutBeginReq& q) {
  PutBeginAck ack;
  std::uint64_t adm_ops = 0, adm_bytes = 0;  // bucket charges of this put, returned if it does not begin
  auto unadmit = [&] {
    if (adm_ops || adm_bytes) store_.put_unadmit(q.principal, adm_ops, adm_bytes);
    adm_ops = adm_bytes = 0;
  };
  auto refuse = [&](std::uint32_t retry_ms, RefuseReason why) {
    unadmit();
    if (mx_) {
      std::uint64_t bytes = 0;
      for (const auto& k : q.keys) bytes += k.stored_len;
      count_put(PutResult::Refused, bytes, q.keys.size());
      bump(mx_->put_refused[static_cast<std::size_t>(why)], q.keys.size());
    }
    ack.status = BeginStatus::Refused;
    ack.retry_after_ms = retry_ms;
    ack.entries.clear();
    return ack;
  };
  const std::size_t n = q.keys.size();
  if (n == 0 || n > proto::kMaxPutKeys) {
    ack.status = BeginStatus::Malformed;
    return ack;
  }
  std::set<KeyHash> seen;
  for (const auto& k : q.keys) {
    // stored_len above a run can never be placed (and would overflow the 4 KiB round-up). Below the 64 B extent header
    // no client extent can be valid, and the restart scan rejects such a header as corrupt (it was accepted here and then lost at the next
    // restart): refused at the door, like 0.
    if (k.stored_len < proto::kExtentHeaderSize || k.stored_len > arena_.config().run_bytes || !seen.insert(k.key).second) {
      ack.status = BeginStatus::Malformed;
      return ack;
    }
    // An all-zero 16 B prefix is the root marker, so no key may have one; a key sharing its
    // parent's prefix would be its own parent.
    if (parent_is_root(k.key) || parent_prefix(k.key) == parent_prefix(k.parent)) {
      ack.status = BeginStatus::Malformed;
      return ack;
    }
  }

  const bool root = parent_is_root(q.keys[0].parent);
  const bool scope_exists = store_.has_scope(q.principal, q.scope);
  if (!scope_exists && !root) {
    if (mx_) bump(mx_->scope_denied);
    return refuse(0, RefuseReason::Other);
  }  // rev 5.1: only a root put opens a scope

  ack.entries.resize(n);
  std::vector<std::size_t> accepted;
  std::vector<std::uint64_t> lens;
  for (std::size_t i = 0; i < n; ++i) {
    const auto& k = q.keys[i];
    if (store_.has_key(q.principal, q.scope, k.key) || inflight_.count({q.principal, q.scope, k.key})) continue;
    accepted.push_back(i);
    lens.push_back(k.stored_len);
  }
  auto count_skipped = [&] {
    if (!mx_ || accepted.size() == n) return;
    std::uint64_t bytes = 0;
    for (std::size_t i = 0, a = 0; i < n; ++i) {
      if (a < accepted.size() && accepted[a] == i) {
        ++a;
        continue;
      }
      bytes += q.keys[i].stored_len;
    }
    count_put(PutResult::Skipped, bytes, n - accepted.size());
  };
  // the put token buckets. Keys are admitted in order; the first one over budget and every key after
  // it is SKIPped (never REFUSED), so no admitted key is left without its parent. The ack stays Ok and carries the
  // time until the balance is positive in retry_after_ms (the wire already has the field; entries say SKIP).
  // Fetches are never throttled.
  std::uint32_t throttle_ms = 0;
  if (!accepted.empty()) {
    std::size_t admitted = 0;
    int kind = 0;
    for (; admitted < accepted.size(); ++admitted) {
      throttle_ms = store_.put_admit(q.principal, lens[admitted], &kind);
      if (throttle_ms) break;
      ++adm_ops;
      adm_bytes += lens[admitted];
    }
    if (admitted < accepted.size()) {
      if (mx_) bump(mx_->put_throttled[kind], accepted.size() - admitted);
      accepted.resize(admitted);
      lens.resize(admitted);
      ack.retry_after_ms = throttle_ms;
    }
  }
  if (accepted.empty()) {  // everything is SKIP
    count_skipped();
    return ack;
  }
  if (accepted.size() > SlabAllocator::kMaxBatch) return refuse(0, RefuseReason::Other);

  if (auto e = ep_puts_.find(ep); e != ep_puts_.end() &&  // no-wrap compare: count >= max (teeth: max + 1, one too many)
      std::uint64_t{e->second} >= std::uint64_t{arena_.config().max_puts_per_endpoint} + (MIRACACHE_TEETH_ON(EndpointCapLax) ? 1u : 0u))
    return refuse(kRetryBusyMs, RefuseReason::ConnCap);

  // Quota: reserve the exact-size bytes first (a cheap refusal before any eviction).
  std::uint64_t reserved = 0;
  for (std::uint64_t l : lens) reserved += slab_.exact_len(l);
  // Blocks this put depends on (its SKIPped keys and parents) must survive any eviction below.
  std::vector<KeyHash> protect;
  for (const auto& k : q.keys) {
    protect.push_back(k.key);
    protect.push_back(k.parent);
  }
  if (!store_.reserve_inflight(q.principal, reserved, &q.scope, protect)) return refuse(kRetryQuotaMs, RefuseReason::Quota);

  auto ext = slab_.alloc_batch(lens, q.principal);
  bool nothing_freeable = false;
  if (!ext && ext.error().code == ErrorCode::ResourceExhausted) {
    // Free one whole slab run (never a run holding a leased or needed block) and retry once.
    if (store_.evict_one_run(q.principal, q.scope, protect) > 0)
      ext = slab_.alloc_batch(lens, q.principal);
    else
      nothing_freeable = true;
  }
  if (!ext) {
    store_.release_inflight(q.principal, reserved);
    if (ext.error().code == ErrorCode::ResourceExhausted) return refuse(nothing_freeable ? kRetryFullMs : kRetryBusyMs, RefuseReason::Full);
    unadmit();
    ack.status = BeginStatus::Malformed;  // permanent: retrying cannot help
    ack.entries.clear();
    return ack;
  }
  std::uint64_t charge = 0;
  for (const auto& e : *ext) charge += e.len;
  auto fail_free = [&](std::uint32_t retry_ms, RefuseReason why) {
    for (const auto& e : *ext) slab_.free(e);
    store_.release_inflight(q.principal, reserved);
    return refuse(retry_ms, why);
  };
  if (charge > reserved) {  // rung classes round up beyond the exact size
    if (!store_.reserve_inflight(q.principal, charge - reserved, &q.scope, protect)) return fail_free(kRetryQuotaMs, RefuseReason::Quota);
    reserved = charge;
  }
  if (root) {
    if (Status st = store_.ensure_scope_for_root_put(q.principal, q.scope, clock_.now()); !st) {
      // The scope is an expired or dropped one still draining: retryable (the client backs off and retries
      // the same job), not the retry-0 "do not retry" failure.
      if (const std::uint32_t ms = store_.drain_retry_ms(q.principal, q.scope)) return fail_free(ms, RefuseReason::Other);
      if (mx_) bump(mx_->scope_denied);
      return fail_free(0, RefuseReason::Other);
    }
  }

  Rec rec;
  rec.charged = reserved;
  rec.id = next_id_++;
  rec.ep = ep;
  rec.principal = q.principal;
  rec.scope = q.scope;
  rec.epoch = store_.scope_epoch();
  rec.keys = q.keys;
  rec.ext_of.assign(n, -1);
  rec.ext = *ext;
  rec.deadline = clock_.now() + put_timeout_;
  rec.begun = clock_.now();

  // One write MR per run of adjacent extents.
  std::vector<std::size_t> first_of(accepted.size());
  std::vector<std::uint64_t> base_off(accepted.size());
  std::size_t g_start = 0;
  auto flush_group = [&](std::size_t end) -> bool {
    const Extent& a = rec.ext[g_start];
    const std::uint64_t len = rec.ext[end - 1].off + rec.ext[end - 1].len - a.off;
    auto mr = mrs_.register_write(arena_.block(a.seg, a.off, len), q.device);
    if (!mr) return false;
    rec.mrs.push_back(*mr);
    ack.mr.push_back({reinterpret_cast<std::uint64_t>(mr->addr), len, mr->rkey});
    for (std::size_t j = g_start; j < end; ++j) {
      first_of[j] = rec.mrs.size() - 1;
      base_off[j] = rec.ext[j].off - a.off;
    }
    return true;
  };
  bool ok = true;
  for (std::size_t j = 1; ok && j <= rec.ext.size(); ++j) {
    if (j == rec.ext.size() || rec.ext[j].seg != rec.ext[j - 1].seg ||
        rec.ext[j].off != rec.ext[j - 1].off + rec.ext[j - 1].len) {
      ok = flush_group(j);
      g_start = j;
    }
  }
  if (!ok) {
    release(rec);
    store_.release_inflight(q.principal, rec.charged);
    ack.mr.clear();
    return refuse(kRetryBusyMs, RefuseReason::Other);
  }
  for (std::size_t j = 0; j < accepted.size(); ++j) {
    rec.ext_of[accepted[j]] = static_cast<int>(j);
    ack.entries[accepted[j]] = {true, static_cast<std::uint8_t>(first_of[j]), base_off[j]};
    inflight_.insert({q.principal, q.scope, q.keys[accepted[j]].key});
  }
  count_skipped();
  ack.put_id = rec.id;
  ++ep_puts_[ep];
  puts_.emplace(rec.id, std::move(rec));
  return ack;
}

PutDoneResult PutPath::all_aborted(const Rec& r, proto::DoneReason why) const {
  PutDoneResult res;
  res.put_id = r.id;
  res.ep = r.ep;
  for (std::size_t i = 0; i < r.keys.size(); ++i)
    if (r.ext_of[i] >= 0)
      res.e.push_back({static_cast<std::uint16_t>(i), static_cast<std::uint8_t>(proto::DoneStatus::Aborted),
                       static_cast<std::uint8_t>(why)});
  return res;
}

void PutPath::abort_put(PutId id, proto::DoneReason why, bool notify) {
  auto it = puts_.find(id);
  if (it == puts_.end()) return;
  Rec& r = it->second;
  PutDoneResult res = all_aborted(r, why);
  release(r);
  end_put(it);
  if (notify && notify_) notify_(res);
}

void PutPath::put_commit(fabric::EndpointId ep, const PutCommitReq& q, PutDoneFn done) {
  PutDoneResult res;
  res.put_id = q.put_id;
  res.ep = ep;
  auto it = puts_.find(q.put_id);
  // Only the QP that carried PUT_BEGIN may commit; another endpoint's id looks unknown.
  if (it == puts_.end() || (it->second.ep != ep && !MIRACACHE_TEETH_ON(ForeignPutId)) || it->second.state != State::Writing) {
    res.status = MIRACACHE_TEETH_ON(UnknownPutOk) ? CommitStatus::Ok : CommitStatus::UnknownPut;  // TEETH: UnknownPutOk
    return done(res);
  }
  Rec& r = it->second;
  // Indexes ascending and exactly the accepted keys, lengths equal to PUT_BEGIN.
  std::vector<std::size_t> want;
  for (std::size_t i = 0; i < r.keys.size(); ++i)
    if (r.ext_of[i] >= 0) want.push_back(i);
  bool good = q.e.size() == want.size();
  for (std::size_t j = 0; good && j < want.size(); ++j)
    good = q.e[j].key_index == want[j] && q.e[j].stored_len == r.keys[want[j]].stored_len;
  if (!good) {  // MALFORMED; the put stays WRITING until commit, cancel or timeout
    res.status = CommitStatus::Malformed;
    return done(res);
  }
  r.crc.assign(r.ext.size(), 0);
  for (const auto& c : q.e) r.crc[static_cast<std::size_t>(r.ext_of[c.key_index])] = c.crc32c;
  r.done = std::move(done);

  // Fence BEFORE the digest: no WRITE can land after this point (a CQE is not placement).
  if (!fence_all(r.mrs)) {
    PutDoneResult ab = all_aborted(r, proto::DoneReason::Doomed);
    PutDoneFn cb = std::move(r.done);
    release(r);  // unfenced MRs go to limbo with their extents
    end_put(it);
    return cb(ab);
  }
  r.state = State::Fenced;
  r.state = State::Digesting;

  struct Job {
    std::vector<std::span<const std::byte>> bytes;
    std::vector<std::uint32_t> crc;
  };
  auto job = std::make_shared<Job>();
  for (std::size_t j = 0; j < r.ext.size(); ++j) {
    const std::size_t ki = static_cast<std::size_t>(std::find(r.ext_of.begin(), r.ext_of.end(), static_cast<int>(j)) -
                                                    r.ext_of.begin());
    job->bytes.push_back(extent_bytes(r.ext[j], r.keys[ki].stored_len));
  }
  job->crc.assign(r.ext.size(), 0);
  const PutId id = r.id;
  exec_.post(
      [job] {
        for (std::size_t j = 0; j < job->bytes.size(); ++j) job->crc[j] = crc32c(job->bytes[j]);
      },
      [this, id, job] { finish_digest(id, job->crc); });
}

void PutPath::finish_digest(PutId id, const std::vector<std::uint32_t>& server_crc) {
  auto it = puts_.find(id);
  if (it == puts_.end()) return;
  Rec& r = it->second;
  PutDoneResult res;
  res.put_id = id;
  res.ep = r.ep;
  if (r.aborted) {  // cancelled or endpoint down while digesting: nothing is committed
    release(r);
    end_put(it);
    return;
  }
  // Commit converts the reservation into committed bytes (charged by commit_block).
  store_.release_inflight(r.principal, r.charged);
  r.charged = 0;
  const auto done_status = static_cast<std::uint8_t>(proto::DoneStatus::Committed);
  const auto aborted_status = static_cast<std::uint8_t>(proto::DoneStatus::Aborted);
  std::vector<Extent> to_free;
  for (std::size_t i = 0; i < r.keys.size(); ++i) {
    if (r.ext_of[i] < 0) continue;
    const auto j = static_cast<std::size_t>(r.ext_of[i]);
    const Extent& e = r.ext[j];
    const PutKey& k = r.keys[i];
    proto::DoneEntry de{static_cast<std::uint16_t>(i), aborted_status, static_cast<std::uint8_t>(proto::DoneReason::None)};
    if (server_crc[j] != r.crc[j] && !MIRACACHE_TEETH_ON(CommitBeforeDigest)) {  // TEETH: ignore the verdict
      de.reason = static_cast<std::uint8_t>(proto::DoneReason::Digest);
      if (mx_) bump(mx_->put_digest_mismatch);
      count_put(PutResult::Aborted, k.stored_len);
      to_free.push_back(e);
    } else {
      proto::ServerHeader h;
      h.stored_len = k.stored_len;
      std::memcpy(h.scope_id, r.scope.data(), 32);
      std::memcpy(h.key_hash, k.key.data(), 32);
      std::memcpy(h.parent_hash, k.parent.data(), 16);
      h.chain_pos = k.chain_pos;
      h.payload_crc = server_crc[j];
      // The header is written only once the block is in the index (same store-thread turn, so no reader or
      // scrub pin sees the gap). A valid header on media therefore always names a live committed block of a live
      // scope: a block refused here never had one, even if the process dies right now.
      if (store_.commit_block(r.principal, r.scope, k.key, k.parent, e, k.stored_len, r.epoch)) {
        slab_.write_header(e, h);
        de.status = done_status;
        count_put(PutResult::Committed, k.stored_len);
      } else {
        de.reason = static_cast<std::uint8_t>(proto::DoneReason::Doomed);
        count_put(PutResult::Aborted, k.stored_len);
        to_free.push_back(e);
      }
    }
    res.e.push_back(de);
  }
  for (const auto& e : to_free) slab_.free(e);
  for (std::size_t i = 0; i < r.keys.size(); ++i)
    if (r.ext_of[i] >= 0) inflight_.erase({r.principal, r.scope, r.keys[i].key});
  r.counted = true;
  if (mx_ && mx_->put_commit_seconds) {
    const auto d = (clock_.now() - r.begun).count();
    mx_->put_commit_seconds->observe_ns(d > 0 ? static_cast<std::uint64_t>(d) : 0);
  }
  PutDoneFn cb = std::move(r.done);
  end_put(it);
  if (cb) cb(res);
}

void PutPath::put_cancel(fabric::EndpointId ep, PutId id, PutDoneFn done) {
  PutDoneResult res;
  res.put_id = id;
  res.ep = ep;
  auto it = puts_.find(id);
  if (it == puts_.end() || (it->second.ep != ep && !MIRACACHE_TEETH_ON(ForeignPutId))) {  // a foreign put id looks unknown
    res.status = MIRACACHE_TEETH_ON(UnknownPutOk) ? CommitStatus::Ok : CommitStatus::UnknownPut;  // TEETH: UnknownPutOk
    return done(res);
  }
  Rec& r = it->second;
  res = all_aborted(r, proto::DoneReason::Cancel);
  if (r.state == State::Writing) {
    abort_put(id, proto::DoneReason::Cancel, false);
  } else {
    r.aborted = true;  // the digest completion frees it
    r.done = {};
  }
  done(res);
}

void PutPath::on_endpoint_down(fabric::EndpointId ep) {
  std::vector<PutId> ids;
  for (auto& [id, r] : puts_)
    if (r.ep == ep) ids.push_back(id);
  for (PutId id : ids) {
    Rec& r = puts_.at(id);
    if (r.state == State::Writing) {
      abort_put(id, proto::DoneReason::Cancel, false);
    } else {
      r.aborted = true;
      r.done = {};
    }
  }
}

void PutPath::tick() {
  const Nanos now = clock_.now();
  std::vector<PutId> expired;
  for (const auto& [id, r] : puts_)
    if (r.state == State::Writing && r.deadline <= now) expired.push_back(id);
  for (PutId id : expired) abort_put(id, proto::DoneReason::Timeout, true);

  std::vector<Limbo> still;
  for (auto& l : limbo_) {
    if (fence_all(l.mrs)) {
      for (const auto& e : l.ext) slab_.free(e);
    } else {
      still.push_back(std::move(l));
    }
  }
  limbo_ = std::move(still);
}

Status PutPath::check_invariants() const {
  auto bad = [](const char* m) -> Status { return Error{ErrorCode::Corrupt, m}; };
  if (Status st = mrs_.check_invariants(); !st) return st;

  // WriteMrFenced: live write MRs belong exactly to WRITING puts (plus limbo, i.e. a
  // fence that failed and is being retried); no put past WRITING holds one.
  std::set<std::uint64_t> owned;
  for (const auto& [id, r] : puts_) {
    if (r.state != State::Writing && !r.mrs.empty()) return bad("put: write MR live after fence");
    for (const auto& m : r.mrs) owned.insert(MrManager::write_key(m));
  }
  for (const auto& l : limbo_)
    for (const auto& m : l.mrs) owned.insert(MrManager::write_key(m));
  for (const auto& [rk, m] : mrs_.write_mrs())
    if (!owned.count(rk)) return bad("put: orphan write MR");
  if (owned.size() != mrs_.live_write_mrs()) return bad("put: write MR bookkeeping");

  // DenyByDefault: a write MR may cover only blocks that are WRITING with the held
  // generation; committed and free blocks are unreachable for writers.
  for (const auto& [id, r] : puts_) {
    for (const auto& m : r.mrs) {
      bool covered = false;
      for (const auto& e : r.ext) {
        auto* base = arena_.block(e.seg, e.off, 1).data();
        if (base >= m.addr && base < m.addr + m.len) {
          covered = true;
          if (arena_.state_gen().state(e.gen_slot) != proto::BlockState::Writing ||
              arena_.state_gen().generation(e.gen_slot) != e.gen)
            return bad("put: write MR over a non-WRITING block");
        }
      }
      if (!covered) return bad("put: write MR covers no extent");
    }
    if (r.state != State::Writing) {
      for (const auto& e : r.ext)
        if (arena_.state_gen().state(e.gen_slot) != proto::BlockState::Writing)
          return bad("put: held extent not WRITING");
    }
  }

  // CommittedIntact: every committed (or zombie) block still matches its header and CRC.
  Status result;
  store_.for_each_block([&](const Extent& e, std::uint64_t stored_len, bool zombie) {
    if (!result) return;
    const auto st = arena_.state_gen().state(e.gen_slot);
    if (st != (zombie ? proto::BlockState::Zombie : proto::BlockState::Committed) ||
        arena_.state_gen().generation(e.gen_slot) != e.gen) {
      result = bad("put: committed block state/gen");
      return;
    }
    auto hb = arena_.block(e.seg, header_off(e), kHeaderSlotBytes);
    if (zombie) {  // a ZOMBIE is out of the index and its header is cleared (never resumed after a crash)
      if (std::any_of(hb.begin(), hb.end(), [](std::byte v) { return v != std::byte{0}; })) result = bad("put: zombie header not cleared");
      return;
    }
    auto h = proto::decode_server_header(std::span<const std::byte, proto::kServerHeaderSize>(hb.data(), proto::kServerHeaderSize));
    if (!h || h->generation != e.gen || h->stored_len != stored_len) {
      result = bad("put: committed header");
      return;
    }
    if (crc32c(extent_bytes(e, stored_len)) != h->payload_crc) result = bad("put: committed payload CRC");
  });
  return result;
}

}  // namespace miracache::store
