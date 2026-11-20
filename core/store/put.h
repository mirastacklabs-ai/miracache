// SPDX-License-Identifier: Apache-2.0
// Client-push put path (spec 8.2 two-phase put, 8.3 idempotent puts).
//
//   put_begin   scope check (implicit open only at the chain root, rev 5.1), SKIP for keys
//               already COMMITTED, allocation, (Writing, gen) in state_gen, write MR(s).
//   put_commit  WRITING -> FENCED (write MR deregistered) -> DIGESTING (CRC32C over the
//               extent on the Executor) -> DONE (header written, then commit_block).
//   put_cancel / timeout / endpoint down: fence, free.
// A CQE is not placement: nothing is trusted until the fence and the digest. Only the
// endpoint that did PUT_BEGIN may commit or cancel. Typed API; the server maps it to frames.
// Batches take at most SlabAllocator::kMaxBatch accepted keys in v0 (larger: REFUSED,
// retry 0). Single-threaded (store thread).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <set>
#include <tuple>
#include <vector>

#include "fabric/types.h"
#include "proto/messages.h"
#include "store/mr_manager.h"
#include "store/slab.h"
#include "store/store.h"
#include "store/store_metrics.h"
#include "util/clock.h"
#include "util/executor.h"

namespace miracache::store {

using PutId = std::uint64_t;

struct PutKey {
  KeyHash key{};
  KeyHash parent{};  // all zero = chain root
  std::uint64_t chain_pos = 0;
  std::uint64_t stored_len = 0;
};
struct PutBeginReq {
  PrincipalId principal = 0;
  ScopeId scope{};
  std::vector<PutKey> keys;  // 1..64
  std::uint32_t device = 0;  // device (fabric index) of the ingest rail the put began on; its write MRs go there
};

enum class BeginStatus : std::uint8_t { Ok = 0, Refused = 1, Malformed = 2 };
struct MrRef {
  std::uint64_t addr = 0, len = 0;
  std::uint32_t rkey = 0;
};
struct BeginEntry {
  bool accept = false;  // false = SKIP
  std::uint8_t mr_index = 0;
  std::uint64_t offset = 0;  // from the MR's addr
};
// Why a Refused PUT_BEGIN is a per-key SKIP and not a failure: the node answered
// StaleEpoch or Draining. Only the wire port sets it; the client counts miracache_client_put_skipped_total{reason}.
enum class BeginSkip : std::uint8_t { None = 0, StaleEpoch = 1, Draining = 2 };
struct PutBeginAck {
  PutId put_id = 0;  // 0 when nothing was accepted
  BeginStatus status = BeginStatus::Ok;
  BeginSkip skip = BeginSkip::None;  // Refused only
  std::uint32_t retry_after_ms = 0;  // Refused: 0 = do not retry
  std::vector<MrRef> mr;
  std::vector<BeginEntry> entries;  // one per requested key
};

struct CommitEntry {
  std::uint16_t key_index = 0;  // index into the PUT_BEGIN keys; strictly ascending
  std::uint32_t crc32c = 0;
  std::uint64_t stored_len = 0;  // must equal the PUT_BEGIN value
};
struct PutCommitReq {
  PutId put_id = 0;
  std::vector<CommitEntry> e;  // exactly the accepted keys
};

// WrongEndpoint is no longer returned: another endpoint's put id answers UnknownPut so
// put ids of other endpoints are not an oracle. The value is kept for compatibility.
enum class CommitStatus : std::uint8_t { Ok, Malformed, UnknownPut, WrongEndpoint };
struct PutDoneResult {
  PutId put_id = 0;
  fabric::EndpointId ep = 0;  // endpoint that owns the put: the server routes PUT_DONE (also for timeouts)
  CommitStatus status = CommitStatus::Ok;
  std::vector<proto::DoneEntry> e;  // per accepted key
};
using PutDoneFn = std::function<void(const PutDoneResult&)>;

class PutPath {
 public:
  // `notify` receives PUT_DONE for puts the store ends on its own (timeout).
  PutPath(Store& store, SlabAllocator& slab, MrManager& mrs, Arena& arena, const Clock& clock, Executor& exec,
          PutDoneFn notify = {});

  // The live put timeout; a put already begun keeps its deadline. Store thread.
  void set_timeouts(Nanos put_timeout) { put_timeout_ = put_timeout; }
  Nanos put_timeout() const { return put_timeout_; }
  // Optional counters (null = none); the pointee must outlive the put path.
  void set_metrics(const StoreMetrics* m) { mx_ = m; }
  PutBeginAck put_begin(fabric::EndpointId ep, const PutBeginReq& q);
  void put_commit(fabric::EndpointId ep, const PutCommitReq& q, PutDoneFn done);
  void put_cancel(fabric::EndpointId ep, PutId id, PutDoneFn done);
  void on_endpoint_down(fabric::EndpointId ep);
  // Times out WRITING puts and retries fences that failed.
  void tick();

  // WriteMrFenced, DenyByDefault (write MRs cover only WRITING blocks), CommittedIntact
  // (CRC recomputed against the header). Ok or Corrupt.
  Status check_invariants() const;

  std::size_t n_puts() const { return puts_.size(); }
  std::size_t n_limbo() const { return limbo_.size(); }

 private:
  enum class State : std::uint8_t { Writing, Fenced, Digesting, Done };
  struct Rec {
    PutId id = 0;
    fabric::EndpointId ep = 0;
    PrincipalId principal = 0;
    ScopeId scope{};
    std::uint64_t epoch = 0;  // Store::scope_epoch() at PUT_BEGIN: a later scope dooms the put
    std::vector<PutKey> keys;
    std::vector<int> ext_of;  // per key: index into ext, -1 = SKIP
    std::vector<Extent> ext;
    std::vector<fabric::MemRegion> mrs;
    std::vector<std::uint32_t> crc;  // client CRCs per ext
    State state = State::Writing;
    Nanos deadline{0};
    bool aborted = false;  // Digesting: free instead of commit
    Nanos begun{0};        // when PUT_BEGIN ran, for the commit-latency histogram
    bool counted = false;  // every accepted key already counted committed/aborted
    std::uint64_t charged = 0;  // in-flight bytes reserved on the principal
    PutDoneFn done;
  };
  struct Limbo {
    std::vector<fabric::MemRegion> mrs;
    std::vector<Extent> ext;
  };
  using InflightKey = std::tuple<PrincipalId, ScopeId, KeyHash>;

  bool fence_all(std::vector<fabric::MemRegion>& mrs);  // true if every MR is fenced
  void release(Rec& r);                                // fence, then free (or limbo)
  void end_put(std::map<PutId, Rec>::iterator it);     // returns quota and the endpoint slot, erases
  void abort_put(PutId id, proto::DoneReason why, bool notify);
  void finish_digest(PutId id, const std::vector<std::uint32_t>& server_crc);
  std::uint64_t header_off(const Extent& e) const;
  std::span<std::byte> extent_bytes(const Extent& e, std::uint64_t len) const;
  PutDoneResult all_aborted(const Rec& r, proto::DoneReason why) const;

  Store& store_;
  SlabAllocator& slab_;
  MrManager& mrs_;
  Arena& arena_;
  const Clock& clock_;
  Executor& exec_;
  PutDoneFn notify_;
  Nanos put_timeout_;
  const StoreMetrics* mx_ = nullptr;
  void count_put(PutResult r, std::uint64_t bytes, std::uint64_t ops = 1) const {
    if (!mx_) return;
    bump(mx_->put_ops[static_cast<std::size_t>(r)], ops);
    bump(mx_->put_bytes[static_cast<std::size_t>(r)], bytes);
  }
  PutId next_id_ = 1;
  std::map<PutId, Rec> puts_;
  std::set<InflightKey> inflight_;
  std::map<fabric::EndpointId, std::uint32_t> ep_puts_;  // live puts per endpoint
  std::vector<Limbo> limbo_;
};

}  // namespace miracache::store
