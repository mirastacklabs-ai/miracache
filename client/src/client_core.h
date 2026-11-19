// SPDX-License-Identifier: Apache-2.0
// ClientCore (A1.6 L3): the deterministic fetch / put / probe state machines. No threads,
// no blocking: submit_* never waits, everything advances in pump(), which polls the fabric
// and runs due timeouts. Not thread-safe (the facade serialises access).
//
// Fetch (spec 8.1): LOOKUP -> lease -> READ each hit into the landing pool -> seq READ of
// its state_gen word -> DecryptPipeline (AEAD verify + decrypt into the engine buffer) ->
// RELEASE. Put (spec 8.2): PUT_BEGIN -> seal with block_codec -> RDMA WRITE -> PUT_COMMIT
// (CRC32C, exact stored_len) -> PUT_DONE. Failure is a status, never an error.
//
// Result vs release: `done` reports per-key statuses; `released` says every pool span, RDMA
// op and pipeline task of the job has drained so the caller's buffers are free again. On
// TIMEOUT `done` fires at once and `released` only after the drain. On cancel() both fire
// after the drain (done first). Engine buffers of non-HIT keys are zeroed before `released`.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <tuple>
#include <vector>

#include "client/decrypt_pipeline.h"
#include "client/landing_pool.h"
#include "crypto/block_codec.h"
#include "crypto/gcm.h"
#include "fabric/fabric.h"
#include "miracache/scope.h"
#include "miracache/types.h"
#include "src/client_metrics.h"
#include "src/server_port.h"
#include "store/slab.h"
#include "util/clock.h"
#include "util/executor.h"
#include "util/nonce_source.h"

namespace miracache {

struct KeyRef {
  std::span<const std::byte> raw;         // engine key (fed to KeySource)
  std::span<const std::byte> parent_raw;  // empty = chain root
  std::uint64_t chain_pos = 0;
};
// Fetch: the engine buffer to fill (exactly the plaintext length). Store: the plaintext.
struct BufRef {
  std::span<std::byte> buf;
};

using ResultFn = std::function<void(Ticket, std::span<const KeyStatus>)>;
using ReleasedFn = std::function<void(Ticket)>;
struct Notify {
  ResultFn done;
  ReleasedFn released;
};

// S02: the two series miracache_client_landing_pool_bytes{state="used"} and {state="free"} of a node come from ONE read
// of the pool, so used + free is the pool size in every scrape, under traffic too. The registry renders a family's
// children in registration order under its one lock, and "used" is always registered first: its callback stores the
// read here, the "free" callback derives from it and never reads the pool.
struct PoolSeriesSnap {
  std::atomic<std::int64_t> used{0}, total{0};
  std::int64_t take(std::int64_t u, std::int64_t t) {  // "used" callback
    used.store(u, std::memory_order_relaxed);
    total.store(t, std::memory_order_relaxed);
    return u;
  }
  std::int64_t free_bytes() const { return total.load(std::memory_order_relaxed) - used.load(std::memory_order_relaxed); }
};

struct ClientCoreOptions {
  std::uint8_t segment_log2 = 16;
  std::uint32_t max_inflight_segments = 8;
  std::size_t pool_bytes = 16u << 20;
  Nanos renew_every = std::chrono::milliseconds(500);
  std::size_t max_put_batch = store::SlabAllocator::kMaxBatch;
  // Several memory nodes share one registry; a non-empty node_label tags every series with node="...".
  telemetry::Registry* registry = nullptr;
  std::string node_label;
  // The core registers miracache_client_landing_pool_bytes{node_label} itself. False (bundle mode, review w3b Z02):
  // several cores may share a node label in turn, so the Client points that series at one of them.
  bool pool_gauges = true;
  // HR2 (class A, fabric.slice_bytes): the size a fetch READ is cut into, read once per key at its start so a change
  // reaches new fetches only. Null or 0 = one READ per block.
  std::function<std::uint64_t()> slice_bytes;
  // RL3 test hook (sim audits): called with every landing-pool span the core gives back to the pool.
  std::function<void(std::span<const std::byte>)> on_span_release;
  // RL3 test hook (sim audits): called with every READ/WRITE completion as the core takes it, before it acts on it.
  std::function<void(const fabric::Completion&)> on_cqe;
};

// RL3 (multi-rail plan decisions 8, 9): a fetch READ's work-request tag, decoded. `group` names one block of one job
// (its payload slices and its state_gen READ share it); `seq` = the state_gen READ. Used by the sim audit.
struct FetchTagInfo {
  std::uint64_t group = 0;
  bool seq = false;
};

class ClientCore {
 public:
  // `ex` runs segment decrypts (and may call back from any thread); `salts` feeds block salts.
  // Q09: `fab`, `port`, `clock`, `ex` and `salts` must outlive the core (~ClientCore unbinds its metrics
  // from `port`). A wire port should release its endpoints (WirePort::release_endpoints) before the core
  // goes, so no QP is left that could still DMA into the landing pool when it is unmapped (Q06).
  static Expected<std::unique_ptr<ClientCore>> create(fabric::Fabric& fab, ServerPort& port, const Clock& clock,
                                                      Executor& ex, NonceSource& salts,
                                                      const ClientCoreOptions& opts = {});
  ~ClientCore();

  // RL3: decodes a fetch READ tag (nullopt for a WRITE tag).
  static std::optional<FetchTagInfo> fetch_tag(std::uint64_t tag);
  // Fetch slices waiting for a fetch window (test hook).
  std::size_t slices_waiting() const { return waitq_.size(); }
  std::uint64_t slices_reissued() const { return reissued_; }  // RL3 test hook

  // `keys` and `bufs` have equal size and stay valid until `released`. `deadline` is absolute
  // (Clock time). Never block; the returned Ticket identifies the job in the callbacks.
  Ticket submit_fetch(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys,
                      std::span<const BufRef> bufs, Nanos deadline, Notify cb);
  Ticket submit_store(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys,
                      std::span<const BufRef> bufs, Nanos deadline, Notify cb);
  // Presence check, separate from fetch: takes no lease that outlives the call.
  Ticket probe(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys, Nanos deadline,
               ResultFn done);
  void cancel(Ticket t);
  // Q05 watchdog support: RDMA ops / decrypt tasks of the job that have not completed yet.
  std::size_t outstanding_ops(Ticket t) const;
  // Last resort for a job whose completions never arrive: fails it (Timeout), abandons its ops and
  // finishes it. Returns the abandoned op count. Their pool spans stay quarantined until the
  // endpoints that carried the ops are reaped (see client_core.cpp, N02).
  std::size_t force_fail(Ticket t);
  std::size_t quarantined_bytes() const { return quarantined_bytes_; }  // N02 (tests, metric)
  std::vector<std::span<std::byte>> quarantined_spans() const;          // N02 test hook
  // Returns true if it processed any completion (a hint for idle back-off, not a guarantee).
  bool pump();

  // Prometheus text of this client's metrics. Thread-safe (atomics + registry mutex).
  std::string metrics_text() const {
    std::string s;
    mx_.reg.write_prometheus(s);
    return s;
  }
  ClientMetrics& metrics() { return mx_; }

  std::size_t jobs_live() const { return jobs_.size(); }
  std::size_t pool_bytes_in_use() const { return pool_->bytes_in_use(); }
  std::size_t pool_bytes_total() const;  // the landing pool size (pool_bytes rounded up to the pool alignment)
  // Client invariants: pool empty and no jobs when idle, endpoints healthy. Ok or Corrupt.
  Status check_invariants() const;

 private:
  struct Job;
  struct FKey;
  struct PKey;
  ClientCore(fabric::Fabric& fab, ServerPort& port, const Clock& clock, Executor& ex, NonceSource& salts,
             const ClientCoreOptions& opts);
  Status init();

  Job& new_job(int kind, Nanos deadline, Notify cb, std::size_t n);
  // fetch
  void fetch_start_key(Job& j, std::size_t i);
  void fetch_on_cqe(Job& j, std::size_t i, std::uint32_t slice, std::uint32_t attempt, bool is_seq, const Status& st);
  void fetch_key_finished(Job& j, std::size_t i, FetchOutcome oc);
  // RL3 slicing: post one payload slice / the seq READ (Busy = every fetch window is full: it waits in waitq_).
  enum class Post { Posted, Busy, Failed };
  Post post_slice(Job& j, std::size_t i, std::uint32_t s);
  Post post_seq(Job& j, std::size_t i);
  Post read_refused(const Status& st);  // R16: what a refused READ post means (Busy = it waits)
  void slice_finished(Job& j, std::size_t i, bool ok);  // a payload slice is done for good (landed or given up)
  void data_complete(Job& j, std::size_t i);            // every payload slice is done: the seq rule's gate
  bool may_reissue(const Job& j, const Status& st) const;
  void post_waiting();
  void free_span(const PoolSpan& s);
  struct WaitRef {
    std::uint64_t job = 0;
    std::size_t key = 0;
    std::uint32_t slice = 0;  // kSeqSlice = the seq READ
  };
  std::list<WaitRef> waitq_;  // a list: post_waiting appends (a seq READ) while it walks it
  std::uint64_t reissued_ = 0;
  // put
  void put_begin_batch(Job& j);
  void put_on_write(Job& j, std::size_t i, const Status& st);
  // R16: posts the WRITE of batch entry b (key j.batch[b]); Busy = its ingest QP's send queue is full (it waits).
  Post put_post_write(Job& j, std::size_t b);
  void put_post_waiting(Job& j);
  void put_commit_batch(Job& j);
  void put_finish_batch(Job& j, const store::PutDoneResult& r);
  void put_free_spans(Job& j);
  void put_drop_rest(Job& j, KeyStatus st);

  // Session loss / reconnect (wire port): see sync_session in client_core.cpp.
  void sync_session();
  void fail_all_jobs();
  // N02 quarantine: a span an abandoned op may still DMA into (see force_fail in client_core.cpp).
  struct Quarantined {
    PoolSpan span;
    std::uint64_t reaped_at = 0;  // released once port_.session_reaped(this) ...
    std::uint64_t job = 0;        // ... and the job (its decrypt task may still read the span) is gone
  };
  void quarantine(const PoolSpan& s, std::uint64_t reaped_at, std::uint64_t job);
  void release_quarantine();
  struct SplitAck {
    std::vector<store::LookupEntry> entries;  // aligned with the request keys
    std::vector<store::LeaseId> leases;       // one per part that took a lease
    std::size_t answered = 0;                 // keys whose part got a well-formed reply
    Nanos lease_expiry = Nanos::max();        // RL3: the earliest lease expiry of the parts (Clock time)
  };
  SplitAck lookup_split(const store::LookupReq& q, bool lease, Nanos deadline);

  void job_tick(Job& j);
  void handle_cqe(const fabric::Completion& c);
  void finish_if_drained(Job& j);
  void report_done(Job& j);
  bool all_final(const Job& j) const;

  fabric::Fabric& fab_;
  ServerPort& port_;
  const Clock& clock_;
  Executor& ex_;
  NonceSource& salts_;
  ClientCoreOptions opts_;
  ClientMetrics mx_;  // before pool_: its callback gauges read pool_, and the registry outlives it
  ServerInfo info_;
  fabric::Endpoint* fetch_ep_ = nullptr;
  fabric::Endpoint* ingest_ep_ = nullptr;
  std::uint64_t seen_down_ = 0;  // ServerPort::session_down_count() last acted on
  bool bound_ = true;            // fetch_ep_/ingest_ep_ are the live session's endpoints
  // R16: READs / WRITEs posted and not completed yet (any endpoint). A send queue that is full (ResourceExhausted)
  // while some are outstanding is backpressure: the post waits for a completion instead of failing.
  std::uint64_t reads_out_ = 0, writes_out_ = 0;
  std::unique_ptr<LandingPool> pool_;
  std::unique_ptr<DecryptPipeline> pipe_;
  SubpoolKey sub_;
  std::optional<GcmCtx> gcm_;
  std::uint64_t next_job_ = 1;
  std::map<std::uint64_t, std::unique_ptr<Job>> jobs_;
  std::vector<ServerPort::Renewed> renewed_;  // RL3 leftover: take_renewed scratch (pump)
  std::mutex qmu_;  // pipeline completions may arrive from executor threads
  std::deque<std::tuple<std::uint64_t, std::size_t, FetchOutcome>> fq_;
  std::vector<Quarantined> quarantine_;
  std::size_t quarantined_bytes_ = 0;
};

}  // namespace miracache
