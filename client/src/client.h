// SPDX-License-Identifier: Apache-2.0
// Client facade (A1.6 L3): thread-safe, non-blocking submit + poll over Runtime (tickets,
// completion queue, eventfd, worker threads) and the deterministic ClientCore. Each job runs
// on a runtime worker, which drives the core under one mutex until the job has drained; so a
// facade Completion means "per-key statuses AND buffers released". Data-path calls never
// throw; failure is a per-key status.
#pragma once

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <vector>

#include "miracache/config.h"
#include "miracache/scope.h"
#include "runtime/runtime.h"
#include "src/bundle_watcher.h"
#include "src/client_core.h"
#include "src/dyn_config.h"
#include "src/wire_port.h"

namespace miracache {

class Client {
 public:
  // Production open over the wire adapter. Unsupported until store S7 lands (frames).
  static Expected<std::unique_ptr<Client>> open(const ClientConfig& cfg, ScopeProvider& provider);

  // Loopback: ClientCore on `fab` against an in-process ServerPort (see loopback_port.h).
  // `drive` runs between pumps when a job waits (tests: step the SimNetwork, or advance a
  // SimClock when idle). All referenced objects must outlive the Client.
  struct Env {
    fabric::Fabric* fab = nullptr;
    ServerPort* port = nullptr;
    const Clock* clock = nullptr;
    Executor* executor = nullptr;
    NonceSource* salts = nullptr;
    std::function<void()> drive;
    // R12 (review s11), sim only: an idle Up node's keepalive tick also calls `drive` once, so its PINGs travel and the
    // PONGs land with no other thread in the sim. Off by default: with it on, every keepalive thread steps the sim on
    // every idle tick, so a rig whose test thread touches sim state directly (clock, fake servers, inject_*, endpoint
    // aborts) races them (the run #277 class). Only for a rig whose test thread never touches the sim while it runs.
    bool drive_when_up = false;
    // Q05 watchdog: a job still inside the pump loop this long after its deadline is force-failed.
    // N04/Q05: above the QP retry exhaustion (ACK timeout x (retry_count + 1)) plus a margin, so a
    // completion that is merely slow (a WR that will still fail with RETRY_EXC) is normally not cut off.
    // The ACK timeout is pinned on the client QPs where the kernel allows it, else assumed (see
    // fabric/types.h: native IB may use a larger one; iWARP has none, the keepalive suspect timer detects a
    // dead peer there). A cut-off that comes too early only quarantines spans, never corrupts.
    // fabric.watchdog_grace_ms overrides it.
    static constexpr Nanos kWatchdogMargin = std::chrono::seconds(2);
    static constexpr Nanos kDefaultWatchdogGrace = fabric::qp_retry_exhaustion() + kWatchdogMargin;  // ~19.2 s
    Nanos watchdog_grace = kDefaultWatchdogGrace;
    // A2.10 best-effort replicas (placement.replicas / replica_mode / replica_buffer_bytes): each scope lives on
    // the first `replicas` nodes of its placement order (one per zone when zones are set). 1 = today's
    // single-owner path. > 1 needs >= replicas + 1 nodes. Async (default): a store job runs one leg and a
    // client-owned replicator (one thread per node) writes the other copies from a bounded plaintext pool
    // (`replica_buffer_bytes`, 0 = replicas off). Sync: the job waits for every leg (or the deadline).
    unsigned replicas = 1;
    ReplicaMode replica_mode = ReplicaMode::Async;
    std::size_t replica_buffer_bytes = 256u << 20;
    // A3.3: the matched NIC profile (empty = none: sim, tests). Exported as
    // miracache_nic_profile_info{profile,verified} and miracache_nic_unprofiled.
    std::string nic_profile;
    bool nic_profile_verified = false;
    bool nic_unprofiled = false;
    // HR2: the open-time live configuration (class A / C values, class B wanted = running). Null = derive it from the
    // fields of this Env, the open options and the WireOptions (the tests). The production open fills it from the
    // client config. `slice_bytes`: NIC profile else 1 MiB (config > profile > built-in); `put_max_ms`: store deadlines
    // are clamped to it (deadline.put_max_ms).
    ClientDynPtr dyn_base;
    std::uint64_t slice_bytes = 1u << 20;
    unsigned put_max_ms = 2500;
    // Class C (crypto.workers): called on the thread that applies a new snapshot. Null = ignored.
    std::function<void(unsigned)> set_crypto_workers;
    // Q15 (review s10): open_wire_nodes with several nodes. A node whose first build fails is retried inside the open,
    // on its build backoff (its ticket source refilled first), until it connects or `open_settle` (env clock) has
    // passed since the first round; only then does the open return with it pending (built later by its keepalive
    // thread). The open always logs "N of M memory nodes connected", naming every pending node (ID, hostname,
    // address); nodes_connected() tells the caller. 0 = one round only (the tests); the production open uses 2 s.
    // R20: this holds when every node failed its first build too; the open fails only if none is up after the settle.
    // R14 (review s11), the real worst case of open(): the first round plus open_settle. The first round is serial and
    // NOT bounded by open_settle: per node, the admin ticket refill (<= 2 s per admin call; a failed call stops it) +
    // per endpoint the fabric default connect timeout (5 s) + HELLO and SEG_TABLE (<= rpc_timeout, 5 s, each). The
    // settle is a bound: no retry starts after it ends, and a retry's admin I/O, connects, HELLO and SEG_TABLE are capped
    // to what is left of it, so it ends within open_settle plus one poll step (<= 100 ms; sim: one drive step). A retry
    // waits for its build backoff and its ticket source's own backoff (R19), so it never fails on a cached admin error.
    Nanos open_settle{0};
  };
  static Expected<std::unique_ptr<Client>> open_loopback(const Env& env, const ClientCoreOptions& copts = {},
                                                         const RuntimeOptions& ropts = {});

  // s12 (tpu-sync cross-check C1): the production runtime for `n_nodes` memory nodes. Every node keeps the concurrency the
  // whole client had before (2 jobs at a time: lane_cap), and there are workers for every node to run that many at once,
  // so the jobs aimed at a node that stops answering hold only that node's 2 workers, and jobs aimed at other nodes do
  // not wait behind them. Not covered: work a job does on a second node (sync replica legs, a read that fails over, a
  // previous-view read) counts against its first-choice lane; the breaker bounds that. One node: the old runtime exactly
  // (2 workers, no lanes). Bundle mode sizes it for at least 16 nodes (room for joins; idle workers cost nothing, they
  // sleep), at most 64 workers. More jobs can now run on one node's core at once (failover, previous-view reads): size
  // landing.subpool_bytes for the batches in flight (runbook §4.3); a full pool degrades to misses, never errors.
  static RuntimeOptions runtime_for_nodes(std::size_t n_nodes) {
    RuntimeOptions ro;
    if (n_nodes <= 1) return ro;
    ro.lane_cap = 2;
    ro.workers = static_cast<unsigned>(std::min<std::size_t>(64, 2 * n_nodes));
    return ro;
  }

  // Wire v0 to a memory node: `env.fab` is the raw fabric (verbs_cm or SimFabric); env.port is
  // ignored (a WirePort is created, connects the three endpoints and does HELLO before this
  // returns). `adopt` objects (fabric, executor...) are kept alive until the Client dies.
  static Expected<std::unique_ptr<Client>> open_wire(const Env& env, WireOptions wopts,
                                                     std::shared_ptr<void> adopt = {},
                                                     const ClientCoreOptions& copts = {},
                                                     const RuntimeOptions& ropts = {});
  // Several memory nodes (A2.2, static placement): every op of a scope goes to owner(scope_id)
  // (client/src/placement.h). Each node has its own raw fabric `fab`, WireOptions (node id, rail,
  // tickets, keepalive, reconnect) and ClientCore; env.fab / env.port are ignored. A node that is
  // unreachable at open is connected later by its keepalive thread (its scopes fail fast until
  // then); the open fails only if no node is reachable. With one node this is open_wire.
  struct NodeSpec {
    fabric::Fabric* fab = nullptr;
    WireOptions wopts;
    std::uint32_t weight = 1;  // > 0
    std::string zone;          // empty = none (own zone); all specs or none
    // Plan 2C: wopts.node == 0 (production) means the node's ID is learned from HELLO_ACK; until then the node
    // owns no scopes. A nonzero wopts.node is a fixed expected ID (sim, tests): in placement from the start.
    // `label` is the stable `node` label of the node's client series (default: the expected ID, else the first
    // rail "host:port"). `hostname` yields the memory node's hostname (from the admin ticket response) for
    // miracache_client_node_info; null or empty = unknown.
    std::string label;
    std::function<std::string()> hostname;
    // The node ID in the memory node's admin ticket answer (0 = none yet); compared with HELLO_ACK (review r9 S10).
    std::function<std::uint32_t()> reported_node_id;
    // F3 (K08): called (build or keepalive thread, no core lock) when the node's ID was learned from HELLO_ACK and
    // differs from the previous one; the production static path re-binds its QP readback series under it.
    // Must not call back into the Client.
    std::function<void(std::uint32_t)> on_id_learned;
    // F5: called (same thread, no core lock) when HELLO_ACK brought a hostname (TLV 0x0004) that the admin/bundle source did
    // not already give; the production static path re-binds its QP readback series under it. Must not call back.
    std::function<void(const std::string&)> on_host_learned;
    // Bundle mode: whatever this node needs to stay alive (its fabric, ticket source, jitter source). The slot keeps it
    // until the node is torn down, after its wire and core are gone, so a flapping node leaks nothing.
    std::shared_ptr<void> owner;
    // HR2: called on the node's keepalive thread when the live configuration changed (and once at its first tick), with
    // the new snapshot: the node's ticket source takes `ticket_batch` here. No I/O, no calls back into the Client.
    std::function<void(const ClientDyn&)> on_dyn;
  };
  static Expected<std::unique_ptr<Client>> open_wire_nodes(const Env& env, std::vector<NodeSpec> nodes,
                                                           std::shared_ptr<void> adopt = {},
                                                           const ClientCoreOptions& copts = {},
                                                           const RuntimeOptions& ropts = {});
  // ---- Bundle mode (membership plan decision 9, MB6a) ----
  // Node table capacity: slots are allocated at open; a node of the bundle takes a slot, a node absent from the
  // bundle's `nodes` is retired and its slot is reused only after no job can touch it and its wire is closed.
  static constexpr std::size_t kMaxNodes = 64;
  struct BundleOpen {
    MembershipSnapPtr initial;  // the first verified bundle (required)
    // Builds the fabric / WireOptions of one bundle node (wopts.node is set from the bundle after the call: the ID is
    // the bundle's, checked against HELLO_ACK). Called on the open thread, then on the membership thread.
    std::function<Expected<NodeSpec>(const control::NodeView&)> make_spec;
    // Posts the client's envelope to the admin address of an ADDED node before its first connect (stage before swap).
    // Default (null): watcher->push_envelope. Both null: no push.
    std::function<Status(const std::string& admin)> push;
    // MB6b: a reply showed that the client lags (a higher bundle_gen_lo, or StaleEpoch with a higher epoch). Called on the
    // data path, so lock-free and no I/O; arguments are the reply's bundle_gen_lo and the replying node's admin address.
    // Default (null): watcher->on_reply_generation. Both null: ignored.
    std::function<void(std::uint32_t bundle_gen_lo, const std::string& admin)> wake;
    // Optional. Stopped first on shutdown, so its callback can never reach a dead Client.
    std::shared_ptr<BundleWatcher> watcher;
    unsigned keepalive_ms = 1000;      // like WireOptions::keepalive_ms; 0 = no threads (tests tick by hand)
    unsigned connect_wait_ms = 2000;   // membership.connect_wait_ms: how long a join waits for the new nodes to be Up
    // MB7 (decision 9). The previous view is a read/store candidate for this long, measured locally from the moment the
    // client first sees that previous_epoch (placement.previous_view_ms); hints are a bounded LRU (placement.hint_entries).
    unsigned previous_view_ms = 3600000;
    std::size_t hint_entries = 65536;
    // Client reports: send_report(body) POSTs `body` to [control] controller's /v1/reports (OK = accepted). Null = no
    // reports. One report every report_ms (0 = no thread; tests call send_report_now).
    std::function<Status(const std::string& body)> send_report;
    // Optional (review w5 U2-27): cuts a send_report in flight short; called once on shutdown, before the reporter
    // thread is joined.
    std::function<void()> cancel_reports;
    unsigned report_ms = 2000;
    // HR3b planned rebuild (class B keys: landing.subpool_bytes, fabric.mtu, fabric.protocol, fabric.fetch_qps). A node
    // whose connection runs values the live configuration no longer wants waits 0..rebuild_jitter_ms, then builds a new
    // connection beside the old one (make_spec is called again: a fresh fabric and ticket source), one node at a time per
    // client, swaps it in and closes the old one once its jobs are done, or runs the §3.7 drain at rebuild_drain_ms
    // (reload.drain_deadline_ms). Env clock. Connection cap rule: see Impl (limits.max_conns_per_principal must leave
    // one extra session per rebuilding client).
    unsigned rebuild_jitter_ms = 5000;
    unsigned rebuild_drain_ms = 30000;
  };
  static Expected<std::unique_ptr<Client>> open_bundle(const Env& env, BundleOpen bo, std::shared_ptr<void> adopt = {},
                                                       const ClientCoreOptions& copts = {},
                                                       const RuntimeOptions& ropts = {});
  // Hands a verified bundle to the membership thread (non-blocking, thread-safe; the newest wins; a generation that
  // is not newer than the applied one is ignored). Wire this to BundleWatcherOptions::on_bundle.
  void apply_membership(MembershipSnapPtr snap);
  std::uint64_t membership_generation() const;  // generation of the published placement (0 = none)
  std::uint32_t membership_epoch() const;
  // ---- HR2: live configuration (internal only: no C ABI, no Python; a lab-mode client restarts) ----
  // The bundle's `config.cluster.client` table reaches the client through apply_membership (the bundle watcher's
  // callback): the newest generation's table is parsed over the open-time values and swapped in as one atomic snapshot
  // (validate -> stage -> swap). A rejected table keeps the old snapshot and is counted. R is not part of it: its one
  // home is the placement snapshot (P32).
  Status apply_config(ClientDynPtr next);  // a validated snapshot (tests; the bundle path uses the table)
  Status apply_config_toml(std::string_view config_toml, std::uint64_t generation);  // same path as a bundle's table
  ClientDynPtr dyn() const;                // the snapshot in force
  std::uint64_t config_applied() const;
  std::uint64_t config_rejected() const;
  std::uint64_t config_unknown_keys() const;  // ignored keys (config.* of a newer controller)
  std::string config_last_error() const;
  int keepalive_period_ms(std::size_t slot) const;  // test hook: the slot's keepalive period now
  // Test hooks: slot of a node ID (-1 = none), slots in use, jobs inside a slot's node, whether it is retiring.
  long slot_of(std::uint32_t node_id) const;
  std::size_t slots_in_use() const;
  int slot_jobs_inside(std::size_t slot) const;
  bool slot_retiring(std::size_t slot) const;
  // J08 test hooks (a client with no keepalive thread, keepalive_ms = 0): an endpoint build failure of slot `slot`'s node
  // on `rail`, owned by the pending planned rebuild (`rebuild`) or by another attempt (a rail rejoin, a reconnect),
  // counted and logged as the real paths do; and the settle a withdrawn planned rebuild runs (returns the entries closed).
  void test_endpoint_failure(std::size_t slot, unsigned rail, const Error& e, bool rebuild);
  std::size_t test_settle_rebuild_failures(std::size_t slot);
  // MB7 test hooks: the body of the next client report (does not advance the AEAD delta); one report now (the same path as
  // the reporter thread); reports accepted / failed so far; hints currently held.
  std::string report_body() const;
  Status send_report_now();
  std::uint64_t reports_sent() const;
  std::uint64_t reports_failed() const;
  std::size_t hint_count() const;
  // Test hooks (review w5 U2-25, U2-14): a hint for scope `group` of `sk` tagged with `prev_epoch` (a stale tag reaches
  // void_epoch on the next read); `n` AEAD failures counted for bundle node `node_id` (as its core would).
  void set_hint_for_test(const ScopeKeys& sk, std::uint32_t group, std::uint32_t prev_epoch);
  void add_aead_failures_for_test(std::uint32_t node_id, std::uint64_t n);
  // The wire port of node `i` of an open_wire client (tests: invalidate/stats/healthy); null if
  // loopback, out of range, or the node has not connected yet.
  WirePort* wire_port(std::size_t i = 0);
  // HR3a test hooks (hot-reload plan decision 6). A node's {WirePort, ClientCore, core lock, jobs inside} is one pair,
  // reached through one pointer; every job pins it once and uses only its copy. slot_pair_for_test: the slot's active
  // pair (null = none) as an opaque handle (use_count() = the node + everyone pinning it + the caller's copies).
  // detach_pair_for_test takes it out of the node (the node then has none: new jobs fail fast, as before its first
  // build) and returns it; reattach_pair_for_test puts it back into a node that has none. A detached pair must be
  // reattached before the Client is destroyed (only the node closes a pair). No keepalive tick may run meanwhile.
  std::shared_ptr<const void> slot_pair_for_test(std::size_t slot) const;
  std::shared_ptr<const void> detach_pair_for_test(std::size_t slot);
  bool reattach_pair_for_test(std::size_t slot, std::shared_ptr<const void> pair);
  // HR3b test hooks: the class B values a slot's active pair runs (false = no pair); planned rebuilds swapped in / failed
  // so far; the slot that holds the client's one rebuild token (-1 = none: no node has two connections now).
  struct SlotClassB {
    std::size_t pool_bytes = 0;
    std::uint32_t mtu = 0;
    std::uint8_t wire_proto = 0;
    std::uint32_t fetch_qps = 0;
  };
  bool slot_class_b(std::size_t slot, SlotClassB& out) const;
  std::uint64_t rebuilds_done() const;
  std::uint64_t rebuild_failures() const;
  long rebuilding_slot() const;
  std::size_t node_count() const;
  // Q15: nodes in use whose session is Up now. Right after open() it says how many connected at open (the others are
  // pending: their keepalive threads keep building them). Thread-safe.
  std::size_t nodes_connected() const;
  // Prometheus text of this client's metrics (A3.5 M2). Thread-safe; callable while jobs run.
  std::string metrics_text() const;
  // Review s9 K03: why one engine block of `plaintext_bytes` cannot be stored, or "" if every connected node that reports
  // its limit (HELLO_ACK TLV 0x0003) places it. The text names the node (ID, hostname, address), the stored size (payload
  // + 64 B header + 16 B tag per segment), the node's limit and the store.run_bytes to set there. Nodes not connected yet
  // and older nodes (no limit sent) are not checked: `checked` (if set) receives how many nodes were. Thread-safe.
  std::string block_size_problem(std::uint64_t plaintext_bytes, std::size_t* checked = nullptr) const;
  // HR4: the client owns `owned` (destroyed with it) and appends `metrics` to metrics_text(). Call once after open, before use.
  void attach_service(std::shared_ptr<void> owned, std::function<void(std::string&)> metrics);

  ~Client();
  Client(const Client&) = delete;
  Client& operator=(const Client&) = delete;

  // Keys are copied; the BufRef memory stays caller-owned and must stay valid until the
  // Completion (fetch: engine buffers to fill, store: plaintext). `timeout` is relative.
  Ticket lookup(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys, Nanos timeout);
  Ticket fetch(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys, std::span<const BufRef> bufs,
               Nanos timeout);
  Ticket store(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys, std::span<const BufRef> bufs,
               Nanos timeout);
  std::size_t poll(std::span<Completion> out) noexcept { return rt_->poll(out); }
  int eventfd() const noexcept { return rt_->eventfd(); }
  void cancel(Ticket t) noexcept { rt_->cancel(t); }
  void shutdown() noexcept;
  // Keepalive test hooks: one tick now (skipped if a worker holds the core lock); ticks run.
  void keepalive_tick();
  std::uint64_t keepalive_ticks() const;
  std::uint64_t fast_failed_jobs() const;  // jobs completed by the session-not-Up fast path (R01)
  // Fail-slow test hooks: jobs the per-node circuit breaker completed at once (reads Miss, stores Skipped); the breaker
  // state of node / slot `slot` (0 closed, 1 open, 2 half-open; -1 = out of range).
  std::uint64_t breaker_fast_jobs() const;
  int breaker_state(std::size_t slot) const;
  std::uint64_t watchdog_trips() const;    // watchdog force-fails that abandoned an op (Q05/N04)
  // Test hook: replica legs queued or running on the replicator, and the plaintext pool bytes they hold.
  std::size_t replicator_pending() const;
  std::size_t replica_buffer_in_use() const;
  // Test hooks: requests copied at submit and not yet picked up / discarded; worker pump-loop turns.
  std::size_t pending_requests() const;
  std::uint64_t pump_iterations() const;
  // Test only (review w4 V11): the owner set (IDs, best first) the client picks for `scope` from a bundle body, built the
  // way publish_bundle + run_bundle build it (view_from_bundle, R clamped to 1..3, owner_set over that view).
  static std::vector<std::uint32_t> OwnerSetForTest(const control::BodyView& body, std::span<const std::uint8_t, 32> scope);

 private:
  struct Req;
  class Impl;
  Client();
  Ticket submit(int kind, const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys,
                std::span<const BufRef> bufs, Nanos timeout);

  std::shared_ptr<void> keep_;  // wire world (fabric, executor...), destroyed last
  std::unique_ptr<Impl> impl_;
  std::unique_ptr<Runtime> rt_;
};

}  // namespace miracache
