// SPDX-License-Identifier: Apache-2.0
#include "src/client.h"

#include <array>
#include <atomic>
#include <bit>
#include <limits>
#include <algorithm>
#include <chrono>
#include <cerrno>
#include <cstring>
#include <cstdio>
#include <deque>
#include <list>
#include <memory>
#include <optional>

#include <map>
#include <set>

#include "control/view.h"
#include "crypto/block_codec.h"
#include "placement/placement.h"
#include "proto/storage_layout.h"
#include "runtime/keepalive.h"
#include "runtime/pause.h"
#include "runtime/task_thread.h"
#include "src/placement.h"
#include "util/check.h"
#include "util/log.h"

namespace miracache {

// A request waiting for (or being run by) a worker. Keys are copied; buffers are the caller's.
struct Client::Req {
  int kind = 0;  // 0 lookup, 1 fetch, 2 store
  ScopeKeys sk;
  std::uint32_t group = 0;
  std::vector<std::vector<std::byte>> raw, parent;
  std::vector<std::uint64_t> pos;
  std::vector<BufRef> bufs;
  Nanos deadline{0};  // absolute (Clock time), fixed at submit()
};

namespace {
// now + d without overflow (a huge timeout means "effectively never").
Nanos sat_add(Nanos now, Nanos d) {
  if (d > Nanos::max() - now) return Nanos::max();
  return now + d;
}

// MB7 (decision 9): per-scope hints "use the previous view's OWNER SET". A bounded LRU keyed by scope ID; each entry is
// tagged with the previous_epoch it was learned under and is void under any other (checked on every get). Thread-safe;
// `n_` lets the data path skip the mutex while no hint exists.
class HintCache {
 public:
  using Key = std::string;  // the 32 bytes of the scope ID
  void configure(std::size_t cap) {  // HR2: class A, may change while the data path runs
    cap_.store(cap, std::memory_order_relaxed);
    std::lock_guard lk(mu_);
    while (m_.size() > cap) {
      m_.erase(lru_.back().first);
      lru_.pop_back();
    }
    n_.store(m_.size(), std::memory_order_release);
  }
  bool enabled() const { return cap_ > 0; }
  bool any() const { return n_.load(std::memory_order_acquire) != 0; }
  std::size_t size() const { return n_.load(std::memory_order_acquire); }
  // true = a hint under `prev_epoch` (touched); an entry of another epoch is erased and `voided` is set.
  bool get(const Key& k, std::uint32_t prev_epoch, bool& voided) {
    voided = false;
    if (!any()) return false;
    std::lock_guard lk(mu_);
    auto it = m_.find(k);
    if (it == m_.end()) return false;
    if (it->second->second != prev_epoch) {
      lru_.erase(it->second);
      m_.erase(it);
      n_.store(m_.size(), std::memory_order_release);
      voided = true;
      return false;
    }
    lru_.splice(lru_.begin(), lru_, it->second);
    return true;
  }
  void set(const Key& k, std::uint32_t prev_epoch) {
    if (cap_ == 0) return;
    std::lock_guard lk(mu_);
    auto it = m_.find(k);
    if (it != m_.end()) {
      it->second->second = prev_epoch;
      lru_.splice(lru_.begin(), lru_, it->second);
      return;
    }
    lru_.emplace_front(k, prev_epoch);
    m_[k] = lru_.begin();
    while (m_.size() > cap_) {
      m_.erase(lru_.back().first);
      lru_.pop_back();
    }
    n_.store(m_.size(), std::memory_order_release);
  }
  bool drop(const Key& k) {
    if (!any()) return false;
    std::lock_guard lk(mu_);
    auto it = m_.find(k);
    if (it == m_.end()) return false;
    lru_.erase(it->second);
    m_.erase(it);
    n_.store(m_.size(), std::memory_order_release);
    return true;
  }
  std::size_t clear() {
    std::lock_guard lk(mu_);
    const std::size_t n = m_.size();
    m_.clear();
    lru_.clear();
    n_.store(0, std::memory_order_release);
    return n;
  }

 private:
  std::atomic<std::size_t> cap_{0};
  std::mutex mu_;
  std::list<std::pair<Key, std::uint32_t>> lru_;
  std::map<Key, std::list<std::pair<Key, std::uint32_t>>::iterator> m_;
  std::atomic<std::size_t> n_{0};
};

std::string json_escape(const std::string& s) {
  std::string o;
  for (char c : s) {
    if (c == '"' || c == '\\') {
      o += '\\';
      o += c;
    } else if (static_cast<unsigned char>(c) < 0x20) {
      o += ' ';
    } else {
      o += c;
    }
  }
  return o;
}
}  // namespace

class Client::Impl final : public Backend {
 public:
  // HR3a (hot-reload plan decision 6): a node's connection. Its own WirePort (rails, tickets, HELLO, keepalive, the
  // reconnect state machine), its own ClientCore (landing pool, endpoints, leases), its own core lock and its own count
  // of the jobs inside, so a node that is down or reconnecting never blocks the others.
  //
  // Lifetime rules. A node reaches its pair through ONE pointer (Node::pair; null = never built, or torn down).
  //   - Whoever works on a node (a job, a sync store leg, an async replica leg, the keepalive tick and the reconnect it
  //     runs, the reporter, a test hook) loads that pointer ONCE and uses only its own copy until it is done: it pins the
  //     pair. No use of a wire, a core, a core_mu or a jobs_inside goes through the node.
  //   - jobs_inside counts the jobs past the session check on THIS pair; the pair's reconnect waits for its own count.
  //   - A pair is made by the node's build (build_pair: the open, or the keepalive thread of a node not reached yet) and
  //     installed with install_pair; it is taken out of the node by its teardown (bundle mode) or ~Node, which close it
  //     (endpoints back to the fabric, then the core, then the wire: Q06). A teardown runs only when no placement
  //     snapshot names the slot (pin_refs) and the pair has no job inside, so no pin outlives the close.
  //   - A reconnect reuses the pair. HR3b's planned rebuild (bundle mode, class B keys) builds a second pair beside the
  //     active one (see rebuild_step), swaps it in and retires the old one: `retired` is set right after the swap, and a
  //     job that pinned the old pair and counts itself in after that lets it go and pins the new one (enter_pair; it has
  //     not touched the old one). The old pair's endpoints go back to the fabric once its own jobs_inside is 0 and no WR
  //     is outstanding on them; its core and wire are freed with the last pin.
  // HR3b: the class B values a pair was built with (landing.subpool_bytes, fabric.mtu, fabric.protocol, fabric.fetch_qps).
  struct ClassB {
    std::size_t pool_bytes = 0;  // the ClientCore's landing pool
    std::uint32_t mtu = 0;       // HELLO mtu
    std::uint8_t wire_proto = 0; // HELLO proto (1 RoCE, 2 iWARP)
    FabricProtocol protocol = FabricProtocol::Auto;
    // HR7: the fetch QPs per paired rail its WirePort runs (WireOptions::fetch_qps, >= 1): the open-time A3.3 value, or
    // the bundle's fabric.fetch_qps once a planned rebuild applied it.
    std::uint32_t fetch_qps = 1;
    bool operator==(const ClassB&) const = default;
  };
  struct Pair {
    std::shared_ptr<void> owner;  // HR3b: a rebuilt pair's own NodeSpec::owner (fabric, ticket source, jitter); freed last
    fabric::Fabric* fab = nullptr;  // the raw fabric under its wire (a rebuild never shares one: one CQ per pair)
    std::unique_ptr<WirePort> wire;  // wire clients only; outlives core
    std::unique_ptr<ClientCore> core;
    std::mutex core_mu;
    std::atomic<int> jobs_inside{0};
    std::atomic<bool> retired{false};  // HR3b: swapped out by a planned rebuild (seq_cst against jobs_inside)
    ClassB open;  // the node's open-time values when it was built (the base the bundle's class B values replace)
    ClassB b;     // what it runs
    std::function<void(const ClientDyn&)> on_dyn;  // HR3b: a rebuilt pair's ticket source (class A ticket_batch)
    Impl* sim = nullptr;  // sim only, a retired pair: ~Pair frees the core and wire in a sim turn (they touch the sim)
    // Q06: the endpoints go back to the fabric before the core unmaps its landing pool; then the core, then the wire.
    void close(Nanos release_until) {
      if (wire && core) wire->release_endpoints(release_until);
      core.reset();
      wire.reset();
      owner.reset();
    }
    ~Pair();  // after SimTurn (below)
  };
  using PairPtr = std::shared_ptr<Pair>;

  // ---- fail-slow: the per-node circuit breaker (spec §3.3, §4.5, §10 "Slow memory node"; keys: ClientDyn breaker_*) ----
  // The not-Up fast path (R01) covers a node that is down; the breaker covers a node whose session is Up but slow.
  //   Closed     every op runs. Each op that ran on the node's wire and was not cancelled is recorded: its latency (core
  //              submit to release, env clock) in a log2 histogram (two bins per octave) and whether it missed its
  //              deadline (it ended past the deadline it started before), in kBrkSubs time buckets of
  //              window_ms / kBrkSubs. The window is judged after each deadline miss and otherwise once per bucket
  //              length (which also refreshes this node's p99, the reference the other nodes' median is taken from).
  //   Open       tripped by the outlier rule (ClientDyn; reason "slow"): reads of the node miss at once (fetch buffers
  //              zeroed), its stores are Skipped (never failed), replica reads and legs go to the other nodes (usable()
  //              is false). Until open_until.
  //   Half-open  open_until passed: at most `probes` ops run on the node at a time (the others still miss / skip). A
  //              probe that misses its deadline or is slower than the outlier bound re-opens it (reason "probe_failed";
  //              the open time doubles up to open_max_ms); `probes` good ones close it (its window starts empty).
  // Transitions run under Brk::mu (one short lock per recorded op, per node; taken under the job's core_mu and sim turn,
  // and it takes nothing itself), are logged with the node's identity, and are exported as
  // miracache_client_breaker_state{node} and miracache_client_breaker_trips_total{node,reason}. The client report (MB7)
  // names the nodes whose breaker is not closed; nothing is removed automatically (the operator drains or reweights).
  // The slot owns its breaker: activate_slot resets it, and a job pins the slot it runs on, so no op of an old occupant
  // records into a new one.
  static constexpr int kBrkBins = 50, kBrkSubs = 4;
  enum BrkState { kBrkClosed = 0, kBrkOpen = 1, kBrkHalfOpen = 2 };
  enum class Admit { Pass, Probe, Reject };
  struct Brk {
    struct Sub {
      std::int64_t idx = -1;  // the time bucket it holds (env clock / bucket length); -1 = empty
      std::uint32_t ops = 0, misses = 0;
      std::array<std::uint32_t, kBrkBins> h{};
    };
    std::mutex mu;
    std::array<Sub, kBrkSubs> sub;           // guarded by mu
    std::atomic<int> state{kBrkClosed};       // written under mu; read lock-free by admit / usable
    std::atomic<Nanos::rep> open_until{0};    // env clock; written under mu
    std::atomic<int> probes_in{0};            // half-open probes running; written under mu
    unsigned probe_ok = 0, reopen = 0;        // guarded by mu: good probes this half-open spell; failed half-opens in a row
    Nanos next_eval{0};                       // guarded by mu
    std::atomic<std::int64_t> p99_us{-1};     // the window's p99 when it held min_ops ops (else -1): the others' reference
    std::atomic<Nanos::rep> p99_at{0};        // env clock when p99_us was computed
    telemetry::Gauge* g_state = nullptr;      // bound while the slot is not in use (open, bind_slot_metrics)
    telemetry::Counter* trips[2] = {};        // reason "slow", "probe_failed"
    std::string series_id;                    // H08: the node_id label g_state and trips carry (guarded by mu)
    std::string series_host;                  // F5: and the hostname label (guarded by mu)
  };

  // One memory node: identity, options, its slot state and threads, and its active Pair. The pair is null until the
  // first HELLO succeeded (a node unreachable at open is built later by its keepalive thread, like a reconnect).
  struct Node {
    // Identity (plan 2C). `label` is the stable `node` label of this node's client series (known before the
    // node answers: the expected ID in tests, else the first rail "host:port"); `addr` is the first rail.
    // `id` is the node ID, 0 until learned from HELLO_ACK (or excluded as a duplicate); it is published to
    // placement only through Impl::publish_places.
    std::string label, addr, zone, hostname;
    std::uint32_t weight = 1;
    std::atomic<std::uint32_t> id{0};
    // The ID placement uses (review r9 S05): set only when the node joins placement (build, or the flip to Up of a
    // reconnect), never by learn_id, so one node's publish cannot expose another node's half-done reconnect.
    std::atomic<std::uint32_t> published_id{0};
    // r9b T07: the reconnect attempt (WirePort::connect_attempts) whose HELLO_ACK brought `id`. Guarded by place_mu.
    std::uint64_t hello_attempt = ~std::uint64_t{0};
    std::uint32_t conflict_logged = 0;           // the duplicate ID last logged for this node (build/keepalive thread only)
    std::function<std::string()> hostname_fn;    // admin ticket response hostname (empty fn = unknown)
    telemetry::Counter* conflict_ctr = nullptr;
    std::atomic<telemetry::Gauge*> info_gauge{nullptr};  // miracache_client_node_info of the published ID (value 1)
    std::atomic<telemetry::Gauge*> info_next{nullptr};   // the series of the ID learned last, not published yet (value 0)
    std::function<std::uint32_t()> reported_id_fn;       // the ID in the admin ticket answer (0 = none), compared with HELLO_ACK
    std::function<void(std::uint32_t)> id_learned_fn;    // F3 (K08): the learned ID reaches the node's QP readback series
    // F5: the hostname HELLO_ACK carried (TLV 0x0004; empty = unknown), the fallback when no admin/bundle hostname exists.
    mutable std::mutex wire_host_mu;
    std::string wire_host;
    std::atomic<bool> host_conflict_logged{false};  // WARN once when the admin/bundle hostname differs from HELLO_ACK's
    std::function<void(const std::string&)> host_learned_fn;  // the QP readback series re-bind under the real hostname
    telemetry::Counter* mismatch_ctr = nullptr;
    std::shared_ptr<void> spec_owner;   // bundle mode: the fabric, ticket source and jitter of this node (NodeSpec::owner); freed at teardown, after wire and core
    fabric::Fabric* raw_fab = nullptr;  // wire clients: the raw fabric of this node
    WireOptions wopts;
    ClientCoreOptions copts;
    // HR3a: the active pair (null = not built / torn down). Stored once it is usable (install_pair, release), taken out
    // by the teardown; everybody else only loads it (acquire) and keeps the copy (see Pair).
    std::atomic<PairPtr> pair;
    PairPtr pin_pair() const { return pair.load(std::memory_order_acquire); }
    // MB6a slots (bundle mode). `active`: the slot holds a node (static mode: always true). Set last when a slot is
    // filled, cleared first when it is torn down. `tick_mu` makes a teardown wait for a tick in flight (bundle mode
    // only). `pin` is a token every published placement snapshot that names this slot holds a copy of (and so every
    // job that read such a snapshot): the slot is torn down and reused only when the slot holds the last copy.
    // `stage_push` posts the client's envelope to the node's admin address; the node's thread runs it before the
    // first connect, retrying with the build backoff (stage before swap).
    std::atomic<bool> active{true};
    std::atomic<int> slot_state{0};  // 0 free, 1 in use, 2 retiring (written by the membership thread only)
    std::mutex tick_mu;
    std::mutex report_mu;  // MB7: the reporter thread pins the pair under it; teardown takes the pair out under it first
    std::atomic<int> pin_refs{0};  // placement snapshots that name this slot (PinTok); teardown needs 0 (acquire)
    std::string bundle_admin, bundle_rail;  // what the slot was built from: a change under the same node_id rebuilds it (Y04)
    std::size_t slot = 0;                   // bundle mode: this node's index in `nodes`
    // Bundle mode (review w3b Z02): this slot's core once it is built, a candidate to back the node's landing pool series
    // (several slots share the `node` label after a rebuild). Guarded by slots_mu; cleared before the core is freed.
    ClientCore* gauge_core = nullptr;
    std::function<Status()> stage_push;
    // HR2: called by the node's own tick when the live configuration changed (its ticket source takes ticket_batch).
    // `seen_dyn` is the snapshot that tick adopted last (touched by the node's tick only).
    std::function<void(const ClientDyn&)> on_dyn;
    ClientDynPtr seen_dyn;
    // MB6b: a reply showed this node behind the client (epoch or bundle generation). The pusher thread posts the
    // client's envelope to the node's admin; once per success per generation, exponential backoff 1 s .. 30 s on failure.
    std::atomic<bool> push_wanted{false};
    std::atomic<std::uint64_t> push_ok_gen{0};  // the generation this node was last pushed (or already had)
    std::atomic<unsigned> push_fails{0};
    std::atomic<Nanos::rep> push_next{0};  // RealClock ns; reset with the slot (membership thread)
    std::uint64_t aead_start = 0;   // U2-14: aead_fail_total{node=label} when this incarnation was filled (slots_mu)
    std::uint64_t incarnation = 0;         // bumped each time the slot is filled (guarded by slots_mu): a push that
                                           // outlived its occupant does not touch the next one
    bool thread_started = false;  // membership thread only
    KeepaliveThread ka;
    std::atomic<std::uint64_t> ka_ticks{0};
    // Q04: first-build retries back off like reconnects. Touched by the thread that builds (open, then
    // this node's keepalive thread / a test tick), never concurrently.
    unsigned build_streak = 0;
    Nanos build_next{0};
    // Q02/N03: this node's build in flight (its WirePort is not in `wire` yet), so stop_keepalive can
    // abort it. Every node's keepalive thread builds on its own: one pointer per node. Guarded by build_mu.
    WirePort* building = nullptr;
    // Q06: the endpoints go back to the fabric (aborted, drained, QPs destroyed) before the core unmaps its
    // landing pool. A span may still be quarantined (an abandoned READ/WRITE): without this its MR stayed
    // registered under a QP that was only safe because it sat in ERR. An endpoint that never drains is
    // left aborted (ERR: no new DMA) after the bounded wait. The keepalive thread is stopped first.
    Nanos release_until{0};  // r7 R04: shared real-time deadline set by ~Impl (0 = this node's own 500 ms)
    // HR3b planned rebuild (the node's keepalive tick, under tick_mu in bundle mode; teardown after the tick barrier).
    control::NodeView view;          // what the slot was set up from: a rebuild makes a fresh NodeSpec from it
    std::atomic<PairPtr> old_pair;   // the pair a planned rebuild swapped out, until its endpoints are released
    Nanos rebuild_due{0};            // env clock: a dirty node rebuilds from then on (0 = not scheduled)
    Nanos retire_until{0};           // env clock: the old pair's drain deadline (BundleOpen::rebuild_drain_ms)
    bool retire_drained = false;     // the §3.7 drain ran on the old pair
    unsigned rebuild_streak = 0;     // failed rebuilds in a row (backoff)
    // H06: the (rail, cause) entries a failed planned rebuild opened in epfail_open (under epfail_mu). Settled when the
    // pending rebuild is withdrawn (the change reverted), so the next failure of that cause is logged again.
    std::set<std::pair<unsigned, std::string>> rebuild_epfail;
    // F09: when this node took the client's rebuild token (env clock), the next "token still held" warning after the
    // drain, and the miracache_client_rebuild_token_held_seconds series of the holder (keepalive thread only).
    Nanos token_at{0};
    Nanos token_relog{0};
    telemetry::Gauge* g_token = nullptr;
    Brk brk;                         // fail-slow circuit breaker (see Brk)
    ~Node() {
      ka.stop();
      for (std::atomic<PairPtr>* slot : {&pair, &old_pair})
        if (PairPtr p = slot->exchange(nullptr, std::memory_order_acq_rel)) {
          p->sim = nullptr;  // every thread is gone and Impl::sim_mu with it
          p->close(release_until);
        }
    }
  };
  // The jobs inside a node's pairs (the active one and one a planned rebuild is retiring; 0 = none).
  static int jobs_inside(const Node& n) {
    int c = 0;
    if (const PairPtr p = n.pin_pair()) c += p->jobs_inside.load(std::memory_order_acquire);
    if (const PairPtr p = n.old_pair.load(std::memory_order_acquire)) c += p->jobs_inside.load(std::memory_order_acquire);
    return c;
  }

  // r7 R04: abort every node's endpoints first, then wait once: the flushes of all nodes run in parallel
  // and the whole release is bounded by one 500 ms real-time deadline, not 500 ms per node in turn.
  ~Impl() {
    stop_membership();  // the watcher callback and the membership thread first: they touch the slots
    stop_replicator();  // before anything a replica leg touches goes away
    for (auto& n : nodes) n->ka.stop();
    for (auto& n : nodes)
      for (const PairPtr& p : {n->pin_pair(), n->old_pair.load(std::memory_order_acquire)})
        if (p && p->wire && p->core) p->wire->abort_endpoints();
    const Nanos until = RealClock().now() + std::chrono::milliseconds(500);
    for (auto& n : nodes) n->release_until = until;
  }

  Env env;
  telemetry::Registry reg;  // shared by all nodes of a multi-node client (before the nodes: they hold pointers into it)
  // ---- HR2: live configuration (class A / C values; class B are recorded as pending) ----
  // Jobs load the snapshot once at submit/run, keepalive threads once per tick, WirePort at each reconnect decision.
  // R is NOT here: its one home is the placement snapshot (P32).
  DynSnap dyn_snap;
  ClientDynPtr dyn_base;     // the open-time values: a key absent from the bundle takes them
  std::mutex dyn_mu;         // writers (apply_config) only
  // HR4: services the Client owns (the credential watch) and their metric writers; svc_mu guards both.
  std::mutex svc_mu;
  std::vector<std::shared_ptr<void>> svc;
  std::vector<std::function<void(std::string&)>> svc_metrics;
  std::function<void(unsigned)> set_crypto_workers;
  telemetry::Counter *cfg_applied = nullptr, *cfg_rejected = nullptr, *cfg_unknown = nullptr;
  telemetry::Gauge *cfg_gen = nullptr, *cfg_pending = nullptr;
  std::string cfg_last_error;  // guarded by dyn_mu
  std::atomic<std::uint64_t> cfg_unknown_n{0}, cfg_rejected_n{0}, cfg_applied_n{0};
  ClientDynPtr dyn() const { return dyn_snap.load(); }
  Nanos watchdog_grace() const { return std::chrono::milliseconds(dyn()->watchdog_grace_ms); }
  // A node's keepalive thread adopts a new snapshot at its next tick: its period and the node's ticket batch.
  void adopt_dyn(Node& n);
  void init_dyn(const ClientDyn& base);
  Status apply_dyn(ClientDynPtr next, const std::vector<std::string>& unknown);
  Status apply_bundle_config(const control::BodyView& body);
  void bind_dyn(Node& n, std::function<void(const ClientDyn&)> on_dyn) {
    if (bundle_mode) n.wopts.dyn = &dyn_snap;  // lab/static clients keep their per-node WireOptions (they restart to change)
    n.on_dyn = std::move(on_dyn);
    n.copts.slice_bytes = [this] { return dyn_snap.load()->slice_bytes; };
  }
  std::vector<std::unique_ptr<Node>> nodes;
  // Placement input: only the nodes whose ID is known (a node not reached yet gets no scopes). Readers are the
  // workers (every op), the writers are the build / keepalive threads (HELLO), so the snapshot is immutable and
  // swapped by writers that hold place_mu. r9b T13: readers take no mutex, only an atomic shared_ptr load (libstdc++
  // spins on a bit of the pointer, so each op writes one shared cache line; measure on hardware if it matters)
  // (an op never waits behind a HELLO's bookkeeping).
  // One count on Node::pin_refs while a placement snapshot that names the node is alive (release on drop, acquire at
  // teardown: everything a job did to the node happens before the teardown frees it).
  struct PinTok {
    std::atomic<int>& c;
    explicit PinTok(std::atomic<int>& cc) : c(cc) { c.fetch_add(1, std::memory_order_relaxed); }
    ~PinTok() { c.fetch_sub(1, std::memory_order_release); }
    PinTok(const PinTok&) = delete;
    PinTok& operator=(const PinTok&) = delete;
  };
  struct PlaceSnap {
    std::vector<PlaceNode> places;
    std::vector<std::size_t> idx;  // places[k] belongs to nodes[idx[k]]
    // MB6a (bundle mode): the placement the bundle defines, read once per job. `view.nodes == places`.
    bool bundle = false;
    View view;                     // epoch + the active nodes (id = node_id as decimal text)
    unsigned replicas = 1;         // R from the bundle
    std::uint64_t generation = 0;
    // One copy of Node::pin per place: while a job (or a queued replica leg) holds this snapshot, the nodes it names
    // cannot be torn down or reused.
    std::vector<std::shared_ptr<PinTok>> pins;
    // MB7 (decision 9): the previous view, FULL (every node it lists, current or not), tagged with its epoch; and every
    // node the bundle's `nodes` names that has a slot (draining and readonly ones included) -> slot, pinned by `pins`.
    // The previous owner set is computed over `prev_view`, then filtered through `slot_of_id` (Q08, P31: a node that
    // left `nodes` is no candidate).
    std::uint32_t previous_epoch = 0;
    View prev_view;
    Nanos prev_until{0};  // env clock: the previous view is a candidate until then (placement.previous_view_ms)
    std::map<std::uint32_t, std::size_t> slot_of_id;
    // Review w4 V12: the bundle's whole CURRENT view, set only when `view` had to leave a node out (it has no slot);
    // empty otherwise (then it equals `view`). Like `prev_view` it is what the memory nodes place by, and it maps to
    // slots through `slot_of_id`: a root put the client sends to a node outside a scope's owner set over `full` is
    // skipped there (not_owner), and the client counts those it can foresee (count_gap_skips).
    View full;
  };
  bool bundle_mode = false;  // slots come and go; placement is published from the bundle (publish_bundle), never from IDs
  std::mutex place_mu;  // serialises the writers: the ID bookkeeping, publish_places and the identity gauges
  std::atomic<std::shared_ptr<const PlaceSnap>> snap{std::make_shared<const PlaceSnap>()};
  std::shared_ptr<const PlaceSnap> snapshot() const { return snap.load(std::memory_order_acquire); }
  void publish_places() {  // caller holds place_mu
    if (bundle_mode) return;  // the bundle decides who is in placement (publish_bundle)
    auto s = std::make_shared<PlaceSnap>();
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      // Only the published ID counts (review r9 S05): a learned ID joins at publish_node (the first build, or the
      // flip to Up of a reconnect); a fixed expected ID (sim, tests) is in from the start.
      const std::uint32_t id = nodes[i]->published_id.load(std::memory_order_acquire);
      if (id == 0) continue;
      s->places.push_back(PlaceNode{std::to_string(id), nodes[i]->weight, nodes[i]->zone});
      s->idx.push_back(i);
    }
    snap.store(std::shared_ptr<const PlaceSnap>(std::move(s)), std::memory_order_release);
  }
  // The node's ID as logs and the node_id label show it ("unknown" until learned).
  static std::string id_text(const Node& n) {
    const std::uint32_t id = n.id.load(std::memory_order_acquire);
    return id ? std::to_string(id) : std::string("unknown");
  }
  // Client log line (logfmt, util/log.h): client_host always, plus the target node's node_id and addr.
  void nlog(log::Level lvl, const Node& n, std::string_view msg, std::initializer_list<log::Field> extra = {}) {
    std::vector<log::Field> f;
    f.reserve(4 + extra.size());
    f.emplace_back("client_host", log::hostname());
    f.emplace_back("node_id", id_text(n));
    f.emplace_back("hostname", host_or_unknown(n));  // F5: "unknown" until the hostname is known
    f.emplace_back("addr", n.addr);
    for (const auto& e : extra) f.push_back(e);
    log::write(lvl, "client", msg, std::span<const log::Field>(f));
  }

  // r9b T07: whether node `m`, which holds an ID another node now claims, keeps it (caller holds place_mu). It keeps
  // it while its session is Up, while its first build is still in flight (not ready yet), and while it is Connecting
  // with a HELLO_ACK for this very ID in the current attempt (r9c U01; it is about to flip to Up). A node that is Down, or
  // Connecting without a HELLO_ACK yet, does not (review r9 S11).
  static bool keeps_id(const Node& m, std::uint32_t id) {
    const PairPtr p = m.pin_pair();
    if (!p || !p->wire) return true;
    const auto s = p->wire->session();
    if (s == WirePort::Session::Up) return true;
    return s == WirePort::Session::Connecting && m.id.load(std::memory_order_acquire) == id &&
           m.hello_attempt == p->wire->connect_attempts();
  }
  // r9b T08: identity gauges change only under place_mu, so a concurrent publish_node and an eviction cannot leave a
  // series at 1 for an ID that is out of placement.
  static void drop_published_gauge(Node& m) {  // caller holds place_mu
    if (auto* g = m.info_gauge.exchange(nullptr)) g->set(0);
  }

  // F5: HELLO_ACK of node `n` carried its hostname (TLV 0x0004; build or keepalive thread, no core lock). The hostname of
  // the admin ticket answer or the bundle keeps priority (node_hostname); this one is the fallback of static/lab mode.
  // A change rebuilds what carries the hostname: the node_info series, the breaker series and (on_host_learned) the QP
  // readback series; the rail series follow at the end of the HELLO (WirePort::publish_rails). The series that said
  // "unknown" are hidden.
  void learn_hostname(Node& n, const std::string& host) {
    std::string prev;
    {
      std::lock_guard lk(n.wire_host_mu);
      prev = n.wire_host;
      n.wire_host = host;
    }
    const std::string admin = n.hostname.empty() ? (n.hostname_fn ? n.hostname_fn() : std::string()) : n.hostname;
    if (!admin.empty() && admin != host && !n.host_conflict_logged.exchange(true)) {
      nlog(log::Level::Warn, n, "memory node hostname in HELLO_ACK differs from the admin/bundle one; keeping the latter",
           {{"hello_hostname", host}, {"admin_hostname", admin}});
    }
    if (!admin.empty() || prev == host) return;  // nothing changed in what the series carry
    const std::uint32_t id = node_id_of(n);
    if (id != 0 || n.wopts.node != 0) {
      telemetry::Gauge* g = &reg.gauge("miracache_client_node_info",
                                       "Memory node identity as the client knows it; the value is 1 once the node is in placement.",
                                       {{"node", n.label}, {"node_id", std::to_string(id)}, {"hostname", host},
                                        {"addr", n.addr}, {"zone", n.zone}});
      std::vector<telemetry::Gauge*> stale;
      {
        std::lock_guard lk(place_mu);
        if (n.id.load(std::memory_order_acquire) == id || n.wopts.node != 0) {
          // L04: the next-to-publish series made for the earlier (e.g. "unknown") hostname is read BEFORE it is replaced
          auto* const nx = n.info_next.load();
          if (auto* cur = n.info_gauge.load(); cur && cur != g) {  // published: the new series takes over its value
            g->set(cur->value());
            cur->set(0);
            n.info_gauge.store(g);
            stale.push_back(cur);
          } else if (!cur) {
            n.info_next.store(g);
          }
          if (nx && nx != g) {
            n.info_next.store(g);
            stale.push_back(nx);
          }
        }
      }
      for (auto* s : stale) reg.hide(s);
    }
    if (!bundle_mode) bind_brk_series(n, /*zero_old=*/true);
    if (n.host_learned_fn) n.host_learned_fn(host);
  }
  // HELLO_ACK of node `n` carried `id` (learn mode; called on the build or keepalive thread, no core lock).
  // Records the ID; the node joins placement under it only at publish_node (end of build, or the flip to Up of a
  // reconnect). A zero ID, or an ID another node holds (learned or still published, r9b T06), is refused: the node is
  // excluded (its ID stays 0, so it owns no scopes), the event is logged once per ID and counted. An ID held by a node
  // that does not keep it (keeps_id) does not count (review r9 S11): that node loses it and the claimant wins.
  // place_mu covers the ID bookkeeping and the identity gauges; logs are written after it is released (S06).
  Status learn_id(Node& n, std::uint32_t id) {
    if (id == 0 && nodes.size() == 1) return {};  // one node needs no placement; a legacy server may say 0
    std::uint32_t had = 0;
    std::string other_addr;
    bool refused = false;
    std::vector<Node*> evicted;
    {
      std::lock_guard lk(place_mu);
      had = n.id.load(std::memory_order_acquire);  // r9b T07: read under the lock
      bool other = false;
      if (id != 0) {
        std::vector<Node*> stale;
        for (const auto& m : nodes) {
          if (m.get() == &n) continue;
          if (m->id.load(std::memory_order_acquire) != id && m->published_id.load(std::memory_order_acquire) != id) continue;
          if (keeps_id(*m, id)) {
            other = true;
            other_addr = m->addr;
          } else {
            stale.push_back(m.get());
          }
        }
        if (!other)
          for (Node* m : stale) {
            if (m->id.load(std::memory_order_acquire) == id) {
              m->id.store(0, std::memory_order_release);
              m->info_next.store(nullptr);
            }
            if (m->published_id.load(std::memory_order_acquire) == id) {
              m->published_id.store(0, std::memory_order_release);
              drop_published_gauge(*m);
            }
            evicted.push_back(m);
          }
      }
      refused = id == 0 || other;
      bool changed = !evicted.empty();
      if (refused) {
        if (had != 0 || n.published_id.load(std::memory_order_acquire) != 0) {  // it had a valid ID: out of placement
          n.id.store(0, std::memory_order_release);
          n.published_id.store(0, std::memory_order_release);
          drop_published_gauge(n);  // S09: the series of the lost ID goes quiet
          changed = true;
        }
        n.info_next.store(nullptr);
      } else {
        if (had != id) n.id.store(id, std::memory_order_release);
        const PairPtr p = n.pin_pair();  // the pair whose reconnect brought this HELLO_ACK (none: the first build)
        n.hello_attempt = p && p->wire ? p->wire->connect_attempts() : ~std::uint64_t{0};
      }
      if (changed) publish_places();
    }
    for (Node* m : evicted)
      nlog(log::Level::Warn, *m, "node id taken over by " + n.addr + " while this node is down; excluded from placement",
           {{"dup_id", std::to_string(id)}, {"other_addr", n.addr}});
    if (refused) {
      if (n.conflict_logged != id) {
        n.conflict_logged = id;
        if (n.conflict_ctr) n.conflict_ctr->inc();
        if (id == 0)
          nlog(log::Level::Error, n, "memory node reported node id 0; excluded from placement");
        else
          nlog(log::Level::Error, n,
               "duplicate node id " + std::to_string(id) + ": " + n.addr + " and " + other_addr + " report the same ID; " +
                   n.addr + " is excluded from placement",
               {{"dup_id", std::to_string(id)}, {"other_addr", other_addr}});
      }
      if (id == 0) return Error{ErrorCode::InvalidArgument, "client: memory node reported node id 0"};
      // The context is a static string by contract; the details are in the log line above.
      return Error{ErrorCode::InvalidArgument, "client: duplicate node id from two memory nodes (see log: addr and other_addr)"};
    }
    n.conflict_logged = 0;
    // S10: the admin ticket answer names the node too; a HELLO_ACK that disagrees is a warning (not a refusal: the
    // HELLO_ACK is the authority, the ticket answer may come from a proxy or an older cache).
    if (n.reported_id_fn) {
      const std::uint32_t rep = n.reported_id_fn();
      if (rep != 0 && rep != id) {
        if (n.mismatch_ctr) n.mismatch_ctr->inc();
        nlog(log::Level::Warn, n, "node id in HELLO_ACK differs from the admin ticket answer",
             {{"hello_id", std::to_string(id)}, {"ticket_id", std::to_string(rep)}});
      }
    }
    if (had != id) {
      // The series of the new ID starts at 0 and turns 1 where the ID is published (S09; the previous one goes quiet then).
      // It is created without place_mu (the registry has its own lock) and handed over under it, only if the node
      // still holds this ID (T08).
      telemetry::Gauge* g = &reg.gauge("miracache_client_node_info",
                                       "Memory node identity as the client knows it; the value is 1 once the node is in placement.",
                                       {{"node", n.label},
                                        {"node_id", std::to_string(id)},
                                        {"hostname", host_or_unknown(n)},
                                        {"addr", n.addr},
                                        {"zone", n.zone}});
      {
        std::lock_guard lk(place_mu);
        if (n.id.load(std::memory_order_acquire) == id) n.info_next.store(g);
      }
      if (!bundle_mode) bind_brk_series(n, /*zero_old=*/true);  // F08: the breaker series follow the learned ID
      if (n.id_learned_fn) n.id_learned_fn(id);  // F3 (K08): the QP readback series re-bind under the real ID
      nlog(log::Level::Info, n, had ? "node id changed (store wiped or replaced)" : "node id learned",
           {{"prev_id", std::to_string(had)}});
    }
    return {};
  }
  // The node joins placement under the ID it learned (end of build, or the flip to Up of a reconnect: the session is
  // Up and the new endpoints are installed), and its identity series turns 1 (T08: only for a non-zero ID, and the
  // gauges change under place_mu).
  void publish_node(Node& n) {
    if (bundle_mode) return;  // the ID is the bundle's and never changes; the identity series follows publish_bundle
    std::lock_guard lk(place_mu);
    const std::uint32_t id = n.id.load(std::memory_order_acquire);
    n.published_id.store(id, std::memory_order_release);
    publish_places();
    if (id == 0) {  // its ID was taken over meanwhile: nothing of it is in placement
      drop_published_gauge(n);
      n.info_next.store(nullptr);
      return;
    }
    if (telemetry::Gauge* next = n.info_next.exchange(nullptr))
      if (auto* old = n.info_gauge.exchange(next); old && old != next) old->set(0);
    if (auto* g = n.info_gauge.load()) g->set(1);
  }
  // ---- review s9 K03 / s9b L08: the engine block size check ----
  // Why one engine block of `plaintext_bytes` cannot be stored on node `n` (connected through pair `p`, whose HELLO_ACK
  // gave `lim` = the node's largest stored block), or "" if it fits. The caller copied the node's fields consistently
  // (under slots_mu in bundle mode, or on the node's own thread).
  static std::string block_refusal(std::uint64_t plaintext_bytes, unsigned segment_log2, std::uint64_t lim,
                                   std::uint32_t node_id, const std::string& host, const std::string& addr) {
    auto lay = layout(plaintext_bytes, segment_log2);
    const std::uint64_t stored = lay ? lay->stored_len : std::numeric_limits<std::uint64_t>::max();
    if (stored <= lim) return {};
    constexpr std::uint64_t kMaxRun = std::uint64_t{1} << proto::kRunLog2;  // store.run_bytes upper bound (256 MiB)
    std::string out = "block of " + std::to_string(plaintext_bytes) + " B is stored as " + std::to_string(stored) +
                      " B (payload + 64 B header + 16 B tag per " + std::to_string(std::uint64_t{1} << segment_log2) +
                      " B segment), larger than memory node " + std::to_string(node_id) + " (hostname " + host_text(host) +
                      ", " + addr + ") places: " + std::to_string(lim) + " B (its store.run_bytes); every put would be refused. ";
    if (stored > kMaxRun) {
      out += "No run_bytes can hold it (max 268435456): use smaller engine blocks (vLLM block_size / SGLang --page-size).";
    } else {
      const std::uint64_t want = std::min(kMaxRun, std::max(std::bit_ceil(4 * stored), std::bit_ceil(stored)));
      out += "Set store.run_bytes = " + std::to_string(want) + " on that node (a power of two >= 4 x the stored block; "
             "segment_bytes >= 2 x run_bytes) and restart it, or use smaller engine blocks.";
    }
    return out;
  }
  // L08: the block size the engine adapter checked at start-up (0 = no check yet). A node that connects later (a pending
  // first build, a reconnect to a restarted node with another run_bytes, a bundle node added later) is checked against
  // it when its session comes up (recheck_block), and a refusal is logged as an ERROR naming the node.
  std::atomic<std::uint64_t> checked_block{0};
  void recheck_block(const Node& n, const Pair& p) {
    std::atomic_thread_fence(std::memory_order_seq_cst);  // R17: pairs with the fence after the check's store
    const std::uint64_t bytes = checked_block.load(std::memory_order_seq_cst);
    if (bytes == 0 || !p.wire) return;
    const std::uint64_t lim = p.wire->max_stored_block();
    if (lim == 0) return;  // an older node: it refuses oversized puts itself
    const std::string why = block_refusal(bytes, n.copts.segment_log2, lim, p.wire->node_id(), node_hostname(n), n.addr);
    if (why.empty()) return;
    nlog(log::Level::Error, n, "memory node that connected after the start-up block size check cannot store an engine block",
         {{"block_bytes", std::to_string(bytes)}, {"max_stored_block", std::to_string(lim)}, {"why", why}});
  }
  void watchdog_fired_log(const Node& nd, const Pair& p, int kind, long long late_ms, int sess, std::size_t out,
                          std::size_t abandoned) {
    nlog(log::Level::Warn, nd, "watchdog: job still inside after its deadline; force-failed",
         {{"job_kind", std::to_string(kind)}, {"late_ms", std::to_string(late_ms)}, {"session", std::to_string(sess)},
          {"jobs_inside", std::to_string(p.jobs_inside.load())}, {"outstanding_ops", std::to_string(out)},
          {"abandoned", std::to_string(abandoned)}, {"endpoint_dead", abandoned > 0 ? "true" : "false"}});
  }
  void watchdog_still_log(const Node& nd, int kind, long long late_ms, int sess, std::size_t out) {
    nlog(log::Level::Warn, nd, "watchdog: job still not released after force-fail (a decrypt task has not ended)",
         {{"job_kind", std::to_string(kind)}, {"late_ms", std::to_string(late_ms)}, {"session", std::to_string(sess)},
          {"outstanding_ops", std::to_string(out)}});
  }
  std::mutex req_mu;
  std::map<std::uint64_t, Req> reqs;
  std::uint64_t next_req = 1;
  std::atomic<std::uint64_t> iterations{0};  // pump-loop turns, for tests
  std::atomic<std::uint64_t> fast_failed{0};  // jobs completed by the not-Up fast path (tests)
  std::atomic<std::uint64_t> wd_trips{0};     // Q05
  // Guards every Node::building together with `stopping` (Q02/N03).
  std::mutex build_mu;
  // Sim only (env.drive set): the simulated network, clock and server are single-threaded, so a thread holds
  // sim_mu for each turn of client work (always taken AFTER the node's core_mu, never while waiting for one) and
  // gives it up inside the drive hook when another thread waits. See SimTurn.
  std::mutex sim_mu;
  std::atomic<int> sim_waiters{0};
  struct SimTurn;
  static SimTurn*& tls_turn() {
    static thread_local SimTurn* t = nullptr;
    return t;
  }
  // RAII over sim_mu for one thread; a no-op when there is no sim. release()/acquire() let the owner step out
  // of the lock around waits on a core_mu. Nested turns on one thread collapse into the outer one.
  struct SimTurn {
    Impl* im = nullptr;
    bool held = false;
    SimTurn* prev = nullptr;
    explicit SimTurn(Impl* i) {
      if (!i->env.drive || tls_turn()) return;
      im = i;
      prev = tls_turn();
      tls_turn() = this;
      acquire();
    }
    ~SimTurn() {
      if (!im) return;
      release();
      tls_turn() = prev;
    }
    SimTurn(const SimTurn&) = delete;
    SimTurn& operator=(const SimTurn&) = delete;
    void acquire() {
      if (!im || held) return;
      im->sim_waiters.fetch_add(1);
      im->sim_mu.lock();
      im->sim_waiters.fetch_sub(1);
      held = true;
    }
    void release() {
      if (!im || !held) return;
      held = false;
      im->sim_mu.unlock();
    }
  };
  // The drive hook handed to the WirePorts and the loops: another thread waiting for the sim gets a turn first.
  std::function<void()> make_sim_drive(std::function<void()> d) {
    return [this, d = std::move(d)] {
      if (SimTurn* t = tls_turn(); t && t->im == this && sim_waiters.load() > 0) {
        t->release();
        pause_for(std::chrono::microseconds(50));
        t->acquire();
      }
      d();
    };
  }
  bool stopping = false;

  // ---- keepalive (spec 3; S01 + S02) ----
  // One background thread per wire node. Every keepalive_ms it try-locks core_mu (a busy node is
  // polling anyway, so a contended tick is skipped), sends PING on control and pumps the core,
  // which polls every endpoint: unsolicited SEG_TABLE/GOAWAY get consumed and receive slots
  // reposted even when no job runs. Joined before teardown.
  //
  // Reconnect (wire_port.h) runs on this same thread: while the session is not Up the tick takes
  // the core lock (jobs fail fast, so workers release it quickly), attempts when the backoff is
  // due, and asks for its next wake-up at the attempt time instead of the keepalive period.
  //
  // R01 (real time and sim alike): the attempt itself runs WITHOUT core_mu. Workers check the
  // session before taking the lock and complete the job at once when it is not Up, so none waits
  // behind a connect; `jobs_inside` counts the workers past that check so the attempt can wait for
  // stragglers before it owns the port. Only the flip to Up (install) takes core_mu, briefly.

  // Creates the WirePort and ClientCore of `n` (HELLO included). Error = the node is unreachable.
  //
  // `background` (Q01/Q02): true for a build on the keepalive thread: short connect on all three endpoints
  // and short HELLO/SEG_TABLE caps, and stop_keepalive can abort it. The build inside Client::open is
  // not background: the fabric default connect timeout and the full rpc_timeout apply.
  Status build(Node& n, bool background, Nanos deadline = Nanos::max()) {  // R14: deadline bounds this attempt (settle)
    bool attempted = false;
    fabric::clear_local_failure();  // Q6: a local device resource failure of THIS build is told from a connect failure
    auto p = build_pair(n, *n.raw_fab, n.wopts, background, attempted, deadline);
    if (!p) {
      if (attempted) {
        forget_id(n);  // a node that did not come up owns no scopes, whatever its HELLO said
        // Q6: an abort (shutdown) is no failure, and an identity fault (InvalidArgument: a duplicate or mismatched node
        // ID) has its own line and counter (node_id_conflicts / node_id_mismatch); a local resource failure always counts.
        // B-1 (review s11): an attempt the settle's `deadline` cut short is no verdict on the node (a healthy slow node
        // looks the same), so it is not counted or logged as a failure; the keepalive retries it with its full caps.
        const ErrorCode c = p.error().code;
        const bool cut = deadline != Nanos::max() && env.clock->now() >= deadline;
        if (fabric::last_local_failure().call || (!cut && c != ErrorCode::Aborted && c != ErrorCode::InvalidArgument))
          note_build_fail(n, p.error());
      }
      return p.error();
    }
    install_pair(n, std::move(*p));
    note_endpoint_ok(fail_key(n), node_id_of(n), node_hostname(n), n.addr);
    return {};
  }

  // ================= Q6: endpoint build failures of a memory node =================
  // A build that fails is counted per attempt in miracache_client_endpoint_build_failures_total{node_id, hostname, addr,
  // rail, cause} and logged ONCE per (node, rail, cause) until the node connects again (then one recovery line). cause:
  //   local_resource  the LOCAL RDMA device would not create a CQ, completion channel, PD, MR or QP (ENOMEM / EINVAL /
  //                   a fabric budget): e.g. soft-iWARP at its CQ limit on the 4th node. Nothing is wrong with the node.
  //   hello           the node accepted the connect but HELLO / SEG_TABLE failed.
  //   connect         anything else: the node, its admin tickets or the link.
  // The retry behaviour is unchanged (build backoff; a bundle node whose set-up fails stays pending with its backoff).
  static constexpr const char* kLocalHint =
      "local RDMA device resource limit (CQ/QP); reduce nodes/rails/fetch_qps or use a device with more resources";
  std::mutex epfail_mu;
  // fail_key -> failed (rail, cause) -> its owners (J08: kEpfailRebuild | kEpfailOther; the entry closes when the node
  // connects, or, for a withdrawn rebuild, only once no other attempt still owns it).
  static constexpr unsigned kEpfailRebuild = 1, kEpfailOther = 2;
  std::map<std::string, std::map<std::pair<unsigned, std::string>, unsigned>> epfail_open;
  // The node a failure belongs to: its expected ID (bundle mode: the bundle's; a pending node has no slot yet), else
  // its first rail address (learn mode: the ID is known only after HELLO_ACK).
  static std::string fail_key(std::uint32_t expected_id, const std::string& addr) {
    return expected_id != 0 ? "id " + std::to_string(expected_id) : "addr " + addr;
  }
  static std::string fail_key(const Node& n) { return fail_key(n.wopts.node, n.addr); }
  static std::uint32_t node_id_of(const Node& n) {
    return n.wopts.node != 0 ? n.wopts.node : n.id.load(std::memory_order_acquire);
  }
  static std::string node_hostname(const Node& n) {
    if (!n.hostname.empty()) return n.hostname;
    if (n.hostname_fn) {
      std::string h = n.hostname_fn();
      if (!h.empty()) return h;
    }
    std::lock_guard lk(n.wire_host_mu);  // F5: what HELLO_ACK said (static/lab mode), else empty = unknown
    return n.wire_host;
  }
  // The hostname label of a series: "unknown" until known, never "" (F5).
  static std::string host_or_unknown(const Node& n) { return host_text(node_hostname(n)); }
  static std::string host_text(const std::string& h) { return h.empty() ? std::string("unknown") : h; }
  static std::string errno_text(int e) {
    const char* s = nullptr;
    switch (e) {
      case 0: return "none";
      case ENOMEM: s = "ENOMEM (cannot allocate memory)"; break;
      case EAGAIN: s = "EAGAIN (resource temporarily unavailable)"; break;
      case EINVAL: s = "EINVAL (invalid argument)"; break;
      case ENOSPC: s = "ENOSPC (no space left on device)"; break;
      case EMFILE: s = "EMFILE (too many open files)"; break;
      case ENFILE: s = "ENFILE (too many open files in system)"; break;
      case EPERM: s = "EPERM (operation not permitted)"; break;
      case EACCES: s = "EACCES (permission denied)"; break;
      case ENODEV: s = "ENODEV (no such device)"; break;
      case EOPNOTSUPP: s = "EOPNOTSUPP (operation not supported)"; break;
      default: break;
    }
    return s ? std::string(s) : "errno " + std::to_string(e);
  }
  // A failed node build (keepalive or open thread): the rail is the one whose device failed (local), else the first.
  void note_build_fail(const Node& n, const Error& e, std::set<std::pair<unsigned, std::string>>* opened = nullptr) {
    unsigned rail = n.wopts.rails.empty() ? 0u : n.wopts.rails[0].index;
    std::string device = n.wopts.rails.empty() ? std::string() : n.wopts.rails[0].device;
    const fabric::LocalFailure& lf = fabric::last_local_failure();
    if (lf.call && lf.rail < 0)
      for (const auto& ro : n.wopts.rails)
        if (ro.device == lf.device) {
          rail = ro.index;
          device = ro.device;
          break;
        }
    note_endpoint_failure(fail_key(n), node_id_of(n), node_hostname(n), n.addr, rail, device, e, opened);
  }
  // Counts one failed attempt and logs it if it is the first of its (node, rail, cause) since the node last connected.
  // Reads and clears fabric::last_local_failure (same thread as the failing call). Returns whether it was local.
  bool note_endpoint_failure(const std::string& key, std::uint32_t node_id, const std::string& hostname_in, const std::string& addr,
                             unsigned rail, std::string device, const Error& e,
                             std::set<std::pair<unsigned, std::string>>* opened = nullptr) {
    const fabric::LocalFailure lf = fabric::last_local_failure();
    fabric::clear_local_failure();
    const std::string_view ctx = e.context ? e.context : "";
    const char* cause = lf.call                                                                     ? "local_resource"
                        : ctx.find("HELLO") != std::string_view::npos || ctx.find("SEG_TABLE") != std::string_view::npos ? "hello"
                                                                                                    : "connect";
    if (lf.rail >= 0) rail = static_cast<unsigned>(lf.rail);
    if (lf.call && !lf.device.empty()) device = lf.device;
    const std::string id = node_id ? std::to_string(node_id) : std::string("unknown");
    const std::string hostname = host_text(hostname_in);  // Q08: "unknown" until known, never ""
    reg.counter("miracache_client_endpoint_build_failures_total",
                "Failed endpoint builds of a memory node, per attempt, by rail and cause (local_resource: the local RDMA "
                "device refused a CQ/QP/MR; connect; hello).",
                {{"node_id", id}, {"hostname", hostname}, {"addr", addr}, {"rail", std::to_string(rail)}, {"cause", cause}})
        .inc();
    bool first = false;
    {
      std::lock_guard lk(epfail_mu);
      auto [ent, ins] = epfail_open[key].try_emplace({rail, cause}, 0u);
      first = ins;
      // J08 (review s8 wave15): the entry records who failed with it (a planned rebuild, or any other attempt), so
      // settling a withdrawn rebuild never closes an entry a rail rejoin or a first build still fails with.
      ent->second |= opened ? kEpfailRebuild : kEpfailOther;
      if (opened) opened->emplace(rail, cause);  // H06: the caller settles its share if its attempt is withdrawn
    }
    if (!first) return lf.call != nullptr;
    static constexpr const char* kLocalMsg =
        "memory-node endpoint build failed: the LOCAL RDMA device refused a resource; node pending, retried with "
        "backoff (logged once until it connects; miracache_client_endpoint_build_failures_total counts attempts)";
    if (lf.call && lf.provider_call) {
      mlog(log::Level::Error, kLocalMsg,
           {{"node_id", id}, {"hostname", hostname}, {"addr", addr}, {"rail", std::to_string(rail)}, {"device", device},
            {"cause", cause}, {"call", lf.call}, {"errno", errno_text(lf.os_errno)},
            {"errno_note", lf.os_errno == 0 ? "the provider set no errno" : "set by the provider"}, {"hint", kLocalHint}});
    } else if (lf.call) {  // Q07: the fabric's own budget (cq_depth) refused: no provider call, so no errno to show
      mlog(log::Level::Error, kLocalMsg,
           {{"node_id", id}, {"hostname", hostname}, {"addr", addr}, {"rail", std::to_string(rail)}, {"device", device},
            {"cause", cause}, {"call", lf.call}, {"limit", "the fabric's own budget (no provider call)"}, {"hint", kLocalHint}});
    } else {
      mlog(log::Level::Warn,
           "memory-node endpoint build failed; node pending, retried with backoff (logged once until it connects; "
           "miracache_client_endpoint_build_failures_total counts attempts)",
           {{"node_id", id}, {"hostname", hostname}, {"addr", addr}, {"rail", std::to_string(rail)}, {"device", device},
            {"cause", cause}, {"error", std::string(ctx.empty() ? "?" : ctx)}});
    }
    return lf.call != nullptr;
  }
  // The node connected: a node whose builds failed logs one recovery line, and its next failure is logged again.
  // `rails` (review s10 Q03): only the entries of these node rails close (a session reconnect: the rails that came up; a
  // rail rejoin: that rail); a rail still down keeps its entry, so its repeated failures stay logged once. Null: every
  // entry (a build that installed the node). `via` names the path in the recovery line.
  void note_endpoint_ok(const std::string& key, std::uint32_t node_id, const std::string& hostname, const std::string& addr,
                        const std::vector<unsigned>* rails = nullptr, const char* via = "build") {
    std::string was;
    {
      std::lock_guard lk(epfail_mu);
      auto it = epfail_open.find(key);
      if (it == epfail_open.end()) return;
      for (auto e = it->second.begin(); e != it->second.end();) {
        if (rails && std::find(rails->begin(), rails->end(), e->first.first) == rails->end()) {
          ++e;
          continue;
        }
        // R09 (review s11): the live port's rails coming up say nothing about a pending planned rebuild's new endpoints
        // (H06: that rebuild owns its entries until it goes through or is withdrawn). Only the other attempts' share
        // closes here; an entry the rebuild still holds stays open, with no "recovered" line.
        if (rails && (e->second & kEpfailRebuild)) {
          e->second &= ~kEpfailOther;
          ++e;
          continue;
        }
        was += (was.empty() ? "" : ",") + e->first.second + "@rail" + std::to_string(e->first.first);
        e = it->second.erase(e);
      }
      if (it->second.empty()) epfail_open.erase(it);
    }
    if (was.empty()) return;
    mlog(log::Level::Info, "memory-node endpoint build recovered; node connected",
         {{"node_id", node_id ? std::to_string(node_id) : std::string("unknown")}, {"hostname", host_text(hostname)},
          {"addr", addr}, {"via", via}, {"failed_before", was}});
  }
  // Q03: the endpoints of node rails `rails` connected on a live port (WireOptions::on_rails_up: a session reconnect or a
  // rail rejoin); their failure entries close with one recovery line.
  void note_rails_up(const Node& n, const std::vector<unsigned>& rails, bool rejoin) {
    note_endpoint_ok(fail_key(n), node_id_of(n), node_hostname(n), n.addr, &rails, rejoin ? "rail rejoin" : "session reconnect");
  }
  // The endpoint-failure hooks of a node's ports (init_node, a rebuilt pair's hook_wopts, a static-mode node): a LOCAL
  // refusal in a rail rejoin or a session reconnect (G09, L13) is counted and logged once; a rail that comes up again
  // closes its entries (Q03).
  void hook_endpoint_diag(Node& n, WireOptions& w) {
    Node* np = &n;
    w.on_local_failure = [this, np](unsigned rail, const std::string& device, const Error& e) {
      note_endpoint_failure(fail_key(*np), node_id_of(*np), node_hostname(*np), np->addr, rail, device, e);
    };
    w.on_rails_up = [this, np](const std::vector<unsigned>& rails, bool rejoin) { note_rails_up(*np, rails, rejoin); };
  }
  // H06: the pending planned rebuild of `n` was withdrawn (its change reverted) after a failure: the entries that failure
  // opened are closed (one line), so the next failure of that cause is logged again and no later rebuild prints a
  // "recovered" line for it. Entries of other attempts (a rail rejoin, a first build) stay. Returns the count closed.
  std::size_t settle_rebuild_failures(Node& n) {
    std::string was;
    std::size_t closed = 0;
    {
      std::lock_guard lk(epfail_mu);
      if (n.rebuild_epfail.empty()) return 0;
      auto it = epfail_open.find(fail_key(n));
      if (it != epfail_open.end()) {
        for (const auto& e : n.rebuild_epfail) {
          auto ent = it->second.find(e);
          if (ent == it->second.end()) continue;
          ent->second &= ~kEpfailRebuild;
          if (ent->second != 0) continue;  // J08: another attempt still fails with it: it stays open (no second line)
          it->second.erase(ent);
          ++closed;
          was += (was.empty() ? "" : ",") + e.second + "@rail" + std::to_string(e.first);
        }
        if (it->second.empty()) epfail_open.erase(it);
      }
      n.rebuild_epfail.clear();
    }
    if (closed > 0) {
      const std::uint32_t id = node_id_of(n);
      mlog(log::Level::Info, "planned rebuild withdrawn (its change was reverted); its endpoint build failures are settled",
           {{"node_id", id ? std::to_string(id) : std::string("unknown")}, {"hostname", host_or_unknown(n)}, {"addr", n.addr},
            {"failed_before", was}});
    }
    return closed;
  }
  // HR3b: the node's open-time class B values (its options), and the values a build uses now: a class B value the bundle
  // changed (it differs from the open-time snapshot) replaces the open-time one.
  ClassB open_b(const Node& n) const {
    ClassB o;
    o.pool_bytes = n.copts.pool_bytes;
    o.mtu = n.wopts.mtu;
    o.wire_proto = n.wopts.wire_proto;
    o.protocol = dyn_base->protocol;
    o.fetch_qps = std::max(1u, n.wopts.fetch_qps);  // what the node's spec opens with (A3.3 operating point)
    return o;
  }
  ClassB wanted_b(const ClassB& open, const ClientDyn& d) const {
    const ClientDyn& base = *dyn_base;
    ClassB w = open;
    if (d.subpool_bytes != base.subpool_bytes) w.pool_bytes = static_cast<std::size_t>(d.subpool_bytes);
    if (d.mtu != base.mtu) w.mtu = d.mtu;
    if (d.protocol != base.protocol) {
      w.protocol = d.protocol;
      w.wire_proto = d.protocol == FabricProtocol::Iwarp ? 2 : 1;
    }
    // HR7: as the other keys, a fetch_qps the bundle changed replaces the open-time one (0 = no value: the profile's).
    if (d.fetch_qps != base.fetch_qps && d.fetch_qps != 0) w.fetch_qps = d.fetch_qps;
    return w;
  }
  // G01: the ticket source's I/O before a build of `n` with `wo` (no core lock): it learns how many fetch tickets per
  // rail the build draws (the fetch_qps build_pair will use), so a fetch_qps above ticket_batch still connects.
  // R14: `budget` (the open's settle) bounds the admin I/O when the source can take a budget (prepare_within).
  void prepare_tickets(const Node& n, const WireOptions& wo, Nanos budget = Nanos::max()) const {
    if (wo.ticket_need) wo.ticket_need(wanted_b(open_b(n), *dyn()).fetch_qps);
    if (budget != Nanos::max() && wo.prepare_within) wo.prepare_within(budget);
    else if (wo.prepare) wo.prepare();
  }
  // R19 (review s11): no build of `n` can draw its tickets before this env-clock time (its ticket source backs off
  // after a failed fetch and its cache cannot serve a build); 0 = now. The settle waits for it, so a retry is a real
  // attempt and miracache_client_endpoint_build_failures_total counts no build that failed on a cached admin error.
  static Nanos tickets_ready_at(const Node& n) { return n.wopts.tickets_ready_at ? n.wopts.tickets_ready_at() : Nanos{0}; }
  // HR3a: the build code of a node's pair (connect + HELLO + SEG_TABLE), shared by the first build and HR3b's planned
  // rebuild (`fab` / `wo`: the node's own, or a fresh NodeSpec's). It does not touch the node's active pointer. The pair
  // runs the class B values wanted now. `attempted`: a connect was tried (false: refused before any I/O: shutting down,
  // slot torn down or retiring).
  Expected<PairPtr> build_pair(Node& n, fabric::Fabric& fab, WireOptions wo, bool background, bool& attempted,
                               Nanos deadline = Nanos::max()) {
    attempted = false;
    const ClassB open = open_b(n);
    const ClassB b = wanted_b(open, *dyn());
    wo.mtu = b.mtu;
    wo.wire_proto = b.wire_proto;
    wo.fetch_qps = b.fetch_qps;  // HR7: per paired rail; a session is rails x (1 control + fetch_qps + 1 ingest) endpoints
    wo.rail_build_off_lock = true;  // run #233: keepalive_tick_body runs build_rails() after unlocking core_mu
    ClientCoreOptions co = n.copts;
    co.pool_bytes = b.pool_bytes;
    auto w = std::make_unique<WirePort>(fab, *env.clock, *env.salts, std::move(wo));
    {
      std::lock_guard lk(build_mu);
      if (stopping) return Error{ErrorCode::Aborted, "client: shutting down"};
      if (!n.active.load(std::memory_order_acquire)) return Error{ErrorCode::Aborted, "client: slot is being torn down"};  // Y15
      if (n.slot_state.load(std::memory_order_acquire) == 2)  // review w3b Z02: a retiring slot runs no first build
        return Error{ErrorCode::Aborted, "client: slot is retiring"};
      n.building = w.get();
    }
    attempted = true;
    w->set_background(background);
    w->set_op_deadline(deadline);  // R14: a settle retry ends its connects, HELLO and SEG_TABLE by the settle's end
    auto core = ClientCore::create(w->fabric(), *w, *env.clock, *env.executor, *env.salts, co);
    {
      std::lock_guard lk(build_mu);
      n.building = nullptr;
    }
    if (!core) {
      // Q04: neither ~ClientCore nor ~WirePort gives endpoints back to the fabric; the HELLO'd control
      // endpoint (and fetch/ingest if they got that far) would stay there with their QPs and pinned buffers.
      w->release_endpoints();
      return core.error();
    }
    w->set_background(false);
    w->set_op_deadline(Nanos::max());  // the jobs set their own
    auto p = std::make_shared<Pair>();
    p->wire = std::move(w);
    p->core = std::move(*core);
    p->fab = &fab;
    p->open = open;
    p->b = b;
    return p;
  }
  // Makes `p` the node's active pair (it was null: the first build).
  void install_pair(Node& n, PairPtr p) {
    if (bundle_mode) adopt_pool_series(n, p->core.get());  // before the store: a teardown sees the series owner it must hand over
    n.pair.store(p, std::memory_order_release);
    publish_node(n);  // a learned ID joins placement now
    recheck_block(n, *p);  // L08: a node that comes up after the engine's start-up check is checked now
  }
  // ---- bundle mode: the landing pool series of a node label (review w3b Z02, Z05) ----
  // After a rebuild (Y04) the old and the new slot of a node share the `node` label, so the series
  // miracache_client_landing_pool_bytes{node} can back only one of their pools. `pool_owner` names the slot whose core
  // the series reads; it is changed only under slots_mu, and a slot hands the series over (or zeroes it) at teardown
  // BEFORE its core is freed, so a scrape never reads a freed pool.
  std::map<std::string, std::size_t> pool_owner;  // node label -> slot; guarded by slots_mu
  // S02: one snapshot per node label, kept across the owners, so "free" always derives from the "used" read of the
  // same scrape, even while the series move from one core to another (see PoolSeriesSnap). Guarded by slots_mu.
  std::map<std::string, std::shared_ptr<PoolSeriesSnap>> pool_snap;
  void point_pool_series(const std::string& label, const ClientCore* c) {  // caller holds slots_mu
    auto& snap = pool_snap[label];
    if (!snap) snap = std::make_shared<PoolSeriesSnap>();
    for (const bool used : {true, false}) {  // "used" first: its child renders before "free" (PoolSeriesSnap)
      std::function<std::int64_t()> fn = [s = snap] { return s->free_bytes(); };
      if (used) fn = [s = snap] { return s->take(0, 0); };
      if (c && used)
        fn = [c, s = snap, total = static_cast<std::int64_t>(c->pool_bytes_total())] {
          return s->take(static_cast<std::int64_t>(c->pool_bytes_in_use()), total);
        };
      reg.callback_gauge("miracache_client_landing_pool_bytes", "Landing pool bytes, by state.",
                         {{"state", used ? "used" : "free"}, {"node", label}}, std::move(fn));
    }
  }
  // A slot that just built its core takes the series if the bundle names this slot for the node (it is the current
  // one), or if no slot has it. A retiring old slot whose build was already in flight never takes it from the new one.
  void adopt_pool_series(Node& n, ClientCore* core) {
    std::lock_guard lk(slots_mu);
    n.gauge_core = core;
    const auto m = slot_by_id.find(n.wopts.node);
    const auto o = pool_owner.find(n.label);
    if ((m != slot_by_id.end() && m->second == n.slot) || o == pool_owner.end()) {
      point_pool_series(n.label, core);
      pool_owner[n.label] = n.slot;
    }
  }
  // HR3b: a planned rebuild's new core takes this slot's place: it backs the series if this slot does (or would take them,
  // as in adopt_pool_series). Called before the swap, so the old core is never read once it can be freed.
  void swap_pool_series(Node& n, ClientCore* core) {
    std::lock_guard lk(slots_mu);
    n.gauge_core = core;
    const auto m = slot_by_id.find(n.wopts.node);
    const auto o = pool_owner.find(n.label);
    if ((o != pool_owner.end() && o->second == n.slot) || (m != slot_by_id.end() && m->second == n.slot) ||
        o == pool_owner.end()) {
      point_pool_series(n.label, core);
      pool_owner[n.label] = n.slot;
    }
  }
  // Teardown of slot `i`, before its core is freed: if it backs the series, they go to another built slot of the node
  // (the current one first), else to 0. A slot that does not back them leaves them alone (Z05: a new slot's series is
  // never zeroed by the old one).
  void release_pool_series(std::size_t i) {
    Node& n = *nodes[i];
    std::lock_guard lk(slots_mu);
    n.gauge_core = nullptr;
    const auto o = pool_owner.find(n.label);
    if (o == pool_owner.end() || o->second != i) return;
    std::size_t j = kNoSlot;
    if (auto m = slot_by_id.find(n.wopts.node); m != slot_by_id.end() && m->second != i && nodes[m->second]->gauge_core)
      j = m->second;
    for (std::size_t k = 0; k < nodes.size() && j == kNoSlot; ++k)
      if (k != i && nodes[k]->gauge_core && nodes[k]->label == n.label) j = k;
    point_pool_series(n.label, j != kNoSlot ? nodes[j]->gauge_core : nullptr);
    if (j != kNoSlot) o->second = j;
    else pool_owner.erase(o);
  }
  // Learn mode: drops the ID of a node whose first build failed (no scopes for a node not reached).
  void forget_id(Node& n) {
    if (n.wopts.node != 0) return;
    std::lock_guard lk(place_mu);  // r9b T08: the gauges too
    n.info_next.store(nullptr);
    if (n.id.load(std::memory_order_acquire) == 0 && n.published_id.load(std::memory_order_acquire) == 0) return;
    n.id.store(0, std::memory_order_release);
    n.published_id.store(0, std::memory_order_release);
    publish_places();
    drop_published_gauge(n);
  }

  // Q04: delay before the next first-build attempt, same shape as the reconnect backoff.
  void note_build_failure(Node& n, const Error& e) {
    ++n.build_streak;
    const auto dy = dyn();  // HR2: class A
    const std::uint64_t lo = std::max(1u, bundle_mode ? dy->reconnect_min_ms : n.wopts.reconnect_min_ms),
                        hi = std::max<std::uint64_t>(lo, bundle_mode ? dy->reconnect_max_ms : n.wopts.reconnect_max_ms);
    std::uint64_t d = e.code == ErrorCode::InvalidArgument ? hi  // nodes[].id mismatch cannot fix itself
                                                           : std::min<std::uint64_t>(hi, lo << std::min(n.build_streak - 1, 20u));
    if (n.wopts.random && d > 1) d = d / 2 + n.wopts.random->below(d / 2 + 1);
    n.build_next = env.clock->now() + std::chrono::milliseconds(d);
  }

  // The reconnect state machine (WirePort::reconnect) of the pair `p` the tick pinned: it waits for the jobs inside
  // THAT pair and flips THAT pair's session to Up.
  void reconnect_off_lock(Node& n, Pair& p) {
    WirePort::ReconnectHooks hk;
    // Sim (S15): the wait for the jobs inside is 200 x 1 ms of real time; the keepalive tick must not hold sim_mu
    // through it, or every worker that wants the simulated network starves. r9b T13: the turn is given away for the
    // whole 1 ms pause between two checks (`wait`), not only for a moment inside the check.
    hk.quiesced = [&p] { return p.jobs_inside.load() == 0; };
    hk.wait = [this] {
      SimTurn* t = tls_turn();
      if (t && t->im != this) t = nullptr;
      if (t) t->release();
      pause_for(std::chrono::milliseconds(1));
      if (t) t->acquire();
    };
    hk.install = [this, &n, &p](const std::function<void()>& flip) {
      SimTurn* t = tls_turn();  // core_mu is taken before the sim lock, never while holding it
      if (t) t->release();
      std::lock_guard lk(p.core_mu);
      if (t) t->acquire();
      flip();
      p.core->pump();  // binds the new endpoints / refreshes the segment table
      publish_node(n);  // a new id learned by this reconnect takes effect now that the session is Up
      recheck_block(n, p);  // L08: a restarted node may run another store.run_bytes
    };
    p.wire->reconnect(hk);
    n.ka_ticks.fetch_add(1, std::memory_order_relaxed);
    // sim (env.drive): virtual time only moves when ticked, so tick fast; real time: sleep to the attempt
    if (!p.wire->session_up()) n.ka.next_in(env.drive ? 1u : std::max(1u, p.wire->reconnect_wait_ms()));
  }
  void keepalive_tick(Node& n) {
    // Bundle mode: a teardown waits for the tick in flight (it takes tick_mu after clearing `active`).
    std::unique_lock tl(n.tick_mu, std::defer_lock);
    if (bundle_mode) {
      tl.lock();
      if (!n.active.load(std::memory_order_acquire)) return;  // free or retiring slot
    }
    adopt_dyn(n);
    keepalive_tick_body(n);
  }
  // MB6a: a node the snapshot adds gets the client's envelope BEFORE its first connect (stage before swap, P05/Q05);
  // an unreachable admin is retried with the build backoff. A mismatch between the bundle's node_id and the HELLO_ACK
  // excludes the node (it never comes Up; the retry backoff is the long one) and is counted and logged.
  bool stage_push_blocked(Node& n) {
    if (!n.stage_push) return false;
    if (!n.active.load(std::memory_order_acquire)) return true;  // being torn down: no push, no build (Y15)
    Status ps = n.stage_push();
    if (ps) {
      n.stage_push = nullptr;
      return false;
    }
    nlog(log::Level::Warn, n, "bundle push to an added node failed; retrying with backoff",
         {{"error", ps.error().context ? ps.error().context : "?"}});
    note_build_failure(n, ps.error());
    return true;
  }
  void note_id_mismatch(Node& n, const Error& e) {
    if (!bundle_mode || e.code != ErrorCode::InvalidArgument) return;
    if (n.mismatch_ctr) n.mismatch_ctr->inc();
    nlog(log::Level::Error, n,
         "HELLO_ACK node id differs from the node_id in the bundle; node excluded until it matches",
         {{"expected_node_id", std::to_string(n.wopts.node)}, {"error", e.context ? e.context : "?"}});
  }
  // B-1 (review s11): the least time of the open's settle a retry of `n` starts with: its connect timeout
  // (reconnect_connect_ms), at most a quarter of the settle so a short settle still retries for most of it.
  Nanos settle_floor(const Node& n) const {
    const unsigned ms = bundle_mode ? dyn()->reconnect_connect_ms : n.wopts.reconnect_connect_ms;
    return std::min<Nanos>(std::chrono::milliseconds(ms), env.open_settle / 4);
  }
  // Q15 (review s10), static and bundle mode: a node of `ns` whose first build failed (its ticket fetch failed or timed
  // out under load, or its HELLO went unanswered) is retried here on its build backoff until env.open_settle has passed,
  // so a transient failure does not leave it pending behind a successful open. A node still down after that stays
  // pending (the open never fails for one node: availability). Returns how many came up. The open thread, before any
  // node thread runs.
  // R14 (review s11): the settle is a bound. `until` is checked before every attempt, and each attempt's admin I/O,
  // connects, HELLO and SEG_TABLE end by `until` (prepare_within, the WirePort op deadline), so the settle ends at
  // `until` plus one poll step. R19: an attempt waits for both the build backoff and its ticket source (tickets_ready_at).
  // B-1: no attempt starts with less than settle_floor() of the settle left, and one the end of the settle cuts short is
  // no failure (no streak, backoff, counter or Error line).
  std::size_t settle_first_builds(const std::vector<Node*>& ns) {
    std::size_t up = 0;
    if (env.open_settle <= Nanos{0}) return 0;
    const Nanos until = env.clock->now() + env.open_settle;
    auto due_of = [](const Node& n) { return std::max(n.build_next, tickets_ready_at(n)); };
    for (;;) {
      bool left = false;
      Nanos next = until;
      for (Node* n : ns) {
        if (n->pin_pair()) continue;
        const Nanos due = due_of(*n);
        // B-1 (review s11): the last start of an attempt leaves it one connect timeout of the settle (at most a quarter
        // of it), so a retry is a real attempt and not one the deadline cuts short against a healthy slow node.
        const Nanos last = until - settle_floor(*n);
        if (due > last) continue;  // its backoff runs past the settle (e.g. an ID mismatch): the keepalive retries it
        left = true;
        const Nanos now = env.clock->now();
        if (now >= until) break;  // R14: no attempt starts once the settle is over
        if (now < due) {
          next = std::min(next, due);
          continue;
        }
        if (now > last) continue;  // B-1: too little of the settle left for a real attempt
        prepare_tickets(*n, n->wopts, until - now);
        if (env.clock->now() >= until) continue;  // B-1: the ticket refill used up the settle; no build starts
        Status st = build(*n, /*background=*/true, until);  // the short caps of a retry, and nothing past the settle
        if (st) {
          ++up;
          n->build_streak = 0;
        } else if (st.error().code != ErrorCode::InvalidArgument && st.error().code != ErrorCode::Aborted &&
                   !fabric::last_local_failure().call && env.clock->now() >= until) {
          // B-1: cut short by the settle's end, no verdict on the node: no streak, no doubled backoff, no failure counted
          // (build() skips it too); the keepalive retries it with its full caps. Not an abort (s11c review P3-8): a
          // shutdown at or after `until` is not "the settle ended", and takes the branch below like one before it.
          nlog(log::Level::Info, *n, "open settle ended during a retry of this node; the keepalive retries it",
               {{"error", st.error().context ? st.error().context : "?"}});
        } else {
          note_id_mismatch(*n, st.error());
          note_build_failure(*n, st.error());
          next = std::min(next, due_of(*n));
        }
      }
      if (!left || env.clock->now() >= until || next >= until) break;
      if (env.drive) {
        while (env.clock->now() < next) env.drive();  // sim: virtual time moves only when driven
      } else {
        pause_for(std::chrono::duration_cast<std::chrono::microseconds>(
            std::clamp<Nanos>(next - env.clock->now(), std::chrono::milliseconds(1), std::chrono::milliseconds(100))));
      }
    }
    return up;
  }
  // Q15: the open's one line "N of M memory nodes connected", naming every pending node (ID, hostname, address).
  static void log_open_result(std::size_t up, std::size_t total, const std::string& pend) {
    log::write(pend.empty() ? log::Level::Info : log::Level::Warn, "client",
               pend.empty() ? "client open: every memory node connected"
                            : "client open: some memory nodes are pending (their first connect failed); each is retried "
                              "with backoff and joins placement when it connects",
               {{"client_host", log::hostname()},
                {"connected", std::to_string(up) + " of " + std::to_string(total)},
                {"pending", pend.empty() ? std::string("none") : pend}});
  }
  static void add_pending(std::string& pend, std::uint32_t id, const std::string& host, const std::string& addr) {
    pend += (pend.empty() ? "" : ", ") + std::string("node_id=") + (id ? std::to_string(id) : std::string("unknown")) +
            " hostname=" + host + " addr=" + addr;
  }
  // One node's connection state machine, on the pair this tick pins: no pair -> build one (like a reconnect); a pair
  // whose session is not Up -> its reconnect; Up -> keepalive + pump, then (HR3b) a planned rebuild when the node runs
  // class B values the live configuration no longer wants. A pair a rebuild swapped out is retired first, every tick.
  void keepalive_tick_body(Node& n) {
    SimTurn turn(this);  // sim: one thread at a time on the simulated network
    if (n.old_pair.load(std::memory_order_acquire)) retire_step(n);
    const PairPtr pp = n.pin_pair();
    if (!pp) {  // never connected: try again like a reconnect
      // Review w3b Z02: a retiring slot that never came up stays down (no push, no build); a revive (back in the bundle
      // before the teardown) makes it in use again and the next tick builds it.
      if (bundle_mode && n.slot_state.load(std::memory_order_acquire) == 2) return;
      if (env.clock->now() < n.build_next) {         // Q04: back off between first-build attempts
        if (env.drive) env.drive();                  // sim: virtual time only moves when something runs
        else n.ka.next_in(std::max(1u, static_cast<unsigned>(std::chrono::duration_cast<std::chrono::milliseconds>(n.build_next - env.clock->now()).count()) + 1));
        return;
      }
      if (stage_push_blocked(n)) {
        if (!env.drive) n.ka.next_in(std::max(1u, static_cast<unsigned>(std::chrono::duration_cast<std::chrono::milliseconds>(n.build_next - env.clock->now()).count())));
        n.ka_ticks.fetch_add(1, std::memory_order_relaxed);
        return;
      }
      prepare_tickets(n, n.wopts);
      Status st = build(n, /*background=*/true);
      if (!st) {
        note_id_mismatch(n, st.error());
        note_build_failure(n, st.error());
        if (!env.drive) n.ka.next_in(std::max(1u, static_cast<unsigned>(std::chrono::duration_cast<std::chrono::milliseconds>(n.build_next - env.clock->now()).count())));
      } else {
        n.build_streak = 0;
      }
      n.ka_ticks.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    Pair& p = *pp;
    if (!p.wire || !p.core) return;
    p.wire->prepare_tickets();  // ticket source network I/O, outside the core lock (bounded by its own 2 s budget)
    if (!p.wire->session_up()) return reconnect_off_lock(n, p);
    std::unique_lock lk(p.core_mu, std::defer_lock);
    if (p.wire->session_up()) {
      if (!lk.try_lock()) return rebuild_step(n, pp);  // a busy node is pumped by its jobs; a rebuild needs no core lock
      // Q17: a job may have taken the session Down between the Up check and the lock. Do not run the
      // reconnect step under core_mu (a due attempt would block every job): drop to the off-lock path.
      if (!p.wire->session_up()) {
        lk.unlock();
        return reconnect_off_lock(n, p);
      }
    } else {
      return reconnect_off_lock(n, p);  // N07: went Down between the two checks; never reconnect under core_mu
    }
    p.wire->keepalive();
    // R12 (review s11): sim only (env.drive set; a real fabric never has one), and only when the rig opts in
    // (Env::drive_when_up): an idle Up node's tick is the only thread in the sim turn, so it moves the simulated network
    // once (the PING it just posted travels, the server answers, a PONG lands); the pump below then takes what arrived.
    // Off by default so rigs whose test thread touches the sim directly keep a quiet sim while every node is Up.
    if (env.drive && env.drive_when_up) env.drive();  // R12
    p.core->pump();
    n.ka_ticks.fetch_add(1, std::memory_order_relaxed);
    if (!p.wire->session_up()) {
      // sim (env.drive): virtual time only moves when ticked, so tick fast; real time: sleep to the attempt
      n.ka.next_in(env.drive ? 1u : std::max(1u, p.wire->reconnect_wait_ms()));
      return;
    }
    lk.unlock();  // a rebuild connects for milliseconds: never under the core lock
    // Run #233 (RL3 leftover): a rejoining rail's connects run here, off the core lock, on the device fabric keepalive()
    // lent to this thread; the next tick (soon) swaps the set in under the lock and sends its HELLOs.
    const bool rail_built = p.wire->build_rails();
    rebuild_step(n, pp);
    if (rail_built) n.ka.next_in(1);
  }

  // ================= HR3b: planned rebuild of a node's pair (hot-reload plan decision 6, make-before-break) =================
  // One state machine per node, run by its keepalive tick (keepalive_tick_body) next to the first build and the reconnect,
  // and sharing their build code (build_pair). Bundle mode only: a lab or static client restarts to change class B.
  //   Up, dirty    the active pair runs class B values (landing.subpool_bytes, fabric.mtu, fabric.protocol,
  //                fabric.fetch_qps) the live snapshot no longer wants. The node waits a jitter of 0..rebuild_jitter_ms
  //                (once per dirty spell; clients spread over a node), then takes the client's one rebuild token.
  //   building     a fresh NodeSpec (make_spec: its own fabric, ticket source and jitter, so the two pairs never share a
  //                completion queue) and build_pair beside the active pair: new tickets, new conn_id, the wanted values.
  //                Failure (connect, HELLO, ticket, the server's connection cap): the old pair stays active and serving,
  //                the token is given back, retry with the reconnect backoff.
  //   swap         the pool series point at the new core, the node's pointer is the new pair (new jobs go there), then
  //                the old one is `retired` (a job that pinned it but was not counted in yet moves to the new one).
  //   retiring     the old pair keeps serving the jobs inside it. Its endpoints go back to the fabric (the server ends
  //                that session and frees whatever it held) once its jobs_inside is 0 and no WR is outstanding on it
  //                (§9.4 class B: no QP is destroyed while a WR is outstanding). At rebuild_drain_ms (30 s) the §3.7
  //                drain runs: its session goes Down, in-flight work flushes, the core fails those jobs, they leave.
  //                Then the token is free and the next dirty node of this client may start.
  // The token makes the overlap one node at a time per client: one extra session (endpoints_per_session endpoints) per
  // rebuilding client. Connection cap rule (decision 6): limits.max_conns_per_principal >= clients x endpoints_per_session
  // + endpoints_per_session x stagger, where stagger is the number of the principal's clients that may rebuild the same
  // node at once (the jitter keeps it small). A cap hit fails the build: the old pair keeps serving, the rebuild retries.
  // HR7: endpoints_per_session = paired rails x (1 control + fetch_qps fetch + 1 ingest) (multi-rail decision 6), so a
  // fabric.fetch_qps change makes the overlap one old-size session plus one new-size session: the rule takes the larger.
  std::atomic<std::size_t> rebuild_slot{kNoSlot};  // the slot holding the token (two pairs: building or retiring)
  unsigned rebuild_jitter_ms = 5000, rebuild_drain_ms = 30000;
  std::mutex spec_mu;  // make_spec calls one by one: the membership thread and a rebuilding keepalive thread
  std::atomic<std::uint64_t> rebuilds_ok{0}, rebuilds_failed{0};
  telemetry::Counter* rebuild_ctr[2] = {};  // miracache_client_rebuilds_total{result="ok"|"failed"}

  static std::string class_b_names(const ClassB& a, const ClassB& b) {
    std::string s;
    auto add = [&](bool d, const char* k) {
      if (d) s += (s.empty() ? "" : ",") + std::string(k);
    };
    add(a.pool_bytes != b.pool_bytes, "landing.subpool_bytes");
    add(a.mtu != b.mtu, "fabric.mtu");
    add(a.protocol != b.protocol || a.wire_proto != b.wire_proto, "fabric.protocol");
    add(a.fetch_qps != b.fetch_qps, "fabric.fetch_qps");
    return s;
  }
  // miracache_client_config_pending_rebuild_keys: the class B keys whose wanted value some node in use does not run yet.
  // Caller holds dyn_mu (so a reload and a swap never publish out of order).
  void pending_gauge_locked() {
    if (!cfg_pending) return;
    const ClientDynPtr d = dyn_snap.load();
    bool k[4] = {};
    for (const auto& np : nodes) {
      if (bundle_mode && np->slot_state.load(std::memory_order_acquire) != 1) continue;
      const PairPtr p = np->pin_pair();
      if (!p) continue;  // not built yet: its first build takes the wanted values
      const ClassB w = wanted_b(p->open, *d);
      k[0] = k[0] || w.pool_bytes != p->b.pool_bytes;
      k[1] = k[1] || w.mtu != p->b.mtu;
      k[2] = k[2] || w.protocol != p->b.protocol || w.wire_proto != p->b.wire_proto;
      k[3] = k[3] || w.fetch_qps != p->b.fetch_qps;
    }
    cfg_pending->set(static_cast<std::int64_t>(k[0] + k[1] + k[2] + k[3]));
  }
  void pending_gauge() {
    std::lock_guard lk(dyn_mu);
    pending_gauge_locked();
  }
  // The WireOptions hooks a node's ports get from the Client (as init_node and bind_dyn give the node's own).
  void hook_wopts(Node& n, WireOptions& w) {
    Node* np = &n;
    w.drive = env.drive;
    w.on_down = [np] { np->ka.kick(); };
    // Goal 10 (HR7 fix): a rebuilt pair's rail series and rail log lines carry the node label and hostname too, as the
    // node's own (init_node); without them they fell back to "host:port" and an empty hostname.
    w.label = n.label;
    w.hostname = [np] { return node_hostname(*np); };
    if (bundle_mode) {
      w.stamp = &stamp_word;
      w.on_reply = [this, np](const WireOptions::ReplyNote& r) { note_reply(*np, r); };
      w.dyn = &dyn_snap;
    }
    if (w.node == 0) w.on_node_id = [this, np](std::uint32_t id) { return learn_id(*np, id); };
    w.on_node_hostname = [this, np](const std::string& h) { learn_hostname(*np, h); };
    hook_endpoint_diag(n, w);  // G09, L13, Q03
  }
  // The next tick of a node that waits for its jitter, the token or a retire: soon (sim: virtual time moves only when
  // something drives it).
  void tick_soon(Node& n, Nanos until) {
    if (env.drive) {
      env.drive();
      n.ka.next_in(1);
      return;
    }
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(until - env.clock->now()).count();
    n.ka.next_in(static_cast<unsigned>(std::clamp<long long>(ms + 1, 1, std::max(1u, n.ka.period()))));
  }

  // F09: the rebuild token's holder is visible: miracache_client_rebuild_token_held_seconds{slot, node, node_id, hostname,
  // addr} counts the seconds this node has held it (its retire ticks move it) and goes to 0 when it is given back. An old
  // pair whose jobs never leave after the drain (a wedged decrypt task) holds the token, and with it every other node's
  // class B change of this client: retire_step warns again every kTokenRelog while that lasts.
  static constexpr Nanos kTokenRelog = std::chrono::seconds(60);
  void token_taken(Node& n) {
    n.token_at = env.clock->now();
    n.token_relog = Nanos{0};
    const std::uint32_t id = node_id_of(n);
    n.g_token = &reg.gauge("miracache_client_rebuild_token_held_seconds",
                           "Seconds a node has held the client's one planned-rebuild token (building or retiring its old "
                           "connection); 0 once given back. A value that keeps growing blocks every other node's class B change.",
                           {{"slot", std::to_string(n.slot)},
                            {"node", n.label},
                            {"node_id", id ? std::to_string(id) : std::string("unknown")},
                            {"hostname", host_or_unknown(n)},  // Q08 (review s10): "unknown" until known, never ""
                            {"addr", n.addr}});
    n.g_token->set(0);
  }
  std::int64_t token_held_s(const Node& n) const {
    return std::chrono::duration_cast<std::chrono::seconds>(env.clock->now() - n.token_at).count();
  }
  void token_given_back(Node& n) {
    if (n.g_token) n.g_token->set(0);
    n.g_token = nullptr;
  }

  // Up, no core lock held. `pp` is the active pair this tick pinned.
  void rebuild_step(Node& n, const PairPtr& pp) {
    if (!bundle_mode || !make_spec || n.slot_state.load(std::memory_order_acquire) != 1) return;
    if (n.old_pair.load(std::memory_order_acquire)) return;  // still retiring the previous one
    const ClassB want = wanted_b(pp->open, *dyn());
    if (want == pp->b) {
      n.rebuild_due = Nanos{0};  // clean (or a change was reverted before it ran)
      settle_rebuild_failures(n);  // H06: a withdrawn rebuild leaves no open failure entry
      return;
    }
    const Nanos now = env.clock->now();
    if (n.rebuild_due == Nanos{0}) {
      const std::uint64_t j = rebuild_jitter_ms > 0 && n.wopts.random ? n.wopts.random->below(rebuild_jitter_ms + 1ull) : 0;
      n.rebuild_due = now + std::chrono::milliseconds(j);
    }
    if (now < n.rebuild_due) return tick_soon(n, n.rebuild_due);
    std::size_t none = kNoSlot;
    if (!rebuild_slot.compare_exchange_strong(none, n.slot, std::memory_order_acq_rel))
      return tick_soon(n, now + std::chrono::milliseconds(50));  // another node of this client goes first
    token_taken(n);
    const std::string keys = class_b_names(pp->b, want);
    bool attempted = false;
    Status st = planned_rebuild(n, pp, attempted);
    if (st) {
      n.rebuild_streak = 0;
      n.rebuild_due = Nanos{0};
      nlog(log::Level::Info, n, "planned rebuild: new connection in service; the old one closes when its jobs are done",
           {{"keys", keys}});
      note_endpoint_ok(fail_key(n), node_id_of(n), node_hostname(n), n.addr);  // G09: as a first build's success
      {
        std::lock_guard lk(epfail_mu);
        n.rebuild_epfail.clear();  // H06: note_endpoint_ok closed them
      }
      n.ka.next_in(env.drive ? 1u : 10u);  // retire it soon
      return;
    }
    // G09 (review G07): the same Q6 accounting as a first build (the overlap is where a local CQ/QP limit is most
    // likely): counted per attempt by cause, logged once per cause; an abort or an identity fault is not counted.
    if (attempted) {
      const ErrorCode c = st.error().code;
      if (fabric::last_local_failure().call || (c != ErrorCode::Aborted && c != ErrorCode::InvalidArgument))
        note_build_fail(n, st.error(), &n.rebuild_epfail);  // H06: settled if this rebuild is withdrawn
    }
    token_given_back(n);
    rebuild_slot.store(kNoSlot, std::memory_order_release);
    rebuilds_failed.fetch_add(1, std::memory_order_relaxed);
    if (rebuild_ctr[1]) rebuild_ctr[1]->inc();
    ++n.rebuild_streak;
    const auto dy = dyn();
    const std::uint64_t lo = std::max(1u, dy->reconnect_min_ms), hi = std::max<std::uint64_t>(lo, dy->reconnect_max_ms);
    std::uint64_t d = std::min<std::uint64_t>(hi, lo << std::min(n.rebuild_streak - 1, 20u));
    if (n.wopts.random && d > 1) d = d / 2 + n.wopts.random->below(d / 2 + 1);
    n.rebuild_due = env.clock->now() + std::chrono::milliseconds(d);
    if (st.error().code != ErrorCode::Aborted && (n.rebuild_streak == 1 || n.rebuild_streak % 32 == 0))
      nlog(log::Level::Warn, n, "planned rebuild failed; the current connection keeps serving, retrying with backoff",
           {{"keys", keys}, {"error", st.error().context ? st.error().context : "?"},
            {"failures", std::to_string(n.rebuild_streak)}});
    tick_soon(n, n.rebuild_due);
  }
  // Builds the new pair beside `old` and swaps it in (the token is held). Error: nothing changed.
  Status planned_rebuild(Node& n, const PairPtr& old, bool& attempted) {
    attempted = false;
    Expected<Client::NodeSpec> sp = [&]() -> Expected<Client::NodeSpec> {
      std::lock_guard lk(spec_mu);
      return make_spec(n.view);
    }();
    if (!sp) return sp.error();
    if (!sp->fab) return Error{ErrorCode::InvalidArgument, "client: bad node spec"};
    if (sp->fab == old->fab)  // two WirePorts on one fabric would take each other's completions
      return Error{ErrorCode::InvalidArgument, "client: make_spec returned the fabric in use; a rebuild needs a fresh one"};
    WireOptions wo = std::move(sp->wopts);
    wo.node = n.wopts.node;  // the bundle's ID, as activate_slot sets it
    hook_wopts(n, wo);
    // G01: the new ticket source takes the live ticket_batch and the new fetch_qps BEFORE its first batch (its I/O; no
    // core lock is held): the open-time batch alone may be smaller than the fetch tickets the new pair draws.
    if (sp->on_dyn) sp->on_dyn(*dyn());
    prepare_tickets(n, wo);
    fabric::clear_local_failure();  // G09 (Q6): a local device resource failure of THIS build is told apart
    auto np = build_pair(n, *sp->fab, std::move(wo), /*background=*/true, attempted);
    if (!np) return np.error();  // its wire and core are gone; sp's fabric and ticket source go with sp
    PairPtr p = std::move(*np);
    p->owner = std::move(sp->owner);
    p->on_dyn = std::move(sp->on_dyn);
    if (p->on_dyn) p->on_dyn(*dyn());  // the new ticket source starts at the live ticket_batch
    swap_pool_series(n, p->core.get());  // Z02/Z05: the series read the new core before the old one can go
    // s12 (#323 Q06): before the swap publishes anything, so every thread that can see `old` as retired also sees which
    // client's sim turn its destructor takes (the tick's own pin keeps it alive meanwhile; this is ordering hygiene).
    if (env.drive) old->sim = this;
    n.pair.store(p, std::memory_order_release);  // new jobs go to the new pair from here
    recheck_block(n, *p);                        // L08: the rebuilt session's HELLO_ACK limit
    old->retired.store(true);                    // after the store (enter_pair re-pins the new one)
    if (old->wire) {
      // J05 (review s8 wave15): the old pair runs no keepalive() again, so a rail set build_rails() connected for it
      // (this tick) would hold its connections, against max_conns_per_principal, until the retire's
      // release_endpoints. Given back now (aborted; released by the retire's reap once drained). Never waits for the
      // core lock (a job inside may hold it for a long time): a busy pair gives the set back in retire_step instead.
      std::unique_lock lk(old->core_mu, std::try_to_lock);
      if (lk.owns_lock()) old->wire->drop_rail_build();
    }
    n.retire_until = sat_add(env.clock->now(), std::chrono::milliseconds(rebuild_drain_ms));
    n.retire_drained = false;
    n.old_pair.store(old, std::memory_order_release);
    // The reporter (report_mu) and another node's learn_id (keeps_id, place_mu) pin a pair under their lock: once these
    // are taken, neither looks at the old pair again. s12 (#323 Q03): the same holds for pending_gauge_locked (dyn_mu):
    // pending_gauge() below takes dyn_mu after the swap, so a pin taken there is dropped before the retire can start.
    // Why it matters (sim only: without env.drive no SimTurn exists): ~Pair takes a SimTurn, so a pin that turned out to
    // be the old pair's LAST reference, dropped under one of these locks, would wait for sim_mu under that lock while
    // this tick (in its turn) waits for the lock. block_size_problem and nodes_connected (both pin under slots_mu, which
    // the tick also takes in its turn: swap_pool_series) have no barrier here: an adapter calls them at start-up and no
    // sim client calls them during a rebuild.
    { std::lock_guard rl(n.report_mu); }
    { std::lock_guard pl(place_mu); }
    rebuilds_ok.fetch_add(1, std::memory_order_relaxed);
    if (rebuild_ctr[0]) rebuild_ctr[0]->inc();
    pending_gauge();
    return {};
  }
  // The old pair of a planned rebuild (tick). See the state list above.
  void retire_step(Node& n) {
    PairPtr old = n.old_pair.load(std::memory_order_acquire);
    if (!old) return;
    const Nanos now = env.clock->now();
    const bool late = now >= n.retire_until;
    bool done = false;
    if (n.g_token) n.g_token->set(token_held_s(n));  // F09
    if (old->jobs_inside.load() != 0 && (!late || n.retire_drained)) {  // its jobs are still running: look again soon
      if (n.retire_drained && now >= n.token_relog) {  // F09: drained, yet a job never left: say so again, rate-limited
        if (n.token_relog != Nanos{0})
          nlog(log::Level::Warn, n,
               "planned rebuild: the old connection still has jobs long after the drain; it holds the client's rebuild "
               "token, so no other node of this client applies a class B change",
               {{"jobs_inside", std::to_string(old->jobs_inside.load())}, {"slot", std::to_string(n.slot)},
                {"token_held_s", std::to_string(token_held_s(n))}});
        n.token_relog = sat_add(now, kTokenRelog);
      }
      if (old->wire) {
        // R21 (J05): the swap's try-lock may have failed; give the old pair's rail set back as soon as the core lock is
        // free, not only after its jobs leave (it holds connections against max_conns_per_principal). Never waits.
        std::unique_lock lk(old->core_mu, std::try_to_lock);
        if (lk.owns_lock()) old->wire->drop_rail_build();
      }
      return tick_soon(n, now + std::chrono::milliseconds(5));
    }
    {
      SimTurn* t = tls_turn();  // core_mu is taken before the sim lock, never while holding it
      if (t && t->im != this) t = nullptr;
      if (t) t->release();
      std::unique_lock lk(old->core_mu);
      if (t) t->acquire();
      old->wire->drop_rail_build();  // J05: a rail set built for the old pair goes back (no-op when none)
      if (old->jobs_inside.load() == 0) {  // seq_cst against enter_pair: nobody is or gets inside any more
        (void)old->core->pump();  // the completions of its last ops (a RELEASE's SEND, ...)
        done = late || old->wire->quiet();
        if (done) old->wire->release_endpoints();  // QPs gone; the server ends the session
      } else if (late && !n.retire_drained) {
        n.retire_drained = true;
        old->wire->drain_session();  // §3.7: Down, in-flight work flushes, the core fails the jobs inside
        lk.unlock();
        nlog(log::Level::Warn, n, "planned rebuild: the old connection still has jobs at the drain deadline; drained",
             {{"jobs_inside", std::to_string(old->jobs_inside.load())}});
      }
    }
    if (!done) return tick_soon(n, env.clock->now() + std::chrono::milliseconds(5));
    n.old_pair.store(nullptr, std::memory_order_release);
    old.reset();  // usually the last copy: its core, wire and fabric go now (else with the last transient pin)
    std::size_t me = n.slot;
    token_given_back(n);  // F09
    rebuild_slot.compare_exchange_strong(me, kNoSlot, std::memory_order_acq_rel);
    nlog(log::Level::Info, n, "planned rebuild: old connection closed");
    if (env.drive) n.ka.next_in(1);
  }
  void start_keepalive(unsigned ms) {
    for (auto& np : nodes) {
      Node* n = np.get();
      if (n->raw_fab) n->ka.start(ms, [this, n] { keepalive_tick(*n); });
    }
  }
  void stop_keepalive() {
    {
      std::lock_guard lk(build_mu);
      stopping = true;
      for (auto& n : nodes)
        if (n->building) n->building->abort_connect();  // Q02/N03: every first build in flight gives up too
    }
    for (auto& n : nodes)
      if (const PairPtr p = n->pin_pair(); p && p->wire) p->wire->abort_connect();  // a Connecting attempt gives up so the join is prompt
    for (auto& n : nodes) n->ka.stop();
  }

  // The node that owns the scope of this request (spec 7.1; every op of a scope goes to its owner).
  Node& owner(const Req& r) {
    if (nodes.size() == 1 || r.group >= r.sk.scopes.size()) return *nodes[0]; 
    const auto s = snapshot();
    if (s->places.empty()) return *nodes[0];  // no node has an ID yet: the job fails fast on a node that is not ready
    return *nodes[s->idx[place_owner(s->places, std::span<const std::uint8_t, 32>(r.sk.scopes[r.group].b))]];
  }

  // s12 (C1): the runtime lane of a job = the node it will most likely run on (the owner of its scope, or the bundle's
  // first owner): a scheduling hint only, so a stale snapshot is harmless. kNoLane when there is no choice to protect.
  std::uint32_t lane_of(const Req& r) {
    if (nodes.size() <= 1 || r.group >= r.sk.scopes.size()) return kNoLane;
    const auto s = snapshot();
    if (s->places.empty()) return kNoLane;
    const std::span<const std::uint8_t, 32> scope(r.sk.scopes[r.group].b);
    if (bundle_mode) {
      const auto o = owner_set(s->view, scope, 1);
      return o.empty() ? kNoLane : static_cast<std::uint32_t>(s->idx[o[0]]);
    }
    return static_cast<std::uint32_t>(s->idx[place_owner(s->places, scope)]);
  }

  // ================= MB6a: bundle membership (node slots) =================
  // Slots: `nodes` holds kMaxNodes preallocated Node structs. A slot is Free (0), In use (1) or Retiring (2). All state
  // transitions run on ONE thread (the membership thread, `mgr`; at open, the open thread before any other thread
  // exists), so there is no slot lock. The data path never takes one either: a job reads the placement snapshot once and
  // the snapshot's copies of Node::pin keep the slots it names from being torn down or reused.
  //
  //   add     activate_slot (fields, metrics, replicator) -> push the client's envelope (on the node's own thread,
  //           before its first connect) -> connect -> wait up to connect_wait_ms for Up -> publish the new snapshot.
  //           The old snapshot stays in force during the wait: a join never makes a job address a node with no
  //           connection (P05, Q10).
  //   retire  absent from the bundle's `nodes` (Q08): the snapshot without it is published; the slot then waits until
  //           the last snapshot copy is gone (and jobs_inside is 0), then: `active` off, the node's thread leaves its
  //           tick, the replicator drains and joins, endpoints go back to the fabric, wire and core are freed, and
  //           the slot is Free (reusable). A node that comes back before that is revived in place.
  static constexpr std::size_t kNoSlot = ~std::size_t{0};
  std::function<Expected<Client::NodeSpec>(const control::NodeView&)> make_spec;
  std::function<Status(const std::string&)> push_fn;
  std::shared_ptr<BundleWatcher> watcher;
  std::function<void(std::uint32_t, const std::string&)> wake_fn;  // MB6b: set once at open
  ClientCoreOptions base_copts;
  unsigned slot_keepalive_ms = 1000, connect_wait_ms = 2000;
  std::mutex mgr_mu;
  MembershipSnapPtr pending;  // the newest bundle handed to apply_membership, not applied yet
  std::map<std::uint32_t, std::size_t> slot_by_id;  // written by the membership thread under slots_mu (hooks read it)
  std::vector<std::size_t> retiring;                // membership thread only
  MembershipSnapPtr retry_snap;                     // membership thread only: a bundle with nodes still without a slot (Y06)
  // Review w3b Z06: a bundle node left without a slot (table full, or its set-up failed) is retried with its own
  // exponential backoff (real time: kRetryMinMs doubling up to kRetryMaxMs), and its error is logged when it changes.
  struct PendingNode {
    std::string admin, rail, last_err;  // what it was set up from (a change starts a fresh backoff); the error logged last
    unsigned streak = 0;                // failed set-ups in a row
    Nanos due{0};                       // RealClock: the earliest retry (0 = now)
  };
  static constexpr unsigned kRetryMinMs = 200, kRetryMaxMs = 30000;
  std::map<std::uint32_t, PendingNode> pend;  // membership thread only
  Nanos next_retry() const {
    Nanos t = Nanos::max();
    for (const auto& e : pend) t = std::min(t, e.second.due);
    return t;
  }
  // MB7: hints (per-scope "use the previous view's owner set"), the previous view's local age, counters.
  HintCache hints;
  unsigned previous_view_ms = 3600000;
  bool prev_seen = false, applied_prev_set = false;  // membership thread (and the open thread before it exists) only
  std::uint32_t prev_epoch_seen = 0, applied_prev_epoch = 0;
  Nanos prev_seen_at{0};
  enum HintEvent { kHintSet, kHintDropMiss, kHintDropRoot, kHintDropRetire, kHintDropEmpty, kHintVoidEpoch, kHintEvents };
  telemetry::Counter* hint_ctr[kHintEvents] = {};
  telemetry::Counter* prev_hit_ctr = nullptr;      // reads answered by the previous set
  telemetry::Counter* prev_store_ctr = nullptr;    // continuation stores that fell through to the previous set
  std::function<Status(const std::string&)> send_report_fn;
  unsigned report_ms = 2000;
  KeepaliveThread reporter;  // MB7: client reports (blocking HTTPS); never on a data-path thread
  std::function<void()> cancel_reports_fn;  // U2-27 (BundleOpen::cancel_reports)
  // U2-27: report_state_mu guards the report state only (never held across a send); report_send_mu makes the senders
  // (the reporter thread, send_report_now) take turns, so two reports never carry the same AEAD failures.
  std::mutex report_state_mu, report_send_mu;
  // U2-14: AEAD failures already reported, per node label (miracache_client_aead_fail_total{node} is cumulative per
  // label, across the incarnations of a node): the value at the last ACCEPTED report of every label in it. A label not
  // in it starts at its slot's aead_start (the value when that incarnation was filled), so a retired node's count
  // never hides new failures elsewhere, and a revived node starts fresh.
  std::map<std::string, std::uint64_t> aead_reported;
  std::atomic<std::uint64_t> reports_ok{0}, reports_bad{0};
  std::string report_last_err;
  std::atomic<std::uint64_t> applied_gen{0};
  std::atomic<std::uint32_t> applied_epoch{0};
  // MB6b: (epoch << 32) | low 32 bits of the generation, stamped on every frame by every node's WirePort. Changes only
  // with the placement snapshot (publish_bundle), so the stage-before-swap wait keeps the old epoch.
  std::atomic<std::uint64_t> stamp_word{0};
  // put_skipped{reason} the Client counts itself (bundle mode): a store to a removed node (V08), and the keys of root
  // puts a node of the client's view will skip as not an owner because the view left a bundle node out (V12).
  telemetry::Counter* skipped_draining = nullptr;
  telemetry::Counter* skipped_not_owner = nullptr;
  std::uint64_t gap_logged_gen = 0;  // membership thread: the generation whose left-out nodes were logged (V12)
  // V12: keys of root batch `r` that go to a node of `order` (the client's current owner set, as slots) outside the
  // scope's owner set over the bundle's whole current view (`full`, mapped to slots through `slot_of_id`, as MB7's
  // previous_set maps `prev_view`): that node skips them as not an owner. Only when the snapshot left a node out.
  void count_gap_skips(const PlaceSnap& s, const Req& r, const std::vector<std::size_t>& order, unsigned R) {
    if (s.full.nodes.empty() || !skipped_not_owner || r.kind != 2) return;
    if (!r.parent.empty() && !r.parent[0].empty()) return;  // a continuation: no owner check on the memory node
    std::vector<std::size_t> owners;  // the whole-view owner set as slots (a node without a slot owns, but has none)
    for (std::size_t k : owner_set(s.full, std::span<const std::uint8_t, 32>(r.sk.scopes[r.group].b), R)) {
      auto it = s.slot_of_id.find(static_cast<std::uint32_t>(std::stoul(s.full.nodes[k].id)));
      if (it != s.slot_of_id.end()) owners.push_back(it->second);
    }
    std::size_t legs = 0;
    for (std::size_t slot : order) legs += std::find(owners.begin(), owners.end(), slot) == owners.end() ? 1 : 0;
    if (legs) skipped_not_owner->inc(legs * r.raw.size());
  }
  std::size_t initial_up = 0;
  KeepaliveThread mgr;  // after everything it touches: destroyed (joined) first
  KeepaliveThread pusher;  // MB6b: envelope pushes to lagging nodes (blocking HTTPS); never on a data-path thread

  // MB6b: one frame from node `n` (WirePort::on_reply: under the caller's lock, so lock-free and no I/O).
  //   node lags    reply bundle_gen_lo below ours (signed 32-bit distance), or a StaleEpoch reply whose epoch is below
  //                ours (the node sees our higher epoch as "above") -> push our envelope (pusher thread).
  //   client lags  a higher bundle_gen_lo, or a StaleEpoch reply with a higher epoch -> BundleWatcher wake, fetching
  //                from this node first (Q05).
  // A zero epoch or generation in the reply is "unstamped" (lab-mode node): ignored.
  void note_reply(Node& n, const WireOptions::ReplyNote& r) {
    const std::uint64_t s = stamp_word.load(std::memory_order_acquire);
    const auto my_epoch = static_cast<std::uint32_t>(s >> 32);
    const auto my_lo = static_cast<std::uint32_t>(s);
    if (s == 0) return;  // nothing applied yet
    bool node_lags = false, client_lags = false;
    if (r.bundle_gen_lo != 0) {
      const auto d = static_cast<std::int32_t>(r.bundle_gen_lo - my_lo);
      node_lags = d < 0;
      client_lags = d > 0;
    }
    if (r.stale_epoch && r.epoch != 0 && my_epoch != 0) {
      if (r.epoch < my_epoch) node_lags = true;
      else if (r.epoch > my_epoch) client_lags = true;
    }
    if (node_lags && !n.push_wanted.exchange(true, std::memory_order_relaxed)) pusher.kick();
    if (client_lags && r.bundle_gen_lo != 0 && wake_fn) wake_fn(r.bundle_gen_lo, n.bundle_admin);
  }
  void push_tick() {
    if (!push_fn || is_stopping()) return;
    bool again = false;
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      Node& n = *nodes[i];
      if (!n.push_wanted.load(std::memory_order_relaxed)) continue;
      // Copied under slots_mu while the slot is in use (run #171): the push blocks on HTTPS, and meanwhile the slot may
      // be retired, torn down and refilled; after it, the node's fields are touched only if the occupant is the same.
      std::string admin, id_s, host, addr;
      std::uint64_t inc = 0;
      {
        std::lock_guard lk(slots_mu);
        if (n.slot_state.load(std::memory_order_acquire) != 1) {
          n.push_wanted.store(false, std::memory_order_relaxed);
          continue;
        }
        admin = n.bundle_admin;
        id_s = id_text(n);
        host = n.hostname;
        addr = n.addr;
        inc = n.incarnation;
      }
      auto plog = [&](log::Level lvl, std::string_view msg, std::initializer_list<log::Field> extra) {
        std::vector<log::Field> f{{"client_host", log::hostname()}, {"node_id", id_s}, {"hostname", host}, {"addr", addr}};
        for (const auto& e : extra) f.push_back(e);
        log::write(lvl, "client", msg, std::span<const log::Field>(f));
      };
      const std::uint64_t gen = applied_gen.load(std::memory_order_acquire);
      if (admin.empty() || n.push_ok_gen.load(std::memory_order_relaxed) == gen) {  // nothing to push to, or done for this generation
        n.push_wanted.store(false, std::memory_order_relaxed);
        continue;
      }
      if (RealClock().now().count() < n.push_next.load(std::memory_order_relaxed)) {
        again = true;
        continue;
      }
      n.push_wanted.store(false, std::memory_order_relaxed);
      Status st = push_fn(admin);
      // Review w4 V14: the push state changes under slots_mu, only for the occupant the push was for (activate_slot
      // resets it under the same lock), so a push that outlived its occupant never lands on the next one.
      unsigned fails = 0;
      {
        std::lock_guard lk(slots_mu);
        if (n.incarnation != inc || n.slot_state.load(std::memory_order_acquire) == 0) continue;  // a new occupant
        if (st) {
          n.push_ok_gen.store(gen, std::memory_order_relaxed);
          n.push_fails.store(0, std::memory_order_relaxed);
        } else {
          fails = std::min(n.push_fails.load(std::memory_order_relaxed) + 1, 6u);
          n.push_fails.store(fails, std::memory_order_relaxed);
          n.push_next.store((RealClock().now() + std::chrono::seconds(std::min(30u, 1u << (fails - 1)))).count(),
                            std::memory_order_relaxed);
          n.push_wanted.store(true, std::memory_order_relaxed);  // the node is still behind: retry after the backoff
        }
      }
      if (st) {
        plog(log::Level::Info, "pushed the bundle to a lagging node", {{"generation", std::to_string(gen)}});
      } else {
        again = true;
        plog(log::Level::Warn, "bundle push to a lagging node failed; backing off",
             {{"error", st.error().context ? st.error().context : "?"}, {"failures", std::to_string(fails)}});
      }
    }
    pusher.next_in(again ? 500u : 0u);
  }

  // ---- MB7: client reports (POST /v1/reports on [control] controller) ----
  // Body: {"generation":G,"nodes":[{"node_id":N,"rails":[{"addr":"host:port","reachable":bool}]}],"aead_fail_delta":D}.
  // One entry per node of the bundle that has a slot; `rails` is the rail this client connects to (the first one),
  // reachable = its session is Up. The controller reads "this client reaches some other node" from the other entries.
  // aead_fail_delta = AEAD failures since the last ACCEPTED report (a failed send keeps the delta). The reporter reads a
  // slot's wire and core only under Node::report_mu, which teardown takes before it frees them.
  // `base`: aead_reported; `seen` gets every reported label's current value (it becomes aead_reported once accepted).
  std::string build_report(const std::map<std::string, std::uint64_t>& base, std::map<std::string, std::uint64_t>& seen) {
    seen.clear();
    std::uint64_t delta = 0;
    std::string o = "{\"generation\":" + std::to_string(applied_gen.load(std::memory_order_acquire)) + ",\"nodes\":[";
    bool first = true;
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      Node& n = *nodes[i];
      std::uint32_t id = 0;
      std::string rail, label;
      std::uint64_t inc = 0, start = 0;
      {
        std::lock_guard lk(slots_mu);
        if (n.slot_state.load(std::memory_order_acquire) != 1) continue;
        id = n.wopts.node;
        rail = n.bundle_rail;
        inc = n.incarnation;
        label = n.label;
        start = n.aead_start;
      }
      if (id == 0 || rail.empty()) continue;
      bool up = false;
      {
        std::lock_guard rl(n.report_mu);
        if (const PairPtr p = n.pin_pair(); p && p->wire) up = p->wire->session_up();
      }
      {
        std::lock_guard lk(slots_mu);
        if (n.incarnation != inc || n.slot_state.load(std::memory_order_acquire) != 1) continue;  // refilled meanwhile
      }
      // U2-14: per label (two slots of one node after a rebuild share the label and the counter: counted once).
      if (!seen.count(label)) {
        const std::uint64_t cur = aead_counter(label).value();
        auto b = base.find(label);
        const std::uint64_t from = b != base.end() ? b->second : start;
        delta += cur > from ? cur - from : 0;
        seen[label] = cur;
      }
      if (!first) o += ',';
      first = false;
      o += "{\"node_id\":" + std::to_string(id) + ",\"rails\":[{\"addr\":\"" + json_escape(rail) + "\",\"reachable\":" +
           (up ? "true" : "false") + "}]";
      // Fail-slow: a node whose breaker is not closed says so (advisory: the operator drains it or lowers its weight).
      if (const int bs = n.brk.state.load(std::memory_order_acquire); bs != kBrkClosed)
        o += std::string(",\"breaker\":\"") + (bs == kBrkOpen ? "open" : "half_open") + "\"";
      o += "}";
    }
    o += "],\"aead_fail_delta\":" + std::to_string(delta) + "}";
    return o;
  }
  // The core's miracache_client_aead_fail_total{node} (ClientMetrics::aead_fail): read from the registry, so no core
  // is needed (it stays readable after the node's core is gone).
  telemetry::Counter& aead_counter(const std::string& label) {
    return reg.counter("miracache_client_aead_fail_total", "Fetched blocks that failed AEAD verification.", {{"node", label}});
  }
  Status do_report() {
    if (!send_report_fn) return Error{ErrorCode::Unsupported, "client: no [control] controller; no reports"};
    if (applied_gen.load(std::memory_order_acquire) == 0) return Error{ErrorCode::NotFound, "client: no bundle applied yet"};
    std::lock_guard sl(report_send_mu);  // one sender at a time; report_state_mu is not held across the send (U2-27)
    std::map<std::string, std::uint64_t> seen;
    std::string body;
    {
      std::lock_guard lk(report_state_mu);
      body = build_report(aead_reported, seen);
    }
    Status st = send_report_fn(body);  // blocking HTTPS, bounded; shutdown cuts it short (cancel_reports)
    std::lock_guard lk(report_state_mu);
    if (st) {
      aead_reported = std::move(seen);
      reports_ok.fetch_add(1, std::memory_order_relaxed);
      report_last_err.clear();
    } else {
      reports_bad.fetch_add(1, std::memory_order_relaxed);
      const std::string err = st.error().context ? st.error().context : "?";
      if (err != report_last_err) {  // logged when the error changes, not every 2 s
        report_last_err = err;
        mlog(log::Level::Warn, "client report to the controller failed", {{"error", err}});
      }
    }
    return st;
  }
  void report_tick() {
    if (is_stopping()) return;
    (void)do_report();
  }

  void mlog(log::Level lvl, std::string_view msg, std::initializer_list<log::Field> extra = {}) {
    std::vector<log::Field> f;
    f.emplace_back("client_host", log::hostname());
    for (const auto& e : extra) f.push_back(e);
    log::write(lvl, "client", msg, std::span<const log::Field>(f));
  }
  bool is_stopping() {
    std::lock_guard lk(build_mu);
    return stopping;
  }
  std::size_t free_slot() const {
    for (std::size_t i = 0; i < nodes.size(); ++i)
      if (nodes[i]->slot_state.load(std::memory_order_acquire) == 0) return i;
    return kNoSlot;
  }
  // Fills `n` from its spec (shared by the static open and the slots). Single-threaded: nothing else can see the node.
  void init_node(Node& n, Client::NodeSpec&& s, const ClientCoreOptions& copts, bool multi) {
    Node* np = &n;
    n.weight = s.weight;
    n.zone = s.zone;
    n.addr = s.wopts.rail.host + ":" + std::to_string(s.wopts.rail.port);
    n.label = !s.label.empty() ? s.label : s.wopts.node != 0 ? std::to_string(s.wopts.node) : n.addr;
    n.hostname_fn = std::move(s.hostname);
    n.id.store(s.wopts.node, std::memory_order_relaxed);  // a fixed expected ID is known from the start
    n.published_id.store(s.wopts.node, std::memory_order_relaxed);  // and is in placement from the start
    n.reported_id_fn = std::move(s.reported_node_id);
    n.id_learned_fn = std::move(s.on_id_learned);
    n.host_learned_fn = std::move(s.on_host_learned);
    n.raw_fab = s.fab;
    n.spec_owner = std::move(s.owner);
    n.wopts = std::move(s.wopts);
    n.wopts.drive = env.drive;
    n.wopts.on_down = [np] { np->ka.kick(); };  // reconnect starts on the keepalive thread, now
    // RL2 / goal 10: the per-rail series and rail log lines carry the node label, ID, hostname and the rail's IP.
    n.wopts.label = n.label;
    n.wopts.hostname = [np] { return node_hostname(*np); };
    if (bundle_mode) {  // MB6b: frames carry the client's epoch / generation; replies show who lags
      n.wopts.stamp = &stamp_word;
      n.wopts.on_reply = [this, np](const WireOptions::ReplyNote& r) { note_reply(*np, r); };
    }
    if (n.wopts.node == 0) n.wopts.on_node_id = [this, np](std::uint32_t id) { return learn_id(*np, id); };
    n.wopts.on_node_hostname = [this, np](const std::string& h) { learn_hostname(*np, h); };
    hook_endpoint_diag(n, n.wopts);  // G09, L13, Q03
    n.copts = copts;
    bind_dyn(n, std::move(s.on_dyn));
    if (multi) {
      n.copts.registry = &reg;
      n.copts.node_label = n.label;
    }
    n.conflict_ctr = &reg.counter("miracache_client_node_id_conflicts_total",
                                  "HELLO_ACKs refused because another memory node already has that node ID.",
                                  {{"node", n.label}});
    n.mismatch_ctr = &reg.counter("miracache_client_node_id_mismatch_total",
                                  "HELLO_ACK node IDs that differ from the node ID in the admin ticket answer.",
                                  {{"node", n.label}});
  }
  // The identity series of a node with a fixed ID.
  void bind_identity_series(Node& n, int value) {
    if (n.wopts.node == 0) return;
    n.info_gauge = &reg.gauge("miracache_client_node_info",
                              "Memory node identity as the client knows it; the value is 1 once the node is in placement.",
                              {{"node", n.label}, {"node_id", std::to_string(n.wopts.node)},
                               {"hostname", host_or_unknown(n)},
                               {"addr", n.addr}, {"zone", n.zone}});
    n.info_gauge.load()->set(value);
  }

  // Fills free slot `i` with bundle node `nv`; `active` is set last. No thread of the slot runs yet.
  Status activate_slot(std::size_t i, const control::NodeView& nv, bool stage_push) {
    if (!make_spec) return Error{ErrorCode::InvalidArgument, "client: no make_spec"};
    Expected<Client::NodeSpec> sp = [&]() -> Expected<Client::NodeSpec> {
      std::lock_guard lk(spec_mu);  // HR3b: a rebuilding keepalive thread calls it too
      return make_spec(nv);
    }();
    if (!sp) return sp.error();
    Client::NodeSpec s = std::move(*sp);
    if (!s.fab) return Error{ErrorCode::InvalidArgument, "client: bad node spec"};
    s.weight = std::max<std::uint32_t>(1, nv.weight);
    s.zone = nv.zone.value_or(std::string());
    s.wopts.node = nv.node_id;  // the bundle's ID; HELLO_ACK must carry exactly this
    // Review w3b Z04 (spec 1.1 goal 10: ID + hostname + IP in all telemetry): the bundle is authoritative for the
    // hostname. The node's own source (the admin ticket answer) has nothing before its first answer, and the identity
    // series is created below, before any ticket I/O.
    if (!nv.hostname.empty() || !s.hostname) s.hostname = [h = nv.hostname] { return h; };
    Node& n = *nodes[i];
    n.id.store(0, std::memory_order_relaxed);
    n.published_id.store(0, std::memory_order_relaxed);
    n.hello_attempt = ~std::uint64_t{0};
    n.conflict_logged = 0;
    n.info_gauge.store(nullptr);
    n.info_next.store(nullptr);
    n.build_streak = 0;
    n.build_next = Nanos{0};
    n.release_until = Nanos{0};
    n.view = nv;  // HR3b: a planned rebuild makes its fresh NodeSpec from it (the tick thread; it does not run yet)
    n.rebuild_due = Nanos{0};
    n.rebuild_streak = 0;
    init_node(n, std::move(s), base_copts, /*multi=*/true);
    n.hostname = nv.hostname;
    {
      std::lock_guard lk(slots_mu);  // the pusher thread reads it
      n.bundle_admin = nv.admin;
      ++n.incarnation;
      n.aead_start = aead_counter(n.label).value();  // U2-14: this incarnation reports AEAD failures from here
      // Review w4 V14: reset with the incarnation, under the lock the pusher's post-push update takes.
      n.push_wanted.store(false, std::memory_order_relaxed);
      n.push_ok_gen.store(0, std::memory_order_relaxed);
      n.push_fails.store(0, std::memory_order_relaxed);
      n.push_next.store(0, std::memory_order_relaxed);
    }
    n.bundle_rail = nv.rails.empty() ? std::string() : nv.rails[0].addr;
    n.pin_refs.store(0, std::memory_order_relaxed);
    bind_slot_metrics(i, n);
    bind_identity_series(n, 0);
    if (stage_push && !nv.admin.empty() && push_fn) {
      n.stage_push = [this, admin = nv.admin] { return push_fn(admin); };
    } else {
      n.stage_push = nullptr;
    }
    n.slot_state.store(1, std::memory_order_release);
    {  // S03: the count and the ID map change together, so a caller that sees the slot also sees it counted
      std::lock_guard lk(slots_mu);
      live_nodes.fetch_add(1, std::memory_order_acq_rel);
      slot_by_id[nv.node_id] = i;
    }
    n.active.store(true, std::memory_order_release);
    return {};
  }
  void start_slot_thread(Node& n) {
    if (slot_keepalive_ms == 0) return;
    if (!n.thread_started) {
      n.thread_started = true;
      Node* np = &n;
      n.ka.start(slot_keepalive_ms, [this, np] { keepalive_tick(*np); });
    }
    n.ka.kick();
  }
  static bool node_up(const Node& n) {
    const PairPtr p = n.pin_pair();
    return p && p->wire && p->wire->session_up();
  }

  // Publishes the placement of `body`: one atomic snapshot {epoch, current view, R, generation} (membership thread).
  void publish_bundle(const control::BodyView& body) {
    auto s = std::make_shared<PlaceSnap>();
    s->bundle = true;
    s->generation = body.generation;
    s->replicas = std::clamp<unsigned>(body.replicas, 1u, 3u);
    const View v = control::view_from_bundle(body);
    s->view.epoch = v.epoch;
    std::set<std::size_t> in_view;
    std::string left_out;  // V12: the bundle nodes without a slot (comma-separated IDs)
    for (const PlaceNode& pn : v.nodes) {
      const auto id = static_cast<std::uint32_t>(std::stoul(pn.id));
      auto it = slot_by_id.find(id);
      if (it == slot_by_id.end() || nodes[it->second]->slot_state.load(std::memory_order_acquire) != 1) {
        left_out += (left_out.empty() ? "" : ",") + pn.id;
        continue;
      }
      s->view.nodes.push_back(pn);
      s->places.push_back(pn);
      s->idx.push_back(it->second);
      s->pins.push_back(std::make_shared<PinTok>(nodes[it->second]->pin_refs));
      in_view.insert(it->second);
    }
    // MB7: every node of `nodes` that has a slot is a read candidate for the previous set; pinned like the current view.
    for (const control::NodeView& nv : body.nodes) {
      auto it = slot_by_id.find(nv.node_id);
      if (it == slot_by_id.end() || nodes[it->second]->slot_state.load(std::memory_order_acquire) != 1) continue;
      s->slot_of_id[nv.node_id] = it->second;
      if (!in_view.count(it->second)) s->pins.push_back(std::make_shared<PinTok>(nodes[it->second]->pin_refs));
    }
    s->previous_epoch = body.previous_epoch;
    if (!body.previous.empty()) {
      s->prev_view.epoch = body.previous_epoch;
      for (const control::PreviousNodeView& p : body.previous)
        s->prev_view.nodes.push_back(PlaceNode{std::to_string(p.node_id), p.weight, p.zone.value_or(std::string())});
      if (!prev_seen || prev_epoch_seen != body.previous_epoch) {  // the age of a previous view starts when this client first sees it
        prev_seen = true;
        prev_epoch_seen = body.previous_epoch;
        prev_seen_at = env.clock->now();
      }
      s->prev_until = sat_add(prev_seen_at, std::chrono::milliseconds(dyn()->previous_view_ms));
    }
    if (!applied_prev_set || applied_prev_epoch != body.previous_epoch) {  // all hints are void when previous_epoch changes
      applied_prev_set = true;
      applied_prev_epoch = body.previous_epoch;
      (void)hints.clear();
    }
    for (std::size_t i = 0; i < nodes.size(); ++i) {
      Node& n = *nodes[i];
      if (n.slot_state.load(std::memory_order_acquire) != 1) continue;  // retiring slots keep their series until teardown
      if (auto* g = n.info_gauge.load()) g->set(in_view.count(i) ? 1 : 0);
    }
    if (!left_out.empty()) {
      s->full = v;
      if (gap_logged_gen != body.generation) {  // once per generation (a retry publishes the same one again)
        gap_logged_gen = body.generation;
        mlog(log::Level::Error,
             "bundle nodes have no slot; left out of placement: root puts the memory nodes place on them are skipped "
             "(miracache_client_put_skipped_total{reason=\"not_owner\"})",
             {{"node_ids", left_out}, {"generation", std::to_string(body.generation)}});
      }
    }
    {
      std::lock_guard lk(place_mu);
      snap.store(std::shared_ptr<const PlaceSnap>(std::move(s)), std::memory_order_release);
    }
    applied_epoch.store(body.epoch, std::memory_order_release);
    applied_gen.store(body.generation, std::memory_order_release);
    stamp_word.store((static_cast<std::uint64_t>(body.epoch) << 32) | static_cast<std::uint32_t>(body.generation),
                     std::memory_order_release);
  }

  // Applies one verified bundle (membership thread; or the open thread with `initial`, which builds in place).
  // `retry` (Y06, review w3b Z06): the applied bundle again, for its pending nodes only; nodes whose backoff has not run
  // out wait, and a retry that sets up nothing changes nothing (no publish, no log line).
  Status apply(const MembershipSnapPtr& snapp, bool initial, bool retry = false) {
    const control::BodyView& body = snapp->view.body;
    if (body.nodes.size() > Client::kMaxNodes) {
      mlog(log::Level::Error, "bundle has more nodes than the node table holds; not applied",
           {{"generation", std::to_string(body.generation)}, {"nodes", std::to_string(body.nodes.size())}});
      return Error{ErrorCode::ResourceExhausted, "client: bundle has more than kMaxNodes nodes"};
    }
    if (!retry) (void)apply_bundle_config(body);  // HR2: a rejected config keeps the old snapshot; the membership still applies
    const Nanos now = RealClock().now();
    std::set<std::uint32_t> want;
    std::vector<std::size_t> staged;
    std::map<std::uint32_t, PendingNode> still;  // the nodes this bundle leaves out; they replace `pend`
    // Keeps `nv` pending. `failed`: one more failed set-up (its backoff doubles, up to kRetryMaxMs). The error is logged
    // only when it differs from the one logged last for this node (same admin and rail).
    auto keep_pending = [&](const control::NodeView& nv, const std::string& rail0, const char* msg, std::string err,
                            bool failed, bool log_it = true) {
      PendingNode p;
      if (auto it = pend.find(nv.node_id); it != pend.end() && it->second.admin == nv.admin && it->second.rail == rail0)
        p = it->second;
      p.admin = nv.admin;
      p.rail = rail0;
      if (failed) {
        ++p.streak;
        const std::uint64_t ms = std::min<std::uint64_t>(kRetryMaxMs, std::uint64_t{kRetryMinMs} << std::min(p.streak - 1, 16u));
        p.due = now + std::chrono::milliseconds(ms);
      }
      if (err != p.last_err) {
        if (log_it)
          mlog(log::Level::Error, msg,
             {{"node_id", std::to_string(nv.node_id)}, {"hostname", nv.hostname}, {"admin", nv.admin}, {"error", err},
              {"generation", std::to_string(body.generation)}});
        p.last_err = std::move(err);
      }
      still[nv.node_id] = std::move(p);
    };
    for (const control::NodeView& nv : body.nodes) {
      want.insert(nv.node_id);
      const std::string rail0 = nv.rails.empty() ? std::string() : nv.rails[0].addr;
      std::size_t old = kNoSlot;  // Y04: the slot this node had under another admin or rail
      if (auto it = slot_by_id.find(nv.node_id); it != slot_by_id.end()) {
        Node& n = *nodes[it->second];
        if (n.bundle_admin == nv.admin && n.bundle_rail == rail0) {
          if (n.slot_state.load(std::memory_order_acquire) == 2) {  // back before its slot was torn down: revive in place
            n.slot_state.store(1, std::memory_order_release);
            retiring.erase(std::remove(retiring.begin(), retiring.end(), it->second), retiring.end());
            nlog(log::Level::Info, n, "retiring node is back in the bundle; kept");
          }
          continue;
        }
        old = it->second;
      }
      if (auto it = pend.find(nv.node_id); retry && it != pend.end() && now < it->second.due) {  // still backing off
        still[nv.node_id] = it->second;
        continue;
      }
      // Y04: the same node_id at another admin or rail gets a new slot, so the old wire is never reused for a different
      // address. The old slot keeps serving until the new one is set up, then retires.
      const std::size_t i = free_slot();
      if (i == kNoSlot) {
        keep_pending(nv, rail0, "node table full; node pending until a slot frees up", "node table full", false);
        continue;
      }
      fabric::clear_local_failure();  // Q6: make_spec opens the node's fabric (its CQ): a local device limit shows here
      if (Status st = activate_slot(i, nv, /*stage_push=*/!initial); !st) {
        // Q6: a local device resource failure is logged once (with the call, errno and a hint) and counted per attempt
        // by note_endpoint_failure; the generic pending line stays for every other set-up failure.
        const bool local = fabric::last_local_failure().call &&
                           note_endpoint_failure(fail_key(nv.node_id, rail0), nv.node_id, nv.hostname, rail0, 0, std::string(), st.error());
        keep_pending(nv, rail0, "cannot set up a bundle node; pending, retried with backoff",
                     st.error().context ? st.error().context : "?", true, /*log_it=*/!local);
        continue;
      }
      if (old != kNoSlot) {
        Node& o = *nodes[old];
        nlog(log::Level::Info, o, "admin or rail changed; rebuilding in a new slot", {{"new_admin", nv.admin}, {"new_rail", rail0}});
        if (o.slot_state.load(std::memory_order_acquire) == 1) {
          o.slot_state.store(2, std::memory_order_release);
          retiring.push_back(old);
        }
      }
      staged.push_back(i);
    }
    pend = std::move(still);
    retry_snap = pend.empty() ? nullptr : snapp;
    if (retry && staged.empty()) return {};
    Status first_err{};
    if (initial) {  // the open: connect now, serially, with the default timeouts; the others retry on their threads
      for (std::size_t i : staged) {
        Node& n = *nodes[i];
        // Review w3b Z01: the ticket source's first batch (its draw() never does I/O), as a node's thread does before
        // each first build. On the open thread: nothing else runs yet.
        prepare_tickets(n, n.wopts);
        Status st = build(n, /*background=*/false);
        if (st) {
          ++initial_up;
        } else {
          if (first_err) first_err = st;
          note_id_mismatch(n, st.error());
          note_build_failure(n, st.error());
        }
      }
      if (initial_up < staged.size()) {  // Q15, as the static open: retried inside the open until Env::open_settle
        std::vector<Node*> ns;
        for (std::size_t i : staged) ns.push_back(nodes[i].get());
        initial_up += settle_first_builds(ns);
      }
      // R20 (review s11): a transient failure of every node is retried in the settle like one of N-1; the open fails
      // only if none came up by its end.
      if (initial_up == 0 && !staged.empty()) return first_err.error();
      std::string waiting;  // the staged nodes still down, and the nodes whose slot could not be set up
      for (std::size_t i : staged)
        if (!nodes[i]->pin_pair()) add_pending(waiting, nodes[i]->wopts.node, host_or_unknown(*nodes[i]), nodes[i]->addr);
      for (const control::NodeView& nv : body.nodes)
        if (pend.count(nv.node_id))
          add_pending(waiting, nv.node_id, nv.hostname.empty() ? std::string("unknown") : nv.hostname, nv.admin);
      log_open_result(initial_up, body.nodes.size(), waiting);
    } else if (!staged.empty()) {  // stage: push, connect (the node threads do it), wait, then swap
      for (std::size_t i : staged) start_slot_thread(*nodes[i]);
      const Nanos until = env.clock->now() + std::chrono::milliseconds(connect_wait_ms);
      auto all_up = [&] {
        for (std::size_t i : staged)
          if (!node_up(*nodes[i])) return false;
        return true;
      };
      while (!all_up() && env.clock->now() < until && !is_stopping()) {
        if (slot_keepalive_ms == 0)  // no node threads (tests): tick the staged nodes here
          for (std::size_t i : staged) keepalive_tick(*nodes[i]);
        if (env.drive) {
          SimTurn turn(this);
          env.drive();
        } else {
          pause_for(std::chrono::milliseconds(2));
        }
      }
      for (std::size_t i : staged)
        if (!node_up(*nodes[i]))
          nlog(log::Level::Warn, *nodes[i], "added node is not Up after the connect wait; published anyway",
               {{"generation", std::to_string(body.generation)}});
    }
    publish_bundle(body);
    bool any_retired = false;
    for (std::size_t i = 0; i < nodes.size(); ++i) {  // retire: absent from `nodes`, whatever the views say (Q08)
      Node& n = *nodes[i];
      if (n.slot_state.load(std::memory_order_acquire) != 1 || want.count(n.wopts.node)) continue;
      n.slot_state.store(2, std::memory_order_release);
      retiring.push_back(i);
      nlog(log::Level::Info, n, "node left the bundle; retiring (waits for the jobs inside)",
           {{"generation", std::to_string(body.generation)}});
      any_retired = true;
    }
    if (any_retired) {  // MB7 (P04): retiring a node drops every hint
      const std::size_t dropped = hints.clear();
      if (dropped && hint_ctr[kHintDropRetire]) hint_ctr[kHintDropRetire]->inc(dropped);
    }
    mlog(log::Level::Info, "membership applied",
         {{"generation", std::to_string(body.generation)}, {"epoch", std::to_string(body.epoch)},
          {"nodes", std::to_string(body.nodes.size())}, {"added", std::to_string(staged.size())},
          {"pending", std::to_string(pend.size())}});
    return {};
  }

  // Tears down a retiring slot whose last user is gone (membership thread). The order matters: the node's thread
  // leaves its tick first (`active` off, a build or connect in flight is aborted), the replicator drains and joins,
  // then the endpoints go back to the fabric before the core unmaps its landing pool (Q06), then the slot is Free.
  void teardown_slot(std::size_t i) {
    Node& n = *nodes[i];
    n.active.store(false, std::memory_order_release);
    {
      std::lock_guard lk(build_mu);
      if (n.building) n.building->abort_connect();
    }
    if (const PairPtr p = n.pin_pair(); p && p->wire) p->wire->abort_connect();
    { std::lock_guard tl(n.tick_mu); }  // a tick in flight is over; later ticks see !active
    if (i < repl.size() && repl[i]) {
      repl[i]->request_stop();
      repl[i]->stop();  // queued legs run cancelled; nothing can push any more (no snapshot names this slot)
      std::lock_guard lk(slots_mu);
      repl[i].reset();
    }
    // The pool series read the landing pool at scrape time: handed over or zeroed before the pool dies (Z02).
    release_pool_series(i);
    PairPtr p, op;
    {  // MB7: from here the reporter thread no longer looks at this slot's pair
      std::lock_guard rl(n.report_mu);
      p = n.pair.exchange(nullptr, std::memory_order_acq_rel);
      op = n.old_pair.exchange(nullptr, std::memory_order_acq_rel);  // HR3b: a pair a planned rebuild was retiring
    }
    if (p || op) {  // HR3a: no job pins them (pin_refs and their jobs_inside are 0), the tick and the reporter are out
      SimTurn turn(this);
      if (op) op->close(Nanos{0});
      if (p) p->close(Nanos{0});
      op.reset();
      p.reset();
    }
    {
      std::size_t me = i;  // HR3b: the slot's rebuild token, if it held it
      if (rebuild_slot.compare_exchange_strong(me, kNoSlot, std::memory_order_acq_rel)) token_given_back(n);  // F09
    }
    n.rebuild_due = Nanos{0};
    n.rebuild_streak = 0;
    // Z05: this slot's identity series goes to 0, unless another slot of the node has the very same series (a rebuild
    // with the same rail, hostname and zone): that one is in use and keeps its value. Membership thread only.
    if (auto* g = n.info_gauge.exchange(nullptr)) {
      bool shared = false;
      for (std::size_t k = 0; k < nodes.size(); ++k)
        shared = shared || (k != i && nodes[k]->slot_state.load(std::memory_order_acquire) != 0 && nodes[k]->info_gauge.load() == g);
      if (!shared) g->set(0);
    }
    {  // fail-slow: the breaker goes back to closed with the slot; its series too, unless another slot of the node uses it
      bool shared = false;
      for (std::size_t k = 0; k < nodes.size(); ++k)
        shared = shared || (k != i && nodes[k]->slot_state.load(std::memory_order_acquire) != 0 && nodes[k]->brk.g_state == n.brk.g_state);
      if (shared) n.brk.g_state = nullptr;  // no job pins this slot: nothing reads it until bind_slot_metrics sets it again
      brk_reset(n);
    }
    nlog(log::Level::Info, n, "retired node's slot is free");
    n.id.store(0, std::memory_order_release);
    n.published_id.store(0, std::memory_order_release);
    n.stage_push = nullptr;
    const auto node_id = n.wopts.node;  // its ID map entry goes in the final step below (wopts is reset before it)
    // Z09: the closures hold the node's ticket source (whose jitter pointer points into spec_owner) and the raw fabric
    // pointer is spec_owner's: both go before it. The slot thread never reads them while `active` is off.
    n.wopts = WireOptions{};
    n.on_dyn = nullptr;  // HR2: it holds the ticket source too
    n.seen_dyn.reset();
    n.hostname_fn = nullptr;
    n.reported_id_fn = nullptr;
    n.id_learned_fn = nullptr;
    n.host_learned_fn = nullptr;
    {
      std::lock_guard hk(n.wire_host_mu);
      n.wire_host.clear();
    }
    n.host_conflict_logged.store(false);
    n.raw_fab = nullptr;
    n.spec_owner.reset();  // the fabric, ticket source and jitter of this node go with it (after wire and core)
    {
      // One step under slots_mu once the slot is fully torn down (run #278): the state goes Free, the slot leaves the ID
      // map and the count. So node_count()/slots_in_use() drop together with slot_of(id) < 0 (S03) and with
      // slot_retiring() going false; no reader sees a slot counted free while it is still retiring.
      // The pusher copies a slot's admin and log fields under slots_mu only while the slot is in use, so no refill
      // (activate_slot, which writes those fields while the slot is Free) can overlap that copy.
      std::lock_guard lk(slots_mu);
      n.slot_state.store(0, std::memory_order_release);
      auto m = slot_by_id.find(node_id);
      if (m != slot_by_id.end() && m->second == i) slot_by_id.erase(m);
      live_nodes.fetch_sub(1, std::memory_order_acq_rel);  // after the state store: an acquire load of it sees state 0
    }
  }
  void reap_retired() {
    for (auto it = retiring.begin(); it != retiring.end();) {
      Node& n = *nodes[*it];
      // No published snapshot names the slot (so no job or queued replica leg does): the pin count is 0.
      if (n.pin_refs.load(std::memory_order_acquire) != 0 || jobs_inside(n) != 0) {
        ++it;
        continue;
      }
      teardown_slot(*it);
      it = retiring.erase(it);
    }
  }
  void mgr_tick() {
    if (is_stopping()) return;
    reap_retired();
    MembershipSnapPtr s;
    {
      std::lock_guard lk(mgr_mu);
      s = std::move(pending);
      pending.reset();
    }
    if (s && s->generation() > applied_gen.load(std::memory_order_acquire)) {
      (void)apply(s, /*initial=*/false);
    } else if (retry_snap && free_slot() != kNoSlot && RealClock().now() >= next_retry()) {  // Y06/Z06: pending nodes
      (void)apply(MembershipSnapPtr(retry_snap), /*initial=*/false, /*retry=*/true);
    }
    // A retire is polled fast; a pending node is retried when its backoff is over (at least kRetryMinMs from now).
    unsigned wait = 0;
    if (!retiring.empty()) {
      wait = 20;
    } else if (retry_snap) {
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(next_retry() - RealClock().now()).count();
      wait = static_cast<unsigned>(std::clamp<long long>(ms, kRetryMinMs, kRetryMaxMs));
    }
    mgr.next_in(wait);
  }
  void stop_membership() noexcept {
    if (bundle_mode) {
      std::lock_guard lk(build_mu);
      stopping = true;  // an apply in its connect wait and a node's build in flight give up
    }
    if (watcher) watcher->stop();
    pusher.stop();
    if (cancel_reports_fn) cancel_reports_fn();  // U2-27: a report in flight gives up, so the join below is prompt
    reporter.stop();
    mgr.stop();
    std::lock_guard lk(mgr_mu);
    pending.reset();
  }

  void discarded(Ticket, const Job& job) noexcept override {
    if (job.keys.empty()) return;
    std::lock_guard lk(req_mu);
    reqs.erase(job.keys[0] >> 20);
  }

  // jobs_inside of one node, held by RAII (the reconnect waits for it to reach 0).
  struct Inside {
    std::atomic<int>* c = nullptr;
    void enter(std::atomic<int>& a) {
      a.fetch_add(1);
      c = &a;
    }
    void leave() {
      if (c) c->fetch_sub(1);
      c = nullptr;
    }
    ~Inside() { leave(); }
  };
  // HR3b: pins `nd`'s active pair and counts the caller inside it (wire pairs; a loopback pair has no count). A pair that a
  // planned rebuild retired between the load and the count is let go again and the node's new active pair is pinned
  // instead: the swap stores the new pointer before it sets `retired` (seq_cst, like the count), so the reload sees it,
  // and the retire waits for a count of 0 after setting it. The caller has not touched the old pair. Null: no pair.
  static PairPtr enter_pair(const Node& nd, Inside& inside) {
    for (;;) {
      PairPtr p = nd.pin_pair();
      if (!p || !p->wire) return p;
      inside.enter(p->jobs_inside);
      if (!p->retired.load()) return p;
      inside.leave();
    }
  }

  // A2.10 replicas. replicas == 1 is exactly the old path (run_one on the owner). With replicas > 1 a read
  // (lookup, fetch) is one leg on the first ready and Up node of the placement order. A store depends on the mode:
  //   sync:  one leg per ready and Up node of the set, the job waits for every leg (run_store_legs);
  //   async: the job runs ONE leg (the first ready and Up node); the plaintext is copied into a bounded
  //          client-owned pool first and the replicator (one thread per node, never a Runtime worker) writes the
  //          other legs from that copy under the job's original deadline (run_store_async).
  unsigned replicas = 1;
  // HR2: the mode and the pool bound are class A; a job reads them from the snapshot (mode_now / repl_cap).
  ReplicaMode mode_now() const { return dyn()->replica_mode; }
  static constexpr const char* kLegResult[5] = {"committed", "refused", "cancelled", "skipped_down", "skipped_full"};
  enum LegResult { kLegCommitted, kLegRefused, kLegCancelled, kLegSkippedDown, kLegSkippedFull };
  std::vector<std::array<telemetry::Counter*, 5>> leg_ctr;  // [node][LegResult]
  std::vector<telemetry::Counter*> failover_ctr;            // [node]
  // Async replicator state. r9b T10: the pool counts the ALLOCATED size of the copies that are queued or being written
  // (BufPool::cap_of: the size class), and idle buffers are kept only in the room the copies in flight leave, so the
  // copies use at most `replica_buffer_bytes` in all.
  // Review r9 S02: besides the global count each node has its own count of the bytes queued or running for it, with a
  // share of the pool, so one hung node cannot make the healthy nodes' replicas skipped_full.
  std::atomic<std::size_t> repl_cap{0};  // = the snapshot's replica_buffer_bytes (the pool's own bound; set with it)
  std::atomic<std::size_t> repl_used{0};
  std::atomic<bool> repl_stopping{false};
  std::unique_ptr<std::atomic<std::size_t>[]> repl_node_used;       // [node]
  std::unique_ptr<std::atomic<Nanos::rep>[]> repl_head_deadline;     // [node] deadline of the leg running now (0 = none)
  // Review r9 S03: the copies are recycled buffers that are not zero-filled (a fresh std::vector was malloc + memset +
  // memcpy on the engine worker). Size classes are powers of two. r9b T10: idle buffers are kept up to half the pool and
  // only in the room the copies in flight leave; the oldest idle buffer of any class is freed first, so a change of
  // block size does not leave the idle list full of a class nobody asks for.
  struct BufPool {
    struct Buf {
      std::unique_ptr<std::byte[]> p;
      std::size_t cap = 0;
    };
    struct Idle {
      std::unique_ptr<std::byte[]> p;
      std::uint64_t seq = 0;  // age: smaller = older
    };
    std::mutex mu;
    std::array<std::deque<Idle>, 48> free_list;  // per size class, back = newest
    std::uint64_t seq = 0;
    std::size_t idle = 0, idle_max = 0;
    std::size_t cap = 0;                              // replica_buffer_bytes
    const std::atomic<std::size_t>* used = nullptr;  // the copies in flight (repl_used)
    static unsigned cls(std::size_t bytes) {
      unsigned c = 12;  // 4 KiB minimum
      while ((std::size_t{1} << c) < bytes) ++c;
      return c;
    }
    static std::size_t cap_of(std::size_t bytes) { return std::size_t{1} << cls(bytes); }
    std::size_t room() const {  // idle bytes allowed next to the copies in flight
      const std::size_t u = used ? used->load(std::memory_order_acquire) : 0;
      return std::min(idle_max, u >= cap ? std::size_t{0} : cap - u);
    }
    // Moves the oldest idle buffer of any class to `out` (caller holds mu; freed after unlock). False: none left.
    bool evict_oldest(std::vector<std::unique_ptr<std::byte[]>>& out) {
      int best = -1;
      for (unsigned c = 0; c < free_list.size(); ++c)
        if (!free_list[c].empty() && (best < 0 || free_list[c].front().seq < free_list[static_cast<unsigned>(best)].front().seq))
          best = static_cast<int>(c);
      if (best < 0) return false;
      auto& q = free_list[static_cast<unsigned>(best)];
      out.push_back(std::move(q.front().p));
      q.pop_front();
      idle -= std::size_t{1} << best;
      return true;
    }
    Buf get(std::size_t bytes) {
      const unsigned c = cls(bytes);
      std::vector<std::unique_ptr<std::byte[]>> drop;  // freed after the unlock
      {
        std::lock_guard lk(mu);
        auto& v = free_list[c];
        if (!v.empty()) {
          Buf b{std::move(v.back().p), std::size_t{1} << c};
          v.pop_back();
          idle -= b.cap;
          return b;
        }
        const std::size_t r = room();
        while (idle > r && evict_oldest(drop)) {
        }
      }
      return Buf{std::make_unique_for_overwrite<std::byte[]>(std::size_t{1} << c), std::size_t{1} << c};
    }
    void put(Buf&& b) {
      if (!b.p) return;
      std::vector<std::unique_ptr<std::byte[]>> drop;
      std::lock_guard lk(mu);
      const std::size_t r = room();
      if (b.cap > r) return;  // freed by the owner
      while (idle + b.cap > r && evict_oldest(drop)) {
      }
      idle += b.cap;
      free_list[cls(b.cap)].push_back(Idle{std::move(b.p), ++seq});
    }
  };
  BufPool repl_bufs;
  std::vector<std::unique_ptr<TaskThread>> repl;  // [node]; empty unless async replication is on

  void init_replicas(unsigned r, ReplicaMode m, std::size_t buffer_bytes) {
    replicas = r;
    (void)m;  // HR2: the mode and the bound come from the snapshot (init_dyn); the replicator exists whatever they are
    repl_cap = buffer_bytes;
    if (r <= 1) return;
    for (auto& n : nodes) {
      std::array<telemetry::Counter*, 5> a{};
      for (int i = 0; i < 5; ++i)
        a[static_cast<std::size_t>(i)] = &reg.counter("miracache_client_replica_legs_total",
                                                      "Per-node store legs of a replicated store, by result.",
                                                      {{"node", n->label}, {"result", kLegResult[i]}});
      leg_ctr.push_back(a);
      failover_ctr.push_back(&reg.counter("miracache_client_read_failover_total",
                                          "Reads served by a node other than the primary of the scope.",
                                          {{"node", n->label}}));
    }
    {  // replica_buffer_bytes = 0 with async: replicas off, decided per job (run)
      repl_node_used = std::make_unique<std::atomic<std::size_t>[]>(nodes.size());
      repl_head_deadline = std::make_unique<std::atomic<Nanos::rep>[]>(nodes.size());
      repl_bufs.idle_max = buffer_bytes / 2;
      repl_bufs.cap = buffer_bytes;
      repl_bufs.used = &repl_used;
      for (std::size_t i = 0; i < nodes.size(); ++i) repl.push_back(std::make_unique<TaskThread>());
    }
  }
  // Drains or cancels the replicator before the nodes go away: queued legs are dropped (counted cancelled), a
  // running leg is cancelled and force-failed if it does not drain in a second. Idempotent.
  void stop_replicator() noexcept {
    repl_stopping.store(true, std::memory_order_release);
    for (auto& t : repl)
      if (t) t->request_stop();  // S12: signal all first, then join: a hung leg delays only its own join
    for (auto& t : repl)
      if (t) t->stop();
  }
  std::atomic<std::size_t> live_nodes{0};  // bundle mode: slots in use (the per-node share of the replica pool)
  // Bundle mode: counters and replicator arrays for kMaxNodes slots, whatever R is now (R changes with a bundle).
  // The replicator threads and the per-node counters are made when a slot is filled.
  void init_replicas_slots(ReplicaMode m, std::size_t buffer_bytes) {
    (void)m;
    repl_cap = buffer_bytes;
    leg_ctr.assign(Client::kMaxNodes, std::array<telemetry::Counter*, 5>{});
    failover_ctr.assign(Client::kMaxNodes, nullptr);
    repl.resize(Client::kMaxNodes);
    {  // HR2: always present, so a live switch to async (or a bigger bound) has what it needs
      repl_node_used = std::make_unique<std::atomic<std::size_t>[]>(Client::kMaxNodes);
      repl_head_deadline = std::make_unique<std::atomic<Nanos::rep>[]>(Client::kMaxNodes);
      repl_bufs.idle_max = buffer_bytes / 2;
      repl_bufs.cap = buffer_bytes;
      repl_bufs.used = &repl_used;
    }
  }
  // Per-slot series and the replicator of a slot that is being filled (membership thread; no pin on the slot exists).
  void bind_slot_metrics(std::size_t i, Node& n) {
    for (int k = 0; k < 5; ++k)
      leg_ctr[i][static_cast<std::size_t>(k)] =
          &reg.counter("miracache_client_replica_legs_total", "Per-node store legs of a replicated store, by result.",
                       {{"node", n.label}, {"result", kLegResult[k]}});
    failover_ctr[i] = &reg.counter("miracache_client_read_failover_total",
                                   "Reads served by a node other than the primary of the scope.", {{"node", n.label}});
    bind_brk_metrics(n);  // and a closed breaker for the new occupant
    if (repl_node_used) {
      repl_node_used[i].store(0, std::memory_order_relaxed);
      repl_head_deadline[i].store(0, std::memory_order_relaxed);
      std::lock_guard lk(slots_mu);
      repl[i] = std::make_unique<TaskThread>();
    }
  }
  std::mutex slots_mu;  // the replicator vector and slot_by_id against the test hooks (workers read repl[] by pin)
  // A node a job may pick: it has a pair, its session is Up and its breaker takes an op now.
  bool usable(const Node& n) const {
    const PairPtr p = n.pin_pair();
    return p && (!p->wire || (p->wire->session_up() && !brk_rejects(n)));
  }
  // The session is Up but the breaker refuses the node now (a store skipped for it is Skipped, not Refused).
  bool brk_blocked(const Node& n) const {
    const PairPtr p = n.pin_pair();
    return p && p->wire && p->wire->session_up() && brk_rejects(n);
  }

  // ---- the breaker (see Brk) ----
  std::atomic<std::uint64_t> brk_fast_n{0};  // jobs the breaker completed at once (tests)
  // Latency bins: 0 = under 1 us, then two per octave: [2^k, 1.5 * 2^k) and [1.5 * 2^k, 2^(k+1)) us.
  static int brk_bin(Nanos lat) {
    const long long c = std::chrono::duration_cast<std::chrono::microseconds>(lat).count();
    if (c < 1) return 0;
    const auto us = static_cast<std::uint64_t>(c);
    const int k = static_cast<int>(std::bit_width(us)) - 1;
    const int upper = us >= (std::uint64_t{3} << k) / 2 ? 1 : 0;
    return std::min(kBrkBins - 1, 1 + 2 * k + upper);
  }
  static std::int64_t brk_bin_us(int b) {  // the upper edge of bin b (the value a quantile in it reports)
    if (b <= 0) return 1;
    const int k = (b - 1) / 2;
    return (b - 1) % 2 ? std::int64_t{1} << (k + 1) : std::max<std::int64_t>(1, (std::int64_t{3} << k) / 2);
  }
  static Nanos brk_sublen(const ClientDyn& d) {
    return std::max<Nanos>(std::chrono::milliseconds(1), std::chrono::milliseconds(d.breaker_window_ms) / kBrkSubs);
  }
  // Lock-free: would the breaker refuse an op on `n` now (Open before open_until, or Half-open with every probe out)?
  bool brk_rejects(const Node& n) const {
    const int s = n.brk.state.load(std::memory_order_acquire);
    if (s == kBrkClosed) return false;
    const ClientDynPtr d = dyn();
    if (!d->breaker_enabled) return false;
    if (s == kBrkOpen) return env.clock->now().count() < n.brk.open_until.load(std::memory_order_acquire);
    return n.brk.probes_in.load(std::memory_order_acquire) >= static_cast<int>(d->breaker_probes);
  }
  // The median p99 (us) of the other nodes in use whose breaker is closed and whose p99 is fresh (-1: none).
  std::int64_t brk_peer_median(const Node& self, Nanos now, const ClientDyn& d) const {
    std::vector<std::int64_t> v;
    const Nanos::rep fresh = std::chrono::duration_cast<Nanos>(std::chrono::milliseconds(d.breaker_window_ms)).count();
    for (const auto& np : nodes) {
      const Node& m = *np;
      if (&m == &self || (bundle_mode && m.slot_state.load(std::memory_order_acquire) != 1)) continue;
      if (m.brk.state.load(std::memory_order_acquire) != kBrkClosed) continue;
      const std::int64_t p = m.brk.p99_us.load(std::memory_order_acquire);
      if (p < 0 || now.count() - m.brk.p99_at.load(std::memory_order_acquire) > fresh) continue;
      v.push_back(p);
    }
    if (v.empty()) return -1;
    std::sort(v.begin(), v.end());
    const std::size_t h = v.size() / 2;
    return v.size() % 2 ? v[h] : (v[h - 1] + v[h]) / 2;
  }
  // The outlier bound (us): latencies at or above it are slow. Max = no reference node (then only deadline misses count).
  std::int64_t brk_bound(const Node& n, Nanos now, const ClientDyn& d) const {
    const std::int64_t med = brk_peer_median(n, now, d);
    if (med < 0) return std::numeric_limits<std::int64_t>::max();
    return std::max<std::int64_t>(d.breaker_floor_us, med * static_cast<std::int64_t>(d.breaker_p99_factor));
  }
  // Caller holds n.brk.mu.
  void brk_set(Node& n, int s, log::Level lvl, std::string_view msg, std::initializer_list<log::Field> extra = {}) {
    n.brk.state.store(s, std::memory_order_release);
    if (n.brk.g_state) n.brk.g_state->set(s);
    nlog(lvl, n, msg, extra);
  }
  void brk_clear_window(Brk& b) {  // caller holds b.mu
    for (auto& s : b.sub) s = Brk::Sub{};
    b.next_eval = Nanos{0};
    b.p99_us.store(-1, std::memory_order_release);
  }
  void brk_open(Node& n, Nanos now, const ClientDyn& d, int reason, std::initializer_list<log::Field> extra) {
    Brk& b = n.brk;  // caller holds b.mu
    const std::uint64_t ms = std::min<std::uint64_t>(d.breaker_open_max_ms,
                                                     std::uint64_t{d.breaker_open_ms} << std::min(b.reopen, 20u));
    b.open_until.store(sat_add(now, std::chrono::milliseconds(ms)).count(), std::memory_order_release);
    b.probes_in.store(0, std::memory_order_release);
    b.probe_ok = 0;
    if (b.trips[reason]) b.trips[reason]->inc();
    // nlog's fields (client_host, node_id, hostname, addr), then the trip's own.
    std::vector<log::Field> f;
    f.emplace_back("client_host", log::hostname());
    f.emplace_back("node_id", id_text(n));
    f.emplace_back("hostname", host_or_unknown(n));  // F5: "unknown" until the hostname is known
    f.emplace_back("addr", n.addr);
    for (const auto& e : extra) f.push_back(e);
    f.emplace_back("reason", reason == 0 ? "slow" : "probe_failed");
    f.emplace_back("open_ms", std::to_string(ms));
    b.state.store(kBrkOpen, std::memory_order_release);
    if (b.g_state) b.g_state->set(kBrkOpen);
    log::write(log::Level::Warn, "client",
               reason == 0 ? "circuit breaker open: memory node is slow (fail-slow); its reads miss and its stores are "
                             "skipped until probes succeed; drain it or lower its weight"
                           : "circuit breaker re-opened: a half-open probe was slow",
               std::span<const log::Field>(f));
  }
  void brk_reset(Node& n) {  // a slot being filled (no job pins it) or an open
    std::lock_guard lk(n.brk.mu);
    brk_clear_window(n.brk);
    n.brk.state.store(kBrkClosed, std::memory_order_release);
    n.brk.open_until.store(0, std::memory_order_release);
    n.brk.probes_in.store(0, std::memory_order_release);
    n.brk.probe_ok = 0;
    n.brk.reopen = 0;
    if (n.brk.g_state) n.brk.g_state->set(kBrkClosed);
  }
  void bind_brk_metrics(Node& n) {  // the slot is not in use (open, or a slot being filled)
    bind_brk_series(n, /*zero_old=*/false);  // the old pointer may be another slot's series now
    brk_reset(n);
  }
  // F08 (goal 10): the breaker series carry node_id, hostname and addr, as the rail series. Bound when the slot is
  // filled (bundle mode: the bundle's ID and hostname) and again when a learn-mode node's ID changes (learn_id); the
  // series of the previous identity goes to 0 and the new one takes the current state. Takes n.brk.mu.
  void bind_brk_series(Node& n, bool zero_old) {
    const std::uint32_t id = node_id_of(n);
    const std::string ids = id ? std::to_string(id) : std::string("unknown");
    const std::string hn = node_hostname(n), host = hn.empty() ? std::string("unknown") : hn;  // F3 (S2): never ""
    telemetry::Gauge* g = &reg.gauge("miracache_client_breaker_state",
                                     "Per-node circuit breaker (fail-slow): 0 closed, 1 open, 2 half-open.",
                                     {{"node", n.label}, {"node_id", ids}, {"hostname", host}, {"addr", n.addr}});
    telemetry::Counter* t[2];
    for (int k = 0; k < 2; ++k)
      t[k] = &reg.counter("miracache_client_breaker_trips_total",
                          "Per-node circuit breaker trips to open, by reason (slow: the fail-slow outlier rule; "
                          "probe_failed: a half-open probe was slow).",
                          {{"node", n.label}, {"node_id", ids}, {"hostname", host}, {"addr", n.addr},
                           {"reason", k == 0 ? "slow" : "probe_failed"}});
    telemetry::Gauge* stale_g = nullptr;  // H08: the "unknown" series a learned ID replaces (hidden after the lock)
    telemetry::Counter* stale_t[2] = {};
    {
      std::lock_guard lk(n.brk.mu);
      if (zero_old && n.brk.g_state && n.brk.g_state != g) {
        n.brk.g_state->set(0);
        if ((n.brk.series_id == "unknown" && ids != "unknown") || (n.brk.series_host == "unknown" && host != "unknown")) {
          stale_g = n.brk.g_state;
          for (int k = 0; k < 2; ++k) stale_t[k] = n.brk.trips[k] != t[k] ? n.brk.trips[k] : nullptr;
        }
      }
      n.brk.g_state = g;
      n.brk.series_id = ids;
      n.brk.series_host = host;
      g->set(n.brk.state.load(std::memory_order_acquire));
      for (int k = 0; k < 2; ++k) n.brk.trips[k] = t[k];
    }
    // brk.mu stays a leaf lock: the registry's lock is taken only after it.
    if (stale_g) reg.hide(stale_g);
    for (auto* c : stale_t) reg.hide(c);
  }
  // Admission of one op on `n`'s wire (session Up).
  Admit brk_admit(Node& n) {
    Brk& b = n.brk;
    if (b.state.load(std::memory_order_acquire) == kBrkClosed) return Admit::Pass;
    const ClientDynPtr d = dyn();
    std::lock_guard lk(b.mu);
    const int s = b.state.load(std::memory_order_relaxed);
    if (s == kBrkClosed) return Admit::Pass;
    if (!d->breaker_enabled) {
      b.probes_in.store(0, std::memory_order_release);
      brk_clear_window(b);
      brk_set(n, kBrkClosed, log::Level::Info, "circuit breaker closed: breaker.enabled is false");
      return Admit::Pass;
    }
    const Nanos now = env.clock->now();
    if (s == kBrkOpen) {
      if (now.count() < b.open_until.load(std::memory_order_relaxed)) return Admit::Reject;
      b.probe_ok = 0;
      b.probes_in.store(0, std::memory_order_release);
      brk_set(n, kBrkHalfOpen, log::Level::Info, "circuit breaker half-open: probing the memory node",
              {{"probes", std::to_string(d->breaker_probes)}});
    }
    if (b.probes_in.load(std::memory_order_relaxed) >= static_cast<int>(d->breaker_probes)) return Admit::Reject;
    b.probes_in.fetch_add(1, std::memory_order_acq_rel);
    return Admit::Probe;
  }
  // One op that ran on `n`'s wire under admission `a`: its core submit `t0`, its deadline, whether the caller cancelled it
  // (not judged). Judges the window (Closed) or the probe (Half-open).
  void brk_record(Node& n, Admit a, Nanos t0, Nanos deadline, bool cancelled) {
    if (a == Admit::Reject) return;
    const ClientDynPtr dp = dyn();
    const ClientDyn& d = *dp;
    Brk& b = n.brk;
    const Nanos now = env.clock->now();
    const bool miss = now >= deadline && t0 < deadline;
    const Nanos lat = now - t0;
    const auto lat_us = std::chrono::duration_cast<std::chrono::microseconds>(lat).count();
    std::lock_guard lk(b.mu);
    if (a == Admit::Probe) {
      if (b.probes_in.load(std::memory_order_relaxed) > 0) b.probes_in.fetch_sub(1, std::memory_order_acq_rel);
      if (b.state.load(std::memory_order_relaxed) == kBrkHalfOpen && !cancelled) {
        const std::int64_t bound = brk_bound(n, now, d);
        if (miss || lat_us >= bound) {
          ++b.reopen;
          brk_open(n, now, d, 1,
                   {{"latency_us", std::to_string(lat_us)}, {"deadline_miss", miss ? "true" : "false"},
                    {"bound_us", bound == std::numeric_limits<std::int64_t>::max() ? std::string("none") : std::to_string(bound)}});
          return;
        }
        if (++b.probe_ok >= d.breaker_probes) {
          b.reopen = 0;
          b.probes_in.store(0, std::memory_order_release);
          brk_clear_window(b);
          brk_set(n, kBrkClosed, log::Level::Info, "circuit breaker closed: probes succeeded",
                  {{"probes", std::to_string(b.probe_ok)}});
          return;
        }
      }
    }
    if (cancelled || !d.breaker_enabled || b.state.load(std::memory_order_relaxed) != kBrkClosed) return;
    const Nanos sublen = brk_sublen(d);
    const std::int64_t idx = now.count() / sublen.count();
    Brk::Sub& s = b.sub[static_cast<std::size_t>(idx % kBrkSubs)];
    if (s.idx != idx) {
      s = Brk::Sub{};
      s.idx = idx;
    }
    ++s.ops;
    s.misses += miss ? 1 : 0;
    ++s.h[static_cast<std::size_t>(brk_bin(lat))];
    if (!miss && now < b.next_eval) return;
    b.next_eval = now + sublen;
    // Judge the window (the buckets of the last window_ms).
    std::uint64_t ops = 0, misses = 0;
    std::array<std::uint64_t, kBrkBins> h{};
    for (const auto& w : b.sub) {
      if (w.idx < 0 || w.idx <= idx - kBrkSubs) continue;
      ops += w.ops;
      misses += w.misses;
      for (int i = 0; i < kBrkBins; ++i) h[static_cast<std::size_t>(i)] += w.h[static_cast<std::size_t>(i)];
    }
    if (ops < d.breaker_min_ops) {
      b.p99_us.store(-1, std::memory_order_release);
      return;
    }
    const std::uint64_t want = (ops * 99 + 99) / 100;  // the 99th percentile's rank (ceil)
    std::uint64_t acc = 0;
    int bin = kBrkBins - 1;
    for (int i = 0; i < kBrkBins; ++i) {
      acc += h[static_cast<std::size_t>(i)];
      if (acc >= want) {
        bin = i;
        break;
      }
    }
    const std::int64_t p99 = brk_bin_us(bin);
    b.p99_us.store(p99, std::memory_order_release);
    b.p99_at.store(now.count(), std::memory_order_release);
    if (misses < d.breaker_min_misses || misses * 100 < std::uint64_t{d.breaker_miss_pct} * ops) return;
    const std::int64_t bound = brk_bound(n, now, d);
    if (p99 < bound) return;  // not an outlier (also: no reference node)
    b.reopen = 0;
    brk_open(n, now, d, 0,
             {{"p99_us", std::to_string(p99)}, {"bound_us", std::to_string(bound)}, {"ops", std::to_string(ops)},
              {"deadline_misses", std::to_string(misses)}, {"window_ms", std::to_string(d.breaker_window_ms)}});
  }
  // A job the breaker refused: reads miss (a fetch zeroes its buffers, as a miss does), stores are Skipped.
  void brk_fast(const Req& r, std::vector<KeyStatus>& status, bool replica, bool* fast) {
    if (r.kind == 1)
      for (const auto& b : r.bufs)
        if (!b.buf.empty()) std::memset(b.buf.data(), 0, b.buf.size());
    status.assign(status.size(), r.kind == 2 ? KeyStatus::Skipped : KeyStatus::Miss);
    if (!replica) brk_fast_n.fetch_add(1, std::memory_order_relaxed);
    if (fast) *fast = true;  // a replica leg that never ran counts as skipped_down
  }
  void count_leg(std::size_t idx, const std::vector<KeyStatus>& st, bool cancelled) {
    bool committed = false;
    for (auto s : st) committed = committed || s == KeyStatus::Committed;
    leg_ctr[idx][committed ? kLegCommitted : cancelled ? kLegCancelled : kLegRefused]->inc();
  }

  void run(Ticket, const Job& job, const JobControl& ctl, std::vector<KeyStatus>& status) noexcept override {
    if (job.keys.empty()) return;
    Req r;
    {
      std::lock_guard lk(req_mu);
      auto it = reqs.find(job.keys[0] >> 20);
      if (it == reqs.end()) return;
      r = std::move(it->second);
      reqs.erase(it);
    }
    std::vector<KeyRef> keys(r.raw.size());
    for (std::size_t i = 0; i < keys.size(); ++i) keys[i] = KeyRef{r.raw[i], r.parent[i], r.pos[i]};
    if (bundle_mode) return run_bundle(r, keys, ctl, status);
    const auto dy = dyn();  // HR2: one snapshot per job
    const unsigned R = dy->replica_mode == ReplicaMode::Async && dy->replica_buffer_bytes == 0 ? 1u : replicas;  // bound 0: replicas off
    if (R <= 1 || nodes.size() == 1 || r.group >= r.sk.scopes.size()) return run_one(owner(r), r, keys, ctl, status);
    const auto snp = snapshot();
    if (snp->places.empty()) return run_one(*nodes[0], r, keys, ctl, status);
    auto order = place_order(snp->places, std::span<const std::uint8_t, 32>(r.sk.scopes[r.group].b), R);
    for (auto& k : order) k = snp->idx[k];  // snapshot index -> node index
    run_ordered(order, nullptr, r, keys, ctl, status);
  }

  // MB6a: the placement snapshot is read ONCE per job; the copy keeps every slot it names alive (Node::pin) until the
  // job (and any replica leg it queued) is done, so a retire or a slot reuse cannot pull a node out from under it.
  // R and the node order come from the bundle (owner_set over the bundle's current view).
  //
  // MB7 (decision 9, P04, Q08, P31): the previous view.
  //   previous set  owner_set over the FULL previous view, then filtered to nodes that are still in `nodes` (have a slot).
  //   hint          per scope: "use the previous set", tagged with previous_epoch. A hint whose filtered set is empty (or
  //                 whose previous view has aged out) is dropped.
  //   reads         hinted: the previous set first; keys[0] not hit there -> drop the hint, current set, same job.
  //                 else: the current set (first Up node), then, on a keys[0] miss, the previous set's other nodes; a hit
  //                 there sets the hint.
  //   stores        root batch: current set, drops the hint. Continuation: the hinted previous set, else the current set;
  //                 Refused at the current set (parent unknown) falls through to the previous set in the same job.
  void run_bundle(Req& r, const std::vector<KeyRef>& keys, const JobControl& ctl, std::vector<KeyStatus>& status) {
    const auto snp = snapshot();
    if (snp->places.empty() || r.group >= r.sk.scopes.size()) {  // no owner at all: fail fast, as a node that is down
      status.assign(status.size(), r.kind == 2 ? KeyStatus::Refused : KeyStatus::Miss);
      fast_failed.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    unsigned R = std::clamp(snp->replicas, 1u, 3u);
    if (const auto dy = dyn(); dy->replica_mode == ReplicaMode::Async && dy->replica_buffer_bytes == 0) R = 1;  // replica_buffer_bytes = 0: replicas off
    const std::span<const std::uint8_t, 32> scope(r.sk.scopes[r.group].b);
    auto order = owner_set(snp->view, scope, R);
    for (auto& k : order) k = snp->idx[k];  // view index -> slot
    const bool prev_alive = !snp->prev_view.nodes.empty() && env.clock->now() < snp->prev_until;
    const HintCache::Key hkey(reinterpret_cast<const char*>(r.sk.scopes[r.group].b), 32);
    std::vector<std::size_t> prev;
    bool prev_ready = false;
    auto get_prev = [&]() -> const std::vector<std::size_t>& {
      if (!prev_ready) {
        prev_ready = true;
        if (prev_alive) prev = previous_set(*snp, scope, R);
      }
      return prev;
    };
    bool hinted = false;
    if (hints.any()) {
      bool voided = false;
      if (hints.get(hkey, snp->previous_epoch, voided)) {
        if (!prev_alive || get_prev().empty()) {  // Q08: nothing left to use
          (void)hints.drop(hkey);
          hint_ctr[kHintDropEmpty]->inc();
        } else {
          hinted = true;
        }
      } else if (voided) {
        hint_ctr[kHintVoidEpoch]->inc();
      }
    }
    auto single_or_set = [&](const std::vector<std::size_t>& set, std::vector<KeyStatus>& st) {
      if (set.size() <= 1) return run_one(*nodes[set.empty() ? snp->idx[0] : set[0]], r, keys, ctl, st);
      run_ordered(set, snp, r, keys, ctl, st);
    };

    if (r.kind == 2) {  // ---- stores ----
      const bool root = keys[0].parent_raw.empty();
      if (root) {  // a root batch goes to the current owner set and drops the hint
        if (hints.drop(hkey)) hint_ctr[kHintDropRoot]->inc();
        count_gap_skips(*snp, r, order, R);  // V12
        return single_or_set(order, status);
      }
      if (hinted) {
        std::vector<KeyStatus> t = status;
        single_or_set(prev, t);
        if (t[0] != KeyStatus::Refused) {
          // V08: Skipped here is a previous node that left the membership (or skips the put): the parent went with it,
          // so the current set (parent unknown) cannot do better. Final, and the hint is void.
          if (t[0] == KeyStatus::Skipped && hints.drop(hkey)) hint_ctr[kHintDropMiss]->inc();
          status = std::move(t);
          return;
        }
        if (hints.drop(hkey)) hint_ctr[kHintDropMiss]->inc();  // not there: the current set, same job
      }
      single_or_set(order, status);
      if (!hinted && status[0] == KeyStatus::Refused && prev_alive) {
        const auto& p = get_prev();
        if (!p.empty() && p != order) {
          std::vector<KeyStatus> t = status;
          single_or_set(p, t);
          if (t[0] != KeyStatus::Refused) {
            prev_store_ctr->inc();
            if (t[0] == KeyStatus::Committed) {
              hints.set(hkey, snp->previous_epoch);
              hint_ctr[kHintSet]->inc();
            }
            status = std::move(t);
          }
        }
      }
      return;
    }

    // ---- reads (lookup, fetch) ----
    std::vector<std::size_t> tried;
    std::vector<KeyStatus> last;  // the result of the last previous-set node that ran and did not hit
    auto was_tried = [&](std::size_t i) { return std::find(tried.begin(), tried.end(), i) != tried.end(); };
    // Runs the read on each usable, untried node of the previous set until keys[0] hits. True: `status` is that hit.
    // A fetch writes every buffer it is given (the bytes of a hit, zeros for a miss), so the statuses a job reports
    // must be those of the node that wrote the buffers last (review w5 U2-01). Nodes of the current set are left out
    // (U2-23): the current-set read answers for them.
    auto read_prev = [&]() -> bool {
      for (std::size_t i : get_prev()) {
        if (was_tried(i) || !usable(*nodes[i])) continue;
        if (std::find(order.begin(), order.end(), i) != order.end()) continue;  // U2-23
        tried.push_back(i);
        std::vector<KeyStatus> t = status;
        run_one(*nodes[i], r, keys, ctl, t);
        if (t[0] == KeyStatus::Hit) {
          status = std::move(t);
          return true;
        }
        last = std::move(t);
      }
      return false;
    };
    bool prev_done = false;
    if (hinted) {
      prev_done = true;
      if (read_prev()) {
        prev_hit_ctr->inc();
        return;
      }
      if (!tried.empty()) {  // it ran and keys[0] was not there: drop the hint, fall through (same job)
        if (hints.drop(hkey)) hint_ctr[kHintDropMiss]->inc();
      }
    }
    std::size_t pick = order[0];
    for (std::size_t i : order)
      if (usable(*nodes[i])) {
        pick = i;
        break;
      }
    if (pick != order[0]) failover_ctr[pick]->inc();
    if (was_tried(pick) && !last.empty()) {
      status = std::move(last);  // the previous set already answered for this node
      return;
    }
    run_one(*nodes[pick], r, keys, ctl, status);
    tried.push_back(pick);
    if (!prev_done && status[0] == KeyStatus::Miss && prev_alive && !get_prev().empty()) {
      std::vector<KeyStatus> cur = status;  // read_prev overwrites `status` only on a hit
      const std::size_t ran_before = tried.size();
      if (read_prev()) {
        hints.set(hkey, snp->previous_epoch);
        hint_ctr[kHintSet]->inc();
        prev_hit_ctr->inc();
      } else if (r.kind == 1 && tried.size() > ran_before) {
        // U2-01 (P0): a previous-set node ran after the current one and rewrote the buffers (zeros or its own bytes):
        // its statuses describe them, the current node's no longer do. A key the current node hit is now a miss.
        status = std::move(last);
      } else {
        status = std::move(cur);  // a lookup (no buffers), or no previous node ran
      }
    }
  }

  // The previous owner set of a scope as slots: over the full previous view, then filtered to nodes still in `nodes`.
  std::vector<std::size_t> previous_set(const PlaceSnap& s, std::span<const std::uint8_t, 32> scope, unsigned R) const {
    std::vector<std::size_t> out;
    for (std::size_t k : owner_set(s.prev_view, scope, R)) {
      const auto id = static_cast<std::uint32_t>(std::stoul(s.prev_view.nodes[k].id));
      auto it = s.slot_of_id.find(id);
      if (it != s.slot_of_id.end()) out.push_back(it->second);
    }
    return out;
  }

  // The part of a job shared by static and bundle mode: `order` is the replica set as slot indexes, best first.
  void run_ordered(const std::vector<std::size_t>& order, const std::shared_ptr<const PlaceSnap>& pin, Req& r,
                   const std::vector<KeyRef>& keys, const JobControl& ctl, std::vector<KeyStatus>& status) {
    if (r.kind != 2) {  // reads: the first usable node of the set; none usable -> the primary's fast path
      std::size_t pick = order[0];
      for (std::size_t i : order)
        if (usable(*nodes[i])) {
          pick = i;
          break;
        }
      if (pick != order[0]) failover_ctr[pick]->inc();
      return run_one(*nodes[pick], r, keys, ctl, status);
    }
    if (mode_now() == ReplicaMode::Async) return run_store_async(order, pin, r, keys, ctl, status);
    run_store_legs(order, r, keys, ctl, status);
  }

  // ---- async replicas ----
  // The plaintext of one store job, copied before the engine's leg starts, plus everything a leg needs. Shared by
  // the replica legs of the job; the pool bytes come back when the last leg lets go of it.
  struct ReplJob {
    Req req;  // keys, scope, group, deadline; req.bufs point into `data`
    BufPool::Buf data;
    BufPool* pool = nullptr;
    std::vector<KeyRef> keys;
    std::size_t bytes = 0;  // the allocated size counted against the pool (T10)
    std::atomic<std::size_t>* used = nullptr;
    std::shared_ptr<const PlaceSnap> pin;  // bundle mode: keeps the slots of the snapshot alive until the leg is gone
    ~ReplJob() {
      if (used) used->fetch_sub(bytes, std::memory_order_acq_rel);  // first: the idle list may use the room it leaves
      if (pool) pool->put(std::move(data));
    }
  };
  // The bytes one queued or running leg holds against its node's share; given back when the leg is dropped or ends.
  struct NodeShare {
    std::atomic<std::size_t>* c;
    std::size_t bytes;
    NodeShare(std::atomic<std::size_t>* cc, std::size_t b) : c(cc), bytes(b) {}
    NodeShare(const NodeShare&) = delete;
    NodeShare& operator=(const NodeShare&) = delete;
    ~NodeShare() { c->fetch_sub(bytes, std::memory_order_acq_rel); }
  };
  bool repl_reserve(std::size_t bytes) {
    std::size_t cur = repl_used.load(std::memory_order_relaxed);
    do {
      if (bytes > repl_cap || cur > repl_cap - bytes) return false;
    } while (!repl_used.compare_exchange_weak(cur, cur + bytes, std::memory_order_acq_rel));
    return true;
  }
  // S02: a node may hold at most its share of the pool (an empty node always accepts one copy, so a block larger
  // than the share still replicates; the global bound still applies). r9b T09: a hard share of cap/N would shrink every
  // node's queue as N grows, so a node may go over its share while the whole pool stays at most half used (with this
  // copy); the other half is then always left for nodes within their share.
  bool repl_node_reserve(std::size_t idx, std::size_t bytes) {
    const std::size_t share = repl_cap / std::max<std::size_t>(1, bundle_mode ? live_nodes.load(std::memory_order_acquire) : nodes.size());
    auto& u = repl_node_used[idx];
    std::size_t cur = u.load(std::memory_order_relaxed);
    do {
      const bool within_share = cur == 0 || (bytes <= share && cur <= share - bytes);
      const std::size_t g = repl_used.load(std::memory_order_acquire);
      const bool pool_half_free = bytes <= repl_cap / 2 && g <= repl_cap / 2 - bytes;
      if (!within_share && !pool_half_free) return false;
    } while (!u.compare_exchange_weak(cur, cur + bytes, std::memory_order_acq_rel));
    return true;
  }
  // S02: the leg running on this node's replicator is past its deadline (hung, waiting for the watchdog).
  bool repl_node_stalled(std::size_t idx) {
    const Nanos::rep d = repl_head_deadline[idx].load(std::memory_order_acquire);
    return d != 0 && env.clock->now().count() > d;
  }
  // One replica leg on the replicator thread of node `idx`: run_one with the thread as its JobControl, so it obeys
  // the job's original deadline, the not-Up fast path, jobs_inside and the watchdog like an engine leg.
  void replica_leg(std::size_t idx, const std::shared_ptr<ReplJob>& job, const JobControl& ctl) {
    std::vector<KeyStatus> st(job->keys.size(), KeyStatus::Aborted);
    if (ctl.cancelled()) {  // dropped by shutdown before it started
      leg_ctr[idx][kLegCancelled]->inc();
      return;
    }
    // S02: queued behind a leg that hung: the job's deadline passed while it waited, so it can only time out.
    if (env.clock->now() >= job->req.deadline) {
      leg_ctr[idx][kLegCancelled]->inc();
      return;
    }
    // S13: the node went down while the leg waited in the queue: not a refusal by the node.
    if (!usable(*nodes[idx])) {
      leg_ctr[idx][kLegSkippedDown]->inc();
      return;
    }
    repl_head_deadline[idx].store(job->req.deadline.count(), std::memory_order_release);
    bool fast = false;
    run_one(*nodes[idx], job->req, job->keys, ctl, st, /*replica=*/true, &fast);
    repl_head_deadline[idx].store(0, std::memory_order_release);
    if (fast) leg_ctr[idx][kLegSkippedDown]->inc();
    else count_leg(idx, st, ctl.cancelled());
  }

  void run_store_async(const std::vector<std::size_t>& order, const std::shared_ptr<const PlaceSnap>& pin, Req& r,
                       const std::vector<KeyRef>& keys, const JobControl& ctl, std::vector<KeyStatus>& status) {
    std::size_t first = order.size();  // position in `order` of the engine's leg
    std::vector<std::size_t> rest;
    bool brk = false;  // a node was left out by its breaker (fail-slow), not because it is down
    for (std::size_t p = 0; p < order.size(); ++p) {
      const std::size_t i = order[p];
      if (!usable(*nodes[i])) {
        brk = brk || brk_blocked(*nodes[i]);
        leg_ctr[i][kLegSkippedDown]->inc();
      } else if (first == order.size()) {
        first = p;
      } else {
        rest.push_back(i);
      }
    }
    if (first == order.size()) {  // no leg can run: Refused, as a single node that is down; Skipped if a breaker said no
      status.assign(status.size(), brk ? KeyStatus::Skipped : KeyStatus::Refused);
      if (brk) brk_fast_n.fetch_add(1, std::memory_order_relaxed);
      else fast_failed.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    if (!rest.empty()) {
      std::size_t bytes = 0;
      for (const auto& b : r.bufs) bytes += b.buf.size();
      const std::size_t alloc = BufPool::cap_of(bytes);  // r9b T10: what the copy really holds
      if (repl_stopping.load(std::memory_order_acquire)) {
        for (std::size_t i : rest) leg_ctr[i][kLegCancelled]->inc();
      } else {
        // S02: a node whose replicator is stalled, or whose share is used up, gets no copy; the others do.
        std::vector<std::size_t> take;
        for (std::size_t i : rest) {
          if (repl_node_stalled(i) || !repl_node_reserve(i, alloc)) leg_ctr[i][kLegSkippedFull]->inc();
          else take.push_back(i);
        }
        if (!take.empty() && !repl_reserve(alloc)) {
          for (std::size_t i : take) {
            repl_node_used[i].fetch_sub(alloc, std::memory_order_acq_rel);
            leg_ctr[i][kLegSkippedFull]->inc();
          }
          take.clear();
        }
        if (!take.empty()) {
          auto job = std::make_shared<ReplJob>();
          job->bytes = alloc;
          job->used = &repl_used;  // from here on the destructor gives the bytes back
          job->req = r;
          job->pin = pin;
          job->data = repl_bufs.get(bytes);
          job->pool = &repl_bufs;
          job->req.bufs.clear();
          std::size_t off = 0;
          for (const auto& b : r.bufs) {
            if (!b.buf.empty()) std::memcpy(job->data.p.get() + off, b.buf.data(), b.buf.size());
            job->req.bufs.push_back(BufRef{std::span<std::byte>(job->data.p.get() + off, b.buf.size())});
            off += b.buf.size();
          }
          job->keys.resize(job->req.raw.size());
          for (std::size_t k = 0; k < job->keys.size(); ++k)
            job->keys[k] = KeyRef{job->req.raw[k], job->req.parent[k], job->req.pos[k]};
          for (std::size_t i : take) {
            auto share = std::make_shared<NodeShare>(&repl_node_used[i], alloc);
            if (!repl[i] || !repl[i]->push([this, i, job, share](const JobControl& c) { replica_leg(i, job, c); }))
              leg_ctr[i][kLegCancelled]->inc();
          }
        }
      }
    }
    // The engine's leg: exactly the single-node path. The job's Completion fires when it is done.
    const std::size_t i = order[first];
    run_one(*nodes[i], r, keys, ctl, status);
    count_leg(i, status, ctl.cancelled());
  }

  // ---- sync replicas ----
  // One store job over several nodes. The Runtime posts the job's completion when run() returns, and the
  // Client contract is that a Completion means "statuses AND buffers released", so run() stays inside until
  // every leg has finished (or the deadline / watchdog ended it). No two core_mu are ever held together: each
  // visit of a leg is lock, pump, read flags, unlock.
  struct Leg {
    Node* nd = nullptr;
    std::size_t idx = 0;  // node index
    PairPtr pair;   // HR3a: the pair this leg pinned (null: the node had none); declared before `inside`, which counts on it
    Inside inside;
    bool submitted = false, done = false, released = false;  // done, released, st: written by the core callbacks under core_mu
    bool fin = false, seen_done = false, want_cancel = false, cancelled_by_us = false;  // worker-private mirrors
    bool watchdog_fired = false;
    Nanos watchdog_at{0};
    std::vector<KeyStatus> st;
    Ticket ct;
    Admit adm = Admit::Pass;    // the breaker's admission of this leg
    bool brk_skipped = false;   // the breaker refused it (not submitted)
    Nanos t0{0};                // core submit (the breaker's latency)
  };
  void run_store_legs(const std::vector<std::size_t>& order, Req& r, const std::vector<KeyRef>& keys, const JobControl& ctl,
                      std::vector<KeyStatus>& status) {
    std::vector<std::unique_ptr<Leg>> legs;
    legs.reserve(order.size());
    const Nanos deadline = r.deadline;
    for (std::size_t i : order) {
      auto lg = std::make_unique<Leg>();
      lg->nd = nodes[i].get();
      lg->idx = i;
      Node& nd = *lg->nd;
      // Per-leg not-Up fast path (R01): the count goes up before the session check, like a single leg (HR3b: enter_pair).
      lg->pair = enter_pair(nd, lg->inside);
      if (lg->pair) {
        Pair& p = *lg->pair;
        if (p.wire && !p.wire->session_up()) {
          lg->inside.leave();
        } else if (p.wire && (lg->adm = brk_admit(nd)) == Admit::Reject) {  // fail-slow: the breaker skips this leg
          lg->inside.leave();
          lg->brk_skipped = true;
        } else {
          lg->submitted = true;
        }
      }
      if (!lg->submitted) {
        leg_ctr[i][kLegSkippedDown]->inc();
        legs.push_back(std::move(lg));
        continue;
      }
      Leg* l = lg.get();
      Notify n;
      n.done = [l](Ticket, std::span<const KeyStatus> s) {
        l->st.assign(s.begin(), s.end());
        l->done = true;
      };
      n.released = [l](Ticket) { l->released = true; };
      l->watchdog_at = sat_add(deadline, watchdog_grace());
      {
        Pair& p = *l->pair;
        std::lock_guard lk(p.core_mu);
        SimTurn turn(this);
        l->t0 = env.clock->now();
        l->ct = p.core->submit_store(r.sk, r.group, keys, r.bufs, deadline, n);
      }
      legs.push_back(std::move(lg));
    }
    auto live = [&] {
      for (auto& l : legs)
        if (l->submitted && !l->fin) return true;
      return false;
    };
    if (!live()) {  // no leg ran: Refused, as a single node that is down (Skipped if the breaker skipped a node: never failed)
      bool brk = false;
      for (auto& l : legs) brk = brk || l->brk_skipped;
      status.assign(status.size(), brk ? KeyStatus::Skipped : KeyStatus::Refused);
      if (brk) brk_fast_n.fetch_add(1, std::memory_order_relaxed);
      else fast_failed.fetch_add(1, std::memory_order_relaxed);
      return;
    }

    bool cancelled_all = false;
    unsigned idle = 0;
    while (live()) {
      bool progress = false;
      for (auto& lp : legs) {
        Leg& l = *lp;
        if (!l.submitted || l.fin) continue;
        Node& nd = *l.nd;
        Pair& p = *l.pair;
        ClientCore& core = *p.core;
        std::unique_lock lk(p.core_mu);
        SimTurn turn(this);
        // Q05/Q08 per leg: past deadline + grace force-fail this leg and let the worker go.
        if (env.clock->now() >= l.watchdog_at && !l.watchdog_fired) {
          (void)core.pump();  // Q08: take completions already in the CQ first
          // released: fall through to the bookkeeping below
        }
        if (!l.released && env.clock->now() >= l.watchdog_at) {
          const long long late_ms = static_cast<long long>(
              std::chrono::duration_cast<std::chrono::milliseconds>(env.clock->now() - deadline).count());
          const int sess = p.wire ? static_cast<int>(p.wire->session()) : -1;
          if (!l.watchdog_fired) {
            l.watchdog_fired = true;
            const std::size_t out = core.outstanding_ops(l.ct);
            const std::size_t abandoned = core.force_fail(l.ct);
            if (abandoned > 0) wd_trips.fetch_add(1, std::memory_order_relaxed);
            watchdog_fired_log(nd, p, r.kind, late_ms, sess, out, abandoned);
          } else {
            watchdog_still_log(nd, r.kind, late_ms, sess, core.outstanding_ops(l.ct));
          }
          l.watchdog_at = sat_add(env.clock->now(), watchdog_grace());
        }
        if (!l.released && l.want_cancel) {
          core.cancel(l.ct);
          l.want_cancel = false;  // sent
        }
        if (!l.released) progress = core.pump() || progress;
        iterations.fetch_add(1, std::memory_order_relaxed);

        const bool rel = l.released, dn = l.done;
        turn.release();
        lk.unlock();
        if (dn) l.seen_done = true;
        if (rel) {  // this leg no longer holds the node for a reconnect
          l.fin = true;
          if (p.wire) brk_record(nd, l.adm, l.t0, deadline, l.cancelled_by_us);
          l.inside.leave();
        }
      }
      // Cancel policy (no lock held): only the caller cancelling the job cancels legs (sync mode has no grace).
      if (ctl.cancelled() && !cancelled_all) {
        cancelled_all = true;
        for (auto& l : legs)
          if (l->submitted && !l->fin && !l->seen_done) l->want_cancel = l->cancelled_by_us = true;
      }
      if (!live()) break;
      if (env.drive) {
        {
          SimTurn turn(this);
          env.drive();
        }
        continue;
      }
      idle = progress ? 0 : idle + 1;
      if (idle >= 64) ctl.wait_cancel_for(std::chrono::microseconds(500));
      else if (idle >= 16) ctl.wait_cancel_for(std::chrono::microseconds(50));
    }

    // Merge, per key: COMMITTED if any leg committed, else the status of the first leg (set order) that ran
    // and finished on its own; a leg that only ended because we cancelled it counts last.
    const std::size_t nk = status.size();
    for (std::size_t k = 0; k < nk; ++k) {
      bool have = false;
      KeyStatus pick = KeyStatus::Refused;
      bool pick_is_cancelled = true;
      bool committed = false;
      for (auto& l : legs) {
        if (!l->submitted || !l->done || l->st.size() != nk) continue;
        if (l->st[k] == KeyStatus::Committed) committed = true;
        if (!have || (pick_is_cancelled && !l->cancelled_by_us)) {
          pick = l->st[k];
          pick_is_cancelled = l->cancelled_by_us;
          have = true;
        }
      }
      status[k] = committed ? KeyStatus::Committed : have ? pick : KeyStatus::Aborted;
    }
    for (auto& l : legs) {
      if (!l->submitted) continue;
      int res = kLegRefused;
      bool any_committed = false;
      if (l->done)
        for (auto s : l->st) any_committed = any_committed || s == KeyStatus::Committed;
      if (any_committed) res = kLegCommitted;
      else if (l->cancelled_by_us) res = kLegCancelled;
      leg_ctr[l->idx][res]->inc();
    }
  }

  // `replica`: a leg of the async replicator (its JobControl is the replicator thread): not counted as a fast-failed
  // job, and after the thread is told to stop the leg is cancelled and force-failed if it does not drain in 1 s.
  void run_one(Node& nd, Req& r, const std::vector<KeyRef>& keys, const JobControl& ctl, std::vector<KeyStatus>& status,
               bool replica = false, bool* fast = nullptr) {
    // R01 fast path: node not ready or session not Up -> complete now (lookup/fetch MISS, store
    // Refused) without core_mu and without touching the port. Only this node's scopes are affected.
    // `status` belongs to this worker, so no lock is needed.
    // HR3a: the job pins the node's pair once, here, and uses only that pair to the end (declared before `inside`,
    // which counts on it). HR3b: enter_pair skips a pair a planned rebuild has just retired.
    PairPtr pp;
    Inside inside;
    pp = enter_pair(nd, inside);
    auto fail_fast = [&] {
      // Review w4 V08: a node that left the membership (its GOAWAY said Epoch) skips a store, it does not refuse it.
      const bool removed = r.kind == 2 && pp && pp->wire && pp->wire->removed_from_membership();
      status.assign(status.size(), r.kind == 2 ? (removed ? KeyStatus::Skipped : KeyStatus::Refused) : KeyStatus::Miss);
      if (removed && skipped_draining) skipped_draining->inc(status.size());
      if (!replica) fast_failed.fetch_add(1, std::memory_order_relaxed);
      if (fast) *fast = true;  // S13: the caller counts a replica leg that never ran as skipped_down
    };
    if (!pp) return fail_fast();
    Pair& p = *pp;
    ClientCore& core = *p.core;
    // Counted (enter_pair) before the check: the reconnect waits for us once it sees Connecting.
    if (p.wire && !p.wire->session_up()) return fail_fast();
    // Fail-slow: the session is Up but the node's breaker is open (or every half-open probe is out): done at once.
    const Admit adm = p.wire ? brk_admit(nd) : Admit::Pass;
    if (adm == Admit::Reject) return brk_fast(r, status, replica, fast);
    std::unique_lock lk(p.core_mu);
    SimTurn turn(this);  // after core_mu; released around every core_mu hand-off below
    const Nanos t0 = env.clock->now();  // the breaker's latency starts at the core submit
    bool done = false, released = false;
    std::vector<KeyStatus> st;
    Notify n;
    n.done = [&](Ticket, std::span<const KeyStatus> s) {
      st.assign(s.begin(), s.end());
      done = true;
    };
    n.released = [&](Ticket) { released = true; };
    const Nanos deadline = r.deadline;
    Ticket ct;
    if (r.kind == 0) {
      core.probe(r.sk, r.group, keys, deadline, n.done);
      released = true;
    } else if (r.kind == 1) {
      ct = core.submit_fetch(r.sk, r.group, keys, r.bufs, deadline, n);
    } else {
      ct = core.submit_store(r.sk, r.group, keys, r.bufs, deadline, n);
    }
    bool cancel_sent = false, watchdog_fired = false;
    Nanos cancel_seen_at{0};  // replica legs: when the stop was first seen
    unsigned idle = 0;  // consecutive pumps that saw no completion
    Nanos watchdog_at = sat_add(deadline, watchdog_grace());
    while (!released) {
      // Q05: the loop has no deadline of its own. A job whose completions never arrive would keep
      // jobs_inside above zero (the reconnect then never gets quiescence) and Runtime::shutdown() joins
      // this worker forever. Past deadline + grace: log, force-fail the job, let the worker go.
      //
      // N09 (out of scope): force_fail abandons RDMA ops only. A decrypt task that never ends (a wedged
      // executor) writes into the caller's buffer, so the job cannot be released before it does: the worker
      // and jobs_inside stay pinned. The watchdog then re-logs once per grace period so it stays visible.
      if (env.clock->now() >= watchdog_at && !watchdog_fired) {
        // Q08: a worker that was stalled itself (SIGSTOP, VM pause) finds the grace gone with the job's
        // completions waiting in the CQ: take them first, and force-fail only what is still missing.
        (void)core.pump();
        if (released) break;
      }
      if (env.clock->now() >= watchdog_at) {
        const long long late_ms =
            static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(env.clock->now() - deadline).count());
        const int sess = p.wire ? static_cast<int>(p.wire->session()) : -1;
        if (!watchdog_fired) {
          watchdog_fired = true;
          const std::size_t out = core.outstanding_ops(ct);
          const std::size_t abandoned = core.force_fail(ct);
          if (abandoned > 0) wd_trips.fetch_add(1, std::memory_order_relaxed);  // N04: only a real abandon counts
          watchdog_fired_log(nd, p, r.kind, late_ms, sess, out, abandoned);
        } else {
          watchdog_still_log(nd, r.kind, late_ms, sess, core.outstanding_ops(ct));
        }
        watchdog_at = sat_add(env.clock->now(), watchdog_grace());
        if (released) break;
      }
      if (!cancel_sent && ctl.cancelled()) {
        core.cancel(ct);
        cancel_sent = true;
        cancel_seen_at = env.clock->now();
      }
      // Replicator shutdown must not wait for a hung replica: a leg that was told to stop and has not drained in
      // 1 s goes through the watchdog now (force-fail; its spans stay quarantined until the endpoints are reaped).
      if (replica && cancel_sent && !watchdog_fired && env.clock->now() >= sat_add(cancel_seen_at, std::chrono::seconds(1)))
        watchdog_at = env.clock->now();
      const bool progress = core.pump();
      iterations.fetch_add(1, std::memory_order_relaxed);
      if (released) break;
      if (env.drive) {
        env.drive();
        turn.release();
        lk.unlock();  // let other workers in between pumps
        lk.lock();
        turn.acquire();
        continue;
      }
      idle = progress ? 0 : idle + 1;
      turn.release();
      lk.unlock();  // let other workers in; when idle, back off instead of spinning
      if (replica && cancel_sent) pause_for(std::chrono::microseconds(200));  // S12: a stopped controller's wait returns at once; do not spin
      else if (idle >= 64) ctl.wait_cancel_for(std::chrono::microseconds(500));
      else if (idle >= 16) ctl.wait_cancel_for(std::chrono::microseconds(50));
      lk.lock();
      turn.acquire();
    }
    if (p.wire) brk_record(nd, adm, t0, deadline, cancel_sent);
    if (done && st.size() == status.size()) status = std::move(st);
  }
};

// The core holds a reference to the wire (its ServerPort); a rebuilt pair's fabric (owner) goes last. A retired pair of a
// sim client may be let go last by any thread: its core and wire touch the simulated network, so in a sim turn.
Client::Impl::Pair::~Pair() {
  std::optional<SimTurn> turn;
  if (sim) turn.emplace(sim);
  core.reset();
  wire.reset();
  owner.reset();
}

// ---- HR2: live configuration ----------------------------------------------------------------------------------

// The open-time snapshot: from `env.dyn_base` when the caller gives one (the production open), else from the Env, the
// open options and the WireOptions defaults. Also makes the config metrics.
void Client::Impl::init_dyn(const ClientDyn& given) {
  dyn_base = std::make_shared<const ClientDyn>(given);
  dyn_snap.store(dyn_base);
  repl_cap = given.replica_buffer_bytes;
  hints.configure(given.hint_entries);
  cfg_applied = &reg.counter("miracache_config_reload_total", "Configuration reloads by result.", {{"result", "applied"}});
  cfg_rejected = &reg.counter("miracache_config_reload_total", "Configuration reloads by result.", {{"result", "rejected"}});
  cfg_unknown = &reg.counter("miracache_config_unknown_keys_total", "Unknown config.* keys ignored (rolling upgrade).", {});
  cfg_gen = &reg.gauge("miracache_config_generation", "Bundle generation of the configuration in force (0 = open-time).", {});
  cfg_pending = &reg.gauge("miracache_client_config_pending_rebuild_keys",
                           "Class B keys whose wanted value is not running yet (applied at the next rebuild).", {});
}

void Client::Impl::adopt_dyn(Node& n) {
  const ClientDynPtr d = dyn_snap.load();
  if (n.seen_dyn == d) return;
  n.seen_dyn = d;
  n.ka.set_period(d->keepalive_ms);  // 0 (a hand-ticked test client) is ignored
  if (n.on_dyn) n.on_dyn(*d);
  if (const PairPtr p = n.pin_pair(); p && p->on_dyn) p->on_dyn(*d);  // HR3b: a rebuilt pair's own ticket source
}

Status Client::Impl::apply_dyn(ClientDynPtr next, const std::vector<std::string>& unknown) {
  if (!next) return Error{ErrorCode::InvalidArgument, "client: null config"};
  std::vector<std::unique_ptr<std::byte[]>> drop;  // freed after the pool lock
  std::vector<std::string> changed;
  bool class_b = false;
  {
    std::lock_guard lk(dyn_mu);
    const ClientDynPtr cur = dyn_snap.load();
    changed = dyn_changed_keys(*cur, *next);
    class_b = next->subpool_bytes != cur->subpool_bytes || next->mtu != cur->mtu || next->protocol != cur->protocol ||
              next->fetch_qps != cur->fetch_qps;
    dyn_snap.store(next);  // jobs started from now on see it; running ones keep the one they loaded
    if (next->replica_buffer_bytes != cur->replica_buffer_bytes) {
      repl_cap = next->replica_buffer_bytes;
      std::lock_guard bl(repl_bufs.mu);
      repl_bufs.cap = next->replica_buffer_bytes;
      repl_bufs.idle_max = next->replica_buffer_bytes / 2;
      while (repl_bufs.idle > repl_bufs.room() && repl_bufs.evict_oldest(drop)) {
      }
    }
    if (next->hint_entries != cur->hint_entries) hints.configure(next->hint_entries);
    if (next->crypto_workers != cur->crypto_workers && set_crypto_workers) set_crypto_workers(next->crypto_workers);
    cfg_gen->set(static_cast<std::int64_t>(next->generation));
    pending_gauge_locked();  // HR3b: against what the nodes run; it falls as the planned rebuilds go through
  }
  if (class_b)
    for (auto& n : nodes) n->ka.kick();  // HR3b: a class B change is seen at the next tick, not a keepalive period later
  cfg_applied->inc();
  cfg_applied_n.fetch_add(1, std::memory_order_relaxed);
  if (!unknown.empty()) {
    cfg_unknown->inc(unknown.size());
    cfg_unknown_n.fetch_add(unknown.size(), std::memory_order_relaxed);
  }
  if (!changed.empty() || !unknown.empty()) {
    std::string names, unk;
    for (const auto& k : changed) names += (names.empty() ? "" : ",") + k;  // names, never values
    for (const auto& k : unknown) unk += (unk.empty() ? "" : ",") + k;
    std::string pend;
    for (const auto& k : next->pending_rebuild) pend += (pend.empty() ? "" : ",") + k;
    mlog(unknown.empty() ? log::Level::Info : log::Level::Warn,
         unknown.empty() ? "client configuration reloaded" : "client configuration reloaded; unknown keys ignored",
         {{"generation", std::to_string(next->generation)}, {"changed", names}, {"unknown", unk}, {"pending_rebuild", pend}});
  }
  return {};
}

Status Client::Impl::apply_bundle_config(const control::BodyView& body) {
  DynParse p = parse_client_dyn(body.config_toml, *dyn_base, body.generation);
  if (body.unknown_keys > 0) {  // config.* keys outside the known tables (counted by the bundle parser)
    cfg_unknown->inc(body.unknown_keys);
    cfg_unknown_n.fetch_add(body.unknown_keys, std::memory_order_relaxed);
    mlog(log::Level::Warn, "bundle has unknown config.* keys; ignored",
         {{"generation", std::to_string(body.generation)}, {"count", std::to_string(body.unknown_keys)}});
  }
  if (!p.error.empty()) {
    cfg_rejected->inc();
    cfg_rejected_n.fetch_add(1, std::memory_order_relaxed);
    {
      std::lock_guard lk(dyn_mu);
      cfg_last_error = p.error;
    }
    mlog(log::Level::Error, "client configuration rejected; the old one stays",
         {{"generation", std::to_string(body.generation)}, {"reason", p.error}});
    return Error{ErrorCode::InvalidArgument, "client: config rejected"};
  }
  return apply_dyn(std::move(p.dyn), p.unknown);
}

Status Client::apply_config(ClientDynPtr next) { return impl_ ? impl_->apply_dyn(std::move(next), {}) : Status(Error{ErrorCode::InvalidArgument, "client: closed"}); }
Status Client::apply_config_toml(std::string_view config_toml, std::uint64_t generation) {
  if (!impl_) return Error{ErrorCode::InvalidArgument, "client: closed"};
  control::BodyView b;
  b.generation = generation;
  b.config_toml = std::string(config_toml);
  return impl_->apply_bundle_config(b);
}
ClientDynPtr Client::dyn() const { return impl_ ? impl_->dyn() : nullptr; }
std::uint64_t Client::config_applied() const { return impl_ ? impl_->cfg_applied_n.load(std::memory_order_relaxed) : 0; }
std::uint64_t Client::config_rejected() const { return impl_ ? impl_->cfg_rejected_n.load(std::memory_order_relaxed) : 0; }
std::uint64_t Client::config_unknown_keys() const { return impl_ ? impl_->cfg_unknown_n.load(std::memory_order_relaxed) : 0; }
std::string Client::config_last_error() const {
  if (!impl_) return {};
  std::lock_guard lk(impl_->dyn_mu);
  return impl_->cfg_last_error;
}
int Client::keepalive_period_ms(std::size_t slot) const {
  if (!impl_ || slot >= impl_->nodes.size()) return 0;
  return static_cast<int>(impl_->nodes[slot]->ka.period());
}

// The open-time snapshot of a caller that gave no `dyn_base` (tests, embedders): what its Env and options say.
static ClientDyn dyn_from_env(const Client::Env& env, unsigned keepalive_ms, const WireOptions& w, unsigned previous_view_ms,
                              std::size_t hint_entries) {
  ClientDyn d;
  d.keepalive_ms = keepalive_ms;
  d.reconnect_min_ms = w.reconnect_min_ms;
  d.reconnect_max_ms = w.reconnect_max_ms;
  d.reconnect_connect_ms = w.reconnect_connect_ms;
  d.watchdog_grace_ms = static_cast<std::uint32_t>(std::max<long long>(
      1, std::chrono::duration_cast<std::chrono::milliseconds>(env.watchdog_grace).count()));
  d.slice_bytes = env.slice_bytes;
  d.put_max_ms = env.put_max_ms;
  d.replica_mode = env.replica_mode;
  d.replica_buffer_bytes = env.replica_buffer_bytes;
  d.previous_view_ms = previous_view_ms;
  d.hint_entries = static_cast<std::uint32_t>(hint_entries);
  d.mtu = w.mtu;
  return d;
}

Client::Client() = default;
Client::~Client() {
  if (impl_) {
    impl_->stop_membership();  // the watcher callback and the slot manager first
    impl_->stop_keepalive();   // before the runtime and core go away
    impl_->stop_replicator();
  }
  if (rt_) rt_->shutdown();
}

void Client::shutdown() noexcept {
  if (impl_) {
    impl_->stop_membership();
    impl_->stop_keepalive();
    impl_->stop_replicator();
  }
  rt_->shutdown();
}
void Client::keepalive_tick() {
  if (!impl_) return;
  for (auto& n : impl_->nodes) impl_->keepalive_tick(*n);  // bundle mode: a free or retiring slot is skipped
}
std::uint64_t Client::keepalive_ticks() const {
  std::uint64_t t = 0;
  if (impl_)
    for (auto& n : impl_->nodes) t += n->ka_ticks.load(std::memory_order_relaxed);
  return t;
}

std::uint64_t Client::fast_failed_jobs() const { return impl_ ? impl_->fast_failed.load(std::memory_order_relaxed) : 0; }
std::uint64_t Client::breaker_fast_jobs() const { return impl_ ? impl_->brk_fast_n.load(std::memory_order_relaxed) : 0; }
int Client::breaker_state(std::size_t slot) const {
  if (!impl_ || slot >= impl_->nodes.size()) return -1;
  return impl_->nodes[slot]->brk.state.load(std::memory_order_acquire);
}
std::uint64_t Client::watchdog_trips() const { return impl_ ? impl_->wd_trips.load(std::memory_order_relaxed) : 0; }
std::size_t Client::replicator_pending() const {
  std::size_t n = 0;
  if (impl_) {
    std::lock_guard lk(impl_->slots_mu);
    for (auto& t : impl_->repl)
      if (t) n += t->pending();
  }
  return n;
}
std::size_t Client::replica_buffer_in_use() const { return impl_ ? impl_->repl_used.load(std::memory_order_acquire) : 0; }

// Client::open (production) lives in wire_open.cpp.

Expected<std::unique_ptr<Client>> Client::open_wire(const Env& env, WireOptions wopts, std::shared_ptr<void> adopt,
                                                    const ClientCoreOptions& copts, const RuntimeOptions& ropts) {
  if (!env.fab) return Error{ErrorCode::InvalidArgument, "client: incomplete Env"};
  std::vector<NodeSpec> one(1);
  one[0].fab = env.fab;
  one[0].wopts = std::move(wopts);
  return open_wire_nodes(env, std::move(one), std::move(adopt), copts, ropts);
}

Expected<std::unique_ptr<Client>> Client::open_wire_nodes(const Env& env, std::vector<NodeSpec> specs,
                                                          std::shared_ptr<void> adopt, const ClientCoreOptions& copts,
                                                          const RuntimeOptions& ropts) {
  if (!env.clock || !env.executor || !env.salts || specs.empty())
    return Error{ErrorCode::InvalidArgument, "client: incomplete Env"};
  for (std::size_t i = 0; i < specs.size(); ++i) {
    if (!specs[i].fab || specs[i].weight == 0) return Error{ErrorCode::InvalidArgument, "client: bad node spec"};
    for (std::size_t j = 0; j < i; ++j) {
      // Nonzero = a fixed expected ID (sim, tests); production specs have 0 and learn the ID from HELLO_ACK.
      if (specs[i].wopts.node != 0 && specs[i].wopts.node == specs[j].wopts.node)
        return Error{ErrorCode::InvalidArgument, "client: duplicate node id"};
      const auto &a = specs[i].wopts.rail, &b = specs[j].wopts.rail;
      if (a.port != 0 && a.port == b.port && a.host == b.host)
        return Error{ErrorCode::InvalidArgument, "client: duplicate node address"};
    }
  }
  if (env.replicas < 1 || env.replicas > 3) return Error{ErrorCode::InvalidArgument, "client: replicas must be 1..3"};
  if (env.replicas > 1 && specs.size() < static_cast<std::size_t>(env.replicas) + 1)
    return Error{ErrorCode::InvalidArgument, "client: replicas > 1 needs at least replicas + 1 nodes"};
  {
    std::size_t zoned = 0;
    std::vector<std::string> zones;
    for (const auto& s : specs) {
      zoned += !s.zone.empty();
      if (std::find(zones.begin(), zones.end(), s.zone) == zones.end()) zones.push_back(s.zone);
    }
    if (zoned != 0 && zoned != specs.size()) return Error{ErrorCode::InvalidArgument, "client: zone must be set on every node or on none"};
    if (zoned != 0 && env.replicas > zones.size())
      return Error{ErrorCode::InvalidArgument, "client: replicas needs nodes in at least that many zones"};
  }
  std::unique_ptr<Client> c(new Client());
  c->keep_ = std::move(adopt);
  c->impl_ = std::make_unique<Impl>();
  Impl* impl = c->impl_.get();
  impl->env = env;
  impl->init_dyn(env.dyn_base ? *env.dyn_base : dyn_from_env(env, specs[0].wopts.keepalive_ms, specs[0].wopts, 3600000, 65536));
  impl->set_crypto_workers = env.set_crypto_workers;
  if (!env.nic_profile.empty()) {  // A3.3: which profile the operating point came from
    impl->reg.gauge("miracache_nic_profile_info", "Matched NIC profile; the value is always 1.",
                    {{"profile", env.nic_profile}, {"verified", env.nic_profile_verified ? "true" : "false"}}).set(1);
    impl->reg.gauge("miracache_nic_unprofiled", "1 when only a generic fallback profile matched this NIC.", {})
        .set(env.nic_unprofiled ? 1 : 0);
  }
  if (env.drive) {  // the sim network is single-threaded: the workers, the replicator and the keepalive ticks take turns
    impl->env.drive = impl->make_sim_drive(env.drive);
  }
  const bool multi = specs.size() > 1;
  const unsigned keepalive_ms = specs[0].wopts.keepalive_ms;
  for (auto& s : specs) {
    auto n = std::make_unique<Impl::Node>();
    Impl::Node* np = n.get();
    n->weight = s.weight;
    n->zone = s.zone;
    n->addr = s.wopts.rail.host + ":" + std::to_string(s.wopts.rail.port);
    n->label = !s.label.empty() ? s.label : s.wopts.node != 0 ? std::to_string(s.wopts.node) : n->addr;
    n->hostname_fn = std::move(s.hostname);
    n->id.store(s.wopts.node, std::memory_order_relaxed);  // a fixed expected ID is known from the start
    n->published_id.store(s.wopts.node, std::memory_order_relaxed);  // and is in placement from the start
    n->reported_id_fn = std::move(s.reported_node_id);
    n->id_learned_fn = std::move(s.on_id_learned);
    n->host_learned_fn = std::move(s.on_host_learned);
    n->raw_fab = s.fab;
    n->wopts = std::move(s.wopts);
    n->wopts.drive = impl->env.drive;
    n->wopts.on_down = [np] { np->ka.kick(); };  // reconnect starts on the keepalive thread, now
    if (n->wopts.node == 0) n->wopts.on_node_id = [impl, np](std::uint32_t id) { return impl->learn_id(*np, id); };
    n->wopts.on_node_hostname = [impl, np](const std::string& h) { impl->learn_hostname(*np, h); };
    impl->hook_endpoint_diag(*n, n->wopts);  // G09, L13, Q03
    n->copts = copts;
    impl->bind_dyn(*n, std::move(s.on_dyn));
    if (multi) {
      n->copts.registry = &impl->reg;
      n->copts.node_label = n->label;
    }
    n->conflict_ctr = &impl->reg.counter("miracache_client_node_id_conflicts_total",
                                         "HELLO_ACKs refused because another memory node already has that node ID.",
                                         {{"node", n->label}});
    n->mismatch_ctr = &impl->reg.counter("miracache_client_node_id_mismatch_total",
                                          "HELLO_ACK node IDs that differ from the node ID in the admin ticket answer.",
                                          {{"node", n->label}});
    impl->nodes.push_back(std::move(n));
  }
  {
    std::lock_guard lk(impl->place_mu);
    impl->publish_places();  // the nodes with a fixed expected ID; learned ones join at their HELLO
  }
  // Single node and fixed IDs (tests): the identity series exist from the start; learned ones appear at HELLO.
  for (auto& n : impl->nodes)
    if (n->wopts.node != 0) {
      n->info_gauge = &impl->reg.gauge("miracache_client_node_info", "Memory node identity as the client knows it; the value is 1 once the node is in placement.",
                                       {{"node", n->label}, {"node_id", std::to_string(n->wopts.node)},
                                        {"hostname", Impl::host_or_unknown(*n)},
                                        {"addr", n->addr}, {"zone", n->zone}});
      n->info_gauge.load()->set(1);
    }
  impl->init_replicas(env.replicas, env.replica_mode, env.replica_buffer_bytes);
  for (auto& n : impl->nodes) impl->bind_brk_metrics(*n);  // fail-slow breaker series, closed
  // Single node: a failure to connect fails the open. Several nodes: one that is unreachable now is
  // built later by its keepalive thread (like a reconnect); the open fails only if none is reachable.
  Status first_err{};
  std::size_t up = 0;
  for (auto& n : impl->nodes) {
    impl->prepare_tickets(*n, n->wopts);  // Q15: the ticket source refills right before the build if it must
    Status st = impl->build(*n, /*background=*/false);  // Q01: the open keeps the default connect timeout
    if (st) {
      ++up;
    } else {
      if (first_err) first_err = st;
      impl->note_build_failure(*n, st.error());  // Q04: the keepalive thread retries with backoff
    }
  }
  if (multi && up < impl->nodes.size()) {  // Q15: retried inside the open until Env::open_settle (settle_first_builds)
    std::vector<Impl::Node*> ns;
    for (auto& n : impl->nodes) ns.push_back(n.get());
    up += impl->settle_first_builds(ns);
  }
  // R20 (review s11): with several nodes a transient failure of all of them is retried in the settle like one of N-1;
  // the open fails only if none came up by its end. A single node fails at once (as before).
  if (up == 0) return first_err.error();
  if (multi) {
    std::string pend;
    for (auto& n : impl->nodes)
      if (!n->pin_pair()) Impl::add_pending(pend, Impl::node_id_of(*n), Impl::host_or_unknown(*n), n->addr);
    Impl::log_open_result(up, impl->nodes.size(), pend);
  }
  c->rt_ = std::make_unique<Runtime>(*impl, ropts);
  impl->start_keepalive(keepalive_ms);
  return c;
}

Expected<std::unique_ptr<Client>> Client::open_bundle(const Env& env, BundleOpen bo, std::shared_ptr<void> adopt,
                                                      const ClientCoreOptions& copts, const RuntimeOptions& ropts) {
  if (!env.clock || !env.executor || !env.salts || !bo.initial || !bo.make_spec)
    return Error{ErrorCode::InvalidArgument, "client: incomplete Env"};
  if (env.replicas < 1 || env.replicas > 3) return Error{ErrorCode::InvalidArgument, "client: replicas must be 1..3"};
  const control::BodyView& body = bo.initial->view.body;
  if (body.nodes.empty() || body.nodes.size() > kMaxNodes)
    return Error{ErrorCode::InvalidArgument, "client: the bundle must name 1..kMaxNodes nodes"};
  std::unique_ptr<Client> c(new Client());
  c->keep_ = std::move(adopt);
  c->impl_ = std::make_unique<Impl>();
  Impl* impl = c->impl_.get();
  impl->env = env;
  {
    ClientDyn b = dyn_from_env(env, bo.keepalive_ms, WireOptions{}, bo.previous_view_ms, bo.hint_entries);
    b.subpool_bytes = copts.pool_bytes;  // HR3b: the running landing pool is the open-time value
    impl->init_dyn(env.dyn_base ? *env.dyn_base : b);
    impl->set_crypto_workers = env.set_crypto_workers;
  }
  impl->bundle_mode = true;
  if (!env.nic_profile.empty()) {  // A3.3: which profile the operating point came from
    impl->reg.gauge("miracache_nic_profile_info", "Matched NIC profile; the value is always 1.",
                    {{"profile", env.nic_profile}, {"verified", env.nic_profile_verified ? "true" : "false"}}).set(1);
    impl->reg.gauge("miracache_nic_unprofiled", "1 when only a generic fallback profile matched this NIC.", {})
        .set(env.nic_unprofiled ? 1 : 0);
  }
  if (env.drive) impl->env.drive = impl->make_sim_drive(env.drive);
  impl->make_spec = std::move(bo.make_spec);
  impl->watcher = bo.watcher;
  if (bo.wake) impl->wake_fn = std::move(bo.wake);
  else if (bo.watcher)
    impl->wake_fn = [w = bo.watcher](std::uint32_t lo, const std::string& admin) { w->on_reply_generation(lo, admin); };
  if (bo.push) impl->push_fn = std::move(bo.push);
  else if (bo.watcher)  // Pushed, AlreadyPushed and NodeAhead all mean: the node has at least our generation
    impl->push_fn = [w = bo.watcher](const std::string& admin) -> Status {
      auto r = w->push_envelope(admin);
      if (!r) return r.error();
      return {};
    };
  impl->base_copts = copts;
  impl->base_copts.pool_gauges = false;  // the slots point the shared-label pool series (Z02: adopt/release_pool_series)
  impl->slot_keepalive_ms = bo.keepalive_ms;
  impl->connect_wait_ms = bo.connect_wait_ms;
  impl->previous_view_ms = bo.previous_view_ms;
  impl->hints.configure(bo.hint_entries);
  impl->send_report_fn = std::move(bo.send_report);
  impl->cancel_reports_fn = std::move(bo.cancel_reports);
  impl->report_ms = bo.report_ms;
  impl->rebuild_jitter_ms = bo.rebuild_jitter_ms;  // HR3b
  impl->rebuild_drain_ms = bo.rebuild_drain_ms;
  for (int k = 0; k < 2; ++k)
    impl->rebuild_ctr[k] = &impl->reg.counter("miracache_client_rebuilds_total",
                                               "Planned rebuilds of a node connection (class B reload), by result.",
                                               {{"result", k == 0 ? "ok" : "failed"}});
  {
    static constexpr const char* kEv[Impl::kHintEvents] = {"set", "drop_miss", "drop_root", "drop_retire", "drop_empty", "void_epoch"};
    for (int e = 0; e < Impl::kHintEvents; ++e)
      impl->hint_ctr[e] = &impl->reg.counter("miracache_client_hint_total",
                                             "Previous-view hints by event (set; dropped on a miss, a root store, a retire or an empty set; voided by an epoch change).",
                                             {{"event", kEv[e]}});
    impl->prev_hit_ctr = &impl->reg.counter("miracache_client_previous_view_read_hit_total",
                                            "Reads whose keys[0] hit on the previous view's owner set.", {});
    impl->prev_store_ctr = &impl->reg.counter("miracache_client_previous_view_store_total",
                                              "Continuation stores that fell through to the previous view's owner set.", {});
  }
  // miracache_client_put_skipped_total{reason}: the series exist from the start (MB6b counts StaleEpoch and Draining).
  for (const char* reason : {"stale_epoch", "draining", "throttled", "not_owner"})
    impl->reg.counter("miracache_client_put_skipped_total", "Root puts skipped by the client or refused as skippable, by reason.",
                      {{"reason", reason}});
  impl->skipped_draining = &impl->reg.counter("miracache_client_put_skipped_total", "", {{"reason", "draining"}});
  impl->skipped_not_owner = &impl->reg.counter("miracache_client_put_skipped_total", "", {{"reason", "not_owner"}});
  for (std::size_t i = 0; i < kMaxNodes; ++i) {
    impl->nodes.push_back(std::make_unique<Impl::Node>());
    impl->nodes.back()->active.store(false, std::memory_order_relaxed);
    impl->nodes.back()->slot = i;
  }
  impl->init_replicas_slots(env.replica_mode, env.replica_buffer_bytes);
  if (Status st = impl->apply(bo.initial, /*initial=*/true); !st) return st.error();
  c->rt_ = std::make_unique<Runtime>(*impl, ropts);
  for (auto& n : impl->nodes)
    if (n->slot_state.load(std::memory_order_acquire) == 1) impl->start_slot_thread(*n);
  impl->mgr.start(500, [impl] { impl->mgr_tick(); });
  impl->pusher.start(1000, [impl] { impl->push_tick(); });
  if (impl->send_report_fn) impl->reporter.start(impl->report_ms, [impl] { impl->report_tick(); });
  return c;
}

void Client::apply_membership(MembershipSnapPtr snap) {
  if (!impl_ || !snap) return;
  {
    std::lock_guard lk(impl_->mgr_mu);
    if (!impl_->pending || snap->generation() > impl_->pending->generation()) impl_->pending = std::move(snap);
  }
  impl_->mgr.kick();
}
std::uint64_t Client::membership_generation() const { return impl_ ? impl_->applied_gen.load(std::memory_order_acquire) : 0; }
std::uint32_t Client::membership_epoch() const { return impl_ ? impl_->applied_epoch.load(std::memory_order_acquire) : 0; }
long Client::slot_of(std::uint32_t node_id) const {
  if (!impl_) return -1;
  std::lock_guard lk(impl_->slots_mu);
  auto it = impl_->slot_by_id.find(node_id);
  return it == impl_->slot_by_id.end() ? -1 : static_cast<long>(it->second);
}
// slots_in_use, slot_retiring and slot_of read under slots_mu, the lock teardown_slot/activate_slot change them under,
// so the three agree (run #278).
std::size_t Client::slots_in_use() const {
  if (!impl_) return 0;
  std::lock_guard lk(impl_->slots_mu);
  return impl_->live_nodes.load(std::memory_order_acquire);
}
int Client::slot_jobs_inside(std::size_t slot) const {
  return impl_ && slot < impl_->nodes.size() ? Impl::jobs_inside(*impl_->nodes[slot]) : 0;
}
bool Client::slot_retiring(std::size_t slot) const {
  if (!impl_ || slot >= impl_->nodes.size()) return false;
  std::lock_guard lk(impl_->slots_mu);
  return impl_->nodes[slot]->slot_state.load(std::memory_order_acquire) == 2;
}
void Client::test_endpoint_failure(std::size_t slot, unsigned rail, const Error& e, bool rebuild) {
  if (!impl_ || slot >= impl_->nodes.size()) return;
  auto& n = *impl_->nodes[slot];
  MIRACACHE_CHECK(!n.ka.running());  // A-3: a test hook for a hand-ticked client (keepalive_ms = 0) only
  impl_->note_endpoint_failure(Impl::fail_key(n), Impl::node_id_of(n), Impl::node_hostname(n), n.addr, rail, std::string(), e,
                               rebuild ? &n.rebuild_epfail : nullptr);
}
std::size_t Client::test_settle_rebuild_failures(std::size_t slot) {
  if (!impl_ || slot >= impl_->nodes.size()) return 0;
  MIRACACHE_CHECK(!impl_->nodes[slot]->ka.running());  // A-3: as test_endpoint_failure
  return impl_->settle_rebuild_failures(*impl_->nodes[slot]);
}

std::string Client::report_body() const {
  if (!impl_) return {};
  std::map<std::string, std::uint64_t> seen;
  std::lock_guard lk(impl_->report_state_mu);
  return impl_->build_report(impl_->aead_reported, seen);
}
Status Client::send_report_now() { return impl_ ? impl_->do_report() : Status(Error{ErrorCode::InvalidArgument, "client: closed"}); }
std::uint64_t Client::reports_sent() const { return impl_ ? impl_->reports_ok.load(std::memory_order_relaxed) : 0; }
std::uint64_t Client::reports_failed() const { return impl_ ? impl_->reports_bad.load(std::memory_order_relaxed) : 0; }
std::size_t Client::hint_count() const { return impl_ ? impl_->hints.size() : 0; }
void Client::set_hint_for_test(const ScopeKeys& sk, std::uint32_t group, std::uint32_t prev_epoch) {
  if (!impl_ || group >= sk.scopes.size()) return;
  impl_->hints.set(HintCache::Key(reinterpret_cast<const char*>(sk.scopes[group].b), 32), prev_epoch);
}
void Client::add_aead_failures_for_test(std::uint32_t node_id, std::uint64_t n) {
  if (impl_) impl_->aead_counter(std::to_string(node_id)).inc(n);
}

WirePort* Client::wire_port(std::size_t node) {
  if (!impl_ || node >= impl_->nodes.size()) return nullptr;
  const Impl::PairPtr p = impl_->nodes[node]->pin_pair();
  return p ? p->wire.get() : nullptr;
}
std::shared_ptr<const void> Client::slot_pair_for_test(std::size_t slot) const {
  if (!impl_ || slot >= impl_->nodes.size()) return nullptr;
  return impl_->nodes[slot]->pin_pair();
}
std::shared_ptr<const void> Client::detach_pair_for_test(std::size_t slot) {
  if (!impl_ || slot >= impl_->nodes.size()) return nullptr;
  return impl_->nodes[slot]->pair.exchange(nullptr, std::memory_order_acq_rel);
}
bool Client::reattach_pair_for_test(std::size_t slot, std::shared_ptr<const void> pair) {
  if (!impl_ || slot >= impl_->nodes.size() || !pair) return false;
  Impl::PairPtr want = std::static_pointer_cast<Impl::Pair>(std::const_pointer_cast<void>(std::move(pair)));
  Impl::PairPtr none;
  return impl_->nodes[slot]->pair.compare_exchange_strong(none, std::move(want), std::memory_order_acq_rel);
}
bool Client::slot_class_b(std::size_t slot, SlotClassB& out) const {
  if (!impl_ || slot >= impl_->nodes.size()) return false;
  const Impl::PairPtr p = impl_->nodes[slot]->pin_pair();
  if (!p) return false;
  out.pool_bytes = p->b.pool_bytes;
  out.mtu = p->b.mtu;
  out.wire_proto = p->b.wire_proto;
  out.fetch_qps = p->b.fetch_qps;
  return true;
}
std::uint64_t Client::rebuilds_done() const { return impl_ ? impl_->rebuilds_ok.load(std::memory_order_relaxed) : 0; }
std::uint64_t Client::rebuild_failures() const { return impl_ ? impl_->rebuilds_failed.load(std::memory_order_relaxed) : 0; }
long Client::rebuilding_slot() const {
  if (!impl_) return -1;
  const std::size_t s = impl_->rebuild_slot.load(std::memory_order_acquire);
  return s == Impl::kNoSlot ? -1 : static_cast<long>(s);
}
std::size_t Client::node_count() const {
  if (!impl_) return 0;
  if (!impl_->bundle_mode) return impl_->nodes.size();
  std::lock_guard lk(impl_->slots_mu);  // A-4: read under slots_mu like slots_in_use() / nodes_connected()
  return impl_->live_nodes.load(std::memory_order_acquire);
}
std::size_t Client::nodes_connected() const {
  if (!impl_) return 0;
  std::size_t n = 0;
  std::lock_guard lk(impl_->slots_mu);  // bundle mode: a slot in use is stable under it (see block_size_problem)
  for (const auto& np : impl_->nodes) {
    if (impl_->bundle_mode ? np->slot_state.load(std::memory_order_acquire) != 1 : !np->active.load(std::memory_order_acquire))
      continue;
    n += Impl::node_up(*np) ? 1 : 0;
  }
  return n;
}
void Client::attach_service(std::shared_ptr<void> owned, std::function<void(std::string&)> metrics) {
  if (!impl_) return;
  std::lock_guard<std::mutex> g(impl_->svc_mu);
  impl_->svc.push_back(std::move(owned));
  if (metrics) impl_->svc_metrics.push_back(std::move(metrics));
}

std::string Client::block_size_problem(std::uint64_t plaintext_bytes, std::size_t* checked) const {
  if (checked) *checked = 0;
  if (!impl_) return {};
  Impl& im = *impl_;
  // L08 (review s9b): every node's fields are copied under slots_mu while its slot is in use (bundle mode: a slot is
  // refilled only while free, and freed under slots_mu, so a slot in use is stable under the lock); the text is built
  // after the lock. Static nodes never change after the open.
  struct Seen {
    std::uint64_t lim;
    unsigned seg_log2;
    std::uint32_t id;
    std::string host, addr;
  };
  std::vector<Seen> seen;
  std::size_t in_use = 0;
  // Nodes that connect later are checked against this size when their session comes up (Impl::recheck_block). R17:
  // stored BEFORE the scan (and fenced against recheck_block's load), so a session that comes up between the scan and
  // the store cannot be missed by both; the worst case is one node checked twice.
  im.checked_block.store(plaintext_bytes, std::memory_order_seq_cst);
  std::atomic_thread_fence(std::memory_order_seq_cst);
  {
    std::lock_guard lk(im.slots_mu);
    for (const auto& np : im.nodes) {
      const Impl::Node& n = *np;
      if (im.bundle_mode ? n.slot_state.load(std::memory_order_acquire) != 1 : !n.active.load(std::memory_order_acquire))
        continue;
      ++in_use;
      const Impl::PairPtr p = n.pin_pair();
      if (!p || !p->wire) continue;
      const std::uint64_t lim = p->wire->max_stored_block();
      if (lim == 0) continue;  // an older node (no TLV) or not connected yet: the node itself still refuses at PUT_BEGIN
      seen.push_back({lim, n.copts.segment_log2, p->wire->node_id(), Impl::node_hostname(n), n.addr});
    }
  }
  if (checked) *checked = seen.size();
  std::string out;
  for (const auto& s : seen) {
    out = Impl::block_refusal(plaintext_bytes, s.seg_log2, s.lim, s.id, s.host, s.addr);
    if (!out.empty()) break;
  }
  log::write(out.empty() ? log::Level::Info : log::Level::Error, "client", "engine block size checked against the memory nodes",
             {{"client_host", log::hostname()},
              {"block_bytes", std::to_string(plaintext_bytes)},
              {"checked", std::to_string(seen.size()) + " of " + std::to_string(in_use)},
              {"later", "a node that connects later is checked when its session comes up"},
              {"result", out.empty() ? "fits" : "refused"}});
  return out;
}

std::string Client::metrics_text() const {
  if (!impl_) return {};
  std::string s;
  if (impl_->nodes.size() > 1) {
    impl_->reg.write_prometheus(s);
  } else {
    const Impl::PairPtr p = impl_->nodes[0]->pin_pair();
    s = p ? p->core->metrics_text() : std::string();
    impl_->reg.write_prometheus(s);  // identity series (node_info, node_id_conflicts); the core keeps its own registry
  }
  std::lock_guard<std::mutex> g(impl_->svc_mu);
  for (const auto& m : impl_->svc_metrics) m(s);  // HR4: miracache_cred_reload_total
  return s;
}

Expected<std::unique_ptr<Client>> Client::open_loopback(const Env& env, const ClientCoreOptions& copts,
                                                        const RuntimeOptions& ropts) {
  if (!env.fab || !env.port || !env.clock || !env.executor || !env.salts)
    return Error{ErrorCode::InvalidArgument, "client: incomplete Env"};
  std::unique_ptr<Client> c(new Client());
  c->impl_ = std::make_unique<Impl>();
  c->impl_->env = env;
  c->impl_->init_dyn(env.dyn_base ? *env.dyn_base : dyn_from_env(env, 0, WireOptions{}, 0, 0));
  c->impl_->set_crypto_workers = env.set_crypto_workers;
  auto core = ClientCore::create(*env.fab, *env.port, *env.clock, *env.executor, *env.salts, copts);
  if (!core) return core.error();
  auto n = std::make_unique<Impl::Node>();
  n->label = "0";
  auto p = std::make_shared<Impl::Pair>();  // loopback: a pair without a wire
  p->core = std::move(*core);
  n->pair.store(std::move(p), std::memory_order_release);
  c->impl_->nodes.push_back(std::move(n));
  c->rt_ = std::make_unique<Runtime>(*c->impl_, ropts);
  return c;
}

Ticket Client::submit(int kind, const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys,
                      std::span<const BufRef> bufs, Nanos timeout) {
  Req r;
  r.kind = kind;
  r.sk = sk;
  r.group = group;
  if (kind == 2) {  // HR2 (class A): store deadlines are clamped to deadline.put_max_ms, read once here
    const Nanos cap = std::chrono::milliseconds(impl_->dyn()->put_max_ms);
    if (timeout > cap) timeout = cap;
  }
  r.deadline = sat_add(impl_->env.clock->now(), timeout);  // from submit, not worker pickup
  for (std::size_t i = 0; i < keys.size(); ++i) {
    r.raw.emplace_back(keys[i].raw.begin(), keys[i].raw.end());
    r.parent.emplace_back(keys[i].parent_raw.begin(), keys[i].parent_raw.end());
    r.pos.push_back(keys[i].chain_pos);
  }
  r.bufs.assign(bufs.begin(), bufs.end());
  Job job;
  job.kind = kind == 0 ? JobKind::Lookup : kind == 1 ? JobKind::Fetch : JobKind::Store;
  job.lane = impl_->lane_of(r);  // s12 (C1): before r is moved into reqs
  std::uint64_t id;
  {
    std::lock_guard lk(impl_->req_mu);
    id = impl_->next_req++;
    impl_->reqs.emplace(id, std::move(r));
  }
  for (std::size_t i = 0; i < keys.size(); ++i) job.keys.push_back((id << 20) | i);
  if (keys.empty()) {
    std::lock_guard lk(impl_->req_mu);
    impl_->reqs.erase(id);
  }
  return rt_->submit(std::move(job));
}

std::size_t Client::pending_requests() const {
  std::lock_guard lk(impl_->req_mu);
  return impl_->reqs.size();
}
std::uint64_t Client::pump_iterations() const { return impl_->iterations.load(std::memory_order_relaxed); }

std::vector<std::uint32_t> Client::OwnerSetForTest(const control::BodyView& body, std::span<const std::uint8_t, 32> scope) {
  const View v = control::view_from_bundle(body);  // as publish_bundle
  const unsigned R = std::clamp<unsigned>(body.replicas, 1u, 3u);
  std::vector<std::uint32_t> out;
  for (std::size_t i : owner_set(v, scope, R)) out.push_back(static_cast<std::uint32_t>(std::stoul(v.nodes[i].id)));  // as run_bundle
  return out;
}

Ticket Client::lookup(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys, Nanos timeout) {
  return submit(0, sk, group, keys, {}, timeout);
}
Ticket Client::fetch(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys,
                     std::span<const BufRef> bufs, Nanos timeout) {
  return submit(1, sk, group, keys, bufs, timeout);
}
Ticket Client::store(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys,
                     std::span<const BufRef> bufs, Nanos timeout) {
  return submit(2, sk, group, keys, bufs, timeout);
}

}  // namespace miracache
