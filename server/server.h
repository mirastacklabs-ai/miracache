// SPDX-License-Identifier: Apache-2.0
// Memory-node wire adapter: maps wire v0 frames onto the typed store API.
//
//   admit      TicketTable::redeem in the fabric's AdmitFn: no connection without a live,
//              single-use ticket; the ticket fixes class, rail and principal. The principal
//              never comes from a frame.
//   dispatch   HELLO (+ SEG_TABLE), PING, STATS, LOOKUP, RENEW, RELEASE, INVALIDATE,
//              PUT_BEGIN, PUT_COMMIT, PUT_CANCEL. Class gating: Control carries everything
//              except PUT_*, Ingest carries PUT_* (PUT_COMMIT only on the endpoint that did
//              the PUT_BEGIN: a foreign put id is UnknownPut), Fetch endpoints only HELLO/PING.
//   SEG_TABLE  sent after HELLO and re-sent to every helloed endpoint each time
//              MrManager::step_registration() grows the registered segment prefix
//              (table_gen increments). Unsolicited SEG_TABLE and GOAWAY go to Control
//              endpoints only: a Fetch endpoint has 2 recv slots that the client reposts
//              only while it polls, so unsolicited frames there can exhaust RNR retries.
//
// Threading: everything here runs on ONE thread (the store thread). Work offload goes
// through the Executor; the caller must pass one whose `done` runs on this thread
// (server/runtime StoreExecutor + drain_done(), or InlineExecutor/sim executors) and must
// drain it before destroying the Server. Deterministic: time and randomness are injected.
// Ticket ids are secrets: production passes a CSPRNG-backed `ticket_rng` (the store's `rng`
// is only used for the sim-reproducible parts); when null, `rng` is used (sim and tests).
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "control/bundle.h"
#include "control/view.h"
#include "fabric/fabric.h"
#include "proto/messages.h"
#include "server/tickets.h"
#include "store/arena.h"
#include "store/mr_manager.h"
#include "store/put.h"
#include "store/restart.h"
#include "store/scrub.h"
#include "store/slab.h"
#include "store/store.h"
#include "store/store_metrics.h"
#include "telemetry/metrics.h"
#include "util/clock.h"
#include "util/log_limiter.h"
#include "util/executor.h"
#include "util/random.h"

namespace miracache::server {

struct DynConfig;  // server/dyn_config.h
using DynPtr = std::shared_ptr<const DynConfig>;

struct ServerConfig {
  store::StoreConfig store;
  std::uint32_t mtu = 4096;
  std::uint8_t wire_protocol = 1;            // HELLO_ACK proto: 1 RoCE, 2 iWARP
  std::vector<fabric::RailAddr> rails;       // one listener per rail (1..4, STATIC); empty = one default listener
  // rail index -> index of the fabric (device) it lives on; empty = every rail on fabric 0. device_names are for
  // labels and logs (same indexing as the fabrics).
  std::vector<std::uint32_t> rail_device;
  std::vector<std::string> device_names;
  Nanos ticket_ttl = std::chrono::seconds(300);
  Nanos tick_interval = std::chrono::milliseconds(1);  // minimum spacing of tick() while the loop is busy
  // Longest an idle loop may sleep before it must call run_once() again (timers: put timeouts, fence
  // retries, sweeps, idle reaping all live in tick()). Completions and worker `done`s wake it earlier.
  Nanos idle_tick = std::chrono::milliseconds(10);
  // Abuse limits (TOML [limits]).
  // Live tickets one identity may hold. 0 = not set: Server::create computes default_ticket_max(rails, fetch_qps).
  std::uint32_t ticket_max_per_identity = 0;
  Nanos admit_timeout = std::chrono::seconds(10);    // redeemed ticket whose connect never completes
  Nanos hello_deadline = std::chrono::seconds(5);    // accepted endpoint must say HELLO within this
  // A session (the 3 endpoints sharing a conn_id) with no frame on any of them for this long is
  // closed, all endpoints together. Fetch endpoints have no timer of their own.
  Nanos idle_timeout = std::chrono::seconds(300);
  Nanos sweep_interval = std::chrono::milliseconds(50);  // ticket/lease expiry sweep period
  // Live + connecting endpoints per principal. 0 = not set: Server::create computes default_max_conns(rails, fetch_qps).
  std::uint32_t max_conns_per_principal = 0;
  std::uint32_t fetch_qps = 1;                       // resolved NIC profile's fetch_qps per rail (feeds the computed default)
  std::uint32_t max_leases_per_principal = 8192;     // live leases across all of a principal's sessions
  // Controller-less lab bring-up: binds one identity to one principal.
  std::string lab_identity;                  // empty = no lab principal
  std::vector<std::string> lab_identities;   // more identities (SPIFFE ids) bound to lab_principal
  // GOAWAY window (ms) sent when an applied bundle removes this node (reason Epoch); [node] drain_ms.
  std::uint32_t goaway_drain_ms = 5000;
  // Lab principal: named "lab", its ID computed from the name like every principal ID (goal 10).
  store::PrincipalId lab_principal = control::principal_id("lab");
  // Unix wall time in ns, for drop_before only (an absolute time from the bundle). Null = miracache::wall_unix_ns.
  std::function<std::int64_t()> wall_unix_ns;
};

// "host:port[,host:port...]" of the RDMA listen rails (what clients connect to); empty if none.
std::string listen_addr_string(const ServerConfig& cfg);

class Server {
 public:
  // One fabric (the usual case): every rail on that device.
  static Expected<std::unique_ptr<Server>> create(const ServerConfig& cfg, fabric::Fabric& fabric, const Clock& clock,
                                                  Random& rng, Executor& exec, Random* ticket_rng = nullptr);
  // one fabric per distinct device; cfg.rail_device maps each rail to its fabric. The fabrics' endpoint IDs must
  // be disjoint (VerbsOptions::ep_id_base; the sim's IDs are network-wide).
  static Expected<std::unique_ptr<Server>> create(const ServerConfig& cfg, std::vector<fabric::Fabric*> fabrics,
                                                  const Clock& clock, Random& rng, Executor& exec,
                                                  Random* ticket_rng = nullptr);
  ~Server();
  Server(const Server&) = delete;
  Server& operator=(const Server&) = delete;

  // Starts the listeners (admission through the ticket table).
  Status start();
  // One loop turn: poll the fabric and dispatch, run timers when due, register one more
  // segment if any is left. Returns the amount of work done (0 = idle).
  std::size_t run_once(fabric::PollBudget budget = {});

  // Admin API (the mTLS front end calls this; tests and the lab bootstrap call it directly).
  Expected<std::vector<proto::Ticket>> issue_ticket(const std::string& identity, fabric::EpClass cls,
                                                    std::uint8_t rail, std::uint32_t count);
  // Whole-batch pre-check for `total` tickets: AccessDenied / ResourceExhausted without issuing any;
  // Busy while draining (the admin API answers 503, no ticket the node would refuse anyway).
  Status check_issue_capacity(const std::string& identity, std::uint32_t total);
  // SIGHUP: re-bind the lab identities. Added ones are bound; removed ones (or all, when the
  // principal id changed) go through remove_identity, which revokes their tickets and connections.
  void reload_identities(const std::string& lab_identity, const std::vector<std::string>& lab_identities,
                         store::PrincipalId lab_principal);
  // Bundle mode: swaps in a verified, parsed and persisted bundle. Store thread only, between run_once
  // turns. Applies, in full and from the bundle alone (a node that missed bundles ends in the same state):
  //   principals   identity -> computed principal ID bindings (identities that disappear or change principal go
  //                through remove_identity: tickets and connections revoked); quota policies;
  //   member state this node's state from `nodes` (absent = Removed), kept apart from the SIGTERM latch;
  //   views, R     stored as given (epoch enforcement is separate);
  //   drop_before  the per-principal maximum ever seen, re-applied on every apply (and by load_drop_before_floor).
  // The member-state refusal of root puts is wired separately (accepts_root_puts()); lab mode is unaffected.
  enum class MemberState : std::uint8_t { Active, Draining, Readonly, Removed };
  struct AppliedBundle {
    std::uint64_t generation = 0, sec_generation = 0;
    std::uint32_t epoch = 0, previous_epoch = 0;
    std::uint32_t replicas = 1;  // config.cluster.placement.replicas (stored, not enforced yet)
    MemberState member_state = MemberState::Active;
    control::Sha256Digest body_hash{}, sec_hash{};
  };
  void apply_bundle(const control::BundleView& view);
  const AppliedBundle& applied_bundle() const { return applied_bundle_; }
  // ---- Live configuration (server/dyn_config.h). ----
  // Store thread, between run_once turns (the parse and validation already ran on the admin or main thread).
  // Swaps every class A key at once: store, put path, slab, ticket table, the limits in ServerConfig, and the policies
  // derived for bundle principals. An op uses the values current when it starts. Counts
  // miracache_config_reload_total{result="applied"}. `source` is "bundle" or "sighup" (log only).
  void apply_dyn(DynPtr d, const char* source);
  // The current snapshot (any thread) and the start-up one (immutable: the base a bundle's config.cluster.memnode is
  // merged over, so a key removed from the bundle restores the start-up value).
  DynPtr dyn() const { return dyn_.load(); }
  DynPtr dyn_base() const { return dyn_base_; }
  // A pre-validated reload that was refused (bad file, STATIC change, bad value): counted, logged by the caller.
  void count_config_rejected(const char* why);
  // The applied view (nodes, previous view, principals, config); null until the first apply.
  const control::BundleView* bundle_view() const { return view_.get(); }
  // Member state as of the last apply. Never touched by begin_drain(): a removed-then-re-added node serves again.
  MemberState member_state() const { return applied_bundle_.member_state; }
  // Root PUT_BEGIN gate: the SIGTERM latch is clear and the bundle says `active`.
  bool accepts_root_puts() const { return !draining_ && applied_bundle_.member_state == MemberState::Active; }
  // Epoch and owner checks (bundle mode only, a node with no applied bundle behaves as in lab mode):
  //   PUT_BEGIN frame epoch != the node's: StaleEpoch (retry 0 below, 50 ms above); then readonly/removed refuse
  //   any PUT_BEGIN (Draining); a root batch also needs accepts_root_puts() (Draining) and this node in the owner
  //   set of the current view (else SKIP for every key). LOOKUP/READ/RENEW/RELEASE are never checked.
  //   Every reply frame carries the node's epoch and the low 32 bits of the bundle generation. A bundle without this
  //   node sends GOAWAY (reason Epoch) and refuses new sessions until a bundle lists it again.
  // True when this node is in place_order(current view, scope, R) for the applied bundle (R clamped to 1..3 as the
  // client does); false when there is no applied bundle.
  bool in_owner_set(const store::ScopeId& scope) const;
  // The same check over a bundle that is not applied (tests, tools): view_from_bundle + owner_set, R clamped to 1..3.
  static bool bundle_owns(const control::BundleView& v, std::uint32_t node_id, const store::ScopeId& scope);
  // Start-up (before apply_bundle): the floor file's per-principal drop_before maxima (name -> unix seconds), so a
  // node whose bundle no longer carries a drop_before still honours the highest one it ever saw.
  void load_drop_before_floor(const std::map<std::string, std::int64_t>& maxima);
  // GET /v1/identity fields that live in the store. Taken on the store thread (publish_gauges / apply_bundle)
  // under a mutex; the admin thread only copies it, it never touches the store.
  // one rail's health as GET /v1/identity reports it: up = port ACTIVE, listener
  // alive and no fatal async event in the last 10 s. Refreshed on the store thread about every 500 ms of Clock time.
  struct RailHealth {
    std::uint32_t rail = 0;
    std::string addr;    // "host:port"
    std::string device;  // device name ("" when unnamed)
    bool up = false;
    std::string port_state = "UNKNOWN";
    bool listener_ok = false;
  };
  struct NodeSnapshot {
    std::string member_state = "active";  // active | draining | readonly | removed
    std::uint64_t scopes = 0, bytes_used = 0;
    std::vector<RailHealth> rails;        // empty until start()
  };
  // Re-reads every fabric's health now (store thread); tick() does this on its own about twice a second.
  void refresh_rail_health();
  NodeSnapshot node_snapshot() const {
    std::lock_guard<std::mutex> g(snap_mu_);
    return snap_;
  }
  // The cap this node enforces for principal `id` (0 = none configured), by the quota formula.
  std::uint64_t principal_cap_bytes(store::PrincipalId id) const;
  TicketTable& tickets() { return tickets_; }
  // Metrics. Counters are live (relaxed atomics, any thread may scrape). The gauges
  // are refreshed on the store thread by tick() (about every 250 ms of Clock time) or by
  // publish_gauges().
  telemetry::Registry& metrics() { return registry_; }
  void publish_gauges();
  // Revokes an identity: drops its live and connecting tickets, its principal binding, and
  // closes every connection it holds (their sessions end, releasing leases and puts).
  void remove_identity(const std::string& identity);
  // GOAWAY to every helloed Control endpoint.
  void goaway(proto::GoawayReason why, std::uint32_t drain_ms);
  // Graceful shutdown (design 9.4 class B): GOAWAY to every session now (and to sessions that say HELLO
  // later) with `drain_ms`, then keep serving lookups/fetches/renews and finishing puts, but refuse root
  // PUT_BEGINs (WireStatus::Draining). The caller decides when to stop: drain_idle() or its own deadline.
  void begin_drain(proto::GoawayReason why, std::uint32_t drain_ms);
  // POST /v1/drain: a node-local drain WITHOUT exit (rolling restarts). Store thread. Same effect as the SIGTERM
  // drain (GOAWAY, no root PUT_BEGIN, no new tickets) but the process keeps running until the operator stops it;
  // the latch lasts for the process. Returns false if the node was already draining (nothing sent again).
  bool admin_drain(std::uint32_t drain_ms);
  // POST /v1/drop_principal: raises the principal's drop_before (unix seconds) at once, the same mechanism as a
  // bundle's drop_before (monotonic, converted once, incremental sweep: lookups of dead scopes miss at once, memory
  // is freed over the next turns, other principals are untouched). This call only changes the running store; the
  // admin route makes it durable (FloorState::raise_drop_before, loaded again by load_persisted_drop_before at start;
  // the controller route persists it through a new `sec`). Store thread. NotFound if a bundle is applied and has no
  // such principal; InvalidArgument if drop_before is later than now + 300 s.
  Status drop_principal_local(const std::string& name, std::int64_t drop_before_unix_s);
  bool draining() const { return draining_; }
  // No session and no put in flight: nothing is left to wait for.
  bool drain_idle() const { return sessions_.empty() && puts_->n_puts() == 0; }
  // Exit, the last call on the store thread: drops every connection (Writing puts are fenced
  // and freed, write MRs deregistered), then marks the superblock clean. The caller must first stop
  // its executor and run every queued `done` (StoreExecutor: stop(); drain_done()), so a Digesting
  // put has committed or been freed: nothing commits after the clean mark. A put still in flight or
  // a write MR that will not fence leaves the media unclean (an error; the next open recovers).
  Status shutdown_clean();
  // The scrubber (null until create()). stop() ends picking; shutdown_clean() calls it.
  store::Scrubber& scrubber() { return *scrub_; }
  // How long an idle loop may sleep: until the next tick() is due (zero = now), capped by idle_tick.
  Nanos next_wake_in() const;

  store::Store& store() { return *store_; }
  store::PutPath& puts() { return *puts_; }
  store::MrManager& mrs() { return *mrs_; }
  store::Arena& arena() { return *arena_; }
  // What the restart scan of this start adopted and discarded (ran == false on a blank store).
  const store::RestartReport& restart_report() const { return restart_report_; }
  // The memory node ID: random, persisted in the superblock (plan 2C).
  std::uint32_t node_id() const { return cfg_.store.node_id; }
  Status check_invariants() const;

  std::size_t n_conns() const { return conns_.size(); }
  std::size_t n_admitted() const { return admitted_.size(); }  // redeemed, endpoint not yet accepted
  std::uint32_t table_gen() const { return table_gen_; }
  // Drawn once per process (Random) and sent in every HELLO_ACK (kTlvTagBootNonce); never 0. A client that sees
  // another value on a rejoining rail knows the node restarted, whatever table_gen the new process reached.
  std::uint64_t boot_nonce() const { return boot_nonce_; }
  std::uint64_t n_registration_errors() const { return reg_errors_; }

 private:
  // The warm-restart scan of a re-opened store (store/restart.h), with its log lines and metrics.
  Status restart();
  // A probe write registration over the first data run, so a backing whose pages cannot be pinned for
  // remote write (a disk file on overlayfs, ext4...) refuses to start with a clear error instead of refusing every put.
  Status probe_backing();
  struct Conn {
    fabric::Endpoint* ep = nullptr;
    TicketGrant grant;
    bool hello = false;
    store::SessionId session = 0;
    std::array<std::uint8_t, 16> conn_id{};
    bool dead = false;  // a send failed or the peer was refused: no more sends; reaped by tick()
    Nanos accepted_at{0};
    Nanos last_rx{0};  // before HELLO only; afterwards the session's last_rx counts
  };
  struct Admitted {
    TicketGrant grant;
    Nanos at{0};
  };
  struct LeaseRec {
    store::PrincipalId principal = 0;
    store::SessionId session = 0;
    Nanos expiry{0};
    std::multimap<Nanos, store::LeaseId>::iterator by_expiry;  // entry in lease_expiry_
  };
  using TicketId = std::array<std::uint8_t, 16>;
  using SessionKey = std::pair<store::PrincipalId, std::array<std::uint8_t, 16>>;
  struct SessionRef {
    store::SessionId id = 0;
    std::uint32_t refs = 0;
    Nanos last_rx{0};  // any frame on any of the session's endpoints
  };

  Server(const ServerConfig& cfg, std::vector<fabric::Fabric*> fabrics, const Clock& c, Random&, Executor&,
         Random& ticket_rng);

  Expected<fabric::Admission> admit(std::span<const std::byte> priv, std::size_t listener);
  void on_accept(fabric::Endpoint* ep, std::size_t rail);
  // The fabric (device index) a rail lives on, and the number of rails.
  std::uint32_t rail_dev(std::size_t rail) const {
    return rail < cfg_.rail_device.size() ? cfg_.rail_device[rail] : 0;
  }
  std::size_t n_rails() const { return cfg_.rails.empty() ? 1 : cfg_.rails.size(); }
  Status release_ep(fabric::Endpoint* ep);  // through the fabric that owns it
  void on_frame(fabric::EndpointId id, std::span<const std::byte> bytes);
  // Erases the conn. Never call from a sender or while a Conn& / map iterator is held; senders
  // use kill() and tick() reaps.
  void drop_conn(fabric::EndpointId id);
  void kill(fabric::EndpointId id);
  std::size_t principal_conns(store::PrincipalId p) const;
  std::size_t live_leases(store::PrincipalId p);
  void purge_leases(Nanos now);
  void add_lease(store::LeaseId id, const LeaseRec& rec);
  void erase_lease(std::map<store::LeaseId, LeaseRec>::iterator it);
  void tick();
  void count_request(std::uint16_t type, bool ok);
  void count_issue_fail(ErrorCode c);

  // Senders. `body_len` bytes of body_buf_ are the body.
  void send_body(fabric::EndpointId id, proto::Op op, std::uint64_t rid, std::size_t body_len, std::uint16_t extra_flags = 0);
  void send_error(fabric::EndpointId id, const proto::FrameHeader& req, proto::WireStatus st, std::uint32_t retry_ms = 0);
  void send_seg_table(Conn& c);

  void on_hello(Conn& c, const proto::FrameHeader& h, std::span<const std::byte> body);
  void on_lookup(Conn& c, const proto::FrameHeader& h, std::span<const std::byte> body);
  void on_renew(Conn& c, const proto::FrameHeader& h, std::span<const std::byte> body);
  void on_release(Conn& c, const proto::FrameHeader& h, std::span<const std::byte> body);
  void on_invalidate(Conn& c, const proto::FrameHeader& h, std::span<const std::byte> body);
  void on_put_begin(Conn& c, const proto::FrameHeader& h, std::span<const std::byte> body);
  void on_put_commit(Conn& c, const proto::FrameHeader& h, std::span<const std::byte> body);
  void on_put_cancel(Conn& c, const proto::FrameHeader& h, std::span<const std::byte> body);
  void on_put_done(fabric::EndpointId ep, std::uint64_t rid, const proto::FrameHeader& req, const store::PutDoneResult& r);
  void send_put_done(fabric::EndpointId ep, std::uint64_t rid, const store::PutDoneResult& r);

  ServerConfig cfg_;
  std::vector<fabric::Fabric*> fabrics_;          // one per distinct device
  std::map<fabric::EndpointId, std::uint32_t> ep_dev_;  // accepted endpoint ID -> its fabric index
  std::size_t poll_rr_ = 0;                       // round-robin start of the fabric poll
  Nanos last_rail_poll_{-1};
  const Clock& clock_;
  // Declared before the store and put path, which hold pointers into mx_; destroyed after them.
  telemetry::Registry registry_;
  store::RestartReport restart_report_;
  struct Mx;
  std::unique_ptr<Mx> mx_;
  TicketTable tickets_;
  std::unique_ptr<store::Arena> arena_;
  std::unique_ptr<store::SlabAllocator> slab_;
  std::unique_ptr<store::Store> store_;
  std::vector<fabric::PdId> fetch_pds_, ingest_pds_;  // per device
  std::unique_ptr<store::MrManager> mrs_;
  std::unique_ptr<store::PutPath> puts_;
  std::unique_ptr<store::Scrubber> scrub_;  // declared after store_/arena_ so it is destroyed first

  std::map<fabric::EndpointId, Conn> conns_;
  std::map<TicketId, Admitted> admitted_;        // redeemed, endpoint not yet accepted
  std::map<store::LeaseId, LeaseRec> leases_;    // leases handed out, per principal cap
  std::multimap<Nanos, store::LeaseId> lease_expiry_;  // expiry index over leases_ (purge pops the front)
  std::map<store::PrincipalId, std::size_t> lease_count_;  // leases_ entries per principal
  Nanos last_sweep_{-1};                         // coarse ticket sweep
  std::map<SessionKey, SessionRef> sessions_;
  std::vector<fabric::Endpoint*> dying_;          // aborted, waiting to drain for release()
  store::SessionId next_session_ = 1;
  std::uint32_t table_gen_ = 0;
  std::uint64_t boot_nonce_ = 1;
  LogLimiter too_large_log_{std::chrono::seconds(60)};  // the too-large PUT_BEGIN WARN, per (principal, size class)
  std::uint64_t reg_errors_ = 0;
  Nanos last_tick_{-1};
  bool draining_ = false;
  AppliedBundle applied_bundle_;
  std::atomic<DynPtr> dyn_;      // the live class A snapshot (readers: admin and metrics threads)
  DynPtr dyn_base_;              // the start-up snapshot, immutable
  store::PrincipalPolicy policy_of(const control::PrincipalView& p) const;
  void apply_bundle_config(const control::BundleView& v);
  void apply_principals(const control::BundleView& v);
  void apply_drop_before();
  std::int64_t wall_now_ns() const;
  void refresh_snapshot(bool counts);
  mutable std::mutex snap_mu_;
  NodeSnapshot snap_;
  std::shared_ptr<const control::BundleView> view_;
  // The current-view placement of the applied bundle (built once per apply) and this node's ID as placement text.
  View place_view_;
  std::string self_id_text_;
  std::uint32_t place_r_ = 1;
  std::uint64_t epoch_violations_ = 0;  // ghost: a PUT_BEGIN accepted against the epoch and owner checks (check_invariants)
  bool refusing_sessions() const { return draining_ || (view_ && applied_bundle_.member_state == MemberState::Removed); }
  void count_epoch_refusal(const char* reason);
  void send_skip_all(fabric::EndpointId id, const proto::FrameHeader& req, std::size_t n);
  std::map<std::string, store::PrincipalId> bundle_identities_;  // identities bound by the applied bundle
  std::map<store::PrincipalId, std::uint64_t> caps_;             // principal ID -> cap bytes
  std::map<std::string, telemetry::Gauge*> cap_gauges_;          // principal name (or "_other") -> cap series
  std::map<std::string, std::int64_t> drop_before_max_;          // principal name -> highest unix seconds ever seen
  // name -> {unix seconds, Clock-domain cutoff}: converted once per rise, so repeated applies do not drift
  std::map<std::string, std::pair<std::int64_t, std::int64_t>> drop_cutoff_ns_;
  Nanos drain_deadline_{0};
  Nanos last_publish_{-1};
  std::uint64_t err_replies_ = 0;  // send_error calls (request status accounting)
  bool listening_ = false;
  std::array<std::byte, proto::kMaxFrameSize> body_buf_{};
  std::array<std::byte, proto::kMaxFrameSize> frame_buf_{};
};

}  // namespace miracache::server
