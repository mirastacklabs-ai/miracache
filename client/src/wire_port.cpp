// SPDX-License-Identifier: Apache-2.0
#include "src/wire_port.h"

#include <poll.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <tuple>

#include "runtime/bounded.h"
#include "src/client_metrics.h"
#include "util/check.h"
#include "util/log.h"
#include "util/log_limiter.h"

namespace miracache {

using proto::FrameHeader;
using proto::Op;
using proto::WireStatus;

namespace {
// Sim (a drive hook): a wait ends on its Clock deadline, as in production; the drive hook advances the sim clock when
// the network is idle. Review w5 U2-26: the guard is in sim time, not a call budget: only a sim clock that stands still
// for kMaxStillSpins drive calls in a row ends the wait (as a full timeout). A frozen server therefore holds a job until
// the job's deadline on every build, fast or slow.
constexpr unsigned kMaxStillSpins = 200000;
struct StillGuard {
  Nanos last{-1};
  unsigned still = 0;
  bool stuck(Nanos now) {  // true: the clock did not move in kMaxStillSpins calls
    if (now != last) {
      last = now;
      still = 0;
      return false;
    }
    return ++still > kMaxStillSpins;
  }
};

Error err(ErrorCode c, const char* ctx) { return Error{c, ctx}; }

bool parse_hex16(const std::string& s, std::array<std::uint8_t, 16>& out) {
  if (s.size() != 32) return false;
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  for (std::size_t i = 0; i < 16; ++i) {
    int a = nib(s[2 * i]), b = nib(s[2 * i + 1]);
    if (a < 0 || b < 0) return false;
    out[i] = static_cast<std::uint8_t>(a * 16 + b);
  }
  return true;
}
}  // namespace

namespace {
// `want_rail` < 0: any rail (the single-rail source); else only lines of that rail (RL2).
Expected<proto::Ticket> lab_draw(const std::string& path, std::set<std::array<std::uint8_t, 16>>& used, fabric::EpClass cls,
                                 int want_rail) {
  static const char* names[] = {"control", "fetch", "ingest"};
  std::ifstream in(path);
  if (!in) return err(ErrorCode::NotFound, "wire: cannot open ticket file");
  std::string line;
  while (std::getline(in, line)) {
    std::istringstream ss(line);
    std::string name, rail, hex;
    if (!(ss >> name >> rail >> hex) || name != names[static_cast<int>(cls)]) continue;
    if (want_rail >= 0 && rail != std::to_string(want_rail)) continue;
    std::array<std::uint8_t, 16> id{};
    if (!parse_hex16(hex, id) || used.count(id)) continue;
    used.insert(id);
    proto::Ticket t;
    t.cls = static_cast<std::uint8_t>(cls);
    std::memcpy(t.id, id.data(), 16);
    return t;
  }
  return err(ErrorCode::NotFound, "wire: no unused ticket in ticket file");
}
// J01 (review s8 wave15): paths under the client lock that touched a device fabric lent to build_rails(), process-wide
// (WirePort::lend_violations(); the tests assert it stays 0).
std::atomic<std::uint64_t> g_lend_violations{0};
}  // namespace

TicketFn lab_ticket_file_source(std::string path) {
  auto used = std::make_shared<std::set<std::array<std::uint8_t, 16>>>();
  return [path = std::move(path), used](fabric::EpClass cls) { return lab_draw(path, *used, cls, -1); };
}

RailTicketFn lab_rail_ticket_file_source(std::string path) {
  auto used = std::make_shared<std::set<std::array<std::uint8_t, 16>>>();
  return [path = std::move(path), used](fabric::EpClass cls, std::uint8_t rail) { return lab_draw(path, *used, cls, rail); };
}

// ---- Impl ----------------------------------------------------------------------------------
struct WirePort::Impl {
  struct Ep {
    fabric::Endpoint* ep = nullptr;
    fabric::EpClass cls = fabric::EpClass::Control;
    bool hello = false;
    bool dead = false;
    bool zombie = false;  // torn down: aborted, waiting to be released once drained; frames ignored
    std::uint64_t down_at = 0;  // Q01: the down count whose go_down tore it down (0 = not a session end)
    // RL2: the key of this endpoint in `eps` (the fabric's id, made unique across local devices), its rail position and
    // its device. `ops` / `op_bytes`: READ/WRITE work requests posted through the mux and not completed yet (RC
    // completes one QP's requests in post order, flushes included), the "outstanding bytes" of decisions 7 and 8.
    fabric::EndpointId key = 0;
    std::size_t rail = 0;
    std::size_t dev = 0;
    std::deque<std::uint32_t> ops;
    std::uint64_t op_bytes = 0;
  };
  // RL2: one node rail and its endpoint set (see wire_port.h). Without WireOptions::rails there is one, built from the
  // single-rail options, and the session logic is exactly the single-rail one.
  struct Rail {
    WireOptions::RailOpt o;
    fabric::Fabric* fab = nullptr;
    std::size_t dev = 0;  // index into devs
    bool up = false;      // not given up: its endpoint set is connected (HELLO + SEG_TABLE done)
    fabric::EndpointId ctl = 0, ing = 0;
    std::vector<fabric::EndpointId> fet;
    bool dead = false;  // one of its endpoints died: give it up at the next check_down
    // W01 suspect (per rail): a control RPC on it timed out, or (several rails) three PINGs went unanswered.
    bool suspect = false;
    Nanos suspect_since{0};
    Nanos last_probe{-1};
    Nanos last_frame{0};  // the last intact frame on any of its endpoints
    unsigned unanswered = 0;  // keepalive PINGs sent on its control QP since its last frame (missed-PING detection)
    Nanos last_ping{std::numeric_limits<std::int64_t>::min() / 2};  // when the last of those PINGs went out
    // F04: a SEG_TABLE at least as new as the session's arrived on this rail since its HELLO (the rail may take work)
    bool have_table = false;
    // F04: only tables older than the session's arrived on it (a joining rail: the node may have restarted)
    bool stale_table = false;
    // H02: a HELLO_ACK on this rail carried another boot nonce than the session's: a new process (its tables are ignored)
    bool boot_mismatch = false;
    std::optional<std::uint64_t> seen_nonce;  // J07: the other nonce that rail's HELLO_ACK carried (for the log line)
    unsigned fail_streak = 0;
    Nanos next_attempt{0};
    std::uint64_t put_bytes = 0;  // outstanding put bytes (begun, not done or cancelled)
    std::uint64_t reads = 0, puts = 0, reconnects = 0;
    // RL2 follow-up B: a reconnect in a live session in progress (join_start .. join_step): its HELLOs awaited, by
    // (endpoint key, request id). The rail is not up (takes no work) until every HELLO_ACK and its SEG_TABLE are in.
    bool joining = false;
    Nanos join_deadline{0};
    std::vector<std::pair<fabric::EndpointId, std::uint64_t>> join;
    bool inlock_logged = false;  // J06b / RL3: the in-lock connect fallback was logged for this rail (once per port)
    bool unpaired_logged = false;
    telemetry::Gauge* g_state = nullptr;
    std::uint32_t g_node = ~0u;  // the node ID g_state was made for (goal 10: the series carries it)
    std::string g_host;          // and the hostname ("unknown" when empty)
    // RL3: READ bytes outstanding on its fetch QPs (miracache_read_window) and landed on it (the rail-labelled fetch
    // byte counter); both series carry the node ID, hostname and the rail's address (goal 10).
    std::uint64_t read_out = 0, read_bytes = 0;
    telemetry::Gauge* g_window = nullptr;
    telemetry::Counter* c_read = nullptr;
    // R16: READs/WRITEs that found this rail's QP send queue full (sq_depth) and waited (miracache_client_sq_full_total).
    std::uint64_t sq_full = 0;
    telemetry::Counter* c_sqfull = nullptr;
    // HR7: miracache_client_rail_fetch_qps, the fetch QPs connected on this rail now (fetch_qps while it is up, 0 down):
    // the "QPs per rail" a planned rebuild changes. Same labels as the rail state.
    telemetry::Gauge* g_qps = nullptr;
  };
  // RL2: a put's rail and the remote ranges its WRITEs go to (the mux routes a WRITE by its remote address).
  struct PutRec {
    fabric::EndpointId ep = 0;
    std::size_t rail = 0;
    std::uint64_t bytes = 0;
    std::vector<std::uint64_t> starts;
  };
  struct SegKeys {
    std::uint64_t len = 0;
    std::array<std::uint32_t, 4> rkey{};
  };
  struct Reply {
    FrameHeader h;
    std::vector<std::byte> body;
    bool filled = false;
  };
  struct PendingCommit {
    store::PutDoneFn done;
    std::uint64_t rid = 0;
    fabric::EndpointId ep = 0;
    Nanos deadline{0};
  };

  Impl(fabric::Fabric& in, const Clock& c, NonceSource& n, WireOptions o)
      : inner(in), clock(c), nonce(n), opts(std::move(o)) {
    node_now.store(opts.node, std::memory_order_relaxed);
    devs.push_back(&inner);
    std::vector<WireOptions::RailOpt> ro = opts.rails;
    if (ro.empty()) {
      WireOptions::RailOpt r;
      r.addr = opts.rail;
      ro.push_back(std::move(r));
    }
    for (auto& o2 : ro) {
      auto r = std::make_unique<Rail>();
      r->fab = o2.fab ? o2.fab : &inner;
      auto d = std::find(devs.begin(), devs.end(), r->fab);
      r->dev = static_cast<std::size_t>(d - devs.begin());
      if (d == devs.end()) devs.push_back(r->fab);
      r->o = std::move(o2);
      rails.push_back(std::move(r));
    }
    MIRACACHE_CHECK(!rails.empty());  // R10: an empty opts.rails is rail 0 = opts.rail; code below indexes rails[0]
    mux = rails.size() > 1 || opts.fetch_qps > 1;
  }

  fabric::Fabric& inner;
  const Clock& clock;
  NonceSource& nonce;
  WireOptions opts;

  std::map<fabric::EndpointId, Ep> eps;
  // RL2: rails in node rail order, the distinct local devices ([0] = inner), and whether ClientCore sees the
  // multiplexing endpoints (several rails or fetch QPs) or the single rail's raw endpoints (the unchanged path).
  std::vector<std::unique_ptr<Rail>> rails;
  std::vector<fabric::Fabric*> devs;
  bool mux = false;
  class Mux;
  std::unique_ptr<Mux> mux_fetch, mux_ingest;
  // Landing sub-pool registrations on the other devices: lkey on devs[0] -> the region on devs[d] (index d - 1).
  std::map<std::uint32_t, std::vector<fabric::MemRegion>> alias;
  // The latest SEG_TABLE's per-rail rkeys by segment base, and the state_gen array's.
  std::map<std::uint64_t, SegKeys> seg_keys;
  std::uint64_t sg_base = 0, sg_len = 0;
  std::array<std::uint32_t, 4> sg_rkey{};
  std::map<store::PutId, PutRec> puts;
  std::map<std::uint64_t, std::pair<std::uint64_t, store::PutId>> put_ranges;  // remote start -> (len, put)
  telemetry::Gauge* g_unpaired = nullptr;
  std::uint32_t g_unpaired_node = ~0u;  // the node ID its labels carry
  std::string g_unpaired_host;          // and the hostname ("unknown" when empty)
  telemetry::Counter* c_reissued = nullptr;  // RL3: miracache_client_slices_reissued_total of this node
  std::uint32_t c_reissued_node = ~0u;
  std::string c_reissued_host;
  std::atomic<std::uint64_t> reissued{0};
  // RL3: RENEWs sent and not yet answered, by request id (lease, send time); bounded. A RENEW_ACK OK of one gives
  // (lease, send time + ttl) to take_renewed.
  std::map<std::uint64_t, std::pair<store::LeaseId, Nanos>> renew_sent;
  std::vector<ServerPort::Renewed> renewed;
  std::map<std::pair<fabric::EndpointId, std::uint64_t>, Reply> awaiting;
  std::uint64_t next_rid = 1;
  std::array<std::uint8_t, 16> conn_id{};
  bool have_conn_id = false;
  // H02: the boot nonce of the session's first HELLO_ACK (nullopt: a node that sends none). Reset with the conn_id.
  bool have_boot = false;
  std::optional<std::uint64_t> boot_nonce;
  // K03: HELLO_ACK kTlvTagMaxStoredBlock of the session's first HELLO_ACK (0 = unknown: an older node). Atomic: the
  // adapters' start-up check (Client::block_size_problem) reads it off the core lock.
  std::atomic<std::uint64_t> max_stored{0};
  // K04: PUT_BEGINs refused locally (too large) or by an error reply the job cannot act on: one WARN per reason per
  // minute (with the count dropped in between) and miracache_client_put_refused_total{reason}. Own mutex: rare path.
  std::mutex refuse_mu;
  LogLimiter refuse_log{std::chrono::seconds(60)};
  // L05: the put_refused counters by (ID label, hostname label, reason): no registry lookup per refusal. Under
  // refuse_mu; cleared when the metrics are rebound (the pointers live in the old registry).
  std::map<std::tuple<std::string, std::string, std::string>, telemetry::Counter*> refuse_ctr;
  std::atomic<std::uint64_t> refusals{0};

  bool have_table = false;
  std::uint32_t table_gen = 0;
  ServerInfo info;
  bool info_dirty = false;
  bool goaway = false;
  // Review w4 V08: the last GOAWAY said Epoch (the node left the membership, MB4). Sticky until a session is Up again,
  // so a store routed there is a per-key skip (BeginSkip::Draining), not a failure. Read without the core lock.
  std::atomic<bool> removed{false};
  bool any_dead = false;
  // W01 (per rail since RL2, Rail::suspect): set when a control RPC times out; control RPCs then fail fast (miss) until
  // any frame arrives on that rail. A fail-fast call sends a rate-limited PING so the state clears without keepalive.
  bool full_timeout = false;  // the last wait_until timeout used the whole rpc_timeout (R02)

  // ---- session state machine (see wire_port.h) ----
  enum class Reason { Goaway = 0, EpError = 1, Suspect = 2 };
  std::atomic<int> sess{static_cast<int>(WirePort::Session::Down)};
  std::atomic<std::uint64_t> down_count{0};
  std::atomic<std::uint64_t> attempts_total{0};
  std::atomic<bool> aborting{false};  // Client shutdown: Connecting gives up
  std::atomic<std::uint64_t> restarts_seen{0};  // F04: sessions ended because a rejoining rail found a restarted node (test hook)
  bool drained_by_retire = false;  // HR3b: drain_session took the session Down (not a lost session: not counted)
  Nanos goaway_until{0};              // GOAWAY drain deadline (receipt + drain_ms); 0 = none (r6 A1)
  unsigned fail_streak = 0;           // consecutive failed attempts
  bool config_error = false;          // the last failure was a node_id mismatch or a refused (duplicate) ID
  std::vector<unsigned> rails_connected;  // Q03: node rail indices the last connect_all connected (reconnecting thread)
  std::atomic<std::uint32_t> node_now{0};  // the node ID (opts.node, or learned from HELLO_ACK)
  // F5: the node's hostname from HELLO_ACK (TLV 0x0004; empty = unknown). The caller's own source (opts.hostname: the
  // admin ticket answer or the bundle) has priority; this is the fallback of static/lab mode.
  mutable std::mutex wire_host_mu;
  std::string wire_host;
  std::string host_now() const {
    std::string h = opts.hostname ? opts.hostname() : std::string();
    if (!h.empty()) return h;
    std::lock_guard lk(wire_host_mu);
    return wire_host;
  }
  // Q03: atomic, and always written BEFORE the Down that makes it readable is published.
  std::atomic<Nanos> next_attempt{Nanos{0}};
  // Q01/Q02: true only while a build or reconnect runs on the Client keepalive thread (set through
  // WirePort::set_background / reconnect_step). Then connect uses reconnect_connect_ms on every endpoint
  // and HELLO / SEG_TABLE use the short RPC cap. Written by the keepalive thread only; atomic because job
  // threads read it in wait_until (they run no RPC while the session is not Up, so they see false).
  std::atomic<bool> background{false};
  static constexpr Nanos kBackgroundRpcCap = std::chrono::seconds(2);
  struct BackgroundScope {
    std::atomic<bool>& flag;
    bool prev;
    explicit BackgroundScope(std::atomic<bool>& f) : flag(f), prev(f.exchange(true)) {}
    ~BackgroundScope() { end(); }
    void end() { flag = prev; }  // N06: before the flip to Up, so no job RPC sees the short cap
  };
  // N02/Q01: the down counts whose go_down tore down endpoints that are not all released yet (see
  // ServerPort::session_reaped). Per session, so one endpoint that never drains holds back only its own
  // session's quarantine, not every later one. reap_mu: reap() may run on the keepalive thread off the
  // client lock while the core reads this from a job thread.
  mutable std::mutex reap_mu;
  std::set<std::uint64_t> unreaped;
  ClientMetrics* mx = nullptr;
  WirePort::Session session() const { return static_cast<WirePort::Session>(sess.load()); }
  void set_session(WirePort::Session s) {
    sess.store(static_cast<int>(s));
    if (mx) mx->session_up->set(s == WirePort::Session::Up ? 1 : 0);
    if (!mux) rails[0]->up = s == WirePort::Session::Up;  // single rail: the rail is the session
    publish_rails();
  }
  Nanos op_deadline = Nanos::max();  // absolute; see ServerPort::set_op_deadline
  std::atomic<std::uint64_t> pings{0}, pongs{0};  // read by tests from other threads
  std::atomic<std::uint64_t> late_acks_released{0};  // R04: unmatched LOOKUP_ACK leases given back

  std::map<store::PutId, PendingCommit> commits;
  std::vector<std::function<void()>> ready;
  std::deque<fabric::Completion> stash;

  // Run #233 (RL3 leftover): a rejoining rail's endpoint set, connected OFF the client lock on the rail's own device
  // fabric (see wire_port.h). Only the keepalive thread touches `rbuild` (keepalive(), build_rails(), reconnect_step(),
  // release_all()); `lent_dev` is written by it under the caller's lock (keepalive) or with no job inside (reconnect,
  // close), and read by service() under the lock. At most one build at a time.
  struct RailBuild {
    std::size_t rail = 0;
    std::uint64_t down = 0;  // down_count when lent: a session end since then voids the build
    unsigned conn_ms = 0;    // reconnect_connect_ms when lent (class A)
    bool built = false;      // build_rails() ran
    Status result;
    std::vector<std::pair<fabric::EpClass, fabric::Endpoint*>> made;  // connected, no HELLO yet; not in `eps`
    // J06a (review s8 wave15): a device-level CqError release_made() polled off the lent fabric. It belongs to
    // ClientCore (as absorb() hands it under the lock): take_back() puts it in `stash`.
    std::optional<fabric::Completion> cq_error;
  };
  std::optional<RailBuild> rbuild;
  // The request id of a build's HELLOs (sent off the lock, so not from next_rid; never reached by it). Unique enough:
  // an awaited reply is keyed by (endpoint key, request id) and every built endpoint is fresh.
  static constexpr std::uint64_t kBuildRid = std::uint64_t{1} << 62;
  static constexpr std::size_t kNoDev = ~std::size_t{0};
  std::size_t lent_dev = kNoDev;  // devs[] index lent to build_rails (service() does not poll it)
  std::atomic<std::uint64_t> off_lock_builds{0};  // build_rails() runs that connected a whole set (tests)

  // J01 (review s8 wave15): while devs[lent_dev] is lent, nothing under the client lock may touch it (no endpoint of
  // ours is on it, nothing polls, posts on, registers on or releases into it). Every under-lock entry that reaches a
  // device fabric calls this with the device it is about to touch (kNoDev: every device, e.g. a landing registration).
  // A violation is logged (node ID, hostname, the rail's address), counted (WirePort::lend_violations()) and traps in
  // debug builds: two threads inside one single-threaded fabric is the VerbsCmFabric::poll crash class.
  void lend_check(std::size_t d, const char* where) {
    if (lent_dev == kNoDev || (d != kNoDev && d != lent_dev)) [[likely]]
      return;
    g_lend_violations.fetch_add(1, std::memory_order_relaxed);
    const Rail& r = *rails[rbuild ? rbuild->rail : 0];
    rail_log(log::Level::Error, r, "device fabric lent to the off-lock rail build touched under the client lock", where);
#ifndef NDEBUG
    ::miracache::check_failed("J01: lent device fabric touched under the client lock", __FILE__, __LINE__);
#endif
  }

  // ---- plumbing -----------------------------------------------------------------------
  Ep* find(fabric::EndpointId id) {
    auto it = eps.find(id);
    return it == eps.end() ? nullptr : &it->second;
  }
  // RL2: endpoint ids are per fabric; with several local devices the key carries the device (device 0 keeps the id).
  static fabric::EndpointId key_of(std::size_t dev, fabric::EndpointId id) {
    return dev == 0 ? id : (static_cast<fabric::EndpointId>(dev) << 56) | id;
  }
  Ep* live(fabric::EndpointId id) {
    Ep* e = find(id);
    return e && !e->dead && !e->zombie ? e : nullptr;
  }
  // A rail that may take new work: not given up, no dead endpoint, not suspect, its SEG_TABLE seen.
  bool healthy(const Rail& r) const { return r.up && !r.dead && !r.suspect && r.have_table; }
  WirePort::RailState rail_state(const Rail& r) const {
    if (!r.up) return WirePort::RailState::Down;
    return r.suspect || r.dead ? WirePort::RailState::Suspect : WirePort::RailState::Up;
  }
  std::string node_label() const {
    if (!opts.label.empty()) return opts.label;
    return rails[0]->o.addr.host + ":" + std::to_string(rails[0]->o.addr.port);
  }
  // Goal 10: every rail series and log line carries the node ID, hostname and the rail's IP.
  // F3 (K09): an unknown ID (0, learn mode before the first HELLO_ACK) or hostname (empty) is labelled "unknown", never
  // "0" or "". H08: the series carrying "unknown" are hidden once the identity is learned (they would stay at 0 for
  // ever); the series of a previous real ID (a replaced node) go to 0 as before (F08).
  static std::string id_label(std::uint32_t id) { return id ? std::to_string(id) : std::string("unknown"); }
  std::string host_label() const {
    std::string h = host_now();
    return h.empty() ? std::string("unknown") : h;
  }
  void publish_rails() {
    if (!mx) return;
    const std::uint32_t id = node_now.load(std::memory_order_acquire);
    const std::string ids = id_label(id), host = host_label();
    // A series is stale-unknown when it was made for an unknown ID or hostname.
    auto unk = [](std::uint32_t was, const std::string& h) { return was == 0 || h == "unknown"; };
    auto retire = [&](auto* s, std::uint32_t was, const std::string& h) {
      if (!s) return;
      s->set(0);
      if (unk(was, h) && (id != 0 || host != "unknown")) mx->reg.hide(s);
    };
    for (auto& rp : rails) {
      Rail& r = *rp;
      if (!r.g_state || r.g_node != id || r.g_host != host) {
        retire(r.g_state, r.g_node, r.g_host);  // the series of an ID this node no longer has goes to Down
        retire(r.g_window, r.g_node, r.g_host);
        retire(r.g_qps, r.g_node, r.g_host);
        if (r.c_read && unk(r.g_node, r.g_host) && (id != 0 || host != "unknown")) mx->reg.hide(r.c_read);
        if (r.c_sqfull && unk(r.g_node, r.g_host) && (id != 0 || host != "unknown")) mx->reg.hide(r.c_sqfull);
        const telemetry::Labels l{{"node", node_label()},
                                  {"node_id", ids},
                                  {"hostname", host},
                                  {"rail", std::to_string(r.o.index)},
                                  {"addr", r.o.addr.host + ":" + std::to_string(r.o.addr.port)}};
        r.g_state = &mx->reg.gauge("miracache_client_rail_state", "Client view of one memory-node rail: 0 down, 1 suspect, 2 up.", l);
        r.g_window = &mx->reg.gauge("miracache_read_window", "READ bytes outstanding on one memory-node rail's fetch QPs (RL3).", l);
        r.g_qps = &mx->reg.gauge("miracache_client_rail_fetch_qps",
                                 "Fetch QPs connected on one memory-node rail (fabric.fetch_qps per rail while it is up; HR7).", l);
        r.c_read = &mx->reg.counter("miracache_client_fetch_rail_bytes_total",
                                    "RDMA READ bytes of fetches that landed, by memory-node rail (RL3).", l);
        r.c_sqfull = &mx->reg.counter("miracache_client_sq_full_total",
                                      "READs/WRITEs that found a QP send queue full (sq_depth) on one memory-node rail and "
                                      "waited for room instead of failing (R16).",
                                      l);
        r.g_node = id;
        r.g_host = host;
      }
      r.g_state->set(static_cast<double>(rail_state(r)));
      r.g_window->set(static_cast<std::int64_t>(r.read_out));
      r.g_qps->set(static_cast<std::int64_t>(r.up ? r.fet.size() : 0));
    }
    if (!c_reissued || c_reissued_node != id || c_reissued_host != host) {
      if (c_reissued && unk(c_reissued_node, c_reissued_host) && (id != 0 || host != "unknown"))
        mx->reg.hide(c_reissued);  // H08
      c_reissued = &mx->reg.counter("miracache_client_slices_reissued_total",
                                    "Fetch slices re-issued on another rail after their own failed or flushed completion (RL3).",
                                    {{"node", node_label()},
                                     {"node_id", ids},
                                     {"hostname", host},
                                     {"addr", rails[0]->o.addr.host + ":" + std::to_string(rails[0]->o.addr.port)}});
      c_reissued_node = id;
      c_reissued_host = host;
    }
    // F08 (goal 10): node_id, hostname and addr as the rail series; the series of a previous ID goes to 0.
    if ((mux || opts.unpaired_rails > 0) && (!g_unpaired || g_unpaired_node != id || g_unpaired_host != host)) {
      retire(g_unpaired, g_unpaired_node, g_unpaired_host);  // H08: hidden when it carried the unknown ID
      g_unpaired = &mx->reg.gauge("miracache_client_rail_unpaired",
                                  "Node rails with no local device of their subnet nor a wildcard device, or of another "
                                  "protocol (unused).",
                                  {{"node", node_label()},
                                   {"node_id", ids},
                                   {"hostname", host},
                                   {"addr", rails[0]->o.addr.host + ":" + std::to_string(rails[0]->o.addr.port)}});
      g_unpaired->set(static_cast<double>(opts.unpaired_rails));
      g_unpaired_node = id;
      g_unpaired_host = host;
    }
  }
  // RL3: the rail's outstanding READ bytes changed (a READ posted or completed).
  void read_window_moved(Rail& r, std::int64_t d) {
    r.read_out = d < 0 ? r.read_out - std::min<std::uint64_t>(r.read_out, static_cast<std::uint64_t>(-d))
                       : r.read_out + static_cast<std::uint64_t>(d);
    if (r.g_window) r.g_window->set(static_cast<std::int64_t>(r.read_out));
  }
  void rail_log(log::Level lvl, const Rail& r, std::string_view msg, std::string_view why = {},
                std::initializer_list<log::Field> extra = {}) {
    // L05: "unknown" for an ID not learned yet or an empty hostname, never "0" or "" (as the series).
    std::vector<log::Field> f{{"node_id", id_label(node_now.load(std::memory_order_acquire))},
                              {"hostname", host_label()},
                              {"addr", r.o.addr.host + ":" + std::to_string(r.o.addr.port)},
                              {"rail", std::to_string(r.o.index)},
                              {"device", r.o.device}};
    if (!why.empty()) f.emplace_back("reason", std::string(why));
    for (const auto& e : extra) f.push_back(e);
    log::write(lvl, "client", msg, std::span<const log::Field>(f));
  }
  // J07: a boot nonce as logged ("none": a node that sends none), to match a client line to the node's start line.
  static std::string nonce_text(const std::optional<std::uint64_t>& n) {
    if (!n) return "none";
    char b[24];
    std::snprintf(b, sizeof b, "%016llx", static_cast<unsigned long long>(*n));
    return b;
  }
  // K04: a PUT_BEGIN on rail `r` that failed for `reason` ("too_large" = refused here before sending, else the wire status
  // of the node's error reply): counted per reason (with the node's ID, hostname and address) and logged, rate-limited.
  void put_refused(const Rail& r, const char* reason, int wire_status, const store::PutBeginReq& q) {
    refusals.fetch_add(1, std::memory_order_relaxed);
    std::uint64_t longest = 0;
    for (const auto& k : q.keys) longest = std::max(longest, k.stored_len);
    const std::string ids = id_label(node_now.load(std::memory_order_acquire));
    const std::string host = host_label();
    const std::uint64_t limit = max_stored.load(std::memory_order_acquire);
    std::optional<std::uint64_t> dropped;
    {
      std::lock_guard lk(refuse_mu);
      if (mx) {  // L05: one registry lookup per (ID, hostname, reason), then the cached pointer
        auto& slot = refuse_ctr[{ids, host, reason}];
        if (!slot) {
          for (auto& [k, c] : refuse_ctr)  // the series made while the identity was unknown go quiet (H08)
            if (c && std::get<2>(k) == reason && (std::get<0>(k) == "unknown" || std::get<1>(k) == "unknown") &&
                ids != "unknown" && host != "unknown")
              mx->reg.hide(c);
          slot = &mx->reg.counter("miracache_client_put_refused_total",
                                  "PUT_BEGINs refused before any data moved: too large for the node (refused locally, no "
                                  "round trip) or an error reply other than busy/draining/stale epoch, by reason.",
                                  {{"node", node_label()},
                                   {"node_id", ids},
                                   {"hostname", host},
                                   {"addr", rails[0]->o.addr.host + ":" + std::to_string(rails[0]->o.addr.port)},
                                   {"reason", reason}});
        }
        slot->inc();
      }
      dropped = refuse_log.admit(reason, clock.now());
    }
    if (!dropped) return;
    const bool local = std::string_view(reason) == "too_large";
    std::vector<log::Field> f{{"node_id", ids},
                              {"hostname", host},
                              {"addr", r.o.addr.host + ":" + std::to_string(r.o.addr.port)},
                              {"rail", std::to_string(r.o.index)},
                              {"reason", reason},
                              {"stored_len", std::to_string(longest)},
                              {"keys", std::to_string(q.keys.size())},
                              {"max_stored_block_bytes", limit ? std::to_string(limit) : std::string("unknown")},
                              {"suppressed", std::to_string(*dropped)}};
    if (wire_status >= 0) f.emplace_back("wire_status", std::to_string(wire_status));
    log::write(log::Level::Warn, "client",
               local ? "PUT_BEGIN refused locally: block larger than the memory node's store.run_bytes (raise run_bytes "
                       "on that node; the store is aborted, the engine recomputes)"
                     : "PUT_BEGIN refused by the memory node (the store is aborted, the engine recomputes)",
               std::span<const log::Field>(f));
  }
  // Remote key of `addr` on node rail `index`: the segment's (or the state_gen array's) rkey[index] from SEG_TABLE.
  std::uint32_t remote_rkey(std::uint64_t addr, std::uint8_t index, std::uint32_t fallback) const {
    if (index >= 4) return fallback;
    if (sg_len > 0 && addr >= sg_base && addr - sg_base < sg_len) return sg_rkey[index];
    auto it = seg_keys.upper_bound(addr);
    if (it == seg_keys.begin()) return fallback;
    --it;
    if (addr - it->first < it->second.len) return it->second.rkey[index];
    return fallback;
  }
  // Local key of a landing-pool lkey (registered on devs[0]) on device `dev`.
  std::optional<std::uint32_t> local_lkey(std::uint32_t lkey, std::size_t dev) const {
    if (dev == 0) return lkey;
    auto it = alias.find(lkey);
    if (it == alias.end() || dev - 1 >= it->second.size()) return std::nullopt;
    return it->second[dev - 1].lkey;
  }
  void finish_put(store::PutId id) {
    auto it = puts.find(id);
    if (it == puts.end()) return;
    Rail& r = *rails[it->second.rail];
    r.put_bytes -= std::min(r.put_bytes, it->second.bytes);
    for (auto s : it->second.starts) {
      auto pr = put_ranges.find(s);
      if (pr != put_ranges.end() && pr->second.second == id) put_ranges.erase(pr);
    }
    puts.erase(it);
  }
  void drop_ranges(store::PutId id) {
    auto it = puts.find(id);
    if (it == puts.end()) return;
    for (auto s : it->second.starts) {
      auto pr = put_ranges.find(s);
      if (pr != put_ranges.end() && pr->second.second == id) put_ranges.erase(pr);
    }
    it->second.starts.clear();
  }

  void fail_commit(store::PutId id, store::CommitStatus st) {
    auto it = commits.find(id);
    if (it == commits.end()) return;
    store::PutDoneResult r;
    r.put_id = id;
    r.ep = it->second.ep;
    r.status = st;
    auto done = std::move(it->second.done);
    commits.erase(it);
    finish_put(id);
    ready.push_back([done = std::move(done), r = std::move(r)] { done(r); });
  }

  void mark_dead(Ep& e) {
    if (e.dead || e.zombie) return;
    e.dead = true;
    any_dead = true;
    rails[e.rail]->dead = true;  // RL2: the rail is given up at the next check_down (the session, if it was the last)
    if (e.cls == fabric::EpClass::Ingest) {
      std::vector<store::PutId> ids;
      for (auto& [id, pc] : commits)
        if (pc.ep == e.key) ids.push_back(id);
      for (auto id : ids) fail_commit(id, store::CommitStatus::UnknownPut);
    }
  }

  void rebuild_info(ServerInfo&& i, std::uint32_t gen) {
    info = std::move(i);
    table_gen = gen;
    have_table = true;
    info_dirty = true;
  }

  void on_frame(Ep& e, const fabric::Completion& c) {
    if (e.zombie) return;  // a frame that raced the teardown of its session
    auto fr = proto::decode_frame(c.frame.bytes);
    if (!fr) {
      mark_dead(e);  // corrupt framing from the server: the QP is not trustworthy
      return;
    }
    Rail& rl = *rails[e.rail];
    rl.suspect = false;  // any intact frame (reply, PONG, push) proves the server is answering on this rail
    rl.last_frame = clock.now();
    rl.unanswered = 0;
    const FrameHeader& h = fr->h;
    const bool is_err = (h.flags & proto::flag::ERROR) != 0;
    const auto type = static_cast<Op>(h.type);
    if (opts.on_reply) {  // MB6b: the node's epoch and generation, from any intact frame
      WireOptions::ReplyNote note;
      note.epoch = h.epoch;
      note.bundle_gen_lo = h.bundle_gen_lo;
      if (is_err) {
        auto er = proto::decode_error_reply(h, fr->body);
        note.stale_epoch = er && er->status == static_cast<std::uint16_t>(WireStatus::StaleEpoch);
      }
      opts.on_reply(note);
    }
    // H02: a HELLO_ACK with another boot nonce than the session's comes from a new process. Marked as it arrives, before
    // the SEG_TABLE behind it on the same QP, so that table never replaces the session's (join_step ends the session).
    if (!is_err && type == Op::HELLO_ACK && have_boot) {
      if (auto a = proto::decode_hello_ack(h, fr->body); a && proto::find_boot_nonce(a->tlvs) != boot_nonce) {
        rl.boot_mismatch = true;
        rl.seen_nonce = proto::find_boot_nonce(a->tlvs);
      }
    }
    if (!is_err) {
      switch (type) {
        case Op::SEG_TABLE: {
          if (rl.boot_mismatch) return;  // H02: the new process's table; the session still runs on the old one
          auto t = std::make_unique<proto::SegTable>();
          auto d = proto::decode_seg_table(h, fr->body);
          if (!d) return;
          *t = *d;
          if (!have_table || t->table_gen >= table_gen) {
            auto i = WirePort::info_from_seg_table(*t, node_now.load(std::memory_order_acquire));
            if (i) {  // malformed table: keep the old one
              rebuild_info(std::move(*i), t->table_gen);
              // RL2: every rail's rkeys (one table carries all of them); the mux puts rkey[r] on a READ of rail r.
              seg_keys.clear();
              for (std::size_t k = 0; k < t->n; ++k) {
                const auto& s = t->e[k];
                if (s.flags & 1) continue;
                SegKeys sk;
                sk.len = s.len;
                for (std::size_t q = 0; q < 4; ++q) sk.rkey[q] = s.rkey[q];
                seg_keys[s.base] = sk;
              }
              sg_base = t->sg_base;
              sg_len = static_cast<std::uint64_t>(t->sg_slots) * 8;
              for (std::size_t q = 0; q < 4; ++q) sg_rkey[q] = t->sg_rkey[q];
            }
          }
          // F04: a rail takes work only on a table at least as new as the session's (an accepted one). A rejoining
          // rail that sees only older ones reached a restarted node (table_gen restarts from zero): join_step ends it.
          if (have_table && t->table_gen >= table_gen) rl.have_table = true;
          else if (have_table) rl.stale_table = true;
          return;
        }
        case Op::PONG: {
          ++pongs;
          return;
        }
        case Op::RENEW_ACK: {  // RL3: an OK moves the lease's re-issue deadline (ClientCore, take_renewed)
          auto it = renew_sent.find(h.request_id);
          if (it == renew_sent.end()) return;
          const auto [lease, sent] = it->second;
          renew_sent.erase(it);
          auto a = proto::decode_renew_ack(h, fr->body);
          if (a && a->status == 0 && a->lease_id == lease)
            renewed.push_back({lease, sent + std::chrono::milliseconds(a->ttl_ms)});
          return;
        }
        case Op::GOAWAY: {
          if (!goaway) {
            auto g = proto::decode_goaway(h, fr->body);
            // The drain deadline: the old node is gone by then. A deadline, not a delay (r6 A1).
            goaway_until = g && g->drain_ms > 0 ? clock.now() + std::chrono::milliseconds(g->drain_ms) : Nanos{0};
            if (g && g->reason == static_cast<std::uint32_t>(proto::GoawayReason::Epoch))
              removed.store(true, std::memory_order_release);
          }
          goaway = true;
          return;
        }
        case Op::PUT_DONE: {
          // Only the ingest QP carries PUT_DONE (W07): a control/fetch PUT_DONE is not ours.
          if (e.cls != fabric::EpClass::Ingest) return;
          auto d = proto::decode_put_done(h, fr->body);
          if (!d) return;
          auto it = commits.find(d->put_id);
          if (it == commits.end()) return;  // reply to a cancel, or a late duplicate
          store::PutDoneResult r;
          r.put_id = d->put_id;
          r.ep = c.endpoint;
          r.status = store::CommitStatus::Ok;
          r.e.assign(d->e.begin(), d->e.begin() + d->n);
          auto done = std::move(it->second.done);
          commits.erase(it);
          finish_put(d->put_id);
          ready.push_back([done = std::move(done), r = std::move(r)] { done(r); });
          return;
        }
        default:
          break;
      }
    } else if (type == Op::PUT_COMMIT) {
      for (auto& [id, pc] : commits)
        if (pc.ep == c.endpoint && pc.rid == h.request_id) {
          fail_commit(id, store::CommitStatus::Malformed);
          return;
        }
      return;
    }
    if (is_err) {
      auto er = proto::decode_error_reply(h, fr->body);
      // A Draining refusal of a PUT_BEGIN is the node's member state (bundle mode): a per-key skip, the session stays
      // up (reads and continuations still work). Any other Draining reply is the SIGTERM latch: go Down.
      if (er && er->status == static_cast<std::uint16_t>(WireStatus::Draining) && type != Op::PUT_BEGIN) goaway = true;
      // J04: a refused RENEW (an error reply keeps the request type) is answered: it no longer waits in renew_sent.
      if (type == Op::RENEW || type == Op::RENEW_ACK) renew_sent.erase(h.request_id);
    }
    auto it = awaiting.find({c.endpoint, h.request_id});
    if (it == awaiting.end()) {
      // R04: a LOOKUP_ACK whose waiter already gave up still carries a lease the server counts
      // against the caps until its TTL: hand it back (fire-and-forget RELEASE on control).
      if (!is_err && type == Op::LOOKUP_ACK) {
        auto a = proto::decode_lookup_ack(h, fr->body);
        Ep* ce = e.cls == fabric::EpClass::Control ? &e : live(rails[e.rail]->ctl);  // the control QP it came on
        if (a && a->lease_id != 0 && ce && !ce->dead && !ce->zombie) {
          proto::Release m;
          m.lease_id = a->lease_id;
          std::array<std::byte, 64> body{};
          if (auto n = proto::encode_release(m, body))
            (void)send_raw(*ce, Op::RELEASE, next_rid++, std::span<const std::byte>(body.data(), *n));
          ++late_acks_released;
        }
      }
      return;
    }
    it->second.h = h;
    it->second.body.assign(fr->body.begin(), fr->body.end());
    it->second.filled = true;
  }

  void absorb(fabric::Completion&& c) {
    const bool wire_op = c.is_recv || c.op == fabric::CompletionOp::Send;
    Ep* e = c.op == fabric::CompletionOp::CqError ? nullptr : find(c.endpoint);
    if (e && !wire_op && (c.op == fabric::CompletionOp::Read || c.op == fabric::CompletionOp::Write) && !e->ops.empty()) {
      const std::uint32_t len = e->ops.front();
      e->op_bytes -= std::min<std::uint64_t>(e->op_bytes, len);  // RC: this QP's oldest request
      e->ops.pop_front();
      if (c.op == fabric::CompletionOp::Read) {  // RL3 telemetry: the rail's window and its landed READ bytes
        Rail& r = *rails[e->rail];
        read_window_moved(r, -static_cast<std::int64_t>(len));
        if (c.status) {
          r.read_bytes += len;
          if (r.c_read) r.c_read->inc(len);
        }
      }
    } else if (e && !mux && !wire_op && c.op == fabric::CompletionOp::Read && c.status) {
      // F3 (K06): the single-rail path posts READs straight on the endpoint (no mux bookkeeping): count the landed bytes
      // from the completion, so fetch_rail_bytes_total moves with one rail and fetch_qps = 1 too.
      Rail& r = *rails[e->rail];
      r.read_bytes += c.bytes;
      if (r.c_read) r.c_read->inc(c.bytes);
    }
    // RL2 decision 9: a CQE error on any QP of a rail makes it suspect and gives it up (ERR + flush of all its QPs).
    // Single rail: unchanged (the ERR state check below takes the session Down).
    if (mux && e && !wire_op && !c.status && c.op != fabric::CompletionOp::CqError) mark_dead(*e);
    if (!e || !wire_op) {
      stash.push_back(std::move(c));  // READ/WRITE CQEs and CqError belong to ClientCore
      return;
    }
    if (!c.status) {
      // The core only counts the completions it sees (READ/WRITE/CqError); count the control
      // endpoint's failed SEND/RECV here (M2: rdma_errors_total{kind}).
      if (mx && e->cls == fabric::EpClass::Control) mx->rdma[ClientMetrics::rdma_kind(c.status.error().code)]->inc();
      mark_dead(*e);
      return;
    }
    if (c.is_recv) on_frame(*e, c);
  }

  void service(fabric::PollBudget budget = {}) {
    for (std::size_t d = 0; d < devs.size(); ++d) {
      if (d == lent_dev) continue;  // run #233: build_rails() owns that fabric now (it has no endpoint of ours in eps)
      lend_check(d, "service_poll");  // J01: states the skip above (a poll of the lent device fires it)
      for (;;) {
        std::array<fabric::Completion, 32> buf;
        const std::size_t n = devs[d]->poll(buf, budget);
        if (n == 0) break;
        for (std::size_t i = 0; i < n; ++i) {
          if (buf[i].op != fabric::CompletionOp::CqError) buf[i].endpoint = key_of(d, buf[i].endpoint);
          absorb(std::move(buf[i]));
        }
      }
    }
    for (auto& [id, e] : eps) {
      lend_check(e.dev, "service");  // J01: no endpoint of ours (live or zombie) is on a lent device
      if (!e.dead && !e.zombie && e.ep->state() == fabric::EpState::Error) mark_dead(e);
    }
    const Nanos now = clock.now();
    std::vector<store::PutId> late;
    for (auto& [id, pc] : commits)
      if (now >= pc.deadline) late.push_back(id);
    for (auto id : late) fail_commit(id, store::CommitStatus::UnknownPut);
    check_down(now);  // note: zombies are only reaped from keepalive()/reconnect_step(), never mid-RPC
  }

  unsigned keepalive_ms_now() const {
    return opts.dyn && opts.keepalive_ms > 0 ? opts.dyn->load()->keepalive_ms : opts.keepalive_ms;  // 0 = timer off
  }

  // ---- session: Up -> Down -> Connecting -> Up ---------------------------------------------
  void check_down(Nanos now) {
    if (session() != WirePort::Session::Up) return;
    if (goaway) return go_down(Reason::Goaway);
    const unsigned ka = keepalive_ms_now();
    for (std::size_t i = 0; i < rails.size() && session() == WirePort::Session::Up; ++i) {
      Rail& r = *rails[i];
      if (!r.up) continue;
      if (r.dead) {
        give_up(i, Reason::EpError);
        continue;
      }
      if (r.suspect && ka > 0 && now - r.suspect_since >= std::chrono::milliseconds(3ull * ka)) give_up(i, Reason::Suspect);
    }
  }

  // RL2: gives up rail `i` (decision 9): every QP of the rail goes to ERR, its in-flight work flushes to the core (each
  // completion arrives before the endpoint is released), its puts fail, and it reconnects on its own backoff. The last
  // rail standing takes the session Down instead (the single-rail path: exactly the old go_down).
  void give_up(std::size_t i, Reason why) {
    if (session() != WirePort::Session::Up) return;
    Rail& r = *rails[i];
    bool other = false;
    for (std::size_t q = 0; q < rails.size(); ++q)
      if (q != i && rails[q]->up && !rails[q]->dead) other = true;
    if (!other) return go_down(why);
    std::vector<store::PutId> ids;
    for (auto& [id, pc] : commits) {
      Ep* e = find(pc.ep);
      if (e && e->rail == i) ids.push_back(id);
    }
    for (auto id : ids) fail_commit(id, store::CommitStatus::UnknownPut);
    std::vector<store::PutId> rest;
    for (auto& [id, pr] : puts)
      if (pr.rail == i) rest.push_back(id);
    for (auto id : rest) finish_put(id);
    teardown_rail(i, down_count.load() + 1);  // Q01: held until the session end after it has them released
    r.up = false;
    r.dead = false;
    r.suspect = false;
    r.have_table = false;
    r.stale_table = false;
    r.boot_mismatch = false;
    r.fail_streak = 0;
    schedule_rail(r, clock.now());
    if (mx) mx->reconnect[static_cast<int>(why)]->inc();
    rail_log(log::Level::Warn, r, "rail given up: QPs to ERR, work flushed; reconnects on its own backoff",
             why == Reason::Suspect ? "suspect" : "endpoint_error");
    publish_rails();
  }

  void schedule_rail(Rail& r, Nanos now) {
    const ClientDynPtr dy = opts.dyn ? opts.dyn->load() : nullptr;
    const std::uint64_t lo = std::max(1u, dy ? dy->reconnect_min_ms : opts.reconnect_min_ms),
                        hi = std::max<std::uint64_t>(lo, dy ? dy->reconnect_max_ms : opts.reconnect_max_ms);
    std::uint64_t d = std::min<std::uint64_t>(hi, lo << std::min(r.fail_streak, 20u));
    if (opts.random && d > 1) d = d / 2 + opts.random->below(d / 2 + 1);
    r.next_attempt = now + std::chrono::milliseconds(d);
  }

  void teardown_rail(std::size_t i, std::uint64_t down_at) {
    for (auto& [id, e] : eps) {
      if (e.zombie || e.rail != i) continue;
      lend_check(e.dev, "teardown_rail");
      e.zombie = true;
      e.dead = true;
      e.down_at = down_at;
      e.ep->abort();
    }
    Rail& r = *rails[i];
    r.ctl = r.ing = 0;
    r.fet.clear();
  }

  // Aborts every live endpoint (in-flight work flushes with Aborted and still reaches the core
  // through the stash); they are released by reap() once drained. Local session state is dropped.
  // `down_at` (Q01): the down count go_down is publishing; 0 for endpoints that never carried a live
  // session (a failed attempt, the final release_all).
  void teardown_endpoints(std::uint64_t down_at = 0) {
    for (auto& [id, e] : eps) {
      if (e.zombie) continue;
      lend_check(e.dev, "teardown_endpoints");
      e.zombie = true;
      e.dead = true;
      e.down_at = down_at;
      e.ep->abort();
    }
    for (auto& r : rails) {
      r->ctl = r->ing = 0;
      r->fet.clear();
    }
  }

  void reap() {
    std::set<std::uint64_t> left;  // down_at of the zombies still held by the fabric
    std::size_t undrained = 0;
    for (auto it = eps.begin(); it != eps.end();) {
      lend_check(it->second.dev, "reap");  // J01: releases go to the endpoint's own device, never a lent one
      if (it->second.zombie && it->second.ep->drained() && devs[it->second.dev]->release(it->second.ep)) {
        it = eps.erase(it);
      } else {
        if (it->second.zombie) {
          left.insert(it->second.down_at);
          ++undrained;
        }
        ++it;
      }
    }
    // r7 R05: visible, not force-destroyed. A QP whose flush never completed may still have CQEs coming
    // on the shared CQ that name it; destroying it (and its Ep) first would turn those into use-after-free
    // in the fabric's poll on verbs, and the sim has no such operation. It is in ERR (no new DMA), so
    // holding it costs one QP and its eps entry; the gauge makes a leak alertable.
    if (mx) mx->undrained_zombies->set(static_cast<double>(undrained));
    // N02/Q01: a session end with no zombie left has every endpoint it tore down released. A zombie that
    // never drains (a lost flush) keeps only its own session end listed: the safe direction, and later
    // trips still get their spans back.
    std::lock_guard g(reap_mu);
    std::erase_if(unreaped, [&](std::uint64_t d) { return !left.count(d); });
  }

  bool session_reaped(std::uint64_t down) const {
    if (down == 0 || down > down_count.load()) return false;  // that session has not ended yet
    std::lock_guard g(reap_mu);
    return !unreaped.count(down);
  }

  // r6 A1: a GOAWAY's drain_ms is a deadline, not the first delay. Waiting it out kept clients away
  // for the whole window (5 s by default, up to 10 min) although the node usually exits as soon as
  // its sessions leave and may be back long before. So backoff runs as usual (a draining node
  // refuses the connect without spending the ticket, and fail_streak grows), and no attempt is
  // scheduled after the deadline, by when the old process is gone. (The other option, clamping the
  // first delay to min(hint, reconnect_max_ms), still waits 5 s with the defaults.)
  void schedule_next(Nanos now) {
    const ClientDynPtr dy = opts.dyn ? opts.dyn->load() : nullptr;  // HR2: class A, read at each attempt
    const std::uint64_t lo = std::max(1u, dy ? dy->reconnect_min_ms : opts.reconnect_min_ms),
                        hi = std::max<std::uint64_t>(lo, dy ? dy->reconnect_max_ms : opts.reconnect_max_ms);
    std::uint64_t d;
    if (config_error) {
      d = hi;  // a nodes.id mismatch cannot fix itself: no retry storm
    } else {
      d = std::min<std::uint64_t>(hi, lo << std::min(fail_streak, 20u));
      if (opts.random && d > 1) d = d / 2 + opts.random->below(d / 2 + 1);  // equal jitter: [d/2, d]
    }
    Nanos at = now + std::chrono::milliseconds(d);
    if (goaway_until > now && at > goaway_until) at = goaway_until;  // try again once the drain is over
    next_attempt.store(at);
  }

  // The session ended (or a new one starts): no rail is up, no put is in flight.
  void reset_rails() {
    for (auto& r : rails) {
      r->up = false;
      r->dead = false;
      r->suspect = false;
      r->have_table = false;
      r->stale_table = false;
      r->boot_mismatch = false;
      r->put_bytes = 0;
      for (const auto& k : r->join) awaiting.erase(k);  // RL2 follow-up B: a join of the ended session is over
      r->join.clear();
      r->joining = false;
    }
    puts.clear();
    put_ranges.clear();
    renew_sent.clear();  // RL3: acks of the ended session move no deadline
    renewed.clear();     // J04: nor do the ones it filed and the core has not taken yet (a new session may reuse the ID)
  }

  void go_down(Reason r) {
    if (session() != WirePort::Session::Up) return;
    const std::uint64_t ending = down_count.load() + 1;
    {  // Q01: listed BEFORE the down count moves, so session_reaped(ending) can never be true early
      std::lock_guard g(reap_mu);
      unreaped.insert(ending);
    }
    ++down_count;
    if (mx && !drained_by_retire) mx->reconnect[static_cast<int>(r)]->inc();
    std::vector<store::PutId> ids;
    for (auto& [id, pc] : commits) ids.push_back(id);
    for (auto id : ids) fail_commit(id, store::CommitStatus::UnknownPut);
    teardown_endpoints(ending);  // RPC waiters notice the new down_count and leave
    reset_rails();
    have_table = false;
    info_dirty = false;
    fail_streak = 0;
    config_error = false;
    schedule_next(clock.now());                // Q03: next_attempt is final before Down becomes visible
    set_session(WirePort::Session::Down);
    if (opts.on_down_tickets) opts.on_down_tickets();
    if (opts.on_down) opts.on_down();
  }

  // One attempt: three fresh tickets, HELLO x3, SEG_TABLE on control (open() waits for it).
  //
  // R01: with `hooks` (real time, Client keepalive thread) the attempt runs WITHOUT the client
  // lock. Exclusivity instead comes from the session state: once Connecting is published every
  // job fails fast before touching the port, and hooks->quiesced() waits for the jobs that were
  // already inside to leave. Only the final flip to Up runs under the lock (hooks->install).
  //
  // Q08 precondition: the null-hooks form (no quiesced callback) reaps without checking that no job is
  // inside the shared fabric; it is only correct when the caller serialises it with every job (the
  // caller holds the client lock, or there is no other thread: sim and unit tests).
  void reconnect_step(const WirePort::ReconnectHooks* hooks = nullptr) {
    if (session() != WirePort::Session::Down || aborting) return;
    BackgroundScope bg(background);  // Q01: reconnect_step only ever runs on the keepalive thread
    if (clock.now() < next_attempt.load()) {
      // Off the core lock (hooks) a job admitted while the session was still Up may be pumping the
      // shared fabric right now; releasing endpoints (eps_ erase) under it is a data race that
      // crashed in VerbsCmFabric::poll under live traffic. Reap only once no job is inside.
      if (!hooks || !hooks->quiesced || hooks->quiesced()) {
        drop_build();  // run #233: a rail build of the ended session (eps is touched only once no job is inside)
        reap();
      }
      if (opts.drive) opts.drive();  // sim: lets virtual time pass while nothing else runs
      return;
    }
    ++attempts_total;  // r9c U02: before Connecting, so a HELLO of the previous attempt never counts as current
    set_session(WirePort::Session::Connecting);
    if (hooks && hooks->quiesced) {
      for (unsigned waited = 0; !hooks->quiesced(); ++waited) {
        if (aborting || waited > 200) {  // about 200 ms wall; the sim clock may stand still
          next_attempt.store(clock.now() + std::chrono::milliseconds(20));  // Q03: before Down is published
          set_session(WirePort::Session::Down);  // a job is still winding down: retry shortly
          return;
        }
        if (hooks->wait) hooks->wait();
        else pause_ms(1);
      }
    }
    drop_build();  // run #233: the device a rail build of the ended session borrowed comes back first
    reap();
    goaway = false;
    reset_rails();
    any_dead = false;
    have_table = false;
    have_conn_id = false;  // a new session: a new conn_id
    have_boot = false;  // H02: and the boot nonce of the process it reaches
    boot_nonce.reset();
    Status s = connect_all(/*report_local=*/true);
    // r6 A3: a GOAWAY (or a Draining reply) while connecting means the node is draining. Going Up
    // would only flip Down again at once with the streak reset (retry at reconnect_min_ms, three
    // tickets per cycle): fail the attempt instead, keeping the drain deadline and the streak.
    if (s && !aborting && !goaway) {
      fail_streak = 0;
      config_error = false;
      goaway_until = Nanos{0};
      removed.store(false, std::memory_order_release);  // the node takes sessions again
      bg.end();  // N06: a job admitted right after the flip uses the full rpc_timeout
      if (hooks && hooks->install) hooks->install([this] { set_session(WirePort::Session::Up); });
      else set_session(WirePort::Session::Up);
      // Q03 (review s10): the rails that came up close their endpoint-failure entries (one recovery line); a rail that
      // stayed down keeps its entry until it rejoins.
      if (opts.on_rails_up && !rails_connected.empty()) opts.on_rails_up(rails_connected, /*rejoin=*/false);
      // J07: every rail reached one process. R22: so did every rail that connected when no rail was refused for another
      // boot nonce (a rail that is merely dead, e.g. a cut link, must not keep the damping count of real restarts).
      if (rails_connected.size() == rails.size() || !connect_other_nonce) nonce_restarts = 0;
      return;
    }
    teardown_endpoints();
    if (mx) mx->reconnect_fail->inc();
    ++fail_streak;
    schedule_next(clock.now());  // Q03: before Down is published
    set_session(WirePort::Session::Down);
  }

  // Q04: gives back every endpoint of a port that is about to be destroyed (a failed first build).
  // Aborts them, then waits (bounded, real time) for the fabric to drain so release() succeeds.
  // r7 R04: without `drive` the wait is bounded by real time (`real_until`; 500 ms from now when 0), so a
  // frozen injected clock no longer spins ~200 s. A Client passes one shared deadline to all its nodes.
  void release_all(Nanos real_until = Nanos{0}) {
    drop_build();  // run #233: a staged or built rail set goes back with the rest (as zombies, released below)
    teardown_endpoints();
    const Nanos until = clock.now() + std::chrono::milliseconds(500);
    const RealClock real;
    if (real_until == Nanos{0}) real_until = real.now() + std::chrono::milliseconds(500);
    StillGuard still;
    for (;;) {
      service();  // absorbs the flush completions (READ/WRITE CQEs land in the stash, dropped with the port)
      reap();
      if (eps.empty() || clock.now() >= until || (opts.drive && still.stuck(clock.now()))) break;
      if (!opts.drive && real.now() >= real_until) break;
      if (opts.drive) opts.drive();
      else pause_ms(1);
    }
    stash.clear();
  }

  // L13 (review s9b): after a node restart the session reconnects here (Down -> Connecting -> Up), not through the
  // Client's build() or a rail rejoin. `report_local` (reconnect_step only: the open is reported by Client::build) hands
  // a refusal of the LOCAL device to opts.on_local_failure, so it is counted and logged once, like a join failure.
  void report_local_failure(const Rail& r, const Error& e) {
    if (!fabric::last_local_failure().call || !opts.on_local_failure) return;
    if (fabric::last_local_failure().rail < 0) fabric::last_local_failure().rail = r.o.index;
    opts.on_local_failure(r.o.index, r.o.device, e);
  }
  Status connect_all(bool report_local = false) {
    rails_connected.clear();
    connect_other_nonce = false;
    if (mux) {
      // RL2: every rail gets its own endpoint set; the session comes up with the rails that connect, the others retry
      // on their own backoff (keepalive) while the session is Up.
      Status last = err(ErrorCode::LinkDown, "wire: no rail connected");
      unsigned ok = 0;
      for (std::size_t i = 0; i < rails.size(); ++i) {
        if (aborting) return err(ErrorCode::Aborted, "wire: shutting down");
        if (goaway) break;
        if (report_local) fabric::clear_local_failure();
        Status s = connect_rail(i);
        if (s) {
          ++ok;
          rails_connected.push_back(rails[i]->o.index);
          continue;
        }
        if (rails[i]->boot_mismatch) connect_other_nonce = true;  // R22: this rail reached another process
        if (report_local) report_local_failure(*rails[i], s.error());
        if (config_error) return s;  // a node ID mismatch is not a rail fault
        last = s;
        rails[i]->fail_streak = 1;
        schedule_rail(*rails[i], clock.now());
        rail_log(log::Level::Warn, *rails[i], "rail did not connect; retries on its own backoff", s.error().context);
      }
      return ok > 0 ? Status{} : last;
    }
    for (auto cls : {fabric::EpClass::Control, fabric::EpClass::Fetch, fabric::EpClass::Ingest}) {
      fabric::ConnParams cp;
      cp.cls = cls;
      if (cls != fabric::EpClass::Control) cp.ord = opts.read_depth;
      if (aborting) return err(ErrorCode::Aborted, "wire: shutting down");
      if (report_local) fabric::clear_local_failure();
      auto r = open(cp, 0);
      if (!r) {
        if (report_local) report_local_failure(*rails[0], r.error());
        return r.error();
      }
    }
    rails_connected.push_back(rails[0]->o.index);  // R10: never empty (constructor), so on_rails_up fires after a reconnect
    return {};
  }

  // RL2: one rail's endpoint set (1 control + SEG_TABLE, fetch_qps fetch, 1 ingest), in the session's conn_id. On a
  // failure the endpoints it opened are torn down and the rail stays down.
  Status connect_rail(std::size_t i) {
    Rail& r = *rails[i];
    r.dead = false;
    r.suspect = false;
    r.have_table = false;
    r.stale_table = false;
    r.boot_mismatch = false;
    const unsigned nf = std::max(1u, opts.fetch_qps);
    for (unsigned k = 0; k < nf + 2; ++k) {
      fabric::ConnParams cp;
      cp.cls = k == 0 ? fabric::EpClass::Control : k <= nf ? fabric::EpClass::Fetch : fabric::EpClass::Ingest;
      if (cp.cls != fabric::EpClass::Control) cp.ord = opts.read_depth;
      Status s = aborting ? Status(err(ErrorCode::Aborted, "wire: shutting down")) : Status{};
      if (s) {
        auto ep = open(cp, i);
        if (!ep) s = ep.error();
      }
      if (!s) {
        teardown_rail(i, 0);
        r.up = false;
        r.dead = false;
        return s;
      }
    }
    r.up = true;
    r.last_frame = clock.now();
    r.unanswered = 0;
    publish_rails();
    return {};
  }

  void run_ready() {
    auto r = std::move(ready);
    ready.clear();
    for (auto& f : r) f();
  }

  // ---- sending ------------------------------------------------------------------------
  Status send_raw(Ep& e, Op op, std::uint64_t rid, std::span<const std::byte> body) {
    if (e.dead) return err(ErrorCode::Aborted, "wire: endpoint down");
    lend_check(e.dev, "send");
    Status st = post_frame(*e.ep, op, rid, body);
    if (!st) mark_dead(e);
    return st;
  }
  // One frame on `ep` (no port state touched: build_rails() sends its HELLOs with it, off the lock).
  Status post_frame(fabric::Endpoint& ep, Op op, std::uint64_t rid, std::span<const std::byte> body) const {
    std::array<std::byte, proto::kMaxFrameSize> buf{};
    FrameHeader fh = proto::header_for(op, rid);
    if (opts.stamp) {  // MB6b: the client's epoch and the low 32 bits of its bundle generation
      const std::uint64_t s = opts.stamp->load(std::memory_order_acquire);
      fh.epoch = static_cast<std::uint32_t>(s >> 32);
      fh.bundle_gen_lo = static_cast<std::uint32_t>(s);
    }
    auto n = proto::encode_frame(fh, body, buf);
    if (!n) return err(ErrorCode::InvalidArgument, "wire: frame encode");
    fabric::Frame f;
    f.bytes.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*n));
    return ep.post_send(std::move(f), 0);
  }

  template <class Pred>
  Status wait_until(Pred done, Ep* watch) {
    // min(rpc_timeout, job deadline - now): a job's deadline bounds every RPC it makes (W01).
    const Nanos t0 = clock.now();
    // Q02: a background build or reconnect (keepalive thread) must not sit out a full rpc_timeout per HELLO.
    const Nanos rpc_to = background ? std::min<Nanos>(opts.rpc_timeout, kBackgroundRpcCap) : opts.rpc_timeout;
    const Nanos deadline = std::min(t0 + rpc_to, op_deadline);
    full_timeout = false;
    const std::uint64_t gen = down_count.load();
    StillGuard still;
    auto stopped = [&]() -> bool {
      return (watch && watch->dead) || down_count.load() != gen || aborting.load();
    };
    for (;;) {
      if (done()) return {};
      if (stopped()) return err(ErrorCode::Aborted, "wire: endpoint down");
      if (opts.drive) {
        service();
      } else {
        // No driver: block on the fabric's completion fd (bounded) instead of spinning on poll().
        // Protocol: arm (wait_fd), poll once more to close the race, then sleep on the fd.
        if (devs.size() == 1) lend_check(0, "wait_until");
        const int fd = devs.size() == 1 ? inner.wait_fd() : -1;  // RL2: several devices: no single fd
        if (fd < 0) {
          service(fabric::PollBudget{std::chrono::microseconds(50)});
        } else {
          service();
          if (!done() && !stopped()) {
            const Nanos left = deadline - clock.now();
            if (left > Nanos{0}) {
              struct pollfd pf{fd, POLLIN, 0};
              const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::min<Nanos>(left, std::chrono::milliseconds(1)));
              (void)::poll(&pf, 1, static_cast<int>(std::max<std::int64_t>(1, ms.count())));
            }
          }
        }
      }
      if (done()) return {};
      if (stopped()) return err(ErrorCode::Aborted, "wire: endpoint down");
      if (opts.drive) opts.drive();
      const bool stuck = opts.drive && still.stuck(clock.now());
      if (clock.now() >= deadline || stuck) {
        // Q15 (B): one last non-blocking poll before the timeout. The slice above may end with the awaited frame in
        // the CQ but not filed (the fd poll woke on it, or the sim's drive delivered it in the deadline tick): take it
        // rather than drop it as late. service() with the default budget never waits, runs under the same caller's
        // lock as every slice above, and files each frame once (on_frame), so no extra wait and no double dispatch.
        // Only `done` decides: everything else (stopped, full_timeout, the suspect mark) is as before.
        service();
        if (done()) return {};
        // s11c review P3-5: the endpoint died in that last poll: an abort, not a timeout (no suspect mark).
        if (stopped()) return err(ErrorCode::Aborted, "wire: endpoint down");
        // R02: only a wait that used up the whole rpc_timeout says anything about the server;
        // one cut short by the job's own (shorter) deadline does not.
        full_timeout = clock.now() >= t0 + rpc_to || stuck;
        return err(ErrorCode::Timeout, "wire: no reply");
      }
    }
  }

  // One request, one reply (error replies come back with the ERROR flag set).
  Expected<Reply> rpc(Ep& e, Op op, std::span<const std::byte> body) {
    if (clock.now() >= op_deadline) return err(ErrorCode::Timeout, "wire: job deadline already passed");
    const std::uint64_t rid = next_rid++;
    const auto key = std::make_pair(e.key, rid);
    awaiting[key];
    if (Status st = send_raw(e, op, rid, body); !st) {
      awaiting.erase(key);
      return st.error();
    }
    Status w = wait_until([&] { return awaiting[key].filled; }, &e);
    Reply r = std::move(awaiting[key]);
    awaiting.erase(key);  // a late reply finds no entry in on_frame and is dropped
    if (!w) {
      Rail& rl = *rails[e.rail];
      if (w.error().code == ErrorCode::Timeout && full_timeout && e.cls == fabric::EpClass::Control && !rl.suspect) {
        rl.suspect = true;
        rl.suspect_since = clock.now();
        if (mux) rail_log(log::Level::Warn, rl, "rail suspect: takes no new work", "rpc_timeout");
        publish_rails();
      }
      return w.error();
    }
    return r;
  }

  Status send_ping(Ep& e) {
    proto::Ping p;
    p.timestamp_ns = static_cast<std::uint64_t>(clock.now().count());
    std::array<std::byte, 64> body{};
    auto n = proto::encode_ping(p, body);
    if (!n) return err(ErrorCode::InvalidArgument, "wire: ping encode");
    ++pings;
    return send_raw(e, Op::PING, next_rid++, std::span<const std::byte>(body.data(), *n));
  }

  template <class M, class Enc>
  Expected<Reply> rpc_msg(Ep& e, Op op, const M& m, Enc enc) {
    std::array<std::byte, proto::kMaxBodyLen> body{};
    auto n = enc(m, std::span<std::byte>(body));
    if (!n) return err(ErrorCode::InvalidArgument, "wire: body encode");
    return rpc(e, op, std::span<const std::byte>(body.data(), *n));
  }

  // Control goes on the lowest-index healthy rail (RL2 decision 7); with one rail this is the old single control QP.
  Ep* ctl_pick() {
    for (auto& rp : rails) {
      Rail& r = *rp;
      if (!r.up || (mux && r.dead) || r.suspect) continue;
      if (Ep* e = live(r.ctl)) return e;
    }
    return nullptr;
  }
  Ep* ctl_ep() {
    if (goaway || session() != WirePort::Session::Up) return nullptr;
    if (Ep* e = ctl_pick()) return e;
    bool any_suspect = false;
    for (auto& rp : rails) any_suspect = any_suspect || (rp->up && rp->suspect && live(rp->ctl));
    if (!any_suspect) return nullptr;
    // R02: read what has arrived first - a late reply (any frame) clears the suspicion.
    service();
    if (goaway || session() != WirePort::Session::Up) return nullptr;
    if (Ep* e = ctl_pick()) return e;
    // Fail fast (a miss) until the server proves alive; probe each suspect rail at most every 200 ms.
    const Nanos now = clock.now();
    for (auto& rp : rails) {
      Rail& r = *rp;
      Ep* e = r.up && r.suspect ? live(r.ctl) : nullptr;
      if (!e) continue;
      if (r.last_probe < Nanos{0} || now - r.last_probe >= std::chrono::milliseconds(200)) {
        r.last_probe = now;
        (void)send_ping(*e);
      }
    }
    return nullptr;
  }
  Ep* ing_ep() {
    if (session() != WirePort::Session::Up) return nullptr;
    if (!mux) return live(rails[0]->ing);
    // RL2 decision 7: a put picks the healthy rail with the fewest outstanding put bytes and stays on its ingest QP.
    Ep* best = nullptr;
    std::uint64_t bb = 0;
    for (auto& rp : rails) {
      Rail& r = *rp;
      if (!healthy(r)) continue;
      Ep* e = live(r.ing);
      if (e && (!best || r.put_bytes < bb)) best = e, bb = r.put_bytes;
    }
    return best;
  }
  // The ingest QP a begun put stays on (RL2); single rail: the one ingest QP.
  Ep* put_ep(store::PutId id) {
    if (!mux) return session() == WirePort::Session::Up ? live(rails[0]->ing) : nullptr;
    auto it = puts.find(id);
    return it == puts.end() || session() != WirePort::Session::Up ? nullptr : live(it->second.ep);
  }
  // Any live control QP (RELEASE: fire-and-forget, a suspect rail is fine).
  Ep* any_ctl() {
    if (Ep* e = ctl_pick()) return e;
    for (auto& rp : rails)
      if (Ep* e = live(rp->ctl)) return e;
    return nullptr;
  }

  // RL2: the mux's READ: the healthy rail's fetch QP with the fewest outstanding bytes, that rail's rkey and lkey.
  // RL3 decision 8: weighted least outstanding bytes (op_bytes / weight, weight = link speed) among the fetch QPs of
  // healthy rails whose window has room for this READ (an idle QP always has). None with room: Busy (the core waits).
  Status mux_read(fabric::RemoteRef remote, fabric::LocalRef local, fabric::WrTag tag) {
    if (session() != WirePort::Session::Up) return err(ErrorCode::Aborted, "wire: session down");
    Ep* best = nullptr;
    Rail* sq_rail = nullptr;  // R16: a rail whose fetch QP was skipped for a full send queue
    std::uint64_t bw = 1;
    bool any = false;
    const std::uint64_t win = opts.window_bytes;
    const std::size_t cap = wr_cap();
    for (auto& rp : rails) {
      if (!healthy(*rp)) continue;
      const std::uint64_t w = std::max<std::uint32_t>(1, rp->o.weight);
      for (auto id : rp->fet) {
        Ep* e = live(id);
        if (!e) continue;
        any = true;
        if (win != 0 && e->op_bytes != 0 && e->op_bytes + remote.len > win) continue;  // its window is full
        if (e->ops.size() >= cap) {  // R16: its send queue is full (the 8-byte seq READ counts as one entry too)
          if (!sq_rail) sq_rail = rp.get();
          continue;
        }
        // e->op_bytes / w < best->op_bytes / bw, without division (op_bytes < 2^40, weights < 2^24)
        if (!best || e->op_bytes * bw < best->op_bytes * w) best = e, bw = w;
      }
    }
    if (!best && any && sq_rail) note_sq_full(*sq_rail);
    if (!best) return any ? err(ErrorCode::Busy, "wire: every fetch window is full") : err(ErrorCode::LinkDown, "wire: no healthy rail");
    Rail& r = *rails[best->rail];
    lend_check(r.dev, "mux_read");
    auto lk = local_lkey(local.lkey, r.dev);
    if (!lk) return err(ErrorCode::InvalidArgument, "wire: landing buffer not registered on the rail's device");
    local.lkey = *lk;
    remote.rkey = remote_rkey(remote.addr, r.o.index, remote.rkey);
    Status s = best->ep->post_read(remote, local, tag);
    if (s) {
      best->ops.push_back(remote.len);
      best->op_bytes += remote.len;
      ++r.reads;
      read_window_moved(r, static_cast<std::int64_t>(remote.len));
    } else if (s.error().code == ErrorCode::ResourceExhausted && !best->ops.empty()) {
      note_sq_full(r);  // R16: the provider's send queue is fuller than sq_depth says: backpressure, it waits
      s = err(ErrorCode::Busy, "wire: fetch QP send queue full");
    } else if (s.error().code == ErrorCode::Busy) {
      s = err(ErrorCode::Aborted, "wire: fetch QP refused the READ");  // Busy means "every window full" to the core
    }
    return s;
  }
  // RL2: the mux's WRITE: the ingest QP its put began on (found by the remote address PUT_BEGIN handed out).
  Status mux_write(fabric::LocalRef local, fabric::RemoteRef remote, fabric::WrTag tag) {
    if (session() != WirePort::Session::Up) return err(ErrorCode::Aborted, "wire: session down");
    auto it = put_ranges.upper_bound(remote.addr);
    if (it == put_ranges.begin()) return err(ErrorCode::Aborted, "wire: write outside a live put");
    --it;
    if (remote.addr - it->first >= it->second.first) return err(ErrorCode::Aborted, "wire: write outside a live put");
    auto pr = puts.find(it->second.second);
    Ep* e = pr == puts.end() ? nullptr : live(pr->second.ep);
    if (!e) return err(ErrorCode::Aborted, "wire: the put's rail is down");
    Rail& r = *rails[e->rail];
    if (e->ops.size() >= wr_cap()) {  // R16: the put's ingest QP has a full send queue: the WRITE waits in ClientCore
      note_sq_full(r);
      return err(ErrorCode::Busy, "wire: ingest QP send queue full");
    }
    lend_check(r.dev, "mux_write");
    auto lk = local_lkey(local.lkey, r.dev);
    if (!lk) return err(ErrorCode::InvalidArgument, "wire: put buffer not registered on the rail's device");
    local.lkey = *lk;
    Status s = e->ep->post_write(local, remote, tag);
    if (s) {
      e->ops.push_back(remote.len);
      e->op_bytes += remote.len;
    } else if (s.error().code == ErrorCode::ResourceExhausted && !e->ops.empty()) {
      note_sq_full(r);
      s = err(ErrorCode::Busy, "wire: ingest QP send queue full");
    }
    return s;
  }
  // R16: READs/WRITEs one QP carries at most (its send queue less the frame reserve; at least 1).
  std::size_t wr_cap() const {
    const std::uint32_t d = opts.sq_depth;
    if (d == 0) return static_cast<std::size_t>(-1);
    return d > WireOptions::kSqReserve ? d - WireOptions::kSqReserve : 1;
  }
  void note_sq_full(Rail& r) {
    ++r.sq_full;
    if (!r.c_sqfull && mx) publish_rails();  // makes the series for the current node ID if it is missing
    if (r.c_sqfull) r.c_sqfull->inc();
  }

  static Error from_error_reply(const Reply& r) {
    auto er = proto::decode_error_reply(r.h, r.body);
    if (!er) return err(ErrorCode::Corrupt, "wire: bad error reply");
    switch (static_cast<WireStatus>(er->status)) {
      case WireStatus::Busy: return err(ErrorCode::Busy, "wire: server busy");
      case WireStatus::Draining: return err(ErrorCode::LinkDown, "wire: server draining");
      case WireStatus::Unsupported: return err(ErrorCode::Unsupported, "wire: unsupported by server");
      default: return err(ErrorCode::Corrupt, "wire: server rejected request");
    }
  }

  // ---- connect + HELLO ----------------------------------------------------------------
  proto::Hello hello_for(const Ep& e) const { return hello_of(e.cls, *e.ep, rails[e.rail]->o.index); }
  // The HELLO of endpoint `ep` of class `cls` on node rail `index` (the session's conn_id, written only by the thread
  // that runs builds and reconnects: build_rails() reads it off the lock).
  proto::Hello hello_of(fabric::EpClass cls, const fabric::Endpoint& ep, std::uint8_t index) const {
    proto::Hello h;
    h.major_min = h.major_max = proto::kVerMajor;
    h.minor = proto::kVerMinor;
    h.cls = static_cast<std::uint8_t>(cls);
    const auto rd = ep.read_depth();
    h.ird = rd.ird;
    h.ord = rd.ord;
    h.rail = index;  // RL2: must equal the ticket's rail
    h.proto = opts.wire_proto;
    h.mtu = opts.mtu;
    std::memcpy(h.conn_id, conn_id.data(), 16);
    return h;
  }
  // The HELLO_ACK (or error reply) `r` to the HELLO `h` sent on `e`.
  Status hello_ack(Ep& e, const proto::Hello& h, const Reply& r) {
    if (r.h.flags & proto::flag::ERROR) return from_error_reply(r);
    auto a = proto::decode_hello_ack(r.h, r.body);
    if (!a || a->cls != h.cls || std::memcmp(a->conn_id, h.conn_id, 16) != 0)
      return err(ErrorCode::Corrupt, "wire: bad HELLO_ACK");
    // H02: every HELLO_ACK of a session must carry the boot nonce of its first one (or none, as that one). Checked before
    // the node ID: a restarted node with a wiped store is a restart, not an ID fault.
    const std::optional<std::uint64_t> bn = proto::find_boot_nonce(a->tlvs);
    if (!have_boot) {
      have_boot = true;
      boot_nonce = bn;
      // K03: the node's largest stored block, per session (same process as the boot nonce; 0 = the node did not say).
      max_stored.store(proto::find_max_stored_block(a->tlvs).value_or(0), std::memory_order_release);
    } else if (bn != boot_nonce) {
      rails[e.rail]->boot_mismatch = true;
      rails[e.rail]->seen_nonce = bn;  // J07
      return err(ErrorCode::Corrupt, "wire: HELLO_ACK boot nonce differs (memory node restarted)");
    }
    if (opts.node != 0) {  // fixed expectation (sim and tests)
      if (a->node_id != opts.node) {
        config_error = true;
        return err(ErrorCode::InvalidArgument, "wire: HELLO_ACK node_id differs from the expected node id");
      }
    } else {  // learn mode: the ID is whatever the memory node says (a wiped store brings a new one)
      if (opts.on_node_id) {
        if (Status s = opts.on_node_id(a->node_id); !s) {
          config_error = true;
          return s.error();
        }
      }
      node_now.store(a->node_id, std::memory_order_release);
    }
    // F5/L03: the node's own hostname (absent or invalid = unknown), learned only now that the boot nonce and the node ID
    // accepted this HELLO_ACK: a rejected one (restarted node, wrong or duplicate ID) must not relabel the node. The
    // rails publish with it after this HELLO (publish_rails); the identity series made by the ID above are relabelled
    // by the client's learn_hostname.
    if (auto hn = proto::find_hostname(a->tlvs)) {
      bool changed;
      {
        std::lock_guard lk(wire_host_mu);
        changed = wire_host != *hn;
        wire_host = *hn;
      }
      if (changed && opts.on_node_hostname) opts.on_node_hostname(*hn);
    }
    e.hello = true;
    return {};
  }
  Status do_hello(Ep& e) {
    const proto::Hello h = hello_for(e);
    auto r = rpc_msg(e, Op::HELLO, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
    if (!r) return r.error();
    return hello_ack(e, h, *r);
  }

  // One endpoint of class cp0.cls on rail `ri` (a ticket of that rail), registered in `eps` and the rail's slots; no
  // HELLO yet.
  Expected<Ep*> connect_ep(const fabric::ConnParams& cp0, std::size_t ri) {
    if (!have_conn_id) {
      auto s = nonce.salt();
      if (!s) return s.error();
      for (std::size_t i = 0; i < 16; ++i) conn_id[i] = static_cast<std::uint8_t>(s->b[i]);
      have_conn_id = true;
    }
    // R01/Q01: a build or reconnect that runs on the keepalive thread (`background`, an explicit flag) gives up on a
    // dead or blackholed peer after reconnect_connect_ms on all three endpoints. The first Client::open build keeps the
    // fabric default connect timeout.
    lend_check(rails[ri]->dev, "connect_ep");  // J01: an under-lock connect never runs on a lent device
    // R14 (review s11): a background build with an op deadline (the open's settle) also ends its connect by then.
    unsigned conn_ms = background ? connect_ms_now() : 0;
    if (background && op_deadline != Nanos::max()) {
      const Nanos left = op_deadline - clock.now();
      if (left <= Nanos{0}) return err(ErrorCode::Timeout, "wire: build deadline passed before the connect");
      const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(left + std::chrono::microseconds(999)).count();
      const auto cap = static_cast<unsigned>(std::clamp<std::int64_t>(ms, 1, 1 << 30));
      conn_ms = conn_ms == 0 ? cap : std::min(conn_ms, cap);  // 0 = the fabric default: the cap replaces it
    }
    auto ep = dial(*rails[ri], cp0, conn_ms);
    if (!ep) return ep.error();
    return &adopt_ep(*ep, cp0.cls, ri);
  }
  unsigned connect_ms_now() const { return opts.dyn ? opts.dyn->load()->reconnect_connect_ms : opts.reconnect_connect_ms; }
  // One connected endpoint of class `cls` on rail `rl` (a ticket of that rail; AccessDenied: the next ticket). Reads
  // only what never changes after construction (the options, the rail's address, route and fabric) and the atomic
  // `aborting`, so build_rails() calls it off the client lock. conn_ms: the connect timeout (0 = the fabric default).
  Expected<fabric::Endpoint*> dial(const Rail& rl, const fabric::ConnParams& cp0, unsigned conn_ms) {
    if (!opts.tickets && !opts.rail_tickets) return err(ErrorCode::InvalidArgument, "wire: no ticket source");
    fabric::Endpoint* ep = nullptr;
    Error last = err(ErrorCode::NotFound, "wire: no ticket");
    for (unsigned a = 0; a < std::max(1u, opts.ticket_attempts) && !ep; ++a) {
      // RL2: the node admits a ticket only on its own rail, so each rail draws its own.
      auto t = opts.rail_tickets ? opts.rail_tickets(cp0.cls, rl.o.index) : opts.tickets(cp0.cls);
      if (!t) return t.error();
      if (aborting) return err(ErrorCode::Aborted, "wire: shutting down");
      fabric::ConnParams cp = cp0;
      if (conn_ms > 0) cp.timeout = std::chrono::milliseconds(conn_ms);
      t->cls = static_cast<std::uint8_t>(cp0.cls);
      auto w = proto::encode_ticket(*t, std::span<std::byte>(cp.ticket.data(), 20));
      if (!w) return err(ErrorCode::InvalidArgument, "wire: ticket encode");
      cp.ticket_len = 20;
      const fabric::NodeId route = rl.o.route != 0 ? rl.o.route : opts.route != 0 ? opts.route : opts.node;
      auto r = rl.fab->connect(fabric::Peer{route, rl.o.addr}, cp);
      if (r) {
        ep = *r;
      } else {
        last = r.error();
        // a used/forged ticket (CM reject byte kRejectAdmit only, r8 N01): try the next. Anything else,
        // e.g. LinkDown for a kernel REJ with no miracache byte (no node listening), ends this attempt.
        if (last.code != ErrorCode::AccessDenied) return last;
      }
    }
    if (!ep) return last;
    return ep;
  }
  // Registers a connected endpoint in `eps` and rail `ri`'s slots (no HELLO yet).
  Ep& adopt_ep(fabric::Endpoint* ep, fabric::EpClass cls, std::size_t ri) {
    Rail& rl = *rails[ri];
    lend_check(rl.dev, "adopt_ep");  // J01: finish_build takes the device back before it adopts the built set
    const fabric::EndpointId key = key_of(rl.dev, ep->id());
    Ep& e = eps[key];
    e.ep = ep;
    e.cls = cls;
    e.key = key;
    e.rail = ri;
    e.dev = rl.dev;
    if (cls == fabric::EpClass::Control) rl.ctl = key;
    if (cls == fabric::EpClass::Ingest) rl.ing = key;
    if (cls == fabric::EpClass::Fetch) {
      if (!mux) rl.fet.clear();  // single rail: the one fetch QP
      rl.fet.push_back(key);
    }
    return e;
  }
  // An endpoint whose setup failed: torn down, released by reap() once drained.
  void drop_ep(Ep& e) {
    Rail& rl = *rails[e.rail];
    e.dead = true;
    e.zombie = true;
    e.ep->abort();
    if (rl.ctl == e.key) rl.ctl = 0;
    if (rl.ing == e.key) rl.ing = 0;
    std::erase(rl.fet, e.key);
  }

  Expected<fabric::Endpoint*> open(const fabric::ConnParams& cp0, std::size_t ri) {
    auto pe = connect_ep(cp0, ri);
    if (!pe) return pe.error();
    Ep& e = **pe;
    Rail& rl = *rails[ri];
    Status hs = do_hello(e);
    if (hs && cp0.cls == fabric::EpClass::Control)  // SEG_TABLE follows the HELLO_ACK
      hs = mux ? wait_until([&] { return rl.have_table; }, &e) : wait_until([&] { return have_table; }, &e);
    if (!hs) {
      drop_ep(e);
      return hs.error();
    }
    return e.ep;
  }

  // ---- RL2 follow-up B: a rail's reconnect inside a live session never waits under the caller's (client) lock -------
  // join_start connects the rail's endpoint set and sends every HELLO without waiting; join_step (each keepalive tick)
  // takes the HELLO_ACKs and the SEG_TABLE as service() files them, and the rail takes work (up) only once all are in.
  // Run #233: the connects (and HELLO sends) run off the lock in build_rails() on the rail's lent device fabric; join_start
  // (under the lock) is left for a rail that cannot lend its device (shared with another rail, or a zombie still on it).
  void join_reset(Rail& r) {
    r.dead = false;
    r.suspect = false;
    r.have_table = false;
    r.stale_table = false;
    r.boot_mismatch = false;
    r.join.clear();
  }
  // The k-th endpoint of a rail's set: control, fetch_qps fetch, ingest.
  fabric::ConnParams set_params(unsigned k) const {
    const unsigned nf = std::max(1u, opts.fetch_qps);
    fabric::ConnParams cp;
    cp.cls = k == 0 ? fabric::EpClass::Control : k <= nf ? fabric::EpClass::Fetch : fabric::EpClass::Ingest;
    if (cp.cls != fabric::EpClass::Control) cp.ord = opts.read_depth;
    return cp;
  }
  unsigned set_size() const { return std::max(1u, opts.fetch_qps) + 2; }
  // The fallback (a rail that shares its device, or a zombie still on it): connects under the caller's lock.
  Status join_start(std::size_t i) {
    Rail& r = *rails[i];
    join_reset(r);
    for (unsigned k = 0; k < set_size(); ++k) {
      Status s = aborting ? Status(err(ErrorCode::Aborted, "wire: shutting down")) : Status{};
      if (s) {
        auto pe = connect_ep(set_params(k), i);
        if (!pe) s = pe.error();
      }
      if (!s) {
        join_abort(i);
        return s;
      }
    }
    return join_hellos(i);
  }
  // Sends a HELLO on every endpoint of rail `i` (connected, in eps) without waiting; join_step takes the replies.
  Status join_hellos(std::size_t i) {
    Rail& r = *rails[i];
    std::vector<fabric::EndpointId> keys{r.ctl};
    keys.insert(keys.end(), r.fet.begin(), r.fet.end());
    keys.push_back(r.ing);
    for (auto id : keys) {
      Ep* e = live(id);
      Status s = e ? Status{} : Status(err(ErrorCode::Aborted, "wire: endpoint down"));
      if (s) {
        const proto::Hello h = hello_for(*e);
        std::array<std::byte, proto::kMaxBodyLen> body{};
        auto n = proto::encode_hello(h, std::span<std::byte>(body));
        if (!n) {
          s = err(ErrorCode::InvalidArgument, "wire: body encode");
        } else {
          const auto key = std::make_pair(e->key, next_rid++);
          awaiting[key];
          s = send_raw(*e, Op::HELLO, key.second, std::span<const std::byte>(body.data(), *n));
          if (s) r.join.push_back(key);
          else awaiting.erase(key);
        }
      }
      if (!s) {
        join_abort(i);
        return s;
      }
    }
    r.joining = true;
    r.join_deadline = clock.now() + std::min<Nanos>(opts.rpc_timeout, kBackgroundRpcCap);
    return {};
  }

  // ---- run #233: the rail's connects off the client lock (see wire_port.h and RailBuild) ----
  // Rail `i` may lend its device: no other rail of this port is on it and no endpoint of ours (live or zombie) is left
  // on it, so nothing under the lock polls, posts on or releases into that fabric while build_rails() connects there.
  bool can_lend(std::size_t i) const {
    if (!have_conn_id) return false;  // (a live session always has one; its HELLOs carry it)
    const std::size_t d = rails[i]->dev;
    for (std::size_t q = 0; q < rails.size(); ++q)
      if (q != i && rails[q]->dev == d) return false;
    for (const auto& [id, e] : eps)
      if (e.dev == d) return false;
    return true;
  }
  // J06b / RL3: rail `r` connects under the caller's lock (it cannot lend its device). Counted in
  // miracache_client_rail_connect_inlock_total{node, node_id, hostname, rail, addr}; logged once per rail and port.
  std::uint64_t inlock_connects = 0;  // test hook
  // J07: sessions a rejoining rail ended by another boot nonce since the last session that came up with every rail.
  static constexpr unsigned kNonceDamp = 3;
  unsigned nonce_restarts = 0;
  bool connect_other_nonce = false;  // R22: the last connect_all had a rail refused for another boot nonce
  void note_inlock(Rail& r) {
    ++inlock_connects;
    bool shared = false;
    for (const auto& q : rails)
      if (q.get() != &r && q->dev == r.dev) shared = true;
    if (mx) {
      mx->reg
          .counter("miracache_client_rail_connect_inlock_total",
                   "Rail reconnects that connected under the client lock because the rail's device is shared with "
                   "another rail of the node, or holds an endpoint not released yet (RL3; the node's jobs wait meanwhile).",
                   {{"node", node_label()},
                    {"node_id", id_label(node_now.load(std::memory_order_acquire))},
                    {"hostname", host_label()},
                    {"rail", std::to_string(r.o.index)},
                    {"addr", r.o.addr.host + ":" + std::to_string(r.o.addr.port)}})
          .inc();
    }
    if (r.inlock_logged) return;
    r.inlock_logged = true;
    rail_log(log::Level::Info, r, "rail reconnects under the client lock (its device cannot be lent); the node's jobs wait for the connect",
             shared ? "device_shared_with_another_rail" : "endpoint_not_released_on_device");
  }
  void lend(std::size_t i) {  // under the caller's lock (keepalive)
    RailBuild b;
    b.rail = i;
    b.down = down_count.load();
    b.conn_ms = connect_ms_now();
    rbuild = std::move(b);
    lent_dev = rails[i]->dev;
  }
  // No lock: connects rail rbuild->rail's set on its lent fabric. Touches only that fabric, the build record, the
  // immutable options and rail address, the ticket source (keepalive thread only, or its own mutex) and `aborting`.
  bool build_rails() {
    if (!rbuild || rbuild->built) return false;
    RailBuild& b = *rbuild;
    const Rail& rl = *rails[b.rail];
    fabric::clear_local_failure();  // G09 (Q6): a CQ/QP the local device refuses is reported with its call and errno
    Status s;
    for (unsigned k = 0; k < set_size() && s; ++k) {
      if (aborting) {
        s = err(ErrorCode::Aborted, "wire: shutting down");
        break;
      }
      const fabric::ConnParams cp = set_params(k);
      auto ep = dial(rl, cp, b.conn_ms);
      if (!ep) {
        s = ep.error();
        break;
      }
      b.made.emplace_back(cp.cls, *ep);
      // Its HELLO goes at once (the node's hello_deadline runs from the accept, as with the in-lock path). The reply
      // and the SEG_TABLE wait in the lent fabric's queue until keepalive() takes it back and files them (kBuildRid).
      const proto::Hello h = hello_of(cp.cls, **ep, rl.o.index);
      std::array<std::byte, proto::kMaxBodyLen> body{};
      auto n = proto::encode_hello(h, std::span<std::byte>(body));
      s = n ? post_frame(**ep, Op::HELLO, kBuildRid, std::span<const std::byte>(body.data(), *n))
            : Status(err(ErrorCode::InvalidArgument, "wire: body encode"));
    }
    if (s && aborting) s = err(ErrorCode::Aborted, "wire: shutting down");  // a stop during the last connect
    if (!s) {
      // G09 (review G07, Q6): counted by the Client in miracache_client_endpoint_build_failures_total (thread-local
      // failure record: this thread, before anything else runs on it).
      if (fabric::last_local_failure().call && opts.on_local_failure) {
        if (fabric::last_local_failure().rail < 0) fabric::last_local_failure().rail = rl.o.index;
        opts.on_local_failure(rl.o.index, rl.o.device, s.error());
      }
      release_made(b);
    }
    if (s) off_lock_builds.fetch_add(1, std::memory_order_relaxed);
    b.result = s;
    b.built = true;
    return true;
  }
  // No lock (the fabric is lent): aborts and releases the endpoints a failed or aborted build made; bounded wait for
  // their flushes. Completions on the lent fabric are only theirs (no endpoint of ours is left there). One that does not
  // drain stays in `made` and becomes a zombie when the fabric is taken back (reap() releases it later).
  void release_made(RailBuild& b) {
    fabric::Fabric& f = *rails[b.rail]->fab;
    for (auto& m : b.made) m.second->abort();
    const RealClock real;
    const Nanos real_until = real.now() + std::chrono::milliseconds(500), until = clock.now() + std::chrono::milliseconds(500);
    StillGuard still;
    for (;;) {
      std::array<fabric::Completion, 32> buf;
      for (std::size_t got; (got = f.poll(buf)) > 0;)
        for (std::size_t k = 0; k < got; ++k)
          if (buf[k].op == fabric::CompletionOp::CqError && !b.cq_error) b.cq_error = std::move(buf[k]);  // J06a
      std::erase_if(b.made, [&](const auto& m) { return m.second->drained() && static_cast<bool>(f.release(m.second)); });
      if (b.made.empty() || clock.now() >= until || (opts.drive && still.stuck(clock.now()))) break;
      if (!opts.drive && real.now() >= real_until) break;
      if (opts.drive) opts.drive();
      else pause_ms(1);
    }
  }
  // The lent fabric comes back (caller's lock, or no job inside): a build's endpoints are zombies in eps (aborted,
  // released by reap() once drained). Returns the build for finish_build.
  std::optional<RailBuild> take_back() {
    if (!rbuild) return std::nullopt;
    std::optional<RailBuild> b = std::move(rbuild);
    rbuild.reset();
    lent_dev = kNoDev;
    if (b->cq_error) {  // J06a: the core sees the device's CqError, as if service() had polled it
      stash.push_back(std::move(*b->cq_error));
      b->cq_error.reset();
    }
    return b;
  }
  void zombify(RailBuild& b) {  // into eps only (the rail's slots are not touched)
    for (auto& [cls, ep] : b.made) {
      const std::size_t d = rails[b.rail]->dev;
      const fabric::EndpointId key = key_of(d, ep->id());
      Ep& e = eps[key];
      e.ep = ep;
      e.cls = cls;
      e.key = key;
      e.rail = b.rail;
      e.dev = d;
      e.dead = true;
      e.zombie = true;
      ep->abort();
    }
    b.made.clear();
  }
  void drop_build() {
    if (auto b = take_back()) zombify(*b);
  }
  // keepalive() (caller's lock): a built set joins (HELLOs, then join_step as RL2 follow-up B) if the session it was
  // lent in is still Up; else it is given back. A failed build backs off on the rail's own schedule.
  void finish_build() {
    if (!rbuild || !rbuild->built) return;
    RailBuild b = std::move(*take_back());
    Rail& r = *rails[b.rail];
    const bool same = session() == WirePort::Session::Up && down_count.load() == b.down && !aborting && !goaway;
    if (!b.result || !same || r.up || r.joining) {
      zombify(b);
      if (!b.result && same && !r.up && !r.joining) {
        ++r.fail_streak;
        schedule_rail(r, clock.now());
      }
      return;
    }
    // Their HELLOs are out (build_rails): the replies are awaited from here, before the next service() files them.
    join_reset(r);
    for (auto& [cls, ep] : b.made) {
      const auto key = std::make_pair(adopt_ep(ep, cls, b.rail).key, kBuildRid);
      awaiting[key];
      r.join.push_back(key);
    }
    b.made.clear();
    r.joining = true;
    r.join_deadline = clock.now() + std::min<Nanos>(opts.rpc_timeout, kBackgroundRpcCap);
  }
  // F04: Restarted = the rail's HELLOs were answered but every SEG_TABLE on it was older than the session's by the
  // join deadline: the node behind it is a new process (its table_gen restarted). A table pushed after the HELLO (a
  // registration racing the join) reaches the rail too, so a live node never ends here.
  enum class Join { Pending, Up, Failed, Restarted };
  Join join_step(std::size_t i, Status& why) {
    Rail& r = *rails[i];
    if (r.boot_mismatch) {  // H02: a HELLO_ACK on the rail named another process (on_frame or hello_ack marked it)
      why = err(ErrorCode::Corrupt, "wire: HELLO_ACK boot nonce differs (memory node restarted)");
      return Join::Restarted;
    }
    for (auto it = r.join.begin(); it != r.join.end();) {
      Ep* e = find(it->first);
      if (!e || e->dead || e->zombie) {
        why = err(ErrorCode::Aborted, "wire: endpoint down");
        return Join::Failed;
      }
      auto a = awaiting.find(*it);
      if (a == awaiting.end() || !a->second.filled) {
        ++it;
        continue;
      }
      const Reply rep = std::move(a->second);
      awaiting.erase(a);
      it = r.join.erase(it);
      if (Status s = hello_ack(*e, hello_for(*e), rep); !s) {
        why = s;
        return r.boot_mismatch ? Join::Restarted : Join::Failed;
      }
    }
    if (r.join.empty() && r.have_table) return Join::Up;
    if (clock.now() >= r.join_deadline) {
      if (r.join.empty() && r.stale_table) {
        why = err(ErrorCode::Corrupt, "wire: only older segment tables on the rejoined rail (node restarted)");
        return Join::Restarted;
      }
      why = err(ErrorCode::Timeout, "wire: no reply");
      return Join::Failed;
    }
    return Join::Pending;
  }
  // A join that failed (or the session ended): its replies are no longer awaited and its endpoints are torn down.
  void join_abort(std::size_t i) {
    Rail& r = *rails[i];
    for (const auto& k : r.join) awaiting.erase(k);
    r.join.clear();
    r.joining = false;
    teardown_rail(i, 0);
    r.up = false;
    r.dead = false;
  }
};

// ---- RL2: the multiplexing endpoints ClientCore sees (several rails or fetch QPs) ----------------------------------
class WirePort::Impl::Mux final : public fabric::Endpoint {
 public:
  Mux(Impl& p, fabric::EpClass cls) : p_(p), cls_(cls) {}
  fabric::EndpointId id() const override { return ~fabric::EndpointId{0} - static_cast<fabric::EndpointId>(cls_); }
  Status post_send(fabric::Frame, fabric::WrTag) override {
    return err(ErrorCode::Unsupported, "wire: frames are sent by the port");
  }
  Status post_read(fabric::RemoteRef r, fabric::LocalRef l, fabric::WrTag t) override {
    if (cls_ != fabric::EpClass::Fetch) return err(ErrorCode::InvalidArgument, "wire: READ on the ingest mux");
    return p_.mux_read(r, l, t);
  }
  Status post_write(fabric::LocalRef l, fabric::RemoteRef r, fabric::WrTag t) override {
    if (cls_ != fabric::EpClass::Ingest) return err(ErrorCode::InvalidArgument, "wire: WRITE on the fetch mux");
    return p_.mux_write(l, r, t);
  }
  void abort() override {
    for (auto& [id, e] : p_.eps)
      if (e.cls == cls_) p_.mark_dead(e);
  }
  bool drained() const override {
    for (const auto& [id, e] : p_.eps)
      if (e.cls == cls_ && !e.ep->drained()) return false;
    return true;
  }
  fabric::EpState state() const override { return usable() ? fabric::EpState::Ready : fabric::EpState::Error; }
  fabric::ReadDepth read_depth() const override {
    for (const auto& [id, e] : p_.eps)
      if (e.cls == cls_ && !e.dead && !e.zombie) return e.ep->read_depth();
    return {};
  }
  std::span<const std::byte> peer_private_data() const override { return {}; }
  // A healthy rail has a live endpoint of this class.
  bool usable() const {
    for (const auto& [id, e] : p_.eps)
      if (e.cls == cls_ && !e.dead && !e.zombie && p_.healthy(*p_.rails[e.rail])) return true;
    return false;
  }

 private:
  Impl& p_;
  fabric::EpClass cls_;
};

// ---- the Fabric ClientCore sees --------------------------------------------------------------
class WireFabric final : public fabric::Fabric {
 public:
  explicit WireFabric(WirePort::Impl& p) : p_(p) {}
  // J01: every entry below runs under the client lock (ClientCore's caller) and reaches devs[0] (`inner`) or every
  // device: none may run while that device is lent to build_rails() (lend_check traps in debug builds).
  static constexpr std::size_t kAll = WirePort::Impl::kNoDev;
  Expected<fabric::DeviceCaps> probe() override {
    p_.lend_check(0, "probe");
    return p_.inner.probe();
  }
  Expected<fabric::PdId> alloc_pd() override {
    p_.lend_check(0, "alloc_pd");
    return p_.inner.alloc_pd();
  }
  Status free_pd(fabric::PdId pd) override {
    p_.lend_check(0, "free_pd");
    return p_.inner.free_pd(pd);
  }
  // RL2 (decision 6: one PD per (node, local device)): with several local devices the landing sub-pool is registered on
  // each of them, so a READ on any rail lands in it with that device's lkey (the mux swaps it in).
  Expected<fabric::MemRegion> reg(std::span<std::byte> buf, fabric::Access a, fabric::PdId pd) override {
    p_.lend_check(kAll, "reg");  // J01: the landing pool registers on every device (LandingPool::resize_subpool too)
    auto r = p_.inner.reg(buf, a, pd);
    if (!r || p_.devs.size() == 1) return r;
    std::vector<fabric::MemRegion> al;
    for (std::size_t d = 1; d < p_.devs.size(); ++d) {
      auto q = p_.devs[d]->reg(buf, a, fabric::PdId{});
      if (!q) {
        for (std::size_t k = 0; k < al.size(); ++k) (void)p_.devs[k + 1]->dereg(al[k]);
        (void)p_.inner.dereg(*r);
        return q.error();
      }
      al.push_back(*q);
    }
    p_.alias[r->lkey] = std::move(al);
    return r;
  }
  Status dereg(const fabric::MemRegion& r) override {
    p_.lend_check(kAll, "dereg");
    Status s = p_.inner.dereg(r);
    if (!s) return s;
    auto it = p_.alias.find(r.lkey);
    if (it == p_.alias.end()) return s;
    for (std::size_t k = 0; k < it->second.size(); ++k)
      if (Status q = p_.devs[k + 1]->dereg(it->second[k]); !q) s = q;
    p_.alias.erase(it);
    return s;
  }
  // The Peer and ticket of the caller are ignored: the wire port owns identity and routing.
  Expected<fabric::Endpoint*> connect(const fabric::Peer&, const fabric::ConnParams& cp) override {
    if (cp.cls == fabric::EpClass::Control) return err(ErrorCode::InvalidArgument, "wire: control is opened by the port");
    if (p_.mux) {  // RL2: hello() connected every rail's endpoint set; the core gets the mux of the class
      WirePort::Impl::Mux* m = cp.cls == fabric::EpClass::Fetch ? p_.mux_fetch.get() : p_.mux_ingest.get();
      if (!m->usable()) return err(ErrorCode::LinkDown, "wire: no healthy rail");
      return m;
    }
    return p_.open(cp, 0);
  }
  Status release(fabric::Endpoint* ep) override {
    if (ep == p_.mux_fetch.get() || ep == p_.mux_ingest.get()) return {};
    for (auto it = p_.eps.begin(); it != p_.eps.end(); ++it) {
      if (it->second.ep != ep) continue;
      p_.lend_check(it->second.dev, "release");
      fabric::Fabric* f = p_.devs[it->second.dev];
      p_.eps.erase(it);
      return f->release(ep);
    }
    p_.lend_check(0, "release");
    return p_.inner.release(ep);
  }
  Status listen(fabric::AcceptFn f, const fabric::ListenParams& lp) override {
    p_.lend_check(0, "listen");
    return p_.inner.listen(std::move(f), lp);
  }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget budget) override {
    p_.service(budget);
    std::size_t n = 0;
    while (n < out.size() && !p_.stash.empty()) {
      out[n++] = std::move(p_.stash.front());
      p_.stash.pop_front();
    }
    p_.run_ready();
    return n;
  }
  int wait_fd() override {
    if (p_.devs.size() != 1) return -1;
    p_.lend_check(0, "wait_fd");
    return p_.inner.wait_fd();
  }

 private:
  WirePort::Impl& p_;
};

// ---- WirePort ---------------------------------------------------------------------------
WirePort::WirePort(fabric::Fabric& inner, const Clock& clock, NonceSource& nonce, WireOptions opts)
    : p_(std::make_unique<Impl>(inner, clock, nonce, std::move(opts))), wf_(std::make_unique<WireFabric>(*p_)) {
  p_->mux_fetch = std::make_unique<Impl::Mux>(*p_, fabric::EpClass::Fetch);
  p_->mux_ingest = std::make_unique<Impl::Mux>(*p_, fabric::EpClass::Ingest);
}
WirePort::~WirePort() = default;

fabric::Fabric& WirePort::fabric() { return *wf_; }
bool WirePort::goaway_received() const { return p_->goaway; }
bool WirePort::removed_from_membership() const { return p_->removed.load(std::memory_order_acquire); }
std::uint32_t WirePort::table_gen() const { return p_->table_gen; }
bool WirePort::healthy() const { return !p_->any_dead && p_->session() == Session::Up; }

Expected<ServerInfo> WirePort::hello() {
  if (p_->mux) {
    bool any = false;
    for (auto& r : p_->rails) any = any || r->up;
    if (!any) {
      p_->have_boot = false;  // H02: no rail up: no state of an earlier process is kept, take the nonce of this one
      p_->boot_nonce.reset();
      if (Status s = p_->connect_all(); !s) return s.error();
    }
  } else if (!p_->find(p_->rails[0]->ctl)) {
    fabric::ConnParams cp;
    cp.cls = fabric::EpClass::Control;
    auto ep = p_->open(cp, 0);
    if (!ep) return ep.error();
  }
  p_->set_session(Session::Up);
  p_->info_dirty = false;
  return p_->info;
}

WirePort::Session WirePort::session() const { return p_->session(); }
std::uint32_t WirePort::node_id() const { return p_->node_now.load(std::memory_order_acquire); }
std::uint64_t WirePort::session_down_count() const { return p_->down_count.load(); }
std::uint64_t WirePort::connect_attempts() const { return p_->attempts_total.load(); }
void WirePort::abort_connect() { p_->aborting = true; }
void WirePort::set_background(bool on) { p_->background = on; }
void WirePort::release_endpoints(Nanos real_until) { p_->release_all(real_until); }
// J10: a staged or built rail set is aborted with the rest (its device comes back first; the keepalive threads are joined).
void WirePort::abort_endpoints() {
  p_->drop_build();
  p_->teardown_endpoints();
}
bool WirePort::quiet() const {
  for (const auto& [id, e] : p_->eps)
    if (!e.ep->drained()) return false;
  return true;
}
void WirePort::drain_session() {
  p_->drained_by_retire = true;
  if (p_->session() == Session::Up) p_->go_down(Impl::Reason::EpError);
}
void WirePort::bind_metrics(ClientMetrics* m) {
  // F3 (K09): the series live in the old registry. Hide those still carrying an unknown identity before the pointers go
  // (a rebind to another registry must not leave an "unknown" series behind), and forget the identity they were made
  // for so the next publish_rails() builds them afresh.
  // L02: only in a PRIVATE registry. A series is keyed by its labels, so in the Client's shared registry the successor
  // core of a planned rebuild owns the very same "unknown" series (same pointer) and hiding it here would blank the
  // live one. A shared "unknown" series is hidden by the pair that publishes the real identity (publish_rails), and a
  // series of a build that never got an identity comes back when the next build registers its labels again.
  if (ClientMetrics* old = p_->mx; old && !old->shared_reg) {
    auto unk = [](std::uint32_t was, const std::string& h) { return was == 0 || h == "unknown"; };
    for (auto& r : p_->rails) {
      if (!unk(r->g_node, r->g_host)) continue;
      old->reg.hide(r->g_state);
      old->reg.hide(r->g_window);
      old->reg.hide(r->g_qps);
      old->reg.hide(r->c_read);
      old->reg.hide(r->c_sqfull);
    }
    if (unk(p_->c_reissued_node, p_->c_reissued_host)) old->reg.hide(p_->c_reissued);
    if (unk(p_->g_unpaired_node, p_->g_unpaired_host)) old->reg.hide(p_->g_unpaired);
  }
  {
    std::lock_guard lk(p_->refuse_mu);
    p_->mx = m;
    p_->refuse_ctr.clear();  // L05: the cached counters live in the old registry
  }
  if (p_->opts.on_metrics) p_->opts.on_metrics(m);  // N01: forwards nullptr too (the ticket source unbinds)
  for (auto& r : p_->rails) {
    r->g_state = nullptr, r->g_window = nullptr, r->c_read = nullptr, r->g_qps = nullptr;  // the series live in m's registry
    r->c_sqfull = nullptr;
    r->g_node = ~0u;
    r->g_host.clear();
  }
  p_->c_reissued = nullptr;
  p_->c_reissued_node = ~0u;
  p_->c_reissued_host.clear();
  p_->g_unpaired = nullptr;
  p_->g_unpaired_node = ~0u;
  p_->g_unpaired_host.clear();
  if (!m) return;
  // F3 (K20): the release lend_check only logs and counts; the count is a client metric (read at scrape time).
  m->reg.callback_gauge("miracache_client_lend_violations_total",
                        "Times a device fabric lent to the off-lock rail build was touched under the client lock (J01; must stay 0).",
                        {}, [] { return static_cast<std::int64_t>(g_lend_violations.load(std::memory_order_relaxed)); });
  m->session_up->set(p_->session() == Session::Up ? 1 : 0);
  p_->publish_rails();  // F08: miracache_client_rail_unpaired too (node_id, hostname, addr as the rail series)
}
void WirePort::endpoint_wedged(fabric::EpClass cls) {
  if (p_->mux) {  // the lost completion's rail is unknown: every endpoint of the class (the old single-rail rule)
    for (auto& [id, e] : p_->eps)
      if (e.cls == cls) p_->mark_dead(e);
  } else {
    const Impl::Rail& r = *p_->rails[0];
    const auto id = cls == fabric::EpClass::Control ? r.ctl : cls == fabric::EpClass::Fetch ? (r.fet.empty() ? 0 : r.fet[0]) : r.ing;
    if (Impl::Ep* e = p_->find(id)) p_->mark_dead(*e);
  }
  p_->check_down(p_->clock.now());  // Down now: aborts every endpoint; reap() releases them once drained
}
bool WirePort::session_reaped(std::uint64_t down) const { return p_->session_reaped(down); }
fabric::Endpoint* WirePort::endpoint(fabric::EpClass cls) {
  if (p_->mux) {
    if (cls == fabric::EpClass::Control) {
      Impl::Ep* e = p_->any_ctl();
      return e ? e->ep : nullptr;
    }
    Impl::Mux* m = cls == fabric::EpClass::Fetch ? p_->mux_fetch.get() : p_->mux_ingest.get();
    return m->usable() ? m : nullptr;
  }
  const Impl::Rail& r = *p_->rails[0];
  const auto id = cls == fabric::EpClass::Control ? r.ctl : cls == fabric::EpClass::Fetch ? (r.fet.empty() ? 0 : r.fet[0]) : r.ing;
  Impl::Ep* e = p_->live(id);
  return e ? e->ep : nullptr;
}
void WirePort::prepare_tickets() {
  if (p_->opts.ticket_need) p_->opts.ticket_need(std::max(1u, p_->opts.fetch_qps));  // G01: this port's builds
  if (p_->opts.prepare) p_->opts.prepare();
}
unsigned WirePort::reconnect_wait_ms() const {
  if (p_->session() != Session::Down) return 0;
  const Nanos left = p_->next_attempt.load() - p_->clock.now();
  if (left <= Nanos{0}) return 0;
  return static_cast<unsigned>(std::chrono::duration_cast<std::chrono::milliseconds>(left).count()) + 1;
}

bool WirePort::refresh_info(ServerInfo& info) {
  if (!p_->info_dirty) return false;
  p_->info_dirty = false;
  info = p_->info;
  return true;
}

void WirePort::set_op_deadline(Nanos d) { p_->op_deadline = d; }
void WirePort::keepalive() {
  if (p_->session() != Session::Up) {
    p_->reconnect_step();  // Down: attempt when due; Connecting never overlaps (single caller)
    return;
  }
  p_->reap();
  if (!p_->mux) {
    // G12: one PING per keepalive period, as the mux path (HR7): the node's thread ticks every 5 ms while it waits on a
    // planned rebuild (tick_soon), and each tick used to PING (about 200 PINGs/s to the node during a 30 s drain).
    Impl::Rail& r0 = *p_->rails[0];
    const unsigned per_ms = p_->opts.dyn ? p_->opts.dyn->load()->keepalive_ms : p_->opts.keepalive_ms;  // 0: every tick
    const Nanos ping_now = p_->clock.now();
    Impl::Ep* c = p_->find(r0.ctl);
    if (c && !c->dead && (per_ms == 0 || ping_now - r0.last_ping >= std::chrono::milliseconds(per_ms))) {
      (void)p_->send_ping(*c);
      r0.last_ping = ping_now;
    }
    p_->service();
    p_->publish_rails();  // HR7: as the mux path, so the node's rail series show the active pair after a rebuild
    return;
  }
  // RL2: PING on every rail's control QP (decision 7), then the per-rail reconnects that are due (decision 9: own
  // backoff, own tickets; the rail takes work again only after its HELLOs and SEG_TABLE). Under the caller's lock, with
  // the background (short) connect and RPC caps.
  // HR7 fix: at most one PING per rail per keepalive period (the client's live keepalive_ms). A node's keepalive thread
  // also ticks every few milliseconds while it waits on a planned rebuild (jitter, token, retire: tick_soon), and every
  // such tick used to send a PING and count it as a period, so three fast ticks made a healthy rail suspect before its
  // PONG could arrive (2-rail sim seeds then saw puts end Aborted).
  const unsigned per_ms = p_->opts.dyn ? p_->opts.dyn->load()->keepalive_ms : p_->opts.keepalive_ms;  // 0: every tick
  const Nanos ping_now = p_->clock.now();
  for (auto& r : p_->rails) {
    if (!r->up) continue;
    if (!r->suspect && r->unanswered >= 3) {  // three PINGs went unanswered for a keepalive period each
      r->suspect = true;
      r->suspect_since = p_->clock.now();
      p_->rail_log(log::Level::Warn, *r, "rail suspect: takes no new work", "missed_pings");
    }
    if (per_ms > 0 && ping_now - r->last_ping < std::chrono::milliseconds(per_ms)) continue;
    if (Impl::Ep* c = p_->live(r->ctl)) {
      (void)p_->send_ping(*c);
      ++r->unanswered;
      r->last_ping = ping_now;
    }
  }
  p_->service();
  p_->finish_build();  // run #233: the set build_rails() connected off the lock joins now (HELLOs), or goes back
  const Nanos now = p_->clock.now();
  for (std::size_t i = 0; i < p_->rails.size(); ++i) {
    Impl::Rail& r = *p_->rails[i];
    if (p_->rbuild && p_->rbuild->rail == i) continue;  // its device is lent: build_rails() connects it
    // RL2 follow-up B: a rail rejoins in steps that never wait under the caller's lock (the other rails keep their
    // traffic): one tick connects and sends the HELLOs, later ticks take the replies service() has filed.
    if (r.joining) {
      if (p_->aborting || p_->goaway || p_->session() != Session::Up) continue;
      Status why;
      const Impl::Join js = p_->join_step(i, why);
      if (js == Impl::Join::Up) {
        r.joining = false;
        r.up = true;
        r.last_frame = p_->clock.now();
        r.unanswered = 0;
        r.fail_streak = 0;
        ++r.reconnects;
        p_->nonce_restarts = 0;  // J07: the rail reached the session's process
        p_->rail_log(log::Level::Info, r, "rail up again: takes work after HELLO and SEG_TABLE");
        if (p_->opts.on_rails_up) p_->opts.on_rails_up({r.o.index}, /*rejoin=*/true);  // Q03: closes its failure entries
      } else if (js == Impl::Join::Restarted) {
        // F04: the other rails still talk to the old process (they have not noticed yet) and the session's segment
        // table is that process's: the rail must not take work on it. The session goes Down and reconnects every rail
        // to the new process (fresh conn_id, its SEG_TABLE), instead of flapping until the last old rail dies.
        const bool by_nonce = r.boot_mismatch;  // H02: another boot nonce (any table_gen); else F04: only older tables
        const std::string sess_nonce = Impl::nonce_text(p_->boot_nonce), rail_nonce = Impl::nonce_text(r.seen_nonce);
        p_->join_abort(i);
        // J07 (review s8 wave15): rails of one node ID that reach two processes (a mis-wired node) would end the session
        // at every rejoin, for ever, failing every job in flight. After kNonceDamp such ends in a row (no session since
        // with every rail on one process), the session stays and the odd rail stays down on the long backoff.
        if (by_nonce && p_->nonce_restarts >= Impl::kNonceDamp) {
          r.fail_streak = 20;  // reconnect_max_ms
          p_->schedule_rail(r, p_->clock.now());
          p_->rail_log(log::Level::Error, r,
                       "a rail of this memory node keeps reaching another process (another boot nonce) while the other "
                       "rails stay up: the node looks mis-wired; the session stays, this rail stays down",
                       "boot_nonce_mismatch_repeated",
                       {{"session_boot_nonce", sess_nonce}, {"rail_boot_nonce", rail_nonce},
                        {"restarts_in_row", std::to_string(p_->nonce_restarts)}});
          continue;
        }
        p_->rail_log(log::Level::Warn, r,
                     by_nonce ? "memory node restarted (a rejoining rail saw another boot nonce); the session reconnects"
                              : "memory node restarted (a rejoining rail saw only older segment tables); the session reconnects",
                     by_nonce ? "node_restarted_boot_nonce" : "node_restarted",
                     {{"session_boot_nonce", sess_nonce}, {"rail_boot_nonce", by_nonce ? rail_nonce : sess_nonce}});
        if (by_nonce) ++p_->nonce_restarts;
        p_->go_down(Impl::Reason::EpError);
        ++p_->restarts_seen;
      } else if (js == Impl::Join::Failed) {
        p_->join_abort(i);
        ++r.fail_streak;
        p_->schedule_rail(r, p_->clock.now());
        p_->rail_log(log::Level::Warn, r, "rail did not reconnect; retries on its own backoff", why ? "" : why.error().context);
      }
      continue;
    }
    if (r.up || now < r.next_attempt || p_->aborting || p_->goaway || p_->session() != Session::Up) continue;
    // Run #233: a rail alone on its device connects off the lock (build_rails); one build at a time, the others wait.
    if (p_->can_lend(i)) {
      if (!p_->rbuild) p_->lend(i);
      continue;
    }
    // A rail that shares its device with another rail, or with a zombie not released yet: connects here, under the lock.
    // RL3 / J06b (review s8 wave15): a design limit, not a bug. The other rail's endpoints on that device fabric are
    // polled and posted under the lock, and VerbsCmFabric is single-threaded (connect pumps the device's CM channel
    // and posts receives into the shared CQ), so the device cannot be lent while another rail uses it. The connect is
    // bounded by reconnect_connect_ms per endpoint and stalls only this node's jobs. It is counted and logged once per
    // rail so a shared-device layout (lab rails, or a zombie that never drains) is visible.
    p_->note_inlock(r);
    Impl::BackgroundScope bg(p_->background);  // the short connect cap (reconnect_connect_ms)
    fabric::clear_local_failure();  // G09: a CQ/QP the local device refuses is reported with its call and errno
    Status s = p_->join_start(i);
    bg.end();
    if (!s) {
      if (fabric::last_local_failure().call && p_->opts.on_local_failure) {
        if (fabric::last_local_failure().rail < 0) fabric::last_local_failure().rail = r.o.index;
        p_->opts.on_local_failure(r.o.index, r.o.device, s.error());
      }
      ++r.fail_streak;
      p_->schedule_rail(r, p_->clock.now());
    }
  }
  if (!p_->opts.rail_build_off_lock && p_->build_rails()) p_->finish_build();  // no off-lock caller: here, as before
  p_->publish_rails();
}
bool WirePort::build_rails() { return p_->build_rails(); }
void WirePort::drop_rail_build() { p_->drop_build(); }
bool WirePort::rail_build_pending() const { return p_->rbuild.has_value(); }
std::uint64_t WirePort::off_lock_builds() const { return p_->off_lock_builds.load(std::memory_order_relaxed); }
std::uint64_t WirePort::lend_violations() { return g_lend_violations.load(std::memory_order_relaxed); }
void WirePort::reconnect(const ReconnectHooks& hooks) {
  if (p_->session() == Session::Down) p_->reconnect_step(&hooks);
}
std::uint64_t WirePort::late_acks_released() const { return p_->late_acks_released; }
std::uint64_t WirePort::restarts_detected() const { return p_->restarts_seen; }
std::optional<std::uint64_t> WirePort::boot_nonce() const { return p_->have_boot ? p_->boot_nonce : std::nullopt; }
std::uint64_t WirePort::max_stored_block() const { return p_->max_stored.load(std::memory_order_acquire); }
std::uint64_t WirePort::put_refusals() const { return p_->refusals.load(std::memory_order_relaxed); }
bool WirePort::control_suspect() const {
  bool sus = false, ok = false;
  for (const auto& r : p_->rails) {
    sus = sus || r->suspect;
    ok = ok || (r->up && !r->suspect && !(p_->mux && r->dead));
  }
  return sus && !(p_->mux && ok);
}
std::uint64_t WirePort::pings_sent() const { return p_->pings; }
std::uint64_t WirePort::pongs_received() const { return p_->pongs; }
std::size_t WirePort::rail_count() const { return p_->rails.size(); }
WirePort::RailState WirePort::rail_state(std::size_t pos) const { return p_->rail_state(*p_->rails.at(pos)); }
std::uint8_t WirePort::rail_index(std::size_t pos) const { return p_->rails.at(pos)->o.index; }
std::size_t WirePort::control_rail() const {
  for (std::size_t i = 0; i < p_->rails.size(); ++i) {
    const Impl::Rail& r = *p_->rails[i];
    if (!r.up || (p_->mux && r.dead) || r.suspect) continue;
    auto it = p_->eps.find(r.ctl);
    if (it != p_->eps.end() && !it->second.dead && !it->second.zombie) return i;
  }
  return p_->rails.size();
}
std::uint64_t WirePort::rail_reads(std::size_t pos) const { return p_->rails.at(pos)->reads; }
std::uint64_t WirePort::rail_puts(std::size_t pos) const { return p_->rails.at(pos)->puts; }
std::uint64_t WirePort::rail_reconnects(std::size_t pos) const { return p_->rails.at(pos)->reconnects; }
std::uint64_t WirePort::rail_read_window(std::size_t pos) const { return p_->rails.at(pos)->read_out; }
std::uint64_t WirePort::rail_read_bytes(std::size_t pos) const { return p_->rails.at(pos)->read_bytes; }
std::uint64_t WirePort::slices_reissued() const { return p_->reissued.load(std::memory_order_relaxed); }
std::uint64_t WirePort::rail_sq_full(std::size_t pos) const { return p_->rails.at(pos)->sq_full; }
void WirePort::send_queue_full(fabric::EpClass) { p_->note_sq_full(*p_->rails[0]); }
void WirePort::slice_reissued() {
  p_->reissued.fetch_add(1, std::memory_order_relaxed);
  if (p_->mx) p_->publish_rails();  // makes the series for the current node ID if it is missing
  if (p_->c_reissued) p_->c_reissued->inc();
}

Expected<ServerInfo> WirePort::info_from_seg_table(const proto::SegTable& t, fabric::NodeId node) {
  ServerInfo i;
  i.node = node;
  const unsigned rail = t.local_rail < t.n_rails ? t.local_rail : 0;
  std::size_t max_id = 0;
  for (std::size_t k = 0; k < t.n; ++k) {
    // The server never announces more than ~200 segments; a larger id would make us allocate
    // a huge region vector (W04). Reject the whole table.
    if (t.e[k].seg_id >= kMaxSegId) return err(ErrorCode::Corrupt, "wire: SEG_TABLE seg_id out of range");
    max_id = std::max<std::size_t>(max_id, t.e[k].seg_id + 1);
  }
  i.segs.assign(max_id, fabric::MemRegion{});
  for (std::size_t k = 0; k < t.n; ++k) {
    const auto& s = t.e[k];
    if (s.flags & 1) continue;  // REMOVED: stays an empty region
    fabric::MemRegion& m = i.segs[s.seg_id];
    m.addr = reinterpret_cast<std::byte*>(s.base);
    m.len = s.len;
    m.rkey = s.rkey[rail];
    m.access = fabric::Access::RemoteRead;
  }
  i.array.addr = reinterpret_cast<std::byte*>(t.sg_base);
  i.array.len = t.sg_slots * 8;
  i.array.rkey = t.sg_rkey[rail];
  i.array.access = fabric::Access::RemoteRead;
  return i;
}

store::LookupAck WirePort::lookup_presence(const store::LookupReq& q) { return lookup_impl(q, false); }
store::LookupAck WirePort::lookup(const store::LookupReq& q) { return lookup_impl(q, true); }

store::LookupAck WirePort::lookup_impl(const store::LookupReq& q, bool lease) {
  store::LookupAck out;  // empty entries = every key a MISS
  Impl::Ep* c = p_->ctl_ep();
  if (!c || q.keys.empty()) return out;
  auto m = std::make_unique<proto::Lookup>();
  std::memcpy(m->scope_id, q.scope.data(), 32);
  m->flags = lease ? 1 : 0;  // bit0 LEASE; 0 = PROBE (presence checks take no lease, W06)
  // ClientCore splits larger batches (max_lookup_keys()); a direct caller's tail is a MISS.
  m->n = static_cast<std::uint16_t>(std::min<std::size_t>(q.keys.size(), proto::kMaxLookupKeys));
  for (std::size_t i = 0; i < m->n; ++i) std::memcpy(m->key_hash[i].data(), q.keys[i].data(), 32);
  auto r = p_->rpc_msg(*c, Op::LOOKUP, *m, [](const proto::Lookup& x, std::span<std::byte> o) { return proto::encode_lookup(x, o); });
  if (!r || (r->h.flags & proto::flag::ERROR)) return out;
  auto a = proto::decode_lookup_ack(r->h, r->body);
  if (!a) return out;
  // A decoded ack may carry a lease even when we reject it: give it back (W03).
  bool bad = a->n != m->n;
  for (std::size_t i = 0; !bad && i < a->n; ++i)
    bad = a->e[i].status == 1 && a->e[i].stored_len > UINT32_MAX;  // W05: lengths go into u32 READs
  if (bad) {
    if (a->lease_id != 0) (void)release(a->lease_id);
    return out;
  }
  out.lease = a->lease_id;
  out.lease_expiry = p_->clock.now() + std::chrono::milliseconds(a->ttl_ms);
  out.entries.resize(a->n);
  for (std::size_t i = 0; i < a->n; ++i) {
    const auto& e = a->e[i];
    if (e.status != 1) continue;
    out.entries[i] = store::LookupEntry{true, e.seg_id, e.offset, e.stored_len, e.gen, e.gen_slot};
  }
  return out;
}

Status WirePort::renew(store::LeaseId lease) {
  Impl::Ep* c = p_->ctl_ep();
  if (!c) return err(ErrorCode::LinkDown, "wire: control endpoint down");
  proto::Renew m;
  m.lease_id = lease;
  // Fire-and-forget (W01): the RENEW_ACK matches nothing and is dropped in on_frame (it still
  // counts as proof of life). A lost renewal is harmless: the seq check rejects stale reads.
  std::array<std::byte, proto::kMaxBodyLen> body{};
  auto n = proto::encode_renew(m, body);
  if (!n) return err(ErrorCode::InvalidArgument, "wire: renew encode");
  const std::uint64_t rid = p_->next_rid++;
  const Nanos sent = p_->clock.now();  // before the send: the node renews after this (conservative)
  Status s = p_->send_raw(*c, Op::RENEW, rid, std::span<const std::byte>(body.data(), *n));
  if (s) {
    if (p_->renew_sent.size() >= 4096) p_->renew_sent.erase(p_->renew_sent.begin());  // acks lost: oldest first
    p_->renew_sent[rid] = {lease, sent};
  }
  return s;
}
void WirePort::take_renewed(std::vector<Renewed>& out) {
  out.clear();
  out.swap(p_->renewed);
}

Status WirePort::release(store::LeaseId lease) {
  Impl::Ep* c = p_->any_ctl();
  if (!c || c->dead) return err(ErrorCode::LinkDown, "wire: control endpoint down");
  proto::Release m;
  m.lease_id = lease;
  std::array<std::byte, 64> body{};
  auto n = proto::encode_release(m, body);
  if (!n) return err(ErrorCode::InvalidArgument, "wire: release encode");
  return p_->send_raw(*c, Op::RELEASE, p_->next_rid++, std::span<const std::byte>(body.data(), *n));  // no reply
}

store::PutBeginAck WirePort::put_begin(const store::PutBeginReq& q) {
  store::PutBeginAck out;
  out.status = store::BeginStatus::Malformed;
  if (p_->session() != Session::Up || p_->goaway) {
    out.status = store::BeginStatus::Refused;  // retry 0: the client drops the store and recomputes later
    // Review w4 V08: a node that left the membership (GOAWAY reason Epoch) skips the store, as a Draining refusal
    // does; a shutdown or a node that is down stays a refusal.
    if (p_->removed.load(std::memory_order_acquire)) out.skip = store::BeginSkip::Draining;
    return out;
  }
  Impl::Ep* c = p_->ing_ep();
  if (!c || q.keys.empty() || q.keys.size() > proto::kMaxPutKeys) return out;
  // K03: a key longer than the node's largest stored block is refused by the node anyway (Malformed); refuse it here,
  // with the same outcome (the batch is aborted) and no round trip.
  if (const std::uint64_t lim = p_->max_stored.load(std::memory_order_acquire); lim != 0) {
    for (const auto& k : q.keys)
      if (k.stored_len > lim) {
        p_->put_refused(*p_->rails[c->rail], "too_large", -1, q);
        return out;
      }
  }
  const std::size_t ri = c->rail;  // K04: kept for the refusal log after the RPC
  ++p_->rails[ri]->puts;
  auto m = std::make_unique<proto::PutBegin>();
  std::memcpy(m->scope_id, q.scope.data(), 32);
  m->n = static_cast<std::uint16_t>(q.keys.size());
  for (std::size_t i = 0; i < q.keys.size(); ++i) {
    auto& e = m->e[i];
    std::memcpy(e.key_hash, q.keys[i].key.data(), 32);
    std::memcpy(e.parent_hash, q.keys[i].parent.data(), 16);  // wire carries a 16 B prefix (spec 5.2)
    e.chain_pos = q.keys[i].chain_pos;
    e.stored_len = q.keys[i].stored_len;
  }
  // PUT_BEGIN timeout caveat (W03): if the ack is lost or late the server still holds the
  // reservation (MRs + bytes) for a put we never learn the id of, so it cannot be cancelled;
  // it is reclaimed by the server's put_timeout TTL. The job just aborts (the engine recomputes).
  auto r = p_->rpc_msg(*c, Op::PUT_BEGIN, *m, [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); });
  if (!r) {
    // V08: the GOAWAY(Epoch) arrived while this PUT_BEGIN waited (its endpoint went down under it): a skip as well.
    if (p_->removed.load(std::memory_order_acquire)) {
      out.status = store::BeginStatus::Refused;
      out.skip = store::BeginSkip::Draining;
    }
    return out;
  }
  if (r->h.flags & proto::flag::ERROR) {
    auto er = proto::decode_error_reply(r->h, r->body);
    if (er && er->status == static_cast<std::uint16_t>(WireStatus::Busy)) {
      out.status = store::BeginStatus::Refused;
      out.retry_after_ms = std::max<std::uint32_t>(er->retry_after_ms, 1);
    } else if (er && er->status == static_cast<std::uint16_t>(WireStatus::Draining)) {
      out.status = store::BeginStatus::Refused;
      out.skip = store::BeginSkip::Draining;  // MB6b: skipped, not failed
    } else if (er && er->status == static_cast<std::uint16_t>(WireStatus::StaleEpoch)) {
      out.status = store::BeginStatus::Refused;  // no in-job retry whatever the node's retry hint says
      out.retry_after_ms = 0;
      out.skip = store::BeginSkip::StaleEpoch;
    } else {  // K04: Malformed (a block too large for an older node), Unsupported, or an undecodable reply: loud, counted
      const char* why = !er                                                                 ? "bad_reply"
                        : er->status == static_cast<std::uint16_t>(WireStatus::Malformed)   ? "malformed"
                        : er->status == static_cast<std::uint16_t>(WireStatus::Unsupported) ? "unsupported"
                                                                                            : "other";
      p_->put_refused(*p_->rails[ri], why, er ? static_cast<int>(er->status) : -1, q);
    }
    return out;
  }
  auto a = proto::decode_put_begin_ack(r->h, r->body);
  if (!a) return out;
  out.put_id = a->put_id;
  out.retry_after_ms = a->retry_after_ms;
  if (a->status != 0) {
    out.status = store::BeginStatus::Refused;
    return out;
  }
  if (a->n != q.keys.size()) return out;
  out.status = store::BeginStatus::Ok;
  for (std::size_t i = 0; i < a->n_mr; ++i) out.mr.push_back(store::MrRef{a->mr[i].addr, a->mr[i].len, a->mr[i].rkey});
  out.entries.resize(a->n);
  for (std::size_t i = 0; i < a->n; ++i) {
    const auto& e = a->e[i];
    if (e.status != 1) continue;
    out.entries[i] = store::BeginEntry{true, e.mr_index, e.offset};
  }
  if (p_->mux) {  // RL2: the put stays on this rail's ingest QP; its WRITEs are routed by their remote address
    Impl::PutRec pr;
    pr.ep = c->key;
    pr.rail = c->rail;
    p_->finish_put(a->put_id);  // a reused id (the node restarted its counter): the old record is stale
    for (std::size_t i = 0; i < a->n; ++i) {
      const auto& e = a->e[i];
      if (e.status != 1 || e.mr_index >= a->n_mr) continue;
      const std::uint64_t at = a->mr[e.mr_index].addr + e.offset;
      p_->put_ranges[at] = {q.keys[i].stored_len, a->put_id};
      pr.starts.push_back(at);
      pr.bytes += q.keys[i].stored_len;
    }
    p_->rails[c->rail]->put_bytes += pr.bytes;
    p_->puts[a->put_id] = std::move(pr);
  }
  return out;
}

void WirePort::put_commit(const store::PutCommitReq& q, store::PutDoneFn done) {
  auto fail = [&](store::CommitStatus st) {
    store::PutDoneResult r;
    r.put_id = q.put_id;
    r.status = st;
    p_->ready.push_back([done = std::move(done), r = std::move(r)] { done(r); });
  };
  Impl::Ep* c = p_->put_ep(q.put_id);  // RL2: the ingest QP the put began on
  if (!c || q.e.empty() || q.e.size() > proto::kMaxPutKeys) return fail(store::CommitStatus::UnknownPut);
  // A live commit with the same put_id keeps its slot (W07): the duplicate fails, never overwrites.
  if (p_->commits.count(q.put_id)) return fail(store::CommitStatus::UnknownPut);
  auto m = std::make_unique<proto::PutCommit>();
  m->put_id = q.put_id;
  m->n = static_cast<std::uint16_t>(q.e.size());
  for (std::size_t i = 0; i < q.e.size(); ++i)
    m->e[i] = proto::CommitEntry{q.e[i].key_index, q.e[i].crc32c, q.e[i].stored_len};
  std::array<std::byte, proto::kMaxBodyLen> body{};
  auto n = proto::encode_put_commit(*m, body);
  if (!n) return fail(store::CommitStatus::Malformed);
  const std::uint64_t rid = p_->next_rid++;
  // Registered before the send: the reply can only be seen by a later poll anyway. The COMMIT
  // goes out on the ingest QP after the WRITEs, so the server sees it after the placed bytes.
  Impl::PendingCommit pc;
  pc.done = std::move(done);
  pc.rid = rid;
  pc.ep = c->key;
  pc.deadline = p_->clock.now() + p_->opts.commit_timeout;
  p_->commits[q.put_id] = std::move(pc);
  p_->drop_ranges(q.put_id);  // every WRITE is posted before the COMMIT
  if (Status st = p_->send_raw(*c, Op::PUT_COMMIT, rid, std::span<const std::byte>(body.data(), *n)); !st)
    p_->fail_commit(q.put_id, store::CommitStatus::UnknownPut);
}

void WirePort::put_cancel(store::PutId id, store::PutDoneFn) {
  Impl::Ep* c = p_->put_ep(id);
  if (!c) {
    p_->finish_put(id);
    return;
  }
  proto::PutCancel m;
  m.put_id = id;
  std::array<std::byte, 64> body{};
  auto n = proto::encode_put_cancel(m, body);
  if (!n) return;
  // The PUT_DONE reply to a cancel matches no pending commit and is dropped.
  (void)p_->send_raw(*c, Op::PUT_CANCEL, p_->next_rid++, std::span<const std::byte>(body.data(), *n));
  p_->finish_put(id);
}

Status WirePort::invalidate(const store::ScopeId& scope, const store::KeyHash& key, std::uint64_t gen) {
  Impl::Ep* c = p_->ctl_ep();
  if (!c) return err(ErrorCode::LinkDown, "wire: control endpoint down");
  proto::Invalidate m;
  std::memcpy(m.scope_id, scope.data(), 32);
  std::memcpy(m.key_hash, key.data(), 32);
  m.gen = gen;
  // Fire-and-forget (W01): best effort, the reply is dropped in on_frame.
  std::array<std::byte, proto::kMaxBodyLen> body{};
  auto n = proto::encode_invalidate(m, body);
  if (!n) return err(ErrorCode::InvalidArgument, "wire: invalidate encode");
  return p_->send_raw(*c, Op::INVALIDATE, p_->next_rid++, std::span<const std::byte>(body.data(), *n));
}

Expected<std::vector<std::byte>> WirePort::stats(std::uint32_t selector) {
  Impl::Ep* c = p_->ctl_ep();
  if (!c) return err(ErrorCode::LinkDown, "wire: control endpoint down");
  proto::Stats m;
  m.selector = selector;
  auto r = p_->rpc_msg(*c, Op::STATS, m, [](const proto::Stats& x, std::span<std::byte> o) { return proto::encode_stats(x, o); });
  if (!r) return r.error();
  if (r->h.flags & proto::flag::ERROR) return Impl::from_error_reply(*r);
  auto a = proto::decode_stats_ack(r->h, r->body);
  if (!a) return err(ErrorCode::Corrupt, "wire: bad STATS_ACK");
  return std::vector<std::byte>(a->tlvs.begin(), a->tlvs.end());
}

}  // namespace miracache
