// SPDX-License-Identifier: Apache-2.0
// RL2: client rails and connections (multi-rail plan decisions 1, 5, 6, 7, 9) over the simulator, against an RL1
// memory node with two devices, one rail each (distinct rkeys per device), and a client with two local devices.
// Each rail has its own endpoint set (control, fetch_qps fetch, ingest) in one session; ClientCore talks to the two
// multiplexing endpoints. Flushing rail 1 keeps the node Up and puts move; the rail comes back on its own backoff;
// losing the control rail moves control; a suspect rail takes no new work; nodes[].rails > 4 is rejected.
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <optional>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <unistd.h>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "fabric/sim/sim_fabric.h"
#include "miracache/config.h"
#include "server/server.h"
#include "src/client.h"
#include "src/client_core.h"
#include "src/rail_pairing.h"
#include "src/wire_port.h"
#include "util/log.h"
#include "util/oracle.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;
using std::chrono::milliseconds;
using std::chrono::seconds;

class CounterSalts final : public NonceSource {
 protected:
  Status fill(std::span<std::byte> out) override {
    const unsigned n = n_.fetch_add(1, std::memory_order_relaxed) + 1;
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::byte>(n * 37 + i * 5 + 1);
    return {};
  }
  std::atomic<unsigned> n_{0};
};

class TestKeys final : public KeySource {
 public:
  Expected<Dek> dek_for(std::span<const std::byte> raw) const override {
    std::array<std::byte, 32> k;
    mix(raw, 0x11, k.data());
    return Dek(std::span<const std::byte, 32>(k));
  }
  Expected<KeyHash> key_hash(std::span<const std::byte> raw) const override {
    KeyHash h;
    std::array<std::byte, 32> k;
    mix(raw, 0x22, k.data());
    std::memcpy(h.b, k.data(), 32);
    return h;
  }

 private:
  static void mix(std::span<const std::byte> raw, int tag, std::byte* out) {
    for (int i = 0; i < 32; ++i) {
      std::uint64_t x = 1469598103934665603ull ^ static_cast<std::uint64_t>(7 * 131 + tag + i);
      for (auto b : raw) x = (x ^ static_cast<std::uint64_t>(b)) * 1099511628211ull;
      x ^= x >> 29;
      x *= 0x9E3779B97F4A7C15ull;
      out[i] = static_cast<std::byte>(x >> 56);
    }
  }
};

ScopeKeys scope_keys(int scope) {
  ScopeKeys sk;
  ScopeId s{};
  s.b[0] = static_cast<std::uint8_t>(scope);
  s.b[31] = 0x5c;
  sk.scopes = {s};
  sk.keys = std::make_shared<TestKeys>();
  sk.kver = 1;
  return sk;
}

struct Chain {
  Chain(const std::string& prefix, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
      std::string s = prefix + std::to_string(i);
      raw.emplace_back(reinterpret_cast<const std::byte*>(s.data()), reinterpret_cast<const std::byte*>(s.data()) + s.size());
    }
    for (std::size_t i = 0; i < n; ++i) {
      KeyRef r;
      r.raw = raw[i];
      if (i > 0) r.parent_raw = raw[i - 1];
      r.chain_pos = i;
      refs.push_back(r);
    }
  }
  std::vector<Bytes> raw;
  std::vector<KeyRef> refs;
};

Bytes payload(std::size_t n, int seed) {
  Bytes v(n);
  for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::byte>((i * 31 + static_cast<std::size_t>(seed) * 7 + 3) & 0xff);
  return v;
}

const fabric::RailAddr kRail[2] = {{"10.0.0.1", 7471}, {"10.0.1.1", 7471}};

struct Res {
  bool done = false, released = false;
  std::vector<KeyStatus> st;
};

// Server: device 0 (sim node 1) carries rail 0, device 1 (sim node 2) rail 1, with distinct rkeys. Client: device 0
// (node 3) pairs with rail 0, device 1 (node 4) with rail 1.
// RL3: the fetch shape (4 MiB blocks, slices, QP windows, a short lease) and the sim audit of the fetch rules.
struct Shape {
  bool big = false;  // 32 MiB segments of 8 MiB runs (a 4 MiB block needs a run above 4 MiB), 64 MiB per principal, a 48 MiB pool
  Nanos lease_ttl = seconds(1000);
  std::uint64_t slice_bytes = 0, window_bytes = 0;
  Nanos renew_every{0};          // RL3 leftover: ClientCoreOptions::renew_every (0 = the default)
  Nanos lease_max = seconds(2000);
  bool no_port = false;          // run #235: only the node and the devices (a Client builds the port and core from `wtmpl`)
  unsigned reconnect_ms = 0;     // run #235: reconnect_min_ms (max: 4x) when nonzero
  // J06a test: rail 1's client device as the port sees it (a wrapper around c1); null = c1 itself.
  std::function<fabric::Fabric*(fabric::SimFabric&)> wrap_rail1;
};
struct MR {
  explicit MR(unsigned fetch_qps = 2, unsigned keepalive_ms = 100, Shape shape = {})
      : rng(5), net(clock, rng, {}, {}), s0(net.add_node(1)), s1(net.add_node(2)), c0(net.add_node(3)), c1(net.add_node(4)) {
    s1.set_key_base_for_test(0x1000);
    c1.set_key_base_for_test(0x5000);
    server::ServerConfig sc;
    auto& c = sc.store;
    c.segment_bytes = shape.big ? 32u << 20 : 4u << 20;
    c.run_bytes = shape.big ? 8u << 20 : 256u << 10;
    c.min_block_bytes = 4096;
    c.n_segments = 4;
    c.gen_chunk = 1000;
    c.put_timeout = seconds(1000);
    c.lease_ttl = shape.lease_ttl;
    c.lease_max = shape.lease_max;
    c.invalidate_per_s = 0;
    c.principal_default.max_scopes = 8;
    c.principal_default.max_bytes = shape.big ? 64u << 20 : 8u << 20;
    c.principal_default.idle_ttl = seconds(100000);
    c.node_id = 1;
    sc.lab_identity = "lab";
    sc.lab_principal = 5;
    sc.rails = {kRail[0], kRail[1]};
    sc.rail_device = {0, 1};
    sc.device_names = {"sdev0", "sdev1"};
    scfg = sc;
    auto s = server::Server::create(sc, std::vector<fabric::Fabric*>{&s0, &s1}, clock, rng, sex);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
    EXPECT_TRUE(server->start());

    WireOptions wo;
    wo.node = 1;
    wo.rail_tickets = [this](fabric::EpClass cls, std::uint8_t rail) -> Expected<proto::Ticket> {
      server::Server* srv = ticket_server ? ticket_server(rail) : server.get();  // J07: two processes, one per rail
      auto t = srv->issue_ticket("lab", cls, rail, 1);
      if (!t) return t.error();
      return (*t)[0];
    };
    wo.drive = [this] { drive(); };
    wo.random = &jit;
    wo.keepalive_ms = keepalive_ms;
    wo.fetch_qps = fetch_qps;
    wo.label = "n1";
    wo.window_bytes = shape.window_bytes;
    wo.hostname = [] { return std::string("memnode-a"); };
    wo.on_local_failure = [this](unsigned rail, const std::string& dev, const Error&) {  // G09
      const char* call = fabric::last_local_failure().call;
      local_fail.push_back(std::to_string(rail) + " " + dev + " " + (call ? call : "?"));
    };
    wo.on_rails_up = [this](const std::vector<unsigned>& rails, bool rejoin) {  // Q03
      std::string s = rejoin ? "rejoin" : "reconnect";
      for (unsigned r : rails) s += " " + std::to_string(r);
      rails_up.push_back(s);
    };
    WireOptions::RailOpt r0, r1;
    r0.index = 0, r0.addr = kRail[0], r0.route = 1, r0.device = "cdev0";
    r1.index = 1, r1.addr = kRail[1], r1.route = 2, r1.fab = shape.wrap_rail1 ? shape.wrap_rail1(c1) : &c1, r1.device = "cdev1";
    wo.rails = {r0, r1};
    wo.rail_build_off_lock = true;  // run #233: ka() runs build_rails() after keepalive(), as the Client
    wo.rail = kRail[0];
    if (shape.reconnect_ms) wo.reconnect_min_ms = shape.reconnect_ms, wo.reconnect_max_ms = 4 * shape.reconnect_ms;
    wtmpl = wo;
    if (shape.no_port) return;
    port = std::make_unique<WirePort>(c0, clock, salts, std::move(wo));
    // RL3: one audit over both client devices; the core reports every span it gives back.
    audit.classify = [](fabric::WrTag t) -> std::optional<fabric::SimWrAudit::TagInfo> {
      auto f = ClientCore::fetch_tag(t);
      if (!f) return std::nullopt;
      return fabric::SimWrAudit::TagInfo{f->group, f->seq};
    };
    c0.set_audit(&audit);
    c1.set_audit(&audit);
    ClientCoreOptions co;
    if (shape.big) co.pool_bytes = 48u << 20;
    if (shape.slice_bytes) co.slice_bytes = [s = shape.slice_bytes] { return s; };
    if (shape.renew_every > Nanos{0}) co.renew_every = shape.renew_every;
    co.on_span_release = [this](std::span<const std::byte> b) { audit.on_release(b.data(), b.size()); };
    // A WR is outstanding until the core itself takes its completion (not when the port has it queued).
    audit.client_view = true;
    co.on_cqe = [this](const fabric::Completion& c) { audit.on_seen(c.op, c.tag, c.status.has_value()); };
    auto cc = ClientCore::create(port->fabric(), *port, clock, cex, salts, co);
    EXPECT_TRUE(cc) << (cc ? "" : cc.error().context);
    if (cc) core = std::move(*cc);
  }
  ~MR() {
    ticking = false;
    core.reset();
    if (port) port->release_endpoints();
    c0.set_audit(nullptr);
    c1.set_audit(nullptr);
  }

  // A 1 ms heartbeat event: virtual time then moves in small steps and never jumps to a far (delayed) delivery.
  void start_ticker() {
    ticking = true;
    net.schedule(milliseconds(1), [this] { tick(); });
  }
  void tick() {
    if (ticking) net.schedule(milliseconds(1), [this] { tick(); });
  }
  bool ticking = false;

  void drive() {
    if (!net.step()) clock.advance_by(milliseconds(1));
    server->run_once();
    for (auto& s : extra) s->run_once();
  }
  // One keepalive tick of the Client (run #233): keepalive() under the client lock, then build_rails() off it.
  bool ka() {
    port->keepalive();
    return port->build_rails();  // true: the next tick comes soon (the Client: next_in(1))
  }
  // Keepalive ticks for `span` of sim time (every keepalive period), pumping the core in between.
  void run_for(Nanos span, Nanos tick = milliseconds(100)) {
    const Nanos until = clock.now() + span;
    Nanos next = clock.now();
    while (clock.now() < until) {
      if (clock.now() >= next) next = clock.now() + (ka() ? milliseconds(1) : tick);
      core->pump();
      drive();
    }
  }
  Notify notify(Res& r) {
    return Notify{[&r](Ticket, std::span<const KeyStatus> s) { r.done = true, r.st.assign(s.begin(), s.end()); },
                  [&r](Ticket) { r.released = true; }};
  }
  bool spin(Res& r) {
    for (int i = 0; i < 400000; ++i) {
      core->pump();
      if (r.released) return true;
      drive();
    }
    return false;
  }
  std::vector<KeyStatus> put(const ScopeKeys& sk, const Chain& ch, std::vector<Bytes>& data) {
    std::vector<BufRef> bufs;
    for (auto& d : data) bufs.push_back({std::span<std::byte>(d)});
    Res r;
    core->submit_store(sk, 0, ch.refs, bufs, clock.now() + seconds(5), notify(r));
    EXPECT_TRUE(spin(r));
    return r.st;
  }
  std::vector<KeyStatus> fetch(const ScopeKeys& sk, const Chain& ch, std::vector<Bytes>& out) {
    std::vector<BufRef> bufs;
    for (auto& d : out) bufs.push_back({std::span<std::byte>(d)});
    Res r;
    core->submit_fetch(sk, 0, ch.refs, bufs, clock.now() + seconds(5), notify(r));
    EXPECT_TRUE(spin(r));
    return r.st;
  }
  // Stores `n` keys of `prefix` and returns their payloads.
  std::vector<Bytes> store(const ScopeKeys& sk, const Chain& ch, int seed, std::size_t len = 16384) {
    std::vector<Bytes> data;
    for (std::size_t i = 0; i < ch.refs.size(); ++i) data.push_back(payload(len + i * 512, seed + static_cast<int>(i)));
    auto st = put(sk, ch, data);
    EXPECT_EQ(st.size(), ch.refs.size());
    for (auto s : st) EXPECT_EQ(s, KeyStatus::Committed);
    return data;
  }
  // The oracle (strict on statuses unless `fault`), and 0 wrong bytes: every Hit must equal what was stored.
  std::size_t check_fetch(const ScopeKeys& sk, const Chain& ch, const std::vector<Bytes>& want, bool fault = false,
                          std::size_t* hits = nullptr) {
    std::vector<Bytes> out;
    for (auto& w : want) out.emplace_back(w.size());
    auto st = fetch(sk, ch, out);
    std::size_t wrong = 0, h = 0;
    for (std::size_t i = 0; i < st.size(); ++i) {
      const char* f = testutil::status_failure(st[i], fault ? testutil::OracleMode::Fault : testutil::OracleMode::Strict, fault);
      EXPECT_EQ(f, nullptr) << "key " << i << ": " << (f ? f : "");
      if (st[i] == KeyStatus::Hit) {
        ++h;
        if (out[i] != want[i]) ++wrong;
      }
    }
    if (hits) *hits = h;
    return wrong;
  }

  SimClock clock;
  SeededRandom rng;
  SeededRandom jit{99};
  fabric::SimNetwork net;
  fabric::SimFabric &s0, &s1, &c0, &c1;
  fabric::SimWrAudit audit;  // before the core and port: they report into it until they are gone
  InlineExecutor sex, cex;
  CounterSalts salts;
  server::ServerConfig scfg;  // the config the node was created with
  std::unique_ptr<server::Server> server;
  // F04: the process a restart replaced. Kept (its endpoints stay connected) but never run: two servers polling one sim
  // device would take each other's completions.
  std::unique_ptr<server::Server> old_server;
  // J07: more processes that run with `server` (each on its own devices), and which one issues a rail's tickets.
  std::vector<std::unique_ptr<server::Server>> extra;
  std::function<server::Server*(std::uint8_t rail)> ticket_server;
  std::vector<std::string> local_fail;  // G09: "rail device call" of each rail rejoin a local device refused
  std::vector<std::string> rails_up;    // Q03: "reconnect 0 1" / "rejoin 1" of each on_rails_up call
  WireOptions wtmpl;  // the port options (run #235: a Client opens its own port from them)
  std::unique_ptr<WirePort> port;
  std::unique_ptr<ClientCore> core;
};

TEST(MultiRail, TwoRailsCarryTrafficAndExactBytes) {
  MR w;
  ASSERT_TRUE(w.core);
  ASSERT_EQ(w.port->rail_count(), 2u);
  EXPECT_EQ(w.port->rail_state(0), WirePort::RailState::Up);
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Up);
  auto sk = scope_keys(1);
  Chain a("a", 8);
  auto data = w.store(sk, a, 1);
  std::size_t hits = 0;
  EXPECT_EQ(w.check_fetch(sk, a, data, false, &hits), 0u);
  EXPECT_EQ(hits, 8u);
  EXPECT_GT(w.port->rail_reads(0), 0u);
  EXPECT_GT(w.port->rail_reads(1), 0u) << "both rails carry READs (rail 1 uses its own rkeys and lkeys)";
  EXPECT_TRUE(w.core->check_invariants());
  const std::string m = w.core->metrics_text();
  EXPECT_NE(m.find("miracache_client_rail_state{node=\"n1\",node_id=\"1\",hostname=\"memnode-a\",rail=\"1\",addr=\"10.0.1.1:7471\"} 2"),
            std::string::npos)
      << m;
  // F08 (goal 10): the unpaired-rail count carries the node's ID, hostname and address too.
  EXPECT_NE(m.find("miracache_client_rail_unpaired{node=\"n1\",node_id=\"1\",hostname=\"memnode-a\",addr=\"10.0.0.1:7471\"} 0"),
            std::string::npos)
      << m;
}

TEST(MultiRail, RailFlushKeepsNodeUpPutsMoveAndTheRailReturns) {
  MR w;
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(1);
  Chain a("a", 6);
  auto da = w.store(sk, a, 1);
  const auto downs = w.port->session_down_count();
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));  // flush every endpoint of rail 1, refuse connects to it
  w.run_for(milliseconds(50));
  EXPECT_TRUE(w.port->session_up()) << "the node stays Up on rail 0";
  EXPECT_EQ(w.port->session_down_count(), downs);
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  EXPECT_EQ(w.port->rail_state(0), WirePort::RailState::Up);
  // Puts move to rail 0; every Hit has exact bytes.
  const auto puts0 = w.port->rail_puts(0), puts1 = w.port->rail_puts(1);
  Chain b("b", 6);
  auto db = w.store(sk, b, 50);
  EXPECT_GT(w.port->rail_puts(0), puts0);
  EXPECT_EQ(w.port->rail_puts(1), puts1);
  EXPECT_EQ(w.check_fetch(sk, a, da), 0u);
  EXPECT_EQ(w.check_fetch(sk, b, db), 0u);
  // The rail returns: own backoff, own tickets, HELLO + SEG_TABLE, then work again.
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
  w.run_for(seconds(3));
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Up);
  EXPECT_GE(w.port->rail_reconnects(1), 1u);
  const auto reads1 = w.port->rail_reads(1);
  Chain c("c", 8);
  auto dc = w.store(sk, c, 90);
  EXPECT_EQ(w.check_fetch(sk, c, dc), 0u);
  EXPECT_EQ(w.check_fetch(sk, a, da), 0u);
  EXPECT_GT(w.port->rail_reads(1), reads1) << "the returned rail takes READs again";
  EXPECT_EQ(w.port->session_down_count(), downs);
  EXPECT_TRUE(w.core->check_invariants());
}

// F04: the memory node restarts while rail 1 is down; rail 0 has not noticed yet (keepalive_ms 0: a suspect rail is never
// given up, so the old session stays Up on rail 0 as long as we like). Rail 1 rejoins the new process with the old
// conn_id and gets a SEG_TABLE whose table_gen restarted from zero (here it stays
// below the old one: the new process has fewer segments). Before the fix the rail went up on the OLD process's table
// (its rkeys and addresses) and its READs used them against the new process. Now the rail never takes work on the old
// table: the join ends as "restarted", the session goes Down once and reconnects both rails to the new process.
TEST(MultiRail, RailRejoiningARestartedNodeNeverUsesTheOldTable) {
  MR w(/*fetch_qps=*/2, /*keepalive_ms=*/0);
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(4);
  Chain a("r", 6);
  auto da = w.store(sk, a, 21);
  const std::uint32_t old_gen = w.port->table_gen();
  ASSERT_GE(old_gen, 3u);
  const auto downs = w.port->session_down_count();
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(50));
  ASSERT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  ASSERT_TRUE(w.port->session_up());

  // The restart: a new process on the same devices and addresses (its listeners replace the old ones), fewer segments.
  auto sc = w.scfg;
  sc.store.n_segments = 2;
  auto s = server::Server::create(sc, std::vector<fabric::Fabric*>{&w.s0, &w.s1}, w.clock, w.rng, w.sex);
  ASSERT_TRUE(s) << s.error().context;
  ASSERT_TRUE((*s)->start());
  w.old_server = std::move(w.server);
  w.server = std::move(*s);
  for (int i = 0; i < 200 && w.server->table_gen() < 2; ++i) w.drive();
  ASSERT_EQ(w.server->table_gen(), 2u);
  ASSERT_LT(w.server->table_gen(), old_gen);

  bool restarted = false, stale_up = false;
  const Nanos until = w.clock.now() + seconds(8);
  Nanos next = w.clock.now();
  while (w.clock.now() < until && !(restarted && w.port->session_up() && w.port->rail_state(1) == WirePort::RailState::Up &&
                                    w.port->rail_state(0) == WirePort::RailState::Up)) {
    if (w.clock.now() >= next) {
      w.ka();
      next = w.clock.now() + milliseconds(100);
    }
    w.core->pump();
    w.drive();
    restarted = restarted || w.port->session_down_count() > downs;
    // Rail 1 up in the old session = up on the old process's table.
    if (!restarted && w.port->rail_state(1) == WirePort::RailState::Up) stale_up = true;
  }
  EXPECT_FALSE(stale_up) << "rail 1 took work on the old process's segment table";
  EXPECT_EQ(w.port->restarts_detected(), 1u);
  EXPECT_EQ(w.port->session_down_count(), downs + 1) << "one Down, then a clean session on the new process";
  ASSERT_TRUE(w.port->session_up());
  EXPECT_EQ(w.port->rail_state(0), WirePort::RailState::Up);
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Up);
  EXPECT_EQ(w.port->table_gen(), w.server->table_gen()) << "the new process's table";
  // The new process is empty: the old keys miss (never wrong bytes); new data round-trips on both rails.
  std::size_t hits = 0;
  EXPECT_EQ(w.check_fetch(sk, a, da, /*fault=*/true, &hits), 0u);
  EXPECT_EQ(hits, 0u);
  Chain b("q", 8);
  auto db = w.store(sk, b, 77);
  EXPECT_EQ(w.check_fetch(sk, b, db, false, &hits), 0u);
  EXPECT_EQ(hits, 8u);
  EXPECT_TRUE(w.core->check_invariants());
}

// H02: as F04, but the new process has the SAME segment count, so its table_gen reaches the old value and the F04 check
// (older tables only) cannot see the restart. The boot nonce in HELLO_ACK can: the rejoining rail's HELLO_ACK names
// another process, its SEG_TABLE never replaces the session's, the rail never takes work, and the session goes Down
// once and reconnects both rails to the new process. (Mutator: with the nonce comparison disabled rail 1 goes up in the
// old session on the new process's table while rail 0 still talks to the old one: stale_up, no restart detected.)
TEST(MultiRail, RestartWithTheSameSegmentCountIsDetectedByTheBootNonce) {
  MR w(/*fetch_qps=*/2, /*keepalive_ms=*/0);
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(8);
  Chain a("n", 6);
  auto da = w.store(sk, a, 31);
  const std::uint32_t old_gen = w.port->table_gen();
  ASSERT_TRUE(w.port->boot_nonce().has_value());
  EXPECT_EQ(*w.port->boot_nonce(), w.server->boot_nonce());
  const std::uint64_t old_nonce = w.server->boot_nonce();
  const auto downs = w.port->session_down_count();
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(50));
  ASSERT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  ASSERT_TRUE(w.port->session_up());

  auto s = server::Server::create(w.scfg, std::vector<fabric::Fabric*>{&w.s0, &w.s1}, w.clock, w.rng, w.sex);
  ASSERT_TRUE(s) << s.error().context;
  ASSERT_TRUE((*s)->start());
  ASSERT_NE((*s)->boot_nonce(), old_nonce);
  w.old_server = std::move(w.server);
  w.server = std::move(*s);
  for (int i = 0; i < 400 && w.server->table_gen() < old_gen; ++i) w.drive();
  ASSERT_EQ(w.server->table_gen(), old_gen) << "same segments, same table_gen: invisible to the F04 check";

  bool restarted = false, stale_up = false;
  const Nanos until = w.clock.now() + seconds(8);
  Nanos next = w.clock.now();
  while (w.clock.now() < until && !(restarted && w.port->session_up() && w.port->rail_state(1) == WirePort::RailState::Up &&
                                    w.port->rail_state(0) == WirePort::RailState::Up)) {
    if (w.clock.now() >= next) {
      w.ka();
      next = w.clock.now() + milliseconds(100);
    }
    w.core->pump();
    w.drive();
    restarted = restarted || w.port->session_down_count() > downs;
    if (!restarted && w.port->rail_state(1) == WirePort::RailState::Up) stale_up = true;
  }
  EXPECT_FALSE(stale_up) << "rail 1 took work in the old session (the old process's or a mixed segment table)";
  EXPECT_EQ(w.port->restarts_detected(), 1u);
  EXPECT_EQ(w.port->session_down_count(), downs + 1) << "one Down, then a clean session on the new process";
  ASSERT_TRUE(w.port->session_up());
  EXPECT_EQ(w.port->rail_state(0), WirePort::RailState::Up);
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Up);
  ASSERT_TRUE(w.port->boot_nonce().has_value());
  EXPECT_EQ(*w.port->boot_nonce(), w.server->boot_nonce()) << "the session belongs to the new process";
  std::size_t hits = 0;
  EXPECT_EQ(w.check_fetch(sk, a, da, /*fault=*/true, &hits), 0u);
  Chain b("m", 8);
  auto db = w.store(sk, b, 87);
  EXPECT_EQ(w.check_fetch(sk, b, db, false, &hits), 0u);
  EXPECT_EQ(hits, 8u);
  EXPECT_EQ(w.port->restarts_detected(), 1u);
  EXPECT_TRUE(w.core->check_invariants());
}

// H02: a rail that reconnects to the SAME process (same boot nonce) rejoins the live session: no restart, no Down.
TEST(MultiRail, RailRejoiningTheSameProcessKeepsTheSession) {
  MR w;
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(9);
  Chain a("s", 6);
  auto da = w.store(sk, a, 41);
  const auto downs = w.port->session_down_count();
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(50));
  ASSERT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
  w.run_for(seconds(3));
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Up);
  EXPECT_GE(w.port->rail_reconnects(1), 1u);
  EXPECT_EQ(w.port->restarts_detected(), 0u);
  EXPECT_EQ(w.port->session_down_count(), downs);
  ASSERT_TRUE(w.port->boot_nonce().has_value());
  EXPECT_EQ(*w.port->boot_nonce(), w.server->boot_nonce());
  EXPECT_EQ(w.check_fetch(sk, a, da), 0u);
}

// R22 (J07): restarts a rejoining rail notices are damped only while the rails reach two processes. A session that
// comes up without a rail that is merely unreachable (no rail refused for another boot nonce) resets the count, so a
// node whose rail 1 is unreachable at every reconnect still has each restart handled. Before the fix the count only
// reset on a session with every rail, and the 4th restart was damped as "mis-wired" (the session stayed on the old
// process).
TEST(MultiRail, RestartsWhileARailIsUnreachableAreNeverDamped) {
  Shape sh;
  sh.reconnect_ms = 50;
  MR w(/*fetch_qps=*/2, /*keepalive_ms=*/0, sh);
  ASSERT_TRUE(w.core);
  auto run_until = [&w](auto pred, Nanos span) {
    const Nanos until = w.clock.now() + span;
    Nanos next = w.clock.now();
    while (w.clock.now() < until && !pred()) {
      if (w.clock.now() >= next) {
        w.ka();
        next = w.clock.now() + milliseconds(20);
      }
      w.core->pump();
      w.drive();
    }
    return pred();
  };
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  ASSERT_TRUE(run_until([&] { return w.port->rail_state(1) == WirePort::RailState::Down; }, seconds(2)));
  ASSERT_TRUE(w.port->session_up());
  constexpr int kCycles = 5;  // > kNonceDamp (3)
  for (int cycle = 0; cycle < kCycles; ++cycle) {
    SCOPED_TRACE("restart " + std::to_string(cycle));
    const auto downs = w.port->session_down_count();
    auto s = server::Server::create(w.scfg, std::vector<fabric::Fabric*>{&w.s0, &w.s1}, w.clock, w.rng, w.sex);
    ASSERT_TRUE(s) << s.error().context;
    ASSERT_TRUE((*s)->start());
    w.old_server = std::move(w.server);  // the old process stays up: rail 0 still talks to it
    w.server = std::move(*s);
    // Rail 1 comes back and reaches the new process: a restart, the session reconnects.
    ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
    ASSERT_TRUE(run_until([&] { return w.port->session_down_count() > downs; }, seconds(5)))
        << "the restart was damped: the session stayed on the old process";
    // ...and is unreachable again before the reconnect: the session comes up on rail 0 alone (no other nonce seen).
    ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
    ASSERT_TRUE(run_until([&] { return w.port->session_up(); }, seconds(5)));
    ASSERT_TRUE(w.port->boot_nonce().has_value());
    EXPECT_EQ(*w.port->boot_nonce(), w.server->boot_nonce()) << "the session belongs to the new process";
    EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  }
  EXPECT_EQ(w.port->restarts_detected(), static_cast<std::uint64_t>(kCycles));
}

// G09 (review G07, Q6): a rail rejoin that the LOCAL device refuses (CQ/QP limit) is handed to the Client with its rail,
// device and the failing call (it counts it by cause and logs it once, as a build); the rail retries on its backoff and
// comes back once the device has room.
TEST(MultiRail, RailRejoinLocalResourceFailureIsReported) {
  MR w;
  ASSERT_TRUE(w.core);
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(50));
  ASSERT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  w.c1.inject_local_failure("ibv_create_cq");
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
  w.run_for(seconds(2));
  ASSERT_FALSE(w.local_fail.empty()) << "the rejoin's local failure reached the Client";
  for (const auto& s : w.local_fail) EXPECT_EQ(s, "1 cdev1 ibv_create_cq");
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  EXPECT_TRUE(w.port->session_up()) << "rail 0 keeps the node Up";
  EXPECT_TRUE(w.rails_up.empty());
  w.c1.inject_local_failure(nullptr);
  w.run_for(seconds(3));
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Up);
  // Q03: the rejoin that took is handed to the Client once, for that rail only (it closes the rail's failure entry).
  ASSERT_EQ(w.rails_up.size(), 1u);
  EXPECT_EQ(w.rails_up[0], "rejoin 1");
}

// L13 (review s9b): the session reconnect after a node restart (every rail Down -> session Down -> Connecting -> Up) is
// not a rail rejoin: a refusal of the LOCAL device there (siw0: "prepare QP mapping failed") must reach the Client
// through the same hook, per rail, with the failing call; the session comes back once the device has room.
TEST(MultiRail, SessionReconnectLocalResourceFailureIsReported) {
  MR w;
  ASSERT_TRUE(w.core);
  ASSERT_TRUE(w.s0.fail_rail(kRail[0]));
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(500));
  ASSERT_FALSE(w.port->session_up());
  w.c0.inject_local_failure("ibv_create_cq", 0);  // errno 0: the provider set none (libsiw)
  w.c1.inject_local_failure("ibv_create_cq", 0);
  ASSERT_TRUE(w.s0.restore_rail(kRail[0]));
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
  w.run_for(seconds(3));
  ASSERT_FALSE(w.local_fail.empty()) << "the reconnect's local failure reached the Client";
  for (const auto& s : w.local_fail) EXPECT_TRUE(s == "0 cdev0 ibv_create_cq" || s == "1 cdev1 ibv_create_cq") << s;
  EXPECT_FALSE(w.port->session_up());
  EXPECT_TRUE(w.rails_up.empty()) << "no rail came up";
  w.c0.inject_local_failure(nullptr);
  w.c1.inject_local_failure(nullptr);
  w.run_for(seconds(5));
  EXPECT_TRUE(w.port->session_up());
  // Q03 / Q09: the reconnect that took is handed to the Client once, with every rail it connected (the Client closes
  // their failure entries; the Client-level counter, log line and recovery line are covered by
  // MembershipSlots.SessionReconnectLocalFailureIsLoggedRecoveredAndLoggedAgain).
  ASSERT_FALSE(w.rails_up.empty());
  EXPECT_EQ(w.rails_up[0], "reconnect 0 1");
  for (std::size_t k = 1; k < w.rails_up.size(); ++k) EXPECT_EQ(w.rails_up[k].rfind("rejoin ", 0), 0u) << w.rails_up[k];
}

// RL2 follow-up B: a rail's reconnect never stalls the other rails. Rail 1 comes back against a slow memory node (300 ms
// each way on its link: its HELLOs and SEG_TABLE take 600 ms and more). The keepalive tick that starts the reconnect
// returns at once and later ticks take the replies, so rail-0 fetches keep their latency bound the whole time (before
// the follow-up, that tick waited for the HELLOs under the client lock and every fetch behind it waited too).
// Run #233: the same with a slow CONNECT (each of rail 1's connects takes `connect_delay`): the connects run in
// build_rails(), off the lock. The sim is single-threaded, so the off-lock part runs between two fetches (no job waits
// on it, as the Client's job threads do not wait on its keepalive thread); `held` is what the tick under the lock costs.
struct SlowRejoin {
  std::vector<Nanos> lat;
  Nanos held{0}, built_for{0};
};
void slow_rejoin(Nanos link_delay, Nanos connect_delay, SlowRejoin& out, std::size_t min_fetches = 100) {
  MR w;
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(3);
  Chain a("p", 4);
  auto da = w.store(sk, a, 11);
  const auto downs = w.port->session_down_count();
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(50));
  ASSERT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  if (link_delay > Nanos{0}) w.net.set_link_delay(4, 2, link_delay);
  if (connect_delay > Nanos{0}) w.c1.set_connect_delay_for_test(connect_delay);
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
  w.start_ticker();
  const auto rc = w.port->rail_reconnects(1);
  Nanos next_ka = w.clock.now();
  const Nanos until = w.clock.now() + seconds(12);
  std::size_t wrong = 0, misses = 0;
  while (w.clock.now() < until && w.port->rail_reconnects(1) == rc) {
    std::vector<Bytes> out_b;
    for (auto& d : da) out_b.emplace_back(d.size());
    std::vector<BufRef> bufs;
    for (auto& d : out_b) bufs.push_back({std::span<std::byte>(d)});
    Res r;
    const Nanos t0 = w.clock.now();
    w.core->submit_fetch(sk, 0, a.refs, bufs, t0 + seconds(5), w.notify(r));
    if (w.clock.now() >= next_ka) {  // the keepalive thread's tick (under the client lock) lands while this fetch is in flight
      const Nanos k0 = w.clock.now();
      w.port->keepalive();
      out.held = std::max(out.held, w.clock.now() - k0);  // sim time the tick held the lock: every job of the node waits that long
      next_ka = w.clock.now() + milliseconds(100);
    }
    ASSERT_TRUE(w.spin(r));
    for (std::size_t i = 0; i < r.st.size(); ++i) {
      EXPECT_EQ(testutil::status_failure(r.st[i], testutil::OracleMode::Strict, false), nullptr);
      if (r.st[i] == KeyStatus::Hit && out_b[i] != da[i]) ++wrong;
      if (r.st[i] == KeyStatus::Miss) ++misses;
    }
    // The fetch during whose flight rail 1 came back may put READs on the slow rail itself: not a handshake stall.
    if (w.port->rail_reconnects(1) != rc) break;
    out.lat.push_back(w.clock.now() - t0);
    // The same tick, after the lock: the rail's connects (no job in flight here).
    const Nanos b0 = w.clock.now();
    if (w.port->build_rails()) {
      out.built_for = std::max(out.built_for, w.clock.now() - b0);
      next_ka = w.clock.now();  // the Client's next_in(1): the set is swapped in at once
    }
    for (const Nanos idle = w.clock.now() + milliseconds(2); w.clock.now() < idle;) w.core->pump(), w.drive();
  }
  EXPECT_EQ(w.port->rail_reconnects(1), rc + 1) << "rail 1 came back against the slow node";
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Up);
  EXPECT_EQ(w.port->session_down_count(), downs);
  EXPECT_EQ(wrong, 0u);
  EXPECT_EQ(misses, 0u);
  EXPECT_LT(out.held, milliseconds(5)) << "a keepalive tick waited for rail 1's connect or handshake under the lock";
  ASSERT_GT(out.lat.size(), min_fetches) << "fetches measured while rail 1 rejoined";
  std::sort(out.lat.begin(), out.lat.end());
  const Nanos p99 = out.lat[out.lat.size() * 99 / 100], worst = out.lat.back();
  EXPECT_LT(p99, milliseconds(20)) << "rail-0 fetch p99 while rail 1 reconnects";
  EXPECT_LT(worst, milliseconds(50)) << "no fetch waited for rail 1's connect or handshake (" << out.lat.size() << " fetches)";
  EXPECT_TRUE(w.core->check_invariants());
}

TEST(MultiRail, RailReconnectAgainstASlowNodeNeverStallsTheOtherRail) {
  SlowRejoin s;
  slow_rejoin(milliseconds(300), Nanos{0}, s);
}

// Run #233: every connect of rail 1 takes 1 s (its set: 1 control + 2 fetch + 1 ingest = 4 s of connects).
TEST(MultiRail, RailConnectAgainstASlowConnectNeverStallsTheOtherRail) {
  SlowRejoin s;
  slow_rejoin(Nanos{0}, seconds(1), s, 50);  // the connects run between two fetches here: fewer fetches see the rejoin
  EXPECT_GE(s.built_for, seconds(4)) << "the slow part was the connects, and they ran in build_rails (off the lock)";
}

// Run #233: a stop (abort_connect) during the off-lock build: the endpoints it connected are released (the device is back
// to its endpoint count before the rejoin), the device comes back to the port, no rail goes up, nothing stays lent. The
// lent build reuses the rail's PD and landing registration, so there is no PD or registration to give back.
TEST(MultiRail, RailBuildAbortedByStopLeaksNothing) {
  MR w;
  ASSERT_TRUE(w.core);
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(50));
  ASSERT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  w.port->keepalive();  // reaps rail 1's zombies (flushed at once in the sim)
  const std::size_t base_c1 = w.c1.endpoint_count();
  EXPECT_EQ(base_c1, 0u) << "only rail 1 uses device 1";
  w.c1.set_connect_delay_for_test(seconds(1));
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
  for (int i = 0; i < 2000 && !w.port->rail_build_pending(); ++i) {
    w.port->keepalive();
    for (const Nanos t = w.clock.now() + milliseconds(10); w.clock.now() < t;) w.core->pump(), w.drive();
  }
  ASSERT_TRUE(w.port->rail_build_pending()) << "rail 1's device was lent to the off-lock build";
  bool stopped = false;
  w.net.schedule(milliseconds(1500), [&] {  // the Client's stop, during the build's second connect
    w.port->abort_connect();
    stopped = true;
  });
  const Nanos b0 = w.clock.now();
  EXPECT_TRUE(w.port->build_rails());
  EXPECT_TRUE(stopped);
  EXPECT_LT(w.clock.now() - b0, milliseconds(2500)) << "the build gave up at the next connect boundary";
  EXPECT_EQ(w.c1.endpoint_count(), base_c1) << "the aborted build released every endpoint it connected";
  w.port->keepalive();  // takes the device back
  EXPECT_FALSE(w.port->rail_build_pending());
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  EXPECT_EQ(w.c1.endpoint_count(), base_c1);
}

// Run #233: a set built off the lock for a session that ended before it was swapped in is given back (its endpoints go
// to the fabric as zombies, reaped), and the next session connects both rails afresh.
TEST(MultiRail, RailBuildOfAnEndedSessionIsGivenBack) {
  MR w;
  ASSERT_TRUE(w.core);
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(50));
  ASSERT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
  for (int i = 0; i < 2000 && !w.port->rail_build_pending(); ++i) {
    w.port->keepalive();
    for (const Nanos t = w.clock.now() + milliseconds(10); w.clock.now() < t;) w.core->pump(), w.drive();
  }
  ASSERT_TRUE(w.port->rail_build_pending());
  ASSERT_TRUE(w.port->build_rails());
  EXPECT_EQ(w.c1.endpoint_count(), 4u) << "rail 1's set (control, 2 fetch, ingest) connected, not swapped in yet";
  const auto downs = w.port->session_down_count();
  ASSERT_TRUE(w.s0.fail_rail(kRail[0]));  // the last up rail: the session ends before the set is taken back
  w.run_for(milliseconds(50));
  EXPECT_GT(w.port->session_down_count(), downs);
  EXPECT_FALSE(w.port->rail_build_pending()) << "the ended session's build went back";
  ASSERT_TRUE(w.s0.restore_rail(kRail[0]));
  w.run_for(seconds(3));
  EXPECT_TRUE(w.port->session_up());
  EXPECT_EQ(w.port->rail_state(0), WirePort::RailState::Up);
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Up);
  EXPECT_EQ(w.c1.endpoint_count(), 4u) << "only the new session's set is on device 1 (the old one was reaped)";
  auto sk = scope_keys(4);
  Chain a("q", 4);
  auto da = w.store(sk, a, 21);
  EXPECT_EQ(w.check_fetch(sk, a, da), 0u);
}

// ---- run #235 (review s8 wave15 J01, J04, J10) ----
// The value of the first series `name{...}` whose labels contain every fragment (-1: none).
double metric(const std::string& text, const std::string& name, std::initializer_list<const char*> frags) {
  std::size_t at = 0;
  while ((at = text.find(name + "{", at)) != std::string::npos) {
    const std::size_t eol = std::min(text.find('\n', at), text.size());
    const std::string line = text.substr(at, eol - at);
    at = eol;
    bool all = true;
    for (const char* f : frags) all = all && line.find(f) != std::string::npos;
    if (all) return std::strtod(line.c_str() + line.rfind(' ') + 1, nullptr);
  }
  return -1;
}
// A Client (real worker threads; a keepalive thread when keepalive_ms > 0) over MR's node and two devices.
std::unique_ptr<Client> open_client(MR& w, std::function<void()> drive, unsigned workers) {
  Client::Env env;
  env.fab = &w.c0;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = std::move(drive);
  RuntimeOptions ro;
  ro.workers = workers;
  auto cl = Client::open_wire(env, w.wtmpl, {}, {}, ro);
  EXPECT_TRUE(cl) << (cl ? "" : cl.error().context);
  return cl ? std::move(*cl) : nullptr;
}

// J01: two worker threads run puts and fetches through a Client while its keepalive thread rejoins rail 1 off the
// lock; every connect on rail 1's device takes 150 ms (sim). Rail 1 is down at open, so its first attempts fail inside
// build_rails (released on the lent device), then it is restored and rejoins (HELLOs + SEG_TABLE) without a session
// end. Exact bytes, every op Committed/Hit (strict oracle), rail 1 carries READs after, and no path under the client
// lock touched the lent device (WirePort::lend_violations(): logged, counted, a trap in debug builds).
TEST(MultiRail, LentDeviceIsNeverTouchedUnderTheLockWhileJobThreadsRun) {
  const std::uint64_t v0 = WirePort::lend_violations();
  Shape sh;
  sh.no_port = true;
  sh.reconnect_ms = 20;
  MR w(2, 20, sh);
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.c1.set_connect_delay_for_test(milliseconds(150));
  std::atomic<bool> restore{false};
  auto drive = [&] {  // always on the thread that holds the Client's sim turn
    if (restore.exchange(false)) EXPECT_TRUE(w.s1.restore_rail(kRail[1]));
    w.drive();
  };
  auto cl = open_client(w, drive, 2);
  ASSERT_TRUE(cl);
  Client& c = *cl;
  ASSERT_NE(c.wire_port(), nullptr);
  auto base = scope_keys(1), news = scope_keys(2);
  Chain bc("base", 4);
  std::vector<Bytes> bdata;
  for (std::size_t i = 0; i < 4; ++i) bdata.push_back(payload(16384 + i * 512, 3 + static_cast<int>(i)));
  std::vector<Completion> got;
  auto collect = [&](std::size_t n) {
    const auto until = std::chrono::steady_clock::now() + seconds(60);
    std::array<Completion, 8> comp;
    while (got.size() < n && std::chrono::steady_clock::now() < until) {
      const std::size_t k = c.poll(comp);
      for (std::size_t i = 0; i < k; ++i) got.push_back(std::move(comp[i]));
      if (k == 0) std::this_thread::sleep_for(std::chrono::microseconds(200));
    }
    return got.size() == n;
  };
  {
    std::vector<BufRef> b;
    for (auto& d : bdata) b.push_back({std::span<std::byte>(d)});
    got.clear();
    c.store(base, 0, bc.refs, b, seconds(5));
    ASSERT_TRUE(collect(1));
    for (auto s : got[0].status) ASSERT_EQ(s, KeyStatus::Committed);
  }
  std::size_t wrong = 0, bad = 0, rounds = 0, after = 0;
  // Up to 120 puts of 3 new keys each (about 3 MiB, under the principal's 8 MiB); later rounds only fetch.
  std::vector<std::pair<std::unique_ptr<Chain>, std::vector<Bytes>>> stored;
  bool rejoined = false;
  const auto wall = std::chrono::steady_clock::now() + seconds(120);
  auto rail1_up = [&] {
    return metric(c.metrics_text(), "miracache_client_rail_state", {"rail=\"1\""}) == 2.0;
  };
  for (; after < 300 && std::chrono::steady_clock::now() < wall; ++rounds) {
    if (rounds == 5) restore = true;
    // Three jobs at once (both workers busy): a put of new keys, a fetch of the base chain, a fetch of an earlier put.
    std::unique_ptr<Chain> ch;
    std::vector<Bytes> data;
    if (stored.size() < 120) {
      ch = std::make_unique<Chain>("r" + std::to_string(rounds) + "-", 3);
      for (std::size_t i = 0; i < 3; ++i) data.push_back(payload(8192 + i * 256, static_cast<int>(rounds * 7 + i)));
    }
    const auto* old = stored.empty() ? nullptr : &stored[rounds % stored.size()];
    std::vector<Bytes> bout, pout;
    for (auto& d : bdata) bout.emplace_back(d.size());
    if (old)
      for (auto& d : old->second) pout.emplace_back(d.size());
    std::vector<BufRef> sb, bb, pb;
    for (auto& d : data) sb.push_back({std::span<std::byte>(d)});
    for (auto& d : bout) bb.push_back({std::span<std::byte>(d)});
    for (auto& d : pout) pb.push_back({std::span<std::byte>(d)});
    got.clear();
    Ticket ts{}, tp{};
    if (ch) ts = c.store(news, 0, ch->refs, sb, seconds(5));
    const Ticket tb = c.fetch(base, 0, bc.refs, bb, seconds(5));
    if (old) tp = c.fetch(news, 0, old->first->refs, pb, seconds(5));
    ASSERT_TRUE(collect(1 + (ch ? 1 : 0) + (old ? 1 : 0))) << "round " << rounds;
    for (const Completion& cp : got) {
      for (std::size_t i = 0; i < cp.status.size(); ++i) {
        if (cp.ticket == ts) {
          bad += cp.status[i] != KeyStatus::Committed;
          continue;
        }
        bad += testutil::status_failure(cp.status[i], testutil::OracleMode::Strict, false) != nullptr ||
               cp.status[i] != KeyStatus::Hit;
        if (cp.ticket == tb && bout[i] != bdata[i]) ++wrong;
        if (cp.ticket == tp && pout[i] != old->second[i]) ++wrong;
      }
    }
    if (ch) stored.emplace_back(std::move(ch), std::move(data));
    if (!rejoined && rounds > 5) rejoined = rail1_up();
    if (rejoined) ++after;
  }
  EXPECT_TRUE(rejoined) << "rail 1 came back (" << rounds << " rounds, " << c.keepalive_ticks() << " keepalive ticks)";
  EXPECT_EQ(after, 300u) << "rounds with rail 1 back";
  EXPECT_EQ(wrong, 0u) << "exact bytes";
  EXPECT_EQ(bad, 0u) << "every put Committed, every fetch a Hit";
  WirePort* wp = c.wire_port();
  ASSERT_NE(wp, nullptr);
  EXPECT_GE(wp->off_lock_builds(), 1u) << "rail 1's set was connected by build_rails (off the lock)";
  EXPECT_EQ(wp->session_down_count(), 0u) << "the rejoin never ended the session";
  const std::string m = c.metrics_text();
  EXPECT_GT(metric(m, "miracache_client_fetch_rail_bytes_total", {"rail=\"1\""}), 0.0) << "rail 1 carried READs";
  c.shutdown();
  EXPECT_EQ(WirePort::lend_violations(), v0) << "a path under the client lock touched the lent device";
}

// J04: a RENEW_ACK filed just before the session ends moves no deadline of the next session (renewed is cleared with
// renew_sent at the session end).
TEST(MultiRail, RenewedAckOfAnEndedSessionIsDropped) {
  MR w;
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(5);
  Chain a("rn", 2);
  w.store(sk, a, 31);
  store::LookupReq q;
  std::memcpy(q.scope.data(), sk.scopes[0].b, 32);
  for (auto& raw : a.raw) {
    auto h = sk.keys->key_hash(raw);
    ASSERT_TRUE(h);
    store::KeyHash k;
    std::memcpy(k.data(), h->b, 32);
    q.keys.push_back(k);
  }
  const store::LookupAck ack = w.port->lookup(q);
  ASSERT_NE(ack.lease, 0u);
  auto filed = [&] {  // the ack is filed by service() (keepalive here: the core is not pumped, so it takes nothing)
    for (int i = 0; i < 200; ++i) {
      w.port->keepalive();
      w.drive();
    }
  };
  std::vector<ServerPort::Renewed> out;
  ASSERT_TRUE(w.port->renew(ack.lease));
  filed();
  w.port->take_renewed(out);
  ASSERT_EQ(out.size(), 1u) << "control: an OK RENEW_ACK is filed";
  EXPECT_EQ(out[0].lease, ack.lease);
  ASSERT_TRUE(w.port->renew(ack.lease));
  filed();
  w.port->drain_session();  // the session ends before the core took the ack
  ASSERT_FALSE(w.port->session_up());
  w.port->take_renewed(out);
  EXPECT_TRUE(out.empty()) << "the ended session's RENEW_ACK was dropped";
  w.run_for(seconds(3));
  EXPECT_TRUE(w.port->session_up());
  w.port->take_renewed(out);
  EXPECT_TRUE(out.empty());
}

// J10: a Client destroyed while a rail set built off the lock is staged (built, not swapped in yet): the abort-all
// pass gives it back with the rest, and device 1 is back to no endpoint once the Client is gone.
TEST(MultiRail, ClientDestroyedWithABuiltRailSetLeaksNothing) {
  Shape sh;
  sh.no_port = true;
  sh.reconnect_ms = 20;
  MR w(2, 0, sh);  // keepalive_ms 0: no keepalive thread, the test ticks
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  auto cl = open_client(w, [&] { w.drive(); }, 1);
  ASSERT_TRUE(cl);
  WirePort* wp = cl->wire_port();
  ASSERT_NE(wp, nullptr);
  EXPECT_EQ(w.c1.endpoint_count(), 0u) << "rail 1 did not connect at open";
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));
  for (int i = 0; i < 2000 && !(wp->rail_build_pending() && wp->off_lock_builds() > 0); ++i) {
    w.clock.advance_by(milliseconds(10));
    cl->keepalive_tick();
  }
  ASSERT_TRUE(wp->rail_build_pending()) << "a built set waits for the next tick";
  ASSERT_EQ(wp->off_lock_builds(), 1u);
  EXPECT_EQ(w.c1.endpoint_count(), 4u) << "rail 1's set (control, 2 fetch, ingest), not swapped in";
  cl.reset();
  EXPECT_EQ(w.c1.endpoint_count(), 0u) << "the built set was aborted and released with the Client";
  EXPECT_EQ(w.c0.endpoint_count(), 0u);
}

TEST(MultiRail, ControlRailLostControlMoves) {
  MR w;
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(2);
  Chain a("k", 6);
  auto da = w.store(sk, a, 7);
  EXPECT_EQ(w.port->control_rail(), 0u);
  const auto downs = w.port->session_down_count();
  ASSERT_TRUE(w.s0.fail_rail(kRail[0]));  // rail 0 carries control
  w.run_for(milliseconds(50));
  EXPECT_TRUE(w.port->session_up());
  EXPECT_EQ(w.port->control_rail(), 1u) << "LOOKUP and the rest move to the next healthy rail";
  std::size_t hits = 0;
  EXPECT_EQ(w.check_fetch(sk, a, da, false, &hits), 0u);
  EXPECT_EQ(hits, 6u) << "the session (and its data) survived: rail 1's LOOKUP finds every key";
  Chain b("m", 4);
  auto db = w.store(sk, b, 70);
  EXPECT_EQ(w.check_fetch(sk, b, db), 0u);
  EXPECT_EQ(w.port->session_down_count(), downs);
}

TEST(MultiRail, SuspectRailTakesNoNewWork) {
  MR w(2, 100);
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(3);
  Chain a("s", 6);
  auto da = w.store(sk, a, 11);
  // Rail 1 goes slow (its PONGs stop coming back in time): three missed PINGs make it suspect.
  w.start_ticker();
  w.net.set_link_delay(4, 2, seconds(2));
  bool suspect = false;
  for (int i = 0; i < 40 && !suspect; ++i) {
    w.run_for(milliseconds(100));
    suspect = w.port->rail_state(1) == WirePort::RailState::Suspect;
  }
  ASSERT_TRUE(suspect);
  const auto reads1 = w.port->rail_reads(1), puts1 = w.port->rail_puts(1);
  EXPECT_EQ(w.check_fetch(sk, a, da, true), 0u);
  Chain b("t", 3);
  std::vector<Bytes> db;
  for (int i = 0; i < 3; ++i) db.push_back(payload(8192, 200 + i));
  auto st = w.put(sk, b, db);
  for (auto s : st) EXPECT_EQ(testutil::status_failure(s, testutil::OracleMode::Strict), nullptr);
  EXPECT_EQ(w.port->rail_reads(1), reads1) << "a suspect rail takes no new READs";
  EXPECT_EQ(w.port->rail_puts(1), puts1) << "a suspect rail takes no new puts";
  EXPECT_TRUE(w.port->session_up());
}

// ---- RL3: fetch slicing, the seq rule and re-issue (multi-rail plan decisions 8, 9) ----------------------------------
// 4 MiB blocks, 1 MiB slices, a 2 MiB window per fetch QP, 2 rails x 2 fetch QPs.
Shape rl3_shape(Nanos lease_ttl = seconds(1000)) {
  Shape s;
  s.big = true;
  s.lease_ttl = lease_ttl;
  s.slice_bytes = 1u << 20;
  s.window_bytes = 2u << 20;
  return s;
}
constexpr std::size_t kBlock = 4u << 20;

// Submits a fetch of `ch` and drives it to its release; `each` runs between steps (fault injection, window probes).
template <class F>
std::vector<KeyStatus> fetch_with(MR& w, const ScopeKeys& sk, const Chain& ch, std::vector<Bytes>& out, F each) {
  std::vector<BufRef> bufs;
  for (auto& d : out) bufs.push_back({std::span<std::byte>(d)});
  Res r;
  w.core->submit_fetch(sk, 0, ch.refs, bufs, w.clock.now() + seconds(5), w.notify(r));
  for (int i = 0; i < 2000000 && !r.released; ++i) {
    w.core->pump();
    if (r.released) break;
    each();
    w.drive();
  }
  EXPECT_TRUE(r.released);
  return r.st;
}
// The oracle: allowed statuses, and every Hit carries exactly the stored bytes. Returns the wrong-byte count.
std::size_t judge(const std::vector<KeyStatus>& st, const std::vector<Bytes>& out, const std::vector<Bytes>& want,
                  std::size_t* hits = nullptr, std::size_t* misses = nullptr) {
  std::size_t wrong = 0, h = 0, m = 0;
  for (std::size_t i = 0; i < st.size(); ++i) {
    const char* f = testutil::status_failure(st[i], testutil::OracleMode::Fault, false);
    EXPECT_EQ(f, nullptr) << "key " << i << ": " << (f ? f : "");
    if (st[i] == KeyStatus::Hit) {
      ++h;
      if (out[i] != want[i]) ++wrong;
    }
    if (st[i] == KeyStatus::Miss) ++m;
  }
  if (hits) *hits = h;
  if (misses) *misses = m;
  return wrong;
}

TEST(MultiRailSlicing, FourMiBBlocksSpreadOverTwoRailsAndTwoQpsWithinTheWindows) {
  MR w(2, 100, rl3_shape());
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(4);
  Chain a("big", 4);
  auto data = w.store(sk, a, 21, kBlock);
  std::vector<Bytes> out;
  for (auto& d : data) out.emplace_back(d.size());
  std::uint64_t max_win[2] = {0, 0};
  std::size_t max_wait = 0;
  auto st = fetch_with(w, sk, a, out, [&] {
    for (std::size_t r = 0; r < 2; ++r) max_win[r] = std::max(max_win[r], w.port->rail_read_window(r));
    max_wait = std::max(max_wait, w.core->slices_waiting());
  });
  std::size_t hits = 0;
  EXPECT_EQ(judge(st, out, data, &hits), 0u);
  EXPECT_EQ(hits, 4u);
  // Both rails carried slices (rkey[r] and rail r's device lkey); no rail ever held more than its 2 QPs' windows.
  EXPECT_GT(w.port->rail_read_bytes(0), 4u << 20);
  EXPECT_GT(w.port->rail_read_bytes(1), 4u << 20);
  for (std::size_t r = 0; r < 2; ++r) EXPECT_LE(max_win[r], 2u * (2u << 20)) << "rail " << r;
  EXPECT_GT(max_wait, 0u) << "16 MiB of slices against 8 MiB of windows: some slices waited for room";
  EXPECT_EQ(w.port->rail_read_window(0) + w.port->rail_read_window(1), 0u);
  EXPECT_EQ(w.core->slices_waiting(), 0u);
  EXPECT_EQ(w.core->slices_reissued(), 0u);
  EXPECT_EQ(w.audit.violations(), 0u) << (w.audit.messages().empty() ? "" : w.audit.messages()[0]);
  EXPECT_EQ(w.audit.outstanding(), 0u);
  EXPECT_TRUE(w.core->check_invariants());
  const std::string m = w.core->metrics_text();
  EXPECT_NE(m.find("miracache_read_window{node=\"n1\",node_id=\"1\",hostname=\"memnode-a\",rail=\"1\",addr=\"10.0.1.1:7471\"} 0"),
            std::string::npos)
      << m;
  EXPECT_NE(m.find("miracache_client_fetch_rail_bytes_total{node=\"n1\",node_id=\"1\",hostname=\"memnode-a\",rail=\"0\""),
            std::string::npos);
}

TEST(MultiRailSlicing, RailFlushedMidFetchReissuesOnlyAfterItsFlushCqes) {
  MR w(2, 100, rl3_shape());
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(5);
  Chain a("mid", 4);
  auto data = w.store(sk, a, 33, kBlock);
  std::vector<Bytes> out;
  for (auto& d : data) out.emplace_back(d.size());
  const auto downs = w.port->session_down_count();
  // Rail 0 is a little slow (5 ms each way), so when rail 1's flush completions arrive the same blocks still have
  // slices in flight on rail 0: a re-issue of a slice whose own CQE has not arrived lands in live bytes (the audit).
  w.start_ticker();
  w.net.set_link_delay(3, 1, milliseconds(5));
  bool failed = false;
  std::uint64_t in_flight_on_1 = 0;
  auto st = fetch_with(w, sk, a, out, [&] {
    // Mid-fetch: some bytes have landed and rail 1 has READs outstanding. Then flush every endpoint of rail 1.
    if (!failed && w.port->rail_read_bytes(0) + w.port->rail_read_bytes(1) > 0 && w.port->rail_read_window(1) > 0) {
      in_flight_on_1 = w.port->rail_read_window(1);
      ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
      failed = true;
    }
  });
  ASSERT_TRUE(failed);
  EXPECT_GT(in_flight_on_1, 0u);
  std::size_t hits = 0;
  EXPECT_EQ(judge(st, out, data, &hits), 0u) << "exact bytes";
  EXPECT_EQ(hits, 4u) << "the lease is long and rail 0 is healthy: every flushed slice is re-read there";
  EXPECT_GT(w.core->slices_reissued(), 0u);
  EXPECT_EQ(w.port->slices_reissued(), w.core->slices_reissued());
  // The audit: no READ was re-posted while the original could still land (re-issue only after its own flush CQE), the
  // seq READ never went before the last slice CQE, and no span was released with a WR outstanding.
  EXPECT_EQ(w.audit.count(fabric::SimWrAudit::kReissueEarly), 0u);
  EXPECT_EQ(w.audit.count(fabric::SimWrAudit::kSeqEarly), 0u);
  EXPECT_EQ(w.audit.count(fabric::SimWrAudit::kReleaseOutstanding), 0u);
  EXPECT_EQ(w.audit.outstanding(), 0u);
  EXPECT_TRUE(w.port->session_up());
  EXPECT_EQ(w.port->session_down_count(), downs);
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  const std::string m = w.core->metrics_text();
  EXPECT_NE(m.find("miracache_client_slices_reissued_total{node=\"n1\",node_id=\"1\",hostname=\"memnode-a\",addr=\"10.0.0.1:7471\"} " +
                   std::to_string(w.core->slices_reissued())),
            std::string::npos)
      << m;
  // The same keys again, on rail 0 alone: exact bytes.
  std::vector<Bytes> again;
  for (auto& d : data) again.emplace_back(d.size());
  auto st2 = fetch_with(w, sk, a, again, [] {});
  EXPECT_EQ(judge(st2, again, data, &hits), 0u);
  EXPECT_EQ(hits, 4u);
  EXPECT_TRUE(w.core->check_invariants());
}

TEST(MultiRailSlicing, LeaseNearExpiryIsAMissNotAReissue) {
  // A 40 ms lease and a slow rail 1 (50 ms each way): by the time rail 1's slices flush, t_lease_granted + ttl - guard
  // has passed, so its blocks are misses (P40), never a re-issue that could read a block the lease no longer pins.
  MR w(2, 100, rl3_shape(milliseconds(40)));
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(6);
  Chain a("exp", 4);
  auto data = w.store(sk, a, 45, kBlock);
  std::vector<Bytes> out;
  for (auto& d : data) out.emplace_back(d.size());
  w.start_ticker();
  w.net.set_link_delay(4, 2, milliseconds(50));
  bool failed = false;
  const Nanos t0 = w.clock.now();
  auto st = fetch_with(w, sk, a, out, [&] {
    if (!failed && w.clock.now() - t0 >= milliseconds(45) && w.port->rail_read_window(1) > 0) {
      ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
      failed = true;
    }
  });
  ASSERT_TRUE(failed);
  std::size_t hits = 0, misses = 0;
  EXPECT_EQ(judge(st, out, data, &hits, &misses), 0u);
  EXPECT_GT(misses, 0u) << "the blocks with slices on the flushed rail";
  EXPECT_EQ(w.core->slices_reissued(), 0u) << "the lease deadline had passed: no re-issue";
  EXPECT_EQ(w.audit.violations(), 0u) << (w.audit.messages().empty() ? "" : w.audit.messages()[0]);
  EXPECT_TRUE(w.port->session_up());
  EXPECT_TRUE(w.core->check_invariants());
}

// RL3 leftover: a confirmed RENEW moves the re-issue deadline to (RENEW send time + granted ttl - guard). A 40 ms lease
// renewed every 5 ms and a slow rail 1 (50 ms each way) flushed at 45 ms: past the LOOKUP's lease, within the renewed
// one, so its slices are re-read on rail 0 with exact bytes. (Before: the LOOKUP time stayed the deadline: misses.)
TEST(MultiRailSlicing, RenewedLeaseAllowsAReissuePastTheLookupLease) {
  Shape sh = rl3_shape(milliseconds(40));
  sh.renew_every = milliseconds(5);
  MR w(2, 100, sh);
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(10);
  Chain a("ren", 4);
  auto data = w.store(sk, a, 65, kBlock);
  std::vector<Bytes> out;
  for (auto& d : data) out.emplace_back(d.size());
  w.start_ticker();
  w.net.set_link_delay(4, 2, milliseconds(50));
  bool failed = false;
  const Nanos t0 = w.clock.now();
  auto st = fetch_with(w, sk, a, out, [&] {
    if (!failed && w.clock.now() - t0 >= milliseconds(45) && w.port->rail_read_window(1) > 0) {
      ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
      failed = true;
    }
  });
  ASSERT_TRUE(failed);
  std::size_t hits = 0, misses = 0;
  EXPECT_EQ(judge(st, out, data, &hits, &misses), 0u) << "exact bytes";
  EXPECT_EQ(hits, 4u) << "the renewed lease still pins the blocks: every flushed slice is re-read on rail 0";
  EXPECT_GT(w.core->slices_reissued(), 0u);
  EXPECT_EQ(w.audit.violations(), 0u) << (w.audit.messages().empty() ? "" : w.audit.messages()[0]);
  EXPECT_TRUE(w.port->session_up());
  EXPECT_TRUE(w.core->check_invariants());
}

// RL3 leftover: renewals that the node caps (lease.max 50 ms after the grant) stop moving the deadline; a flush at 60 ms
// (after the renewed lease, before the slow rail 1 lands) is a miss, never a re-issue.
TEST(MultiRailSlicing, FlushPastTheRenewedLeaseIsAMiss) {
  Shape sh = rl3_shape(milliseconds(40));
  sh.renew_every = milliseconds(5);
  sh.lease_max = milliseconds(50);
  MR w(2, 100, sh);
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(11);
  Chain a("cap", 4);
  auto data = w.store(sk, a, 75, kBlock);
  std::vector<Bytes> out;
  for (auto& d : data) out.emplace_back(d.size());
  w.start_ticker();
  w.net.set_link_delay(4, 2, milliseconds(100));  // rail 1 READs land after about 100 ms
  bool failed = false;
  const Nanos t0 = w.clock.now();
  Nanos last_win1{0};
  auto st = fetch_with(w, sk, a, out, [&] {
    if (w.port->rail_read_window(1) > 0) last_win1 = w.clock.now() - t0;
    if (!failed && w.clock.now() - t0 >= milliseconds(60) && w.port->rail_read_window(1) > 0) {
      ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
      failed = true;
    }
  });
  ASSERT_TRUE(failed) << "rail 1 last had READs out at " << last_win1.count() / 1000000 << " ms, fetch ended at "
                      << (w.clock.now() - t0).count() / 1000000 << " ms";
  std::size_t hits = 0, misses = 0;
  EXPECT_EQ(judge(st, out, data, &hits, &misses), 0u);
  EXPECT_GT(misses, 0u) << "the blocks with slices on the flushed rail";
  EXPECT_EQ(w.core->slices_reissued(), 0u) << "past the renewed lease: no re-issue";
  EXPECT_EQ(w.audit.violations(), 0u) << (w.audit.messages().empty() ? "" : w.audit.messages()[0]);
  EXPECT_TRUE(w.core->check_invariants());
}

TEST(MultiRailSlicing, SlowRailIsNeverReissuedWithoutItsCqe) {
  // Rail 1 is slow but alive (20 ms each way): its slices take long, and none is re-issued (no timer guesses): the
  // fetch waits for their CQEs. (Mutator target: a timer-based re-issue posts a second READ into live bytes.)
  MR w(2, 100, rl3_shape());
  ASSERT_TRUE(w.core);
  auto sk = scope_keys(7);
  Chain a("slow", 4);
  auto data = w.store(sk, a, 57, kBlock);
  std::vector<Bytes> out;
  for (auto& d : data) out.emplace_back(d.size());
  w.start_ticker();
  w.net.set_link_delay(4, 2, milliseconds(20));
  auto st = fetch_with(w, sk, a, out, [] {});
  std::size_t hits = 0;
  EXPECT_EQ(judge(st, out, data, &hits), 0u);
  EXPECT_EQ(hits, 4u);
  EXPECT_EQ(w.core->slices_reissued(), 0u);
  EXPECT_GT(w.port->rail_read_bytes(1), 0u) << "the slow rail still carried slices";
  EXPECT_EQ(w.audit.violations(), 0u) << (w.audit.messages().empty() ? "" : w.audit.messages()[0]);
}

TEST(MultiRail, ConfigRejectsMoreThanFourRails) {
  const std::string head = "[scope]\nsecret_file = \"/s\"\n[lab]\nstatic_membership = true\n[[nodes]]\nrails = [";
  auto rails = [](int n) {
    std::string s;
    for (int i = 0; i < n; ++i) s += (i ? ", " : "") + std::string("\"10.0.") + std::to_string(i) + ".1:7471\"";
    return s;
  };
  auto four = load_config(head + rails(4) + "]\n");
  ASSERT_TRUE(four) << four.error().context;
  EXPECT_EQ(four->nodes[0].rails.size(), 4u);
  auto five = load_config(head + rails(5) + "]\n");
  ASSERT_FALSE(five);
  EXPECT_NE(std::string(five.error().context).find("1..4"), std::string::npos) << five.error().context;
  // fabric.devices: 1..4 {device, subnet}; exclusive with fabric.device.
  auto devs = load_config(head + rails(2) + "]\n[fabric]\ndevices = [{device = \"mlx5_0\", subnet = \"10.0.0.0/24\"}, "
                                           "{device = \"mlx5_1\", subnet = \"10.0.1.0/24\"}]\n");
  ASSERT_TRUE(devs) << devs.error().context;
  ASSERT_EQ(devs->devices.size(), 2u);
  EXPECT_EQ(devs->devices[1].subnet, "10.0.1.0/24");
  EXPECT_EQ(devs->device, "mlx5_0");
  EXPECT_FALSE(load_config(head + rails(1) + "]\n[fabric]\ndevice = \"a\"\ndevices = [{device = \"b\"}]\n"));
  // H01: one wildcard (blank subnet) device at most; a second would never be paired.
  auto one_wild = load_config(head + rails(2) + "]\n[fabric]\ndevices = [{device = \"mlx5_0\"}, "
                                               "{device = \"mlx5_1\", subnet = \"10.0.1.0/24\"}]\n");
  ASSERT_TRUE(one_wild) << one_wild.error().context;
  auto two_wild = load_config(head + rails(2) + "]\n[fabric]\ndevices = [{device = \"mlx5_0\"}, "
                                               "{device = \"mlx5_1\", subnet = \"10.0.1.0/24\"}, {device = \"mlx5_2\", subnet = \"\"}]\n");
  ASSERT_FALSE(two_wild);
  EXPECT_NE(std::string(two_wild.error().context).find("only one wildcard device"), std::string::npos)
      << two_wild.error().context;
}

// Run #219 (RL4 finding): bundle nodes always report a subnet per rail (the address's /24). A local device with a
// blank subnet is a wildcard: it takes every rail of the client's protocol that no subnet device claims.
ClientConfig pairing_cfg(std::vector<LocalDevice> devs, FabricProtocol proto = FabricProtocol::Auto) {
  ClientConfig c;
  c.protocol = proto;
  if (devs.size() == 1 && devs[0].subnet.empty()) {
    c.device = devs[0].device;  // the legacy single fabric.device
  } else {
    c.devices = std::move(devs);
    c.device = c.devices[0].device;
  }
  return c;
}

TEST(RailPairing, LegacySingleDevicePairsEveryBundleRail) {
  const auto cfg = pairing_cfg({{"rxe0", ""}});
  ASSERT_TRUE(cfg.devices.empty());
  const std::vector<NodeRail> rails = {{"192.168.5.2:7471", "192.168.5.0/24", "roce"},
                                       {"10.98.0.1:7472", "10.98.0.0/24", "roce"}};
  std::uint32_t unpaired = 9;
  const auto p = pair_rails(cfg, rails, 7, "memnode-a", unpaired);
  EXPECT_EQ(unpaired, 0u);
  ASSERT_EQ(p.size(), 2u);
  EXPECT_EQ(p[0].index, 0);
  EXPECT_EQ(p[0].device, 0u);
  EXPECT_EQ(p[0].addr.host, "192.168.5.2");
  EXPECT_EQ(p[0].addr.port, 7471);
  EXPECT_EQ(p[1].index, 1);
  EXPECT_EQ(p[1].device, 0u);
  EXPECT_EQ(p[1].addr.host, "10.98.0.1");
}

TEST(RailPairing, SubnetDevicesPairExactly) {
  const auto cfg = pairing_cfg({{"mlx5_0", "10.0.0.0/24"}, {"mlx5_1", "10.0.1.0/24"}});
  const std::vector<NodeRail> rails = {{"10.0.1.5:7471", "10.0.1.0/24", "roce"},
                                       {"10.0.0.5:7471", "10.0.0.0/24", "roce"},
                                       {"10.0.2.5:7471", "10.0.2.0/24", "roce"}};  // no device, no wildcard
  std::uint32_t unpaired = 0;
  const auto p = pair_rails(cfg, rails, 7, "memnode-a", unpaired);
  EXPECT_EQ(unpaired, 1u);
  ASSERT_EQ(p.size(), 2u);
  EXPECT_EQ(p[0].index, 0);
  EXPECT_EQ(p[0].device, 1u);
  EXPECT_EQ(p[1].index, 1);
  EXPECT_EQ(p[1].device, 0u);
}

TEST(RailPairing, ExactSubnetWinsOverTheWildcard) {
  // The wildcard is listed first: the exact device still wins its subnet; the wildcard takes the rest.
  const auto cfg = pairing_cfg({{"mlx5_any", ""}, {"mlx5_1", "10.0.1.0/24"}, {"mlx5_2", "10.9.9.0/24"}});
  const std::vector<NodeRail> rails = {{"10.0.0.5:7471", "10.0.0.0/24", "roce"},
                                       {"10.0.1.5:7471", "10.0.1.0/24", "roce"},
                                       {"10.0.2.5:7471", "10.0.2.0/24", ""},
                                       {"10.0.3.5:7471", "", "roce"}};  // a legacy rail with no subnet
  std::uint32_t unpaired = 9;
  const auto p = pair_rails(cfg, rails, 7, "memnode-a", unpaired);
  EXPECT_EQ(unpaired, 0u);
  ASSERT_EQ(p.size(), 4u);
  EXPECT_EQ(p[0].device, 0u) << "no subnet device: the first wildcard";
  EXPECT_EQ(p[1].device, 1u) << "exact subnet beats the wildcard";
  EXPECT_EQ(p[2].device, 0u);
  EXPECT_EQ(p[3].device, 0u) << "a rail with no subnet: the first wildcard";
}

// H01: the wildcard taking a rail that has a subnet is logged once per (node, rail), with the node's ID, hostname and
// addr; a legacy rail with no subnet and an exact-subnet pair are not logged.
TEST(RailPairing, WildcardTakingASubnetRailIsLoggedOnce) {
  char tmpl[] = "/tmp/mira-wild-XXXXXX";
  const int lfd = ::mkstemp(tmpl);
  ASSERT_GE(lfd, 0);
  log::set_sink_fd(lfd);
  const auto cfg = pairing_cfg({{"mlx5_any", ""}, {"mlx5_1", "10.0.1.0/24"}});
  const std::vector<NodeRail> rails = {{"10.0.7.5:7471", "10.0.7.0/24", "iwarp"},
                                       {"10.0.1.5:7471", "10.0.1.0/24", "roce"},
                                       {"10.0.3.5:7471", "", "roce"}};
  std::uint32_t unpaired = 9;
  for (int i = 0; i < 3; ++i) {  // open + two rebuilds of the same node
    const auto p = pair_rails(cfg, rails, 4242, "memnode-w", unpaired);
    EXPECT_EQ(unpaired, 0u);
    ASSERT_EQ(p.size(), 3u);
    EXPECT_EQ(p[0].device, 0u) << "auto: the wildcard takes a rail of any protocol and subnet";
  }
  log::set_sink_fd(2);
  std::string text;
  {
    char buf[4096];
    ssize_t n;
    ::lseek(lfd, 0, SEEK_SET);
    while ((n = ::read(lfd, buf, sizeof buf)) > 0) text.append(buf, static_cast<std::size_t>(n));
  }
  ::close(lfd);
  ::unlink(tmpl);
  const std::string msg = "memory-node rail paired with the wildcard device";
  const auto first = text.find(msg);
  ASSERT_NE(first, std::string::npos) << text;
  EXPECT_EQ(text.find(msg, first + 1), std::string::npos) << "once, not per call:\n" << text;
  EXPECT_NE(text.find("node_id=4242"), std::string::npos) << text;
  EXPECT_NE(text.find("hostname=memnode-w"), std::string::npos) << text;
  EXPECT_NE(text.find("addr=10.0.7.5:7471"), std::string::npos) << text;
  EXPECT_NE(text.find("subnet=10.0.7.0/24"), std::string::npos) << text;
  EXPECT_NE(text.find("device=mlx5_any"), std::string::npos) << text;
  EXPECT_EQ(text.find("addr=10.0.3.5:7471"), std::string::npos) << "a rail with no subnet is not logged:\n" << text;
  EXPECT_EQ(text.find("addr=10.0.1.5:7471"), std::string::npos) << "an exact pair is not logged:\n" << text;
}

TEST(RailPairing, ProtocolMismatchStaysUnpairedEvenOnTheWildcard) {
  const auto cfg = pairing_cfg({{"rxe0", ""}}, FabricProtocol::Roce);
  const std::vector<NodeRail> rails = {{"192.168.5.2:7471", "192.168.5.0/24", "iwarp"},
                                       {"192.168.5.2:7472", "192.168.5.0/24", "roce"}};
  std::uint32_t unpaired = 0;
  const auto p = pair_rails(cfg, rails, 7, "memnode-a", unpaired);
  EXPECT_EQ(unpaired, 1u);
  ASSERT_EQ(p.size(), 1u);
  EXPECT_EQ(p[0].index, 1);
  // Subnet devices: a matching subnet does not excuse another protocol either.
  const auto cfg2 = pairing_cfg({{"mlx5_0", "192.168.5.0/24"}}, FabricProtocol::Iwarp);
  const auto p2 = pair_rails(cfg2, {{"192.168.5.2:7471", "192.168.5.0/24", "roce"}}, 7, "memnode-a", unpaired);
  EXPECT_TRUE(p2.empty());
  EXPECT_EQ(unpaired, 1u);
}

// ---- run #279: tests for J06a, J07 (review s8 wave15; fixed in run #267) ----
// The log lines of a test's scope, in a temp file: count(msg) counts the lines that carry `msg` (and node_id=1).
struct LogCapture {
  LogCapture() {
    fd = ::mkstemp(path);
    if (fd >= 0) log::set_sink_fd(fd);
  }
  ~LogCapture() {
    log::set_sink_fd(2);
    if (fd >= 0) ::close(fd);
    ::unlink(path);
  }
  std::string text() const {
    std::string t;
    char buf[4096];
    ssize_t n;
    ::lseek(fd, 0, SEEK_SET);
    while ((n = ::read(fd, buf, sizeof buf)) > 0) t.append(buf, static_cast<std::size_t>(n));
    return t;
  }
  std::size_t count(const std::string& msg) const {
    const std::string t = text();
    std::size_t c = 0, at = 0;
    while (at < t.size()) {
      const std::size_t eol = std::min(t.find('\n', at), t.size());
      const std::string line = t.substr(at, eol - at);
      if (line.find(msg) != std::string::npos && line.find("node_id=1 ") != std::string::npos) ++c;
      at = eol + 1;
    }
    return c;
  }
  char path[32] = "/tmp/mira-mr-XXXXXX";
  int fd = -1;
};

// A rail device that can report one device-level CqError (a CQ overflow) on its next poll; forwards everything else.
class CqErrorFabric final : public fabric::Fabric {
 public:
  explicit CqErrorFabric(fabric::Fabric& in) : in_(in) {}
  Expected<fabric::DeviceCaps> probe() override { return in_.probe(); }
  Expected<fabric::PdId> alloc_pd() override { return in_.alloc_pd(); }
  Status free_pd(fabric::PdId pd) override { return in_.free_pd(pd); }
  Expected<fabric::MemRegion> reg(std::span<std::byte> b, fabric::Access a, fabric::PdId pd) override { return in_.reg(b, a, pd); }
  Status dereg(const fabric::MemRegion& r) override { return in_.dereg(r); }
  Expected<fabric::Endpoint*> connect(const fabric::Peer& p, const fabric::ConnParams& cp) override { return in_.connect(p, cp); }
  Status release(fabric::Endpoint* ep) override { return in_.release(ep); }
  Status listen(fabric::AcceptFn f, const fabric::ListenParams& lp) override { return in_.listen(std::move(f), lp); }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget b) override {
    std::size_t n = in_.poll(out, b);
    if (armed && n < out.size()) {
      armed = false;
      fabric::Completion c;
      c.op = fabric::CompletionOp::CqError;
      c.status = Error{ErrorCode::ResourceExhausted, "test: completion queue overflow"};
      out[n++] = std::move(c);
      ++delivered;
    }
    return n;
  }
  int wait_fd() override { return in_.wait_fd(); }
  fabric::FabricHealth health() override { return in_.health(); }
  bool armed = false;
  unsigned delivered = 0;

 private:
  fabric::Fabric& in_;
};

// J06a (review s8 wave15): rail 1's device reports a CqError while it is lent to a rail build that fails (the node's
// rail is still down). release_made() polls it off the lent fabric; it must reach ClientCore (counted as an RDMA error,
// kind "other") as the same completion polled under the lock does. Before the fix release_made threw it away.
TEST(MultiRail, CqErrorPolledWhileReleasingAFailedRailBuildReachesTheCore) {
  std::unique_ptr<CqErrorFabric> wf;
  Shape sh;
  sh.wrap_rail1 = [&wf](fabric::SimFabric& c1) -> fabric::Fabric* {
    wf = std::make_unique<CqErrorFabric>(c1);
    return wf.get();
  };
  MR w(/*fetch_qps=*/2, /*keepalive_ms=*/100, sh);
  ASSERT_TRUE(w.core);
  ASSERT_TRUE(wf);
  auto cq_errors = [&] { return metric(w.core->metrics_text(), "miracache_client_rdma_errors_total", {"kind=\"other\""}); };
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  w.run_for(milliseconds(50));
  ASSERT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  ASSERT_TRUE(w.port->session_up());
  const double before = cq_errors();
  ASSERT_GE(before, 0.0) << "the series exists";
  // Rail 1's rejoin builds off the lock (its device lent). The device is armed only while it is lent, so the CqError
  // can only be polled by the failed build's release, never by service() under the lock.
  bool lent = false;
  const Nanos until = w.clock.now() + seconds(10);
  Nanos next = w.clock.now();
  while (w.clock.now() < until && wf->delivered == 0) {
    if (w.clock.now() >= next) {
      w.port->keepalive();
      if (w.port->rail_build_pending() && !lent) {
        lent = true;
        wf->armed = true;
      }
      next = w.clock.now() + (w.port->build_rails() ? milliseconds(1) : milliseconds(100));
    }
    w.core->pump();
    w.drive();
  }
  ASSERT_TRUE(lent) << "rail 1's device was never lent to a build";
  ASSERT_EQ(wf->delivered, 1u) << "the failed build's release never polled the lent device";
  w.run_for(milliseconds(500));  // the next keepalive takes the device back; the core pumps
  EXPECT_EQ(cq_errors(), before + 1) << "the CqError polled off the lent device never reached ClientCore";
  EXPECT_TRUE(w.port->session_up()) << "rail 0 keeps the node Up";
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
}

// J07 (review s8 wave15) and R22: a mis-wired node, whose rail 0 reaches process A and rail 1 process B (each on its
// own devices, both running). Every session comes up on rail 0 (A) with rail 1 refused for B's boot nonce; rail 1's
// rejoin then sees B's nonce and ends the session. After 3 such ends in a row the session stays, rail 1 stays down on
// the long backoff, and one Error line says so (with both nonces). Then (R22) a session that comes up while rail 1 is
// merely unreachable (no rail refused for another nonce) resets the count: rail 1's next rejoin to B is handled as a
// restart again (Warn, the session reconnects), not damped.
TEST(MultiRail, MisWiredRailIsDampedAfterThreeNonceRestartsAndACleanSessionResetsTheCount) {
  LogCapture logs;
  const std::string damped = "boot_nonce_mismatch_repeated", restarted = "node_restarted_boot_nonce";
  MR w(/*fetch_qps=*/2, /*keepalive_ms=*/0);  // reconnect 100 ms .. 5 s (the defaults)
  ASSERT_TRUE(w.core);
  auto run_until = [&w](auto pred, Nanos span) {
    const Nanos until = w.clock.now() + span;
    Nanos next = w.clock.now();
    while (w.clock.now() < until && !pred()) {
      if (w.clock.now() >= next) next = w.clock.now() + (w.ka() ? milliseconds(1) : milliseconds(20));
      w.core->pump();
      w.drive();
    }
    return pred();
  };
  // The session ends (both rails cut); two processes take the node's addresses, one per rail.
  ASSERT_TRUE(w.s0.fail_rail(kRail[0]));
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  ASSERT_TRUE(run_until([&] { return !w.port->session_up(); }, seconds(5)));
  fabric::SimFabric& da = w.net.add_node(5);  // A's rail-1 device and B's rail-0 device: nobody reaches them
  fabric::SimFabric& db = w.net.add_node(6);
  da.set_key_base_for_test(0x9000);
  db.set_key_base_for_test(0xA000);
  auto a = server::Server::create(w.scfg, std::vector<fabric::Fabric*>{&w.s0, &da}, w.clock, w.rng, w.sex);
  ASSERT_TRUE(a) << a.error().context;
  ASSERT_TRUE((*a)->start());
  auto b = server::Server::create(w.scfg, std::vector<fabric::Fabric*>{&db, &w.s1}, w.clock, w.rng, w.sex);
  ASSERT_TRUE(b) << b.error().context;
  ASSERT_TRUE((*b)->start());
  ASSERT_NE((*a)->boot_nonce(), (*b)->boot_nonce());
  const std::uint64_t nonce_a = (*a)->boot_nonce();
  w.old_server = std::move(w.server);  // never run again (it shares the devices with A and B)
  w.server = std::move(*a);
  w.extra.push_back(std::move(*b));
  w.ticket_server = [&w](std::uint8_t rail) { return rail == 0 ? w.server.get() : w.extra[0].get(); };
  const auto downs0 = w.port->session_down_count();
  ASSERT_TRUE(w.s0.restore_rail(kRail[0]));
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));

  // Three nonce restarts (each: a session on A, rail 1's rejoin reaches B, the session ends), then the damping.
  ASSERT_TRUE(run_until([&] { return logs.count(damped) >= 1; }, seconds(30))) << logs.text();
  EXPECT_EQ(w.port->restarts_detected(), 3u);
  EXPECT_EQ(logs.count(restarted), 3u);
  EXPECT_TRUE(w.port->session_up()) << "the session stays";
  ASSERT_TRUE(w.port->boot_nonce().has_value());
  EXPECT_EQ(*w.port->boot_nonce(), nonce_a) << "on rail 0's process";
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  const auto downs_damped = w.port->session_down_count();
  EXPECT_EQ(downs_damped, downs0 + 3) << "one Down per restart, none for the damped one";
  // The long backoff (reconnect_max_ms 5 s, jittered down to 2.5 s): 2 s on, still one Error line, no new restart.
  run_until([] { return false; }, seconds(2));
  EXPECT_EQ(logs.count(damped), 1u) << logs.text();
  EXPECT_EQ(w.port->restarts_detected(), 3u);
  EXPECT_EQ(w.port->session_down_count(), downs_damped);
  EXPECT_TRUE(w.port->session_up());
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  for (const auto& l : {std::string("session_boot_nonce="), std::string("rail_boot_nonce=")})
    EXPECT_NE(logs.text().find(l), std::string::npos) << "both nonces are logged: " << l;

  // R22: a session that comes up with rail 1 merely unreachable (no rail refused for another nonce) resets the count.
  ASSERT_TRUE(w.s0.fail_rail(kRail[0]));
  ASSERT_TRUE(w.s1.fail_rail(kRail[1]));
  ASSERT_TRUE(run_until([&] { return !w.port->session_up(); }, seconds(5)));
  ASSERT_TRUE(w.s0.restore_rail(kRail[0]));  // rail 1 stays cut
  ASSERT_TRUE(run_until([&] { return w.port->session_up(); }, seconds(10)));
  EXPECT_EQ(w.port->rail_state(1), WirePort::RailState::Down);
  const auto downs_clean = w.port->session_down_count();
  ASSERT_TRUE(w.s1.restore_rail(kRail[1]));  // rail 1's rejoin reaches B again: a restart, handled as one
  ASSERT_TRUE(run_until([&] { return w.port->restarts_detected() >= 4; }, seconds(15)))
      << "the restart after a clean session was damped\n" << logs.text();
  EXPECT_EQ(logs.count(restarted), 4u);
  EXPECT_EQ(logs.count(damped), 1u);
  EXPECT_GT(w.port->session_down_count(), downs_clean) << "the session reconnects";
}

}  // namespace
}  // namespace miracache
