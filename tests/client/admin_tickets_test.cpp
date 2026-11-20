// SPDX-License-Identifier: Apache-2.0
// Client side of IssueTicket over mTLS: the ticket cache (refill / no reuse / expiry), strict
// response parsing, server-certificate checks, key-file mode, and a sim session that outlives a
// dead admin endpoint. The server is the real server::AdminHttps; certs come from
// deploy/examples/lab-certs.sh (openssl CLI) into a temp dir.
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <thread>

#include <chrono>
#include <cstdlib>
#include <fstream>
#include <future>
#include <memory>
#include <set>
#include <vector>
#include <string>

#include "fabric/sim/sim_fabric.h"
#include "miracache/config.h"
#include "server/runtime/admin_https.h"
#include "server/server.h"
#include "src/admin_tickets.h"
#include "src/client_metrics.h"
#include "src/client_core.h"
#include "src/wire_port.h"
#include "util/clock.h"
#include "util/random.h"

namespace miracache {
namespace {

using std::chrono::milliseconds;
using std::chrono::seconds;

struct Certs {
  std::string root, pki, rogue;
  static void sh(const std::string& cmd) { EXPECT_EQ(std::system(cmd.c_str()), 0) << cmd; }
  Certs() {
    char t[] = "/tmp/mira-cadm-XXXXXX";
    EXPECT_NE(::mkdtemp(t), nullptr);
    root = t;
    pki = root + "/pki";
    rogue = root + "/rogue";
    sh(std::string("bash ") + MIRACACHE_LAB_CERTS_SH + " " + pki + " --nodes 1 --clients 1,2 >/dev/null");
    sh(std::string("bash ") + MIRACACHE_LAB_CERTS_SH + " " + rogue + " --nodes 1 --clients 1 >/dev/null");
  }
  ~Certs() { sh("rm -rf " + root); }
  Certs(const Certs&) = delete;
};
const Certs& certs() {
  static const Certs c;
  return c;
}

class CounterSalts final : public NonceSource {
 protected:
  Status fill(std::span<std::byte> out) override {
    ++n_;
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::byte>(n_ * 37 + i * 5 + 1);
    return {};
  }
  unsigned n_ = 0;
};

server::ServerConfig server_cfg() {
  server::ServerConfig sc;
  auto& c = sc.store;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 4;
  c.gen_chunk = 1000;
  c.put_timeout = seconds(1000);
  c.lease_ttl = seconds(1000);
  c.lease_max = seconds(2000);
  c.invalidate_per_s = 0;
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 8u << 20;
  c.principal_default.idle_ttl = seconds(100000);
  c.node_id = 1;
  sc.lab_identity = "lab";
  sc.lab_principal = 5;
  sc.lab_identities = {"spiffe://lab/client-1"};
  return sc;
}

std::string metrics_text(ClientMetrics& m) {
  std::string t;
  m.reg.write_prometheus(t);
  return t;
}
double metric(const std::string& text, const std::string& series) {
  const auto p = text.find("\n" + series + " ") + 1;  // line start: HELP lines also name the metric
  return p == 0 ? -1 : std::atof(text.c_str() + p + series.size() + 1);
}

// Node: sim server + real admin endpoint. The test thread is the "store thread": it pumps the
// admin mailbox while a client call runs on another thread.
struct Node {
  // `rails` > 0 (RL2 follow-up): that many listeners on the one sim device, 10.0.<r>.1:7471.
  explicit Node(std::size_t rails = 0) : rng(1), net(clock, rng, {}, {}), srv_fab(net.add_node(1)), cli(net.add_node(2)) {
    auto cfg = server_cfg();
    for (std::size_t r = 0; r < rails; ++r) cfg.rails.push_back(fabric::RailAddr{"10.0." + std::to_string(r) + ".1", 7471});
    auto s = server::Server::create(cfg, srv_fab, clock, rng, sex);
    EXPECT_TRUE(s);
    server = std::move(*s);
    EXPECT_TRUE(server->start());
    start_admin(5000);
  }
  void start_admin(std::uint32_t handshake_ms = 0) {
    const auto& c = certs();
    server::AdminOptions ao{"127.0.0.1:0", c.pki + "/node-1.pem", c.pki + "/node-1.key", c.pki + "/ca.pem", 300};
    ao.handshake_ms_for_test = handshake_ms;
    ao.node_id = server->node_id();
    ao.hostname = "hostA";
    auto a = server::AdminHttps::start(ao, server->metrics());
    EXPECT_TRUE(a && *a);
    if (a && *a) admin = std::move(*a);
  }
  template <class F>
  auto run(F fn) {
    auto fut = std::async(std::launch::async, fn);
    while (fut.wait_for(milliseconds(2)) != std::future_status::ready)
      if (admin) admin->pump(*server);
    return fut.get();
  }
  void drive() {
    if (!net.step()) clock.advance_by(milliseconds(1));
    server->run_once();
  }
  AdminTicketOptions opts(const std::string& who = "client-1") const {
    const auto& c = certs();
    AdminTicketOptions o;
    o.admin = "127.0.0.1:" + std::to_string(admin->port());
    o.cert = c.pki + "/" + who + ".pem";
    o.key = c.pki + "/" + who + ".key";
    o.ca = c.pki + "/ca.pem";
    return o;
  }
  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& srv_fab;
  fabric::SimFabric& cli;
  InlineExecutor sex;
  std::unique_ptr<server::Server> server;
  std::unique_ptr<server::AdminHttps> admin;
};

std::string hexid(const proto::Ticket& t) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (auto b : t.id) s += {d[b >> 4], d[b & 15]};
  return s;
}

TEST(AdminTicketsParse, StrictResponse) {
  const std::string id = "00112233445566778899aabbccddeeff";
  auto ok = AdminTicketSource::parse_response(
      "{\"ttl_s\":300,\"tickets\":[{\"class\":\"fetch\",\"rail\":0,\"id\":\"" + id + "\"}]}", 4);
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->ttl_s, 300u);
  EXPECT_EQ(ok->by_class[1].size(), 1u);
  EXPECT_EQ(hexid(ok->by_class[1][0]), id);
  const std::string t = "{\"class\":\"fetch\",\"rail\":0,\"id\":\"" + id + "\"}";
  for (const std::string& bad : std::vector<std::string>{
           std::string(""), std::string("{"), std::string("[]"),
           "{\"ttl_s\":300}", "{\"tickets\":[]}",
           "{\"ttl_s\":300,\"tickets\":[]} x",
           "{\"ttl_s\":300,\"ttl_s\":300,\"tickets\":[]}",
           "{\"ttl_s\":0,\"tickets\":[]}",
           "{\"ttl_s\":1.5,\"tickets\":[]}",
           "{\"ttl_s\":300,\"tickets\":[{\"class\":\"nope\",\"rail\":0,\"id\":\"" + id + "\"}]}",
           "{\"ttl_s\":300,\"tickets\":[{\"class\":\"fetch\",\"rail\":1,\"id\":\"" + id + "\"}]}",
           "{\"ttl_s\":300,\"tickets\":[{\"class\":\"fetch\",\"rail\":0,\"id\":\"zz112233445566778899aabbccddeeff\"}]}",
           "{\"ttl_s\":300,\"tickets\":[{\"class\":\"fetch\",\"rail\":0,\"id\":\"0011\"}]}",
           "{\"ttl_s\":300,\"tickets\":[{\"class\":\"fetch\",\"rail\":0}]}",
           "{\"ttl_s\":300,\"tickets\":[{\"class\":\"fe\\tch\",\"rail\":0,\"id\":\"" + id + "\"}]}",
       })
    EXPECT_FALSE(AdminTicketSource::parse_response(bad, 4))
        << bad;
  EXPECT_FALSE(AdminTicketSource::parse_response("{\"ttl_s\":300,\"tickets\":[" + t + "," + t + "]}", 1));  // over the batch
}


// Review r9 S08: the hostname lands in a metric label, so only 1..64 of [A-Za-z0-9._-] is kept; anything else is unknown.
TEST(AdminTicketsParse, HostnameIsValidatedForMetricLabels) {
  auto parse = [](const std::string& host_json) {
    return AdminTicketSource::parse_response("{\"ttl_s\":300,\"tickets\":[],\"hostname\":" + host_json + "}", 4);
  };
  for (const char* good : {"\"hostA\"", "\"gpu-07.rack_2.lab\"", "\"a\""}) {
    auto r = parse(good);
    ASSERT_TRUE(r) << good;
    EXPECT_FALSE(r->hostname.empty()) << good;
  }
  EXPECT_EQ(parse("\"" + std::string(64, 'a') + "\"")->hostname.size(), 64u);
  for (const std::string& bad : std::vector<std::string>{
           "\"" + std::string(65, 'a') + "\"", "\"\"", "\"a b\"", "\"a=b\"",
           "\"\xc3\xa9\"", "\"\x7f\""}) {
    auto r = parse(bad);
    ASSERT_TRUE(r) << bad;  // not an error: the node just stays unknown
    EXPECT_TRUE(r->hostname.empty()) << bad;
  }
}
// Plan 2C forward compatibility: a newer server may add fields. The parser skips unknown fields at the top
// level and per ticket (any JSON value), reads the node_id / hostname it knows, and still refuses duplicates.
TEST(AdminTicketsParse, IgnoresUnknownFieldsAndReadsIdentity) {
  const std::string id = "00112233445566778899aabbccddeeff";
  const std::string tk = "{\"class\":\"fetch\",\"rail\":0,\"id\":\"" + id + "\"";
  auto ok = AdminTicketSource::parse_response(
      "{\"ttl_s\":300,\"future\":{\"a\":[1,2.5e3,true,null,\"x\\\"y\"],\"b\":{}},\"tickets\":[" + tk +
          ",\"expires\":12345,\"tags\":[\"a\",\"b\"],\"meta\":{\"k\":\"v\"}}],\"node_id\":4021,\"hostname\":\"hostA\","
          "\"zone\":\"rack-1\",\"flag\":false}",
      4);
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->ttl_s, 300u);
  ASSERT_EQ(ok->by_class[1].size(), 1u);
  EXPECT_EQ(hexid(ok->by_class[1][0]), id);
  EXPECT_EQ(ok->node_id, 4021u);
  EXPECT_EQ(ok->hostname, "hostA");
  // Without the identity fields (an older server) both stay empty.
  auto old = AdminTicketSource::parse_response("{\"ttl_s\":300,\"tickets\":[" + tk + "}]}", 4);
  ASSERT_TRUE(old);
  EXPECT_EQ(old->node_id, 0u);
  EXPECT_TRUE(old->hostname.empty());
  // Still errors: a malformed unknown value, a duplicate known field (top level and per ticket), a bad node_id.
  for (const std::string& bad : std::vector<std::string>{
           "{\"ttl_s\":300,\"tickets\":[],\"x\":[1,}",
           "{\"ttl_s\":300,\"tickets\":[],\"x\":\"unterminated}",
           "{\"ttl_s\":300,\"tickets\":[],\"x\":nul}",
           "{\"ttl_s\":300,\"tickets\":[],\"node_id\":1,\"node_id\":2}",
           "{\"ttl_s\":300,\"tickets\":[],\"node_id\":0}",
           "{\"ttl_s\":300,\"tickets\":[],\"node_id\":4294967296}",
           "{\"ttl_s\":300,\"tickets\":[" + tk + ",\"id\":\"" + id + "\"}]}",
           "{\"ttl_s\":300,\"tickets\":[" + tk + ",\"x\":[1,}]}",
       })
    EXPECT_FALSE(AdminTicketSource::parse_response(bad, 4)) << bad;
}

TEST(AdminTickets, CacheRefillNoReuseAndExpiry) {
  Node n;
  SimClock clk;  // the source's own clock: tickets age here
  auto o = n.opts();
  o.batch = 4;
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src) << src.error().context;
  auto& s = **src;
  ClientMetrics mx;
  s.bind_metrics(&mx);
  EXPECT_FALSE(s.draw(fabric::EpClass::Fetch));  // nothing before the first prepare: draw never fetches
  ASSERT_TRUE(n.run([&] { return s.prepare(); }));
  EXPECT_EQ(s.fetches(), 1u);
  EXPECT_EQ(s.hostname(), "hostA");  // plan 2C: learned from the ticket response
  EXPECT_EQ(s.reported_node_id(), n.server->node_id());
  for (auto c : {fabric::EpClass::Control, fabric::EpClass::Fetch, fabric::EpClass::Ingest}) EXPECT_EQ(s.cached(c), 4u);

  std::set<std::string> seen;
  auto take = [&](fabric::EpClass c) {
    auto t = s.draw(c);
    EXPECT_TRUE(t);
    if (t) {
      EXPECT_EQ(t->cls, static_cast<std::uint8_t>(c));
      EXPECT_TRUE(seen.insert(hexid(*t)).second) << "a ticket was handed out twice";
    }
  };
  for (int i = 0; i < 2; ++i)
    for (auto c : {fabric::EpClass::Control, fabric::EpClass::Fetch, fabric::EpClass::Ingest}) take(c);
  // 2 left per class: no refill yet.
  ASSERT_TRUE(n.run([&] { return s.prepare(); }));
  EXPECT_EQ(s.fetches(), 1u);
  take(fabric::EpClass::Fetch);  // fetch now has 1 (< 2): refill
  ASSERT_TRUE(n.run([&] { return s.prepare(); }));
  EXPECT_EQ(s.fetches(), 2u);
  EXPECT_EQ(s.cached(fabric::EpClass::Fetch), 5u);
  EXPECT_EQ(s.cached(fabric::EpClass::Control), 2u);  // A03: only the low class (fetch) was asked for
  for (int i = 0; i < 5; ++i) take(fabric::EpClass::Fetch);
  EXPECT_EQ(seen.size(), 2u * 3 + 1 + 5);
  EXPECT_FALSE(s.draw(fabric::EpClass::Fetch));  // empty: NotFound, no network
  EXPECT_EQ(s.fetches(), 2u);

  auto text = metrics_text(mx);
  EXPECT_EQ(metric(text, "miracache_client_ticket_fetch_total{result=\"ok\"}"), 2);
  EXPECT_EQ(metric(text, "miracache_client_ticket_fetch_total{result=\"error\"}"), 0);
  EXPECT_EQ(metric(text, "miracache_client_ticket_cache{class=\"fetch\"}"), 0);
  EXPECT_EQ(metric(text, "miracache_client_ticket_cache{class=\"control\"}"), 2);

  // Expiry: older than ttl_s/2 (150 s) is dropped on draw and counted as missing for the refill.
  clk.advance_by(seconds(149));
  EXPECT_TRUE(s.draw(fabric::EpClass::Control));
  clk.advance_by(seconds(2));
  EXPECT_FALSE(s.draw(fabric::EpClass::Control));
  ASSERT_TRUE(n.run([&] { return s.prepare(); }));
  EXPECT_EQ(s.fetches(), 3u);
  EXPECT_TRUE(s.draw(fabric::EpClass::Control));
  // The server really accepts what we hold: each id is single-use at HELLO; covered by the server tests.
}

// RL2 follow-up A: a node with two rails (nodes[].admin, the normal multi-node path). The source keeps tickets per rail
// (one request per rail, "rail": r) and a WirePort draws each rail's own, so both rails come up: the node admits a
// ticket only on its own rail (reject 2), so rail-0 tickets on rail 1 would leave that rail down forever.
TEST(AdminTickets, PerRailTicketsBringUpEveryRail) {
  Node n(2);
  SimClock clk;
  auto o = n.opts();
  o.batch = 4;
  o.rails = {0, 1};
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src) << src.error().context;
  std::shared_ptr<AdminTicketSource> s = *src;
  ASSERT_TRUE(n.run([&] { return s->prepare(); }));
  EXPECT_EQ(s->fetches(), 2u) << "one request per rail";
  for (std::uint8_t r = 0; r < 2; ++r)
    for (auto c : {fabric::EpClass::Control, fabric::EpClass::Fetch, fabric::EpClass::Ingest}) EXPECT_EQ(s->cached(c, r), 4u);
  EXPECT_FALSE(s->draw(fabric::EpClass::Fetch, 2)) << "a rail it was not asked for has no tickets";

  CounterSalts salts;
  WireOptions wo;
  wo.node = n.server->node_id();
  wo.rail_tickets = s->rail_ticket_fn();
  wo.drive = [&] { n.drive(); };
  wo.label = "n1";
  WireOptions::RailOpt r0, r1;
  r0.index = 0, r0.addr = {"10.0.0.1", 7471}, r0.route = 1;
  r1.index = 1, r1.addr = {"10.0.1.1", 7471}, r1.route = 1;
  wo.rails = {r0, r1};
  WirePort port(n.cli, n.clock, salts, std::move(wo));
  auto info = port.hello();
  ASSERT_TRUE(info) << info.error().context;
  EXPECT_EQ(port.rail_state(0), WirePort::RailState::Up);
  EXPECT_EQ(port.rail_state(1), WirePort::RailState::Up) << "rail 1 was admitted with its own tickets";
  EXPECT_EQ(s->cached(fabric::EpClass::Fetch, 1), 3u);
  EXPECT_EQ(s->cached(fabric::EpClass::Control, 0), 3u);
  // A response whose tickets name another rail than the request is refused.
  const std::string t1 = "{\"class\":\"fetch\",\"rail\":1,\"id\":\"" + std::string(32, 'a') + "\"}";
  EXPECT_FALSE(AdminTicketSource::parse_response("{\"ttl_s\":300,\"tickets\":[" + t1 + "]}", 4, 0));
  EXPECT_TRUE(AdminTicketSource::parse_response("{\"ttl_s\":300,\"tickets\":[" + t1 + "]}", 4, 1));
  port.release_endpoints();
}

// G01: one build draws fetch_qps fetch tickets per rail. With the default ticket_batch (4) a node of fetch_qps 8 (the
// shipped irdma-e810-iwarp profile) or 16 (the bundle maximum) used to find at most 4 in the cache and never connect.
// The port tells the source its need (ticket_need, from its own fetch_qps) before prepare: the fetch class then asks
// for and keeps fetch_qps tickets per rail, control and ingest keep the batch. Admin path, 2 rails.
TEST(AdminTickets, FetchQpsAboveTheBatchConnectsEveryRail) {
  for (const unsigned qps : {8u, 16u}) {
    SCOPED_TRACE("fetch_qps " + std::to_string(qps));
    Node n(2);
    SimClock clk;
    auto o = n.opts();
    o.rails = {0, 1};  // batch: the default (4); fetch_need: the default (1), the port sets it
    auto src = AdminTicketSource::create(o, clk);
    ASSERT_TRUE(src) << src.error().context;
    std::shared_ptr<AdminTicketSource> s = *src;

    CounterSalts salts;
    WireOptions wo;
    wo.node = n.server->node_id();
    wo.rail_tickets = s->rail_ticket_fn();
    wo.prepare = [s] { (void)s->prepare(); };
    wo.ticket_need = [s](std::uint32_t k) { s->set_fetch_need(k); };
    wo.drive = [&] { n.drive(); };
    wo.label = "n1";
    wo.fetch_qps = qps;
    WireOptions::RailOpt r0, r1;
    r0.index = 0, r0.addr = {"10.0.0.1", 7471}, r0.route = 1;
    r1.index = 1, r1.addr = {"10.0.1.1", 7471}, r1.route = 1;
    wo.rails = {r0, r1};
    WirePort port(n.cli, n.clock, salts, std::move(wo));
    ASSERT_TRUE(n.run([&] {
      port.prepare_tickets();  // what the Client does before every build (WireOptions::prepare)
      return true;
    }));
    for (std::uint8_t r = 0; r < 2; ++r) {
      EXPECT_EQ(s->cached(fabric::EpClass::Fetch, r), qps) << "rail " << int(r) << ": one build's fetch tickets";
      EXPECT_EQ(s->cached(fabric::EpClass::Control, r), 4u);
      EXPECT_EQ(s->cached(fabric::EpClass::Ingest, r), 4u);
    }
    EXPECT_EQ(s->fetches(), 4u) << "per rail: one request for fetch (its size), one for control + ingest (the batch)";
    auto info = port.hello();
    ASSERT_TRUE(info) << info.error().context;
    EXPECT_EQ(port.rail_state(0), WirePort::RailState::Up);
    EXPECT_EQ(port.rail_state(1), WirePort::RailState::Up);
    for (std::uint8_t r = 0; r < 2; ++r) EXPECT_EQ(s->cached(fabric::EpClass::Fetch, r), 0u) << "rail " << int(r);
    // The next refill (a keepalive tick) brings the fetch class back to one build's worth: a rail rejoin or a
    // reconnect draws fetch_qps again.
    ASSERT_TRUE(n.run([&] {
      port.prepare_tickets();
      return true;
    }));
    for (std::uint8_t r = 0; r < 2; ++r) EXPECT_EQ(s->cached(fabric::EpClass::Fetch, r), qps) << "rail " << int(r);
    port.release_endpoints();
  }
}

// G01 (minor case): for 2 < fetch_qps <= batch a cache left between 2 and fetch_qps - 1 refills (the mark is the need).
TEST(AdminTickets, FetchClassRefillsBelowItsNeed) {
  Node n;
  SimClock clk;
  auto o = n.opts();
  o.batch = 4;
  o.fetch_need = 3;
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto& s = **src;
  ASSERT_TRUE(n.run([&] { return s.prepare(); }));
  EXPECT_EQ(s.cached(fabric::EpClass::Fetch), 4u);
  ASSERT_TRUE(s.draw(fabric::EpClass::Fetch));
  ASSERT_TRUE(s.draw(fabric::EpClass::Fetch));  // 2 left: below the need of 3
  ASSERT_TRUE(n.run([&] { return s.prepare(); }));
  EXPECT_EQ(s.cached(fabric::EpClass::Fetch), 6u);
  EXPECT_EQ(s.cached(fabric::EpClass::Control), 4u) << "control was not low: not asked for";
  EXPECT_EQ(s.fetches(), 2u);
}

// r7 R03: deterministic. Each block gets a fresh admin endpoint (reset() joins the previous one's
// connection threads, so no stale per-IP count), the client a generous io budget and the server a test
// handshake budget (a sanitizer build can need more than 300 ms per handshake). No connection may be
// refused at accept: a per_ip reject here would be the flake, not the behaviour under test.
TEST(AdminTickets, BadServerCertAndWrongIdentityAreRefused) {
  Node n;
  RealClock clk;
  auto fresh = [&](const std::string& who = "client-1") {
    n.admin.reset();
    n.start_admin(5000);
    auto o = n.opts(who);
    o.io_timeout_ms = 10000;
    return o;
  };
  {  // server cert signed by a CA we do not trust
    auto o = fresh();
    o.ca = certs().rogue + "/ca.pem";
    auto src = AdminTicketSource::create(o, clk);
    ASSERT_TRUE(src);
    ClientMetrics mx;
    (*src)->bind_metrics(&mx);
    auto st = n.run([&] { return (*src)->prepare(); });
    ASSERT_FALSE(st);
    EXPECT_EQ(st.error().code, ErrorCode::AccessDenied);
    EXPECT_EQ((*src)->cached(fabric::EpClass::Fetch), 0u);
    EXPECT_EQ(metric(metrics_text(mx), "miracache_client_ticket_fetch_total{result=\"error\"}"), 1);
  }
  {  // trusted chain, but not the node we expect
    auto o = fresh();
    o.server_identity = "spiffe://lab/node-9";
    auto src = AdminTicketSource::create(o, clk);
    ASSERT_TRUE(src);
    auto st = n.run([&] { return (*src)->prepare(); });
    ASSERT_FALSE(st);
    EXPECT_EQ(st.error().code, ErrorCode::AccessDenied);
  }
  {  // the right identity works
    auto o = fresh();
    o.server_identity = "spiffe://lab/node-1";
    auto src = AdminTicketSource::create(o, clk);
    ASSERT_TRUE(src);
    auto st = n.run([&] { return (*src)->prepare(); });
    EXPECT_TRUE(st) << (st ? "" : st.error().context);
    EXPECT_EQ((*src)->cached(fabric::EpClass::Ingest), 4u);
  }
  {  // an identity that is not in the principal table: 403 -> AccessDenied
    auto o = fresh("client-2");
    auto src = AdminTicketSource::create(o, clk);
    ASSERT_TRUE(src);
    auto st = n.run([&] { return (*src)->prepare(); });
    ASSERT_FALSE(st);
    EXPECT_EQ(st.error().code, ErrorCode::AccessDenied);
  }
  std::string t;
  n.server->metrics().write_prometheus(t);
  // -1 = the series was never created, i.e. no per_ip reject at all.
  EXPECT_LE(metric(t, "miracache_admin_conn_rejected_total{reason=\"per_ip\"}"), 0) << "a connection was refused per_ip";
}

// r7 R01: a draining node answers IssueTicket with 503 (no ticket it would refuse at connect anyway); the
// client reads it as Busy and backs off; reset_backoff() (called on session Down) lets the very next
// prepare() fetch again instead of waiting out the backoff.
TEST(AdminTickets, DrainingNodeAnswers503AndBackoffResetsOnDown) {
  Node n;
  SimClock clk;  // the source's clock stands still: only reset_backoff() can end the backoff
  auto o = n.opts();
  o.io_timeout_ms = 10000;
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto& s = **src;
  n.server->begin_drain(proto::GoawayReason::Shutdown, 60000);
  auto st = n.run([&] { return s.prepare(); });
  ASSERT_FALSE(st);
  EXPECT_EQ(st.error().code, ErrorCode::Busy) << st.error().context;
  EXPECT_EQ(s.fetches(), 1u);
  EXPECT_FALSE(n.run([&] { return s.prepare(); }));  // backing off: no network
  EXPECT_EQ(s.fetches(), 1u);
  // r8 N03: a 503 does not grow the backoff: every retry is backoff_min_ms (1 s, no jitter here) later.
  for (unsigned k = 2; k <= 4; ++k) {
    clk.advance_by(milliseconds(999));
    EXPECT_FALSE(n.run([&] { return s.prepare(); }));
    EXPECT_EQ(s.fetches(), k - 1) << "still backing off";
    clk.advance_by(milliseconds(1));
    EXPECT_FALSE(n.run([&] { return s.prepare(); }));  // the node is still draining
    EXPECT_EQ(s.fetches(), k) << "a 503 streak must not double the wait";
  }
}

// r8 N08: reset_backoff() (session Down) cuts a grown backoff to backoff_min_ms from now, not to zero, so
// a still-failing admin is never retried in a tight loop.
TEST(AdminTickets, ResetBackoffKeepsAFloor) {
  SimClock clk;
  AdminTicketOptions o;
  const auto& c = certs();
  o.admin = "127.0.0.1:1";  // nothing listens: connection refused at once
  o.cert = c.pki + "/client-1.pem";
  o.key = c.pki + "/client-1.key";
  o.ca = c.pki + "/ca.pem";
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto& s = **src;
  for (unsigned ms : {1000u, 2000u}) {  // two failures: the next wait is 4 s
    EXPECT_FALSE(s.prepare());
    clk.advance_by(milliseconds(ms));
  }
  EXPECT_FALSE(s.prepare());
  EXPECT_EQ(s.fetches(), 3u);
  s.reset_backoff();
  EXPECT_FALSE(s.prepare());
  EXPECT_EQ(s.fetches(), 3u) << "the floor: no fetch right after the reset";
  clk.advance_by(milliseconds(1000));
  EXPECT_FALSE(s.prepare());
  EXPECT_EQ(s.fetches(), 4u) << "backoff_min_ms after the reset, not the 4 s the streak had grown to";
}

// R19 (review s11): ready_at() is the end of the fetch backoff while the cache cannot serve a build (0 otherwise), so
// the open's settle waits for it. R14: prepare(budget) starts no admin call once the budget is spent.
TEST(AdminTickets, ReadyAtIsTheBackoffEndAndASpentBudgetStartsNoFetch) {
  SimClock clk;
  AdminTicketOptions o;
  const auto& c = certs();
  o.admin = "127.0.0.1:1";  // nothing listens: connection refused at once
  o.cert = c.pki + "/client-1.pem";
  o.key = c.pki + "/client-1.key";
  o.ca = c.pki + "/ca.pem";
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto& s = **src;
  EXPECT_EQ(s.ready_at(), Nanos{0}) << "no fetch yet: nothing to wait for";
  const Nanos t0 = clk.now();
  EXPECT_FALSE(s.prepare());
  EXPECT_EQ(s.fetches(), 1u);
  EXPECT_EQ(s.ready_at(), t0 + milliseconds(1000)) << "backoff_min_ms, no jitter here";
  clk.advance_by(milliseconds(1000));
  EXPECT_EQ(s.ready_at(), Nanos{0}) << "the backoff is over: the next prepare fetches";
  auto st = s.prepare(Nanos{0});
  ASSERT_FALSE(st);
  EXPECT_EQ(st.error().code, ErrorCode::Timeout) << st.error().context;
  EXPECT_EQ(s.fetches(), 1u) << "a spent budget starts no admin call";
  EXPECT_FALSE(s.prepare(milliseconds(500)));
  EXPECT_EQ(s.fetches(), 2u) << "a budget left: the call runs (refused at once here)";
}

// r8b Q02: away_backoff_max_ms (reconnect_max_ms in wire_open) caps the wait only while the node is away
// (here LinkDown: nothing listens); a 403 keeps growing to backoff_max_ms.
TEST(AdminTickets, AwayCapAppliesToLinkDownOnly) {
  const auto& c = certs();
  auto three_failures = [](AdminTicketSource& s, SimClock& clk, const std::function<Status()>& prep) {
    for (unsigned ms : {1000u, 2000u}) {  // failures at 0 s and 1 s; the next wait is 4 s uncapped
      EXPECT_FALSE(prep());
      clk.advance_by(milliseconds(ms));
    }
    EXPECT_FALSE(prep());
    EXPECT_EQ(s.fetches(), 3u);
    clk.advance_by(milliseconds(2000));
    return prep();
  };
  {  // node away: the 3rd wait is capped at 2 s
    SimClock clk;
    AdminTicketOptions o;
    o.admin = "127.0.0.1:1";
    o.cert = c.pki + "/client-1.pem";
    o.key = c.pki + "/client-1.key";
    o.ca = c.pki + "/ca.pem";
    o.away_backoff_max_ms = 2000;
    auto src = AdminTicketSource::create(o, clk);
    ASSERT_TRUE(src);
    auto& s = **src;
    auto st = three_failures(s, clk, [&] { return s.prepare(); });
    ASSERT_FALSE(st);
    EXPECT_TRUE(st.error().code == ErrorCode::LinkDown || st.error().code == ErrorCode::Timeout) << st.error().context;
    EXPECT_EQ(s.fetches(), 4u) << "a node that is away is retried at most away_backoff_max_ms later";
  }
  {  // 403 (identity not in the principal table): the 3rd wait is the full 4 s
    Node n;
    SimClock clk;
    auto o = n.opts("client-2");
    o.away_backoff_max_ms = 2000;
    auto src = AdminTicketSource::create(o, clk);
    ASSERT_TRUE(src);
    auto& s = **src;
    auto st = three_failures(s, clk, [&] { return n.run([&] { return s.prepare(); }); });
    ASSERT_FALSE(st);
    EXPECT_EQ(st.error().code, ErrorCode::AccessDenied) << st.error().context;
    EXPECT_EQ(s.fetches(), 3u) << "a 403 must not be retried at the away cap";
    clk.advance_by(milliseconds(2000));
    EXPECT_FALSE(n.run([&] { return s.prepare(); }));
    EXPECT_EQ(s.fetches(), 4u);
  }
}

// r8 N07: the product side of r7 R03 (reap after accept): three calls in a row on ONE admin endpoint,
// each from a fresh source, are all served; none is refused per_ip (2 per source address) by a finished
// connection thread that was not reaped yet.
TEST(AdminTickets, ThreeSequentialCallsOnOneAdminAreNotRefusedPerIp) {
  Node n;
  RealClock clk;
  for (int i = 0; i < 3; ++i) {
    SCOPED_TRACE(i);
    auto o = n.opts();
    o.io_timeout_ms = 10000;
    o.batch = 1;
    auto src = AdminTicketSource::create(o, clk);
    ASSERT_TRUE(src);
    auto st = n.run([&] { return (*src)->prepare(); });
    EXPECT_TRUE(st) << (st ? "" : st.error().context);
    EXPECT_EQ((*src)->cached(fabric::EpClass::Fetch), 1u);
  }
  std::string t;
  n.server->metrics().write_prometheus(t);
  EXPECT_LE(metric(t, "miracache_admin_conn_rejected_total{reason=\"per_ip\"}"), 0) << "a connection was refused per_ip";
}

TEST(AdminTickets, KeyFileModeIsAConfigError) {
  const auto& c = certs();
  char t[] = "/tmp/mira-cadm-key-XXXXXX";
  ASSERT_NE(::mkdtemp(t), nullptr);
  const std::string dir = t;
  ASSERT_EQ(std::system(("cp " + c.pki + "/client-1.key " + c.pki + "/client-1.pem " + c.pki + "/ca.pem " + dir).c_str()), 0);
  ASSERT_EQ(::chmod((dir + "/client-1.key").c_str(), 0640), 0);
  AdminTicketOptions o;
  o.admin = "127.0.0.1:9465";
  o.cert = dir + "/client-1.pem";
  o.key = dir + "/client-1.key";
  o.ca = dir + "/ca.pem";
  RealClock clk;
  auto bad = AdminTicketSource::create(o, clk);
  ASSERT_FALSE(bad);
  EXPECT_EQ(bad.error().code, ErrorCode::AccessDenied);

  // Same check when the client config is loaded from a file.
  ASSERT_EQ(std::system(("printf x > " + dir + "/secret && chmod 600 " + dir + "/secret").c_str()), 0);
  std::ofstream(dir + "/client.toml") << "[scope]\nsecret_file = \"" << dir << "/secret\"\n[[nodes]]\n"
      << "rails = [\"10.0.0.1:7100\"]\nadmin = \"10.0.0.1:9465\"\nidentity = \"spiffe://lab/node-1\"\n[tls]\ncert = \"" << o.cert << "\"\nkey = \"" << o.key
      << "\"\nca = \"" << o.ca << "\"\n[lab]\nstatic_membership = true\n";
  auto cfg = load_config(dir + "/client.toml");
  ASSERT_FALSE(cfg);
  EXPECT_EQ(cfg.error().code, ErrorCode::AccessDenied);
  ASSERT_EQ(::chmod((dir + "/client-1.key").c_str(), 0600), 0);
  cfg = load_config(dir + "/client.toml");
  ASSERT_TRUE(cfg) << cfg.error().context;
  EXPECT_EQ(cfg->nodes[0].admin, "10.0.0.1:9465");
  EXPECT_TRUE(AdminTicketSource::create(o, clk));
  ASSERT_EQ(std::system(("rm -rf " + dir).c_str()), 0);
}

TEST(AdminTicketsConfig, KeysAndRules) {
  const std::string base = "[scope]\nsecret_file = \"x\"\n[lab]\nstatic_membership = true\n";
  const std::string tls = "[tls]\ncert = \"c\"\nkey = \"k\"\nca = \"a\"\n";
  auto ok = load_config(base + tls + "[fabric]\nticket_batch = 8\n[[nodes]]\nrails = [\"h:1\"]\nadmin = \"h:9465\"\n"
                                     "identity = \"spiffe://lab/node-1\"\n");
  ASSERT_TRUE(ok) << ok.error().context;
  EXPECT_EQ(ok->ticket_batch, 8u);
  EXPECT_EQ(ok->nodes[0].identity, "spiffe://lab/node-1");
  EXPECT_EQ(ok->tls_ca, "a");
  auto dflt = load_config(base + "[[nodes]]\nrails = [\"h:1\"]\n");
  ASSERT_TRUE(dflt);
  EXPECT_EQ(dflt->ticket_batch, 4u);
  EXPECT_TRUE(dflt->nodes[0].admin.empty());
  const std::string node = "[[nodes]]\nrails = [\"h:1\"]\n";
  EXPECT_FALSE(load_config(base + node + "admin = \"h:9465\"\n"));                      // admin without [tls]
  EXPECT_FALSE(load_config(base + tls + node + "admin = \"nohostport\"\n"));
  EXPECT_FALSE(load_config(base + tls + node + "admin = \"h:9465\"\n"));  // A09: admin needs identity
  EXPECT_FALSE(load_config(base + tls + node + "identity = \"spiffe://lab/node-1\"\n"));  // identity without admin
  EXPECT_FALSE(load_config(base + tls + node + "admin = \"h:1\"\nidentity = \"node-1\"\n"));
  EXPECT_FALSE(load_config(base + tls + "[fabric]\nticket_batch = 0\n" + node));
  EXPECT_FALSE(load_config(base + tls + "[fabric]\nticket_batch = 65\n" + node));
  EXPECT_FALSE(load_config(base + "[tls]\nbogus = 1\n" + node));
}

TEST(AdminTickets, AdminDownFailsCleanlyAndExistingSessionKeepsWorking) {
  Node n;
  CounterSalts salts;
  RealClock real;
  auto o = n.opts();
  o.batch = 1;           // one ticket per class: the first session uses them all
  o.io_timeout_ms = 500;
  auto src = AdminTicketSource::create(o, real);
  ASSERT_TRUE(src);
  auto& s = **src;
  ClientMetrics mx;
  ASSERT_TRUE(n.run([&] { return s.prepare(); }));

  WireOptions wo;
  wo.node = 1;
  wo.tickets = [&s](fabric::EpClass c) { return s.draw(c); };
  wo.prepare = [&s] { (void)s.prepare(); };
  wo.drive = [&n] { n.drive(); };
  wo.keepalive_ms = 0;
  SeededRandom jit(99);
  wo.random = &jit;
  WirePort port(n.cli, n.clock, salts, wo);
  port.bind_metrics(&mx);
  s.bind_metrics(&mx);
  ASSERT_TRUE(port.hello());
  ASSERT_TRUE(port.session_up());
  EXPECT_EQ(s.cached(fabric::EpClass::Control), 0u);

  n.admin->stop();  // the admin endpoint goes away
  EXPECT_TRUE(port.stats(0)) << "an established session does not need the admin API";
  EXPECT_TRUE(port.session_up());

  port.endpoint(fabric::EpClass::Control)->abort();  // the session drops
  const Nanos t0 = n.clock.now();
  while (n.clock.now() - t0 < seconds(2)) {
    port.prepare_tickets();  // the Client's keepalive thread does this before every tick
    port.keepalive();
    n.drive();
  }
  EXPECT_FALSE(port.session_up());
  EXPECT_GE(port.connect_attempts(), 1u);
  const auto text = metrics_text(mx);
  EXPECT_GE(metric(text, "miracache_client_reconnect_fail_total"), 1);
  EXPECT_GE(metric(text, "miracache_client_ticket_fetch_total{result=\"error\"}"), 1);
  EXPECT_EQ(metric(text, "miracache_client_session_up"), 0);
}

TEST(AdminTickets, AdminUnreachableAtOpenReturnsAnError) {
  RealClock clk;
  const auto& c = certs();
  AdminTicketOptions o;
  o.admin = "127.0.0.1:1";  // nothing listens
  o.cert = c.pki + "/client-1.pem";
  o.key = c.pki + "/client-1.key";
  o.ca = c.pki + "/ca.pem";
  o.io_timeout_ms = 500;
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto st = (*src)->prepare();
  ASSERT_FALSE(st);
  EXPECT_TRUE(st.error().code == ErrorCode::LinkDown || st.error().code == ErrorCode::Timeout);
  EXPECT_FALSE((*src)->draw(fabric::EpClass::Control));
}

// ---- review r4 -------------------------------------------------------------------------------
// A01 (client): a peer that resets the connection must not kill the process with SIGPIPE. The
// library must not change signal dispositions, so SIGPIPE is deliberately left at its default.
TEST(AdminTickets, ResetPeerNeverRaisesSigpipe) {
  struct sigaction dfl{}, old{};
  dfl.sa_handler = SIG_DFL;
  ASSERT_EQ(::sigaction(SIGPIPE, &dfl, &old), 0);
  const int ls = ::socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_GE(ls, 0);
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ASSERT_EQ(::bind(ls, reinterpret_cast<sockaddr*>(&a), sizeof a), 0);
  ASSERT_EQ(::listen(ls, 4), 0);
  socklen_t al = sizeof a;
  ASSERT_EQ(::getsockname(ls, reinterpret_cast<sockaddr*>(&a), &al), 0);
  std::thread srv([ls] {  // accept, then reset (RST, not FIN) without a byte of TLS
    const int c = ::accept(ls, nullptr, nullptr);
    if (c < 0) return;
    linger lg{1, 0};
    ::setsockopt(c, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    ::close(c);
  });
  RealClock clk;
  const auto& c = certs();
  AdminTicketOptions o;
  o.admin = "127.0.0.1:" + std::to_string(ntohs(a.sin_port));
  o.cert = c.pki + "/client-1.pem";
  o.key = c.pki + "/client-1.key";
  o.ca = c.pki + "/ca.pem";
  o.io_timeout_ms = 1500;
  o.test_after_connect = [](int fd) {
    // Wait for the RST, then consume the pending ECONNRESET: the next write is a plain EPIPE.
    pollfd p{fd, POLLIN, 0};
    ASSERT_GT(::poll(&p, 1, 2000), 0);
    char b;
    (void)::recv(fd, &b, 1, MSG_DONTWAIT);
  };
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto st = (*src)->prepare();  // old code: the process dies of SIGPIPE here
  EXPECT_FALSE(st);
  srv.join();
  ::close(ls);
  struct sigaction cur{};
  ASSERT_EQ(::sigaction(SIGPIPE, nullptr, &cur), 0);
  EXPECT_EQ(cur.sa_handler, SIG_DFL) << "the library changed the SIGPIPE disposition";
  ::sigaction(SIGPIPE, &old, nullptr);
}

// A03: a failing admin (403) is retried on a growing, jittered schedule, not on every tick.
TEST(AdminTickets, FailedFetchesBackOff) {
  Node n;
  SimClock clk;
  auto o = n.opts("client-2");  // not in the principal table: 403 every time
  SeededRandom jit(7);
  o.random = &jit;
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto& s = **src;
  for (int i = 0; i < 100; ++i) {  // 10 s of keepalive ticks at 100 ms
    auto st = n.run([&] { return s.prepare(); });
    EXPECT_FALSE(st);
    clk.advance_by(milliseconds(100));
  }
  EXPECT_GE(s.fetches(), 3u);
  EXPECT_LE(s.fetches(), 5u) << "attempts over 10 s with a 1 s -> 30 s backoff";
  clk.advance_by(seconds(31));  // past any cap: the next tick tries again
  const auto before = s.fetches();
  (void)n.run([&] { return s.prepare(); });
  EXPECT_EQ(s.fetches(), before + 1);
}

// A03: only classes below the refill mark are requested, and no class is ever cached past 2 x batch.
TEST(AdminTickets, RefillAsksOnlyLowClassesAndNeverExceedsTheCap) {
  Node n;
  SimClock clk;
  auto o = n.opts();
  o.batch = 4;
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto& s = **src;
  ASSERT_TRUE(n.run([&] { return s.prepare(); }));
  const fabric::EpClass all[] = {fabric::EpClass::Control, fabric::EpClass::Fetch, fabric::EpClass::Ingest};
  for (int round = 0; round < 6; ++round) {
    while (s.cached(fabric::EpClass::Fetch) > 1) ASSERT_TRUE(s.draw(fabric::EpClass::Fetch));  // only fetch drains
    ASSERT_TRUE(n.run([&] { return s.prepare(); }));
    EXPECT_EQ(s.cached(fabric::EpClass::Control), 4u) << "control was not low: it must not be asked for";
    EXPECT_EQ(s.cached(fabric::EpClass::Ingest), 4u);
    for (auto c : all) EXPECT_LE(s.cached(c), 8u);
  }
  EXPECT_EQ(s.fetches(), 7u);  // the first batch + one refill per round
}

// A09 (client): a server cert with two spiffe:// URI SANs is refused even when one matches.
TEST(AdminTickets, ServerCertWithTwoSpiffeSansIsRefused) {
  Node n;
  const auto& c = certs();
  const std::string d = c.root + "/dual";
  ASSERT_EQ(std::system(("mkdir -p " + d + " && cd " + d +
                         " && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out dual.key 2>/dev/null"
                         " && chmod 600 dual.key && openssl req -new -key dual.key -subj /CN=dual -out dual.csr"
                         " && printf 'basicConstraints=CA:FALSE\\nkeyUsage=critical,digitalSignature\\nextendedKeyUsage=serverAuth,clientAuth\\n"
                         "subjectAltName=URI:spiffe://lab/node-1,URI:spiffe://lab/impostor,IP:127.0.0.1\\n' > dual.ext"
                         " && openssl x509 -req -in dual.csr -CA " + c.pki + "/ca.pem -CAkey " + c.pki + "/ca.key -CAcreateserial"
                         " -sha256 -days 2 -extfile dual.ext -out dual.pem 2>/dev/null")
                            .c_str()),
            0);
  auto a = server::AdminHttps::start(server::AdminOptions{"127.0.0.1:0", d + "/dual.pem", d + "/dual.key", c.pki + "/ca.pem", 300},
                                     n.server->metrics());
  ASSERT_TRUE(a && *a);
  RealClock clk;
  auto o = n.opts();
  o.admin = "127.0.0.1:" + std::to_string((*a)->port());
  o.server_identity = "spiffe://lab/node-1";
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  auto st = (*src)->prepare();
  ASSERT_FALSE(st);
  EXPECT_EQ(st.error().code, ErrorCode::AccessDenied);
  EXPECT_NE(std::string(st.error().context).find("exactly one"), std::string::npos) << st.error().context;
  // R18: the build sees the admin failure's text with a fixed transport-class code, never the admin's own code (the
  // build path keys node-ID conflicts on InvalidArgument and shutdowns on Aborted).
  auto t = (*src)->draw(fabric::EpClass::Control);
  ASSERT_FALSE(t);
  EXPECT_EQ(t.error().code, ErrorCode::LinkDown);
  EXPECT_STREQ(t.error().context, st.error().context);
}

// A03: name resolution is bounded by the call's budget (a hung resolver cannot stall the keepalive thread).
TEST(AdminTickets, UnresolvableNameReturnsWithinTheBudget) {
  RealClock clk;
  const auto& c = certs();
  AdminTicketOptions o;
  o.admin = "no-such-host.invalid:9465";
  o.cert = c.pki + "/client-1.pem";
  o.key = c.pki + "/client-1.key";
  o.ca = c.pki + "/ca.pem";
  o.io_timeout_ms = 300;
  auto src = AdminTicketSource::create(o, clk);
  ASSERT_TRUE(src);
  const auto t0 = std::chrono::steady_clock::now();
  EXPECT_FALSE((*src)->prepare());
  EXPECT_LT(std::chrono::steady_clock::now() - t0, milliseconds(1000));
}

// Minor: the fetch counters stay exact when the registry is bound while a fetch is finishing.
TEST(AdminTickets, BindMetricsDuringAFetchCountsOnce) {
  Node n;
  RealClock clk;
  for (int i = 0; i < 12; ++i) {
    auto src = AdminTicketSource::create(n.opts(), clk);
    ASSERT_TRUE(src);
    ClientMetrics mx;
    std::thread binder([&] { (*src)->bind_metrics(&mx); });
    ASSERT_TRUE(n.run([&] { return (*src)->prepare(); }));
    binder.join();
    EXPECT_EQ(metric(metrics_text(mx), "miracache_client_ticket_fetch_total{result=\"ok\"}"), 1) << i;
  }
}

}  // namespace
}  // namespace miracache
