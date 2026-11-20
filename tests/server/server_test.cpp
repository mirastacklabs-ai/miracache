// SPDX-License-Identifier: Apache-2.0
// A1.4 S7: tickets, frame dispatch and the segment table, end to end through wire frames
// over SimFabric (put -> lookup -> READ -> invalidate -> miss), plus the ordering rule that
// PUT_COMMIT is accepted only on the endpoint that did the PUT_BEGIN.
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <cstdlib>
#include <deque>
#include <filesystem>
#include <future>
#include <fstream>
#include <functional>
#include <memory>
#include <regex>
#include <thread>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <gtest/gtest.h>

#include "fabric/sim/sim_fabric.h"
#include "server/lab_tickets.h"
#include "server/node_config.h"
#include "server/runtime/admin_https.h"
#include "server/runtime/metrics_http.h"
#include "server/runtime/net_util.h"
#include "server/runtime/store_executor.h"
#include "server/server.h"
#include "util/crc32c.h"
#include "util/log.h"

namespace miracache::server {
namespace {

using namespace std::chrono_literals;
using proto::Op;

store::StoreConfig store_cfg(std::uint32_t n_segments = 2) {
  store::StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = n_segments;
  c.gen_chunk = 1000;
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 1u << 20;
  c.principal_default.idle_ttl = std::chrono::seconds(1000);
  c.invalidate_per_s = 0;
  return c;
}

// ---- tickets -------------------------------------------------------------------------
struct TicketFx {
  SimClock clock;
  SeededRandom rng{7};
  TicketTable t{clock, rng, 300s};
  TicketFx() { t.principals().add("lab", 11); }
  static std::array<std::byte, 20> bytes(const proto::Ticket& tk) {
    std::array<std::byte, 20> b{};
    EXPECT_TRUE(proto::encode_ticket(tk, b));
    return b;
  }
};

TEST(Tickets, SingleUse) {
  TicketFx f;
  auto tk = f.t.issue("lab", fabric::EpClass::Ingest, 1, 3);
  ASSERT_TRUE(tk);
  ASSERT_EQ(tk->size(), 3u);
  EXPECT_EQ(f.t.live(), 3u);
  auto b = TicketFx::bytes((*tk)[0]);
  auto g = f.t.redeem(b);
  ASSERT_TRUE(g);
  EXPECT_EQ(g->principal, 11u);
  EXPECT_EQ(g->cls, fabric::EpClass::Ingest);
  EXPECT_EQ(g->rail, 1);
  auto again = f.t.redeem(b);
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error().code, ErrorCode::AccessDenied);
  EXPECT_EQ(f.t.live(), 2u);
  EXPECT_TRUE(f.t.redeem(TicketFx::bytes((*tk)[1])));  // the others still work
}

TEST(Tickets, Expiry) {
  TicketFx f;
  auto tk = f.t.issue("lab", fabric::EpClass::Control, 0, 2);
  ASSERT_TRUE(tk);
  f.clock.advance_by(299s);
  EXPECT_TRUE(f.t.redeem(TicketFx::bytes((*tk)[0])));
  f.clock.advance_by(2s);
  auto late = f.t.redeem(TicketFx::bytes((*tk)[1]));
  ASSERT_FALSE(late);
  EXPECT_EQ(late.error().code, ErrorCode::Timeout);
  EXPECT_EQ(f.t.live(), 0u);  // consumed even though refused
}

TEST(Tickets, UnknownIdentityRejected) {
  TicketFx f;
  auto r = f.t.issue("stranger", fabric::EpClass::Control, 0, 1);
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, ErrorCode::AccessDenied);
  EXPECT_EQ(f.t.live(), 0u);
  EXPECT_FALSE(f.t.issue("lab", fabric::EpClass::Control, 4, 1));  // rail out of range
  EXPECT_FALSE(f.t.issue("lab", fabric::EpClass::Control, 0, 0));
}

TEST(Tickets, ForgedAndMalformedRefused) {
  TicketFx f;
  auto tk = f.t.issue("lab", fabric::EpClass::Control, 0, 1);
  ASSERT_TRUE(tk);
  proto::Ticket forged = (*tk)[0];
  forged.id[0] ^= 1;
  EXPECT_FALSE(f.t.redeem(TicketFx::bytes(forged)));
  proto::Ticket wrong_cls = (*tk)[0];
  wrong_cls.cls = 2;
  EXPECT_FALSE(f.t.redeem(TicketFx::bytes(wrong_cls)));
  std::array<std::byte, 7> junk{};
  EXPECT_FALSE(f.t.redeem(junk));
}

// ---- node config -----------------------------------------------------------------------
TEST(NodeConfig, RetentionEvictAndPutQuotaKnobs) {  // U2-15 + HR1: QT1/QT2 knobs under retention.*, evict.*, quota.* (live)
  auto ok = parse_node_config(R"(
[store]
backing = "anon"
[retention]
max_ttl_s = 3600
[evict]
sweep_bytes_per_s = 1048576
sweep_blocks_per_turn = 32
high_pct = 90
low_pct = 80
[quota]
put_ops_per_s = 500
put_bytes_per_s = 1000000
)");
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->server.store.max_ttl, std::chrono::seconds(3600));
  EXPECT_EQ(ok->server.store.sweep_bytes_per_s, 1048576u);
  EXPECT_EQ(ok->server.store.sweep_blocks_per_turn, 32u);
  EXPECT_EQ(ok->server.store.high_pct, 90u);
  EXPECT_EQ(ok->server.store.low_pct, 80u);
  EXPECT_EQ(ok->server.store.principal_default.put_ops_per_s, 500u);
  EXPECT_EQ(ok->server.store.principal_default.put_bytes_per_s, 1000000u);
  auto def = parse_node_config("[store]\nbacking = \"anon\"\n");
  ASSERT_TRUE(def);
  EXPECT_EQ(def->server.store.max_ttl, std::chrono::seconds(0));  // off
  EXPECT_FALSE(parse_node_config("[retention]\nmax_ttl_s = -1\n[store]\nbacking = \"anon\"\n"));
  auto stale = parse_node_config("[store]\nbacking = \"anon\"\nmax_ttl_s = 5\n");  // the pre-HR1 flat name: never released
  ASSERT_FALSE(stale);
  EXPECT_NE(std::string(stale.error().context).find("retention.max_ttl_s"), std::string::npos);
}

TEST(NodeConfig, ParsesAndRejects) {
  auto ok = parse_node_config(R"(
[node]
protocol = "iwarp"
listen = ["10.0.0.5:7100"]
[store]
backing = "anon"
segment_bytes = 4194304
run_bytes = 262144
min_block_bytes = 4096
n_segments = 2
[lab]
principal = "lab-1"
ticket_file = "/tmp/t"
)");
  ASSERT_TRUE(ok) << ok.error().context;
  EXPECT_EQ(ok->server.store.node_id, 0u);  // assigned at store open (plan 2C)
  EXPECT_EQ(ok->server.store.state_dir, "/var/lib/miracache");  // review r9 S04: the default state directory
  auto sd = parse_node_config("[node]\nstate_dir = \"/srv/mira\"\n[store]\nbacking = \"anon\"\n");
  ASSERT_TRUE(sd) << sd.error().context;
  EXPECT_EQ(sd->server.store.state_dir, "/srv/mira");
  EXPECT_FALSE(parse_node_config("[node]\nstate_dir = \"\"\n[store]\nbacking = \"anon\"\n"));  // a path, never empty
  EXPECT_FALSE(parse_node_config("[node]\nstate_dir = 5\n[store]\nbacking = \"anon\"\n"));  // not an ID either
  {  // A3.3 [nic]: explicit operating-point keys beat the profile; unknown keys and bad values are errors
    auto nic = parse_node_config("[store]\nbacking = \"anon\"\n[nic]\nprofiles_file = \"/x.toml\"\nmtu = 1024\ninline_bytes = 64\n"
                                 "ack_timeout_exp = 14\nretry_count = 3\nrnr_retry_count = 5\n");
    ASSERT_TRUE(nic) << nic.error().context;
    EXPECT_EQ(nic->profiles_file, "/x.toml");
    EXPECT_EQ(*nic->nic.mtu, 1024u);
    EXPECT_EQ(*nic->nic.ack_timeout_exp, 14);
    auto none = parse_node_config("[store]\nbacking = \"anon\"\n");
    ASSERT_TRUE(none);
    EXPECT_FALSE(none->nic.mtu.has_value());
    EXPECT_TRUE(none->profiles_file.empty());
    for (const char* bad : {"bogus = 1\n", "mtu = 1500\n", "ack_timeout_exp = 20\n", "retry_count = 8\n", "rnr_retry_count = 7\n",
                            "inline_bytes = 300\n", "profiles_file = \"\"\n", "mtu = \"1024\"\n"})
      EXPECT_FALSE(parse_node_config(std::string("[store]\nbacking = \"anon\"\n[nic]\n") + bad)) << bad;
  }
  EXPECT_EQ(ok->server.wire_protocol, 2);
  ASSERT_EQ(ok->server.rails.size(), 1u);
  EXPECT_EQ(ok->server.rails[0].port, 7100);
  EXPECT_EQ(ok->server.lab_principal, control::principal_id("lab"));  // computed, never typed (goal 10)
  EXPECT_FALSE(parse_node_config("[store]\nbacking = \"anon\"\n[lab]\nprincipal = \"x\"\nprincipal_id = 9\n"));  // stale key
  EXPECT_FALSE(parse_node_config("[node]\nbogus = 1\n"));
  EXPECT_FALSE(parse_node_config("[nope]\n"));
  EXPECT_FALSE(parse_node_config("[lab]\nticket_file = \"x\"\n"));          // needs a principal
  EXPECT_FALSE(parse_node_config("[store]\nbacking = \"anon\"\nsegment_bytes = 3\n"));  // not pow2
  EXPECT_FALSE(parse_node_config("[store]\nbacking = \"file\"\n"));         // dir required
}

// ---- server over SimFabric ------------------------------------------------------------------
struct Reply {
  proto::FrameHeader h;
  std::vector<std::byte> body;
  bool error() const { return (h.flags & proto::flag::ERROR) != 0; }
  proto::WireStatus err_status() const {
    auto e = proto::decode_error_reply(h, body);
    return e ? static_cast<proto::WireStatus>(e->status) : proto::WireStatus::Corrupt;
  }
};

struct Fx {
  explicit Fx(std::uint32_t n_segments = 2, Executor* ex = nullptr, StoreExecutor* real = nullptr,
              const std::function<void(ServerConfig&)>& tweak = {},
              std::size_t cli_cq = fabric::SimNetwork::kDefaultCqCapacity,
              const std::function<std::unique_ptr<fabric::Fabric>(fabric::SimFabric&, SimClock&)>& wrap = {})
      : rng(3), net(clock, rng, {}, {}), srv_fab(net.add_node(1)), cli(net.add_node(2, cli_cq)), real_exec(real) {
    ServerConfig sc;
    sc.store = store_cfg(n_segments);
    sc.lab_identity = "lab";
    sc.lab_principal = 5;
    if (tweak) tweak(sc);
    if (wrap) wrapped = wrap(srv_fab, clock);  // r8b Q01: the server sees a decorated fabric
    fabric::Fabric& fab = wrapped ? *wrapped : static_cast<fabric::Fabric&>(srv_fab);
    auto s = Server::create(sc, fab, clock, rng, ex ? *ex : inline_exec);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
    EXPECT_TRUE(server->tickets().principals().find("lab"));
    EXPECT_TRUE(server->start());
    cbuf.assign(1 << 16, std::byte{0});
    cmr = cli.reg(cbuf, fabric::Access::LocalWrite).value();
  }

  void pump() {
    for (int quiet = 0; quiet < 3;) {
      net.run_until_idle();
      std::size_t w = server->run_once();
      if (real_exec) {
        w += real_exec->drain_done();
        if (real_exec->outstanding() != 0) w += 1;  // still working: keep pumping
      }
      quiet = w ? 0 : quiet + 1;
    }
    net.run_until_idle();
    collect();
  }
  void collect() {
    std::array<fabric::Completion, 32> out;
    for (;;) {
      std::size_t n = cli.poll(out);
      if (!n) break;
      for (std::size_t i = 0; i < n; ++i) {
        auto& c = out[i];
        if (c.is_recv) {
          auto fr = proto::decode_frame(c.frame.bytes);
          EXPECT_TRUE(fr);
          if (!fr) continue;
          Reply rp{fr->h, std::vector<std::byte>(fr->body.begin(), fr->body.end())};
          (fr->h.type == static_cast<std::uint16_t>(Op::SEG_TABLE) ? segtabs : inbox)[c.endpoint].push_back(std::move(rp));
        } else if (c.op == fabric::CompletionOp::Write || c.op == fabric::CompletionOp::Read) {
          tags[c.tag] = c.status;
        }
      }
    }
  }

  // Connects an endpoint of `cls` with a fresh ticket for `identity`.
  Expected<fabric::Endpoint*> connect(fabric::EpClass cls, const std::string& identity = "lab") {
    auto tk = server->issue_ticket(identity, cls, 0, 1);
    if (!tk) return tk.error();
    return connect_with((*tk)[0], cls);
  }
  Expected<fabric::Endpoint*> connect_with(const proto::Ticket& tk, fabric::EpClass cls, fabric::RailAddr addr = {}) {
    fabric::ConnParams cp;
    cp.cls = cls;
    std::span<std::byte> out(cp.ticket.data(), 20);
    EXPECT_TRUE(proto::encode_ticket(tk, out));
    cp.ticket_len = 20;
    return cli.connect(fabric::Peer{1, std::move(addr)}, cp);
  }

  template <typename Msg, typename Enc>
  void send(fabric::Endpoint* ep, Op op, std::uint64_t rid, const Msg& m, Enc enc) {
    std::array<std::byte, 8192> body{}, frame{};
    auto bn = enc(m, std::span<std::byte>(body));
    ASSERT_TRUE(bn);
    auto fn = proto::encode_frame(proto::header_for(op, rid), std::span<const std::byte>(body.data(), *bn), frame);
    ASSERT_TRUE(fn);
    fabric::Frame f;
    f.bytes.assign(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(*fn));
    ASSERT_TRUE(ep->post_send(std::move(f), 0));
  }
  // Waits for the next reply on the SERVER-side id of this client endpoint (peer id is
  // the endpoint the frame arrived at: our own id).
  Reply next(fabric::Endpoint* ep) {
    pump();
    auto& q = inbox[ep->id()];
    EXPECT_FALSE(q.empty());
    if (q.empty()) return {};
    Reply r = std::move(q.front());
    q.pop_front();
    return r;
  }
  Reply next_of(fabric::Endpoint* ep, Op op) {
    for (;;) {
      Reply r = next(ep);
      if (r.h.type == static_cast<std::uint16_t>(op) || r.h.type == 0) return r;
    }
  }

  void hello(fabric::Endpoint* ep, fabric::EpClass cls, std::uint8_t id = 1) {
    proto::Hello h;
    h.cls = static_cast<std::uint8_t>(cls);
    std::memset(h.conn_id, id, 16);
    send(ep, Op::HELLO, 1, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
    Reply a = next_of(ep, Op::HELLO_ACK);
    ASSERT_EQ(a.h.type, static_cast<std::uint16_t>(Op::HELLO_ACK));
    auto d = proto::decode_hello_ack(a.h, a.body);
    ASSERT_TRUE(d);
    EXPECT_EQ(d->cls, static_cast<std::uint8_t>(cls));
    EXPECT_NE(d->node_id, 0u);  // random, non-zero (plan 2C)
  }

  static store::ScopeId scope() {
    store::ScopeId s{};
    s[0] = 0x5c;
    return s;
  }
  static std::array<std::uint8_t, 32> key(int k) {
    std::array<std::uint8_t, 32> a{};
    a[0] = static_cast<std::uint8_t>(k);
    a[31] = 0xa1;
    return a;
  }
  static std::vector<std::byte> payload(std::size_t n, int seed) {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::byte>((i * 31 + static_cast<std::size_t>(seed)) & 0xff);
    return v;
  }

  // PUT_BEGIN for one root-or-child key. Returns the ack (status OK expected).
  Reply put_begin(fabric::Endpoint* ing, int k, int parent, std::size_t len) {
    auto m = std::make_unique<proto::PutBegin>();
    std::memcpy(m->scope_id, scope().data(), 32);
    m->n = 1;
    std::memcpy(m->e[0].key_hash, key(k).data(), 32);
    if (parent) std::memcpy(m->e[0].parent_hash, key(parent).data(), 16);
    m->e[0].chain_pos = parent ? 1 : 0;
    m->e[0].stored_len = len;
    send(ing, Op::PUT_BEGIN, 40 + static_cast<std::uint64_t>(k), *m,
         [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); });
    return next_of(ing, Op::PUT_BEGIN_ACK);
  }
  Status write_to(fabric::Endpoint* ing, const proto::PutBeginAck& a, std::size_t entry,
                  const std::vector<std::byte>& data) {
    const auto& e = a.e[entry];
    const auto& mr = a.mr[e.mr_index];
    std::memcpy(cbuf.data(), data.data(), data.size());
    const std::uint64_t t = ++tag;
    Status st = ing->post_write({cmr.lkey, cbuf.data(), static_cast<std::uint32_t>(data.size())},
                                {mr.rkey, mr.addr + e.offset, static_cast<std::uint32_t>(data.size())}, t);
    if (!st) return st;
    pump();
    return tags.count(t) ? tags[t] : Status(Error{ErrorCode::Timeout, "no write completion"});
  }
  void send_commit(fabric::Endpoint* ep, std::uint64_t put_id, const std::vector<std::byte>& data) {
    proto::PutCommit c;
    c.put_id = put_id;
    c.n = 1;
    c.e[0] = proto::CommitEntry{0, crc32c(data), data.size()};
    send(ep, Op::PUT_COMMIT, 99, c, [](const proto::PutCommit& x, std::span<std::byte> o) { return proto::encode_put_commit(x, o); });
  }
  Reply lookup(fabric::Endpoint* ctl, std::vector<int> ks, bool lease) {
    auto m = std::make_unique<proto::Lookup>();
    std::memcpy(m->scope_id, scope().data(), 32);
    m->flags = lease ? 1 : 0;
    m->n = static_cast<std::uint16_t>(ks.size());
    for (std::size_t i = 0; i < ks.size(); ++i) std::memcpy(m->key_hash[i].data(), key(ks[i]).data(), 32);
    send(ctl, Op::LOOKUP, 7, *m, [](const proto::Lookup& x, std::span<std::byte> o) { return proto::encode_lookup(x, o); });
    return next_of(ctl, Op::LOOKUP_ACK);
  }

  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& srv_fab;
  fabric::SimFabric& cli;
  InlineExecutor inline_exec;
  StoreExecutor* real_exec;
  std::unique_ptr<fabric::Fabric> wrapped;  // outlives the server (declared before it)
  std::unique_ptr<Server> server;
  std::map<fabric::EndpointId, std::deque<Reply>> inbox;
  std::map<fabric::EndpointId, std::deque<Reply>> segtabs;  // unsolicited SEG_TABLE frames
  std::map<std::uint64_t, Status> tags;
  std::vector<std::byte> cbuf;
  fabric::MemRegion cmr;
  std::uint64_t tag = 0;
};

TEST(ServerTickets, ReuseAndUnknownRefusedAtConnect) {
  Fx f;
  auto tk = f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1);
  ASSERT_TRUE(tk);
  auto a = f.connect_with((*tk)[0], fabric::EpClass::Control);
  EXPECT_TRUE(a);
  auto b = f.connect_with((*tk)[0], fabric::EpClass::Control);  // second use
  EXPECT_FALSE(b);
  proto::Ticket forged = (*tk)[0];
  forged.id[3] ^= 0x40;
  EXPECT_FALSE(f.connect_with(forged, fabric::EpClass::Control));
  EXPECT_FALSE(f.connect(fabric::EpClass::Control, "stranger"));  // IssueTicket rejects the identity
  // Expired ticket.
  auto tk2 = f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1);
  ASSERT_TRUE(tk2);
  f.clock.advance_by(301s);
  EXPECT_FALSE(f.connect_with((*tk2)[0], fabric::EpClass::Control));
  f.pump();
  EXPECT_EQ(f.server->n_conns(), 0u);  // `a` never said HELLO: reaped by the HELLO deadline; the expired connect added none
}

TEST(ServerWire, SegTableResentAsPrefixGrows) {
  Fx f(/*n_segments=*/3);
  auto ctl = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(ctl);
  // Drive manually: each run_once registers one more piece (3 segments, then the array).
  f.hello(*ctl, fabric::EpClass::Control);  // pump() ran the server until idle: everything registered
  f.collect();
  std::vector<proto::SegTable> tables;
  auto& q = f.segtabs[(*ctl)->id()];
  for (auto& r : q) {
    if (r.h.type != static_cast<std::uint16_t>(Op::SEG_TABLE)) continue;
    auto t = proto::decode_seg_table(r.h, r.body);
    ASSERT_TRUE(t);
    tables.push_back(*t);
  }
  ASSERT_FALSE(tables.empty());
  EXPECT_EQ(tables.back().n, 3);
  EXPECT_NE(tables.back().sg_rkey[0], 0u);
  EXPECT_EQ(tables.back().sg_slots, f.server->mrs().array_mr()->len / 8);
  for (std::size_t i = 1; i < tables.size(); ++i) {
    EXPECT_GE(tables[i].n, tables[i - 1].n);
    EXPECT_GT(tables[i].table_gen, tables[i - 1].table_gen);
  }
}

TEST(ServerWire, SegTableGrowsStepByStep) {
  Fx f(/*n_segments=*/3);
  // Connect and HELLO without letting registration run ahead: one run_once per step.
  auto ctl = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(ctl);
  proto::Hello h;
  h.cls = 0;
  f.send(*ctl, Op::HELLO, 1, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
  std::vector<std::uint16_t> ns;
  std::vector<std::uint32_t> gens;
  for (int i = 0; i < 6; ++i) {
    f.net.run_until_idle();
    f.server->run_once();
    f.net.run_until_idle();
    f.collect();
  }
  for (auto& r : f.segtabs[(*ctl)->id()]) {
    if (r.h.type != static_cast<std::uint16_t>(Op::SEG_TABLE)) continue;
    auto t = proto::decode_seg_table(r.h, r.body);
    ASSERT_TRUE(t);
    ns.push_back(t->n);
    gens.push_back(t->table_gen);
  }
  // HELLO reply table (n = 0 or 1 depending on when HELLO landed), then 1, 2, 3, 3(+array).
  ASSERT_GE(ns.size(), 4u);
  EXPECT_EQ(ns.back(), 3);
  EXPECT_LT(ns.front(), 3);
  for (std::size_t i = 1; i < ns.size(); ++i) {
    EXPECT_GE(ns[i], ns[i - 1]);
    EXPECT_GT(gens[i], gens[i - 1]);
  }
}

TEST(ServerWire, PutLookupFetchInvalidateMiss) {
  Fx f;
  auto ctl = f.connect(fabric::EpClass::Control);
  auto ing = f.connect(fabric::EpClass::Ingest);
  auto fet = f.connect(fabric::EpClass::Fetch);
  ASSERT_TRUE(ctl && ing && fet);
  f.hello(*ctl, fabric::EpClass::Control);
  f.hello(*ing, fabric::EpClass::Ingest);
  f.hello(*fet, fabric::EpClass::Fetch);

  const auto data = Fx::payload(6000, 1);
  Reply pb = f.put_begin(*ing, 1, 0, data.size());
  ASSERT_FALSE(pb.error());
  auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
  ASSERT_TRUE(ack);
  ASSERT_EQ(ack->status, 0);
  ASSERT_EQ(ack->n, 1);
  ASSERT_EQ(ack->e[0].status, 1);
  ASSERT_TRUE(f.write_to(*ing, *ack, 0, data));
  f.send_commit(*ing, ack->put_id, data);
  Reply pd = f.next_of(*ing, Op::PUT_DONE);
  ASSERT_FALSE(pd.error());
  auto done = proto::decode_put_done(pd.h, pd.body);
  ASSERT_TRUE(done);
  EXPECT_EQ(done->put_id, ack->put_id);
  EXPECT_EQ(done->e[0].status, 0);  // committed
  EXPECT_EQ(pd.h.request_id, 99u);

  // A child block: its parent travels as a 16 B prefix.
  const auto data2 = Fx::payload(4096, 2);
  Reply pb2 = f.put_begin(*ing, 2, 1, data2.size());
  auto ack2 = proto::decode_put_begin_ack(pb2.h, pb2.body);
  ASSERT_TRUE(ack2);
  ASSERT_EQ(ack2->e[0].status, 1);
  ASSERT_TRUE(f.write_to(*ing, *ack2, 0, data2));
  f.send_commit(*ing, ack2->put_id, data2);
  Reply pd2 = f.next_of(*ing, Op::PUT_DONE);
  auto done2 = proto::decode_put_done(pd2.h, pd2.body);
  ASSERT_TRUE(done2);
  EXPECT_EQ(done2->e[0].status, 0);

  // LOOKUP with a lease: both hit, a third key misses.
  Reply lr = f.lookup(*ctl, {1, 2, 3}, true);
  ASSERT_FALSE(lr.error());
  auto la = proto::decode_lookup_ack(lr.h, lr.body);
  ASSERT_TRUE(la);
  ASSERT_EQ(la->n, 3);
  EXPECT_NE(la->lease_id, 0u);
  EXPECT_GT(la->ttl_ms, 0u);
  EXPECT_EQ(la->e[0].status, 1);
  EXPECT_EQ(la->e[1].status, 1);
  EXPECT_EQ(la->e[2].status, 0);
  EXPECT_EQ(la->e[0].stored_len, data.size());

  // READ the bytes through the fetch endpoint using the SEG_TABLE-advertised rkey.
  std::map<std::uint32_t, proto::SegEntry> segs;
  for (auto& r : f.segtabs[(*ctl)->id()]) {
    if (r.h.type != static_cast<std::uint16_t>(Op::SEG_TABLE)) continue;
    auto t = proto::decode_seg_table(r.h, r.body);
    ASSERT_TRUE(t);
    for (std::size_t i = 0; i < t->n; ++i) segs[t->e[i].seg_id] = t->e[i];
  }
  ASSERT_TRUE(segs.count(la->e[0].seg_id));
  const auto& se = segs[la->e[0].seg_id];
  const std::uint64_t rt = ++f.tag;
  ASSERT_TRUE((*fet)->post_read({se.rkey[0], se.base + la->e[0].offset, static_cast<std::uint32_t>(data.size())},
                                {f.cmr.lkey, f.cbuf.data(), static_cast<std::uint32_t>(data.size())}, rt));
  f.pump();
  ASSERT_TRUE(f.tags.count(rt));
  ASSERT_TRUE(f.tags[rt]);
  EXPECT_EQ(std::memcmp(f.cbuf.data(), data.data(), data.size()), 0);

  // RENEW then RELEASE the lease.
  proto::Renew rn;
  rn.lease_id = la->lease_id;
  f.send(*ctl, Op::RENEW, 8, rn, [](const proto::Renew& m, std::span<std::byte> o) { return proto::encode_renew(m, o); });
  Reply rr = f.next_of(*ctl, Op::RENEW_ACK);
  auto rra = proto::decode_renew_ack(rr.h, rr.body);
  ASSERT_TRUE(rra);
  EXPECT_EQ(rra->status, 0);
  proto::Release rl;
  rl.lease_id = la->lease_id;
  f.send(*ctl, Op::RELEASE, 9, rl, [](const proto::Release& m, std::span<std::byte> o) { return proto::encode_release(m, o); });
  f.pump();
  EXPECT_EQ(f.server->store().n_leases(), 0u);
  f.send(*ctl, Op::RENEW, 10, rn, [](const proto::Renew& m, std::span<std::byte> o) { return proto::encode_renew(m, o); });
  rr = f.next_of(*ctl, Op::RENEW_ACK);
  rra = proto::decode_renew_ack(rr.h, rr.body);
  ASSERT_TRUE(rra);
  EXPECT_EQ(rra->status, 1);  // EXPIRED

  // INVALIDATE key 1 (drops the subtree: key 2 too), then both MISS.
  proto::Invalidate iv;
  std::memcpy(iv.scope_id, Fx::scope().data(), 32);
  std::memcpy(iv.key_hash, Fx::key(1).data(), 32);
  iv.gen = la->e[0].gen;
  f.send(*ctl, Op::INVALIDATE, 11, iv, [](const proto::Invalidate& m, std::span<std::byte> o) { return proto::encode_invalidate(m, o); });
  Reply ir = f.next_of(*ctl, Op::INVALIDATE_ACK);
  EXPECT_FALSE(ir.error());
  Reply lr2 = f.lookup(*ctl, {1, 2}, true);
  auto la2 = proto::decode_lookup_ack(lr2.h, lr2.body);
  ASSERT_TRUE(la2);
  EXPECT_EQ(la2->e[0].status, 0);
  EXPECT_EQ(la2->e[1].status, 0);
  EXPECT_EQ(la2->lease_id, 0u);

  // PING / STATS.
  proto::Ping pg;
  pg.timestamp_ns = 12345;
  f.send(*ctl, Op::PING, 12, pg, [](const proto::Ping& m, std::span<std::byte> o) { return proto::encode_ping(m, o); });
  Reply po = f.next_of(*ctl, Op::PONG);
  auto pong = proto::decode_pong(po.h, po.body);
  ASSERT_TRUE(pong);
  EXPECT_EQ(pong->timestamp_ns, 12345u);
  auto inv = f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

TEST(ServerWire, ProbeTakesNoLease) {
  Fx f;
  auto ctl = f.connect(fabric::EpClass::Control);
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ctl && ing);
  f.hello(*ctl, fabric::EpClass::Control);
  f.hello(*ing, fabric::EpClass::Ingest);
  const auto data = Fx::payload(4096, 4);
  auto pb = f.put_begin(*ing, 1, 0, data.size());
  auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
  ASSERT_TRUE(ack);
  ASSERT_TRUE(f.write_to(*ing, *ack, 0, data));
  f.send_commit(*ing, ack->put_id, data);
  (void)f.next_of(*ing, Op::PUT_DONE);
  auto lr = f.lookup(*ctl, {1}, /*lease=*/false);
  auto la = proto::decode_lookup_ack(lr.h, lr.body);
  ASSERT_TRUE(la);
  EXPECT_EQ(la->e[0].status, 1);
  EXPECT_EQ(la->lease_id, 0u);
  EXPECT_EQ(f.server->store().n_leases(), 0u);
}

TEST(ServerWire, CommitOnOtherQpRejected) {
  Fx f;
  auto a = f.connect(fabric::EpClass::Ingest);
  auto b = f.connect(fabric::EpClass::Ingest);
  auto ctl = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(a && b && ctl);
  f.hello(*a, fabric::EpClass::Ingest, 1);
  f.hello(*b, fabric::EpClass::Ingest, 1);  // same session: still the wrong QP
  f.hello(*ctl, fabric::EpClass::Control, 1);
  const auto data = Fx::payload(8192, 9);
  auto pb = f.put_begin(*a, 1, 0, data.size());
  auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
  ASSERT_TRUE(ack);
  ASSERT_TRUE(f.write_to(*a, *ack, 0, data));

  f.send_commit(*b, ack->put_id, data);  // wrong QP
  Reply bad = f.next(*b);
  EXPECT_TRUE(bad.error());
  EXPECT_EQ(bad.err_status(), proto::WireStatus::Malformed);
  EXPECT_EQ(f.server->puts().n_puts(), 1u);  // the put is untouched
  auto miss = f.lookup(*ctl, {1}, true);
  EXPECT_EQ(proto::decode_lookup_ack(miss.h, miss.body)->e[0].status, 0);  // nothing committed

  f.send_commit(*a, ack->put_id, data);  // the right QP
  Reply good = f.next_of(*a, Op::PUT_DONE);
  EXPECT_FALSE(good.error());
  auto hit = f.lookup(*ctl, {1}, true);
  EXPECT_EQ(proto::decode_lookup_ack(hit.h, hit.body)->e[0].status, 1);
}

TEST(ServerWire, CorruptPayloadAbortsWithDigest) {
  Fx f;
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ing);
  f.hello(*ing, fabric::EpClass::Ingest);
  const auto data = Fx::payload(4096, 1);
  auto pb = f.put_begin(*ing, 1, 0, data.size());
  auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
  ASSERT_TRUE(ack);
  auto bad = data;
  bad[17] ^= std::byte{0xff};
  ASSERT_TRUE(f.write_to(*ing, *ack, 0, bad));
  f.send_commit(*ing, ack->put_id, data);  // CRC of the intended bytes
  Reply pd = f.next_of(*ing, Op::PUT_DONE);
  auto done = proto::decode_put_done(pd.h, pd.body);
  ASSERT_TRUE(done);
  EXPECT_EQ(done->e[0].status, 1);  // aborted
  EXPECT_EQ(done->e[0].reason, static_cast<std::uint8_t>(proto::DoneReason::Digest));
}

TEST(ServerWire, ClassGatingAndHelloFirst) {
  Fx f;
  auto ctl = f.connect(fabric::EpClass::Control);
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ctl && ing);
  // Anything before HELLO is refused.
  proto::Ping pg;
  f.send(*ctl, Op::PING, 1, pg, [](const proto::Ping& m, std::span<std::byte> o) { return proto::encode_ping(m, o); });
  EXPECT_TRUE(f.next(*ctl).error());
  f.hello(*ctl, fabric::EpClass::Control);
  f.hello(*ing, fabric::EpClass::Ingest);
  // PUT_BEGIN on a control endpoint and LOOKUP on an ingest endpoint: Unsupported.
  auto m = std::make_unique<proto::PutBegin>();
  m->n = 1;
  m->e[0].stored_len = 4096;
  f.send(*ctl, Op::PUT_BEGIN, 2, *m, [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); });
  Reply r1 = f.next(*ctl);
  EXPECT_TRUE(r1.error());
  EXPECT_EQ(r1.err_status(), proto::WireStatus::Unsupported);
  auto lk = std::make_unique<proto::Lookup>();
  lk->n = 1;
  f.send(*ing, Op::LOOKUP, 3, *lk, [](const proto::Lookup& x, std::span<std::byte> o) { return proto::encode_lookup(x, o); });
  Reply r2 = f.next(*ing);
  EXPECT_TRUE(r2.error());
  EXPECT_EQ(r2.err_status(), proto::WireStatus::Unsupported);
  // A HELLO whose class disagrees with the ticket.
  proto::Hello h;
  h.cls = 2;
  auto ctl2 = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(ctl2);
  f.send(*ctl2, Op::HELLO, 4, h, [](const proto::Hello& x, std::span<std::byte> o) { return proto::encode_hello(x, o); });
  EXPECT_TRUE(f.next(*ctl2).error());
}

TEST(ServerWire, PrincipalsAreIsolated) {
  Fx f;
  f.server->tickets().principals().add("other", 6);
  auto a = f.connect(fabric::EpClass::Ingest, "lab");
  auto actl = f.connect(fabric::EpClass::Control, "lab");
  auto bctl = f.connect(fabric::EpClass::Control, "other");
  ASSERT_TRUE(a && actl && bctl);
  f.hello(*a, fabric::EpClass::Ingest);
  f.hello(*actl, fabric::EpClass::Control);
  f.hello(*bctl, fabric::EpClass::Control, 2);
  const auto data = Fx::payload(4096, 5);
  auto pb = f.put_begin(*a, 1, 0, data.size());
  auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
  ASSERT_TRUE(ack);
  ASSERT_TRUE(f.write_to(*a, *ack, 0, data));
  f.send_commit(*a, ack->put_id, data);
  (void)f.next_of(*a, Op::PUT_DONE);
  auto mine = f.lookup(*actl, {1}, true);
  EXPECT_EQ(proto::decode_lookup_ack(mine.h, mine.body)->e[0].status, 1);
  auto theirs = f.lookup(*bctl, {1}, true);  // same scope id, other principal: MISS
  EXPECT_EQ(proto::decode_lookup_ack(theirs.h, theirs.body)->e[0].status, 0);
}

TEST(ServerWire, EndpointDownEndsPutAndSession) {
  Fx f;
  auto ing = f.connect(fabric::EpClass::Ingest);
  auto ctl = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(ing && ctl);
  f.hello(*ing, fabric::EpClass::Ingest, 4);
  f.hello(*ctl, fabric::EpClass::Control, 4);
  auto pb = f.put_begin(*ing, 1, 0, 4096);
  ASSERT_FALSE(pb.error());
  EXPECT_EQ(f.server->puts().n_puts(), 1u);
  (*ing)->abort();
  f.pump();
  f.clock.advance_by(2ms);
  f.pump();
  EXPECT_EQ(f.server->puts().n_puts(), 0u);
  EXPECT_EQ(f.server->n_conns(), 1u);
  auto inv = f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

// The same put through the production executor: `done` runs on this thread via drain_done.
TEST(ServerWire, PutThroughThreadPoolExecutor) {
  StoreExecutor exec(2);
  Fx f(2, &exec, &exec);
  auto ctl = f.connect(fabric::EpClass::Control);
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ctl && ing);
  f.hello(*ctl, fabric::EpClass::Control);
  f.hello(*ing, fabric::EpClass::Ingest);
  for (int k = 1; k <= 8; ++k) {
    const auto data = Fx::payload(4096 * static_cast<std::size_t>(1 + k % 3), k);
    auto pb = f.put_begin(*ing, k, 0, data.size());
    auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
    ASSERT_TRUE(ack);
    ASSERT_EQ(ack->e[0].status, 1);
    ASSERT_TRUE(f.write_to(*ing, *ack, 0, data));
    f.send_commit(*ing, ack->put_id, data);
    Reply pd = f.next_of(*ing, Op::PUT_DONE);
    auto done = proto::decode_put_done(pd.h, pd.body);
    ASSERT_TRUE(done);
    EXPECT_EQ(done->e[0].status, 0);
  }
  auto lr = f.lookup(*ctl, {1, 2, 3, 4, 5, 6, 7, 8}, true);
  auto la = proto::decode_lookup_ack(lr.h, lr.body);
  ASSERT_TRUE(la);
  for (int i = 0; i < 8; ++i) EXPECT_EQ(la->e[i].status, 1);
  exec.stop();
  exec.drain_done();
  auto inv = f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

// ---- S7 fix round 2: R01 (send failure must not erase a conn under a caller) -------------------
void send_hello_raw(Fx& f, fabric::Endpoint* ep, fabric::EpClass cls, std::uint8_t cid) {
  proto::Hello h;
  h.cls = static_cast<std::uint8_t>(cls);
  std::memset(h.conn_id, cid, 16);
  f.send(ep, Op::HELLO, 1, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
}

TEST(ServerRobust, SendFailureDuringHelloIsSafe) {
  Fx f;
  auto ctl = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(ctl);
  send_hello_raw(f, *ctl, fabric::EpClass::Control, 1);
  f.net.run_until_idle();  // HELLO is in the server's CQ
  (*ctl)->abort();         // the server endpoint now fails every post_send
  f.server->run_once();    // on_hello: HELLO_ACK fails, then send_seg_table(c) on the same Conn
  f.clock.advance_by(2ms);
  f.server->run_once();
  f.server->run_once();
  EXPECT_EQ(f.server->n_conns(), 0u);
  auto inv = f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

TEST(ServerRobust, SendFailureDuringSegTableResendIsSafe) {
  // tick() would reap the dead conn first; keep it from running so the resend loop meets it.
  Fx f(3, nullptr, nullptr, [](ServerConfig& c) { c.tick_interval = std::chrono::hours(1); });
  auto a = f.connect(fabric::EpClass::Control);
  auto b = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(a && b);
  send_hello_raw(f, *a, fabric::EpClass::Control, 1);
  send_hello_raw(f, *b, fabric::EpClass::Control, 2);
  f.net.run_until_idle();
  f.server->run_once();  // both helloed; first registration step
  f.net.run_until_idle();
  f.collect();
  ASSERT_EQ(f.server->n_conns(), 2u);
  const auto tables_before = f.segtabs[(*b)->id()].size();
  (*a)->abort();  // a is the lower id: erasing it under the range-for iterator is the old bug
  for (int i = 0; i < 6; ++i) {
    f.server->run_once();  // each step grows the prefix and resends to every helloed conn
    f.net.run_until_idle();
  }
  f.collect();
  EXPECT_EQ(f.server->n_conns(), 2u);  // the sender only marked a dead; tick() (not run here) reaps it
  auto& q = f.segtabs[(*b)->id()];  // the healthy conn kept getting tables
  ASSERT_GT(q.size(), tables_before);  // growth happened after a died, and b still got it
  auto t = proto::decode_seg_table(q.back().h, q.back().body);
  ASSERT_TRUE(t);
  EXPECT_EQ(t->n, 3);
  auto inv = f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

TEST(ServerRobust, PeerThatStopsDrainingIsDropped) {
  Fx f(2, nullptr, nullptr, {}, /*cli_cq=*/8);
  auto ctl = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(ctl);
  f.hello(*ctl, fabric::EpClass::Control);
  proto::Ping pg;
  for (int i = 0; i < 64 && (*ctl)->state() == fabric::EpState::Ready; ++i) {  // never polls its CQ again
    f.send(*ctl, Op::PING, static_cast<std::uint64_t>(i + 2), pg,
           [](const proto::Ping& m, std::span<std::byte> o) { return proto::encode_ping(m, o); });
    f.net.run_until_idle();
    f.server->run_once();
  }
  f.clock.advance_by(2ms);
  f.net.run_until_idle();
  f.server->run_once();
  EXPECT_EQ(f.server->n_conns(), 0u);
  auto inv = f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

// ---- R07: per-identity ticket cap ------------------------------------------------------------
TEST(ServerLimits, OneIdentityAtItsTicketCapDoesNotBlockAnother) {
  Fx f(2, nullptr, nullptr, [](ServerConfig& c) { c.ticket_max_per_identity = 4; });
  f.server->tickets().principals().add("other", 6);
  auto tk = f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 4);
  ASSERT_TRUE(tk);
  auto more = f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1);
  ASSERT_FALSE(more);
  EXPECT_EQ(more.error().code, ErrorCode::ResourceExhausted);
  EXPECT_TRUE(f.server->issue_ticket("other", fabric::EpClass::Control, 0, 4));  // not blocked
  EXPECT_EQ(f.server->tickets().live_for("lab"), 4u);
  // Redeeming frees a slot for that identity.
  EXPECT_TRUE(f.connect_with((*tk)[0], fabric::EpClass::Control));
  EXPECT_EQ(f.server->tickets().live_for("lab"), 3u);
  EXPECT_TRUE(f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1));
  // Expiry frees the rest.
  f.clock.advance_by(301s);
  EXPECT_TRUE(f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 4));
}

// ---- R08 ------------------------------------------------------------------------------------
TEST(ServerLimits, AdmittedButNeverAcceptedExpires) {
  Fx f;
  auto tk = f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1);
  ASSERT_TRUE(tk);
  fabric::ConnParams cp;
  cp.cls = fabric::EpClass::Control;
  cp.pd = fabric::PdId{999};  // the sim refuses this after the server admitted the ticket
  std::span<std::byte> out(cp.ticket.data(), 20);
  ASSERT_TRUE(proto::encode_ticket((*tk)[0], out));
  cp.ticket_len = 20;
  EXPECT_FALSE(f.cli.connect(fabric::Peer{1}, cp));
  EXPECT_EQ(f.server->n_admitted(), 1u);
  f.clock.advance_by(5s);
  f.server->run_once();
  EXPECT_EQ(f.server->n_admitted(), 1u);  // not yet (default 10 s)
  f.clock.advance_by(6s);
  f.server->run_once();
  EXPECT_EQ(f.server->n_admitted(), 0u);
}

TEST(ServerLimits, HelloDeadline) {
  Fx f;
  auto silent = f.connect(fabric::EpClass::Control);
  auto talker = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(silent && talker);
  f.hello(*talker, fabric::EpClass::Control, 2);
  f.clock.advance_by(4s);
  f.pump();
  EXPECT_EQ(f.server->n_conns(), 2u);
  f.clock.advance_by(2s);  // 6 s since accept > 5 s
  f.pump();
  EXPECT_EQ(f.server->n_conns(), 1u);  // the helloed one stays
  EXPECT_EQ((*silent)->state(), fabric::EpState::Error);
}

TEST(ServerLimits, IdleTimeout) {
  Fx f;
  auto idle = f.connect(fabric::EpClass::Control);
  auto busy = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(idle && busy);
  f.hello(*idle, fabric::EpClass::Control, 1);
  f.hello(*busy, fabric::EpClass::Control, 2);
  proto::Ping pg;
  for (int i = 0; i < 4; ++i) {  // 4 x 100 s: busy keeps talking, idle does not
    f.clock.advance_by(100s);
    f.send(*busy, Op::PING, 10 + static_cast<std::uint64_t>(i), pg,
           [](const proto::Ping& m, std::span<std::byte> o) { return proto::encode_ping(m, o); });
    f.pump();
  }
  EXPECT_EQ(f.server->n_conns(), 1u);
  EXPECT_EQ((*idle)->state(), fabric::EpState::Error);
  EXPECT_EQ((*busy)->state(), fabric::EpState::Ready);
}

// S01: idle is per session. The client PINGs on control only; its fetch endpoint is silent.
TEST(ServerLimits, IdleIsPerSessionAndFetchIsExempt) {
  Fx f;
  auto ctl = f.connect(fabric::EpClass::Control);
  auto fet = f.connect(fabric::EpClass::Fetch);
  auto ctl2 = f.connect(fabric::EpClass::Control);
  auto fet2 = f.connect(fabric::EpClass::Fetch);
  ASSERT_TRUE(ctl && fet && ctl2 && fet2);
  f.hello(*ctl, fabric::EpClass::Control, 1);
  f.hello(*fet, fabric::EpClass::Fetch, 1);  // same session
  f.hello(*ctl2, fabric::EpClass::Control, 2);
  f.hello(*fet2, fabric::EpClass::Fetch, 2);  // a session that then says nothing at all
  proto::Ping pg;
  for (int i = 0; i < 4; ++i) {  // 4 x 100 s > 300 s idle_timeout
    f.clock.advance_by(100s);
    f.send(*ctl, Op::PING, 10 + static_cast<std::uint64_t>(i), pg,
           [](const proto::Ping& m, std::span<std::byte> o) { return proto::encode_ping(m, o); });
    f.pump();
  }
  EXPECT_EQ((*ctl)->state(), fabric::EpState::Ready);
  EXPECT_EQ((*fet)->state(), fabric::EpState::Ready) << "fetch endpoint of a live session was timed out";
  EXPECT_EQ((*ctl2)->state(), fabric::EpState::Error);
  EXPECT_EQ((*fet2)->state(), fabric::EpState::Error);  // the silent session goes as a whole
  EXPECT_EQ(f.server->n_conns(), 2u);
}

// S02: unsolicited SEG_TABLE and GOAWAY go to Control only.
TEST(ServerWire, UnsolicitedFramesGoToControlOnly) {
  Fx f(/*n_segments=*/6);
  auto ctl = f.connect(fabric::EpClass::Control);
  auto fet = f.connect(fabric::EpClass::Fetch);
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ctl && fet && ing);
  send_hello_raw(f, *ctl, fabric::EpClass::Control, 1);
  send_hello_raw(f, *fet, fabric::EpClass::Fetch, 1);
  send_hello_raw(f, *ing, fabric::EpClass::Ingest, 1);
  for (int i = 0; i < 10; ++i) {  // segments register one per turn, after the HELLOs
    f.net.run_until_idle();
    f.server->run_once();
  }
  f.net.run_until_idle();
  f.server->goaway(proto::GoawayReason::Shutdown, 100);
  f.net.run_until_idle();
  f.collect();
  EXPECT_GE(f.segtabs[(*ctl)->id()].size(), 3u);
  EXPECT_EQ(f.segtabs[(*fet)->id()].size(), 0u);
  EXPECT_EQ(f.segtabs[(*ing)->id()].size(), 0u);
  int goaways_ctl = 0, other_fetch = 0, other_ing = 0;
  for (auto& r : f.inbox[(*ctl)->id()]) goaways_ctl += r.h.type == static_cast<std::uint16_t>(Op::GOAWAY);
  for (auto& r : f.inbox[(*fet)->id()]) other_fetch += r.h.type != static_cast<std::uint16_t>(Op::HELLO_ACK);
  for (auto& r : f.inbox[(*ing)->id()]) other_ing += r.h.type != static_cast<std::uint16_t>(Op::HELLO_ACK);
  EXPECT_EQ(goaways_ctl, 1);
  EXPECT_EQ(other_fetch, 0);  // only the HELLO_ACK
  EXPECT_EQ(other_ing, 0);
}

// Graceful drain (SIGTERM path): GOAWAY with the window, reads and in-flight puts keep working, root
// PUT_BEGINs are refused with Draining, no new session is admitted (connect refused, a late new-session
// HELLO answered Draining), drain_idle() turns true once the session and its puts are gone.
TEST(ServerDrain, GoawayThenServeReadsAndFinishPutsRefuseRoots) {
  Fx f;
  auto ctl = f.connect(fabric::EpClass::Control);
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ctl && ing);
  f.hello(*ctl, fabric::EpClass::Control);
  f.hello(*ing, fabric::EpClass::Ingest);

  const auto d1 = Fx::payload(4096, 1);
  auto pb1 = f.put_begin(*ing, 1, 0, d1.size());
  auto a1 = proto::decode_put_begin_ack(pb1.h, pb1.body);
  ASSERT_TRUE(a1);
  ASSERT_EQ(a1->e[0].status, 1);
  ASSERT_TRUE(f.write_to(*ing, *a1, 0, d1));
  const auto d9 = Fx::payload(4096, 9);  // a second put begun before the drain, committed during it
  auto pb9 = f.put_begin(*ing, 9, 0, d9.size());
  auto a9 = proto::decode_put_begin_ack(pb9.h, pb9.body);
  ASSERT_TRUE(a9);
  ASSERT_EQ(a9->e[0].status, 1);
  ASSERT_TRUE(f.write_to(*ing, *a9, 0, d9));
  f.send_commit(*ing, a1->put_id, d1);
  ASSERT_FALSE(f.next_of(*ing, Op::PUT_DONE).error());  // key 1 is committed (the parent for a child below)
  auto ctl2 = f.connect(fabric::EpClass::Control);  // admitted before the drain, says HELLO during it
  ASSERT_TRUE(ctl2);

  EXPECT_FALSE(f.server->draining());
  f.server->begin_drain(proto::GoawayReason::Shutdown, 2500);
  f.net.run_until_idle();
  f.collect();
  EXPECT_TRUE(f.server->draining());
  int goaways = 0;
  std::uint32_t hint = 0;
  for (auto& r : f.inbox[(*ctl)->id()])
    if (r.h.type == static_cast<std::uint16_t>(Op::GOAWAY)) {
      ++goaways;
      auto g = proto::decode_goaway(r.h, r.body);
      ASSERT_TRUE(g);
      hint = g->drain_ms;
    }
  EXPECT_EQ(goaways, 1);
  EXPECT_EQ(hint, 2500u);
  EXPECT_FALSE(f.server->drain_idle());  // a session and a put (key 9) are live

  // Reads still work.
  auto lr = f.lookup(*ctl, {1}, false);
  auto la = proto::decode_lookup_ack(lr.h, lr.body);
  ASSERT_TRUE(la);
  EXPECT_EQ(la->e[0].status, 1);
  // A new root PUT_BEGIN is refused with Draining; no put is created.
  const auto before = f.server->puts().n_puts();
  auto rb = std::make_unique<proto::PutBegin>();  // by hand: Fx::put_begin skips error replies
  std::memcpy(rb->scope_id, Fx::scope().data(), 32);
  rb->n = 1;
  std::memcpy(rb->e[0].key_hash, Fx::key(5).data(), 32);
  rb->e[0].stored_len = 4096;
  f.send(*ing, Op::PUT_BEGIN, 45, *rb,
         [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); });
  Reply root = f.next(*ing);
  ASSERT_TRUE(root.error());
  EXPECT_EQ(root.err_status(), proto::WireStatus::Draining);
  EXPECT_EQ(f.server->puts().n_puts(), before);
  // A child of a committed block (a chain in progress) is still accepted.
  Reply child = f.put_begin(*ing, 2, 1, 4096);
  ASSERT_FALSE(child.error());
  // The in-flight put finishes.
  f.send_commit(*ing, a9->put_id, d9);
  Reply pd = f.next_of(*ing, Op::PUT_DONE);
  auto done = proto::decode_put_done(pd.h, pd.body);
  ASSERT_TRUE(done);
  EXPECT_EQ(done->e[0].status, 0);

  // r6 A8: no new session during the drain. A connect is refused (before its ticket is redeemed, so
  // the ticket table keeps it until its TTL), and a HELLO that would start a new
  // session is answered Draining: no HELLO_ACK, so the client cannot flip Up and Down again.
  auto tk = f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1);
  ASSERT_TRUE(tk);
  EXPECT_FALSE(f.connect_with((*tk)[0], fabric::EpClass::Control));
  EXPECT_EQ(f.server->n_admitted(), 0u);
  send_hello_raw(f, *ctl2, fabric::EpClass::Control, 7);
  Reply late = f.next(*ctl2);
  ASSERT_TRUE(late.error());
  EXPECT_EQ(late.err_status(), proto::WireStatus::Draining);
  int acks2 = 0;
  for (auto& r : f.inbox[(*ctl2)->id()]) acks2 += r.h.type == static_cast<std::uint16_t>(Op::HELLO_ACK);
  EXPECT_EQ(acks2, 0);

  // Everything goes away: nothing left to wait for.
  (*ctl)->abort();
  (*ing)->abort();
  (*ctl2)->abort();
  f.pump();
  f.clock.advance_by(2ms);
  f.pump();
  EXPECT_EQ(f.server->puts().n_puts(), 0u);
  EXPECT_TRUE(f.server->drain_idle());
  auto inv = f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

// Holds every `done` until the test releases it (a put stays Digesting).
class HeldExecutor final : public Executor {
 public:
  void post(std::function<void()> work, std::function<void()> done) override {
    work();
    q.push_back(std::move(done));
  }
  void run_all() {
    while (!q.empty()) {
      auto d = std::move(q.front());
      q.pop_front();
      d();
    }
  }
  std::deque<std::function<void()>> q;
};

// A drain that hits its deadline with one put Digesting (its CRC done, the `done` still queued).
struct DigestingAtDeadline {
  HeldExecutor ex;
  Fx f{2, &ex};
  bool setup() {
    auto ctl = f.connect(fabric::EpClass::Control);
    auto ing = f.connect(fabric::EpClass::Ingest);
    if (!ctl || !ing) return false;
    f.hello(*ctl, fabric::EpClass::Control);
    f.hello(*ing, fabric::EpClass::Ingest);
    const auto d = Fx::payload(4096, 3);
    auto pb = f.put_begin(*ing, 3, 0, d.size());
    auto a = proto::decode_put_begin_ack(pb.h, pb.body);
    if (!a || a->e[0].status != 1 || !f.write_to(*ing, *a, 0, d)) return false;
    f.send_commit(*ing, a->put_id, d);
    f.pump();
    f.server->begin_drain(proto::GoawayReason::Shutdown, 50);
    f.pump();
    f.clock.advance_by(60ms);  // the drain deadline passes: main leaves its loop with the put in flight
    f.pump();
    return ex.q.size() == 1 && !f.server->drain_idle() && f.server->puts().n_puts() == 1;
  }
  bool committed() { return f.server->store().has_key(5, Fx::scope(), Fx::key(3)); }
  bool clean() { return f.server->arena().superblock().clean_shutdown == 1; }
};

// r6 A2: the exit order of main.cpp. The executor's queued `done`s run first, so the Digesting put
// commits, and only then are the connections dropped and the superblock marked clean.
TEST(ServerDrain, DeadlineExitCommitsADigestingPutBeforeTheCleanMark) {
  DigestingAtDeadline x;
  ASSERT_TRUE(x.setup());
  EXPECT_FALSE(x.committed());
  x.ex.run_all();  // main.cpp: exec.stop(); exec.drain_done();
  EXPECT_TRUE(x.committed());
  ASSERT_TRUE(x.f.server->shutdown_clean());
  EXPECT_TRUE(x.clean());
  EXPECT_TRUE(x.committed());
  EXPECT_EQ(x.f.server->n_conns(), 0u);
  EXPECT_EQ(x.f.server->puts().n_puts(), 0u);
  auto inv = x.f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

// The old order (clean mark first, `done`s after) must not produce a clean superblock with a commit
// after it: the clean mark is refused while a put is in flight, and the put is then freed, not committed.
TEST(ServerDrain, CleanMarkWithAPutStillDigestingIsRefused) {
  DigestingAtDeadline x;
  ASSERT_TRUE(x.setup());
  EXPECT_FALSE(x.f.server->shutdown_clean());
  EXPECT_FALSE(x.clean());
  x.ex.run_all();  // the late `done`: the connection is gone, so the put is freed
  EXPECT_FALSE(x.committed());
  EXPECT_FALSE(x.clean());
  ASSERT_TRUE(x.f.server->shutdown_clean());  // nothing in flight any more
  EXPECT_TRUE(x.clean());
  auto inv = x.f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

// drain_ms = 0 and the second signal leave the loop without a drain, through the same exit: with
// nothing queued the clean mark is immediate.
TEST(ServerDrain, ExitWithoutDrainMarksCleanAtOnce) {
  Fx f;
  auto ctl = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(ctl);
  f.hello(*ctl, fabric::EpClass::Control);
  EXPECT_FALSE(f.server->draining());
  ASSERT_TRUE(f.server->shutdown_clean());
  EXPECT_EQ(f.server->arena().superblock().clean_shutdown, 1);
  EXPECT_EQ(f.server->n_conns(), 0u);
}

// r8b Q01/Q04: the server's fabric, with the exit fence made slow. The first `fail_dereg` deregs fail
// (a dropped QP's flush has not landed yet). While `trickle` is set every poll returns one completion
// (a CQ-level event the server only counts), as a verbs poll returns as soon as it has one; each poll
// moves the clock by `step`. `on_poll` runs at the start of every poll.
struct TrickleFabric final : fabric::Fabric {
  TrickleFabric(fabric::SimFabric& s, SimClock& c) : sim(s), clock(c) {}
  Expected<fabric::DeviceCaps> probe() override { return sim.probe(); }
  Expected<fabric::PdId> alloc_pd() override { return sim.alloc_pd(); }
  Status free_pd(fabric::PdId pd) override { return sim.free_pd(pd); }
  Expected<fabric::MemRegion> reg(std::span<std::byte> buf, fabric::Access a, fabric::PdId pd) override {
    return sim.reg(buf, a, pd);
  }
  Status dereg(const fabric::MemRegion& r) override {
    if (fail_dereg > 0) {
      --fail_dereg;
      return Error{ErrorCode::Busy, "test: flush not landed yet"};
    }
    return sim.dereg(r);
  }
  Expected<fabric::Endpoint*> connect(const fabric::Peer& p, const fabric::ConnParams& cp) override {
    return sim.connect(p, cp);
  }
  Status release(fabric::Endpoint* ep) override { return sim.release(ep); }
  Status listen(fabric::AcceptFn fn, const fabric::ListenParams& lp) override { return sim.listen(std::move(fn), lp); }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget b) override {
    ++polls;
    if (on_poll) on_poll();
    std::size_t n = sim.poll(out, b);
    if (trickle && n == 0 && !out.empty()) {
      out[0] = fabric::Completion{};
      out[0].op = fabric::CompletionOp::CqError;  // endpoint 0: CQ-level, counted and skipped
      n = 1;
    }
    clock.advance_by(step);
    return n;
  }
  int wait_fd() override { return sim.wait_fd(); }

  fabric::SimFabric& sim;
  SimClock& clock;
  int fail_dereg = 0;
  bool trickle = false;
  Nanos step{0};
  int polls = 0;
  std::function<void()> on_poll;
};

// A WRITING put on an ingest endpoint: shutdown_clean() drops it, and its write MR must be fenced.
struct SlowFence {
  TrickleFabric* tf = nullptr;
  Fx f{2, nullptr, nullptr, {}, fabric::SimNetwork::kDefaultCqCapacity,
       [this](fabric::SimFabric& s, SimClock& c) {
         auto p = std::make_unique<TrickleFabric>(s, c);
         tf = p.get();
         return std::unique_ptr<fabric::Fabric>(std::move(p));
       }};
  bool setup() {
    auto ctl = f.connect(fabric::EpClass::Control);
    auto ing = f.connect(fabric::EpClass::Ingest);
    if (!ctl || !ing) return false;
    f.hello(*ctl, fabric::EpClass::Control);
    f.hello(*ing, fabric::EpClass::Ingest);
    auto pb = f.put_begin(*ing, 3, 0, 4096);
    auto a = proto::decode_put_begin_ack(pb.h, pb.body);
    return a && a->e[0].status == 1 && f.server->puts().n_puts() == 1;
  }
};

// r8b Q01: flushes trickling in one per poll (each poll returns early, 1 ms apart) must not use up a
// fixed iteration cap well inside the 150 ms budget: the fence lands at ~50 ms and the exit is clean.
TEST(ServerDrain, ExitFenceRetryIsBoundedByTheClockNotByPolls) {
  SlowFence x;
  ASSERT_TRUE(x.setup());
  x.tf->trickle = true;
  x.tf->step = 1ms;
  x.tf->fail_dereg = 100;  // ~2 fence attempts per iteration (the loop's tick and run_once's)
  const Nanos t0 = x.f.clock.now();
  const int before = x.tf->polls;
  auto st = x.f.server->shutdown_clean();
  EXPECT_TRUE(st) << (st ? "" : st.error().context) << " after " << x.tf->polls - before << " polls";
  EXPECT_EQ(x.tf->fail_dereg, 0);
  EXPECT_GT(x.tf->polls - before, 32) << "the old cap would have stopped here";
  EXPECT_LT(x.f.clock.now() - t0, 150ms);
  EXPECT_EQ(x.f.server->arena().superblock().clean_shutdown, 1);
}

// r8b Q01: the bounds still hold. A fence that never lands stops at the 150 ms clock; a frozen clock
// stops after 32 idle polls, or after the hard cap when completions never stop either.
TEST(ServerDrain, ExitFenceRetryStillTerminates) {
  {
    SlowFence x;
    ASSERT_TRUE(x.setup());
    x.tf->trickle = true;
    x.tf->step = 1ms;
    x.tf->fail_dereg = 1 << 30;
    const Nanos t0 = x.f.clock.now();
    const int before = x.tf->polls;
    EXPECT_FALSE(x.f.server->shutdown_clean());
    EXPECT_GE(x.f.clock.now() - t0, 150ms);
    EXPECT_LE(x.tf->polls - before, 151);
  }
  {
    SlowFence x;
    ASSERT_TRUE(x.setup());
    x.tf->fail_dereg = 1 << 30;  // frozen clock, nothing polled
    const int before = x.tf->polls;
    EXPECT_FALSE(x.f.server->shutdown_clean());
    EXPECT_EQ(x.tf->polls - before, 32);
  }
  {
    SlowFence x;
    ASSERT_TRUE(x.setup());
    x.tf->trickle = true;  // frozen clock, a completion on every poll
    x.tf->fail_dereg = 1 << 30;
    const int before = x.tf->polls;
    EXPECT_FALSE(x.f.server->shutdown_clean());
    EXPECT_EQ(x.tf->polls - before, 4096);
  }
}

// r8b Q04: with drain_ms == 0 begin_drain never ran. The exit fence loop polls, so a connect landing
// then must be refused (draining), and no ticket is handed out.
TEST(ServerDrain, ExitWithoutDrainAdmitsNoSessionDuringTheFence) {
  SlowFence x;
  ASSERT_TRUE(x.setup());
  auto tk = x.f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1);
  ASSERT_TRUE(tk);
  EXPECT_FALSE(x.f.server->draining());
  x.tf->step = 1ms;
  x.tf->fail_dereg = 4;  // a few polls of fence loop
  bool tried = false, connected = false, issued = false;
  x.tf->on_poll = [&] {
    if (tried) return;
    tried = true;
    connected = static_cast<bool>(x.f.connect_with((*tk)[0], fabric::EpClass::Control));
    issued = static_cast<bool>(x.f.server->check_issue_capacity("lab", 1));  // the admin API's 503 gate
  };
  (void)x.f.server->shutdown_clean();
  ASSERT_TRUE(tried) << "the fence loop never polled";
  EXPECT_TRUE(x.f.server->draining());
  EXPECT_FALSE(connected) << "a session was admitted during the exit fence";
  EXPECT_FALSE(issued) << "the admin API would issue tickets during the exit fence";
}

// next_wake_in(): zero before the first tick, then the idle_tick horizon, shrinking as time passes.
TEST(ServerDrain, NextWakeIsTheNextTick) {
  Fx f;
  EXPECT_EQ(f.server->next_wake_in(), Nanos{0});
  f.server->run_once();
  const auto w = f.server->next_wake_in();
  EXPECT_GT(w, Nanos{0});
  EXPECT_LE(w, std::chrono::milliseconds(10));
  f.clock.advance_by(4ms);
  EXPECT_LE(f.server->next_wake_in(), w - std::chrono::milliseconds(4));
  f.clock.advance_by(20ms);
  EXPECT_EQ(f.server->next_wake_in(), Nanos{0});
}

// S03/S04: lab ticket file is 0600, and a failed issue keeps the old file.
TEST(LabTickets, FileIs0600AndFailedIssueKeepsOldFile) {
  Fx f(2, nullptr, nullptr, [](ServerConfig& c) { c.ticket_max_per_identity = 12; });
  const std::string path = "/tmp/miracache_lab_tickets_" + std::to_string(::getpid());
  (void)::unlink(path.c_str());
  const mode_t old_umask = ::umask(0);  // a permissive umask must not widen the file
  auto st = write_lab_tickets(*f.server, "lab", path, 2);
  ASSERT_TRUE(st) << st.error().context;
  ::umask(old_umask);
  struct stat sb{};
  ASSERT_EQ(::stat(path.c_str(), &sb), 0);
  EXPECT_EQ(sb.st_mode & 0777, mode_t{0600});
  auto slurp = [&] {
    std::ifstream in(path);
    return std::string(std::istreambuf_iterator<char>(in), {});
  };
  const std::string first = slurp();
  EXPECT_EQ(std::count(first.begin(), first.end(), '\n'), 6);
  // 6 live tickets already; asking for 3 per class needs 9 more (> 12): the issue fails part-way.
  auto bad = write_lab_tickets(*f.server, "lab", path, 3);
  EXPECT_FALSE(bad);
  EXPECT_EQ(slurp(), first);
  struct stat tb{};
  EXPECT_NE(::stat((path + ".tmp").c_str(), &tb), 0);  // no stray tmp file
  (void)::unlink(path.c_str());
}

// S04/S06: config validation.
TEST(NodeConfig, PortsAndRangesAreChecked) {
  const std::string base = "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n";
  EXPECT_TRUE(parse_node_config(base + "[node]\nlisten = [\"h:7100\"]\n"));
  for (const char* p : {"abc", "0", "65536", "-1", "", "71x", "99999999999"})
    EXPECT_FALSE(parse_node_config(base + "[node]\nlisten = [\"h:" + std::string(p) + "\"]\n")) << p;
  EXPECT_FALSE(parse_node_config(base + "[telemetry]\nlisten = \"127.0.0.1:abc\"\n"));
  EXPECT_FALSE(parse_node_config(base + "[telemetry]\nlisten = \"127.0.0.1:70000\"\n"));
  EXPECT_TRUE(parse_node_config(base + "[telemetry]\nlisten = \"127.0.0.1:0\"\n"));
  for (const char* v : {"4294967296", "7"}) {  // the key was removed (plan 2C): any value is the stale-key error
    auto r = parse_node_config(std::string("[node]\nid = ") + v + "\n" + base);
    ASSERT_FALSE(r) << v;
    EXPECT_NE(std::string(r.error().context).find("node id was removed; node IDs are assigned automatically"),
              std::string::npos)
        << r.error().context;
  }
  EXPECT_FALSE(parse_node_config(base + "[limits]\nmax_leases_per_principal = 4294967296\n"));
  EXPECT_FALSE(parse_node_config(base + "[lab]\ntickets = 4294967297\n"));
  auto e = parse_node_config(base + "[limits]\nmax_conns_per_principal = 4294967296\n");
  ASSERT_FALSE(e);
  EXPECT_NE(std::string(e.error().context).find("max_conns_per_principal"), std::string::npos) << e.error().context;
  EXPECT_TRUE(parse_port("65535"));
  EXPECT_FALSE(parse_port("0"));
  // node.drain_ms: default 5000, 0 = no drain, at most 10 minutes.
  EXPECT_EQ(parse_node_config(base)->drain_ms, 5000u);
  EXPECT_EQ(parse_node_config("[node]\ndrain_ms = 0\n" + base)->drain_ms, 0u);
  EXPECT_EQ(parse_node_config("[node]\ndrain_ms = 600000\n" + base)->drain_ms, 600000u);
  EXPECT_FALSE(parse_node_config("[node]\ndrain_ms = 600001\n" + base));
  // lab.tickets x 6 (3 classes, 2 live rounds) must fit the per-identity ticket cap.
  const std::string lab = "[lab]\nprincipal = \"x\"\nticket_file = \"/tmp/t\"\n";
  EXPECT_TRUE(parse_node_config(base + lab + "tickets = 170\n"));
  EXPECT_FALSE(parse_node_config(base + lab + "tickets = 171\n"));
  auto small = parse_node_config(base + "[limits]\nticket_max_per_identity = 12\n" + lab + "tickets = 2\n");
  EXPECT_TRUE(small) << (small ? "" : small.error().context);
  EXPECT_FALSE(parse_node_config(base + "[limits]\nticket_max_per_identity = 12\n" + lab + "tickets = 3\n"));
}

TEST(ServerLimits, ConnectionsPerPrincipalCapped) {
  Fx f(2, nullptr, nullptr, [](ServerConfig& c) { c.max_conns_per_principal = 2; });
  f.server->tickets().principals().add("other", 6);
  auto a = f.connect(fabric::EpClass::Control);
  auto b = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(a && b);
  EXPECT_FALSE(f.connect(fabric::EpClass::Control));              // third for "lab"
  EXPECT_TRUE(f.connect(fabric::EpClass::Control, "other"));       // another principal is not affected
  EXPECT_EQ(f.server->n_conns(), 3u);
  (*a)->abort();
  f.pump();
  f.clock.advance_by(2ms);
  f.pump();
  EXPECT_TRUE(f.connect(fabric::EpClass::Control));  // a slot is free again
}

TEST(ServerLimits, LeasesPerPrincipalCapped) {
  Fx f(2, nullptr, nullptr, [](ServerConfig& c) { c.max_leases_per_principal = 2; });
  auto ing = f.connect(fabric::EpClass::Ingest);
  auto c1 = f.connect(fabric::EpClass::Control);
  auto c2 = f.connect(fabric::EpClass::Control);  // second session of the same principal
  ASSERT_TRUE(ing && c1 && c2);
  f.hello(*ing, fabric::EpClass::Ingest);
  f.hello(*c1, fabric::EpClass::Control, 5);  // ingest uses conn_id 1: c1 must be a session of its own
  f.hello(*c2, fabric::EpClass::Control, 2);
  const auto data = Fx::payload(4096, 5);
  auto pb = f.put_begin(*ing, 1, 0, data.size());
  auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
  ASSERT_TRUE(ack);
  ASSERT_TRUE(f.write_to(*ing, *ack, 0, data));
  f.send_commit(*ing, ack->put_id, data);
  (void)f.next_of(*ing, Op::PUT_DONE);
  auto lease_of = [&](fabric::Endpoint* ep, bool lease) {
    auto r = f.lookup(ep, {1}, lease);
    auto d = proto::decode_lookup_ack(r.h, r.body);
    EXPECT_TRUE(d);
    return std::pair<std::uint64_t, int>(d ? d->lease_id : 0, d ? d->e[0].status : -1);
  };
  auto l1 = lease_of(*c1, true);
  auto l2 = lease_of(*c2, true);  // across sessions
  EXPECT_NE(l1.first, 0u);
  EXPECT_NE(l2.first, 0u);
  auto l3 = lease_of(*c1, true);  // over the cap: all-MISS, lease 0
  EXPECT_EQ(l3.first, 0u);
  EXPECT_EQ(l3.second, 0);
  auto probe = lease_of(*c1, false);  // PROBE takes no lease and is not refused
  EXPECT_EQ(probe.first, 0u);
  EXPECT_EQ(probe.second, 1);
  // Release frees a slot.
  proto::Release rel;
  rel.lease_id = l1.first;
  f.send(*c1, Op::RELEASE, 77, rel, [](const proto::Release& m, std::span<std::byte> o) { return proto::encode_release(m, o); });
  f.pump();
  auto l4 = lease_of(*c1, true);
  EXPECT_NE(l4.first, 0u);
  EXPECT_EQ(lease_of(*c2, true).first, 0u);  // full again
  // Ending a session frees its leases.
  (*c1)->abort();
  f.pump();
  f.clock.advance_by(2ms);
  f.pump();
  EXPECT_NE(lease_of(*c2, true).first, 0u);
  // Expiry frees them too (lease TTL 30 s, renewals not asked for; keep c2 alive with a PING).
  EXPECT_EQ(lease_of(*c2, true).first, 0u);  // c2 holds 2 live leases again (cap 2)
  f.clock.advance_by(31s);
  f.pump();
  EXPECT_NE(lease_of(*c2, true).first, 0u);
}

// ---- R16 --------------------------------------------------------------------------------------
TEST(ServerCreate, TooManySegmentsRefused) {
  SimClock clock;
  SeededRandom rng(3);
  fabric::SimNetwork net(clock, rng, {}, {});
  auto& fab = net.add_node(1);
  InlineExecutor ex;
  ServerConfig sc;
  sc.store = store_cfg(static_cast<std::uint32_t>(proto::kMaxSegEntries) + 1);
  auto s = Server::create(sc, fab, clock, rng, ex);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::InvalidArgument);
}

// ---- A3.1: warm restart and the backing probe ---------------------------------------------------
// A fabric that refuses every remote-write registration, as the kernel does for pages of a disk file (UP1).
struct NoPinFabric final : fabric::Fabric {
  explicit NoPinFabric(fabric::SimFabric& s) : sim(s) {}
  Expected<fabric::DeviceCaps> probe() override { return sim.probe(); }
  Expected<fabric::PdId> alloc_pd() override { return sim.alloc_pd(); }
  Status free_pd(fabric::PdId pd) override { return sim.free_pd(pd); }
  Expected<fabric::MemRegion> reg(std::span<std::byte> buf, fabric::Access a, fabric::PdId pd) override {
    if (a == fabric::Access::RemoteWrite) return Error{ErrorCode::Unsupported, "test: cannot pin file pages"};
    return sim.reg(buf, a, pd);
  }
  Status dereg(const fabric::MemRegion& r) override { return sim.dereg(r); }
  Expected<fabric::Endpoint*> connect(const fabric::Peer& p, const fabric::ConnParams& cp) override { return sim.connect(p, cp); }
  Status release(fabric::Endpoint* ep) override { return sim.release(ep); }
  Status listen(fabric::AcceptFn fn, const fabric::ListenParams& lp) override { return sim.listen(std::move(fn), lp); }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget b) override { return sim.poll(out, b); }
  int wait_fd() override { return sim.wait_fd(); }
  fabric::SimFabric& sim;
};

TEST(ServerCreate, BackingThatCannotBePinnedForRemoteWriteIsRefused) {
  char t[] = "/tmp/mira-pin-XXXXXX";
  ASSERT_NE(::mkdtemp(t), nullptr);
  SimClock clock;
  SeededRandom rng(3);
  fabric::SimNetwork net(clock, rng, {}, {});
  auto& sim = net.add_node(1);
  InlineExecutor ex;
  ServerConfig sc;
  sc.store = store_cfg();
  sc.store.backing = store::BackingKind::File;
  sc.store.dir = t;
  {
    NoPinFabric fab(sim);
    auto s = Server::create(sc, fab, clock, rng, ex);
    ASSERT_FALSE(s);
    EXPECT_EQ(s.error().code, ErrorCode::Unsupported);
  }
  auto ok = Server::create(sc, sim, clock, rng, ex);  // the plain fabric pins it
  EXPECT_TRUE(ok) << (ok ? "" : ok.error().context);
  ok->reset();
  std::error_code ec;
  std::filesystem::remove_all(t, ec);
}

TEST(ServerCreate, WarmRestartRunsTheScanAndCountsIt) {
  char t[] = "/tmp/mira-warm-XXXXXX";
  ASSERT_NE(::mkdtemp(t), nullptr);
  SimClock clock;
  SeededRandom rng(3);
  fabric::SimNetwork net(clock, rng, {}, {});
  auto& fab = net.add_node(1);
  InlineExecutor ex;
  ServerConfig sc;
  sc.store = store_cfg();
  sc.store.backing = store::BackingKind::File;
  sc.store.dir = t;
  std::uint32_t id = 0;
  {
    auto s = Server::create(sc, fab, clock, rng, ex);
    ASSERT_TRUE(s) << s.error().context;
    EXPECT_FALSE((*s)->restart_report().ran);  // a blank store
    id = (*s)->node_id();
    ASSERT_TRUE((*s)->store().ensure_scope_for_root_put(5, store::ScopeId{1}, clock.now()));
    ASSERT_TRUE((*s)->shutdown_clean());
  }
  auto s = Server::create(sc, fab, clock, rng, ex);
  ASSERT_TRUE(s) << s.error().context;
  EXPECT_EQ((*s)->node_id(), id);
  EXPECT_TRUE((*s)->restart_report().ran);
  EXPECT_TRUE((*s)->restart_report().clean);
  EXPECT_EQ((*s)->restart_report().scopes_resumed, 1u);
  EXPECT_TRUE((*s)->store().has_scope(5, store::ScopeId{1}));
  std::string m;
  (*s)->metrics().write_prometheus(m);
  EXPECT_NE(m.find("miracache_restart_adopted_blocks_total"), std::string::npos);
  EXPECT_NE(m.find("miracache_restart_discarded_blocks_total{"), std::string::npos);
  EXPECT_NE(m.find("reason=\"digest\""), std::string::npos);
  s->reset();
  std::error_code ec;
  std::filesystem::remove_all(t, ec);
}

TEST(ServerTickets, RailMustMatchListener) {
  Fx f;  // one listener = rail 0
  auto wrong = f.server->issue_ticket("lab", fabric::EpClass::Control, 1, 1);
  ASSERT_TRUE(wrong);
  EXPECT_FALSE(f.connect_with((*wrong)[0], fabric::EpClass::Control));
  EXPECT_EQ(f.server->n_admitted(), 0u);
  EXPECT_TRUE(f.connect(fabric::EpClass::Control));  // rail 0 works
  // Two listeners (RL1: the sim keeps one per address): a connect picks its listener by address.
  Fx g(2, nullptr, nullptr, [](ServerConfig& c) { c.rails = {fabric::RailAddr{"a", 1}, fabric::RailAddr{"b", 2}}; });
  auto r0 = g.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1);
  auto r1 = g.server->issue_ticket("lab", fabric::EpClass::Control, 1, 1);
  ASSERT_TRUE(r0 && r1);
  EXPECT_FALSE(g.connect_with((*r0)[0], fabric::EpClass::Control, fabric::RailAddr{"b", 2}));  // rail 0 ticket on rail 1
  EXPECT_TRUE(g.connect_with((*r1)[0], fabric::EpClass::Control, fabric::RailAddr{"b", 2}));
  auto r0b = g.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1);
  ASSERT_TRUE(r0b);
  EXPECT_TRUE(g.connect_with((*r0b)[0], fabric::EpClass::Control, fabric::RailAddr{"a", 1}));
}

TEST(ServerTickets, RemoveIdentityDropsTicketsAndConnections) {
  Fx f;
  f.server->tickets().principals().add("other", 6);
  auto o1 = f.connect(fabric::EpClass::Control, "other");
  auto o2 = f.connect(fabric::EpClass::Fetch, "other");
  auto l1 = f.connect(fabric::EpClass::Control, "lab");
  ASSERT_TRUE(o1 && o2 && l1);
  f.hello(*o1, fabric::EpClass::Control, 3);
  f.hello(*l1, fabric::EpClass::Control, 4);
  auto spare = f.server->issue_ticket("other", fabric::EpClass::Control, 0, 3);
  ASSERT_TRUE(spare);
  EXPECT_EQ(f.server->tickets().live_for("other"), 3u);
  f.server->remove_identity("other");
  EXPECT_EQ(f.server->tickets().live_for("other"), 0u);
  EXPECT_EQ(f.server->n_conns(), 1u);  // only lab's
  f.pump();
  EXPECT_EQ((*o1)->state(), fabric::EpState::Error);
  EXPECT_EQ((*o2)->state(), fabric::EpState::Error);
  EXPECT_EQ((*l1)->state(), fabric::EpState::Ready);
  EXPECT_FALSE(f.connect_with((*spare)[0], fabric::EpClass::Control));
  auto again = f.server->issue_ticket("other", fabric::EpClass::Control, 0, 1);
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error().code, ErrorCode::AccessDenied);
  EXPECT_TRUE(f.server->issue_ticket("lab", fabric::EpClass::Control, 0, 1));
  auto inv = f.server->check_invariants();
  EXPECT_TRUE(inv) << (inv ? "" : inv.error().context);
}

TEST(Tickets, PrincipalTableRemove) {
  PrincipalTable p;
  p.add("a", 1);
  EXPECT_TRUE(p.remove("a"));
  EXPECT_FALSE(p.remove("a"));
  EXPECT_FALSE(p.find("a"));
}

TEST(NodeConfig, LimitsSection) {
  auto d = parse_node_config("[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n");
  ASSERT_TRUE(d) << d.error().context;
  EXPECT_EQ(d->server.ticket_max_per_identity, 0u);  // unset: Server::create computes it (H07)
  EXPECT_EQ(d->server.admit_timeout, 10s);
  EXPECT_EQ(d->server.hello_deadline, 5s);
  EXPECT_EQ(d->server.idle_timeout, 300s);
  EXPECT_EQ(d->server.max_conns_per_principal, 0u);  // unset: Server::create computes it (G02)
  EXPECT_EQ(d->server.max_leases_per_principal, 8192u);
  auto c = parse_node_config(R"(
[store]
backing = "anon"
segment_bytes = 4194304
run_bytes = 262144
min_block_bytes = 4096
[limits]
ticket_max_per_identity = 7
admit_timeout_s = 3
hello_deadline_s = 2
idle_timeout_s = 60
max_conns_per_principal = 9
max_leases_per_principal = 11
)");
  ASSERT_TRUE(c) << c.error().context;
  EXPECT_EQ(c->server.ticket_max_per_identity, 7u);
  EXPECT_EQ(c->server.admit_timeout, 3s);
  EXPECT_EQ(c->server.hello_deadline, 2s);
  EXPECT_EQ(c->server.idle_timeout, 60s);
  EXPECT_EQ(c->server.max_conns_per_principal, 9u);
  EXPECT_EQ(c->server.max_leases_per_principal, 11u);
  EXPECT_FALSE(parse_node_config("[limits]\nbogus = 1\n"));
  EXPECT_FALSE(parse_node_config("[limits]\nmax_conns_per_principal = 0\n"));
}

// ---- metrics (A3.5 M1) ---------------------------------------------------------------------
std::string http_get(std::uint16_t port, const std::string& request) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  EXPECT_GE(fd, 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
    ::close(fd);
    return "connect failed";
  }
  if (!request.empty()) (void)::send(fd, request.data(), request.size(), 0);
  std::string out;
  char buf[4096];
  for (;;) {
    ssize_t n = ::recv(fd, buf, sizeof buf, 0);
    if (n <= 0) break;
    out.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);
  return out;
}
std::string body_of(const std::string& resp) {
  const auto p = resp.find("\r\n\r\n");
  return p == std::string::npos ? "" : resp.substr(p + 4);
}
// Every memnode series starts with the const label node_id="N" (plan 2B). The assertions below
// name a series by its own labels, so they read the text with that label removed.
std::string strip_node_id(const std::string& text) {
  static const std::regex lone("\\{node_id=\"[0-9]+\"\\}"), first("\\{node_id=\"[0-9]+\",");
  return std::regex_replace(std::regex_replace(text, lone, ""), first, "{");
}
// Value of one series, e.g. `miracache_lookup_keys_total{result="hit"}`. -1 if absent.
double series(const std::string& txt, const std::string& name) {
  const std::string hay = "\n" + strip_node_id(txt);
  const std::string needle = "\n" + name + " ";
  const auto p = hay.find(needle);
  if (p == std::string::npos) return -1;
  return std::atof(hay.c_str() + p + needle.size());
}
std::string render_raw(Server& s) {
  std::string t;
  s.metrics().write_prometheus(t);
  return t;
}
std::string render(Server& s) {
  std::string t;
  s.metrics().write_prometheus(t);
  return t;
}

// One put of key k (child of `parent`, 0 = root) with `len` payload bytes. `corrupt` writes other
// bytes than the CRC the client commits with (digest mismatch). Returns the PUT_DONE status
// (0 committed, 1 aborted), -1 when the begin was refused or skipped, -2 on a protocol error.
int do_put(Fx& f, fabric::Endpoint* ing, int k, int parent, std::size_t len, bool corrupt = false) {
  Reply pb = f.put_begin(ing, k, parent, len);
  if (pb.error()) return -2;
  auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
  if (!ack) return -2;
  if (ack->status != 0 || ack->n != 1 || ack->e[0].status != 1) return -1;
  const auto data = Fx::payload(len, k);
  const auto bad = Fx::payload(len, k + 77);
  EXPECT_TRUE(f.write_to(ing, *ack, 0, corrupt ? bad : data));
  f.send_commit(ing, ack->put_id, data);
  Reply pd = f.next_of(ing, Op::PUT_DONE);
  auto done = proto::decode_put_done(pd.h, pd.body);
  return done ? done->e[0].status : -2;
}

struct Conns {
  fabric::Endpoint *ctl, *ing;
};
Conns open_conns(Fx& f) {
  auto ctl = f.connect(fabric::EpClass::Control);
  auto ing = f.connect(fabric::EpClass::Ingest);
  EXPECT_TRUE(ctl && ing);
  f.hello(*ctl, fabric::EpClass::Control);
  f.hello(*ing, fabric::EpClass::Ingest);
  return {*ctl, *ing};
}

// Plan 2B: node_id is a const label on every series and miracache_node_info carries hostname/addr.
TEST(ServerMetrics, NodeIdLabelOnEverySeriesAndNodeInfo) {
  Fx f(2, nullptr, nullptr, [](ServerConfig& sc) {
    sc.store.node_id = 7;
    sc.rails = {fabric::RailAddr{"10.0.0.5", 7471}, fabric::RailAddr{"10.0.1.5", 7471}};
  });
  const std::string t = render_raw(*f.server);
  EXPECT_NE(t.find("miracache_node_info{node_id=\"7\",hostname=\"" + log::hostname() +
                   "\",addr=\"10.0.0.5:7471,10.0.1.5:7471\"} 1\n"), std::string::npos) << t;
  std::size_t n = 0;
  std::size_t pos = 0;
  while (pos < t.size()) {
    auto eol = t.find('\n', pos);
    if (eol == std::string::npos) eol = t.size();
    const std::string line = t.substr(pos, eol - pos);
    pos = eol + 1;
    if (line.empty() || line[0] == '#') continue;
    ++n;
    EXPECT_NE(line.find("{node_id=\"7\""), std::string::npos) << line;  // histogram buckets included
  }
  EXPECT_GT(n, 50u);
}

TEST(ServerMetrics, EndpointDeltasOverLoopback) {
  Fx f;
  auto http = MetricsHttp::start("127.0.0.1:0", f.server->metrics());
  ASSERT_TRUE(http) << http.error().context;
  ASSERT_TRUE(*http);
  const std::uint16_t port = (*http)->port();
  const std::string before = body_of(http_get(port, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"));
  EXPECT_NE(before.find("# TYPE miracache_put_commit_seconds histogram"), std::string::npos);
  EXPECT_NE(before.find("miracache_build_info{node_id=\"" + std::to_string(f.server->node_id()) + "\",version="), std::string::npos);
  EXPECT_EQ(series(before, "miracache_lookup_keys_total{result=\"hit\"}"), 0);

  auto c = open_conns(f);
  EXPECT_EQ(do_put(f, c.ing, 1, 0, 6000), 0);                    // committed
  EXPECT_EQ(do_put(f, c.ing, 2, 1, 4096), 0);                    // committed child
  EXPECT_EQ(do_put(f, c.ing, 1, 0, 6000), -1);                   // already there: skipped
  EXPECT_EQ(do_put(f, c.ing, 5, 0, 4096, /*corrupt=*/true), 1);  // digest mismatch: aborted
  Reply lr = f.lookup(c.ctl, {1, 2, 3}, true);                   // 2 hits, 1 miss, one lease
  auto la = proto::decode_lookup_ack(lr.h, lr.body);
  ASSERT_TRUE(la);
  EXPECT_FALSE(f.lookup(c.ctl, {9}, false).error());  // 1 miss, a PROBE
  // INVALIDATE the root: drops the subtree (2 blocks); an unknown key is ignored.
  proto::Invalidate iv;
  std::memcpy(iv.scope_id, Fx::scope().data(), 32);
  std::memcpy(iv.key_hash, Fx::key(1).data(), 32);
  iv.gen = la->e[0].gen;
  f.send(c.ctl, Op::INVALIDATE, 11, iv, [](const proto::Invalidate& m, std::span<std::byte> o) { return proto::encode_invalidate(m, o); });
  EXPECT_FALSE(f.next_of(c.ctl, Op::INVALIDATE_ACK).error());
  std::memcpy(iv.key_hash, Fx::key(7).data(), 32);
  f.send(c.ctl, Op::INVALIDATE, 12, iv, [](const proto::Invalidate& m, std::span<std::byte> o) { return proto::encode_invalidate(m, o); });
  EXPECT_FALSE(f.next_of(c.ctl, Op::INVALIDATE_ACK).error());
  f.server->publish_gauges();
  const std::string after = body_of(http_get(port, "GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"));
  auto d = [&](const std::string& s) { return series(after, s) - series(before, s); };
  EXPECT_EQ(d("miracache_lookup_keys_total{result=\"hit\"}"), 2);
  EXPECT_EQ(d("miracache_lookup_keys_total{result=\"miss\"}"), 2);
  EXPECT_EQ(d("miracache_put_ops_total{result=\"committed\"}"), 2);
  EXPECT_EQ(d("miracache_put_ops_total{result=\"skipped\"}"), 1);
  EXPECT_EQ(d("miracache_put_ops_total{result=\"aborted\"}"), 1);
  EXPECT_EQ(d("miracache_put_ops_total{result=\"refused\"}"), 0);
  EXPECT_EQ(d("miracache_put_bytes_total{result=\"committed\"}"), 6000 + 4096);
  EXPECT_EQ(d("miracache_put_digest_mismatch_total"), 1);
  EXPECT_EQ(d("miracache_put_commit_seconds_count"), 3);  // three puts reached the digest
  EXPECT_EQ(d("miracache_invalidate_total{result=\"dropped\"}"), 1);
  EXPECT_EQ(d("miracache_invalidate_total{result=\"ignored\"}"), 1);
  EXPECT_EQ(d("miracache_evict_blocks_total{reason=\"invalidate\"}"), 2);
  EXPECT_EQ(d("miracache_lease_granted_total"), 1);
  EXPECT_EQ(d("miracache_scope_opened_total"), 1);
  EXPECT_NE(after.find("miracache_store_occupancy_ratio_ppm"), std::string::npos);  // U2-15: registered and exported
  EXPECT_NE(after.find("miracache_evict_backlog_blocks"), std::string::npos);
  EXPECT_NE(after.find("kind=\"ops\"} 0", after.find("miracache_put_throttled_total")), std::string::npos);
  EXPECT_EQ(d("miracache_requests_total{op=\"lookup\",status=\"ok\"}"), 2);
  EXPECT_EQ(d("miracache_requests_total{op=\"put_begin\",status=\"ok\"}"), 4);
  EXPECT_EQ(d("miracache_requests_total{op=\"put_commit\",status=\"ok\"}"), 3);
  EXPECT_EQ(d("miracache_requests_total{op=\"invalidate\",status=\"ok\"}"), 2);
  EXPECT_EQ(series(after, "miracache_conn_active{class=\"control\"}"), 1);
  EXPECT_EQ(series(after, "miracache_conn_active{class=\"ingest\"}"), 1);
  EXPECT_EQ(series(after, "miracache_lease_active"), 1);
  EXPECT_EQ(series(after, "miracache_principal_bytes{principal=\"5\"}"), 0);  // subtree invalidated
  EXPECT_GE(series(after, "miracache_ticket_issued_total"), 2);
  EXPECT_EQ(after.find("scope="), std::string::npos);  // no scope / session / key label ever
  EXPECT_EQ(after.find("session="), std::string::npos);
  EXPECT_EQ(after.find("key="), std::string::npos);
}

TEST(ServerMetrics, PutRefusedWithoutScope) {
  Fx f;
  auto c = open_conns(f);
  EXPECT_EQ(do_put(f, c.ing, 6, 3, 4096), -1);  // non-root put into a scope that does not exist
  const std::string t = render(*f.server);
  EXPECT_EQ(series(t, "miracache_put_ops_total{result=\"refused\"}"), 1);
  EXPECT_EQ(series(t, "miracache_put_refused_total{reason=\"other\"}"), 1);
  EXPECT_EQ(series(t, "miracache_scope_denied_total"), 1);
  EXPECT_EQ(series(t, "miracache_put_bytes_total{result=\"refused\"}"), 4096);
}

TEST(ServerMetrics, HttpEndpointRules) {
  telemetry::Registry reg;
  reg.counter("t_total", "T.").inc(4);
  auto http = MetricsHttp::start("127.0.0.1:0", reg);
  ASSERT_TRUE(http && *http);
  const auto port = (*http)->port();
  const std::string ok = http_get(port, "GET /metrics HTTP/1.1\r\n\r\n");
  EXPECT_EQ(ok.rfind("HTTP/1.1 200 OK\r\n", 0), 0u);
  EXPECT_NE(ok.find("Connection: close"), std::string::npos);
  EXPECT_NE(ok.find("version=0.0.4"), std::string::npos);
  EXPECT_EQ(body_of(ok), "# HELP t_total T.\n# TYPE t_total counter\nt_total 4\n");
  EXPECT_EQ(http_get(port, "GET /other HTTP/1.1\r\n\r\n").rfind("HTTP/1.1 404", 0), 0u);
  EXPECT_EQ(http_get(port, "POST /metrics HTTP/1.1\r\n\r\n").rfind("HTTP/1.1 405", 0), 0u);
  // 8 KiB cap: a header block that never ends is cut off.
  EXPECT_EQ(http_get(port, "GET /metrics HTTP/1.1\r\nX: " + std::string(9000, 'a')).rfind("HTTP/1.1 431", 0), 0u);
  // Read timeout: a client that sends nothing gets 408 after about 2 s.
  EXPECT_EQ(http_get(port, "").rfind("HTTP/1.1 408", 0), 0u);
}

TEST(ServerMetrics, MaxFourConcurrentScrapes) {
  telemetry::Registry reg;
  auto http = MetricsHttp::start("127.0.0.1:0", reg);
  ASSERT_TRUE(http && *http);
  const auto port = (*http)->port();
  std::vector<int> idle;  // four clients that connect and say nothing hold the four slots
  for (int i = 0; i < 4; ++i) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    ASSERT_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa), 0);
    idle.push_back(fd);
  }
  EXPECT_EQ(http_get(port, "GET /metrics HTTP/1.1\r\n\r\n").rfind("HTTP/1.1 503", 0), 0u);
  for (int fd : idle) ::close(fd);
}

TEST(ServerMetrics, TelemetryConfig) {
  auto def = parse_node_config("[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n");
  ASSERT_TRUE(def);
  EXPECT_EQ(def->telemetry_listen, "127.0.0.1:9464");
  auto off = parse_node_config("[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n[telemetry]\nlisten = \"\"\n");
  ASSERT_TRUE(off);
  EXPECT_TRUE(off->telemetry_listen.empty());
  auto on = parse_node_config("[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n[telemetry]\nlisten = \"0.0.0.0:9500\"\n");
  ASSERT_TRUE(on);
  EXPECT_EQ(on->telemetry_listen, "0.0.0.0:9500");
  EXPECT_FALSE(parse_node_config("[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n[telemetry]\nlisten = \"nocolon\"\n"));
  EXPECT_FALSE(parse_node_config("[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n[telemetry]\nbogus = 1\n"));
}

// Seeded op mix; afterwards every looked-up key was a hit or a miss, and every put key ended as
// exactly one of committed / skipped / refused / aborted.
TEST(ServerMetrics, SimConservation) {
  for (std::uint64_t seed = 1; seed <= 12; ++seed) {
    Fx f;
    auto c = open_conns(f);
    SeededRandom r(seed);
    std::uint64_t looked_up = 0, puts = 0;
    for (int step = 0; step < 40; ++step) {
      if (r.next_u64() % 3 == 0) {
        std::vector<int> ks;
        for (std::uint64_t n = 1 + r.next_u64() % 4; n > 0; --n) ks.push_back(1 + static_cast<int>(r.next_u64() % 8));
        std::sort(ks.begin(), ks.end());
        ks.erase(std::unique(ks.begin(), ks.end()), ks.end());
        Reply lr = f.lookup(c.ctl, ks, r.next_u64() % 2 == 0);
        ASSERT_FALSE(lr.error());
        looked_up += ks.size();
      } else {
        const int k = 1 + static_cast<int>(r.next_u64() % 8);
        int parent = r.next_u64() % 2 ? 0 : 1 + static_cast<int>(r.next_u64() % 8);
        if (parent == k) parent = 0;
        const std::size_t len = 4096 + (r.next_u64() % 3) * 2048;
        ++puts;
        EXPECT_NE(do_put(f, c.ing, k, parent, len, r.next_u64() % 5 == 0), -2);
      }
    }
    const std::string t = render(*f.server);
    const double hit = series(t, "miracache_lookup_keys_total{result=\"hit\"}");
    const double miss = series(t, "miracache_lookup_keys_total{result=\"miss\"}");
    EXPECT_EQ(hit + miss, static_cast<double>(looked_up)) << "seed " << seed;
    double ops = 0, refused_by_reason = 0;
    for (const char* res : {"committed", "skipped", "refused", "aborted"})
      ops += series(t, std::string("miracache_put_ops_total{result=\"") + res + "\"}");
    for (const char* why : {"quota", "full", "class_cap", "conn_cap", "lease_cap", "other"})
      refused_by_reason += series(t, std::string("miracache_put_refused_total{reason=\"") + why + "\"}");
    EXPECT_EQ(ops, static_cast<double>(puts)) << "seed " << seed;
    EXPECT_EQ(refused_by_reason, series(t, "miracache_put_ops_total{result=\"refused\"}")) << "seed " << seed;
    EXPECT_TRUE(f.server->check_invariants());
  }
}

// ---- admin API: IssueTicket over HTTPS + mTLS (A2.1) -------------------------------------------
// Certs come from deploy/examples/lab-certs.sh (the openssl CLI) into a temp dir, once per test binary:
// `pki` is the lab CA with node-1, client-1, client-2; `rogue` is another CA with a client-1 of its own.
struct Certs {
  std::string root, pki, rogue;
  static void sh(const std::string& cmd) { EXPECT_EQ(std::system(cmd.c_str()), 0) << cmd; }
  Certs() {
    char t[] = "/tmp/mira-admin-XXXXXX";
    EXPECT_NE(::mkdtemp(t), nullptr);
    root = t;
    pki = root + "/pki";
    rogue = root + "/rogue";
    sh(std::string("bash ") + MIRACACHE_LAB_CERTS_SH + " " + pki + " --nodes 1 --clients 1,2 >/dev/null");
    sh(std::string("bash ") + MIRACACHE_LAB_CERTS_SH + " " + rogue + " --nodes 1 --clients 1 >/dev/null");
    // "multi": a client cert (lab CA) that carries two spiffe:// URI SANs (A09).
    sh("cd " + pki +
       " && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out multi.key 2>/dev/null"
       " && openssl req -new -key multi.key -subj /CN=multi -out multi.csr 2>/dev/null"
       " && printf 'basicConstraints=CA:FALSE\\nkeyUsage=critical,digitalSignature\\nextendedKeyUsage=clientAuth\\n"
       "subjectAltName=URI:spiffe://lab/client-1,URI:spiffe://lab/client-2\\n' > multi.ext"
       " && openssl x509 -req -in multi.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 30 -extfile multi.ext"
       " -out multi.pem 2>/dev/null && chmod 600 multi.key");
  }
  ~Certs() { sh("rm -rf " + root); }
  Certs(const Certs&) = delete;
};
const Certs& certs() {
  static const Certs c;
  return c;
}

struct Https {
  bool connected = false;
  std::string raw;
  int code() const { return raw.rfind("HTTP/1.1 ", 0) == 0 ? std::atoi(raw.c_str() + 9) : 0; }
  std::string body() const {
    const auto p = raw.find("\r\n\r\n");
    return p == std::string::npos ? "" : raw.substr(p + 4);
  }
};

int tcp_connect(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
  EXPECT_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa), 0);
  timeval tv{6, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  return fd;
}

// The test clients write through the no-SIGPIPE BIO too (review r9 S07): with SIGPIPE at its default, a stock socket BIO
// would kill the test process when the server closes first (a handshake budget missed on a loaded host).
void ssl_use_fd(SSL* ssl, int fd) {
  BIO* bio = new_nosigpipe_socket_bio(fd);  // the fd stays ours; SSL_free frees the BIO
  SSL_set_bio(ssl, bio, bio);
}

// A TLS 1.3 client. `who` = client cert name in `cert_dir` ("" = none); the server cert is checked against `ca_dir`/ca.pem.
Https tls_call(std::uint16_t port, const std::string& cert_dir, const std::string& who, const std::string& ca_dir,
               const std::string& req, int delay_ms = 0) {
  Https r;
  int fd = tcp_connect(port);
  if (delay_ms > 0) std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));  // a slow client: connected, silent
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  EXPECT_EQ(SSL_CTX_load_verify_locations(ctx, (ca_dir + "/ca.pem").c_str(), nullptr), 1);
  if (!who.empty()) {
    EXPECT_EQ(SSL_CTX_use_certificate_file(ctx, (cert_dir + "/" + who + ".pem").c_str(), SSL_FILETYPE_PEM), 1);
    EXPECT_EQ(SSL_CTX_use_PrivateKey_file(ctx, (cert_dir + "/" + who + ".key").c_str(), SSL_FILETYPE_PEM), 1);
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  SSL* ssl = SSL_new(ctx);
  ssl_use_fd(ssl, fd);
  if (SSL_connect(ssl) == 1) {
    r.connected = true;  // TLS 1.3: the server may still refuse our certificate after this point
    if (SSL_write(ssl, req.data(), static_cast<int>(req.size())) > 0) {
      char buf[2048];
      for (;;) {
        const int n = SSL_read(ssl, buf, sizeof buf);
        if (n <= 0) break;
        r.raw.append(buf, static_cast<std::size_t>(n));
      }
    }
  }
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  ::close(fd);
  ERR_clear_error();
  return r;
}

std::string post(const std::string& body, const std::string& path = "/v1/tickets", const char* method = "POST") {
  return std::string(method) + " " + path + " HTTP/1.1\r\nHost: x\r\nContent-Length: " + std::to_string(body.size()) +
         "\r\n\r\n" + body;
}

// Sum of the series of `name` whose line contains every fragment.
double metric(Server& s, const std::string& name, const std::vector<std::string>& frags = {}) {
  std::string text;
  s.metrics().write_prometheus(text);
  text = strip_node_id(text);
  double sum = 0;
  std::size_t pos = 0;
  while (pos < text.size()) {
    auto eol = text.find('\n', pos);
    if (eol == std::string::npos) eol = text.size();
    const std::string line = text.substr(pos, eol - pos);
    pos = eol + 1;
    if (line.rfind(name, 0) != 0 || (line.size() > name.size() && line[name.size()] != '{' && line[name.size()] != ' ')) continue;
    bool all = true;
    for (const auto& fr : frags) all = all && line.find(fr) != std::string::npos;
    if (all) sum += std::atof(line.c_str() + line.rfind(' ') + 1);
  }
  return sum;
}

struct IssuedTicket {
  std::string cls;
  proto::Ticket tk;
};
std::vector<IssuedTicket> parse_tickets(const std::string& body) {
  std::vector<IssuedTicket> out;
  for (std::size_t p = body.find("{\"class\":\""); p != std::string::npos; p = body.find("{\"class\":\"", p + 1)) {
    IssuedTicket it;
    const auto c0 = p + 10, c1 = body.find('"', c0);
    it.cls = body.substr(c0, c1 - c0);
    const auto i0 = body.find("\"id\":\"", c1) + 6;
    const std::string hex = body.substr(i0, 32);
    it.tk.cls = it.cls == "control" ? 0 : it.cls == "fetch" ? 1 : 2;
    for (int i = 0; i < 16; ++i)
      it.tk.id[i] = static_cast<std::uint8_t>(std::stoi(hex.substr(static_cast<std::size_t>(i) * 2, 2), nullptr, 16));
    out.push_back(it);
  }
  return out;
}

struct AdminFx {
  // hs_ms: the TLS handshake budget (review r9 S07); 0 = the real 300 ms. The tests that run with SIGPIPE at its
  // default give the handshake room on a loaded host, so a closed socket is a test failure, not noise.
  explicit AdminFx(std::uint32_t cap = 1024, std::uint32_t hs_ms = 0, std::uint32_t store_wait_ms = 0)
      : f(2, nullptr, nullptr, [cap](ServerConfig& c) {
          c.lab_identities = {"spiffe://lab/client-1"};
          c.ticket_max_per_identity = cap;
        }) {
    const auto& c = certs();
    AdminOptions ao{"127.0.0.1:0", c.pki + "/node-1.pem", c.pki + "/node-1.key", c.pki + "/ca.pem", 300};
    ao.node_id = f.server->node_id();  // plan 2C: the response names the node
    ao.hostname = "hostA";
    ao.handshake_ms_for_test = hs_ms;
    ao.store_wait_ms_for_test = store_wait_ms;
    auto a = AdminHttps::start(ao, f.server->metrics());
    EXPECT_TRUE(a && *a) << (a ? "" : a.error().context);
    if (a && *a) admin = std::move(*a);
  }
  // Runs `fn` on a client thread while this (the store) thread answers the admin mailbox.
  template <typename F>
  auto run(F fn) {
    auto fut = std::async(std::launch::async, fn);
    while (fut.wait_for(2ms) != std::future_status::ready) admin->pump(*f.server);
    return fut.get();
  }
  Https call(const std::string& body, const std::string& who = "client-1", const std::string& dir = "") {
    const auto& c = certs();
    const std::string d = dir.empty() ? c.pki : dir;
    const auto port = admin->port();
    const std::string pki = c.pki;
    return run([=] { return tls_call(port, d, who, pki, post(body)); });
  }
  Fx f;
  std::unique_ptr<AdminHttps> admin;
};

TEST(AdminJson, StrictParsing) {
  auto ok = parse_ticket_request(R"({"class":"fetch","rail":1,"count":4})");
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->classes.size(), 1u);
  EXPECT_EQ(ok->rail, 1);
  EXPECT_EQ(ok->count, 4u);
  auto batch = parse_ticket_request(R"( { "classes" : ["control","fetch","ingest"] , "count":64 } )");
  ASSERT_TRUE(batch);
  EXPECT_EQ(batch->classes.size(), 3u);
  EXPECT_EQ(batch->rail, 0);
  for (const char* bad : {"", "{", "[]", "null", R"({"class":"fetch"} x)", R"({"class":"fetch","bogus":1})",
                          R"({"class":"fetch","class":"fetch"})", R"({"class":"fetch","classes":["fetch"]})", R"({"count":1})",
                          R"({"class":"nope"})", R"({"class":"fetch","count":0})", R"({"class":"fetch","count":65})",
                          R"({"class":"fetch","count":01})", R"({"class":"fetch","count":1.5})", R"({"class":"fetch","count":-1})",
                          R"({"class":"fetch","count":"4"})", R"({"class":"fe\tch"})", R"({"classes":[]})",
                          R"({"classes":["fetch","fetch"]})", R"({"class":"fetch","rail":256})", R"({"class":"fetch",})"})
    EXPECT_FALSE(parse_ticket_request(bad)) << "[" << bad << "] " << std::strlen(bad);
}

TEST(AdminHttpsTest, NoClientCertIsRefused) {
  AdminFx a(1024, 5000);  // generous handshake budget (S07); production default unchanged
  const auto& c = certs();
  const auto port = a.admin->port();
  Https r = a.run([&] { return tls_call(port, c.pki, "", c.pki, post(R"({"class":"fetch"})")); });
  EXPECT_TRUE(r.raw.empty());  // no HTTP bytes: TLS 1.3 reports the refusal on the first read
  EXPECT_EQ(a.f.server->tickets().live(), 0u);
  // The worker counts the failure after the client already saw it: wait for the counter (no fixed margin).
  for (int i = 0; i < 1000 && metric(*a.f.server, "miracache_admin_tls_fail_total") < 1.0; ++i) std::this_thread::sleep_for(5ms);
  EXPECT_GE(metric(*a.f.server, "miracache_admin_tls_fail_total"), 1.0);
}

TEST(AdminHttpsTest, CertFromOtherCaIsRefused) {
  AdminFx a(1024, 5000);  // generous handshake budget (S07); production default unchanged
  Https r = a.call(R"({"class":"fetch"})", "client-1", certs().rogue);
  EXPECT_TRUE(r.raw.empty());
  EXPECT_EQ(a.f.server->tickets().live(), 0u);
  // The worker counts the failure after the client already saw it: wait for the counter (no fixed margin).
  for (int i = 0; i < 1000 && metric(*a.f.server, "miracache_admin_tls_fail_total") < 1.0; ++i) std::this_thread::sleep_for(5ms);
  EXPECT_GE(metric(*a.f.server, "miracache_admin_tls_fail_total"), 1.0);
}

TEST(AdminHttpsTest, IdentityNotInTableIs403) {
  AdminFx a(1024, 5000);  // generous handshake budget (S07); production default unchanged
  Https r = a.call(R"({"class":"fetch","count":2})", "client-2");  // valid cert, not in lab.identities
  EXPECT_EQ(r.code(), 403);
  EXPECT_EQ(a.f.server->tickets().live(), 0u);
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_requests_total", {"code=\"403\"", "path=\"/v1/tickets\""}), 1.0);
  EXPECT_EQ(metric(*a.f.server, "miracache_ticket_issue_fail_total", {"reason=\"unknown_identity\""}), 1.0);  // S02
  EXPECT_EQ(metric(*a.f.server, "miracache_ticket_reject_total"), 0.0);  // redeem refusals only
}

TEST(AdminHttpsTest, GoodIdentityGetsSingleUseTickets) {
  AdminFx a(1024, 5000);  // generous handshake budget (S07); production default unchanged
  Https r = a.call(R"({"classes":["control","fetch","ingest"],"rail":0,"count":2})");
  ASSERT_EQ(r.code(), 200) << r.raw;
  EXPECT_NE(r.raw.find("Connection: close"), std::string::npos);
  EXPECT_EQ(r.body().rfind("{\"ttl_s\":300,\"tickets\":[", 0), 0u);
  // Plan 2C: the response also names the answering node (additive fields after "tickets").
  EXPECT_NE(a.f.server->node_id(), 0u);
  EXPECT_NE(r.body().find("],\"node_id\":" + std::to_string(a.f.server->node_id()) + ",\"hostname\":\"hostA\"}"),
            std::string::npos)
      << r.body();
  auto tks = parse_tickets(r.body());
  ASSERT_EQ(tks.size(), 6u);
  EXPECT_EQ(a.f.server->tickets().live_for("spiffe://lab/client-1"), 6u);
  EXPECT_EQ(metric(*a.f.server, "miracache_ticket_issued_total"), 6.0);
  // A control ticket from the admin API lets a HELLO through exactly once.
  const IssuedTicket* ctl = nullptr;
  for (const auto& t : tks)
    if (t.cls == "control") ctl = &t;
  ASSERT_NE(ctl, nullptr);
  auto ep = a.f.connect_with(ctl->tk, fabric::EpClass::Control);
  ASSERT_TRUE(ep);
  a.f.hello(*ep, fabric::EpClass::Control);
  EXPECT_FALSE(a.f.connect_with(ctl->tk, fabric::EpClass::Control));  // reuse refused
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_requests_total", {"code=\"200\""}), 1.0);
  // The single-class form.
  Https one = a.call(R"({"class":"ingest","rail":0,"count":1})");
  ASSERT_EQ(one.code(), 200);
  ASSERT_EQ(parse_tickets(one.body()).size(), 1u);
  // The ticket is a bearer secret: it must not appear in /metrics.
  std::string text;
  a.f.server->metrics().write_prometheus(text);
  EXPECT_EQ(text.find(r.body().substr(r.body().find("\"id\":\"") + 6, 32)), std::string::npos);
}

TEST(AdminHttpsTest, PerIdentityCapIs429) {
  AdminFx a(4, 5000);
  ASSERT_EQ(a.call(R"({"class":"control","count":4})").code(), 200);
  Https r = a.call(R"({"class":"control","count":1})");
  EXPECT_EQ(r.code(), 429);
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_requests_total", {"code=\"429\""}), 1.0);
  EXPECT_EQ(metric(*a.f.server, "miracache_ticket_issue_fail_total", {"reason=\"limit\""}), 1.0);  // S02
  EXPECT_EQ(metric(*a.f.server, "miracache_ticket_reject_total"), 0.0);
}

TEST(AdminHttpsTest, MalformedAndUnknownFieldsAre400) {
  AdminFx a(1024, 5000);  // generous handshake budget (S07); production default unchanged
  for (const char* body : {"", "not json", R"({"class":"fetch","extra":1})", R"({"class":"fetch","count":65})",
                           R"({"class":"fetch","rail":9})" /* the table rejects rail >= 4 */})
    EXPECT_EQ(a.call(body).code(), 400) << body;
  EXPECT_EQ(a.f.server->tickets().live(), 0u);
}

TEST(AdminHttpsTest, RoutingAndLimits) {
  AdminFx a(1024, 5000);  // generous handshake budget (S07); production default unchanged
  const auto& c = certs();
  const auto port = a.admin->port();
  auto raw = [&](const std::string& req) { return a.run([&] { return tls_call(port, c.pki, "client-1", c.pki, req); }); };
  EXPECT_EQ(raw(post("{}", "/v1/other")).code(), 404);
  EXPECT_EQ(raw(post("", "/v1/tickets", "GET")).code(), 405);
  EXPECT_EQ(raw(post(std::string(9000, ' '))).code(), 413);  // over the 8 KiB cap
  EXPECT_EQ(raw("POST /v1/tickets HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").code(), 400);
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_requests_total", {"code=\"404\"", "path=\"other\""}), 1.0);
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_requests_total", {"code=\"405\""}), 1.0);
}

// ---- r4 helpers: raw sockets from chosen source addresses, a TLS client that can reset -----------
int tcp_connect_from(std::uint16_t port, const char* src) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in me{};
  me.sin_family = AF_INET;
  ::inet_pton(AF_INET, src, &me.sin_addr);
  EXPECT_EQ(::bind(fd, reinterpret_cast<sockaddr*>(&me), sizeof me), 0) << src;
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
  EXPECT_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa), 0);
  timeval tv{6, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  return fd;
}

struct TlsConn {
  SSL_CTX* ctx = nullptr;
  SSL* ssl = nullptr;
  int fd = -1;
  bool ok = false;
};
// Connects and completes the TLS handshake as `who` (blocking). Sends nothing else.
TlsConn tls_open(std::uint16_t port, const std::string& who = "client-1") {
  TlsConn c;
  const auto& ce = certs();
  c.fd = tcp_connect(port);
  c.ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(c.ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(c.ctx, TLS1_3_VERSION);
  EXPECT_EQ(SSL_CTX_load_verify_locations(c.ctx, (ce.pki + "/ca.pem").c_str(), nullptr), 1);
  EXPECT_EQ(SSL_CTX_use_certificate_file(c.ctx, (ce.pki + "/" + who + ".pem").c_str(), SSL_FILETYPE_PEM), 1);
  EXPECT_EQ(SSL_CTX_use_PrivateKey_file(c.ctx, (ce.pki + "/" + who + ".key").c_str(), SSL_FILETYPE_PEM), 1);
  SSL_CTX_set_verify(c.ctx, SSL_VERIFY_PEER, nullptr);
  c.ssl = SSL_new(c.ctx);
  ssl_use_fd(c.ssl, c.fd);
  c.ok = SSL_connect(c.ssl) == 1;
  return c;
}
void tls_free(TlsConn& c) {
  if (c.ssl) SSL_free(c.ssl);
  if (c.ctx) SSL_CTX_free(c.ctx);
  if (c.fd >= 0) ::close(c.fd);
  c = TlsConn{};
  ERR_clear_error();
}
// Drops the connection with a TCP RST (SO_LINGER 0), without a TLS close_notify.
void tls_reset(TlsConn& c) {
  linger lg{1, 0};
  ::setsockopt(c.fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
  tls_free(c);
}
// A mid-handshake peer: sends a ClientHello, then resets before reading the server's flight.
void hello_then_reset(std::uint16_t port) {
  int fd = tcp_connect(port);
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL* ssl = SSL_new(ctx);
  ssl_use_fd(ssl, fd);
  ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
  (void)SSL_connect(ssl);  // writes the ClientHello, then wants the ServerHello
  linger lg{1, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  ::close(fd);
  ERR_clear_error();
}

long ms_since(std::chrono::steady_clock::time_point t0) {
  return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
}

TEST(AdminHttpsTest, SlowlorisHandshakeClosedWithinHandshakeBudget) {  // A02: the budget, not 2 s
  AdminFx a(1024, 300);  // the mechanism at a short budget (production default: 1500 ms)
  int fd = tcp_connect(a.admin->port());  // connects, sends nothing
  const auto t0 = std::chrono::steady_clock::now();
  char b;
  EXPECT_LE(::recv(fd, &b, 1, 0), 0);  // EOF when the server gives up
  const auto ms = ms_since(t0);
  EXPECT_GE(ms, 200);
  EXPECT_LE(ms, 900);
  ::close(fd);
  // The worker counts the failure after the client already saw it: wait for the counter (no fixed margin).
  for (int i = 0; i < 1000 && metric(*a.f.server, "miracache_admin_tls_fail_total") < 1.0; ++i) std::this_thread::sleep_for(5ms);
  EXPECT_GE(metric(*a.f.server, "miracache_admin_tls_fail_total"), 1.0);
}

TEST(AdminHttpsTest, RequestBudgetIsSeparateFromHandshake) {  // A02
  AdminFx a;
  const auto port = a.admin->port();
  Https r = a.run([&] {
    Https h;
    TlsConn c = tls_open(port);
    if (!c.ok) return h;
    std::this_thread::sleep_for(600ms);  // longer than the whole handshake budget
    const std::string req = post(R"({"class":"fetch"})");
    if (SSL_write(c.ssl, req.data(), static_cast<int>(req.size())) > 0) {
      char buf[2048];
      for (;;) {
        const int n = SSL_read(c.ssl, buf, sizeof buf);
        if (n <= 0) break;
        h.raw.append(buf, static_cast<std::size_t>(n));
      }
    }
    tls_free(c);
    return h;
  });
  EXPECT_EQ(r.code(), 200) << r.raw;
}

TEST(AdminHttpsTest, IdleConnectionsDoNotStarveRealClients) {  // A02
  AdminFx a(1024, 300);  // short test budget (production default: 1500 ms)
  const auto port = a.admin->port();
  std::vector<int> idle;  // 8 workers held: four source addresses x the per-IP limit of 2
  for (const char* ip : {"127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5"})
    for (int i = 0; i < 2; ++i) idle.push_back(tcp_connect_from(port, ip));
  std::this_thread::sleep_for(100ms);
  {  // a 9th connection is over the cap: closed at once, no TLS on the accept thread
    int extra = tcp_connect_from(port, "127.0.0.6");
    const auto t0 = std::chrono::steady_clock::now();
    char b;
    EXPECT_LE(::recv(extra, &b, 1, 0), 0);
    EXPECT_LT(ms_since(t0), 250);
    ::close(extra);
  }
  struct sigaction ign {}, old {};
  ign.sa_handler = SIG_IGN;
  ::sigaction(SIGPIPE, &ign, &old);  // the TEST client may write to a socket the server already closed
  const auto t0 = std::chrono::steady_clock::now();
  Https r;
  for (;;) {  // the real client retries (its tick is 1 s); the idle ones are gone after the handshake budget
    r = a.call(R"({"class":"fetch","count":4})");
    if (r.code() == 200 || ms_since(t0) > 1000) break;
    std::this_thread::sleep_for(50ms);
  }
  EXPECT_EQ(r.code(), 200) << r.raw;
  EXPECT_LT(ms_since(t0), 1000);
  EXPECT_EQ(parse_tickets(r.body()).size(), 4u);
  EXPECT_GE(metric(*a.f.server, "miracache_admin_conn_rejected_total", {"reason=\"busy\""}), 1.0);
  for (int fd : idle) ::close(fd);
  ::sigaction(SIGPIPE, &old, nullptr);
}

TEST(AdminHttpsTest, PerSourceIpLimit) {  // A02
  AdminFx a;
  const auto port = a.admin->port();
  int c1 = tcp_connect_from(port, "127.0.0.2");
  int c2 = tcp_connect_from(port, "127.0.0.2");
  int c3 = tcp_connect_from(port, "127.0.0.2");
  const auto t0 = std::chrono::steady_clock::now();
  char b;
  EXPECT_LE(::recv(c3, &b, 1, 0), 0);  // the third from one address is closed at once
  EXPECT_LT(ms_since(t0), 250);
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_conn_rejected_total", {"reason=\"per_ip\""}), 1.0);
  for (int fd : {c1, c2, c3}) ::close(fd);
}

TEST(AdminHttpsTest, ResetAfterRequestCannotKillTheServer) {  // A01: SIGPIPE is at its default here
  AdminFx a(1024, 5000);  // S07: a roomy handshake budget; the client writes through the no-SIGPIPE BIO
  struct sigaction dfl {}, old {};
  dfl.sa_handler = SIG_DFL;
  ::sigaction(SIGPIPE, &dfl, &old);  // the listener must not depend on main() ignoring SIGPIPE
  for (int i = 0; i < 3; ++i) {
    TlsConn c = tls_open(a.admin->port());
    ASSERT_TRUE(c.ok);
    const std::string req = post(R"({"class":"fetch"})");
    ASSERT_GT(SSL_write(c.ssl, req.data(), static_cast<int>(req.size())), 0);
    tls_reset(c);  // RST before the reply: the reply and the shutdown both write to a dead socket
    std::this_thread::sleep_for(100ms);
    for (int k = 0; k < 15; ++k) {  // now answer: the worker's writes hit the reset connection
      a.admin->pump(*a.f.server);
      std::this_thread::sleep_for(20ms);
    }
  }
  Https r = a.call(R"({"class":"fetch"})");
  EXPECT_EQ(r.code(), 200) << r.raw;  // still alive and serving
  ::sigaction(SIGPIPE, &old, nullptr);
}

TEST(AdminHttpsTest, TlsBioNeverRaisesSigpipe) {  // A01, deterministic: writes to a reset socket, SIGPIPE at default
  int ls = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
  ASSERT_EQ(::bind(ls, reinterpret_cast<sockaddr*>(&sa), sizeof sa), 0);
  ASSERT_EQ(::listen(ls, 1), 0);
  socklen_t sl = sizeof sa;
  ASSERT_EQ(::getsockname(ls, reinterpret_cast<sockaddr*>(&sa), &sl), 0);
  int cli = ::socket(AF_INET, SOCK_STREAM, 0);
  ASSERT_EQ(::connect(cli, reinterpret_cast<sockaddr*>(&sa), sizeof sa), 0);
  int srv = ::accept(ls, nullptr, nullptr);
  ASSERT_GE(srv, 0);
  linger lg{1, 0};
  ::setsockopt(cli, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
  ::close(cli);  // RST
  std::this_thread::sleep_for(50ms);
  struct sigaction dfl {}, old {};
  dfl.sa_handler = SIG_DFL;
  ::sigaction(SIGPIPE, &dfl, &old);
  BIO* bio = new_nosigpipe_socket_bio(srv);
  ASSERT_NE(bio, nullptr);
  char buf[16] = "hello";
  for (int i = 0; i < 4; ++i) EXPECT_LE(BIO_write(bio, buf, 5), 0);  // errors, and the process is still here
  BIO_free(bio);
  ::sigaction(SIGPIPE, &old, nullptr);
  ::close(srv);
  ::close(ls);
  ERR_clear_error();
}

TEST(AdminHttpsTest, ResetMidHandshakeCannotKillTheServer) {  // A01
  AdminFx a(1024, 5000);
  struct sigaction dfl {}, old {};
  dfl.sa_handler = SIG_DFL;
  ::sigaction(SIGPIPE, &dfl, &old);
  for (int i = 0; i < 6; ++i) {
    hello_then_reset(a.admin->port());
    std::this_thread::sleep_for(30ms);
  }
  std::this_thread::sleep_for(300ms);
  Https r = a.call(R"({"class":"fetch"})");
  EXPECT_EQ(r.code(), 200) << r.raw;
  ::sigaction(SIGPIPE, &old, nullptr);
}

TEST(AdminHttpsTest, StopIsPromptWithBusyConnections) {  // A07: SIGHUP rebinds on the store thread
  AdminFx a;
  TlsConn c1 = tls_open(a.admin->port());
  TlsConn c2 = tls_open(a.admin->port());
  ASSERT_TRUE(c1.ok && c2.ok);
  std::this_thread::sleep_for(100ms);  // both workers now wait for a request (2 s budget)
  const auto t0 = std::chrono::steady_clock::now();
  a.admin.reset();
  EXPECT_LT(ms_since(t0), 400);
  tls_free(c1);
  tls_free(c2);
}

TEST(AdminHttpsTest, BatchOverTheCapIssuesNothing) {  // A08
  AdminFx a(4, 5000);
  Https r = a.call(R"({"classes":["control","fetch","ingest"],"count":2})");  // 6 > cap 4
  EXPECT_EQ(r.code(), 429) << r.raw;
  EXPECT_EQ(a.f.server->tickets().live(), 0u) << "earlier classes of the failed batch stayed live";
  EXPECT_EQ(a.f.server->tickets().live_for("spiffe://lab/client-1"), 0u);
}

TEST(AdminHttpsTest, TwoSpiffeSansAre403) {  // A09 (server side)
  AdminFx a(1024, 5000);  // generous handshake budget (S07); production default unchanged
  Https r = a.call(R"({"class":"fetch"})", "multi");  // one cert carrying spiffe://lab/client-1 and client-2
  EXPECT_EQ(r.code(), 403) << r.raw;
  EXPECT_EQ(a.f.server->tickets().live(), 0u);
}

TEST(MetricsHttpTest, StopIsPromptAndPortIsParsedStrictly) {  // A07, M03
  telemetry::Registry reg;
  EXPECT_FALSE(MetricsHttp::start("127.0.0.1:12abc", reg));  // atoi would have taken 12
  EXPECT_FALSE(MetricsHttp::start("127.0.0.1:70000", reg));
  auto http = MetricsHttp::start("127.0.0.1:0", reg);
  ASSERT_TRUE(http && *http);
  std::vector<int> idle;
  for (int i = 0; i < 3; ++i) idle.push_back(tcp_connect((*http)->port()));
  std::this_thread::sleep_for(100ms);
  const auto t0 = std::chrono::steady_clock::now();
  (*http).reset();
  EXPECT_LT(ms_since(t0), 400);
  for (int fd : idle) ::close(fd);
}

TEST(NetUtil, PollRetrySurvivesSignals) {  // A06: a SIGHUP must not turn into a timeout
  struct sigaction sa {}, old {};
  sa.sa_handler = [](int) {};
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;  // no SA_RESTART: poll() returns EINTR
  ::sigaction(SIGALRM, &sa, &old);
  int sv[2];
  ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
  itimerval it{};
  it.it_value.tv_usec = 40000;
  ::setitimer(ITIMER_REAL, &it, nullptr);
  pollfd p{sv[0], POLLIN, 0};
  EXPECT_EQ(net::poll_retry(&p, 1, 150), 0);  // plain poll() would have returned -1 (EINTR)
  ::sigaction(SIGALRM, &old, nullptr);
  ::close(sv[0]);
  ::close(sv[1]);
}

TEST(ServerReload, LabIdentitiesFollowTheConfig) {  // A04
  Fx f(2, nullptr, nullptr, [](ServerConfig& c) { c.lab_identities = {"spiffe://lab/client-1"}; });
  const auto C = fabric::EpClass::Control;
  ASSERT_TRUE(f.server->issue_ticket("spiffe://lab/client-1", C, 0, 2));
  EXPECT_FALSE(f.server->issue_ticket("spiffe://lab/client-3", C, 0, 1));
  f.server->reload_identities("lab", {"spiffe://lab/client-3"}, 5);  // client-1 removed, client-3 added
  EXPECT_EQ(f.server->tickets().live_for("spiffe://lab/client-1"), 0u);  // its tickets were revoked
  EXPECT_FALSE(f.server->issue_ticket("spiffe://lab/client-1", C, 0, 1));
  EXPECT_TRUE(f.server->issue_ticket("spiffe://lab/client-3", C, 0, 1));
  EXPECT_TRUE(f.server->issue_ticket("lab", C, 0, 1));  // lab.principal is untouched
  f.server->reload_identities("lab", {}, 5);
  EXPECT_FALSE(f.server->issue_ticket("spiffe://lab/client-3", C, 0, 1));
}


TEST(AdminHttpsTest, KeyFileMustBe0600) {
  const auto& c = certs();
  telemetry::Registry reg;
  const AdminOptions o{"127.0.0.1:0", c.pki + "/node-1.pem", c.pki + "/node-1.key", c.pki + "/ca.pem", 300};
  ASSERT_EQ(::chmod((c.pki + "/node-1.key").c_str(), 0640), 0);
  EXPECT_FALSE(AdminHttps::start(o, reg));
  ASSERT_EQ(::chmod((c.pki + "/node-1.key").c_str(), 0400), 0);  // the client demands exactly 0600; so do we
  EXPECT_FALSE(AdminHttps::start(o, reg));
  ASSERT_EQ(::chmod((c.pki + "/node-1.key").c_str(), 0600), 0);
  auto good = AdminHttps::start(o, reg);
  ASSERT_TRUE(good && *good);
  auto off = AdminHttps::start(AdminOptions{}, reg);  // empty listen = off
  ASSERT_TRUE(off);
  EXPECT_EQ(off->get(), nullptr);
  // A reload with a bad key keeps the old credentials.
  ASSERT_EQ(::chmod((c.pki + "/node-1.key").c_str(), 0644), 0);
  EXPECT_FALSE((*good)->reload_credentials(o));
  ASSERT_EQ(::chmod((c.pki + "/node-1.key").c_str(), 0600), 0);
  EXPECT_TRUE((*good)->reload_credentials(o));
}

TEST(AdminHttpsTest, AdminConfig) {
  const std::string base = "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n";
  auto def = parse_node_config(base);
  ASSERT_TRUE(def);
  EXPECT_TRUE(def->admin_listen.empty());  // default off
  auto on = parse_node_config(base + "[lab]\nprincipal = \"lab\"\nidentities = [\"spiffe://lab/client-1\", \"spiffe://lab/client-2\"]\n"
                                     "[admin]\nlisten = \"0.0.0.0:9465\"\ncert = \"/c\"\nkey = \"/k\"\nca = \"/ca\"\n");
  ASSERT_TRUE(on);
  EXPECT_EQ(on->admin_listen, "0.0.0.0:9465");
  EXPECT_EQ(on->admin_ca, "/ca");
  EXPECT_EQ(on->admin_max_conns, 8u);  // default
  const std::string adm = "[admin]\nlisten = \"0.0.0.0:9465\"\ncert = \"/c\"\nkey = \"/k\"\nca = \"/ca\"\n";
  auto many = parse_node_config(base + adm + "max_conns = 16\n");
  ASSERT_TRUE(many);
  EXPECT_EQ(many->admin_max_conns, 16u);
  EXPECT_FALSE(parse_node_config(base + adm + "max_conns = 0\n"));
  EXPECT_FALSE(parse_node_config(base + adm + "max_conns = 5000\n"));
  EXPECT_EQ(on->server.lab_identities.size(), 2u);
  EXPECT_FALSE(parse_node_config(base + "[admin]\nlisten = \"0.0.0.0:9465\"\n"));  // needs cert, key, ca
  EXPECT_FALSE(parse_node_config(base + "[admin]\nlisten = \"nocolon\"\ncert = \"a\"\nkey = \"b\"\nca = \"c\"\n"));
  EXPECT_FALSE(parse_node_config(base + "[admin]\nbogus = 1\n"));
  EXPECT_FALSE(parse_node_config(base + "[lab]\nidentities = [\"x\"]\n"));  // needs lab.principal
  EXPECT_FALSE(parse_node_config(base + "[lab]\nprincipal = \"p\"\nidentities = [1]\n"));
}


// A block longer than store.run_bytes can never be placed: PUT_BEGIN is refused at once with a Malformed error reply, the
// node counts it (miracache_put_too_large_total) and logs it; a block of exactly run_bytes still goes through.
TEST(ServerWire, BlockLargerThanRunIsRefusedAtOnceAndCounted) {
  Fx f;
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ing);
  f.hello(*ing, fabric::EpClass::Ingest, 1);
  const std::size_t run = 256u << 10;  // the fixture's run_bytes (line 53)
  auto m = std::make_unique<proto::PutBegin>();  // by hand: put_begin() waits for an ACK, this one answers with an error
  std::memcpy(m->scope_id, Fx::scope().data(), 32);
  m->n = 1;
  std::memcpy(m->e[0].key_hash, Fx::key(1).data(), 32);
  m->e[0].stored_len = run + 4096;
  f.send(*ing, Op::PUT_BEGIN, 41, *m, [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); });
  Reply big = f.next(*ing);
  EXPECT_TRUE(big.error());
  EXPECT_EQ(big.err_status(), proto::WireStatus::Malformed);
  EXPECT_EQ(series(render(*f.server), "miracache_put_too_large_total"), 1.0);
  EXPECT_EQ(f.server->puts().n_puts(), 0u);
  Reply ok = f.put_begin(*ing, 2, 0, run);
  EXPECT_FALSE(ok.error());
  EXPECT_EQ(series(render(*f.server), "miracache_put_too_large_total"), 1.0);
}

// Review s9 K03: every HELLO_ACK carries the node's largest stored block (TLV 0x0003 = store.run_bytes) behind the boot
// nonce, both non-critical (CRITICAL_EXT clear: an older client skips them).
TEST(ServerWire, HelloAckCarriesTheMaxStoredBlock) {
  Fx f;
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ing);
  proto::Hello h;
  h.cls = static_cast<std::uint8_t>(fabric::EpClass::Ingest);
  std::memset(h.conn_id, 1, 16);
  f.send(*ing, Op::HELLO, 1, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
  Reply a = f.next_of(*ing, Op::HELLO_ACK);
  ASSERT_EQ(a.h.type, static_cast<std::uint16_t>(Op::HELLO_ACK));
  EXPECT_EQ(a.h.flags & proto::flag::CRITICAL_EXT, 0);
  auto d = proto::decode_hello_ack(a.h, a.body);
  ASSERT_TRUE(d);
  const std::string host = log::hostname();  // F5: the node's own hostname, as its log lines carry it
  EXPECT_EQ(d->tlvs.size(), proto::kBootNonceTlvSize + proto::kMaxStoredBlockTlvSize + ((4 + host.size() + 7) / 8) * 8);
  EXPECT_EQ(proto::find_hostname(d->tlvs), host);
  ASSERT_TRUE(proto::find_max_stored_block(d->tlvs).has_value());
  EXPECT_EQ(*proto::find_max_stored_block(d->tlvs), 256u << 10);  // the fixture's run_bytes
  EXPECT_EQ(proto::find_boot_nonce(d->tlvs), f.server->boot_nonce());
}

// The log lines written while it lives (log::set_sink_fd to a temporary file).
struct LogCapture {
  LogCapture() : f(std::tmpfile()) {
    if (f) log::set_sink_fd(fileno(f));
  }
  ~LogCapture() {
    log::set_sink_fd(2);
    if (f) std::fclose(f);
  }
  std::string text() const {
    std::string s;
    if (!f) return s;
    char buf[4096];
    for (off_t off = 0;;) {
      const ssize_t k = pread(fileno(f), buf, sizeof buf, off);
      if (k <= 0) break;
      s.append(buf, static_cast<std::size_t>(k));
      off += k;
    }
    return s;
  }
  std::FILE* f;
};
std::size_t count_of(const std::string& text, const std::string& what) {
  std::size_t n = 0;
  for (std::size_t p = text.find(what); p != std::string::npos; p = text.find(what, p + 1)) ++n;
  return n;
}

// Run #272 (Q15): the admin server's time budgets. A client that is slow within the budget succeeds; beyond it the
// failure is counted and logged with its cause and the client's address.
TEST(AdminHttpsTest, DefaultBudgetsAreAboveTheOldTightValues) {
  EXPECT_GE(AdminHttps::kHandshakeMs, 1000);
  EXPECT_GE(AdminHttps::kStoreWaitMs, 1000);
  EXPECT_LE(AdminHttps::kHandshakeMs, 2000);  // the client's whole-call budget is 2 s: more only holds a thread for nobody
}

TEST(AdminHttpsTest, SlowHandshakeWithinBudgetSucceeds) {
  AdminFx a(1024, 1500);
  const auto& c = certs();
  const auto port = a.admin->port();
  Https r = a.run([&] { return tls_call(port, c.pki, "client-1", c.pki, post(R"({"class":"fetch"})"), 400); });
  EXPECT_EQ(r.code(), 200);
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_budget_expired_total", {"cause=\"handshake_timeout\""}), 0.0);
}

TEST(AdminHttpsTest, SlowHandshakeBeyondBudgetFailsWithNamedCause) {
  LogCapture cap;
  AdminFx a(1024, 300);
  const auto& c = certs();
  const auto port = a.admin->port();
  Https r = a.run([&] { return tls_call(port, c.pki, "client-1", c.pki, post(R"({"class":"fetch"})"), 900); });
  EXPECT_TRUE(r.raw.empty());
  EXPECT_EQ(a.f.server->tickets().live(), 0u);
  for (int i = 0; i < 1000 && metric(*a.f.server, "miracache_admin_budget_expired_total", {"cause=\"handshake_timeout\""}) < 1.0; ++i)
    std::this_thread::sleep_for(5ms);
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_budget_expired_total", {"cause=\"handshake_timeout\""}), 1.0);
  const std::string t = cap.text();
  EXPECT_NE(t.find("cause=handshake_timeout"), std::string::npos) << t;
  EXPECT_NE(t.find("client=127.0.0.1:"), std::string::npos) << t;
  EXPECT_NE(t.find("budget_ms=300"), std::string::npos) << t;
}

TEST(AdminHttpsTest, SlowStoreThreadWithinBudgetSucceeds) {
  AdminFx a(1024, 5000, 1500);
  const auto& c = certs();
  const auto port = a.admin->port();
  auto fut = std::async(std::launch::async, [&] { return tls_call(port, c.pki, "client-1", c.pki, post(R"({"class":"fetch"})")); });
  std::this_thread::sleep_for(400ms);  // the store thread is busy: it does not pump for a while
  while (fut.wait_for(2ms) != std::future_status::ready) a.admin->pump(*a.f.server);
  EXPECT_EQ(fut.get().code(), 200);
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_budget_expired_total", {"cause=\"store_thread_busy\""}), 0.0);
}

TEST(AdminHttpsTest, SlowStoreThreadBeyondBudgetIs504WithNamedCause) {
  LogCapture cap;
  AdminFx a(1024, 5000, 300);
  const auto& c = certs();
  const auto port = a.admin->port();
  auto fut = std::async(std::launch::async, [&] { return tls_call(port, c.pki, "client-1", c.pki, post(R"({"class":"fetch"})")); });
  std::this_thread::sleep_for(900ms);
  while (fut.wait_for(2ms) != std::future_status::ready) a.admin->pump(*a.f.server);
  EXPECT_EQ(fut.get().code(), 504);
  EXPECT_EQ(a.f.server->tickets().live(), 0u);  // abandoned: nothing was issued
  EXPECT_EQ(metric(*a.f.server, "miracache_admin_budget_expired_total", {"cause=\"store_thread_busy\""}), 1.0);
  const std::string t = cap.text();
  EXPECT_NE(t.find("cause=store_thread_busy"), std::string::npos) << t;
  EXPECT_NE(t.find("client=127.0.0.1:"), std::string::npos) << t;
}

// Review s9 K10: the too-large WARN is rate-limited per (principal, size class): one line per minute, carrying the
// principal, the client identity, the peer and the refusals dropped since; the counter still counts every refusal.
TEST(ServerWire, TooLargeWarnIsRateLimitedPerPrincipalAndSizeClass) {
  Fx f;
  auto ing = f.connect(fabric::EpClass::Ingest);
  ASSERT_TRUE(ing);
  f.hello(*ing, fabric::EpClass::Ingest, 1);
  const std::size_t run = 256u << 10;
  auto refuse = [&](std::uint64_t rid, std::uint64_t len) {
    auto m = std::make_unique<proto::PutBegin>();
    std::memcpy(m->scope_id, Fx::scope().data(), 32);
    m->n = 1;
    std::memcpy(m->e[0].key_hash, Fx::key(1).data(), 32);
    m->e[0].stored_len = len;
    f.send(*ing, Op::PUT_BEGIN, rid, *m, [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); });
    Reply r = f.next(*ing);
    EXPECT_TRUE(r.error());
    EXPECT_EQ(r.err_status(), proto::WireStatus::Malformed);
  };
  const std::string msg = "PUT_BEGIN refused: block larger than store.run_bytes";
  LogCapture cap;
  for (std::uint64_t i = 0; i < 5; ++i) refuse(50 + i, run + 4096);  // one size class (2^19 bucket)
  std::string t = cap.text();
  EXPECT_EQ(count_of(t, msg), 1u) << t;
  EXPECT_NE(t.find("principal="), std::string::npos) << t;
  EXPECT_NE(t.find("identity="), std::string::npos) << t;
  EXPECT_NE(t.find("peer="), std::string::npos) << t;
  EXPECT_NE(t.find("suppressed=0"), std::string::npos) << t;
  refuse(60, 4 * run);  // another size class: its own first line
  t = cap.text();
  EXPECT_EQ(count_of(t, msg), 2u) << t;
  f.clock.advance_by(61s);
  refuse(61, run + 4096);  // the first class again after the interval: logged, with the 4 dropped since
  t = cap.text();
  EXPECT_EQ(count_of(t, msg), 3u) << t;
  EXPECT_NE(t.find("suppressed=4"), std::string::npos) << t;
  EXPECT_EQ(series(render(*f.server), "miracache_put_too_large_total"), 7.0);
}

}  // namespace
}  // namespace miracache::server
