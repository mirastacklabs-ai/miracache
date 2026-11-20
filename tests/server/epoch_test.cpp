// SPDX-License-Identifier: Apache-2.0
// Epoch and owner-set enforcement on the memory node, through wire frames
// over SimFabric. One test per refusal reason, the owner-set check with R = 2 and zones, GOAWAY on removal, a
// re-added node serving again, lab mode untouched, and client-vs-server agreement over the golden placement
// files (the client computes owner_set(view_from_bundle(...)); the server must reach the same answer).
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include "control/bundle.h"
#include "control/view.h"
#include "src/client.h"
#include "fabric/sim/sim_fabric.h"
#include "server/server.h"
#include "util/clock.h"
#include "util/crc32c.h"
#include "util/executor.h"
#include "util/random.h"

namespace miracache::server {
namespace {

using namespace std::chrono_literals;
using control::MemberState;
using proto::Op;
using proto::WireStatus;

constexpr const char* kIdentity = "spiffe://p/a";

store::StoreConfig store_cfg() {
  store::StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.principal_default.max_scopes = 64;
  c.principal_default.max_bytes = 8u << 20;
  c.principal_default.idle_ttl = std::chrono::seconds(10000);
  c.invalidate_per_s = 0;
  return c;
}

struct Reply {
  proto::FrameHeader h;
  std::vector<std::byte> body;
  bool error() const { return (h.flags & proto::flag::ERROR) != 0; }
  WireStatus err_status() const {
    auto e = proto::decode_error_reply(h, body);
    return e ? static_cast<WireStatus>(e->status) : WireStatus::Corrupt;
  }
  std::uint32_t retry_ms() const {
    auto e = proto::decode_error_reply(h, body);
    return e ? e->retry_after_ms : 0;
  }
};

control::NodeView nview(std::uint32_t id, MemberState st = MemberState::Active, std::optional<std::string> zone = std::nullopt,
                        std::uint32_t weight = 1) {
  control::NodeView n;
  n.node_id = id;
  n.hostname = "host" + std::to_string(id);
  n.admin = "10.0.0." + std::to_string(id % 200) + ":9465";
  n.rails.push_back({"10.0.0.1:7471", "a", "roce"});
  n.weight = weight;
  n.zone = std::move(zone);
  n.state = st;
  return n;
}

struct Fx {
  explicit Fx(bool lab = false) : rng(3), net(clock, rng, {}, {}), srv_fab(net.add_node(1)), cli(net.add_node(2)) {
    ServerConfig sc;
    sc.store = store_cfg();
    sc.goaway_drain_ms = 1234;
    if (lab) {
      sc.lab_identity = kIdentity;
      sc.lab_principal = 5;
    }
    auto s = Server::create(sc, srv_fab, clock, rng, exec);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
    EXPECT_TRUE(server->start());
    self = server->node_id();
    cbuf.assign(1 << 16, std::byte{0});
    cmr = cli.reg(cbuf, fabric::Access::LocalWrite).value();
  }

  control::BundleView bundle(std::uint64_t gen, std::uint32_t epoch, std::vector<control::NodeView> nodes, std::uint32_t r = 1) {
    control::BundleView v;
    v.body.generation = gen;
    v.body.epoch = epoch;
    v.body.replicas = r;
    v.sec.sec_generation = 1;
    control::PrincipalView p;
    p.name = "p";
    p.id = control::principal_id("p");
    p.identities = {kIdentity};
    p.quota_bytes = 8u << 20;
    p.max_scopes = 64;
    v.sec.principals.push_back(p);
    v.body.nodes = std::move(nodes);
    return v;
  }
  void apply(std::uint64_t gen, std::uint32_t epoch, std::vector<control::NodeView> nodes, std::uint32_t r = 1) {
    server->apply_bundle(bundle(gen, epoch, std::move(nodes), r));
    pump();
  }

  void pump() {
    for (int quiet = 0; quiet < 3;) {
      net.run_until_idle();
      quiet = server->run_once() ? 0 : quiet + 1;
    }
    net.run_until_idle();
    collect();
  }
  void collect() {
    std::array<fabric::Completion, 32> out;
    for (;;) {
      const std::size_t n = cli.poll(out);
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
  Expected<fabric::Endpoint*> connect(fabric::EpClass cls) {
    auto tk = server->issue_ticket(kIdentity, cls, 0, 1);
    if (!tk) return tk.error();
    return connect_with((*tk)[0], cls);
  }
  Expected<fabric::Endpoint*> connect_with(const proto::Ticket& tk, fabric::EpClass cls) {
    fabric::ConnParams cp;
    cp.cls = cls;
    std::span<std::byte> out(cp.ticket.data(), 20);
    EXPECT_TRUE(proto::encode_ticket(tk, out));
    cp.ticket_len = 20;
    return cli.connect(fabric::Peer{1}, cp);
  }
  template <typename Msg, typename Enc>
  void send(fabric::Endpoint* ep, Op op, std::uint64_t rid, const Msg& m, Enc enc, std::uint32_t epoch = 0) {
    std::array<std::byte, 8192> body{}, frame{};
    auto bn = enc(m, std::span<std::byte>(body));
    ASSERT_TRUE(bn);
    auto h = proto::header_for(op, rid);
    h.epoch = epoch;
    auto fn = proto::encode_frame(h, std::span<const std::byte>(body.data(), *bn), frame);
    ASSERT_TRUE(fn);
    fabric::Frame f;
    f.bytes.assign(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(*fn));
    ASSERT_TRUE(ep->post_send(std::move(f), 0));
  }
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
  Reply hello(fabric::Endpoint* ep, fabric::EpClass cls) {
    proto::Hello h;
    h.cls = static_cast<std::uint8_t>(cls);
    std::memset(h.conn_id, 1, 16);
    send(ep, Op::HELLO, 1, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
    Reply a = next_of(ep, Op::HELLO_ACK);
    EXPECT_EQ(a.h.type, static_cast<std::uint16_t>(Op::HELLO_ACK));
    return a;
  }

  static store::ScopeId scope_of(int k) {
    store::ScopeId s{};
    s[0] = static_cast<std::uint8_t>(k);
    s[1] = static_cast<std::uint8_t>(k * 7 + 3);
    s[31] = 0x5c;
    return s;
  }
  // A scope this node does / does not own (by the server's own answer; the tests cross-check it against owner_set).
  store::ScopeId find_scope(bool owned) {
    for (int k = 0; k < 256; ++k)
      if (server->in_owner_set(scope_of(k)) == owned) return scope_of(k);
    ADD_FAILURE() << "no scope found";
    return {};
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
  // PUT_BEGIN of one key (parent 0 = root) at frame epoch `epoch`; returns whatever the server answers first.
  Reply put_begin(fabric::Endpoint* ing, const store::ScopeId& scope, int k, int parent, std::uint32_t epoch, std::size_t len = 4096) {
    auto m = std::make_unique<proto::PutBegin>();
    std::memcpy(m->scope_id, scope.data(), 32);
    m->n = 1;
    std::memcpy(m->e[0].key_hash, key(k).data(), 32);
    if (parent) std::memcpy(m->e[0].parent_hash, key(parent).data(), 16);
    m->e[0].chain_pos = parent ? 1 : 0;
    m->e[0].stored_len = len;
    send(ing, Op::PUT_BEGIN, 40 + static_cast<std::uint64_t>(k), *m,
         [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); }, epoch);
    return next(ing);
  }
  // true: the ack accepted the key; false: it was skipped (ack OK, entry 0).
  static bool accepted(const Reply& r) {
    if (r.error()) return false;
    auto a = proto::decode_put_begin_ack(r.h, r.body);
    return a && a->status == 0 && a->n == 1 && a->e[0].status == 1;
  }
  static bool skipped(const Reply& r) {
    if (r.error()) return false;
    auto a = proto::decode_put_begin_ack(r.h, r.body);
    return a && a->status == 0 && a->n == 1 && a->e[0].status == 0 && a->put_id == 0;
  }
  // A committed root block `k` in `scope` (needs an Active owner at `epoch`).
  void commit_root(fabric::Endpoint* ing, const store::ScopeId& scope, int k, std::uint32_t epoch) {
    const auto data = payload(4096, k);
    Reply pb = put_begin(ing, scope, k, 0, epoch, data.size());
    ASSERT_TRUE(accepted(pb));
    auto a = proto::decode_put_begin_ack(pb.h, pb.body);
    ASSERT_TRUE(a);
    std::memcpy(cbuf.data(), data.data(), data.size());
    const std::uint64_t t = ++tag;
    const auto& e = a->e[0];
    const auto& mr = a->mr[e.mr_index];
    ASSERT_TRUE(ing->post_write({cmr.lkey, cbuf.data(), static_cast<std::uint32_t>(data.size())},
                                {mr.rkey, mr.addr + e.offset, static_cast<std::uint32_t>(data.size())}, t));
    pump();
    proto::PutCommit c;
    c.put_id = a->put_id;
    c.n = 1;
    c.e[0] = proto::CommitEntry{0, crc32c(data), data.size()};
    send(ing, Op::PUT_COMMIT, 99, c, [](const proto::PutCommit& x, std::span<std::byte> o) { return proto::encode_put_commit(x, o); }, epoch);
    ASSERT_FALSE(next_of(ing, Op::PUT_DONE).error());
  }
  Reply lookup(fabric::Endpoint* ctl, const store::ScopeId& scope, int k, std::uint32_t epoch) {
    auto m = std::make_unique<proto::Lookup>();
    std::memcpy(m->scope_id, scope.data(), 32);
    m->n = 1;
    std::memcpy(m->key_hash[0].data(), key(k).data(), 32);
    send(ctl, Op::LOOKUP, 7, *m, [](const proto::Lookup& x, std::span<std::byte> o) { return proto::encode_lookup(x, o); }, epoch);
    return next_of(ctl, Op::LOOKUP_ACK);
  }
  double metric(const std::string& name, const std::string& label) {
    std::string text;
    server->metrics().write_prometheus(text);
    std::stringstream ss(text);
    std::string line;
    while (std::getline(ss, line))  // the node_id const label comes first: match the name and the label fragment
      if (line.rfind(name + "{", 0) == 0 && line.find(label) != std::string::npos) return std::stod(line.substr(line.rfind(' ') + 1));
    return 0;
  }

  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& srv_fab;
  fabric::SimFabric& cli;
  InlineExecutor exec;
  std::unique_ptr<Server> server;
  std::uint32_t self = 0;
  std::map<fabric::EndpointId, std::deque<Reply>> inbox, segtabs;
  std::map<std::uint64_t, Status> tags;
  std::vector<std::byte> cbuf;
  fabric::MemRegion cmr;
  std::uint64_t tag = 0;
};

struct Ing {  // one ingest + one control endpoint, HELLO done
  explicit Ing(Fx& f) {
    auto c = f.connect(fabric::EpClass::Control);
    auto i = f.connect(fabric::EpClass::Ingest);
    EXPECT_TRUE(c && i);
    ctl = *c;
    ing = *i;
    ctl_ack = f.hello(ctl, fabric::EpClass::Control);
    ing_ack = f.hello(ing, fabric::EpClass::Ingest);
  }
  Reply ctl_ack, ing_ack;
  fabric::Endpoint* ctl = nullptr;
  fabric::Endpoint* ing = nullptr;
};

// ---- lab mode ---------------------------------------------------------------------------------------------------

TEST(Epoch, LabModeIgnoresEpochAndStampsNothing) {
  Fx f(/*lab=*/true);
  Ing e(f);
  const auto sc = Fx::scope_of(1);
  EXPECT_TRUE(Fx::accepted(f.put_begin(e.ing, sc, 1, 0, /*epoch=*/99)));  // any frame epoch is fine without a bundle
  EXPECT_TRUE(Fx::accepted(f.put_begin(e.ing, sc, 2, 0, 0)));
  Reply la = f.lookup(e.ctl, sc, 1, 5);
  EXPECT_EQ(la.h.epoch, 0u);  // replies are not stamped without a bundle
  EXPECT_EQ(la.h.bundle_gen_lo, 0u);
  EXPECT_TRUE(f.server->in_owner_set(sc) == false);  // no bundle: no owner-set opinion (the gate is off)
  EXPECT_TRUE(f.server->check_invariants());
}

// ---- stamping and StaleEpoch --------------------------------------------------------------------------------------

TEST(Epoch, EveryReplyCarriesTheNodesEpochAndBundleGeneration) {
  Fx f;
  f.apply(0x1'0000'0007ull, 5, {nview(f.self), nview(f.self + 1)});  // generation low 32 bits = 7
  Ing e(f);
  EXPECT_EQ(e.ing_ack.h.epoch, 5u);  // HELLO_ACK too
  EXPECT_EQ(e.ing_ack.h.bundle_gen_lo, 7u);
  Reply la = f.lookup(e.ctl, Fx::scope_of(1), 1, /*epoch ignored*/ 0);
  EXPECT_EQ(la.h.epoch, 5u);
  EXPECT_EQ(la.h.bundle_gen_lo, 7u);
  Reply ok = f.put_begin(e.ing, f.find_scope(true), 1, 0, 5);
  EXPECT_TRUE(Fx::accepted(ok));
  EXPECT_EQ(ok.h.epoch, 5u);
  EXPECT_EQ(ok.h.bundle_gen_lo, 7u);
}

TEST(Epoch, StaleEpochBelowAndAboveCarryTheNodesEpochAndGeneration) {
  Fx f;
  f.apply(9, 5, {nview(f.self), nview(f.self + 1)});
  Ing e(f);
  const auto sc = f.find_scope(true);
  Reply low = f.put_begin(e.ing, sc, 1, 0, 4);  // the sender is behind: retry 0
  ASSERT_TRUE(low.error());
  EXPECT_EQ(low.err_status(), WireStatus::StaleEpoch);
  EXPECT_EQ(low.retry_ms(), 0u);
  EXPECT_EQ(low.h.epoch, 5u);  // the node's epoch, not the sender's
  EXPECT_EQ(low.h.bundle_gen_lo, 9u);
  Reply zero = f.put_begin(e.ing, sc, 1, 0, 0);  // an unstamped frame is behind too
  ASSERT_TRUE(zero.error());
  EXPECT_EQ(zero.err_status(), WireStatus::StaleEpoch);
  Reply high = f.put_begin(e.ing, sc, 1, 0, 6);  // this node lags: retry in 50 ms
  ASSERT_TRUE(high.error());
  EXPECT_EQ(high.err_status(), WireStatus::StaleEpoch);
  EXPECT_EQ(high.retry_ms(), 50u);
  EXPECT_EQ(high.h.epoch, 5u);
  EXPECT_EQ(f.server->puts().n_puts(), 0u);  // nothing was created
  EXPECT_EQ(f.metric("miracache_put_epoch_refused_total", "reason=\"stale_epoch\""), 3.0);
  EXPECT_TRUE(Fx::accepted(f.put_begin(e.ing, sc, 1, 0, 5)));  // the matching epoch goes through
  EXPECT_TRUE(f.server->check_invariants());
}

TEST(Epoch, NonRootPutNeedsTheMatchingEpoch) {
  Fx f;
  f.apply(9, 5, {nview(f.self), nview(f.self + 1)});
  Ing e(f);
  const auto sc = f.find_scope(true);
  f.commit_root(e.ing, sc, 1, 5);
  Reply low = f.put_begin(e.ing, sc, 2, 1, 4);
  ASSERT_TRUE(low.error());
  EXPECT_EQ(low.err_status(), WireStatus::StaleEpoch);
  EXPECT_EQ(low.retry_ms(), 0u);
  Reply high = f.put_begin(e.ing, sc, 2, 1, 6);
  ASSERT_TRUE(high.error());
  EXPECT_EQ(high.err_status(), WireStatus::StaleEpoch);
  EXPECT_EQ(high.retry_ms(), 50u);
  EXPECT_TRUE(Fx::accepted(f.put_begin(e.ing, sc, 2, 1, 5)));
}

TEST(Epoch, LookupsAreNeverCheckedAgainstTheEpoch) {
  Fx f;
  f.apply(9, 5, {nview(f.self), nview(f.self + 1)});
  Ing e(f);
  const auto sc = f.find_scope(true);
  f.commit_root(e.ing, sc, 1, 5);
  for (std::uint32_t ep : {0u, 4u, 5u, 6u, 0xffffffffu}) {
    Reply la = f.lookup(e.ctl, sc, 1, ep);
    ASSERT_FALSE(la.error()) << ep;
    auto d = proto::decode_lookup_ack(la.h, la.body);
    ASSERT_TRUE(d);
    EXPECT_EQ(d->e[0].status, 1) << ep;
  }
}

// ---- owner set ----------------------------------------------------------------------------------------------------

TEST(Epoch, RootPutAcceptedOnlyInTheOwnerSetElseSkip) {
  Fx f;
  f.apply(3, 5, {nview(f.self), nview(f.self + 1), nview(f.self + 2)}, /*R=*/1);
  Ing e(f);
  int owned = 0, other = 0;
  // 48 scopes: the node ID differs per run, and with 6 scopes on 3 nodes this node owned none ~9% of the time.
  for (int k = 0; k < 48; ++k) {
    const auto sc = Fx::scope_of(100 + k);
    const bool own = f.server->in_owner_set(sc);
    Reply r = f.put_begin(e.ing, sc, 1, 0, 5);
    if (own) {
      EXPECT_TRUE(Fx::accepted(r)) << k;
      ++owned;
    } else {
      EXPECT_TRUE(Fx::skipped(r)) << k;  // SKIP for the key, not an error, nothing created
      ++other;
    }
  }
  EXPECT_GT(owned, 0);
  EXPECT_GT(other, 0);
  EXPECT_EQ(f.server->puts().n_puts(), static_cast<std::size_t>(owned));
  EXPECT_EQ(f.metric("miracache_put_epoch_refused_total", "reason=\"not_owner\""), static_cast<double>(other));
  // A SKIP-all answer is one ok request, not two.
  EXPECT_EQ(f.metric("miracache_requests_total", "op=\"put_begin\",status=\"ok\""), static_cast<double>(owned + other));
  EXPECT_TRUE(f.server->check_invariants());
  // A continuation is not an owner-set question (it extends where the parent lives).
  const auto mine = f.find_scope(true);
  f.commit_root(e.ing, mine, 7, 5);
  EXPECT_TRUE(Fx::accepted(f.put_begin(e.ing, mine, 8, 7, 5)));
}

TEST(Epoch, ServerAgreesWithTheClientsOwnerSetForR1R2R3WithZones) {
  Fx f;
  const std::uint32_t ids[4] = {f.self, f.self + 1, f.self + 2, f.self + 3};
  for (int zoned = 0; zoned < 2; ++zoned) {
    for (std::uint32_t r : {1u, 2u, 3u}) {
      std::vector<control::NodeView> nodes;
      for (int i = 0; i < 4; ++i)
        nodes.push_back(nview(ids[i], MemberState::Active, zoned ? std::optional<std::string>(i < 2 ? "z0" : i == 2 ? "z1" : "z2") : std::nullopt));
      auto b = f.bundle(10 + r, 5, nodes, r);
      f.server->apply_bundle(b);
      int in = 0;
      for (int k = 0; k < 64; ++k) {
        const auto sc = Fx::scope_of(k);
        bool want = false;
        // The client's own pick: Client::OwnerSetForTest builds it the way publish_bundle + run_bundle do.
        const auto set = Client::OwnerSetForTest(b.body, std::span<const std::uint8_t, 32>(sc));
        EXPECT_EQ(set.size(), r);
        for (auto id : set) want = want || id == f.self;
        EXPECT_EQ(f.server->in_owner_set(sc), want) << "zoned " << zoned << " R " << r << " scope " << k;
        EXPECT_EQ(Server::bundle_owns(b, f.self, sc), want);
        in += want;
      }
      EXPECT_GT(in, 0);
      EXPECT_LT(in, 64 + 1);
    }
  }
  // A zone holding two nodes: R = 2 puts the lone-zone node in every set.
  std::vector<control::NodeView> nodes{nview(f.self, MemberState::Active, "solo"), nview(f.self + 1, MemberState::Active, "pair"),
                                       nview(f.self + 2, MemberState::Active, "pair")};
  f.server->apply_bundle(f.bundle(20, 5, nodes, 2));
  for (int k = 0; k < 64; ++k) EXPECT_TRUE(f.server->in_owner_set(Fx::scope_of(k)));
}

TEST(Epoch, R2RootPutLandsOnEveryReplicaAndSkipsTheRest) {
  Fx f;
  f.apply(3, 5, {nview(f.self), nview(f.self + 1), nview(f.self + 2)}, /*R=*/2);
  Ing e(f);
  int in = 0, out = 0;
  // 60 scopes (at most 64, the principal's max_scopes): the node ID differs per run, and with 12 scopes the two checks
  // below failed ~3% of runs; with 60 the odds are below 1e-7.
  for (int k = 0; k < 60; ++k) {
    const auto sc = Fx::scope_of(200 + k);
    Reply r = f.put_begin(e.ing, sc, 1, 0, 5);
    if (f.server->in_owner_set(sc)) {
      EXPECT_TRUE(Fx::accepted(r)) << k;  // primary or replica: both take the root (RootPutAtReplica)
      ++in;
    } else {
      EXPECT_TRUE(Fx::skipped(r)) << k;
      ++out;
    }
  }
  EXPECT_GT(in, out / 2);  // two of three nodes hold each scope: about 40 of 60
  EXPECT_GT(out, 0);
  EXPECT_TRUE(f.server->check_invariants());
}

// ---- member states ------------------------------------------------------------------------------------------------

TEST(Epoch, DrainingRefusesRootsButTakesContinuations) {
  Fx f;
  f.apply(1, 5, {nview(f.self), nview(f.self + 1)});
  Ing e(f);
  const auto sc = f.find_scope(true);
  f.commit_root(e.ing, sc, 1, 5);
  f.apply(2, 6, {nview(f.self, MemberState::Draining), nview(f.self + 1)});  // drain = epoch + 1
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Draining);
  Reply root = f.put_begin(e.ing, sc, 5, 0, 6);
  ASSERT_TRUE(root.error());
  EXPECT_EQ(root.err_status(), WireStatus::Draining);
  EXPECT_EQ(root.h.epoch, 6u);
  EXPECT_TRUE(Fx::accepted(f.put_begin(e.ing, sc, 2, 1, 6)));  // chain in progress extends here
  EXPECT_EQ(f.metric("miracache_put_epoch_refused_total", "reason=\"draining\""), 1.0);
  // Reads and the stale-epoch rule still apply first: a sender at the old epoch is told so.
  Reply stale = f.put_begin(e.ing, sc, 6, 0, 5);
  ASSERT_TRUE(stale.error());
  EXPECT_EQ(stale.err_status(), WireStatus::StaleEpoch);
  EXPECT_TRUE(f.server->check_invariants());
}

TEST(Epoch, ReadonlyRefusesEveryPutBegin) {
  Fx f;
  f.apply(1, 5, {nview(f.self), nview(f.self + 1)});
  Ing e(f);
  const auto sc = f.find_scope(true);
  f.commit_root(e.ing, sc, 1, 5);
  f.apply(2, 6, {nview(f.self, MemberState::Draining), nview(f.self + 1)});
  f.apply(3, 6, {nview(f.self, MemberState::Readonly), nview(f.self + 1)});  // same epoch
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Readonly);
  Reply root = f.put_begin(e.ing, sc, 5, 0, 6);
  ASSERT_TRUE(root.error());
  EXPECT_EQ(root.err_status(), WireStatus::Draining);
  Reply child = f.put_begin(e.ing, sc, 2, 1, 6);  // a continuation is refused too
  ASSERT_TRUE(child.error());
  EXPECT_EQ(child.err_status(), WireStatus::Draining);
  EXPECT_EQ(f.server->puts().n_puts(), 0u);
  EXPECT_EQ(f.metric("miracache_put_epoch_refused_total", "reason=\"readonly\""), 2.0);
  Reply la = f.lookup(e.ctl, sc, 1, 6);  // reads still served
  auto d = proto::decode_lookup_ack(la.h, la.body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->e[0].status, 1);
  EXPECT_TRUE(f.server->check_invariants());
}

TEST(Epoch, SigtermLatchRefusesRootsInBundleMode) {
  Fx f;
  f.apply(1, 5, {nview(f.self), nview(f.self + 1)});
  Ing e(f);
  const auto sc = f.find_scope(true);
  f.commit_root(e.ing, sc, 1, 5);
  f.server->begin_drain(proto::GoawayReason::Shutdown, 2500);
  f.pump();
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Active);  // the bundle still says active
  Reply root = f.put_begin(e.ing, sc, 5, 0, 5);
  ASSERT_TRUE(root.error());
  EXPECT_EQ(root.err_status(), WireStatus::Draining);
  EXPECT_EQ(f.metric("miracache_put_epoch_refused_total", "reason=\"latch\""), 1.0);
  EXPECT_TRUE(Fx::accepted(f.put_begin(e.ing, sc, 2, 1, 5)));  // continuation of a chain: allowed
}

TEST(Epoch, RemovalSendsGoawayRefusesNewSessionsAndReAddServesAgain) {
  Fx f;
  f.apply(1, 5, {nview(f.self), nview(f.self + 1)});
  Ing e(f);
  const auto sc = f.find_scope(true);
  f.commit_root(e.ing, sc, 1, 5);
  f.inbox[e.ctl->id()].clear();
  f.apply(2, 5, {nview(f.self + 1)});  // a bundle without this node; the current view does not change
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Removed);
  int goaways = 0;
  for (auto& r : f.inbox[e.ctl->id()])
    if (r.h.type == static_cast<std::uint16_t>(Op::GOAWAY)) {
      ++goaways;
      auto g = proto::decode_goaway(r.h, r.body);
      ASSERT_TRUE(g);
      EXPECT_EQ(g->reason, static_cast<std::uint32_t>(proto::GoawayReason::Epoch));
      EXPECT_EQ(g->drain_ms, 1234u);  // [node] drain_ms
      EXPECT_EQ(r.h.epoch, 5u);
    }
  EXPECT_EQ(goaways, 1);
  // Any PUT_BEGIN is refused; reads still work; a new session is refused.
  Reply root = f.put_begin(e.ing, sc, 5, 0, 5);
  ASSERT_TRUE(root.error());
  EXPECT_EQ(root.err_status(), WireStatus::Draining);
  Reply child = f.put_begin(e.ing, sc, 2, 1, 5);
  ASSERT_TRUE(child.error());
  EXPECT_EQ(child.err_status(), WireStatus::Draining);
  Reply la = f.lookup(e.ctl, sc, 1, 5);
  auto d = proto::decode_lookup_ack(la.h, la.body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->e[0].status, 1);
  auto tk = f.server->issue_ticket(kIdentity, fabric::EpClass::Control, 0, 1);
  ASSERT_TRUE(tk);
  EXPECT_FALSE(f.connect_with((*tk)[0], fabric::EpClass::Control));  // admit() refuses a new session
  EXPECT_FALSE(f.server->check_issue_capacity(kIdentity, 1));  // admin API: Busy
  EXPECT_FALSE(f.server->draining());  // not the SIGTERM latch
  // A later bundle that lists the node lifts the state: it serves again.
  f.apply(3, 6, {nview(f.self), nview(f.self + 1)});
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Active);
  EXPECT_TRUE(f.server->issue_ticket(kIdentity, fabric::EpClass::Control, 0, 1));
  Reply again = f.put_begin(e.ing, sc, 6, 0, 6);
  EXPECT_TRUE(Fx::accepted(again));
  EXPECT_EQ(again.h.epoch, 6u);
  Ing e2(f);  // new sessions are admitted again
  EXPECT_TRUE(Fx::accepted(f.put_begin(e2.ing, sc, 7, 0, 6)));
  EXPECT_TRUE(f.server->check_invariants());
}

TEST(Epoch, RemovedNodeRefusesALateNewSessionAndGoawaysALateJoiner) {
  Fx f;
  f.apply(1, 5, {nview(f.self), nview(f.self + 1)});
  Ing e(f);                                         // a session (conn_id 1) exists
  auto joiner = f.connect(fabric::EpClass::Control);  // admitted before the removal, HELLO after it
  auto fresh = f.connect(fabric::EpClass::Control);
  ASSERT_TRUE(joiner && fresh);
  f.apply(2, 5, {nview(f.self + 1)});
  auto say_hello = [&](fabric::Endpoint* ep, std::uint8_t conn) {
    proto::Hello h;
    h.cls = static_cast<std::uint8_t>(fabric::EpClass::Control);
    std::memset(h.conn_id, conn, 16);
    f.send(ep, Op::HELLO, 1, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
    f.pump();
  };
  say_hello(*fresh, 9);  // a new session: refused like during the SIGTERM drain
  auto& qf = f.inbox[(*fresh)->id()];
  ASSERT_FALSE(qf.empty());
  ASSERT_TRUE(qf.front().error());
  EXPECT_EQ(qf.front().err_status(), WireStatus::Draining);
  say_hello(*joiner, 1);  // joins the existing session: HELLO_ACK, then GOAWAY (reason Epoch) at once
  bool ack = false, goaway = false;
  for (auto& r : f.inbox[(*joiner)->id()]) {
    ack = ack || r.h.type == static_cast<std::uint16_t>(Op::HELLO_ACK);
    if (r.h.type == static_cast<std::uint16_t>(Op::GOAWAY)) {
      goaway = true;
      auto g = proto::decode_goaway(r.h, r.body);
      ASSERT_TRUE(g);
      EXPECT_EQ(g->reason, static_cast<std::uint32_t>(proto::GoawayReason::Epoch));
    }
  }
  EXPECT_TRUE(ack);
  EXPECT_TRUE(goaway);
}

// ---- agreement over the golden placement files --------------------------------------------------------------------

std::array<std::uint8_t, 32> hex32(const std::string& s) {
  std::array<std::uint8_t, 32> a{};
  for (std::size_t i = 0; i < 32; ++i) a[i] = static_cast<std::uint8_t>(std::stoi(s.substr(2 * i, 2), nullptr, 16));
  return a;
}
std::vector<std::string> split(const std::string& s, char c) {
  std::vector<std::string> out;
  std::stringstream ss(s);
  std::string t;
  while (std::getline(ss, t, c)) out.push_back(t);
  return out;
}

// Node ids in the golden files are decimal; a non-numeric id cannot be a node_id, so such lines are skipped.
bool numeric(const std::string& s) { return !s.empty() && std::all_of(s.begin(), s.end(), [](char ch) { return ch >= '0' && ch <= '9'; }); }

control::BundleView golden_bundle(const std::vector<std::string>& specs, std::uint32_t r) {  // "id:w" or "id:w:zone"
  control::BundleView v;
  v.body.epoch = 3;
  v.body.replicas = r;
  for (const auto& sp : specs) {
    const auto p = split(sp, ':');
    control::NodeView n;
    n.node_id = static_cast<std::uint32_t>(std::stoul(p[0]));
    n.weight = static_cast<std::uint32_t>(std::stoul(p[1]));
    if (p.size() > 2) n.zone = p[2];
    v.body.nodes.push_back(n);
  }
  return v;
}

// For every node of the line: the server's answer (Server::bundle_owns, the code root PUT_BEGIN uses) is "in the
// golden pick list"; the picks themselves are what the client's owner_set returns.
void check_line(const std::vector<std::string>& specs, const std::string& scope_hex, std::uint32_t r, const std::vector<std::string>& picks) {
  auto b = golden_bundle(specs, r);
  const auto sc = hex32(scope_hex);
  for (const auto& nv : b.body.nodes) {
    const bool want = std::find(picks.begin(), picks.end(), std::to_string(nv.node_id)) != picks.end();
    EXPECT_EQ(Server::bundle_owns(b, nv.node_id, sc), want) << "node " << nv.node_id << " scope " << scope_hex << " R " << r;
  }
  const auto set = Client::OwnerSetForTest(b.body, std::span<const std::uint8_t, 32>(sc));  // the client's own pick
  ASSERT_EQ(set.size(), picks.size());
  for (std::size_t i = 0; i < set.size(); ++i) EXPECT_EQ(std::to_string(set[i]), picks[i]);
}

TEST(Epoch, ServerAgreesWithTheGoldenPlacementFiles) {
  const std::string dir = MIRACACHE_GOLDEN_DIR;
  int lines = 0;
  {  // owner lines: R = 1
    std::ifstream f(dir + "/placement_v1.txt");
    ASSERT_TRUE(f);
    std::string line;
    while (std::getline(f, line)) {
      std::istringstream is(line);
      std::string kind, scope, nodes, owner;
      if (!(is >> kind >> scope >> nodes >> owner) || kind != "owner") continue;
      auto specs = split(nodes, ',');
      bool ok = true;
      for (auto& s : specs) ok = ok && numeric(split(s, ':')[0]);
      if (!ok) continue;
      check_line(specs, scope, 1, {owner});
      ++lines;
    }
  }
  {  // order lines: every R from 1 to the node count, the first R of the full order
    std::ifstream f(dir + "/placement_order_v1.txt");
    ASSERT_TRUE(f);
    std::string line;
    while (std::getline(f, line)) {
      std::istringstream is(line);
      std::string kind, scope, nodes, order;
      if (!(is >> kind >> scope >> nodes >> order) || kind != "order") continue;
      const auto specs = split(nodes, ',');
      const auto full = split(order, ',');
      for (std::uint32_t r = 1; r <= std::min<std::size_t>(3, full.size()); ++r)
        check_line(specs, scope, r, std::vector<std::string>(full.begin(), full.begin() + r));
      ++lines;
    }
  }
  {  // zorder lines: zones included
    std::ifstream f(dir + "/placement_zones_v1.txt");
    ASSERT_TRUE(f);
    std::string line;
    while (std::getline(f, line)) {
      std::istringstream is(line);
      std::string kind, scope, nodes, picks;
      std::uint32_t r = 0;
      if (!(is >> kind >> scope >> nodes >> r >> picks) || kind != "zorder") continue;
      check_line(split(nodes, ','), scope, std::clamp<std::uint32_t>(r, 1, 3), split(picks, ','));
      ++lines;
    }
  }
  EXPECT_GE(lines, 20);
}

}  // namespace
}  // namespace miracache::server
