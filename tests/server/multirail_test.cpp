// SPDX-License-Identifier: Apache-2.0
// RL1: memory-node rails over the simulator. Two devices x two rails: one listener per rail, rkeys per device
// (SEG_TABLE carries one per rail), a segment readable only when registered on every device, a put on the ingest
// rail it began on, one session across rails, a flushed rail that leaves the session and its leases alone, and real
// per-rail health (port state, listener, fatal events) in the server snapshot and in GET /v1/identity.
#include <array>
#include <cstring>
#include <deque>
#include <optional>
#include <map>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "fabric/sim/sim_fabric.h"
#include "server/node_config.h"
#include "server/runtime/bundle_store.h"
#include "server/server.h"
#include "util/crc32c.h"
#include "util/log.h"

namespace miracache::server {
namespace {

using proto::Op;

store::StoreConfig store_cfg(std::uint32_t n_segments) {
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

struct Reply {
  proto::FrameHeader h;
  std::vector<std::byte> body;
};

const fabric::RailAddr kRail[4] = {{"10.0.0.1", 7471}, {"10.0.1.1", 7471}, {"10.0.2.1", 7471}, {"10.0.3.1", 7471}};

// Rails 0 and 1 live on device 0 (node 1), rails 2 and 3 on device 1 (node 2). The client is node 3.
struct Mx2 {
  explicit Mx2(std::uint32_t n_segments = 2, bool distinct_keys = true, std::uint32_t scope_records = 0)
      : rng(3), net(clock, rng, {}, {}), d0(net.add_node(1)), d1(net.add_node(2)), cli(net.add_node(3)) {
    if (distinct_keys) d1.set_key_base_for_test(0x1000);  // rkeys differ per device, as on real NICs
    ServerConfig sc;
    sc.store = store_cfg(n_segments);
    sc.store.node_id = 9;
    sc.store.scope_records = scope_records;
    sc.lab_identity = "lab";
    sc.lab_principal = 5;
    sc.rails = {kRail[0], kRail[1], kRail[2], kRail[3]};
    sc.rail_device = {0, 0, 1, 1};
    sc.device_names = {"dev0", "dev1"};
    auto s = Server::create(sc, std::vector<fabric::Fabric*>{&d0, &d1}, clock, rng, inline_exec);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
    EXPECT_TRUE(server->start());
    cbuf.assign(1 << 16, std::byte{0});
    cmr = cli.reg(cbuf, fabric::Access::LocalWrite).value();
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
          if (!fr) continue;
          Reply rp{fr->h, std::vector<std::byte>(fr->body.begin(), fr->body.end())};
          (fr->h.type == static_cast<std::uint16_t>(Op::SEG_TABLE) ? segtabs : inbox)[c.endpoint].push_back(std::move(rp));
        } else if (c.op == fabric::CompletionOp::Write || c.op == fabric::CompletionOp::Read) {
          tags[c.tag] = c.status;
        }
      }
    }
  }

  Expected<fabric::Endpoint*> connect(fabric::EpClass cls, std::uint8_t rail, std::uint8_t ticket_rail = 255) {
    auto tk = server->issue_ticket("lab", cls, ticket_rail == 255 ? rail : ticket_rail, 1);
    if (!tk) return tk.error();
    fabric::ConnParams cp;
    cp.cls = cls;
    std::span<std::byte> out(cp.ticket.data(), 20);
    EXPECT_TRUE(proto::encode_ticket((*tk)[0], out));
    cp.ticket_len = 20;
    return cli.connect(fabric::Peer{static_cast<fabric::NodeId>(rail < 2 ? 1 : 2), kRail[rail]}, cp);
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
  Reply next_of(fabric::Endpoint* ep, Op op) {
    for (int i = 0; i < 8; ++i) {
      pump();
      auto& q = inbox[ep->id()];
      while (!q.empty()) {
        Reply r = std::move(q.front());
        q.pop_front();
        if (r.h.type == static_cast<std::uint16_t>(op)) return r;
      }
    }
    ADD_FAILURE() << "no reply";
    return {};
  }
  // HELLO with a fixed conn_id: every endpoint of one client shares it, so they are one session.
  void hello(fabric::Endpoint* ep, fabric::EpClass cls) {
    proto::Hello h;
    h.cls = static_cast<std::uint8_t>(cls);
    std::memset(h.conn_id, 1, 16);
    send(ep, Op::HELLO, 1, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
    Reply a = next_of(ep, Op::HELLO_ACK);
    ASSERT_EQ(a.h.type, static_cast<std::uint16_t>(Op::HELLO_ACK));
  }
  // The newest SEG_TABLE the control endpoint received.
  std::optional<proto::SegTable> last_table(fabric::Endpoint* ctl) {
    collect();
    std::optional<proto::SegTable> out;
    for (auto& r : segtabs[ctl->id()])
      if (auto t = proto::decode_seg_table(r.h, r.body)) out = *t;
    return out;
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
  // PUT_BEGIN for one root key on `ing`, WRITE with the rkey the ack gave, PUT_COMMIT; returns the committed status.
  Status put(fabric::Endpoint* ing, int k, const std::vector<std::byte>& data, std::uint32_t* mr_rkey = nullptr) {
    auto m = std::make_unique<proto::PutBegin>();
    std::memcpy(m->scope_id, scope().data(), 32);
    m->n = 1;
    std::memcpy(m->e[0].key_hash, key(k).data(), 32);
    m->e[0].stored_len = data.size();
    send(ing, Op::PUT_BEGIN, 40, *m, [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); });
    Reply pb = next_of(ing, Op::PUT_BEGIN_ACK);
    auto ack = proto::decode_put_begin_ack(pb.h, pb.body);
    if (!ack || ack->n != 1 || ack->e[0].status != 1) return Error{ErrorCode::Corrupt, "put_begin refused"};
    const auto& mr = ack->mr[ack->e[0].mr_index];
    if (mr_rkey) *mr_rkey = mr.rkey;
    std::memcpy(cbuf.data(), data.data(), data.size());
    const std::uint64_t t = ++tag;
    if (Status st = ing->post_write({cmr.lkey, cbuf.data(), static_cast<std::uint32_t>(data.size())},
                                    {mr.rkey, mr.addr + ack->e[0].offset, static_cast<std::uint32_t>(data.size())}, t);
        !st)
      return st;
    pump();
    if (!tags.count(t) || !tags[t]) return Error{ErrorCode::Aborted, "write failed"};
    proto::PutCommit c;
    c.put_id = ack->put_id;
    c.n = 1;
    c.e[0] = proto::CommitEntry{0, crc32c(data), data.size()};
    send(ing, Op::PUT_COMMIT, 99, c, [](const proto::PutCommit& x, std::span<std::byte> o) { return proto::encode_put_commit(x, o); });
    Reply pd = next_of(ing, Op::PUT_DONE);
    auto done = proto::decode_put_done(pd.h, pd.body);
    if (!done || done->e[0].status != 0) return Error{ErrorCode::Corrupt, "commit refused"};
    return {};
  }
  std::optional<proto::LookupAck> lookup(fabric::Endpoint* ctl, int k) {
    auto m = std::make_unique<proto::Lookup>();
    std::memcpy(m->scope_id, scope().data(), 32);
    m->flags = 1;
    m->n = 1;
    std::memcpy(m->key_hash[0].data(), key(k).data(), 32);
    send(ctl, Op::LOOKUP, 7, *m, [](const proto::Lookup& x, std::span<std::byte> o) { return proto::encode_lookup(x, o); });
    Reply r = next_of(ctl, Op::LOOKUP_ACK);
    auto d = proto::decode_lookup_ack(r.h, r.body);
    if (!d) return std::nullopt;
    return *d;
  }
  Status read(fabric::Endpoint* fet, std::uint32_t rkey, std::uint64_t addr, std::uint32_t len) {
    const std::uint64_t t = ++tag;
    if (Status st = fet->post_read({rkey, addr, len}, {cmr.lkey, cbuf.data(), len}, t); !st) return st;
    pump();
    return tags.count(t) ? tags[t] : Status(Error{ErrorCode::Timeout, "no read completion"});
  }
  int renew_status(fabric::Endpoint* ctl, std::uint64_t lease) {
    proto::Renew rn;
    rn.lease_id = lease;
    send(ctl, Op::RENEW, 8, rn, [](const proto::Renew& m, std::span<std::byte> o) { return proto::encode_renew(m, o); });
    Reply rr = next_of(ctl, Op::RENEW_ACK);
    auto a = proto::decode_renew_ack(rr.h, rr.body);
    return a ? a->status : -1;
  }

  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric &d0, &d1, &cli;
  InlineExecutor inline_exec;
  std::unique_ptr<Server> server;
  std::map<fabric::EndpointId, std::deque<Reply>> inbox, segtabs;
  std::map<std::uint64_t, Status> tags;
  std::vector<std::byte> cbuf;
  fabric::MemRegion cmr;
  std::uint64_t tag = 0;
};

TEST(MultiRail, OneListenerPerRailAndWrongRailTicketRejected) {
  Mx2 f;
  for (std::uint8_t r = 0; r < 4; ++r) {
    auto ep = f.connect(fabric::EpClass::Control, r);
    EXPECT_TRUE(ep) << int(r);
  }
  // A ticket for rail 1 presented to rail 0's listener (reject 2: wrong rail), and across devices.
  EXPECT_FALSE(f.connect(fabric::EpClass::Control, 0, 1));
  EXPECT_FALSE(f.connect(fabric::EpClass::Control, 2, 0));
  EXPECT_FALSE(f.connect(fabric::EpClass::Fetch, 3, 2));
  EXPECT_EQ(f.server->n_conns(), 4u);  // only the four good ones were accepted (they wait for their HELLO)
  EXPECT_EQ(f.server->n_admitted(), 0u);
  f.pump();
  EXPECT_TRUE(f.server->check_invariants());
}

TEST(MultiRail, SegTableCarriesAnRkeyPerRail) {
  Mx2 f(/*n_segments=*/2);
  auto c0 = f.connect(fabric::EpClass::Control, 0);
  auto c2 = f.connect(fabric::EpClass::Control, 2);
  ASSERT_TRUE(c0 && c2);
  f.hello(*c0, fabric::EpClass::Control);
  f.hello(*c2, fabric::EpClass::Control);
  auto t0 = f.last_table(*c0);
  auto t2 = f.last_table(*c2);
  ASSERT_TRUE(t0 && t2);
  EXPECT_EQ(t0->n_rails, 4);
  EXPECT_EQ(t0->local_rail, 0);
  EXPECT_EQ(t2->local_rail, 2);
  EXPECT_EQ(t0->n, 2);
  for (std::size_t i = 0; i < t0->n; ++i) {
    EXPECT_EQ(t0->e[i].rkey[0], t0->e[i].rkey[1]);  // rails on one device share rkeys
    EXPECT_EQ(t0->e[i].rkey[2], t0->e[i].rkey[3]);
    EXPECT_NE(t0->e[i].rkey[0], t0->e[i].rkey[2]);  // devices differ
    EXPECT_EQ(t0->e[i].rkey[2], t2->e[i].rkey[2]);  // the same table whatever rail asked
    EXPECT_NE(t0->e[i].rkey[0], 0u);
  }
  EXPECT_EQ(t0->sg_rkey[0], t0->sg_rkey[1]);
  EXPECT_NE(t0->sg_rkey[0], t0->sg_rkey[2]);
  EXPECT_NE(t0->sg_rkey[2], 0u);
}

TEST(MultiRail, SegmentReadableOnlyWhenRegisteredOnEveryDevice) {
  Mx2 f(/*n_segments=*/2);
  store::MrManager& m = f.server->mrs();
  // One piece per run_once: seg0@dev0, seg0@dev1, seg1@dev0, seg1@dev1, array@dev0, array@dev1.
  std::vector<std::pair<std::uint32_t, bool>> seen;  // (common prefix, readable(0)) after each piece
  for (int step = 0; step < 6 && !m.registration_complete(); ++step) {
    f.server->run_once();
    seen.push_back({m.registered_segments(), m.readable(0)});
  }
  ASSERT_EQ(seen.size(), 6u);
  const std::uint32_t want_prefix[] = {0, 1, 1, 2, 2, 2};
  for (std::size_t i = 0; i < 6; ++i) EXPECT_EQ(seen[i].first, want_prefix[i]) << i;
  // Every segment is on both devices after piece 4, yet nothing is readable until the array is on both too.
  for (std::size_t i = 0; i < 5; ++i) EXPECT_FALSE(seen[i].second) << i;
  EXPECT_TRUE(seen[5].second);
  EXPECT_TRUE(m.registration_complete());
  EXPECT_TRUE(m.readable(1));
  EXPECT_FALSE(m.readable(2));
}

TEST(MultiRail, PutOnItsIngestRailAndFetchWithThatRailsRkey) {
  Mx2 f;
  auto c0 = f.connect(fabric::EpClass::Control, 0);
  auto in2 = f.connect(fabric::EpClass::Ingest, 2);
  auto fe0 = f.connect(fabric::EpClass::Fetch, 0);
  auto fe2 = f.connect(fabric::EpClass::Fetch, 2);
  ASSERT_TRUE(c0 && in2 && fe0 && fe2);
  f.hello(*c0, fabric::EpClass::Control);
  f.hello(*in2, fabric::EpClass::Ingest);
  f.hello(*fe0, fabric::EpClass::Fetch);
  f.hello(*fe2, fabric::EpClass::Fetch);

  const auto data = Mx2::payload(6000, 1);
  std::uint32_t mr_rkey = 0;
  ASSERT_TRUE(f.put(*in2, 1, data, &mr_rkey));  // begun, written and committed on rail 2 (device 1)
  EXPECT_GE(mr_rkey, 0x1000u);                  // its write MR was registered on device 1

  auto la = f.lookup(*c0, 1);  // looked up on rail 0 (device 0)
  ASSERT_TRUE(la);
  ASSERT_EQ(la->e[0].status, 1);
  auto t = f.last_table(*c0);
  ASSERT_TRUE(t);
  const auto* se = &t->e[0];
  for (std::size_t i = 0; i < t->n; ++i)
    if (t->e[i].seg_id == la->e[0].seg_id) se = &t->e[i];
  const std::uint64_t addr = se->base + la->e[0].offset;
  const auto len = static_cast<std::uint32_t>(data.size());
  // Each fetch endpoint reads with its own rail's rkey; the other device's rkey is not valid there.
  ASSERT_TRUE(f.read(*fe0, se->rkey[0], addr, len));
  EXPECT_EQ(std::memcmp(f.cbuf.data(), data.data(), data.size()), 0);
  std::fill(f.cbuf.begin(), f.cbuf.end(), std::byte{0});
  ASSERT_TRUE(f.read(*fe2, se->rkey[2], addr, len));
  EXPECT_EQ(std::memcmp(f.cbuf.data(), data.data(), data.size()), 0);
  EXPECT_FALSE(f.read(*fe2, se->rkey[0], addr, len));
  f.pump();
  EXPECT_TRUE(f.server->check_invariants());
}

TEST(MultiRail, FlushedRailKeepsSessionAndLeases) {
  Mx2 f;
  auto c0 = f.connect(fabric::EpClass::Control, 0);
  auto c2 = f.connect(fabric::EpClass::Control, 2);
  auto in0 = f.connect(fabric::EpClass::Ingest, 0);
  auto fe2 = f.connect(fabric::EpClass::Fetch, 2);
  ASSERT_TRUE(c0 && c2 && in0 && fe2);
  f.hello(*c0, fabric::EpClass::Control);
  f.hello(*c2, fabric::EpClass::Control);
  f.hello(*in0, fabric::EpClass::Ingest);
  f.hello(*fe2, fabric::EpClass::Fetch);
  const auto data = Mx2::payload(4096, 4);
  ASSERT_TRUE(f.put(*in0, 1, data));
  auto la = f.lookup(*c0, 1);  // the lease is taken on rail 0
  ASSERT_TRUE(la);
  ASSERT_NE(la->lease_id, 0u);
  EXPECT_EQ(f.renew_status(*c2, la->lease_id), 0);  // one session: rail 2 can renew rail 0's lease
  EXPECT_EQ(f.server->store().n_leases(), 1u);

  // Rail 0 is flushed (its endpoints go to ERR on both sides): the lease and the session live on through rail 2.
  const auto conns_before = f.server->n_conns();
  ASSERT_TRUE(f.d0.fail_rail(kRail[0]));
  f.clock.advance_by(std::chrono::milliseconds(20));  // the loop notices an endpoint in ERR on its next tick
  f.pump();
  EXPECT_EQ((*c0)->state(), fabric::EpState::Error);
  EXPECT_EQ((*in0)->state(), fabric::EpState::Error);
  EXPECT_EQ((*c2)->state(), fabric::EpState::Ready);
  EXPECT_EQ((*fe2)->state(), fabric::EpState::Ready);
  EXPECT_EQ(f.server->n_conns(), conns_before - 2);
  EXPECT_EQ(f.server->store().n_leases(), 1u);
  EXPECT_EQ(f.renew_status(*c2, la->lease_id), 0);
  // The lease still covers a READ on the surviving rail.
  auto t = f.last_table(*c2);
  ASSERT_TRUE(t);
  const auto* se = &t->e[0];
  for (std::size_t i = 0; i < t->n; ++i)
    if (t->e[i].seg_id == la->e[0].seg_id) se = &t->e[i];
  ASSERT_TRUE(f.read(*fe2, se->rkey[2], se->base + la->e[0].offset, static_cast<std::uint32_t>(data.size())));
  EXPECT_EQ(std::memcmp(f.cbuf.data(), data.data(), data.size()), 0);
  // A new connection on the failed rail is refused until it is restored.
  EXPECT_FALSE(f.connect(fabric::EpClass::Control, 0));
  EXPECT_TRUE(f.d0.restore_rail(kRail[0]));
  EXPECT_TRUE(f.connect(fabric::EpClass::Control, 0));
  f.pump();
  EXPECT_TRUE(f.server->check_invariants());
}

TEST(MultiRail, LostIngestRailAbortsOnlyItsPuts) {
  Mx2 f;
  auto in0 = f.connect(fabric::EpClass::Ingest, 0);
  auto in2 = f.connect(fabric::EpClass::Ingest, 2);
  ASSERT_TRUE(in0 && in2);
  f.hello(*in0, fabric::EpClass::Ingest);
  f.hello(*in2, fabric::EpClass::Ingest);
  // Begin a put on each rail (no commit yet), then lose rail 2 only.
  for (auto* ing : {*in0, *in2}) {
    auto m = std::make_unique<proto::PutBegin>();
    std::memcpy(m->scope_id, Mx2::scope().data(), 32);
    m->n = 1;
    std::memcpy(m->e[0].key_hash, Mx2::key(ing == *in0 ? 1 : 2).data(), 32);
    m->e[0].stored_len = 4096;
    f.send(ing, Op::PUT_BEGIN, 40, *m, [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); });
    (void)f.next_of(ing, Op::PUT_BEGIN_ACK);
  }
  EXPECT_EQ(f.server->puts().n_puts(), 2u);
  ASSERT_TRUE(f.d1.fail_rail(kRail[2]));
  f.clock.advance_by(std::chrono::milliseconds(20));
  f.pump();
  EXPECT_EQ(f.server->puts().n_puts(), 1u);  // rail 2's put is gone, rail 0's lives
  EXPECT_EQ((*in0)->state(), fabric::EpState::Ready);
  EXPECT_EQ(f.server->puts().n_limbo(), 0u);
  EXPECT_EQ(f.server->mrs().live_write_mrs(), 1u);
  EXPECT_TRUE(f.server->check_invariants());
}

TEST(MultiRail, LegacySingleListenerConfigIsUnchanged) {
  auto c = parse_node_config("[node]\ndevice = \"rxe0\"\nlisten = [\"10.0.0.5:7471\", \"10.0.1.5:7471\"]\n[store]\nbacking = \"anon\"\n");
  ASSERT_TRUE(c) << c.error().context;
  EXPECT_EQ(c->device, "rxe0");
  EXPECT_TRUE(c->devices.empty());  // one device, every rail on it
  EXPECT_TRUE(c->server.rail_device.empty());
  EXPECT_EQ(c->server.rails.size(), 2u);
  // A plain one-listener server still advertises one rail with its own rkeys.
  SimClock clock;
  SeededRandom rng(1);
  fabric::SimNetwork net(clock, rng, {}, {});
  auto& d = net.add_node(1);
  InlineExecutor ex;
  ServerConfig sc;
  sc.store = store_cfg(1);
  auto s = Server::create(sc, d, clock, rng, ex);
  ASSERT_TRUE(s);
  ASSERT_TRUE((*s)->start());
  const auto snap = (*s)->node_snapshot();
  ASSERT_EQ(snap.rails.size(), 1u);
  EXPECT_TRUE(snap.rails[0].up);
}

TEST(MultiRail, NodeRailsConfig) {
  auto c = parse_node_config(
      "[store]\nbacking = \"anon\"\n"
      "[[node.rails]]\ndevice = \"mlx5_0\"\nlisten = \"10.0.0.5:7471\"\nsubnet = \"10.0.0.0/24\"\n"
      "[[node.rails]]\ndevice = \"mlx5_1\"\nlisten = \"10.0.1.5:7471\"\nsubnet = \"10.0.1.0/24\"\n"
      "[[node.rails]]\ndevice = \"mlx5_0\"\nlisten = \"10.0.2.5:7471\"\nsubnet = \"10.0.2.0/24\"\n");
  ASSERT_TRUE(c) << c.error().context;
  ASSERT_EQ(c->server.rails.size(), 3u);
  EXPECT_EQ(c->devices, (std::vector<std::string>{"mlx5_0", "mlx5_1"}));
  EXPECT_EQ(c->server.rail_device, (std::vector<std::uint32_t>{0, 1, 0}));
  EXPECT_EQ(c->rail_subnets[1], "10.0.1.0/24");
  EXPECT_EQ(c->server.rails[2].host, "10.0.2.5");
  // Errors: both forms, more than 4 rails, duplicates, a missing key.
  EXPECT_FALSE(parse_node_config("[node]\nlisten = [\"10.0.0.5:1\"]\n[[node.rails]]\ndevice = \"a\"\nlisten = \"10.0.0.6:1\"\nsubnet = \"\"\n"));
  std::string five = "[store]\nbacking = \"anon\"\n";
  for (int i = 0; i < 5; ++i)
    five += "[[node.rails]]\ndevice = \"a\"\nlisten = \"10.0.0." + std::to_string(i + 1) + ":7471\"\nsubnet = \"\"\n";
  EXPECT_FALSE(parse_node_config(five));
  EXPECT_FALSE(parse_node_config("[[node.rails]]\ndevice = \"a\"\nlisten = \"10.0.0.1:1\"\nsubnet = \"\"\n[[node.rails]]\ndevice = \"b\"\nlisten = \"10.0.0.1:1\"\nsubnet = \"\"\n"));
  EXPECT_FALSE(parse_node_config("[[node.rails]]\ndevice = \"a\"\nsubnet = \"\"\n"));
  EXPECT_FALSE(parse_node_config("[[node.rails]]\nlisten = \"10.0.0.1:1\"\n"));
  // The server refuses more than 4 rails and a rail on an unknown device.
  SimClock clock;
  SeededRandom rng(1);
  fabric::SimNetwork net(clock, rng, {}, {});
  auto& d = net.add_node(1);
  InlineExecutor ex;
  ServerConfig sc;
  sc.store = store_cfg(1);
  for (int i = 0; i < 5; ++i) sc.rails.push_back({"h" + std::to_string(i), 1});
  EXPECT_FALSE(Server::create(sc, d, clock, rng, ex));
  sc.rails.resize(2);
  sc.rail_device = {0, 1};
  EXPECT_FALSE(Server::create(sc, d, clock, rng, ex));
}

// ---- health -------------------------------------------------------------------------------------------------

TEST(RailHealth, FakePortEventsMoveTheRailsOfThatDevice) {
  Mx2 f;
  auto up = [&](std::size_t r) { return f.server->node_snapshot().rails.at(r).up; };
  f.server->refresh_rail_health();
  auto s = f.server->node_snapshot();
  ASSERT_EQ(s.rails.size(), 4u);
  for (const auto& r : s.rails) {
    EXPECT_TRUE(r.up);
    EXPECT_EQ(r.port_state, "ACTIVE");
    EXPECT_TRUE(r.listener_ok);
  }
  EXPECT_EQ(s.rails[0].addr, "10.0.0.1:7471");
  EXPECT_EQ(s.rails[2].device, "dev1");

  // Port down on device 1: rails 2 and 3 go down, rails 0 and 1 stay up.
  f.d1.set_port_state_for_test("DOWN");
  f.server->refresh_rail_health();
  EXPECT_TRUE(up(0) && up(1));
  EXPECT_FALSE(up(2));
  EXPECT_FALSE(up(3));
  EXPECT_EQ(f.server->node_snapshot().rails[3].port_state, "DOWN");
  EXPECT_TRUE(f.server->node_snapshot().rails[3].listener_ok);  // the listener itself is fine
  // ...and comes back.
  f.d1.set_port_state_for_test("ACTIVE");
  f.server->refresh_rail_health();
  EXPECT_TRUE(up(2) && up(3));

  // One listener lost: only that rail goes down, and its listener_ok says why.
  ASSERT_TRUE(f.d1.fail_rail(kRail[3]));
  f.server->refresh_rail_health();
  EXPECT_TRUE(up(0) && up(1) && up(2));
  EXPECT_FALSE(up(3));
  EXPECT_FALSE(f.server->node_snapshot().rails[3].listener_ok);
  EXPECT_EQ(f.server->node_snapshot().rails[3].port_state, "ACTIVE");
  ASSERT_TRUE(f.d1.restore_rail(kRail[3]));

  // A fatal async event on device 0 takes both its rails down while its port still reads ACTIVE.
  f.d0.set_fatal_for_test(true);
  f.server->refresh_rail_health();
  EXPECT_FALSE(up(0));
  EXPECT_FALSE(up(1));
  EXPECT_TRUE(up(2) && up(3));
  EXPECT_EQ(f.server->node_snapshot().rails[0].port_state, "ACTIVE");
  f.d0.set_fatal_for_test(false);
  f.server->refresh_rail_health();
  EXPECT_TRUE(up(0) && up(1));
}

TEST(RailHealth, TickRefreshesAndMetricsFollow) {
  Mx2 f;
  f.pump();
  auto gauge = [&](const std::string& rail) {
    std::string t;
    f.server->metrics().write_prometheus(t);
    const std::string needle = "miracache_rail_state{node_id=\"9\",hostname=\"" + log::hostname() + "\",rail=\"" + rail + "\"";
    const auto p = t.find(needle);
    if (p == std::string::npos) return std::int64_t{-1};
    const auto e = t.find('\n', p);
    return static_cast<std::int64_t>(std::stoll(t.substr(t.rfind(' ', e) + 1, e - t.rfind(' ', e) - 1)));
  };
  EXPECT_EQ(gauge("0"), 1);
  EXPECT_EQ(gauge("3"), 1);
  f.d1.set_port_state_for_test("INIT");
  f.clock.advance_by(std::chrono::seconds(1));  // the loop refreshes on its own twice a second
  f.pump();
  EXPECT_EQ(gauge("0"), 1);
  EXPECT_EQ(gauge("2"), 0);
  EXPECT_EQ(gauge("3"), 0);
  EXPECT_EQ(f.server->node_snapshot().rails[2].port_state, "INIT");
  // qp_active counts live endpoints by class and rail.
  auto c0 = f.connect(fabric::EpClass::Control, 0);
  auto c3 = f.connect(fabric::EpClass::Control, 3);
  ASSERT_TRUE(c0 && c3);
  f.hello(*c0, fabric::EpClass::Control);
  f.hello(*c3, fabric::EpClass::Control);
  f.server->refresh_rail_health();
  std::string t;
  f.server->metrics().write_prometheus(t);
  EXPECT_NE(t.find("miracache_qp_active{node_id=\"9\",class=\"control\",rail=\"3\"} 1"), std::string::npos) << t;
  EXPECT_NE(t.find("miracache_qp_active{node_id=\"9\",class=\"ingest\",rail=\"3\"} 0"), std::string::npos);
}

// Q2: a fetch rkey reaches the data runs only. A valid rkey on either device must be refused for the superblock,
// segment meta, run table, header table, the scope region and anything past the data (incl. segment 0's reserved tail
// runs), and a read that straddles the start or end of the data; block bytes read back exactly.
void check_fetch_mr_bounds(std::uint32_t scope_records, bool expect_reserved) {
  Mx2 f(2, true, scope_records);
  const auto& lay = f.server->arena().layout();
  ASSERT_EQ(lay.scope.reserved_runs > 0, expect_reserved);
  if (scope_records > 0) {
    ASSERT_GT(lay.scope.len, 0u);
  }
  auto c0 = f.connect(fabric::EpClass::Control, 0);
  auto in0 = f.connect(fabric::EpClass::Ingest, 0);
  auto fe0 = f.connect(fabric::EpClass::Fetch, 0);
  auto fe2 = f.connect(fabric::EpClass::Fetch, 2);
  ASSERT_TRUE(c0 && in0 && fe0 && fe2);
  f.hello(*c0, fabric::EpClass::Control);
  f.hello(*in0, fabric::EpClass::Ingest);
  f.hello(*fe0, fabric::EpClass::Fetch);
  f.hello(*fe2, fabric::EpClass::Fetch);
  const auto data = Mx2::payload(6000, 1);
  ASSERT_TRUE(f.put(*in0, 1, data));
  auto la = f.lookup(*c0, 1);
  ASSERT_TRUE(la);
  ASSERT_EQ(la->e[0].status, 1);
  auto t = f.last_table(*c0);
  ASSERT_TRUE(t);

  const auto len = static_cast<std::uint32_t>(data.size());
  for (std::size_t i = 0; i < t->n; ++i) {
    const auto& se = t->e[i];
    const auto& sl = lay.seg;
    const std::uint64_t data_end =
        sl.data_off + std::uint64_t{sl.n_runs - (se.seg_id == 0 ? lay.scope.reserved_runs : 0)} * sl.run_bytes;
    EXPECT_EQ(se.len, data_end) << "SEG_TABLE len ends where the data MR ends";
    for (int dev = 0; dev < 2; ++dev) {
      auto* fe = dev == 0 ? *fe0 : *fe2;
      const std::uint32_t rk = se.rkey[dev * 2];
      auto denied = [&](std::uint64_t off, std::uint32_t n, const char* what) {
        Status st = f.read(fe, rk, se.base + off, n);
        EXPECT_FALSE(st) << what << " seg " << se.seg_id << " dev " << dev;
      };
      denied(0, 64, "superblock");
      denied(proto::kSuperblockSize, 64, "superblock copy 2");
      denied(store::kSegmentMetaOff, 64, "segment meta");
      denied(sl.run_table_off, 64, "run table");
      denied(sl.header_off(0, 0), 128, "block header");
      denied(sl.header_off(sl.n_runs - 1, 4095), 128, "last block header");
      denied(sl.data_off - 32, 64, "straddles the data start");
      denied(sl.data_off - 1, 2, "straddles the data start by one byte");
      denied(data_end - 32, 64, "straddles the data end");
      denied(data_end, 64, "past the data");
      if (se.seg_id == 0 && lay.scope.len > 0) {
        denied(lay.scope.off, 72, "scope record");
        denied(lay.scope.off + 72, 72, "scope record 1");
        denied(lay.scope.off + lay.scope.len - 72, 72, "last scope record");
      }
    }
  }
  // Block data still reads exactly, with each device's rkey.
  const auto& se = [&]() -> const proto::SegEntry& {
    for (std::size_t i = 0; i < t->n; ++i)
      if (t->e[i].seg_id == la->e[0].seg_id) return t->e[i];
    return t->e[0];
  }();
  const std::uint64_t addr = se.base + la->e[0].offset;
  ASSERT_TRUE(f.read(*fe0, se.rkey[0], addr, len));
  EXPECT_EQ(std::memcmp(f.cbuf.data(), data.data(), data.size()), 0);
  std::fill(f.cbuf.begin(), f.cbuf.end(), std::byte{0});
  ASSERT_TRUE(f.read(*fe2, se.rkey[2], addr, len));
  EXPECT_EQ(std::memcmp(f.cbuf.data(), data.data(), data.size()), 0);
  // The state_gen array stays readable (generations only).
  EXPECT_TRUE(f.read(*fe0, t->sg_rkey[0], t->sg_base, 8));
  EXPECT_TRUE(f.server->mrs().check_invariants());
}

TEST(MultiRail, FetchMrCoversDataRunsOnly) { check_fetch_mr_bounds(/*scope_records=*/0, /*expect_reserved=*/false); }

TEST(MultiRail, FetchMrCoversDataRunsOnlyScopeRegionInTheGap) {
  check_fetch_mr_bounds(/*scope_records=*/64, /*expect_reserved=*/false);
}

TEST(MultiRail, FetchMrCoversDataRunsOnlyScopeRegionInReservedTailRuns) {
  check_fetch_mr_bounds(/*scope_records=*/8000, /*expect_reserved=*/true);
}

}  // namespace
}  // namespace miracache::server
