// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <array>
#include <cmath>
#include <cstring>
#include <vector>

#include "fabric/sim/sim_fabric.h"
#include "fabric/verbs_cm/protocol_rules.h"

using namespace miracache;
using namespace miracache::fabric;

namespace {

ListenParams open_listen() {
  ListenParams lp;
  lp.allow_unauthenticated_for_test = true;
  return lp;
}

struct Rig {
  SimClock clock;
  SeededRandom rng;
  SimNetwork net;
  SimFabric& a;
  SimFabric& b;
  std::vector<std::byte> remote_buf = std::vector<std::byte>(4096);
  std::vector<std::byte> local_buf = std::vector<std::byte>(4096);
  MemRegion remote_mr, local_mr;
  Endpoint* ep = nullptr;
  Endpoint* accepted = nullptr;

  explicit Rig(FaultConfig f = {}, std::uint64_t seed = 1, SimOptions o = {})
      : rng(seed), net(clock, rng, f, o), a(net.add_node(1)), b(net.add_node(2)) {
    for (std::size_t i = 0; i < remote_buf.size(); ++i) remote_buf[i] = static_cast<std::byte>(i * 7);
    remote_mr = b.reg(remote_buf, Access::RemoteRead | Access::RemoteWrite).value();
    local_mr = a.reg(local_buf, Access::LocalWrite).value();
    EXPECT_TRUE(b.listen([this](Endpoint* e) { accepted = e; }, open_listen()));
    ep = a.connect(Peer{2}).value();
  }

  RemoteRef remote(std::uint32_t off, std::uint32_t len) {
    return {remote_mr.rkey, reinterpret_cast<std::uint64_t>(remote_buf.data()) + off, len};
  }
  LocalRef local(std::uint32_t off, std::uint32_t len) { return {local_mr.lkey, local_buf.data() + off, len}; }

  std::vector<Completion> drain(SimFabric& f) {
    net.run_until_idle();
    std::vector<Completion> out;
    std::array<Completion, 8> batch;
    while (auto n = f.poll(batch)) for (std::size_t i = 0; i < n; ++i) out.push_back(std::move(batch[i]));
    return out;
  }
};

}  // namespace

TEST(SimFabric, ReadCopiesRemoteBytes) {
  Rig r;
  ASSERT_TRUE(r.ep->post_read(r.remote(100, 64), r.local(0, 64), 11));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_TRUE(c[0].status);
  EXPECT_EQ(c[0].tag, 11u);
  EXPECT_EQ(c[0].op, CompletionOp::Read);
  EXPECT_EQ(std::memcmp(r.local_buf.data(), r.remote_buf.data() + 100, 64), 0);
  EXPECT_TRUE(r.ep->drained());
  EXPECT_GT(r.clock.now(), Nanos{0});
}

TEST(SimFabric, WriteCopiesToRemote) {
  Rig r;
  std::memset(r.local_buf.data(), 0x5a, 32);
  ASSERT_TRUE(r.ep->post_write(r.local(0, 32), r.remote(8, 32), 3));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_TRUE(c[0].status);
  EXPECT_EQ(static_cast<int>(r.remote_buf[8]), 0x5a);
}

TEST(SimFabric, SendDeliversRecvToPeer) {
  Rig r;
  ASSERT_NE(r.accepted, nullptr);
  ASSERT_TRUE(r.ep->post_send(Frame{{std::byte{1}, std::byte{2}, std::byte{3}}}, 5));
  r.net.run_until_idle();
  auto recv = r.drain(r.b);
  ASSERT_EQ(recv.size(), 1u);
  EXPECT_EQ(recv[0].op, CompletionOp::Recv);
  EXPECT_EQ(recv[0].frame.bytes.size(), 3u);
  auto sent = r.drain(r.a);
  ASSERT_EQ(sent.size(), 1u);
  EXPECT_EQ(sent[0].op, CompletionOp::Send);
}

TEST(SimFabric, BadRkeyAndBoundsAreAccessErrors) {
  Rig r;
  auto bad_key = r.remote(0, 16);
  bad_key.rkey = 999;
  ASSERT_TRUE(r.ep->post_read(bad_key, r.local(0, 16), 1));
  ASSERT_TRUE(r.ep->post_read(r.remote(4090, 16), r.local(0, 16), 2));  // runs past the MR
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 2u);
  for (auto& x : c) {
    ASSERT_FALSE(x.status);
    EXPECT_EQ(x.status.error().code, ErrorCode::AccessDenied);
  }
}

TEST(SimFabric, RemoteReadRequiresAccessFlag) {
  Rig r;
  std::vector<std::byte> priv(64);
  auto mr = r.b.reg(priv, Access::RemoteWrite).value();
  RemoteRef ref{mr.rkey, reinterpret_cast<std::uint64_t>(priv.data()), 64};
  ASSERT_TRUE(r.ep->post_read(ref, r.local(0, 64), 1));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].status.error().code, ErrorCode::AccessDenied);
}

TEST(SimFabric, PostRejectsBadLocalRef) {
  Rig r;
  EXPECT_FALSE(r.ep->post_read(r.remote(0, 16), LocalRef{r.local_mr.lkey, r.local_buf.data() + 4090, 16}, 1));
  EXPECT_FALSE(r.ep->post_read(r.remote(0, 16), LocalRef{777, r.local_buf.data(), 16}, 1));
  // Sink region without LocalWrite is refused.
  std::vector<std::byte> ro(64);
  auto mr = r.a.reg(ro, Access::RemoteRead).value();
  EXPECT_FALSE(r.ep->post_read(r.remote(0, 16), LocalRef{mr.lkey, ro.data(), 16}, 1));
}

TEST(SimFabric, DeregRefusedWhileWorkInFlight) {
  Rig r;
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  EXPECT_FALSE(r.ep->drained());
  auto busy = r.a.dereg(r.local_mr);
  ASSERT_FALSE(busy);
  EXPECT_EQ(busy.error().code, ErrorCode::Busy);
  r.drain(r.a);
  EXPECT_TRUE(r.a.dereg(r.local_mr));
}

TEST(SimFabric, LinkDownFailsInFlightAndRecovers) {
  Rig r;
  r.net.set_link(1, 2, false);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].status.error().code, ErrorCode::LinkDown);
  EXPECT_FALSE(r.a.connect(Peer{2}));
  r.net.set_link(1, 2, true);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 2));
  EXPECT_TRUE(r.drain(r.a)[0].status);
}

TEST(SimFabric, AbortFlushesAndRefusesNewWork) {
  Rig r;
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  r.ep->abort();
  EXPECT_FALSE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 2));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].status.error().code, ErrorCode::Aborted);
  EXPECT_TRUE(r.ep->drained());
}

TEST(SimFabric, DropCompletesWithTimeout) {
  FaultConfig f;
  f.drop = 1.0;
  Rig r(f);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].status.error().code, ErrorCode::Timeout);
  EXPECT_GE(r.clock.now(), f.drop_timeout);
}

TEST(SimFabric, DuplicateCompletionDeliversTwice) {
  FaultConfig f;
  f.duplicate_completion = 1.0;
  Rig r(f);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  EXPECT_EQ(r.drain(r.a).size(), 2u);
}

TEST(SimFabric, ReorderCanInvertCompletionOrder) {
  FaultConfig f;
  f.ordered = false;  // reordering is an explicit opt-in
  f.reorder = 0.5;
  f.reorder_window = Nanos{50'000};
  bool inverted = false;
  for (std::uint64_t seed = 1; seed < 20 && !inverted; ++seed) {
    Rig r(f, seed);
    for (WrTag t = 0; t < 8; ++t) ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(t * 16, 16), t));
    auto c = r.drain(r.a);
    for (std::size_t i = 1; i < c.size(); ++i) inverted |= c[i].tag < c[i - 1].tag;
  }
  EXPECT_TRUE(inverted);
}

TEST(SimFabric, SameSeedSameTraceDifferentSeedDiffers) {
  FaultConfig f;
  f.drop = 0.2;
  f.ordered = false;
  f.reorder = 0.3;
  f.duplicate_completion = 0.2;
  auto run = [&](std::uint64_t seed) {
    Rig r(f, seed);
    for (WrTag t = 0; t < 16; ++t) EXPECT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(t * 16, 16), t));
    r.net.run_until_idle();
    return r.net.trace_hash();
  };
  EXPECT_EQ(run(5), run(5));
  EXPECT_NE(run(5), run(6));
}

TEST(SimFabric, OrderedByDefaultEvenWithLargeJitter) {
  FaultConfig f;
  f.jitter = Nanos{500'000};
  for (std::uint64_t seed = 1; seed < 20; ++seed) {
    Rig r(f, seed);
    for (WrTag t = 0; t < 16; ++t) ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(t * 16, 16), t));
    auto c = r.drain(r.a);
    ASSERT_EQ(c.size(), 16u);
    for (std::size_t i = 0; i < c.size(); ++i) EXPECT_EQ(c[i].tag, i) << "seed " << seed;
  }
}

TEST(SimFabric, DropBreaksTheEndpointPair) {
  FaultConfig f;
  f.drop = 1.0;
  Rig r(f);
  for (WrTag t = 1; t <= 3; ++t) ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), t));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 3u);
  EXPECT_EQ(c[0].tag, 1u);
  EXPECT_EQ(c[0].status.error().code, ErrorCode::Timeout);  // the lost request
  for (int i = 1; i < 3; ++i) EXPECT_EQ(c[i].status.error().code, ErrorCode::Aborted);  // flushed
  EXPECT_TRUE(r.ep->drained());
  // Both ends are in ERR: new posts fail on either side.
  auto s = r.ep->post_read(r.remote(0, 16), r.local(0, 16), 9);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::Aborted);
  ASSERT_NE(r.accepted, nullptr);
  EXPECT_FALSE(r.accepted->post_send(Frame{{std::byte{1}}}, 1));
}

TEST(SimFabric, AbortFlushesEagerlyWithoutAdvancingTime) {
  Rig r;
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  r.ep->abort();
  EXPECT_TRUE(r.ep->drained());  // before any event ran
  std::array<Completion, 4> batch;
  ASSERT_EQ(r.a.poll(batch), 1u);
  EXPECT_EQ(batch[0].status.error().code, ErrorCode::Aborted);
  EXPECT_EQ(r.clock.now(), Nanos{0});
  r.net.run_until_idle();  // the stale delivery event must be a no-op
  EXPECT_EQ(r.a.poll(batch), 0u);
}

TEST(SimFabric, AbortBeatsDropFate) {
  FaultConfig f;
  f.drop = 1.0;
  Rig r(f);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  r.ep->abort();
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].status.error().code, ErrorCode::Aborted);
}

TEST(SimFabric, AbortOnOneEndFlushesTheOther) {
  Rig r;
  ASSERT_NE(r.accepted, nullptr);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  r.accepted->abort();
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].status.error().code, ErrorCode::Aborted);
}

TEST(SimFabric, LinkDownBeatsDropFate) {
  FaultConfig f;
  f.drop = 1.0;
  Rig r(f);
  r.net.set_link(1, 2, false);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 16), r.local(0, 16), 1));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].status.error().code, ErrorCode::LinkDown);
}

TEST(SimFabric, RecvIsFlaggedNotTagZero) {
  Rig r;
  ASSERT_TRUE(r.ep->post_send(Frame{{std::byte{7}}}, 0));  // caller tag 0 is legal
  r.net.run_until_idle();
  auto recv = r.drain(r.b);
  ASSERT_EQ(recv.size(), 1u);
  EXPECT_TRUE(recv[0].is_recv);
  auto sent = r.drain(r.a);
  ASSERT_EQ(sent.size(), 1u);
  EXPECT_FALSE(sent[0].is_recv);
  EXPECT_EQ(sent[0].tag, 0u);
}

TEST(SimFabric, OversizedFrameRefused) {
  Rig r;
  auto s = r.ep->post_send(Frame{std::vector<std::byte>(kMaxFrameBytes + 1)}, 1);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::InvalidArgument);
  EXPECT_TRUE(r.ep->post_send(Frame{std::vector<std::byte>(kMaxFrameBytes)}, 2));
}

TEST(SimFabric, CqOverflowIsAnErrorAndBreaksEndpoints) {
  SimClock clock;
  SeededRandom rng(1);
  SimNetwork net(clock, rng, {});
  auto& a = net.add_node(1, /*cq_capacity=*/2);
  auto& b = net.add_node(2);
  std::vector<std::byte> rbuf(64), lbuf(64);
  auto rmr = b.reg(rbuf, Access::RemoteRead).value();
  auto lmr = a.reg(lbuf, Access::LocalWrite).value();
  ASSERT_TRUE(b.listen([](Endpoint*) {}, open_listen()));
  Endpoint* ep = a.connect(Peer{2}).value();
  for (WrTag t = 0; t < 5; ++t) {
    ASSERT_TRUE(ep->post_read({rmr.rkey, reinterpret_cast<std::uint64_t>(rbuf.data()), 8},
                              {lmr.lkey, lbuf.data(), 8}, t));
  }
  net.run_until_idle();
  EXPECT_TRUE(a.cq_overflowed());
  std::array<Completion, 16> out;
  const auto n = a.poll(out);
  ASSERT_EQ(n, 3u);  // two queued completions, then the overflow error
  EXPECT_EQ(out[2].op, CompletionOp::CqError);
  EXPECT_EQ(out[2].status.error().code, ErrorCode::ResourceExhausted);
  EXPECT_EQ(a.poll(out), 0u);
  EXPECT_FALSE(ep->post_read({rmr.rkey, reinterpret_cast<std::uint64_t>(rbuf.data()), 8},
                             {lmr.lkey, lbuf.data(), 8}, 9));
  EXPECT_TRUE(ep->drained());
}

TEST(SimFabric, DeregMustMatchRegistration) {
  Rig r;
  MemRegion wrong = r.local_mr;
  wrong.len -= 1;
  auto s = r.a.dereg(wrong);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::InvalidArgument);
  wrong = r.local_mr;
  wrong.addr += 1;
  EXPECT_FALSE(r.a.dereg(wrong));
  EXPECT_TRUE(r.a.dereg(r.local_mr));
}

TEST(SimFabric, OverlappingReadUsesMemmove) {
  Rig r;
  // The "remote" region and the local sink alias the same bytes.
  auto alias = r.a.reg(r.remote_buf, Access::LocalWrite).value();
  std::vector<std::byte> expect(r.remote_buf.begin(), r.remote_buf.begin() + 200);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 200), LocalRef{alias.lkey, r.remote_buf.data() + 50, 200}, 1));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_TRUE(c[0].status);
  EXPECT_EQ(std::memcmp(r.remote_buf.data() + 50, expect.data(), 200), 0);
}

// As on verbs, a connect to a node with no listener (or no node at all) is LinkDown.
TEST(SimFabric, ConnectWithoutListenerIsLinkDown) {
  Rig r;
  for (std::uint32_t node : {1u, 7u}) {  // node 1 (r.a) never listens; node 7 does not exist
    auto e = r.b.connect(Peer{node});
    ASSERT_FALSE(e);
    EXPECT_EQ(e.error().code, ErrorCode::LinkDown) << e.error().context;
  }
}

// As on verbs, a connect to an address the node is not listening on is refused, even with one listener.
TEST(SimFabric, ConnectToAnAddressNobodyListensOnIsLinkDown) {
  SimClock clock;
  SeededRandom rng(1);
  SimNetwork net(clock, rng, {}, {});
  SimFabric& a = net.add_node(1);
  SimFabric& b = net.add_node(2);
  ListenParams lp = open_listen();
  lp.addr = RailAddr{"10.0.0.1", 7471};
  ASSERT_TRUE(b.listen([](Endpoint*) {}, lp));
  Peer wrong{2};
  wrong.addr = RailAddr{"10.0.0.9", 7471};
  auto e = a.connect(wrong);
  ASSERT_FALSE(e);
  EXPECT_EQ(e.error().code, ErrorCode::LinkDown) << e.error().context;
  Peer right{2};
  right.addr = lp.addr;
  EXPECT_TRUE(a.connect(right));
  EXPECT_TRUE(a.connect(Peer{2}));  // no address given: the only listener
}

TEST(SimFabric, UnconnectedEndpointRefusesPosts) {
  Rig r;
  SimEndpoint lone(r.a, 99);
  auto s = lone.post_send(Frame{}, 1);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::NotFound);
  EXPECT_FALSE(lone.post_read(r.remote(0, 16), r.local(0, 16), 1));
}

TEST(FaultConfig, Validation) {
  EXPECT_TRUE(FaultConfig{}.validate());
  auto bad = [](auto mutate) {
    FaultConfig f;
    mutate(f);
    return !f.validate().has_value();
  };
  EXPECT_TRUE(bad([](FaultConfig& f) { f.base_delay = Nanos{-1}; }));
  EXPECT_TRUE(bad([](FaultConfig& f) { f.jitter = Nanos{-1}; }));
  EXPECT_TRUE(bad([](FaultConfig& f) { f.drop_timeout = Nanos{-5}; }));
  EXPECT_TRUE(bad([](FaultConfig& f) { f.reorder_window = Nanos{-5}; }));
  EXPECT_TRUE(bad([](FaultConfig& f) { f.jitter = FaultConfig::kMaxDelay + Nanos{1}; }));
  EXPECT_TRUE(bad([](FaultConfig& f) { f.drop = -0.1; }));
  EXPECT_TRUE(bad([](FaultConfig& f) { f.drop = 1.1; }));
  EXPECT_TRUE(bad([](FaultConfig& f) { f.duplicate_completion = std::nan(""); }));
  EXPECT_TRUE(bad([](FaultConfig& f) { f.reorder = 0.1; }));  // needs ordered = false
  EXPECT_FALSE(bad([](FaultConfig& f) { f.ordered = false; f.reorder = 0.1; }));
}

TEST(SimNetworkDeathTest, NegativeScheduleDelayAndInvalidConfigTrap) {
  SimClock clock;
  SeededRandom rng(1);
  SimNetwork net(clock, rng, {});
  EXPECT_DEATH(net.schedule(Nanos{-1}, [] {}), "check failed");
  FaultConfig bad;
  bad.drop = 2.0;
  EXPECT_DEATH(SimNetwork(clock, rng, bad), "check failed");
}

TEST(SimFabric, ReleaseFreesEndpointsAndRefusesBusy) {
  Rig r;
  ASSERT_TRUE(r.accepted != nullptr);
  EXPECT_EQ(r.a.endpoint_count(), 1u);
  ASSERT_TRUE(r.ep->post_read(r.remote(0, 64), r.local(0, 64), 1));
  auto busy = r.a.release(r.ep);
  ASSERT_FALSE(busy);
  EXPECT_EQ(busy.error().code, ErrorCode::Busy);
  r.drain(r.a);
  EXPECT_TRUE(r.a.release(r.ep));
  EXPECT_EQ(r.a.endpoint_count(), 0u);
  EXPECT_FALSE(r.a.release(r.ep));  // already gone
  EXPECT_EQ(r.accepted->state(), EpState::Error);  // the peer end went to ERR
  ASSERT_TRUE(r.b.release(r.accepted));
  for (int i = 0; i < 10; ++i) {
    auto e = r.a.connect(Peer{2});
    ASSERT_TRUE(e);
    ASSERT_TRUE(r.a.release(*e));
    ASSERT_TRUE(r.b.release(r.accepted));
  }
  EXPECT_EQ(r.a.endpoint_count(), 0u);
  EXPECT_EQ(r.b.endpoint_count(), 0u);
}

TEST(SimFabric, RegionInOtherPdIsNotUsable) {
  Rig r;
  auto pd_a = r.a.alloc_pd();
  auto pd_b = r.b.alloc_pd();
  ASSERT_TRUE(pd_a);
  ASSERT_TRUE(pd_b);
  std::vector<std::byte> lbuf(4096), rbuf(4096);
  auto sink = r.a.reg(lbuf, Access::LocalWrite, *pd_a).value();
  auto remote = r.b.reg(rbuf, Access::RemoteRead, *pd_b).value();
  EXPECT_FALSE(r.a.free_pd(*pd_a));  // region still registered
  RemoteRef rr{remote.rkey, reinterpret_cast<std::uint64_t>(rbuf.data()), 4096};
  // The rig's endpoints live in the default PD: the local sink in PD A is refused.
  auto local = r.ep->post_read(rr, LocalRef{sink.lkey, lbuf.data(), 4096}, 1);
  ASSERT_FALSE(local);
  EXPECT_EQ(local.error().code, ErrorCode::InvalidArgument);
  // The remote region in PD B is not reachable through the peer's default-PD endpoint.
  auto dst = r.a.reg(r.local_buf, Access::LocalWrite).value();
  ASSERT_TRUE(r.ep->post_read(rr, LocalRef{dst.lkey, r.local_buf.data(), 4096}, 2));
  auto c = r.drain(r.a);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_FALSE(c[0].status);
}

// The sim follows the verbs listen/admission rules (class and PD from the Admission,
// unknown PDs refused, max_pending_accepts must be positive).
TEST(SimFabric, AdmissionChoosesClassAndPd) {
  SimClock clock;
  SeededRandom rng(1);
  SimNetwork net(clock, rng, FaultConfig{});
  SimFabric& a = net.add_node(1);
  SimFabric& b = net.add_node(2);
  auto pd = b.alloc_pd();
  ASSERT_TRUE(pd);
  ListenParams zero;
  zero.allow_unauthenticated_for_test = true;
  zero.max_pending_accepts = 0;
  EXPECT_FALSE(b.listen([](Endpoint*) {}, zero));
  ListenParams bad_pd;
  bad_pd.allow_unauthenticated_for_test = true;
  bad_pd.accept_pd = PdId{99};
  EXPECT_FALSE(b.listen([](Endpoint*) {}, bad_pd));

  SimEndpoint* accepted = nullptr;
  ListenParams lp;
  lp.admit = [pd = *pd](std::span<const std::byte> t) -> Expected<Admission> {
    if (t.size() == 1 && t[0] == std::byte{1}) return Admission{EpClass::Fetch, pd};
    if (t.size() == 1 && t[0] == std::byte{2}) return Admission{EpClass::Control, PdId{77}};  // unknown PD
    return Error{ErrorCode::AccessDenied, "unknown ticket"};
  };
  ASSERT_TRUE(b.listen([&](Endpoint* e) { accepted = static_cast<SimEndpoint*>(e); }, lp));

  ConnParams cp;
  cp.ticket_len = 1;
  cp.ticket[0] = std::byte{1};
  ASSERT_TRUE(a.connect(Peer{2}, cp));
  ASSERT_NE(accepted, nullptr);
  EXPECT_EQ(accepted->cls(), EpClass::Fetch);
  EXPECT_EQ(accepted->pd(), *pd);

  cp.ticket[0] = std::byte{2};
  auto unknown = a.connect(Peer{2}, cp);
  ASSERT_FALSE(unknown);
  EXPECT_EQ(unknown.error().code, ErrorCode::AccessDenied);
  cp.ticket[0] = std::byte{3};
  auto refused = a.connect(Peer{2}, cp);
  ASSERT_FALSE(refused);
  EXPECT_EQ(refused.error().code, ErrorCode::AccessDenied);
}

// ---- Sliced placement, iWARP early WRITE CQE, mandatory admission ----

namespace {

constexpr std::uint32_t kOp = 2048;

SimOptions sliced(std::uint32_t slice, bool iwarp = false) {
  SimOptions o;
  o.slice_size = slice;
  o.iwarp_early_write_cqe = iwarp;
  return o;
}

// A WRITE of 0xBB over bytes [0, kOp) racing a READ of the same bytes. Returns true when the
// READ saw a mix of old and new bytes.
bool read_is_torn(std::uint64_t seed, std::uint32_t slice) {
  Rig r({}, seed, sliced(slice));
  std::memset(r.local_buf.data() + kOp, 0xBB, kOp);
  EXPECT_TRUE(r.ep->post_write(r.local(kOp, kOp), r.remote(0, kOp), 1));
  EXPECT_TRUE(r.ep->post_read(r.remote(0, kOp), r.local(0, kOp), 2));
  const auto c = r.drain(r.a);
  EXPECT_EQ(c.size(), 2u);
  bool any_new = false, any_old = false;
  for (std::uint32_t i = 0; i < kOp; ++i) {
    (r.local_buf[i] == std::byte{0xBB} ? any_new : any_old) = true;
  }
  return any_new && any_old;
}

// True when the WRITE's CQE was visible before the whole payload was placed.
bool write_cqe_before_placement(std::uint64_t seed, bool iwarp) {
  Rig r({}, seed, sliced(256, iwarp));
  std::memset(r.local_buf.data(), 0xCC, kOp);
  EXPECT_TRUE(r.ep->post_write(r.local(0, kOp), r.remote(0, kOp), 1));
  std::array<Completion, 4> out;
  for (int guard = 0; guard < 10000; ++guard) {
    if (r.a.poll(out) > 0) {
      bool all = true;
      for (std::uint32_t i = 0; i < kOp; ++i) all = all && r.remote_buf[i] == std::byte{0xCC};
      r.net.run_until_idle();
      for (std::uint32_t i = 0; i < kOp; ++i) EXPECT_EQ(r.remote_buf[i], std::byte{0xCC});  // lands eventually
      return !all;
    }
    if (!r.net.step()) break;
  }
  ADD_FAILURE() << "no completion";
  return false;
}

std::uint64_t sliced_trace(std::uint64_t seed) {
  Rig r({}, seed, sliced(256, true));
  std::memset(r.local_buf.data() + kOp, 0xBB, kOp);
  EXPECT_TRUE(r.ep->post_write(r.local(kOp, kOp), r.remote(0, kOp), 1));
  EXPECT_TRUE(r.ep->post_read(r.remote(0, kOp), r.local(0, kOp), 2));
  r.drain(r.a);
  return r.net.trace_hash();
}

}  // namespace

TEST(SimFabric, SlicedReadVsWriteIsTornForSomeSeed) {
  int torn = 0;
  for (std::uint64_t seed = 1; seed <= 200; ++seed) torn += read_is_torn(seed, 256) ? 1 : 0;
  EXPECT_GT(torn, 0);
}

TEST(SimFabric, NoTearWhenSliceCoversOp) {
  for (std::uint64_t seed = 1; seed <= 200; ++seed) {
    EXPECT_FALSE(read_is_torn(seed, kOp)) << seed;
    EXPECT_FALSE(read_is_torn(seed, 4096)) << seed;
  }
}

TEST(SimFabric, IwarpWriteCqeCanPrecedePlacement) {
  int early = 0;
  for (std::uint64_t seed = 1; seed <= 200; ++seed) early += write_cqe_before_placement(seed, true) ? 1 : 0;
  EXPECT_GT(early, 0);
}

TEST(SimFabric, RoceWriteCqeFollowsLastSlice) {
  for (std::uint64_t seed = 1; seed <= 200; ++seed) EXPECT_FALSE(write_cqe_before_placement(seed, false)) << seed;
}

TEST(SimFabric, SameSeedSameSlicedTrace) {
  EXPECT_EQ(sliced_trace(7), sliced_trace(7));
  EXPECT_NE(sliced_trace(7), sliced_trace(8));
}

TEST(SimFabric, ListenRequiresAdmitUnlessOptedOut) {
  SimClock clock;
  SeededRandom rng(1);
  SimNetwork net(clock, rng, FaultConfig{});
  SimFabric& b = net.add_node(2);
  EXPECT_FALSE(b.listen([](Endpoint*) {}));
  EXPECT_FALSE(b.listen([](Endpoint*) {}, ListenParams{}));
  EXPECT_TRUE(b.listen([](Endpoint*) {}, open_listen()));
}

TEST(SimFabric, AdmitCanReject) {
  SimClock clock;
  SeededRandom rng(1);
  SimNetwork net(clock, rng, FaultConfig{});
  SimFabric& a = net.add_node(1);
  SimFabric& b = net.add_node(2);
  ListenParams lp;
  lp.admit = [](std::span<const std::byte>) -> Expected<Admission> {
    return Error{ErrorCode::AccessDenied, "no"};
  };
  bool accepted = false;
  ASSERT_TRUE(b.listen([&](Endpoint*) { accepted = true; }, lp));
  auto e = a.connect(Peer{2});
  ASSERT_FALSE(e);
  EXPECT_EQ(e.error().code, ErrorCode::AccessDenied);
  EXPECT_FALSE(accepted);
}

// The admit-error -> CM reject byte -> active-side error table. A "busy" refusal (a draining
// node) must not read as AccessDenied, or the client burns ticket_attempts tickets per refused attempt.
TEST(ProtocolRules, AdmitRejectMapping) {
  using namespace miracache::fabric::protocol;
  EXPECT_EQ(admit_reject_code(ErrorCode::Busy), kRejectBusy);
  EXPECT_EQ(admit_reject_code(ErrorCode::ResourceExhausted), kRejectResources);
  for (auto c : {ErrorCode::AccessDenied, ErrorCode::Timeout, ErrorCode::InvalidArgument, ErrorCode::Corrupt})
    EXPECT_EQ(admit_reject_code(c), kRejectAdmit);
  EXPECT_EQ(reject_error(kRejectBusy).code, ErrorCode::Busy);
  EXPECT_EQ(reject_error(kRejectResources).code, ErrorCode::ResourceExhausted);
  EXPECT_EQ(reject_error(kRejectAdmit).code, ErrorCode::AccessDenied);
  // No miracache byte (kernel REJ / ECONNREFUSED: host up, memory node gone) is LinkDown, not
  // AccessDenied, so a client in the down window draws one ticket per attempt, not ticket_attempts.
  EXPECT_EQ(reject_error(kRejectNone).code, ErrorCode::LinkDown);
  EXPECT_EQ(reject_error(200).code, ErrorCode::LinkDown);  // unknown byte from a newer peer: backoff, one ticket
  // Round trip: what the passive side's admit said is what the active side sees, for the codes that matter.
  for (auto c : {ErrorCode::Busy, ErrorCode::ResourceExhausted, ErrorCode::AccessDenied})
    EXPECT_EQ(reject_error(admit_reject_code(c)).code, c);
}

// The sim maps admit errors through the same table: Busy stays Busy, an expired ticket
// (Timeout from the ticket table) reads as AccessDenied exactly as on verbs.
TEST(SimFabric, AdmitErrorsGoThroughTheRejectTable) {
  SimClock clock;
  SeededRandom rng(1);
  SimNetwork net(clock, rng, FaultConfig{});
  SimFabric& a = net.add_node(1);
  SimFabric& b = net.add_node(2);
  ErrorCode next = ErrorCode::Busy;
  ListenParams lp;
  lp.admit = [&next](std::span<const std::byte>) -> Expected<Admission> { return Error{next, "refused"}; };
  ASSERT_TRUE(b.listen([](Endpoint*) {}, lp));
  for (auto [in, out] : {std::pair{ErrorCode::Busy, ErrorCode::Busy},
                         std::pair{ErrorCode::ResourceExhausted, ErrorCode::ResourceExhausted},
                         std::pair{ErrorCode::Timeout, ErrorCode::AccessDenied},
                         std::pair{ErrorCode::AccessDenied, ErrorCode::AccessDenied}}) {
    next = in;
    auto e = a.connect(Peer{2});
    ASSERT_FALSE(e);
    EXPECT_EQ(e.error().code, out) << static_cast<int>(in);
  }
}
