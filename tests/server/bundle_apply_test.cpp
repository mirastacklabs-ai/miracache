// SPDX-License-Identifier: Apache-2.0
// MB3b: Server::apply_bundle in full. Principals (computed IDs, bindings, revocation), quota policies by the QT3
// formula, member state apart from the SIGTERM latch (P08), drop_before (monotonic, opened_at, re-applied, at load).
// Bundles are built directly as views (the signature path is MB2/MB3a's tests).
#include <memory>
#include <string>

#include <gtest/gtest.h>

#include "control/bundle.h"
#include "fabric/sim/sim_fabric.h"
#include "server/node_config.h"
#include "server/server.h"
#include "util/clock.h"
#include "util/executor.h"
#include "util/random.h"

namespace miracache::server {
namespace {

using namespace std::chrono_literals;
using control::MemberState;

constexpr std::int64_t kWallBase = 1'700'000'000LL * 1'000'000'000LL;  // wall time at clock 0 (injected)

store::StoreConfig store_cfg() {
  store::StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 1u << 20;
  c.principal_default.idle_ttl = std::chrono::seconds(10000);
  c.invalidate_per_s = 0;
  return c;
}

control::PrincipalView principal(const std::string& name, std::vector<std::string> ids, std::uint64_t quota,
                                 std::optional<std::int64_t> drop_before = std::nullopt) {
  control::PrincipalView p;
  p.name = name;
  p.id = control::principal_id(name);
  p.identities = std::move(ids);
  p.quota_bytes = quota;
  p.max_scopes = 100;
  p.drop_before = drop_before;
  return p;
}

control::NodeView node(std::uint32_t id, std::uint32_t weight, MemberState st = MemberState::Active) {
  control::NodeView n;
  n.node_id = id;
  n.hostname = "host" + std::to_string(id);
  n.admin = "10.0.0." + std::to_string(id % 200) + ":9465";
  n.rails.push_back({"10.0.0.1:7471", "a", "roce"});
  n.weight = weight;
  n.state = st;
  return n;
}

struct Fx {
  Fx() : rng(3), net(clock, rng, {}, {}), fab(net.add_node(1)) {
    ServerConfig sc;
    sc.store = store_cfg();
    sc.lab_identity = "spiffe://lab/old";
    sc.wall_unix_ns = [this] { return kWallBase + clock.now().count(); };
    auto s = Server::create(sc, fab, clock, rng, exec);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
    self = server->node_id();
  }
  control::BundleView bundle(std::uint64_t gen, std::vector<control::PrincipalView> ps, std::vector<control::NodeView> nodes) {
    control::BundleView v;
    v.body.generation = gen;
    v.body.epoch = static_cast<std::uint32_t>(gen);
    v.sec.sec_generation = gen;
    v.sec.principals = std::move(ps);
    v.body.nodes = std::move(nodes);
    return v;
  }
  void turn(std::chrono::milliseconds d = 5ms) {  // advance time and run the loop (tick + sweep)
    clock.advance_by(d);
    server->run_once();
  }
  void settle() {
    for (int i = 0; i < 200 && server->store().sweep_pending(); ++i) turn();
  }
  store::ScopeId sc(int i) {
    store::ScopeId s{};
    s[0] = static_cast<std::uint8_t>(i);
    return s;
  }
  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& fab;
  InlineExecutor exec;
  std::unique_ptr<Server> server;
  std::uint32_t self = 0;
};

TEST(BundleApply, PrincipalIdsAreComputedAndIdentitiesBound) {
  Fx f;
  ASSERT_TRUE(f.server->issue_ticket("spiffe://lab/old", fabric::EpClass::Control, 0, 1));  // lab mode before the bundle
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a", "spiffe://prod/b"}, 1 << 20)}, {node(f.self, 1)}));
  auto b = f.server->tickets().principals().find("spiffe://prod/a");
  ASSERT_TRUE(b);
  EXPECT_EQ(*b, control::principal_id("prod"));  // the ID is computed from the name, never typed
  EXPECT_TRUE(f.server->issue_ticket("spiffe://prod/b", fabric::EpClass::Control, 0, 1));
  EXPECT_FALSE(f.server->issue_ticket("spiffe://lab/old", fabric::EpClass::Control, 0, 1));  // lab binding gone in bundle mode
  EXPECT_EQ(f.server->applied_bundle().generation, 1u);
}

TEST(BundleApply, NewIdentitiesGetTicketsRemovedOnesLoseThemAndTheirTickets) {
  Fx f;
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a", "spiffe://prod/b"}, 1 << 20)}, {node(f.self, 1)}));
  EXPECT_FALSE(f.server->issue_ticket("spiffe://new/c", fabric::EpClass::Control, 0, 1));
  ASSERT_TRUE(f.server->issue_ticket("spiffe://prod/a", fabric::EpClass::Control, 0, 3));
  ASSERT_TRUE(f.server->issue_ticket("spiffe://prod/b", fabric::EpClass::Control, 0, 2));
  EXPECT_EQ(f.server->tickets().live_for("spiffe://prod/a"), 3u);
  // b leaves, c arrives under another principal.
  f.server->apply_bundle(f.bundle(2, {principal("prod", {"spiffe://prod/a"}, 1 << 20), principal("dev", {"spiffe://new/c"}, 1 << 20)},
                                  {node(f.self, 1)}));
  EXPECT_FALSE(f.server->issue_ticket("spiffe://prod/b", fabric::EpClass::Control, 0, 1));
  EXPECT_EQ(f.server->tickets().live_for("spiffe://prod/b"), 0u);  // its live tickets are revoked
  EXPECT_EQ(f.server->tickets().live_for("spiffe://prod/a"), 3u);  // untouched
  EXPECT_TRUE(f.server->issue_ticket("spiffe://new/c", fabric::EpClass::Control, 0, 1));
  // a moves to dev: re-bound, its tickets revoked (they named the old principal).
  f.server->apply_bundle(f.bundle(3, {principal("dev", {"spiffe://new/c", "spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1)}));
  EXPECT_EQ(*f.server->tickets().principals().find("spiffe://prod/a"), control::principal_id("dev"));
  EXPECT_EQ(f.server->tickets().live_for("spiffe://prod/a"), 0u);
}

TEST(BundleApply, QuotaShareFollowsWeights) {  // QT3: 1/1/2 -> 1/4, 1/4, 1/2
  const std::uint64_t quota = 4ull << 30;
  const std::uint32_t w[3][3] = {{1, 1, 2}, {1, 1, 2}, {1, 1, 2}};
  for (int me = 0; me < 3; ++me) {
    Fx f;
    std::vector<control::NodeView> ns{node(f.self, w[me][0]), node(f.self + 1, w[me][1]), node(f.self + 2, w[me][2])};
    // Put this node in slot `me` of the weights 1/1/2.
    const std::uint32_t weights[3] = {1, 1, 2};
    ns[0].weight = weights[me];
    ns[1].weight = weights[(me + 1) % 3];
    ns[2].weight = weights[(me + 2) % 3];
    f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a"}, quota)}, ns));
    const std::uint64_t want = me == 2 ? quota / 2 : quota / 4;
    EXPECT_EQ(f.server->principal_cap_bytes(control::principal_id("prod")), want) << "slot " << me;
  }
}

TEST(BundleApply, DrainingNodeCapIsStatelessSelfShare) {  // P38: w_self / (sum w_active + w_self)
  Fx f;
  const std::uint64_t quota = 4ull << 30;
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a"}, quota)},
                                  {node(f.self, 1, MemberState::Draining), node(f.self + 1, 1), node(f.self + 2, 2)}));
  EXPECT_EQ(f.server->principal_cap_bytes(control::principal_id("prod")), quota / 4);  // 1 / (3 + 1)
  // A node the bundle does not list: weight 1, non-active.
  f.server->apply_bundle(f.bundle(2, {principal("prod", {"spiffe://prod/a"}, quota)}, {node(f.self + 1, 1), node(f.self + 2, 2)}));
  EXPECT_EQ(f.server->principal_cap_bytes(control::principal_id("prod")), quota / 4);
}

TEST(BundleApply, CapReachesTheStoreAndAJoinCutIsBounded) {
  Fx f;
  const auto pid = control::principal_id("prod");
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1)}));
  EXPECT_TRUE(f.server->store().reserve_inflight(pid, 1 << 20));  // the whole quota fits alone
  f.server->store().release_inflight(pid, 1 << 20);
  // Join: the node is one of two equal nodes now, cap halves.
  f.server->apply_bundle(f.bundle(2, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1), node(f.self + 1, 1)}));
  EXPECT_EQ(f.server->principal_cap_bytes(pid), (1u << 20) / 2);
  EXPECT_FALSE(f.server->store().reserve_inflight(pid, (1 << 20) / 2 + 1));
  EXPECT_TRUE(f.server->store().reserve_inflight(pid, (1 << 20) / 2));
  f.server->store().release_inflight(pid, (1 << 20) / 2);
}

TEST(BundleApply, MemberStateIsDerivedAndSeparateFromTheSigtermLatch) {  // P08
  Fx f;
  auto ps = [] { return std::vector<control::PrincipalView>{principal("prod", {"spiffe://prod/a"}, 1 << 20)}; };
  f.server->apply_bundle(f.bundle(1, ps(), {node(f.self, 1), node(f.self + 1, 1)}));
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Active);
  EXPECT_TRUE(f.server->accepts_root_puts());
  f.server->apply_bundle(f.bundle(2, ps(), {node(f.self, 1, MemberState::Draining), node(f.self + 1, 1)}));
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Draining);
  EXPECT_FALSE(f.server->accepts_root_puts());
  f.server->apply_bundle(f.bundle(3, ps(), {node(f.self, 1, MemberState::Readonly), node(f.self + 1, 1)}));
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Readonly);
  f.server->apply_bundle(f.bundle(4, ps(), {node(f.self + 1, 1)}));  // removed
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Removed);
  EXPECT_FALSE(f.server->accepts_root_puts());
  f.server->apply_bundle(f.bundle(5, ps(), {node(f.self, 1), node(f.self + 1, 1)}));  // re-added: serves again
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Active);
  EXPECT_TRUE(f.server->accepts_root_puts());
  EXPECT_FALSE(f.server->draining());
}

TEST(BundleApply, SigtermLatchSurvivesApplyAndDoesNotLeakIntoMemberState) {
  Fx f;
  auto ps = [] { return std::vector<control::PrincipalView>{principal("prod", {"spiffe://prod/a"}, 1 << 20)}; };
  f.server->apply_bundle(f.bundle(1, ps(), {node(f.self, 1)}));
  f.server->begin_drain(proto::GoawayReason::Shutdown, 1000);
  f.server->apply_bundle(f.bundle(2, ps(), {node(f.self, 1)}));
  EXPECT_EQ(f.server->member_state(), Server::MemberState::Active);  // the bundle says active ...
  EXPECT_TRUE(f.server->draining());                                    // ... the one-way latch is untouched
  EXPECT_FALSE(f.server->accepts_root_puts());
}

TEST(BundleApply, DropBeforeComparesOpenedAtAndIsIncremental) {
  Fx f;
  const auto pid = control::principal_id("prod");
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1)}));
  // Scope 1 is opened at 0 s and kept fresh by activity (last_used recent); scope 2 opens at 100 s.
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));
  f.clock.advance_by(100s);
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));  // renewed: last_used = 100 s
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(2), f.clock.now()));
  const std::int64_t drop = kWallBase / 1'000'000'000LL + 50;  // 50 s after scope 1 opened, 50 s before scope 2
  f.server->apply_bundle(f.bundle(2, {principal("prod", {"spiffe://prod/a"}, 1 << 20, drop)}, {node(f.self, 1)}));
  f.settle();
  EXPECT_FALSE(f.server->store().has_scope(pid, f.sc(1)));  // opened_at < drop_before, though last_used is recent
  EXPECT_TRUE(f.server->store().has_scope(pid, f.sc(2)));
}

TEST(BundleApply, DropBeforeIsMonotonicAndReappliedOnEveryApply) {
  Fx f;
  const auto pid = control::principal_id("prod");
  auto ps = [](std::optional<std::int64_t> d) { return std::vector<control::PrincipalView>{principal("prod", {"spiffe://prod/a"}, 1 << 20, d)}; };
  f.server->apply_bundle(f.bundle(1, ps(std::nullopt), {node(f.self, 1)}));
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));
  f.clock.advance_by(100s);
  const std::int64_t base = kWallBase / 1'000'000'000LL;
  f.server->apply_bundle(f.bundle(2, ps(base + 50), {node(f.self, 1)}));
  f.settle();
  EXPECT_FALSE(f.server->store().has_scope(pid, f.sc(1)));
  // A scope opened at 100 s survives; later bundles with a LOWER or absent drop_before must not lift or lower anything.
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(2), f.clock.now()));
  f.server->apply_bundle(f.bundle(3, ps(base + 10), {node(f.self, 1)}));
  f.server->apply_bundle(f.bundle(4, ps(std::nullopt), {node(f.self, 1)}));
  f.settle();
  EXPECT_TRUE(f.server->store().has_scope(pid, f.sc(2)));
  // The maximum rises: a newer drop_before kills the scope opened at 100 s.
  f.clock.advance_by(100s);
  f.server->apply_bundle(f.bundle(5, ps(base + 150), {node(f.self, 1)}));
  f.settle();
  EXPECT_FALSE(f.server->store().has_scope(pid, f.sc(2)));
}

TEST(BundleApply, DropBeforeFromTheFloorIsHonouredAtLoad) {
  Fx f;
  const auto pid = control::principal_id("prod");
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));  // warm scope from before
  f.clock.advance_by(100s);
  const std::int64_t base = kWallBase / 1'000'000'000LL;
  f.server->load_drop_before_floor({{"prod", base + 50}});  // the floor remembers it ...
  f.server->apply_bundle(f.bundle(9, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1)}));  // ... the bundle does not
  f.settle();
  EXPECT_FALSE(f.server->store().has_scope(pid, f.sc(1)));
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(2), f.clock.now()));
  EXPECT_TRUE(f.server->store().has_scope(pid, f.sc(2)));
}

TEST(BundleApply, RootPutToADeadScopeStartsAFreshOne) {
  Fx f;
  const auto pid = control::principal_id("prod");
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1)}));
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));
  f.clock.advance_by(100s);
  const std::int64_t base = kWallBase / 1'000'000'000LL;
  f.server->apply_bundle(f.bundle(2, {principal("prod", {"spiffe://prod/a"}, 1 << 20, base + 50)}, {node(f.self, 1)}));
  // Before any sweep turn: the reopen drops the (empty) old record and the put proceeds in a fresh scope.
  EXPECT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));
  f.settle();
  EXPECT_TRUE(f.server->store().has_scope(pid, f.sc(1)));  // the fresh one survives the sweep
}

TEST(BundleApply, MetricsCarryTheCapsAndMemberState) {
  Fx f;
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1)}));
  std::string text;
  f.server->metrics().write_prometheus(text);
  EXPECT_NE(text.find("miracache_principal_cap_bytes{"), std::string::npos);
  EXPECT_NE(text.find("principal=\"prod\""), std::string::npos);
  EXPECT_NE(text.find("miracache_member_state{"), std::string::npos);
  EXPECT_NE(text.find("miracache_bundle_principals"), std::string::npos);
}

TEST(BundleApply, Y08IdentitySnapshotCarriesMemberStateScopesAndBytes) {
  Fx f;
  const auto pid = control::principal_id("prod");
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1, MemberState::Draining)}));
  EXPECT_EQ(f.server->node_snapshot().member_state, "draining");  // set by the apply itself
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));
  f.server->publish_gauges();
  const auto s = f.server->node_snapshot();
  EXPECT_EQ(s.scopes, 1u);
  EXPECT_EQ(s.bytes_used, 0u);
  f.server->apply_bundle(f.bundle(2, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {}));
  EXPECT_EQ(f.server->node_snapshot().member_state, "removed");
}

TEST(BundleApply, Y18FutureDropBeforeIsClampedToNowAndZeroQuotaMeansNothing) {
  Fx f;
  const auto pid = control::principal_id("prod");
  f.server->apply_bundle(f.bundle(1, {principal("prod", {"spiffe://prod/a"}, 1 << 20)}, {node(f.self, 1)}));
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));
  f.clock.advance_by(1s);
  const std::int64_t future = kWallBase / 1'000'000'000LL + 100000;
  f.server->apply_bundle(f.bundle(2, {principal("prod", {"spiffe://prod/a"}, 1 << 20, future)}, {node(f.self, 1)}));
  f.settle();
  EXPECT_FALSE(f.server->store().has_scope(pid, f.sc(1)));  // existing scopes drop ...
  f.clock.advance_by(1s);
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(2), f.clock.now()));  // ... new ones live
  f.settle();
  EXPECT_TRUE(f.server->store().has_scope(pid, f.sc(2)));
  f.server->apply_bundle(f.bundle(3, {principal("zero", {"spiffe://zero/a"}, 0)}, {node(f.self, 1)}));
  EXPECT_EQ(f.server->principal_cap_bytes(control::principal_id("zero")), 1u);  // documented: stores nothing
}

}  // namespace
}  // namespace miracache::server
