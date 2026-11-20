// SPDX-License-Identifier: Apache-2.0
// HR1: the store-side setters behind the class A keys (Store::set_limits, set_retention, set_evict,
// SlabAllocator::set_max_exact_classes_per_owner, PutPath::set_timeouts). Each one changes the NEXT operation only;
// leases already granted and puts already begun keep what they were given.
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "fabric/sim/sim_fabric.h"
#include "store/mr_manager.h"
#include "store/put.h"

namespace miracache::store {
namespace {

using std::chrono::milliseconds;
using std::chrono::seconds;
constexpr std::uint64_t kBlk = 4096;

StoreConfig cfg() {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 8;
  c.gen_chunk = 1000;
  c.reap_grace = seconds(5);
  c.invalidate_per_s = 0;
  c.principal_default.max_scopes = 16;
  c.principal_default.max_bytes = 8000 * kBlk;
  c.principal_default.idle_ttl = seconds(10000);
  return c;
}
ScopeId sid(int i) {
  ScopeId s{};
  s[0] = static_cast<std::uint8_t>(i);
  s[31] = 0x5c;
  return s;
}
KeyHash kh(int i) {
  KeyHash k{};
  if (i != 0) k[0] = static_cast<std::uint8_t>(i & 0xff), k[1] = static_cast<std::uint8_t>(i >> 8), k[31] = 0xa1;
  return k;
}

struct Dummy final : Executor {
  void post(std::function<void()> work, std::function<void()> done) override {
    work();
    done();
  }
};

struct Fx {
  explicit Fx(StoreConfig c = cfg()) : rng(1), net(clock, rng, {}, {}), srv(net.add_node(1)) {
    auto a = Arena::open(c);
    EXPECT_TRUE(a);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
    ingest_pd = srv.alloc_pd().value();
    mrs = std::make_unique<MrManager>(srv, *arena, fabric::PdId{}, ingest_pd);
    while (mrs->step_registration().value()) {}
    store->set_readable([this](std::uint32_t seg) { return mrs->readable(seg); });
    puts = std::make_unique<PutPath>(*store, *slab, *mrs, *arena, clock, exec);
  }
  Status put(PrincipalId p, int s, int k, int parent) {
    if (parent == 0) {
      if (auto st = store->ensure_scope_for_root_put(p, sid(s), clock.now()); !st) return st;
    }
    const std::uint64_t lens[] = {kBlk};
    auto r = slab->alloc_batch(lens);
    EXPECT_TRUE(r);
    Status st = store->commit_block(p, sid(s), kh(k), kh(parent), (*r)[0], kBlk);
    if (!st) slab->free((*r)[0]);
    return st;
  }
  void chain(PrincipalId p, int s, int n) {
    for (int k = 1; k <= n; ++k) ASSERT_TRUE(put(p, s, k, k == 1 ? 0 : k - 1)) << k;
  }
  LookupAck look(PrincipalId p, int s, SessionId session = 99) {
    LookupReq q;
    q.principal = p;
    q.scope = sid(s);
    q.keys.push_back(kh(1));
    return store->lookup(session, q);
  }
  PutBeginAck begin(int scope, int first_key, int n) {
    PutBeginReq q;
    q.principal = 1;
    q.scope = sid(scope);
    for (int i = 0; i < n; ++i) {
      PutKey k;
      k.key = kh(first_key + i);
      k.parent = kh(i == 0 ? 0 : first_key + i - 1);
      k.chain_pos = static_cast<std::uint64_t>(i);
      k.stored_len = kBlk;
      q.keys.push_back(k);
    }
    return puts->put_begin(1, q);
  }
  static int accepted(const PutBeginAck& a) {
    int n = 0;
    for (auto& e : a.entries) n += e.accept;
    return n;
  }
  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& srv;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
  fabric::PdId ingest_pd;
  std::unique_ptr<MrManager> mrs;
  Dummy exec;
  std::unique_ptr<PutPath> puts;
};

TEST(LiveLimits, LeaseTtlAndMaxApplyToTheNextOperations) {
  Fx f;
  f.chain(1, 1, 3);
  const Nanos t0 = f.clock.now();
  const auto before = f.look(1, 1, 1);
  ASSERT_NE(before.lease, 0u);
  EXPECT_EQ(before.lease_expiry, t0 + seconds(30));  // the config default
  Store::Limits l = f.store->limits();
  l.lease_ttl = seconds(5);
  l.lease_max = seconds(8);
  f.store->set_limits(l);
  const auto after = f.look(1, 1, 2);
  EXPECT_EQ(after.lease_expiry, t0 + seconds(5));
  // The lease granted earlier keeps its expiry (a renew never shortens it); a renew of the new one follows ttl 5 / max 8.
  f.clock.advance_by(seconds(4));
  auto old_renew = f.store->renew(1, before.lease);
  ASSERT_TRUE(old_renew);
  EXPECT_EQ(*old_renew, t0 + seconds(30));
  auto ne = f.store->renew(2, after.lease);
  ASSERT_TRUE(ne);
  EXPECT_EQ(*ne, t0 + seconds(8));  // min(now + 5, granted + 8)
  auto st = f.store->check_invariants();
  EXPECT_TRUE(st) << (st ? "" : st.error().context);
  // Raising lease_max again keeps the ceiling rule: the invariant never trips on leases granted under a larger max.
  l.lease_max = seconds(2);
  l.lease_ttl = seconds(1);
  f.store->set_limits(l);
  EXPECT_TRUE(f.store->check_invariants());
}

TEST(LiveLimits, InvalidateRateIsLive) {
  Fx f;
  f.chain(1, 1, 3);
  for (int i = 0; i < 5; ++i) EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(90 + i), 1));  // 0 = unlimited
  Store::Limits l = f.store->limits();
  l.invalidate_per_s = 1;
  f.store->set_limits(l);
  EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(95), 1));
  auto second = f.store->invalidate(1, sid(1), kh(96), 1);
  ASSERT_FALSE(second);
  EXPECT_EQ(second.error().code, ErrorCode::ResourceExhausted);
}

TEST(LiveLimits, DefaultPolicyCapAndIdleTtlAreLive) {
  Fx f;
  f.chain(1, 1, 20);
  f.chain(2, 5, 4);
  EXPECT_EQ(f.store->bytes_used(1), 20 * kBlk);
  Store::Limits l = f.store->limits();
  l.def.max_bytes = 10 * kBlk;  // store.max_bytes: the default principal cap
  f.store->set_limits(l);
  for (int i = 0; i < 8; ++i) f.store->tick();
  EXPECT_LE(f.store->bytes_used(1), 10 * kBlk);  // a cap cut converges through the sweep
  EXPECT_LE(f.store->bytes_used(2), 10 * kBlk);
  // retention.idle_ttl_s: a scope idle past the new TTL misses.
  EXPECT_NE(f.look(2, 5, 3).lease, 0u);
  l.def.idle_ttl = seconds(20);
  f.store->set_limits(l);
  f.clock.advance_by(seconds(21));
  LookupReq q;
  q.principal = 2;
  q.scope = sid(5);
  q.keys.push_back(kh(1));
  auto a = f.store->lookup(98, q);
  EXPECT_FALSE(a.entries[0].hit);
}

TEST(LiveLimits, MaxScopesOfTheDefaultPolicyIsLive) {
  Fx f;
  Store::Limits l = f.store->limits();
  l.def.max_scopes = 2;
  f.store->set_limits(l);
  f.chain(1, 1, 2);
  f.chain(1, 2, 2);
  f.chain(1, 3, 2);  // the third root evicts the principal's LRU scope
  int live = 0;
  for (int s = 1; s <= 3; ++s) live += f.store->has_scope(1, sid(s)) ? 1 : 0;
  EXPECT_EQ(live, 2);
}

TEST(LiveLimits, RetentionAndEvictBudgetSetters) {
  Fx f;
  f.chain(1, 1, 50);
  f.store->set_retention(seconds(100));
  f.clock.advance_by(seconds(101));
  EXPECT_EQ(f.look(1, 1, 5).entries[0].hit, false);  // max_ttl from the next lookup on
  f.store->set_retention(Nanos{0});
  Fx g;
  g.store->set_evict(kBlk, 1, 90, 80);  // one block per turn, 4 KiB/s
  g.chain(1, 1, 30);
  g.store->set_retention(seconds(1));
  g.clock.advance_by(seconds(2));
  g.store->tick();
  EXPECT_GE(g.store->bytes_used(1), 28 * kBlk);  // the new budget bounds the reaping turn
}

TEST(LiveLimits, PutBucketsAreLive) {
  Fx f;
  EXPECT_EQ(Fx::accepted(f.begin(1, 1, 4)), 4);  // unlimited by default
  Store::Limits l = f.store->limits();
  l.def.put_ops_per_s = 2;  // quota.put_ops_per_s
  f.store->set_limits(l);
  f.clock.advance_by(seconds(2));
  EXPECT_EQ(Fx::accepted(f.begin(2, 10, 4)), 2);
  l.def.put_ops_per_s = 0;
  f.store->set_limits(l);
  EXPECT_EQ(Fx::accepted(f.begin(3, 20, 4)), 4);
}

TEST(LiveLimits, PutTimeoutAppliesToPutsBegunAfterwards) {
  Fx f;
  auto old_put = f.begin(1, 1, 1);
  ASSERT_NE(old_put.put_id, 0u);
  f.puts->set_timeouts(seconds(2));
  auto new_put = f.begin(2, 10, 1);
  ASSERT_NE(new_put.put_id, 0u);
  EXPECT_EQ(f.puts->n_puts(), 2u);
  f.clock.advance_by(seconds(3));
  f.puts->tick();
  EXPECT_EQ(f.puts->n_puts(), 1u);  // the new one timed out at 2 s; the first still has its 10 s
  f.clock.advance_by(seconds(8));
  f.puts->tick();
  EXPECT_EQ(f.puts->n_puts(), 0u);
}

TEST(LiveLimits, MaxExactClassesPerOwnerIsLive) {
  Fx f;
  const std::uint64_t a = 5 * kBlk, b = 7 * kBlk;  // exact sizes that are not ladder rungs
  auto base = f.slab->alloc_batch(std::vector<std::uint64_t>{b}, 7);
  ASSERT_TRUE(base);
  EXPECT_EQ((*base)[0].len, b);  // default: an exact class
  Fx g;
  g.slab->set_max_exact_classes_per_owner(1);
  auto x = g.slab->alloc_batch(std::vector<std::uint64_t>{a}, 7);
  ASSERT_TRUE(x);
  EXPECT_EQ((*x)[0].len, a);
  auto y = g.slab->alloc_batch(std::vector<std::uint64_t>{b}, 7);
  ASSERT_TRUE(y);
  EXPECT_GT((*y)[0].len, b);  // the owner is at its cap: the ladder rung
}

}  // namespace
}  // namespace miracache::store
