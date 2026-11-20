// SPDX-License-Identifier: Apache-2.0
// Store reclaim tests: INVALIDATE, drops, reaping, zombies, eviction, rate limit.
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "store/store.h"
#include "util/clock.h"
#include "util/random.h"

namespace miracache::store {
namespace {

using std::chrono::milliseconds;
using std::chrono::seconds;

StoreConfig cfg() {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.lease_ttl = seconds(30);
  c.lease_max = seconds(100);
  c.reap_grace = seconds(5);
  c.invalidate_per_s = 3;
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 64 * 4096;
  c.principal_default.idle_ttl = seconds(40);
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
  if (i != 0) k[0] = static_cast<std::uint8_t>(i), k[31] = 0xa1;
  return k;
}

struct Fx {
  Fx() : rng(1) {
    auto a = Arena::open(cfg());
    EXPECT_TRUE(a);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
  }
  Status put(PrincipalId p, int s, int k, int parent) {
    if (parent == 0) EXPECT_TRUE(store->ensure_scope_for_root_put(p, sid(s), clock.now()));
    const std::uint64_t lens[] = {4096};
    auto r = slab->alloc_batch(lens);
    EXPECT_TRUE(r);
    Status st = store->commit_block(p, sid(s), kh(k), kh(parent), (*r)[0], 4096);
    if (!st) slab->free((*r)[0]);
    return st;
  }
  LookupAck look(PrincipalId p, int s, std::vector<int> ks, SessionId sess = 7) {
    LookupReq q;
    q.principal = p;
    q.scope = sid(s);
    for (int k : ks) q.keys.push_back(kh(k));
    return store->lookup(sess, q);
  }
  std::uint64_t hits(PrincipalId p, int s, std::vector<int> ks) {
    std::uint64_t n = 0;
    auto a = look(p, s, ks, 99);
    for (auto& e : a.entries) n += e.hit;
    if (a.lease) EXPECT_TRUE(store->release(99, a.lease));
    return n;
  }
  void inv() {
    auto s1 = store->check_invariants();
    ASSERT_TRUE(s1) << s1.error().context;
    auto s2 = slab->check_invariants();
    ASSERT_TRUE(s2) << s2.error().context;
  }
  std::uint64_t allocated() {
    std::uint64_t n = 0;
    for (auto& c : slab->class_stats()) n += c.allocated;
    return n;
  }
  SimClock clock;
  SeededRandom rng;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
};

// Chain 1 <- 2 <- 3, and 2 <- 4 (a fork), plus an unrelated root 5.
void build(Fx& f, PrincipalId p = 1, int s = 1) {
  ASSERT_TRUE(f.put(p, s, 1, 0));
  ASSERT_TRUE(f.put(p, s, 2, 1));
  ASSERT_TRUE(f.put(p, s, 3, 2));
  ASSERT_TRUE(f.put(p, s, 4, 2));
  ASSERT_TRUE(f.put(p, s, 5, 0));
}

TEST(Reclaim, WrongGenerationInvalidateIsNoOpButOk) {
  Fx f;
  build(f);
  auto a = f.look(1, 1, {2});
  const auto gen = a.entries[0].gen;
  EXPECT_TRUE(f.store->release(7, a.lease));
  EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(2), gen + 1));
  EXPECT_EQ(f.hits(1, 1, {1, 2, 3, 4, 5}), 5u);
  EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(99), gen));  // unknown key
  EXPECT_TRUE(f.store->invalidate(1, sid(9), kh(2), gen));   // unknown scope
  EXPECT_TRUE(f.store->invalidate(2, sid(1), kh(2), gen));   // foreign principal
  EXPECT_EQ(f.hits(1, 1, {1, 2, 3, 4, 5}), 5u);
  f.inv();
}

TEST(Reclaim, InvalidateDropsTheSubtree) {
  Fx f;
  build(f);
  auto a = f.look(1, 1, {2});
  const auto gen = a.entries[0].gen;
  EXPECT_TRUE(f.store->release(7, a.lease));
  EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(2), gen));
  EXPECT_EQ(f.hits(1, 1, {2, 3, 4}), 0u);
  EXPECT_EQ(f.hits(1, 1, {1, 5}), 2u);
  EXPECT_EQ(f.allocated(), 2u);
  EXPECT_EQ(f.store->bytes_used(1), 2u * 4096);
  f.inv();
}

TEST(Reclaim, InvalidateOfLeasedBlockIsZombieUntilLastRelease) {
  Fx f;
  build(f);
  auto a = f.look(1, 1, {2, 3});
  auto b = f.look(1, 1, {3}, 8);
  EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(2), a.entries[0].gen));
  EXPECT_EQ(f.store->n_zombies(), 2u);  // 2 and 3 are leased; 4 is freed
  EXPECT_EQ(f.allocated(), 4u);         // 1, 5 live + 2 zombies
  EXPECT_EQ(f.hits(1, 1, {2, 3}), 0u);
  f.inv();
  EXPECT_TRUE(f.store->renew(7, a.lease));  // RENEW on ZOMBIE leases succeeds
  EXPECT_TRUE(f.store->release(7, a.lease));
  EXPECT_EQ(f.store->n_zombies(), 1u);  // block 3 is still leased by session 8
  EXPECT_EQ(f.allocated(), 3u);
  f.inv();
  EXPECT_TRUE(f.store->release(8, b.lease));
  EXPECT_EQ(f.store->n_zombies(), 0u);
  EXPECT_EQ(f.allocated(), 2u);  // freed exactly at the last release
  f.inv();
}

TEST(Reclaim, SessionEndReleasesLeasesAndFreesZombies) {
  Fx f;
  build(f);
  auto a = f.look(1, 1, {1, 2});
  f.store->drop_scope(1, sid(1));
  EXPECT_EQ(f.store->n_zombies(), 2u);
  f.store->on_session_end(7);
  EXPECT_EQ(f.store->n_zombies(), 0u);
  EXPECT_EQ(f.store->n_leases(), 0u);
  EXPECT_EQ(f.allocated(), 0u);
  f.inv();
  (void)a;
}

TEST(Reclaim, DropPrincipalAffectsOnlyThatPrincipal) {
  Fx f;
  build(f, 1, 1);
  build(f, 1, 2);
  build(f, 2, 1);
  f.clock.advance_by(seconds(10));
  ASSERT_TRUE(f.put(1, 3, 1, 0));  // newer scope
  EXPECT_EQ(f.store->drop_principal(1, f.clock.now() - seconds(5)), 2u);  // old scopes only (by opened_at)
  EXPECT_EQ(f.hits(1, 1, {1}), 0u);  // incremental: they miss at once ...
  f.store->tick();                   // ... and their blocks go under the budget
  EXPECT_EQ(f.store->n_scopes(1), 1u);
  EXPECT_EQ(f.hits(1, 3, {1}), 1u);
  EXPECT_EQ(f.hits(2, 1, {1, 2, 3, 4, 5}), 5u);
  EXPECT_EQ(f.store->drop_principal(1, f.clock.now() + seconds(1)), 1u);
  f.store->tick();
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  EXPECT_EQ(f.store->n_scopes(2), 1u);
  EXPECT_EQ(f.store->bytes_used(2), 5u * 4096);
  f.inv();
}

TEST(Reclaim, IdleScopeIsReapedAfterTtlPlusGrace) {
  Fx f;
  build(f);
  f.clock.advance_by(seconds(42));  // past idle_ttl, inside the grace
  f.store->tick();
  EXPECT_EQ(f.hits(1, 1, {1}), 0u);  // lookups already MISS
  EXPECT_EQ(f.store->n_scopes(1), 1u);
  f.inv();
  f.clock.advance_by(seconds(4));
  f.store->tick();
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  EXPECT_EQ(f.allocated(), 0u);
  f.inv();
}

TEST(Reclaim, EvictorTakesLeavesTailFirstAndNeverLeasedOrNonLeaf) {
  Fx f;
  ASSERT_TRUE(f.put(1, 1, 1, 0));  // chain 1 <- 2 <- 3
  ASSERT_TRUE(f.put(1, 1, 2, 1));
  ASSERT_TRUE(f.put(1, 1, 3, 2));
  ASSERT_TRUE(f.put(1, 1, 4, 0));  // lone root, newest
  auto leased = f.look(1, 1, {4});
  ASSERT_NE(leased.lease, 0u);
  // Only leaf candidate that is unleased: 3. Asking for more frees 2 then 1 as they turn leaf.
  EXPECT_EQ(f.store->evict(4096), 4096u);
  EXPECT_EQ(f.hits(1, 1, {3}), 0u);
  EXPECT_EQ(f.hits(1, 1, {1, 2}), 2u);  // non-leaf survived the first eviction
  f.inv();
  EXPECT_EQ(f.store->evict(1u << 30), 2u * 4096);  // 2, then 1; never the leased 4
  EXPECT_EQ(f.hits(1, 1, {1, 2, 3}), 0u);
  EXPECT_EQ(f.hits(1, 1, {4}), 1u);
  EXPECT_EQ(f.store->evict(1u << 30), 0u);
  EXPECT_EQ(f.store->n_zombies(), 0u);
  f.inv();
}

TEST(Reclaim, EvictorIsLruAmongLeaves) {
  Fx f;
  ASSERT_TRUE(f.put(1, 1, 1, 0));
  ASSERT_TRUE(f.put(1, 1, 2, 0));
  ASSERT_TRUE(f.put(1, 2, 3, 0));
  EXPECT_EQ(f.hits(1, 1, {1}), 1u);  // touch 1: now 2 is the oldest
  EXPECT_EQ(f.store->evict(1), 4096u);
  EXPECT_EQ(f.hits(1, 1, {2}), 0u);
  EXPECT_EQ(f.hits(1, 1, {1}), 1u);
  EXPECT_EQ(f.hits(1, 2, {3}), 1u);
  f.inv();
}

TEST(Reclaim, InvalidateRateLimitedPerPrincipal) {
  Fx f;
  build(f, 1, 1);
  build(f, 2, 1);
  for (int i = 0; i < 3; ++i) EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(1), 1));
  auto st = f.store->invalidate(1, sid(1), kh(1), 1);
  ASSERT_FALSE(st);
  EXPECT_EQ(st.error().code, ErrorCode::ResourceExhausted);
  EXPECT_TRUE(f.store->invalidate(2, sid(1), kh(1), 1));  // other principal unaffected
  f.clock.advance_by(milliseconds(340));                  // 3/s: one token back
  EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(1), 1));
  EXPECT_FALSE(f.store->invalidate(1, sid(1), kh(1), 1));
  f.clock.advance_by(seconds(5));
  for (int i = 0; i < 3; ++i) EXPECT_TRUE(f.store->invalidate(1, sid(1), kh(1), 1));  // burst is capped at 3
  EXPECT_FALSE(f.store->invalidate(1, sid(1), kh(1), 1));
}

TEST(Reclaim, OrphanChildCommitIsRefused) {
  Fx f;
  build(f);
  EXPECT_FALSE(f.put(1, 1, 9, 77));  // parent 77 does not exist
  EXPECT_EQ(f.allocated(), 5u);
  f.inv();
}

}  // namespace
}  // namespace miracache::store
