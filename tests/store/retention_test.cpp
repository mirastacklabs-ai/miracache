// SPDX-License-Identifier: Apache-2.0
// QT1: retention (max_ttl, reopen of an expired scope), the one eviction budget (bytes per second and blocks per turn),
// pressure watermarks, incremental drop_before by opened_at, and the per-call bound in commit_block (Y17).
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
constexpr std::uint64_t kBlk = 4096;

StoreConfig cfg() {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 8;  // 40 runs of 64 blocks = 2,560 blocks of 4 KiB (10 MiB)
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

struct Fx {
  explicit Fx(StoreConfig c = cfg()) : rng(1) {
    auto a = Arena::open(c);
    EXPECT_TRUE(a);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
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
  void chain(PrincipalId p, int s, int n, int first = 1) {
    for (int k = first; k < first + n; ++k) ASSERT_TRUE(put(p, s, k, k == first ? 0 : k - 1)) << "scope " << s << " key " << k;
  }
  std::uint64_t hits(PrincipalId p, int s, int n) {
    LookupReq q;
    q.principal = p;
    q.scope = sid(s);
    for (int k = 1; k <= n; ++k) q.keys.push_back(kh(k));
    auto a = store->lookup(99, q);
    std::uint64_t h = 0;
    for (auto& e : a.entries) h += e.hit;
    if (a.lease) EXPECT_TRUE(store->release(99, a.lease));
    return h;
  }
  std::uint64_t blocks(PrincipalId p) { return store->bytes_used(p) / kBlk; }
  void inv() {
    auto s1 = store->check_invariants();
    ASSERT_TRUE(s1) << s1.error().context;
    auto s2 = slab->check_invariants();
    ASSERT_TRUE(s2) << s2.error().context;
  }
  SimClock clock;
  SeededRandom rng;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
};

TEST(Retention, MaxTtlDefaultIsNone) {
  Fx f;
  f.chain(1, 1, 10);
  f.clock.advance_by(seconds(9000));  // far past any daily-style cut, inside idle_ttl
  EXPECT_EQ(f.hits(1, 1, 10), 10u);
  f.store->tick();
  EXPECT_EQ(f.blocks(1), 10u);
}

TEST(Retention, MaxTtlMissesAtOnceAndReapsUnderTheBudget) {
  Fx f;
  f.store->set_retention(seconds(100));
  f.chain(1, 1, 150);
  f.clock.advance_by(seconds(60));
  ASSERT_EQ(f.hits(1, 1, 150), 150u);  // activity renews the idle TTL, not max_ttl
  f.clock.advance_by(seconds(41));      // opened 101 s ago
  EXPECT_EQ(f.hits(1, 1, 150), 0u);     // misses before any tick
  f.chain(2, 1, 20);                    // another principal, opened now
  std::uint64_t prev = f.blocks(1);
  int ticks = 0;
  while (f.store->n_scopes(1) > 0 && ticks < 20) {
    f.store->tick();
    ++ticks;
    EXPECT_LE(prev - f.blocks(1), 64u);  // bounded per turn
    prev = f.blocks(1);
    EXPECT_EQ(f.hits(2, 1, 20), 20u);
    f.inv();
  }
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  EXPECT_EQ(ticks, 3);  // 150 blocks at <= 64 per turn
  EXPECT_EQ(f.store->evict_backlog_blocks(), 0u);
}

TEST(Retention, ReopenOfAnExpiredUnreapedScopeDropsOldBlocksAndTakesANewOpenedAt) {
  Fx f;
  PrincipalPolicy pol = cfg().principal_default;
  pol.idle_ttl = seconds(10);
  f.store->set_policy(1, pol);
  f.chain(1, 1, 20);
  f.clock.advance_by(seconds(11));  // past idle_ttl, inside the reap grace: not reaped yet
  EXPECT_EQ(f.hits(1, 1, 20), 0u);
  ASSERT_TRUE(f.put(1, 1, 1, 0));   // root PUT_BEGIN reopens it
  EXPECT_EQ(f.hits(1, 1, 20), 1u);  // only the new root: the old blocks are never visible again
  EXPECT_EQ(f.blocks(1), 1u);
  f.inv();
  // The new opened_at is 11 s: a drop_before of 5 s (older than the reopen) must not touch it.
  EXPECT_EQ(f.store->drop_principal(1, Nanos{seconds(5)}), 0u);
  EXPECT_EQ(f.hits(1, 1, 1), 1u);
}

TEST(Retention, ReopenAfterMaxTtlOfALargeScopeIsBoundedPerCall) {
  Fx f;
  f.store->set_retention(seconds(100));
  f.chain(1, 1, 150);
  f.clock.advance_by(seconds(101));
  int refused = 0;
  Status st = f.put(1, 1, 1, 0);
  while (!st && refused < 10) {
    EXPECT_EQ(st.error().code, ErrorCode::ResourceExhausted);
    ++refused;
    st = f.put(1, 1, 1, 0);
  }
  EXPECT_EQ(refused, 2);
  ASSERT_TRUE(st);
  EXPECT_EQ(f.blocks(1), 1u);
  f.inv();
}

TEST(Retention, TtlCutBoundedPerTurnAndLookupsStayUp) {
  Fx f;
  for (int s = 1; s <= 8; ++s) f.chain(1, s, 100);
  f.chain(2, 1, 30);
  PrincipalPolicy cut = cfg().principal_default;
  cut.idle_ttl = seconds(60);  // 30 min -> 1 min
  f.store->set_policy(1, cut);
  f.clock.advance_by(seconds(100));  // past 60 s + 5 s grace for every scope of principal 1
  PrincipalPolicy keep = cfg().principal_default;
  f.store->set_policy(2, keep);
  std::uint64_t prev = f.blocks(1);
  int ticks = 0;
  while (f.store->n_scopes(1) > 0 && ticks < 100) {
    f.store->tick();
    ++ticks;
    EXPECT_LE(prev - f.blocks(1), 64u);
    prev = f.blocks(1);
    EXPECT_EQ(f.hits(2, 1, 30), 30u);
    if (ticks % 4 == 0) f.inv();
  }
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  EXPECT_EQ(ticks, 13);  // 800 blocks / 64
  f.inv();
}

TEST(Retention, DropBeforeComparesOpenedAtNotLastUsed) {
  Fx f;
  f.chain(1, 1, 5);  // opened at 0
  f.clock.advance_by(seconds(100));
  ASSERT_EQ(f.hits(1, 1, 5), 5u);  // last_used = 100 s
  f.chain(1, 2, 5);                // opened at 100 s
  EXPECT_EQ(f.store->drop_principal(1, Nanos{seconds(50)}), 1u);  // opened before 50 s: scope 1 only
  EXPECT_EQ(f.hits(1, 1, 5), 0u);                                 // misses at once
  EXPECT_EQ(f.hits(1, 2, 5), 5u);
  f.store->tick();
  EXPECT_EQ(f.store->n_scopes(1), 1u);
  EXPECT_EQ(f.blocks(1), 5u);
  f.inv();
}

TEST(Retention, DropPrincipalIsIncrementalAndBounded) {
  Fx f;
  f.chain(1, 1, 200);
  f.clock.advance_by(seconds(1));
  EXPECT_EQ(f.store->drop_principal(1, f.clock.now()), 1u);
  EXPECT_EQ(f.blocks(1), 200u);  // nothing freed by the call itself
  EXPECT_EQ(f.hits(1, 1, 200), 0u);
  std::uint64_t prev = f.blocks(1);
  int turns = 0;
  while (f.store->sweep_pending() && turns < 20) {
    f.store->tick();
    ++turns;
    EXPECT_LE(prev - f.blocks(1), 64u);
    prev = f.blocks(1);
    f.inv();
  }
  EXPECT_EQ(turns, 4);
  EXPECT_EQ(f.store->n_scopes(1), 0u);
}

// Eight scopes of 304 blocks fill 2,432 of 2,560 blocks: 95 % occupancy.
void fill(Fx& f) {
  for (int s = 1; s <= 8; ++s) f.chain(1, s, 304);
}

TEST(Pressure, FromAboveHighToLowWatermarkAtMost64BlocksPerTurn) {
  Fx f;
  fill(f);
  EXPECT_GT(f.store->occupancy_ppm(), 920'000u);
  std::uint64_t prev = f.blocks(1);
  int ticks = 0;
  while (ticks < 50) {
    f.store->tick();
    ++ticks;
    const std::uint64_t now = f.blocks(1);
    EXPECT_LE(prev - now, 64u);
    prev = now;
    f.inv();
    if (!f.store->pressure()) break;
  }
  EXPECT_FALSE(f.store->pressure());
  EXPECT_LE(f.store->occupancy_ppm(), 880'000u);
  EXPECT_GT(f.store->occupancy_ppm(), 850'000u);  // stopped at the low watermark, did not empty the store
  EXPECT_GE(ticks, 3);
  EXPECT_FALSE(f.store->sweep_pending());
}

TEST(Pressure, NoWorkBelowTheHighWatermark) {
  Fx f;
  for (int s = 1; s <= 7; ++s) f.chain(1, s, 304);  // 83 %
  const auto before = f.blocks(1);
  for (int i = 0; i < 5; ++i) f.store->tick();
  EXPECT_EQ(f.blocks(1), before);
  EXPECT_FALSE(f.store->pressure());
}

TEST(Pressure, FreesAtTheBudgetRate) {
  Fx f;
  fill(f);
  // 10 blocks per second, one tick per second; the first turn also spends the one-second burst.
  f.store->set_evict(10 * kBlk, 64, 92, 88);
  std::uint64_t prev = f.blocks(1);
  std::uint64_t total = 0;
  for (int t = 0; t < 10; ++t) {
    f.clock.advance_by(seconds(1));
    f.store->tick();
    const std::uint64_t d = prev - f.blocks(1);
    EXPECT_LE(d, 11u) << "turn " << t;  // rate * dt + at most one block of debt
    EXPECT_GE(d, 9u) << "turn " << t;
    total += d;
    prev = f.blocks(1);
  }
  EXPECT_GE(total, 95u);
  EXPECT_LE(total, 105u);
  EXPECT_TRUE(f.store->pressure());  // 179 blocks needed, only ~100 freed so far
  f.inv();
}

TEST(Pressure, LookupsStayBoundedPerTurnUnderSustainedPressure) {
  Fx f;
  fill(f);
  f.chain(2, 1, 20);  // principal 2 on top: also counted in occupancy
  int ticks = 0;
  do {
    const std::uint64_t before = f.blocks(1) + f.blocks(2);
    f.store->tick();
    EXPECT_LE(before - (f.blocks(1) + f.blocks(2)), 64u);  // no turn does more than the budget
    ++ticks;
  } while (f.store->pressure() && ticks < 10);
  EXPECT_GE(ticks, 2);
  EXPECT_FALSE(f.store->pressure());
  f.inv();
}

TEST(Pressure, EvictsEvenWhenOnlyOnePrincipalHoldsEverything) {
  Fx f;
  fill(f);
  for (int i = 0; i < 20; ++i) f.store->tick();
  EXPECT_LE(f.store->occupancy_ppm(), 880'000u);
}

TEST(Pressure, LeasedBlocksAreNeverEvicted) {
  Fx f;
  fill(f);
  LookupReq q;
  q.principal = 1;
  q.scope = sid(1);
  for (int k = 1; k <= 304; ++k) q.keys.push_back(kh(k));
  auto a = f.store->lookup(7, q);
  ASSERT_NE(a.lease, 0u);
  for (int i = 0; i < 30; ++i) f.store->tick();
  EXPECT_EQ(f.hits(1, 1, 304), 304u);  // scope 1 is wholly leased: survives
  ASSERT_TRUE(f.store->release(7, a.lease));
  f.inv();
}

TEST(Pressure, MetricsAreSetEachTick) {
  telemetry::Gauge occ, backlog;
  StoreMetrics mx;
  mx.occupancy_ratio_ppm = &occ;
  mx.evict_backlog_blocks = &backlog;
  Fx f;
  f.store->set_metrics(&mx);
  f.chain(1, 1, 100);
  f.clock.advance_by(seconds(1));
  EXPECT_EQ(f.store->drop_principal(1, f.clock.now()), 1u);
  EXPECT_EQ(f.store->evict_backlog_blocks(), 100u);
  f.store->tick();
  EXPECT_EQ(backlog.value(), 36);
  EXPECT_EQ(occ.value(), static_cast<std::int64_t>(f.store->occupancy_ppm()));
  f.store->tick();
  EXPECT_EQ(backlog.value(), 0);
  EXPECT_EQ(occ.value(), 0);
}

// Y17/P20: one commit_block never evicts more than 64 blocks, even from one huge victim scope.
TEST(CommitBlock, VictimScopeIsDrainedBlockGranularly) {
  Fx f;
  PrincipalPolicy pol = cfg().principal_default;
  pol.max_bytes = 201 * kBlk;
  f.store->set_policy(1, pol);
  f.chain(1, 1, 200);  // the oldest scope, 200 blocks
  ASSERT_TRUE(f.put(1, 2, 1, 0));
  EXPECT_EQ(f.blocks(1), 201u);
  f.clock.advance_by(seconds(1));
  // Tighten the cap by 100 blocks, then put into scope 2: the victim is scope 1.
  pol.max_bytes = 101 * kBlk;
  f.store->set_policy(1, pol);
  ASSERT_TRUE(f.store->ensure_scope_for_root_put(1, sid(3), f.clock.now()));
  const std::uint64_t before = f.blocks(1);
  Status st = f.put(1, 3, 1, 0);
  EXPECT_FALSE(st);  // needs 101 evictions: the first call is bounded at 64 and refuses
  EXPECT_LE(before - f.blocks(1), 64u);
  EXPECT_GT(before - f.blocks(1), 0u);
  EXPECT_TRUE(f.store->has_scope(1, sid(1)));  // still there, partly drained, tail first
  f.inv();
  st = f.put(1, 3, 1, 0);
  EXPECT_TRUE(st) << (st ? "" : st.error().context);
  f.inv();
}

// V17: a key inserted into a scope that a bounded eviction is draining must reset the non-leaf run, and the drain
// still frees leaf first (check_invariants proves no block is ever left without its parent).
TEST(CommitBlock, V17InsertIntoAScopeBeingDrainedStillFreesLeafFirst) {
  Fx f;
  PrincipalPolicy pol = cfg().principal_default;
  pol.max_bytes = 300 * kBlk;
  f.store->set_policy(1, pol);
  f.chain(1, 1, 150);  // oldest: the victim
  for (int round = 0; round < 6; ++round) {
    f.clock.advance_by(seconds(1));
    // Fill the rest of the cap in scope 2 so that scope 2's puts evict from scope 1.
    for (int i = 0; i < 70; ++i) {
      const int k = 1000 * (round + 1) + i;
      Status st = f.put(1, 2, k, i == 0 ? 0 : k - 1);
      if (!st) break;
    }
    // A new leaf behind the drain, if the victim still has a tail.
    if (f.store->has_scope(1, sid(1)) && f.hits(1, 1, 150) > 0) {
      const int top = static_cast<int>(f.hits(1, 1, 150));
      (void)f.put(1, 1, 5000 + round, top);
    }
    f.inv();
  }
}

}  // namespace
}  // namespace miracache::store
