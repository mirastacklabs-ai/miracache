// SPDX-License-Identifier: Apache-2.0
// Store hooks: drop_before by opened_at (monotonic, incremental, lookups miss at once) and cap-cut
// convergence (a cut never evicts the whole overage in one call; the rest converges through sweep_step).
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "store/store.h"
#include "util/clock.h"
#include "util/random.h"

namespace miracache::store {
namespace {

using std::chrono::seconds;
constexpr std::uint64_t kBlk = 4096;

StoreConfig cfg(std::uint32_t segs = 2) {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = segs;
  c.gen_chunk = 1000;
  c.reap_grace = seconds(5);
  c.invalidate_per_s = 0;
  c.principal_default.max_scopes = 8;
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
  explicit Fx(std::uint32_t segs = 2) : rng(1) {
    auto a = Arena::open(cfg(segs));
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
  // A chain 1 <- 2 <- ... <- n in scope s.
  void chain(PrincipalId p, int s, int n) {
    for (int k = 1; k <= n; ++k) ASSERT_TRUE(put(p, s, k, k - 1)) << "scope " << s << " key " << k;
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

TEST(Sweep, DropBeforeMissesAtOnceAndFreesIncrementally) {
  Fx f;
  for (int s = 1; s <= 3; ++s) f.chain(1, s, 150);
  f.clock.advance_by(seconds(10));
  f.chain(1, 4, 20);  // opened later: survives
  ASSERT_EQ(f.hits(1, 1, 150), 150u);
  f.store->set_drop_cutoff(1, seconds(5).count());  // opened_at < 5 s: scopes 1..3
  for (int s = 1; s <= 3; ++s) EXPECT_EQ(f.hits(1, s, 150), 0u) << "dead scope " << s << " must miss before any sweep";
  EXPECT_EQ(f.hits(1, 4, 20), 20u);
  ASSERT_TRUE(f.store->sweep_pending());
  std::size_t total = 0, calls = 0;
  while (f.store->sweep_pending() && calls < 1000) {
    const std::size_t n = f.store->sweep_step(64);
    EXPECT_LE(n, 64u);  // bounded work per turn
    total += n;
    ++calls;
    if (calls % 3 == 0) f.inv();
  }
  EXPECT_EQ(total, 450u);
  EXPECT_FALSE(f.store->sweep_pending());
  EXPECT_EQ(f.store->n_scopes(1), 1u);
  EXPECT_EQ(f.store->bytes_used(1), 20 * kBlk);
  EXPECT_EQ(f.hits(1, 4, 20), 20u);
  f.inv();
}

TEST(Sweep, CutoffIsMonotonic) {
  Fx f;
  f.store->set_drop_cutoff(1, 100);
  f.store->set_drop_cutoff(1, 50);  // lower: ignored
  EXPECT_EQ(*f.store->drop_cutoff(1), 100);
  f.store->set_drop_cutoff(1, 200);
  EXPECT_EQ(*f.store->drop_cutoff(1), 200);
  EXPECT_FALSE(f.store->drop_cutoff(2));
}

TEST(Sweep, ReopenOfADeadScopeDropsOldBlocksBoundedThenStartsFresh) {
  Fx f;
  f.chain(1, 1, 150);
  f.clock.advance_by(seconds(10));
  f.store->set_drop_cutoff(1, seconds(5).count());
  int refused = 0;
  Status st = f.put(1, 1, 1, 0);
  while (!st && refused < 10) {
    EXPECT_EQ(st.error().code, ErrorCode::ResourceExhausted);
    EXPECT_LE(f.store->bytes_used(1), 150 * kBlk);
    ++refused;
    st = f.put(1, 1, 1, 0);
  }
  EXPECT_EQ(refused, 2);  // 150 blocks at <= 64 per call: 64, 64, then the third call finds 22, empties it and opens fresh
  ASSERT_TRUE(st);
  EXPECT_EQ(f.hits(1, 1, 150), 1u);  // only the new root; the old chain is gone for good
  f.inv();
}

TEST(Sweep, PutIntoADeadScopeIsDoomed) {
  Fx f;
  f.chain(1, 1, 3);
  f.clock.advance_by(seconds(10));
  f.store->set_drop_cutoff(1, seconds(5).count());
  EXPECT_FALSE(f.put(1, 1, 4, 3));  // commit into a scope dropped mid-put
  EXPECT_FALSE(f.store->has_key(1, sid(1), kh(1)));
}

TEST(Sweep, CapCutNeverEvictsTheWholeOverageInOneCall) {
  Fx f;
  f.chain(1, 1, 100);
  f.chain(1, 2, 100);
  ASSERT_EQ(f.store->bytes_used(1), 200 * kBlk);
  PrincipalPolicy pol = cfg().principal_default;
  pol.max_bytes = 100 * kBlk;  // a 50 % cut
  f.store->set_policy(1, pol);
  const auto before = f.store->bytes_used(1);
  EXPECT_FALSE(f.store->reserve_inflight(1, kBlk));  // still over after the bounded eviction: this put is refused
  const auto after = f.store->bytes_used(1);
  EXPECT_LE(before - after, 64 * kBlk);
  EXPECT_GT(before - after, 0u);
  ASSERT_TRUE(f.store->sweep_pending());
  std::size_t calls = 0;
  while (f.store->bytes_used(1) > 100 * kBlk && calls < 100) {
    EXPECT_LE(f.store->sweep_step(64), 64u);
    ++calls;
  }
  EXPECT_LE(f.store->bytes_used(1), 100 * kBlk);
  EXPECT_GE(f.store->bytes_used(1), 90 * kBlk);  // converged to the cap, not past it
  EXPECT_LE(calls, 3u);
  f.inv();
  while (f.store->sweep_pending()) f.store->sweep_step(64);
  EXPECT_TRUE(f.store->reserve_inflight(1, kBlk));
  f.store->release_inflight(1, kBlk);
}

TEST(Sweep, LookupsStayResponsiveBetweenSweepTurns) {
  Fx f;
  for (int s = 1; s <= 2; ++s) f.chain(1, s, 200);
  f.clock.advance_by(seconds(10));
  f.chain(2, 1, 30);
  f.store->set_drop_cutoff(1, seconds(5).count());
  // Every turn does at most 64 blocks of work, and another principal's lookups hit throughout.
  while (f.store->sweep_pending()) {
    EXPECT_LE(f.store->sweep_step(64), 64u);
    EXPECT_EQ(f.hits(2, 1, 30), 30u);
  }
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  f.inv();
}

TEST(Sweep, Y02LongChainConvergesAndDeadScopesBehindItAreFreed) {
  Fx f(24);  // 96 MiB: room for 5,000 blocks
  f.chain(1, 1, 5000);
  f.chain(1, 2, 10);  // behind the long chain in scope order
  f.clock.advance_by(seconds(10));
  f.store->set_drop_cutoff(1, seconds(5).count());
  std::size_t calls = 0;
  while (f.store->sweep_pending() && calls < 5000) {
    EXPECT_LE(f.store->sweep_step(64), 64u);
    ++calls;
  }
  EXPECT_LT(calls, 5000u);
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  EXPECT_EQ(f.store->bytes_used(1), 0u);
  f.inv();
}

// kh() orders keys by their low byte first, so in a 1,000-block chain the leaf (1000) sits ~930 keys into the
// scope and, once the tail is being dropped, the next leaf lies more than one scan cap (576 keys) past the cursor,
// across the wrap. A capped scan that wrapped must not be taken for "no leaf anywhere": every turn still frees the
// chain tail first, so no block is ever left without its parent.
TEST(Sweep, Z08LeavesBeyondTheScanCapStillFreeLeafFirst) {
  Fx f(4);
  f.chain(1, 1, 1000);
  f.clock.advance_by(seconds(10));
  f.store->set_drop_cutoff(1, seconds(5).count());
  std::size_t calls = 0;
  while (f.store->sweep_pending() && calls < 1000) {
    EXPECT_LE(f.store->sweep_step(64), 64u);
    ++calls;
    auto s = f.store->check_invariants();
    ASSERT_TRUE(s) << "after sweep turn " << calls << ": " << s.error().context;
  }
  EXPECT_LT(calls, 1000u);
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  EXPECT_EQ(f.store->bytes_used(1), 0u);
  f.inv();
}

TEST(Sweep, Y07EveryPrincipalIsSweptWhenTheBudgetEndsAtABoundary) {
  Fx f;
  for (PrincipalId p = 1; p <= 4; ++p) f.chain(p, 1, 64);  // exactly one turn of budget each
  f.clock.advance_by(seconds(10));
  for (PrincipalId p = 1; p <= 4; ++p) f.store->set_drop_cutoff(p, seconds(5).count());
  std::size_t calls = 0;
  while (f.store->sweep_pending() && calls < 50) {
    EXPECT_LE(f.store->sweep_step(64), 64u);
    ++calls;
  }
  for (PrincipalId p = 1; p <= 4; ++p) EXPECT_EQ(f.store->n_scopes(p), 0u) << "principal " << p;
  f.inv();
}

TEST(Sweep, Y17ReleasingLeasesReArmsCapConvergence) {
  Fx f;
  f.chain(1, 1, 100);
  LookupReq q;
  q.principal = 1;
  q.scope = sid(1);
  for (int k = 1; k <= 100; ++k) q.keys.push_back(kh(k));
  auto a = f.store->lookup(7, q);  // every block leased: nothing is evictable
  ASSERT_NE(a.lease, 0u);
  PrincipalPolicy pol = cfg().principal_default;
  pol.max_bytes = 50 * kBlk;
  f.store->set_policy(1, pol);
  while (f.store->sweep_pending()) f.store->sweep_step(64);  // an all-leased pass ends the sweep ...
  EXPECT_EQ(f.store->bytes_used(1), 100 * kBlk);
  ASSERT_TRUE(f.store->release(7, a.lease));
  EXPECT_TRUE(f.store->sweep_pending());  // ... and the release wakes it again
  while (f.store->sweep_pending()) f.store->sweep_step(64);
  EXPECT_LE(f.store->bytes_used(1), 50 * kBlk);
  f.inv();
}

}  // namespace
}  // namespace miracache::store
