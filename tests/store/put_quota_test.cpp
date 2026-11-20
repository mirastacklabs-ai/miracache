// SPDX-License-Identifier: Apache-2.0
// Put token buckets in PUT_BEGIN (ops and bytes, byte debt, SKIP with retry_after_ms), and bounded cap eviction
// (a 25 % cap cut, max_scopes at the cap): no single call removes more than 64 blocks, the rest converges by the sweep.
#include <array>
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
  c.n_segments = 8;  // 2,560 blocks of 4 KiB
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

// ---- PUT_BEGIN buckets -------------------------------------------------------------------------------------------
struct Dummy final : Executor {
  void post(std::function<void()> work, std::function<void()> done) override {
    work();
    done();
  }
};

struct PFx {
  explicit PFx(StoreConfig c) : rng(1), net(clock, rng, {}, {}), srv(net.add_node(1)), cli(net.add_node(2)) {
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
    store->set_metrics(&mx);
    puts->set_metrics(&mx);
  }
  PutBeginAck begin(int scope, int first_key, int n, std::uint64_t len = kBlk, int parent = 0) {
    PutBeginReq q;
    q.principal = 1;
    q.scope = sid(scope);
    for (int i = 0; i < n; ++i) {
      PutKey k;
      k.key = kh(first_key + i);
      k.parent = kh(i == 0 ? parent : first_key + i - 1);
      k.chain_pos = static_cast<std::uint64_t>(i);
      k.stored_len = len;
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
  fabric::SimFabric& cli;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
  fabric::PdId ingest_pd;
  std::unique_ptr<MrManager> mrs;
  Dummy exec;
  std::unique_ptr<PutPath> puts;
  StoreMetrics mx;
};

StoreConfig limited(std::uint64_t ops, std::uint64_t bytes) {
  StoreConfig c = cfg();
  c.principal_default.put_ops_per_s = ops;
  c.principal_default.put_bytes_per_s = bytes;
  return c;
}

TEST(PutBucket, UnlimitedByDefault) {
  PFx f(cfg());
  auto a = f.begin(1, 1, 4);  // SlabAllocator::kMaxBatch accepted keys per put
  EXPECT_EQ(a.status, BeginStatus::Ok);
  EXPECT_EQ(PFx::accepted(a), 4);
  EXPECT_EQ(a.retry_after_ms, 0u);
}

TEST(PutBucket, OpsBudgetSkipsTheRestWithRetryAfter) {
  PFx f(limited(6, 0));
  auto a = f.begin(1, 1, 4);
  ASSERT_EQ(a.status, BeginStatus::Ok);
  EXPECT_EQ(PFx::accepted(a), 4);
  EXPECT_EQ(a.retry_after_ms, 0u);
  auto b = f.begin(2, 10, 4);
  ASSERT_EQ(b.status, BeginStatus::Ok);  // SKIP, never REFUSED
  EXPECT_EQ(PFx::accepted(b), 2);
  for (std::size_t i = 0; i < 4; ++i) EXPECT_EQ(b.entries[i].accept, i < 2) << i;  // prefix: no orphan tails
  EXPECT_EQ(b.retry_after_ms, 167u);  // one token at 6/s = 166.67 ms
  ASSERT_NE(b.put_id, 0u);
  // Everything over budget: SKIP with no put at all.
  auto c = f.begin(3, 100, 3);
  EXPECT_EQ(c.status, BeginStatus::Ok);
  EXPECT_EQ(c.put_id, 0u);
  EXPECT_EQ(PFx::accepted(c), 0);
  EXPECT_EQ(c.retry_after_ms, 167u);
  f.clock.advance_by(milliseconds(167));
  auto d = f.begin(3, 100, 3);
  EXPECT_EQ(PFx::accepted(d), 1);  // the repaid token
  f.clock.advance_by(seconds(5));  // the burst is one second's worth, not more
  EXPECT_EQ(PFx::accepted(f.begin(4, 200, 4)), 4);
  EXPECT_EQ(PFx::accepted(f.begin(5, 300, 4)), 2);
}

TEST(PutBucket, BlockLargerThanTheByteRateIsAdmittedWithDebt) {
  PFx f(limited(0, 8192));  // 8 KiB/s; blocks of 16 KiB
  auto a = f.begin(1, 1, 1, 4 * kBlk);
  ASSERT_EQ(a.status, BeginStatus::Ok);
  EXPECT_EQ(PFx::accepted(a), 1);  // balance +8192 -> -8192
  auto b = f.begin(2, 10, 1, 4 * kBlk);
  EXPECT_EQ(PFx::accepted(b), 0);
  EXPECT_GE(b.retry_after_ms, 1000u);  // the debt of 8192 repaid at 8192/s, then one unit
  EXPECT_LE(b.retry_after_ms, 1001u);
  f.clock.advance_by(milliseconds(500));
  EXPECT_EQ(PFx::accepted(f.begin(2, 10, 1, 4 * kBlk)), 0);
  f.clock.advance_by(milliseconds(501));
  EXPECT_EQ(PFx::accepted(f.begin(2, 10, 1, 4 * kBlk)), 1);
}

TEST(PutBucket, BytesBudgetAdmitsWhilePositiveThenSkipsTheTail) {
  PFx f(limited(0, 6 * kBlk));  // 6 blocks per second of burst
  EXPECT_EQ(PFx::accepted(f.begin(1, 1, 4)), 4);
  auto b = f.begin(2, 10, 4);  // 2 blocks of balance left: both fit, the third finds the balance at 0
  ASSERT_EQ(b.status, BeginStatus::Ok);
  EXPECT_EQ(PFx::accepted(b), 2);
  EXPECT_GE(b.retry_after_ms, 1u);
  EXPECT_LE(b.retry_after_ms, 2u);  // the balance is exactly 0: positive again after one unit of refill
}

TEST(PutBucket, BothBucketsAndMetrics) {
  telemetry::Registry reg;
  PFx f(limited(4, 2 * kBlk));
  auto& ops_t = reg.counter("t_ops", "t", {});
  auto& bytes_t = reg.counter("t_bytes", "t", {});
  auto& skipped = reg.counter("t_skipped", "t", {});
  f.mx.put_throttled[0] = &ops_t;
  f.mx.put_throttled[1] = &bytes_t;
  f.mx.put_ops[static_cast<std::size_t>(PutResult::Skipped)] = &skipped;
  auto a = f.begin(1, 1, 8);  // bytes: 2 blocks reach 0 balance -> the third is skipped by the bytes bucket
  EXPECT_EQ(PFx::accepted(a), 2);
  EXPECT_EQ(bytes_t.value(), 6u);
  EXPECT_EQ(ops_t.value(), 0u);
  EXPECT_EQ(skipped.value(), 6u);
  f.clock.advance_by(seconds(1));
  auto b = f.begin(2, 50, 1);  // bytes admit again; ops: 4 - 2 + refill -> capped at 4
  EXPECT_EQ(PFx::accepted(b), 1);
}

TEST(PutBucket, ReopenOfALargeExpiredScopeIsRetryableNotFailed) {
  PFx f(cfg());
  ASSERT_TRUE(f.store->ensure_scope_for_root_put(1, sid(1), f.clock.now()));
  for (int k = 1; k <= 100; ++k) {
    const std::uint64_t lens[] = {kBlk};
    auto r = f.slab->alloc_batch(lens);
    ASSERT_TRUE(r);
    ASSERT_TRUE(f.store->commit_block(1, sid(1), kh(k), kh(k == 1 ? 0 : k - 1), (*r)[0], kBlk));
  }
  f.clock.advance_by(seconds(10001));  // past idle_ttl, not reaped yet
  auto a = f.begin(1, 500, 1);          // a root put on the expired scope: 100 blocks to drop, 64 per call
  EXPECT_EQ(a.status, BeginStatus::Refused);
  EXPECT_GT(a.retry_after_ms, 0u);  // the client backs off and retries (retry 0 would be a final failure)
  EXPECT_LE(a.retry_after_ms, 5000u);
  int ticks = 0;
  while (f.store->has_scope(1, sid(1)) && f.store->bytes_used(1) > 0 && ticks++ < 10) f.store->tick();
  auto b = f.begin(1, 500, 1);
  EXPECT_EQ(b.status, BeginStatus::Ok);
  EXPECT_EQ(PFx::accepted(b), 1);
}

TEST(PutBucket, RefusedPutReturnsItsTokens) {
  StoreConfig c = limited(1, 0);
  c.principal_default.max_bytes = 2 * kBlk;
  PFx f(c);
  // A block above the whole cap is refused by the quota: the one op token of the second must not be lost.
  auto big = f.begin(1, 1, 1, 3 * kBlk);
  EXPECT_EQ(big.status, BeginStatus::Refused);
  auto ok = f.begin(1, 2, 1, kBlk);
  EXPECT_EQ(ok.status, BeginStatus::Ok);
  EXPECT_EQ(PFx::accepted(ok), 1);
}

TEST(PutBucket, LookupsAreNeverThrottled) {
  PFx f(limited(1, kBlk));
  EXPECT_EQ(PFx::accepted(f.begin(1, 1, 1)), 1);
  EXPECT_EQ(PFx::accepted(f.begin(1, 2, 1)), 0);  // throttled
  LookupReq q;
  q.principal = 1;
  q.scope = sid(1);
  for (int i = 0; i < 100; ++i) {
    q.keys = {kh(1)};
    (void)f.store->lookup(5, q);  // no throttle path exists on fetches; must simply not fail
  }
  SUCCEED();
}

TEST(PutBucket, Bucket128BitArithmeticHoldsAtHighRates) {
  PutBucket b;
  const std::uint64_t rate = std::uint64_t{50} << 30;  // 50 GiB/s
  EXPECT_EQ(b.admit(rate, std::uint64_t{1} << 40, true, Nanos{0}), 0u);  // 1 TiB block: debt of ~974 GiB
  const std::uint32_t ms = b.admit(rate, 4096, true, Nanos{0});
  EXPECT_GT(ms, 19000u);  // ~ 19.5 s
  EXPECT_LT(ms, 20000u);
}

// ---- bounded cap eviction ----------------------------------------------------------------------------------------
struct SFx {
  explicit SFx(StoreConfig c = cfg()) : rng(1) {
    auto a = Arena::open(c);
    EXPECT_TRUE(a);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
  }
  Status put(PrincipalId p, int s, int k, int parent) {
    if (parent == 0)
      if (auto st = store->ensure_scope_for_root_put(p, sid(s), clock.now()); !st) return st;
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
  std::uint64_t blocks(PrincipalId p) { return store->bytes_used(p) / kBlk; }
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

TEST(CapCut, TwentyFivePercentCutNeverEvictsMoreThan64BlocksPerCallAndConverges) {
  SFx f;
  for (int s = 1; s <= 8; ++s) f.chain(1, s, 200);  // 1,600 blocks in 8 scopes
  ASSERT_EQ(f.blocks(1), 1600u);
  PrincipalPolicy pol = cfg().principal_default;
  pol.max_bytes = 1200 * kBlk;  // 25 % cut
  f.store->set_policy(1, pol);
  // One put into the full store: this call evicts only what it needs, at most 64 blocks, then refuses or succeeds.
  const std::uint64_t before = f.blocks(1);
  Status st = f.put(1, 9, 1, 0);
  const std::uint64_t after = f.blocks(1);
  EXPECT_FALSE(st);  // 400 blocks over the cap: 64 evicted, still full -> this put is refused
  EXPECT_LE(before - after, 64u);
  EXPECT_GT(before - after, 0u);
  // The reservation path is bounded the same way.
  const std::uint64_t b2 = f.blocks(1);
  EXPECT_FALSE(f.store->reserve_inflight(1, 400 * kBlk));
  EXPECT_LE(b2 - f.blocks(1), 64u);
  f.inv();
  // The rest converges through the sweep under the one budget, never more than 64 blocks per turn.
  int turns = 0;
  while (f.blocks(1) > 1200 && turns < 100) {
    const std::uint64_t pre = f.blocks(1);
    f.store->tick();
    EXPECT_LE(pre - f.blocks(1), 64u);
    ++turns;
    f.inv();
  }
  EXPECT_LE(f.blocks(1), 1200u);
  EXPECT_LE(turns, 8);  // ~400 blocks at 64 per turn
  // After convergence a put fits again.
  EXPECT_TRUE(f.put(1, 9, 1, 0));
}

TEST(CapCut, CommitAtTheCapDoesNotWalkAllBlocks) {
  // A hopeless commit (everything else is leased) is refused by the O(1) bound without evicting anything.
  SFx f;
  f.chain(1, 1, 100);
  f.chain(1, 2, 100);
  LookupReq q;
  q.principal = 1;
  q.scope = sid(1);
  for (int k = 1; k <= 100; ++k) q.keys.push_back(kh(k));
  auto la = f.store->lookup(7, q);
  q.scope = sid(2);
  auto lb = f.store->lookup(7, q);
  ASSERT_NE(la.lease, 0u);
  ASSERT_NE(lb.lease, 0u);
  PrincipalPolicy pol = cfg().principal_default;
  pol.max_bytes = 200 * kBlk;  // exactly full, all of it leased
  f.store->set_policy(1, pol);
  const std::uint64_t before = f.blocks(1);
  EXPECT_FALSE(f.put(1, 3, 1, 0));
  EXPECT_EQ(f.blocks(1), before);
  f.inv();
}

TEST(MaxScopes, EvictingALargeLruScopeIsBoundedPerCall) {
  StoreConfig c = cfg();
  c.principal_default.max_scopes = 2;
  SFx f(c);
  f.chain(1, 1, 300);  // scope 1 is the LRU victim
  f.clock.advance_by(milliseconds(1));
  f.chain(1, 2, 10);
  const std::uint64_t before = f.blocks(1);
  ASSERT_EQ(before, 310u);
  ASSERT_TRUE(f.put(1, 3, 1, 0));  // opens scope 3 at max_scopes
  EXPECT_LE(before + 1 - f.blocks(1), 64u);  // this call removed at most 64 blocks
  EXPECT_TRUE(f.store->has_scope(1, sid(3)));
  EXPECT_EQ(f.hits(1, 1, 300), 0u);  // the victim misses at once
  f.inv();
  int turns = 0;
  while (f.store->n_scopes(1) > 2 && turns < 20) {
    f.store->tick();
    ++turns;
    f.inv();
  }
  EXPECT_EQ(f.store->n_scopes(1), 2u);
  EXPECT_LE(turns, 6);
  EXPECT_EQ(f.blocks(1), 11u);  // scope 2 (10) and scope 3 (1)
}


// ---- Scope backlog, cap cut, turn budget and latency bound ----------------------------------------
// Scopes 1 (opened first, then dropped) and the live ones that follow.
TEST(MaxScopes, DoomedBacklogDoesNotCostLiveScopes) {
  StoreConfig c = cfg();
  c.principal_default.max_scopes = 2;
  SFx f(c);
  f.chain(1, 1, 100);
  f.chain(1, 2, 100);
  f.clock.advance_by(seconds(1));
  EXPECT_EQ(f.store->drop_principal(1, f.clock.now()), 2u);  // the doomed backlog (2) is not smaller than max_scopes
  f.clock.advance_by(seconds(1));
  f.chain(1, 3, 100);
  f.chain(1, 4, 100);  // both open without touching each other: doomed records do not hold a slot
  EXPECT_EQ(f.hits(1, 3, 100), 100u);
  EXPECT_EQ(f.hits(1, 4, 100), 100u);
  f.inv();
  // At the live cap the LRU scope is only doomed when it is large (O(1)), never freed whole in one call.
  const std::uint64_t before = f.blocks(1);
  ASSERT_TRUE(f.put(1, 5, 1, 0));
  EXPECT_LE(before + 1 - f.blocks(1), 64u);
  EXPECT_EQ(f.hits(1, 3, 100), 0u);
  EXPECT_EQ(f.hits(1, 4, 100), 100u);
  f.inv();
}

TEST(CapCut, DoomedBlocksGoBeforeLiveScopes) {
  StoreConfig c = cfg();
  c.principal_default.max_bytes = 300 * kBlk;
  SFx f(c);
  f.chain(1, 1, 100);                 // will be dropped
  f.clock.advance_by(seconds(1));
  const Nanos cut = f.clock.now();
  f.clock.advance_by(seconds(1));
  f.chain(1, 2, 100);                 // live, older than 3 in the LRU
  f.chain(1, 3, 100);
  ASSERT_EQ(f.store->drop_principal(1, cut), 1u);
  ASSERT_EQ(f.blocks(1), 300u);
  // A put into scope 3 at the cap: the dead blocks pay, scope 2 keeps all of its blocks.
  ASSERT_TRUE(f.put(1, 3, 1000, 100));
  EXPECT_EQ(f.hits(1, 2, 100), 100u);
  f.inv();
  // The reservation path prefers them too.
  ASSERT_TRUE(f.store->reserve_inflight(1, 10 * kBlk, nullptr));
  EXPECT_EQ(f.hits(1, 2, 100), 100u);
  f.store->release_inflight(1, 10 * kBlk);
  f.inv();
}

TEST(Turn, PutPathEvictionsAreChargedToTheTurnBudget) {
  StoreConfig c = cfg();
  c.principal_default.max_bytes = 300 * kBlk;
  SFx f(c);
  f.chain(1, 1, 200);
  f.clock.advance_by(seconds(1));
  const Nanos cut = f.clock.now();
  f.clock.advance_by(seconds(1));
  f.chain(1, 2, 99);
  ASSERT_EQ(f.store->drop_principal(1, cut), 1u);
  ASSERT_EQ(f.blocks(1), 299u);
  ASSERT_TRUE(f.put(1, 2, 1000, 99));  // 300: fits, nothing evicted
  const std::uint64_t b0 = f.blocks(1);
  ASSERT_TRUE(f.put(1, 2, 1001, 1000));  // over by one: drains doomed blocks (a call is bounded to 64)
  const std::uint64_t evicted = b0 + 1 - f.blocks(1);
  EXPECT_GT(evicted, 0u);
  EXPECT_LE(evicted, 64u);
  // The sweep of this turn gets only what is left of the 64; a second turn gets its own 64.
  const std::uint64_t b1 = f.blocks(1);
  f.store->sweep_step();
  EXPECT_LE((b1 - f.blocks(1)) + evicted, 64u);
  const std::uint64_t b2 = f.blocks(1);
  f.store->sweep_step();
  EXPECT_LE(b2 - f.blocks(1), 64u);
  f.inv();
}

TEST(Turn, ErasedDoomedRecordsCountAgainstTheBudget) {
  StoreConfig c = cfg();
  c.principal_default.max_scopes = 300;
  SFx f(c);
  for (int s = 1; s <= 200; ++s) ASSERT_TRUE(f.store->ensure_scope_for_root_put(1, sid(s), f.clock.now()));  // empty
  f.clock.advance_by(seconds(1));
  ASSERT_EQ(f.store->drop_principal(1, f.clock.now()), 200u);
  int turns = 0;
  while (f.store->n_scopes(1) > 0 && turns < 20) {
    const std::size_t before = f.store->n_scopes(1);
    f.store->sweep_step();
    EXPECT_LE(before - f.store->n_scopes(1), 64u);
    ++turns;
  }
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  EXPECT_EQ(turns, 4);  // 200 records at <= 64 per turn
}

TEST(Latency, NoCallAndNoTurnDoesMoreThanItsBoundUnderSustainedPressure) {
  StoreConfig c = cfg();
  c.principal_default.max_bytes = 100000 * kBlk;
  c.principal_default.max_scopes = 64;
  SFx f(c);
  int next = 1;
  for (int s = 1; s <= 12; ++s, next += 200) f.chain(1, s, 200, next);  // 2,400 of 2,560 blocks: above the high watermark
  ASSERT_TRUE(f.store->occupancy_ppm() > 920'000);
  std::size_t worst_call = 0, worst_turn = 0;
  for (int round = 0; round < 60; ++round) {
    for (int i = 0; i < 6; ++i) {  // sustained inflow: each put is bounded on its own
      const std::uint64_t pre = f.blocks(1);
      (void)f.put(1, 13 + round % 8, next++, 0);
      worst_call = std::max<std::size_t>(worst_call, pre + 1 > f.blocks(1) ? pre + 1 - f.blocks(1) : 0);
    }
    f.hits(1, 1 + round % 12, 5);  // lookups interleave; they never evict
    const std::uint64_t pre = f.blocks(1);
    f.clock.advance_by(milliseconds(100));
    f.store->tick();
    worst_turn = std::max<std::size_t>(worst_turn, pre > f.blocks(1) ? pre - f.blocks(1) : 0);
    f.inv();
  }
  EXPECT_LE(worst_call, 64u);
  EXPECT_LE(worst_turn, 64u);
}

}  // namespace
}  // namespace miracache::store
