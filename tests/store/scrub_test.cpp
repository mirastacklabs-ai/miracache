// SPDX-License-Identifier: Apache-2.0
// SC1: the scrubber finds a corrupted extent and drops it (and its subtree), a pinned block is never freed mid-check,
// and the rate and per-turn bounds hold.
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "store/scrub.h"
#include "store/store.h"
#include "util/clock.h"
#include "util/crc32c.h"
#include "util/executor.h"
#include "util/random.h"

namespace miracache::store {
namespace {

using std::chrono::seconds;
constexpr std::uint64_t kBlk = 4096;

StoreConfig cfg() {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
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

// Runs `work` at post time, queues `done` until the test drains it: the executor finishes "later".
class DeferredExecutor final : public Executor {
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

struct Fx {
  Fx() : rng(1) {
    auto a = Arena::open(cfg());
    EXPECT_TRUE(a);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
    scrub = std::make_unique<Scrubber>(*store, *arena, exec, clock, nullptr, [this](const Extent& e) { bad.push_back(e); });
  }
  // A committed block with a real header and a payload of a recognisable pattern.
  void put(int s, int k, int parent) {
    if (parent == 0) ASSERT_TRUE(store->ensure_scope_for_root_put(1, sid(s), clock.now()));
    const std::uint64_t lens[] = {kBlk};
    auto r = slab->alloc_batch(lens);
    ASSERT_TRUE(r);
    const Extent e = (*r)[0];
    auto bytes = arena->block(e.seg, e.off, kBlk);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::byte>((i * 31 + static_cast<std::size_t>(k)) & 0xff);
    proto::ServerHeader h;
    h.stored_len = kBlk;
    h.payload_crc = crc32c(bytes);
    slab->write_header(e, h);
    ASSERT_TRUE(store->commit_block(1, sid(s), kh(k), kh(parent), e, kBlk));
  }
  void chain(int s, int from, int to) {
    for (int k = from; k <= to; ++k) put(s, k, k == from ? 0 : k - 1);
  }
  LookupEntry entry(int s, int k, LeaseId* lease = nullptr, SessionId sess = 7) {
    LookupReq q;
    q.principal = 1;
    q.scope = sid(s);
    q.keys.push_back(kh(k));
    auto a = store->lookup(sess, q);
    if (lease) *lease = a.lease;
    else if (a.lease) EXPECT_TRUE(store->release(sess, a.lease));
    return a.entries[0];
  }
  std::size_t hits(int s, int from, int to) {
    std::size_t h = 0;
    for (int k = from; k <= to; ++k) h += entry(s, k).hit;
    return h;
  }
  void flip(const LookupEntry& e) {
    ASSERT_TRUE(e.hit);
    arena->block(e.seg_id, e.offset + 100, 1)[0] ^= std::byte{0x40};
  }
  std::uint64_t allocated() const {
    std::uint64_t n = 0;
    for (const auto& c : slab->class_stats()) n += c.allocated;
    return n;
  }
  void inv() {
    auto s1 = store->check_invariants();
    ASSERT_TRUE(s1) << s1.error().context;
    auto s2 = slab->check_invariants();
    ASSERT_TRUE(s2) << s2.error().context;
  }
  // Steps until one full cycle completed (bounded).
  void one_cycle() {
    const auto c0 = scrub->cycles();
    for (int i = 0; i < 1000 && scrub->cycles() == c0; ++i) {
      clock.advance_by(std::chrono::milliseconds(100));
      scrub->step();
      exec.run_all();
    }
    ASSERT_GT(scrub->cycles(), c0);
  }
  SimClock clock;
  SeededRandom rng;
  DeferredExecutor exec;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
  std::unique_ptr<Scrubber> scrub;
  std::vector<Extent> bad;
};

TEST(Scrub, CleanStoreIsCheckedAndKept) {
  Fx f;
  f.chain(1, 1, 5);
  f.chain(2, 6, 9);
  f.scrub->set_rate(64u << 20);
  f.one_cycle();
  EXPECT_EQ(f.scrub->checked(), 9u);
  EXPECT_EQ(f.scrub->failed(), 0u);
  EXPECT_EQ(f.scrub->bytes(), 9 * kBlk);
  EXPECT_EQ(f.hits(1, 1, 5) + f.hits(2, 6, 9), 9u);
  EXPECT_EQ(f.store->n_scrub_pins(), 0u);
  f.inv();
}

TEST(Scrub, CorruptExtentIsFoundAndDroppedWithSubtree) {
  Fx f;
  f.chain(1, 1, 5);   // 1 <- 2 <- 3 <- 4 <- 5
  f.chain(2, 6, 8);   // another scope, untouched
  f.flip(f.entry(1, 3));
  f.scrub->set_rate(64u << 20);
  f.one_cycle();
  EXPECT_EQ(f.scrub->failed(), 1u);
  ASSERT_EQ(f.bad.size(), 1u);
  // The corrupt block and its descendants miss; ancestors and other scopes still hit. Never a wrong-bytes hit.
  EXPECT_FALSE(f.entry(1, 3).hit);
  EXPECT_FALSE(f.entry(1, 4).hit);
  EXPECT_FALSE(f.entry(1, 5).hit);
  EXPECT_TRUE(f.entry(1, 1).hit);
  EXPECT_TRUE(f.entry(1, 2).hit);
  EXPECT_EQ(f.hits(2, 6, 8), 3u);
  EXPECT_EQ(f.store->n_scrub_pins(), 0u);
  f.inv();
  // The next cycle is clean.
  const auto failed = f.scrub->failed();
  f.one_cycle();
  EXPECT_EQ(f.scrub->failed(), failed);
}

TEST(Scrub, CorruptHeaderIsDropped) {
  Fx f;
  f.chain(1, 1, 2);
  const auto e = f.entry(1, 2);
  const auto& l = f.arena->layout();
  const std::uint64_t slot = e.gen_slot - std::uint64_t{e.seg_id} * l.seg.slots();
  f.arena->block(e.seg_id, l.seg.hdr_table_off + slot * kHeaderSlotBytes + 40, 1)[0] ^= std::byte{1};
  f.scrub->set_rate(64u << 20);
  f.one_cycle();
  EXPECT_EQ(f.scrub->failed(), 1u);
  EXPECT_FALSE(f.entry(1, 2).hit);
  EXPECT_TRUE(f.entry(1, 1).hit);
  f.inv();
}

TEST(Scrub, PinnedBlockEvictedMidCheckIsZombieUntilUnpin) {
  Fx f;
  f.chain(1, 1, 3);
  f.scrub->set_rate(64u << 20);
  f.scrub->step();  // picks all three; the executor has not finished
  ASSERT_EQ(f.scrub->in_flight(), 3u);
  ASSERT_EQ(f.store->n_scrub_pins(), 3u);
  f.inv();
  const std::uint64_t used = f.allocated();
  // INVALIDATE the root: the whole chain is removed while pinned -> ZOMBIE, memory intact, not reusable.
  const auto e1 = f.entry(1, 1);
  ASSERT_TRUE(f.store->invalidate(1, sid(1), kh(1), e1.gen));
  EXPECT_EQ(f.store->n_zombies(), 3u);
  EXPECT_EQ(f.allocated(), used);  // nothing was freed
  f.inv();
  f.exec.run_all();  // unpin: freed now
  EXPECT_EQ(f.store->n_zombies(), 0u);
  EXPECT_EQ(f.store->n_scrub_pins(), 0u);
  EXPECT_EQ(f.allocated(), used - 3);
  f.inv();
}

TEST(Scrub, CorruptBlockHeldByReaderLeaseTurnsZombieUntilRelease) {
  Fx f;
  f.chain(1, 1, 2);
  LeaseId lease = 0;
  const auto e = f.entry(1, 2, &lease);
  ASSERT_TRUE(e.hit);
  f.flip(e);
  f.scrub->set_rate(64u << 20);
  f.one_cycle();
  EXPECT_EQ(f.scrub->failed(), 1u);
  EXPECT_FALSE(f.entry(1, 2).hit);          // new lookups miss
  EXPECT_EQ(f.store->n_zombies(), 1u);       // the reader's lease keeps the memory (seq check rejects its read)
  f.inv();
  ASSERT_TRUE(f.store->release(7, lease));
  EXPECT_EQ(f.store->n_zombies(), 0u);
  f.inv();
}

TEST(Scrub, RateAndPerTurnBounds) {
  Fx f;
  f.chain(1, 1, 40);
  // 20 blocks of credit per second; one burst at the start.
  f.scrub->set_rate(20 * kBlk);
  EXPECT_EQ(f.scrub->step(), 16u);  // <= 16 blocks per turn
  f.exec.run_all();
  EXPECT_EQ(f.scrub->step(), 4u);   // the remaining credit
  f.exec.run_all();
  EXPECT_EQ(f.scrub->step(), 0u);   // no time passed: nothing
  f.clock.advance_by(std::chrono::milliseconds(500));
  EXPECT_EQ(f.scrub->step(), 10u);  // 0.5 s = 10 blocks
  f.exec.run_all();
  EXPECT_EQ(f.scrub->checked(), 30u);
  f.scrub->set_rate(0);             // off
  f.clock.advance_by(seconds(10));
  EXPECT_EQ(f.scrub->step(), 0u);
  f.inv();
}

TEST(Scrub, ResumesAcrossTurnsAndWraps) {
  Fx f;
  f.chain(1, 1, 10);
  f.scrub->set_rate(3 * kBlk);
  std::uint64_t seen = 0;
  for (int i = 0; i < 20 && f.scrub->cycles() < 2; ++i) {
    f.clock.advance_by(seconds(1));
    seen += f.scrub->step();
    f.exec.run_all();
  }
  EXPECT_GE(f.scrub->cycles(), 2u);
  EXPECT_GE(seen, 20u);
  EXPECT_EQ(f.scrub->failed(), 0u);
  f.inv();
}

TEST(Scrub, StopsCleanly) {
  Fx f;
  f.chain(1, 1, 6);
  f.scrub->set_rate(64u << 20);
  f.scrub->step();
  ASSERT_EQ(f.scrub->in_flight(), 6u);
  f.scrub->stop();
  EXPECT_EQ(f.scrub->step(), 0u);
  f.exec.run_all();  // in-flight checks still finish and unpin
  EXPECT_EQ(f.scrub->in_flight(), 0u);
  EXPECT_EQ(f.store->n_scrub_pins(), 0u);
  f.inv();
}

TEST(Scrub, LateDoneAfterScrubberDestroyedIsHarmless) {
  Fx f;
  f.chain(1, 1, 3);
  f.scrub->set_rate(64u << 20);
  f.scrub->step();
  f.scrub.reset();   // shutdown with checks in flight
  f.exec.run_all();  // their `done`s do nothing
}

}  // namespace
}  // namespace miracache::store
