// SPDX-License-Identifier: Apache-2.0
// Slab allocator tests: seeded-loop properties, no external property library.
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include <gtest/gtest.h>

#include "store/slab.h"
#include "util/random.h"

namespace miracache::store {
namespace {

StoreConfig small_cfg() {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  return c;
}

// Many runs so the 64-class cap is reachable: 512 KiB runs, 64 MiB segments.
StoreConfig wide_cfg() {
  StoreConfig c = small_cfg();
  c.segment_bytes = 64u << 20;
  c.run_bytes = 512u << 10;
  return c;
}

struct Fixture {
  explicit Fixture(const StoreConfig& c) {
    auto a = Arena::open(c);
    EXPECT_TRUE(a);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
  }
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
};

// Live-extent model: no byte of two live extents overlaps; slots are distinct.
struct Live {
  std::map<std::pair<std::uint32_t, std::uint64_t>, Extent> by_off;  // (seg, off)
  std::set<std::uint64_t> slots;

  void add(const Extent& e) {
    auto it = by_off.lower_bound({e.seg, e.off});
    if (it != by_off.end() && it->first.first == e.seg) ASSERT_GE(it->first.second, e.off + e.len);
    if (it != by_off.begin()) {
      auto p = std::prev(it);
      if (p->first.first == e.seg) ASSERT_LE(p->first.second + p->second.len, e.off);
    }
    ASSERT_TRUE(slots.insert(e.gen_slot).second);
    by_off.emplace(std::make_pair(e.seg, e.off), e);
  }
  void remove(const Extent& e) {
    by_off.erase({e.seg, e.off});
    slots.erase(e.gen_slot);
  }
};

TEST(Slab, FreshBatchAdjacentSameClass) {
  Fixture f(small_cfg());
  const std::uint64_t lens[] = {5000, 6000, 8192, 7000};  // all round to 8 KiB
  auto r = f.slab->alloc_batch(lens);
  ASSERT_TRUE(r);
  ASSERT_EQ(r->size(), 4u);
  for (std::size_t i = 0; i < 4; ++i) {
    EXPECT_EQ((*r)[i].len, 8192u);
    EXPECT_EQ((*r)[i].seg, (*r)[0].seg);
    EXPECT_EQ((*r)[i].off, (*r)[0].off + i * 8192);
    EXPECT_EQ((*r)[i].gen_slot, (*r)[0].gen_slot + i);
  }
  EXPECT_TRUE(f.slab->check_invariants());
}

TEST(Slab, MixedBatchSeparateClassesInInputOrder) {
  Fixture f(small_cfg());
  const std::uint64_t lens[] = {4096, 9000, 4000, 20000};
  auto r = f.slab->alloc_batch(lens);
  ASSERT_TRUE(r);
  const std::uint64_t want[] = {4096, 12288, 4096, 20480};
  for (std::size_t i = 0; i < 4; ++i) EXPECT_EQ((*r)[i].len, want[i]);
  EXPECT_EQ((*r)[2].off, (*r)[0].off + 4096);  // same class stays adjacent
  EXPECT_EQ(f.slab->n_classes(), 3u);
  EXPECT_TRUE(f.slab->check_invariants());
}

TEST(Slab, BadBatches) {
  Fixture f(small_cfg());
  const std::uint64_t five[] = {1, 1, 1, 1, 1};
  EXPECT_EQ(f.slab->alloc_batch(five).error().code, ErrorCode::InvalidArgument);
  EXPECT_EQ(f.slab->alloc_batch(std::span<const std::uint64_t>{}).error().code, ErrorCode::InvalidArgument);
  const std::uint64_t big[] = {(256u << 10) + 1};
  EXPECT_EQ(f.slab->alloc_batch(big).error().code, ErrorCode::InvalidArgument);
  EXPECT_EQ(f.slab->n_classes(), 0u);
  EXPECT_EQ(f.arena->gens().last(), 0u);
}

TEST(Slab, StateWordIsWritingBeforeHeader) {
  Fixture f(small_cfg());
  const std::uint64_t lens[] = {10000};
  auto r = f.slab->alloc_batch(lens);
  ASSERT_TRUE(r);
  const Extent& e = (*r)[0];
  const auto& sg = f.arena->state_gen();
  EXPECT_EQ(sg.load(e.gen_slot), proto::pack_state_gen(proto::BlockState::Writing, e.gen));
  EXPECT_EQ(sg.state(e.gen_slot), proto::BlockState::Writing);
  // The header slot is still blank: the state word came first.
  const auto& l = f.arena->layout();
  const std::uint64_t hoff = l.seg.hdr_table_off + (e.gen_slot - std::uint64_t{e.seg} * l.seg.slots()) * kHeaderSlotBytes;
  auto hb = f.arena->block(e.seg, hoff, kHeaderSlotBytes);
  std::array<std::byte, proto::kServerHeaderSize> zero{};
  EXPECT_EQ(std::memcmp(hb.data(), zero.data(), zero.size()), 0);
  proto::ServerHeader h;
  h.stored_len = 10000;
  f.slab->write_header(e, h);
  auto d = proto::decode_server_header(std::span<const std::byte, proto::kServerHeaderSize>(hb.data(), proto::kServerHeaderSize));
  ASSERT_TRUE(d);
  EXPECT_EQ(d->generation, e.gen);
  EXPECT_EQ(d->stored_len, 10000u);
}

// One owner creates at most max_exact_classes_per_owner exact classes; further sizes use
// the fixed ladder rungs, and a second owner is never refused because of the first one's classes.
TEST(Slab, PerOwnerExactClassBudgetAndRungFallback) {
  Fixture f(wide_cfg());
  const auto budget = f.arena->config().max_exact_classes_per_owner;
  std::vector<Extent> held;
  for (std::uint64_t k = 1; k <= 3 * budget; ++k) {  // owner 1 tries many distinct sizes
    const std::uint64_t len[] = {8192 * k + 1};
    auto r = f.slab->alloc_batch(len, 1);
    ASSERT_TRUE(r) << k;
    EXPECT_GE((*r)[0].len, len[0]);
    held.push_back((*r)[0]);
  }
  std::size_t exact = 0;
  for (auto& s : f.slab->class_stats()) exact += s.len == f.slab->ladder_len(s.len) ? 0 : 1;
  EXPECT_LE(exact, budget);
  // Owner 2 gets its own budget although owner 1 filled the exact-class space of its own.
  for (std::uint64_t k = 1; k <= 3 * budget; ++k) {
    const std::uint64_t len[] = {4096 * k + 7};
    auto r = f.slab->alloc_batch(len, 2);
    ASSERT_TRUE(r) << k;
    held.push_back((*r)[0]);
  }
  // Even with the global exact cap reached by many owners, a new owner is served by a rung.
  for (std::uint64_t o = 10; o < 10 + 80; ++o) {
    const std::uint64_t len[] = {4096 * (o - 9) - 5};
    auto r = f.slab->alloc_batch(len, o);
    ASSERT_TRUE(r) << o;
    held.push_back((*r)[0]);
  }
  std::size_t n_exact = 0;
  for (auto& s : f.slab->class_stats()) n_exact += s.len == f.slab->ladder_len(s.len) ? 0 : 1;
  ASSERT_EQ(n_exact, SlabAllocator::kMaxClasses);  // the global exact cap is reached
  const std::uint64_t odd[] = {(400u << 10) - 3};
  auto last = f.slab->alloc_batch(odd, 999);
  ASSERT_TRUE(last);  // never "class cap reached" because of other owners
  EXPECT_EQ((*last)[0].len, f.slab->ladder_len(odd[0]));
  held.push_back((*last)[0]);
  EXPECT_TRUE(f.slab->check_invariants());
  for (auto& e : held) f.slab->free(e);
  EXPECT_EQ(f.slab->n_classes(), 0u);
  EXPECT_TRUE(f.slab->check_invariants());
}

TEST(Slab, LadderRungsAreMonotoneAndBounded) {
  Fixture f(wide_cfg());
  std::uint64_t prev = 0;
  for (std::uint64_t len = 1; len <= (512u << 10); len += 977) {
    const std::uint64_t rung = f.slab->ladder_len(len);
    EXPECT_GE(rung, len);
    EXPECT_LE(rung, 2 * std::max<std::uint64_t>(len, 4096));
    EXPECT_GE(rung, prev);
    prev = rung;
  }
}

// Huge peer-supplied lengths must neither wrap align_up (divide by zero) nor allocate.
TEST(Slab, HugeLengthsAreRejectedNotWrapped) {
  Fixture f(small_cfg());
  const std::uint64_t run = f.arena->config().run_bytes;
  for (std::uint64_t huge : {~std::uint64_t{0}, ~std::uint64_t{0} - 4095, ~std::uint64_t{0} - 4096, run + 1}) {
    const std::uint64_t len[] = {huge};
    auto r = f.slab->alloc_batch(len);
    ASSERT_FALSE(r) << huge;
    EXPECT_EQ(r.error().code, ErrorCode::InvalidArgument);
  }
  EXPECT_GT(f.slab->exact_len(~std::uint64_t{0}), f.arena->config().run_bytes);
  EXPECT_EQ(f.slab->n_classes(), 0u);
  EXPECT_TRUE(f.slab->check_invariants());
}

TEST(Slab, ExhaustionNeverPartialAndFreeReuseGetsNewGeneration) {
  Fixture f(small_cfg());
  std::vector<Extent> all;
  std::set<std::uint64_t> gens;
  const std::uint64_t one[] = {4096};
  for (;;) {
    auto r = f.slab->alloc_batch(one);
    if (!r) {
      EXPECT_EQ(r.error().code, ErrorCode::ResourceExhausted);
      break;
    }
    ASSERT_TRUE(gens.insert((*r)[0].gen).second);
    all.push_back((*r)[0]);
  }
  ASSERT_FALSE(all.empty());
  auto st = f.slab->class_stats();
  ASSERT_EQ(st.size(), 1u);
  EXPECT_EQ(st[0].free, 0u);
  EXPECT_EQ(st[0].allocated, all.size());
  // Capacity: every run is formatted for 4 KiB blocks.
  EXPECT_EQ(st[0].blocks, std::uint64_t{f.slab->total_runs()} * (256u << 10) / 4096);

  // A 4-batch with 3 free blocks must fail whole.
  for (int i = 0; i < 3; ++i) {
    f.slab->free(all.back());
    all.pop_back();
  }
  const std::uint64_t four[] = {4096, 4096, 4096, 4096};
  const auto last = f.arena->gens().last();
  std::vector<std::uint64_t> words;
  for (const auto& e : all) words.push_back(f.arena->state_gen().load(e.gen_slot));
  auto r4 = f.slab->alloc_batch(four);
  ASSERT_FALSE(r4);
  EXPECT_EQ(r4.error().code, ErrorCode::ResourceExhausted);
  EXPECT_EQ(f.arena->gens().last(), last);
  EXPECT_EQ(f.slab->class_stats()[0].free, 3u);
  EXPECT_TRUE(f.slab->check_invariants());

  // Reuse: freed slots come back with fresh, larger generations.
  const std::uint64_t three[] = {4096, 4096, 4096};
  auto r3 = f.slab->alloc_batch(three);
  ASSERT_TRUE(r3);
  for (const auto& e : *r3) {
    EXPECT_GT(e.gen, last);
    EXPECT_TRUE(gens.insert(e.gen).second);  // GenerationsUnique
    EXPECT_EQ(f.arena->state_gen().state(e.gen_slot), proto::BlockState::Writing);
  }
  EXPECT_EQ(f.slab->class_stats()[0].free, 0u);
}

TEST(Slab, FreeMarksSlotFreeAndRecyclesRuns) {
  Fixture f(small_cfg());
  const std::uint64_t lens[] = {4096, 8192};
  auto r = f.slab->alloc_batch(lens);
  ASSERT_TRUE(r);
  EXPECT_EQ(f.slab->free_runs(), f.slab->total_runs() - 2);
  for (const auto& e : *r) {
    f.slab->free(e);
    EXPECT_EQ(f.arena->state_gen().state(e.gen_slot), proto::BlockState::Free);
    EXPECT_EQ(f.arena->state_gen().generation(e.gen_slot), e.gen);
  }
  EXPECT_EQ(f.slab->free_runs(), f.slab->total_runs());
  EXPECT_EQ(f.slab->n_classes(), 0u);
  // A run can be re-formatted for another class.
  const std::uint64_t other[] = {12288};
  ASSERT_TRUE(f.slab->alloc_batch(other));
  EXPECT_TRUE(f.slab->check_invariants());
}

class SlabProperty : public ::testing::TestWithParam<std::uint64_t> {};

TEST_P(SlabProperty, RandomOps) {
  SeededRandom rng(GetParam());
  Fixture f(rng.chance(0.5) ? small_cfg() : wide_cfg());
  Live live;
  std::vector<Extent> pool;
  std::uint64_t last_gen = 0;
  std::set<std::uint64_t> seen_gens;
  std::size_t exhausted = 0;
  const std::uint64_t max_len = f.arena->config().run_bytes;

  for (int step = 0; step < 1500; ++step) {
    if (pool.empty() || rng.chance(0.6)) {
      const std::size_t n = 1 + rng.below(4);
      std::vector<std::uint64_t> lens(n);
      const bool few = rng.chance(0.7);
      for (auto& l : lens) l = few ? 4096 * (1 + rng.below(4)) - rng.below(100) : 1 + rng.below(max_len);
      const auto before_last = f.arena->gens().last();
      std::uint64_t used_before = 0;
      for (auto& s : f.slab->class_stats()) used_before += s.allocated;
      auto r = f.slab->alloc_batch(lens);
      std::uint64_t used_after = 0;
      for (auto& s : f.slab->class_stats()) used_after += s.allocated;
      if (!r) {
        ASSERT_EQ(r.error().code, ErrorCode::ResourceExhausted);
        ASSERT_EQ(f.arena->gens().last(), before_last);
        ASSERT_EQ(used_after, used_before);  // never a partial batch
        ++exhausted;
      } else {
        ASSERT_EQ(r->size(), n);
        ASSERT_EQ(used_after, used_before + n);
        for (std::size_t i = 0; i < n; ++i) {
          const Extent& e = (*r)[i];
          ASSERT_GE(e.len, lens[i]);
          ASSERT_EQ(e.len % 4096, 0u);
          ASSERT_GT(e.gen, last_gen);  // strictly increasing across and within batches
          last_gen = e.gen;
          ASSERT_TRUE(seen_gens.insert(e.gen).second);
          ASSERT_EQ(f.arena->state_gen().load(e.gen_slot),
                    proto::pack_state_gen(proto::BlockState::Writing, e.gen));
          live.add(e);
          if (::testing::Test::HasFatalFailure()) return;
          pool.push_back(e);
        }
      }
    } else {
      const std::size_t i = rng.below(pool.size());
      const Extent e = pool[i];
      pool[i] = pool.back();
      pool.pop_back();
      f.slab->free(e);
      live.remove(e);
      ASSERT_EQ(f.arena->state_gen().state(e.gen_slot), proto::BlockState::Free);
    }
    if (step % 25 == 0) {
      ASSERT_TRUE(f.slab->check_invariants());
      // Exact accounting: allocated + free = capacity per class, allocated = live count.
      std::map<std::uint64_t, std::uint64_t> live_per_class;
      for (const auto& e : pool) ++live_per_class[e.len];
      for (const auto& s : f.slab->class_stats()) {
        ASSERT_EQ(s.allocated + s.free, s.blocks);
        ASSERT_EQ(s.allocated, live_per_class[s.len]);
        ASSERT_GT(s.runs, 0u);
      }
      ASSERT_LE(f.slab->n_classes(), SlabAllocator::kMaxClasses);
    }
  }
  for (const auto& e : pool) f.slab->free(e);
  ASSERT_TRUE(f.slab->check_invariants());
  EXPECT_EQ(f.slab->free_runs(), f.slab->total_runs());
  EXPECT_EQ(f.slab->n_classes(), 0u);
  (void)exhausted;
}

INSTANTIATE_TEST_SUITE_P(Seeds, SlabProperty, ::testing::Range<std::uint64_t>(1, 41));

// Pressure variant: tiny pool so ResourceExhausted and scatter paths are hit often.
TEST(Slab, PressureSeeds) {
  std::size_t exhausted = 0;
  for (std::uint64_t seed = 1; seed <= 20; ++seed) {
    SeededRandom rng(seed);
    StoreConfig c = small_cfg();
    c.n_segments = 1;
    Fixture f(c);
    Live live;
    std::vector<Extent> pool;
    for (int step = 0; step < 600; ++step) {
      if (pool.empty() || rng.chance(0.65)) {
        std::vector<std::uint64_t> lens(1 + rng.below(4));
        for (auto& l : lens) l = 4096 * (1 + rng.below(3));
        auto r = f.slab->alloc_batch(lens);
        if (!r) {
          ASSERT_EQ(r.error().code, ErrorCode::ResourceExhausted);
          ++exhausted;
          continue;
        }
        for (const auto& e : *r) {
          live.add(e);
          if (::testing::Test::HasFatalFailure()) return;
          pool.push_back(e);
        }
      } else {
        const std::size_t i = rng.below(pool.size());
        f.slab->free(pool[i]);
        live.remove(pool[i]);
        pool[i] = pool.back();
        pool.pop_back();
      }
      ASSERT_TRUE(f.slab->check_invariants());
    }
  }
  EXPECT_GT(exhausted, 0u);
}

}  // namespace
}  // namespace miracache::store
