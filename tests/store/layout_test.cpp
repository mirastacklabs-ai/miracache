// SPDX-License-Identifier: Apache-2.0
#include <algorithm>
#include <cstring>
#include <vector>

#include <gtest/gtest.h>

#include "proto/state_gen.h"
#include "store/config.h"
#include "store/layout.h"
#include "store/state_gen.h"

namespace miracache::store {
namespace {

TEST(StoreLayout, RegionsAreOrderedAndNonOverlapping) {
  struct Case { std::uint64_t seg, run; };
  const Case cases[] = {{4u << 20, 256u << 10}, {1u << 20, 64u << 10}, {64u << 20, 4u << 20},
                        {4ull << 30, 256ull << 20}, {8u << 20, 512u << 10}};
  for (const auto& c : cases) {
    auto l = compute_segment_layout(c.seg, c.run);
    ASSERT_TRUE(l) << c.seg << "/" << c.run;
    ASSERT_GE(l->n_runs, 1u);
    std::uint64_t end = 0;
    for (const auto& r : l->regions()) {
      EXPECT_GE(r.off, end) << r.name << " overlaps its predecessor";
      EXPECT_GT(r.len, 0u) << r.name;
      end = r.off + r.len;
    }
    EXPECT_LE(end, c.seg);
    EXPECT_EQ(l->data_off % std::min<std::uint64_t>(c.run, 2u << 20), 0u);
    // One more run would not fit (the layout is maximal).
    SegmentLayout more = *l;
    more.n_runs += 1;
    more.data_off = align_up(more.hdr_table_off + more.hdr_table_bytes(), std::min<std::uint64_t>(c.run, 2u << 20));
    EXPECT_GT(more.data_off + more.n_runs * c.run, c.seg);
  }
}

TEST(StoreLayout, RejectsBadGeometry) {
  EXPECT_FALSE(compute_segment_layout(1u << 20, 3000));
  EXPECT_FALSE(compute_segment_layout(64u << 10, 64u << 10));        // tables leave no room
  EXPECT_FALSE(compute_segment_layout(1ull << 40, 1ull << 29));      // run > 256 MiB
}

TEST(StoreLayout, BlockAndHeaderOffsetsStayInsideTheirRegions) {
  auto l = compute_segment_layout(4u << 20, 256u << 10);
  ASSERT_TRUE(l);
  for (std::uint32_t run = 0; run < l->n_runs; ++run) {
    // Smallest blocks: 4 KiB, 64 per 256 KiB run.
    const std::uint32_t nb = static_cast<std::uint32_t>(l->run_bytes >> 12);
    EXPECT_EQ(l->block_off(run, 0, 12), l->run_data_off(run));
    EXPECT_EQ(l->block_off(run, nb - 1, 12) + 4096, l->run_data_off(run) + l->run_bytes);
    EXPECT_GE(l->header_off(run, 0), l->hdr_table_off);
    EXPECT_LE(l->header_off(run, proto::kSlotsPerRun - 1) + kHeaderSlotBytes, l->hdr_table_off + l->hdr_table_bytes());
    EXPECT_LT(l->run_entry_off(run) + proto::kRunEntrySize, l->run_table_off + l->run_table_bytes() + 1);
  }
}

TEST(StoreLayout, GenSlotsAreUniqueAndDense) {
  StoreLayout sl;
  auto l = compute_segment_layout(4u << 20, 256u << 10);
  ASSERT_TRUE(l);
  sl.seg = *l;
  sl.n_segments = 3;
  std::vector<std::uint64_t> slots;
  for (std::uint32_t s = 0; s < 3; ++s)
    for (std::uint32_t r = 0; r < l->n_runs; ++r)
      for (std::uint32_t b = 0; b < proto::kSlotsPerRun; b += 7) slots.push_back(sl.gen_slot(s, r, b));
  std::vector<std::uint64_t> sorted = slots;
  std::sort(sorted.begin(), sorted.end());
  EXPECT_EQ(std::adjacent_find(sorted.begin(), sorted.end()), sorted.end());
  EXPECT_LT(sorted.back(), sl.sg_slots());
  EXPECT_EQ(sl.gen_slot(2, l->n_runs - 1, proto::kSlotsPerRun - 1), sl.sg_slots() - 1);
}

TEST(StateGenArray, StoreLoadAndBytes) {
  StateGenArray a(100);
  EXPECT_EQ(a.load(5), 0u);
  EXPECT_EQ(a.state(5), proto::BlockState::Free);
  a.store(5, proto::BlockState::Writing, 42);
  EXPECT_EQ(a.state(5), proto::BlockState::Writing);
  EXPECT_EQ(a.generation(5), 42u);
  EXPECT_EQ(a.load(5), proto::pack_state_gen(proto::BlockState::Writing, 42));
  a.store(5, proto::BlockState::Committed, 42);
  EXPECT_EQ(a.state(5), proto::BlockState::Committed);
  EXPECT_EQ(a.state(6), proto::BlockState::Free);
  EXPECT_EQ(a.bytes().size(), 800u);
  EXPECT_EQ(reinterpret_cast<std::uintptr_t>(a.bytes().data()) % 4096, 0u);
  // The array's bytes are the words themselves (what the array MR exposes).
  std::uint64_t w;
  std::memcpy(&w, a.bytes().data() + 5 * 8, 8);
  EXPECT_EQ(w, a.load(5));
}

TEST(StoreConfig, ProductionRejectsAnon) {
  StoreConfig c;
  c.backing = BackingKind::Anon;
  EXPECT_TRUE(c.validate());
  c.production = true;
  ASSERT_FALSE(c.validate());
  EXPECT_EQ(c.validate().error().code, ErrorCode::InvalidArgument);
  c.backing = BackingKind::Hugetlbfs;
  EXPECT_FALSE(c.validate());  // dir required
  c.dir = "/mnt/huge";
  EXPECT_TRUE(c.validate());
}

TEST(StoreConfig, RejectsBadSizes) {
  StoreConfig c;
  c.run_bytes = 3 << 10;
  EXPECT_FALSE(c.validate());
  c = StoreConfig{};
  c.n_segments = 0;
  EXPECT_FALSE(c.validate());
  c = StoreConfig{};
  c.run_bytes = 512ull << 20;
  c.segment_bytes = 4ull << 30;
  EXPECT_FALSE(c.validate());
}

}  // namespace
}  // namespace miracache::store
