// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <cstdint>
#include <set>

#include "util/clock.h"
#include "util/random.h"

using namespace miracache;

TEST(SimClock, OnlyMovesWhenTold) {
  SimClock c;
  EXPECT_EQ(c.now(), Nanos{0});
  c.advance_by(Nanos{50});
  c.advance_to(Nanos{20});  // never backwards
  EXPECT_EQ(c.now(), Nanos{50});
  c.advance_to(Nanos{70});
  EXPECT_EQ(c.now(), Nanos{70});
}

TEST(RealClock, IsMonotonic) {
  RealClock c;
  auto a = c.now();
  EXPECT_GE(c.now(), a);
}

TEST(SeededRandom, SameSeedSameStream) {
  SeededRandom a(42), b(42), c(43);
  bool differs = false;
  for (int i = 0; i < 100; ++i) {
    auto x = a.next_u64();
    EXPECT_EQ(x, b.next_u64());
    differs |= x != c.next_u64();
  }
  EXPECT_TRUE(differs);
}

// Regression pin for the stream of xoshiro256** seeded via splitmix64(0): changing the algorithm
// would silently change every recorded simulation seed.
TEST(SeededRandom, GoldenStream) {
  SeededRandom r(0);
  EXPECT_EQ(r.next_u64(), 0x99ec5f36cb75f2b4ULL);
  EXPECT_EQ(r.next_u64(), 0xbf6e1f784956452aULL);
}

TEST(Random, BoundsAndChance) {
  SeededRandom r(7);
  std::set<std::uint64_t> seen;
  for (int i = 0; i < 2000; ++i) {
    auto v = r.below(6);
    ASSERT_LT(v, 6u);
    seen.insert(v);
    auto w = r.between(10, 12);
    ASSERT_TRUE(w >= 10 && w <= 12);
  }
  EXPECT_EQ(seen.size(), 6u);
  EXPECT_FALSE(r.chance(0.0));
  EXPECT_TRUE(r.chance(1.0));
  int hits = 0;
  for (int i = 0; i < 10000; ++i) hits += r.chance(0.25);
  EXPECT_NEAR(hits, 2500, 300);
}

TEST(RealRandom, Produces) {
  RealRandom r;
  r.next_u64();
}

TEST(SimClockDeathTest, NegativeAdvanceTraps) {
  SimClock c;
  EXPECT_DEATH(c.advance_by(Nanos{-1}), "check failed");
}

TEST(RandomDeathTest, MisuseTraps) {
  SeededRandom r(1);
  EXPECT_DEATH(r.below(0), "check failed");
  EXPECT_DEATH(r.between(5, 4), "check failed");
}

TEST(Random, FullRangeBetweenDoesNotOverflow) {
  SeededRandom r(3), same(3);
  EXPECT_EQ(r.between(0, UINT64_MAX), same.next_u64());  // full range is a raw draw
  EXPECT_EQ(r.between(7, 7), 7u);
  for (int i = 0; i < 100; ++i) {
    auto v = r.between(UINT64_MAX - 1, UINT64_MAX);
    EXPECT_GE(v, UINT64_MAX - 1);
  }
  EXPECT_LT(r.below(UINT64_MAX), UINT64_MAX);
  r.below(1ULL << 63);
}
