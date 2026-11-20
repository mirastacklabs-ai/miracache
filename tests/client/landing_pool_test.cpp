// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <vector>

#include "client/landing_pool.h"
#include "fabric/sim/sim_fabric.h"

namespace miracache {
namespace {

struct Env {
  SimClock clock;
  SeededRandom rng{1};
  fabric::SimNetwork net{clock, rng, fabric::FaultConfig{}};
  fabric::SimFabric& fab = net.add_node(1);
};

constexpr SubpoolKey kKey{7, 0};

TEST(LandingPool, SpansDoNotOverlapAndAreAligned) {
  Env e;
  LandingPool p(e.fab);
  ASSERT_TRUE(p.add_subpool(kKey, fabric::PdId{}, 64 * 1024).has_value());
  std::vector<PoolSpan> spans;
  for (std::size_t len : {1u, 4096u, 5000u, 12288u, 100u}) {
    auto s = p.acquire(kKey, len);
    ASSERT_TRUE(s.has_value());
    EXPECT_EQ(s->off % kPoolAlign, 0u);
    EXPECT_EQ(reinterpret_cast<std::uintptr_t>(s->addr) % kPoolAlign, 0u);
    EXPECT_EQ(s->len, len);
    for (const auto& o : spans) {
      EXPECT_TRUE(s->off >= o.off + (o.len + 4095) / 4096 * 4096 || o.off >= s->off + (s->len + 4095) / 4096 * 4096);
    }
    spans.push_back(*s);
  }
  EXPECT_EQ(p.bytes_in_use(), 4096u + 4096 + 8192 + 12288 + 4096);
  for (const auto& s : spans) p.release(s);
  EXPECT_EQ(p.bytes_in_use(), 0u);
}

TEST(LandingPool, FullPoolIsBackpressureAndReleaseCoalesces) {
  Env e;
  LandingPool p(e.fab);
  ASSERT_TRUE(p.add_subpool(kKey, fabric::PdId{}, 16 * 1024).has_value());
  auto a = p.acquire(kKey, 8192), b = p.acquire(kKey, 8192);
  ASSERT_TRUE(a && b);
  auto full = p.acquire(kKey, 1);
  ASSERT_FALSE(full.has_value());
  EXPECT_EQ(full.error().code, ErrorCode::ResourceExhausted);
  p.release(*a);
  p.release(*b);  // two halves coalesce back into one 16 KiB extent
  auto whole = p.acquire(kKey, 16 * 1024);
  EXPECT_TRUE(whole.has_value());
}

TEST(LandingPool, ResizeRetiresOldGenerationAfterLastRelease) {
  Env e;
  LandingPool p(e.fab);
  ASSERT_TRUE(p.add_subpool(kKey, fabric::PdId{}, 16 * 1024).has_value());
  auto old = p.acquire(kKey, 4096);
  ASSERT_TRUE(old.has_value());
  ASSERT_TRUE(p.resize_subpool(kKey, 64 * 1024).has_value());
  EXPECT_EQ(p.live_generations(kKey), 2u);
  auto fresh = p.acquire(kKey, 32 * 1024);  // only fits in the new generation
  ASSERT_TRUE(fresh.has_value());
  EXPECT_NE(fresh->gen, old->gen);
  p.release(*old);
  EXPECT_EQ(p.live_generations(kKey), 1u);
  p.release(*fresh);
  EXPECT_EQ(p.bytes_in_use(), 0u);
}

TEST(LandingPool, ErrorsAndBacking) {
  Env e;
  LandingPool p(e.fab);
  EXPECT_FALSE(p.acquire(kKey, 1).has_value());
  EXPECT_FALSE(p.resize_subpool(kKey, 4096).has_value());
  ASSERT_TRUE(p.add_subpool(kKey, fabric::PdId{}, 4096).has_value());
  EXPECT_FALSE(p.add_subpool(kKey, fabric::PdId{}, 4096).has_value());
  EXPECT_FALSE(p.acquire(kKey, 0).has_value());
  const auto b = p.backing();
  EXPECT_TRUE(b == PoolBacking::Anon || b == PoolBacking::Thp || b == PoolBacking::Huge2M ||
              b == PoolBacking::Huge1G);
  // The span is writable memory registered for LocalWrite|RemoteWrite.
  auto s = p.acquire(kKey, 4096);
  ASSERT_TRUE(s.has_value());
  s->addr[0] = std::byte{1};
  const auto* mr = e.fab.find_region(s->lkey);
  ASSERT_NE(mr, nullptr);
  EXPECT_TRUE(fabric::has(mr->access, fabric::Access::RemoteWrite));
  EXPECT_TRUE(fabric::has(mr->access, fabric::Access::LocalWrite));
}

}  // namespace
}  // namespace miracache
