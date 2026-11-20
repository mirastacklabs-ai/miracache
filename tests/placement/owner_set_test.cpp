// SPDX-License-Identifier: Apache-2.0
// owner_set: view-based placement order, short sets, thread-local hash context.
#include <gtest/gtest.h>

#include <array>
#include <thread>
#include <vector>

#include "placement/placement.h"

namespace miracache {
namespace {

using Scope = std::array<std::uint8_t, 32>;

Scope scope_of(std::uint8_t k) {
  Scope s{};
  for (std::size_t i = 0; i < 32; ++i) s[i] = static_cast<std::uint8_t>(k * 31 + i);
  return s;
}

View view_of(std::size_t n, bool zoned, std::size_t zones = 0) {
  View v;
  v.epoch = 7;
  for (std::size_t i = 0; i < n; ++i)
    v.nodes.push_back(PlaceNode{std::to_string(i + 1), 1, zoned ? "z" + std::to_string(i % zones) : std::string{}});
  return v;
}

TEST(OwnerSet, EqualsPlaceOrderAndOwnerIsIndexZero) {
  const View v = view_of(5, false);
  for (std::uint8_t k = 0; k < 50; ++k) {
    const Scope s = scope_of(k);
    const auto set = owner_set(v, s, 3);
    EXPECT_EQ(set, place_order(v.nodes, s, 3));
    ASSERT_EQ(set.size(), 3u);
    EXPECT_EQ(set[0], place_owner(v.nodes, s));
    EXPECT_EQ(owner_set(v, s, 1)[0], set[0]);
  }
}

TEST(OwnerSet, RGreaterThanNodesGivesShorterSet) {
  const View v = view_of(2, false);
  const auto set = owner_set(v, scope_of(1), 5);
  ASSERT_EQ(set.size(), 2u);
  EXPECT_NE(set[0], set[1]);
  EXPECT_TRUE(owner_set(View{}, scope_of(1), 3).empty());
}

TEST(OwnerSet, RGreaterThanZonesGivesShorterSet) {
  const View v = view_of(6, true, 2);
  for (std::uint8_t k = 0; k < 20; ++k) {
    const Scope s = scope_of(k);
    const auto set = owner_set(v, s, 4);
    ASSERT_EQ(set.size(), 2u);
    EXPECT_NE(v.nodes[set[0]].zone, v.nodes[set[1]].zone);
    EXPECT_EQ(set[0], place_owner(v.nodes, s));  // the owner does not depend on zones
  }
}

TEST(OwnerSet, ThreadLocalContextFromSeveralThreads) {
  const View v = view_of(7, false);
  std::vector<std::vector<std::size_t>> want;
  for (std::uint8_t k = 0; k < 64; ++k) want.push_back(owner_set(v, scope_of(k), 3));
  std::vector<std::thread> ts;
  std::vector<int> bad(8, 0);
  for (int t = 0; t < 8; ++t)
    ts.emplace_back([&, t] {
      for (int rep = 0; rep < 200; ++rep)
        for (std::uint8_t k = 0; k < 64; ++k)
          if (owner_set(v, scope_of(k), 3) != want[k]) ++bad[static_cast<std::size_t>(t)];
    });
  for (auto& th : ts) th.join();
  for (int b : bad) EXPECT_EQ(b, 0);
}

}  // namespace
}  // namespace miracache
