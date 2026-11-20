// SPDX-License-Identifier: Apache-2.0
// The placement View of a bundle body.
#include <gtest/gtest.h>

#include <array>

#include "control/bundle.h"
#include "control/view.h"
#include "control/bundle_test_util.h"

using namespace miracache::control;
namespace tu = miracache::control::testutil;

TEST(ViewFromBundle, ActiveNodesOnlyDecimalIdsWeightsZones) {
  auto body = parse_body(tu::body_toml());  // node 3141592653 active (w1, rack1), node 7 draining
  ASSERT_TRUE(body.has_value());
  const miracache::View v = view_from_bundle(body.value());
  EXPECT_EQ(v.epoch, 7u);
  ASSERT_EQ(v.nodes.size(), 1u);
  EXPECT_EQ(v.nodes[0].id, "3141592653");
  EXPECT_EQ(v.nodes[0].weight, 1u);
  EXPECT_EQ(v.nodes[0].zone, "rack1");
}

TEST(ViewFromBundle, FeedsOwnerSetAndKeepsBundleOrder) {
  std::string b = tu::body_toml();
  b.replace(b.find("state = \"draining\""), 18, "state = \"active\"");
  auto body = parse_body(b);
  ASSERT_TRUE(body.has_value());
  const miracache::View v = view_from_bundle(body.value());
  ASSERT_EQ(v.nodes.size(), 2u);
  EXPECT_EQ(v.nodes[1].id, "7");
  EXPECT_EQ(v.nodes[1].weight, 2u);
  std::array<std::uint8_t, 32> scope{};
  const auto set = miracache::owner_set(v, scope, 2);
  EXPECT_EQ(set.size(), 2u);
  // Readonly is not an owner either, and a zoneless node gets an empty zone.
  std::string r = tu::body_toml();
  r.replace(r.find("state = \"draining\""), 18, "state = \"readonly\"");
  EXPECT_EQ(view_from_bundle(parse_body(r).value()).nodes.size(), 1u);
}
