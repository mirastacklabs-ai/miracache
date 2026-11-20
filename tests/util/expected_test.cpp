// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include "util/expected.h"

using namespace miracache;

namespace {
Expected<int> half(int v) {
  if (v % 2) return Error{ErrorCode::InvalidArgument, "odd"};
  return v / 2;
}
Status check(bool ok) {
  if (!ok) return Error{ErrorCode::Busy, "nope"};
  return {};
}
}  // namespace

TEST(Expected, ValueAndError) {
  auto ok = half(10);
  ASSERT_TRUE(ok);
  EXPECT_EQ(*ok, 5);
  auto bad = half(3);
  ASSERT_FALSE(bad);
  EXPECT_EQ(bad.error().code, ErrorCode::InvalidArgument);
  EXPECT_STREQ(bad.error().context, "odd");
}

TEST(Expected, Status) {
  EXPECT_TRUE(check(true));
  auto s = check(false);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::Busy);
}

TEST(Expected, ErrorCodeNames) {
  EXPECT_STREQ(to_string(ErrorCode::NotImplemented), "NotImplemented");
}

TEST(ExpectedDeathTest, MisuseTrapsInEveryBuildType) {
  EXPECT_DEATH((void)half(3).value(), "check failed");
  EXPECT_DEATH((void)half(4).error(), "check failed");
  EXPECT_DEATH((void)check(true).error(), "check failed");
}
