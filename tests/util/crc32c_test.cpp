// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <cstring>

#include "util/crc32c.h"

using namespace miracache;

namespace {
std::uint32_t crc_of(const char* s, std::uint32_t seed = 0) {
  return crc32c(std::as_bytes(std::span(s, std::strlen(s))), seed);
}
}  // namespace

TEST(Crc32c, KnownVectors) {
  EXPECT_EQ(crc_of(""), 0u);
  EXPECT_EQ(crc_of("123456789"), 0xE3069283u);
  const std::byte zeros[32] = {};
  EXPECT_EQ(crc32c(zeros), 0x8A9136AAu);  // RFC 3720 B.4: 32 zero bytes
}

TEST(Crc32c, Chaining) {
  EXPECT_EQ(crc_of("6789", crc_of("12345")), crc_of("123456789"));
}
