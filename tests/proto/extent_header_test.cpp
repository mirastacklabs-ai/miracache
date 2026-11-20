// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>

#include "golden.h"
#include "proto/extent_header.h"
#include "test_util.h"

using namespace miracache;
using namespace miracache::proto;
using namespace miracache::testutil;

namespace {

ExtentHeader golden_header() {
  ExtentHeader h;
  h.log2_segment = 18;
  h.kver = 0x01020304;
  for (int i = 0; i < 16; ++i) h.block_salt[i] = static_cast<std::uint8_t>(0xA0 + i);
  h.plaintext_len = 0x0000000200000001ULL;
  return h;
}

std::array<std::byte, kExtentHeaderSize> encoded(const ExtentHeader& h) {
  std::array<std::byte, kExtentHeaderSize> buf{};
  EXPECT_TRUE(encode(h, buf));
  return buf;
}

void scope_key(std::uint8_t (&scope)[32], std::uint8_t (&key)[32]) {
  for (int i = 0; i < 32; ++i) { scope[i] = static_cast<std::uint8_t>(i); key[i] = static_cast<std::uint8_t>(0x40 + i); }
}

}  // namespace

TEST(ExtentHeader, LittleEndianPlacement) {
  const Bytes want = cat({bytes({'M', 'I', 'R', 'C'}),             // 0  magic
                          bytes({1, 1, 18, 0}),                    // 4  ver, cipher, log2, z
                          bytes({4, 3, 2, 1}),                     // 8  kver = 0x01020304
                          bytes({0, 0, 0, 0}),                     // 12 z
                          ramp(16, 0xA0),                          // 16 block_salt
                          bytes({1, 0, 0, 0, 2, 0, 0, 0}),         // 32 plaintext_len
                          zeros(24)});                             // 40 z
  ASSERT_EQ(want.size(), kExtentHeaderSize);
  const auto b = encoded(golden_header());
  EXPECT_TRUE(std::equal(want.begin(), want.end(), b.begin()));
}

TEST(ExtentHeader, MatchesGoldenVector) {
  EXPECT_TRUE(golden::matches("extent_header_v0.hex", encoded(golden_header())));
}

TEST(ExtentHeader, RoundTrip) {
  const auto h = golden_header();
  auto d = decode_extent_header(encoded(h));
  ASSERT_TRUE(d);
  EXPECT_EQ(d->kver, h.kver);
  EXPECT_EQ(d->plaintext_len, h.plaintext_len);
  EXPECT_EQ(d->log2_segment, 18);
  EXPECT_EQ(std::memcmp(d->block_salt, h.block_salt, 16), 0);
}

TEST(ExtentHeader, EncodeRejectsBadFields) {
  std::array<std::byte, kExtentHeaderSize> buf{};
  for (std::uint8_t log2 : {15, 21}) {
    auto h = golden_header();
    h.log2_segment = log2;
    EXPECT_FALSE(encode(h, buf)) << int(log2);
  }
  auto h = golden_header();
  h.reserved[23] = 1;
  EXPECT_FALSE(encode(h, buf));
  h = golden_header();
  h.z7 = 1;
  EXPECT_FALSE(encode(h, buf));
  h = golden_header();
  h.z12 = 1;
  EXPECT_FALSE(encode(h, buf));
}

TEST(ExtentHeader, DecodeRejectsBadBytes) {
  const auto good = encoded(golden_header());
  struct Case { std::size_t off; std::uint8_t val; ErrorCode code; };
  for (Case c : {Case{0, 'X', ErrorCode::Corrupt}, Case{4, 9, ErrorCode::Unsupported},
                 Case{5, 7, ErrorCode::Unsupported}, Case{6, 15, ErrorCode::Corrupt},
                 Case{6, 21, ErrorCode::Corrupt}, Case{7, 1, ErrorCode::Corrupt},
                 Case{12, 1, ErrorCode::Corrupt}, Case{15, 1, ErrorCode::Corrupt},
                 Case{40, 1, ErrorCode::Corrupt}, Case{63, 1, ErrorCode::Corrupt}}) {
    auto b = good;
    b[c.off] = static_cast<std::byte>(c.val);
    auto d = decode_extent_header(b);
    ASSERT_FALSE(d) << "off " << c.off;
    EXPECT_EQ(d.error().code, c.code) << "off " << c.off;
  }
}

TEST(ExtentHeader, ReservedAegisIdIsAccepted) {
  auto h = golden_header();
  h.cipher_id = static_cast<std::uint8_t>(CipherId::Aegis256);
  EXPECT_TRUE(decode_extent_header(encoded(h)));
}

TEST(ExtentHeader, SegmentCountD17) {
  EXPECT_EQ(segment_count(0, 16), 1u);  // empty plaintext still has a final segment
  EXPECT_EQ(segment_count(1, 16), 1u);
  EXPECT_EQ(segment_count(65536, 16), 1u);
  EXPECT_EQ(segment_count(65537, 16), 2u);
  EXPECT_EQ(segment_count(3u << 20, 20), 3u);
}

TEST(ExtentHeader, AadIs80BytesHandPlaced) {
  std::uint8_t scope[32], key[32];
  scope_key(scope, key);
  const Bytes want = cat({bytes({1, 1, 18, 0}),                   // ver, cipher, log2, 0
                          bytes({4, 3, 2, 1}),                    // kver LE
                          ramp(32, 0x00), ramp(32, 0x40),         // scope_id, key_hash
                          bytes({1, 0, 0, 0, 2, 0, 0, 0})});      // plaintext_len LE
  ASSERT_EQ(want.size(), kAadSize);
  const auto a = build_aad(golden_header(), scope, key);
  EXPECT_TRUE(std::equal(want.begin(), want.end(), a.begin()));
  EXPECT_TRUE(golden::matches("aad_v0.hex", a));
}

TEST(ExtentHeader, StreamNonceBigEndianCounter) {
  const Bytes n0 = cat({zeros(11), bytes({0})});
  const auto a = stream_nonce(0, false);
  EXPECT_TRUE(std::equal(n0.begin(), n0.end(), a.begin()));
  EXPECT_TRUE(golden::matches("nonce_v0_i0_last0.hex", a));
  const Bytes n1 = cat({zeros(7), bytes({0x01, 0x02, 0x03, 0x04, 1})});
  const auto b = stream_nonce(0x01020304, true);
  EXPECT_TRUE(std::equal(n1.begin(), n1.end(), b.begin()));
  EXPECT_TRUE(golden::matches("nonce_v0_i01020304_last1.hex", b));
}
