// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>

#include "golden.h"
#include "proto/server_header.h"
#include "test_util.h"
#include "util/crc32c.h"

using namespace miracache;
using namespace miracache::proto;
using namespace miracache::testutil;

namespace {

ServerHeader golden_header() {
  ServerHeader h;
  h.flags = 0;
  h.generation = 0x0102030405ULL;
  h.stored_len = 0x1000;
  for (int i = 0; i < 32; ++i) h.scope_id[i] = static_cast<std::uint8_t>(i);
  for (int i = 0; i < 32; ++i) h.key_hash[i] = static_cast<std::uint8_t>(0x40 + i);
  for (int i = 0; i < 16; ++i) h.parent_hash[i] = static_cast<std::uint8_t>(0x80 + i);
  h.chain_pos = 7;
  h.writer_id = 0xAABBCCDD;
  h.format_epoch = 9;
  h.payload_crc = 0xDEADBEEF;
  return h;
}

std::array<std::byte, kServerHeaderSize> encoded(const ServerHeader& h) {
  std::array<std::byte, kServerHeaderSize> buf{};
  encode(h, buf);
  return buf;
}

// Hand-placed bytes 0..123 of golden_header(), written from the spec table, not from encode().
Bytes hand_prefix() {
  return cat({bytes({'M', 'I', 'R', 'H'}),          // 0  magic
              bytes({0, 0}),                        // 4  hdr_version
              bytes({0, 0}),                        // 6  flags
              bytes({5, 4, 3, 2, 1, 0, 0, 0}),      // 8  generation = 0x0102030405
              bytes({0, 0x10, 0, 0, 0, 0, 0, 0}),   // 16 stored_len = 0x1000
              ramp(32, 0x00),                       // 24 scope_id
              ramp(32, 0x40),                       // 56 key_hash
              ramp(16, 0x80),                       // 88 parent_hash
              bytes({7, 0, 0, 0, 0, 0, 0, 0}),      // 104 chain_pos
              bytes({0xDD, 0xCC, 0xBB, 0xAA}),      // 112 writer_id
              bytes({9, 0, 0, 0}),                  // 116 format_epoch
              bytes({0xEF, 0xBE, 0xAD, 0xDE})});    // 120 payload_crc
}

}  // namespace

TEST(ServerHeader, LittleEndianPlacement) {
  const auto b = encoded(golden_header());
  const Bytes want_prefix = hand_prefix();
  ASSERT_EQ(want_prefix.size(), 124u);
  EXPECT_TRUE(std::equal(want_prefix.begin(), want_prefix.end(), b.begin()));
  const std::uint32_t crc = crc32c(std::span<const std::byte>(want_prefix));  // CRC covers 0..123
  for (int i = 0; i < 4; ++i) {
    EXPECT_EQ(static_cast<std::uint8_t>(b[124 + i]), (crc >> (8 * i)) & 0xff) << i;
  }
}

TEST(ServerHeader, MatchesGoldenVector) {
  EXPECT_TRUE(golden::matches("server_header_v0.hex", encoded(golden_header())));
}

TEST(ServerHeader, MatchesGoldenVectorMaxGeneration) {
  auto h = golden_header();
  h.generation = kMaxGeneration;  // 2^56-1
  const auto b = encoded(h);
  const Bytes gen = bytes({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00});
  EXPECT_TRUE(std::equal(gen.begin(), gen.end(), b.begin() + 8));
  EXPECT_TRUE(golden::matches("server_header_v0_maxgen.hex", b));
  EXPECT_TRUE(decode_server_header(b));
}

TEST(ServerHeader, RoundTrip) {
  const auto h = golden_header();
  const auto b = encoded(h);
  auto d = decode_server_header(b);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->generation, h.generation);
  EXPECT_EQ(d->stored_len, h.stored_len);
  EXPECT_EQ(d->writer_id, h.writer_id);
  EXPECT_EQ(d->payload_crc, h.payload_crc);
  EXPECT_EQ(std::memcmp(d->scope_id, h.scope_id, 32), 0);
  EXPECT_EQ(std::memcmp(d->parent_hash, h.parent_hash, 16), 0);
}

// The header is immutable: EVERY single-bit flip (including the generation) is rejected.
TEST(ServerHeader, EveryBitFlipRejected) {
  const auto good = encoded(golden_header());
  for (std::size_t off = 0; off < kServerHeaderSize; ++off) {
    for (int bit = 0; bit < 8; ++bit) {
      auto b = good;
      b[off] ^= static_cast<std::byte>(1u << bit);
      EXPECT_FALSE(decode_server_header(b)) << "flip accepted at byte " << off << " bit " << bit;
    }
  }
}

TEST(ServerHeader, DecodeChecksMagicThenVersionThenCrc) {
  auto b = encoded(golden_header());
  b[4] = std::byte{9};  // bad version AND (so) bad CRC: version wins
  auto d = decode_server_header(b);
  ASSERT_FALSE(d);
  EXPECT_EQ(d.error().code, ErrorCode::Unsupported);
  b[0] = std::byte{'X'};  // bad magic wins over both
  d = decode_server_header(b);
  ASSERT_FALSE(d);
  EXPECT_EQ(d.error().code, ErrorCode::Corrupt);
}

TEST(ServerHeader, DecodeRejectsInvalidGenerationWithValidCrc) {
  for (std::uint64_t g : {std::uint64_t{0}, kMaxGeneration + 1, ~std::uint64_t{0}}) {
    auto h = golden_header();
    h.generation = g;
    auto d = decode_server_header(encoded(h));
    ASSERT_FALSE(d) << g;
    EXPECT_EQ(d.error().code, ErrorCode::Corrupt);
  }
}

TEST(ServerHeader, ValidateBoundsAndFlags) {
  ServerHeader h = golden_header();  // stored_len 0x1000
  EXPECT_TRUE(validate(h, 0x1000));
  EXPECT_FALSE(validate(h, 0xfff));  // stored_len > capacity
  h.flags = 0x0001;
  EXPECT_FALSE(validate(h, 0x1000));  // no flag bits are known in v0
  h = golden_header();
  h.stored_len = kExtentHeaderSize - 1;  // too small to hold an extent header
  EXPECT_FALSE(validate(h, 0x1000));
  h.stored_len = ~std::uint64_t{0};
  EXPECT_FALSE(validate(h, 0x1000));
}

TEST(ServerHeader, ValidatePairChecksStoredLenCoversPayloadAndTags) {
  ServerHeader s = golden_header();
  ExtentHeader e;
  e.log2_segment = 16;                 // 64 KiB segments
  e.plaintext_len = 3 * 65536 + 1;     // 4 segments -> 4 tags
  const std::uint64_t need = 64 + e.plaintext_len + 4 * 16;
  EXPECT_EQ(*min_stored_len(e), need);
  s.stored_len = need;
  EXPECT_TRUE(validate(s, e, need));
  s.stored_len = need - 1;
  EXPECT_FALSE(validate(s, e, need));
  s.stored_len = need;
  EXPECT_FALSE(validate(s, e, need - 1));  // capacity too small
  e.plaintext_len = ~std::uint64_t{0};     // overflow in the size computation
  EXPECT_FALSE(min_stored_len(e));
  s.stored_len = ~std::uint64_t{0};
  EXPECT_FALSE(validate(s, e, ~std::uint64_t{0}));
  e.plaintext_len = 0;                     // D17: empty plaintext still has one segment/tag
  EXPECT_EQ(*min_stored_len(e), 64u + 16u);
  s.stored_len = 80;
  EXPECT_TRUE(validate(s, e, 80));
  s.stored_len = 64;
  EXPECT_FALSE(validate(s, e, 80));
}

TEST(ServerHeader, RejectsUnknownVersionWithValidCrc) {
  ServerHeader h = golden_header();
  h.hdr_version = 1;
  auto d = decode_server_header(encoded(h));
  ASSERT_FALSE(d);
  EXPECT_EQ(d.error().code, ErrorCode::Unsupported);
}

TEST(StateGen, Packing) {
  const auto w = pack_state_gen(BlockState::Zombie, 0xABCDEF);
  EXPECT_EQ(state_of(w), BlockState::Zombie);
  EXPECT_EQ(generation_of(w), 0xABCDEFu);
  EXPECT_EQ(w & 0xff, 3u);
  EXPECT_FALSE(generation_valid(0));
  EXPECT_TRUE(generation_valid(1));
  EXPECT_TRUE(generation_valid(kMaxGeneration));
  EXPECT_FALSE(generation_valid(kMaxGeneration + 1));
}
