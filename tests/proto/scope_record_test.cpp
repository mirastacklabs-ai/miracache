// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <algorithm>
#include <array>

#include "golden.h"
#include "proto/scope_record.h"
#include "test_util.h"
#include "util/crc32c.h"

using namespace miracache;
using namespace miracache::proto;
using namespace miracache::testutil;

namespace {

ScopeRecord rec_msg() {
  ScopeRecord r;
  r.principal_id = 0x11223344;
  r.state = kScopeOpen;
  for (int i = 0; i < 32; ++i) r.scope_id[i] = static_cast<std::uint8_t>(0x10 + i);
  r.opened_at_ms = 0x0102030405060708ULL;
  r.expires_at_ms = 0x1112131415161718ULL;
  r.last_used_ms = 0x2122232425262728ULL;
  return r;
}

Bytes with_crc(Bytes b, std::size_t crc_off) {
  const std::uint32_t crc = crc32c(std::span<const std::byte>(b).first(crc_off));
  for (int i = 0; i < 4; ++i) b[crc_off + i] = static_cast<std::byte>((crc >> (8 * i)) & 0xff);
  return b;
}

std::array<std::byte, kScopeRecordSize> enc(const ScopeRecord& r) {
  std::array<std::byte, kScopeRecordSize> a{};
  EXPECT_TRUE(encode(r, a));
  return a;
}

std::array<std::byte, kScopeRegionHeaderSize> enc_hdr(const ScopeRegionHeader& h) {
  std::array<std::byte, kScopeRegionHeaderSize> a{};
  EXPECT_TRUE(encode(h, a));
  return a;
}

}  // namespace

TEST(ScopeRecord, Layout) {
  static_assert(kScopeRecordSize == 72 && scr::crc == 68 && scr::last_used_ms == 56);
  static_assert(kScopeRegionHeaderSize == 16 && srh::n_records == 8 && srh::crc == 12);
  EXPECT_EQ(scope_region_size(kDefaultMaxScopeRecords), 301989904u);
  EXPECT_EQ(scope_record_offset(2), 16u + 144u);
}

TEST(ScopeRecord, PlacementAndGolden) {
  const Bytes want = with_crc(cat({bytes({0x44, 0x33, 0x22, 0x11}),              // 0  principal_id
                                   bytes({0, 1, 0, 0}),                          // 4  mode, state, z6
                                   ramp(32, 0x10),                               // 8  scope_id
                                   bytes({8, 7, 6, 5, 4, 3, 2, 1}),              // 40 opened_at_ms
                                   bytes({0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11}),  // 48 expires
                                   bytes({0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21}),  // 56 last_used
                                   bytes({0, 0, 0, 0}),                          // 64 z
                                   zeros(4)}),                                   // 68 crc
                              68);
  ASSERT_EQ(want.size(), kScopeRecordSize);
  const auto got = enc(rec_msg());
  EXPECT_TRUE(std::equal(want.begin(), want.end(), got.begin()));
  EXPECT_TRUE(golden::matches("scope_record_v0.hex", got));
  auto d = decode_scope_record(got);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->principal_id, 0x11223344u);
  EXPECT_EQ(d->state, kScopeOpen);
  EXPECT_EQ(d->scope_id[31], 0x2f);
  EXPECT_EQ(d->last_used_ms, 0x2122232425262728ULL);
}

TEST(ScopeRecord, DrainingRoundTrips) {
  ScopeRecord r = rec_msg();
  r.state = kScopeDraining;
  auto d = decode_scope_record(enc(r));
  ASSERT_TRUE(d);
  EXPECT_EQ(d->state, kScopeDraining);
}

TEST(ScopeRecord, FreeSlotIsAllZero) {
  std::array<std::byte, kScopeRecordSize> z{};
  auto d = decode_scope_record(z);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->state, kScopeFree);
  EXPECT_EQ(enc(*d), z);
  EXPECT_EQ(enc(ScopeRecord{}), z);
  ScopeRecord bad;  // free but with content
  bad.opened_at_ms = 1;
  EXPECT_FALSE(encode(bad, z));
  bad = ScopeRecord{};
  bad.principal_id = 5;
  EXPECT_FALSE(encode(bad, z));
}

TEST(ScopeRecord, DecodeErrors) {
  const auto good = enc(rec_msg());
  auto code = [&](std::size_t off, int v, bool fix) {
    Bytes b(good.begin(), good.end());
    b[off] = static_cast<std::byte>(v);
    if (fix) b = with_crc(b, 68);
    std::array<std::byte, kScopeRecordSize> a;
    std::copy(b.begin(), b.end(), a.begin());
    auto r = decode_scope_record(a);
    return r ? ErrorCode::NotFound : r.error().code;  // NotFound = accepted
  };
  EXPECT_EQ(code(8, 0xEE, false), ErrorCode::Corrupt) << "bad CRC";
  EXPECT_EQ(code(68, 0, false), ErrorCode::Corrupt) << "bad CRC byte";
  EXPECT_EQ(code(6, 1, true), ErrorCode::Corrupt) << "z6 lo";
  EXPECT_EQ(code(7, 1, true), ErrorCode::Corrupt) << "z6 hi";
  for (std::size_t i = 64; i < 68; ++i) EXPECT_EQ(code(i, 1, true), ErrorCode::Corrupt) << "z64+" << i;
  EXPECT_EQ(code(4, 1, true), ErrorCode::Corrupt) << "mode 1 reserved";
  EXPECT_EQ(code(4, 255, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(5, 3, true), ErrorCode::Corrupt) << "unknown state";
  EXPECT_EQ(code(5, 0, true), ErrorCode::Corrupt) << "state free with content";
  EXPECT_EQ(code(5, 2, true), ErrorCode::NotFound) << "draining is valid";
  // principal_id == 0 on a non-free slot
  Bytes b(good.begin(), good.end());
  for (int i = 0; i < 4; ++i) b[i] = std::byte{0};
  b = with_crc(b, 68);
  std::array<std::byte, kScopeRecordSize> a;
  std::copy(b.begin(), b.end(), a.begin());
  auto r = decode_scope_record(a);
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, ErrorCode::Corrupt);
}

TEST(ScopeRecord, EncodeRejects) {
  std::array<std::byte, kScopeRecordSize> a{};
  ScopeRecord r = rec_msg();
  r.principal_id = 0;
  EXPECT_FALSE(encode(r, a));
  r = rec_msg();
  r.mode = 1;
  EXPECT_FALSE(encode(r, a));
  r = rec_msg();
  r.state = 3;
  EXPECT_FALSE(encode(r, a));
}

TEST(ScopeRegionHeader, PlacementAndGolden) {
  const Bytes want = with_crc(cat({bytes({'M', 'I', 'R', 'S'}),     // 0  magic
                                   bytes({0, 0}),                   // 4  layout_version
                                   bytes({72, 0}),                  // 6  record_size
                                   bytes({0, 0, 0x40, 0}),          // 8  n_records = 4 Mi
                                   zeros(4)}),                      // 12 crc
                              12);
  ASSERT_EQ(want.size(), kScopeRegionHeaderSize);
  ScopeRegionHeader h;
  h.n_records = kDefaultMaxScopeRecords;
  const auto got = enc_hdr(h);
  EXPECT_TRUE(std::equal(want.begin(), want.end(), got.begin()));
  EXPECT_TRUE(golden::matches("scope_region_header_v0.hex", got));
  auto d = decode_scope_region_header(got);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->n_records, 4194304u);
  EXPECT_EQ(d->record_size, 72);
  EXPECT_TRUE(scope_region_fits(*d, scope_region_size(4194304)));
  EXPECT_FALSE(scope_region_fits(*d, scope_region_size(4194304) - 1));
}

TEST(ScopeRegionHeader, DecodeErrors) {
  ScopeRegionHeader h;
  h.n_records = 100;
  const auto good = enc_hdr(h);
  auto code = [&](std::size_t off, int v, bool fix) {
    Bytes b(good.begin(), good.end());
    b[off] = static_cast<std::byte>(v);
    if (fix) b = with_crc(b, 12);
    std::array<std::byte, kScopeRegionHeaderSize> a;
    std::copy(b.begin(), b.end(), a.begin());
    auto r = decode_scope_region_header(a);
    return r ? ErrorCode::NotFound : r.error().code;
  };
  EXPECT_EQ(code(0, 'X', true), ErrorCode::Corrupt) << "magic";
  EXPECT_EQ(code(8, 7, false), ErrorCode::Corrupt) << "bad CRC";
  EXPECT_EQ(code(4, 1, true), ErrorCode::Unsupported) << "layout_version";
  EXPECT_EQ(code(6, 64, true), ErrorCode::Corrupt) << "record_size";
  EXPECT_EQ(code(8, 0, true), ErrorCode::Corrupt) << "n_records 0";
  ScopeRegionHeader bad = h;
  std::array<std::byte, kScopeRegionHeaderSize> a{};
  bad.n_records = 0;
  EXPECT_FALSE(encode(bad, a));
  bad = h;
  bad.record_size = 80;
  EXPECT_FALSE(encode(bad, a));
  bad = h;
  bad.layout_version = 1;
  EXPECT_FALSE(encode(bad, a));
}
