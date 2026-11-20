// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <algorithm>
#include <array>

#include "golden.h"
#include "proto/storage_layout.h"
#include "test_util.h"
#include "util/crc32c.h"

using namespace miracache;
using namespace miracache::proto;
using namespace miracache::testutil;

namespace {

Superblock sb_msg() {
  Superblock s;
  s.format_epoch = 7;
  s.seq = 0x0102;
  s.node_id = 0x11223344;
  s.owner_pid = 0x1234;
  s.gen_hwm = 0x0A0B0C0D;
  s.bundle_gen = 9;
  s.segment_size = 1ULL << 30;
  s.n_segments = 4;
  s.clean_shutdown = 1;
  s.sg_off = 0x2000;
  s.sg_slots = 0x100;
  s.scope_off = 0x3000;
  s.scope_len = 0x400;
  s.min_block_log2 = 16;
  return s;
}

Bytes with_crc(Bytes b, std::size_t crc_off) {
  const std::uint32_t crc = crc32c(std::span<const std::byte>(b).first(crc_off));
  for (int i = 0; i < 4; ++i) b[crc_off + i] = static_cast<std::byte>((crc >> (8 * i)) & 0xff);
  return b;
}

Bytes sb_prefix() {  // hand-placed bytes 0..4091 of sb_msg()
  return cat({bytes({'M', 'I', 'R', 'A', 'S', 'B', 0, 0}),         // 0  magic
              bytes({0, 0, 0, 0}),                                 // 8  layout_version
              bytes({7, 0, 0, 0}),                                 // 12 format_epoch
              bytes({2, 1, 0, 0, 0, 0, 0, 0}),                     // 16 seq
              bytes({0x44, 0x33, 0x22, 0x11}),                     // 24 node_id
              bytes({0x34, 0x12, 0, 0}),                           // 28 owner_pid
              bytes({0x0D, 0x0C, 0x0B, 0x0A, 0, 0, 0, 0}),         // 32 gen_hwm
              bytes({9, 0, 0, 0, 0, 0, 0, 0}),                     // 40 bundle_gen
              bytes({0, 0, 0, 0x40, 0, 0, 0, 0}),                  // 48 segment_size
              bytes({4, 0, 0, 0}),                                 // 56 n_segments
              bytes({1, 28, 0, 0}),                                // 60 clean, run_log2, z
              bytes({0, 0x20, 0, 0, 0, 0, 0, 0}),                  // 64 sg_off
              bytes({0, 1, 0, 0, 0, 0, 0, 0}),                     // 72 sg_slots
              bytes({0, 0x30, 0, 0, 0, 0, 0, 0}),                  // 80 scope_off
              bytes({0, 4, 0, 0, 0, 0, 0, 0}),                     // 88 scope_len
              bytes({16}),                                         // 96 min_block_log2 (s12 C2)
              zeros(3995)});                                       // 97 z
}

SegmentMeta sm_msg() {
  SegmentMeta m;
  m.seg_id = 3;
  m.n_runs = 2;
  m.run_table_off = 0x40;
  m.hdr_table_off = 0x1000;
  m.data_off = 0x100000;
  m.format_epoch = 7;
  return m;
}
Bytes sm_prefix() {
  return cat({bytes({'M', 'I', 'R', 'M'}), bytes({0, 0}), bytes({0, 0}),  // magic, layout_version, z
              bytes({3, 0, 0, 0}), bytes({2, 0, 0, 0}),                   // seg_id, n_runs
              bytes({0x40, 0, 0, 0, 0, 0, 0, 0}),                         // run_table_off
              bytes({0, 0x10, 0, 0, 0, 0, 0, 0}),                         // hdr_table_off
              bytes({0, 0, 0x10, 0, 0, 0, 0, 0}),                         // data_off
              bytes({7, 0, 0, 0}), zeros(16)});                           // format_epoch, z
}

std::array<std::byte, kSuperblockSize> enc_sb(const Superblock& s) {
  std::array<std::byte, kSuperblockSize> a{};
  EXPECT_TRUE(encode(s, a));
  return a;
}

}  // namespace

TEST(Superblock, PlacementAndGolden) {
  const Bytes want = with_crc(cat({sb_prefix(), zeros(4)}), 4092);
  ASSERT_EQ(want.size(), kSuperblockSize);
  const auto got = enc_sb(sb_msg());
  EXPECT_TRUE(std::equal(want.begin(), want.end(), got.begin()));
  EXPECT_TRUE(golden::matches("superblock_v0.hex", got));
  auto d = decode_superblock(got);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->seq, 0x0102u);
  EXPECT_EQ(d->node_id, 0x11223344u);
  EXPECT_EQ(d->scope_len, 0x400u);
  EXPECT_EQ(d->clean_shutdown, 1);
}

TEST(Superblock, DecodeErrors) {
  const auto good = enc_sb(sb_msg());
  auto code = [&](std::size_t off, int v, bool fix) {
    Bytes b(good.begin(), good.end());
    b[off] = static_cast<std::byte>(v);
    if (fix) b = with_crc(b, 4092);
    std::array<std::byte, kSuperblockSize> a;
    std::copy(b.begin(), b.end(), a.begin());
    auto r = decode_superblock(a);
    return r ? ErrorCode::NotFound : r.error().code;  // NotFound = accepted
  };
  EXPECT_EQ(code(0, 'X', true), ErrorCode::Corrupt);
  EXPECT_EQ(code(24, 0x45, false), ErrorCode::Corrupt) << "bad CRC";
  EXPECT_EQ(code(4092, 0, false), ErrorCode::Corrupt) << "bad CRC byte";
  EXPECT_EQ(code(8, 1, true), ErrorCode::Unsupported) << "layout_version != 0 refuses to start";
  EXPECT_EQ(code(60, 2, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(61, 27, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(62, 1, true), ErrorCode::Corrupt);
  // s12 C2: byte 96 is min_block_log2: 0 (a store from before s12) or 12..28.
  EXPECT_EQ(code(96, 1, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(96, 11, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(96, 29, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(96, 0, true), ErrorCode::NotFound);
  EXPECT_EQ(code(96, 12, true), ErrorCode::NotFound);
  EXPECT_EQ(code(96, 28, true), ErrorCode::NotFound);
  EXPECT_EQ(code(97, 1, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(4091, 1, true), ErrorCode::Corrupt);
  Superblock s = sb_msg();
  std::array<std::byte, kSuperblockSize> a{};
  s.min_block_log2 = 11;
  EXPECT_FALSE(encode(s, a));
  s = sb_msg();
  s.run_log2 = 27;
  EXPECT_FALSE(encode(s, a));
  s = sb_msg();
  s.layout_version = 1;
  EXPECT_FALSE(encode(s, a));
}

TEST(Superblock, ChooseHighestValidSeq) {
  Superblock a = sb_msg(), b = sb_msg();
  a.seq = 10;
  b.seq = 11;
  auto ea = enc_sb(a), eb = enc_sb(b);
  EXPECT_EQ(choose_superblock(ea, eb)->seq, 11u);
  EXPECT_EQ(choose_superblock(eb, ea)->seq, 11u);
  auto bad = eb;
  bad[20] ^= std::byte{1};  // corrupt copy with the higher seq: the valid one wins
  EXPECT_EQ(choose_superblock(ea, bad)->seq, 10u);
  EXPECT_EQ(choose_superblock(bad, ea)->seq, 10u);
  EXPECT_FALSE(choose_superblock(bad, bad));
  b.seq = 10;
  b.node_id = 99;
  EXPECT_EQ(choose_superblock(ea, enc_sb(b))->node_id, sb_msg().node_id) << "tie: copy 0";
}

TEST(SegmentMeta, PlacementAndGolden) {
  const Bytes want = with_crc(cat({sm_prefix(), zeros(4)}), 60);
  ASSERT_EQ(want.size(), kSegmentMetaSize);
  std::array<std::byte, kSegmentMetaSize> got{};
  ASSERT_TRUE(encode(sm_msg(), got));
  EXPECT_TRUE(std::equal(want.begin(), want.end(), got.begin()));
  EXPECT_TRUE(golden::matches("segment_meta_v0.hex", got));
  auto d = decode_segment_meta(got);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->hdr_table_off, 0x1000u);
  EXPECT_EQ(d->data_off, 0x100000u);
  EXPECT_EQ(d->seg_id, 3u);
}

TEST(SegmentMeta, DecodeErrors) {
  std::array<std::byte, kSegmentMetaSize> good{};
  ASSERT_TRUE(encode(sm_msg(), good));
  auto code = [&](std::size_t off, int v, bool fix) {
    Bytes b(good.begin(), good.end());
    b[off] = static_cast<std::byte>(v);
    if (fix) b = with_crc(b, 60);
    std::array<std::byte, kSegmentMetaSize> a;
    std::copy(b.begin(), b.end(), a.begin());
    auto r = decode_segment_meta(a);
    return r ? ErrorCode::NotFound : r.error().code;
  };
  EXPECT_EQ(code(0, 'X', true), ErrorCode::Corrupt);
  EXPECT_EQ(code(8, 4, false), ErrorCode::Corrupt) << "bad CRC";
  EXPECT_EQ(code(4, 1, true), ErrorCode::Unsupported);
  EXPECT_EQ(code(6, 1, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(44, 1, true), ErrorCode::Corrupt);
  EXPECT_EQ(code(59, 1, true), ErrorCode::Corrupt);
}

TEST(RunEntry, PlacementAndGolden) {
  const Bytes want = bytes({20, 0, 0, 0, 0, 0x10, 0, 0});  // block_log2 20, n_blocks 4096
  std::array<std::byte, kRunEntrySize> got{};
  ASSERT_TRUE(encode(RunEntry{20, 4096}, got));
  EXPECT_TRUE(std::equal(want.begin(), want.end(), got.begin()));
  EXPECT_TRUE(golden::matches("run_entry_v0.hex", got));
  auto d = decode_run_entry(got);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->block_log2, 20);
  EXPECT_EQ(d->n_blocks, 4096u);
}

TEST(RunEntry, Rejects) {
  std::array<std::byte, kRunEntrySize> a{};
  EXPECT_TRUE(decode_run_entry(a));  // unformatted
  for (int v : {1, 15, 29}) {
    a = {};
    a[0] = static_cast<std::byte>(v);
    EXPECT_FALSE(decode_run_entry(a)) << v;
  }
  a = {};
  a[1] = std::byte{1};
  EXPECT_FALSE(decode_run_entry(a));
  a = {};
  a[0] = std::byte{16};
  a[5] = std::byte{0x10};
  a[4] = std::byte{1};  // n_blocks 4097
  EXPECT_FALSE(decode_run_entry(a));
  EXPECT_FALSE(encode(RunEntry{15, 1}, a));
  EXPECT_FALSE(encode(RunEntry{16, 4097}, a));
}

TEST(SlotRule, GenSlotAndHeaderOffset) {
  EXPECT_EQ(gen_slot(0, 3, 0, 0), 0u);
  EXPECT_EQ(gen_slot(2, 3, 1, 5), 7u * 4096u + 5u);
  EXPECT_EQ(header_offset(0x1000, 1, 5), 0x1000u + 4101u * 128u);
}
