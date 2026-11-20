// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <algorithm>

#include "golden.h"
#include "proto/frame.h"
#include "test_util.h"

using namespace miracache;
using namespace miracache::proto;
using namespace miracache::testutil;

namespace {
FrameHeader test_header(int type, int flags) {
  FrameHeader h;
  h.type = static_cast<std::uint16_t>(type);
  h.flags = static_cast<std::uint16_t>(flags);
  h.credits = 3;
  h.request_id = 0x1122334455667788ULL;
  h.epoch = 0xA1B2C3D4;
  h.bundle_gen_lo = 0xBEEF;
  return h;
}
}  // namespace

TEST(Frame, HeaderLittleEndianPlacement) {
  const Bytes body = bytes({1, 2, 3, 4, 5, 6, 7, 8});
  const Bytes want = cat({hand_header(0x12, 0, 8), body});
  Bytes out(want.size());
  auto n = encode_frame(test_header(0x12, 0), body, out);
  ASSERT_TRUE(n);
  EXPECT_EQ(*n, want.size());
  EXPECT_EQ(out, want);
  EXPECT_TRUE(golden::matches("frame_header_v0.hex", std::span<const std::byte>(out).first(32)));
}

TEST(Frame, DecodeRoundTrip) {
  const Bytes frame = cat({hand_header(0x12, 5, 8), bytes({1, 2, 3, 4, 5, 6, 7, 8})});
  auto f = decode_frame(frame);
  ASSERT_TRUE(f);
  EXPECT_EQ(f->h.type, 0x12);
  EXPECT_EQ(f->h.flags, 5);
  EXPECT_EQ(f->h.credits, 3);
  EXPECT_EQ(f->h.body_len, 8u);
  EXPECT_EQ(f->h.request_id, 0x1122334455667788ULL);
  EXPECT_EQ(f->h.epoch, 0xA1B2C3D4u);
  EXPECT_EQ(f->h.bundle_gen_lo, 0xBEEFu);
  EXPECT_EQ(f->body.size(), 8u);
  Bytes out(frame.size());
  ASSERT_TRUE(encode_frame(f->h, f->body, out));
  EXPECT_EQ(out, frame);
}

TEST(Frame, VersioningTable) {
  Bytes f = cat({hand_header(0x14, 0, 0), {}});
  f.resize(32);
  auto mut = [&](std::size_t off, int v) { Bytes g = f; g[off] = static_cast<std::byte>(v); return decode_frame(g); };
  auto bad_magic = mut(0, 'X');
  ASSERT_FALSE(bad_magic);
  EXPECT_EQ(bad_magic.error().status, WireStatus::Corrupt);
  EXPECT_TRUE(bad_magic.error().close_qp);
  auto major = mut(4, 1);
  ASSERT_FALSE(major);
  EXPECT_EQ(major.error().status, WireStatus::Unsupported);
  EXPECT_TRUE(major.error().close_qp);
  EXPECT_TRUE(mut(5, 9));  // higher minor accepted
  auto flags = mut(8, 0x10);
  ASSERT_FALSE(flags);
  EXPECT_EQ(flags.error().status, WireStatus::Malformed);
  EXPECT_FALSE(flags.error().close_qp);
  EXPECT_FALSE(mut(9, 1));  // flag bit 8
  EXPECT_TRUE(mut(8, 0x0F));  // all four known flags
  EXPECT_FALSE(decode_frame(std::span<const std::byte>(f).first(31)));
}

TEST(Frame, BodyLenRules) {
  Bytes f = cat({hand_header(0x14, 0, 8), zeros(8)});
  EXPECT_TRUE(decode_frame(f));
  Bytes shorter(f.begin(), f.end() - 1);  // body_len 8 but 7 received
  auto e = decode_frame(shorter);
  ASSERT_FALSE(e);
  EXPECT_EQ(e.error().status, WireStatus::Corrupt);
  Bytes longer = f;
  longer.push_back(std::byte{0});
  EXPECT_FALSE(decode_frame(longer));
  // body_len = 8161 > 8160 even when it matches the received length
  Bytes big = cat({hand_header(0x14, 0, 8161), zeros(8161)});
  EXPECT_FALSE(decode_frame(big));
  Bytes max = cat({hand_header(0x14, 0, 8160), zeros(8160)});
  EXPECT_TRUE(decode_frame(max));
  Bytes out(8192);
  EXPECT_TRUE(encode_frame(test_header(0x14, 0), std::span<const std::byte>(max).subspan(32), out));
  EXPECT_FALSE(encode_frame(test_header(0x14, 0), std::span<const std::byte>(big).subspan(32), out));
}

TEST(Frame, UnknownOpcode) {
  EXPECT_TRUE(check_opcode(0x01));
  EXPECT_TRUE(check_opcode(0x24));
  for (int t : {0x00, 0x09, 0x0F, 0x17, 0x1F, 0x25, 0x7FFF}) {
    auto r = check_opcode(static_cast<std::uint16_t>(t));
    ASSERT_FALSE(r) << t;
    EXPECT_EQ(r.error().status, WireStatus::Unsupported);
    EXPECT_FALSE(r.error().close_qp);
  }
}

TEST(Tlv, WalkSkipAndPadding) {
  // tag 0x0001 len 3 "AAA" pad1; tag 0x0042 len 0 pad4; tag 0x0043 len 8 value; (no pad)
  const Bytes tail = cat({bytes({1, 0, 3, 0, 0xAA, 0xBB, 0xCC, 0}), bytes({0x42, 0, 0, 0, 0, 0, 0, 0}),
                          bytes({0x43, 0, 8, 0}), bytes({1, 2, 3, 4, 5, 6, 7, 8}), zeros(4)});
  TlvReader r(tail);
  auto a = r.next();
  ASSERT_TRUE(a);
  EXPECT_EQ(a->tag, 1);
  EXPECT_EQ(a->value.size(), 3u);
  EXPECT_FALSE(a->critical());
  auto b = r.next();
  ASSERT_TRUE(b);
  EXPECT_EQ(b->value.size(), 0u);
  auto c = r.next();
  ASSERT_TRUE(c);
  EXPECT_EQ(c->value.size(), 8u);
  EXPECT_TRUE(r.done());
  EXPECT_TRUE(check_tlv_tail(0, tail));
}

TEST(Tlv, IllFormed) {
  auto code = [](std::uint16_t flags, const Bytes& t) { auto r = check_tlv_tail(flags, t); return r ? WireStatus::Ok : r.error().status; };
  EXPECT_EQ(code(0, bytes({1, 0, 3, 0})), WireStatus::Malformed);                           // header only
  EXPECT_EQ(code(0, bytes({1, 0, 8, 0, 1, 2, 3, 4})), WireStatus::Malformed);              // value overruns
  EXPECT_EQ(code(0, bytes({1, 0, 3, 0, 1, 2, 3, 9})), WireStatus::Malformed);              // pad not zero
  EXPECT_EQ(code(0, bytes({1, 0, 0})), WireStatus::Malformed);                             // < 4 B
  // critical: unknown -> Unsupported; critical-flag mismatch -> Malformed
  const Bytes crit = bytes({1, 0x80, 0, 0, 0, 0, 0, 0});
  EXPECT_EQ(code(flag::CRITICAL_EXT, crit), WireStatus::Unsupported);
  EXPECT_EQ(code(0, crit), WireStatus::Malformed);
  EXPECT_EQ(code(flag::CRITICAL_EXT, bytes({1, 0, 0, 0, 0, 0, 0, 0})), WireStatus::Malformed);
  EXPECT_EQ(code(flag::CRITICAL_EXT, {}), WireStatus::Malformed);
}

TEST(Tlv, EncodePads) {
  Bytes out(16, std::byte{0xFF});
  auto n = encode_tlv(1, bytes({0xAA, 0xBB, 0xCC}), out);
  ASSERT_TRUE(n);
  EXPECT_EQ(*n, 8u);
  const Bytes want = bytes({1, 0, 3, 0, 0xAA, 0xBB, 0xCC, 0});
  EXPECT_TRUE(std::equal(want.begin(), want.end(), out.begin()));
  EXPECT_FALSE(encode_tlv(1, zeros(20), std::span<std::byte>(out).first(16)));
}
