// SPDX-License-Identifier: Apache-2.0
// Run B message codecs: hand-placed byte layouts first, then the golden files, then the
// boundary vectors and the table-driven error mutations (plan section 4).
#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "golden.h"
#include "proto/messages.h"
#include "proto/state_gen.h"
#include "test_util.h"

using namespace miracache;
using namespace miracache::proto;
using namespace miracache::testutil;

namespace {

FrameHeader test_header(Op op) {
  FrameHeader h = header_for(op, 0x1122334455667788ULL);
  h.credits = 3;
  h.epoch = 0xA1B2C3D4;
  h.bundle_gen_lo = 0xBEEF;
  return h;
}

template <typename M, typename Enc>
Bytes frame_of(Op op, const M& m, Enc enc) {
  Bytes body(kMaxBodyLen);
  auto n = enc(m, body);
  EXPECT_TRUE(n);
  if (!n) return {};
  body.resize(*n);
  Bytes out(kFrameHeaderSize + body.size());
  EXPECT_TRUE(encode_frame(test_header(op), body, out));
  return out;
}

WireStatus run(const Bytes& wire) {
  auto f = decode_frame(wire);
  if (!f) return f.error().status;
  if (auto o = check_opcode(f->h.type); !o) return o.error().status;
  const auto& h = f->h;
  auto st = [](const auto& r) { return r ? WireStatus::Ok : r.error().status; };
  switch (static_cast<Op>(h.type)) {
    case Op::HELLO: return st(decode_hello(h, f->body));
    case Op::HELLO_ACK: return st(decode_hello_ack(h, f->body));
    case Op::SEG_TABLE: return st(decode_seg_table(h, f->body));
    case Op::PING: return st(decode_ping(h, f->body));
    case Op::PONG: return st(decode_pong(h, f->body));
    case Op::GOAWAY: return st(decode_goaway(h, f->body));
    case Op::STATS: return st(decode_stats(h, f->body));
    case Op::STATS_ACK: return st(decode_stats_ack(h, f->body));
    case Op::LOOKUP: return st(decode_lookup(h, f->body));
    case Op::LOOKUP_ACK: return st(decode_lookup_ack(h, f->body));
    case Op::PUT_BEGIN: return st(decode_put_begin(h, f->body));
    case Op::PUT_BEGIN_ACK: return st(decode_put_begin_ack(h, f->body));
    default: return WireStatus::Ok;  // Run A ops
  }
}

Frame parse(const Bytes& wire) {
  auto f = decode_frame(wire);
  EXPECT_TRUE(f);
  return f ? *f : Frame{};
}

Bytes le(std::uint64_t v, int n) {
  Bytes b;
  for (int i = 0; i < n; ++i) b.push_back(static_cast<std::byte>((v >> (8 * i)) & 0xff));
  return b;
}

// ---- HELLO ----
Bytes hello_hand(int type, int flags) {
  return cat({hand_header(type, flags, 48),
              bytes({0, 0, 0, 1, 16, 8, 2, 1}),  // major_min, major_max, minor, class, ird, ord, rail, proto
              bytes({1, 2, 3, 4, 5, 6, 7, 8}),   // features
              bytes({0x0D, 0x0C, 0x0B, 0x0A}),   // node_id
              bytes({0, 0x10, 0, 0}),            // mtu 4096
              ramp(16, 0xA0),                    // conn_id
              bytes({0, 0x20, 0, 0}),            // max_frame 8192
              zeros(4)});                        // z
}
Hello hello_msg() {
  Hello m;
  m.cls = 1; m.ird = 16; m.ord = 8; m.rail = 2; m.proto = 1;
  m.features = 0x0807060504030201ULL;
  m.node_id = 0x0A0B0C0D;
  m.mtu = 4096;
  for (int i = 0; i < 16; ++i) m.conn_id[i] = static_cast<std::uint8_t>(0xA0 + i);
  return m;
}

// ---- SEG_TABLE ----
Bytes seg_hand2() {
  return cat({hand_header(0x03, 0, 120),
              bytes({2, 0}), bytes({2, 1}), bytes({4, 3, 2, 1}),       // n, n_rails, local_rail, table_gen
              bytes({0, 0x10, 0, 0, 0, 0, 0, 0}),                      // sg_base 0x1000
              bytes({0, 0x20, 0, 0, 0, 0, 0, 0}),                      // sg_slots 0x2000
              bytes({0x11, 0, 0, 0}), bytes({0x22, 0, 0, 0}), zeros(8),  // sg_rkey[4]
              bytes({7, 0, 0, 0}), bytes({0, 0, 0, 0}),                // seg 7, flags 0
              bytes({0, 0, 0x10, 0, 0, 0, 0, 0}), bytes({0, 0, 0x20, 0, 0, 0, 0, 0}),
              bytes({0x31, 0, 0, 0}), bytes({0x32, 0, 0, 0}), zeros(8),
              bytes({9, 0, 0, 0}), bytes({1, 0, 0, 0}),                // seg 9, REMOVED
              bytes({0, 0, 0x30, 0, 0, 0, 0, 0}), bytes({0, 0, 0x40, 0, 0, 0, 0, 0}),
              bytes({0x41, 0, 0, 0}), bytes({0x42, 0, 0, 0}), zeros(8)});
}
SegTable seg_msg2() {
  SegTable m;
  m.n = 2; m.n_rails = 2; m.local_rail = 1; m.table_gen = 0x01020304;
  m.sg_base = 0x1000; m.sg_slots = 0x2000; m.sg_rkey[0] = 0x11; m.sg_rkey[1] = 0x22;
  m.e[0] = {7, 0, 0x100000, 0x200000, {0x31, 0x32, 0, 0}};
  m.e[1] = {9, 1, 0x300000, 0x400000, {0x41, 0x42, 0, 0}};
  return m;
}

// ---- LOOKUP ----
Bytes lookup_hand2() {
  return cat({hand_header(0x10, 0, 104), ramp(32, 0), bytes({1, 0}), bytes({2, 0}), zeros(4),
              ramp(32, 0x40), ramp(32, 0x80)});
}
Lookup lookup_msg2() {
  Lookup m;
  for (int i = 0; i < 32; ++i) {
    m.scope_id[i] = static_cast<std::uint8_t>(i);
    m.key_hash[0][i] = static_cast<std::uint8_t>(0x40 + i);
    m.key_hash[1][i] = static_cast<std::uint8_t>(0x80 + i);
  }
  m.flags = 1;
  m.n = 2;
  return m;
}

// ---- LOOKUP_ACK ----
Bytes lookup_ack_hand2() {
  return cat({hand_header(0x11, 1, 96), bytes({0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}),
              bytes({0x10, 0x27, 0, 0}), bytes({2, 0}), bytes({0, 0}),
              bytes({1, 0, 0, 0}), bytes({5, 0, 0, 0}),                // HIT, z[3], seg_id 5
              bytes({0, 0x10, 0, 0, 0, 0, 0, 0}),                      // offset
              bytes({0, 0x20, 0, 0, 0, 0, 0, 0}),                      // stored_len
              bytes({5, 4, 3, 2, 1, 0, 0, 0}),                         // gen
              bytes({0x77, 0, 0, 0, 0, 0, 0, 0}),                      // gen_slot
              zeros(40)});                                             // MISS: all zero (D5)
}
LookupAck lookup_ack_msg2() {
  LookupAck m;
  m.lease_id = 0x1122334455667788ULL; m.ttl_ms = 10000; m.n = 2;
  m.e[0] = {1, 5, 0x1000, 0x2000, 0x0102030405ULL, 0x77};
  return m;
}
Bytes n128_ack_entry(int i) {
  const std::uint64_t gen = (i == 0) ? kMaxGeneration : static_cast<std::uint64_t>(i + 1);
  return cat({bytes({1, 0, 0, 0}), le(i, 4), le(static_cast<std::uint64_t>(i) * 0x100, 8),
              le(0x2000 + i, 8), le(gen, 8), le(static_cast<std::uint64_t>(i) * 3, 8)});
}

// ---- PUT_BEGIN / PUT_BEGIN_ACK ----
Bytes put_begin_hand2() {
  return cat({hand_header(0x20, 0, 168), ramp(32, 0x10), bytes({2, 0}), zeros(6),
              ramp(32, 0x20), ramp(16, 0x60), bytes({0, 0, 0, 0, 0, 0, 0, 0}), bytes({0, 0, 1, 0, 0, 0, 0, 0}),
              ramp(32, 0x30), ramp(16, 0x70), bytes({1, 0, 0, 0, 0, 0, 0, 0}), bytes({0, 0, 2, 0, 0, 0, 0, 0})});
}
PutBegin put_begin_msg2() {
  PutBegin m;
  for (int i = 0; i < 32; ++i) m.scope_id[i] = static_cast<std::uint8_t>(0x10 + i);
  m.n = 2;
  for (int k = 0; k < 2; ++k) {
    for (int i = 0; i < 32; ++i) m.e[k].key_hash[i] = static_cast<std::uint8_t>(0x20 + 0x10 * k + i);
    for (int i = 0; i < 16; ++i) m.e[k].parent_hash[i] = static_cast<std::uint8_t>(0x60 + 0x10 * k + i);
    m.e[k].chain_pos = static_cast<std::uint64_t>(k);
    m.e[k].stored_len = 0x10000ULL * (k + 1);
  }
  return m;
}

Bytes ack_hand3() {
  return cat({hand_header(0x21, 1, 160),
              bytes({0x22, 0x11, 0, 0, 0, 0, 0, 0}),                    // put_id
              bytes({0}), bytes({2}), bytes({3, 0}), bytes({0, 0, 0, 0}),  // status OK, n_mr 2, n 3, retry
              bytes({0, 0x10, 0, 0, 0x00, 0x7f, 0, 0}), bytes({0, 0, 0x10, 0, 0, 0, 0, 0}),  // mr0 addr 0x7f000000 1000, len
              bytes({0xDD, 0xCC, 0xBB, 0xAA}), zeros(4),
              bytes({0, 0, 0x20, 0, 0x00, 0x7f, 0, 0}), bytes({0, 0, 8, 0, 0, 0, 0, 0}),     // mr1
              bytes({0x44, 0x33, 0x22, 0x11}), zeros(4),
              zeros(48),                                                // mr2, mr3 unused
              bytes({1, 0}), zeros(6), zeros(8),                        // ACCEPT mr0 offset 0
              bytes({0, 0}), zeros(6), zeros(8),                        // SKIP
              bytes({1, 1}), zeros(6), bytes({0, 0x40, 0, 0, 0, 0, 0, 0})});  // ACCEPT mr1 offset 0x4000
}
PutBeginAck ack_msg3() {
  PutBeginAck m;
  m.put_id = 0x1122; m.status = 0; m.n_mr = 2; m.n = 3;
  m.mr[0] = {0x7f0000001000ULL, 0x100000, 0xAABBCCDD};
  m.mr[1] = {0x7f0000200000ULL, 0x80000, 0x11223344};
  m.e[0] = {1, 0, 0};
  m.e[1] = {0, 0, 0};
  m.e[2] = {1, 1, 0x4000};
  return m;
}

}  // namespace

TEST(MessagesB, HelloPlacementAndGolden) {
  const Bytes got = frame_of(Op::HELLO, hello_msg(), encode_hello);
  EXPECT_EQ(got, hello_hand(0x01, 0));
  EXPECT_TRUE(golden::matches("hello_v0.hex", got));
  auto d = decode_hello(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->node_id, 0x0A0B0C0Du);
  EXPECT_EQ(d->features, 0x0807060504030201ULL);
  EXPECT_EQ(d->conn_id[15], 0xAF);
  EXPECT_EQ(d->max_frame, 8192u);
}

TEST(MessagesB, HelloAckPlacementAndGolden) {
  const Bytes got = frame_of(Op::HELLO_ACK, hello_msg(), encode_hello_ack);
  EXPECT_EQ(got, hello_hand(0x02, 1));
  EXPECT_TRUE(golden::matches("hello_ack_v0.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
}

// H02: the boot nonce is a non-critical TLV behind the fixed 48 B (tag 0x0002, u64 LE, padded to 16 B). The old frame
// (no TLV) decodes with no nonce; the new one decodes with it, and its tail passes the generic TLV rule an older peer
// applies (unknown non-critical tag skipped, CRITICAL_EXT clear).
TEST(MessagesB, HelloAckBootNonceTlvOldAndNewFrames) {
  const Bytes old = golden::load("hello_ack_v0.hex");
  auto d0 = decode_hello_ack(parse(old).h, parse(old).body);
  ASSERT_TRUE(d0);
  EXPECT_FALSE(find_boot_nonce(d0->tlvs).has_value());

  HelloAck m = hello_msg();
  std::array<std::byte, kBootNonceTlvSize> t{};
  auto n = encode_boot_nonce_tlv(0x8877665544332211ULL, t);
  ASSERT_TRUE(n);
  EXPECT_EQ(*n, kBootNonceTlvSize);
  m.tlvs = std::span<const std::byte>(t.data(), *n);
  const Bytes got = frame_of(Op::HELLO_ACK, m, encode_hello_ack);
  ASSERT_EQ(got.size(), kFrameHeaderSize + kHelloSize + kBootNonceTlvSize);
  EXPECT_TRUE(golden::matches("hello_ack_v0_boot_nonce.hex", got));
  EXPECT_EQ(got[12], std::byte{0x40}) << "body_len 64";
  EXPECT_EQ(run(got), WireStatus::Ok);
  const Frame f = parse(got);
  EXPECT_EQ(f.h.flags & flag::CRITICAL_EXT, 0);
  auto d1 = decode_hello_ack(f.h, f.body);
  ASSERT_TRUE(d1);
  EXPECT_EQ(d1->node_id, 0x0A0B0C0Du);
  ASSERT_TRUE(find_boot_nonce(d1->tlvs).has_value());
  EXPECT_EQ(*find_boot_nonce(d1->tlvs), 0x8877665544332211ULL);
  EXPECT_TRUE(check_tlv_tail(f.h.flags, f.body.subspan(kHelloSize)));
  // A boot-nonce entry of the wrong length is no nonce (skipped as any unknown entry).
  std::array<std::byte, 4> four{};
  std::array<std::byte, 8> bad{};
  ASSERT_TRUE(encode_tlv(kTlvTagBootNonce, four, bad));
  EXPECT_FALSE(find_boot_nonce(bad).has_value());
}

// Review s9 K03: the max-stored-block TLV (tag 0x0003, u64 LE, 16 B with padding) after the boot nonce. The old frame
// and the boot-nonce-only frame have none (unknown); the new frame passes the generic TLV rule an older peer applies;
// 0 and a wrong length are unknown too.
TEST(MessagesB, HelloAckMaxStoredBlockTlvOldAndNewFrames) {
  for (const char* g : {"hello_ack_v0.hex", "hello_ack_v0_boot_nonce.hex"}) {
    const Bytes old = golden::load(g);
    auto d0 = decode_hello_ack(parse(old).h, parse(old).body);
    ASSERT_TRUE(d0) << g;
    EXPECT_FALSE(find_max_stored_block(d0->tlvs).has_value()) << g;
  }
  HelloAck m = hello_msg();
  std::array<std::byte, kBootNonceTlvSize + kMaxStoredBlockTlvSize> t{};
  auto n1 = encode_boot_nonce_tlv(0x8877665544332211ULL, std::span<std::byte>(t).first(kBootNonceTlvSize));
  ASSERT_TRUE(n1);
  auto n2 = encode_max_stored_block_tlv(8u << 20, std::span<std::byte>(t).subspan(*n1));
  ASSERT_TRUE(n2);
  EXPECT_EQ(*n2, kMaxStoredBlockTlvSize);
  m.tlvs = std::span<const std::byte>(t.data(), *n1 + *n2);
  const Bytes got = frame_of(Op::HELLO_ACK, m, encode_hello_ack);
  ASSERT_EQ(got.size(), kFrameHeaderSize + kHelloSize + kBootNonceTlvSize + kMaxStoredBlockTlvSize);
  EXPECT_TRUE(golden::matches("hello_ack_v0_boot_nonce_max_block.hex", got));
  EXPECT_EQ(got[12], std::byte{0x50}) << "body_len 80";
  // Byte placement: tag 0x0003 LE, len 8, value 0x800000 LE, 4 zero pad bytes.
  const std::size_t at = kFrameHeaderSize + kHelloSize + kBootNonceTlvSize;
  EXPECT_EQ(got[at], std::byte{0x03});
  EXPECT_EQ(got[at + 1], std::byte{0x00});
  EXPECT_EQ(got[at + 2], std::byte{0x08});
  EXPECT_EQ(got[at + 6], std::byte{0x80});
  EXPECT_EQ(run(got), WireStatus::Ok);
  const Frame f = parse(got);
  EXPECT_EQ(f.h.flags & flag::CRITICAL_EXT, 0);
  auto d1 = decode_hello_ack(f.h, f.body);
  ASSERT_TRUE(d1);
  ASSERT_TRUE(find_max_stored_block(d1->tlvs).has_value());
  EXPECT_EQ(*find_max_stored_block(d1->tlvs), 8u << 20);
  EXPECT_EQ(find_boot_nonce(d1->tlvs), 0x8877665544332211ULL);  // the nonce is still found in front of it
  EXPECT_TRUE(check_tlv_tail(f.h.flags, f.body.subspan(kHelloSize)));
  // Zero and a wrong length mean unknown.
  std::array<std::byte, kMaxStoredBlockTlvSize> zero{};
  ASSERT_TRUE(encode_max_stored_block_tlv(0, zero));
  EXPECT_FALSE(find_max_stored_block(zero).has_value());
  std::array<std::byte, 4> four{};
  std::array<std::byte, 8> bad{};
  ASSERT_TRUE(encode_tlv(kTlvTagMaxStoredBlock, four, bad));
  EXPECT_FALSE(find_max_stored_block(bad).has_value());
}

// Review s9 F5: the hostname TLV (tag 0x0004, 1..255 printable bytes, padded to 8 B) after the boot nonce and the max
// stored block. Old frames have none (unknown); the new frame passes the generic TLV rule an older peer applies; an empty,
// too long or non-printable name is refused by the encoder and read as unknown by the finder.
TEST(MessagesB, HelloAckHostnameTlvOldAndNewFrames) {
  for (const char* g : {"hello_ack_v0.hex", "hello_ack_v0_boot_nonce.hex", "hello_ack_v0_boot_nonce_max_block.hex"}) {
    const Bytes old = golden::load(g);
    auto d0 = decode_hello_ack(parse(old).h, parse(old).body);
    ASSERT_TRUE(d0) << g;
    EXPECT_FALSE(find_hostname(d0->tlvs).has_value()) << g;
  }
  HelloAck m = hello_msg();
  std::array<std::byte, kBootNonceTlvSize + kMaxStoredBlockTlvSize + kMaxHostnameTlvSize> t{};
  auto n1 = encode_boot_nonce_tlv(0x8877665544332211ULL, std::span<std::byte>(t).first(kBootNonceTlvSize));
  ASSERT_TRUE(n1);
  auto n2 = encode_max_stored_block_tlv(8u << 20, std::span<std::byte>(t).subspan(*n1));
  ASSERT_TRUE(n2);
  auto n3 = encode_hostname_tlv("mira-node-01.lab", std::span<std::byte>(t).subspan(*n1 + *n2));
  ASSERT_TRUE(n3);
  EXPECT_EQ(*n3, 24u) << "4 B header + 16 B name";
  m.tlvs = std::span<const std::byte>(t.data(), *n1 + *n2 + *n3);
  const Bytes got = frame_of(Op::HELLO_ACK, m, encode_hello_ack);
  EXPECT_TRUE(golden::matches("hello_ack_v0_boot_nonce_max_block_hostname.hex", got));
  // Byte placement: tag 0x0004 LE, len 16, then the name.
  const std::size_t at = kFrameHeaderSize + kHelloSize + kBootNonceTlvSize + kMaxStoredBlockTlvSize;
  EXPECT_EQ(got[at], std::byte{0x04});
  EXPECT_EQ(got[at + 1], std::byte{0x00});
  EXPECT_EQ(got[at + 2], std::byte{0x10});
  EXPECT_EQ(got[at + 3], std::byte{0x00});
  EXPECT_EQ(got[at + 4], std::byte{'m'});
  EXPECT_EQ(got[at + 19], std::byte{'b'});
  EXPECT_EQ(run(got), WireStatus::Ok);
  const Frame f = parse(got);
  EXPECT_EQ(f.h.flags & flag::CRITICAL_EXT, 0);
  auto d1 = decode_hello_ack(f.h, f.body);
  ASSERT_TRUE(d1);
  ASSERT_TRUE(find_hostname(d1->tlvs).has_value());
  EXPECT_EQ(*find_hostname(d1->tlvs), "mira-node-01.lab");
  EXPECT_EQ(find_max_stored_block(d1->tlvs), 8u << 20);  // the earlier TLVs are still found
  EXPECT_EQ(find_boot_nonce(d1->tlvs), 0x8877665544332211ULL);
  EXPECT_TRUE(check_tlv_tail(f.h.flags, f.body.subspan(kHelloSize)));
}

TEST(MessagesB, HostnameTlvBoundsAndInvalidBytes) {
  std::array<std::byte, kMaxHostnameTlvSize + 8> out{};
  // The encoder refuses what the finder would not accept.
  EXPECT_FALSE(encode_hostname_tlv("", out));
  EXPECT_FALSE(encode_hostname_tlv(std::string(kMaxHostnameLen + 1, 'a'), out));
  EXPECT_FALSE(encode_hostname_tlv("has space", out));
  EXPECT_FALSE(encode_hostname_tlv(std::string("nul\0byte", 8), out));
  EXPECT_FALSE(encode_hostname_tlv("caf\xc3\xa9", out));
  EXPECT_FALSE(encode_hostname_tlv("tab\there", out));
  // The largest name fits in kMaxHostnameTlvSize and round-trips.
  const std::string longest(kMaxHostnameLen, 'h');
  auto n = encode_hostname_tlv(longest, out);
  ASSERT_TRUE(n);
  EXPECT_EQ(*n, kMaxHostnameTlvSize);
  EXPECT_EQ(find_hostname(std::span<const std::byte>(out.data(), *n)), longest);
  // A hand-made TLV with a bad length or bad bytes reads as unknown (the frame itself stays valid: non-critical).
  auto hand = [](std::string_view v) {
    std::array<std::byte, 320> b{};
    auto r = encode_tlv(kTlvTagHostname, std::as_bytes(std::span<const char>(v.data(), v.size())), b);
    EXPECT_TRUE(r);
    return std::pair{b, *r};
  };
  for (std::string_view bad : {std::string_view(""), std::string_view("a b"), std::string_view("a\x7f"), std::string_view("a\0b", 3),
                               std::string_view("\xff\xfe")}) {
    auto [b, len] = hand(bad);
    EXPECT_FALSE(find_hostname(std::span<const std::byte>(b.data(), len)).has_value());
  }
  const std::string too_long(300, 'x');
  auto [b2, len2] = hand(too_long);
  EXPECT_FALSE(find_hostname(std::span<const std::byte>(b2.data(), len2)).has_value());
  // Absent and truncated tails: unknown.
  EXPECT_FALSE(find_hostname({}).has_value());
  std::array<std::byte, 8> trunc{};
  trunc[0] = std::byte{0x04};
  trunc[2] = std::byte{0x40};  // declares 64 B in an 8 B tail
  EXPECT_FALSE(find_hostname(trunc).has_value());
}

TEST(MessagesB, SegTablePlacementAndGolden) {
  const Bytes got = frame_of(Op::SEG_TABLE, seg_msg2(), encode_seg_table);
  EXPECT_EQ(got, seg_hand2());
  EXPECT_TRUE(golden::matches("seg_table_v0.hex", got));
  auto d = decode_seg_table(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->n, 2);
  EXPECT_EQ(d->e[1].flags, 1u);
  EXPECT_EQ(d->e[1].rkey[1], 0x42u);
  EXPECT_EQ(d->sg_rkey[1], 0x22u);
}

TEST(MessagesB, SegTableN200Golden) {
  SegTable m = seg_msg2();
  m.n = 200;
  Bytes want = cat({hand_header(0x03, 0, 40 + 200 * 40), bytes({200, 0}), bytes({2, 1}), bytes({4, 3, 2, 1}),
                    bytes({0, 0x10, 0, 0, 0, 0, 0, 0}), bytes({0, 0x20, 0, 0, 0, 0, 0, 0}),
                    bytes({0x11, 0, 0, 0}), bytes({0x22, 0, 0, 0}), zeros(8)});
  for (int i = 0; i < 200; ++i) {
    m.e[i] = {static_cast<std::uint32_t>(i), static_cast<std::uint32_t>(i & 1), 0x1000ULL * i, 0x800ULL + i,
              {static_cast<std::uint32_t>(i), 1u, 0u, 0u}};
    const Bytes ent = cat({le(i, 4), le(i & 1, 4), le(0x1000ULL * i, 8), le(0x800 + i, 8), le(i, 4), le(1, 4), zeros(8)});
    want.insert(want.end(), ent.begin(), ent.end());
  }
  ASSERT_EQ(want.size(), 32u + 8040u);
  const Bytes got = frame_of(Op::SEG_TABLE, m, encode_seg_table);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("seg_table_v0_n200.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
  m.n = 201;
  Bytes tmp(kMaxBodyLen);
  EXPECT_FALSE(encode_seg_table(m, tmp));
}

TEST(MessagesB, PingPongGoawayStatsGolden) {
  const Bytes ts = bytes({8, 7, 6, 5, 4, 3, 2, 1});
  Ping p; p.timestamp_ns = 0x0102030405060708ULL;
  Bytes got = frame_of(Op::PING, p, encode_ping);
  EXPECT_EQ(got, cat({hand_header(0x04, 0, 8), ts}));
  EXPECT_TRUE(golden::matches("ping_v0.hex", got));
  got = frame_of(Op::PONG, p, encode_pong);
  EXPECT_EQ(got, cat({hand_header(0x05, 1, 8), ts}));
  EXPECT_TRUE(golden::matches("pong_v0.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);

  Goaway g; g.reason = 2; g.drain_ms = 30000;
  got = frame_of(Op::GOAWAY, g, encode_goaway);
  EXPECT_EQ(got, cat({hand_header(0x06, 0, 8), bytes({2, 0, 0, 0}), bytes({0x30, 0x75, 0, 0})}));
  EXPECT_TRUE(golden::matches("goaway_v0.hex", got));

  Stats s; s.selector = 0x01020304;
  got = frame_of(Op::STATS, s, encode_stats);
  EXPECT_EQ(got, cat({hand_header(0x07, 0, 8), bytes({4, 3, 2, 1}), zeros(4)}));
  EXPECT_TRUE(golden::matches("stats_v0.hex", got));

  // STATS_ACK carries a non-critical counter TLV: tag 0x0010, len 8, value 42, padded 12 -> 16.
  const Bytes tlv = bytes({0x10, 0, 8, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});
  StatsAck a; a.selector = 0x01020304; a.tlvs = tlv;
  got = frame_of(Op::STATS_ACK, a, encode_stats_ack);
  EXPECT_EQ(got, cat({hand_header(0x08, 1, 24), bytes({4, 3, 2, 1}), zeros(4), tlv}));
  EXPECT_TRUE(golden::matches("stats_ack_v0.hex", got));
  auto d = decode_stats_ack(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->selector, 0x01020304u);
  EXPECT_EQ(d->tlvs.size(), 16u);
}

TEST(MessagesB, LookupPlacementAndGolden) {
  const Bytes got = frame_of(Op::LOOKUP, lookup_msg2(), encode_lookup);
  EXPECT_EQ(got, lookup_hand2());
  EXPECT_TRUE(golden::matches("lookup_v0.hex", got));
  auto d = decode_lookup(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->n, 2);
  EXPECT_EQ(d->flags, 1);
  EXPECT_EQ(d->key_hash[1][31], 0x9F);
}

TEST(MessagesB, LookupN128Golden) {
  Lookup m;
  m.n = 128;
  Bytes want = cat({hand_header(0x10, 0, 40 + 128 * 32), zeros(32), bytes({0, 0}), bytes({128, 0}), zeros(4)});
  for (int i = 0; i < 128; ++i) {
    for (int j = 0; j < 32; ++j) m.key_hash[i][j] = static_cast<std::uint8_t>(i + j);
    const Bytes k = ramp(32, i);
    want.insert(want.end(), k.begin(), k.end());
  }
  const Bytes got = frame_of(Op::LOOKUP, m, encode_lookup);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("lookup_v0_n128.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
  m.n = 129;
  Bytes tmp(kMaxBodyLen);
  EXPECT_FALSE(encode_lookup(m, tmp));
}

TEST(MessagesB, LookupAckPlacementAndGolden) {
  const Bytes got = frame_of(Op::LOOKUP_ACK, lookup_ack_msg2(), encode_lookup_ack);
  EXPECT_EQ(got, lookup_ack_hand2());
  EXPECT_TRUE(golden::matches("lookup_ack_v0.hex", got));
  auto d = decode_lookup_ack(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->lease_id, 0x1122334455667788ULL);
  EXPECT_EQ(d->e[0].gen, 0x0102030405ULL);
  EXPECT_EQ(d->e[0].gen_slot, 0x77u);
  EXPECT_EQ(d->e[1].status, 0);
}

TEST(MessagesB, LookupAckMaxGenGolden) {
  LookupAck m;
  m.n = 1;
  m.e[0] = {1, 1, 0, 1, kMaxGeneration, 0};
  const Bytes want = cat({hand_header(0x11, 1, 56), zeros(8), zeros(4), bytes({1, 0}), zeros(2),
                          bytes({1, 0, 0, 0}), bytes({1, 0, 0, 0}), zeros(8), bytes({1, 0, 0, 0, 0, 0, 0, 0}),
                          bytes({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0}), zeros(8)});
  const Bytes got = frame_of(Op::LOOKUP_ACK, m, encode_lookup_ack);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("lookup_ack_v0_maxgen.hex", got));
}

TEST(MessagesB, LookupAckN128Golden) {
  LookupAck m;
  m.n = 128;
  m.ttl_ms = 500;
  Bytes want = cat({hand_header(0x11, 1, 16 + 128 * 40), zeros(8), bytes({0xF4, 1, 0, 0}), bytes({128, 0}), zeros(2)});
  for (int i = 0; i < 128; ++i) {
    m.e[i] = {1, static_cast<std::uint32_t>(i), static_cast<std::uint64_t>(i) * 0x100, 0x2000u + i,
              i == 0 ? kMaxGeneration : static_cast<std::uint64_t>(i + 1), static_cast<std::uint64_t>(i) * 3};
    const Bytes e = n128_ack_entry(i);
    want.insert(want.end(), e.begin(), e.end());
  }
  const Bytes got = frame_of(Op::LOOKUP_ACK, m, encode_lookup_ack);
  ASSERT_EQ(got.size(), 5168u);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("lookup_ack_v0_n128.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
}

TEST(MessagesB, LookupAckRules) {
  Bytes tmp(kMaxBodyLen);
  LookupAck m = lookup_ack_msg2();
  m.e[0].gen = 0;
  EXPECT_FALSE(encode_lookup_ack(m, tmp)) << "HIT gen 0";
  m.e[0].gen = kMaxGeneration + 1;
  EXPECT_FALSE(encode_lookup_ack(m, tmp)) << "gen top byte";
  m = lookup_ack_msg2();
  m.e[1].seg_id = 1;
  EXPECT_FALSE(encode_lookup_ack(m, tmp)) << "MISS not zero";
  m = lookup_ack_msg2();
  m.n = 0;
  EXPECT_FALSE(encode_lookup_ack(m, tmp));
  m.n = 129;
  EXPECT_FALSE(encode_lookup_ack(m, tmp));
}

TEST(MessagesB, PutBeginPlacementAndGolden) {
  const Bytes got = frame_of(Op::PUT_BEGIN, put_begin_msg2(), encode_put_begin);
  EXPECT_EQ(got, put_begin_hand2());
  EXPECT_TRUE(golden::matches("put_begin_v0.hex", got));
  auto d = decode_put_begin(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->e[1].stored_len, 0x20000u);
  EXPECT_EQ(d->e[1].parent_hash[0], 0x70);
}

TEST(MessagesB, PutBeginN64Golden) {
  PutBegin m;
  m.n = 64;
  Bytes want = cat({hand_header(0x20, 0, 40 + 64 * 64), zeros(32), bytes({64, 0}), zeros(6)});
  for (int i = 0; i < 64; ++i) {
    for (int j = 0; j < 32; ++j) m.e[i].key_hash[j] = static_cast<std::uint8_t>(i + j);
    for (int j = 0; j < 16; ++j) m.e[i].parent_hash[j] = static_cast<std::uint8_t>(0x80 + i + j);
    m.e[i].chain_pos = static_cast<std::uint64_t>(i);
    m.e[i].stored_len = 0x1000u + i;
    const Bytes e = cat({ramp(32, i), ramp(16, 0x80 + i), le(i, 8), le(0x1000 + i, 8)});
    want.insert(want.end(), e.begin(), e.end());
  }
  const Bytes got = frame_of(Op::PUT_BEGIN, m, encode_put_begin);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("put_begin_v0_n64.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
  m.n = 65;
  Bytes tmp(kMaxBodyLen);
  EXPECT_FALSE(encode_put_begin(m, tmp));
  m.n = 0;
  EXPECT_FALSE(encode_put_begin(m, tmp));
}

TEST(MessagesB, PutBeginAckPlacementAndGolden) {
  const Bytes got = frame_of(Op::PUT_BEGIN_ACK, ack_msg3(), encode_put_begin_ack);
  EXPECT_EQ(got, ack_hand3());
  EXPECT_TRUE(golden::matches("put_begin_ack_v0.hex", got));
  auto d = decode_put_begin_ack(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->mr[1].rkey, 0x11223344u);
  EXPECT_EQ(d->e[2].offset, 0x4000u);
  EXPECT_EQ(d->e[2].mr_index, 1);
}

TEST(MessagesB, PutBeginAckRefusedGolden) {
  PutBeginAck m;
  m.put_id = 0x1122; m.status = 1; m.retry_after_ms = 500;
  const Bytes want = cat({hand_header(0x21, 1, 112), bytes({0x22, 0x11, 0, 0, 0, 0, 0, 0}), bytes({1}), bytes({0}),
                          bytes({0, 0}), bytes({0xF4, 1, 0, 0}), zeros(96)});
  const Bytes got = frame_of(Op::PUT_BEGIN_ACK, m, encode_put_begin_ack);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("put_begin_ack_v0_refused.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
}

TEST(MessagesB, PutBeginAckN64RoundTrip) {
  PutBeginAck m;
  m.n_mr = 4; m.n = 64;
  for (int r = 0; r < 4; ++r) m.mr[r] = {0x1000ULL * (r + 1), 0x100, static_cast<std::uint32_t>(r + 1)};
  for (int i = 0; i < 64; ++i) m.e[i] = {1, static_cast<std::uint8_t>(i & 3), static_cast<std::uint64_t>(i) * 8};
  const Bytes got = frame_of(Op::PUT_BEGIN_ACK, m, encode_put_begin_ack);
  ASSERT_EQ(got.size(), 32u + 112 + 64 * 16);
  auto d = decode_put_begin_ack(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->e[63].mr_index, 3);
  EXPECT_EQ(d->e[63].offset, 63u * 8);
}

TEST(MessagesB, TicketPlacementAndGolden) {
  Ticket t;
  t.cls = 1;
  for (int i = 0; i < 16; ++i) t.id[i] = static_cast<std::uint8_t>(0xC0 + i);
  Bytes got(kTicketSize);
  auto n = encode_ticket(t, got);
  ASSERT_TRUE(n);
  EXPECT_EQ(*n, 20u);
  EXPECT_EQ(got, cat({bytes({0, 1, 0, 0}), ramp(16, 0xC0)}));  // ver, class, z u16, id
  EXPECT_TRUE(golden::matches("ticket_v0.hex", got));
  auto d = decode_ticket(got);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->cls, 1);
  EXPECT_EQ(d->id[15], 0xCF);
  t.cls = 3;
  EXPECT_FALSE(encode_ticket(t, got));
  // Errors: version, z, class, length.
  for (auto [off, v] : std::vector<std::pair<int, int>>{{0, 1}, {2, 1}, {3, 1}, {1, 3}}) {
    Bytes b = cat({bytes({0, 1, 0, 0}), ramp(16, 0xC0)});
    b[off] = static_cast<std::byte>(v);
    auto r = decode_ticket(b);
    ASSERT_FALSE(r) << off;
    EXPECT_EQ(r.error().status, WireStatus::Malformed);
  }
  Bytes longer = got;
  longer.push_back(std::byte{0});
  EXPECT_FALSE(decode_ticket(longer));
  EXPECT_FALSE(decode_ticket(std::span<const std::byte>(got).first(19)));
}

// ---- Table-driven error mutations over the normal vectors ----------------------------
namespace {
struct Edit { std::size_t off; int val; };
struct Case { const char* name; std::vector<Edit> edits; WireStatus want; };

Bytes mutate(Bytes b, const std::vector<Edit>& edits) {
  for (auto [o, v] : edits) b[o] = static_cast<std::byte>(v);
  return b;
}
Bytes resize_body(Bytes b, std::size_t body_len) {
  b.resize(kFrameHeaderSize + body_len);
  b[12] = static_cast<std::byte>(body_len & 0xff);
  b[13] = static_cast<std::byte>(body_len >> 8);
  return b;
}
void check_cases(const Bytes& base, const std::vector<Case>& cases, const char* msg) {
  ASSERT_EQ(run(base), WireStatus::Ok) << msg;
  for (const auto& c : cases) EXPECT_EQ(run(mutate(base, c.edits)), c.want) << msg << ": " << c.name;
}
const WireStatus M = WireStatus::Malformed;
}  // namespace

TEST(MessagesBErrors, Common) {
  // Framing-level rows of the plan table apply to every new opcode.
  for (const Bytes& base : {hello_hand(0x01, 0), seg_hand2(), lookup_hand2(), put_begin_hand2()}) {
    EXPECT_EQ(run(mutate(base, {{0, 'X'}})), WireStatus::Corrupt);
    EXPECT_EQ(run(mutate(base, {{4, 1}})), WireStatus::Unsupported);
    EXPECT_EQ(run(mutate(base, {{6, 0x7f}})), WireStatus::Unsupported);
    EXPECT_EQ(run(mutate(base, {{8, 0x10}})), M);
    EXPECT_EQ(run(mutate(base, {{8, 0x01}})), M) << "RESPONSE on a request";
  }
  for (const Bytes& base : {hello_hand(0x02, 1), lookup_ack_hand2(), ack_hand3()}) {
    EXPECT_EQ(run(mutate(base, {{8, 0}})), M) << "ack without RESPONSE";
    EXPECT_EQ(run(mutate(base, {{8, 3}})), M) << "ERROR flag on a normal ack";
  }
}

TEST(MessagesBErrors, Hello) {
  check_cases(hello_hand(0x01, 0),
              {{"class 3", {{35, 3}}, M}, {"rail 4", {{38, 4}}, M}, {"proto 0", {{39, 0}}, M},
               {"proto 3", {{39, 3}}, M}, {"major_min > major_max", {{32, 1}}, M},
               {"max_frame 4096", {{73, 0x10}}, M}, {"max_frame 8193", {{72, 1}}, M},
               {"z", {{76, 1}}, M}, {"z last", {{79, 1}}, M}},
              "HELLO");
  EXPECT_EQ(run(resize_body(hello_hand(0x01, 0), 47)), M);
  EXPECT_EQ(run(mutate(hello_hand(0x02, 1), {{76, 1}})), M) << "HELLO_ACK z";
  EXPECT_EQ(run(mutate(hello_hand(0x02, 1), {{35, 3}})), M) << "HELLO_ACK class";
}

TEST(MessagesBErrors, SegTable) {
  check_cases(seg_hand2(),
              {{"n 201", {{32, 201}}, M}, {"n 3 but 2 entries", {{32, 3}}, M}, {"n_rails 0", {{34, 0}}, M},
               {"n_rails 5", {{34, 5}}, M}, {"local_rail 2 >= n_rails", {{35, 2}}, M},
               {"entry flags bit1", {{76, 2}}, M}, {"entry flags bit8", {{77, 1}}, M}},
              "SEG_TABLE");
  EXPECT_EQ(run(resize_body(seg_hand2(), 39)), M);
  EXPECT_EQ(run(resize_body(seg_hand2(), 100)), M);
  EXPECT_EQ(run(mutate(resize_body(seg_hand2(), 40), {{32, 0}})), WireStatus::Ok) << "n = 0 is allowed";
  EXPECT_EQ(run(mutate(seg_hand2(), {{8, 1}})), M) << "SEG_TABLE is a push: no RESPONSE";
}

TEST(MessagesBErrors, PingGoawayStats) {
  const Bytes ping = cat({hand_header(0x04, 0, 8), bytes({8, 7, 6, 5, 4, 3, 2, 1})});
  EXPECT_EQ(run(ping), WireStatus::Ok);
  EXPECT_EQ(run(resize_body(ping, 7)), M);
  EXPECT_EQ(run(mutate(ping, {{8, 1}})), M) << "PING with RESPONSE";
  EXPECT_EQ(run(mutate(ping, {{6, 5}})), M) << "PONG without RESPONSE";

  const Bytes goaway = cat({hand_header(0x06, 0, 8), bytes({2, 0, 0, 0}), bytes({0x30, 0x75, 0, 0})});
  check_cases(goaway,
              {{"reason 0", {{32, 0}}, M}, {"reason 5", {{32, 5}}, M}, {"reason high byte", {{33, 1}}, M},
               {"RESPONSE", {{8, 1}}, M}},
              "GOAWAY");
  EXPECT_EQ(run(resize_body(goaway, 4)), M);

  const Bytes stats = cat({hand_header(0x07, 0, 8), bytes({4, 3, 2, 1}), zeros(4)});
  check_cases(stats, {{"z", {{36, 1}}, M}, {"z last", {{39, 1}}, M}, {"RESPONSE", {{8, 1}}, M}}, "STATS");
  EXPECT_EQ(run(resize_body(stats, 7)), M);
  const Bytes sack = cat({hand_header(0x08, 1, 8), bytes({4, 3, 2, 1}), zeros(4)});
  check_cases(sack, {{"z", {{37, 1}}, M}, {"no RESPONSE", {{8, 0}}, M}}, "STATS_ACK");
  // Counter TLV: critical unknown -> Unsupported; truncated -> Malformed; D11 mismatch.
  auto with = [&](const Bytes& tlv, int flags) {
    Bytes b = sack;
    b.insert(b.end(), tlv.begin(), tlv.end());
    return mutate(resize_body(b, 8 + tlv.size()), {{8, flags}});
  };
  EXPECT_EQ(run(with(bytes({1, 0x80, 0, 0, 0, 0, 0, 0}), 1 | flag::CRITICAL_EXT)), WireStatus::Unsupported);
  EXPECT_EQ(run(with(bytes({0x10, 0, 8, 0}), 1)), M) << "truncated TLV";
  EXPECT_EQ(run(with(bytes({1, 0x80, 0, 0, 0, 0, 0, 0}), 1)), M) << "D11";
  EXPECT_EQ(run(with(bytes({0x10, 0, 4, 0, 1, 2, 3, 4}), 1)), WireStatus::Ok);
}

TEST(MessagesBErrors, Lookup) {
  check_cases(lookup_hand2(),
              {{"unknown flag bit1", {{64, 2}}, M}, {"unknown flag bit8", {{65, 1}}, M}, {"n 0", {{66, 0}}, M},
               {"n 129", {{66, 129}}, M}, {"n 3 but 2 keys", {{66, 3}}, M}, {"z", {{68, 1}}, M},
               {"z last", {{71, 1}}, M}},
              "LOOKUP");
  EXPECT_EQ(run(resize_body(lookup_hand2(), 39)), M);
  EXPECT_EQ(run(resize_body(lookup_hand2(), 100)), M);
  EXPECT_EQ(run(mutate(lookup_hand2(), {{64, 0}})), WireStatus::Ok) << "PROBE";
}

TEST(MessagesBErrors, LookupAck) {
  check_cases(lookup_ack_hand2(),
              {{"n 0", {{44, 0}}, M}, {"n 129", {{44, 129}}, M}, {"n 3 but 2 entries", {{44, 3}}, M},
               {"z", {{46, 1}}, M}, {"entry status 2", {{48, 2}}, M}, {"entry z", {{49, 1}}, M},
               {"HIT gen 0", {{72, 0}, {73, 0}, {74, 0}, {75, 0}, {76, 0}}, M}, {"HIT gen top byte", {{79, 1}}, M},
               {"MISS with seg_id", {{92, 1}}, M}, {"MISS with offset", {{96, 1}}, M},
               {"MISS with gen", {{112, 1}}, M}, {"MISS with gen_slot", {{120, 1}}, M},
               {"MISS entry z", {{89, 1}}, M}},
              "LOOKUP_ACK");
  EXPECT_EQ(run(resize_body(lookup_ack_hand2(), 15)), M);
  EXPECT_EQ(run(resize_body(lookup_ack_hand2(), 95)), M);
  EXPECT_EQ(run(mutate(lookup_ack_hand2(), {{32, 0}, {33, 0}, {34, 0}, {35, 0}, {36, 0}, {37, 0}, {38, 0}, {39, 0}})),
            WireStatus::Ok) << "lease_id 0 = none";
}

TEST(MessagesBErrors, PutBegin) {
  check_cases(put_begin_hand2(),
              {{"n 0", {{64, 0}}, M}, {"n 65", {{64, 65}}, M}, {"n 3 but 2 entries", {{64, 3}}, M},
               {"n high byte", {{65, 1}}, M}, {"z", {{66, 1}}, M}, {"z last", {{71, 1}}, M}},
              "PUT_BEGIN");
  EXPECT_EQ(run(resize_body(put_begin_hand2(), 39)), M);
  EXPECT_EQ(run(resize_body(put_begin_hand2(), 100)), M);
}

TEST(MessagesBErrors, PutBeginAck) {
  check_cases(ack_hand3(),
              {{"status 2", {{40, 2}}, M}, {"n_mr 5", {{41, 5}}, M}, {"n 65", {{42, 65}}, M},
               {"n 4 but 3 entries", {{42, 4}}, M}, {"mr z", {{68, 1}}, M},
               {"unused mr2 addr", {{96, 1}}, M}, {"unused mr3 rkey", {{136, 1}}, M},
               {"n_mr 1 but entry uses mr1", {{41, 1}}, M}, {"entry status 2", {{144, 2}}, M},
               {"mr_index >= n_mr", {{145, 2}}, M}, {"entry z", {{146, 1}}, M}, {"entry z last", {{151, 1}}, M},
               {"SKIP with mr_index", {{161, 1}}, M}, {"SKIP with offset", {{168, 1}}, M}},
              "PUT_BEGIN_ACK");
  EXPECT_EQ(run(resize_body(ack_hand3(), 111)), M);
  EXPECT_EQ(run(resize_body(ack_hand3(), 150)), M);
}
