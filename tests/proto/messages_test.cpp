// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <algorithm>
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

FrameHeader test_header(Op op, int extra_flags = 0) {
  FrameHeader h = header_for(op, 0x1122334455667788ULL);
  h.flags = static_cast<std::uint16_t>(h.flags | extra_flags);
  h.credits = 3;
  h.epoch = 0xA1B2C3D4;
  h.bundle_gen_lo = 0xBEEF;
  return h;
}

template <typename M, typename Enc>
Bytes frame_of(Op op, const M& m, Enc enc, int extra_flags = 0) {
  Bytes body(kMaxBodyLen);
  auto n = enc(m, body);
  EXPECT_TRUE(n);
  if (!n) return {};
  body.resize(*n);
  Bytes out(kFrameHeaderSize + body.size());
  EXPECT_TRUE(encode_frame(test_header(op, extra_flags), body, out));
  return out;
}

// Decodes a whole frame for a Run A op; returns the first error status, Ok if accepted.
WireStatus run(const Bytes& wire) {
  auto f = decode_frame(wire);
  if (!f) return f.error().status;
  if (auto o = check_opcode(f->h.type); !o) return o.error().status;
  const auto& h = f->h;
  auto st = [](const auto& r) { return r ? WireStatus::Ok : r.error().status; };
  switch (static_cast<Op>(h.type)) {
    case Op::RENEW: return st(decode_renew(h, f->body));
    case Op::RENEW_ACK: return st(decode_renew_ack(h, f->body));
    case Op::RELEASE: return st(decode_release(h, f->body));
    case Op::INVALIDATE: return st(decode_invalidate(h, f->body));
    case Op::INVALIDATE_ACK: return st(decode_invalidate_ack(h, f->body));
    case Op::PUT_COMMIT: return st(decode_put_commit(h, f->body));
    case Op::PUT_DONE: return st(decode_put_done(h, f->body));
    case Op::PUT_CANCEL: return st(decode_put_cancel(h, f->body));
    default: return WireStatus::Ok;  // Run B
  }
}

Frame parse(const Bytes& wire) {
  auto f = decode_frame(wire);
  EXPECT_TRUE(f);
  return f ? *f : Frame{};
}

PutCommit commit2() {
  PutCommit m;
  m.put_id = 0x1122;
  m.n = 2;
  m.e[0] = {0, 0xDEADBEEF, 0x1000};
  m.e[1] = {5, 0x01020304, 0x2000};
  return m;
}
Bytes commit2_hand() {
  return cat({hand_header(0x22, 0, 48),
              bytes({0x22, 0x11, 0, 0, 0, 0, 0, 0}),  // put_id
              bytes({2, 0}), zeros(6),                // n, z
              bytes({0, 0}), bytes({0, 0}), bytes({0xEF, 0xBE, 0xAD, 0xDE}), bytes({0, 0x10, 0, 0, 0, 0, 0, 0}),
              bytes({5, 0}), bytes({0, 0}), bytes({4, 3, 2, 1}), bytes({0, 0x20, 0, 0, 0, 0, 0, 0})});
}

Bytes invalidate_hand(const Bytes& gen) {
  return cat({hand_header(0x15, 0, 72), ramp(32, 0x00), ramp(32, 0x40), gen});
}
Invalidate invalidate_msg(std::uint64_t gen) {
  Invalidate m;
  for (int i = 0; i < 32; ++i) { m.scope_id[i] = static_cast<std::uint8_t>(i); m.key_hash[i] = static_cast<std::uint8_t>(0x40 + i); }
  m.gen = gen;
  return m;
}

Bytes done_hand1() {
  return cat({hand_header(0x23, 1, 24), bytes({0x22, 0x11, 0, 0, 0, 0, 0, 0}), bytes({1, 0}), zeros(6),
              bytes({0, 0, 0, 0}),  // key_index 0, COMMITTED, none
              zeros(4)});           // pad to 8
}
Bytes done_hand3() {
  return cat({hand_header(0x23, 1, 32), bytes({0x22, 0x11, 0, 0, 0, 0, 0, 0}), bytes({3, 0}), zeros(6),
              bytes({0, 0, 0, 0}), bytes({1, 0, 1, 1}), bytes({2, 0, 1, 4}), zeros(4)});
}

}  // namespace

TEST(Messages, RenewPlacementAndGolden) {
  const Bytes want = cat({hand_header(0x12, 0, 8), bytes({1, 2, 3, 4, 5, 6, 7, 8})});
  Renew m;
  m.lease_id = 0x0807060504030201ULL;
  const Bytes got = frame_of(Op::RENEW, m, encode_renew);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("renew_v0.hex", got));
  auto d = decode_renew(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->lease_id, m.lease_id);
  m.lease_id = 0;
  Bytes tmp(8);
  EXPECT_FALSE(encode_renew(m, tmp));
}

TEST(Messages, RenewAckPlacementAndGolden) {
  const Bytes want = cat({hand_header(0x13, 1, 16), bytes({1, 2, 3, 4, 5, 6, 7, 8}), bytes({0x10, 0x27, 0, 0}),
                          bytes({1, 0, 0, 0})});
  RenewAck m;
  m.lease_id = 0x0807060504030201ULL;
  m.ttl_ms = 10000;
  m.status = 1;
  const Bytes got = frame_of(Op::RENEW_ACK, m, encode_renew_ack);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("renew_ack_v0.hex", got));
  auto d = decode_renew_ack(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->ttl_ms, 10000u);
  EXPECT_EQ(d->status, 1);
}

TEST(Messages, ReleasePlacementAndGolden) {
  const Bytes want = cat({hand_header(0x14, 0, 8), bytes({9, 8, 7, 6, 5, 4, 3, 2})});
  Release m;
  m.lease_id = 0x0203040506070809ULL;
  const Bytes got = frame_of(Op::RELEASE, m, encode_release);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("release_v0.hex", got));
}

TEST(Messages, ReleaseWithSkippableTlvGolden) {
  // Non-critical tag 0x0001, value "ABC", padded to 8 B: skipped, tail preserved verbatim.
  const Bytes tlv = bytes({1, 0, 3, 0, 0x41, 0x42, 0x43, 0});
  const Bytes want = cat({hand_header(0x14, 0, 16), bytes({9, 8, 7, 6, 5, 4, 3, 2}), tlv});
  Release m;
  m.lease_id = 0x0203040506070809ULL;
  m.tlvs = tlv;
  const Bytes got = frame_of(Op::RELEASE, m, encode_release);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("release_v0_tlv.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
  auto d = decode_release(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->tlvs.size(), 8u);
  // Unknown non-critical tag is skipped too.
  Bytes other = got;
  other[32 + 8] = std::byte{0x42};
  EXPECT_EQ(run(other), WireStatus::Ok);
}

TEST(Messages, InvalidatePlacementAndGolden) {
  const Bytes want = invalidate_hand(bytes({5, 4, 3, 2, 1, 0, 0, 0}));
  const Bytes got = frame_of(Op::INVALIDATE, invalidate_msg(0x0102030405ULL), encode_invalidate);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("invalidate_v0.hex", got));
  auto d = decode_invalidate(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->gen, 0x0102030405ULL);
  EXPECT_EQ(d->key_hash[0], 0x40);
}

TEST(Messages, InvalidateMaxGenGolden) {
  const Bytes want = invalidate_hand(bytes({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0}));
  const Bytes got = frame_of(Op::INVALIDATE, invalidate_msg(kMaxGeneration), encode_invalidate);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("invalidate_v0_maxgen.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
}

TEST(Messages, InvalidateGenRange) {
  Bytes tmp(kMaxBodyLen);
  EXPECT_FALSE(encode_invalidate(invalidate_msg(0), tmp));
  EXPECT_FALSE(encode_invalidate(invalidate_msg(kMaxGeneration + 1), tmp));
  Bytes zero_gen = invalidate_hand(zeros(8));
  EXPECT_EQ(run(zero_gen), WireStatus::Malformed);
  Bytes top = invalidate_hand(bytes({1, 0, 0, 0, 0, 0, 0, 1}));
  EXPECT_EQ(run(top), WireStatus::Malformed);
}

TEST(Messages, InvalidateAckGolden) {
  const Bytes want = hand_header(0x16, 1, 0);
  const Bytes got = frame_of(Op::INVALIDATE_ACK, InvalidateAck{}, encode_invalidate_ack);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("invalidate_ack_v0.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
}

TEST(Messages, PutCommitPlacementAndGolden) {
  const Bytes got = frame_of(Op::PUT_COMMIT, commit2(), encode_put_commit);
  EXPECT_EQ(got, commit2_hand());
  EXPECT_TRUE(golden::matches("put_commit_v0.hex", got));
  auto d = decode_put_commit(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->n, 2);
  EXPECT_EQ(d->e[1].key_index, 5);
  EXPECT_EQ(d->e[1].crc32c, 0x01020304u);
  EXPECT_EQ(d->e[1].stored_len, 0x2000u);
}

TEST(Messages, PutCommitN64Golden) {
  PutCommit m;
  m.put_id = 0x1122;
  m.n = 64;
  Bytes want = cat({hand_header(0x22, 0, 16 + 64 * 16), bytes({0x22, 0x11, 0, 0, 0, 0, 0, 0}), bytes({64, 0}), zeros(6)});
  for (int i = 0; i < 64; ++i) {
    m.e[i] = {static_cast<std::uint16_t>(2 * i), static_cast<std::uint32_t>(i), 0x1000u + i};
    const Bytes ent = cat({bytes({2 * i, 0}), bytes({0, 0}), bytes({i, 0, 0, 0}),
                           bytes({(0x1000 + i) & 0xff, (0x1000 + i) >> 8, 0, 0, 0, 0, 0, 0})});
    want.insert(want.end(), ent.begin(), ent.end());
  }
  ASSERT_EQ(want.size(), 32u + 1040u);
  const Bytes got = frame_of(Op::PUT_COMMIT, m, encode_put_commit);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("put_commit_v0_n64.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
  m.n = 65;
  Bytes tmp(kMaxBodyLen);
  EXPECT_FALSE(encode_put_commit(m, tmp));
}

TEST(Messages, PutDonePaddingGolden) {
  PutDone m;
  m.put_id = 0x1122;
  m.n = 1;
  const Bytes got = frame_of(Op::PUT_DONE, m, encode_put_done);
  EXPECT_EQ(got, done_hand1());  // 16 + 4 = 20 -> padded to 24
  EXPECT_TRUE(golden::matches("put_done_v0_n1.hex", got));
  EXPECT_EQ(run(got), WireStatus::Ok);
  Bytes badpad = got;
  badpad[32 + 20] = std::byte{1};
  EXPECT_EQ(run(badpad), WireStatus::Malformed);
}

TEST(Messages, PutDoneN3Golden) {
  PutDone m;
  m.put_id = 0x1122;
  m.n = 3;
  m.e[0] = {0, 0, 0};
  m.e[1] = {1, 1, 1};
  m.e[2] = {2, 1, 4};
  const Bytes got = frame_of(Op::PUT_DONE, m, encode_put_done);
  EXPECT_EQ(got, done_hand3());
  EXPECT_TRUE(golden::matches("put_done_v0.hex", got));
  auto d = decode_put_done(parse(got).h, parse(got).body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->e[2].reason, 4);
  EXPECT_EQ(d->e[1].status, 1);
}

TEST(Messages, PutCancelGolden) {
  const Bytes want = cat({hand_header(0x24, 0, 8), bytes({0x22, 0x11, 0, 0, 0, 0, 0, 0})});
  PutCancel m;
  m.put_id = 0x1122;
  const Bytes got = frame_of(Op::PUT_CANCEL, m, encode_put_cancel);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("put_cancel_v0.hex", got));
}

TEST(Messages, ErrorReplyGolden) {
  // Reply to a PUT_COMMIT: type stays 0x22, flags RESPONSE|ERROR = 3.
  const Bytes want = cat({hand_header(0x22, 3, 8), bytes({5, 0}), bytes({0, 0}), bytes({0xFA, 0, 0, 0})});
  Bytes got(40);
  auto n = encode_error_reply_frame(test_header(Op::PUT_COMMIT), ErrorReply{5, 250}, got);
  ASSERT_TRUE(n);
  EXPECT_EQ(*n, 40u);
  EXPECT_EQ(got, want);
  EXPECT_TRUE(golden::matches("error_reply_v0.hex", got));
  auto f = parse(got);
  auto d = decode_error_reply(f.h, f.body);
  ASSERT_TRUE(d);
  EXPECT_EQ(d->status, 5);
  EXPECT_EQ(d->retry_after_ms, 250u);
  EXPECT_FALSE(encode_error_reply_frame(test_header(Op::PUT_COMMIT), ErrorReply{6, 0}, got));
  EXPECT_FALSE(encode_error_reply_frame(test_header(Op::PUT_COMMIT), ErrorReply{0, 0}, got));
}

TEST(Messages, ErrorReplyRejects) {
  Bytes good(40);
  ASSERT_TRUE(encode_error_reply_frame(test_header(Op::PUT_COMMIT), ErrorReply{2, 0}, good));
  auto code = [](const Bytes& w) { auto f = decode_frame(w); auto r = decode_error_reply(f->h, f->body); return r ? WireStatus::Ok : r.error().status; };
  EXPECT_EQ(code(good), WireStatus::Ok);
  for (auto [off, v] : std::vector<std::pair<int, int>>{{32, 0}, {32, 6}, {34, 1}, {8, 1}, {8, 2}, {8, 7}, {8, 11}}) {
    Bytes b = good;
    b[off] = static_cast<std::byte>(v);
    EXPECT_EQ(code(b), WireStatus::Malformed) << off << "=" << v;
  }
}

// ---- Table-driven error mutations over the normal vectors ----------------------------
namespace {
struct Edit { std::size_t off; int val; };
struct Case { const char* name; std::vector<Edit> edits; WireStatus want; };

Bytes mutate(Bytes b, const std::vector<Edit>& edits) {
  for (auto [o, v] : edits) b[o] = static_cast<std::byte>(v);
  return b;
}
// Truncate/extend the body to `body_len` bytes and patch the header's body_len.
Bytes resize_body(Bytes b, std::size_t body_len) {
  b.resize(kFrameHeaderSize + body_len);
  b[12] = static_cast<std::byte>(body_len & 0xff);
  b[13] = static_cast<std::byte>(body_len >> 8);
  return b;
}
}  // namespace

TEST(MessagesErrors, PutCommitMutations) {
  const Bytes base = commit2_hand();  // offsets: n@40, z@42..47, e0@48, e1@64
  ASSERT_EQ(run(base), WireStatus::Ok);
  const std::vector<Case> cases = {
      {"bad magic", {{0, 'X'}}, WireStatus::Corrupt},
      {"major 1", {{4, 1}}, WireStatus::Unsupported},
      {"unknown opcode", {{6, 0x7f}}, WireStatus::Unsupported},
      {"unknown opcode 0x25", {{6, 0x25}}, WireStatus::Unsupported},
      {"unknown flag bit 4", {{8, 0x10}}, WireStatus::Malformed},
      {"unknown flag bit 8", {{9, 0x01}}, WireStatus::Malformed},
      {"RESPONSE on a request", {{8, 0x01}}, WireStatus::Malformed},
      {"body_len > 8160", {{12, 0xE1}, {13, 0x1F}}, WireStatus::Corrupt},
      {"body_len mismatch", {{12, 47}}, WireStatus::Corrupt},
      {"z in fixed part", {{42, 1}}, WireStatus::Malformed},
      {"z last byte", {{47, 1}}, WireStatus::Malformed},
      {"entry z", {{50, 1}}, WireStatus::Malformed},
      {"n = 0", {{40, 0}}, WireStatus::Malformed},
      {"n = 65", {{40, 65}}, WireStatus::Malformed},
      {"n = 3 but 2 entries", {{40, 3}}, WireStatus::Malformed},
      {"key_index equal", {{64, 0}}, WireStatus::Malformed},
      {"key_index descending", {{48, 9}}, WireStatus::Malformed},
  };
  for (const auto& c : cases) EXPECT_EQ(run(mutate(base, c.edits)), c.want) << c.name;
  EXPECT_EQ(run(resize_body(base, 8)), WireStatus::Malformed) << "short body (< fixed)";
  EXPECT_EQ(run(resize_body(base, 40)), WireStatus::Malformed) << "short body (entries)";
}

TEST(MessagesErrors, TlvTailMutations) {
  const Bytes base = commit2_hand();
  const Bytes crit = bytes({1, 0x80, 0, 0, 0, 0, 0, 0});
  auto with = [&](const Bytes& tlv, int flags) {
    Bytes b = base;
    b.insert(b.end(), tlv.begin(), tlv.end());
    return mutate(resize_body(b, 48 + tlv.size()), {{8, flags}});
  };
  EXPECT_EQ(run(with(crit, flag::CRITICAL_EXT)), WireStatus::Unsupported) << "critical unknown";
  EXPECT_EQ(run(with(crit, 0)), WireStatus::Malformed) << "D11: critical TLV without flag";
  EXPECT_EQ(run(with(bytes({1, 0, 0, 0, 0, 0, 0, 0}), flag::CRITICAL_EXT)), WireStatus::Malformed) << "D11: flag without critical";
  EXPECT_EQ(run(with(bytes({1, 0, 8, 0}), 0)), WireStatus::Malformed) << "truncated TLV";
  EXPECT_EQ(run(with(bytes({1, 0, 1, 0, 7, 9, 0, 0}), 0)), WireStatus::Malformed) << "padding not zero";
  EXPECT_EQ(run(with(bytes({1, 0, 3, 0, 1, 2, 3, 0}), 0)), WireStatus::Ok) << "skippable";
  EXPECT_EQ(run(with(bytes({0x42, 0, 3, 0, 1, 2, 3, 0}), 0)), WireStatus::Ok) << "unknown non-critical";
}

TEST(MessagesErrors, OtherMessages) {
  const Bytes renew = cat({hand_header(0x12, 0, 8), bytes({1, 2, 3, 4, 5, 6, 7, 8})});
  EXPECT_EQ(run(renew), WireStatus::Ok);
  EXPECT_EQ(run(mutate(renew, {{32, 0}, {33, 0}, {34, 0}, {35, 0}, {36, 0}, {37, 0}, {38, 0}, {39, 0}})), WireStatus::Malformed) << "lease_id 0";
  EXPECT_EQ(run(resize_body(renew, 4)), WireStatus::Malformed);
  EXPECT_EQ(run(mutate(renew, {{6, 0x13}})), WireStatus::Malformed) << "ack type without RESPONSE";
  const Bytes ack = cat({hand_header(0x13, 1, 16), bytes({1, 2, 3, 4, 5, 6, 7, 8}), bytes({0x10, 0x27, 0, 0}), bytes({1, 0, 0, 0})});
  EXPECT_EQ(run(ack), WireStatus::Ok);
  EXPECT_EQ(run(mutate(ack, {{44, 2}})), WireStatus::Malformed) << "status 2";
  EXPECT_EQ(run(mutate(ack, {{45, 1}})), WireStatus::Malformed) << "z";
  EXPECT_EQ(run(mutate(ack, {{8, 0}})), WireStatus::Malformed) << "ack without RESPONSE";
  const Bytes done = done_hand1();
  EXPECT_EQ(run(mutate(done, {{40, 0}})), WireStatus::Malformed) << "n = 0";
  EXPECT_EQ(run(mutate(done, {{42, 1}})), WireStatus::Malformed) << "z";
  EXPECT_EQ(run(mutate(done, {{50, 2}})), WireStatus::Malformed) << "status 2";
  EXPECT_EQ(run(mutate(done, {{51, 5}})), WireStatus::Malformed) << "reason 5";
  EXPECT_EQ(run(resize_body(done, 20)), WireStatus::Malformed) << "missing pad";
}

TEST(MessagesErrors, HigherMinorVersionAccepted) {
  Bytes b = commit2_hand();
  b[5] = std::byte{7};
  EXPECT_EQ(run(b), WireStatus::Ok);
}
