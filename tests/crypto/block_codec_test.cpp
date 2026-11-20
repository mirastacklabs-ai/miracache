// SPDX-License-Identifier: Apache-2.0
// A1.5 S2: block segmenter. Round trips, golden vector (freezes crypto v1), AAD and
// structure negatives, CRC combine, nonce-reuse guard.
#include <gtest/gtest.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cstring>
#include <set>
#include <vector>

#include "crypto/block_codec.h"
#include "proto/golden.h"
#include "util/crc32c.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;

Bytes pattern(std::size_t n, unsigned seed = 3) {
  Bytes b(n);
  for (std::size_t i = 0; i < n; ++i) b[i] = static_cast<std::byte>((i * 7 + seed + (i >> 8)) & 0xff);
  return b;
}

Dek test_dek() {
  std::array<std::byte, 32> k;
  for (int i = 0; i < 32; ++i) k[i] = static_cast<std::byte>(i);
  return Dek(std::span<const std::byte, 32>(k));
}

BlockMeta test_meta(std::uint64_t len, std::uint8_t log2) {
  BlockMeta m{};
  m.kver = 7;
  for (int i = 0; i < 32; ++i) {
    m.scope_id.b[i] = static_cast<std::uint8_t>(0x10 + i);
    m.key_hash.b[i] = static_cast<std::uint8_t>(0x40 + i);
  }
  m.plaintext_len = len;
  m.segment_log2 = log2;
  return m;
}

// Test-only source: returns salts from a script, then repeats the last one forever.
class ScriptedNonceSource final : public NonceSource {
 public:
  explicit ScriptedNonceSource(std::vector<std::array<std::byte, 16>> s) : salts_(std::move(s)) {}
  ScriptedNonceSource(std::byte fill_byte) { salts_.push_back({}); salts_[0].fill(fill_byte); }

 protected:
  Status fill(std::span<std::byte> out) override {
    const auto& s = salts_[std::min(n_, salts_.size() - 1)];
    ++n_;
    std::memcpy(out.data(), s.data(), 16);
    return {};
  }

 private:
  std::vector<std::array<std::byte, 16>> salts_;
  std::size_t n_ = 0;
};

// Sim-only ledger: counter-driven distinct salts, recording every salt ever issued so a
// test can assert no salt was reused across blocks.
class SaltLedger final : public NonceSource {
 public:
  std::set<std::array<std::byte, 16>> seen;
  bool duplicate = false;

 protected:
  Status fill(std::span<std::byte> out) override {
    std::array<std::byte, 16> s{};
    std::uint64_t v = ++ctr_ * 0x9E3779B97F4A7C15ull;
    std::memcpy(s.data(), &v, 8);
    s[15] = std::byte{0x5a};
    if (!seen.insert(s).second) duplicate = true;
    std::memcpy(out.data(), s.data(), 16);
    return {};
  }

 private:
  std::uint64_t ctr_ = 0;
};

struct Sealed {
  Bytes block;
  std::uint32_t whole_crc = 0;  // combined from header + segment CRCs
  SealCtx ctx;
};

Sealed seal_all(const Dek& dek, const BlockMeta& meta, NonceSource& ns, const Bytes& pt) {
  auto lay = layout(meta.plaintext_len, meta.segment_log2);
  EXPECT_TRUE(lay.has_value());
  Bytes block(lay->stored_len);
  auto ctx = seal_begin(dek, meta, ns, std::span<std::byte>(block).first(64));
  EXPECT_TRUE(ctx.has_value());
  auto gcm = GcmCtx::create();
  EXPECT_TRUE(gcm.has_value());
  std::uint32_t crc = crc32c(std::span<const std::byte>(block).first(64));
  const std::uint64_t seg = std::uint64_t{1} << meta.segment_log2;
  for (std::uint32_t i = 0; i < ctx->lay.segments; ++i) {
    std::uint32_t sc = 0;
    Status st = seal_segment(*gcm, *ctx, i,
                             std::span<const std::byte>(pt).subspan(i * seg, ctx->lay.pt_len(i)),
                             block, &sc);
    EXPECT_TRUE(st.has_value());
    crc = crc32c_combine(crc, sc, ctx->lay.ct_len(i));
  }
  return Sealed{std::move(block), crc, std::move(*ctx)};
}

Status open_all(const Dek& dek, const BlockMeta& m, const Bytes& block, Bytes& out) {
  auto gcm = GcmCtx::create();
  auto oc = open_begin(dek, m, block);
  if (!oc) return oc.error();
  out.assign(m.plaintext_len, std::byte{0xAA});
  return open_block(*gcm, *oc, block, out);
}

bool all_zero(const Bytes& b) {
  return std::all_of(b.begin(), b.end(), [](std::byte x) { return x == std::byte{0}; });
}

// ---------------------------------------------------------------------------

TEST(BlockLayout, Geometry) {
  auto l = layout(0, 16);
  ASSERT_TRUE(l.has_value());
  EXPECT_EQ(l->segments, 1u);  // D17: empty plaintext still has one segment
  EXPECT_EQ(l->stored_len, 64u + 16u);
  EXPECT_EQ(l->ct_len(0), 16u);
  l = layout(65536, 16);
  EXPECT_EQ(l->segments, 1u);
  l = layout(65537, 16);
  EXPECT_EQ(l->segments, 2u);
  EXPECT_EQ(l->seg_off(1), 64u + 65536u + 16u);
  EXPECT_EQ(l->ct_len(1), 1u + 16u);
  EXPECT_EQ(l->stored_len, 64u + 65537u + 32u);
  EXPECT_FALSE(layout(1, 15).has_value());
  EXPECT_FALSE(layout(1, 21).has_value());
  EXPECT_FALSE(layout(~std::uint64_t{0}, 16).has_value());
}

TEST(BlockCodec, RoundTripSizes) {
  const Dek dek = test_dek();
  for (std::uint8_t log2 : {16, 18}) {
    const std::size_t S = std::size_t{1} << log2;
    for (std::size_t n : {std::size_t{0}, std::size_t{1}, S - 1, S, S + 1, 3 * S + 7}) {
      SCOPED_TRACE(testing::Message() << "log2=" << int(log2) << " n=" << n);
      const BlockMeta m = test_meta(n, log2);
      const Bytes pt = pattern(n);
      SaltLedger ns;
      Sealed s = seal_all(dek, m, ns, pt);
      EXPECT_EQ(s.block.size(), s.ctx.lay.stored_len);
      // Combined CRC equals CRC over the whole extent.
      EXPECT_EQ(s.whole_crc, crc32c(s.block));
      Bytes out;
      ASSERT_TRUE(open_all(dek, m, s.block, out).has_value());
      EXPECT_EQ(out, pt);
      // A wrong DEK must fail and leave nothing behind.
      std::array<std::byte, 32> other{};
      other[0] = std::byte{1};
      EXPECT_FALSE(open_all(Dek(std::span<const std::byte, 32>(other)), m, s.block, out).has_value());
      EXPECT_TRUE(all_zero(out));
    }
  }
}

TEST(Crc32cCombine, MatchesWholeForManySplits) {
  const Bytes data = pattern(5000, 11);
  const std::uint32_t whole = crc32c(data);
  for (std::size_t cut : {std::size_t{0}, std::size_t{1}, std::size_t{7}, std::size_t{4096}, std::size_t{4999}, std::size_t{5000}}) {
    const std::span<const std::byte> a(data.data(), cut), b(data.data() + cut, data.size() - cut);
    EXPECT_EQ(crc32c_combine(crc32c(a), crc32c(b), b.size()), whole) << cut;
  }
}

// By-hand structural check, written WITHOUT block_codec: literal header, AAD and nonce
// bytes (per extent_header.h D16/D18), HKDF via the KAT-tested primitive, raw EVP GCM.
// This pins the codec to the documented layout before the golden file is trusted.
Bytes hand_block_100() {
  const Bytes pt = pattern(100);
  std::array<std::byte, 16> salt;
  for (int i = 0; i < 16; ++i) salt[i] = static_cast<std::byte>(0xA0 + i);
  Bytes hdr(64, std::byte{0});
  const unsigned char head[] = {'M', 'I', 'R', 'C', 1, 1, 16, 0, 7, 0, 0, 0, 0, 0, 0, 0};
  std::memcpy(hdr.data(), head, 16);
  std::memcpy(hdr.data() + 16, salt.data(), 16);
  hdr[32] = std::byte{100};  // plaintext_len u64 LE
  Bytes aad(80, std::byte{0});
  aad[0] = std::byte{1}; aad[1] = std::byte{1}; aad[2] = std::byte{16}; aad[4] = std::byte{7};
  for (int i = 0; i < 32; ++i) { aad[8 + i] = std::byte(0x10 + i); aad[40 + i] = std::byte(0x40 + i); }
  aad[72] = std::byte{100};
  unsigned char nonce[12] = {0};
  nonce[11] = 1;  // segment 0, last = 1
  Dek dek = test_dek();
  Bytes key(32);
  const char info[] = "mira-blk-v1";
  EXPECT_TRUE(hkdf_sha256(dek.bytes(), salt, std::as_bytes(std::span(info, 11)), key).has_value());
  Bytes ct(100 + 16);
  EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
  int n = 0;
  EXPECT_EQ(EVP_EncryptInit_ex(c, EVP_aes_256_gcm(), nullptr, nullptr, nullptr), 1);
  EXPECT_EQ(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr), 1);
  EXPECT_EQ(EVP_EncryptInit_ex(c, nullptr, nullptr, reinterpret_cast<unsigned char*>(key.data()), nonce), 1);
  EXPECT_EQ(EVP_EncryptUpdate(c, nullptr, &n, reinterpret_cast<unsigned char*>(aad.data()), 80), 1);
  EXPECT_EQ(EVP_EncryptUpdate(c, reinterpret_cast<unsigned char*>(ct.data()), &n,
                              reinterpret_cast<const unsigned char*>(pt.data()), 100), 1);
  EXPECT_EQ(EVP_EncryptFinal_ex(c, reinterpret_cast<unsigned char*>(ct.data()) + 100, &n), 1);
  EXPECT_EQ(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_GCM_GET_TAG, 16, ct.data() + 100), 1);
  EVP_CIPHER_CTX_free(c);
  Bytes block = hdr;
  block.insert(block.end(), ct.begin(), ct.end());
  return block;
}

Bytes golden_salt_block() {
  std::array<std::byte, 16> salt;
  for (int i = 0; i < 16; ++i) salt[i] = static_cast<std::byte>(0xA0 + i);
  ScriptedNonceSource ns({salt});
  return seal_all(test_dek(), test_meta(100, 16), ns, pattern(100)).block;
}

TEST(BlockGolden, StructureByHand) {
  EXPECT_EQ(golden_salt_block(), hand_block_100());
}

TEST(BlockGolden, FrozenV1) {
  const Bytes b = golden_salt_block();
  EXPECT_EQ(b.size(), 64u + 100u + 16u);
  EXPECT_TRUE(golden::matches("block_v1.hex", b));
  // The frozen bytes must open with the frozen key material.
  Bytes out;
  const Bytes g = golden::load("block_v1.hex");
  ASSERT_TRUE(open_all(test_dek(), test_meta(100, 16), g, out).has_value());
  EXPECT_EQ(out, pattern(100));
}

// ---------------------------------------------------------------------------
// Negatives: every one must fail AND leave the engine buffer zeroed.

struct Fixture {
  Dek dek = test_dek();
  BlockMeta meta = test_meta(3 * 65536 + 7, 16);  // 4 segments
  Bytes pt = pattern(3 * 65536 + 7);
  SaltLedger ns;
  Sealed s = seal_all(dek, meta, ns, pt);
};

TEST(BlockNegative, EachAadFieldIsBound) {
  Fixture f;
  // 7 AAD fields: ver, cipher, segment_log2, kver, scope_id, key_hash, plaintext_len.
  const std::size_t offs[7] = {0, 1, 2, 4, 8, 40, 72};
  for (std::size_t off : offs) {
    SCOPED_TRACE(off);
    auto oc = open_begin(f.dek, f.meta, f.s.block);
    ASSERT_TRUE(oc.has_value());
    oc->aad[off] ^= std::byte{1};
    auto gcm = GcmCtx::create();
    Bytes out(f.meta.plaintext_len, std::byte{0xAA});
    EXPECT_FALSE(open_block(*gcm, *oc, f.s.block, out).has_value());
    EXPECT_TRUE(all_zero(out));
  }
}

TEST(BlockNegative, ExpectationMismatch) {
  Fixture f;
  Bytes out;
  {  // scope / key_hash: header is fine, tag fails
    BlockMeta m = f.meta; m.scope_id.b[31] ^= 1;
    EXPECT_FALSE(open_all(f.dek, m, f.s.block, out).has_value());
    EXPECT_TRUE(all_zero(out));
    m = f.meta; m.key_hash.b[0] ^= 1;
    EXPECT_FALSE(open_all(f.dek, m, f.s.block, out).has_value());
    EXPECT_TRUE(all_zero(out));
  }
  {  // kver / plaintext_len / log2: rejected at open_begin (Decision 6: Corrupt)
    BlockMeta m = f.meta; m.kver += 1;
    auto r = open_begin(f.dek, m, f.s.block);
    ASSERT_FALSE(r.has_value());
    EXPECT_EQ(r.error().code, ErrorCode::Corrupt);
    m = f.meta; m.plaintext_len -= 1;
    EXPECT_FALSE(open_begin(f.dek, m, f.s.block).has_value());
    m = f.meta; m.segment_log2 = 17;
    EXPECT_FALSE(open_begin(f.dek, m, f.s.block).has_value());
  }
}

TEST(BlockNegative, SegmentReorderDropTruncate) {
  Fixture f;
  const Layout& L = f.s.ctx.lay;
  ASSERT_EQ(L.segments, 4u);
  Bytes out;
  {  // reorder: swap segments 0 and 1 (same size)
    Bytes b = f.s.block;
    std::swap_ranges(b.begin() + L.seg_off(0), b.begin() + L.seg_off(0) + L.ct_len(0),
                     b.begin() + L.seg_off(1));
    EXPECT_FALSE(open_all(f.dek, f.meta, b, out).has_value());
    EXPECT_TRUE(all_zero(out));
  }
  {  // drop segment 1: later segments shift down, tail zero padded
    Bytes b = f.s.block;
    std::copy(b.begin() + L.seg_off(2), b.end(), b.begin() + L.seg_off(1));
    std::fill(b.end() - L.ct_len(1), b.end(), std::byte{0});
    EXPECT_FALSE(open_all(f.dek, f.meta, b, out).has_value());
    EXPECT_TRUE(all_zero(out));
  }
  {  // truncate by one byte: shorter than stored_len
    Bytes b = f.s.block;
    b.pop_back();
    auto gcm = GcmCtx::create();
    EXPECT_FALSE(open_begin(f.dek, f.meta, b).has_value());
  }
  {  // cleared `last`: final segment sealed with last = 0
    Bytes b = f.s.block;
    auto gcm = GcmCtx::create();
    const std::uint32_t i = L.segments - 1;
    const std::size_t seg = std::size_t{1} << 16;
    ASSERT_TRUE(gcm->seal(f.s.ctx.key, proto::stream_nonce(i, false), f.s.ctx.aad,
                          std::span<const std::byte>(f.pt).subspan(i * seg, L.pt_len(i)),
                          std::span<std::byte>(b).subspan(L.seg_off(i), L.ct_len(i)), nullptr).has_value());
    EXPECT_FALSE(open_all(f.dek, f.meta, b, out).has_value());
    EXPECT_TRUE(all_zero(out));
  }
}

TEST(BlockNegative, SaltAndTagFlips) {
  Fixture f;
  Bytes out;
  for (std::size_t pos : {std::size_t{16}, std::size_t{31}}) {  // header block_salt
    Bytes b = f.s.block;
    b[pos] ^= std::byte{0x80};
    EXPECT_FALSE(open_all(f.dek, f.meta, b, out).has_value());
    EXPECT_TRUE(all_zero(out));
  }
  const Layout& L = f.s.ctx.lay;
  for (std::uint32_t i : {0u, L.segments - 1}) {  // tag of first / last segment
    Bytes b = f.s.block;
    b[L.seg_off(i) + L.ct_len(i) - 1] ^= std::byte{1};
    EXPECT_FALSE(open_all(f.dek, f.meta, b, out).has_value());
    EXPECT_TRUE(all_zero(out));
  }
  Bytes b = f.s.block;  // ciphertext bit flip
  b[L.seg_off(1) + 100] ^= std::byte{1};
  EXPECT_FALSE(open_all(f.dek, f.meta, b, out).has_value());
  EXPECT_TRUE(all_zero(out));
}

// ---------------------------------------------------------------------------
// Nonce-reuse guard.

TEST(BlockNonce, AllZeroSourceFailsAtSealBegin) {
  ScriptedNonceSource ns(std::byte{0});
  Bytes hdr(64);
  auto r = seal_begin(test_dek(), test_meta(10, 16), ns, hdr);
  EXPECT_FALSE(r.has_value());
}

TEST(BlockNonce, RepeatingSourceFailsOnSecondSeal) {
  ScriptedNonceSource ns(std::byte{0x42});
  Bytes hdr(64);
  EXPECT_TRUE(seal_begin(test_dek(), test_meta(10, 16), ns, hdr).has_value());
  EXPECT_FALSE(seal_begin(test_dek(), test_meta(10, 16), ns, hdr).has_value());
}

TEST(BlockNonce, LedgerSeesNoSaltReuse) {
  SaltLedger ns;
  Bytes hdr(64);
  for (int i = 0; i < 500; ++i)
    ASSERT_TRUE(seal_begin(test_dek(), test_meta(10, 16), ns, hdr).has_value());
  EXPECT_FALSE(ns.duplicate);
  EXPECT_EQ(ns.seen.size(), 500u);
}

TEST(BlockNonce, SealBeginRejectsShortHeaderSpan) {
  SaltLedger ns;
  Bytes hdr(63);
  EXPECT_FALSE(seal_begin(test_dek(), test_meta(10, 16), ns, hdr).has_value());
}

}  // namespace
}  // namespace miracache
