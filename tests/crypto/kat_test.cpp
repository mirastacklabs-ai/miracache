// SPDX-License-Identifier: Apache-2.0
// Known-answer tests for the A1.5 S1 primitives. GCM vectors: McGrew & Viega, "The
// Galois/Counter Mode of Operation (GCM)", AES-256 test cases 13-16. HKDF vectors:
// RFC 5869 Appendix A.1-A.3. Registered a second time with hardware AES disabled
// (see tests/CMakeLists.txt) so both OpenSSL code paths are covered.
#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "crypto/gcm.h"
#include "crypto/hkdf.h"
#include "util/crc32c.h"
#include "util/nonce_source.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;

Bytes hex(const std::string& s) {
  Bytes out;
  auto nib = [](char c) { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
  for (std::size_t i = 0; i + 1 < s.size(); i += 2)
    out.push_back(static_cast<std::byte>(nib(s[i]) * 16 + nib(s[i + 1])));
  return out;
}

Bytes iota(int first, int last) {
  Bytes b;
  for (int i = first; i <= last; ++i) b.push_back(static_cast<std::byte>(i));
  return b;
}

BlockKey key_of(const Bytes& k) {
  EXPECT_EQ(k.size(), 32u);
  return BlockKey(std::span<const std::byte, 32>(k.data(), 32));
}

std::span<const std::byte, 12> nonce_of(const Bytes& n) {
  EXPECT_EQ(n.size(), 12u);
  return std::span<const std::byte, 12>(n.data(), 12);
}

// ---------------- HKDF (RFC 5869) ----------------

struct HkdfCase { Bytes ikm, salt, info; std::size_t len; std::string okm; };

TEST(Hkdf, Rfc5869Vectors) {
  const HkdfCase cases[] = {
      {Bytes(22, std::byte{0x0b}), iota(0, 12), iota(0xf0, 0xf9), 42,
       "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"},
      {iota(0x00, 0x4f), iota(0x60, 0xaf), iota(0xb0, 0xff), 82,
       "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c6"
       "5e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"},
      {Bytes(22, std::byte{0x0b}), {}, {}, 42,
       "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"},
  };
  for (const auto& c : cases) {
    Bytes okm(c.len);
    ASSERT_TRUE(hkdf_sha256(c.ikm, c.salt, c.info, okm).has_value());
    EXPECT_EQ(okm, hex(c.okm));
  }
}

TEST(Hkdf, RejectsBadLength) {
  Bytes none;
  Bytes big(255 * 32 + 1);
  EXPECT_FALSE(hkdf_sha256(Bytes(8), {}, {}, none).has_value());
  EXPECT_FALSE(hkdf_sha256(Bytes(8), {}, {}, big).has_value());
}

// Test-only NonceSource replaying fixed values.
class FixedSource final : public NonceSource {
 public:
  explicit FixedSource(std::vector<Bytes> v) : v_(std::move(v)) {}
 protected:
  Status fill(std::span<std::byte> out) override {
    const Bytes& b = v_[i_ < v_.size() ? i_ : v_.size() - 1];
    ++i_;
    std::memcpy(out.data(), b.data(), out.size());
    return {};
  }
 private:
  std::vector<Bytes> v_;
  std::size_t i_ = 0;
};

TEST(Hkdf, DeriveBlockKeyUsesInfoAndL32) {
  Bytes dek_b = iota(1, 32), salt_b = iota(0x40, 0x4f);
  Dek dek{std::span<const std::byte, 32>(dek_b.data(), 32)};
  FixedSource src({salt_b});
  auto salt = src.salt();
  ASSERT_TRUE(salt.has_value());
  auto key = derive_block_key(dek, *salt);
  ASSERT_TRUE(key.has_value());
  const char* info = "mira-blk-v1";
  Bytes expect(32);
  ASSERT_TRUE(hkdf_sha256(dek_b, salt_b, std::as_bytes(std::span<const char>(info, 11)), expect).has_value());
  EXPECT_EQ(Bytes(key->bytes().begin(), key->bytes().end()), expect);
  // A different salt gives a different key.
  Bytes salt2 = salt_b;
  salt2[0] = std::byte{0xee};
  FixedSource src2({salt2});
  auto key2 = derive_block_key(dek, *src2.salt());
  EXPECT_NE(Bytes(key->bytes().begin(), key->bytes().end()),
            Bytes(key2->bytes().begin(), key2->bytes().end()));
}

// ---------------- AES-256-GCM (McGrew-Viega TC13-16) ----------------

struct GcmCase { std::string name, k, iv, p, a, c, t; };

const char* kP64 =
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255";
const char* kK = "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308";

std::vector<GcmCase> gcm_cases() {
  const std::string zk(64, '0');
  return {
      {"TC13", zk, "000000000000000000000000", "", "", "", "530f8afbc74536b9a963b4f1c4cb738b"},
      {"TC14", zk, "000000000000000000000000", "00000000000000000000000000000000", "",
       "cea7403d4d606b6e074ec5d3baf39d18", "d0d1c8a799996bf0265b98b5d48ab919"},
      {"TC15", kK, "cafebabefacedbaddecaf888", kP64, "",
       "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
       "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
       "b094dac5d93471bdec1a502270e3cc6c"},
      {"TC16", kK, "cafebabefacedbaddecaf888", std::string(kP64).substr(0, 120),
       "feedfacedeadbeeffeedfacedeadbeefabaddad2",
       "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
       "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
       "76fc6ece0f4e1768cddf8853bb2d551b"},
  };
}

TEST(Gcm, McGrewViegaVectors) {
  auto g = GcmCtx::create();
  ASSERT_TRUE(g.has_value());
  for (const auto& c : gcm_cases()) {
    SCOPED_TRACE(c.name);
    BlockKey key = key_of(hex(c.k));
    Bytes iv = hex(c.iv), p = hex(c.p), a = hex(c.a);
    Bytes want = hex(c.c);
    Bytes t = hex(c.t);
    want.insert(want.end(), t.begin(), t.end());

    Bytes out(p.size() + 16);
    std::uint32_t crc = 0;
    ASSERT_TRUE(g->seal(key, nonce_of(iv), a, p, out, &crc).has_value());
    EXPECT_EQ(out, want);
    EXPECT_EQ(crc, crc32c(out));  // crc_io chains over ciphertext||tag

    Bytes back(p.size());
    ASSERT_TRUE(g->open_single_fetch(key, nonce_of(iv), a, want, back).has_value());
    EXPECT_EQ(back, p);
  }
}

TEST(Gcm, TamperingFailsAndZeroesOutput) {
  auto g = GcmCtx::create();
  const auto c = gcm_cases()[3];  // TC16 has AAD and a partial last block
  BlockKey key = key_of(hex(c.k));
  Bytes iv = hex(c.iv), p = hex(c.p), a = hex(c.a);
  Bytes sealed(p.size() + 16);
  ASSERT_TRUE(g->seal(key, nonce_of(iv), a, p, sealed, nullptr).has_value());

  auto expect_fail = [&](const Bytes& ct, const Bytes& aad, const Bytes& nonce, const char* what) {
    SCOPED_TRACE(what);
    Bytes out(p.size(), std::byte{0x55});
    auto st = g->open_single_fetch(key, nonce_of(nonce), aad, ct, out);
    ASSERT_FALSE(st.has_value());
    EXPECT_EQ(st.error().code, ErrorCode::Corrupt);
    EXPECT_EQ(out, Bytes(p.size(), std::byte{0}));
  };
  for (std::size_t i : {std::size_t{0}, p.size() - 1, p.size(), p.size() + 15}) {  // ct first/last, tag first/last
    Bytes bad = sealed;
    bad[i] ^= std::byte{0x01};
    expect_fail(bad, a, iv, "bit flip");
  }
  Bytes bad_aad = a;
  bad_aad[3] ^= std::byte{0x80};
  expect_fail(sealed, bad_aad, iv, "aad flip");
  Bytes bad_iv = iv;
  bad_iv[11] ^= std::byte{0x01};
  expect_fail(sealed, a, bad_iv, "nonce flip");
  Bytes truncated(sealed.begin(), sealed.end() - 1);
  Bytes out(p.size() - 1);
  EXPECT_FALSE(g->open_single_fetch(key, nonce_of(iv), a, truncated, out).has_value());
  // Wrong key.
  Bytes k2 = hex(c.k);
  k2[0] ^= std::byte{1};
  Bytes out2(p.size());
  EXPECT_FALSE(g->open_single_fetch(key_of(k2), nonce_of(iv), a, sealed, out2).has_value());
  // Still works afterwards (ctx reusable after failures).
  Bytes good(p.size());
  EXPECT_TRUE(g->open_single_fetch(key, nonce_of(iv), a, sealed, good).has_value());
  EXPECT_EQ(good, p);
}

struct HookState { Bytes* buf; std::size_t at; std::size_t target; std::size_t calls; };
void flip_hook(void* arg, std::size_t chunk) {
  auto* s = static_cast<HookState*>(arg);
  ++s->calls;
  if (chunk == s->at) (*s->buf)[s->target] ^= std::byte{0x01};
}

TEST(Gcm, SingleFetchChunking) {
  auto g = GcmCtx::create();
  BlockKey key = key_of(iota(1, 32));
  Bytes iv = iota(0, 11);
  const std::size_t n = 2 * kGcmChunk + 100;  // 3 chunks
  Bytes p(n);
  for (std::size_t i = 0; i < n; ++i) p[i] = static_cast<std::byte>(i * 7 + 3);
  Bytes sealed(n + 16);
  ASSERT_TRUE(g->seal(key, nonce_of(iv), {}, p, sealed, nullptr).has_value());

  {  // no mutation: hook called once per chunk, result exact
    Bytes remote = sealed, out(n);
    HookState s{&remote, 99, 0, 0};
    ASSERT_TRUE(g->open_single_fetch(key, nonce_of(iv), {}, remote, out, flip_hook, &s).has_value());
    EXPECT_EQ(s.calls, 3u);
    EXPECT_EQ(out, p);
  }
  {  // mutate an already-copied chunk (chunk 0 mutated while handling chunk 1): no effect
    Bytes remote = sealed, out(n);
    HookState s{&remote, 1, 5, 0};
    ASSERT_TRUE(g->open_single_fetch(key, nonce_of(iv), {}, remote, out, flip_hook, &s).has_value());
    EXPECT_EQ(out, p);
  }
  {  // mutate a not-yet-copied chunk: must fail
    Bytes remote = sealed, out(n);
    HookState s{&remote, 0, 2 * kGcmChunk + 1, 0};
    EXPECT_FALSE(g->open_single_fetch(key, nonce_of(iv), {}, remote, out, flip_hook, &s).has_value());
    EXPECT_EQ(out, Bytes(n, std::byte{0}));
  }
  {  // mutate the tag after it was read (tag is fetched first): no effect
    Bytes remote = sealed, out(n);
    HookState s{&remote, 0, n + 3, 0};
    ASSERT_TRUE(g->open_single_fetch(key, nonce_of(iv), {}, remote, out, flip_hook, &s).has_value());
    EXPECT_EQ(out, p);
  }
}

// ---------------- Secret / NonceSource ----------------

TEST(Secret, MoveCleansesSource) {
  Bytes raw = iota(1, 32);
  Secret<32> a{std::span<const std::byte, 32>(raw.data(), 32)};
  Secret<32> b(std::move(a));
  EXPECT_TRUE(std::equal(raw.begin(), raw.end(), b.bytes().begin()));
  for (auto x : std::as_const(a).bytes()) EXPECT_EQ(x, std::byte{0});  // NOLINT(bugprone-use-after-move)
  Secret<32> c;
  c = std::move(b);
  EXPECT_TRUE(std::equal(raw.begin(), raw.end(), c.bytes().begin()));
  for (auto x : std::as_const(b).bytes()) EXPECT_EQ(x, std::byte{0});
  static_assert(!std::is_copy_constructible_v<Secret<32>>);
  static_assert(!std::is_copy_assignable_v<Secret<32>>);
}

TEST(NonceSource, RejectsZeroAndRepeat) {
  FixedSource zero({Bytes(16, std::byte{0})});
  auto z = zero.salt();
  ASSERT_FALSE(z.has_value());
  EXPECT_EQ(z.error().code, ErrorCode::Corrupt);

  FixedSource stuck({Bytes(16, std::byte{7})});
  EXPECT_TRUE(stuck.salt().has_value());
  auto r = stuck.salt();
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, ErrorCode::Corrupt);

  FixedSource ok({Bytes(16, std::byte{1}), Bytes(16, std::byte{2}), Bytes(16, std::byte{1})});
  EXPECT_TRUE(ok.salt().has_value());
  EXPECT_TRUE(ok.salt().has_value());
  EXPECT_TRUE(ok.salt().has_value());  // non-adjacent repeat is allowed
}

TEST(NonceSource, OsSourceGivesDistinctNonZeroSalts) {
  OsNonceSource os;
  auto a = os.salt();
  auto b = os.salt();
  ASSERT_TRUE(a.has_value());
  ASSERT_TRUE(b.has_value());
  EXPECT_NE(a->b, b->b);
  EXPECT_NE(a->b, (std::array<std::byte, 16>{}));
}

}  // namespace
}  // namespace miracache
