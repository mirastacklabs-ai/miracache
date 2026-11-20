// SPDX-License-Identifier: Apache-2.0
// L6: engine-native KeySource (spec rev 5.1 §2.6). The known-answer values are pinned as hex
// literals AND recomputed in the test from scratch with raw OpenSSL calls (EVP_PKEY HKDF,
// one-shot HMAC, SHA256) using only the documented labels, so the KATs do not rely on the
// production code path.
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "crypto/block_codec.h"
#include "crypto/hmac.h"
#include "scope/engine_native.h"
#include "util/nonce_source.h"

using namespace miracache;

namespace {

using B = std::vector<std::byte>;
using U = std::vector<unsigned char>;

B bytes_of(const std::string& s) {
  B b(s.size());
  for (std::size_t i = 0; i < s.size(); ++i) b[i] = static_cast<std::byte>(s[i]);
  return b;
}
U ubytes_of(const std::string& s) { return U(s.begin(), s.end()); }

template <typename Arr>
std::string hex(const Arr& a) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (auto c : a) {
    auto v = static_cast<unsigned>(static_cast<unsigned char>(c));
    s += d[v >> 4];
    s += d[v & 15];
  }
  return s;
}
std::string hex_of(std::span<const std::byte> a) { return hex(a); }

// ---- independent reference implementations (raw OpenSSL, no production code) ----
U ref_hkdf(const U& ikm, const U& salt, const U& info) {
  EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  U out(32);
  size_t n = 32;
  EXPECT_EQ(EVP_PKEY_derive_init(c), 1);
  EXPECT_EQ(EVP_PKEY_CTX_set_hkdf_md(c, EVP_sha256()), 1);
  static const unsigned char z = 0;
  EXPECT_EQ(EVP_PKEY_CTX_set1_hkdf_salt(c, salt.empty() ? &z : salt.data(), (int)salt.size()), 1);
  EXPECT_EQ(EVP_PKEY_CTX_set1_hkdf_key(c, ikm.data(), (int)ikm.size()), 1);
  EXPECT_EQ(EVP_PKEY_CTX_add1_hkdf_info(c, info.empty() ? &z : info.data(), (int)info.size()), 1);
  EXPECT_EQ(EVP_PKEY_derive(c, out.data(), &n), 1);
  EVP_PKEY_CTX_free(c);
  return out;
}
U ref_hmac(const U& key, const U& msg) {
  U out(32);
  unsigned int n = 0;
  HMAC(EVP_sha256(), key.data(), (int)key.size(), msg.data(), msg.size(), out.data(), &n);
  return out;
}
U cat(std::initializer_list<U> parts) {
  U o;
  for (auto& p : parts) o.insert(o.end(), p.begin(), p.end());
  return o;
}
// ns is 32 opaque bytes to the core (computed by the adapters: python/miracache/ns.py). Two
// fixed test values; they are the bytes the retired C++ encoder gave for a vLLM and an SGLang
// field set, kept so every pinned KAT below is unchanged.
Hash256 ns_of(const char* h64) {
  Hash256 h{};
  for (std::size_t i = 0; i < 32; ++i)
    h[i] = static_cast<std::uint8_t>(std::stoi(std::string(h64 + 2 * i, 2), nullptr, 16));
  return h;
}
const Hash256 kNsA = ns_of("6bb5441dd21e7a74ab0f038107228616e5665168079c49cdd3e289a6447847e7");
const Hash256 kNsB = ns_of("7262fd875ebb350bbdd7bfad4ef1af296881ecd3f16ef42636818378b664e576");

constexpr char kS1Hex[] = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
constexpr char kS2Hex[] = "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf";

U unhex(const std::string& h) {
  U o;
  for (std::size_t i = 0; i + 1 < h.size(); i += 2) o.push_back((unsigned char)std::stoi(h.substr(i, 2), nullptr, 16));
  return o;
}
Secret<32> secret_from_hex(const std::string& h) {
  U u = unhex(h);
  std::array<std::byte, 32> a;
  for (int i = 0; i < 32; ++i) a[i] = (std::byte)u[i];
  return Secret<32>(std::span<const std::byte, 32>(a));
}

struct TmpDir {
  std::string dir;
  TmpDir() {
    char t[] = "/tmp/mira_en_XXXXXX";
    dir = mkdtemp(t);
  }
  ~TmpDir() {
    std::string c = "rm -rf " + dir;
    int rc = std::system(c.c_str());
    (void)rc;
  }
  std::string write(const std::string& name, const std::string& body, mode_t mode = 0600) {
    std::string p = dir + "/" + name;
    { std::ofstream(p) << body; }
    chmod(p.c_str(), mode);
    return p;
  }
};

std::string secret_text(std::uint32_t current, bool k1 = true, bool k2 = true) {
  std::string s = "# test\ncurrent = " + std::to_string(current) + "\n";
  if (k1) s += std::string("1 = ") + kS1Hex + "\n";
  if (k2) s += std::string("2 = ") + kS2Hex + "\n";
  return s;
}

EngineNativeProvider provider_for(std::uint32_t current) {
  SecretSet set;
  set.secrets.emplace(1, secret_from_hex(kS1Hex));
  set.secrets.emplace(2, secret_from_hex(kS2Hex));
  set.current = current;
  auto p = EngineNativeProvider::create(set);
  EXPECT_TRUE(p.has_value());
  return std::move(*p);
}

const B kRoot = bytes_of("root-key-chunk0");
const B kRaw = bytes_of("raw-key-block-7");

}  // namespace

// ---- HMAC helper ----
TEST(Hmac, Rfc4231Case1) {
  std::array<std::byte, 20> key;
  key.fill(std::byte{0x0b});
  const B msg = bytes_of("Hi There");
  std::array<std::byte, 32> out;
  const std::span<const std::byte> parts[] = {msg};
  ASSERT_TRUE(hmac_sha256(key, parts, out).has_value());
  EXPECT_EQ(hex(out), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
}

TEST(Hmac, PartsAreConcatenated) {
  const B key = bytes_of("k");
  const B a = bytes_of("ab"), b = bytes_of("cd"), ab = bytes_of("abcd");
  std::array<std::byte, 32> o1, o2;
  const std::span<const std::byte> p1[] = {a, b};
  const std::span<const std::byte> p2[] = {ab};
  ASSERT_TRUE(hmac_sha256(key, p1, o1).has_value());
  ASSERT_TRUE(hmac_sha256(key, p2, o2).has_value());
  EXPECT_EQ(o1, o2);
}

// ---- ns ----
// The encoding and its golden vectors are tests/python/test_ns.py; here only the log helper.
TEST(Ns, Fingerprint) {
  EXPECT_EQ(ns_fingerprint(kNsA), "6bb5441d");
  EXPECT_EQ(ns_fingerprint(kNsA), hex(kNsA).substr(0, 8));
}

// ---- subkeys, scope_id, key_hash, DEK_k ----
struct Derived {
  U s_scope, s_key, s_dek, scope, key_hash, dek;
};
Derived reference(const U& S, const Hash256& ns, const B& root, const B& raw) {
  Derived d;
  d.s_scope = ref_hkdf(S, {}, ubytes_of("mira-sub-scope"));
  d.s_key = ref_hkdf(S, {}, ubytes_of("mira-sub-key"));
  d.s_dek = ref_hkdf(S, {}, ubytes_of("mira-sub-dek"));
  U nsu(ns.begin(), ns.end());
  U rootu((const unsigned char*)root.data(), (const unsigned char*)root.data() + root.size());
  U rawu((const unsigned char*)raw.data(), (const unsigned char*)raw.data() + raw.size());
  d.scope = ref_hkdf(d.s_scope, nsu, cat({ubytes_of("mira-scope-nat-v1"), rootu}));
  d.dek = ref_hkdf(d.s_dek, nsu, cat({ubytes_of("mira-dek-nat-v1"), rawu}));
  d.key_hash = ref_hmac(d.s_key, cat({ubytes_of("mira-key-v1"), nsu, rawu}));
  return d;
}

TEST(EngineNative, MatchesIndependentReference) {
  const Hash256 ns = kNsA;
  const Secret<32> S = secret_from_hex(kS1Hex);
  auto sk = derive_subkeys(S);
  ASSERT_TRUE(sk.has_value());
  const Derived ref = reference(unhex(kS1Hex), ns, kRoot, kRaw);
  EXPECT_EQ(hex_of(sk->scope.bytes()), hex(ref.s_scope));
  EXPECT_EQ(hex_of(sk->key.bytes()), hex(ref.s_key));
  EXPECT_EQ(hex_of(sk->dek.bytes()), hex(ref.s_dek));

  EngineNativeProvider p = provider_for(1);
  auto sid = p.scope_id(ns, kRoot);
  ASSERT_TRUE(sid.has_value());
  EXPECT_EQ(hex(sid->b), hex(ref.scope));
  EngineNativeKeySource ks(*sk, ns);
  auto kh = ks.key_hash(kRaw);
  ASSERT_TRUE(kh.has_value());
  EXPECT_EQ(hex(kh->b), hex(ref.key_hash));
  auto dek = ks.dek_for(kRaw);
  ASSERT_TRUE(dek.has_value());
  EXPECT_EQ(hex_of(dek->bytes()), hex(ref.dek));
}

TEST(EngineNative, PinnedVectors) {
  const Hash256 ns = kNsA;
  const Secret<32> S = secret_from_hex(kS1Hex);
  auto sk = derive_subkeys(S);
  ASSERT_TRUE(sk.has_value());
  EXPECT_EQ(hex_of(sk->scope.bytes()), "cf2ad9c901c8510191f5b379ffed341547eab1b8c3dc31b5e0e8dfd84f6604c8");
  EXPECT_EQ(hex_of(sk->key.bytes()), "2fe3308a0afd0ddbdc8d54c8ef615db1e2f28e168734b65831ec028570c8bf37");
  EXPECT_EQ(hex_of(sk->dek.bytes()), "e4c3e864a3b9286b9f504b104e781d855a9ceef373f4aaa1020a20045bb798eb");
  EngineNativeProvider p = provider_for(1);
  EXPECT_EQ(hex(p.scope_id(ns, kRoot)->b), "2819dd7a106be1eb7ac2119376a26d5b763b4a27b443e37034b80f96f18919e5");
  EngineNativeKeySource ks(*sk, ns);
  EXPECT_EQ(hex(ks.key_hash(kRaw)->b), "89ac706b9dae2f80d6b48c0951b5ccf4b41d5459f68488c355812df9152dbdbb");
  EXPECT_EQ(hex_of(ks.dek_for(kRaw)->bytes()), "3243ba8372d57de708efa4bb4d3df6c8da1348b4d0e7f9de4eb52d9453e7d1ca");
}

TEST(EngineNative, ThreeSubkeysAndOutputsAreDistinct) {
  const Hash256 ns = kNsA;
  EngineNativeProvider p = provider_for(1);
  auto sk = derive_subkeys(secret_from_hex(kS1Hex));
  EngineNativeKeySource ks(*sk, ns);
  const B same = bytes_of("same-bytes");
  std::set<std::string> v{hex_of(sk->scope.bytes()), hex_of(sk->key.bytes()), hex_of(sk->dek.bytes()),
                          hex(p.scope_id(ns, same)->b), hex(ks.key_hash(same)->b),
                          hex_of(ks.dek_for(same)->bytes())};
  EXPECT_EQ(v.size(), 6u);  // scope != DEK != key_hash even for identical input bytes
}

TEST(EngineNative, AnyNsChangeChangesEverythingDownstream) {
  EngineNativeProvider p = provider_for(1);
  auto sk = derive_subkeys(secret_from_hex(kS1Hex));
  const Hash256 ns0 = kNsB;
  EngineNativeKeySource k0(*sk, ns0);
  Hash256 ns1 = kNsB;
  ns1[31] ^= 1;  // one bit
  EngineNativeKeySource k1(*sk, ns1);
  EXPECT_NE(hex(p.scope_id(ns0, kRoot)->b), hex(p.scope_id(ns1, kRoot)->b));
  EXPECT_NE(hex(k0.key_hash(kRaw)->b), hex(k1.key_hash(kRaw)->b));
  EXPECT_NE(hex_of(k0.dek_for(kRaw)->bytes()), hex_of(k1.dek_for(kRaw)->bytes()));
}

TEST(EngineNative, DifferentRawKeysNeverShareDek) {
  const Hash256 ns = kNsA;
  auto sk = derive_subkeys(secret_from_hex(kS1Hex));
  EngineNativeKeySource ks(*sk, ns);
  std::set<std::string> deks, hashes;
  for (int i = 0; i < 64; ++i) {
    B raw = bytes_of("raw-key-" + std::to_string(i));
    EXPECT_TRUE(deks.insert(hex_of(ks.dek_for(raw)->bytes())).second);
    EXPECT_TRUE(hashes.insert(hex(ks.key_hash(raw)->b)).second);
  }
  // Prefix relation: a key and its extension (chain parent vs child) differ too.
  EXPECT_NE(hex_of(ks.dek_for(bytes_of("a"))->bytes()), hex_of(ks.dek_for(bytes_of("ab"))->bytes()));
}

TEST(EngineNative, KverChangeIsColdCache) {
  const Hash256 ns = kNsA;
  EngineNativeProvider p1 = provider_for(1), p2 = provider_for(2);
  EXPECT_EQ(p1.kver(), 1u);
  EXPECT_EQ(p2.kver(), 2u);
  EXPECT_NE(hex(p1.scope_id(ns, kRoot)->b), hex(p2.scope_id(ns, kRoot)->b));
  RequestMeta m{EngineKind::Vllm, ns, {kRoot}};
  auto a = p1.derive(m), b = p2.derive(m);
  ASSERT_TRUE(a.has_value() && b.has_value());
  EXPECT_EQ(a->kver, 1u);
  EXPECT_EQ(b->kver, 2u);
  EXPECT_NE(hex(a->keys->key_hash(kRaw)->b), hex(b->keys->key_hash(kRaw)->b));
  EXPECT_NE(hex_of(a->keys->dek_for(kRaw)->bytes()), hex_of(b->keys->dek_for(kRaw)->bytes()));
}

TEST(EngineNative, DerivePerGroupRoots) {
  const Hash256 ns = kNsA;
  EngineNativeProvider p = provider_for(1);
  RequestMeta m{EngineKind::Vllm, ns, {bytes_of("g0"), bytes_of("g1"), bytes_of("g2")}};
  auto k = p.derive(m);
  ASSERT_TRUE(k.has_value());
  ASSERT_EQ(k->scopes.size(), 3u);
  std::set<std::string> s;
  for (std::size_t g = 0; g < 3; ++g) {
    EXPECT_EQ(hex(k->scopes[g].b), hex(p.scope_id(ns, m.roots[g])->b));
    s.insert(hex(k->scopes[g].b));
  }
  EXPECT_EQ(s.size(), 3u);
  // Deterministic.
  EXPECT_EQ(hex(p.derive(m)->scopes[1].b), hex(k->scopes[1].b));
  // Two different salts (different roots) share no scope.
  RequestMeta m2{EngineKind::Vllm, ns, {bytes_of("g0-salted")}};
  EXPECT_NE(hex(p.derive(m2)->scopes[0].b), hex(k->scopes[0].b));
  // No roots / empty root: skip L3.
  EXPECT_FALSE(p.derive(RequestMeta{EngineKind::Vllm, ns, {}}).has_value());
  EXPECT_FALSE(p.derive(RequestMeta{EngineKind::Vllm, ns, {bytes_of("x"), {}}}).has_value());
}

// ---- secret file ----
TEST(SecretFile, LoadsAndSelectsCurrent) {
  TmpDir d;
  auto set = load_secret_file(d.write("s", secret_text(2)));
  ASSERT_TRUE(set.has_value());
  EXPECT_EQ(set->current, 2u);
  EXPECT_EQ(set->secrets.size(), 2u);
  auto p = EngineNativeProvider::from_file(d.dir + "/s");
  ASSERT_TRUE(p.has_value());
  EXPECT_EQ(p->kver(), 2u);
  const Hash256 ns = kNsA;
  EXPECT_EQ(hex(p->scope_id(ns, kRoot)->b), hex(provider_for(2).scope_id(ns, kRoot)->b));
}

// Shared with tests/python/test_preflight.py (preflight must accept exactly what this loader accepts).
TEST(SecretFile, SharedGoldenFixture) {
  std::string src = __FILE__;
  src = src.substr(0, src.rfind("/client/")) + "/../proto/golden/secret_golden.txt";
  std::ifstream in(src, std::ios::binary);
  ASSERT_TRUE(in.good()) << src;
  std::string body((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  TmpDir d;
  auto set = load_secret_file(d.write("golden", body));
  ASSERT_TRUE(set.has_value());
  EXPECT_EQ(set->current, 2u);
  EXPECT_EQ(set->secrets.size(), 3u);
  EXPECT_TRUE(set->secrets.count(1) && set->secrets.count(2) && set->secrets.count(7));
}

TEST(SecretFile, Errors) {
  TmpDir d;
  auto code = [](const Expected<SecretSet>& e) { return e.has_value() ? 255 : (int)e.error().code; };
  EXPECT_EQ(code(load_secret_file(d.dir + "/missing")), (int)ErrorCode::NotFound);
  EXPECT_EQ(code(load_secret_file(d.write("m640", secret_text(1), 0640))), (int)ErrorCode::AccessDenied);
  EXPECT_EQ(code(load_secret_file(d.write("m400", secret_text(1), 0400))), (int)ErrorCode::AccessDenied);
  // wrong length: 31 bytes, 33 bytes, empty
  EXPECT_EQ(code(load_secret_file(d.write("short", "current = 1\n1 = " + std::string(kS1Hex).substr(2) + "\n"))),
            (int)ErrorCode::InvalidArgument);
  EXPECT_EQ(code(load_secret_file(d.write("long", "current = 1\n1 = " + std::string(kS1Hex) + "00\n"))),
            (int)ErrorCode::InvalidArgument);
  EXPECT_EQ(code(load_secret_file(d.write("empty", "current = 1\n1 =\n"))), (int)ErrorCode::InvalidArgument);
  // unknown current kver
  EXPECT_EQ(code(load_secret_file(d.write("cur3", secret_text(3)))), (int)ErrorCode::NotFound);
  EXPECT_EQ(code(load_secret_file(d.write("cur2only1", secret_text(2, true, false)))), (int)ErrorCode::NotFound);
  // other malformations
  EXPECT_EQ(code(load_secret_file(d.write("nocur", std::string("1 = ") + kS1Hex + "\n"))), (int)ErrorCode::InvalidArgument);
  EXPECT_EQ(code(load_secret_file(d.write("nonhex", "current = 1\n1 = " + std::string(64, 'z') + "\n"))), (int)ErrorCode::InvalidArgument);
  EXPECT_EQ(code(load_secret_file(d.write("dup", secret_text(1) + "1 = " + kS2Hex + "\n"))), (int)ErrorCode::InvalidArgument);
  EXPECT_EQ(code(load_secret_file(d.write("zero", "current = 0\n0 = " + std::string(kS1Hex) + "\n"))), (int)ErrorCode::InvalidArgument);
  EXPECT_EQ(code(load_secret_file(d.write("junk", "current = 1\nhello\n"))), (int)ErrorCode::InvalidArgument);
  // Provider creation also rejects an unknown current.
  SecretSet set;
  set.secrets.emplace(1, secret_from_hex(kS1Hex));
  set.current = 9;
  EXPECT_FALSE(EngineNativeProvider::create(set).has_value());
}

// ---- crypto integration ----
TEST(EngineNative, DekPlugsIntoBlockCodec) {
  const Hash256 ns = kNsA;
  EngineNativeProvider p = provider_for(1);
  RequestMeta rm{EngineKind::Vllm, ns, {kRoot}};
  auto sk = p.derive(rm);
  ASSERT_TRUE(sk.has_value());
  auto dek = sk->keys->dek_for(kRaw);
  ASSERT_TRUE(dek.has_value());

  BlockMeta meta{};
  meta.kver = sk->kver;
  std::memcpy(meta.scope_id.b, sk->scopes[0].b, 32);
  auto kh = sk->keys->key_hash(kRaw);
  std::memcpy(meta.key_hash.b, kh->b, 32);
  meta.plaintext_len = 70000;
  meta.segment_log2 = 16;

  B pt(meta.plaintext_len);
  for (std::size_t i = 0; i < pt.size(); ++i) pt[i] = (std::byte)((i * 13 + 5) & 0xff);
  auto lay = layout(meta.plaintext_len, meta.segment_log2);
  ASSERT_TRUE(lay.has_value());
  B block(lay->stored_len);
  OsNonceSource nonces;
  auto sc = seal_begin(*dek, meta, nonces, std::span<std::byte>(block).first(64));
  ASSERT_TRUE(sc.has_value());
  auto gcm = GcmCtx::create();
  ASSERT_TRUE(gcm.has_value());
  for (std::uint32_t i = 0; i < sc->lay.segments; ++i) {
    std::uint32_t crc = 0;
    const std::uint64_t seg = 1ull << meta.segment_log2;
    ASSERT_TRUE(seal_segment(*gcm, *sc, i, std::span<const std::byte>(pt).subspan(i * seg, sc->lay.pt_len(i)),
                             block, &crc).has_value());
  }
  B out(pt.size());
  auto oc = open_begin(*dek, meta, block);
  ASSERT_TRUE(oc.has_value());
  ASSERT_TRUE(open_block(*gcm, *oc, block, out).has_value());
  EXPECT_EQ(out, pt);

  // A different raw key's DEK cannot open it.
  auto other = sk->keys->dek_for(bytes_of("another-raw-key"));
  auto oc2 = open_begin(*other, meta, block);
  if (oc2.has_value()) {
    B out2(pt.size());
    EXPECT_FALSE(open_block(*gcm, *oc2, block, out2).has_value());
  }
}
