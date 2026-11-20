// SPDX-License-Identifier: Apache-2.0
// Test-only signer for the bundle envelope, written directly against OpenSSL EVP (not the
// library under test) so the goldens are produced independently. Test seeds (membership plan,
// MB2 row): publish key seed bytes 0x01..0x20, security key seed bytes 0x21..0x40.
#pragma once

#include <openssl/evp.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace miracache::control::testutil {

using Seed = std::array<std::uint8_t, 32>;

inline Seed seed_from(std::uint8_t first) {
  Seed s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(first + i);
  return s;
}
inline Seed publish_seed() { return seed_from(0x01); }
inline Seed security_seed() { return seed_from(0x21); }

inline std::string hex(const std::uint8_t* p, std::size_t n) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (std::size_t i = 0; i < n; ++i) {
    s.push_back(d[p[i] >> 4]);
    s.push_back(d[p[i] & 15]);
  }
  return s;
}

inline std::array<std::uint8_t, 32> public_key(const Seed& seed) {
  EVP_PKEY* pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
  std::array<std::uint8_t, 32> pub{};
  std::size_t n = pub.size();
  if (!pk || EVP_PKEY_get_raw_public_key(pk, pub.data(), &n) != 1 || n != 32) std::abort();
  EVP_PKEY_free(pk);
  return pub;
}

inline std::array<std::uint8_t, 64> sign(const Seed& seed, const std::string& msg) {
  EVP_PKEY* pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size());
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  std::array<std::uint8_t, 64> sig{};
  std::size_t n = sig.size();
  if (!pk || !ctx || EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, pk) != 1 ||
      EVP_DigestSign(ctx, sig.data(), &n, reinterpret_cast<const unsigned char*>(msg.data()), msg.size()) != 1 ||
      n != 64) {
    std::abort();
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pk);
  return sig;
}

inline std::array<std::uint8_t, 32> sha256(const std::string& s) {
  std::array<std::uint8_t, 32> d{};
  unsigned int n = 0;
  if (EVP_Digest(s.data(), s.size(), d.data(), &n, EVP_sha256(), nullptr) != 1 || n != 32) std::abort();
  return d;
}

inline std::string key_id_hex(const Seed& seed) {
  const auto pub = public_key(seed);
  const auto d = sha256(std::string(reinterpret_cast<const char*>(pub.data()), pub.size()));
  return hex(d.data(), 8);
}

// Trust file with one publish-only and one security-only key.
inline std::string trust_toml(bool single_key_both_roles = false, const std::string& top = "") {
  const auto p = public_key(publish_seed());
  const auto s = public_key(security_seed());
  std::string t = top;
  if (single_key_both_roles) {
    t += "[[key]]\npublic = \"" + hex(p.data(), 32) + "\"\nroles = [\"publish\", \"security\"]\n";
    return t;
  }
  t += "[[key]]\npublic = \"" + hex(p.data(), 32) + "\"\nroles = [\"publish\"]\n\n";
  t += "[[key]]\npublic = \"" + hex(s.data(), 32) + "\"\nroles = [\"security\"]\n";
  return t;
}

inline std::string sec_toml(std::uint64_t sec_generation = 5, const std::string& drop_before = "") {
  std::string s = "sec_generation = " + std::to_string(sec_generation) + "\n\n";
  s += "[[principals]]\nname = \"prod-llama\"\nidentities = [\"spiffe://prod/vllm-host-1\"]\n";
  s += "quota_bytes = 2199023255552\nmax_scopes = 4000000\n";
  if (!drop_before.empty()) s += "drop_before = \"" + drop_before + "\"\n";
  s += "\n[[principals]]\nname = \"lab\"\nidentities = [\"spiffe://lab/client\"]\nquota_bytes = 1073741824\nmax_scopes = 1000\n\n";
  s += "[[rbac]]\nidentity = \"spiffe://ops/alice\"\nroles = [\"security-admin\"]\n";
  return s;
}

inline std::string body_toml(std::uint64_t generation = 42, std::uint32_t epoch = 7, std::uint32_t previous_epoch = 6,
                             const std::string& extra_config = "") {
  std::string b = "schema_version = 1\ngeneration = " + std::to_string(generation) + "\n";
  b += "created_at = \"2026-11-12T09:00:00Z\"\nauthor = \"spiffe://ops/alice\"\nreason = \"add hostD\"\n\n";
  b += "[membership]\nepoch = " + std::to_string(epoch) + "\nprevious_epoch = " + std::to_string(previous_epoch) + "\n\n";
  b += "[[membership.nodes]]\nnode_id = 3141592653\nhostname = \"hostA\"\nadmin = \"10.0.0.10:9465\"\n";
  b += "rails = [{ addr = \"10.0.0.10:7471\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }]\nweight = 1\nzone = \"rack1\"\nstate = \"active\"\n\n";
  b += "[[membership.nodes]]\nnode_id = 7\nhostname = \"hostB\"\nadmin = \"10.0.0.11:9465\"\n";
  b += "rails = [{ addr = \"10.0.0.11:7471\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }, { addr = \"10.1.0.11:7471\", subnet = \"10.1.0.0/24\", protocol = \"roce\" }]\n";
  b += "weight = 2\nzone = \"rack2\"\nstate = \"draining\"\n\n";
  b += "[[membership.previous]]\nnode_id = 3141592653\nweight = 1\nzone = \"rack1\"\n\n";
  b += "[config.cluster.placement]\nreplicas = 2\n\n[config.cluster.memnode]\nlog_level = \"info\"\n";
  b += extra_config;
  return b;
}

struct Parts {
  std::string magic = "mira-bundle-v1";
  std::string key_id;
  std::string sig;
  std::string sec_key_id;
  std::string sec_sig;
  std::string sec_len;
  std::string sec;
  std::string body;
};

inline std::string u32be(std::uint32_t n) {
  std::string s(4, '\0');
  s[0] = static_cast<char>(n >> 24);
  s[1] = static_cast<char>(n >> 16);
  s[2] = static_cast<char>(n >> 8);
  s[3] = static_cast<char>(n);
  return s;
}

// Signs `sec` and `body` per decision 2. `len_in_signature` overrides the u32be value (rule 6 tests).
inline Parts sign_parts(const std::string& sec, const std::string& body, const Seed& pub_seed = publish_seed(),
                        const Seed& sec_seed = security_seed(), std::int64_t len_in_signature = -1) {
  Parts p;
  p.sec = sec;
  p.body = body;
  p.key_id = key_id_hex(pub_seed);
  p.sec_key_id = key_id_hex(sec_seed);
  p.sec_len = std::to_string(sec.size());
  const std::uint32_t n = len_in_signature < 0 ? static_cast<std::uint32_t>(sec.size()) : static_cast<std::uint32_t>(len_in_signature);
  const std::string domain("mira-bundle-v1\0", 15);
  const auto sig = sign(pub_seed, domain + u32be(n) + sec + body);
  p.sig = hex(sig.data(), sig.size());
  const std::string sdomain("mira-bundle-sec-v1\0", 19);
  const auto ssig = sign(sec_seed, sdomain + sec);
  p.sec_sig = hex(ssig.data(), ssig.size());
  return p;
}

inline std::string assemble(const Parts& p) {
  return p.magic + "\nkey_id: " + p.key_id + "\nsig: " + p.sig + "\nsec_key_id: " + p.sec_key_id +
         "\nsec_sig: " + p.sec_sig + "\nsec_len: " + p.sec_len + "\n\n" + p.sec + p.body;
}

inline std::string make_envelope(const std::string& sec = sec_toml(), const std::string& body = body_toml()) {
  return assemble(sign_parts(sec, body));
}

inline bool read_file(const std::string& path, std::string& out) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return false;
  out.assign(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
  return true;
}

}  // namespace miracache::control::testutil
