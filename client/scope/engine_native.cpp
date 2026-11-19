// SPDX-License-Identifier: Apache-2.0
#include "scope/engine_native.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <memory>
#include <string_view>

#include "crypto/hkdf.h"
#include "crypto/hmac.h"
#include "miracache/config.h"  // check_secret_file

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;

Error bad(const char* ctx) { return Error{ErrorCode::InvalidArgument, ctx}; }

std::span<const std::byte> as_bytes_sv(std::string_view s) {
  return std::as_bytes(std::span<const char>(s.data(), s.size()));
}
std::span<const std::byte> ns_span(const Hash256& ns) {
  return std::as_bytes(std::span<const std::uint8_t, 32>(ns));
}

// HKDF-SHA256(ikm, salt, info = label || tail), L = 32.
Status hkdf32(std::span<const std::byte> ikm, std::span<const std::byte> salt,
              std::string_view label, std::span<const std::byte> tail, std::span<std::byte, 32> out) {
  Bytes info;
  info.reserve(label.size() + tail.size());
  auto l = as_bytes_sv(label);
  info.insert(info.end(), l.begin(), l.end());
  info.insert(info.end(), tail.begin(), tail.end());
  return hkdf_sha256(ikm, salt, info, out);
}

int hexval(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

std::string_view trim(std::string_view s) {
  while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.remove_prefix(1);
  while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
  return s;
}

bool parse_u32(std::string_view s, std::uint32_t* out) {
  if (s.empty() || s.size() > 10) return false;
  std::uint64_t v = 0;
  for (char c : s) {
    if (c < '0' || c > '9') return false;
    v = v * 10 + static_cast<std::uint64_t>(c - '0');
  }
  if (v > 0xffffffffull) return false;
  *out = static_cast<std::uint32_t>(v);
  return true;
}

}  // namespace

std::string ns_fingerprint(const Hash256& ns) {
  char buf[9];
  std::snprintf(buf, sizeof buf, "%02x%02x%02x%02x", ns[0], ns[1], ns[2], ns[3]);
  return buf;
}

Expected<SecretSet> load_secret_file(const std::string& path) {
  Status chk = check_secret_file(path);
  if (!chk) return chk.error();
  std::ifstream in(path, std::ios::binary);
  if (!in) return Error{ErrorCode::NotFound, "secret: cannot open file"};
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  struct Wipe {
    std::string& s;
    ~Wipe() { OPENSSL_cleanse(s.data(), s.size()); }
  } wipe{text};

  SecretSet set;
  bool have_current = false;
  std::size_t pos = 0;
  while (pos <= text.size()) {
    std::size_t nl = text.find('\n', pos);
    if (nl == std::string::npos) nl = text.size();
    std::string_view line = trim(std::string_view(text).substr(pos, nl - pos));
    pos = nl + 1;
    if (line.empty() || line.front() == '#') continue;
    const std::size_t eq = line.find('=');
    if (eq == std::string_view::npos) return bad("secret: line without '='");
    std::string_view k = trim(line.substr(0, eq));
    std::string_view v = trim(line.substr(eq + 1));
    if (k == "current") {
      if (have_current) return bad("secret: duplicate current");
      if (!parse_u32(v, &set.current) || set.current == 0) return bad("secret: bad current");
      have_current = true;
      continue;
    }
    std::uint32_t kver = 0;
    if (!parse_u32(k, &kver) || kver == 0) return bad("secret: bad kver");
    if (v.size() != 64) return bad("secret: S must be exactly 32 bytes (64 hex chars)");
    std::array<std::byte, 32> raw{};
    for (std::size_t i = 0; i < 32; ++i) {
      int hi = hexval(v[2 * i]), lo = hexval(v[2 * i + 1]);
      if (hi < 0 || lo < 0) {
        OPENSSL_cleanse(raw.data(), raw.size());
        return bad("secret: S is not hex");
      }
      raw[i] = static_cast<std::byte>(hi * 16 + lo);
    }
    const bool inserted =
        set.secrets.emplace(kver, Secret<32>(std::span<const std::byte, 32>(raw))).second;
    OPENSSL_cleanse(raw.data(), raw.size());
    if (!inserted) return bad("secret: duplicate kver");
  }
  if (!have_current) return bad("secret: missing current");
  if (set.secrets.find(set.current) == set.secrets.end())
    return Error{ErrorCode::NotFound, "secret: current kver has no secret"};
  return set;
}

Expected<Subkeys> derive_subkeys(const Secret<32>& s) {
  Subkeys sk;
  const std::span<const std::byte> none;
  if (Status st = hkdf32(s.bytes(), none, "mira-sub-scope", none, sk.scope.bytes()); !st) return st.error();
  if (Status st = hkdf32(s.bytes(), none, "mira-sub-key", none, sk.key.bytes()); !st) return st.error();
  if (Status st = hkdf32(s.bytes(), none, "mira-sub-dek", none, sk.dek.bytes()); !st) return st.error();
  return sk;
}

EngineNativeKeySource::EngineNativeKeySource(const Subkeys& sk, const Hash256& ns)
    : s_key_(sk.key.bytes()), s_dek_(sk.dek.bytes()), ns_(ns) {}

Expected<Dek> EngineNativeKeySource::dek_for(std::span<const std::byte> raw_key) const {
  Dek d;
  if (Status st = hkdf32(s_dek_.bytes(), ns_span(ns_), "mira-dek-nat-v1", raw_key, d.bytes()); !st)
    return st.error();
  return d;
}

Expected<KeyHash> EngineNativeKeySource::key_hash(std::span<const std::byte> raw_key) const {
  KeyHash h{};
  const auto label = as_bytes_sv("mira-key-v1");
  const std::span<const std::byte> parts[] = {label, ns_span(ns_), raw_key};
  if (Status st = hmac_sha256(s_key_.bytes(), parts,
                              std::span<std::byte, 32>(reinterpret_cast<std::byte*>(h.b), 32));
      !st)
    return st.error();
  return h;
}

Expected<EngineNativeProvider> EngineNativeProvider::create(const SecretSet& set) {
  auto it = set.secrets.find(set.current);
  if (it == set.secrets.end()) return Error{ErrorCode::NotFound, "secret: current kver has no secret"};
  auto sk = derive_subkeys(it->second);
  if (!sk) return sk.error();
  return EngineNativeProvider(std::move(*sk), set.current);
}

Expected<EngineNativeProvider> EngineNativeProvider::from_file(const std::string& path) {
  auto set = load_secret_file(path);
  if (!set) return set.error();
  return create(*set);
}

Expected<ScopeId> EngineNativeProvider::scope_id(const Hash256& ns,
                                                 std::span<const std::byte> root_key) const {
  ScopeId id{};
  if (Status st = hkdf32(sk_.scope.bytes(), ns_span(ns), "mira-scope-nat-v1", root_key,
                         std::span<std::byte, 32>(reinterpret_cast<std::byte*>(id.b), 32));
      !st)
    return st.error();
  return id;
}

Expected<ScopeKeys> EngineNativeProvider::derive(const RequestMeta& meta) const {
  if (meta.roots.empty()) return bad("scope: no chain roots");
  ScopeKeys out;
  out.kver = kver_;
  out.scopes.reserve(meta.roots.size());
  for (const auto& r : meta.roots) {
    if (r.empty()) return bad("scope: empty chain root");
    auto id = scope_id(meta.ns, r);
    if (!id) return id.error();
    out.scopes.push_back(*id);
  }
  out.keys = std::make_shared<EngineNativeKeySource>(sk_, meta.ns);
  return out;
}

}  // namespace miracache

namespace miracache {

Expected<std::unique_ptr<ReloadableEngineNativeProvider>> ReloadableEngineNativeProvider::create(const SecretSet& set) {
  auto p = EngineNativeProvider::create(set);
  if (!p) return p.error();
  return std::unique_ptr<ReloadableEngineNativeProvider>(
      new ReloadableEngineNativeProvider(std::make_shared<const EngineNativeProvider>(std::move(*p))));
}

Expected<std::unique_ptr<ReloadableEngineNativeProvider>> ReloadableEngineNativeProvider::from_file(const std::string& path) {
  auto set = load_secret_file(path);
  if (!set) return set.error();
  auto p = create(*set);
  if (p) (*p)->path_ = path;
  return p;
}

Expected<ScopeKeys> ReloadableEngineNativeProvider::derive(const RequestMeta& meta) const {
  const std::shared_ptr<const EngineNativeProvider> p = cur_.load(std::memory_order_acquire);
  return p->derive(meta);
}

Status ReloadableEngineNativeProvider::reload(const SecretSet& set) {
  auto p = EngineNativeProvider::create(set);
  if (!p) return p.error();
  cur_.store(std::make_shared<const EngineNativeProvider>(std::move(*p)), std::memory_order_release);
  return {};
}

std::uint32_t ReloadableEngineNativeProvider::kver() const { return cur_.load(std::memory_order_acquire)->kver(); }

}  // namespace miracache
