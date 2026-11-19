// SPDX-License-Identifier: Apache-2.0
#include "control/trust_keys.h"

#include "control/toml_guard.h"

#include <fstream>
#include <iterator>

#include <toml++/toml.hpp>

namespace miracache::control {

namespace {

BundleError bad(const char* detail) { return BundleError{Reject::TrustFile, detail}; }

bool read_pin(const toml::table& t, std::uint64_t& pin, const char*& err) {
  const toml::node* n = t.get("min_sec_generation");
  if (!n) return true;
  const toml::value<std::int64_t>* v = n->as_integer();
  if (!v || v->get() < 1) {
    err = "min_sec_generation must be an integer in 1..2^63-1";
    return false;
  }
  if (static_cast<std::uint64_t>(v->get()) > pin) pin = static_cast<std::uint64_t>(v->get());
  return true;
}

}  // namespace

KeyId compute_key_id(const std::array<std::uint8_t, 32>& public_key) {
  const Sha256Digest d =
      sha256(std::string_view(reinterpret_cast<const char*>(public_key.data()), public_key.size()));
  KeyId id{};
  for (std::size_t i = 0; i < id.size(); ++i) id[i] = d[i];
  return id;
}

const TrustKey* TrustKeys::find(const KeyId& id) const {
  for (const TrustKey& k : keys_) {
    if (k.key_id == id) return &k;
  }
  return nullptr;
}

Expected<TrustKeys, BundleError> parse_trust_keys(std::string_view text) {
  if (!toml_text_ok(text)) return bad("trust file has non-ASCII bytes outside strings");
  toml::parse_result parsed = toml::parse(text);
  if (!parsed) return bad("trust file is not valid TOML");
  const toml::table& root = parsed.table();
  for (const auto& [k, v] : root) {
    (void)v;
    if (k.str() != "key" && k.str() != "min_sec_generation") return bad("unknown top-level key in trust file");
  }
  TrustKeys out;
  const char* err = nullptr;
  if (!read_pin(root, out.min_sec_generation_, err)) return bad(err);
  const toml::array* arr = root.get("key") ? root.get("key")->as_array() : nullptr;
  if (!arr || arr->empty() || !arr->is_homogeneous(toml::node_type::table)) {
    return bad("trust file needs at least one [[key]]");
  }
  for (const toml::node& el : *arr) {
    const toml::table& t = *el.as_table();
    if (t.contains("id")) return bad("stale key: key_id is computed, a typed `id` is an error");
    for (const auto& [k, v] : t) {
      (void)v;
      if (k.str() != "public" && k.str() != "roles" && k.str() != "min_sec_generation") {
        return bad("unknown key in [[key]]");
      }
    }
    if (!read_pin(t, out.min_sec_generation_, err)) return bad(err);
    const toml::value<std::string>* pub = t.get("public") ? t.get("public")->as_string() : nullptr;
    if (!pub) return bad("[[key]] needs `public`");
    TrustKey key;
    if (!from_hex_lower(pub->get(), key.public_key)) return bad("`public` must be 64 lower-case hex characters");
    const toml::array* roles = t.get("roles") ? t.get("roles")->as_array() : nullptr;
    if (!roles || roles->empty()) return bad("[[key]] needs a non-empty `roles`");
    for (const toml::node& r : *roles) {
      const toml::value<std::string>* s = r.as_string();
      if (!s) return bad("`roles` entries must be strings");
      if (s->get() == "publish") {
        if (key.publish) return bad("duplicate role");
        key.publish = true;
      } else if (s->get() == "security") {
        if (key.security) return bad("duplicate role");
        key.security = true;
      } else {
        return bad("unknown role (allowed: publish, security)");
      }
    }
    key.key_id = compute_key_id(key.public_key);
    for (const TrustKey& other : out.keys_) {
      if (other.public_key == key.public_key) return bad("the same public key appears twice");
      if (other.key_id == key.key_id) return bad("key_id collision between two keys");
    }
    out.keys_.push_back(key);
  }
  return out;
}

Expected<TrustKeys, BundleError> load_trust_keys(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  if (!f) return bad("cannot open the trust file");
  std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  if (f.bad()) return bad("cannot read the trust file");
  return parse_trust_keys(text);
}

}  // namespace miracache::control
