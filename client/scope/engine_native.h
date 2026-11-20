// SPDX-License-Identifier: Apache-2.0
// Engine-native ScopeProvider (spec rev 5.1 §2.6).
#pragma once

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "crypto/secret.h"
#include "miracache/scope.h"

namespace miracache {

// `ns` is computed by the engine adapters, in ONE place: python/miracache/ns.py (the
// encoding) with each adapter's field list (vllm/compat.py, sglang/storage.py). The core takes
// it as 32 opaque bytes (mira_derive). First 8 hex digits of ns, for logs.
std::string ns_fingerprint(const Hash256& ns);

// {kver -> S} plus `current`. Text file (tmpfs, mode 0600), one entry per line, '#' comments:
//   current = 2
//   1 = <64 hex chars>
//   2 = <64 hex chars>
struct SecretSet {
  std::map<std::uint32_t, Secret<32>> secrets;
  std::uint32_t current = 0;
};
// NotFound: file missing / current not in set. AccessDenied: mode != 0600 (check_secret_file).
// InvalidArgument: syntax, duplicate, kver 0, S not exactly 32 bytes (64 hex), no `current`.
Expected<SecretSet> load_secret_file(const std::string& path);

// S_x = HKDF-SHA256(ikm = S, salt = "", info = label), L = 32.
struct Subkeys {
  Secret<32> scope;  // "mira-sub-scope"
  Secret<32> key;    // "mira-sub-key"
  Secret<32> dek;    // "mira-sub-dek"
};
Expected<Subkeys> derive_subkeys(const Secret<32>& s);

// Per-(kver, ns) key material. DEK_k = HKDF(S_dek, salt = ns, info = "mira-dek-nat-v1" || raw_key);
// key_hash = HMAC-SHA256(S_key, "mira-key-v1" || ns || raw_key).
class EngineNativeKeySource final : public KeySource {
 public:
  EngineNativeKeySource(const Subkeys& sk, const Hash256& ns);
  Expected<Dek> dek_for(std::span<const std::byte> raw_key) const override;
  Expected<KeyHash> key_hash(std::span<const std::byte> raw_key) const override;

 private:
  Secret<32> s_key_;
  Secret<32> s_dek_;
  Hash256 ns_;
};

// Uses only `current`'s subkeys; S itself is not retained.
class EngineNativeProvider final : public ScopeProvider {
 public:
  static Expected<EngineNativeProvider> create(const SecretSet& set);
  static Expected<EngineNativeProvider> from_file(const std::string& path);

  // scope_id = HKDF(S_scope, salt = ns, info = "mira-scope-nat-v1" || root_key).
  Expected<ScopeId> scope_id(const Hash256& ns, std::span<const std::byte> root_key) const;
  // One scope per group; InvalidArgument if there are no roots or any root is empty.
  Expected<ScopeKeys> derive(const RequestMeta& meta) const override;
  std::uint32_t kver() const { return kver_; }

 private:
  EngineNativeProvider(Subkeys sk, std::uint32_t kver) : sk_(std::move(sk)), kver_(kver) {}
  Subkeys sk_;
  std::uint32_t kver_;
};

// Spec §2.6 rotation: an EngineNativeProvider whose `current` kver can change while jobs run.
// reload() swaps the whole {kver -> S} view in one step: a derive() that started before the swap finishes with the
// old subkeys (its ScopeKeys keeps its own KeySource), every later derive() uses the new `current`. A new kver is
// therefore usable at once for reads and stores of new scopes; scopes derived under the old kver miss (cold cache,
// no previous-kver probe). Thread-safe.
class ReloadableEngineNativeProvider final : public ScopeProvider {
 public:
  static Expected<std::unique_ptr<ReloadableEngineNativeProvider>> create(const SecretSet& set);
  static Expected<std::unique_ptr<ReloadableEngineNativeProvider>> from_file(const std::string& path);
  Expected<ScopeKeys> derive(const RequestMeta& meta) const override;
  // Replaces the view; on error (the set has no usable `current`) the old one stays.
  Status reload(const SecretSet& set);
  // The file from_file() read ("" when built from a SecretSet): what the credential watch re-reads.
  const std::string& source_path() const { return path_; }
  std::uint32_t kver() const;

 private:
  explicit ReloadableEngineNativeProvider(std::shared_ptr<const EngineNativeProvider> p) : cur_(std::move(p)) {}
  std::string path_;
  std::atomic<std::shared_ptr<const EngineNativeProvider>> cur_;
};

}  // namespace miracache
