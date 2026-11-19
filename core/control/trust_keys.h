// SPDX-License-Identifier: Apache-2.0
// The trust file (membership plan decision 4): public keys with roles. key_id is computed from
// the key, never typed; a typed `id` is an error (goal 10).
//
//   min_sec_generation = 5            # optional pin (top level or inside a [[key]])
//   [[key]]
//   public = "<64 lower-case hex>"    # raw 32-byte Ed25519 public key
//   roles  = ["publish"]              # "publish", "security" or both
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "control/reject.h"
#include "control/sha256.h"
#include "util/expected.h"

namespace miracache::control {

struct TrustKey {
  std::array<std::uint8_t, 32> public_key{};
  KeyId key_id{};  // computed
  bool publish = false;
  bool security = false;
};

class TrustKeys {
 public:
  // The key whose computed key_id is `id`, or nullptr.
  const TrustKey* find(const KeyId& id) const;
  const std::vector<TrustKey>& keys() const { return keys_; }
  // Highest `min_sec_generation` pinned anywhere in the file (0 = none).
  std::uint64_t min_sec_generation() const { return min_sec_generation_; }

 private:
  friend Expected<TrustKeys, BundleError> parse_trust_keys(std::string_view toml);
  std::vector<TrustKey> keys_;
  std::uint64_t min_sec_generation_ = 0;
};

// key_id = first 8 bytes of SHA-256 of the raw 32-byte public key (envelope rule 7).
KeyId compute_key_id(const std::array<std::uint8_t, 32>& public_key);

Expected<TrustKeys, BundleError> parse_trust_keys(std::string_view toml);
Expected<TrustKeys, BundleError> load_trust_keys(const std::string& path);

}  // namespace miracache::control
