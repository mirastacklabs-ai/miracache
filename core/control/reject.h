// SPDX-License-Identifier: Apache-2.0
// Why a bundle (or a trust file) was refused. The reason strings are the values of the
// miracache_bundle_reject_total{reason} label.
// This is THE canonical label set (design spec 9.2): the Go controller (controller/bundle)
// uses exactly these strings, and looks up an unknown key (body key, then sec key) before the role.
#pragma once

#include <cstdint>

namespace miracache::control {

enum class Reject : std::uint8_t {
  EnvelopeFormat,      // "envelope_format": any byte-exact rule 1-6 or the 1 MiB cap
  UnknownKey,          // "unknown_key": key_id / sec_key_id names no trust key
  KeyRole,             // "key_role": the key lacks the publish / security role (rule 8)
  BadSignature,        // "bad_signature": the publish signature does not verify
  BadSecSignature,     // "bad_sec_signature": the security signature does not verify
  Schema,              // "schema": TOML or field validation failed (rule 9 included)
  GenerationLower,     // "generation_lower": below the floor
  EqualGeneration,     // "equal_generation": floor generation, different body hash
  EpochBackwards,      // "epoch_backwards": epoch below the floor's epoch
  SecGenerationLower,  // "sec_generation_lower": below max(persisted, pinned)
  SecEqualGeneration,  // "sec_equal_generation": equal sec_generation, different sec hash
  TrustFile,           // "trust_file": the trust file is unusable
};

constexpr const char* reason_string(Reject r) noexcept {
  switch (r) {
    case Reject::EnvelopeFormat: return "envelope_format";
    case Reject::UnknownKey: return "unknown_key";
    case Reject::KeyRole: return "key_role";
    case Reject::BadSignature: return "bad_signature";
    case Reject::BadSecSignature: return "bad_sec_signature";
    case Reject::Schema: return "schema";
    case Reject::GenerationLower: return "generation_lower";
    case Reject::EqualGeneration: return "equal_generation";
    case Reject::EpochBackwards: return "epoch_backwards";
    case Reject::SecGenerationLower: return "sec_generation_lower";
    case Reject::SecEqualGeneration: return "sec_equal_generation";
    case Reject::TrustFile: return "trust_file";
  }
  return "unknown";
}

// `detail` has static storage duration (no allocation on error paths).
struct BundleError {
  Reject reason;
  const char* detail = "";
};

}  // namespace miracache::control
