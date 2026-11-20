// SPDX-License-Identifier: Apache-2.0
// The signed cluster bundle, C++ side.
//
// Envelope `mira-bundle-v1`, byte for byte (any deviation is Reject::EnvelopeFormat):
//   mira-bundle-v1\n
//   key_id: <16 lower-case hex>\n
//   sig: <128 lower-case hex>\n
//   sec_key_id: <16 lower-case hex>\n
//   sec_sig: <128 lower-case hex>\n
//   sec_len: <decimal, no sign, no leading zero, 1..7 digits, > 0>\n
//   \n
//   <sec: TOML, sec_len bytes><body: TOML>        (whole envelope <= 1 MiB)
// sig     = Ed25519(publish key,  "mira-bundle-v1\0"     || u32be(sec_len) || sec || body)
// sec_sig = Ed25519(security key, "mira-bundle-sec-v1\0" || sec)
// Every hash is SHA-256; key_id = first 8 bytes of SHA-256(raw public key).
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "control/reject.h"
#include "control/sha256.h"
#include "control/trust_keys.h"
#include "util/expected.h"

namespace miracache::control {

inline constexpr std::size_t kMaxEnvelopeBytes = 1u << 20;  // 1 MiB
inline constexpr std::int64_t kMaxGeneration = INT64_MAX;     // 2^63 - 1 (rule 9)

// ---- Stage 1: the envelope bytes ------------------------------------------------------------
struct Envelope {
  KeyId key_id{};
  std::array<std::uint8_t, 64> sig{};
  KeyId sec_key_id{};
  std::array<std::uint8_t, 64> sec_sig{};
  std::string_view sec;  // views into the input buffer, which must outlive the Envelope
  std::string_view body;
};

// Rules 1-6 (format only; no key lookup, no signature check).
Expected<Envelope, BundleError> parse_envelope(std::string_view bytes);

// Rule 8 role binding, then both Ed25519 verifies. Stateless; nothing is parsed.
Expected<void, BundleError> verify_envelope(const Envelope& env, const TrustKeys& trust);

// ---- Stage 2: TOML into a view --------------------------------------------------------------
enum class MemberState : std::uint8_t { Active, Draining, Readonly };

struct RailView {
  std::string addr;
  std::string subnet;
  std::string protocol;
};

struct NodeView {
  std::uint32_t node_id = 0;
  std::string hostname;
  std::string admin;
  std::vector<RailView> rails;  // 1..4
  std::uint32_t weight = 1;
  std::optional<std::string> zone;  // all nodes or none
  MemberState state = MemberState::Active;
};

struct PreviousNodeView {
  std::uint32_t node_id = 0;
  std::uint32_t weight = 1;
  std::optional<std::string> zone;
};

struct PrincipalView {
  std::string name;
  std::uint32_t id = 0;  // computed from the name
  std::vector<std::string> identities;
  std::uint64_t quota_bytes = 0;
  std::uint64_t max_scopes = 0;
  std::optional<std::int64_t> drop_before;  // unix seconds (UTC)
};

struct RbacView {
  std::string identity;
  std::vector<std::string> roles;
};

struct SecView {
  std::uint64_t sec_generation = 0;
  std::vector<PrincipalView> principals;
  std::vector<RbacView> rbac;
};

struct BodyView {
  std::uint32_t schema_version = 0;
  std::uint64_t generation = 0;
  std::string created_at;  // informational
  std::string author;
  std::string reason;
  std::uint32_t epoch = 0;
  std::uint32_t previous_epoch = 0;
  std::vector<NodeView> nodes;
  std::vector<PreviousNodeView> previous;
  bool replicas_present = false;
  std::uint32_t replicas = 1;  // config.cluster.placement.replicas
  // The `config` table re-serialised as TOML (rooted at `config`; sub-tables such as
  // [cluster.placement], [cluster.memnode], [cluster.client], [node."<admin>".memnode]) for the hot-reload class A keys.
  std::string config_toml;
  // Keys ignored under config.* (everything else is strict) (miracache_bundle_unknown_keys_total).
  std::uint32_t unknown_keys = 0;
};

struct BundleView {
  BodyView body;
  SecView sec;
  KeyId key_id{};
  KeyId sec_key_id{};
  Sha256Digest body_hash{};  // SHA-256 of the body bytes
  Sha256Digest sec_hash{};   // SHA-256 of the sec bytes
};

// principal_id = u32be(SHA-256("mira-principal-v1" || name)[0..4]); 0 maps to 1.
std::uint32_t principal_id(std::string_view name);

// Parses and validates `sec` (strict: unknown keys are errors) / `body` (membership strict,
// config.* opaque with unknown keys counted). Reject::Schema on any failure.
Expected<SecView, BundleError> parse_sec(std::string_view sec);
Expected<BodyView, BundleError> parse_body(std::string_view body);

// Parse both parts of a format-valid envelope (no signature check).
Expected<BundleView, BundleError> parse_bundle(const Envelope& env);

// The whole receive path: format, role binding, both signatures, then TOML. Nothing is parsed
// before both signatures verify.
Expected<BundleView, BundleError> open_bundle(std::string_view bytes, const TrustKeys& trust);

// A principal drop_before later than now + 300 s is refused (Reject::Schema). A future cutoff is stored max-only
// by every node but converted once (clamped to now), so a later real cutoff below it would be a silent no-op. Parsing is
// pure (no clock), so this runs where a clock exists: the memory node at apply time (BundleStore::push, before the
// floor is touched) and the Go controller at publish time (bundle.CheckDropBeforeNotFuture, same rule and skew).
inline constexpr std::int64_t kDropBeforeSkewSeconds = 300;
// Stored_max (principal -> highest drop_before in the floor, may be null) exempts a drop_before that is not above
// that stored maximum: it is already stored, so a clock step back must not make it unpublishable. A value above the
// stored maximum is still refused (fail-closed for real rewinds).
std::optional<BundleError> check_drop_before_not_future(const BundleView& v, std::int64_t now_unix_s,
                                                        const std::map<std::string, std::int64_t>* stored_max = nullptr);

}  // namespace miracache::control
