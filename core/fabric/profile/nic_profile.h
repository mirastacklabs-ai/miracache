// SPDX-License-Identifier: Apache-2.0
// NIC profile registry (spec 4.3/4.4). `profiles/nic-profiles.toml` (compiled in, or a file)
// is parsed into a Registry; `select()` matches a probe result (NicFacts) to the most
// specific profile and yields the fixed operating point. Pure functions of their inputs: no
// hardware, no global state, so tests drive them from golden NicFacts fixtures.
//
// Precedence of every operating-point value: explicit config key > profile > built-in default.
// There is no auto-tuner and no AIMD in v1 (spec 15 #8): the point is the same on every start.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "fabric/probe/nic_probe.h"
#include "util/error.h"
#include "util/expected.h"

namespace miracache::fabric::profile {

inline constexpr int kSchema = 1;
inline constexpr std::size_t kMaxProfiles = 256;       // parse bound (fuzz safety)
inline constexpr std::size_t kMaxRegistryBytes = 1u << 20;

// The values a connection is built from (spec 4.4).
struct OperatingPoint {
  std::uint32_t fetch_qps = 1;     // per rail
  std::uint32_t ingest_qps = 1;    // per rail
  std::uint64_t slice_bytes = 1u << 20;
  std::uint64_t window_bytes = 16u << 20;  // outstanding READ bytes per fetch QP
  std::uint32_t read_depth = 16;           // outstanding READs per fetch QP (ORD requested)
  std::uint32_t inline_bytes = 0;
  std::uint8_t ack_timeout_exp = 19;       // RoCE: 4.096 us * 2^exp
  std::uint8_t retry_count = 7;
  std::uint8_t rnr_retry_count = 6;
  std::uint32_t mtu = 4096;
  friend bool operator==(const OperatingPoint&, const OperatingPoint&) = default;
};

// What the code did before the registry existed (wire_port ord 16, verbs_cm kQpAckTimeoutExpMax /
// kQpRetryCount / kRnrRetryCount, fabric.mtu 4096). Used when no profile can be consulted.
OperatingPoint builtin_default();

struct MatchRule {
  std::vector<std::uint32_t> vendor_id;  // any of
  std::vector<std::uint32_t> part_id;    // any of (verbs vendor_part_id)
  std::vector<std::string> driver;       // any of (sysfs driver name)
  std::string device_prefix;             // ibv device name prefix, e.g. "rxe" (soft RDMA has no PCI identity)
  std::string transport;                 // "roce" | "iwarp" | "" (any)
};

struct Profile {
  std::string id;
  std::uint32_t tier = 0;
  bool verified = false;
  std::string fw_min;  // dotted numeric minimum ("22.31.0"), "" = none
  std::string notes, warn;
  MatchRule match;
  std::vector<std::string> loss_require_any;  // "pfc_ecn" | "ztr_rttcc" | "tcp" | "soft"
  OperatingPoint op;
};

struct Registry {
  int schema = kSchema;
  std::string version;
  std::vector<Profile> profiles;
  std::string source = "builtin";  // "builtin" or the file path (set by load_registry_file)
};

// Strict: unknown tables/keys, wrong types, out-of-range values and an empty match are errors.
// Never throws, never reads out of bounds, bounded work for any input.
Expected<Registry> parse_registry(std::string_view toml_text);
Expected<Registry> load_registry_file(const std::string& path);
// The compiled-in copy of profiles/nic-profiles.toml (parsed once, cached).
Expected<const Registry*> builtin_registry();

enum class FwStatus : std::uint8_t { NotChecked, Ok, BelowMin, Unknown };
const char* to_string(FwStatus s);
// Numeric dotted compare of the leading "a.b.c" of `fw` against `min`; Unknown if `fw` has none.
FwStatus check_firmware(std::string_view fw, std::string_view min);

// Explicit config values. Each one that is set beats the profile.
struct Overrides {
  std::optional<std::uint32_t> fetch_qps, ingest_qps, inline_bytes, read_depth, mtu;
  std::optional<std::uint64_t> slice_bytes, window_bytes;
  std::optional<std::uint8_t> ack_timeout_exp, retry_count, rnr_retry_count;
};

struct Selection {
  std::string profile_id;
  std::uint32_t tier = 0;
  bool verified = false;
  bool unprofiled = false;  // a generic-* fallback (warn set)
  std::string warn;
  int score = 0;
  FwStatus fw = FwStatus::NotChecked;
  std::string fw_min, fw_version;
  std::vector<std::string> loss_require_any;
  OperatingPoint profile_op;  // the profile's values as written
  OperatingPoint op;          // effective: profile, clamped to the probe, then overrides
  std::vector<std::string> notes;  // clamps and overrides applied, human readable
  std::string source;              // registry source
  std::string registry_version;
};

// Most specific match wins (score = sum of the points of the match keys, all of which must
// match); a tie goes to the earlier profile. Fails (never silently open) when nothing matches
// or when the device is not RoCE/iWARP. The operating point is clamped by the probe (MTU to the
// active port MTU, read depth to the device ORD) and then the explicit overrides apply.
Expected<Selection> select(const Registry& reg, const probe::NicFacts& facts, const Overrides& ov = {});

// One structured log line (comp=nic_profile) with the matched profile, verified flag, operating
// point and device identity; the log prefix adds node_id/host/addr (spec goal 10). Warns for an
// unprofiled NIC, an unverified profile and a firmware below the profile minimum.
void log_selection(const Selection& s, const probe::NicFacts& facts);

// Renderers for mira-nicprobe: a table block and a JSON object (no trailing newline).
std::string selection_to_text(const Selection& s);
std::string selection_to_json(const Selection& s);

#ifdef MIRACACHE_WITH_VERBS
// Probe `device` (empty = the first RDMA device), load `profiles_file` (empty = the built-in
// registry; a file that fails to load is an error, not a fallback), select, and log the match.
// `facts_out`, when non-null, receives the probe result.
Expected<Selection> select_for_device(const std::string& device, const std::string& profiles_file, const Overrides& ov,
                                      probe::NicFacts* facts_out = nullptr);
#endif

// Label values of miracache_nic_profile_info{profile,verified}.
inline const char* verified_label(bool v) { return v ? "true" : "false"; }

}  // namespace miracache::fabric::profile
