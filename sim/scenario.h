// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <string>

namespace miracache::sim {

struct ScenarioResult {
  bool ok = true;
  std::string failure;       // empty when ok
  std::uint64_t trace_hash = 0;  // identical across runs of the same seed
};

// Two nodes exchange RDMA READs over fabric/sim with drop (which breaks the RC
// endpoint pair), duplicate completion and link flaps enabled; odd seeds also opt in
// to reordering, even seeds check in-order completion. Checks per-seed invariants (every request
// completes, successful reads return exactly the peer's bytes, endpoints drain).
ScenarioResult run_two_node_reads(std::uint64_t seed);

struct AeadFetchResult {
  bool ok = true;
  std::string failure;
  std::uint64_t trace_hash = 0;
  std::uint32_t hits = 0, miss_seq = 0, miss_aead = 0;
  std::uint64_t scribbles = 0;
};

// Sliced READs of pre-sealed blocks into the landing pool + decrypt pipeline.
// nemesis=false: every block must validate. nemesis=true: a rogue writer scribbles the
// pool (between slices and during decrypt); every case must be Hit with exact bytes,
// MissAead or MissSeq (engine buffer zeroed), never Hit with wrong bytes.
AeadFetchResult run_aead_fetch(std::uint64_t seed, bool nemesis);

struct ScenarioStats {
  std::uint64_t puts = 0, refused = 0, commits = 0, aborted = 0, timeouts = 0;
  std::uint64_t writes_landed = 0, writes_rejected = 0;
  std::uint64_t hits = 0, misses = 0, fetch_hits = 0, miss_seq = 0, miss_aead = 0;
  std::uint64_t invalidates = 0, drops = 0;
  std::uint64_t ep_cap_hits = 0, lease_cap_hits = 0, unknown_probes = 0;  // oracle-checked limit paths
  std::uint64_t below_cap_checks = 0;  // roomy seeds: PUT_BEGINs below the endpoint cap that must not be refused
  std::uint64_t max_ep_puts = 0;       // most puts ever live on one endpoint (a max, not a sum)
  std::uint64_t crash_checks = 0, crash_adopted = 0;  // crash snapshots re-opened and scanned, blocks adopted
};
struct StoreScenarioResult {
  bool ok = true;
  std::string failure;
  std::uint64_t trace_hash = 0;
  ScenarioStats stats;
};

// Randomized multi-client scenario over the whole store, every invariant checked
// after every step (the CRC-recomputing CommittedIntact sweep every `full_every` steps and
// at the end; 0 = only at the end). Teeth variants are selected with buggify::set_teeth.
StoreScenarioResult run_store_scenario(std::uint64_t seed, std::uint32_t full_every = 1);
struct MembershipStats {
  std::uint64_t bundles = 0, pushes = 0, goaways = 0, commits = 0, lookups = 0;
  std::uint64_t root_accepted = 0, child_accepted = 0, skipped = 0, stale = 0, draining = 0;
  std::uint64_t readded_accepts = 0;  // roots accepted by a node that had been removed
};
struct MembershipResult {
  bool ok = true;
  std::string failure;
  std::uint64_t trace_hash = 0;
  MembershipStats stats;
};
// Three real memory nodes under a controller that joins, drains, removes, fails and re-adds them with random
// bundle lag, and a client sending PUT_BEGIN / LOOKUP with right, behind and ahead frame epochs. An independent
// oracle (owner_set over view_from_bundle) predicts every reply; see membership_scenario.cpp. `replicas` = R.
MembershipResult run_membership_scenario(std::uint64_t seed, std::uint32_t replicas);

// Debug: one stderr line per store-sim operation (--store-trace).
extern bool g_store_trace;

}  // namespace miracache::sim
