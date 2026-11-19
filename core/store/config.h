// SPDX-License-Identifier: Apache-2.0
// Store configuration (A1.4 plan, "CI without hugetlbfs"). Pure data plus validate().
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "proto/state_gen.h"
#include "proto/storage_layout.h"
#include "util/clock.h"
#include "util/expected.h"

namespace miracache::store {

enum class BackingKind : std::uint8_t {
  Anon,        // test-only: anonymous memory, nothing persists
  File,        // file per segment in `dir` (flock, ftruncate, mmap MAP_SHARED)
  Hugetlbfs,   // File path plus fstatfs page-size check and prefault; Linux only
};

namespace detail {
constexpr bool pow2(std::uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }
}  // namespace detail

// Per-principal limits (design rev 5.1). Scopes are implicit; the caps bound what one
// principal can hold, so eviction never crosses principals.
struct PrincipalPolicy {
  std::uint32_t max_scopes = 1024;
  std::uint64_t max_bytes = std::uint64_t{1} << 30;
  Nanos idle_ttl{std::chrono::minutes(30)};  // scope idle TTL, renewed by any hit or commit
  // Put token buckets (QT2, quota plan decision 4), per principal per node; 0 = unlimited. Burst = one second.
  std::uint64_t put_ops_per_s = 0;    // keys per second
  std::uint64_t put_bytes_per_s = 0;  // stored bytes per second; a larger block is admitted with debt (P22)
};

struct StoreConfig {
  std::size_t segment_bytes = 4u << 20;
  std::size_t run_bytes = 256u << 10;
  std::size_t min_block_bytes = 4096;
  std::uint32_t n_segments = 4;
  BackingKind backing = BackingKind::Anon;
  std::string dir;           // File / Hugetlbfs
  bool require_1g = false;   // Hugetlbfs: demand 1 GiB pages
  bool production = false;   // production configs reject Anon backing
  std::uint32_t node_id = 0;  // test hook: a fixed ID (honoured only when state_dir is empty)
  // Review r9 S04 + r9b T01-T03: the node state directory (store/node_state.h: node-id, initialised, node-id.lock; locked
  // while the Arena lives). The node ID lives there; empty = no file
  // (tests, the ID then lives in the superblock only). The memory node always sets it ([node] state_dir).
  std::string state_dir;
  std::uint32_t owner_pid = 0;  // recorded in the superblock; injected (no getpid in core)
  // The generation high-water mark is persisted every `gen_chunk` values (spec 6.1).
  std::uint64_t gen_chunk = std::uint64_t{1} << 20;
  // A3.1: records in the persisted scope region (spec 6.1, at the end of segment 0). 0 = auto: none for the volatile
  // Anon backing (nothing survives a restart), else one per min_block of data, capped at 4 Mi (kDefaultMaxScopeRecords).
  // STATIC: a change re-formats the store.
  std::uint32_t scope_records = 0;

  Nanos lease_ttl{std::chrono::seconds(30)};
  Nanos lease_max{std::chrono::seconds(300)};
  Nanos put_timeout{std::chrono::seconds(10)};
  Nanos reap_grace{std::chrono::seconds(5)};
  std::uint32_t invalidate_per_s = 10;
  // Retention (QT1, decision 1): a scope whose opened_at is older than max_ttl misses and is reaped under the sweep
  // budget; renewal does not extend it. 0 = none (v1 default, P21). Hot-reloadable (Store::set_retention).
  Nanos max_ttl{0};
  // The one eviction budget (QT1, decision 3; P20), per Store::tick turn. Hot-reloadable (Store::set_evict).
  std::uint64_t sweep_bytes_per_s = std::uint64_t{1} << 30;  // evict.sweep_bytes_per_s: bytes freed per second
  std::uint32_t sweep_blocks_per_turn = 64;                  // at most this many blocks per turn
  std::uint32_t high_pct = 92;                               // evict.high_pct: pressure starts above this occupancy
  std::uint32_t low_pct = 88;                                // evict.low_pct: pressure stops at or below this
  // SC1 scrubber (class A, hot-reloadable): enabled and the bytes/s of extents re-checked (0 = off).
  bool scrub_enabled = true;
  std::uint64_t scrub_bytes_per_s = std::uint64_t{64} << 20;
  // Exact size classes one principal may create; further sizes use the fixed ladder rungs (Q10).
  std::uint32_t max_exact_classes_per_owner = 8;
  // Concurrent PUT_BEGIN puts per endpoint (Q08).
  std::uint32_t max_puts_per_endpoint = 64;
  // Leases one session may hold; further LOOKUPs return all-MISS (Q09).
  std::uint32_t max_leases_per_session = 4096;
  // max_bytes 0 = "computed" = n_segments x segment_bytes of this config: the same default the node loader produces
  // (K02; server/dyn_config.h backing_bytes), so a StoreConfig / ServerConfig not built by the loader (tests, tools)
  // does not get a different cap. Store resolves it; an explicit value wins.
  PrincipalPolicy principal_default = [] {
    PrincipalPolicy p;
    p.max_bytes = 0;
    return p;
  }();

  Status validate() const {
    using detail::pow2;
    if (production && backing == BackingKind::Anon)
      return Error{ErrorCode::InvalidArgument, "config: Anon backing is test-only"};
    if ((backing == BackingKind::File || backing == BackingKind::Hugetlbfs) && dir.empty())
      return Error{ErrorCode::InvalidArgument, "config: dir required"};
    if (!pow2(segment_bytes) || !pow2(run_bytes) || !pow2(min_block_bytes))
      return Error{ErrorCode::InvalidArgument, "config: sizes must be powers of two"};
    if (min_block_bytes < 4096) return Error{ErrorCode::InvalidArgument, "config: min_block_bytes < 4096"};
    if (run_bytes < min_block_bytes) return Error{ErrorCode::InvalidArgument, "config: run_bytes < min_block_bytes"};
    if (run_bytes > (std::size_t{1} << proto::kRunLog2))
      return Error{ErrorCode::InvalidArgument, "config: run_bytes > 256 MiB"};
    if (segment_bytes < 2 * run_bytes) return Error{ErrorCode::InvalidArgument, "config: segment_bytes < 2 runs"};
    if (n_segments == 0) return Error{ErrorCode::InvalidArgument, "config: n_segments == 0"};
    if (gen_chunk == 0 || gen_chunk > proto::kMaxGeneration / 4)
      return Error{ErrorCode::InvalidArgument, "config: gen_chunk"};
    if (lease_ttl <= Nanos{0} || lease_max < lease_ttl || put_timeout <= Nanos{0} || reap_grace < Nanos{0})
      return Error{ErrorCode::InvalidArgument, "config: durations"};
    if (max_ttl < Nanos{0}) return Error{ErrorCode::InvalidArgument, "config: max_ttl"};
    if (sweep_bytes_per_s == 0 || sweep_blocks_per_turn == 0 || low_pct == 0 || low_pct >= high_pct || high_pct > 100)
      return Error{ErrorCode::InvalidArgument, "config: evict budget / watermarks"};
    if (max_exact_classes_per_owner == 0 || max_puts_per_endpoint == 0 || max_leases_per_session == 0)
      return Error{ErrorCode::InvalidArgument, "config: per-owner caps"};
    if (principal_default.max_scopes == 0 || principal_default.idle_ttl <= Nanos{0})
      return Error{ErrorCode::InvalidArgument, "config: principal_default"};
    return {};
  }
};

}  // namespace miracache::store
