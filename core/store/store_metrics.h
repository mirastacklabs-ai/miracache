// SPDX-License-Identifier: Apache-2.0
// Optional counters the store and put path bump at their real decision points.
// Every pointer may be null (tests, sim): the hooks are then no-ops. The owner (the server)
// registers them in a telemetry::Registry. Counting only: no behavior depends on these.
#pragma once

#include <cstddef>

#include "telemetry/metrics.h"

namespace miracache::store {

enum class EvictReason : std::uint8_t { Cap, Pressure, Invalidate, Drop, Ttl };
inline constexpr std::size_t kEvictReasons = 5;
enum class PutResult : std::uint8_t { Committed, Skipped, Refused, Aborted };
inline constexpr std::size_t kPutResults = 4;
enum class RefuseReason : std::uint8_t { Quota, Full, ClassCap, ConnCap, LeaseCap, Other };
inline constexpr std::size_t kRefuseReasons = 6;

struct StoreMetrics {
  telemetry::Counter* evict_bytes[kEvictReasons] = {};
  telemetry::Counter* evict_blocks[kEvictReasons] = {};
  telemetry::Counter* invalidate_dropped = nullptr;
  telemetry::Counter* invalidate_ignored = nullptr;
  telemetry::Counter* scope_opened = nullptr;
  telemetry::Counter* scope_denied = nullptr;
  telemetry::Counter* lease_expired = nullptr;
  telemetry::Counter* put_ops[kPutResults] = {};
  telemetry::Counter* put_bytes[kPutResults] = {};
  telemetry::Counter* put_refused[kRefuseReasons] = {};
  telemetry::Counter* put_digest_mismatch = nullptr;
  telemetry::Histogram* put_commit_seconds = nullptr;  // PUT_BEGIN -> commit done
  // Retention gauges, set each Store::tick. occupancy_ratio is (committed + zombie + in-flight) / registered capacity in
  // parts per million (the registry has integer gauges only; the exporter scales it). evict_backlog_blocks is the
  // number of blocks still waiting to be freed in expired or dropped scopes.
  telemetry::Gauge* occupancy_ratio_ppm = nullptr;
  telemetry::Gauge* evict_backlog_blocks = nullptr;
  // Keys SKIPped by the put token buckets, by kind (0 = ops, 1 = bytes). Also counted in put_ops{skipped}.
  telemetry::Counter* put_throttled[2] = {};
  // Scrubber: blocks checked / failed, bytes checked, and the duration of the last completed cycle (seconds).
  telemetry::Counter* scrub_checked = nullptr;
  telemetry::Counter* scrub_failed = nullptr;
  telemetry::Counter* scrub_bytes = nullptr;
  telemetry::Gauge* scrub_cycle_seconds = nullptr;
};

inline void bump(telemetry::Counter* c, std::uint64_t n = 1) {
  if (c) c->inc(n);
}

}  // namespace miracache::store
