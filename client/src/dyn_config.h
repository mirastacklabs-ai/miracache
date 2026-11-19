// SPDX-License-Identifier: Apache-2.0
// HR2: the client's live configuration (hot-reload plan decisions 1-4). Internal only: there is no C ABI or
// Python reload call (P34). The source is the bundle's `config.cluster.client` table; the lab-mode client restarts.
//
// The key table lives here and only here (P16: two C++ tables, none in Go). Every key has one class:
//
//   key                          class  source                         default (before any bundle value)
//   ---------------------------  -----  -----------------------------  ---------------------------------
//   fabric.keepalive_ms          A      [cluster.client.fabric]        the open-time config (1000)
//   fabric.reconnect_min_ms      A      same                           100
//   fabric.reconnect_max_ms      A      same                           5000
//   fabric.reconnect_connect_ms  A      same                           1000
//   fabric.watchdog_grace_ms     A      same                           derived (~19200)
//   fabric.ticket_batch          A      same                           4
//   fabric.slice_bytes           A      same                           NIC profile, else 1 MiB (config > profile > built-in)
//   deadline.put_max_ms          A      [cluster.client.deadline]      2500 (store deadlines are clamped to it)
//   placement.replica_mode       A      [cluster.client.placement]     async
//   placement.replica_buffer_bytes A    same                           256 MiB
//   placement.previous_view_ms   A      same                           3600000
//   placement.hint_entries       A      same                           65536
//   breaker.enabled              A      [cluster.client.breaker]       true
//   breaker.window_ms            A      same                           10000 (rolling window of the fail-slow detector)
//   breaker.min_ops / min_misses A      same                           20 / 5
//   breaker.miss_pct             A      same                           20 (deadline misses, % of the window's ops)
//   breaker.p99_factor           A      same                           4 (p99 vs the other nodes' median p99)
//   breaker.floor_us             A      same                           1000 (a p99 below it is never an outlier)
//   breaker.open_ms / open_max_ms A     same                           5000 / 60000 (Open time, doubling per failed probe)
//   breaker.probes               A      same                           3 (Half-open: ops at a time, and good ones to close)
//   crypto.workers               C      [cluster.client.crypto]        4 (applied by the membership thread)
//   landing.subpool_bytes        B      [cluster.client.landing]       64 MiB   \  recorded as pending: "applied at next
//   fabric.mtu / protocol / fetch_qps B same fabric table              4096 / auto / profile  /  rebuild" (HR3b)
//   R (placement.replicas)       A      config.cluster.placement       NOT here: its one home is the placement snapshot (P32)
//
// STATIC keys (scope.*, tls.*, control.*, lab.*, nodes, fabric.device(s), fabric.profiles_file) in the table are an
// error: the whole table is rejected and the old snapshot stays. Unknown keys are ignored (rolling upgrades), counted
// and logged. A bad value rejects the whole table, keeps the old snapshot and counts it.
//
// A value absent from the bundle takes the BASE (the open-time configuration), so removing a key from the bundle
// restores the open-time value.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "miracache/config.h"

namespace miracache {

struct ClientDyn {
  // ---- class A ----
  std::uint32_t keepalive_ms = 1000;
  std::uint32_t reconnect_min_ms = 100;
  std::uint32_t reconnect_max_ms = 5000;
  std::uint32_t reconnect_connect_ms = 1000;
  std::uint32_t watchdog_grace_ms = 19200;
  std::uint32_t ticket_batch = 4;
  std::uint64_t slice_bytes = 1u << 20;
  std::uint32_t put_max_ms = 2500;
  ReplicaMode replica_mode = ReplicaMode::Async;
  std::uint64_t replica_buffer_bytes = 256ull << 20;
  std::uint32_t previous_view_ms = 3600000;
  std::uint32_t hint_entries = 65536;
  // Per-node circuit breaker, fail-slow detection (spec §3.3, §4.5, §10 "Slow memory node"; [cluster.client.breaker]).
  // A node whose session is Up trips (Open) when, over the last `window_ms`, it ran at least `min_ops` ops, at least
  // `min_misses` of them and at least `miss_pct` % missed their deadline, AND its p99 latency is at least `p99_factor`
  // times the median p99 of the other nodes (and at least `floor_us`): an outlier, so a cluster that is slow as a whole
  // trips nothing (the deadline handles it). Open: its reads miss at once, its stores are skipped (never failed), replica
  // legs go around it. After `open_ms` (doubling per failed half-open, up to `open_max_ms`) it is Half-open: at most
  // `probes` ops run on it at a time; `probes` good ones (no deadline miss, latency within the outlier bound) close
  // it, one bad one re-opens it. The operator drains the node or lowers its weight; nothing is removed automatically.
  bool breaker_enabled = true;
  std::uint32_t breaker_window_ms = 10000;
  std::uint32_t breaker_min_ops = 20;
  std::uint32_t breaker_min_misses = 5;
  std::uint32_t breaker_miss_pct = 20;
  std::uint32_t breaker_p99_factor = 4;
  std::uint32_t breaker_floor_us = 1000;
  std::uint32_t breaker_open_ms = 5000;
  std::uint32_t breaker_open_max_ms = 60000;
  std::uint32_t breaker_probes = 3;
  // ---- class C ----
  std::uint32_t crypto_workers = 4;
  // ---- class B: the wanted value; the running one is the base. Applied by the HR3b rebuild. ----
  std::uint64_t subpool_bytes = 64ull << 20;
  std::uint32_t mtu = 4096;
  FabricProtocol protocol = FabricProtocol::Auto;
  std::uint32_t fetch_qps = 0;  // 0 = the NIC profile's value
  // Class B keys whose wanted value differs from the running one ("applied at next rebuild").
  std::vector<std::string> pending_rebuild;
  std::uint64_t generation = 0;  // the bundle generation this snapshot came from (0 = the open-time one)
};
using ClientDynPtr = std::shared_ptr<const ClientDyn>;

// The one holder of the snapshot. Readers: one lock-free-ish atomic load per job (at submit) and per keepalive tick;
// the writer is the thread that applies a bundle (or a test).
class DynSnap {
 public:
  explicit DynSnap(ClientDynPtr d = std::make_shared<const ClientDyn>()) : p_(std::move(d)) {}
  ClientDynPtr load() const { return p_.load(std::memory_order_acquire); }
  void store(ClientDynPtr d) { p_.store(std::move(d), std::memory_order_release); }

 private:
  std::atomic<std::shared_ptr<const ClientDyn>> p_;
};

struct DynParse {
  ClientDynPtr dyn;                   // null when `error` is set
  std::string error;                  // empty = accepted; else the reason (key names, never values)
  std::vector<std::string> unknown;   // keys ignored (dotted names)
};

// Parses `config_toml` (BodyView::config_toml, rooted at `config`) over `base`. An absent or empty
// `cluster.client` table gives `base` itself with only `generation` set.
DynParse parse_client_dyn(std::string_view config_toml, const ClientDyn& base, std::uint64_t generation);

// Dotted names of the class A and C keys whose values differ (for the reload log line: names, never values).
std::vector<std::string> dyn_changed_keys(const ClientDyn& a, const ClientDyn& b);

}  // namespace miracache
