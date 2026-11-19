// SPDX-License-Identifier: Apache-2.0
// B11: QP attribute readback. After a QP reaches RTS the fabric calls ibv_query_qp once per rail (the
// first QP per key, see QpReadback::claim) and hands the values here. This file holds the hardware-free
// part: compare against what config asked for, format, log once, expose gauges + a mismatch counter.
//
// Granularity: one report per (role, device, port, addr). `addr` is the remote memory-node rail IP on the
// active (client) side and the local bound IP on the passive (memory-node) side, so every rail of a node
// is reported once, however many QPs it carries.
//
// Metrics (labels role, device, port, addr + the extra labels set by set_metrics, e.g. node_id, hostname):
//   miracache_qp_ack_timeout_exp, miracache_qp_retry_count, miracache_qp_rnr_retry,
//   miracache_qp_min_rnr_timer, miracache_qp_path_mtu_bytes  (gauges)
//   miracache_qp_attr_mismatch_total{...,attr}               (counter; read-back differs from config)
//   miracache_qp_query_fail_total{...}                       (counter; ibv_query_qp failed)
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include "telemetry/metrics.h"

namespace miracache::fabric {

struct QpAttrs {
  std::uint8_t ack_timeout_exp = 0;  // 0 = no timeout (IB), else 4.096 us * 2^exp
  std::uint8_t retry_count = 0;
  std::uint8_t rnr_retry = 0;
  std::uint8_t min_rnr_timer = 0;
  std::uint32_t path_mtu_bytes = 0;
};

// What config asked for; an unset field is not compared (e.g. the passive side never asks for an ACK timeout).
struct QpExpect {
  std::optional<std::uint8_t> ack_timeout_exp, retry_count, rnr_retry;
};

struct QpMismatch {
  const char* attr;
  unsigned expected, actual;
  bool operator==(const QpMismatch&) const = default;
};

std::vector<QpMismatch> qp_compare(const QpAttrs& got, const QpExpect& want);
// enum ibv_mtu (1..5 = 256..4096) -> bytes; 0 for anything else.
std::uint32_t qp_mtu_bytes(int ibv_mtu_enum);
// "ack_timeout_exp=19 (2.1s) retry_count=7 ..." for tests and plain logs.
std::string qp_format(const QpAttrs& a);

struct QpSite {
  std::string role;    // "active" | "passive"
  std::string device;  // local RDMA device
  std::string port;    // local port number
  std::string addr;    // see header comment
  auto key() const { return std::tie(role, device, port, addr); }
};

class QpReadback {
 public:
  // Extra labels/log fields on every series and line (the client passes node_id + hostname; on the memory
  // node the registry's const labels and the process log identity already carry them). nullptr registry
  // unbinds; reports made while unbound are published when a registry is bound. Calling it again with other labels
  // (the client learned the node ID) hides the series published under the old labels and publishes under the new.
  // A claimed site with no report yet publishes nothing.
  void set_metrics(telemetry::Registry* reg, telemetry::Labels extra);
  // True exactly once per site: the caller then queries the QP and calls report().
  bool claim(const QpSite& site);
  // attrs == nullptr: ibv_query_qp failed with `err` (WARN once, counter, connection continues).
  void report(const QpSite& site, const QpAttrs* attrs, int err, const QpExpect& want);

 private:
  struct Entry {
    bool have_attrs = false;
    QpAttrs attrs;
    std::vector<QpMismatch> mism;
    bool failed = false;
    int err = 0;               // errno of the failed query
    QpExpect want;             // L06: kept for the second log line
    bool log_unknown = false;  // L06: logged while the node ID or hostname said "unknown"; logs once more when learned
    telemetry::Registry* published_to = nullptr;
    telemetry::Labels published_labels;  // extra labels the series were published with (F3: rebind hides them)
    std::vector<telemetry::Counter*> series_c;
    std::vector<telemetry::Gauge*> series_g;
    // L07 (review s9b): the counter series this entry already counted. Labels A -> B -> A give back A's series (the
    // registry keeps it, hidden): it is shown again but not counted twice.
    std::vector<const telemetry::Counter*> counted;  // a few entries; a vector keeps the order deterministic
  };
  // Counts `c` once for entry `e` (`by`: its value for this entry); a series seen before is not counted again unless it
  // reads below `by` (a new registry that reused a freed one's address).
  static void count_once(Entry& e, telemetry::Counter& c, std::uint64_t by);
  void publish_locked(const QpSite& s, Entry& e);
  // `again`: the second line of a site first logged while its identity was "unknown" (L06).
  static void log_entry(const QpSite& site, const Entry& e, const telemetry::Labels& extra, bool again);
  using Key = std::tuple<std::string, std::string, std::string, std::string>;
  std::mutex mu_;
  telemetry::Registry* reg_ = nullptr;
  telemetry::Labels extra_;
  std::map<Key, Entry> entries_;
};

}  // namespace miracache::fabric
