// SPDX-License-Identifier: Apache-2.0
// mira-memnode configuration file (TOML). Sections: [node], [store], [lease], [ticket],
// [lab], [executor]. Unknown keys are errors. See `mira-memnode --help`.
//
//   [node]     device, protocol ("auto"|"roce"|"iwarp"), listen = ["10.0.0.5:7100", ...], drain_ms (5000), state_dir
//   [[node.rails]] device, listen = "10.0.0.5:7471", subnet   1..4 rails, STATIC (rolling restart to change); replaces
//              node.device + node.listen (the legacy form = all rails on one device)
//   [store]    backing ("file"|"hugetlbfs"|"anon"), dir, segment_bytes, run_bytes,
//              min_block_bytes, n_segments, require_1g, invalidate_per_s,
//              max_scopes, max_bytes (the DEFAULT per-principal byte cap, not the store reservation: that is
//              n_segments x segment_bytes), max_exact_classes_per_owner, max_puts_per_endpoint, max_leases_per_session
//   [retention] idle_ttl_s (1800), max_ttl_s (0 = off)                                     class A (live)
//   [evict]    sweep_bytes_per_s, sweep_blocks_per_turn, high_pct, low_pct                 class A (live)
//   [scrub]    enabled, bytes_per_s                                                        class A (live)
//   [quota]    put_ops_per_s, put_bytes_per_s (0 = unlimited)                              class A (live)
//   The class A keys reload on SIGHUP (lab mode) or from the bundle's config.cluster.memnode (bundle mode); the full
//   table is in server/dyn_config.h. The earlier flat [store] names for retention/evict/quota are stale-key errors.
//   [lease]    ttl_s, max_s, put_timeout_s
//   [ticket]   ttl_s
//   [limits]   ticket_max_per_identity, admit_timeout_s, hello_deadline_s, idle_timeout_s,
//              max_conns_per_principal, max_leases_per_principal
//   [lab]      principal = "lab-identity", identities = ["spiffe://lab/client-1", ...],
//              ticket_file, tickets
//   [admin]    listen = "0.0.0.0:9465" (empty = off), cert, key, ca, max_conns (8)   POST /v1/tickets over mTLS; SIGHUP reloads
//   [[admin.rbac]] identity = "spiffe://...", roles = ["operator"]   lab mode roles for /v1/drain, /v1/drop_principal
//   [audit]    dir, max_bytes (64 MiB), max_total_bytes (1 GiB)   hash-chained audit log (node-local)
//   [control]  trust_keys = "/etc/miracache/trust.toml"   bundle mode on (needs [admin]); STATIC path
//   [executor] workers
//   [nic]      profiles_file, mtu, inline_bytes, ack_timeout_exp, retry_count, rnr_retry_count   (all optional)
//   [telemetry] listen ="127.0.0.1:9464"   GET /metrics (Prometheus text); "" = off; SIGHUP rebinds
#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "fabric/profile/nic_profile.h"
#include "fabric/verbs_cm/protocol_rules.h"
#include "server/server.h"
#include "util/expected.h"

namespace miracache::server {

struct NodeConfig {
  ServerConfig server;
  std::string device;                       // legacy form: the one device; with [[node.rails]], the first rail's
  // [[node.rails]] — distinct device names (fabric index = position) and each rail's subnet label (parallel to
  // server.rails / server.rail_device). Both empty in the legacy form (one device, every rail on it, subnets derived).
  std::vector<std::string> devices;
  std::vector<std::string> rail_subnets;
  fabric::protocol::Setting protocol = fabric::protocol::Setting::Auto;
  std::size_t workers = 2;
  // [node] drain_ms: on SIGTERM/SIGINT send GOAWAY and keep serving this long (or until no session or put is
  // left); 0 = stop at once. A second signal stops at once. Max 600000.
  std::uint32_t drain_ms = 5000;
  std::string lab_ticket_file;   // lab bring-up: tickets for lab.principal are written here
  std::uint32_t lab_tickets = 16;  // per class (control, fetch, ingest), rail 0, refreshed at ttl/2
  // [telemetry] listen: the /metrics endpoint, "host:port"; empty = off. Hot-reloadable (SIGHUP).
  std::string telemetry_listen = "127.0.0.1:9464";
  // [admin]: IssueTicket over HTTPS + mTLS. Empty listen = off (default). cert/key/ca are PEM paths;
  // the key must be 0600. SIGHUP re-reads the file: new credentials are picked up, a new listen rebinds.
  std::string admin_listen, admin_cert, admin_key, admin_ca;
  // [nic]: profiles_file replaces the built-in NIC profile registry (empty = built-in); `nic` holds the
  // explicit operating-point keys (config > profile > built-in default). The server consumes mtu, inline_bytes,
  // ack_timeout_exp, retry_count and rnr_retry_count; the others in Overrides are unused here.
  std::string profiles_file;
  fabric::profile::Overrides nic;
  // [control] trust_keys (STATIC path): non-empty = bundle mode (signed bundles over POST /v1/bundle; the trust file
  // reloads on SIGHUP and every 10 s). Needs [admin] listen. The bundle files live in [node] state_dir.
  std::string trust_keys;
  std::uint32_t admin_max_conns = 8; // [admin] max_conns: concurrent connections (1..1024); per-source-IP limit is 2
  // [[admin.rbac]] identity, roles (lab mode; SIGHUP). Bundle mode takes roles from the bundle's [[rbac]] instead.
  std::vector<std::pair<std::string, std::vector<std::string>>> admin_rbac;
  // [audit]: see node_config.cpp. Empty dir = <state_dir>/audit in bundle mode, no audit log otherwise.
  std::string audit_dir;
  std::uint64_t audit_max_bytes = 64ull << 20;
  std::uint64_t audit_max_total_bytes = 1ull << 30;
  // Dotted names of the class A keys present in the file ("lease.ttl_s", ...). In bundle mode (trust_keys set)
  // any of them is a config error: the bundle's config.cluster.memnode is the one source.
  std::vector<std::string> dyn_keys_present;
};

// Decimal digits only, 1..65535 (0 too with allow_zero). "abc", "", "-1", "70000" are errors.
Expected<std::uint16_t> parse_port(std::string_view s, bool allow_zero = false);
Expected<NodeConfig> parse_node_config(std::string_view toml_text);
Expected<NodeConfig> load_node_config(const std::string& path);

}  // namespace miracache::server
