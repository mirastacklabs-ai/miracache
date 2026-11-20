// SPDX-License-Identifier: Apache-2.0
// The memory node's live configuration.
//
// One key table, C++ only (no Go copy: the controller and mirctl use the node's dry run, POST /v1/bundle?dry_run=1).
// Source, by mode (never both): bundle mode = `config.cluster.memnode` of the signed bundle, merged key by key with the
// node override `config.node."<admin addr>".memnode`; lab mode = the local TOML, re-read on SIGHUP. Both use the same
// section.key names and give the same DynConfig for the same values.
//
//   key                                       class  default     applied by
//   ----------------------------------------  -----  ----------  -------------------------------------------
//   lease.ttl_s / max_s / put_timeout_s        A      30/300/10   Store::set_limits, PutPath::set_timeouts
//   ticket.ttl_s                               A      300         TicketTable::set_limits (new tickets)
//   limits.ticket_max_per_identity             A      computed    TicketTable::set_limits (default_ticket_max)
//   limits.admit_timeout_s / hello_deadline_s / idle_timeout_s / max_conns_per_principal / max_leases_per_principal
//                                              A      10/5/300/computed/8192   ServerConfig (read on each use)
//   store.invalidate_per_s                     A      10          Store::set_limits
//   store.max_scopes / max_bytes               A      1024 / computed  max_bytes unset (0) = n_segments x segment_bytes of THIS node; the DEFAULT principal policy (max_bytes is the
//                                                     per-principal cap for principals without a bundle quota. It is NOT the
//                                                     store's reservation: that is n_segments x segment_bytes, STATIC)
//   store.max_exact_classes_per_owner          A      8           SlabAllocator
//   retention.idle_ttl_s / max_ttl_s           A      1800 / 0    default policy / Store::set_retention
//   evict.sweep_bytes_per_s / sweep_blocks_per_turn / high_pct / low_pct
//                                              A      1 GiB/s, 64, 92, 88   Store::set_evict
//   quota.put_ops_per_s / put_bytes_per_s      A      0 / 0       default policy (token buckets read it on each put)
//   scrub.enabled / bytes_per_s                A      true, 64 MiB/s  Scrubber::set_rate (0 bytes/s = off)
//   node.drain_ms                              A, node-local     5000   local file only (SIGHUP); in the bundle table: pending
//   admin.* / telemetry.listen / log.* / audit.*  B, node-local  local file only; in the bundle table: pending
//
// STATIC (restart, or drain and re-format): store.backing, dir, segment_bytes, run_bytes, min_block_bytes, n_segments,
// (hugepage_size, control.endpoints, log.level are v1.x: not accepted),
// require_1g, hugepage_size, scope_records, max_puts_per_endpoint, max_leases_per_session; node.* except drain_ms;
// control.*; executor.*; nic.*. In the bundle table a STATIC key rejects the WHOLE table (and the bundle: the dry run
// says so); on SIGHUP a STATIC key whose value changed rejects the whole dynamic reload and the old snapshot stays.
//
// The earlier flat names store.scope_idle_ttl_s, max_ttl_s, sweep_*, high_pct, low_pct, put_* were never released:
// they are STALE-KEY ERRORS that name the new key (no deprecation alias). Unknown keys: an error in the local file
// (it is the operator's own file), ignored + warned + counted in the bundle table (rolling upgrades).
//
// Applying: parse and validate are pure (admin thread for a bundle, main for SIGHUP); Server::apply_dyn swaps on
// the store thread between run_once turns. An op uses the values current when it starts; granted leases keep their
// expiry, begun puts keep their deadline.
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "server/node_config.h"
#include "server/server.h"
#include "util/clock.h"
#include "util/expected.h"

namespace miracache::server {

struct DynConfig {
  // lease / ticket / limits
  Nanos lease_ttl{std::chrono::seconds(30)};
  Nanos lease_max{std::chrono::seconds(300)};
  Nanos put_timeout{std::chrono::seconds(10)};
  Nanos ticket_ttl{std::chrono::seconds(300)};
  std::uint32_t ticket_max_per_identity = 0;  // 0 only before Server::create resolves the computed default
  Nanos admit_timeout{std::chrono::seconds(10)};
  Nanos hello_deadline{std::chrono::seconds(5)};
  Nanos idle_timeout{std::chrono::seconds(300)};
  std::uint32_t max_conns_per_principal = 0;  // 0 only before Server::create resolves the computed default
  std::uint32_t max_leases_per_principal = 8192;
  // store
  std::uint32_t invalidate_per_s = 10;
  std::uint32_t max_scopes = 1024;
  std::uint64_t max_bytes = 0;  // 0 only before it is resolved to n_segments x segment_bytes of this node
  std::uint32_t max_exact_classes_per_owner = 8;
  // retention / evict / quota
  Nanos idle_ttl{std::chrono::minutes(30)};
  Nanos max_ttl{0};
  std::uint64_t sweep_bytes_per_s = std::uint64_t{1} << 30;
  std::uint32_t sweep_blocks_per_turn = 64;
  std::uint32_t high_pct = 92;
  std::uint32_t low_pct = 88;
  bool scrub_enabled = true;
  std::uint64_t scrub_bytes_per_s = std::uint64_t{64} << 20;
  std::uint64_t put_ops_per_s = 0;
  std::uint64_t put_bytes_per_s = 0;
  // node-local
  std::uint32_t drain_ms = 5000;
  // Provenance (not compared by dyn_changed_keys).
  std::uint64_t generation = 0;            // the bundle generation (0 = the start-up / local-file snapshot)
  std::vector<std::string> pending;        // node-local keys found in the bundle table: set in the local file instead
};
using DynPtr = std::shared_ptr<const DynConfig>;

// The snapshot a ServerConfig already encodes (the start-up one).
DynConfig dyn_from_server_config(const ServerConfig& c);
// Writes the class A fields into a ServerConfig (the file parser and the Server both use it).
void dyn_into_server_config(const DynConfig& d, ServerConfig& c);

// Cross-field and range rules. Error context names keys, never values.
Status validate_dyn(const DynConfig& d);

struct DynParse {
  DynPtr dyn;                         // null when `error` is set
  std::string error;                  // empty = accepted
  std::vector<std::string> unknown;   // keys ignored (dotted names): warn + count
};
// Parses BodyView::config_toml (rooted at `config`): `cluster.memnode` merged with `node."<node_admin>".memnode` over
// `base`. An absent table gives `base` with only `generation` set. A bad value, a STATIC key or a stale key rejects the
// whole table. A key absent from the bundle takes `base`, so removing it restores the start-up value.
DynParse parse_memnode_dyn(std::string_view config_toml, const DynConfig& base, std::string_view node_admin,
                           std::uint64_t generation);

// The admin address whose `node."<admin>".memnode` override applies to this node: the bundle's own listing of
// `node_id`, or "" when the bundle does not list it. The ONE source for BundleStore::push validation and
// Server::apply_bundle_config, so an override can never validate at push and then not apply.
std::string bundle_node_admin(const control::BodyView& body, std::uint32_t node_id);

// Dotted names of the class A keys whose values differ (the reload log line carries names, never values).
std::vector<std::string> dyn_changed_keys(const DynConfig& a, const DynConfig& b);
// Dotted names of STATIC keys whose values differ between two parsed local files (SIGHUP: any entry rejects the
// dynamic reload and keeps the old snapshot).
std::vector<std::string> static_changed_keys(const NodeConfig& a, const NodeConfig& b);

// SIGHUP: what to apply after the local file was re-read (`fresh`, already validated by parse_node_config) against the
// file as it was at start-up (`boot`). A STATIC change gives no snapshot (`dyn` null, names in `static_changed`): the old
// snapshot stays. Lab mode takes every class A key from the file; bundle mode keeps `current` and takes only the
// node-local node.drain_ms.
struct SighupPlan {
  DynPtr dyn;
  std::vector<std::string> static_changed;
};
// The one rule for store.max_bytes: 0 = computed = n_segments x segment_bytes of THIS node. Resolved in
// dyn_from_server_config (so Server::create, SIGHUP and bundle mode, which starts from that snapshot, all agree).
constexpr std::uint64_t backing_bytes(const store::StoreConfig& s) {
  return static_cast<std::uint64_t>(s.segment_bytes) * s.n_segments;
}

// `conns_default` is the node's computed limits.max_conns_per_principal (0 = keep `current`'s): a file that does not set
// the key falls back to it; `tickets_default` likewise for limits.ticket_max_per_identity. A changed [[node.rails]]
// device or subnet is a STATIC change.
SighupPlan plan_sighup(const NodeConfig& boot, const NodeConfig& fresh, const DynConfig& current, bool bundle_mode,
                       std::uint32_t conns_default = 0, std::uint32_t tickets_default = 0);

// The default limits.max_conns_per_principal when the key is not set: room for 16 client sessions of one principal,
// each `rails x (2 + fetch_qps)` endpoints (control + ingest + fetch_qps fetch per rail).
constexpr std::uint32_t default_max_conns(std::size_t rails, std::uint32_t fetch_qps) {
  return static_cast<std::uint32_t>(16 * (rails == 0 ? 1 : rails) * (2 + fetch_qps));
}

// The default limits.ticket_max_per_identity when the key is not set, sized like default_max_conns: room for 16
// client sessions of one identity, each holding the ticket inventory on every rail.
//   - Per (session, rail, class) the client's admin ticket cache holds at most cap(need) = 2 x max(ticket_batch, need)
//     (AdminTicketSource::want: request = max(batch, need), cap = max(2 x request, max(refill_below, need)), and
//     refill_below 2 <= 2 x batch). need = 1 for control and ingest, fetch_qps for fetch (clamped to 1..64).
//   - The client drops a cached ticket at ttl/2 and refills, but the node keeps it live until ttl: x 2.
//   - With the client default ticket_batch = 4: per rail 2 x (cap(1) + cap(1) + cap(q)) = 2 x (8 + 8 + 2 x max(4, q))
//     = 32 + 4 x max(4, q).
//   default = max(1024, 16 x rails x (32 + 4 x max(4, fetch_qps))); the old fixed 1024 is the floor. E.g. 1 rail at
//   fetch_qps 4: 768 -> 1024; 2 rails at 4: 1536; 2 rails at 16: 3072; 4 rails at 16: 6144. A client with a larger
//   fabric.ticket_batch needs an explicit value; an explicit value always wins.
inline constexpr std::uint32_t kTicketMaxFloor = 1024;
constexpr std::uint32_t default_ticket_max(std::size_t rails, std::uint32_t fetch_qps) {
  const std::uint64_t q = fetch_qps < 4 ? 4 : (fetch_qps > 64 ? 64 : fetch_qps);
  const std::uint64_t v = 16 * std::uint64_t{rails == 0 ? 1 : rails} * (32 + 4 * q);
  return static_cast<std::uint32_t>(v < kTicketMaxFloor ? kTicketMaxFloor : v);
}

}  // namespace miracache::server
