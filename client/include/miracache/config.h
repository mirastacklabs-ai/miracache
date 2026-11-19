// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "miracache/types.h"

namespace miracache {

// Client configuration (client.toml). Hot-reloadability follows spec §9.1:
//
//   key                   type          range / values                    hot-reload
//   --------------------  ------------  --------------------------------  ----------
//   scope.provider        string        "static"                          yes (ScopeProvider settings)
//   scope.secret_file     string        path; exists, mode 0600 (files)   yes (ScopeProvider settings)
//   nodes[].id            (removed)     any value is the error "node id was removed; node IDs are assigned automatically"
//                                       (the memory node draws a random ID once; the client learns it from HELLO_ACK;
//                                       a node not reached yet owns no scopes; two nodes with one ID: the later one is excluded)
//   nodes[].rails         [string]      1..4 non-empty "host:port"        no  (RL2: one rail = (device, port, IP); rails are
//                                                                           positional and STATIC: adding one is a restart)
//   fabric.devices        [{device,     1..4 local devices, STATIC        no  (RL2 decision 5: a device with a subnet pairs
//                          subnet}]                                             only with node rails of that exact subnet;
//                                                                           a device without `subnet` is a WILDCARD: it takes
//                                                                           every rail of the client's protocol (any protocol
//                                                                           with "auto") that no subnet device claims (exact wins;
//                                                                           at most one wildcard: a second is a config error;
//                                                                           each subnet rail it takes is logged once);
//                                                                           a rail with no subnet pairs with the wildcard, else
//                                                                           device 0. An unpaired rail is unused, logged once
//                                                                           and counted in miracache_client_rail_unpaired{node};
//                                                                           exclusive with fabric.device, which means one
//                                                                           wildcard device)
//   nodes[].admin         string        "host:port" of the node admin API no  (set: tickets come from POST /v1/tickets over
//                                                                           mTLS; unset: lab.ticket_file. Needs [tls])
//   nodes[].identity      string        "spiffe://..." (optional)         no  (expected SPIFFE URI SAN of the node cert; with
//                                                                           nodes[].admin only; unset = chain check only)
//   tls.cert / tls.key /  string        PEM paths; key mode 0600 (files)  no  (client identity + CA for the admin mTLS;
//   tls.ca                                                                  all three required when any nodes[].admin is set)
//   fabric.ticket_batch   integer       1..64, def 4                      no  (tickets per class per admin call; cache refills
//                                                                           below 2 per class, drops tickets older than ttl_s/2)
//   fabric.protocol       string        "auto" | "roce" | "iwarp"         no  (transport layout; warm restart)
//   fabric.keepalive_ms   integer       10..600000, def 1000 (0 rejected)  no  (PING cadence + reconnect driver of the wire client;
//                                                                           0 is a config error: it would turn reconnect off)
//   fabric.mtu            integer       256|512|1024|2048|4096, def 4096  no  (HELLO mtu; the HELLO proto follows fabric.protocol)
//   fabric.profiles_file  string        path of a nic-profiles.toml       no  (A3.3: replaces the built-in NIC profile registry; a
//                                                                           file that does not load is an error, never a fallback)
//   fabric.read_depth     integer       1..255, unset = NIC profile       no  (A3.3 operating point: ORD asked on fetch/ingest QPs;
//                                                                           precedence: config > profile > built-in default)
//   fabric.inline_bytes   integer       0..256, unset = NIC profile       no  (QP max_inline_data; falls back to 0 if refused)
//   fabric.ack_timeout_exp integer      1..19, unset = NIC profile        no  (RoCE QP ACK timeout 4.096 us * 2^exp; the watchdog
//                                                                           grace default assumes 19, a smaller value only shortens real waits)
//   fabric.retry_count    integer       0..7, unset = NIC profile         no  (QP transport retries)
//   fabric.rnr_retry_count integer      0..6, unset = NIC profile         no  (QP RNR retries; 7 = "forever" is refused)
//   fabric.reconnect_min_ms integer     1..60000, def 100               no  (first reconnect delay; doubles per failed attempt)
//   fabric.reconnect_max_ms integer     reconnect_min_ms..600000, def 5000 no (backoff cap; also the delay after a nodes.id mismatch)
//   fabric.reconnect_connect_ms integer 1..60000, def 1000                  no  (connect timeout of each endpoint of a reconnect or of a
//                                                                           background build by the keepalive thread; the first
//                                                                           Client::open connect keeps the 5 s fabric default)
//   fabric.watchdog_grace_ms integer   1..600000, def derived (~19200)   no  (a job still running this long after its deadline is
//                                                                           force-failed; default = QP ACK timeout x (retry + 1) + 2 s)
//   landing.subpool_bytes integer      multiple of 4096, 1 MiB..64 GiB   yes
//   crypto.workers        integer       1..64                             yes
//   placement.replicas    integer       1..3, def 1                       yes (when A2.6 lands; restart until then) (best-effort
//                                                                           copies per scope on the top R nodes of the placement
//                                                                           order; R > 1 needs at least R + 1 nodes, so >= 3)
//   placement.replica_mode string       "async" | "sync", def "async"     yes (when A2.6 lands; restart until then) (async: the
//                                                                           engine's store runs one leg and a client replicator
//                                                                           writes the other copies; sync: the job waits for every
//                                                                           leg or the deadline)
//   placement.replica_buffer_bytes integer 0..2^40, def 268435456 (256 MiB) yes (when A2.6 lands; restart until then) (async:
//                                                                           bound of the plaintext copies waiting for the
//                                                                           replicator; full = that copy is skipped; 0 = replicas off)
//   nodes[].zone          string        1..64 of [A-Za-z0-9._-], optional no  (all nodes or none; replicas go to distinct zones;
//                                                                           replicas > zones is a config error)
//   lab.static_membership bool          must be true for now              no  (lab mode, when [control] is absent)
//   control.endpoints     [string]      1..16 memory-node admin "host:port" no  (bundle mode, MB5: the watcher's bootstrap list;
//                                                                           the bundle's nodes[].admin takes over once applied.
//                                                                           [control] together with [[nodes]] or with
//                                                                           lab.static_membership = true is a config error)
//   control.controller    string        "host:port" (optional)            no  (the controller's API, used only for client reports)
//   control.trust_keys    string        path of the trust file            no  (required with [control]; same file format as the
//                                                                           memory node's [control] trust_keys)
//   control.state_dir     string        directory                         no  (required with [control]; holds the shared
//                                                                           bundle-floor file; mode 0700 dir is created)
//                                       Bundle mode also needs [tls] cert/key/ca (the admin mTLS identity) and rejects the local
//                                       placement.replicas (R comes from the bundle).
//
// HR2 live reload (internal only; no C ABI or Python call, a lab-mode client restarts): in bundle mode the signed bundle's
// `config.cluster.client` table can change, while the client runs, the keys marked A or C in client/src/dyn_config.h:
// fabric.keepalive_ms, reconnect_min_ms, reconnect_max_ms, reconnect_connect_ms, watchdog_grace_ms, ticket_batch,
// slice_bytes (A, new fetches), deadline.put_max_ms (A, store deadlines are clamped to it, default 2500),
// placement.replica_mode, replica_buffer_bytes, previous_view_ms, hint_entries (A), crypto.workers (C). R has one home,
// `config.cluster.placement.replicas` of the bundle. landing.subpool_bytes, fabric.mtu, fabric.protocol and
// fabric.fetch_qps are class B: recorded as pending, applied at the next planned rebuild (HR3). The keys in this file are
// the open-time values; a key absent from the bundle takes them. Precedence for slice_bytes: bundle > NIC profile > 1 MiB.
//
// Unknown tables or keys are an error (typo safety). Missing optional keys take the
// defaults below. `scope.secret_file` and at least one node are required.
// fabric.devices[] (RL2 decision 5): one local RDMA device and the subnet its rails serve ("" = a wildcard device: it
// serves every rail no subnet device claims; client/src/rail_pairing.h).
struct LocalDevice {
  std::string device;
  std::string subnet;
};

struct NodeConfig {
  std::vector<std::string> rails;
  std::string admin;     // nodes[].admin "host:port" (empty = use lab.ticket_file)
  std::string identity;  // nodes[].identity expected server SPIFFE id (empty = not checked)
  std::uint32_t weight = 1;  // nodes[].weight: placement weight, a positive integer (default 1)
  std::string zone;          // nodes[].zone (empty = none: the node is its own zone); all nodes or none
};

// [control]: bundle mode (membership plan decision 9). Absent = lab static mode, unchanged.
struct ControlConfig {
  std::vector<std::string> endpoints;  // memory-node admin addresses "host:port"
  std::string controller;              // optional; empty = no client reports
  std::string trust_keys;              // trust file path
  std::string state_dir;               // shared bundle-floor directory
};

// placement.replica_mode: how a store reaches the replicas (spec 7.7).
enum class ReplicaMode { Async, Sync };

struct ClientConfig {
  ScopeProviderKind provider = ScopeProviderKind::Static;
  std::string secret_file;
  std::vector<NodeConfig> nodes;
  FabricProtocol protocol = FabricProtocol::Auto;
  std::uint64_t subpool_bytes = 64ull << 20;
  std::uint32_t crypto_workers = 4;
  // fabric.keepalive_ms: keepalive PING period of the wire client (0 is rejected: it also drives reconnect).
  std::uint32_t keepalive_ms = 1000;
  // fabric.mtu: HELLO mtu. fabric.reconnect_min_ms / reconnect_max_ms: session reconnect backoff.
  std::uint32_t mtu = 4096;
  std::uint32_t reconnect_min_ms = 100;
  std::uint32_t reconnect_max_ms = 5000;
  // fabric.reconnect_connect_ms: connect timeout of each endpoint of a reconnect, or of a build that the
  // keepalive thread runs for a node that was unreachable at open (default 1000). Client::open's own
  // first connect keeps the fabric default (5 s).
  std::uint32_t reconnect_connect_ms = 1000;
  // fabric.watchdog_grace_ms: stuck-job watchdog grace past the deadline. 0 (unset) = derived from the
  // worst-case QP retry exhaustion plus a margin (Client::Env::kDefaultWatchdogGrace, about 19.2 s).
  std::uint32_t watchdog_grace_ms = 0;
  // [placement] replicas (1..3), replica_mode and replica_buffer_bytes: best-effort replicas, see the key table.
  std::uint32_t replicas = 1;
  ReplicaMode replica_mode = ReplicaMode::Async;
  std::uint64_t replica_buffer_bytes = 256ull << 20;  // async: bounded pool for the replicas' plaintext copies; 0 = replicas off
  // Lab mode: membership is the static [[nodes]] list; no controller. Must be true until
  // controller-driven membership (A2.1/A2.8) exists.
  bool static_membership = false;
  // Bundle mode (MB5): set when [control] is present; then `nodes` is empty and MB6a takes membership from
  // the verified bundle. Until MB6a lands Client::open refuses a config with `control` set (ErrorCode::Unsupported).
  std::optional<ControlConfig> control;
  // Lab ticket distribution: the file mira-memnode writes ([lab] ticket_file); required by
  // Client::open (lab.ticket_file).
  std::string ticket_file;
  // [tls] (admin mTLS ticket source): client cert/key and the CA that signed the node certs.
  std::string tls_cert, tls_key, tls_ca;
  std::uint32_t ticket_batch = 4;  // fabric.ticket_batch
  // verbs device name (fabric.device, e.g. "rxe0"); empty = first device. With fabric.devices it is devices[0].device.
  std::string device;
  // fabric.devices (RL2): empty = the legacy single device `device` as one wildcard device (subnet "").
  std::vector<LocalDevice> devices;
  // A3.3 NIC profile operating point. Precedence: explicit config > profile > built-in default. An unset
  // optional means "take the profile's value". fabric.mtu is explicit only when `mtu_explicit`.
  bool mtu_explicit = false;
  std::string profiles_file;  // fabric.profiles_file; empty = the built-in registry
  std::optional<std::uint32_t> read_depth, inline_bytes;
  std::optional<std::uint8_t> ack_timeout_exp, retry_count, rnr_retry_count;
};

// Loads and validates a config. `path_or_toml` is TOML text when it starts with '['
// (after leading whitespace) or contains a newline; otherwise it is a file path.
// When loaded from a path, secret_file must exist and be a regular file with mode 0600
// (no group/other bits). TOML text skips the filesystem checks (used by tests and embedding).
// Errors carry a specific static context string.
Expected<ClientConfig> load_config(std::string_view path_or_toml);

// The secret-file check on its own (exists, regular file, mode exactly 0600).
Status check_secret_file(const std::string& path);

}  // namespace miracache
