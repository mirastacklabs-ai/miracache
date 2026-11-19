// SPDX-License-Identifier: Apache-2.0
// Memory-node side of the signed cluster bundle (membership plan decisions 4 and 5; MB3a).
//
// BundleStore owns the trust keys, the persisted floor and `bundle.current` in `state_dir`, and the
// last applied snapshot that GET /v1/identity and GET /v1/bundle read. Threading (P13):
//   admin thread   push(): verify + parse + floor check + persist (fsync) of bundle.current and the floor;
//   store thread   the posted task swaps the snapshot (Server::apply_bundle), then records it here;
//   reply          only after the swap (200 = applied and persisted).
// Pushes are serialised; readers only take a short snapshot lock. This slice applies generation, epoch and
// hashes only (principals, quota and member state are MB3b; epoch enforcement is MB4).
//
// Start-up (P14, X03, X04): bundle.current is re-verified against the trust file AND checked against the floor.
// If it does not pass, the node serves without a bundle, counts reject{reason="startup_unverified"}, sets the gauge
// miracache_bundle_startup_unverified and logs an error; a valid pushed bundle supersedes it (and clears the alert).
// Exception (design decision): when the ONLY failure is unknown_key / key_role (a key rotated out of the trust
// file) and the bundle's body hash, sec hash and both generations equal the floor's, it is applied anyway and the
// alert stays up until the next successful push. Anything else (bad signature, format, schema, floor mismatch)
// means no bundle.
//
// Files (atomic: tmp + fsync + rename + directory fsync): `bundle.current` (the envelope bytes), plus the
// MB2 floor files `bundle-floor` / `bundle-floor.lock`. A push writes and fsyncs `bundle.current.tmp`, commits the
// floor, then renames (X02): a crash in between leaves a tmp that start-up promotes when it matches the floor
// exactly (hashes and generations), so a committed floor never leaves the node without its bundle.
//
// GET /v1/identity: FROZEN field list (spec 9.2; MB8a parses it): node_id, hostname, addr, admin, generation,
// applied_generation, applied_hash, sec_generation, sec_hash, key_id, sec_key_id, epoch, startup_unverified,
// rails[{addr, subnet, protocol, up, port_state, listener_ok}] (RL1: real per-rail health from the Server snapshot; up = port
// ACTIVE, listener alive, no fatal async event in the last 10 s), member_state ("active"|"draining"|"readonly"|"removed"), scopes, bytes_used
// (a store-thread snapshot, Y08), audit_seq, audit_head (RB2, Y08 note: seq and hash of the last audit entry, the
// anchor the controller records; 0 and 64 zeros when the node has no audit log).
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "control/bundle.h"
#include "control/floor_state.h"
#include "control/trust_keys.h"
#include "server/runtime/rbac.h"
#include "server/server.h"
#include "telemetry/metrics.h"
#include "util/expected.h"

namespace miracache::server {

struct BundleStoreOptions {
  std::string state_dir;
  std::string trust_path;  // [control] trust_keys
  std::uint32_t node_id = 0;
  std::string hostname;
  std::string addr;   // the node's RDMA listen addresses ("host:port[,host:port...]")
  std::string admin;  // the admin listen address
  telemetry::Registry* reg = nullptr;
  const Clock* clock = nullptr;  // injected clock for the 10 s trust-file stat check
  // GET /v1/identity "rails" (frozen field list; MB8a builds membership.nodes[].rails from it): one per RDMA listen
  // rail. protocol = the resolved transport ("roce" | "iwarp" | "ib"); subnet = the interface prefix in CIDR form.
  struct Rail {
    std::string addr, subnet, protocol;
  };
  std::vector<Rail> rails;
  // member_state, scopes, bytes_used (Y08): a snapshot the store thread keeps (Server::node_snapshot). Null = defaults.
  std::function<Server::NodeSnapshot()> snapshot;
  // audit_seq / audit_head for GET /v1/identity (RB2). Null = no audit log: 0 and 64 zeros.
  std::function<std::pair<std::uint64_t, std::string>()> audit_anchor;
  // Unix wall seconds for the future-drop_before rule (U2-02). Null = the real wall clock.
  std::function<std::int64_t()> wall_unix_s;
  // HR1: the start-up DynConfig (Server::dyn_base()). When set, a push validates config.cluster.memnode (plus this
  // node's override) against it and rejects the bundle on a STATIC key or a bad value. Null = no check (tests).
  DynPtr dyn_base;
};

// What a push learned, for the audit entry (RB2). Filled by BundleStore::push; the store-thread part is written by the
// swap task, so the object is shared (the task may outlive a timed-out call).
struct PushOutcome {
  std::optional<std::uint64_t> generation, sec_generation;
  std::uint32_t epoch = 0;
  std::string applied_hash;  // hex, once the bundle parsed
  // Set by the swap task (store thread), valid once the push returned 200 "applied": changes against the bundle that
  // was applied before (on the first bundle every binding counts as added).
  std::uint64_t rbac_added = 0, rbac_removed = 0, rbac_changed = 0;
  std::uint64_t bindings_added = 0, bindings_removed = 0, bindings_changed = 0;  // identity -> principal
  // Called on the store thread by the swap task right after the bundle is applied, even when the pushing call already
  // gave up with 504 apply_timeout (U2-06): the audit entries for a late apply are written from here.
  std::function<void(const PushOutcome&)> on_applied;
};

struct HttpReply {
  int code = 500;
  std::string ctype = "application/json";
  std::string body;
};

// CIDR prefix of the interface that owns `host` (getifaddrs: address + netmask), e.g. "10.0.0.0/24". Empty for a
// wildcard / unknown address (the caller logs a warning).
std::string rail_subnet(const std::string& host);

// Y12: the rails a bundle-mode node advertises (GET /v1/identity). The controller refuses a node whose rail has no
// subnet or a transport other than roce/iwarp, so the node refuses to start instead: `error` is non-empty (and
// `bad_rail` names the rail) when there is no listen rail, a rail address has no resolvable interface subnet
// (wildcard, hostname, unlisted address), or `protocol` is not "roce" / "iwarp" (e.g. "ib").
struct BundleRails {
  std::vector<BundleStoreOptions::Rail> rails;
  std::string error, bad_rail;
};
// `subnets` (optional, parallel to `listen`): the [[node.rails]] subnet labels; an empty entry is derived from the address.
BundleRails bundle_rails(const std::vector<fabric::RailAddr>& listen, const std::string& protocol,
                         const std::vector<std::string>& subnets = {});

class BundleStore {
 public:
  // Runs `task` on the store thread (between run_once turns) and returns true once it has finished,
  // false if the store thread did not answer in time. Provided by AdminHttps.
  using StoreCall = std::function<bool(std::function<void(Server&)> task)>;

  static constexpr Nanos kTrustStatInterval = std::chrono::seconds(10);

  // Loads the trust file (unusable = error), the floor (corrupt = error, never blank) and bundle.current.
  static Expected<std::unique_ptr<BundleStore>> open(BundleStoreOptions o);

  // The bundle verified from disk at start-up, or null (none, or unverified). main applies it to the
  // Server once, before the store loop runs.
  std::shared_ptr<const control::BundleView> startup_view() const { return startup_view_; }
  bool startup_unverified() const { return startup_unverified_.load(); }
  // Fallback for rails[].up until the Server has a first health reading (RL1: the real health replaces it).
  void set_rails_up(bool up) { rails_up_.store(up); }

  // SIGHUP / the 10 s stat check: re-read the trust file. On failure the old keys stay in use.
  Status reload_trust();
  void maybe_reload_trust();

  // POST /v1/bundle[?dry_run=1]. Admin thread.
  HttpReply push(std::string_view bytes, bool dry_run, const StoreCall& call, std::shared_ptr<PushOutcome> out = nullptr);
  // Roles from the applied bundle's [[rbac]] (empty until a bundle is applied). Updated before a push replies.
  const RbacTable& rbac() const { return rbac_; }
  // GET /v1/bundle[?after=G]: 200 envelope, 304 nothing newer, 404 none, 400 bad `after`.
  HttpReply get_bundle(const std::string& query);
  // GET /v1/identity.
  HttpReply identity();

 private:
  struct Applied {
    bool present = false;
    std::uint64_t generation = 0, sec_generation = 0;
    std::uint32_t epoch = 0;
    control::Sha256Digest body_hash{}, sec_hash{};
    control::KeyId key_id{}, sec_key_id{};
    std::shared_ptr<const std::string> envelope;
  };
  explicit BundleStore(BundleStoreOptions o, control::FloorState f) : opt_(std::move(o)), floor_(std::move(f)) {}

  void count_reject(const char* reason);
  void count_result(const char* result);
  Expected<control::Verdict, control::BundleError> floor_admit(const control::BundleView& v, std::uint64_t pinned,
                                                               bool commit, bool& io_failed);
  // bundle.current.tmp: written and fsynced BEFORE the floor commit, renamed after it (X02).
  Status write_tmp(std::string_view envelope);
  Status publish_tmp();
  void clear_startup_alert();
  // Store thread (after Server::apply_bundle) or admin thread (replace): publish the snapshot.
  void set_applied(const control::BundleView& v, std::shared_ptr<const std::string> envelope);
  std::shared_ptr<const control::TrustKeys> trust() const;
  std::string summary_json(const char* result) const;

  BundleStoreOptions opt_;
  control::FloorState floor_;
  std::mutex push_mu_;  // serialises pushes
  mutable std::mutex mu_;  // guards trust_, applied_, stat_, next_stat_
  std::shared_ptr<const control::TrustKeys> trust_;
  Applied applied_;
  struct StatSig {
    std::int64_t mtime_ns = 0, size = -1, ino = 0;
    bool operator==(const StatSig&) const = default;
  } stat_;
  Nanos next_stat_{0};
  std::shared_ptr<const control::BundleView> startup_view_;
  std::atomic<bool> startup_unverified_{false};
  std::atomic<bool> rails_up_{false};
  telemetry::Gauge* unverified_gauge_ = nullptr;
  RbacTable rbac_;
};

}  // namespace miracache::server
