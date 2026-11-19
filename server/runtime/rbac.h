// SPDX-License-Identifier: Apache-2.0
// Memory-node RBAC and audit wiring for the admin API (RBAC/audit plan decisions 2-6; slice RB2).
//
//  * The route table (decision 4) is ONE code table: enforcement and tests both read it.
//      POST /v1/tickets                principal identity (the principal table decides, not a role)
//      GET  /v1/bundle                 authenticated mTLS only (bundle mode)
//      POST /v1/bundle[?dry_run=1]     authenticated mTLS only; the bundle signatures are the gate (P03)
//      GET  /v1/identity               authenticated mTLS only (bundle mode)
//      POST /v1/drain                  operator
//      POST /v1/drop_principal         security-admin
//  * Roles: viewer, operator, security-admin, scope-provider. viewer reads (no memory-node route needs it);
//    operator may drain; security-admin may drop a principal; scope-provider grants nothing in v1. An unknown
//    role string grants nothing.
//  * Bindings (identity -> roles) come from the applied bundle's `[[rbac]]` (bundle mode) or from the node-local
//    `[[admin.rbac]]` (lab mode, SIGHUP). A bundle-mode node with no bundle applied has no bindings.
//  * AdminAudit wraps control::AuditLog + AuditCoalescer behind one mutex: immediate entries for actions
//    (bundle apply, drain, drop_principal), per-(identity, action, result)-per-second coalesced entries for
//    denials and ticket refusals (P19). Every entry carries node ID + hostname + IP (spec goal 10).
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "control/audit.h"
#include "util/expected.h"

namespace miracache::server {

enum class Need : std::uint8_t { Principal, Authenticated, Operator, SecurityAdmin };
enum class RouteId : std::uint8_t { Tickets, BundleGet, BundlePost, Identity, Drain, DropPrincipal };

struct RouteRule {
  RouteId id;
  const char* method;
  const char* path;
  Need need;
  bool bundle_mode_only;  // 404 in lab mode (no [control] trust_keys)
};

// The decision 4 table, memory-node side.
const std::vector<RouteRule>& route_table();
// Exact method + path; null if there is none.
const RouteRule* find_route(std::string_view method, std::string_view path);
// True if some rule has this path (a wrong method on it is 405, not 404).
bool path_known(std::string_view path);
// "operator" / "security-admin" for the role-gated needs, "" otherwise.
const char* need_role(Need n);
// Does `role` satisfy `n`? (viewer, operator, security-admin, scope-provider; anything else: no.)
bool role_grants(std::string_view role, Need n);

struct RbacBinding {
  std::string identity;
  std::vector<std::string> roles;
};

// identity -> roles; swapped atomically, read from connection threads.
class RbacTable {
 public:
  void set(const std::vector<RbacBinding>& bindings);
  std::vector<std::string> roles_of(const std::string& identity) const;
  // True when `n` needs no role, or the identity holds a role that grants it.
  bool allows(const std::string& identity, Need n) const;
  // "operator,viewer" for the audit `role` field; "none" if the identity has no binding.
  std::string label(const std::string& identity) const;
  std::size_t size() const;

 private:
  using Map = std::map<std::string, std::vector<std::string>>;
  mutable std::mutex m_;
  std::shared_ptr<const Map> t_ = std::make_shared<const Map>();
};

struct AdminAuditOptions {
  std::string dir;
  std::uint64_t max_bytes = 64ull << 20;
  std::uint64_t max_total_bytes = 1ull << 30;
  std::uint32_t node_id = 0;
  std::string host, addr;
  std::function<std::uint64_t()> now_ms;  // unix ms; null = wall clock (tests inject one)
  std::function<long(int fd, const void* p, std::size_t n)> write_fn;  // tests: failure injection (AuditConfig::write_fn)
  std::function<int(int fd)> fsync_fn;                                 // tests: ditto
};

class Server;
// Start-up (main and tests): applies the drop_before maxima persisted in `<state_dir>/bundle-floor` (bundle deliveries
// and POST /v1/drop_principal) with Server::load_drop_before_floor. No state_dir or no floor file = nothing to load (ok).
// A floor file that cannot be opened, read or parsed is an error: the caller refuses to start, a corrupt floor must
// never silently drop persisted revocations (U2-07). Store thread / before the loop runs.
Status load_persisted_drop_before(Server& srv, const std::string& state_dir);

class AdminAudit {
 public:
  // Fails (I/O error, lock held, ...): the caller refuses the admin API and keeps the data plane (audit.h).
  static Expected<std::unique_ptr<AdminAudit>> open(AdminAuditOptions o);
  ~AdminAudit();
  AdminAudit(const AdminAudit&) = delete;
  AdminAudit& operator=(const AdminAudit&) = delete;

  // Appends now (after writing any closed coalescing windows). Returns false if the append failed (counted, logged).
  bool record(const control::AuditEntry& e);
  // Counts one event into the per-second window of (actor, action, result).
  void deny(const control::AuditEntry& e);
  // Timer: writes closed windows, fsyncs if due.
  void tick();
  // Shutdown: writes every open window and fsyncs.
  void flush_all();

  std::uint64_t seq() const;   // last written entry
  std::string head() const;
  // (seq, head) of the last entry known to be fsynced (U2-19): GET /v1/identity shows this, so a controller never records
  // an anchor the node could lose in a crash. Forces an fsync of what is pending; if that fails, the previous anchor.
  std::pair<std::uint64_t, std::string> anchor();
  std::uint64_t errors() const;

 private:
  AdminAudit() = default;
  std::uint64_t now() const;
  bool append_locked(const control::AuditEntry& e);
  void flush_locked(bool all);

  mutable std::mutex m_;
  std::unique_ptr<control::AuditLog> log_;
  control::AuditCoalescer co_;
  std::function<std::uint64_t()> now_ms_;
  std::uint64_t errors_ = 0;
  std::uint64_t last_sync_ms_ = 0;
  std::uint64_t synced_seq_ = 0;
  std::string synced_head_;
};

}  // namespace miracache::server
