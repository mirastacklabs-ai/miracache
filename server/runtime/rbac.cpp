// SPDX-License-Identifier: Apache-2.0
#include "server/runtime/rbac.h"

#include <unistd.h>

#include <algorithm>
#include <cerrno>

#include "control/floor_state.h"
#include "server/server.h"
#include "util/clock.h"
#include "util/log.h"

namespace miracache::server {

const std::vector<RouteRule>& route_table() {
  static const std::vector<RouteRule> t = {
      {RouteId::Tickets, "POST", "/v1/tickets", Need::Principal, false},
      {RouteId::BundleGet, "GET", "/v1/bundle", Need::Authenticated, true},
      {RouteId::BundlePost, "POST", "/v1/bundle", Need::Authenticated, true},
      {RouteId::Identity, "GET", "/v1/identity", Need::Authenticated, true},
      {RouteId::Drain, "POST", "/v1/drain", Need::Operator, false},
      {RouteId::DropPrincipal, "POST", "/v1/drop_principal", Need::SecurityAdmin, false},
  };
  return t;
}

const RouteRule* find_route(std::string_view method, std::string_view path) {
  for (const auto& r : route_table())
    if (method == r.method && path == r.path) return &r;
  return nullptr;
}

bool path_known(std::string_view path) {
  for (const auto& r : route_table())
    if (path == r.path) return true;
  return false;
}

const char* need_role(Need n) {
  switch (n) {
    case Need::Operator: return "operator";
    case Need::SecurityAdmin: return "security-admin";
    default: return "";
  }
}

bool role_grants(std::string_view role, Need n) {
  switch (n) {
    case Need::Principal:
    case Need::Authenticated: return true;
    case Need::Operator: return role == "operator";
    case Need::SecurityAdmin: return role == "security-admin";
  }
  return false;  // viewer reads; scope-provider grants nothing in v1; unknown roles grant nothing
}

void RbacTable::set(const std::vector<RbacBinding>& bindings) {
  auto m = std::make_shared<Map>();
  for (const auto& b : bindings) {
    auto& v = (*m)[b.identity];
    for (const auto& r : b.roles)
      if (std::find(v.begin(), v.end(), r) == v.end()) v.push_back(r);
    std::sort(v.begin(), v.end());
  }
  std::lock_guard<std::mutex> g(m_);
  t_ = std::move(m);
}

std::vector<std::string> RbacTable::roles_of(const std::string& identity) const {
  std::shared_ptr<const Map> t;
  {
    std::lock_guard<std::mutex> g(m_);
    t = t_;
  }
  const auto it = t->find(identity);
  return it == t->end() ? std::vector<std::string>{} : it->second;
}

bool RbacTable::allows(const std::string& identity, Need n) const {
  if (n == Need::Principal || n == Need::Authenticated) return true;
  for (const auto& r : roles_of(identity))
    if (role_grants(r, n)) return true;
  return false;
}

std::string RbacTable::label(const std::string& identity) const {
  std::string out;
  for (const auto& r : roles_of(identity)) {
    if (!out.empty()) out += ',';
    out += r;
  }
  return out.empty() ? "none" : out;
}

std::size_t RbacTable::size() const {
  std::lock_guard<std::mutex> g(m_);
  return t_->size();
}

// ---- audit ----------------------------------------------------------------------------------------

Expected<std::unique_ptr<AdminAudit>> AdminAudit::open(AdminAuditOptions o) {
  control::AuditConfig c;
  c.dir = o.dir;
  c.src.controller = false;
  c.src.node_id = o.node_id;
  c.src.host = o.host;
  c.src.addr = o.addr;
  c.max_bytes = o.max_bytes;
  c.max_total_bytes = o.max_total_bytes;
  c.fsync_every_entry = false;  // memory node: one write(2) per entry, at most one fsync per second
  c.now_ms = o.now_ms;
  c.write_fn = o.write_fn;
  c.fsync_fn = o.fsync_fn;
  auto l = control::AuditLog::open(std::move(c));
  if (!l) return l.error();
  std::unique_ptr<AdminAudit> a(new AdminAudit());
  a->log_ = std::make_unique<control::AuditLog>(std::move(*l));
  a->now_ms_ = o.now_ms ? o.now_ms : [] { return static_cast<std::uint64_t>(wall_unix_ns() / 1000000); };
  a->synced_seq_ = a->log_->seq();  // what open() found on disk (and its recover entry) is as durable as it will get
  a->synced_head_ = a->log_->head();
  return a;
}

AdminAudit::~AdminAudit() { flush_all(); }

std::uint64_t AdminAudit::now() const { return now_ms_(); }

bool AdminAudit::append_locked(const control::AuditEntry& e) {
  const Status st = log_->append(e);
  if (!st) {
    ++errors_;
    log::write(log::Level::Error, "audit", "audit append failed", {{"action", e.action}, {"err", st.error().context}});
    return false;
  }
  // Each entry is also logged as logfmt (comp=audit) with the same fields.
  log::write(log::Level::Info, "audit", e.action,
             {{"seq", std::to_string(log_->seq())}, {"actor", e.actor}, {"role", e.role}, {"target", e.target},
              {"result", e.result}, {"reason", e.reason}, {"count", std::to_string(e.count)}});
  return true;
}

void AdminAudit::flush_locked(bool all) {
  for (const auto& e : co_.flush(now(), all)) (void)append_locked(e);
}

bool AdminAudit::record(const control::AuditEntry& e) {
  std::lock_guard<std::mutex> g(m_);
  flush_locked(false);
  return append_locked(e);
}

void AdminAudit::deny(const control::AuditEntry& e) {
  std::lock_guard<std::mutex> g(m_);
  co_.add(e, now());
}

void AdminAudit::tick() {
  std::lock_guard<std::mutex> g(m_);
  flush_locked(false);
  const std::uint64_t t = now();
  if (t >= last_sync_ms_ + 1000 || t < last_sync_ms_) {  // at most one fsync per second
    last_sync_ms_ = t;
    if (log_->sync()) {
      synced_seq_ = log_->seq();
      synced_head_ = log_->head();
    }
  }
}

std::pair<std::uint64_t, std::string> AdminAudit::anchor() {
  std::lock_guard<std::mutex> g(m_);
  if (log_->sync()) {
    synced_seq_ = log_->seq();
    synced_head_ = log_->head();
  }
  return {synced_seq_, synced_head_};
}

void AdminAudit::flush_all() {
  std::lock_guard<std::mutex> g(m_);
  flush_locked(true);
  if (log_->sync()) {
    synced_seq_ = log_->seq();
    synced_head_ = log_->head();
  }
}

Status load_persisted_drop_before(Server& srv, const std::string& state_dir) {
  if (state_dir.empty()) return {};
  const std::string path = state_dir + "/bundle-floor";
  if (::access(path.c_str(), F_OK) != 0 && errno == ENOENT) return {};  // no floor yet: nothing was ever persisted
  auto fs = control::FloorState::open(state_dir);
  if (!fs) return fs.error();
  auto fl = fs->load();
  if (!fl) return fl.error();
  srv.load_drop_before_floor(fl->drop_before);
  return {};
}

std::uint64_t AdminAudit::seq() const {
  std::lock_guard<std::mutex> g(m_);
  return log_->seq();
}

std::string AdminAudit::head() const {
  std::lock_guard<std::mutex> g(m_);
  return log_->head();
}

std::uint64_t AdminAudit::errors() const {
  std::lock_guard<std::mutex> g(m_);
  return errors_;
}

}  // namespace miracache::server
