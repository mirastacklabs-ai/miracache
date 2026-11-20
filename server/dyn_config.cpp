// SPDX-License-Identifier: Apache-2.0
#include "server/dyn_config.h"

#include <algorithm>
#include <chrono>
#include <cstring>

#include <toml++/toml.hpp>

namespace miracache::server {
namespace {

using std::chrono::seconds;

Error bad(const char* what) { return Error{ErrorCode::InvalidArgument, what}; }

struct Ctx {
  DynConfig out;
  std::string error;
  std::vector<std::string> unknown;
  bool fail(std::string m) {
    if (error.empty()) error = std::move(m);
    return false;
  }
};

bool get_uint(Ctx& c, const toml::table& t, const char* sec, const char* key, std::uint64_t lo, std::uint64_t hi,
              std::uint64_t& out) {
  const toml::node* n = t.get(key);
  if (!n) return true;
  const auto v = n->value<std::int64_t>();
  if (!n->is_integer() || !v || *v < 0 || static_cast<std::uint64_t>(*v) < lo || static_cast<std::uint64_t>(*v) > hi)
    return c.fail(std::string(sec) + "." + key + " must be an integer in " + std::to_string(lo) + ".." + std::to_string(hi));
  out = static_cast<std::uint64_t>(*v);
  return true;
}
template <class T>
bool get_u(Ctx& c, const toml::table& t, const char* sec, const char* key, std::uint64_t lo, std::uint64_t hi, T& out) {
  std::uint64_t v = static_cast<std::uint64_t>(out);
  if (!get_uint(c, t, sec, key, lo, hi, v)) return false;
  out = static_cast<T>(v);
  return true;
}
bool get_secs(Ctx& c, const toml::table& t, const char* sec, const char* key, std::uint64_t lo, Nanos& out) {
  std::uint64_t v = static_cast<std::uint64_t>(std::chrono::duration_cast<seconds>(out).count());
  if (!get_uint(c, t, sec, key, lo, 86400ull * 366, v)) return false;
  out = seconds(static_cast<std::int64_t>(v));
  return true;
}

bool in(std::string_view k, std::initializer_list<const char*> names) {
  for (const char* n : names)
    if (k == n) return true;
  return false;
}

// Flat pre-reload [store] names -> their new home.
const char* stale_target(std::string_view k) {
  if (k == "scope_idle_ttl_s") return "retention.idle_ttl_s";
  if (k == "max_ttl_s") return "retention.max_ttl_s";
  if (k == "sweep_bytes_per_s") return "evict.sweep_bytes_per_s";
  if (k == "sweep_blocks_per_turn") return "evict.sweep_blocks_per_turn";
  if (k == "high_pct") return "evict.high_pct";
  if (k == "low_pct") return "evict.low_pct";
  if (k == "put_ops_per_s") return "quota.put_ops_per_s";
  if (k == "put_bytes_per_s") return "quota.put_bytes_per_s";
  return nullptr;
}

constexpr std::initializer_list<const char*> kStoreStatic = {
    "backing",      "dir",           "segment_bytes",       "run_bytes",      "min_block_bytes",
    "n_segments",   "require_1g",    "hugepage_size",       "scope_records",  "max_puts_per_endpoint",
    "max_leases_per_session"};

// Walks a section: stale and STATIC names reject, unknown names are collected. `known` are the dynamic keys.
bool scan(Ctx& c, const toml::table& t, const char* sec, std::initializer_list<const char*> known) {
  for (const auto& [k, v] : t) {
    (void)v;
    const std::string_view key = k.str();
    if (std::string_view(sec) == "store") {
      if (const char* to = stale_target(key))
        return c.fail(std::string("stale key store.") + std::string(key) + ": renamed " + to);
      if (in(key, kStoreStatic)) return c.fail("store." + std::string(key) + " is STATIC (restart the node)");
    }
    if (!in(key, known)) c.unknown.push_back(std::string(sec) + "." + std::string(key));
  }
  return true;
}

bool parse_lease(Ctx& c, const toml::table& t) {
  DynConfig& o = c.out;
  return scan(c, t, "lease", {"ttl_s", "max_s", "put_timeout_s"}) && get_secs(c, t, "lease", "ttl_s", 1, o.lease_ttl) &&
         get_secs(c, t, "lease", "max_s", 1, o.lease_max) && get_secs(c, t, "lease", "put_timeout_s", 1, o.put_timeout);
}
bool parse_ticket(Ctx& c, const toml::table& t) {
  return scan(c, t, "ticket", {"ttl_s"}) && get_secs(c, t, "ticket", "ttl_s", 1, c.out.ticket_ttl);
}
bool parse_limits(Ctx& c, const toml::table& t) {
  DynConfig& o = c.out;
  return scan(c, t, "limits",
              {"ticket_max_per_identity", "admit_timeout_s", "hello_deadline_s", "idle_timeout_s", "max_conns_per_principal",
               "max_leases_per_principal"}) &&
         get_u(c, t, "limits", "ticket_max_per_identity", 1, 1u << 24, o.ticket_max_per_identity) &&
         get_secs(c, t, "limits", "admit_timeout_s", 1, o.admit_timeout) &&
         get_secs(c, t, "limits", "hello_deadline_s", 1, o.hello_deadline) &&
         get_secs(c, t, "limits", "idle_timeout_s", 1, o.idle_timeout) &&
         get_u(c, t, "limits", "max_conns_per_principal", 1, 1u << 24, o.max_conns_per_principal) &&
         get_u(c, t, "limits", "max_leases_per_principal", 1, 1u << 24, o.max_leases_per_principal);
}
bool parse_store(Ctx& c, const toml::table& t) {
  DynConfig& o = c.out;
  return scan(c, t, "store", {"invalidate_per_s", "max_scopes", "max_bytes", "max_exact_classes_per_owner"}) &&
         get_u(c, t, "store", "invalidate_per_s", 0, 1u << 30, o.invalidate_per_s) &&
         get_u(c, t, "store", "max_scopes", 1, UINT32_MAX, o.max_scopes) &&
         get_u(c, t, "store", "max_bytes", 1, INT64_MAX, o.max_bytes) &&
         get_u(c, t, "store", "max_exact_classes_per_owner", 1, 64, o.max_exact_classes_per_owner);
}
bool parse_retention(Ctx& c, const toml::table& t) {
  DynConfig& o = c.out;
  return scan(c, t, "retention", {"idle_ttl_s", "max_ttl_s"}) && get_secs(c, t, "retention", "idle_ttl_s", 1, o.idle_ttl) &&
         get_secs(c, t, "retention", "max_ttl_s", 0, o.max_ttl);  // 0 = off
}
bool parse_evict(Ctx& c, const toml::table& t) {
  DynConfig& o = c.out;
  return scan(c, t, "evict", {"sweep_bytes_per_s", "sweep_blocks_per_turn", "high_pct", "low_pct"}) &&
         get_u(c, t, "evict", "sweep_bytes_per_s", 1, INT64_MAX, o.sweep_bytes_per_s) &&
         get_u(c, t, "evict", "sweep_blocks_per_turn", 1, 1u << 20, o.sweep_blocks_per_turn) &&
         get_u(c, t, "evict", "high_pct", 1, 100, o.high_pct) && get_u(c, t, "evict", "low_pct", 1, 100, o.low_pct);
}
bool parse_scrub(Ctx& c, const toml::table& t) {
  DynConfig& o = c.out;
  if (!scan(c, t, "scrub", {"enabled", "bytes_per_s"})) return false;
  if (const toml::node* n = t.get("enabled")) {
    const auto v = n->value<bool>();
    if (!n->is_boolean() || !v) return c.fail("scrub.enabled must be a boolean");
    o.scrub_enabled = *v;
  }
  return get_u(c, t, "scrub", "bytes_per_s", 0, INT64_MAX, o.scrub_bytes_per_s);  // 0 = off
}
bool parse_quota(Ctx& c, const toml::table& t) {
  DynConfig& o = c.out;
  return scan(c, t, "quota", {"put_ops_per_s", "put_bytes_per_s"}) &&
         get_u(c, t, "quota", "put_ops_per_s", 0, INT64_MAX, o.put_ops_per_s) &&
         get_u(c, t, "quota", "put_bytes_per_s", 0, INT64_MAX, o.put_bytes_per_s);  // 0 = unlimited
}

// Shallow merge, section by section and key by key: the node override wins.
void merge_over(toml::table& dst, const toml::table& over) {
  for (const auto& [sec, node] : over) {
    const toml::table* ot = node.as_table();
    toml::table* dt = dst.get_as<toml::table>(sec);
    if (!ot || !dt) {
      dst.insert_or_assign(sec, node);
      continue;
    }
    for (const auto& [k, v] : *ot) dt->insert_or_assign(k, v);
  }
}

}  // namespace

DynConfig dyn_from_server_config(const ServerConfig& c) {
  DynConfig d;
  d.lease_ttl = c.store.lease_ttl;
  d.lease_max = c.store.lease_max;
  d.put_timeout = c.store.put_timeout;
  d.ticket_ttl = c.ticket_ttl;
  d.ticket_max_per_identity = c.ticket_max_per_identity;
  d.admit_timeout = c.admit_timeout;
  d.hello_deadline = c.hello_deadline;
  d.idle_timeout = c.idle_timeout;
  d.max_conns_per_principal = c.max_conns_per_principal;
  d.max_leases_per_principal = c.max_leases_per_principal;
  d.invalidate_per_s = c.store.invalidate_per_s;
  d.max_scopes = c.store.principal_default.max_scopes;
  d.max_bytes = c.store.principal_default.max_bytes != 0 ? c.store.principal_default.max_bytes : backing_bytes(c.store);
  d.max_exact_classes_per_owner = c.store.max_exact_classes_per_owner;
  d.idle_ttl = c.store.principal_default.idle_ttl;
  d.max_ttl = c.store.max_ttl;
  d.sweep_bytes_per_s = c.store.sweep_bytes_per_s;
  d.sweep_blocks_per_turn = c.store.sweep_blocks_per_turn;
  d.high_pct = c.store.high_pct;
  d.low_pct = c.store.low_pct;
  d.scrub_enabled = c.store.scrub_enabled;
  d.scrub_bytes_per_s = c.store.scrub_bytes_per_s;
  d.put_ops_per_s = c.store.principal_default.put_ops_per_s;
  d.put_bytes_per_s = c.store.principal_default.put_bytes_per_s;
  d.drain_ms = c.goaway_drain_ms;
  return d;
}

void dyn_into_server_config(const DynConfig& d, ServerConfig& c) {
  c.store.lease_ttl = d.lease_ttl;
  c.store.lease_max = d.lease_max;
  c.store.put_timeout = d.put_timeout;
  c.ticket_ttl = d.ticket_ttl;
  c.ticket_max_per_identity = d.ticket_max_per_identity;
  c.admit_timeout = d.admit_timeout;
  c.hello_deadline = d.hello_deadline;
  c.idle_timeout = d.idle_timeout;
  c.max_conns_per_principal = d.max_conns_per_principal;
  c.max_leases_per_principal = d.max_leases_per_principal;
  c.store.invalidate_per_s = d.invalidate_per_s;
  c.store.principal_default.max_scopes = d.max_scopes;
  c.store.principal_default.max_bytes = d.max_bytes;
  c.store.max_exact_classes_per_owner = d.max_exact_classes_per_owner;
  c.store.principal_default.idle_ttl = d.idle_ttl;
  c.store.max_ttl = d.max_ttl;
  c.store.sweep_bytes_per_s = d.sweep_bytes_per_s;
  c.store.sweep_blocks_per_turn = d.sweep_blocks_per_turn;
  c.store.high_pct = d.high_pct;
  c.store.low_pct = d.low_pct;
  c.store.scrub_enabled = d.scrub_enabled;
  c.store.scrub_bytes_per_s = d.scrub_bytes_per_s;
  c.store.principal_default.put_ops_per_s = d.put_ops_per_s;
  c.store.principal_default.put_bytes_per_s = d.put_bytes_per_s;
  c.goaway_drain_ms = d.drain_ms;
}

Status validate_dyn(const DynConfig& d) {
  const Nanos z{0};
  if (d.lease_ttl <= z || d.lease_max < d.lease_ttl) return bad("config: lease.max_s must be >= lease.ttl_s, both > 0");
  if (d.put_timeout <= z) return bad("config: lease.put_timeout_s must be > 0");
  if (d.ticket_ttl <= z) return bad("config: ticket.ttl_s must be > 0");
  if (d.admit_timeout <= z || d.admit_timeout >= d.ticket_ttl)
    return bad("config: limits.admit_timeout_s must be > 0 and < ticket.ttl_s");
  if (d.hello_deadline <= z || d.idle_timeout <= z) return bad("config: limits.hello_deadline_s and idle_timeout_s must be > 0");
  // max_conns_per_principal == 0 and ticket_max_per_identity == 0 mean "computed at Server::create"; an
  // explicit 0 is refused where the key is parsed.
  if (d.max_leases_per_principal < 1)
    return bad("config: limits.* counts must be >= 1");
  if (d.max_scopes < 1 || d.max_bytes < 1 || d.max_exact_classes_per_owner < 1)
    return bad("config: store.max_scopes, max_bytes and max_exact_classes_per_owner must be >= 1");
  if (d.idle_ttl <= z) return bad("config: retention.idle_ttl_s must be > 0");
  if (d.max_ttl < z) return bad("config: retention.max_ttl_s must be >= 0");
  if (d.sweep_bytes_per_s < 1 || d.sweep_blocks_per_turn < 1) return bad("config: evict.sweep_* must be >= 1");
  if (d.low_pct < 1 || d.low_pct >= d.high_pct || d.high_pct > 99)
    return bad("config: evict.low_pct must be < evict.high_pct <= 99");
  if (d.drain_ms > 600000) return bad("config: node.drain_ms must be <= 600000");
  return {};
}

std::string bundle_node_admin(const control::BodyView& body, std::uint32_t node_id) {
  for (const auto& n : body.nodes)
    if (n.node_id == node_id) return n.admin;
  return {};
}

DynParse parse_memnode_dyn(std::string_view config_toml, const DynConfig& base, std::string_view node_admin,
                           std::uint64_t generation) {
  DynParse res;
  Ctx c;
  c.out = base;
  c.out.generation = generation;
  c.out.pending.clear();
  toml::table root;
  if (!config_toml.empty()) {
    toml::parse_result pr = toml::parse(config_toml);
    if (!pr) {
      res.error = "config does not parse";
      return res;
    }
    root = std::move(pr).table();
  }
  toml::table merged;
  if (const toml::table* cl = root.get_as<toml::table>("cluster"))
    if (const toml::table* mn = cl->get_as<toml::table>("memnode")) merged = *mn;
  if (!node_admin.empty()) {
    if (const toml::table* nodes = root.get_as<toml::table>("node"))
      if (const toml::table* me = nodes->get_as<toml::table>(node_admin))
        if (const toml::table* mn = me->get_as<toml::table>("memnode")) merge_over(merged, *mn);
  }
  for (const auto& [k, v] : merged) {
    const std::string_view name = k.str();
    const toml::table* t = v.as_table();
    if (!t) {
      c.unknown.push_back(std::string(name));
      continue;
    }
    bool ok = true;
    if (name == "lease") ok = parse_lease(c, *t);
    else if (name == "ticket") ok = parse_ticket(c, *t);
    else if (name == "limits") ok = parse_limits(c, *t);
    else if (name == "store") ok = parse_store(c, *t);
    else if (name == "retention") ok = parse_retention(c, *t);
    else if (name == "evict") ok = parse_evict(c, *t);
    else if (name == "quota") ok = parse_quota(c, *t);
    else if (name == "scrub") ok = parse_scrub(c, *t);
    else if (name == "node") {
      for (const auto& [nk, nv] : *t) {
        (void)nv;
        if (nk.str() == "drain_ms") c.out.pending.push_back("node.drain_ms");  // class A but node-local: the local file
        else ok = c.fail("node." + std::string(nk.str()) + " is STATIC (restart the node)");
        if (!ok) break;
      }
    } else if (name == "admin" || name == "telemetry" || name == "log" || name == "audit") {
      for (const auto& [nk, nv] : *t) {  // class B / node-local: recorded as pending, never applied from the bundle
        (void)nv;
        c.out.pending.push_back(std::string(name) + "." + std::string(nk.str()));
      }
    } else if (name == "control" || name == "executor" || name == "nic") {
      ok = c.fail(std::string(name) + ".* is STATIC (restart the node)");
    } else {
      c.unknown.push_back(std::string(name));
    }
    if (!ok) {
      res.error = c.error;
      return res;
    }
  }
  if (auto st = validate_dyn(c.out); !st) {
    res.error = st.error().context;
    return res;
  }
  // put_timeout >= 4 x the clients' deadline.put_max_ms (default 2500 ms), both from this bundle.
  {
    std::int64_t put_max_ms = 2500;
    bool mentioned = false;  // only a bundle that sets one of the two keys is checked (a local base value is not bundle content)
    if (const toml::table* ls = merged.get_as<toml::table>("lease")) mentioned = ls->contains("put_timeout_s");
    auto client_put_max = [&](const toml::table* parent) {
      if (!parent) return;
      if (const toml::table* cl = parent->get_as<toml::table>("client"))
        if (const toml::table* dl = cl->get_as<toml::table>("deadline"))
          if (const toml::node* n = dl->get("put_max_ms"))
            if (auto v = n->value<std::int64_t>(); n->is_integer() && v) put_max_ms = *v, mentioned = true;
    };
    if (const toml::table* cl = root.get_as<toml::table>("cluster")) client_put_max(cl);
    if (!node_admin.empty())
      if (const toml::table* nodes = root.get_as<toml::table>("node"))
        client_put_max(nodes->get_as<toml::table>(node_admin));
    const std::int64_t put_ms = std::chrono::duration_cast<std::chrono::milliseconds>(c.out.put_timeout).count();
    if (mentioned && put_max_ms > 0 && put_ms < 4 * put_max_ms) {
      res.error = "config: lease.put_timeout_s must be >= 4 x client deadline.put_max_ms";
      return res;
    }
  }
  res.dyn = std::make_shared<const DynConfig>(std::move(c.out));
  res.unknown = std::move(c.unknown);
  return res;
}

std::vector<std::string> dyn_changed_keys(const DynConfig& a, const DynConfig& b) {
  std::vector<std::string> k;
#define MC_DIFF(field, name) \
  if (a.field != b.field) k.push_back(name)
  MC_DIFF(lease_ttl, "lease.ttl_s");
  MC_DIFF(lease_max, "lease.max_s");
  MC_DIFF(put_timeout, "lease.put_timeout_s");
  MC_DIFF(ticket_ttl, "ticket.ttl_s");
  MC_DIFF(ticket_max_per_identity, "limits.ticket_max_per_identity");
  MC_DIFF(admit_timeout, "limits.admit_timeout_s");
  MC_DIFF(hello_deadline, "limits.hello_deadline_s");
  MC_DIFF(idle_timeout, "limits.idle_timeout_s");
  MC_DIFF(max_conns_per_principal, "limits.max_conns_per_principal");
  MC_DIFF(max_leases_per_principal, "limits.max_leases_per_principal");
  MC_DIFF(invalidate_per_s, "store.invalidate_per_s");
  MC_DIFF(max_scopes, "store.max_scopes");
  MC_DIFF(max_bytes, "store.max_bytes");
  MC_DIFF(max_exact_classes_per_owner, "store.max_exact_classes_per_owner");
  MC_DIFF(idle_ttl, "retention.idle_ttl_s");
  MC_DIFF(max_ttl, "retention.max_ttl_s");
  MC_DIFF(sweep_bytes_per_s, "evict.sweep_bytes_per_s");
  MC_DIFF(sweep_blocks_per_turn, "evict.sweep_blocks_per_turn");
  MC_DIFF(high_pct, "evict.high_pct");
  MC_DIFF(low_pct, "evict.low_pct");
  MC_DIFF(scrub_enabled, "scrub.enabled");
  MC_DIFF(scrub_bytes_per_s, "scrub.bytes_per_s");
  MC_DIFF(put_ops_per_s, "quota.put_ops_per_s");
  MC_DIFF(put_bytes_per_s, "quota.put_bytes_per_s");
  MC_DIFF(drain_ms, "node.drain_ms");
#undef MC_DIFF
  return k;
}

std::vector<std::string> static_changed_keys(const NodeConfig& a, const NodeConfig& b) {
  std::vector<std::string> k;
  const auto& x = a.server;
  const auto& y = b.server;
#define MC_DIFF(lhs, rhs, name) \
  if ((lhs) != (rhs)) k.push_back(name)
  MC_DIFF(x.store.backing, y.store.backing, "store.backing");
  MC_DIFF(x.store.dir, y.store.dir, "store.dir");
  MC_DIFF(x.store.segment_bytes, y.store.segment_bytes, "store.segment_bytes");
  MC_DIFF(x.store.run_bytes, y.store.run_bytes, "store.run_bytes");
  MC_DIFF(x.store.min_block_bytes, y.store.min_block_bytes, "store.min_block_bytes");
  MC_DIFF(x.store.n_segments, y.store.n_segments, "store.n_segments");
  MC_DIFF(x.store.require_1g, y.store.require_1g, "store.require_1g");
  MC_DIFF(x.store.max_puts_per_endpoint, y.store.max_puts_per_endpoint, "store.max_puts_per_endpoint");
  MC_DIFF(x.store.max_leases_per_session, y.store.max_leases_per_session, "store.max_leases_per_session");
  MC_DIFF(x.store.scope_records, y.store.scope_records, "store.scope_records");
  MC_DIFF(x.store.state_dir, y.store.state_dir, "node.state_dir");
  MC_DIFF(a.device, b.device, "node.device");
  MC_DIFF(a.protocol, b.protocol, "node.protocol");
  MC_DIFF(x.wire_protocol, y.wire_protocol, "node.protocol");
  if (x.rails.size() != y.rails.size()) {
    k.push_back("node.listen");
  } else {
    for (std::size_t i = 0; i < x.rails.size(); ++i)
      if (x.rails[i].host != y.rails[i].host || x.rails[i].port != y.rails[i].port) {
        k.push_back("node.listen");
        break;
      }
  }
  // Rails are restart-class: a changed device (per rail) or subnet label is a STATIC change too.
  MC_DIFF(a.devices, b.devices, "node.rails");
  MC_DIFF(x.rail_device, y.rail_device, "node.rails");
  MC_DIFF(a.rail_subnets, b.rail_subnets, "node.rails");
  // The admin.ca PATH is STATIC (the file's contents reload, a different path needs a restart).
  MC_DIFF(a.admin_ca, b.admin_ca, "admin.ca");
  MC_DIFF(a.trust_keys, b.trust_keys, "control.trust_keys");
  MC_DIFF(a.workers, b.workers, "executor.workers");
  MC_DIFF(a.profiles_file, b.profiles_file, "nic.profiles_file");
#undef MC_DIFF
  k.erase(std::unique(k.begin(), k.end()), k.end());
  return k;
}

SighupPlan plan_sighup(const NodeConfig& boot, const NodeConfig& fresh, const DynConfig& current, bool bundle_mode,
                       std::uint32_t conns_default, std::uint32_t tickets_default) {
  SighupPlan p;
  p.static_changed = static_changed_keys(boot, fresh);
  if (!p.static_changed.empty()) return p;
  DynConfig next = bundle_mode ? current : dyn_from_server_config(fresh.server);
  next.drain_ms = fresh.drain_ms;
  if (next.max_conns_per_principal == 0)  // key not in the file: the computed default
    next.max_conns_per_principal = conns_default != 0 ? conns_default : current.max_conns_per_principal;
  if (next.ticket_max_per_identity == 0)  // key not in the file: the computed default
    next.ticket_max_per_identity = tickets_default != 0 ? tickets_default : current.ticket_max_per_identity;
  if (!bundle_mode) next.generation = 0;
  p.dyn = std::make_shared<const DynConfig>(std::move(next));
  return p;
}

}  // namespace miracache::server
