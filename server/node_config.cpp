// SPDX-License-Identifier: Apache-2.0
#include "server/node_config.h"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <sstream>

#include <toml++/toml.hpp>

#include "server/dyn_config.h"

namespace miracache::server {
namespace {

Error bad(const char* ctx) { return Error{ErrorCode::InvalidArgument, ctx}; }
// A message that names a key: kept in a thread-local until the next call on this thread (Error holds a const char*).
Error bad_named(std::string msg) {
  thread_local std::string keep;
  keep = std::move(msg);
  return Error{ErrorCode::InvalidArgument, keep.c_str()};
}

template <std::size_t N>
bool keys_ok(const toml::table& t, const char* const (&allowed)[N]) {
  for (auto&& [k, v] : t) {
    bool ok = false;
    for (const char* a : allowed) ok = ok || k.str() == a;
    if (!ok) return false;
  }
  return true;
}

// Reads t[key] into out when present. False = present with the wrong type.
template <typename T>
bool get(const toml::table& t, const char* key, T& out) {
  const auto* n = t.get(key);
  if (!n) return true;
  auto v = n->value<T>();
  if (!v) return false;
  out = *v;
  return true;
}
bool get_u64(const toml::table& t, const char* key, std::uint64_t& out) {
  std::int64_t v = static_cast<std::int64_t>(out);
  if (!get(t, key, v) || v < 0) return false;
  out = static_cast<std::uint64_t>(v);
  return true;
}
// Why the last get_u32 failed (a string literal); parse_node_config reports it.
thread_local const char* g_why = nullptr;
bool get_u32(const toml::table& t, const char* key, std::uint32_t& out, const char* why) {
  std::uint64_t v = out;
  if (!get_u64(t, key, v) || v > std::numeric_limits<std::uint32_t>::max()) {
    g_why = why;
    return false;
  }
  out = static_cast<std::uint32_t>(v);
  return true;
}
#define GET_U32(t, key, dst) get_u32((t), (key), (dst), "config: " key " must be an integer in 0..4294967295")
bool get_secs(const toml::table& t, const char* key, Nanos& out) {
  std::int64_t v = std::chrono::duration_cast<std::chrono::seconds>(out).count();
  if (!get(t, key, v) || v <= 0) return false;
  out = std::chrono::seconds(v);
  return true;
}
const toml::table* section(const toml::table& root, const char* name, bool& ok) {
  const auto* n = root.get(name);
  if (!n) return nullptr;
  const auto* t = n->as_table();
  if (!t) ok = false;
  return t;
}

}  // namespace

Expected<std::uint16_t> parse_port(std::string_view s, bool allow_zero) {
  if (s.empty() || s.size() > 5) return Error{ErrorCode::InvalidArgument, "port must be a number in 1..65535"};
  std::uint32_t v = 0;
  for (char ch : s) {
    if (ch < '0' || ch > '9') return Error{ErrorCode::InvalidArgument, "port must be a number in 1..65535"};
    v = v * 10 + static_cast<std::uint32_t>(ch - '0');
  }
  if (v > 65535 || (v == 0 && !allow_zero)) return Error{ErrorCode::InvalidArgument, "port must be a number in 1..65535"};
  return static_cast<std::uint16_t>(v);
}

Expected<NodeConfig> parse_node_config(std::string_view text) {
  g_why = nullptr;
  toml::parse_result parsed = toml::parse(text);
  if (!parsed) return bad("config: TOML syntax error");
  const toml::table& root = parsed.table();
  static constexpr const char* kRoot[] = {"node", "store", "lease", "ticket", "limits", "lab", "executor", "telemetry", "admin", "nic", "control", "audit", "retention", "evict", "quota", "scrub"};
  if (!keys_ok(root, kRoot)) return bad("config: unknown section");

  NodeConfig c;
  auto& s = c.server;
  s.store.backing = store::BackingKind::File;
  s.store.production = true;
  // Review r9 S04 + r9b T02/T03: the node ID file and its marker; [node] state_dir overrides. One memory node per
  // state_dir (locked for the process lifetime); it must be owned by this user and not group/world-writable.
  s.store.state_dir = "/var/lib/miracache";
  s.store.segment_bytes = std::size_t{4} << 30;
  s.store.run_bytes = std::size_t{256} << 20;
  s.store.min_block_bytes = std::size_t{64} << 10;
  s.store.n_segments = 1;
  // store.max_bytes absent = 0 = "computed": Server::create / dyn_from_server_config resolve it to this node's
  // n_segments x segment_bytes (one rule, one place; K02). An explicit value wins.
  s.store.principal_default.max_bytes = 0;
  bool ok = true;

  if (const auto* t = section(root, "node", ok)) {
    static constexpr const char* k[] = {"device", "protocol", "listen", "drain_ms", "state_dir", "rails"};
    // Plan 2C + review r9 S04: the ID is drawn at random once and kept in <state_dir>/node-id (mode 0600). There is no
    // way to set it by hand: state_dir is a path.
    if (t->contains("id")) return bad("config: node id was removed; node IDs are assigned automatically");
    if (!keys_ok(*t, k)) return bad("config: unknown key in [node]");
    ok = ok && GET_U32(*t, "drain_ms", c.drain_ms) && c.drain_ms <= 600000;
    s.goaway_drain_ms = c.drain_ms;
    ok = ok && get(*t, "device", c.device);
    ok = ok && get(*t, "state_dir", s.store.state_dir) && !s.store.state_dir.empty();
    std::string proto = "auto";
    ok = ok && get(*t, "protocol", proto);
    if (proto == "auto") c.protocol = fabric::protocol::Setting::Auto;
    else if (proto == "roce") c.protocol = fabric::protocol::Setting::RoCE;
    else if (proto == "iwarp") c.protocol = fabric::protocol::Setting::IWarp;
    else return bad("config: node.protocol must be auto, roce or iwarp");
    s.wire_protocol = proto == "iwarp" ? 2 : 1;
    if (const auto* l = t->get("listen")) {
      const auto* arr = l->as_array();
      if (!arr) return bad("config: node.listen must be an array");
      for (const auto& e : *arr) {
        auto str = e.value<std::string>();
        auto colon = str ? str->rfind(':') : std::string::npos;
        if (colon == std::string::npos) return bad("config: node.listen entries are host:port");
        auto port = parse_port(str->substr(colon + 1));
        if (!port) return bad("config: node.listen port must be a number in 1..65535");
        s.rails.push_back(fabric::RailAddr{str->substr(0, colon), *port});
      }
    }
    // RL1 (multi-rail plan decisions 1 and 2): [[node.rails]] device, listen, subnet, 1..4 entries, STATIC (changing
    // them needs a rolling restart). The legacy form (node.device + node.listen) means every rail on that one device.
    if (const auto* rn = t->get("rails")) {
      if (t->contains("listen") || t->contains("device"))
        return bad("config: node.rails replaces node.device and node.listen; use one form");
      const auto* arr = rn->as_array();
      if (!arr || arr->empty() || !arr->is_homogeneous(toml::node_type::table))
        return bad("config: node.rails must be an array of tables ([[node.rails]])");
      if (arr->size() > 4) return bad("config: at most 4 node.rails (the wire carries 4)");
      for (const auto& e : *arr) {
        const auto& rt = *e.as_table();
        static constexpr const char* rk[] = {"device", "listen", "subnet"};
        if (!keys_ok(rt, rk)) return bad("config: unknown key in [[node.rails]]");
        std::string dev, listen, subnet;
        if (!get(rt, "device", dev) || dev.empty()) return bad("config: node.rails device is required");
        if (!get(rt, "listen", listen) || listen.empty()) return bad("config: node.rails listen (host:port) is required");
        if (!get(rt, "subnet", subnet)) return bad("config: node.rails subnet must be a string");
        const auto colon = listen.rfind(':');
        if (colon == std::string::npos) return bad("config: node.rails listen is host:port");
        auto port = parse_port(listen.substr(colon + 1));
        if (!port) return bad("config: node.rails listen port must be a number in 1..65535");
        for (const auto& prev : s.rails)
          if (prev.host == listen.substr(0, colon) && prev.port == *port) return bad("config: duplicate node.rails listen address");
        auto di = std::find(c.devices.begin(), c.devices.end(), dev);
        if (di == c.devices.end()) {
          c.devices.push_back(dev);
          di = c.devices.end() - 1;
        }
        s.rails.push_back(fabric::RailAddr{listen.substr(0, colon), *port});
        s.rail_device.push_back(static_cast<std::uint32_t>(di - c.devices.begin()));
        c.rail_subnets.push_back(subnet);
      }
      c.device = c.devices.front();
      s.device_names = c.devices;
    }
  }
  if (const auto* t = section(root, "store", ok)) {
    static constexpr const char* k[] = {"backing", "dir", "segment_bytes", "run_bytes", "min_block_bytes",
                                        "n_segments", "require_1g", "invalidate_per_s", "max_scopes",
                                        "max_bytes", "max_exact_classes_per_owner",
                                        "max_puts_per_endpoint", "max_leases_per_session", "scope_records"};
    // HR1: the QT1/QT2 knobs moved out of [store] (they were never released): a stale name is an error that says where
    // the key lives now.
    static constexpr std::pair<const char*, const char*> kStale[] = {
        {"scope_idle_ttl_s", "retention.idle_ttl_s"},         {"max_ttl_s", "retention.max_ttl_s"},
        {"sweep_bytes_per_s", "evict.sweep_bytes_per_s"},     {"sweep_blocks_per_turn", "evict.sweep_blocks_per_turn"},
        {"high_pct", "evict.high_pct"},                       {"low_pct", "evict.low_pct"},
        {"put_ops_per_s", "quota.put_ops_per_s"},             {"put_bytes_per_s", "quota.put_bytes_per_s"}};
    for (const auto& [old_key, new_key] : kStale)
      if (t->contains(old_key)) return bad_named(std::string("config: stale key store.") + old_key + ": renamed " + new_key);
    if (!keys_ok(*t, k)) return bad("config: unknown key in [store]");
    for (const char* dk : {"invalidate_per_s", "max_scopes", "max_bytes", "max_exact_classes_per_owner"})
      if (t->contains(dk)) c.dyn_keys_present.push_back(std::string("store.") + dk);
    std::string backing = "file";
    ok = ok && get(*t, "backing", backing);
    if (backing == "file") s.store.backing = store::BackingKind::File;
    else if (backing == "hugetlbfs") s.store.backing = store::BackingKind::Hugetlbfs;
    else if (backing == "anon") s.store.backing = store::BackingKind::Anon, s.store.production = false;
    else return bad("config: store.backing must be file, hugetlbfs or anon");
    ok = ok && get(*t, "dir", s.store.dir);
    std::uint64_t v = s.store.segment_bytes;
    ok = ok && get_u64(*t, "segment_bytes", v);
    s.store.segment_bytes = v;
    v = s.store.run_bytes;
    ok = ok && get_u64(*t, "run_bytes", v);
    s.store.run_bytes = v;
    v = s.store.min_block_bytes;
    ok = ok && get_u64(*t, "min_block_bytes", v);
    s.store.min_block_bytes = v;
    ok = ok && GET_U32(*t, "n_segments", s.store.n_segments);
    ok = ok && get(*t, "require_1g", s.store.require_1g);
    ok = ok && GET_U32(*t, "invalidate_per_s", s.store.invalidate_per_s);
    ok = ok && GET_U32(*t, "max_scopes", s.store.principal_default.max_scopes);
    ok = ok && get_u64(*t, "max_bytes", s.store.principal_default.max_bytes);
    ok = ok && GET_U32(*t, "max_exact_classes_per_owner", s.store.max_exact_classes_per_owner);
    ok = ok && GET_U32(*t, "max_puts_per_endpoint", s.store.max_puts_per_endpoint);
    ok = ok && GET_U32(*t, "max_leases_per_session", s.store.max_leases_per_session);
    ok = ok && GET_U32(*t, "scope_records", s.store.scope_records);  // STATIC; 0 = auto (G06)
  }
  // HR1: [retention] (QT1 decision 1), [evict] (QT1 decision 3), [quota] (QT2 decision 4): class A.
  if (const auto* t = section(root, "retention", ok)) {
    static constexpr const char* k[] = {"idle_ttl_s", "max_ttl_s"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [retention]");
    for (const auto& [kk, vv] : *t) { (void)vv; c.dyn_keys_present.push_back("retention." + std::string(kk.str())); }
    ok = ok && get_secs(*t, "idle_ttl_s", s.store.principal_default.idle_ttl);
    std::int64_t mt = std::chrono::duration_cast<std::chrono::seconds>(s.store.max_ttl).count();
    ok = ok && get(*t, "max_ttl_s", mt) && mt >= 0;  // 0 = off (get_secs wants > 0)
    s.store.max_ttl = std::chrono::seconds(mt);
  }
  if (const auto* t = section(root, "evict", ok)) {
    static constexpr const char* k[] = {"sweep_bytes_per_s", "sweep_blocks_per_turn", "high_pct", "low_pct"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [evict]");
    for (const auto& [kk, vv] : *t) { (void)vv; c.dyn_keys_present.push_back("evict." + std::string(kk.str())); }
    ok = ok && get_u64(*t, "sweep_bytes_per_s", s.store.sweep_bytes_per_s);
    ok = ok && GET_U32(*t, "sweep_blocks_per_turn", s.store.sweep_blocks_per_turn);
    ok = ok && GET_U32(*t, "high_pct", s.store.high_pct);
    ok = ok && GET_U32(*t, "low_pct", s.store.low_pct);
  }
  if (const auto* t = section(root, "scrub", ok)) {
    static constexpr const char* k[] = {"enabled", "bytes_per_s"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [scrub]");
    for (const auto& [kk, vv] : *t) { (void)vv; c.dyn_keys_present.push_back("scrub." + std::string(kk.str())); }
    ok = ok && get(*t, "enabled", s.store.scrub_enabled);
    ok = ok && get_u64(*t, "bytes_per_s", s.store.scrub_bytes_per_s);
  }
  if (const auto* t = section(root, "quota", ok)) {
    static constexpr const char* k[] = {"put_ops_per_s", "put_bytes_per_s"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [quota]");
    for (const auto& [kk, vv] : *t) { (void)vv; c.dyn_keys_present.push_back("quota." + std::string(kk.str())); }
    ok = ok && get_u64(*t, "put_ops_per_s", s.store.principal_default.put_ops_per_s);
    ok = ok && get_u64(*t, "put_bytes_per_s", s.store.principal_default.put_bytes_per_s);
  }
  if (const auto* t = section(root, "lease", ok)) {
    static constexpr const char* k[] = {"ttl_s", "max_s", "put_timeout_s"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [lease]");
    for (const auto& [kk, vv] : *t) { (void)vv; c.dyn_keys_present.push_back("lease." + std::string(kk.str())); }
    ok = ok && get_secs(*t, "ttl_s", s.store.lease_ttl) && get_secs(*t, "max_s", s.store.lease_max) &&
         get_secs(*t, "put_timeout_s", s.store.put_timeout);
  }
  if (const auto* t = section(root, "ticket", ok)) {
    static constexpr const char* k[] = {"ttl_s"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [ticket]");
    for (const auto& [kk, vv] : *t) { (void)vv; c.dyn_keys_present.push_back("ticket." + std::string(kk.str())); }
    ok = ok && get_secs(*t, "ttl_s", s.ticket_ttl);
  }
  if (const auto* t = section(root, "limits", ok)) {
    static constexpr const char* k[] = {"ticket_max_per_identity", "admit_timeout_s", "hello_deadline_s",
                                        "idle_timeout_s", "max_conns_per_principal", "max_leases_per_principal"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [limits]");
    for (const auto& [kk, vv] : *t) { (void)vv; c.dyn_keys_present.push_back("limits." + std::string(kk.str())); }
    ok = ok && GET_U32(*t, "ticket_max_per_identity", s.ticket_max_per_identity) &&
         (!t->contains("ticket_max_per_identity") || s.ticket_max_per_identity >= 1);  // unset = 0 = computed (H07)
    ok = ok && get_secs(*t, "admit_timeout_s", s.admit_timeout) && get_secs(*t, "hello_deadline_s", s.hello_deadline) &&
         get_secs(*t, "idle_timeout_s", s.idle_timeout);
    ok = ok && GET_U32(*t, "max_conns_per_principal", s.max_conns_per_principal) &&
         (!t->contains("max_conns_per_principal") || s.max_conns_per_principal >= 1);  // unset = 0 = computed
    ok = ok && GET_U32(*t, "max_leases_per_principal", s.max_leases_per_principal) && s.max_leases_per_principal >= 1;
  }
  if (const auto* t = section(root, "lab", ok)) {
    static constexpr const char* k[] = {"principal", "ticket_file", "tickets", "identities"};
    if (t->get("principal_id")) return bad("config: stale key [lab] principal_id: principal IDs are computed from the name");
    if (!keys_ok(*t, k)) return bad("config: unknown key in [lab]");
    ok = ok && get(*t, "principal", s.lab_identity) &&
         get(*t, "ticket_file", c.lab_ticket_file);
    ok = ok && GET_U32(*t, "tickets", c.lab_tickets);
    if (const auto* l = t->get("identities")) {
      const auto* arr = l->as_array();
      if (!arr) return bad("config: lab.identities must be an array of strings");
      for (const auto& e : *arr) {
        auto str = e.value<std::string>();
        if (!str || str->empty() || str->size() > 256) return bad("config: lab.identities entries are non-empty strings");
        s.lab_identities.push_back(*str);
      }
      if (!s.lab_identities.empty() && s.lab_identity.empty()) return bad("config: lab.identities needs lab.principal");
    }
  }
  if (const auto* t = section(root, "admin", ok)) {
    static constexpr const char* k[] = {"listen", "cert", "key", "ca", "max_conns", "rbac"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [admin]");
    // RB2: [[admin.rbac]] identity = "spiffe://...", roles = ["operator", ...] (lab mode; bundle mode reads the bundle's).
    if (const auto* rn = t->get("rbac")) {
      const auto* arr = rn->as_array();
      if (!arr || !arr->is_homogeneous(toml::node_type::table)) return bad("config: admin.rbac must be an array of tables");
      for (const auto& e : *arr) {
        const auto& rt = *e.as_table();
        static constexpr const char* rk[] = {"identity", "roles"};
        if (!keys_ok(rt, rk)) return bad("config: unknown key in [[admin.rbac]]");
        std::string identity;
        if (!get(rt, "identity", identity) || identity.rfind("spiffe://", 0) != 0 || identity.size() > 256)
          return bad("config: admin.rbac identity must be a spiffe:// string");
        const auto* roles = rt.get("roles");
        const auto* ra = roles ? roles->as_array() : nullptr;
        if (!ra || ra->empty()) return bad("config: admin.rbac roles must be a non-empty array of strings");
        std::vector<std::string> rl;
        for (const auto& r : *ra) {
          auto sv = r.value<std::string>();
          if (!sv || (*sv != "viewer" && *sv != "operator" && *sv != "security-admin" && *sv != "scope-provider"))
            return bad("config: admin.rbac roles are viewer, operator, security-admin or scope-provider");
          rl.push_back(*sv);
        }
        for (const auto& b : c.admin_rbac)
          if (b.first == identity) return bad("config: duplicate admin.rbac identity");
        c.admin_rbac.emplace_back(std::move(identity), std::move(rl));
      }
    }
    ok = ok && get(*t, "listen", c.admin_listen) && get(*t, "cert", c.admin_cert) && get(*t, "key", c.admin_key) &&
         get(*t, "ca", c.admin_ca);
    ok = ok && GET_U32(*t, "max_conns", c.admin_max_conns) && c.admin_max_conns >= 1 && c.admin_max_conns <= 1024;
    if (ok && !c.admin_listen.empty()) {
      const auto colon = c.admin_listen.rfind(':');
      if (colon == std::string::npos) return bad("config: admin.listen is host:port or empty");
      if (!parse_port(c.admin_listen.substr(colon + 1), /*allow_zero=*/true))
        return bad("config: admin.listen port must be a number in 0..65535");
      if (c.admin_cert.empty() || c.admin_key.empty() || c.admin_ca.empty())
        return bad("config: admin.listen needs admin.cert, admin.key and admin.ca");
    }
  }
  // [nic] (A3.3): the NIC profile registry and explicit operating-point keys. Precedence: config > profile > default.
  if (const auto* t = section(root, "nic", ok)) {
    static constexpr const char* k[] = {"profiles_file", "mtu", "inline_bytes", "ack_timeout_exp", "retry_count", "rnr_retry_count"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [nic]");
    ok = ok && get(*t, "profiles_file", c.profiles_file);
    auto opt = [&](const char* key, std::int64_t lo, std::int64_t hi, auto& out) {
      const auto* n = t->get(key);
      if (!n) return true;
      auto v = n->value<std::int64_t>();
      if (!n->is_integer() || !v || *v < lo || *v > hi) return false;
      out = static_cast<typename std::decay_t<decltype(out)>::value_type>(*v);
      return true;
    };
    if (!opt("mtu", 256, 4096, c.nic.mtu) ||
        (c.nic.mtu && *c.nic.mtu != 256 && *c.nic.mtu != 512 && *c.nic.mtu != 1024 && *c.nic.mtu != 2048 && *c.nic.mtu != 4096))
      return bad("config: nic.mtu must be 256, 512, 1024, 2048 or 4096");
    if (!opt("inline_bytes", 0, 256, c.nic.inline_bytes)) return bad("config: nic.inline_bytes must be 0..256");
    if (!opt("ack_timeout_exp", 1, 19, c.nic.ack_timeout_exp)) return bad("config: nic.ack_timeout_exp must be 1..19");
    if (!opt("retry_count", 0, 7, c.nic.retry_count)) return bad("config: nic.retry_count must be 0..7");
    if (!opt("rnr_retry_count", 0, 6, c.nic.rnr_retry_count)) return bad("config: nic.rnr_retry_count must be 0..6");
    if (ok && t->contains("profiles_file") && c.profiles_file.empty()) return bad("config: nic.profiles_file must not be empty");
  }
  if (const auto* t = section(root, "telemetry", ok)) {
    static constexpr const char* k[] = {"listen"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [telemetry]");
    ok = ok && get(*t, "listen", c.telemetry_listen);
    if (ok && !c.telemetry_listen.empty()) {
      const auto colon = c.telemetry_listen.rfind(':');
      if (colon == std::string::npos) return bad("config: telemetry.listen is host:port or empty");
      if (!parse_port(c.telemetry_listen.substr(colon + 1), /*allow_zero=*/true))  // 0 = pick a free port
        return bad("config: telemetry.listen port must be a number in 0..65535");
    }
  }
  // [control] (membership plan decision 4): trust_keys switches bundle mode on. STATIC: read at start-up; the file's
  // contents reload on SIGHUP and on a 10 s stat check.
  if (const auto* t = section(root, "control", ok)) {
    static constexpr const char* k[] = {"trust_keys"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [control]");
    ok = ok && get(*t, "trust_keys", c.trust_keys);
    if (ok && t->contains("trust_keys") && c.trust_keys.empty()) return bad("config: control.trust_keys must not be empty");
  }
  // [audit] (RB2, node-local): dir (default <state_dir>/audit in bundle mode; empty and no bundle mode = no audit log),
  // max_bytes (rotation, default 64 MiB), max_total_bytes (default 1 GiB; never more than 10 % of the free space).
  if (const auto* t = section(root, "audit", ok)) {
    static constexpr const char* k[] = {"dir", "max_bytes", "max_total_bytes"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [audit]");
    ok = ok && get(*t, "dir", c.audit_dir) && get_u64(*t, "max_bytes", c.audit_max_bytes) &&
         get_u64(*t, "max_total_bytes", c.audit_max_total_bytes);
    if (ok && (c.audit_max_bytes < 4096 || c.audit_max_total_bytes < c.audit_max_bytes))
      return bad("config: audit.max_bytes must be at least 4096 and audit.max_total_bytes at least audit.max_bytes");
  }
  if (const auto* t = section(root, "executor", ok)) {
    static constexpr const char* k[] = {"workers"};
    if (!keys_ok(*t, k)) return bad("config: unknown key in [executor]");
    std::uint64_t w = c.workers;
    ok = ok && get_u64(*t, "workers", w) && w >= 1 && w <= 64;
    c.workers = w;
  }
  if (!ok) return bad(g_why ? g_why : "config: wrong type or value");
  {  // max_bytes unset (0) is resolved at Server::create (K02): validate the resolved store
    store::StoreConfig resolved_store = s.store;
    if (resolved_store.principal_default.max_bytes == 0) resolved_store.principal_default.max_bytes = backing_bytes(resolved_store);
    if (auto st = resolved_store.validate(); !st) return st.error();
  }
  // The lab refresh runs at ttl/2, so up to two rounds of 3 classes are live at once.
  // H07: unset (0) is computed at Server::create, never below kTicketMaxFloor: check against the floor.
  if (!c.lab_ticket_file.empty() &&
      std::uint64_t{c.lab_tickets} * 6 > (s.ticket_max_per_identity != 0 ? s.ticket_max_per_identity : kTicketMaxFloor))
    return bad("config: lab.tickets x 6 (3 classes, 2 live rounds) exceeds limits.ticket_max_per_identity");
  if (!c.lab_ticket_file.empty() && s.lab_identity.empty()) return bad("config: lab.ticket_file needs lab.principal");
  if (!c.trust_keys.empty() && c.admin_listen.empty()) return bad("config: control.trust_keys needs admin.listen (bundles arrive over the admin API)");
  // HR1 decision 1: one source per mode. In bundle mode every class A key comes from the bundle's config.cluster.memnode.
  if (!c.trust_keys.empty() && !c.dyn_keys_present.empty())
    return bad_named("config: " + c.dyn_keys_present.front() + " is cluster config in bundle mode (set it in the bundle's config.cluster.memnode)");
  if (auto st = validate_dyn(dyn_from_server_config(s)); !st) return st.error();
  return c;
}

Expected<NodeConfig> load_node_config(const std::string& path) {
  std::ifstream in(path);
  if (!in) return Error{ErrorCode::NotFound, "config: cannot open file"};
  std::stringstream ss;
  ss << in.rdbuf();
  return parse_node_config(ss.str());
}

}  // namespace miracache::server
