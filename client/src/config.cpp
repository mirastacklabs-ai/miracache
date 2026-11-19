// SPDX-License-Identifier: Apache-2.0
#include "miracache/config.h"

#include <sys/stat.h>

#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>

#include <toml++/toml.hpp>

namespace miracache {

const char* to_string(FabricProtocol p) noexcept {
  switch (p) {
    case FabricProtocol::Auto: return "auto";
    case FabricProtocol::Roce: return "roce";
    case FabricProtocol::Iwarp: return "iwarp";
  }
  return "?";
}

const char* to_string(ScopeProviderKind k) noexcept {
  switch (k) {
    case ScopeProviderKind::Static: return "static";
  }
  return "?";
}

namespace {

constexpr std::uint64_t kMinSubpool = 1ull << 20;
constexpr std::uint64_t kMaxSubpool = 64ull << 30;
constexpr std::uint64_t kSubpoolAlign = 4096;
constexpr std::int64_t kMinWorkers = 1, kMaxWorkers = 64;
constexpr std::size_t kMaxRails = 4;  // RL2 decision 1: a rail = (device, port, IP), at most 4 per node (the wire carries 4)

Error bad(const char* ctx) { return Error{ErrorCode::InvalidArgument, ctx}; }

// Returns an error context if `tbl` has a key outside `allowed`.
template <std::size_t N>
const char* unknown_key(const toml::table& tbl, const char* const (&allowed)[N]) {
  for (auto&& [k, v] : tbl) {
    bool ok = false;
    for (const char* a : allowed) ok = ok || k.str() == a;
    if (!ok) return "config: unknown key";
  }
  return nullptr;
}

bool looks_like_text(std::string_view s) {
  if (s.find('\n') != std::string_view::npos) return true;
  auto p = s.find_first_not_of(" \t\r");
  return p != std::string_view::npos && s[p] == '[';
}

}  // namespace

Status check_secret_file(const std::string& path) {
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0)
    return Error{ErrorCode::NotFound, "config: scope.secret_file does not exist"};
  if (!S_ISREG(st.st_mode))
    return bad("config: scope.secret_file is not a regular file");
  if ((st.st_mode & 07777) != 0600)
    return Error{ErrorCode::AccessDenied, "config: scope.secret_file must have mode 0600"};
  return {};
}

namespace {

Expected<ClientConfig> parse_validate(std::string_view text, bool check_fs) {
  toml::parse_result parsed = toml::parse(text);
  if (!parsed) return bad("config: TOML syntax error");
  const toml::table& root = parsed.table();

  static constexpr const char* kRoot[] = {"scope", "nodes", "fabric", "landing", "crypto", "lab", "tls", "placement", "control"};
  if (auto* e = unknown_key(root, kRoot)) return bad(e);

  ClientConfig cfg;
  bool replicas_set = false;  // [placement] replicas present (a config error in bundle mode)

  // [scope]
  const toml::table* scope = root["scope"].as_table();
  if (root.contains("scope") && !scope) return bad("config: [scope] must be a table");
  if (!scope) return bad("config: [scope] is required");
  static constexpr const char* kScope[] = {"provider", "secret_file"};
  if (auto* e = unknown_key(*scope, kScope)) return bad(e);
  if (auto* n = scope->get("provider")) {
    auto s = n->value<std::string_view>();
    if (!s) return bad("config: scope.provider must be a string");
    if (*s != "static") return bad("config: scope.provider must be \"static\"");
  }
  cfg.provider = ScopeProviderKind::Static;
  {
    auto* n = scope->get("secret_file");
    if (!n) return bad("config: scope.secret_file is required");
    auto s = n->value<std::string>();
    if (!s || s->empty()) return bad("config: scope.secret_file must be a non-empty string");
    cfg.secret_file = std::move(*s);
  }

  // [[nodes]]
  if (auto* n = root.get("nodes")) {
    const toml::array* arr = n->as_array();
    if (!arr || !arr->is_homogeneous(toml::node_type::table))
      return bad("config: nodes must be an array of tables ([[nodes]])");
    std::set<std::string> seen_rails;
    for (auto&& el : *arr) {
      const toml::table& t = *el.as_table();
      static constexpr const char* kNode[] = {"rails", "admin", "identity", "weight", "zone"};
      // Plan 2C: the ID is the memory node's own (random, in its superblock); the client learns it from HELLO_ACK.
      if (t.contains("id")) return bad("config: node id was removed; node IDs are assigned automatically");
      if (auto* e = unknown_key(t, kNode)) return bad(e);
      NodeConfig nc;
      if (auto* wn = t.get("weight")) {
        if (!wn->is_integer()) return bad("config: nodes.weight must be an integer");
        const std::int64_t w = wn->as_integer()->get();
        if (w < 1 || w > 1000000) return bad("config: nodes.weight must be 1..1000000");
        nc.weight = static_cast<std::uint32_t>(w);
      }
      if (auto* zn = t.get("zone")) {
        auto s = zn->value<std::string>();
        if (!s) return bad("config: nodes.zone must be a string");
        bool ok = !s->empty() && s->size() <= 64;
        for (char ch : *s)
          ok = ok && ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' ||
                      ch == '_' || ch == '-');
        if (!ok) return bad("config: nodes.zone must be 1..64 characters of [A-Za-z0-9._-]");
        nc.zone = std::move(*s);
      }
      auto* rn = t.get("rails");
      const toml::array* ra = rn ? rn->as_array() : nullptr;
      if (!ra) return bad("config: nodes.rails must be an array of strings");
      if (ra->empty() || ra->size() > kMaxRails) return bad("config: nodes.rails needs 1..4 entries");
      for (auto&& r : *ra) {
        auto s = r.value<std::string>();
        if (!s || s->empty()) return bad("config: nodes.rails entries must be non-empty strings");
        if (!seen_rails.insert(*s).second) return bad("config: duplicate nodes.rails address (two nodes, or one node twice, list the same host:port)");
        nc.rails.push_back(std::move(*s));
      }
      if (auto* an = t.get("admin")) {
        auto s = an->value<std::string>();
        if (!s || s->empty()) return bad("config: nodes.admin must be a non-empty string");
        const auto colon = s->rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= s->size())
          return bad("config: nodes.admin must be host:port");
        nc.admin = std::move(*s);
      }
      if (auto* in = t.get("identity")) {
        auto s = in->value<std::string>();
        if (!s || s->rfind("spiffe://", 0) != 0 || s->size() <= 9) return bad("config: nodes.identity must be a spiffe:// URI");
        if (nc.admin.empty()) return bad("config: nodes.identity needs nodes.admin");
        nc.identity = std::move(*s);
      }
      // A09: without a pinned identity any serverAuth cert under the lab CA would pass as the admin server.
      if (!nc.admin.empty() && nc.identity.empty()) return bad("config: nodes.identity is required when nodes.admin is set");
      cfg.nodes.push_back(std::move(nc));
    }
  }

  // [fabric]
  if (auto* n = root.get("fabric")) {
    const toml::table* t = n->as_table();
    if (!t) return bad("config: [fabric] must be a table");
    static constexpr const char* kFabric[] = {"protocol", "device", "keepalive_ms", "mtu", "reconnect_min_ms", "reconnect_max_ms", "reconnect_connect_ms", "ticket_batch", "watchdog_grace_ms",
                                              "profiles_file", "read_depth", "inline_bytes", "ack_timeout_exp", "retry_count", "rnr_retry_count", "devices"};
    if (auto* e = unknown_key(*t, kFabric)) return bad(e);
    if (auto* p = t->get("profiles_file")) {
      auto s = p->value<std::string>();
      if (!s || s->empty()) return bad("config: fabric.profiles_file must be a non-empty string");
      cfg.profiles_file = std::move(*s);
    }
    // A3.3 operating point keys: a set key beats the NIC profile.
    auto opt_int = [&](const char* key, std::int64_t lo, std::int64_t hi, auto& out, const char* ctx) -> const char* {
      if (auto* p = t->get(key)) {
        if (!p->is_integer()) return ctx;
        const std::int64_t v = p->as_integer()->get();
        if (v < lo || v > hi) return ctx;
        out = static_cast<typename std::decay_t<decltype(out)>::value_type>(v);
      }
      return nullptr;
    };
    if (auto* e = opt_int("read_depth", 1, 255, cfg.read_depth, "config: fabric.read_depth must be 1..255")) return bad(e);
    if (auto* e = opt_int("inline_bytes", 0, 256, cfg.inline_bytes, "config: fabric.inline_bytes must be 0..256")) return bad(e);
    if (auto* e = opt_int("ack_timeout_exp", 1, 19, cfg.ack_timeout_exp, "config: fabric.ack_timeout_exp must be 1..19")) return bad(e);
    if (auto* e = opt_int("retry_count", 0, 7, cfg.retry_count, "config: fabric.retry_count must be 0..7")) return bad(e);
    if (auto* e = opt_int("rnr_retry_count", 0, 6, cfg.rnr_retry_count, "config: fabric.rnr_retry_count must be 0..6")) return bad(e);
    if (auto* p = t->get("mtu")) {
      if (!p->is_integer()) return bad("config: fabric.mtu must be an integer");
      const std::int64_t v = p->as_integer()->get();
      if (v != 256 && v != 512 && v != 1024 && v != 2048 && v != 4096) return bad("config: fabric.mtu must be 256, 512, 1024, 2048 or 4096");
      cfg.mtu = static_cast<std::uint32_t>(v);
      cfg.mtu_explicit = true;
    }
    if (auto* p = t->get("reconnect_min_ms")) {
      if (!p->is_integer()) return bad("config: fabric.reconnect_min_ms must be an integer");
      const std::int64_t v = p->as_integer()->get();
      if (v < 1 || v > 60000) return bad("config: fabric.reconnect_min_ms must be 1..60000");
      cfg.reconnect_min_ms = static_cast<std::uint32_t>(v);
    }
    if (auto* p = t->get("reconnect_max_ms")) {
      if (!p->is_integer()) return bad("config: fabric.reconnect_max_ms must be an integer");
      const std::int64_t v = p->as_integer()->get();
      if (v < 1 || v > 600000) return bad("config: fabric.reconnect_max_ms must be 1..600000");
      cfg.reconnect_max_ms = static_cast<std::uint32_t>(v);
    }
    if (cfg.reconnect_max_ms < cfg.reconnect_min_ms) return bad("config: fabric.reconnect_max_ms must be >= reconnect_min_ms");
    if (auto* p = t->get("reconnect_connect_ms")) {
      if (!p->is_integer()) return bad("config: fabric.reconnect_connect_ms must be an integer");
      const std::int64_t v = p->as_integer()->get();
      if (v < 1 || v > 60000) return bad("config: fabric.reconnect_connect_ms must be 1..60000");
      cfg.reconnect_connect_ms = static_cast<std::uint32_t>(v);
    }
    if (auto* p = t->get("watchdog_grace_ms")) {
      if (!p->is_integer()) return bad("config: fabric.watchdog_grace_ms must be an integer");
      const std::int64_t v = p->as_integer()->get();
      if (v < 1 || v > 600000) return bad("config: fabric.watchdog_grace_ms must be 1..600000");
      cfg.watchdog_grace_ms = static_cast<std::uint32_t>(v);
    }
    if (auto* p = t->get("keepalive_ms")) {
      if (!p->is_integer()) return bad("config: fabric.keepalive_ms must be an integer");
      std::int64_t v = p->as_integer()->get();
      // R03: the keepalive thread also runs the reconnect; without it a dropped session never heals.
      if (v == 0) return bad("config: fabric.keepalive_ms = 0 is not allowed for a wire client (it drives PING and reconnect); use 10..600000");
      if (v < 10 || v > 600000) return bad("config: fabric.keepalive_ms must be 10..600000");
      cfg.keepalive_ms = static_cast<std::uint32_t>(v);
    }
    if (auto* p = t->get("ticket_batch")) {
      if (!p->is_integer()) return bad("config: fabric.ticket_batch must be an integer");
      const std::int64_t v = p->as_integer()->get();
      if (v < 1 || v > 64) return bad("config: fabric.ticket_batch must be 1..64");
      cfg.ticket_batch = static_cast<std::uint32_t>(v);
    }
    if (auto* p = t->get("device")) {
      auto s = p->value<std::string>();
      if (!s) return bad("config: fabric.device must be a string");
      cfg.device = std::move(*s);
    }
    // RL2 decision 5: fabric.devices = [{device, subnet}, ...] (1..4, STATIC). The legacy fabric.device is one device
    // with subnet "" (both together are a config error: one home per value).
    if (auto* p = t->get("devices")) {
      const toml::array* a = p->as_array();
      if (!a || a->empty() || a->size() > kMaxRails || !a->is_homogeneous(toml::node_type::table))
        return bad("config: fabric.devices must be an array of 1..4 tables {device, subnet}");
      if (t->get("device")) return bad("config: fabric.device and fabric.devices are exclusive");
      std::set<std::string> seen;
      for (auto& el : *a) {
        const toml::table& d = *el.as_table();
        static constexpr const char* kDev[] = {"device", "subnet"};
        if (auto* e = unknown_key(d, kDev)) return bad(e);
        LocalDevice ld;
        auto dv = d["device"].value<std::string>();
        if (!dv || dv->empty()) return bad("config: fabric.devices[].device must be a non-empty string");
        ld.device = std::move(*dv);
        if (auto* sn = d.get("subnet")) {
          auto s = sn->value<std::string>();
          if (!s) return bad("config: fabric.devices[].subnet must be a string");
          ld.subnet = std::move(*s);
        }
        if (!seen.insert(ld.device).second) return bad("config: duplicate fabric.devices[].device");
        cfg.devices.push_back(std::move(ld));
      }
      // H01: only the first device without a subnet (the wildcard) is ever paired; a second one would sit unused.
      std::size_t wildcards = 0;
      for (const auto& ld : cfg.devices) wildcards += ld.subnet.empty() ? 1 : 0;
      if (wildcards > 1)
        return bad("config: fabric.devices has more than one entry without `subnet`; only one wildcard device is allowed "
                   "(give each other device the subnet its rails serve)");
      cfg.device = cfg.devices[0].device;  // device 0: the NIC profile and the legacy single-device paths use it
    }
    if (auto* p = t->get("protocol")) {
      auto s = p->value<std::string_view>();
      if (!s) return bad("config: fabric.protocol must be a string");
      if (*s == "auto") cfg.protocol = FabricProtocol::Auto;
      else if (*s == "roce") cfg.protocol = FabricProtocol::Roce;
      else if (*s == "iwarp") cfg.protocol = FabricProtocol::Iwarp;
      else return bad("config: fabric.protocol must be auto, roce or iwarp");
    }
  }

  // [placement]
  if (auto* n = root.get("placement")) {
    const toml::table* t = n->as_table();
    if (!t) return bad("config: [placement] must be a table");
    static constexpr const char* kPlacement[] = {"replicas", "replica_mode", "replica_buffer_bytes"};
    if (auto* e = unknown_key(*t, kPlacement)) return bad(e);
    if (auto* p = t->get("replicas")) {
      if (!p->is_integer()) return bad("config: placement.replicas must be an integer");
      const std::int64_t v = p->as_integer()->get();
      if (v < 1 || v > 3) return bad("config: placement.replicas must be 1..3");
      cfg.replicas = static_cast<std::uint32_t>(v);
      replicas_set = true;
    }
    if (auto* p = t->get("replica_mode")) {
      auto s = p->value<std::string_view>();
      if (!s) return bad("config: placement.replica_mode must be a string");
      if (*s == "async") cfg.replica_mode = ReplicaMode::Async;
      else if (*s == "sync") cfg.replica_mode = ReplicaMode::Sync;
      else return bad("config: placement.replica_mode must be \"async\" or \"sync\"");
    }
    if (auto* p = t->get("replica_buffer_bytes")) {
      if (!p->is_integer()) return bad("config: placement.replica_buffer_bytes must be an integer");
      const std::int64_t v = p->as_integer()->get();
      if (v < 0 || v > (std::int64_t{1} << 40)) return bad("config: placement.replica_buffer_bytes must be 0..2^40");
      cfg.replica_buffer_bytes = static_cast<std::uint64_t>(v);
    }
  }

  // [landing]
  if (auto* n = root.get("landing")) {
    const toml::table* t = n->as_table();
    if (!t) return bad("config: [landing] must be a table");
    static constexpr const char* kLanding[] = {"subpool_bytes"};
    if (auto* e = unknown_key(*t, kLanding)) return bad(e);
    if (auto* p = t->get("subpool_bytes")) {
      if (!p->is_integer()) return bad("config: landing.subpool_bytes must be an integer");
      std::int64_t v = p->as_integer()->get();
      if (v < 0 || static_cast<std::uint64_t>(v) < kMinSubpool ||
          static_cast<std::uint64_t>(v) > kMaxSubpool)
        return bad("config: landing.subpool_bytes out of range 1 MiB..64 GiB");
      if (static_cast<std::uint64_t>(v) % kSubpoolAlign != 0)
        return bad("config: landing.subpool_bytes must be a multiple of 4096");
      cfg.subpool_bytes = static_cast<std::uint64_t>(v);
    }
  }

  // [crypto]
  if (auto* n = root.get("crypto")) {
    const toml::table* t = n->as_table();
    if (!t) return bad("config: [crypto] must be a table");
    static constexpr const char* kCrypto[] = {"workers"};
    if (auto* e = unknown_key(*t, kCrypto)) return bad(e);
    if (auto* p = t->get("workers")) {
      if (!p->is_integer()) return bad("config: crypto.workers must be an integer");
      std::int64_t v = p->as_integer()->get();
      if (v < kMinWorkers || v > kMaxWorkers) return bad("config: crypto.workers out of range 1..64");
      cfg.crypto_workers = static_cast<std::uint32_t>(v);
    }
  }

  // [lab]
  if (auto* n = root.get("lab")) {
    const toml::table* t = n->as_table();
    if (!t) return bad("config: [lab] must be a table");
    static constexpr const char* kLab[] = {"static_membership", "ticket_file"};
    if (auto* e = unknown_key(*t, kLab)) return bad(e);
    if (auto* p = t->get("ticket_file")) {
      auto s = p->value<std::string>();
      if (!s || s->empty()) return bad("config: lab.ticket_file must be a non-empty string");
      cfg.ticket_file = std::move(*s);
    }
    if (auto* p = t->get("static_membership")) {
      if (!p->is_boolean()) return bad("config: lab.static_membership must be a boolean");
      cfg.static_membership = p->as_boolean()->get();
    }
  }

  // [tls]
  if (auto* n = root.get("tls")) {
    const toml::table* t = n->as_table();
    if (!t) return bad("config: [tls] must be a table");
    static constexpr const char* kTls[] = {"cert", "key", "ca"};
    if (auto* e = unknown_key(*t, kTls)) return bad(e);
    auto path = [&](const char* k, std::string& dst) -> const char* {
      auto* p = t->get(k);
      if (!p) return nullptr;
      auto s = p->value<std::string>();
      if (!s || s->empty()) return "config: tls.cert, tls.key and tls.ca must be non-empty strings";
      dst = std::move(*s);
      return nullptr;
    };
    for (const char* e : {path("cert", cfg.tls_cert), path("key", cfg.tls_key), path("ca", cfg.tls_ca)})
      if (e) return bad(e);
  }
  // [control] (MB5, bundle mode)
  if (auto* n = root.get("control")) {
    const toml::table* t = n->as_table();
    if (!t) return bad("config: [control] must be a table");
    static constexpr const char* kControl[] = {"endpoints", "controller", "trust_keys", "state_dir"};
    if (auto* e = unknown_key(*t, kControl)) return bad(e);
    ControlConfig cc;
    auto hostport = [](const std::string& s) {
      const auto colon = s.rfind(':');
      return !s.empty() && colon != std::string::npos && colon != 0 && colon + 1 < s.size();
    };
    auto* en = t->get("endpoints");
    const toml::array* ea = en ? en->as_array() : nullptr;
    if (!ea) return bad("config: control.endpoints must be an array of host:port strings");
    if (ea->empty() || ea->size() > 16) return bad("config: control.endpoints needs 1..16 entries");
    std::set<std::string> seen;
    for (auto&& el : *ea) {
      auto s = el.value<std::string>();
      if (!s || !hostport(*s)) return bad("config: control.endpoints entries must be host:port");
      if (!seen.insert(*s).second) return bad("config: duplicate control.endpoints entry");
      cc.endpoints.push_back(std::move(*s));
    }
    if (auto* p = t->get("controller")) {
      auto s = p->value<std::string>();
      if (!s || !hostport(*s)) return bad("config: control.controller must be host:port");
      cc.controller = std::move(*s);
    }
    for (auto [key, dst] : {std::pair<const char*, std::string*>{"trust_keys", &cc.trust_keys}, {"state_dir", &cc.state_dir}}) {
      auto* p = t->get(key);
      if (!p) return bad("config: control.trust_keys and control.state_dir are required");
      auto s = p->value<std::string>();
      if (!s || s->empty()) return bad("config: control.trust_keys and control.state_dir must be non-empty strings");
      *dst = std::move(*s);
    }
    cfg.control = std::move(cc);
  }

  bool any_admin = false;
  for (const auto& nc : cfg.nodes) any_admin = any_admin || !nc.admin.empty();
  if (any_admin && (cfg.tls_cert.empty() || cfg.tls_key.empty() || cfg.tls_ca.empty()))
    return bad("config: nodes.admin needs tls.cert, tls.key and tls.ca");

  // Bundle mode (MB5): membership comes from the signed bundle, so the static lab inputs are errors.
  if (cfg.control) {
    if (!cfg.nodes.empty()) return bad("config: [control] and [[nodes]] are mutually exclusive");
    if (cfg.static_membership) return bad("config: [control] and lab.static_membership = true are mutually exclusive");
    if (cfg.tls_cert.empty() || cfg.tls_key.empty() || cfg.tls_ca.empty())
      return bad("config: [control] needs tls.cert, tls.key and tls.ca");
    if (replicas_set) return bad("config: placement.replicas is not allowed with [control]; R comes from the bundle");
  } else {
  // Cross-field rules. No controller exists yet, so membership must be the static list.
  if (!cfg.static_membership)
    return Error{ErrorCode::Unsupported, "config: controller membership not implemented; set lab.static_membership = true"};
  if (cfg.nodes.empty()) return bad("config: at least one [[nodes]] entry is required");
  // replicas > 1 needs at least replicas + 1 nodes (and so at least 3): with fewer, one failure leaves no spare.
  if (cfg.replicas > 1 && cfg.nodes.size() < static_cast<std::size_t>(cfg.replicas) + 1)
    return bad(cfg.replicas == 2 ? "config: placement.replicas = 2 needs at least 3 [[nodes]]"
                                 : "config: placement.replicas = 3 needs at least 4 [[nodes]]");
  // Zones: all nodes or none. With zones, every replica must land in a different zone.
  {
    std::size_t zoned = 0;
    std::set<std::string> zones;
    for (const auto& nc : cfg.nodes) {
      zoned += !nc.zone.empty();
      zones.insert(nc.zone);
    }
    if (zoned != 0 && zoned != cfg.nodes.size()) return bad("config: nodes.zone must be set on every node or on none");
    if (zoned != 0 && cfg.replicas > zones.size())
      return bad(cfg.replicas == 2 ? "config: replicas=2 needs nodes in at least 2 zones"
                                   : "config: replicas=3 needs nodes in at least 3 zones");
  }
  }


  if (check_fs) {
    Status s = check_secret_file(cfg.secret_file);
    if (!s) return s.error();
    if (!cfg.tls_key.empty()) {  // the client private key: exists, regular file, exactly 0600
      struct stat st{};
      if (::stat(cfg.tls_key.c_str(), &st) != 0 || !S_ISREG(st.st_mode)) return bad("config: tls.key is not a readable file");
      if ((st.st_mode & 07777) != 0600) return Error{ErrorCode::AccessDenied, "config: tls.key must have mode 0600"};
    }
  }
  return cfg;
}

}  // namespace

Expected<ClientConfig> load_config(std::string_view path_or_toml) {
  if (looks_like_text(path_or_toml)) return parse_validate(path_or_toml, false);
  std::string path(path_or_toml);
  if (path.empty()) return bad("config: empty path");
  std::ifstream in(path, std::ios::binary);
  if (!in) return Error{ErrorCode::NotFound, "config: cannot open config file"};
  std::ostringstream ss;
  ss << in.rdbuf();
  return parse_validate(ss.str(), true);
}

}  // namespace miracache
