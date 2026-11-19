// SPDX-License-Identifier: Apache-2.0
#include "src/dyn_config.h"

#include <toml++/toml.hpp>

#include <algorithm>
#include <cstring>

namespace miracache {
namespace {

// A key of the table and the section it lives in. `kind`: A / C apply live, B is recorded as pending.
struct Ctx {
  ClientDyn out;
  const ClientDyn& base;
  std::string error;
  std::vector<std::string> unknown;
  bool fail(std::string m) {
    if (error.empty()) error = std::move(m);
    return false;
  }
};

bool get_uint(Ctx& c, const toml::table& t, const char* section, const char* key, std::uint64_t lo, std::uint64_t hi,
              std::uint64_t& out) {
  const toml::node* n = t.get(key);
  if (!n) return true;
  const auto v = n->value<std::int64_t>();
  if (!n->is_integer() || !v || *v < 0 || static_cast<std::uint64_t>(*v) < lo || static_cast<std::uint64_t>(*v) > hi)
    return c.fail(std::string(section) + "." + key + " must be an integer in " + std::to_string(lo) + ".." + std::to_string(hi));
  out = static_cast<std::uint64_t>(*v);
  return true;
}
template <class T>
bool get_u(Ctx& c, const toml::table& t, const char* section, const char* key, std::uint64_t lo, std::uint64_t hi, T& out) {
  std::uint64_t v = out;
  if (!get_uint(c, t, section, key, lo, hi, v)) return false;
  out = static_cast<T>(v);
  return true;
}

// STATIC names per section: present in the table = the whole table is an error (restart required).
bool is_static(std::string_view section, std::string_view key) {
  // The NIC operating-point keys are set from the local file / profile only (G06): in a bundle they are refused with
  // their name (logged, counted as miracache_config_reload_total{result="rejected"}), never ignored.
  if (section == "fabric")
    return key == "device" || key == "devices" || key == "profiles_file" || key == "read_depth" || key == "inline_bytes" ||
           key == "ack_timeout_exp" || key == "retry_count" || key == "rnr_retry_count" || key == "window_bytes";
  return false;
}

bool parse_section(Ctx& c, const toml::table& t, const char* section, std::initializer_list<const char*> known) {
  for (const auto& [k, v] : t) {
    (void)v;
    const std::string_view key = k.str();
    if (is_static(section, key)) return c.fail(std::string(section) + "." + std::string(key) + " is STATIC (restart the client)");
    bool ok = false;
    for (const char* n : known) ok = ok || key == n;
    if (!ok) c.unknown.push_back(std::string(section) + "." + std::string(key));
  }
  return true;
}

bool parse_fabric(Ctx& c, const toml::table& t) {
  if (!parse_section(c, t, "fabric",
                     {"keepalive_ms", "reconnect_min_ms", "reconnect_max_ms", "reconnect_connect_ms", "watchdog_grace_ms",
                      "ticket_batch", "slice_bytes", "mtu", "protocol", "fetch_qps"}))
    return false;
  ClientDyn& o = c.out;
  if (!get_u(c, t, "fabric", "keepalive_ms", 10, 600000, o.keepalive_ms)) return false;  // 0 stays rejected (it drives reconnect)
  if (!get_u(c, t, "fabric", "reconnect_min_ms", 1, 60000, o.reconnect_min_ms)) return false;
  if (!get_u(c, t, "fabric", "reconnect_max_ms", 1, 600000, o.reconnect_max_ms)) return false;
  if (o.reconnect_max_ms < o.reconnect_min_ms) return c.fail("fabric.reconnect_max_ms must be >= reconnect_min_ms");
  if (!get_u(c, t, "fabric", "reconnect_connect_ms", 1, 60000, o.reconnect_connect_ms)) return false;
  if (!get_u(c, t, "fabric", "watchdog_grace_ms", 1, 600000, o.watchdog_grace_ms)) return false;
  if (!get_u(c, t, "fabric", "ticket_batch", 1, 64, o.ticket_batch)) return false;
  if (!get_u(c, t, "fabric", "slice_bytes", 4096, 4u << 20, o.slice_bytes)) return false;
  if (t.get("slice_bytes") && (o.slice_bytes & (o.slice_bytes - 1)))  // A3.3: power of two, 4 KiB..4 MiB
    return c.fail("fabric.slice_bytes must be a power of two, 4 KiB..4 MiB");
  // class B (pending until the rebuild)
  if (const toml::node* n = t.get("mtu")) {
    const auto v = n->value<std::int64_t>();
    if (!n->is_integer() || !v || (*v != 256 && *v != 512 && *v != 1024 && *v != 2048 && *v != 4096))
      return c.fail("fabric.mtu must be 256, 512, 1024, 2048 or 4096");
    o.mtu = static_cast<std::uint32_t>(*v);
  }
  if (const toml::node* n = t.get("protocol")) {
    const auto s = n->value<std::string_view>();
    if (!s) return c.fail("fabric.protocol must be a string");
    if (*s == "auto") o.protocol = FabricProtocol::Auto;
    else if (*s == "roce") o.protocol = FabricProtocol::Roce;
    else if (*s == "iwarp") o.protocol = FabricProtocol::Iwarp;
    else return c.fail("fabric.protocol must be auto, roce or iwarp");
  }
  if (!get_u(c, t, "fabric", "fetch_qps", 1, 16, o.fetch_qps)) return false;
  return true;
}

// [cluster.client.breaker]: the per-node circuit breaker (class A).
bool parse_breaker(Ctx& c, const toml::table& t) {
  if (!parse_section(c, t, "breaker",
                     {"enabled", "window_ms", "min_ops", "min_misses", "miss_pct", "p99_factor", "floor_us", "open_ms",
                      "open_max_ms", "probes"}))
    return false;
  ClientDyn& o = c.out;
  if (const toml::node* n = t.get("enabled")) {
    const auto v = n->value<bool>();
    if (!n->is_boolean() || !v) return c.fail("breaker.enabled must be true or false");
    o.breaker_enabled = *v;
  }
  if (!get_u(c, t, "breaker", "window_ms", 100, 600000, o.breaker_window_ms)) return false;
  if (!get_u(c, t, "breaker", "min_ops", 1, 1000000, o.breaker_min_ops)) return false;
  if (!get_u(c, t, "breaker", "min_misses", 1, 1000000, o.breaker_min_misses)) return false;
  if (!get_u(c, t, "breaker", "miss_pct", 1, 100, o.breaker_miss_pct)) return false;
  if (!get_u(c, t, "breaker", "p99_factor", 2, 1000, o.breaker_p99_factor)) return false;
  if (!get_u(c, t, "breaker", "floor_us", 0, 60000000, o.breaker_floor_us)) return false;
  if (!get_u(c, t, "breaker", "open_ms", 1, 600000, o.breaker_open_ms)) return false;
  if (!get_u(c, t, "breaker", "open_max_ms", 1, 3600000, o.breaker_open_max_ms)) return false;
  if (o.breaker_open_max_ms < o.breaker_open_ms) return c.fail("breaker.open_max_ms must be >= open_ms");
  if (!get_u(c, t, "breaker", "probes", 1, 64, o.breaker_probes)) return false;
  return true;
}

}  // namespace

DynParse parse_client_dyn(std::string_view config_toml, const ClientDyn& base, std::uint64_t generation) {
  DynParse res;
  Ctx c{base, base, {}, {}};
  c.out.generation = generation;
  c.out.pending_rebuild.clear();
  toml::table root;
  if (!config_toml.empty()) {
    toml::parse_result pr = toml::parse(config_toml);
    if (!pr) {
      res.error = "config does not parse";
      return res;
    }
    root = std::move(pr).table();
  }
  const toml::table* client = nullptr;
  if (const toml::table* cl = root.get_as<toml::table>("cluster")) client = cl->get_as<toml::table>("client");
  if (client) {
    for (const auto& [k, v] : *client) {
      const std::string_view name = k.str();
      const toml::table* t = v.as_table();
      if (name == "scope" || name == "tls" || name == "control" || name == "lab" || name == "nodes") {
        res.error = std::string(name) + " is STATIC (restart the client)";
        return res;
      }
      if (!t) {
        c.unknown.push_back(std::string(name));
        continue;
      }
      bool ok = true;
      if (name == "fabric") {
        ok = parse_fabric(c, *t);
      } else if (name == "deadline") {
        ok = parse_section(c, *t, "deadline", {"put_max_ms"}) && get_u(c, *t, "deadline", "put_max_ms", 1, 600000, c.out.put_max_ms);
      } else if (name == "placement") {
        ok = parse_section(c, *t, "placement", {"replica_mode", "replica_buffer_bytes", "previous_view_ms", "hint_entries"});
        if (ok) {
          if (const toml::node* n = t->get("replica_mode")) {
            const auto s = n->value<std::string_view>();
            if (!s || (*s != "async" && *s != "sync")) ok = c.fail("placement.replica_mode must be async or sync");
            else c.out.replica_mode = *s == "sync" ? ReplicaMode::Sync : ReplicaMode::Async;
          }
        }
        ok = ok && get_u(c, *t, "placement", "replica_buffer_bytes", 0, 1ull << 40, c.out.replica_buffer_bytes) &&
             get_u(c, *t, "placement", "previous_view_ms", 0, 7ull * 24 * 3600 * 1000, c.out.previous_view_ms) &&
             get_u(c, *t, "placement", "hint_entries", 0, 1u << 24, c.out.hint_entries);
      } else if (name == "breaker") {
        ok = parse_breaker(c, *t);
      } else if (name == "crypto") {
        ok = parse_section(c, *t, "crypto", {"workers"}) && get_u(c, *t, "crypto", "workers", 1, 64, c.out.crypto_workers);
      } else if (name == "landing") {
        ok = parse_section(c, *t, "landing", {"subpool_bytes"}) &&
             get_u(c, *t, "landing", "subpool_bytes", 1ull << 20, 64ull << 30, c.out.subpool_bytes);
        if (ok && c.out.subpool_bytes % 4096 != 0) ok = c.fail("landing.subpool_bytes must be a multiple of 4096");
      } else {
        c.unknown.push_back(std::string(name));
      }
      if (!ok) {
        res.error = c.error;
        return res;
      }
    }
  }
  ClientDyn& o = c.out;
  {  // G06 (decision 7): the memory nodes' lease.put_timeout_s (this bundle's cluster table, default 10 s) >= 4 x put_max_ms
    std::int64_t put_ms = 10000;
    bool mentioned = false;  // only a bundle that sets put_max_ms is checked (a put_max_ms from the local base is not bundle content)
    if (client)
      if (const toml::table* dl = client->get_as<toml::table>("deadline")) mentioned = dl->contains("put_max_ms");
    if (const toml::table* cl = root.get_as<toml::table>("cluster"))
      if (const toml::table* mn = cl->get_as<toml::table>("memnode"))
        if (const toml::table* ls = mn->get_as<toml::table>("lease"))
          if (const toml::node* n = ls->get("put_timeout_s"))
            if (auto v = n->value<std::int64_t>(); n->is_integer() && v && *v > 0) put_ms = *v * 1000;
    if (mentioned && put_ms < 4 * static_cast<std::int64_t>(o.put_max_ms)) {
      res.error = "config: lease.put_timeout_s must be >= 4 x client deadline.put_max_ms";
      return res;
    }
  }
  if (o.subpool_bytes != base.subpool_bytes) o.pending_rebuild.push_back("landing.subpool_bytes");
  if (o.mtu != base.mtu) o.pending_rebuild.push_back("fabric.mtu");
  if (o.protocol != base.protocol) o.pending_rebuild.push_back("fabric.protocol");
  if (o.fetch_qps != base.fetch_qps) o.pending_rebuild.push_back("fabric.fetch_qps");
  res.dyn = std::make_shared<const ClientDyn>(std::move(o));
  res.unknown = std::move(c.unknown);
  return res;
}

std::vector<std::string> dyn_changed_keys(const ClientDyn& a, const ClientDyn& b) {
  std::vector<std::string> k;
#define MC_DIFF(field, name) \
  if (a.field != b.field) k.push_back(name)
  MC_DIFF(keepalive_ms, "fabric.keepalive_ms");
  MC_DIFF(reconnect_min_ms, "fabric.reconnect_min_ms");
  MC_DIFF(reconnect_max_ms, "fabric.reconnect_max_ms");
  MC_DIFF(reconnect_connect_ms, "fabric.reconnect_connect_ms");
  MC_DIFF(watchdog_grace_ms, "fabric.watchdog_grace_ms");
  MC_DIFF(ticket_batch, "fabric.ticket_batch");
  MC_DIFF(slice_bytes, "fabric.slice_bytes");
  MC_DIFF(put_max_ms, "deadline.put_max_ms");
  MC_DIFF(replica_mode, "placement.replica_mode");
  MC_DIFF(replica_buffer_bytes, "placement.replica_buffer_bytes");
  MC_DIFF(previous_view_ms, "placement.previous_view_ms");
  MC_DIFF(hint_entries, "placement.hint_entries");
  MC_DIFF(breaker_enabled, "breaker.enabled");
  MC_DIFF(breaker_window_ms, "breaker.window_ms");
  MC_DIFF(breaker_min_ops, "breaker.min_ops");
  MC_DIFF(breaker_min_misses, "breaker.min_misses");
  MC_DIFF(breaker_miss_pct, "breaker.miss_pct");
  MC_DIFF(breaker_p99_factor, "breaker.p99_factor");
  MC_DIFF(breaker_floor_us, "breaker.floor_us");
  MC_DIFF(breaker_open_ms, "breaker.open_ms");
  MC_DIFF(breaker_open_max_ms, "breaker.open_max_ms");
  MC_DIFF(breaker_probes, "breaker.probes");
  MC_DIFF(crypto_workers, "crypto.workers");
  MC_DIFF(subpool_bytes, "landing.subpool_bytes");
  MC_DIFF(mtu, "fabric.mtu");
  MC_DIFF(protocol, "fabric.protocol");
  MC_DIFF(fetch_qps, "fabric.fetch_qps");
#undef MC_DIFF
  return k;
}

}  // namespace miracache
