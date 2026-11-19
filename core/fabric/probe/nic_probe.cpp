// SPDX-License-Identifier: Apache-2.0
#include "fabric/probe/nic_probe.h"

#include <cstdio>

namespace miracache::fabric::probe {

namespace {

using protocol::Protocol;

// Local so this file builds without the verbs backend (protocol_rules.cpp is verbs-only).
const char* proto_name(Protocol p) {
  switch (p) {
    case Protocol::RoCE: return "roce-v2";
    case Protocol::IWarp: return "iwarp";
    case Protocol::InfiniBand: return "infiniband";
    case Protocol::Unknown: break;
  }
  return "unknown";
}

std::string hex(std::uint64_t v, int width) {
  char b[32];
  std::snprintf(b, sizeof b, "0x%0*llx", width, static_cast<unsigned long long>(v));
  return b;
}

std::string guid_text(std::uint64_t g) {
  char b[32];
  std::snprintf(b, sizeof b, "%04x:%04x:%04x:%04x", static_cast<unsigned>((g >> 48) & 0xffff),
                static_cast<unsigned>((g >> 32) & 0xffff), static_cast<unsigned>((g >> 16) & 0xffff),
                static_cast<unsigned>(g & 0xffff));
  return b;
}

std::string page_sizes(std::uint64_t cap) {
  std::string out;
  for (int bit = 0; bit < 64; ++bit) {
    if ((cap >> bit & 1) == 0) continue;
    const std::uint64_t sz = std::uint64_t{1} << bit;
    char b[24];
    if (sz >= (1ULL << 30)) std::snprintf(b, sizeof b, "%lluG", static_cast<unsigned long long>(sz >> 30));
    else if (sz >= (1ULL << 20)) std::snprintf(b, sizeof b, "%lluM", static_cast<unsigned long long>(sz >> 20));
    else if (sz >= (1ULL << 10)) std::snprintf(b, sizeof b, "%lluK", static_cast<unsigned long long>(sz >> 10));
    else std::snprintf(b, sizeof b, "%llu", static_cast<unsigned long long>(sz));
    if (!out.empty()) out += ',';
    out += b;
  }
  return out;
}

void json_str(std::string& o, const std::string& s) {
  o += '"';
  for (const char c : s) {
    switch (c) {
      case '"': o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n"; break;
      default:
        if (static_cast<unsigned char>(c) < 0x20) {
          char b[8];
          std::snprintf(b, sizeof b, "\\u%04x", static_cast<unsigned>(c));
          o += b;
        } else {
          o += c;
        }
    }
  }
  o += '"';
}

void json_strs(std::string& o, const std::vector<std::string>& v) {
  o += '[';
  for (std::size_t i = 0; i < v.size(); ++i) {
    if (i != 0) o += ',';
    json_str(o, v[i]);
  }
  o += ']';
}

void json_trial(std::string& o, const TrialResult& t) {
  o += "{\"result\":";
  json_str(o, to_string(t.result));
  o += ",\"detail\":";
  json_str(o, t.detail);
  o += '}';
}

void kv_u(std::string& o, const char* k, std::uint64_t v, bool comma = true) {
  o += '"';
  o += k;
  o += "\":";
  o += std::to_string(v);
  if (comma) o += ',';
}

}  // namespace

const char* to_string(Trial t) {
  switch (t) {
    case Trial::NotTried: return "not tried";
    case Trial::Supported: return "supported";
    case Trial::Unsupported: return "unsupported";
  }
  return "?";
}

Verdict evaluate(const NicFacts& f) {
  Verdict v;
  if (f.protocol != Protocol::RoCE && f.protocol != Protocol::IWarp) {
    v.reasons.push_back(f.protocol == Protocol::InfiniBand
                            ? "native InfiniBand is not supported (RoCE v2 or iWARP only)"
                            : "transport/link layer is neither RoCE nor iWARP");
  }
  bool any_active = false;
  bool roce_v2_gid = false;
  for (const auto& p : f.ports) {
    if (p.state == "active") any_active = true;
    for (const auto& g : p.gids) {
      if (g.type == "roce-v2") roce_v2_gid = true;
    }
  }
  if (!any_active) v.reasons.push_back("no port is ACTIVE");
  if (f.protocol == Protocol::RoCE && any_active && !roce_v2_gid) {
    v.reasons.push_back("no RoCE v2 GID on any port");
  }
  if (f.limits.max_qp_rd_atom < kReadDepthFloor) {
    v.reasons.push_back("max_qp_rd_atom " + std::to_string(f.limits.max_qp_rd_atom) + " < floor " +
                        std::to_string(kReadDepthFloor));
  }
  if (f.limits.max_qp_init_rd_atom < kReadDepthFloor) {
    v.reasons.push_back("max_qp_init_rd_atom " + std::to_string(f.limits.max_qp_init_rd_atom) +
                        " < floor " + std::to_string(kReadDepthFloor));
  }
  v.usable = v.reasons.empty();

  if (f.mw_type1.result != Trial::Supported && f.mw_type2.result != Trial::Supported) {
    v.warnings.push_back("no memory windows: rkey rotation falls back to re-registration");
  }
  if (f.dmabuf.result != Trial::Supported) v.warnings.push_back("dma-buf registration not confirmed (v2 feature)");
  if (f.limits.max_mr_size != 0 && f.limits.max_mr_size < (1ULL << 30)) {
    v.warnings.push_back("max_mr_size below 1 GiB: segments must be smaller");
  }
  return v;
}

std::string to_json(const std::vector<NicFacts>& devices) {
  std::string o = "{\"schema\":\"miracache.nicprobe\",\"schema_version\":" + std::to_string(kJsonSchemaVersion) +
                  ",\"devices\":[";
  for (std::size_t i = 0; i < devices.size(); ++i) {
    const NicFacts& f = devices[i];
    const Verdict v = evaluate(f);
    if (i != 0) o += ',';
    o += "{\"device\":";
    json_str(o, f.device);
    o += ",\"driver\":";
    json_str(o, f.driver);
    o += ",";
    kv_u(o, "vendor_id", f.vendor_id);
    kv_u(o, "vendor_part_id", f.vendor_part_id);
    kv_u(o, "hw_ver", f.hw_ver);
    o += "\"node_guid\":";
    json_str(o, guid_text(f.node_guid));
    o += ",\"fw_version\":";
    json_str(o, f.fw_version);
    o += ",\"transport\":";
    json_str(o, f.transport);
    o += ",\"protocol\":";
    json_str(o, proto_name(f.protocol));
    o += ",\"ports\":[";
    for (std::size_t pi = 0; pi < f.ports.size(); ++pi) {
      const PortFacts& p = f.ports[pi];
      if (pi != 0) o += ',';
      o += '{';
      kv_u(o, "port", p.port);
      o += "\"state\":";
      json_str(o, p.state);
      o += ",\"link_layer\":";
      json_str(o, p.link_layer);
      o += ',';
      kv_u(o, "speed_mbps", p.speed_mbps);
      kv_u(o, "active_mtu", p.active_mtu);
      kv_u(o, "max_mtu", p.max_mtu);
      o += "\"gids\":[";
      for (std::size_t gi = 0; gi < p.gids.size(); ++gi) {
        const GidEntry& g = p.gids[gi];
        if (gi != 0) o += ',';
        o += '{';
        kv_u(o, "index", g.index);
        o += "\"gid\":";
        json_str(o, g.gid);
        o += ",\"type\":";
        json_str(o, g.type);
        o += std::string(",\"ipv4_mapped\":") + (g.ipv4_mapped ? "true" : "false") + '}';
      }
      o += "]}";
    }
    o += "],\"limits\":{";
    kv_u(o, "max_qp", f.limits.max_qp);
    kv_u(o, "max_cq", f.limits.max_cq);
    kv_u(o, "max_cqe", f.limits.max_cqe);
    kv_u(o, "max_mr", f.limits.max_mr);
    kv_u(o, "max_mr_size", f.limits.max_mr_size);
    kv_u(o, "max_pd", f.limits.max_pd);
    kv_u(o, "max_sge", f.limits.max_sge);
    kv_u(o, "max_sge_rd", f.limits.max_sge_rd);
    kv_u(o, "max_qp_wr", f.limits.max_qp_wr);
    kv_u(o, "page_size_cap", f.limits.page_size_cap);
    kv_u(o, "max_qp_rd_atom", f.limits.max_qp_rd_atom);
    kv_u(o, "max_qp_init_rd_atom", f.limits.max_qp_init_rd_atom, false);
    o += "},\"odp\":";
    o += f.odp ? "true" : "false";
    o += ",\"mw_type1\":";
    json_trial(o, f.mw_type1);
    o += ",\"mw_type2\":";
    json_trial(o, f.mw_type2);
    o += ",\"dmabuf\":";
    json_trial(o, f.dmabuf);
    o += ",\"verdict\":{\"usable\":";
    o += v.usable ? "true" : "false";
    o += ",\"reasons\":";
    json_strs(o, v.reasons);
    o += ",\"warnings\":";
    json_strs(o, v.warnings);
    o += "}}";
  }
  o += "]}\n";
  return o;
}

std::string to_table(const std::vector<NicFacts>& devices) {
  std::string o;
  auto line = [&](const std::string& k, const std::string& val) {
    std::string key = k;
    key.resize(22, ' ');
    o += "  " + key + val + "\n";
  };
  for (const NicFacts& f : devices) {
    const Verdict v = evaluate(f);
    o += "== " + f.device + " ==\n";
    line("driver", f.driver.empty() ? "-" : f.driver);
    line("vendor/part", hex(f.vendor_id, 4) + "/" + hex(f.vendor_part_id, 4) + " hw " + std::to_string(f.hw_ver));
    line("node guid", guid_text(f.node_guid));
    line("firmware", f.fw_version.empty() ? "-" : f.fw_version);
    line("transport/protocol", f.transport + " -> " + proto_name(f.protocol));
    for (const PortFacts& p : f.ports) {
      line("port " + std::to_string(p.port), p.state + ", " + p.link_layer + ", " + std::to_string(p.speed_mbps) +
                                                 " Mb/s, mtu " + std::to_string(p.active_mtu) + "/" +
                                                 std::to_string(p.max_mtu));
      for (const GidEntry& g : p.gids) {
        line("  gid " + std::to_string(g.index), g.gid + " " + g.type + (g.ipv4_mapped ? " (ipv4)" : ""));
      }
    }
    const DeviceLimits& l = f.limits;
    line("read depth", "rd_atom (IRD) " + std::to_string(l.max_qp_rd_atom) + ", init_rd_atom (ORD) " +
                           std::to_string(l.max_qp_init_rd_atom));
    line("mr", "max_mr " + std::to_string(l.max_mr) + ", max_mr_size " + std::to_string(l.max_mr_size) +
                   ", pages " + page_sizes(l.page_size_cap));
    line("qp/cq/sge", "max_qp " + std::to_string(l.max_qp) + ", max_cq " + std::to_string(l.max_cq) +
                          ", max_sge " + std::to_string(l.max_sge));
    line("mw type 1", std::string(to_string(f.mw_type1.result)) + (f.mw_type1.detail.empty() ? "" : " (" + f.mw_type1.detail + ")"));
    line("mw type 2", std::string(to_string(f.mw_type2.result)) + (f.mw_type2.detail.empty() ? "" : " (" + f.mw_type2.detail + ")"));
    line("dma-buf mr", std::string(to_string(f.dmabuf.result)) + (f.dmabuf.detail.empty() ? "" : " (" + f.dmabuf.detail + ")"));
    line("odp", f.odp ? "yes" : "no");
    line("usable", v.usable ? "YES" : "NO");
    for (const auto& r : v.reasons) line("  reason", r);
    for (const auto& w : v.warnings) line("  warning", w);
  }
  return o;
}

}  // namespace miracache::fabric::probe
