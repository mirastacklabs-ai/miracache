// SPDX-License-Identifier: Apache-2.0
#include "fabric/profile/nic_profile.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>

// toml++ 3.4.0 asserts (debug builds only) on some malformed key starts that its release build rejects
// with a normal parse error; found by NicProfile.FuzzedInputNeverCrashes. Operator-supplied registry files
// must produce an error, never an abort, so this translation unit compiles the library with its asserts off.
#define TOML_ASSERT(expr) (void)0
#include <toml++/toml.hpp>

#include "util/log.h"

namespace miracache::fabric::profile {

extern const char* const kEmbeddedProfilesToml;  // generated from profiles/nic-profiles.toml

OperatingPoint builtin_default() { return OperatingPoint{}; }

const char* to_string(FwStatus s) {
  switch (s) {
    case FwStatus::NotChecked: return "not_checked";
    case FwStatus::Ok: return "ok";
    case FwStatus::BelowMin: return "below_min";
    case FwStatus::Unknown: return "unknown";
  }
  return "?";
}

namespace {

Error bad(const char* ctx) { return Error{ErrorCode::InvalidArgument, ctx}; }

template <std::size_t N>
bool keys_ok(const toml::table& t, const char* const (&allowed)[N]) {
  for (auto&& [k, v] : t) {
    bool ok = false;
    for (const char* a : allowed) ok = ok || k.str() == a;
    if (!ok) return false;
  }
  return true;
}

bool is_pow2(std::uint64_t v) { return v != 0 && (v & (v - 1)) == 0; }

bool valid_mtu(std::uint64_t m) { return m == 256 || m == 512 || m == 1024 || m == 2048 || m == 4096; }

bool valid_loss(const std::string& s) { return s == "pfc_ecn" || s == "ztr_rttcc" || s == "tcp" || s == "soft"; }

bool valid_id(const std::string& s) {
  if (s.empty() || s.size() > 64) return false;
  for (char c : s)
    if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_')) return false;
  return true;
}

// Reads an optional integer into [lo, hi]. Returns false on a wrong type or out of range.
template <typename T>
bool get_int(const toml::table& t, const char* key, std::int64_t lo, std::int64_t hi, T& out) {
  const toml::node* n = t.get(key);
  if (n == nullptr) return true;
  auto v = n->value<std::int64_t>();
  if (!n->is_integer() || !v || *v < lo || *v > hi) return false;
  out = static_cast<T>(*v);
  return true;
}

bool get_str(const toml::table& t, const char* key, std::size_t max_len, std::string& out) {
  const toml::node* n = t.get(key);
  if (n == nullptr) return true;
  if (!n->is_string()) return false;
  out = n->as_string()->get();
  return out.size() <= max_len;
}

bool get_uint_list(const toml::table& t, const char* key, std::vector<std::uint32_t>& out) {
  const toml::node* n = t.get(key);
  if (n == nullptr) return true;
  const toml::array* a = n->as_array();
  if (a == nullptr || a->empty() || a->size() > 64) return false;
  for (const auto& e : *a) {
    if (!e.is_integer()) return false;
    const std::int64_t v = e.as_integer()->get();
    if (v < 0 || v > 0xffffffffll) return false;
    out.push_back(static_cast<std::uint32_t>(v));
  }
  return true;
}

bool get_str_list(const toml::table& t, const char* key, std::vector<std::string>& out) {
  const toml::node* n = t.get(key);
  if (n == nullptr) return true;
  const toml::array* a = n->as_array();
  if (a == nullptr || a->empty() || a->size() > 16) return false;
  for (const auto& e : *a) {
    if (!e.is_string()) return false;
    out.push_back(e.as_string()->get());
    if (out.back().empty() || out.back().size() > 64) return false;
  }
  return true;
}

// The relations between the operating-point values (shared by the file parser and the overrides).
const char* check_op(const OperatingPoint& o) {
  if (o.fetch_qps < 1 || o.fetch_qps > 64) return "nic profile: fetch_qps must be 1..64";
  if (o.ingest_qps < 1 || o.ingest_qps > 64) return "nic profile: ingest_qps must be 1..64";
  if (!is_pow2(o.slice_bytes) || o.slice_bytes < 4096 || o.slice_bytes > (4u << 20))
    return "nic profile: slice_bytes must be a power of two, 4 KiB..4 MiB";
  if (o.read_depth < 1 || o.read_depth > 255) return "nic profile: read_depth must be 1..255";
  if (o.window_bytes < o.slice_bytes || o.window_bytes % o.slice_bytes != 0)
    return "nic profile: window_bytes must be a positive multiple of slice_bytes";
  if (o.window_bytes / o.slice_bytes > o.read_depth)
    return "nic profile: window_bytes must be at most read_depth * slice_bytes";
  if (o.inline_bytes > 256) return "nic profile: inline_bytes must be 0..256";
  if (o.ack_timeout_exp < 1 || o.ack_timeout_exp > 19) return "nic profile: ack_timeout_exp must be 1..19";
  if (o.retry_count > 7) return "nic profile: retry_count must be 0..7";
  if (o.rnr_retry_count > 6) return "nic profile: rnr_retry_count must be 0..6 (7 means retry forever)";
  if (!valid_mtu(o.mtu)) return "nic profile: mtu must be 256, 512, 1024, 2048 or 4096";
  return nullptr;
}

Expected<OperatingPoint> parse_op(const toml::table& t) {
  static constexpr const char* k[] = {"fetch_qps", "ingest_qps", "slice_bytes", "window_bytes", "read_depth", "inline_bytes",
                                      "ack_timeout_exp", "retry_count", "rnr_retry_count", "mtu"};
  if (!keys_ok(t, k)) return bad("nic profile: unknown key in [profile.op]");
  OperatingPoint o = builtin_default();
  constexpr std::int64_t kBig = std::int64_t{1} << 40;
  bool ok = get_int(t, "fetch_qps", 0, 1000, o.fetch_qps) && get_int(t, "ingest_qps", 0, 1000, o.ingest_qps) &&
            get_int(t, "slice_bytes", 0, kBig, o.slice_bytes) && get_int(t, "window_bytes", 0, kBig, o.window_bytes) &&
            get_int(t, "read_depth", 0, 100000, o.read_depth) && get_int(t, "inline_bytes", 0, 100000, o.inline_bytes) &&
            get_int(t, "ack_timeout_exp", 0, 255, o.ack_timeout_exp) && get_int(t, "retry_count", 0, 255, o.retry_count) &&
            get_int(t, "rnr_retry_count", 0, 255, o.rnr_retry_count) && get_int(t, "mtu", 0, 1 << 20, o.mtu);
  if (!ok) return bad("nic profile: [profile.op] value has the wrong type or is out of range");
  if (const char* e = check_op(o)) return bad(e);
  return o;
}

Expected<Profile> parse_profile(const toml::table& t) {
  static constexpr const char* k[] = {"id", "tier", "verified", "fw_min", "notes", "warn", "match", "loss_handling", "op"};
  if (!keys_ok(t, k)) return bad("nic profile: unknown key in [[profile]]");
  Profile p;
  if (!get_str(t, "id", 64, p.id) || !valid_id(p.id)) return bad("nic profile: id missing or not [a-z0-9._-]{1,64}");
  if (!get_int(t, "tier", 0, 2, p.tier)) return bad("nic profile: tier must be 0..2");
  if (const toml::node* v = t.get("verified")) {
    if (!v->is_boolean()) return bad("nic profile: verified must be a boolean");
    p.verified = v->as_boolean()->get();
  } else {
    return bad("nic profile: verified is required (true or false)");
  }
  if (!get_str(t, "fw_min", 64, p.fw_min) || !get_str(t, "notes", 1024, p.notes) || !get_str(t, "warn", 256, p.warn))
    return bad("nic profile: fw_min/notes/warn must be short strings");
  if (!p.fw_min.empty() && check_firmware("1", p.fw_min) == FwStatus::Unknown)
    return bad("nic profile: fw_min must be dotted numbers like 22.31.0");

  const toml::table* m = t["match"].as_table();
  if (m == nullptr) return bad("nic profile: [profile.match] is required");
  static constexpr const char* km[] = {"vendor_id", "part_id", "driver", "device_prefix", "transport"};
  if (!keys_ok(*m, km)) return bad("nic profile: unknown key in [profile.match]");
  if (!get_uint_list(*m, "vendor_id", p.match.vendor_id) || !get_uint_list(*m, "part_id", p.match.part_id) ||
      !get_str_list(*m, "driver", p.match.driver) || !get_str(*m, "device_prefix", 32, p.match.device_prefix) ||
      !get_str(*m, "transport", 8, p.match.transport))
    return bad("nic profile: [profile.match] value has the wrong type or is out of range");
  if (!p.match.transport.empty() && p.match.transport != "roce" && p.match.transport != "iwarp")
    return bad("nic profile: match.transport must be roce or iwarp");
  if (p.match.vendor_id.empty() && p.match.part_id.empty() && p.match.driver.empty() && p.match.device_prefix.empty() &&
      p.match.transport.empty())
    return bad("nic profile: [profile.match] has no keys (a match-all profile would hide an unprofiled NIC)");

  const toml::table* lh = t["loss_handling"].as_table();
  if (lh == nullptr) return bad("nic profile: [profile.loss_handling] is required");
  static constexpr const char* kl[] = {"require_any"};
  if (!keys_ok(*lh, kl)) return bad("nic profile: unknown key in [profile.loss_handling]");
  if (!get_str_list(*lh, "require_any", p.loss_require_any) || p.loss_require_any.empty())
    return bad("nic profile: loss_handling.require_any must be a non-empty string list");
  for (const auto& s : p.loss_require_any)
    if (!valid_loss(s)) return bad("nic profile: loss_handling value must be pfc_ecn, ztr_rttcc, tcp or soft");

  const toml::table* op = t["op"].as_table();
  if (op == nullptr) return bad("nic profile: [profile.op] is required");
  auto o = parse_op(*op);
  if (!o) return o.error();
  p.op = *o;
  return p;
}

}  // namespace

Expected<Registry> parse_registry(std::string_view text) {
  if (text.size() > kMaxRegistryBytes) return bad("nic profile: registry too large");
  // The registry is plain ASCII data. Refusing control characters and non-ASCII bytes up front also keeps
  // hostile bytes away from toml++ (its debug build asserts on some malformed key starts; found by the fuzz test).
  for (char ch : text) {
    const auto c = static_cast<unsigned char>(ch);
    if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c >= 0x7f)
      return bad("nic profile: registry must be ASCII text without control characters");
  }
  toml::parse_result parsed = toml::parse(text);
  if (!parsed) return bad("nic profile: TOML syntax error");
  const toml::table& root = parsed.table();
  static constexpr const char* k[] = {"schema", "registry_version", "profile"};
  if (!keys_ok(root, k)) return bad("nic profile: unknown top-level key");
  Registry r;
  std::int64_t schema = 0;
  if (!get_int(root, "schema", 0, 1000, schema) || schema != kSchema) return bad("nic profile: schema must be 1");
  if (!get_str(root, "registry_version", 64, r.version) || r.version.empty())
    return bad("nic profile: registry_version is required");
  const toml::array* arr = root["profile"].as_array();
  if (arr == nullptr || arr->empty() || arr->size() > kMaxProfiles || !arr->is_homogeneous(toml::node_type::table))
    return bad("nic profile: [[profile]] entries are required");
  for (const auto& el : *arr) {
    auto p = parse_profile(*el.as_table());
    if (!p) return p.error();
    for (const auto& q : r.profiles)
      if (q.id == p->id) return bad("nic profile: duplicate profile id");
    r.profiles.push_back(std::move(*p));
  }
  // Every transport must have a fallback, or an unprofiled NIC would have nothing to land on.
  bool roce = false, iwarp = false;
  for (const auto& p : r.profiles) {
    const bool only_transport = p.match.vendor_id.empty() && p.match.part_id.empty() && p.match.driver.empty() &&
                                p.match.device_prefix.empty();
    if (only_transport && p.match.transport == "roce") roce = true;
    if (only_transport && p.match.transport == "iwarp") iwarp = true;
  }
  if (!roce || !iwarp) return bad("nic profile: a transport-only fallback profile for both roce and iwarp is required");
  return r;
}

Expected<Registry> load_registry_file(const std::string& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) return Error{ErrorCode::NotFound, "nic profile: cannot open the profiles file"};
  std::string text;
  char buf[4096];
  while (in.read(buf, sizeof buf) || in.gcount() > 0) {
    text.append(buf, static_cast<std::size_t>(in.gcount()));
    if (text.size() > kMaxRegistryBytes) return bad("nic profile: registry too large");
  }
  auto r = parse_registry(text);
  if (!r) return r.error();
  r->source = path;
  return r;
}

Expected<const Registry*> builtin_registry() {
  // Parsed once. A function-local static of Expected<Registry>: a broken built-in is a build bug
  // (the unit test parses it), but it is still reported as an error rather than trusted.
  static const Expected<Registry> cached = parse_registry(kEmbeddedProfilesToml);
  if (!cached) return cached.error();
  return &*cached;
}

FwStatus check_firmware(std::string_view fw, std::string_view min) {
  auto parse = [](std::string_view s, std::vector<std::uint64_t>& out) {
    std::size_t i = 0;
    while (i < s.size() && (s[i] == ' ' || s[i] == 'v')) ++i;
    while (i < s.size() && out.size() < 8) {
      if (s[i] < '0' || s[i] > '9') break;
      std::uint64_t v = 0;
      while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
        v = std::min<std::uint64_t>(v * 10 + static_cast<std::uint64_t>(s[i] - '0'), 1u << 30);
        ++i;
      }
      out.push_back(v);
      if (i < s.size() && s[i] == '.' && i + 1 < s.size() && s[i + 1] >= '0' && s[i + 1] <= '9') ++i;
      else break;
    }
    return !out.empty();
  };
  if (min.empty()) return FwStatus::NotChecked;
  std::vector<std::uint64_t> a, b;
  if (!parse(min, b)) return FwStatus::Unknown;
  if (!parse(fw, a)) return FwStatus::Unknown;
  const std::size_t n = std::max(a.size(), b.size());
  a.resize(n, 0);
  b.resize(n, 0);
  return a < b ? FwStatus::BelowMin : FwStatus::Ok;
}

namespace {

struct Scored {
  const Profile* p = nullptr;
  int score = 0;
};

template <typename T>
bool has(const std::vector<T>& v, const T& x) {
  return std::find(v.begin(), v.end(), x) != v.end();
}

// Every given key must match; the score is the sum of their points. -1 = no match.
int match_score(const MatchRule& m, const probe::NicFacts& f) {
  int s = 0;
  if (!m.vendor_id.empty()) {
    if (!has(m.vendor_id, f.vendor_id)) return -1;
    s += 1;
  }
  if (!m.part_id.empty()) {
    if (!has(m.part_id, f.vendor_part_id)) return -1;
    s += 2;
  }
  if (!m.driver.empty()) {
    if (!has(m.driver, f.driver)) return -1;
    s += 2;
  }
  if (!m.device_prefix.empty()) {
    if (f.device.compare(0, m.device_prefix.size(), m.device_prefix) != 0) return -1;
    s += 2;
  }
  if (!m.transport.empty()) {
    const char* t = f.protocol == protocol::Protocol::RoCE ? "roce" : f.protocol == protocol::Protocol::IWarp ? "iwarp" : "";
    if (m.transport != t) return -1;
    s += 1;
  }
  return s;
}

std::string num(std::uint64_t v) { return std::to_string(v); }

}  // namespace

Expected<Selection> select(const Registry& reg, const probe::NicFacts& f, const Overrides& ov) {
  if (f.protocol != protocol::Protocol::RoCE && f.protocol != protocol::Protocol::IWarp)
    return Error{ErrorCode::Unsupported, "nic profile: the device is neither RoCE nor iWARP, no profile applies"};
  Scored best;
  for (const auto& p : reg.profiles) {
    const int s = match_score(p.match, f);
    if (s > best.score || (s >= 0 && best.p == nullptr)) best = {&p, s};
  }
  if (best.p == nullptr) return Error{ErrorCode::NotFound, "nic profile: no profile matches (registry has no fallback)"};
  const Profile& p = *best.p;

  Selection sel;
  sel.profile_id = p.id;
  sel.tier = p.tier;
  sel.verified = p.verified;
  sel.warn = p.warn;
  sel.unprofiled = !p.warn.empty();
  sel.score = best.score;
  sel.fw_min = p.fw_min;
  sel.fw_version = f.fw_version;
  sel.fw = check_firmware(f.fw_version, p.fw_min);
  sel.loss_require_any = p.loss_require_any;
  sel.profile_op = p.op;
  sel.source = reg.source;
  sel.registry_version = reg.version;

  OperatingPoint o = p.op;
  // Clamp by the probe (spec 4.4): never ask for more than the device or port can do.
  std::uint32_t port_mtu = 0;
  for (const auto& port : f.ports)
    if (port.state == "active" && port.active_mtu != 0) {
      port_mtu = port.active_mtu;
      break;
    }
  if (port_mtu != 0 && o.mtu > port_mtu && valid_mtu(port_mtu)) {
    sel.notes.push_back("mtu " + num(o.mtu) + " -> " + num(port_mtu) + " (port active MTU)");
    o.mtu = port_mtu;
  }
  const std::uint32_t dev_ord = f.limits.max_qp_init_rd_atom;
  if (dev_ord != 0 && o.read_depth > dev_ord) {
    sel.notes.push_back("read_depth " + num(o.read_depth) + " -> " + num(dev_ord) + " (device ORD)");
    o.read_depth = dev_ord;
  }
  // Explicit config beats the profile.
  auto apply = [&](const char* name, auto& dst, const auto& v) {
    if (v) {
      if (static_cast<std::uint64_t>(dst) != static_cast<std::uint64_t>(*v))
        sel.notes.push_back(std::string(name) + " " + num(dst) + " -> " + num(*v) + " (config)");
      dst = *v;
    }
  };
  apply("fetch_qps", o.fetch_qps, ov.fetch_qps);
  apply("ingest_qps", o.ingest_qps, ov.ingest_qps);
  apply("slice_bytes", o.slice_bytes, ov.slice_bytes);
  apply("window_bytes", o.window_bytes, ov.window_bytes);
  apply("read_depth", o.read_depth, ov.read_depth);
  apply("inline_bytes", o.inline_bytes, ov.inline_bytes);
  apply("ack_timeout_exp", o.ack_timeout_exp, ov.ack_timeout_exp);
  apply("retry_count", o.retry_count, ov.retry_count);
  apply("rnr_retry_count", o.rnr_retry_count, ov.rnr_retry_count);
  apply("mtu", o.mtu, ov.mtu);
  // Keep the window inside read_depth * slice (a smaller depth or a larger slice shrinks it).
  if (o.slice_bytes != 0 && o.read_depth != 0) {
    const std::uint64_t cap = o.slice_bytes * o.read_depth;
    std::uint64_t w = std::min(o.window_bytes, cap);
    w -= w % o.slice_bytes;
    if (w < o.slice_bytes) w = o.slice_bytes;
    if (w != o.window_bytes) {
      sel.notes.push_back("window_bytes " + num(o.window_bytes) + " -> " + num(w) + " (read_depth * slice_bytes)");
      o.window_bytes = w;
    }
  }
  if (const char* e = check_op(o)) return Error{ErrorCode::InvalidArgument, e};
  sel.op = o;
  return sel;
}

void log_selection(const Selection& s, const probe::NicFacts& f) {
  using log::Level;
  const char* transport = f.protocol == protocol::Protocol::RoCE ? "roce" : "iwarp";
  std::string clamps;
  for (const auto& n : s.notes) clamps += (clamps.empty() ? "" : "; ") + n;
  log::write(Level::Info, "nic_profile", "profile matched",
             {{"device", f.device}, {"driver", f.driver.empty() ? "-" : f.driver}, {"transport", transport},
              {"vendor_id", num(f.vendor_id)}, {"part_id", num(f.vendor_part_id)}, {"fw", f.fw_version},
              {"profile", s.profile_id}, {"verified", verified_label(s.verified)}, {"tier", num(s.tier)},
              {"score", std::to_string(s.score)}, {"registry", s.source}, {"registry_version", s.registry_version},
              {"fetch_qps", num(s.op.fetch_qps)}, {"ingest_qps", num(s.op.ingest_qps)}, {"slice_bytes", num(s.op.slice_bytes)},
              {"window_bytes", num(s.op.window_bytes)}, {"read_depth", num(s.op.read_depth)},
              {"inline_bytes", num(s.op.inline_bytes)}, {"ack_timeout_exp", num(s.op.ack_timeout_exp)},
              {"retry_count", num(s.op.retry_count)}, {"mtu", num(s.op.mtu)}, {"adjusted", clamps.empty() ? "-" : clamps}});
  if (s.unprofiled)
    log::write(Level::Warn, "nic_profile", s.warn.c_str(),
               {{"device", f.device}, {"driver", f.driver.empty() ? "-" : f.driver}, {"vendor_id", num(f.vendor_id)},
                {"part_id", num(f.vendor_part_id)}, {"profile", s.profile_id}});
  else if (!s.verified)
    log::write(Level::Warn, "nic_profile", "profile values are not verified on hardware",
               {{"device", f.device}, {"profile", s.profile_id}});
  if (s.fw == FwStatus::BelowMin)
    log::write(Level::Warn, "nic_profile", "firmware below the profile minimum",
               {{"device", f.device}, {"profile", s.profile_id}, {"fw", f.fw_version}, {"fw_min", s.fw_min}});
}

std::string selection_to_text(const Selection& s) {
  std::ostringstream o;
  o << "  profile: " << s.profile_id << " (tier " << s.tier << ", verified=" << verified_label(s.verified)
    << ", score " << s.score << ", registry " << s.registry_version << " from " << s.source << ")\n";
  if (s.unprofiled) o << "  WARNING: " << s.warn << "\n";
  if (!s.fw_min.empty()) o << "  firmware: " << (s.fw_version.empty() ? "?" : s.fw_version) << " vs minimum " << s.fw_min << ": " << to_string(s.fw) << "\n";
  o << "  loss handling (any of):";
  for (const auto& l : s.loss_require_any) o << ' ' << l;
  o << "\n  operating point: fetch_qps=" << s.op.fetch_qps << " ingest_qps=" << s.op.ingest_qps
    << " slice_bytes=" << s.op.slice_bytes << " window_bytes=" << s.op.window_bytes << " read_depth=" << s.op.read_depth
    << " inline_bytes=" << s.op.inline_bytes << " ack_timeout_exp=" << unsigned(s.op.ack_timeout_exp)
    << " retry_count=" << unsigned(s.op.retry_count) << " rnr_retry_count=" << unsigned(s.op.rnr_retry_count)
    << " mtu=" << s.op.mtu << "\n";
  for (const auto& n : s.notes) o << "  adjusted: " << n << "\n";
  return o.str();
}

namespace {
std::string jstr(const std::string& s) {
  std::string o = "\"";
  for (char c : s) {
    if (c == '"' || c == '\\') { o += '\\'; o += c; }
    else if (static_cast<unsigned char>(c) < 0x20) { char b[8]; std::snprintf(b, sizeof b, "\\u%04x", c); o += b; }
    else o += c;
  }
  return o + "\"";
}
}  // namespace

std::string selection_to_json(const Selection& s) {
  std::ostringstream o;
  o << "{\"id\":" << jstr(s.profile_id) << ",\"tier\":" << s.tier << ",\"verified\":" << (s.verified ? "true" : "false")
    << ",\"unprofiled\":" << (s.unprofiled ? "true" : "false") << ",\"score\":" << s.score
    << ",\"registry_version\":" << jstr(s.registry_version) << ",\"registry\":" << jstr(s.source)
    << ",\"firmware\":{\"version\":" << jstr(s.fw_version) << ",\"min\":" << jstr(s.fw_min) << ",\"status\":" << jstr(to_string(s.fw))
    << "},\"loss_handling\":[";
  for (std::size_t i = 0; i < s.loss_require_any.size(); ++i) o << (i ? "," : "") << jstr(s.loss_require_any[i]);
  o << "],\"operating_point\":{\"fetch_qps\":" << s.op.fetch_qps << ",\"ingest_qps\":" << s.op.ingest_qps
    << ",\"slice_bytes\":" << s.op.slice_bytes << ",\"window_bytes\":" << s.op.window_bytes
    << ",\"read_depth\":" << s.op.read_depth << ",\"inline_bytes\":" << s.op.inline_bytes
    << ",\"ack_timeout_exp\":" << unsigned(s.op.ack_timeout_exp) << ",\"retry_count\":" << unsigned(s.op.retry_count)
    << ",\"rnr_retry_count\":" << unsigned(s.op.rnr_retry_count) << ",\"mtu\":" << s.op.mtu << "},\"adjusted\":[";
  for (std::size_t i = 0; i < s.notes.size(); ++i) o << (i ? "," : "") << jstr(s.notes[i]);
  o << "]}";
  return o.str();
}

}  // namespace miracache::fabric::profile
