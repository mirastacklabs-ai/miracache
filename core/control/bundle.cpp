// SPDX-License-Identifier: Apache-2.0
#include "control/bundle.h"

#include "control/toml_guard.h"

#include <openssl/evp.h>

#include <cstring>
#include <limits>
#include <set>
#include <sstream>

#include <toml++/toml.hpp>

namespace miracache::control {

namespace {

// ---- envelope --------------------------------------------------------------------------------

BundleError fmt(const char* detail) { return BundleError{Reject::EnvelopeFormat, detail}; }

constexpr char kSigDomain[] = "mira-bundle-v1";          // sizeof includes the NUL: "…\0"
constexpr char kSecSigDomain[] = "mira-bundle-sec-v1";  // likewise

// Reads one LF-terminated line starting at `pos`; a CR anywhere in it is a reject (rule 2).
bool next_line(std::string_view b, std::size_t& pos, std::string_view& line, const char*& err) {
  const std::size_t nl = b.find('\n', pos);
  if (nl == std::string_view::npos) {
    err = "header line without LF";
    return false;
  }
  line = b.substr(pos, nl - pos);
  pos = nl + 1;
  if (line.find('\r') != std::string_view::npos) {
    err = "CR in header";
    return false;
  }
  return true;
}

// `line` must be exactly `<name>: <value>` (rule 3); returns the value.
bool header_value(std::string_view line, std::string_view name, std::string_view& value) {
  if (line.size() < name.size() + 2) return false;
  if (line.substr(0, name.size()) != name) return false;
  if (line[name.size()] != ':' || line[name.size() + 1] != ' ') return false;
  value = line.substr(name.size() + 2);
  return true;
}

bool verify_ed25519(const std::array<std::uint8_t, 32>& pub, std::string_view msg,
                    const std::array<std::uint8_t, 64>& sig) {
  EVP_PKEY* pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
  if (!pk) return false;
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  bool ok = false;
  if (ctx && EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, pk) == 1) {
    ok = EVP_DigestVerify(ctx, sig.data(), sig.size(), reinterpret_cast<const unsigned char*>(msg.data()),
                          msg.size()) == 1;
  }
  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(pk);
  return ok;
}

// ---- TOML helpers (no exceptions) --------------------------------------------------------------

BundleError schema(const char* detail) { return BundleError{Reject::Schema, detail}; }

struct Fail {
  const char* err = nullptr;
  bool operator()(const char* e) {
    if (!err) err = e;
    return false;
  }
};

template <std::size_t N>
bool only_keys(const toml::table& t, const char* const (&allowed)[N], Fail& f, const char* msg) {
  for (const auto& [k, v] : t) {
    (void)v;
    bool ok = false;
    for (const char* a : allowed) ok = ok || k.str() == a;
    if (!ok) return f(msg);
  }
  return true;
}

// Optional string field. Wrong type is an error.
bool get_str(const toml::table& t, std::string_view key, std::string& out, bool& present, Fail& f,
             const char* msg) {
  present = false;
  const toml::node* n = t.get(key);
  if (!n) return true;
  const toml::value<std::string>* s = n->as_string();
  if (!s) return f(msg);
  out = s->get();
  present = true;
  return true;
}

// Integer field in [lo, hi].
bool get_int(const toml::table& t, std::string_view key, std::int64_t lo, std::int64_t hi, std::int64_t& out,
             bool& present, Fail& f, const char* msg) {
  present = false;
  const toml::node* n = t.get(key);
  if (!n) return true;
  const toml::value<std::int64_t>* v = n->as_integer();
  if (!v || v->get() < lo || v->get() > hi) return f(msg);
  out = v->get();
  present = true;
  return true;
}

constexpr std::int64_t kU32Max = std::numeric_limits<std::uint32_t>::max();

const toml::table* sub_table(const toml::table& t, std::string_view key) {
  const toml::node* n = t.get(key);
  return n ? n->as_table() : nullptr;
}

// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's civil algorithm).
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

// "YYYY-MM-DDTHH:MM:SSZ" exactly, UTC.
bool parse_utc_time(std::string_view s, std::int64_t& out) {
  if (s.size() != 20) return false;
  const char* sep = "0000-00-00T00:00:00Z";
  int v[6];
  const int pos[6] = {0, 5, 8, 11, 14, 17};
  const int len[6] = {4, 2, 2, 2, 2, 2};
  for (int i = 0; i < 20; ++i) {
    const bool digit = sep[i] == '0';
    if (digit ? !(s[i] >= '0' && s[i] <= '9') : s[i] != sep[i]) return false;
  }
  for (int f = 0; f < 6; ++f) {
    v[f] = 0;
    for (int i = 0; i < len[f]; ++i) v[f] = v[f] * 10 + (s[pos[f] + i] - '0');
  }
  const int y = v[0], mo = v[1], d = v[2];
  if (mo < 1 || mo > 12 || d < 1 || v[3] > 23 || v[4] > 59 || v[5] > 59) return false;
  static constexpr int kDays[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  const bool leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
  if (d > kDays[mo - 1] + (mo == 2 && leap ? 1 : 0)) return false;
  out = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d)) * 86400 + v[3] * 3600 +
        v[4] * 60 + v[5];
  return true;
}

// ---- character rules (the Go parser applies the same ones) -------------------------------------

// [A-Za-z0-9._-], 1..max bytes: zone, principal name, role names, hostname.
bool name_ok(std::string_view s, std::size_t max) {
  if (s.empty() || s.size() > max) return false;
  for (const char c : s) {
    const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
    if (!ok) return false;
  }
  return true;
}

// Printable ASCII (0x21..0x7e) "host:port", port 1..65535, at most 255 bytes: admin and rail addr.
bool hostport_ok(std::string_view s) {
  if (s.empty() || s.size() > 255) return false;
  for (const char c : s) {
    if (c < 0x21 || c > 0x7e) return false;
  }
  const std::size_t colon = s.rfind(':');
  if (colon == std::string_view::npos || colon == 0 || colon + 1 >= s.size()) return false;
  const std::string_view port = s.substr(colon + 1);
  if (port.size() > 5) return false;
  unsigned p = 0;
  for (const char c : port) {
    if (c < '0' || c > '9') return false;
    p = p * 10 + static_cast<unsigned>(c - '0');
  }
  return p >= 1 && p <= 65535;
}

// CIDR text: <addr>/<prefix>; addr is hex digits, '.' and ':' only and holds a '.' or ':'; prefix
// is 1..3 digits, at most 32 for a dotted address without ':' and at most 128 otherwise.
bool cidr_ok(std::string_view s) {
  const std::size_t slash = s.find('/');
  if (slash == std::string_view::npos || slash == 0 || s.find('/', slash + 1) != std::string_view::npos) return false;
  const std::string_view addr = s.substr(0, slash);
  const std::string_view pre = s.substr(slash + 1);
  if (pre.empty() || pre.size() > 3) return false;
  bool colon = false, dot = false;
  for (const char c : addr) {
    const bool hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    if (!hex && c != '.' && c != ':') return false;
    colon = colon || c == ':';
    dot = dot || c == '.';
  }
  if (!colon && !dot) return false;
  unsigned p = 0;
  for (const char c : pre) {
    if (c < '0' || c > '9') return false;
    p = p * 10 + static_cast<unsigned>(c - '0');
  }
  return p <= (colon ? 128u : 32u);
}

bool string_array(const toml::node* n, std::vector<std::string>& out, bool allow_empty) {
  const toml::array* a = n ? n->as_array() : nullptr;
  if (!a || (!allow_empty && a->empty())) return false;
  for (const toml::node& el : *a) {
    const toml::value<std::string>* s = el.as_string();
    if (!s || s->get().empty()) return false;
    out.push_back(s->get());
  }
  return true;
}

// ---- config.* (opaque; known keys counted against) --------------------------------------------

bool parse_config(const toml::table& cfg, BodyView& out, Fail& f) {
  for (const auto& [k, v] : cfg) {
    if (k.str() == "cluster") {
      const toml::table* cl = v.as_table();
      if (!cl) return f("config.cluster must be a table");
      for (const auto& [ck, cv] : *cl) {
        if (ck.str() == "placement") {
          const toml::table* pl = cv.as_table();
          if (!pl) return f("config.cluster.placement must be a table");
          for (const auto& [pk, pv] : *pl) {
            (void)pv;
            if (pk.str() != "replicas") ++out.unknown_keys;
          }
          std::int64_t r = 0;
          bool present = false;
          if (!get_int(*pl, "replicas", 1, kU32Max, r, present, f, "config.cluster.placement.replicas must be an integer >= 1")) {
            return false;
          }
          if (present) {
            out.replicas_present = true;
            out.replicas = static_cast<std::uint32_t>(r);
          }
        } else if (ck.str() == "memnode" || ck.str() == "client") {
          if (!cv.as_table()) return f("config.cluster.memnode/client must be a table");
        } else {
          ++out.unknown_keys;
        }
      }
    } else if (k.str() == "node") {
      const toml::table* nodes = v.as_table();
      if (!nodes) return f("config.node must be a table");
      for (const auto& [nk, nv] : *nodes) {
        (void)nk;
        const toml::table* nt = nv.as_table();
        if (!nt) return f("config.node.<admin> must be a table");
        for (const auto& [ok, ov] : *nt) {
          if (ok.str() == "memnode" || ok.str() == "client") {
            if (!ov.as_table()) return f("config.node.<admin>.memnode/client must be a table");
          } else {
            ++out.unknown_keys;
          }
        }
      }
    } else {
      ++out.unknown_keys;
    }
  }
  std::ostringstream os;
  os << toml::toml_formatter{cfg};
  out.config_toml = os.str();
  return true;
}

bool parse_zone(const toml::table& t, std::optional<std::string>& zone, Fail& f) {
  std::string z;
  bool present = false;
  if (!get_str(t, "zone", z, present, f, "zone must be a string")) return false;
  if (present) {
    if (z.empty()) return f("zone must not be empty");
    if (!name_ok(z, 64)) return f("zone has invalid characters or is too long");
    zone = std::move(z);
  }
  return true;
}

bool parse_membership(const toml::table& m, BodyView& out, Fail& f) {
  static constexpr const char* kKeys[] = {"epoch", "previous_epoch", "nodes", "previous"};
  if (!only_keys(m, kKeys, f, "unknown key in [membership]")) return false;
  std::int64_t v = 0;
  bool present = false;
  if (!get_int(m, "epoch", 1, kU32Max, v, present, f, "membership.epoch must be an integer in 1..2^32-1")) return false;
  if (!present) return f("membership.epoch is required");
  out.epoch = static_cast<std::uint32_t>(v);
  if (!get_int(m, "previous_epoch", 0, kU32Max, v, present, f, "membership.previous_epoch must be an integer in 0..2^32-1")) {
    return false;
  }
  if (present) out.previous_epoch = static_cast<std::uint32_t>(v);
  if (out.previous_epoch >= out.epoch) return f("membership.previous_epoch must be below epoch");

  const toml::node* nn = m.get("nodes");
  const toml::array* nodes = nn ? nn->as_array() : nullptr;
  if (!nodes || !nodes->is_homogeneous(toml::node_type::table)) return f("membership.nodes must be an array of tables");
  std::set<std::uint32_t> ids;
  std::set<std::string> admins;
  std::size_t with_zone = 0;
  for (const toml::node& el : *nodes) {
    const toml::table& t = *el.as_table();
    static constexpr const char* kNodeKeys[] = {"node_id", "hostname", "admin", "rails", "weight", "zone", "state"};
    if (!only_keys(t, kNodeKeys, f, "unknown key in [[membership.nodes]]")) return false;
    NodeView nv;
    if (!get_int(t, "node_id", 1, kU32Max, v, present, f, "node_id must be an integer in 1..2^32-1")) return false;
    if (!present) return f("node_id is required");
    nv.node_id = static_cast<std::uint32_t>(v);
    if (!ids.insert(nv.node_id).second) return f("duplicate node_id");
    bool sp = false;
    if (!get_str(t, "hostname", nv.hostname, sp, f, "hostname must be a string") || !sp || nv.hostname.empty()) {
      return f("hostname is required");
    }
    if (!name_ok(nv.hostname, 253)) return f("hostname has invalid characters or is too long");
    if (!get_str(t, "admin", nv.admin, sp, f, "admin must be a string") || !sp || nv.admin.empty()) {
      return f("admin is required");
    }
    if (!hostport_ok(nv.admin)) return f("admin must be printable ASCII host:port, at most 255 bytes");
    if (!admins.insert(nv.admin).second) return f("duplicate admin address");
    if (!get_int(t, "weight", 1, kU32Max, v, present, f, "weight must be an integer in 1..2^32-1")) return false;
    if (!present) return f("weight is required");
    nv.weight = static_cast<std::uint32_t>(v);
    if (!parse_zone(t, nv.zone, f)) return false;
    if (nv.zone) ++with_zone;
    std::string st;
    if (!get_str(t, "state", st, sp, f, "state must be a string") || !sp) return f("state is required");
    if (st == "active") nv.state = MemberState::Active;
    else if (st == "draining") nv.state = MemberState::Draining;
    else if (st == "readonly") nv.state = MemberState::Readonly;
    else return f("state must be active, draining or readonly");
    const toml::node* rn = t.get("rails");
    const toml::array* rails = rn ? rn->as_array() : nullptr;
    if (!rails || rails->size() < 1 || rails->size() > 4 || !rails->is_homogeneous(toml::node_type::table)) {
      return f("rails must be 1..4 tables");
    }
    for (const toml::node& rel : *rails) {
      const toml::table& rt = *rel.as_table();
      static constexpr const char* kRailKeys[] = {"addr", "subnet", "protocol"};
      if (!only_keys(rt, kRailKeys, f, "unknown key in a rail")) return false;
      RailView rv;
      if (!get_str(rt, "addr", rv.addr, sp, f, "rail addr must be a string") || !sp || rv.addr.empty()) return f("rail addr is required");
      if (!get_str(rt, "subnet", rv.subnet, sp, f, "rail subnet must be a string") || !sp || rv.subnet.empty()) return f("rail subnet is required");
      if (!get_str(rt, "protocol", rv.protocol, sp, f, "rail protocol must be a string") || !sp || rv.protocol.empty()) return f("rail protocol is required");
      if (!hostport_ok(rv.addr)) return f("rail addr must be printable ASCII host:port, at most 255 bytes");
      if (!cidr_ok(rv.subnet)) return f("rail subnet must be CIDR text");
      if (rv.protocol != "roce" && rv.protocol != "iwarp") return f("rail protocol must be roce or iwarp");
      nv.rails.push_back(std::move(rv));
    }
    out.nodes.push_back(std::move(nv));
  }
  if (with_zone != 0 && with_zone != out.nodes.size()) return f("zone must be set on all nodes or none");

  if (const toml::node* pn = m.get("previous")) {
    const toml::array* prev = pn->as_array();
    if (!prev || !prev->is_homogeneous(toml::node_type::table)) return f("membership.previous must be an array of tables");
    std::set<std::uint32_t> pids;
    std::size_t pzone = 0;
    for (const toml::node& el : *prev) {
      const toml::table& t = *el.as_table();
      static constexpr const char* kPrevKeys[] = {"node_id", "weight", "zone"};
      if (!only_keys(t, kPrevKeys, f, "unknown key in [[membership.previous]]")) return false;
      PreviousNodeView pv;
      if (!get_int(t, "node_id", 1, kU32Max, v, present, f, "previous node_id must be an integer in 1..2^32-1")) return false;
      if (!present) return f("previous node_id is required");
      pv.node_id = static_cast<std::uint32_t>(v);
      if (!pids.insert(pv.node_id).second) return f("duplicate previous node_id");
      if (!get_int(t, "weight", 1, kU32Max, v, present, f, "previous weight must be an integer in 1..2^32-1")) return false;
      if (!present) return f("previous weight is required");
      pv.weight = static_cast<std::uint32_t>(v);
      if (!parse_zone(t, pv.zone, f)) return false;
      if (pv.zone) ++pzone;
      out.previous.push_back(std::move(pv));
    }
    if (pzone != 0 && pzone != out.previous.size()) return f("previous zone must be set on all entries or none");
  }
  return true;
}

}  // namespace

// ---- envelope --------------------------------------------------------------------------------

Expected<Envelope, BundleError> parse_envelope(std::string_view b) {
  if (b.size() > kMaxEnvelopeBytes) return fmt("envelope larger than 1 MiB");
  Envelope env;
  std::size_t pos = 0;
  std::string_view line;
  const char* err = nullptr;
  if (!next_line(b, pos, line, err)) return fmt(err);
  if (line != "mira-bundle-v1") return fmt("bad magic line");

  std::string_view value;
  if (!next_line(b, pos, line, err)) return fmt(err);
  if (!header_value(line, "key_id", value) || !from_hex_lower(value, env.key_id)) return fmt("bad key_id line");
  if (!next_line(b, pos, line, err)) return fmt(err);
  if (!header_value(line, "sig", value) || !from_hex_lower(value, env.sig)) return fmt("bad sig line");
  if (!next_line(b, pos, line, err)) return fmt(err);
  if (!header_value(line, "sec_key_id", value) || !from_hex_lower(value, env.sec_key_id)) return fmt("bad sec_key_id line");
  if (!next_line(b, pos, line, err)) return fmt(err);
  if (!header_value(line, "sec_sig", value) || !from_hex_lower(value, env.sec_sig)) return fmt("bad sec_sig line");
  if (!next_line(b, pos, line, err)) return fmt(err);
  if (!header_value(line, "sec_len", value)) return fmt("bad sec_len line");
  // Rule 5: ASCII digits only, no sign, no leading zero (so 0 is invalid too), at most 7 digits.
  if (value.empty() || value.size() > 7 || value[0] < '1' || value[0] > '9') return fmt("bad sec_len value");
  std::size_t sec_len = 0;
  for (const char c : value) {
    if (c < '0' || c > '9') return fmt("bad sec_len value");
    sec_len = sec_len * 10 + static_cast<std::size_t>(c - '0');
  }
  if (!next_line(b, pos, line, err)) return fmt(err);
  if (!line.empty()) return fmt("header not closed by an empty line");
  if (sec_len > b.size() - pos) return fmt("sec_len exceeds the bytes after the header");
  env.sec = b.substr(pos, sec_len);
  env.body = b.substr(pos + sec_len);
  return env;
}

Expected<void, BundleError> verify_envelope(const Envelope& env, const TrustKeys& trust) {
  const TrustKey* pub = trust.find(env.key_id);
  const TrustKey* sec = trust.find(env.sec_key_id);
  if (!pub || !sec) return BundleError{Reject::UnknownKey, "key_id or sec_key_id is not a trust key"};
  if (!pub->publish) return BundleError{Reject::KeyRole, "key_id does not hold the publish role"};
  if (!sec->security) return BundleError{Reject::KeyRole, "sec_key_id does not hold the security role"};

  // Rule 6: u32be(len(sec)) in the signed message is the same value as sec_len.
  const std::uint32_t n = static_cast<std::uint32_t>(env.sec.size());
  std::string msg(kSigDomain, sizeof(kSigDomain));
  msg.push_back(static_cast<char>(n >> 24));
  msg.push_back(static_cast<char>(n >> 16));
  msg.push_back(static_cast<char>(n >> 8));
  msg.push_back(static_cast<char>(n));
  msg.append(env.sec);
  msg.append(env.body);
  if (!verify_ed25519(pub->public_key, msg, env.sig)) {
    return BundleError{Reject::BadSignature, "publish signature does not verify"};
  }
  std::string smsg(kSecSigDomain, sizeof(kSecSigDomain));
  smsg.append(env.sec);
  if (!verify_ed25519(sec->public_key, smsg, env.sec_sig)) {
    return BundleError{Reject::BadSecSignature, "security signature does not verify"};
  }
  return {};
}

// ---- TOML into views -------------------------------------------------------------------------

std::uint32_t principal_id(std::string_view name) {
  std::string in("mira-principal-v1");
  in.append(name);
  const Sha256Digest d = sha256(in);
  const std::uint32_t id = (static_cast<std::uint32_t>(d[0]) << 24) | (static_cast<std::uint32_t>(d[1]) << 16) |
                           (static_cast<std::uint32_t>(d[2]) << 8) | static_cast<std::uint32_t>(d[3]);
  return id == 0 ? 1 : id;
}

Expected<SecView, BundleError> parse_sec(std::string_view text) {
  if (text.starts_with("\xEF\xBB\xBF")) return schema("sec starts with a UTF-8 BOM");
  if (!toml_text_ok(text)) return schema("sec has non-ASCII bytes outside strings");
  toml::parse_result parsed = toml::parse(text);
  if (!parsed) return schema("sec is not valid TOML");
  const toml::table& root = parsed.table();
  Fail f;
  static constexpr const char* kKeys[] = {"sec_generation", "principals", "rbac"};
  if (!only_keys(root, kKeys, f, "unknown key in sec")) return schema(f.err);
  SecView out;
  std::int64_t v = 0;
  bool present = false;
  if (!get_int(root, "sec_generation", 1, kMaxGeneration, v, present, f, "sec_generation must be an integer in 1..2^63-1") ||
      !present) {
    return schema(f.err ? f.err : "sec_generation is required");
  }
  out.sec_generation = static_cast<std::uint64_t>(v);

  if (const toml::node* pn = root.get("principals")) {
    const toml::array* arr = pn->as_array();
    if (!arr || !arr->is_homogeneous(toml::node_type::table)) return schema("principals must be an array of tables");
    std::set<std::string> names;
    std::set<std::uint32_t> ids;
    std::set<std::string> identities;
    for (const toml::node& el : *arr) {
      const toml::table& t = *el.as_table();
      if (t.contains("id")) return schema("principal id is computed from the name; a typed `id` is an error");
      static constexpr const char* kPKeys[] = {"name", "identities", "quota_bytes", "max_scopes", "drop_before"};
      if (!only_keys(t, kPKeys, f, "unknown key in [[principals]]")) return schema(f.err);
      PrincipalView p;
      bool sp = false;
      if (!get_str(t, "name", p.name, sp, f, "principal name must be a string") || !sp || p.name.empty()) {
        return schema(f.err ? f.err : "principal name is required");
      }
      if (!name_ok(p.name, 64)) return schema("principal name has invalid characters or is too long");
      if (!names.insert(p.name).second) return schema("duplicate principal name");
      if (!string_array(t.get("identities"), p.identities, false)) return schema("principal identities must be a non-empty array of strings");
      if (!get_int(t, "quota_bytes", 0, INT64_MAX, v, present, f, "quota_bytes must be an integer >= 0") || !present) {
        return schema(f.err ? f.err : "quota_bytes is required");
      }
      p.quota_bytes = static_cast<std::uint64_t>(v);
      if (!get_int(t, "max_scopes", 0, INT64_MAX, v, present, f, "max_scopes must be an integer >= 0") || !present) {
        return schema(f.err ? f.err : "max_scopes is required");
      }
      p.max_scopes = static_cast<std::uint64_t>(v);
      std::string db;
      if (!get_str(t, "drop_before", db, sp, f, "drop_before must be a string")) return schema(f.err);
      if (sp) {
        std::int64_t secs = 0;
        if (!parse_utc_time(db, secs)) return schema("drop_before must be YYYY-MM-DDTHH:MM:SSZ");
        p.drop_before = secs;
      }
      // One identity maps to exactly one principal, once.
      for (const std::string& ident : p.identities) {
        if (ident.empty()) return schema("principal identity must not be empty");
        if (!identities.insert(ident).second) return schema("identity bound to two principals (or twice in one)");
      }
      p.id = principal_id(p.name);
      if (!ids.insert(p.id).second) return schema("principal id collision between two names");
      out.principals.push_back(std::move(p));
    }
  }
  if (const toml::node* rn = root.get("rbac")) {
    const toml::array* arr = rn->as_array();
    if (!arr || !arr->is_homogeneous(toml::node_type::table)) return schema("rbac must be an array of tables");
    std::set<std::string> rbac_identities;
    for (const toml::node& el : *arr) {
      const toml::table& t = *el.as_table();
      static constexpr const char* kRKeys[] = {"identity", "roles"};
      if (!only_keys(t, kRKeys, f, "unknown key in [[rbac]]")) return schema(f.err);
      RbacView r;
      bool sp = false;
      if (!get_str(t, "identity", r.identity, sp, f, "rbac identity must be a string") || !sp || r.identity.empty()) {
        return schema(f.err ? f.err : "rbac identity is required");
      }
      if (!rbac_identities.insert(r.identity).second) return schema("duplicate rbac identity");
      if (!string_array(t.get("roles"), r.roles, false)) return schema("rbac roles must be a non-empty array of strings");
      for (const std::string& role : r.roles) {
        if (!name_ok(role, 64)) return schema("role name has invalid characters or is too long");
      }
      out.rbac.push_back(std::move(r));
    }
  }
  return out;
}

Expected<BodyView, BundleError> parse_body(std::string_view text) {
  if (text.starts_with("\xEF\xBB\xBF")) return schema("body starts with a UTF-8 BOM");
  if (!toml_text_ok(text)) return schema("body has non-ASCII bytes outside strings");
  toml::parse_result parsed = toml::parse(text);
  if (!parsed) return schema("body is not valid TOML");
  const toml::table& root = parsed.table();
  Fail f;
  BodyView out;
  std::int64_t v = 0;
  bool present = false;
  if (!get_int(root, "schema_version", 1, 1, v, present, f, "schema_version must be 1") || !present) {
    return schema(f.err ? f.err : "schema_version is required");
  }
  out.schema_version = 1;
  if (!get_int(root, "generation", 1, kMaxGeneration, v, present, f, "generation must be an integer in 1..2^63-1") || !present) {
    return schema(f.err ? f.err : "generation is required");
  }
  out.generation = static_cast<std::uint64_t>(v);
  bool sp = false;
  if (!get_str(root, "created_at", out.created_at, sp, f, "created_at must be a string") ||
      !get_str(root, "author", out.author, sp, f, "author must be a string") ||
      !get_str(root, "reason", out.reason, sp, f, "reason must be a string")) {
    return schema(f.err);
  }
  for (const auto& [k, val] : root) {
    (void)val;
    const std::string_view key = k.str();
    if (key != "schema_version" && key != "generation" && key != "created_at" && key != "author" &&
        key != "reason" && key != "membership" && key != "config") {
      return schema("unknown top-level key in body");
    }
  }
  const toml::table* m = sub_table(root, "membership");
  if (!m) return schema("[membership] is required");
  if (!parse_membership(*m, out, f)) return schema(f.err);
  if (root.contains("config")) {
    const toml::table* cfg = sub_table(root, "config");
    if (!cfg) return schema("config must be a table");
    if (!parse_config(*cfg, out, f)) return schema(f.err);
  }
  return out;
}

Expected<BundleView, BundleError> parse_bundle(const Envelope& env) {
  auto sec = parse_sec(env.sec);
  if (!sec) return sec.error();
  auto body = parse_body(env.body);
  if (!body) return body.error();
  BundleView v;
  v.sec = std::move(sec.value());
  v.body = std::move(body.value());
  v.key_id = env.key_id;
  v.sec_key_id = env.sec_key_id;
  v.body_hash = sha256(env.body);
  v.sec_hash = sha256(env.sec);
  return v;
}

Expected<BundleView, BundleError> open_bundle(std::string_view bytes, const TrustKeys& trust) {
  auto env = parse_envelope(bytes);
  if (!env) return env.error();
  auto ok = verify_envelope(env.value(), trust);
  if (!ok) return ok.error();
  return parse_bundle(env.value());
}


std::optional<BundleError> check_drop_before_not_future(const BundleView& v, std::int64_t now_unix_s,
                                                        const std::map<std::string, std::int64_t>* stored_max) {
  for (const auto& p : v.sec.principals) {
    if (p.drop_before && *p.drop_before > now_unix_s + kDropBeforeSkewSeconds) {
      if (stored_max) {
        auto it = stored_max->find(p.name);
        if (it != stored_max->end() && *p.drop_before <= it->second) continue;  // already stored, not a new value
      }
      return BundleError{Reject::Schema, "a principal drop_before is later than now + 300 s"};
    }
  }
  return std::nullopt;
}

}  // namespace miracache::control
