// SPDX-License-Identifier: Apache-2.0
#include "control/audit.h"

#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <fstream>
#include <iterator>
#include <set>

#include "control/sha256.h"
#include "util/clock.h"

namespace miracache::control {

namespace {

Error io(const char* ctx) { return Error{ErrorCode::Aborted, ctx}; }
Error corrupt(const char* ctx) { return Error{ErrorCode::Corrupt, ctx}; }

// ---- encoding ---------------------------------------------------------------------------

// Go's utf8.DecodeRune: returns the width (1 for any invalid byte, cp = 0xFFFD).
int decode_utf8(std::string_view s, std::size_t i, std::uint32_t& cp) {
  const auto b0 = static_cast<std::uint8_t>(s[i]);
  const std::size_t n = s.size() - i;
  auto cont = [&](std::size_t k) { return (static_cast<std::uint8_t>(s[i + k]) & 0xC0) == 0x80; };
  cp = 0xFFFD;
  if (b0 < 0x80) {
    cp = b0;
    return 1;
  }
  if (b0 >= 0xC2 && b0 <= 0xDF && n >= 2 && cont(1)) {
    cp = ((b0 & 0x1Fu) << 6) | (static_cast<std::uint8_t>(s[i + 1]) & 0x3Fu);
    return 2;
  }
  if (b0 >= 0xE0 && b0 <= 0xEF && n >= 3 && cont(1) && cont(2)) {
    const auto b1 = static_cast<std::uint8_t>(s[i + 1]);
    if ((b0 == 0xE0 && b1 < 0xA0) || (b0 == 0xED && b1 > 0x9F)) return 1;  // overlong / surrogate
    cp = ((b0 & 0x0Fu) << 12) | ((b1 & 0x3Fu) << 6) | (static_cast<std::uint8_t>(s[i + 2]) & 0x3Fu);
    return 3;
  }
  if (b0 >= 0xF0 && b0 <= 0xF4 && n >= 4 && cont(1) && cont(2) && cont(3)) {
    const auto b1 = static_cast<std::uint8_t>(s[i + 1]);
    if ((b0 == 0xF0 && b1 < 0x90) || (b0 == 0xF4 && b1 > 0x8F)) return 1;
    cp = ((b0 & 0x07u) << 18) | ((b1 & 0x3Fu) << 12) | ((static_cast<std::uint8_t>(s[i + 2]) & 0x3Fu) << 6) |
         (static_cast<std::uint8_t>(s[i + 3]) & 0x3Fu);
    return 4;
  }
  return 1;
}

void put_u_escape(std::uint32_t v, std::string& out) {
  static const char* d = "0123456789abcdef";
  out += "\\u";
  out += d[(v >> 12) & 0xF];
  out += d[(v >> 8) & 0xF];
  out += d[(v >> 4) & 0xF];
  out += d[v & 0xF];
}

void put_str(std::string_view s, std::string& out) {
  out += '"';
  audit_escape_json(s, out);
  out += '"';
}

std::string src_json(const AuditSource& s) {
  std::string o;
  if (s.controller) {
    o += "{\"controller\":";
    put_str(s.host, o);
  } else {
    o += "{\"node_id\":" + std::to_string(s.node_id) + ",\"host\":";
    put_str(s.host, o);
  }
  o += ",\"addr\":";
  put_str(s.addr, o);
  o += '}';
  return o;
}

// The entry without `hash`, ending in `}`.
std::string build_body(const AuditSource& src, std::uint64_t seq, std::uint64_t ts_ms, const AuditEntry& e,
                       std::string_view prev) {
  std::string o;
  o.reserve(256);
  o += "{\"v\":1,\"seq\":" + std::to_string(seq) + ",\"ts\":\"" + audit_format_ts(ts_ms) + "\",\"src\":" + src_json(src);
  o += ",\"actor\":";
  put_str(e.actor, o);
  o += ",\"role\":";
  put_str(e.role, o);
  o += ",\"action\":";
  put_str(e.action, o);
  o += ",\"target\":";
  put_str(e.target, o);
  o += ",\"result\":";
  put_str(e.result, o);
  o += ",\"reason\":";
  put_str(e.reason, o);
  o += ",\"count\":" + std::to_string(e.count == 0 ? 1 : e.count);
  if (e.generation) o += ",\"generation\":" + std::to_string(*e.generation);
  o += ",\"detail\":{";
  bool first = true;
  for (const auto& [k, v] : e.detail) {
    if (!first) o += ',';
    first = false;
    put_str(k, o);
    o += ':';
    if (const auto* s = std::get_if<std::string>(&v)) put_str(*s, o);
    else o += std::to_string(std::get<std::uint64_t>(v));
  }
  o += "},\"prev\":\"";
  o.append(prev);
  o += "\"}";
  return o;
}

// body (ending `}`) -> stored line without the newline; hash_hex receives the hash.
std::string seal(const std::string& body, std::string& hash_hex) {
  const auto d = sha256(body);
  hash_hex = to_hex(d);
  std::string line(body, 0, body.size() - 1);
  line += ",\"hash\":\"";
  line += hash_hex;
  line += "\"}";
  return line;
}

// ---- parsing (verifier) ---------------------------------------------------------------------

struct Cursor {
  std::string_view s;
  std::size_t i = 0;
};

bool is_hex(char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'); }

// At s[i] == '"'. On success i is past the closing quote; `inner` is the raw text between them.
bool parse_string(Cursor& c, std::string_view& inner) {
  if (c.i >= c.s.size() || c.s[c.i] != '"') return false;
  const std::size_t start = ++c.i;
  while (c.i < c.s.size()) {
    const auto ch = static_cast<unsigned char>(c.s[c.i]);
    if (ch == '"') {
      inner = c.s.substr(start, c.i - start);
      ++c.i;
      return true;
    }
    if (ch < 0x20) return false;
    if (ch == '\\') {
      if (c.i + 1 >= c.s.size()) return false;
      const char e = c.s[c.i + 1];
      if (e == 'u') {
        if (c.i + 6 > c.s.size()) return false;
        for (int k = 2; k < 6; ++k)
          if (!is_hex(c.s[c.i + k])) return false;
        c.i += 6;
        continue;
      }
      if (std::strchr("\"\\/bfnrt", e) == nullptr || e == '\0') return false;
      c.i += 2;
      continue;
    }
    ++c.i;
  }
  return false;
}

bool parse_value(Cursor& c, std::string_view& raw, int depth);

bool parse_number(Cursor& c) {
  std::size_t i = c.i;
  const auto& s = c.s;
  auto digit = [&](std::size_t k) { return k < s.size() && s[k] >= '0' && s[k] <= '9'; };
  if (i < s.size() && s[i] == '-') ++i;
  if (!digit(i)) return false;
  if (s[i] == '0') ++i;
  else while (digit(i)) ++i;
  if (i < s.size() && s[i] == '.') {
    ++i;
    if (!digit(i)) return false;
    while (digit(i)) ++i;
  }
  if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) {
    ++i;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i;
    if (!digit(i)) return false;
    while (digit(i)) ++i;
  }
  c.i = i;
  return true;
}

using Members = std::vector<std::pair<std::string_view, std::string_view>>;  // key (raw), raw value

// Compact JSON object at c.i; members' raw values are spans of the input.
bool parse_object(Cursor& c, Members* out, int depth) {
  if (depth > 16 || c.i >= c.s.size() || c.s[c.i] != '{') return false;
  ++c.i;
  if (c.i < c.s.size() && c.s[c.i] == '}') {
    ++c.i;
    return true;
  }
  for (;;) {
    std::string_view key;
    if (!parse_string(c, key)) return false;
    if (c.i >= c.s.size() || c.s[c.i] != ':') return false;
    ++c.i;
    std::string_view raw;
    if (!parse_value(c, raw, depth + 1)) return false;
    if (out) out->emplace_back(key, raw);
    if (c.i >= c.s.size()) return false;
    if (c.s[c.i] == ',') {
      ++c.i;
      continue;
    }
    if (c.s[c.i] == '}') {
      ++c.i;
      return true;
    }
    return false;
  }
}

bool parse_value(Cursor& c, std::string_view& raw, int depth) {
  if (depth > 16 || c.i >= c.s.size()) return false;
  const std::size_t start = c.i;
  const char ch = c.s[c.i];
  bool ok = false;
  if (ch == '"') {
    std::string_view in;
    ok = parse_string(c, in);
  } else if (ch == '{') {
    ok = parse_object(c, nullptr, depth);
  } else if (ch == '[') {
    ++c.i;
    if (c.i < c.s.size() && c.s[c.i] == ']') {
      ++c.i;
      ok = true;
    } else {
      for (;;) {
        std::string_view r;
        if (!parse_value(c, r, depth + 1) || c.i >= c.s.size()) break;
        if (c.s[c.i] == ',') {
          ++c.i;
          continue;
        }
        if (c.s[c.i] == ']') {
          ++c.i;
          ok = true;
        }
        break;
      }
    }
  } else if (c.s.substr(c.i, 4) == "true" || c.s.substr(c.i, 4) == "null") {
    c.i += 4;
    ok = true;
  } else if (c.s.substr(c.i, 5) == "false") {
    c.i += 5;
    ok = true;
  } else {
    ok = parse_number(c);
  }
  if (ok) raw = c.s.substr(start, c.i - start);
  return ok;
}

bool parse_u64(std::string_view s, std::uint64_t& v) {
  if (s.empty() || s.size() > 20) return false;
  std::uint64_t r = 0;
  for (char ch : s) {
    if (ch < '0' || ch > '9') return false;
    const std::uint64_t d = static_cast<std::uint64_t>(ch - '0');
    if (r > (UINT64_MAX - d) / 10) return false;
    r = r * 10 + d;
  }
  if (s.size() > 1 && s[0] == '0') return false;
  v = r;
  return true;
}

bool is_hash64(std::string_view s) {
  if (s.size() != 64) return false;
  return std::all_of(s.begin(), s.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

struct Checked {
  std::uint64_t seq = 0;
  std::string prev;
  std::string hash;
  std::string action;  // raw (escapes not decoded); the audit.* names contain none
  std::optional<std::uint64_t> first_kept_seq;
};

// Validates one stored line (no newline). Returns an empty string on success.
std::string check_line(std::string_view line, Checked& out) {
  if (line.size() < kAuditHashSuffixBytes + 2) return "line too short";
  const std::string_view suffix = line.substr(line.size() - kAuditHashSuffixBytes);
  if (suffix.substr(0, 9) != ",\"hash\":\"" || suffix.substr(73) != "\"}") return "bad hash suffix";
  const std::string_view hash = suffix.substr(9, 64);
  if (!is_hash64(hash)) return "bad hash suffix";
  std::string body(line.substr(0, line.size() - kAuditHashSuffixBytes));
  body += '}';
  if (to_hex(sha256(body)) != hash) return "hash mismatch";
  out.hash = std::string(hash);

  Cursor c{body, 0};
  Members m;
  if (!parse_object(c, &m, 0) || c.i != body.size()) return "malformed JSON";
  static const char* const kHead[] = {"v", "seq", "ts", "src", "actor", "role", "action", "target", "result", "reason", "count"};
  std::size_t k = 0;
  for (const char* want : kHead) {
    if (k >= m.size() || m[k].first != want) return std::string("field order: expected ") + want;
    ++k;
  }
  if (k < m.size() && m[k].first == "generation") ++k;
  if (k + 2 != m.size() || m[k].first != "detail" || m[k + 1].first != "prev") return "field order: expected detail, prev";
  std::uint64_t v = 0, cnt = 0;
  if (!parse_u64(m[0].second, v) || v != 1) return "unsupported version";
  if (!parse_u64(m[1].second, out.seq) || out.seq == 0) return "bad seq";
  if (!parse_u64(m[10].second, cnt) || cnt == 0) return "bad count";
  // Type checks: every string field is a JSON string, src is an object of the expected shape.
  auto is_str = [](std::string_view r) { return r.size() >= 2 && r.front() == '"' && r.back() == '"'; };
  for (std::size_t idx : {2u, 4u, 5u, 6u, 7u, 8u, 9u}) {
    if (!is_str(m[idx].second)) return "field " + std::string(m[idx].first) + " is not a string";
  }
  {
    Cursor sc{m[3].second, 0};
    Members sm;
    if (m[3].second.empty() || m[3].second[0] != '{' || !parse_object(sc, &sm, 0)) return "src is not an object";
    bool ok = false;
    if (sm.size() == 3 && sm[0].first == "node_id" && sm[1].first == "host" && sm[2].first == "addr") {
      std::uint64_t nid = 0;
      ok = parse_u64(sm[0].second, nid) && is_str(sm[1].second) && is_str(sm[2].second);
    } else if (sm.size() == 2 && sm[0].first == "controller" && sm[1].first == "addr") {
      ok = is_str(sm[0].second) && is_str(sm[1].second);
    }
    if (!ok) return "bad src";
  }
  if (m[k - 1].first == "generation") {
    std::uint64_t g = 0;
    if (!parse_u64(m[k - 1].second, g)) return "bad generation";
  }
  if (m[k].second.empty() || m[k].second[0] != '{') return "detail is not an object";
  const std::string_view prev = m.back().second;
  if (prev.size() != 66 || prev.front() != '"' || prev.back() != '"' || !is_hash64(prev.substr(1, 64))) return "bad prev";
  out.prev = std::string(prev.substr(1, 64));
  if (m[6].second.size() < 2) return "bad action";
  out.action = std::string(m[6].second.substr(1, m[6].second.size() - 2));
  out.first_kept_seq.reset();
  if (out.action == "audit.truncate") {
    Cursor dc{m[k].second, 0};
    Members dm;
    if (!parse_object(dc, &dm, 0)) return "bad detail";
    for (const auto& [dk, dv] : dm) {
      if (dk == "first_kept_seq") {
        std::uint64_t f = 0;
        if (!parse_u64(dv, f) || f == 0) return "bad first_kept_seq";
        out.first_kept_seq = f;
      }
    }
    if (!out.first_kept_seq) return "audit.truncate without first_kept_seq";
  }
  return "";
}

bool parse_audit_name(std::string_view base, std::uint64_t& first_seq) {
  if (base.size() < 12 || base.substr(0, 6) != "audit-" || base.substr(base.size() - 6) != ".jsonl") return false;
  return parse_u64(base.substr(6, base.size() - 12), first_seq) && first_seq > 0;
}

std::string basename_of(const std::string& p) {
  const auto pos = p.find_last_of('/');
  return pos == std::string::npos ? p : p.substr(pos + 1);
}

std::string file_name_for(std::uint64_t first_seq) { return "audit-" + std::to_string(first_seq) + ".jsonl"; }

void fsync_dir(const std::string& dir) {
  const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd >= 0) {
    ::fsync(fd);
    ::close(fd);
  }
}

}  // namespace

// ---- public encoding helpers ---------------------------------------------------------------

void audit_escape_json(std::string_view s, std::string& out) {
  std::size_t i = 0;
  while (i < s.size()) {
    const auto b = static_cast<unsigned char>(s[i]);
    if (b < 0x80) {
      switch (b) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        default:
          if (b < 0x20) put_u_escape(b, out);
          else out += static_cast<char>(b);
      }
      ++i;
      continue;
    }
    std::uint32_t cp = 0;
    const int w = decode_utf8(s, i, cp);
    if (w == 1) {
      put_u_escape(0xFFFD, out);  // invalid byte
    } else if (cp == 0x2028 || cp == 0x2029) {
      put_u_escape(cp, out);
    } else {
      out.append(s.substr(i, static_cast<std::size_t>(w)));
    }
    i += static_cast<std::size_t>(w);
  }
}

std::string audit_format_ts(std::uint64_t unix_ms) {
  const std::int64_t secs = static_cast<std::int64_t>(unix_ms / 1000);
  const unsigned ms = static_cast<unsigned>(unix_ms % 1000);
  std::int64_t days = secs / 86400;
  const std::int64_t rem = secs % 86400;
  // Howard Hinnant's civil_from_days.
  days += 719468;
  const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(days - era * 146097);
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;
  const unsigned d = doy - (153 * mp + 2) / 5 + 1;
  const unsigned m = mp < 10 ? mp + 3 : mp - 9;
  if (m <= 2) ++y;
  char buf[40];
  std::snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02u:%02u:%02u.%03uZ", static_cast<long long>(y), m, d,
                static_cast<unsigned>(rem / 3600), static_cast<unsigned>((rem % 3600) / 60),
                static_cast<unsigned>(rem % 60), ms);
  return buf;
}

// ---- files ---------------------------------------------------------------------------------

std::vector<std::string> list_audit_files(const std::string& dir) {
  std::vector<std::pair<std::uint64_t, std::string>> v;
  DIR* d = ::opendir(dir.c_str());
  if (!d) return {};
  while (const dirent* e = ::readdir(d)) {
    std::uint64_t first = 0;
    if (parse_audit_name(e->d_name, first)) v.emplace_back(first, dir + "/" + e->d_name);
  }
  ::closedir(d);
  std::sort(v.begin(), v.end());
  std::vector<std::string> out;
  for (auto& p : v) out.push_back(std::move(p.second));
  return out;
}

// ---- writer --------------------------------------------------------------------------------

namespace {
constexpr std::uint64_t kMaxRecoverBytes = 512ull << 20;
}

struct AuditLog::Impl {
  AuditConfig cfg;
  std::uint64_t max_bytes = 0;
  std::uint64_t max_total = 0;
  int fd = -1;
  int lock_fd = -1;             // flock on the directory: one writer
  std::uint64_t cur_first = 0;  // first seq of the current file
  std::uint64_t cur_size = 0;
  std::uint64_t seq = 0;
  std::string head = kAuditGenesisPrev;
  std::uint64_t recovered = 0;
  std::uint64_t last_sync_ms = 0;
  bool dirty = false;
  bool broken = false;  // a failed write could not be rolled back: reopen through recovery

  struct Prepared {
    std::uint64_t ts = 0;
    std::string line;  // with trailing newline
    std::string hash;
  };

  ~Impl() {
    if (fd >= 0) {
      if (dirty) do_fsync(fd);
      ::close(fd);
    }
    if (lock_fd >= 0) ::close(lock_fd);
  }

  std::uint64_t now() const { return cfg.now_ms(); }
  int do_fsync(int f) const { return cfg.fsync_fn ? cfg.fsync_fn(f) : ::fsync(f); }
  int do_ftruncate(int f, std::uint64_t len) const {
    return cfg.ftruncate_fn ? cfg.ftruncate_fn(f, len) : ::ftruncate(f, static_cast<off_t>(len));
  }

  Status write_all(int f, const std::string& s) {
    std::size_t off = 0;
    while (off < s.size()) {
      const ssize_t n = cfg.write_fn ? static_cast<ssize_t>(cfg.write_fn(f, s.data() + off, s.size() - off))
                                     : ::write(f, s.data() + off, s.size() - off);
      if (n < 0) {
        if (errno == EINTR && !cfg.write_fn) continue;
        return io("audit write failed");
      }
      off += static_cast<std::size_t>(n);
    }
    return {};
  }

  // Builds the next entry (seq + 1, chained from head). The body is built once per append.
  Prepared prepare(const AuditEntry& e) const {
    Prepared p;
    p.ts = now();
    p.line = seal(build_body(cfg.src, seq + 1, p.ts, e, head), p.hash);
    p.line += '\n';
    return p;
  }

  // Writes a prepared line to `f` (the current file, at size `at`). On success updates
  // seq/head/cur_size. If only the fsync fails, the line is written and the state advanced: the
  // result is ok and `dirty` stays set (durability pending; sync() reports the error).
  Status write_line(int f, std::uint64_t at, const Prepared& p) {
    if (p.line.size() > kAuditMaxLineBytes) return Error{ErrorCode::InvalidArgument, "audit entry too large"};
    if (auto st = write_all(f, p.line); !st) {
      if (do_ftruncate(f, at) != 0) broken = true;  // next append reopens through recovery
      return st;
    }
    seq += 1;
    head = p.hash;
    cur_size = at + p.line.size();
    dirty = true;
    if (cfg.fsync_every_entry || p.ts >= last_sync_ms + cfg.fsync_interval_ms) {
      if (do_fsync(f) == 0) {
        dirty = false;
        last_sync_ms = p.ts;
      }
    }
    return {};
  }

  Status write_entry(int f, std::uint64_t at, const AuditEntry& e) { return write_line(f, at, prepare(e)); }

  Status open_new_file(std::uint64_t first_seq, int& out_fd) {
    const std::string path = cfg.dir + "/" + file_name_for(first_seq);
    const int f = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_CLOEXEC, 0600);
    if (f < 0) return io("audit file create failed");
    out_fd = f;
    return {};
  }

  Status rotate() {
    // The old file must be durable BEFORE the new file exists: otherwise a power loss could keep
    // the new file's first entry (prev = old last hash) but lose the old tail, and the chain
    // would fail forever.
    if (do_fsync(fd) != 0) return io("audit fsync failed before rotation");
    dirty = false;
    int nf = -1;
    if (auto st = open_new_file(seq + 1, nf); !st) return st;
    const std::string old_name = file_name_for(cur_first);
    const std::uint64_t old_seq = seq;
    AuditEntry r;
    r.actor = "local";
    r.action = "audit.rotate";
    r.target = file_name_for(seq + 1);
    r.result = "ok";
    r.reason = "max_bytes";
    r.detail = {{"prev_file", old_name}};
    if (auto st = write_entry(nf, 0, r); !st) {
      ::close(nf);
      ::unlink((cfg.dir + "/" + file_name_for(old_seq + 1)).c_str());
      return st;  // write_line left seq/head/cur_size untouched on failure
    }
    ::close(fd);
    fd = nf;
    cur_first = old_seq + 1;
    fsync_dir(cfg.dir);
    return enforce_total();
  }

  // Keep sum(files except the newest) + max_bytes <= max_total by deleting the oldest files.
  Status enforce_total() {
    auto files = list_audit_files(cfg.dir);
    if (files.size() < 2) return {};
    std::vector<std::uint64_t> sizes;
    std::uint64_t sum = 0;
    for (std::size_t i = 0; i + 1 < files.size(); ++i) {
      struct stat sb{};
      if (::stat(files[i].c_str(), &sb) != 0) return io("audit stat failed");
      sizes.push_back(static_cast<std::uint64_t>(sb.st_size));
      sum += sizes.back();
    }
    std::size_t del = 0;
    while (del < sizes.size() && sum + max_bytes > max_total) {
      if (::unlink(files[del].c_str()) != 0) return io("audit unlink failed");
      sum -= sizes[del];
      ++del;
    }
    if (del == 0) return {};
    fsync_dir(cfg.dir);
    std::uint64_t kept_first = 0;
    parse_audit_name(basename_of(files[del]), kept_first);
    AuditEntry t;
    t.actor = "local";
    t.action = "audit.truncate";
    t.target = "audit";
    t.result = "ok";
    t.reason = "max_total_bytes";
    t.detail = {{"first_kept_seq", kept_first}, {"deleted_files", static_cast<std::uint64_t>(del)}};
    return write_entry(fd, cur_size, t);
  }

  // Tail recovery (P19): in the newest file, keep everything up to the last line that verifies
  // and drop the rest (a partial line, or entries that do not verify); a file left empty is
  // removed and the predecessor becomes the tail. Writes audit.recover if anything was dropped.
  Status recover() {
    if (fd >= 0) {
      ::close(fd);
      fd = -1;
    }
    seq = 0;
    head = kAuditGenesisPrev;
    cur_first = 0;
    cur_size = 0;
    dirty = false;
    auto files = list_audit_files(cfg.dir);
    std::uint64_t dropped = 0;
    while (!files.empty()) {
      const std::string path = files.back();
      const int f = ::open(path.c_str(), O_RDWR | O_APPEND | O_CLOEXEC);
      if (f < 0) return io("audit file open failed");
      struct stat fb{};
      if (::fstat(f, &fb) != 0) {
        ::close(f);
        return io("audit file stat failed");
      }
      const std::uint64_t size = static_cast<std::uint64_t>(fb.st_size);
      if (size > kMaxRecoverBytes) {
        ::close(f);
        return corrupt("audit file too large to recover");
      }
      std::string buf(size, '\0');
      std::size_t got = 0;
      while (got < size) {
        const ssize_t n = ::pread(f, buf.data() + got, size - got, static_cast<off_t>(got));
        if (n <= 0) {
          ::close(f);
          return io("audit file read failed");
        }
        got += static_cast<std::size_t>(n);
      }
      std::size_t end = size;
      bool found = false;
      Checked ck;
      while (end > 0) {
        const auto nl = buf.rfind('\n', end - 1);
        end = nl == std::string::npos ? 0 : nl + 1;  // drop a partial tail
        if (end == 0) break;
        const auto pn = end >= 2 ? buf.rfind('\n', end - 2) : std::string::npos;
        const std::size_t lstart = pn == std::string::npos ? 0 : pn + 1;
        if (check_line(std::string_view(buf).substr(lstart, end - 1 - lstart), ck).empty()) {
          found = true;
          break;
        }
        end = lstart;  // this line does not verify: drop it too
      }
      if (end < size) {
        dropped += size - end;
        if (do_ftruncate(f, end) != 0) {
          ::close(f);
          return io("audit truncate failed");
        }
        do_fsync(f);
      }
      if (!found) {  // no verifying line left: remove the file, fall back to the predecessor
        ::close(f);
        ::unlink(path.c_str());
        fsync_dir(cfg.dir);
        files.pop_back();
        continue;
      }
      std::uint64_t first = 0;
      parse_audit_name(basename_of(path), first);
      fd = f;
      cur_first = first;
      cur_size = end;
      seq = ck.seq;
      head = ck.hash;
      break;
    }
    if (dropped > 0) {
      recovered += dropped;
      if (fd < 0) {
        // Nothing usable was left: start the log again so the recover entry is seq 1.
        if (auto st = open_new_file(1, fd); !st) return st;
        cur_first = 1;
        cur_size = 0;
      }
      AuditEntry r;
      r.actor = "local";
      r.action = "audit.recover";
      r.target = "audit";
      r.result = "ok";
      r.reason = "partial_tail";
      r.detail = {{"dropped_bytes", dropped}};
      if (auto st = write_entry(fd, cur_size, r); !st) return st;
    }
    if (fd >= 0) return enforce_total();
    return {};
  }
};

AuditLog::AuditLog(Impl* p) : p_(p) {}
AuditLog::AuditLog(AuditLog&& o) noexcept : p_(o.p_) { o.p_ = nullptr; }
AuditLog& AuditLog::operator=(AuditLog&& o) noexcept {
  if (this != &o) {
    delete p_;
    p_ = o.p_;
    o.p_ = nullptr;
  }
  return *this;
}
AuditLog::~AuditLog() { delete p_; }

std::uint64_t AuditLog::seq() const { return p_->seq; }
std::string AuditLog::head() const { return p_->head; }
std::uint64_t AuditLog::recovered_bytes() const { return p_->recovered; }
std::uint64_t AuditLog::effective_max_bytes() const { return p_->max_bytes; }
std::uint64_t AuditLog::effective_max_total_bytes() const { return p_->max_total; }

Status AuditLog::sync() {
  if (p_->fd >= 0 && p_->dirty) {
    if (p_->do_fsync(p_->fd) != 0) return io("audit fsync failed");
    p_->dirty = false;
    p_->last_sync_ms = p_->now();
  }
  return {};
}

Status AuditLog::append(const AuditEntry& e) {
  Impl& s = *p_;
  if (s.broken) {
    if (auto st = s.recover(); !st) return st;
    s.broken = false;
  }
  if (s.fd < 0) {
    if (auto st = s.open_new_file(s.seq + 1, s.fd); !st) return st;
    s.cur_first = s.seq + 1;
    s.cur_size = 0;
    fsync_dir(s.cfg.dir);
    return s.write_line(s.fd, 0, s.prepare(e));
  }
  Impl::Prepared pr = s.prepare(e);
  // Rotate when this line would push a non-empty file past max_bytes. After a rotation the
  // entry's seq and prev change, so it is built again.
  if (s.cur_size > 0 && s.cur_size + pr.line.size() > s.max_bytes) {
    if (auto st = s.rotate(); !st) return st;
    pr = s.prepare(e);
  }
  return s.write_line(s.fd, s.cur_size, pr);
}

Expected<AuditLog, Error> AuditLog::open(AuditConfig cfg) {
  if (cfg.dir.empty()) return Error{ErrorCode::InvalidArgument, "audit dir empty"};
  if (!cfg.now_ms) cfg.now_ms = [] { return static_cast<std::uint64_t>(wall_unix_ns() / 1000000); };
  struct stat sb{};
  if (::stat(cfg.dir.c_str(), &sb) != 0) {
    if (::mkdir(cfg.dir.c_str(), 0700) != 0 && errno != EEXIST) return io("audit dir create failed");
    if (::stat(cfg.dir.c_str(), &sb) != 0) return io("audit dir stat failed");
  }
  if (!S_ISDIR(sb.st_mode)) return Error{ErrorCode::InvalidArgument, "audit dir is not a directory"};

  auto s = std::make_unique<Impl>();
  s->cfg = cfg;
  s->lock_fd = ::open(cfg.dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (s->lock_fd < 0) return io("audit dir open failed");
  if (::flock(s->lock_fd, LOCK_EX | LOCK_NB) != 0) {
    return Error{ErrorCode::Busy, "audit dir is locked by another writer"};
  }
  auto files = list_audit_files(cfg.dir);

  // Total cap: configured, and never more than 10 % of the free space (our own bytes count as
  // free, so a full log does not shrink the cap on every restart).
  std::uint64_t existing = 0;
  for (const auto& f : files) {
    struct stat fb{};
    if (::stat(f.c_str(), &fb) == 0) existing += static_cast<std::uint64_t>(fb.st_size);
  }
  s->max_total = cfg.max_total_bytes;
  struct statvfs vf{};
  if (::statvfs(cfg.dir.c_str(), &vf) == 0) {
    const std::uint64_t avail = static_cast<std::uint64_t>(vf.f_bavail) * vf.f_frsize + existing;
    s->max_total = std::min(s->max_total, avail / 10);
  }
  s->max_bytes = std::max<std::uint64_t>(1, std::min(cfg.max_bytes, s->max_total / 4));

  if (auto st = s->recover(); !st) return st.error();
  return AuditLog(s.release());
}

// ---- coalescer -----------------------------------------------------------------------------

void AuditCoalescer::add(const AuditEntry& e, std::uint64_t now_ms) {
  const std::uint64_t sec = now_ms / 1000;
  auto key_of = [&](const std::string& actor) {
    std::string k = std::to_string(sec);
    k.insert(0, 20 - k.size(), '0');
    k += '\x1f' + actor + '\x1f' + e.action + '\x1f' + e.result;
    return k;
  };
  std::string key = key_of(e.actor);
  auto it = wins_.find(key);
  if (it == wins_.end() && wins_.size() >= max_keys_) {
    key = key_of("(other)");
    it = wins_.find(key);
    if (it == wins_.end()) {
      Win w;
      w.second = sec;
      w.entry = e;
      w.entry.actor = "(other)";
      w.entry.count = 0;
      it = wins_.emplace(key, std::move(w)).first;
    }
  } else if (it == wins_.end()) {
    Win w;
    w.second = sec;
    w.entry = e;
    w.entry.count = 0;
    it = wins_.emplace(key, std::move(w)).first;
  }
  it->second.entry.count += e.count == 0 ? 1 : e.count;
}

std::vector<AuditEntry> AuditCoalescer::flush(std::uint64_t now_ms, bool all) {
  std::vector<AuditEntry> out;
  const std::uint64_t sec = now_ms / 1000;
  for (auto it = wins_.begin(); it != wins_.end();) {
    if (all || it->second.second < sec) {
      out.push_back(std::move(it->second.entry));
      it = wins_.erase(it);
    } else {
      ++it;
    }
  }
  return out;
}

// ---- verifier ------------------------------------------------------------------------------

std::string AuditVerifyResult::text() const {
  if (ok) return "OK " + std::to_string(entries) + " entries";
  return "FAIL " + file + ":" + std::to_string(line) + " seq=" + std::to_string(seq) + ": " + message;
}

AuditVerifyResult audit_verify(const std::vector<AuditFileBytes>& files, const AuditAnchor* anchor) {
  AuditVerifyResult r;
  auto fail = [&](const std::string& f, std::uint64_t line, std::uint64_t seq, std::string msg) {
    r.ok = false;
    r.file = f;
    r.line = line;
    r.seq = seq;
    r.message = std::move(msg);
    return r;
  };
  if (files.empty()) return fail("", 0, 0, "no files");

  struct Trunc {
    std::size_t file;
    std::uint64_t line, seq, kept;
  };
  std::vector<Trunc> truncs;
  std::vector<std::uint64_t> first_seqs;
  std::string last_hash;
  std::uint64_t last_seq = 0;
  bool have_last = false;

  for (std::size_t fi = 0; fi < files.size(); ++fi) {
    const auto& f = files[fi];
    const std::string_view b = f.bytes;
    if (b.empty()) return fail(f.name, 0, 0, "file has no entries");
    if (b.back() != '\n') return fail(f.name, 0, 0, "partial last line (no trailing newline)");
    std::size_t pos = 0;
    std::uint64_t lineno = 0;
    bool first_in_file = true;
    while (pos < b.size()) {
      const std::size_t nl = b.find('\n', pos);
      const std::string_view line = b.substr(pos, nl - pos);
      pos = nl + 1;
      ++lineno;
      if (line.size() > kAuditMaxLineBytes) return fail(f.name, lineno, 0, "line too long");
      Checked ck;
      const std::string err = check_line(line, ck);
      if (!err.empty()) return fail(f.name, lineno, ck.seq, err);
      if (have_last) {
        if (ck.seq != last_seq + 1) return fail(f.name, lineno, ck.seq, "seq gap (expected " + std::to_string(last_seq + 1) + ")");
        if (ck.prev != last_hash) return fail(f.name, lineno, ck.seq, "prev does not match the previous entry");
        if (first_in_file && ck.action != "audit.rotate") return fail(f.name, lineno, ck.seq, "file does not begin with audit.rotate");
      } else {
        // Anchor of the chain.
        if (ck.seq == 1 && ck.prev != kAuditGenesisPrev) return fail(f.name, lineno, ck.seq, "seq 1 must chain from the genesis prev");
      }
      if (first_in_file) {
        first_seqs.push_back(ck.seq);
        std::uint64_t named = 0;
        if (parse_audit_name(basename_of(f.name), named) && named != ck.seq)
          return fail(f.name, lineno, ck.seq, "file name does not match its first seq");
      }
      if (ck.first_kept_seq) truncs.push_back({fi, lineno, ck.seq, *ck.first_kept_seq});
      first_in_file = false;
      have_last = true;
      last_seq = ck.seq;
      last_hash = ck.hash;
      if (r.entries == 0) r.first_seq = ck.seq;
      r.last_seq = ck.seq;
      r.head = ck.hash;
      if (anchor && ck.seq == anchor->seq && ck.hash != anchor->head)
        return fail(f.name, lineno, ck.seq, "hash differs from the anchor (log rewritten)");
      ++r.entries;
    }
  }
  for (const auto& t : truncs) {
    const bool is_start = std::find(first_seqs.begin(), first_seqs.end(), t.kept) != first_seqs.end();
    if (t.kept > t.seq || !(is_start || t.kept < first_seqs.front()))
      return fail(files[t.file].name, t.line, t.seq, "audit.truncate first_kept_seq names no file");
  }
  if (anchor) {
    if (anchor->seq < r.first_seq)
      return fail(files.front().name, 0, anchor->seq, "anchor seq precedes the first kept entry (oldest files deleted)");
    if (anchor->seq > r.last_seq)
      return fail(files.back().name, 0, r.last_seq, "log ends before the anchor seq (tail truncated)");
  }
  r.ok = true;
  return r;
}

AuditVerifyResult audit_verify_paths(const std::vector<std::string>& paths, const AuditAnchor* anchor) {
  std::vector<AuditFileBytes> fs;
  for (const auto& p : paths) {
    std::ifstream in(p, std::ios::binary);
    if (!in) {
      AuditVerifyResult r;
      r.file = p;
      r.message = "cannot read file";
      return r;
    }
    fs.push_back({p, std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>())});
  }
  return audit_verify(fs, anchor);
}

}  // namespace miracache::control
