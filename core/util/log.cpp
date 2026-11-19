// SPDX-License-Identifier: Apache-2.0
#include "util/log.h"

#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <vector>

#include "util/clock.h"

namespace miracache::log {

namespace {
std::atomic<const Identity*> g_identity{nullptr};  // a replaced identity is never freed (lock-free readers may hold it), see set_identity
std::atomic<int> g_fd{2};

const char* level_name(Level l) {
  switch (l) {
    case Level::Debug: return "debug";
    case Level::Info: return "info";
    case Level::Warn: return "warn";
    case Level::Error: return "error";
    case Level::Fatal: return "fatal";
  }
  return "info";
}

bool needs_quote(std::string_view v) {
  if (v.empty()) return true;
  for (unsigned char c : v)
    if (c <= ' ' || c == '=' || c == '"' || c == '\\' || c == 0x7f) return true;
  return false;
}

void append_value(std::string& out, std::string_view v, bool force_quote) {
  if (!force_quote && !needs_quote(v)) {
    out.append(v);
    return;
  }
  out += '"';
  for (unsigned char c : v) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c < 0x20 || c == 0x7f) {
          char b[8];
          std::snprintf(b, sizeof b, "\\u%04x", c);
          out += b;
        } else {
          out += static_cast<char>(c);
        }
    }
  }
  out += '"';
}

void append_kv(std::string& out, std::string_view k, std::string_view v, bool force_quote = false) {
  out += ' ';
  out.append(k);
  out += '=';
  append_value(out, v, force_quote);
}

std::string iso_utc(std::int64_t unix_ns) {
  std::int64_t s = unix_ns / 1000000000;
  std::int64_t ms = (unix_ns % 1000000000) / 1000000;
  if (ms < 0) {
    ms += 1000;
    --s;
  }
  const std::time_t t = static_cast<std::time_t>(s);
  std::tm tm{};
  gmtime_r(&t, &tm);
  char b[40];
  std::snprintf(b, sizeof b, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms));
  return b;
}
}  // namespace

std::string hostname() {
  static const std::string h = [] {
    char b[256] = {};
    if (::gethostname(b, sizeof b - 1) != 0 || b[0] == '\0') return std::string("unknown");
    return std::string(b);
  }();
  return h;
}

void set_identity(Identity id) {
  if (id.host.empty()) id.host = hostname();
  // Readers are lock-free and may still hold the old pointer, so a replaced identity is never freed. It is
  // parked in a list that stays reachable from a global (a plain drop would be a LeakSanitizer report when
  // a test sets the identity more than once).
  static std::mutex mu;
  static std::vector<const Identity*>* retired = new std::vector<const Identity*>();
  std::lock_guard<std::mutex> lk(mu);
  const Identity* fresh = new Identity(std::move(id));
  if (const Identity* old = g_identity.exchange(fresh, std::memory_order_acq_rel)) retired->push_back(old);
}

Identity identity() {
  if (const Identity* p = g_identity.load(std::memory_order_acquire)) return *p;
  Identity id;
  id.host = hostname();
  return id;
}

void set_sink_fd(int fd) { g_fd.store(fd, std::memory_order_relaxed); }

std::string format_line(std::int64_t unix_ns, Level lvl, std::string_view comp, std::string_view msg,
                        std::initializer_list<Field> extra) {
  return format_line(unix_ns, lvl, comp, msg, std::span<const Field>(extra.begin(), extra.size()));
}

std::string format_line(std::int64_t unix_ns, Level lvl, std::string_view comp, std::string_view msg,
                        std::span<const Field> extra) {
  std::string out;
  out.reserve(160);
  out += "ts=";
  out += iso_utc(unix_ns);
  append_kv(out, "level", level_name(lvl));
  append_kv(out, "comp", comp);
  const Identity* id = g_identity.load(std::memory_order_acquire);
  if (id && id->node_id != 0) append_kv(out, "node_id", std::to_string(id->node_id));
  append_kv(out, "host", id ? id->host : hostname());
  if (id && !id->addr.empty()) append_kv(out, "addr", id->addr);
  append_kv(out, "msg", msg, true);
  for (const auto& [k, v] : extra) append_kv(out, k, v);
  out += '\n';
  return out;
}

void write(Level lvl, std::string_view comp, std::string_view msg, std::initializer_list<Field> extra) {
  write(lvl, comp, msg, std::span<const Field>(extra.begin(), extra.size()));
}

void write(Level lvl, std::string_view comp, std::string_view msg, std::span<const Field> extra) {
  const std::string line = format_line(wall_unix_ns(), lvl, comp, msg, extra);
  const int fd = g_fd.load(std::memory_order_relaxed);
  const char* p = line.data();
  std::size_t left = line.size();
  while (left > 0) {  // one write(2) in practice; the loop only covers a short write or EINTR
    const ssize_t n = ::write(fd, p, left);
    if (n < 0) {
      if (errno == EINTR) continue;
      return;
    }
    p += n;
    left -= static_cast<std::size_t>(n);
  }
}

void writef(Level lvl, std::string_view comp, const char* fmt, ...) {
  char buf[512];
  va_list ap;
  va_start(ap, fmt);
  std::vsnprintf(buf, sizeof buf, fmt, ap);
  va_end(ap);
  write(lvl, comp, buf);
}

}  // namespace miracache::log
