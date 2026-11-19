// SPDX-License-Identifier: Apache-2.0
// Structured log lines (logfmt) on stderr. Lives in miracache_util so the memory node, core and
// (later) the client all use one format without linking server code.
//
//   ts=2026-11-11T09:30:00.123Z level=info comp=memnode node_id=7 host=hostA addr=10.0.0.10:7471 msg="listening" port=9464
//
// - One line = one write(2) call (up to PIPE_BUF the kernel keeps lines of concurrent
//   threads and processes apart; longer lines are still written whole by this process).
// - The identity (node_id, host, addr) is set once at startup with set_identity(); until then
//   node_id and addr are left out and host is the machine's hostname.
// - Values with a space, '=', '"' or a control character are quoted and escaped; msg always is.
// - Never log a scope, session, key, salt or ticket value.
#pragma once

#include <cstdint>
#include <initializer_list>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace miracache::log {

enum class Level : std::uint8_t { Debug, Info, Warn, Error, Fatal };

struct Identity {
  std::uint32_t node_id = 0;  // 0 = unknown / not a memory node: the field is left out
  std::string host;           // empty = gethostname()
  std::string addr;           // empty = left out; "host:port[,host:port...]"
};

// Call once, before other threads log. A later call replaces the identity (tests only).
void set_identity(Identity id);
// The identity lines carry now (host filled in).
Identity identity();
// This machine's hostname ("unknown" if the OS cannot say).
std::string hostname();

using Field = std::pair<std::string_view, std::string>;

// Writes one line. `comp` is the component ("memnode", "verbs_cm", ...).
void write(Level lvl, std::string_view comp, std::string_view msg, std::initializer_list<Field> extra = {});
void write(Level lvl, std::string_view comp, std::string_view msg, std::span<const Field> extra);
// printf-style msg (no extras).
void writef(Level lvl, std::string_view comp, const char* fmt, ...) __attribute__((format(printf, 3, 4)));

// The line write() would emit for a given time, with the trailing newline. For tests.
std::string format_line(std::int64_t unix_ns, Level lvl, std::string_view comp, std::string_view msg,
                        std::initializer_list<Field> extra = {});
std::string format_line(std::int64_t unix_ns, Level lvl, std::string_view comp, std::string_view msg,
                        std::span<const Field> extra);

// Redirects output to fd (default 2). For tests.
void set_sink_fd(int fd);

}  // namespace miracache::log
