// SPDX-License-Identifier: Apache-2.0
// Hash-chained audit log `mira-audit-v1` (RBAC/audit plan decisions 5-7, RB1): the JSON Lines
// writer (rotation, total byte cap, batched fsync, tail recovery), the per-second coalescer for
// denied / 429 entries, and the verifier. The Go side (mirctl, controller) must produce files the
// verifier accepts and verify files this writer produces.
#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "util/expected.h"

namespace miracache::control {

inline constexpr std::size_t kAuditHashSuffixBytes = 75;  // `,"hash":"` (9) + 64 hex + `"}` (2)
inline constexpr std::size_t kAuditMaxLineBytes = 16 * 1024;
inline const char kAuditGenesisPrev[] = "0000000000000000000000000000000000000000000000000000000000000000";

// Appends `s` as a JSON string body (no surrounding quotes) in the canonical form: `"` `\` and
// control characters escaped (`\n \r \t \b \f` short, others `\u00xx` lower-case), U+2028/U+2029
// as ` `/` `, each invalid UTF-8 byte as `�`, everything else (including `<>&` and
// non-ASCII) raw. This is exactly Go's encoding/json with SetEscapeHTML(false).
void audit_escape_json(std::string_view s, std::string& out);

// "YYYY-MM-DDTHH:MM:SS.mmmZ"
std::string audit_format_ts(std::uint64_t unix_ms);

// Where an entry comes from: a memory node (node_id, host, addr) or the controller (host, addr).
struct AuditSource {
  bool controller = false;
  std::uint64_t node_id = 0;
  std::string host;  // memory node: `host`; controller: its hostname
  std::string addr;
};

using AuditDetailValue = std::variant<std::string, std::uint64_t>;

struct AuditEntry {
  std::string actor;  // SPIFFE ID or "local"
  std::string role;
  std::string action;
  std::string target;
  std::string result;  // "ok" | "denied" | "error"
  std::string reason;
  std::uint64_t count = 1;
  std::optional<std::uint64_t> generation;
  // Ordered; rendered as a JSON object (`{}` when empty). Never put secrets here.
  std::vector<std::pair<std::string, AuditDetailValue>> detail;
};

struct AuditConfig {
  std::string dir;  // created (one level, 0700) if missing
  AuditSource src;
  std::uint64_t max_bytes = 64ull << 20;         // rotate above this
  std::uint64_t max_total_bytes = 1ull << 30;    // never more than 10 % of the free space at open
  bool fsync_every_entry = false;                // controller: true
  std::uint64_t fsync_interval_ms = 1000;        // memory node: at most one fsync per interval
  std::function<std::uint64_t()> now_ms;         // unix ms; default = wall_unix_ns()/1e6
  // Test hooks for failure injection / observation; null = the real syscall.
  std::function<int(int fd)> fsync_fn;                                   // returns 0 or -1
  std::function<long(int fd, const void* p, std::size_t n)> write_fn;    // write(2) semantics
  std::function<int(int fd, std::uint64_t len)> ftruncate_fn;            // returns 0 or -1
};

// Single-writer append-only log. Not thread-safe: the owner serialises calls.
class AuditLog {
 public:
  // Takes an exclusive flock on `cfg.dir` for the life of the object: a second writer gets
  // ErrorCode::Busy. Tail recovery (P19): everything after the last line that verifies (a partial
  // line, or entries that do not verify) is dropped and an `audit.recover` entry is written.
  // If open() still fails (I/O error, lock held, unreadable or oversize file), the caller (RB2)
  // decides; the recommended policy is: refuse to start the admin API but keep the data plane
  // running, and alarm. Never write to the files by other means.
  static Expected<AuditLog, Error> open(AuditConfig cfg);
  AuditLog(AuditLog&&) noexcept;
  AuditLog& operator=(AuditLog&&) noexcept;
  AuditLog(const AuditLog&) = delete;
  AuditLog& operator=(const AuditLog&) = delete;
  ~AuditLog();

  // One write(2) per line; fsync per the config. If the write fails nothing is appended (seq/head
  // intact; if the file cannot be rolled back the next append reopens it through recovery). If
  // only the fsync fails, the line IS written and seq/head have advanced: append returns ok, the
  // log stays dirty, and the next fsync (a later append or sync()) retries; only durability is
  // pending, and sync() reports the error.
  Status append(const AuditEntry& e);
  // fsync now if anything is unsynced (timer / shutdown hook).
  Status sync();

  std::uint64_t seq() const;       // last written seq (0 = empty log)
  std::string head() const;        // last hash, 64 hex (genesis zeros when empty)
  // Bytes dropped from a partial tail by open() (0 = none); an audit.recover entry was written.
  std::uint64_t recovered_bytes() const;
  std::uint64_t effective_max_bytes() const;
  std::uint64_t effective_max_total_bytes() const;

 private:
  struct Impl;
  explicit AuditLog(Impl* p);
  Impl* p_;
};

// Paths of `audit-<first seq>.jsonl` in `dir`, ordered by first seq.
std::vector<std::string> list_audit_files(const std::string& dir);

// Per-(actor, action, result) one-second coalescing of denied / 429 entries (decision 6).
class AuditCoalescer {
 public:
  explicit AuditCoalescer(std::size_t max_keys = 1024) : max_keys_(max_keys) {}
  // Count one event at `now_ms`. `e` supplies role/target/reason of the window (first one wins).
  void add(const AuditEntry& e, std::uint64_t now_ms);
  // Entries (count = events) of every window whose second ended before `now_ms`'s second; with
  // `all` every window. Beyond max_keys distinct keys per second, further events fold into
  // actor "(other)".
  std::vector<AuditEntry> flush(std::uint64_t now_ms, bool all = false);

 private:
  struct Win {
    std::uint64_t second = 0;
    AuditEntry entry;
  };
  std::size_t max_keys_;
  std::map<std::string, Win> wins_;
};

struct AuditVerifyResult {
  bool ok = false;
  std::uint64_t entries = 0;
  // On failure: where and why.
  std::string file;
  std::uint64_t line = 0;  // 1-based line in `file`
  std::uint64_t seq = 0;   // seq of the broken entry if it could be read, else 0
  std::string message;
  // The verified range (filled as far as the walk got, also on failure): first and last seq read
  // and the hash of the last entry. A caller records (last_seq, head) as an anchor.
  std::uint64_t first_seq = 0;
  std::uint64_t last_seq = 0;
  std::string head;
  // `OK <n> entries` or `FAIL <file>:<line> seq=<seq>: <message>`
  std::string text() const;
};

// Verifies the bytes of one or more files in chain order: v, field order, hash, seq continuity,
// prev links across files, and that every file after the first begins with audit.rotate.
// audit.truncate's first_kept_seq must name the first seq of a given file (or lie before the
// first given file). The first entry of the first file anchors the chain (genesis zeros when its
// seq is 1). A partial last line is a failure.
struct AuditFileBytes {
  std::string name;
  std::string bytes;
};
//
// Optional anchor (seq, head) recorded earlier (e.g. from /v1/identity audit_seq / audit_head):
// verification fails unless the chain contains that seq with exactly that hash. So tail
// truncation (last_seq < anchor.seq), a rewrite (hash differs) and deletion of the oldest files
// past the anchor (anchor.seq < first_seq: it can no longer be checked) are all detected.
struct AuditAnchor {
  std::uint64_t seq = 0;
  std::string head;  // 64 hex
};
AuditVerifyResult audit_verify(const std::vector<AuditFileBytes>& files, const AuditAnchor* anchor = nullptr);
// Same, reading paths from disk.
AuditVerifyResult audit_verify_paths(const std::vector<std::string>& paths, const AuditAnchor* anchor = nullptr);

}  // namespace miracache::control
