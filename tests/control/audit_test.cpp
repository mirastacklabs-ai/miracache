// SPDX-License-Identifier: Apache-2.0
// Hash-chained audit log `mira-audit-v1`.
//
// Goldens live in proto/golden/audit_v1/. Regenerate them (inside the dev container) with
//   MIRA_AUDIT_GOLDEN_WRITE=1 miracache_control_tests --gtest_filter='AuditGolden.Regenerate'
// The regular run checks that the writer reproduces them byte for byte and that the verifier
// accepts EVERY file there (a glob: go_sample.jsonl and any later file are checked automatically).
#include <gtest/gtest.h>

#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

#include "control/audit.h"
#include "control/sha256.h"

using namespace miracache::control;
namespace fs = std::filesystem;

namespace {

struct TempDir {
  std::string path;
  TempDir() {
    std::string tmpl = (fs::temp_directory_path() / "mira_audit_XXXXXX").string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (!::mkdtemp(buf.data())) std::abort();
    path = buf.data();
  }
  ~TempDir() {
    std::error_code ec;
    fs::remove_all(path, ec);
  }
};

std::string slurp(const std::string& p) {
  std::ifstream in(p, std::ios::binary);
  return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}
void spit(const std::string& p, const std::string& s, bool append = false) {
  std::ofstream o(p, std::ios::binary | (append ? std::ios::app : std::ios::trunc));
  o << s;
}

std::vector<std::string> lines_of(const std::string& b) {
  std::vector<std::string> v;
  std::size_t pos = 0;
  while (pos < b.size()) {
    const auto nl = b.find('\n', pos);
    v.push_back(b.substr(pos, nl - pos));
    pos = nl + 1;
  }
  return v;
}

struct Clock {
  std::uint64_t t = 1767225600123ull;  // 2026-01-01T00:00:00.123Z
  std::uint64_t operator()() { return t += 250; }
};

AuditSource node_src() { return {false, 7, "hostA", "10.0.0.10:7471"}; }

AuditConfig cfg_for(const std::string& dir, Clock& clk) {
  AuditConfig c;
  c.dir = dir;
  c.src = node_src();
  c.now_ms = [&clk] { return clk(); };
  return c;
}

AuditEntry ent(const std::string& action, const std::string& result = "ok", const std::string& reason = "") {
  AuditEntry e;
  e.actor = "spiffe://lab/ops/alice";
  e.role = "operator";
  e.action = action;
  e.target = "node:3";
  e.result = result;
  e.reason = reason;
  return e;
}

// Reason with `<`, `>`, `&`, quotes, a backslash, a tab, a control byte, non-ASCII, U+2028.
const char kNasty[] = "role <operator> & \"admin\" required \\ path\tTab \x01 \xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC \xE2\x80\xA8 end";

// ---- scenarios (also the golden generators) ------------------------------------------------------

void scenario_basic(const std::string& dir) {
  Clock clk;
  auto log = AuditLog::open(cfg_for(dir, clk));
  ASSERT_TRUE(log.has_value());
  AuditEntry a = ent("bundle.apply", "ok", "accepted");
  a.generation = 42;
  a.detail = {{"changed", std::string("config,nodes")}, {"nodes", std::uint64_t{3}}};
  ASSERT_TRUE(log->append(a).has_value());
  AuditEntry d = ent("admin.call", "denied", kNasty);
  d.target = "POST /v1/drain";
  d.role = "viewer";
  d.count = 17;
  ASSERT_TRUE(log->append(d).has_value());
  AuditEntry e = ent("bundle.apply", "error", "generation_lower");
  e.actor = "local";
  e.role = "";
  e.generation = 41;
  ASSERT_TRUE(log->append(e).has_value());
  AuditEntry f = ent("drop_principal");
  f.detail = {{"name", std::string("p<1>")}, {"drop_before", std::uint64_t{1767225600}}};
  ASSERT_TRUE(log->append(f).has_value());
}

void scenario_controller(const std::string& dir) {
  Clock clk;
  AuditConfig c = cfg_for(dir, clk);
  c.src = {true, 0, "ctl-1.example", "10.0.0.2:9470"};
  c.fsync_every_entry = true;
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  AuditEntry a = ent("bundle.publish", "ok", "rollout");
  a.generation = 7;
  a.detail = {{"keys", std::string("membership.nodes")}, {"node_ids", std::string("1,2,3")}};
  ASSERT_TRUE(log->append(a).has_value());
  AuditEntry b = ent("member.remove", "ok", "fail_timeout");
  b.actor = "local";
  b.target = "node:9";
  ASSERT_TRUE(log->append(b).has_value());
}

void fill(AuditLog& log, int from, int to) {
  for (int i = from; i < to; ++i) {
    AuditEntry e = ent("config.set", "ok", "entry " + std::to_string(i));
    e.generation = static_cast<std::uint64_t>(i);
    ASSERT_TRUE(log.append(e).has_value());
  }
}

void scenario_rotation(const std::string& dir) {
  Clock clk;
  AuditConfig c = cfg_for(dir, clk);
  c.max_bytes = 800;
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  fill(*log, 0, 6);
}

void scenario_truncate(const std::string& dir) {
  Clock clk;
  AuditConfig c = cfg_for(dir, clk);
  c.max_bytes = 800;
  c.max_total_bytes = 4000;
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  fill(*log, 0, 14);
}

void scenario_recover(const std::string& dir) {
  Clock clk;
  {
    auto log = AuditLog::open(cfg_for(dir, clk));
    ASSERT_TRUE(log.has_value());
    fill(*log, 0, 3);
  }
  spit(dir + "/audit-1.jsonl", "{\"v\":1,\"seq\":4,\"ts\":\"2026-01-01T00:00:01", true);  // crash mid-write
  auto log = AuditLog::open(cfg_for(dir, clk));
  ASSERT_TRUE(log.has_value());
  ASSERT_GT(log->recovered_bytes(), 0u);
  fill(*log, 3, 5);
}

struct Scenario {
  const char* rel;  // path under audit_v1: "x.jsonl" (single file) or "dir/" (all audit-*.jsonl)
  void (*run)(const std::string&);
};
const Scenario kScenarios[] = {
    {"basic.jsonl", scenario_basic},       {"controller.jsonl", scenario_controller},
    {"rotation/", scenario_rotation},      {"truncate/", scenario_truncate},
    {"recover/", scenario_recover},
};

std::string golden_root() { return std::string(MIRACACHE_GOLDEN_DIR) + "/audit_v1"; }

// Runs `s` into a fresh temp dir; returns relative path -> bytes.
std::map<std::string, std::string> produce(const Scenario& s) {
  TempDir td;
  s.run(td.path);
  std::map<std::string, std::string> out;
  const std::string rel = s.rel;
  if (rel.back() == '/') {
    for (const auto& f : list_audit_files(td.path)) out[rel + fs::path(f).filename().string()] = slurp(f);
  } else {
    out[rel] = slurp(td.path + "/audit-1.jsonl");
  }
  return out;
}

std::vector<std::string> sorted_names(const std::string& dir) {
  return list_audit_files(dir);
}

}  // namespace

// ---- encoding ------------------------------------------------------------------------------------

TEST(AuditEncoding, EscapeRules) {
  auto esc = [](std::string_view s) {
    std::string o;
    audit_escape_json(s, o);
    return o;
  };
  EXPECT_EQ(esc("a<b>&c"), "a<b>&c");  // never HTML-escaped
  EXPECT_EQ(esc("q\"b\\"), "q\\\"b\\\\");
  EXPECT_EQ(esc("\n\r\t\b\f"), "\\n\\r\\t\\b\\f");
  EXPECT_EQ(esc(std::string("\x01\x1f", 2)), "\\u0001\\u001f");
  EXPECT_EQ(esc("\x7f"), "\x7f");
  EXPECT_EQ(esc("\xC3\xA9\xE6\x97\xA5"), "\xC3\xA9\xE6\x97\xA5");  // non-ASCII raw
  EXPECT_EQ(esc("\xE2\x80\xA8\xE2\x80\xA9"), "\\u2028\\u2029");     // Go always escapes these
  EXPECT_EQ(esc("\xFF"), "\\ufffd");                                 // invalid byte
  EXPECT_EQ(esc("\xC3"), "\\ufffd");                                 // truncated sequence
  EXPECT_EQ(esc("\xED\xA0\x80"), "\\ufffd\\ufffd\\ufffd");           // surrogate: one per byte
  EXPECT_EQ(esc("\xC0\x80"), "\\ufffd\\ufffd");                      // overlong
  EXPECT_EQ(esc("\xF0\x9F\x98\x80"), "\xF0\x9F\x98\x80");            // 4-byte valid
}

TEST(AuditEncoding, Timestamp) {
  EXPECT_EQ(audit_format_ts(0), "1970-01-01T00:00:00.000Z");
  EXPECT_EQ(audit_format_ts(1767225600123ull), "2026-01-01T00:00:00.123Z");
  EXPECT_EQ(audit_format_ts(951782400999ull), "2000-02-29T00:00:00.999Z");
}

// ---- writer / verifier ---------------------------------------------------------------------------

TEST(Audit, RoundTripAndSuffix) {
  TempDir td;
  scenario_basic(td.path);
  const std::string b = slurp(td.path + "/audit-1.jsonl");
  const auto ls = lines_of(b);
  ASSERT_EQ(ls.size(), 4u);
  std::string prev = kAuditGenesisPrev;
  for (const auto& l : ls) {
    // 75-byte suffix: `,"hash":"` + 64 hex + `"}`.
    ASSERT_GT(l.size(), 75u);
    const std::string suffix = l.substr(l.size() - 75);
    EXPECT_EQ(suffix.substr(0, 9), ",\"hash\":\"");
    EXPECT_EQ(suffix.substr(73), "\"}");
    std::string body = l.substr(0, l.size() - 75) + "}";
    EXPECT_EQ(to_hex(sha256(body)), suffix.substr(9, 64));
    EXPECT_NE(l.find("\"prev\":\"" + prev + "\""), std::string::npos);
    prev = suffix.substr(9, 64);
  }
  EXPECT_EQ(ls[0].rfind("{\"v\":1,\"seq\":1,\"ts\":\"2026-01-01T00:00:00.373Z\",\"src\":{\"node_id\":7,\"host\":\"hostA\",", 0), 0u);
  const auto r = audit_verify_paths({td.path + "/audit-1.jsonl"});
  EXPECT_TRUE(r.ok) << r.text();
  EXPECT_EQ(r.text(), "OK 4 entries");
  // Reopen continues the chain.
  Clock clk;
  auto log = AuditLog::open(cfg_for(td.path, clk));
  ASSERT_TRUE(log.has_value());
  EXPECT_EQ(log->seq(), 4u);
  EXPECT_EQ(log->head(), prev);
  ASSERT_TRUE(log->append(ent("drain")).has_value());
  EXPECT_TRUE(audit_verify_paths({td.path + "/audit-1.jsonl"}).ok);
}

TEST(Audit, NastyReasonIsCanonical) {
  TempDir td;
  scenario_basic(td.path);
  const auto ls = lines_of(slurp(td.path + "/audit-1.jsonl"));
  const std::string want =
      "\"reason\":\"role <operator> & \\\"admin\\\" required \\\\ path\\tTab \\u0001 \xC3\xA9 \xE6\x97\xA5\xE6\x9C\xAC \\u2028 end\"";
  EXPECT_NE(ls[1].find(want), std::string::npos) << ls[1];
  EXPECT_NE(ls[1].find("\"count\":17,"), std::string::npos);
}

TEST(Audit, TamperNamesTheEntry) {
  TempDir td;
  scenario_basic(td.path);
  const std::string path = td.path + "/audit-1.jsonl";
  const std::string good = slurp(path);
  const auto ls = lines_of(good);
  ASSERT_EQ(ls.size(), 4u);
  std::size_t off = 0;
  for (std::size_t k = 0; k < ls.size(); ++k) {
    // Flip one byte inside the `actor` value of entry k+1.
    std::string bad = good;
    const std::size_t at = off + ls[k].find("spiffe") + 2;
    bad[at] = static_cast<char>(bad[at] ^ 0x01);
    const auto r = audit_verify({{"f", bad}});
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.line, k + 1) << r.text();
    EXPECT_NE(r.message.find("hash"), std::string::npos) << r.text();
    // Flip one byte of the stored hash.
    std::string bad2 = good;
    const std::size_t h = off + ls[k].size() - 5;
    bad2[h] = bad2[h] == 'a' ? 'b' : 'a';
    const auto r2 = audit_verify({{"f", bad2}});
    EXPECT_FALSE(r2.ok);
    EXPECT_EQ(r2.line, k + 1) << r2.text();
    off += ls[k].size() + 1;
  }
  // A consistently re-hashed edit still breaks the next entry's prev link.
  {
    std::string body = ls[1].substr(0, ls[1].size() - 75) + "}";
    const auto p = body.find("viewer");
    ASSERT_NE(p, std::string::npos);
    body.replace(p, 6, "admin1");
    const std::string forged = body.substr(0, body.size() - 1) + ",\"hash\":\"" + to_hex(sha256(body)) + "\"}";
    const std::string bad = ls[0] + "\n" + forged + "\n" + ls[2] + "\n" + ls[3] + "\n";
    const auto r = audit_verify({{"f", bad}});
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.line, 3u) << r.text();
    EXPECT_EQ(r.seq, 3u);
  }
  // Deleted and swapped entries.
  EXPECT_FALSE(audit_verify({{"f", ls[0] + "\n" + ls[2] + "\n" + ls[3] + "\n"}}).ok);
  EXPECT_FALSE(audit_verify({{"f", ls[1] + "\n" + ls[0] + "\n" + ls[2] + "\n" + ls[3] + "\n"}}).ok);
  // Truncation of the file's end is not detectable without an anchor, but a partial line is.
  EXPECT_FALSE(audit_verify({{"f", good.substr(0, good.size() - 10)}}).ok);
  // seq 1 must chain from genesis.
  EXPECT_FALSE(audit_verify({{"f", ls[0].substr(0, ls[0].find("\"prev\":\"") + 8) + std::string(64, '1') + "\"}\n"}}).ok);
}

TEST(Audit, RotationLinksFiles) {
  TempDir td;
  scenario_rotation(td.path);
  const auto files = sorted_names(td.path);
  ASSERT_GE(files.size(), 2u);
  EXPECT_NE(files[0].find("audit-1.jsonl"), std::string::npos);
  const auto a = lines_of(slurp(files[0]));
  const auto b = lines_of(slurp(files[1]));
  EXPECT_NE(b[0].find("\"action\":\"audit.rotate\""), std::string::npos);
  const std::string last_hash = a.back().substr(a.back().size() - 75 + 9, 64);
  EXPECT_NE(b[0].find("\"prev\":\"" + last_hash + "\""), std::string::npos);
  const auto r = audit_verify_paths(files);
  EXPECT_TRUE(r.ok) << r.text();
  // The later file alone verifies from its anchor (the tail after a truncate).
  EXPECT_TRUE(audit_verify_paths({files[1]}).ok);
  // Wrong order and a missing middle file are caught.
  std::vector<std::string> rev(files.rbegin(), files.rend());
  EXPECT_FALSE(audit_verify_paths(rev).ok);
  if (files.size() >= 3) EXPECT_FALSE(audit_verify_paths({files.front(), files.back()}).ok);
  // A file that does not start with audit.rotate cannot follow another.
  const std::string second_wo_rotate = a.back() + "\n";
  EXPECT_FALSE(audit_verify({{"audit-1.jsonl", slurp(files[0])}, {"x.jsonl", second_wo_rotate}}).ok);
}

TEST(Audit, PartialTailRecovered) {
  TempDir td;
  scenario_recover(td.path);
  const auto files = sorted_names(td.path);
  ASSERT_EQ(files.size(), 1u);
  const auto ls = lines_of(slurp(files[0]));
  ASSERT_EQ(ls.size(), 6u);  // 3 + recover + 2
  EXPECT_NE(ls[3].find("\"action\":\"audit.recover\""), std::string::npos);
  EXPECT_NE(ls[3].find("\"detail\":{\"dropped_bytes\":"), std::string::npos);
  EXPECT_NE(ls[3].find("\"seq\":4,"), std::string::npos);
  const auto r = audit_verify_paths(files);
  EXPECT_TRUE(r.ok) << r.text();
  EXPECT_EQ(r.entries, 6u);
  // The recover entry chains from the last whole entry.
  const std::string h3 = ls[2].substr(ls[2].size() - 75 + 9, 64);
  EXPECT_NE(ls[3].find("\"prev\":\"" + h3 + "\""), std::string::npos);
}

TEST(Audit, PartialTailWithoutNewlineOnly) {
  TempDir td;
  Clock clk;
  { auto log = AuditLog::open(cfg_for(td.path, clk)); ASSERT_TRUE(log.has_value()); fill(*log, 0, 2); }
  // A tail that is a whole line missing only its newline is also dropped (it was never complete).
  std::string b = slurp(td.path + "/audit-1.jsonl");
  b.pop_back();
  spit(td.path + "/audit-1.jsonl", b);
  auto log = AuditLog::open(cfg_for(td.path, clk));
  ASSERT_TRUE(log.has_value());
  EXPECT_GT(log->recovered_bytes(), 0u);
  EXPECT_EQ(log->seq(), 2u);  // entry 1, then audit.recover as seq 2
  EXPECT_TRUE(audit_verify_paths(sorted_names(td.path)).ok);
}

TEST(Audit, CrashRightAfterRotationFallsBackToPredecessor) {
  TempDir td;
  scenario_rotation(td.path);
  auto files = sorted_names(td.path);
  ASSERT_GE(files.size(), 2u);
  // Simulate a crash while the newest file's first line was being written.
  spit(files.back(), "{\"v\":1,\"seq\":99,\"ts\":\"2026", false);
  Clock clk;
  AuditConfig c = cfg_for(td.path, clk);
  c.max_bytes = 800;
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  EXPECT_GT(log->recovered_bytes(), 0u);
  ASSERT_TRUE(log->append(ent("drain")).has_value());
  const auto r = audit_verify_paths(sorted_names(td.path));
  EXPECT_TRUE(r.ok) << r.text();
}

// Recovery scans back to the last line that verifies and drops the rest.
TEST(Audit, UnverifiableTailEntriesAreDroppedAndRecovered) {
  TempDir td;
  scenario_basic(td.path);
  std::string b = slurp(td.path + "/audit-1.jsonl");
  const auto ls = lines_of(b);
  // Corrupt entries 3 and 4 (the last two), and add a >64 KiB partial line after them.
  std::string bad = ls[0] + "\n" + ls[1] + "\n" + ls[2] + "\n" + ls[3] + "\n";
  bad[ls[0].size() + ls[1].size() + 2 + 20] ^= 1;
  bad[ls[0].size() + ls[1].size() + ls[2].size() + 3 + 20] ^= 1;
  bad += std::string(100 * 1024, 'x');
  spit(td.path + "/audit-1.jsonl", bad);
  Clock clk;
  auto log = AuditLog::open(cfg_for(td.path, clk));
  ASSERT_TRUE(log.has_value());
  EXPECT_EQ(log->recovered_bytes(), bad.size() - (ls[0].size() + ls[1].size() + 2));
  EXPECT_EQ(log->seq(), 3u);  // entries 1, 2, then audit.recover
  const auto r = audit_verify_paths(sorted_names(td.path));
  EXPECT_TRUE(r.ok) << r.text();
  EXPECT_EQ(r.entries, 3u);
}

// The old file is fsynced before the new file exists.
TEST(Audit, RotationFsyncsOldFileBeforeCreatingNew) {
  TempDir td;
  Clock clk;
  AuditConfig c = cfg_for(td.path, clk);
  c.max_bytes = 800;
  c.fsync_interval_ms = ~0ull >> 2;  // no batched fsync: only the rotation's calls reach the hook
  std::vector<std::pair<std::string, std::size_t>> calls;  // fsynced file, number of audit files then
  const std::string dir = td.path;
  c.fsync_fn = [&](int fd) {
    char link[64], buf[512];
    std::snprintf(link, sizeof link, "/proc/self/fd/%d", fd);
    const auto n = ::readlink(link, buf, sizeof buf - 1);
    calls.emplace_back(n > 0 ? fs::path(std::string(buf, static_cast<std::size_t>(n))).filename().string() : "?",
                       list_audit_files(dir).size());
    return 0;
  };
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  fill(*log, 0, 3);  // rotates at least once
  ASSERT_FALSE(calls.empty());
  EXPECT_EQ(calls[0].first, "audit-1.jsonl");
  EXPECT_EQ(calls[0].second, 1u) << "the old file must be fsynced while the new file does not exist yet";
}

// Anchor detects tail truncation, rewrite and oldest-file deletion; result carries the range.
TEST(Audit, AnchorDetectsTruncationRewriteAndDeletion) {
  TempDir td;
  scenario_rotation(td.path);
  const auto files = sorted_names(td.path);
  const auto base = audit_verify_paths(files);
  ASSERT_TRUE(base.ok);
  EXPECT_EQ(base.first_seq, 1u);
  EXPECT_EQ(base.last_seq, base.entries);
  EXPECT_EQ(base.head.size(), 64u);
  AuditAnchor tip{base.last_seq, base.head};
  EXPECT_TRUE(audit_verify_paths(files, &tip).ok);
  AuditAnchor mid{3, ""};
  {  // hash of seq 3 from the lines
    std::string all;
    for (const auto& f : files) all += slurp(f);
    for (const auto& l : lines_of(all))
      if (l.find("\"seq\":3,") != std::string::npos) mid.head = l.substr(l.size() - 75 + 9, 64);
  }
  EXPECT_TRUE(audit_verify_paths(files, &mid).ok);
  // Tail truncation: drop the last file.
  std::vector<std::string> shorter(files.begin(), files.end() - 1);
  EXPECT_TRUE(audit_verify_paths(shorter).ok);  // without an anchor it is invisible
  const auto cut = audit_verify_paths(shorter, &tip);
  EXPECT_FALSE(cut.ok);
  EXPECT_NE(cut.message.find("tail truncated"), std::string::npos) << cut.text();
  // Oldest file deleted.
  std::vector<std::string> rest(files.begin() + 1, files.end());
  EXPECT_TRUE(audit_verify_paths(rest).ok);
  AuditAnchor first1{1, base.head};
  for (const auto& l : lines_of(slurp(files[0]))) first1.head = l.substr(l.size() - 75 + 9, 64);
  const auto del = audit_verify_paths(rest, &first1);
  EXPECT_FALSE(del.ok);
  EXPECT_NE(del.message.find("oldest"), std::string::npos) << del.text();
  // Wrong head at a right seq.
  AuditAnchor wrong{3, std::string(64, 'a')};
  EXPECT_FALSE(audit_verify_paths(files, &wrong).ok);
}

// A failed fsync after the line was written returns ok; sync() reports and retries.
TEST(Audit, FsyncFailureKeepsEntryAndStaysDirty) {
  TempDir td;
  Clock clk;
  AuditConfig c = cfg_for(td.path, clk);
  c.fsync_every_entry = true;
  bool fail = true;
  int calls = 0;
  c.fsync_fn = [&](int) { ++calls; return fail ? -1 : 0; };
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  ASSERT_TRUE(log->append(ent("drain")).has_value());
  EXPECT_EQ(log->seq(), 1u);
  EXPECT_FALSE(log->sync().has_value());  // still dirty, error reported
  fail = false;
  EXPECT_TRUE(log->sync().has_value());
  const int after = calls;
  EXPECT_TRUE(log->sync().has_value());
  EXPECT_EQ(calls, after);  // clean now: no further fsync
  EXPECT_TRUE(audit_verify_paths(sorted_names(td.path)).ok);
}

// A short write whose rollback fails reopens through recovery on the next append.
TEST(Audit, FailedRollbackReopensThroughRecovery) {
  TempDir td;
  Clock clk;
  AuditConfig c = cfg_for(td.path, clk);
  bool inject = false;
  c.write_fn = [&](int fd, const void* p, std::size_t n) -> long {
    if (!inject) return static_cast<long>(::write(fd, p, n));
    inject = false;
    const long half = static_cast<long>(::write(fd, p, n / 2));  // short write, then the next call fails
    (void)half;
    errno = EIO;
    return -1;
  };
  bool rollback_fails = false;
  c.ftruncate_fn = [&](int fd, std::uint64_t len) { return rollback_fails ? -1 : ::ftruncate(fd, static_cast<off_t>(len)); };
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  ASSERT_TRUE(log->append(ent("drain")).has_value());
  inject = true;
  rollback_fails = true;
  EXPECT_FALSE(log->append(ent("drain")).has_value());
  EXPECT_EQ(log->seq(), 1u);
  rollback_fails = false;
  ASSERT_TRUE(log->append(ent("drain")).has_value());  // recovery drops the half line, writes audit.recover
  EXPECT_GT(log->recovered_bytes(), 0u);
  EXPECT_EQ(log->seq(), 3u);
  const auto r = audit_verify_paths(sorted_names(td.path));
  EXPECT_TRUE(r.ok) << r.text();
  EXPECT_EQ(r.entries, 3u);
}

// One body build (one clock read) per append without rotation.
TEST(Audit, OneClockReadPerAppend) {
  TempDir td;
  int reads = 0;
  AuditConfig c;
  c.dir = td.path;
  c.src = node_src();
  c.now_ms = [&] { return 1767225600000ull + static_cast<std::uint64_t>(++reads); };
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  const int before = reads;
  fill(*log, 0, 5);
  EXPECT_EQ(reads - before, 5);
}

// The verifier type-checks string fields and quotes; a second writer is refused.
TEST(Audit, VerifierTypeChecksFields) {
  TempDir td;
  scenario_basic(td.path);
  const auto ls = lines_of(slurp(td.path + "/audit-1.jsonl"));
  auto reseal = [](std::string line, const std::string& from, const std::string& to) {
    std::string body = line.substr(0, line.size() - 75) + "}";
    const auto p = body.find(from);
    EXPECT_NE(p, std::string::npos) << from;
    body.replace(p, from.size(), to);
    return body.substr(0, body.size() - 1) + ",\"hash\":\"" + to_hex(sha256(body)) + "\"}";
  };
  // Single-entry file for each mutation (seq 1, valid hash, only the type is wrong).
  const std::vector<std::pair<std::string, std::string>> muts = {
      {"\"actor\":\"spiffe://lab/ops/alice\"", "\"actor\":7"},
      {"\"role\":\"operator\"", "\"role\":null"},
      {"\"action\":\"bundle.apply\"", "\"action\":true"},
      {"\"target\":\"node:3\"", "\"target\":{}"},
      {"\"result\":\"ok\"", "\"result\":[]"},
      {"\"reason\":\"accepted\"", "\"reason\":1"},
      {"\"ts\":\"2026-01-01T00:00:00.373Z\"", "\"ts\":1767225600373"},
      {"\"src\":{\"node_id\":7,\"host\":\"hostA\"", "\"src\":{\"node_id\":7,\"host\":5"},
      {"\"src\":{\"node_id\":7,", "\"src\":{\"node_id\":\"7\","},
      {"\"detail\":{", "\"detail\":["},
      {"\"prev\":\"0000000000000000000000000000000000000000000000000000000000000000\"",
       "\"prev\":00000000000000000000000000000000000000000000000000000000000000000"},
  };
  for (const auto& [from, to] : muts) {
    const std::string forged = reseal(ls[0], from, to);
    const auto r = audit_verify({{"f", forged + "\n"}});
    EXPECT_FALSE(r.ok) << to;
  }
  EXPECT_TRUE(audit_verify({{"f", ls[0] + "\n"}}).ok);
}

TEST(Audit, SecondWriterOnSameDirIsRefused) {
  TempDir td;
  Clock clk;
  auto a = AuditLog::open(cfg_for(td.path, clk));
  ASSERT_TRUE(a.has_value());
  auto b = AuditLog::open(cfg_for(td.path, clk));
  ASSERT_FALSE(b.has_value());
  EXPECT_EQ(b.error().code, miracache::ErrorCode::Busy);
}

// Batching is observable through the fsync hook.
TEST(Audit, BatchedFsyncSkipsWithinIntervalAndSyncFlushes) {
  TempDir td;
  Clock clk;  // +250 ms per entry
  AuditConfig c = cfg_for(td.path, clk);
  c.fsync_interval_ms = 1000;
  int calls = 0;
  c.fsync_fn = [&](int fd) { ++calls; return ::fsync(fd); };
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  fill(*log, 0, 8);  // 2000 ms of entries
  EXPECT_GE(calls, 1);
  EXPECT_LE(calls, 3);
  const int before = calls;
  ASSERT_TRUE(log->sync().has_value());
  ASSERT_TRUE(log->sync().has_value());
  EXPECT_LE(calls - before, 1);  // at most the one flush; a clean log needs none
  EXPECT_TRUE(audit_verify_paths(sorted_names(td.path)).ok);
}


TEST(Audit, TotalCapTruncates) {
  TempDir td;
  Clock clk;
  AuditConfig c = cfg_for(td.path, clk);
  c.max_bytes = 800;
  c.max_total_bytes = 4000;
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  fill(*log, 0, 60);
  EXPECT_EQ(log->effective_max_total_bytes(), 4000u);
  const auto files = sorted_names(td.path);
  std::uint64_t total = 0;
  for (const auto& f : files) total += fs::file_size(f);
  EXPECT_LE(total, 4000u);
  // The first file was deleted: it starts after seq 1 and verifies from there.
  EXPECT_EQ(files[0].find("audit-1.jsonl"), std::string::npos);
  bool saw_truncate = false;
  for (const auto& f : files)
    for (const auto& l : lines_of(slurp(f)))
      if (l.find("\"action\":\"audit.truncate\"") != std::string::npos) saw_truncate = true;
  EXPECT_TRUE(saw_truncate);
  const auto r = audit_verify_paths(files);
  EXPECT_TRUE(r.ok) << r.text();
  EXPECT_EQ(log->seq(), r.entries == 0 ? 0u : log->seq());
  // Naming a first_kept_seq that matches no file is rejected: forge it.
  for (const auto& f : files) {
    std::string b = slurp(f);
    const auto p = b.find("\"action\":\"audit.truncate\"");
    if (p == std::string::npos) continue;
    const auto ls = lines_of(b);
    for (std::size_t i = 0; i < ls.size(); ++i) {
      if (ls[i].find("audit.truncate") == std::string::npos) continue;
      std::string body = ls[i].substr(0, ls[i].size() - 75) + "}";
      const auto q = body.find("\"first_kept_seq\":");
      body.replace(q + 17, body.find(',', q) - q - 17, "999999");
      // Re-hashing breaks the next link, but the truncate check or the link must fail either way.
      std::string forged = body.substr(0, body.size() - 1) + ",\"hash\":\"" + to_hex(sha256(body)) + "\"}";
      std::string nb;
      for (std::size_t j = 0; j < ls.size(); ++j) nb += (j == i ? forged : ls[j]) + "\n";
      std::vector<AuditFileBytes> in;
      for (const auto& g : files) in.push_back({g, g == f ? nb : slurp(g)});
      EXPECT_FALSE(audit_verify(in).ok);
      return;
    }
  }
}

TEST(Audit, TotalCapNeverExceedsTenPercentOfFree) {
  TempDir td;
  Clock clk;
  AuditConfig c = cfg_for(td.path, clk);
  c.max_total_bytes = ~0ull >> 1;  // absurd
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  EXPECT_LT(log->effective_max_total_bytes(), ~0ull >> 1);
  EXPECT_LE(log->effective_max_bytes(), log->effective_max_total_bytes() / 4);
}

TEST(Audit, OversizeEntryRejectedStateIntact) {
  TempDir td;
  Clock clk;
  auto log = AuditLog::open(cfg_for(td.path, clk));
  ASSERT_TRUE(log.has_value());
  ASSERT_TRUE(log->append(ent("drain")).has_value());
  const std::string head = log->head();
  AuditEntry big = ent("drain", "ok", std::string(20000, 'x'));
  EXPECT_FALSE(log->append(big).has_value());
  EXPECT_EQ(log->seq(), 1u);
  EXPECT_EQ(log->head(), head);
  ASSERT_TRUE(log->append(ent("drain")).has_value());
  EXPECT_TRUE(audit_verify_paths(sorted_names(td.path)).ok);
}


// ---- coalescer -----------------------------------------------------------------------------------

TEST(AuditCoalescer, PerIdentityActionResultPerSecond) {
  AuditCoalescer co;
  AuditEntry a = ent("admin.call", "denied", "role operator required");
  AuditEntry b = a;
  b.actor = "spiffe://lab/ops/bob";
  AuditEntry c = a;
  c.result = "error";
  for (int i = 0; i < 100; ++i) co.add(a, 5000 + static_cast<std::uint64_t>(i));
  for (int i = 0; i < 3; ++i) co.add(b, 5100);
  co.add(c, 5200);
  EXPECT_TRUE(co.flush(5999).empty());  // second 5 not over yet
  co.add(a, 6001);                      // next second: its own window
  auto out = co.flush(6500);
  ASSERT_EQ(out.size(), 3u);
  std::uint64_t sum = 0;
  for (const auto& e : out) sum += e.count;
  EXPECT_EQ(sum, 104u);
  bool saw100 = false;
  for (const auto& e : out) saw100 |= (e.actor == a.actor && e.result == "denied" && e.count == 100);
  EXPECT_TRUE(saw100);
  auto rest = co.flush(7000);
  ASSERT_EQ(rest.size(), 1u);
  EXPECT_EQ(rest[0].count, 1u);
  EXPECT_TRUE(co.flush(9000, true).empty());
}

TEST(AuditCoalescer, KeyCapFoldsIntoOther) {
  AuditCoalescer co(4);
  for (int i = 0; i < 50; ++i) {
    AuditEntry e = ent("ticket.refused", "denied", "rate");
    e.actor = "spiffe://lab/p" + std::to_string(i);
    co.add(e, 1000);
  }
  auto out = co.flush(2000);
  EXPECT_LE(out.size(), 5u);
  std::uint64_t sum = 0;
  for (const auto& e : out) sum += e.count;
  EXPECT_EQ(sum, 50u);
}

TEST(AuditCoalescer, FloodProducesBoundedLog) {
  TempDir td;
  Clock clk;
  auto log = AuditLog::open(cfg_for(td.path, clk));
  ASSERT_TRUE(log.has_value());
  AuditCoalescer co;
  for (int i = 0; i < 100000; ++i) co.add(ent("admin.call", "denied", "x"), 1000 + static_cast<std::uint64_t>(i % 1000));
  for (const auto& e : co.flush(10000, true)) ASSERT_TRUE(log->append(e).has_value());
  EXPECT_EQ(log->seq(), 1u);
  EXPECT_NE(slurp(td.path + "/audit-1.jsonl").find("\"count\":100000,"), std::string::npos);
}

// ---- goldens (every file) ----------------------------------------------------------------

TEST(AuditGolden, Regenerate) {
  if (!std::getenv("MIRA_AUDIT_GOLDEN_WRITE")) GTEST_SKIP() << "set MIRA_AUDIT_GOLDEN_WRITE=1 to rewrite the goldens";
  for (const auto& s : kScenarios) {
    for (const auto& [rel, bytes] : produce(s)) {
      fs::create_directories(fs::path(golden_root() + "/" + rel).parent_path());
      spit(golden_root() + "/" + rel, bytes);
    }
  }
}

TEST(AuditGolden, WriterReproducesGoldens) {
  if (std::getenv("MIRA_AUDIT_GOLDEN_WRITE")) GTEST_SKIP();
  for (const auto& s : kScenarios) {
    for (const auto& [rel, bytes] : produce(s)) {
      EXPECT_EQ(slurp(golden_root() + "/" + rel), bytes) << rel;
    }
  }
}

// The C++ writer, fed the six entries the Go writer used for go_sample.jsonl (controller/audit/audit_test.go
// sampleEntries), produces the same bytes: both directions are byte-exact, not only "the verifier accepts the file".
TEST(AuditGolden, CppWriterReproducesGoSample) {
  TempDir td;
  Clock clk;  // first entry 00:00:00.373Z, +250 ms each: the Go fixedClock
  AuditConfig c = cfg_for(td.path, clk);
  c.src = {true, 0, "ctl-1.example", "10.0.0.2:9470"};
  auto log = AuditLog::open(std::move(c));
  ASSERT_TRUE(log.has_value());
  auto mk = [](const char* actor, const char* role, const char* action, const char* target, const char* result, std::string reason) {
    AuditEntry e;
    e.actor = actor;
    e.role = role;
    e.action = action;
    e.target = target;
    e.result = result;
    e.reason = std::move(reason);
    return e;
  };
  AuditEntry e1 = mk("spiffe://lab/ops/alice", "operator", "bundle.publish", "cluster", "ok", "join 10.0.0.4:7471");
  e1.generation = 12;
  e1.detail = {{"keys", std::string("membership.nodes,config.engine")}, {"node_ids", std::string("1,2,3,4")}, {"epoch", std::uint64_t{5}}};
  AuditEntry e2 = mk("spiffe://lab/ops/alice", "operator", "config.set", "config", "error",
                     "dry run rejected: <schema> & \"quotes\" \\ back\tslash\nnewline \x01 \x7f \xC3\xA9 "
                     "\xE6\x97\xA5\xE6\x9C\xAC \xE2\x80\xA8 \xE2\x80\xA9 bad:\xff\xfe end");
  AuditEntry e3 = mk("spiffe://lab/ops/bob", "viewer", "api.call", "POST /v1/rollback", "denied", "role_required operator");
  e3.count = 41;
  AuditEntry e4 = mk("spiffe://lab/ops/alice", "operator", "config.rollback", "generation:9", "ok", "config only");
  e4.generation = 13;
  e4.detail = {{"from_generation", std::uint64_t{9}}, {"keys", std::string("config.engine")}};
  AuditEntry e5 = mk("local", "operator", "member.remove", "node:9", "ok", "fail_timeout");
  e5.generation = 14;
  AuditEntry e6 = mk("spiffe://lab/security/carol", "security-admin", "principals.set", "sec", "denied", "sec routes deny by default until RB3");
  for (const auto* e : {&e1, &e2, &e3, &e4, &e5, &e6}) ASSERT_TRUE(log->append(*e).has_value());
  EXPECT_EQ(slurp(td.path + "/audit-1.jsonl"), slurp(golden_root() + "/go_sample.jsonl"));
}

TEST(AuditGolden, VerifyEveryFile) {
  // Each directory holding audit-<seq>.jsonl files is one chain; every other *.jsonl (basic,
  // controller, and go_sample.jsonl) is a chain of its own.
  std::size_t chains = 0, files = 0;
  bool saw_go_style_escape = false;
  std::vector<fs::path> dirs{golden_root()};
  for (const auto& e : fs::recursive_directory_iterator(golden_root()))
    if (e.is_directory()) dirs.push_back(e.path());
  for (const auto& d : dirs) {
    std::vector<std::string> set = list_audit_files(d.string());
    if (!set.empty()) {
      const auto r = audit_verify_paths(set);
      EXPECT_TRUE(r.ok) << d << ": " << r.text();
      ++chains;
      files += set.size();
    }
    for (const auto& e : fs::directory_iterator(d)) {
      if (!e.is_regular_file() || e.path().extension() != ".jsonl") continue;
      std::uint64_t dummy = 0;
      const std::string name = e.path().filename().string();
      const bool in_set = name.rfind("audit-", 0) == 0 && !set.empty();
      (void)dummy;
      if (in_set) continue;
      const auto r = audit_verify_paths({e.path().string()});
      EXPECT_TRUE(r.ok) << e.path() << ": " << r.text();
      ++chains;
      ++files;
      const std::string b = slurp(e.path().string());
      if (name == "basic.jsonl") {
        saw_go_style_escape = b.find("<operator> &") != std::string::npos && b.find("\\u2028") != std::string::npos &&
                              b.find("\xC3\xA9") != std::string::npos;
      }
    }
  }
  EXPECT_GE(chains, 5u);
  EXPECT_GE(files, 8u);
  EXPECT_TRUE(saw_go_style_escape);
}

TEST(AuditGolden, RecoverGoldenHasRecoverEntry) {
  const std::string b = slurp(golden_root() + "/recover/audit-1.jsonl");
  EXPECT_NE(b.find("\"action\":\"audit.recover\""), std::string::npos);
  const std::string t = slurp(list_audit_files(golden_root() + "/truncate").front());
  EXPECT_EQ(t.find("\"seq\":1,"), std::string::npos);  // the first kept file starts after seq 1
}
