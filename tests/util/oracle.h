// SPDX-License-Identifier: Apache-2.0
// The failed-operations oracle.
// Header only; written by MB6a, the first user. Later slices include it and do not edit it.
//
// Per key the client returns a KeyStatus (Hit, Miss, Committed, Skipped, Refused, Aborted, Timeout).
//
// STRICT (join, drain, reload and controller-outage tests, with all memory nodes and rails healthy):
//   allowed: Hit with exact bytes, Miss, Committed, Skipped (StaleEpoch, Draining, throttling, admission SKIP).
//   failed:  Refused, Aborted, Timeout; a Hit whose bytes differ from the last committed version of that key (payloads
//            are versioned), except a version still in flight or one whose store ended without Committed and was not
//            superseded (its outcome is unknown: it may have landed, run #200); a job without a Completion by
//            deadline + watchdog grace; a Completion whose engine buffers are never released; any API error return.
//   exception: a continuation Refused because its parent is nowhere is allowed only if the harness itself saw that
//            parent evicted or invalidated (note_parent_gone). The harness tracks every parent it committed.
// FAULT (node kill, rail loss, partition tests): STRICT, except that Refused and Timeout are also allowed for keys whose
//   whole owner set was not Up at submit, or whose op was in flight on the failed node or rail (the caller passes
//   `excused = true`). Aborted is excused under the same condition (Q1, option A: an op in flight on the killed or
//   restarting node ends Aborted when its connection goes); never for a healthy node. Excused Refused/Timeout/Aborted
//   are also counted apart (report(): excused{..}, excused_count()) so they stay visible.
//   For a fetch "in flight" means its lease deadline t_lease_granted + ttl - guard passed during the
//   outage. Wrong bytes are never allowed.
//
// Usage: one Oracle per test, shared by the traffic threads (it is thread-safe). A thread calls begin_store before it
// submits a store of version v and end_store(committed) when the completion came; on a fetch Hit it decodes the version
// from the bytes and calls on_fetch with it. The harness reports counts per status and per failure reason (report()).
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "miracache/types.h"

namespace miracache::testutil {

enum class OracleMode { Strict, Fault };

// The verdict on a bare status, without bytes: nullptr = allowed, else the failure reason. `excused` is the Fault-oracle
// exception (ignored in Strict).
inline const char* status_failure(KeyStatus s, OracleMode mode, bool excused = false) {
  switch (s) {
    case KeyStatus::Hit:
    case KeyStatus::Miss:
    case KeyStatus::Committed:
    case KeyStatus::Skipped:
      return nullptr;
    case KeyStatus::Refused:
    case KeyStatus::Timeout:
      if (mode == OracleMode::Fault && excused) return nullptr;
      return s == KeyStatus::Refused ? "refused" : "timeout";
    case KeyStatus::Aborted:
      if (mode == OracleMode::Fault && excused) return nullptr;
      return "aborted";
  }
  return "unknown_status";
}

class Oracle {
 public:
  explicit Oracle(OracleMode mode) : mode_(mode) {}

  // ---- the harness's own bookkeeping ----
  // Version `v` of `key` is about to be submitted (a Hit may show it before the completion arrives).
  void begin_store(const std::string& key, std::uint64_t v) {
    std::lock_guard lk(mu_);
    inflight_[key].insert(v);
    submitted_[key].insert(v);
  }
  // The store completed; `committed` = the key's status was Committed.
  void end_store(const std::string& key, std::uint64_t v, bool committed) {
    std::lock_guard lk(mu_);
    auto& f = inflight_[key];
    f.erase(v);
    if (!committed) maybe_[key].insert(v);  // run #200: no "Committed" is not "nothing landed" (see on_fetch)
    if (committed) {
      auto& last = last_[key];
      if (!last || *last < v) last = v;
      parent_gone_.erase(key);
    }
  }
  // The harness saw the key evicted or invalidated (a continuation whose parent is this key may be Refused).
  void note_parent_gone(const std::string& key) {
    std::lock_guard lk(mu_);
    parent_gone_.insert(key);
  }

  // ---- outcomes ----
  // A store result. `excused`: Fault mode only (see the header).
  void on_store(const std::string& key, KeyStatus s, bool excused = false, const std::string& ctx = {}) {
    std::lock_guard lk(mu_);
    tally(s, excused);
    stores_[key] += std::string(stores_[key].empty() ? "" : ",") + to_string(s);
    if (const char* why = status_failure(s, mode_, excused)) fail(key, why, "store " + ctx);
  }
  // A fetch / lookup result. `version` = the version decoded from the Hit's bytes (nullopt = the bytes decode to nothing
  // the harness ever wrote). A Hit is right if it shows the last committed version, one still in flight, or one whose
  // store ended without Committed and that no committed version superseded. Run #200: a store that ends Timeout or
  // Aborted (its deadline passed while PUT_COMMIT was out) may still have committed on the node: its outcome is
  // unknown, not "nothing stored", and a later Hit on exactly those bytes is right (the Timeout itself is still counted
  // as a failure in Strict mode). Wrong bytes stay wrong: a version never submitted for the key (unknown), one older than
  // the last committed (stale), or bytes that decode to nothing (undecodable).
  // `ctx`: free text for the failure details (what served it, when).
  void on_fetch(const std::string& key, KeyStatus s, std::optional<std::uint64_t> version = std::nullopt,
                bool excused = false, const std::string& ctx = {}) {
    std::lock_guard lk(mu_);
    tally(s, excused);
    if (const char* why = status_failure(s, mode_, excused)) return fail(key, why, "fetch " + ctx);
    if (s != KeyStatus::Hit) return;
    auto l = last_.find(key);
    const bool known = l != last_.end() && l->second.has_value();
    auto f = inflight_.find(key);
    auto m = maybe_.find(key);
    const bool maybe = version && m != maybe_.end() && m->second.count(*version) && (!known || *version > *l->second);
    const bool ok =
        version && ((known && *version == *l->second) || (f != inflight_.end() && f->second.count(*version)) || maybe);
    if (!ok) {
      std::ostringstream d;
      d << "fetch got_v=" << (version ? std::to_string(*version) : std::string("none"))
        << " last=" << (known ? std::to_string(*l->second) : std::string("none")) << " submitted={";
      if (auto u = submitted_.find(key); u != submitted_.end())
        for (auto v : u->second) d << v << ' ';
      d << "} store_statuses={" << stores_[key] << "} " << ctx;
      fail(key, version ? (known ? "wrong_bytes_stale" : "wrong_bytes_unknown") : "wrong_bytes_undecodable", d.str());
    }
  }
  // A continuation store (chain position > 0) result: a Refused is allowed iff the parent was seen gone.
  void on_continuation(const std::string& key, const std::string& parent, KeyStatus s, bool excused = false) {
    std::lock_guard lk(mu_);
    tally(s, excused);
    if (s == KeyStatus::Refused && parent_gone_.count(parent)) return;
    if (const char* why = status_failure(s, mode_, excused)) fail(key, why);
  }
  // A job that has no Completion by deadline + watchdog grace.
  void on_missing_completion(const std::string& what) {
    std::lock_guard lk(mu_);
    fail(what, "no_completion");
  }
  // A Completion whose engine buffers were never released.
  void on_unreleased_buffers(const std::string& what) {
    std::lock_guard lk(mu_);
    fail(what, "buffers_not_released");
  }
  // Any API error return (open, submit...).
  void on_api_error(const std::string& what) {
    std::lock_guard lk(mu_);
    fail(what, "api_error");
  }

  // ---- results ----
  std::uint64_t failed() const {
    std::lock_guard lk(mu_);
    return failed_;
  }
  std::uint64_t total() const {
    std::lock_guard lk(mu_);
    std::uint64_t t = 0;
    for (auto c : by_status_) t += c;
    return t;
  }
  std::uint64_t count_of(KeyStatus s) const {
    std::lock_guard lk(mu_);
    return by_status_[static_cast<std::size_t>(s)];
  }
  // Refused/Timeout/Aborted results the Fault oracle excused (op in flight on the failed node); 0 in Strict mode.
  std::uint64_t excused_count(KeyStatus s) const {
    std::lock_guard lk(mu_);
    return excused_[static_cast<std::size_t>(s)];
  }
  std::uint64_t reason_count(const std::string& reason) const {
    std::lock_guard lk(mu_);
    auto it = by_reason_.find(reason);
    return it == by_reason_.end() ? 0 : it->second;
  }
  // "ops=N failed=F hit=.. miss=.. committed=.. skipped=.. refused=.. aborted=.. timeout=.. reasons{..} first=<key: why>"
  std::string report() const {
    std::lock_guard lk(mu_);
    std::ostringstream o;
    std::uint64_t t = 0;
    for (auto c : by_status_) t += c;
    o << "oracle(" << (mode_ == OracleMode::Strict ? "strict" : "fault") << "): ops=" << t << " failed=" << failed_;
    for (std::size_t i = 0; i < by_status_.size(); ++i) o << ' ' << to_string(static_cast<KeyStatus>(i)) << '=' << by_status_[i];
    o << " reasons{";
    bool first = true;
    for (const auto& [r, c] : by_reason_) {
      o << (first ? "" : ",") << r << '=' << c;
      first = false;
    }
    o << '}';
    o << " excused{refused=" << excused_[static_cast<std::size_t>(KeyStatus::Refused)] << ",timeout="
      << excused_[static_cast<std::size_t>(KeyStatus::Timeout)] << ",aborted=" << excused_[static_cast<std::size_t>(KeyStatus::Aborted)] << '}';
    if (!first_failure_.empty()) o << " first=" << first_failure_;
    for (const auto& d : details_) o << "\n  failure: " << d;
    return o.str();
  }

 private:
  static constexpr std::size_t kMaxDetails = 8;
  void count(KeyStatus s) { ++by_status_[static_cast<std::size_t>(s)]; }
  // Counts the status; in Fault mode an excused Refused/Timeout/Aborted is also counted apart.
  void tally(KeyStatus s, bool excused) {
    count(s);
    if (mode_ == OracleMode::Fault && excused &&
        (s == KeyStatus::Refused || s == KeyStatus::Timeout || s == KeyStatus::Aborted))
      ++excused_[static_cast<std::size_t>(s)];
  }
  void fail(const std::string& what, const char* why, const std::string& detail = {}) {
    ++failed_;
    ++by_reason_[why];
    if (first_failure_.empty()) first_failure_ = what + ": " + why;
    if (details_.size() < kMaxDetails) details_.push_back(what + ": " + why + (detail.empty() ? "" : " [" + detail + "]"));
  }

  const OracleMode mode_;
  mutable std::mutex mu_;
  std::array<std::uint64_t, 7> by_status_{};
  std::array<std::uint64_t, 7> excused_{};
  std::map<std::string, std::uint64_t> by_reason_;
  std::uint64_t failed_ = 0;
  std::string first_failure_;
  std::vector<std::string> details_;                          // the first kMaxDetails failures, with their context
  std::map<std::string, std::set<std::uint64_t>> submitted_;  // key -> every version ever submitted (diagnostics)
  std::map<std::string, std::string> stores_;                 // key -> its store statuses so far (diagnostics)
  std::map<std::string, std::optional<std::uint64_t>> last_;  // key -> last committed version
  std::map<std::string, std::set<std::uint64_t>> inflight_;   // key -> versions submitted, not completed
  std::map<std::string, std::set<std::uint64_t>> maybe_;      // key -> versions whose store ended without Committed
  std::set<std::string> parent_gone_;
};

}  // namespace miracache::testutil
