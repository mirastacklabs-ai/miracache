// SPDX-License-Identifier: Apache-2.0
// The client's bundle watcher.
//
// It pulls the signed cluster bundle from the memory nodes' admin listeners (`GET /v1/bundle?after=G`),
// verifies it (both Ed25519 signatures, role binding, the shared floor file) and hands a verified
// `MembershipSnap` to a callback. It changes nothing else: placement and the node tables belong to the bundle membership code.
//
//   * Floor vs applied. The floor is the shared max-only file `<state_dir>/bundle-floor`: it only
//     rejects older bundles. The applied generation is per process, in memory. A bundle is accepted when
//     it is >= the floor (an equal one with an equal hash is fine) and newer than this process's applied
//     generation, so a second process on the same host, or a restart, applies the current generation too.
//   * Start-up. The first fetch polls EVERY endpoint without `after` and takes the highest valid
//     bundle: one stale endpoint cannot pin a process with an empty state_dir to an old bundle.
//   * Poll every `poll_ms` (30 s), one endpoint per poll, round-robin. Once a bundle is applied its
//     `nodes[].admin` addresses come first in the list (the configured endpoints stay as a fallback).
//   * Wake. `on_reply_generation()` is cheap and thread-safe; call it with the `bundle_gen_lo` of any
//     reply frame. A value ahead of the applied generation wakes the watcher once per value (edge
//     triggered); the first fetch goes to the node that replied, then the other endpoints in turn
//     (a 304 while a higher generation is known rotates), at most one full cycle, then the chase ends.
//     Fetches are at least `min_interval_ms` apart (200 ms) and back off exponentially on failure.
//   * push_envelope(admin): POSTs the current envelope to a lagging or newly added node; once per success
//     per (node, generation), exponential backoff (1 s up to 30 s) on failure.
//   * The trust file is re-read when its stat changes; a bad new file keeps the old keys.
//   * Logs about a memory node carry its ID, hostname and address (from the bundle once known).
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "control/bundle.h"
#include "control/floor_state.h"
#include "control/trust_keys.h"
#include "runtime/keepalive.h"
#include "src/admin_http.h"
#include "util/clock.h"
#include "util/random.h"

namespace miracache {

// A verified bundle plus the exact envelope bytes (so a client can push it to a lagging node).
struct MembershipSnap {
  control::BundleView view;
  std::string envelope;
  std::uint64_t generation() const { return view.body.generation; }
};
using MembershipSnapPtr = std::shared_ptr<const MembershipSnap>;
// Called on the watcher thread (or the poll_now() caller), once per applied generation, UNDER round_mu_ (not mu_):
// it must hand off (queue the work) and return at once: no I/O, no push_envelope, no poll_now() inside.
using MembershipFn = std::function<void(MembershipSnapPtr)>;

struct BundleWatcherOptions {
  std::vector<std::string> endpoints;  // memory-node admin addresses "host:port" (bootstrap list)
  std::string trust_keys;              // trust file path
  std::string state_dir;               // shared floor directory
  std::string cert, key, ca;           // admin mTLS identity (PEM paths; key mode 0600)
  unsigned poll_ms = 30000;
  unsigned min_interval_ms = 200;  // between two fetches
  unsigned backoff_min_ms = 1000;  // failure backoff 1 s .. 30 s (equal jitter when `random` is set)
  unsigned backoff_max_ms = 30000;
  unsigned io_timeout_ms = 2000;  // per HTTPS call
  Random* random = nullptr;
  MembershipFn on_bundle;
  std::function<void(const std::string&)> log;  // optional; one line per event, no trailing newline
};

struct BundleWatcherStats {
  std::uint64_t fetches = 0;        // GET /v1/bundle calls attempted
  std::uint64_t ok = 0;             // 200 with a bundle
  std::uint64_t not_modified = 0;   // 304
  std::uint64_t failed = 0;         // transport / TLS / unexpected status / no bundle yet
  std::uint64_t rejected = 0;       // a bundle that failed verification or the floor
  std::array<std::uint64_t, 12> rejected_by_reason{};  // indexed by control::Reject
  std::uint64_t not_newer = 0;      // valid but not newer than this process's applied generation
  std::uint64_t applied = 0;        // generations handed to the callback
  std::uint64_t wakes = 0;          // reply generations that started a chase
  std::uint64_t wakes_coalesced = 0;  // reply generations already chased (or not ahead): no wake
  std::uint64_t pushes_ok = 0;
  std::uint64_t push_failed = 0;
};

class BundleWatcher {
 public:
  // Loads the trust file (it must parse), opens the floor directory and the HTTPS client.
  static Expected<std::unique_ptr<BundleWatcher>> create(BundleWatcherOptions o, const Clock& clock);
  ~BundleWatcher();

  void start();  // starts the thread (idempotent)
  void stop();   // joins it (idempotent)

  // Thread-safe, no I/O. `bundle_gen_lo` is the low 32 bits of a generation seen in a reply frame;
  // `from_admin` is the replying node's admin address ("" = unknown).
  void on_reply_generation(std::uint32_t bundle_gen_lo, const std::string& from_admin = {});

  // One fetch step (the start-up sweep over all endpoints before the first bundle, else one fetch),
  // exactly what the thread runs. For tests and callers that want a synchronous refresh; serialised
  // with the thread. Returns the error of a failed step; a 304 is success.
  Status poll_now();

  MembershipSnapPtr current() const;           // null until the first bundle is applied
  std::uint64_t applied_generation() const;    // 0 until then

  // POST the current envelope to `admin`. Ok = the node has it at this generation (now or earlier);
  // Busy = backing off after a failure; NotFound = nothing applied yet. Blocks up to io_timeout_ms:
  // never call it under a lock the data path takes.
  // Ok(Pushed): the node applied it. Ok(AlreadyPushed): done earlier for this (node, generation). Ok(NodeAhead): the
  // node answered 409 generation_lower / equal_generation, so it is ahead (or diverged): no re-POST for this
  // generation, and a fetch from that node is woken. Errors: Busy (backing off), NotFound (nothing applied yet),
  // LinkDown / Timeout / ... (the node is not ready).
  enum class PushOutcome : std::uint8_t { Pushed, AlreadyPushed, NodeAhead };
  Expected<PushOutcome> push_envelope(const std::string& admin);

  BundleWatcherStats stats() const;

  // The text of `GET /v1/bundle` target for tests.
  static std::string bundle_target(std::uint64_t after);

 private:
  BundleWatcher(BundleWatcherOptions o, const Clock& clock, std::shared_ptr<HttpsClient> http, control::FloorState floor,
                control::TrustKeys trust);

  enum class Step { Applied, NotModified, Nothing, Failed };
  Step step(Status& why);                 // round_mu_ held
  Step sweep_all(Status& why);            // start-up: every endpoint, highest valid bundle wins
  Step fetch_one(const std::string& admin, Status& why);  // steady state: GET ?after=applied
  // Format, role binding, both signatures, TOML, then the floor. Counts a reject by reason.
  bool verify(const std::string& envelope, const std::string& admin, control::BundleView& out, Status& why);
  enum class Commit { Applied, NotNewer, Error };
  // Newer than this process's applied generation: persist to the floor file, publish, call back.
  Commit commit(control::BundleView&& v, std::string&& envelope, const std::string& admin, Status& why);
  Step finish_step(Step s, const Status& why);  // mu_ NOT held: bookkeeping after a step
  Step do_step(Status& why);
  template <class F>
  void with_stats(F f) {
    std::lock_guard lk(mu_);
    f(stats_);
  }
  void maybe_reload_trust();
  std::vector<std::string> targets();     // round_mu_ held
  std::string describe(const std::string& admin) const;
  void note(const std::string& line) const;
  Nanos backoff_delay(unsigned streak);
  void tick();                           // the KeepaliveThread callback
  unsigned next_wait_ms();               // mu_ NOT held: when tick() should run next (always >= 1)

  BundleWatcherOptions o_;
  const Clock& clock_;
  std::shared_ptr<HttpsClient> http_;
  control::FloorState floor_;

  // ---- round state (round_mu_) ----
  std::mutex round_mu_;
  control::TrustKeys trust_;
  std::uint64_t trust_stamp_ = 0;  // stat fingerprint of the trust file
  std::size_t cursor_ = 0;         // next endpoint to poll
  std::vector<std::string> bundle_admins_;  // nodes[].admin of the applied bundle

  // ---- shared (mu_) ----
  mutable std::mutex mu_;
  MembershipSnapPtr snap_;
  std::uint64_t applied_ = 0;
  std::uint64_t wake_seq_ = 0;
  bool chase_active_ = false;
  bool chase_seen_ = false;        // chased_lo_ is meaningful
  std::uint32_t chased_lo_ = 0;    // last generation value that started a chase
  std::string hint_;               // replying node of the current chase (consumed by the first step)
  unsigned chase_steps_ = 0;       // steps left in the current chase
  std::size_t n_targets_ = 1;      // endpoints known (bounds a chase to one cycle)
  // Lock-free mirrors for the data-path fast path of on_reply_generation().
  std::atomic<std::uint64_t> applied_fast_{0};  // = applied_
  std::atomic<std::uint64_t> chased_fast_{0};   // 0 = none, else (1 << 32) | chased_lo_
  std::atomic<std::uint64_t> coalesced_fast_{0};  // wakes_coalesced counted without the lock
  std::atomic<bool> stopping_{false};
  void wake_fetch_from(const std::string& admin);  // start a chase at `admin` (no generation known)
  Nanos last_fetch_{0};
  bool fetched_any_ = false;
  Nanos backoff_until_{0};
  unsigned fail_streak_ = 0;
  Nanos next_poll_{0};
  bool retry_ = false;
  BundleWatcherStats stats_;

  // ---- push state (push_mu_) ----
  struct PushState {
    std::uint64_t ok_generation = 0;
    std::uint64_t ahead_generation = 0;  // the node answered 409 for this generation
    unsigned fails = 0;
    Nanos next_try{0};
  };
  std::mutex push_mu_;
  std::map<std::string, PushState> pushes_;

  KeepaliveThread ka_;  // last member: destroyed (joined) first

};

}  // namespace miracache
