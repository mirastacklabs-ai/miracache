// SPDX-License-Identifier: Apache-2.0
#include "src/bundle_watcher.h"

#include <sys/stat.h>

#include <algorithm>
#include <cstdlib>

namespace miracache {

namespace {

constexpr std::size_t kMaxBundleResponse = control::kMaxEnvelopeBytes + 16 * 1024;
constexpr std::size_t kMaxPushEntries = 1024;

// low-32-bit comparison: true when `a` is ahead of `b` (serial-number arithmetic).
bool ahead_lo(std::uint32_t a, std::uint32_t b) { return static_cast<std::int32_t>(a - b) > 0; }

std::uint64_t stat_stamp(const std::string& path) {
  struct stat st{};
  if (::stat(path.c_str(), &st) != 0) return 0;
#ifdef __APPLE__
  const std::uint64_t ns = static_cast<std::uint64_t>(st.st_mtimespec.tv_sec) * 1000000007ull + static_cast<std::uint64_t>(st.st_mtimespec.tv_nsec);
#else
  const std::uint64_t ns = static_cast<std::uint64_t>(st.st_mtim.tv_sec) * 1000000007ull + static_cast<std::uint64_t>(st.st_mtim.tv_nsec);
#endif
  return ns * 31 + static_cast<std::uint64_t>(st.st_size) * 7 + static_cast<std::uint64_t>(st.st_ino) + 1;
}

}  // namespace

std::string BundleWatcher::bundle_target(std::uint64_t after) {
  return after == 0 ? "/v1/bundle" : "/v1/bundle?after=" + std::to_string(after);
}

Expected<std::unique_ptr<BundleWatcher>> BundleWatcher::create(BundleWatcherOptions o, const Clock& clock) {
  if (o.endpoints.empty()) return Error{ErrorCode::InvalidArgument, "bundle watcher: endpoints is empty"};
  if (o.poll_ms == 0 || o.backoff_min_ms == 0 || o.backoff_max_ms < o.backoff_min_ms)
    return Error{ErrorCode::InvalidArgument, "bundle watcher: bad poll or backoff settings"};
  auto trust = control::load_trust_keys(o.trust_keys);
  if (!trust) return Error{ErrorCode::InvalidArgument, "bundle watcher: trust file does not load"};
  auto floor = control::FloorState::open(o.state_dir);
  if (!floor) return floor.error();
  HttpsOptions ho;
  ho.cert = o.cert;
  ho.key = o.key;
  ho.ca = o.ca;
  ho.io_timeout_ms = o.io_timeout_ms;
  ho.max_response = kMaxBundleResponse;
  auto http = HttpsClient::create(std::move(ho));
  if (!http) return http.error();
  return std::unique_ptr<BundleWatcher>(
      new BundleWatcher(std::move(o), clock, std::move(*http), std::move(*floor), std::move(*trust)));
}

BundleWatcher::BundleWatcher(BundleWatcherOptions o, const Clock& clock, std::shared_ptr<HttpsClient> http,
                             control::FloorState floor, control::TrustKeys trust)
    : o_(std::move(o)), clock_(clock), http_(std::move(http)), floor_(std::move(floor)), trust_(std::move(trust)) {
  trust_stamp_ = stat_stamp(o_.trust_keys);
  n_targets_ = o_.endpoints.size();
}

BundleWatcher::~BundleWatcher() { stop(); }

void BundleWatcher::start() {
  stopping_.store(false);
  ka_.start(1, [this] { tick(); });  // the first tick is at once; tick() sets every later wait
}

void BundleWatcher::stop() {
  stopping_.store(true);  // a start-up sweep in progress stops between endpoints
  ka_.stop();
  stopping_.store(false);  // joined: poll_now() works again
}

MembershipSnapPtr BundleWatcher::current() const {
  std::lock_guard lk(mu_);
  return snap_;
}

std::uint64_t BundleWatcher::applied_generation() const {
  std::lock_guard lk(mu_);
  return applied_;
}

BundleWatcherStats BundleWatcher::stats() const {
  std::lock_guard lk(mu_);
  BundleWatcherStats s = stats_;
  s.wakes_coalesced += coalesced_fast_.load(std::memory_order_relaxed);
  return s;
}

void BundleWatcher::note(const std::string& line) const {
  if (o_.log) o_.log(line);
}

// "node_id=N hostname=H addr=A" when the address belongs to a node of the applied bundle, else the address alone
// (a bootstrap endpoint not yet known by ID).
std::string BundleWatcher::describe(const std::string& admin) const {
  MembershipSnapPtr s = current();
  if (s)
    for (const auto& n : s->view.body.nodes)
      if (n.admin == admin) return "node_id=" + std::to_string(n.node_id) + " hostname=" + n.hostname + " addr=" + admin;
  return "node_id=unknown hostname=unknown addr=" + admin;
}

Nanos BundleWatcher::backoff_delay(unsigned streak) {
  const std::uint64_t lo = o_.backoff_min_ms, hi = o_.backoff_max_ms;
  std::uint64_t d = std::min<std::uint64_t>(hi, lo << std::min(streak, 20u));
  if (o_.random && d > 1) d = d / 2 + o_.random->below(d / 2 + 1);
  return std::chrono::milliseconds(d);
}

void BundleWatcher::maybe_reload_trust() {
  const std::uint64_t stamp = stat_stamp(o_.trust_keys);
  if (stamp == trust_stamp_) return;
  trust_stamp_ = stamp;
  auto t = control::load_trust_keys(o_.trust_keys);
  if (!t) {
    note("bundle: trust file changed but does not load; keeping the old keys");
    return;
  }
  trust_ = std::move(*t);
  note("bundle: trust file reloaded");
}

// ---- wake rule (P17) --------------------------------------------------------------------------
void BundleWatcher::on_reply_generation(std::uint32_t gen_lo, const std::string& from_admin) {
  // Fast path (data path, every reply frame): two relaxed atomic loads, no lock. A value that is not ahead of
  // the applied generation, or is the value already chased, returns here (edge trigger, P17).
  const std::uint64_t ap = applied_fast_.load(std::memory_order_acquire);
  if (ap == 0 || !ahead_lo(gen_lo, static_cast<std::uint32_t>(ap))) {
    coalesced_fast_.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  const std::uint64_t ch = chased_fast_.load(std::memory_order_acquire);
  if (ch != 0 && !ahead_lo(gen_lo, static_cast<std::uint32_t>(ch))) {  // not beyond the highest value already chased
    coalesced_fast_.fetch_add(1, std::memory_order_relaxed);
    return;
  }
  {
    std::lock_guard lk(mu_);
    if (applied_ == 0 || !ahead_lo(gen_lo, static_cast<std::uint32_t>(applied_)) || (chase_seen_ && !ahead_lo(gen_lo, chased_lo_))) {
      coalesced_fast_.fetch_add(1, std::memory_order_relaxed);
      return;
    }
    chase_seen_ = true;
    chased_lo_ = gen_lo;
    chased_fast_.store((std::uint64_t{1} << 32) | gen_lo, std::memory_order_release);
    chase_active_ = true;
    hint_ = from_admin;
    chase_steps_ = static_cast<unsigned>(n_targets_ + 1);  // the replying node, then one cycle
    ++wake_seq_;
    ++stats_.wakes;
  }
  ka_.kick();
}

// A node told us it is ahead (push_envelope got 409): fetch from it. Not edge-tracked by value; the caller
// does it once per (node, generation).
void BundleWatcher::wake_fetch_from(const std::string& admin) {
  {
    std::lock_guard lk(mu_);
    chase_active_ = true;
    hint_ = admin;
    chase_steps_ = static_cast<unsigned>(n_targets_ + 1);
    ++wake_seq_;
    ++stats_.wakes;
  }
  ka_.kick();
}

// ---- verify and commit ------------------------------------------------------------------------
bool BundleWatcher::verify(const std::string& envelope, const std::string& admin, control::BundleView& out, Status& why) {
  auto v = control::open_bundle(envelope, trust_);
  if (!v) {
    const auto reason = v.error().reason;
    with_stats([&](BundleWatcherStats& s) {
      ++s.rejected;
      ++s.rejected_by_reason[static_cast<std::size_t>(reason)];
    });
    note(std::string("bundle: rejected reason=") + control::reason_string(reason) + " from " + describe(admin));
    why = Error{ErrorCode::Corrupt, "bundle: rejected"};
    return false;
  }
  auto fl = floor_.load();
  if (!fl) {
    with_stats([&](BundleWatcherStats& s) { ++s.failed; });
    note("bundle: floor file unreadable; refusing bundles");
    why = fl.error();
    return false;
  }
  auto verdict = control::check_against_floor(*fl, *v, trust_.min_sec_generation());
  if (!verdict) {
    const auto reason = verdict.error().reason;
    with_stats([&](BundleWatcherStats& s) {
      ++s.rejected;
      ++s.rejected_by_reason[static_cast<std::size_t>(reason)];
    });
    note(std::string("bundle: rejected reason=") + control::reason_string(reason) + " from " + describe(admin));
    why = Error{ErrorCode::Corrupt, "bundle: rejected by the floor"};
    return false;
  }
  out = std::move(*v);
  return true;
}

BundleWatcher::Commit BundleWatcher::commit(control::BundleView&& v, std::string&& envelope, const std::string& admin,
                                            Status& why) {
  const std::uint64_t gen = v.body.generation;
  {
    std::lock_guard lk(mu_);
    if (applied_ != 0 && gen <= applied_) {
      ++stats_.not_newer;
      return Commit::NotNewer;
    }
  }
  // W06: commit re-runs the floor check under the exclusive lock. Apply = floor written; Replace = nothing to
  // write (equal generation, body and sec: another process, or an earlier run, applied this exact bundle).
  // Both publish. A reject means another process on this host already committed something at least as new:
  // do not publish ours; the step fails, and the retry (backoff) fetches the newer generation.
  auto fs = floor_.commit(v, trust_.min_sec_generation());
  if (!fs) {
    if (fs.error().rejected) {
      const auto reason = fs.error().reject.reason;
      with_stats([&](BundleWatcherStats& s) {
        ++s.rejected;
        ++s.rejected_by_reason[static_cast<std::size_t>(reason)];
      });
      note(std::string("bundle: floor commit lost reason=") + control::reason_string(reason) + " from " + describe(admin));
      why = Error{ErrorCode::Aborted, "bundle: another process committed a newer floor"};
    } else {
      with_stats([&](BundleWatcherStats& s) { ++s.failed; });
      note("bundle: cannot persist the floor; not applying");
      why = fs.error().io;
    }
    return Commit::Error;
  }
  auto snap = std::make_shared<MembershipSnap>();
  snap->view = std::move(v);
  snap->envelope = std::move(envelope);
  std::vector<std::string> admins;
  for (const auto& n : snap->view.body.nodes)
    if (!n.admin.empty() && std::find(admins.begin(), admins.end(), n.admin) == admins.end()) admins.push_back(n.admin);
  bundle_admins_ = admins;
  {
    std::lock_guard lk(mu_);
    snap_ = snap;
    applied_ = gen;
    applied_fast_.store(gen, std::memory_order_release);
    ++stats_.applied;
    std::size_t uni = admins.size();  // the union: an endpoint that is also a bundle admin counts once
    for (const auto& ep : o_.endpoints)
      if (std::find(admins.begin(), admins.end(), ep) == admins.end()) ++uni;
    n_targets_ = std::max<std::size_t>(1, uni);
  }
  note("bundle: applied generation=" + std::to_string(gen) + " epoch=" + std::to_string(snap->view.body.epoch) +
       " from " + describe(admin));
  if (o_.on_bundle) o_.on_bundle(snap);
  return Commit::Applied;
}

// ---- fetching ---------------------------------------------------------------------------------
std::vector<std::string> BundleWatcher::targets() {
  std::vector<std::string> t = bundle_admins_;
  for (const auto& e : o_.endpoints)
    if (std::find(t.begin(), t.end(), e) == t.end()) t.push_back(e);
  return t;
}

BundleWatcher::Step BundleWatcher::sweep_all(Status& why) {
  // P36: no bundle yet. Ask every endpoint without `after`; the highest valid bundle wins, so a stale
  // endpoint cannot pin a process whose state_dir is empty.
  control::BundleView best;
  std::string best_env;
  bool have = false;
  bool any_reply = false;
  why = Error{ErrorCode::NotFound, "bundle: no endpoint returned a bundle"};
  for (const std::string& ep : o_.endpoints) {
    if (stopping_.load()) {
      why = Error{ErrorCode::Aborted, "bundle: stopping"};
      return Step::Failed;
    }
    with_stats([](BundleWatcherStats& s) { ++s.fetches; });
    auto r = http_->request(ep, "GET", bundle_target(0), "", "");
    if (!r) {
      with_stats([](BundleWatcherStats& s) { ++s.failed; });
      note("bundle: fetch failed (" + std::string(r.error().context) + ") from " + describe(ep));
      continue;
    }
    any_reply = true;
    if (r->code != 200) {
      with_stats([](BundleWatcherStats& s) { ++s.failed; });
      continue;
    }
    with_stats([](BundleWatcherStats& s) { ++s.ok; });
    control::BundleView v;
    Status w;
    if (!verify(r->body, ep, v, w)) continue;
    const bool better = !have || v.body.generation > best.body.generation ||
                        (v.body.generation == best.body.generation && v.sec.sec_generation > best.sec.sec_generation);
    if (better) {
      best = std::move(v);
      best_env = std::move(r->body);
      have = true;
    }
  }
  if (!have) {
    if (any_reply) why = Error{ErrorCode::NotFound, "bundle: no usable bundle at start-up"};
    else why = Error{ErrorCode::LinkDown, "bundle: no endpoint reachable"};
    return Step::Failed;
  }
  Status w;
  switch (commit(std::move(best), std::move(best_env), o_.endpoints.front(), w)) {
    case Commit::Applied: return Step::Applied;
    case Commit::NotNewer: return Step::NotModified;
    case Commit::Error: why = w; return Step::Failed;
  }
  return Step::Failed;
}

BundleWatcher::Step BundleWatcher::fetch_one(const std::string& admin, Status& why) {
  std::uint64_t after;
  {
    std::lock_guard lk(mu_);
    after = applied_;
    ++stats_.fetches;
  }
  auto r = http_->request(admin, "GET", bundle_target(after), "", "");
  if (!r) {
    with_stats([](BundleWatcherStats& s) { ++s.failed; });
    note("bundle: fetch failed (" + std::string(r.error().context) + ") from " + describe(admin));
    why = r.error();
    return Step::Failed;
  }
  if (r->code == 304) {
    with_stats([](BundleWatcherStats& s) { ++s.not_modified; });
    return Step::NotModified;
  }
  if (r->code != 200) {
    with_stats([](BundleWatcherStats& s) { ++s.failed; });
    why = Error{ErrorCode::LinkDown, "bundle: unexpected HTTP status"};
    return Step::Failed;
  }
  with_stats([](BundleWatcherStats& s) { ++s.ok; });
  control::BundleView v;
  if (!verify(r->body, admin, v, why)) return Step::Failed;
  switch (commit(std::move(v), std::move(r->body), admin, why)) {
    case Commit::Applied: return Step::Applied;
    case Commit::NotNewer: return Step::NotModified;
    case Commit::Error: return Step::Failed;
  }
  return Step::Failed;
}

BundleWatcher::Step BundleWatcher::step(Status& why) {
  maybe_reload_trust();
  std::uint64_t applied;
  std::string hint;
  {
    std::lock_guard lk(mu_);
    applied = applied_;
    if (chase_active_ && !hint_.empty()) {
      hint = hint_;
      hint_.clear();
    }
  }
  if (applied == 0) return sweep_all(why);
  if (!hint.empty()) return fetch_one(hint, why);  // the node that replied has the newer bundle (Q05)
  const std::vector<std::string> t = targets();
  return fetch_one(t[cursor_++ % t.size()], why);  // round-robin: every step rotates, so a 304 moves on
}

BundleWatcher::Step BundleWatcher::finish_step(Step s, const Status& why) {
  (void)why;
  std::lock_guard lk(mu_);
  const Nanos now = clock_.now();
  last_fetch_ = now;
  fetched_any_ = true;
  if (s == Step::Failed) {
    backoff_until_ = now + backoff_delay(fail_streak_);
    if (fail_streak_ < 30) ++fail_streak_;
    retry_ = true;
  } else {
    fail_streak_ = 0;
    backoff_until_ = Nanos{0};
    retry_ = false;
    next_poll_ = now + std::chrono::milliseconds(o_.poll_ms);
  }
  if (chase_active_) {
    const bool caught_up = applied_ != 0 && !ahead_lo(chased_lo_, static_cast<std::uint32_t>(applied_));
    if (caught_up || chase_steps_ <= 1) chase_active_ = false;  // done, or one full cycle without finding it
    else --chase_steps_;
  }
  return s;
}

BundleWatcher::Step BundleWatcher::do_step(Status& why) {
  Step s;
  {
    std::lock_guard rl(round_mu_);
    s = step(why);
  }
  return finish_step(s, why);
}

Status BundleWatcher::poll_now() {
  Status why;
  const Step s = do_step(why);
  if (s == Step::Failed) {
    if (why) return Error{ErrorCode::LinkDown, "bundle: poll failed"};
    return why.error();
  }
  return {};
}

// ---- the thread -------------------------------------------------------------------------------
// One tick: take a step when one is wanted and allowed (start-up, a retry after a failure, a chase, or the
// 30 s poll; never sooner than min_interval after the last fetch, never inside a failure backoff), then set
// the wait to the next opportunity. A wake kicks the thread, which re-evaluates here.
unsigned BundleWatcher::next_wait_ms() {
  std::lock_guard lk(mu_);
  const Nanos now = clock_.now();
  const bool want = applied_ == 0 || retry_ || chase_active_;
  Nanos at = next_poll_;
  if (want) {
    at = backoff_until_;
    if (fetched_any_) at = std::max(at, last_fetch_ + std::chrono::milliseconds(o_.min_interval_ms));
  }
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(at - now).count();
  return static_cast<unsigned>(std::clamp<std::int64_t>(ms + 1, 1, 60000));
}

void BundleWatcher::tick() {
  bool go;
  {
    std::lock_guard lk(mu_);
    const Nanos now = clock_.now();
    const bool want = applied_ == 0 || retry_ || chase_active_;
    Nanos earliest = backoff_until_;
    if (fetched_any_) earliest = std::max(earliest, last_fetch_ + std::chrono::milliseconds(o_.min_interval_ms));
    go = (want || now >= next_poll_) && now >= earliest;
  }
  if (go) {
    Status why;
    do_step(why);
  }
  ka_.next_in(next_wait_ms());
}

// ---- push_envelope ----------------------------------------------------------------------------
Expected<BundleWatcher::PushOutcome> BundleWatcher::push_envelope(const std::string& admin) {
  MembershipSnapPtr s = current();
  if (!s) return Error{ErrorCode::NotFound, "bundle: nothing applied yet"};
  const std::uint64_t gen = s->generation();
  {
    std::lock_guard lk(push_mu_);
    if (pushes_.size() > kMaxPushEntries) pushes_.clear();
    const PushState& ps = pushes_[admin];
    if (ps.ok_generation == gen) return PushOutcome::AlreadyPushed;  // once per success per (node, generation)
    if (ps.ahead_generation == gen) return PushOutcome::NodeAhead;  // told us so already: no re-POST
    if (clock_.now() < ps.next_try) return Error{ErrorCode::Busy, "bundle: push backing off"};
  }
  auto r = http_->request(admin, "POST", "/v1/bundle", "application/octet-stream", s->envelope);
  const bool ok = r && r->code == 200;
  // 409 with generation_lower / equal_generation: the node already holds this generation or a newer one.
  // Nothing to push; fetch from it instead.
  const bool ahead = r && r->code == 409 &&
                     (r->body.find("generation_lower") != std::string::npos || r->body.find("equal_generation") != std::string::npos);
  {
    std::lock_guard lk(push_mu_);
    PushState& ps = pushes_[admin];
    if (ok) {
      ps.ok_generation = gen;
      ps.fails = 0;
      ps.next_try = Nanos{0};
    } else if (ahead) {
      ps.ahead_generation = gen;
      ps.fails = 0;
      ps.next_try = Nanos{0};
    } else {
      const std::uint64_t lo = 1000, hi = 30000;  // 1 s up to 30 s
      const std::uint64_t d = std::min<std::uint64_t>(hi, lo << std::min(ps.fails, 20u));
      if (ps.fails < 30) ++ps.fails;
      ps.next_try = clock_.now() + std::chrono::milliseconds(d);
    }
  }
  with_stats([&](BundleWatcherStats& st) { ++((ok || ahead) ? st.pushes_ok : st.push_failed); });
  if (ok) {
    note("bundle: pushed generation=" + std::to_string(gen) + " to " + describe(admin));
    return PushOutcome::Pushed;
  }
  if (ahead) {
    note("bundle: node is ahead of generation=" + std::to_string(gen) + "; fetching from " + describe(admin));
    wake_fetch_from(admin);
    return PushOutcome::NodeAhead;
  }
  note("bundle: push of generation=" + std::to_string(gen) + " failed to " + describe(admin));
  if (!r) return r.error();
  return Error{ErrorCode::LinkDown, "bundle: push refused"};
}

}  // namespace miracache
