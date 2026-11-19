// SPDX-License-Identifier: Apache-2.0
#include "server/runtime/bundle_store.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cctype>
#include <cstring>
#include <cerrno>
#include <map>

#include "server/dyn_config.h"
#include "util/clock.h"
#include "util/log.h"

namespace miracache::server {
namespace {

using control::Reject;

void logb(log::Level l, std::string_view msg, std::initializer_list<log::Field> extra = {}) {
  log::write(l, "bundle", msg, extra);
}

struct Fd {
  int fd = -1;
  explicit Fd(int f) : fd(f) {}
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  ~Fd() {
    if (fd >= 0) ::close(fd);
  }
};

bool write_all(int fd, std::string_view s) {
  std::size_t off = 0;
  while (off < s.size()) {
    const ssize_t n = ::write(fd, s.data() + off, s.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    off += static_cast<std::size_t>(n);
  }
  return true;
}

// Whole file; `missing` when it does not exist. False on any other error or when larger than `cap`.
bool read_file(const std::string& path, std::string& out, bool& missing, std::size_t cap) {
  missing = false;
  Fd f(::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW));  // never follows a symlink (X12)
  if (f.fd < 0) {
    missing = errno == ENOENT;
    return missing;
  }
  char buf[8192];
  for (;;) {
    const ssize_t n = ::read(f.fd, buf, sizeof buf);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) return true;
    out.append(buf, static_cast<std::size_t>(n));
    if (out.size() > cap) return false;
  }
}

std::string json_escape(const std::string& s) {
  std::string o;
  for (const char c : s) {
    const auto u = static_cast<unsigned char>(c);
    if (c == '"' || c == '\\') {
      o.push_back('\\');
      o.push_back(c);
    } else if (u < 0x20 || u >= 0x7f) {
      o.push_back('?');
    } else {
      o.push_back(c);
    }
  }
  return o;
}

std::string hex(const control::Sha256Digest& d) { return control::to_hex(d); }
std::string hex(const control::KeyId& d) { return control::to_hex(d); }

int http_code(Reject r) {
  switch (r) {
    case Reject::EnvelopeFormat:
    case Reject::Schema:
    case Reject::TrustFile: return 400;
    case Reject::UnknownKey:
    case Reject::KeyRole:
    case Reject::BadSignature:
    case Reject::BadSecSignature: return 403;
    case Reject::GenerationLower:
    case Reject::EqualGeneration:
    case Reject::EpochBackwards:
    case Reject::SecGenerationLower:
    case Reject::SecEqualGeneration: return 409;
  }
  return 400;
}

HttpReply error_reply(int code, const char* reason, const char* detail) {
  HttpReply r;
  r.code = code;
  r.body = std::string("{\"error\":\"") + json_escape(detail) + "\",\"reason\":\"" + reason + "\"}";
  return r;
}

bool stat_sig(const std::string& path, std::int64_t& mtime_ns, std::int64_t& size, std::int64_t& ino) {
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0) return false;
#ifdef __APPLE__
  mtime_ns = static_cast<std::int64_t>(st.st_mtimespec.tv_sec) * 1000000000 + st.st_mtimespec.tv_nsec;
#else
  mtime_ns = static_cast<std::int64_t>(st.st_mtim.tv_sec) * 1000000000 + st.st_mtim.tv_nsec;
#endif
  size = static_cast<std::int64_t>(st.st_size);
  ino = static_cast<std::int64_t>(st.st_ino);
  return true;
}


// A stored bundle is acceptable only if it matches the floor exactly (hashes and both generations).
bool matches_floor(const control::Floor& f, const control::BundleView& v) {
  return f.generation > 0 && v.body.generation == f.generation && v.body_hash == f.body_hash &&
         v.sec.sec_generation == f.sec_generation && v.sec_hash == f.sec_hash;
}

struct Stored {
  std::shared_ptr<control::BundleView> view;  // null = not usable
  bool alert = false;                         // applied although a key is gone (X03)
  const char* why = "";
};

// Start-up judgement of stored bytes (X03, X04). `exact`: the bytes must match the floor exactly (a tmp file).
Stored judge_stored(std::string_view bytes, const control::TrustKeys& tk, const control::Floor& floor, bool exact) {
  Stored s;
  auto v = control::open_bundle(bytes, tk);
  if (v) {
    auto verdict = control::check_against_floor(floor, *v, tk.min_sec_generation());
    if (!verdict) {
      s.why = control::reason_string(verdict.error().reason);
      return s;
    }
    if (exact && !matches_floor(floor, *v)) {
      s.why = "tmp_mismatch";
      return s;
    }
    s.view = std::make_shared<control::BundleView>(std::move(*v));
    return s;
  }
  s.why = control::reason_string(v.error().reason);
  if (v.error().reason != Reject::UnknownKey && v.error().reason != Reject::KeyRole) return s;
  // Only a rotated-out key: integrity comes from the hashes the floor recorded when the bundle was verified.
  auto env = control::parse_envelope(bytes);
  if (!env) return s;
  auto pv = control::parse_bundle(*env);
  // Y03: the trust file's pin still applies (effective security floor = max(persisted, pinned)).
  if (!pv || !matches_floor(floor, *pv) || pv->sec.sec_generation < tk.min_sec_generation()) return s;
  s.view = std::make_shared<control::BundleView>(std::move(*pv));
  s.alert = true;
  return s;
}

bool fsync_dir(const std::string& dir) {
  Fd d(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  return d.fd >= 0 && ::fsync(d.fd) == 0;
}

}  // namespace

std::string rail_subnet(const std::string& host) {
  in_addr a4{};
  in6_addr a6{};
  const bool v4 = ::inet_pton(AF_INET, host.c_str(), &a4) == 1;
  const bool v6 = !v4 && ::inet_pton(AF_INET6, host.c_str(), &a6) == 1;
  if ((!v4 && !v6) || (v4 && a4.s_addr == 0) || (v6 && IN6_IS_ADDR_UNSPECIFIED(&a6))) return "";
  ifaddrs* all = nullptr;
  if (::getifaddrs(&all) != 0) return "";
  std::string out;
  for (const ifaddrs* i = all; i != nullptr && out.empty(); i = i->ifa_next) {
    if (!i->ifa_addr || !i->ifa_netmask) continue;
    char buf[INET6_ADDRSTRLEN];
    if (v4 && i->ifa_addr->sa_family == AF_INET) {
      const auto* ad = reinterpret_cast<const sockaddr_in*>(i->ifa_addr);
      const auto* mk = reinterpret_cast<const sockaddr_in*>(i->ifa_netmask);
      if (ad->sin_addr.s_addr != a4.s_addr) continue;
      in_addr net{};
      net.s_addr = ad->sin_addr.s_addr & mk->sin_addr.s_addr;
      int len = 0;
      for (std::uint32_t m = ntohl(mk->sin_addr.s_addr); m & 0x80000000u; m <<= 1) ++len;
      if (::inet_ntop(AF_INET, &net, buf, sizeof buf)) out = std::string(buf) + "/" + std::to_string(len);
    } else if (v6 && i->ifa_addr->sa_family == AF_INET6) {
      const auto* ad = reinterpret_cast<const sockaddr_in6*>(i->ifa_addr);
      const auto* mk = reinterpret_cast<const sockaddr_in6*>(i->ifa_netmask);
      if (std::memcmp(&ad->sin6_addr, &a6, sizeof a6) != 0) continue;
      in6_addr net{};
      int len = 0;
      for (int b = 0; b < 16; ++b) {
        net.s6_addr[b] = ad->sin6_addr.s6_addr[b] & mk->sin6_addr.s6_addr[b];
        for (std::uint8_t m = mk->sin6_addr.s6_addr[b]; m & 0x80; m = static_cast<std::uint8_t>(m << 1)) ++len;
      }
      if (::inet_ntop(AF_INET6, &net, buf, sizeof buf)) out = std::string(buf) + "/" + std::to_string(len);
    }
  }
  ::freeifaddrs(all);
  return out;
}

Expected<std::unique_ptr<BundleStore>> BundleStore::open(BundleStoreOptions o) {
  if (o.reg == nullptr || o.clock == nullptr) return Error{ErrorCode::InvalidArgument, "bundle: registry required"};
  if (o.trust_path.empty()) return Error{ErrorCode::InvalidArgument, "bundle: trust_keys path required"};
  auto fs = control::FloorState::open(o.state_dir);
  if (!fs) return fs.error();
  std::unique_ptr<BundleStore> b(new BundleStore(std::move(o), std::move(*fs)));
  auto tk = control::load_trust_keys(b->opt_.trust_path);
  if (!tk) return Error{ErrorCode::InvalidArgument, tk.error().detail};
  b->trust_ = std::make_shared<const control::TrustKeys>(std::move(*tk));
  stat_sig(b->opt_.trust_path, b->stat_.mtime_ns, b->stat_.size, b->stat_.ino);
  b->next_stat_ = b->opt_.clock->now() + kTrustStatInterval;
  // A corrupt floor is an error, never a blank floor.
  auto floor = b->floor_.load();
  if (!floor) return floor.error();

  b->unverified_gauge_ = &b->opt_.reg->gauge(
      "miracache_bundle_startup_unverified",
      "1 while bundle.current did not verify at start-up (cleared by the next successful push).");
  const std::string path = b->opt_.state_dir + "/bundle.current";
  const std::string tmp = path + ".tmp";
  std::string bytes;
  Stored st;
  bool existed = false;

  // X02: a tmp left by a crash between the floor commit and the rename is promoted when it matches the floor exactly.
  {
    std::string tb;
    bool tmissing = false;
    if (read_file(tmp, tb, tmissing, control::kMaxEnvelopeBytes) && !tmissing) {
      Stored ts = judge_stored(tb, *b->trust_, *floor, /*exact=*/true);
      if (ts.view && ::rename(tmp.c_str(), path.c_str()) == 0 && fsync_dir(b->opt_.state_dir)) {
        logb(log::Level::Warn, "promoted bundle.current.tmp left by an interrupted push",
             {{"generation", std::to_string(ts.view->body.generation)}});
        st = std::move(ts);
        bytes = std::move(tb);
        existed = true;
      } else {
        logb(log::Level::Warn, "discarding bundle.current.tmp", {{"why", ts.view ? "rename failed" : ts.why}});
        ::unlink(tmp.c_str());
      }
    } else if (!tmissing) {
      ::unlink(tmp.c_str());  // unreadable (a symlink, a directory...): never followed
    }
  }
  if (!st.view) {
    bool missing = false;
    bytes.clear();
    if (!read_file(path, bytes, missing, control::kMaxEnvelopeBytes)) {
      existed = true;
      st.why = "unreadable";
    } else if (!missing) {
      existed = true;
      st = judge_stored(bytes, *b->trust_, *floor, /*exact=*/false);
    }
  }
  if (st.view) {
    auto env = std::make_shared<const std::string>(std::move(bytes));
    b->set_applied(*st.view, env);
    b->startup_view_ = st.view;
    // Heals a floor that is behind the stored bundle. Replace = already there.
    if (auto r = b->floor_.commit(*st.view, b->trust_->min_sec_generation()); !r) {
      logb(log::Level::Warn, "floor commit at start-up failed",
           {{"err", r.error().rejected ? r.error().reject.detail : r.error().io.context}});
    }
    if (st.alert) {
      logb(log::Level::Error, "bundle.current is signed by a key no longer trusted; applied because it equals the floor",
           {{"generation", std::to_string(st.view->body.generation)}});
    }
    logb(log::Level::Info, "bundle.current loaded", {{"generation", std::to_string(st.view->body.generation)},
                                                     {"epoch", std::to_string(st.view->body.epoch)},
                                                     {"applied_hash", hex(st.view->body_hash)}});
  } else if (existed) {
    logb(log::Level::Error, "bundle.current is not usable at start-up; serving without a bundle", {{"why", st.why}});
  }
  if (existed && (!st.view || st.alert)) {
    b->startup_unverified_ = true;
    b->count_reject("startup_unverified");
    b->unverified_gauge_->set(1);
  }
  return b;
}

void BundleStore::count_reject(const char* reason) {
  opt_.reg->counter("miracache_bundle_reject_total", "Bundles rejected, by reason.", {{"reason", reason}}).inc();
}
void BundleStore::count_result(const char* result) {
  opt_.reg->counter("miracache_bundle_apply_total", "Bundle pushes, by result.", {{"result", result}}).inc();
}

std::shared_ptr<const control::TrustKeys> BundleStore::trust() const {
  std::lock_guard<std::mutex> g(mu_);
  return trust_;
}

Status BundleStore::reload_trust() {
  std::int64_t m = 0, s = -1, i = 0;
  stat_sig(opt_.trust_path, m, s, i);  // stat BEFORE the load: a change after it is seen by the next check (X13)
  auto tk = control::load_trust_keys(opt_.trust_path);
  std::lock_guard<std::mutex> g(mu_);
  next_stat_ = opt_.clock->now() + kTrustStatInterval;
  stat_ = {m, s, i};
  if (!tk) {
    // P39: a half-written trust file keeps the old keys, is counted, and is retried at the next tick (the failed
    // signature is not remembered).
    stat_ = StatSig{};
    stat_.size = -1;
    opt_.reg->counter("miracache_cred_reload_total", "Credential file reloads, by kind and result.",
                      {{"kind", "trust_keys"}, {"result", "rejected"}}).inc();
    count_reject("trust_file");
    logb(log::Level::Error, "trust file reload failed; keeping the old keys", {{"detail", tk.error().detail}});
    return Error{ErrorCode::InvalidArgument, tk.error().detail};
  }
  trust_ = std::make_shared<const control::TrustKeys>(std::move(*tk));
  opt_.reg->counter("miracache_cred_reload_total", "Credential file reloads, by kind and result.",
                    {{"kind", "trust_keys"}, {"result", "applied"}}).inc();
  logb(log::Level::Info, "trust file reloaded", {{"keys", std::to_string(trust_->keys().size())}});
  return {};
}

void BundleStore::maybe_reload_trust() {
  {
    std::lock_guard<std::mutex> g(mu_);
    const auto now = opt_.clock->now();
    if (now < next_stat_) return;
    next_stat_ = now + kTrustStatInterval;
    std::int64_t m = 0, s = -1, i = 0;
    if (stat_sig(opt_.trust_path, m, s, i) && StatSig{m, s, i} == stat_) return;
  }
  (void)reload_trust();
}

Status BundleStore::write_tmp(std::string_view envelope) {
  const std::string tmp = opt_.state_dir + "/bundle.current.tmp";
  ::unlink(tmp.c_str());  // a stale tmp (or a planted symlink) is removed, never followed (X12)
  Fd out(::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (out.fd < 0) return Error{ErrorCode::Aborted, "bundle: cannot create the temp file"};
  if (!write_all(out.fd, envelope) || ::fsync(out.fd) != 0) {
    ::unlink(tmp.c_str());
    return Error{ErrorCode::Aborted, "bundle: cannot write the temp file"};
  }
  return {};
}

Status BundleStore::publish_tmp() {
  const std::string path = opt_.state_dir + "/bundle.current";
  const std::string tmp = path + ".tmp";
  if (::rename(tmp.c_str(), path.c_str()) != 0) return Error{ErrorCode::Aborted, "bundle: rename failed"};
  if (!fsync_dir(opt_.state_dir)) return Error{ErrorCode::Aborted, "bundle: directory fsync failed"};
  return {};
}

void BundleStore::clear_startup_alert() {
  if (startup_unverified_.exchange(false) && unverified_gauge_) unverified_gauge_->set(0);  // X11
}

void BundleStore::set_applied(const control::BundleView& v, std::shared_ptr<const std::string> envelope) {
  std::lock_guard<std::mutex> g(mu_);
  applied_.present = true;
  applied_.generation = v.body.generation;
  applied_.sec_generation = v.sec.sec_generation;
  applied_.epoch = v.body.epoch;
  applied_.body_hash = v.body_hash;
  applied_.sec_hash = v.sec_hash;
  applied_.key_id = v.key_id;
  applied_.sec_key_id = v.sec_key_id;
  applied_.envelope = std::move(envelope);
  std::vector<RbacBinding> rb;  // RB2: the bindings of the applied bundle (decision 3), live before a push replies
  for (const auto& r : v.sec.rbac) rb.push_back({r.identity, r.roles});
  rbac_.set(rb);
}

std::string BundleStore::summary_json(const char* result) const {
  std::lock_guard<std::mutex> g(mu_);
  return std::string("{\"result\":\"") + result + "\",\"generation\":" + std::to_string(applied_.generation) +
         ",\"epoch\":" + std::to_string(applied_.epoch) + ",\"applied_hash\":\"" + hex(applied_.body_hash) +
         "\",\"sec_generation\":" + std::to_string(applied_.sec_generation) + ",\"sec_hash\":\"" +
         hex(applied_.sec_hash) + "\"}";
}

// The ONLY place a push touches the floor: a check, or (when `commit`) the commit, which re-checks under the lock.
// push() checks first, writes the fsynced tmp, commits, then renames (X02).
// Review W06/W07: when FloorState::commit returns the verdict (or a reject) under its exclusive lock, replace the
// two calls below by that one result; callers already treat a reject like a failed check (no ack, no swap).
Expected<control::Verdict, control::BundleError> BundleStore::floor_admit(const control::BundleView& v,
                                                                          std::uint64_t pinned, bool commit,
                                                                          bool& io_failed) {
  io_failed = false;
  if (commit) {  // W06: commit re-checks under the exclusive lock and returns the verdict or the reject
    auto r = floor_.commit(v, pinned);
    if (r) return *r;
    if (r.error().rejected) return r.error().reject;
    logb(log::Level::Error, "floor commit failed", {{"err", r.error().io.context}});
    io_failed = true;
    return control::BundleError{Reject::Schema, "floor commit failed"};
  }
  auto floor = floor_.load();
  if (!floor) {
    logb(log::Level::Error, "floor unreadable", {{"err", floor.error().context}});
    io_failed = true;
    return control::BundleError{Reject::Schema, "floor unreadable"};
  }
  return control::check_against_floor(*floor, v, pinned);
}

namespace {
// RB2: what an apply changes in the security section, for the audit entry. Counts only (identities are not secret, but
// the entry stays small and the diff is not a place for surprises).
void diff_sec(const control::BundleView* old, const control::BundleView& nw, PushOutcome& o) {
  std::map<std::string, std::vector<std::string>> r0, r1;
  std::map<std::string, std::string> b0, b1;
  if (old) {
    for (const auto& r : old->sec.rbac) r0[r.identity] = r.roles;
    for (const auto& p : old->sec.principals)
      for (const auto& i : p.identities) b0[i] = p.name;
  }
  for (const auto& r : nw.sec.rbac) r1[r.identity] = r.roles;
  for (const auto& p : nw.sec.principals)
    for (const auto& i : p.identities) b1[i] = p.name;
  auto cmp = [](const auto& a, const auto& b, std::uint64_t& added, std::uint64_t& removed, std::uint64_t& changed) {
    for (const auto& [k, v] : b) {
      const auto it = a.find(k);
      if (it == a.end()) ++added;
      else if (it->second != v) ++changed;
    }
    for (const auto& kv : a)
      if (!b.count(kv.first)) ++removed;
  };
  cmp(r0, r1, o.rbac_added, o.rbac_removed, o.rbac_changed);
  cmp(b0, b1, o.bindings_added, o.bindings_removed, o.bindings_changed);
}
}  // namespace

HttpReply BundleStore::push(std::string_view bytes, bool dry_run, const StoreCall& call, std::shared_ptr<PushOutcome> out) {
  std::lock_guard<std::mutex> serial(push_mu_);
  if (!out) out = std::make_shared<PushOutcome>();
  const auto tk = trust();
  auto reject_reply = [&](const control::BundleError& e, const char* what) {
    count_reject(control::reason_string(e.reason));
    logb(log::Level::Warn, what, {{"reason", control::reason_string(e.reason)}, {"detail", e.detail}});
    return error_reply(http_code(e.reason), control::reason_string(e.reason), e.detail);
  };
  auto opened = control::open_bundle(bytes, *tk);
  if (!opened) return reject_reply(opened.error(), "bundle rejected");
  auto view = std::make_shared<control::BundleView>(std::move(*opened));
  // U2-02: a drop_before ahead of the wall clock (+ 300 s skew) is refused before anything is written.
  {
    const std::int64_t now_s = opt_.wall_unix_s ? opt_.wall_unix_s() : wall_unix_ns() / 1'000'000'000LL;
    // J03/H09: a drop_before the floor already holds (not above its stored maximum) is exempt, so a cluster-wide clock
    // step back does not make every publish fail. An unreadable floor gives no exemption (fail-closed; floor_admit
    // reports the I/O failure below).
    auto stored = floor_.load();
    if (auto fut = control::check_drop_before_not_future(*view, now_s, stored ? &stored->drop_before : nullptr)) {
      out->generation = view->body.generation;
      out->sec_generation = view->sec.sec_generation;
      return reject_reply(*fut, "bundle rejected");
    }
  }
  // HR1 (P13/P16): the memory-node part of config.* is validated here, pure, before anything is persisted or swapped
  // (the dry run runs it too). A STATIC or stale key, a bad value or a broken cross-field rule rejects the bundle; unknown
  // keys do not (rolling upgrades).
  if (opt_.dyn_base) {
    const std::string admin = bundle_node_admin(view->body, opt_.node_id);  // same helper as Server::apply_bundle_config
    auto pr = parse_memnode_dyn(view->body.config_toml, *opt_.dyn_base, admin, view->body.generation);
    if (!pr.dyn) {
      out->generation = view->body.generation;
      out->sec_generation = view->sec.sec_generation;
      opt_.reg->counter("miracache_config_reload_total", "Configuration reloads, by result.", {{"result", "rejected"}}).inc();
      count_reject("config");
      logb(log::Level::Warn, "bundle rejected", {{"reason", "config"}, {"detail", pr.error}});
      return error_reply(400, "config", pr.error.c_str());
    }
  }
  const std::uint64_t pin = tk->min_sec_generation();
  out->generation = view->body.generation;
  out->sec_generation = view->sec.sec_generation;
  out->epoch = view->body.epoch;
  out->applied_hash = hex(view->body_hash);

  // First a check only (early reject, dry run, idempotent re-push); the commit comes after the tmp file is durable.
  bool io_failed = false;
  auto verdict = floor_admit(*view, pin, /*commit=*/false, io_failed);
  if (io_failed) {
    count_result("persist_error");
    return error_reply(500, "floor", "the bundle floor cannot be read or written");
  }
  if (!verdict) return reject_reply(verdict.error(), "bundle rejected");

  // The swap is still needed when this process has not applied exactly this bundle (for example after a
  // start-up that could not verify bundle.current: a valid push supersedes it, whatever the floor says).
  bool needs_apply = *verdict == control::Verdict::Apply;
  bool same_bytes = false;
  {
    std::lock_guard<std::mutex> g(mu_);
    if (!applied_.present || applied_.generation != view->body.generation || applied_.body_hash != view->body_hash ||
        applied_.sec_hash != view->sec_hash) {
      needs_apply = true;
    }
    same_bytes = applied_.present && applied_.envelope && *applied_.envelope == bytes;
  }

  if (dry_run) {
    HttpReply r;
    r.code = 200;
    r.body = std::string("{\"result\":\"dry_run_ok\",\"would\":\"") + (needs_apply ? "apply" : "replace") +
             "\",\"generation\":" + std::to_string(view->body.generation) +
             ",\"epoch\":" + std::to_string(view->body.epoch) +
             ",\"unknown_keys\":" + std::to_string(view->body.unknown_keys) + "}";
    return r;
  }

  if (!needs_apply && same_bytes) {  // idempotent re-push
    count_result("noop");
    clear_startup_alert();
    HttpReply r;
    r.code = 200;
    r.body = summary_json("noop");
    return r;
  }

  // X02: tmp written + fsynced, THEN the floor commit, THEN the rename. A crash between the last two leaves a tmp
  // that matches the floor exactly; start-up promotes it. The commit's verdict (W06) is the one that counts.
  auto envelope = std::make_shared<const std::string>(bytes);
  if (auto st = write_tmp(*envelope); !st) {
    count_result("persist_error");
    logb(log::Level::Error, "bundle persist failed", {{"err", st.error().context}});
    return error_reply(500, "persist", "the bundle could not be persisted");
  }
  const std::string tmp_path = opt_.state_dir + "/bundle.current.tmp";
  auto committed = floor_admit(*view, pin, /*commit=*/true, io_failed);
  if (io_failed) {
    ::unlink(tmp_path.c_str());
    count_result("persist_error");
    return error_reply(500, "floor", "the bundle floor cannot be read or written");
  }
  if (!committed) {  // lost a race against another process on the floor: no ack, no swap
    ::unlink(tmp_path.c_str());
    return reject_reply(committed.error(), "bundle rejected");
  }
  if (*committed == control::Verdict::Apply) needs_apply = true;
  if (auto st = publish_tmp(); !st) {  // the tmp stays: the floor is committed and start-up promotes it
    count_result("persist_error");
    logb(log::Level::Error, "bundle persist failed", {{"err", st.error().context}});
    return error_reply(500, "persist", "the bundle could not be persisted");
  }

  if (!needs_apply) {  // a new valid signature over the same content (key rotation): replace, no apply
    set_applied(*view, envelope);
    clear_startup_alert();
    count_result("replaced");
    logb(log::Level::Info, "bundle envelope replaced",
         {{"generation", std::to_string(view->body.generation)}, {"key_id", hex(view->key_id)}});
    HttpReply r;
    r.code = 200;
    r.body = summary_json("replaced");
    return r;
  }

  const bool swapped = call([this, view, envelope, out](Server& s) {
    diff_sec(s.bundle_view(), *view, *out);
    s.apply_bundle(*view);
    set_applied(*view, envelope);
    if (out->on_applied) out->on_applied(*out);
  });
  if (!swapped) {
    count_result("apply_timeout");
    logb(log::Level::Error, "store thread did not answer the bundle swap; the bundle is persisted",
         {{"generation", std::to_string(view->body.generation)}});
    return error_reply(504, "apply_timeout", "store thread busy; the bundle is persisted");
  }
  clear_startup_alert();
  count_result("applied");
  logb(log::Level::Info, "bundle applied",
       {{"generation", std::to_string(view->body.generation)}, {"epoch", std::to_string(view->body.epoch)},
        {"sec_generation", std::to_string(view->sec.sec_generation)}, {"applied_hash", hex(view->body_hash)}});
  HttpReply r;
  r.code = 200;
  r.body = summary_json("applied");
  return r;
}

HttpReply BundleStore::get_bundle(const std::string& query) {
  std::optional<std::uint64_t> after;
  for (std::size_t pos = 0; pos < query.size();) {
    auto amp = query.find('&', pos);
    if (amp == std::string::npos) amp = query.size();
    const std::string kv = query.substr(pos, amp - pos);
    pos = amp + 1;
    if (kv.rfind("after=", 0) != 0) return error_reply(400, "query", "only `after` is accepted");
    const std::string v = kv.substr(6);
    if (v.empty() || v.size() > 19 || v.find_first_not_of("0123456789") != std::string::npos)
      return error_reply(400, "query", "after must be a decimal generation");
    after = std::stoull(v);
  }
  std::shared_ptr<const std::string> env;
  std::uint64_t gen = 0;
  {
    std::lock_guard<std::mutex> g(mu_);
    env = applied_.envelope;
    gen = applied_.generation;
  }
  if (!env) return error_reply(404, "no_bundle", "no bundle applied");
  HttpReply r;
  if (after && gen <= *after) {
    r.code = 304;
    return r;
  }
  r.code = 200;
  r.ctype = "application/octet-stream";
  r.body = *env;
  return r;
}

HttpReply BundleStore::identity() {
  Applied a;
  {
    std::lock_guard<std::mutex> g(mu_);
    a = applied_;
  }
  const Server::NodeSnapshot snap = opt_.snapshot ? opt_.snapshot() : Server::NodeSnapshot{};
  const auto anchor = opt_.audit_anchor ? opt_.audit_anchor() : std::make_pair(std::uint64_t{0}, std::string(64, '0'));
  std::string host;  // hostnames are [A-Za-z0-9._-]; anything else is dropped
  for (const char ch : opt_.hostname)
    if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '_' || ch == '-') host.push_back(ch);
  std::string rails;
  for (std::size_t i = 0; i < opt_.rails.size(); ++i) {
    const auto& rl = opt_.rails[i];
    if (!rails.empty()) rails += ',';
    // RL1: real health from the server (port state, listener, fatal events); before the first reading, the flag main sets.
    const Server::RailHealth* h = i < snap.rails.size() ? &snap.rails[i] : nullptr;
    rails += "{\"addr\":\"" + json_escape(rl.addr) + "\",\"subnet\":\"" + json_escape(rl.subnet) + "\",\"protocol\":\"" +
             json_escape(rl.protocol) + "\",\"up\":" + ((h != nullptr ? h->up : rails_up_.load()) ? "true" : "false");
    if (h != nullptr)
      rails += ",\"port_state\":\"" + json_escape(h->port_state) + "\",\"listener_ok\":" + (h->listener_ok ? "true" : "false");
    rails += "}";
  }
  HttpReply r;
  r.code = 200;
  r.body = "{\"node_id\":" + std::to_string(opt_.node_id) + ",\"hostname\":\"" + host + "\",\"addr\":\"" +
           json_escape(opt_.addr) + "\",\"admin\":\"" + json_escape(opt_.admin) +
           "\",\"generation\":" + std::to_string(a.generation) +
           ",\"applied_generation\":" + std::to_string(a.generation) + ",\"applied_hash\":\"" + hex(a.body_hash) +
           "\",\"sec_generation\":" + std::to_string(a.sec_generation) + ",\"sec_hash\":\"" + hex(a.sec_hash) +
           "\",\"key_id\":\"" + hex(a.key_id) + "\",\"sec_key_id\":\"" + hex(a.sec_key_id) +
           "\",\"epoch\":" + std::to_string(a.epoch) + ",\"startup_unverified\":" +
           (startup_unverified_.load() ? "true" : "false") + ",\"rails\":[" + rails + "],\"member_state\":\"" + snap.member_state +
           "\",\"scopes\":" + std::to_string(snap.scopes) + ",\"bytes_used\":" + std::to_string(snap.bytes_used) +
           ",\"audit_seq\":" + std::to_string(anchor.first) + ",\"audit_head\":\"" + anchor.second + "\"}";
  return r;
}

BundleRails bundle_rails(const std::vector<fabric::RailAddr>& listen, const std::string& protocol,
                         const std::vector<std::string>& subnets) {
  BundleRails out;
  if (listen.empty()) {
    out.error = "bundle mode needs at least one [node] listen address (a concrete interface address)";
    return out;
  }
  if (protocol != "roce" && protocol != "iwarp") {
    out.error = "the active RDMA transport is \"" + protocol + "\"; bundle mode supports only roce and iwarp";
    out.bad_rail = listen.front().host + ":" + std::to_string(listen.front().port);
    return out;
  }
  for (std::size_t i = 0; i < listen.size(); ++i) {
    const auto& r = listen[i];
    const std::string name = (r.host.empty() ? "0.0.0.0" : r.host) + ":" + std::to_string(r.port);
    std::string subnet = i < subnets.size() && !subnets[i].empty() ? subnets[i] : rail_subnet(r.host);
    if (subnet.empty()) {
      out.error = "cannot determine the subnet of this rail; in bundle mode listen on a concrete interface address "
                  "(not a wildcard or a hostname)";
      out.bad_rail = name;
      out.rails.clear();
      return out;
    }
    out.rails.push_back({name, std::move(subnet), protocol});
  }
  return out;
}

}  // namespace miracache::server
