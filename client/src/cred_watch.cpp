// SPDX-License-Identifier: Apache-2.0
#include "src/cred_watch.h"

#include <sys/stat.h>

#include "util/log.h"

namespace miracache {
namespace {
constexpr const char* kKinds[2] = {"client_tls", "secret"};
constexpr const char* kResults[2] = {"applied", "rejected"};
}  // namespace

CredWatch::CredWatch(CredWatchOptions o, ReloadableEngineNativeProvider* p) : o_(std::move(o)), provider_(p) {
  for (int k = 0; k < 2; ++k)
    for (int r = 0; r < 2; ++r)
      ctr_[k][r] = &reg_.counter("miracache_cred_reload_total", "Credential file reloads, by kind and result.",
                                 {{"kind", kKinds[k]}, {"result", kResults[r]}});
}

CredWatch::~CredWatch() { stop(); }

CredWatch::FileSig CredWatch::sig_of(const std::string& path) {
  FileSig s;
  struct stat st {};
  if (path.empty() || ::stat(path.c_str(), &st) != 0) return s;
#ifdef __APPLE__
  s.mtime = st.st_mtimespec.tv_sec * 1'000'000'000LL + st.st_mtimespec.tv_nsec;
#else
  s.mtime = st.st_mtim.tv_sec * 1'000'000'000LL + st.st_mtim.tv_nsec;
#endif
  s.size = static_cast<std::int64_t>(st.st_size);
  s.ino = static_cast<std::int64_t>(st.st_ino);
  return s;
}

Expected<std::unique_ptr<CredWatch>> CredWatch::create(CredWatchOptions o, ReloadableEngineNativeProvider* provider) {
  if (o.stat_ms == 0) return Error{ErrorCode::InvalidArgument, "cred watch: stat_ms must be > 0"};
  const bool want_tls = !o.cert.empty() && !o.key.empty() && !o.ca.empty();
  const bool want_secret = provider && !o.secret_file.empty();
  if (!want_tls && !want_secret) return std::unique_ptr<CredWatch>();  // nothing to watch
  const std::string secret_file = want_secret ? o.secret_file : std::string();
  std::unique_ptr<CredWatch> w(new CredWatch(std::move(o), want_secret ? provider : nullptr));
  if (want_tls) {
    auto t = ClientTlsCtx::acquire(w->o_.cert, w->o_.key, w->o_.ca);
    if (!t) return t.error();
    w->tls_ = std::move(*t);
  }
  w->secret_sig_ = sig_of(secret_file);  // BEFORE the caller's load is trusted: a change after it is seen by the next check
  return w;
}

void CredWatch::start() { ka_.start(o_.stat_ms, [this] { check_now(); }); }
void CredWatch::stop() { ka_.stop(); }

void CredWatch::bump(int kind, int result) { ctr_[kind][result]->inc(); }

void CredWatch::check_now() {
  std::lock_guard<std::mutex> g(mu_);
  check_tls();
  check_secret();
}

void CredWatch::check_tls() {
  if (!tls_) return;
  std::string why;
  switch (tls_->reload_if_changed(&why)) {
    case ClientTlsCtx::Reload::Unchanged: return;
    case ClientTlsCtx::Reload::Applied:
      bump(0, 0);
      log::write(log::Level::Info, "client", "tls credentials reloaded (file change)");
      return;
    case ClientTlsCtx::Reload::Rejected:
      bump(0, 1);
      log::write(log::Level::Warn, "client", "tls credential reload rejected; keeping the old certificate", {{"err", why}});
      return;
  }
}

void CredWatch::check_secret() {
  if (!provider_) return;
  const FileSig now = sig_of(o_.secret_file);
  if (now == secret_sig_) return;
  auto set = load_secret_file(o_.secret_file);
  if (set) {
    if (Status st = provider_->reload(*set); !st) {
      bump(1, 1);
      log::write(log::Level::Warn, "client", "secret reload rejected; keeping the old secret", {{"err", st.error().context}});
      return;
    }
    secret_sig_ = now;
    bump(1, 0);
    log::write(log::Level::Info, "client", "secret file reloaded (file change)", {{"kver", std::to_string(set->current)}});
    return;
  }
  // Half-written, wrong mode, no `current`: keep the old secret and look again next tick (secret_sig_ unchanged).
  bump(1, 1);
  log::write(log::Level::Warn, "client", "secret reload rejected; keeping the old secret", {{"err", set.error().context}});
}

void CredWatch::write_metrics(std::string& out) const { reg_.write_prometheus(out); }

std::uint64_t CredWatch::count(const char* kind, bool applied) const {
  const int k = std::string(kind) == "secret" ? 1 : 0;
  return ctr_[k][applied ? 0 : 1]->value();
}

}  // namespace miracache
