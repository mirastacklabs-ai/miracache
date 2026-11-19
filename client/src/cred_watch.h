// SPDX-License-Identifier: Apache-2.0
// HR4 (hot-reload plan decision 1, P39): the client notices new contents of its credential files without a restart.
//   * [tls] cert/key/ca: ClientTlsCtx::reload_if_changed() (admin_http.h). Every HttpsClient with those paths (ticket
//     sources, the bundle watcher, client reports) takes the new SSL_CTX for its NEW connections.
//   * scope.secret_file: a changed file (inode, mtime, size) is parsed whole; if it loads, ReloadableEngineNativeProvider
//     switches to the new `current` kver (new kvers from `mirctl secret add-kver`).
// A failure of any kind (half-written file, cert/key replaced one after the other, mode wrong, `current` missing) keeps
// the OLD material, is counted as miracache_cred_reload_total{kind,result="rejected"} and is retried at the next tick,
// because a failed signature is never remembered. Neither the log nor the metrics ever carry key material.
#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>

#include "runtime/keepalive.h"
#include "scope/engine_native.h"
#include "src/admin_http.h"
#include "telemetry/metrics.h"
#include "util/expected.h"

namespace miracache {

struct CredWatchOptions {
  std::string cert, key, ca;  // [tls]; all empty = no TLS part
  std::string secret_file;    // scope.secret_file; empty = no secret part
  unsigned stat_ms = 10000;   // the stat check period (the memory node's admin.cred_stat_ms default)
};

class CredWatch {
 public:
  // `provider` may be null (no secret part); it must outlive the CredWatch. Nothing runs until start().
  static Expected<std::unique_ptr<CredWatch>> create(CredWatchOptions o, ReloadableEngineNativeProvider* provider);
  ~CredWatch();
  void start();  // the first check is one period after start; the files were just loaded by the caller
  void stop();   // joins the thread
  // One check of every part now (the thread's tick; also the test hook). Thread-safe.
  void check_now();
  // Prometheus text of miracache_cred_reload_total.
  void write_metrics(std::string& out) const;
  std::uint64_t count(const char* kind, bool applied) const;  // kind: "client_tls" or "secret"

 private:
  CredWatch(CredWatchOptions o, ReloadableEngineNativeProvider* p);
  struct FileSig {
    std::int64_t mtime = -1, size = -1, ino = -1;
    bool operator==(const FileSig&) const = default;
  };
  static FileSig sig_of(const std::string& path);
  void check_tls();
  void check_secret();
  void bump(int kind, int result);

  const CredWatchOptions o_;
  ReloadableEngineNativeProvider* const provider_;
  std::mutex mu_;  // serialises check_now() callers; guards the signatures
  std::shared_ptr<ClientTlsCtx> tls_;
  FileSig secret_sig_;
  telemetry::Registry reg_;
  telemetry::Counter* ctr_[2][2] = {};  // [client_tls, secret][applied, rejected]
  KeepaliveThread ka_;                  // last member: joined first
};

}  // namespace miracache
