// SPDX-License-Identifier: Apache-2.0
// One HTTPS request to a memory node's admin listener (membership plan decisions 1, 9), shared by
// the ticket source (POST /v1/tickets) and the bundle watcher (GET/POST /v1/bundle).
//
//   * TLS 1.3 only; mTLS with the client cert/key (key file mode 0600); the server chain is verified
//     against `ca`; if `server_identity` is given its single spiffe:// URI SAN must equal it. No
//     hostname check (lab certs carry the SPIFFE id).
//   * One request per connection (`Connection: close`); the response is read to EOF, at most
//     `max_response` bytes. The whole call (resolve, connect, handshake, request, response) is bounded
//     by `io_timeout_ms` of real time.
//   * Thread-safe: request() only reads the shared SSL_CTX.
#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include "miracache/types.h"
#include "util/clock.h"

typedef struct ssl_ctx_st SSL_CTX;

namespace miracache {

struct HttpsOptions {
  std::string cert, key, ca;  // PEM paths
  unsigned io_timeout_ms = 2000;
  std::size_t max_response = 64 * 1024;
  // Test hook: called with the connected TCP fd before the TLS handshake starts.
  std::function<void(int)> test_after_connect;
  // Optional (review w5 U2-27): once it reads true, a request in flight gives up within ~50 ms (Timeout). Must outlive
  // the client.
  const std::atomic<bool>* cancel = nullptr;
};

struct HttpResponse {
  int code = 0;
  std::string body;
};

// HR4 (P39): the client's TLS material, shared by every HttpsClient with the same cert/key/ca paths (ticket sources,
// the bundle watcher, client reports). A new connection takes the SSL_CTX in force at that moment; a connection in
// flight keeps the one it started with. reload_if_changed() is the stat check (inode, mtime, size of the three files):
// a changed set is loaded as a whole, and if it does not parse or the key does not match the certificate (a
// non-atomic replacement, a half-written file) the old context stays and the same check runs again at the next call,
// because a failed signature is not remembered. Thread-safe.
class ClientTlsCtx {
 public:
  enum class Reload { Unchanged, Applied, Rejected };
  // Shared per (cert, key, ca): the same paths return the same object while any holder lives. Errors as HttpsClient::create.
  static Expected<std::shared_ptr<ClientTlsCtx>> acquire(const std::string& cert, const std::string& key, const std::string& ca);
  // Bumped by every applied reload. Each HttpsClient keeps its OWN SSL_CTX (so no context is shared between threads of
  // different clients) and rebuilds it with fresh() when the generation moved.
  std::uint64_t generation() const { return gen_.load(std::memory_order_acquire); }
  Expected<std::shared_ptr<SSL_CTX>> fresh() const { return build(cert_, key_, ca_); }
  // `why` (optional) receives the reject reason (never key material).
  Reload reload_if_changed(std::string* why = nullptr);
  const std::string& cert() const { return cert_; }
  const std::string& key() const { return key_; }
  const std::string& ca() const { return ca_; }

 private:
  struct Sig {
    std::int64_t mtime = -1, size = -1, ino = -1;
    bool operator==(const Sig&) const = default;
  };
  using Sigs = std::array<Sig, 3>;
  ClientTlsCtx(std::string c, std::string k, std::string a) : cert_(std::move(c)), key_(std::move(k)), ca_(std::move(a)) {}
  static Sigs sigs_of(const std::string& c, const std::string& k, const std::string& a);
  static Expected<std::shared_ptr<SSL_CTX>> build(const std::string& c, const std::string& k, const std::string& a);
  const std::string cert_, key_, ca_;
  std::atomic<std::uint64_t> gen_{1};
  mutable std::mutex mu_;
  Sigs sig_{};
};

class HttpsClient {
 public:
  // Errors: InvalidArgument, NotFound, AccessDenied (key mode), ResourceExhausted. The messages
  // begin with "admin:".
  static Expected<std::shared_ptr<HttpsClient>> create(HttpsOptions o);
  ~HttpsClient();

  // `hostport` is "host:port". An HTTP status is not an error here (the caller reads `code`); a
  // transport, TLS or identity failure is: LinkDown, Timeout, AccessDenied, Corrupt.
  Expected<HttpResponse> request(const std::string& hostport, const std::string& method, const std::string& target,
                                 const std::string& content_type, const std::string& body,
                                 const std::string& server_identity = {},
                                 unsigned timeout_ms = 0) const;  // R14: 0 = io_timeout_ms, else min(it, io_timeout_ms)

 private:
  HttpsClient(HttpsOptions o, std::shared_ptr<ClientTlsCtx> tls, std::shared_ptr<SSL_CTX> ctx);
  const HttpsOptions o_;
  std::shared_ptr<ClientTlsCtx> tls_;  // HR4: shared signature/generation; the SSL_CTX below is this client's own
  mutable std::mutex ctx_mu_;
  mutable std::shared_ptr<SSL_CTX> ctx_;
  mutable std::uint64_t ctx_gen_ = 0;
  std::shared_ptr<SSL_CTX> current_ctx() const;
};

}  // namespace miracache
