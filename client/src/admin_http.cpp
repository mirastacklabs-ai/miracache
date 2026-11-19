// SPDX-License-Identifier: Apache-2.0
#include "src/admin_http.h"

#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <map>
#include <mutex>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "runtime/bounded.h"
#include "util/clock.h"

namespace miracache {

namespace {

Error err(ErrorCode c, const char* ctx) { return Error{c, ctx}; }

// ---- sockets --------------------------------------------------------------------------------
struct Fd {
  int fd = -1;
  ~Fd() {
    if (fd >= 0) ::close(fd);
  }
};

// Real time budget for one admin call (RealClock: the injected Clock may be a sim clock).
struct Budget {
  RealClock rc;
  Nanos end;
  const std::atomic<bool>* cancel = nullptr;  // HttpsOptions::cancel: true = no time left
  explicit Budget(unsigned ms, const std::atomic<bool>* c = nullptr) : end(rc.now() + std::chrono::milliseconds(ms)), cancel(c) {}
  int left_ms() const {
    if (cancel && cancel->load(std::memory_order_acquire)) return 0;
    const auto l = std::chrono::duration_cast<std::chrono::milliseconds>(end - rc.now()).count();
    return l <= 0 ? 0 : static_cast<int>(std::min<std::int64_t>(l, 1 << 30));
  }
};

// Waits for fd readiness; false on timeout (or cancel: with a cancel flag the wait polls in 50 ms slices).
bool wait_fd(int fd, short ev, const Budget& b) {
  for (;;) {
    int ms = b.left_ms();
    if (ms <= 0) return false;
    if (b.cancel) ms = std::min(ms, 50);
    pollfd p{fd, ev, 0};
    const int r = ::poll(&p, 1, ms);
    if (r == 0) continue;  // a slice (or the whole budget) passed: left_ms decides
    if (r > 0) return true;
    if (r < 0 && errno != EINTR) return false;
  }
}

bool split_hostport(const std::string& hp, std::string& host, std::string& port) {
  const auto c = hp.rfind(':');
  if (c == std::string::npos || c == 0 || c + 1 >= hp.size()) return false;
  host = hp.substr(0, c);
  if (host.size() > 2 && host.front() == '[' && host.back() == ']') host = host.substr(1, host.size() - 2);
  port = hp.substr(c + 1);
  return true;
}

struct Addr {
  int family = 0, socktype = 0, protocol = 0;
  sockaddr_storage ss{};
  socklen_t len = 0;
};
using AddrList = std::vector<Addr>;

AddrList resolve_now(const std::string& host, const std::string& port, int flags) {
  AddrList out;
  addrinfo hints{};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = flags;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res) return out;
  for (addrinfo* a = res; a; a = a->ai_next) {
    Addr x;
    x.family = a->ai_family;
    x.socktype = a->ai_socktype;
    x.protocol = a->ai_protocol;
    x.len = a->ai_addrlen;
    if (x.len > sizeof x.ss) continue;
    std::memcpy(&x.ss, a->ai_addr, x.len);
    out.push_back(x);
  }
  ::freeaddrinfo(res);
  return out;
}

// A03: a numeric address never touches the resolver; a name is resolved on a helper thread and
// the call gives up when the budget runs out (getaddrinfo has no timeout of its own).
Expected<AddrList> resolve(const std::string& host, const std::string& port, const Budget& b) {
  AddrList l = resolve_now(host, port, AI_NUMERICHOST | AI_NUMERICSERV);
  if (!l.empty()) return l;
  if (!run_bounded<AddrList>([host, port] { return resolve_now(host, port, 0); }, static_cast<unsigned>(b.left_ms()), l))
    return err(ErrorCode::Timeout, "admin: resolving the admin address timed out");
  if (l.empty()) return err(ErrorCode::LinkDown, "admin: cannot resolve the admin address");
  return l;
}

Expected<int> tcp_connect(const std::string& hp, const Budget& b) {
  std::string host, port;
  if (!split_hostport(hp, host, port)) return err(ErrorCode::InvalidArgument, "admin: nodes.admin must be host:port");
  auto addrs = resolve(host, port, b);
  if (!addrs) return addrs.error();
  Error last = err(ErrorCode::LinkDown, "admin: connect failed");
  for (const Addr& a : *addrs) {
    Fd s;
    s.fd = ::socket(a.family, a.socktype, a.protocol);
    if (s.fd < 0) continue;
    ::fcntl(s.fd, F_SETFL, ::fcntl(s.fd, F_GETFL, 0) | O_NONBLOCK);
    ::fcntl(s.fd, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
    const int on = 1;
    ::setsockopt(s.fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#endif
    int r = ::connect(s.fd, reinterpret_cast<const sockaddr*>(&a.ss), a.len);
    if (r != 0 && errno == EINPROGRESS) {
      if (!wait_fd(s.fd, POLLOUT, b)) {
        last = err(ErrorCode::Timeout, "admin: connect timed out");
        continue;
      }
      int soerr = 0;
      socklen_t sl = sizeof soerr;
      ::getsockopt(s.fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
      r = soerr == 0 ? 0 : -1;
    }
    if (r == 0) {
      const int fd = s.fd;
      s.fd = -1;
      return fd;
    }
  }
  return last;
}

// The peer leaf's spiffe:// URI SAN. A09: exactly one is accepted; none or several -> false.
bool peer_spiffe(SSL* ssl, std::string& out) {
  out.clear();
  X509* x = SSL_get1_peer_certificate(ssl);
  if (!x) return false;
  int n = 0;
  auto* gns = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr));
  if (gns) {
    for (int i = 0; i < sk_GENERAL_NAME_num(gns); ++i) {
      const GENERAL_NAME* g = sk_GENERAL_NAME_value(gns, i);
      if (g->type != GEN_URI) continue;
      const ASN1_IA5STRING* ia = g->d.uniformResourceIdentifier;
      const std::string v(reinterpret_cast<const char*>(ASN1_STRING_get0_data(ia)), static_cast<std::size_t>(ASN1_STRING_length(ia)));
      if (v.rfind("spiffe://", 0) == 0 && n++ == 0) out = v;
    }
    GENERAL_NAMES_free(gns);
  }
  X509_free(x);
  return n == 1;
}

// A01: OpenSSL's stock socket BIO writes with write(), which raises SIGPIPE on a reset peer. A
// library must not change the process's signal dispositions, so this BIO sends with MSG_NOSIGNAL.
struct SockCtx {
  int fd;
};
int nosig_write(BIO* b, const char* d, size_t n, size_t* written) {
  BIO_clear_retry_flags(b);
  *written = 0;
  if (n == 0) return 1;
  const int fd = static_cast<SockCtx*>(BIO_get_data(b))->fd;
  for (;;) {
    const ssize_t r = ::send(fd, d, n, MSG_NOSIGNAL);
    if (r >= 0) {
      *written = static_cast<size_t>(r);
      return 1;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) BIO_set_retry_write(b);
    return 0;
  }
}
int nosig_read(BIO* b, char* d, size_t n, size_t* got) {
  BIO_clear_retry_flags(b);
  *got = 0;
  if (n == 0) return 1;
  const int fd = static_cast<SockCtx*>(BIO_get_data(b))->fd;
  for (;;) {
    const ssize_t r = ::recv(fd, d, n, 0);
    if (r > 0) {
      *got = static_cast<size_t>(r);
      return 1;
    }
    if (r == 0) {
      BIO_set_flags(b, BIO_FLAGS_IN_EOF);
      return 0;
    }
    if (errno == EINTR) continue;
    if (errno == EAGAIN || errno == EWOULDBLOCK) BIO_set_retry_read(b);
    return 0;
  }
}
long nosig_ctrl(BIO*, int cmd, long, void*) {
  switch (cmd) {
    case BIO_CTRL_FLUSH:
    case BIO_CTRL_PUSH:
    case BIO_CTRL_POP:
    case BIO_CTRL_GET_CLOSE:
    case BIO_CTRL_SET_CLOSE:
      return 1;
    default:
      return 0;
  }
}
int nosig_create(BIO* b) {
  BIO_set_init(b, 1);
  return 1;
}
BIO_METHOD* nosig_method() {
  static BIO_METHOD* m = [] {
    BIO_METHOD* x = BIO_meth_new(BIO_TYPE_SOURCE_SINK | BIO_get_new_index(), "mira-nosigpipe-socket");
    if (x) {
      BIO_meth_set_write_ex(x, nosig_write);
      BIO_meth_set_read_ex(x, nosig_read);
      BIO_meth_set_ctrl(x, nosig_ctrl);
      BIO_meth_set_create(x, nosig_create);
    }
    return x;
  }();
  return m;
}
// Gives `ssl` a socket BIO over `ctx->fd` (not owned; ctx must outlive ssl) that never raises SIGPIPE.
bool attach_nosig_bio(SSL* ssl, SockCtx* ctx) {
  BIO_METHOD* m = nosig_method();
  BIO* b = m ? BIO_new(m) : nullptr;
  if (!b) return false;
  BIO_set_data(b, ctx);
  SSL_set_bio(ssl, b, b);  // one BIO for both directions: SSL owns the single reference
  return true;
}

// Drives an SSL operation to completion within the budget. `op` returns the SSL_* result;
// -2 = timed out.
template <class F>
int ssl_io(SSL* ssl, int fd, const Budget& b, F op, int& ssl_err) {
  for (;;) {
    ERR_clear_error();
    const int r = op();
    if (r > 0) return r;
    ssl_err = SSL_get_error(ssl, r);
    if (ssl_err == SSL_ERROR_WANT_READ) {
      if (!wait_fd(fd, POLLIN, b)) return -2;
    } else if (ssl_err == SSL_ERROR_WANT_WRITE) {
      if (!wait_fd(fd, POLLOUT, b)) return -2;
    } else {
      return r;
    }
  }
}

struct SslFree {
  void operator()(SSL* s) const { SSL_free(s); }
};


}  // namespace

Expected<std::shared_ptr<SSL_CTX>> ClientTlsCtx::build(const std::string& cert, const std::string& key, const std::string& ca) {
  if (cert.empty() || key.empty() || ca.empty())
    return err(ErrorCode::InvalidArgument, "admin: nodes.admin needs tls.cert, tls.key and tls.ca");
  struct stat st{};
  if (::stat(key.c_str(), &st) != 0) return err(ErrorCode::NotFound, "admin: tls.key does not exist");
  if (!S_ISREG(st.st_mode)) return err(ErrorCode::InvalidArgument, "admin: tls.key is not a regular file");
  if ((st.st_mode & 07777) != 0600) return err(ErrorCode::AccessDenied, "admin: tls.key must have mode 0600");

  std::shared_ptr<SSL_CTX> ctx(SSL_CTX_new(TLS_client_method()), SSL_CTX_free);
  if (!ctx) return err(ErrorCode::ResourceExhausted, "admin: SSL_CTX_new");
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
  if (SSL_CTX_load_verify_locations(ctx.get(), ca.c_str(), nullptr) != 1) {
    ERR_clear_error();
    return err(ErrorCode::InvalidArgument, "admin: cannot read tls.ca");
  }
  if (SSL_CTX_use_certificate_chain_file(ctx.get(), cert.c_str()) != 1) {
    ERR_clear_error();
    return err(ErrorCode::InvalidArgument, "admin: cannot read tls.cert");
  }
  if (SSL_CTX_use_PrivateKey_file(ctx.get(), key.c_str(), SSL_FILETYPE_PEM) != 1 || SSL_CTX_check_private_key(ctx.get()) != 1) {
    ERR_clear_error();
    return err(ErrorCode::InvalidArgument, "admin: tls.key unreadable or does not match tls.cert");
  }
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
  SSL_CTX_set_verify_depth(ctx.get(), 4);
  ERR_clear_error();
  return ctx;
}

ClientTlsCtx::Sigs ClientTlsCtx::sigs_of(const std::string& c, const std::string& k, const std::string& a) {
  Sigs s{};
  const std::string* paths[3] = {&c, &k, &a};
  for (int i = 0; i < 3; ++i) {
    struct stat st {};
    if (::stat(paths[i]->c_str(), &st) != 0) continue;  // missing: stays -1
#ifdef __APPLE__
    const std::int64_t m = st.st_mtimespec.tv_sec * 1'000'000'000LL + st.st_mtimespec.tv_nsec;
#else
    const std::int64_t m = st.st_mtim.tv_sec * 1'000'000'000LL + st.st_mtim.tv_nsec;
#endif
    s[static_cast<std::size_t>(i)] = Sig{m, static_cast<std::int64_t>(st.st_size), static_cast<std::int64_t>(st.st_ino)};
  }
  return s;
}

namespace {
std::mutex g_tls_mu;
std::map<std::string, std::weak_ptr<ClientTlsCtx>> g_tls;  // keyed by cert NUL key NUL ca
}  // namespace

Expected<std::shared_ptr<ClientTlsCtx>> ClientTlsCtx::acquire(const std::string& cert, const std::string& key, const std::string& ca) {
  const std::string k = cert + '\0' + key + '\0' + ca;
  std::lock_guard<std::mutex> g(g_tls_mu);
  if (auto it = g_tls.find(k); it != g_tls.end()) {
    if (auto sp = it->second.lock()) {
      // A holder that was idle meanwhile: pick up a rotation that happened before this caller asked.
      (void)sp->reload_if_changed();
      return sp;
    }
  }
  const Sigs sigs = sigs_of(cert, key, ca);  // BEFORE the load: a change after it is seen by the next check
  auto ctx = build(cert, key, ca);           // validates the set; each HttpsClient builds its own context
  if (!ctx) return ctx.error();
  std::shared_ptr<ClientTlsCtx> t(new ClientTlsCtx(cert, key, ca));
  t->sig_ = sigs;
  g_tls[k] = t;
  for (auto it = g_tls.begin(); it != g_tls.end();) it = it->second.expired() ? g_tls.erase(it) : std::next(it);
  return t;
}

ClientTlsCtx::Reload ClientTlsCtx::reload_if_changed(std::string* why) {
  const Sigs now = sigs_of(cert_, key_, ca_);
  {
    std::lock_guard<std::mutex> g(mu_);
    if (now == sig_) return Reload::Unchanged;
  }
  auto c = build(cert_, key_, ca_);
  if (!c) {
    if (why) *why = c.error().context;
    return Reload::Rejected;  // the old contexts stay; sig_ is not updated, so the next call tries again
  }
  std::lock_guard<std::mutex> g(mu_);
  sig_ = now;
  gen_.fetch_add(1, std::memory_order_acq_rel);
  return Reload::Applied;
}

Expected<std::shared_ptr<HttpsClient>> HttpsClient::create(HttpsOptions o) {
  auto tls = ClientTlsCtx::acquire(o.cert, o.key, o.ca);
  if (!tls) return tls.error();
  const std::uint64_t gen = (*tls)->generation();
  auto ctx = (*tls)->fresh();
  if (!ctx) return ctx.error();
  std::shared_ptr<HttpsClient> h(new HttpsClient(std::move(o), std::move(*tls), std::move(*ctx)));
  h->ctx_gen_ = gen;
  return h;
}

HttpsClient::HttpsClient(HttpsOptions o, std::shared_ptr<ClientTlsCtx> tls, std::shared_ptr<SSL_CTX> ctx)
    : o_(std::move(o)), tls_(std::move(tls)), ctx_(std::move(ctx)) {}

// HR4: the context for a NEW connection. After an applied reload this client rebuilds its own from the files; if that
// build fails (the files changed again mid-way) the old context serves and the next request tries again.
std::shared_ptr<SSL_CTX> HttpsClient::current_ctx() const {
  std::lock_guard<std::mutex> g(ctx_mu_);
  const std::uint64_t gen = tls_->generation();
  if (gen != ctx_gen_) {
    if (auto c = tls_->fresh()) {
      ctx_ = std::move(*c);
      ctx_gen_ = gen;
    }
  }
  return ctx_;
}
HttpsClient::~HttpsClient() = default;

Expected<HttpResponse> HttpsClient::request(const std::string& hostport, const std::string& method, const std::string& target,
                                            const std::string& content_type, const std::string& body,
                                            const std::string& server_identity, unsigned timeout_ms) const {
  Budget b(timeout_ms != 0 ? std::min(timeout_ms, o_.io_timeout_ms) : o_.io_timeout_ms, o_.cancel);
  auto cfd = tcp_connect(hostport, b);
  if (!cfd) return cfd.error();
  Fd sock;
  sock.fd = *cfd;
  const int one = 1;
  ::setsockopt(sock.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
  SockCtx sctx{sock.fd};  // outlives ssl (declared first)
  const std::shared_ptr<SSL_CTX> ctx = current_ctx();  // HR4: the context in force for this connection
  std::unique_ptr<SSL, SslFree> ssl(SSL_new(ctx.get()));
  if (!ssl) return err(ErrorCode::ResourceExhausted, "admin: SSL_new");
  if (o_.test_after_connect) o_.test_after_connect(sock.fd);
  if (!attach_nosig_bio(ssl.get(), &sctx)) return err(ErrorCode::ResourceExhausted, "admin: BIO_new");
  SSL_set_connect_state(ssl.get());
  int se = 0;
  int r = ssl_io(ssl.get(), sock.fd, b, [&] { return SSL_connect(ssl.get()); }, se);
  if (r == -2) return err(ErrorCode::Timeout, "admin: TLS handshake timed out");
  if (r <= 0) {
    ERR_clear_error();
    // Chain/cert problems surface as SSL_ERROR_SSL; a reset before any TLS bytes is a down node.
    return se == SSL_ERROR_SSL ? err(ErrorCode::AccessDenied, "admin: TLS handshake failed (server certificate not trusted?)")
                               : err(ErrorCode::LinkDown, "admin: TLS connection failed");
  }
  if (SSL_get_verify_result(ssl.get()) != X509_V_OK) return err(ErrorCode::AccessDenied, "admin: server certificate not trusted");
  if (!server_identity.empty()) {
    std::string id;
    if (!peer_spiffe(ssl.get(), id))
      return err(ErrorCode::AccessDenied, "admin: server certificate must carry exactly one spiffe:// URI SAN");
    if (id != server_identity) return err(ErrorCode::AccessDenied, "admin: server identity does not match nodes.identity");
  }

  std::string req = method + " " + target + " HTTP/1.1\r\nHost: " + hostport + "\r\n";
  if (!content_type.empty()) req += "Content-Type: " + content_type + "\r\n";
  if (method != "GET") req += "Content-Length: " + std::to_string(body.size()) + "\r\n";
  req += "Connection: close\r\n\r\n";
  req += body;
  for (std::size_t off = 0; off < req.size();) {
    r = ssl_io(ssl.get(), sock.fd, b, [&] { return SSL_write(ssl.get(), req.data() + off, static_cast<int>(req.size() - off)); }, se);
    if (r == -2) return err(ErrorCode::Timeout, "admin: request timed out");
    if (r <= 0) {
      ERR_clear_error();
      return err(ErrorCode::LinkDown, "admin: request failed");
    }
    off += static_cast<std::size_t>(r);
  }
  std::string resp;
  bool clean_close = false;  // the peer sent close_notify
  for (;;) {
    char buf[4096];
    r = ssl_io(ssl.get(), sock.fd, b, [&] { return SSL_read(ssl.get(), buf, sizeof buf); }, se);
    if (r == -2) return err(ErrorCode::Timeout, "admin: response timed out");
    if (r <= 0) {
      ERR_clear_error();
      if (resp.empty()) return err(ErrorCode::AccessDenied, "admin: connection closed (client certificate refused?)");
      clean_close = se == SSL_ERROR_ZERO_RETURN;
      break;  // end of response (Connection: close)
    }
    resp.append(buf, static_cast<std::size_t>(r));
    if (resp.size() > o_.max_response) return err(ErrorCode::Corrupt, "admin: response too large");
  }
  if (resp.rfind("HTTP/1.1 ", 0) != 0 || resp.size() < 12) return err(ErrorCode::Corrupt, "admin: not an HTTP response");
  HttpResponse out;
  out.code = std::atoi(resp.c_str() + 9);
  const auto hdr_end = resp.find("\r\n\r\n");
  if (hdr_end != std::string::npos) out.body = resp.substr(hdr_end + 4);
  else if (out.code == 200) return err(ErrorCode::Corrupt, "admin: bad response");
  // X15: a body cut short by a dropped connection must be a transport error, never a (bad) bundle. Either the
  // Content-Length matches the bytes received, or the TLS connection closed cleanly (close_notify).
  if (hdr_end != std::string::npos) {
    std::string head = resp.substr(0, hdr_end);
    for (char& c : head) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const auto cl = head.find("\r\ncontent-length:");
    if (cl != std::string::npos) {
      char* endp = nullptr;
      const unsigned long long want = std::strtoull(head.c_str() + cl + 17, &endp, 10);
      if (endp == head.c_str() + cl + 17 || out.body.size() != want) return err(ErrorCode::LinkDown, "admin: response truncated");
    } else if (!clean_close) {
      return err(ErrorCode::LinkDown, "admin: response truncated (connection dropped)");
    }
  }
  return out;
}

}  // namespace miracache
