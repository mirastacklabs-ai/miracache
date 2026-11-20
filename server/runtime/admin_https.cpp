// SPDX-License-Identifier: Apache-2.0
#include "server/runtime/admin_https.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <memory>
#include <optional>
#include <cstdlib>
#include <cstring>

#include "control/floor_state.h"
#include "server/node_config.h"
#include "server/runtime/bundle_store.h"
#include "server/runtime/net_util.h"
#include "util/clock.h"
#include "util/log.h"

namespace miracache::server {
namespace {

// ---- strict JSON for the one request shape ---------------------------------------------------
struct Json {
  const std::string& s;
  std::size_t i = 0;
  void ws() {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
  }
  bool eat(char c) {
    ws();
    if (i < s.size() && s[i] == c) {
      ++i;
      return true;
    }
    return false;
  }
  // A string without escapes or control characters, at most 32 bytes.
  bool str(std::string& out, std::size_t max_len = 32) {
    ws();
    if (i >= s.size() || s[i] != '"') return false;
    ++i;
    out.clear();
    while (i < s.size() && s[i] != '"') {
      const unsigned char c = static_cast<unsigned char>(s[i]);
      if (c < 0x20 || c == '\\' || c >= 0x80 || out.size() >= max_len) return false;
      out.push_back(static_cast<char>(c));
      ++i;
    }
    if (i >= s.size()) return false;
    ++i;
    return true;
  }
  // A non-negative integer without sign, fraction, exponent or leading zeros, at most 6 digits.
  bool num(std::uint32_t& out) {
    ws();
    const std::size_t b = i;
    std::uint32_t v = 0;
    while (i < s.size() && s[i] >= '0' && s[i] <= '9' && i - b < 7) v = v * 10 + static_cast<std::uint32_t>(s[i++] - '0');
    if (i == b || i - b > 6 || (s[b] == '0' && i - b > 1)) return false;
    if (i < s.size() && (s[i] == '.' || s[i] == 'e' || s[i] == 'E' || (s[i] >= '0' && s[i] <= '9'))) return false;
    out = v;
    return true;
  }
};

bool class_of(const std::string& n, fabric::EpClass& c) {
  if (n == "control") c = fabric::EpClass::Control;
  else if (n == "fetch") c = fabric::EpClass::Fetch;
  else if (n == "ingest") c = fabric::EpClass::Ingest;
  else return false;
  return true;
}
const char* class_name(std::uint8_t c) {
  static const char* n[] = {"control", "fetch", "ingest"};
  return c < 3 ? n[c] : "?";
}

// ---- Request bodies ------------------------------------------------------------------------
// POST /v1/drain: empty, `{}` or `{"drain_ms":N}` (N in 0..600000). Strict like the ticket body.
bool parse_drain_request(const std::string& body, std::optional<std::uint32_t>& drain_ms) {
  Json j{body};
  j.ws();
  if (j.i == body.size()) return true;
  if (!j.eat('{')) return false;
  if (!j.eat('}')) {
    std::string key;
    std::uint32_t v = 0;
    if (!j.str(key) || key != "drain_ms" || !j.eat(':') || !j.num(v) || v > 600000 || !j.eat('}')) return false;
    drain_ms = v;
  }
  j.ws();
  return j.i == body.size();
}

// "YYYY-MM-DDTHH:MM:SSZ" (1970..9999) to unix seconds; false on anything else.
bool parse_utc_seconds(const std::string& s, std::int64_t& out) {
  if (s.size() != 20 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' || s[16] != ':' || s[19] != 'Z') return false;
  auto d = [&](std::size_t at, std::size_t n, int& v) {
    v = 0;
    for (std::size_t k = 0; k < n; ++k) {
      if (s[at + k] < '0' || s[at + k] > '9') return false;
      v = v * 10 + (s[at + k] - '0');
    }
    return true;
  };
  int Y, M, D, h, m, sec;
  if (!d(0, 4, Y) || !d(5, 2, M) || !d(8, 2, D) || !d(11, 2, h) || !d(14, 2, m) || !d(17, 2, sec)) return false;
  static const int mdays[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  const bool leap = (Y % 4 == 0 && Y % 100 != 0) || Y % 400 == 0;
  if (Y < 1970 || M < 1 || M > 12 || D < 1 || D > mdays[M - 1] + (M == 2 && leap ? 1 : 0) || h > 23 || m > 59 || sec > 59) return false;
  // days from civil (Howard Hinnant)
  const int y = Y - (M <= 2 ? 1 : 0);
  const int era = y / 400;
  const int yoe = y - era * 400;
  const int doy = (153 * (M + (M > 2 ? -3 : 9)) + 2) / 5 + D - 1;
  const int doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  const std::int64_t days = static_cast<std::int64_t>(era) * 146097 + doe - 719468;
  out = days * 86400 + h * 3600 + m * 60 + sec;
  return true;
}

// POST /v1/drop_principal {"name":"...","drop_before":"YYYY-MM-DDTHH:MM:SSZ"}, both required, any order.
bool parse_drop_request(const std::string& body, std::string& name, std::string& when, std::int64_t& secs) {
  Json j{body};
  bool have_name = false, have_when = false;
  if (!j.eat('{')) return false;
  for (;;) {
    std::string key, v;
    if (!j.str(key) || !j.eat(':') || !j.str(v, 128)) return false;
    if (key == "name" && !have_name) {
      name = v;
      have_name = true;
    } else if (key == "drop_before" && !have_when) {
      when = v;
      have_when = true;
    } else {
      return false;
    }
    if (j.eat(',')) continue;
    if (!j.eat('}')) return false;
    break;
  }
  j.ws();
  return j.i == body.size() && have_name && have_when && !name.empty() && parse_utc_seconds(when, secs);
}

// The value of a top-level `"key":"value"` in one of our own reply bodies (no escapes in what we look up).
std::string reply_field(const std::string& body, const char* key) {
  const std::string pat = std::string("\"") + key + "\":\"";
  const auto p = body.find(pat);
  if (p == std::string::npos) return {};
  const auto b = p + pat.size();
  const auto e = body.find('"', b);
  return e == std::string::npos ? std::string() : body.substr(b, e - b);
}

const char* action_of(RouteId id) {
  switch (id) {
    case RouteId::Tickets: return "tickets.issue";
    case RouteId::BundleGet: return "bundle.get";
    case RouteId::BundlePost: return "bundle.push";
    case RouteId::Identity: return "identity.get";
    case RouteId::Drain: return "drain";
    case RouteId::DropPrincipal: return "drop_principal";
  }
  return "?";
}

// ---- socket BIO that never raises SIGPIPE -----------------------------------------------
// OpenSSL's stock socket BIO uses write(2): a peer that already reset the connection makes the first
// write kill the process unless SIGPIPE is ignored. This BIO sends with MSG_NOSIGNAL, so the
// listener is safe whatever the process's signal disposition is.
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
int nosig_write(BIO* b, const char* in, int inl) {
  BIO_clear_retry_flags(b);
  if (inl <= 0) return 0;
  const ssize_t n = ::send(BIO_get_fd(b, nullptr), in, static_cast<std::size_t>(inl), MSG_NOSIGNAL);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR || errno == ENOBUFS) BIO_set_retry_write(b);
    return -1;
  }
  return static_cast<int>(n);
}
int nosig_read(BIO* b, char* out, int outl) {
  BIO_clear_retry_flags(b);
  if (out == nullptr || outl <= 0) return 0;
  const ssize_t n = ::recv(BIO_get_fd(b, nullptr), out, static_cast<std::size_t>(outl), 0);
  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) BIO_set_retry_read(b);
    return -1;
  }
  return static_cast<int>(n);
}
BIO_METHOD* nosig_method() {
  static BIO_METHOD* m = [] {
    BIO_METHOD* x = BIO_meth_new(BIO_TYPE_SOCKET, "mira-nosigpipe-socket");
    const BIO_METHOD* s = BIO_s_socket();
    BIO_meth_set_create(x, BIO_meth_get_create(s));
    BIO_meth_set_destroy(x, BIO_meth_get_destroy(s));
    BIO_meth_set_ctrl(x, BIO_meth_get_ctrl(s));
    BIO_meth_set_write(x, nosig_write);
    BIO_meth_set_read(x, nosig_read);
    return x;
  }();
  return m;
}

// ---- TLS I/O under a deadline ----------------------------------------------------------------
constexpr long kTimeout = -2;
constexpr int kSliceMs = 50;  // longest a connection thread sleeps before it re-checks the stop flag

// Runs a non-blocking SSL op until it finishes or `deadline` passes (or `stop` is set). >0 result,
// 0 closed, -1 error, -2 timeout/stopped. poll() is sliced and EINTR is retried.
template <typename F>
long io(SSL* ssl, int fd, Nanos deadline, const std::atomic<bool>& stop, F op) {
  RealClock clock;
  for (;;) {
    ERR_clear_error();
    const long r = op();
    if (r > 0) return r;
    const int e = SSL_get_error(ssl, static_cast<int>(r));
    short ev = 0;
    if (e == SSL_ERROR_WANT_READ) ev = POLLIN;
    else if (e == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
    else return e == SSL_ERROR_ZERO_RETURN ? 0 : -1;
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock.now()).count();
    if (left <= 0 || stop.load()) return kTimeout;
    pollfd p{fd, ev, 0};
    if (net::poll_retry(&p, 1, static_cast<int>(std::min<long long>(left, kSliceMs))) < 0) return -1;
  }
}

bool write_all(SSL* ssl, int fd, Nanos deadline, const std::atomic<bool>& stop, const std::string& s) {
  std::size_t off = 0;
  while (off < s.size()) {
    const long n = io(ssl, fd, deadline, stop, [&] {
      return static_cast<long>(SSL_write(ssl, s.data() + off, static_cast<int>(s.size() - off)));
    });
    if (n <= 0) return false;
    off += static_cast<std::size_t>(n);
  }
  return true;
}

std::string response(int code, const char* reason, const std::string& body, const char* ctype = "application/json") {
  return "HTTP/1.1 " + std::to_string(code) + ' ' + reason + "\r\nContent-Type: " + ctype +
         "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
}
const char* http_reason(int code) {
  switch (code) {
    case 200: return "OK";
    case 304: return "Not Modified";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 409: return "Conflict";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    default: return "Internal Server Error";
  }
}
std::string err_body(const char* msg) { return std::string("{\"error\":\"") + msg + "\"}"; }

// The spiffe:// URI SAN of the peer leaf; empty if none. `multi` is set when the leaf carries more
// than one spiffe:// URI SAN (ambiguous identity: refused).
std::string peer_identity(SSL* ssl, bool& multi) {
  std::string id;
  multi = false;
  X509* x = SSL_get1_peer_certificate(ssl);
  if (!x) return id;
  auto* gns = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x, NID_subject_alt_name, nullptr, nullptr));
  if (gns) {
    for (int i = 0; i < sk_GENERAL_NAME_num(gns); ++i) {
      const GENERAL_NAME* g = sk_GENERAL_NAME_value(gns, i);
      if (g->type != GEN_URI) continue;
      const ASN1_IA5STRING* u = g->d.uniformResourceIdentifier;
      std::string v(reinterpret_cast<const char*>(ASN1_STRING_get0_data(u)), static_cast<std::size_t>(ASN1_STRING_length(u)));
      if (v.rfind("spiffe://", 0) == 0) {
        if (!id.empty() || multi) {
          multi = true;
          continue;
        }
        if (v.size() <= 256) id = std::move(v);
        else multi = true;  // oversized: refuse rather than fall through to a later SAN
      }
    }
    GENERAL_NAMES_free(gns);
  }
  X509_free(x);
  return id;
}

std::string lower(std::string s) {
  for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return s;
}

Expected<std::shared_ptr<SSL_CTX>> make_ctx(const AdminOptions& o) {
  if (o.cert.empty() || o.key.empty() || o.ca.empty()) return Error{ErrorCode::InvalidArgument, "admin: cert, key and ca are required"};
  // Open once, check the opened fd (no stat-then-open race), and parse the key from the bytes read.
  std::string key_pem;
  {
    const int kfd = ::open(o.key.c_str(), O_RDONLY | O_CLOEXEC);
    if (kfd < 0) return Error{ErrorCode::NotFound, "admin: cannot read the key file"};
    struct stat st {};
    if (::fstat(kfd, &st) != 0 || !S_ISREG(st.st_mode) || (st.st_mode & 07777) != 0600 || st.st_size > (1 << 20)) {
      ::close(kfd);
      return Error{ErrorCode::AccessDenied, "admin: key file must be a regular file with mode 0600"};
    }
    char kb[4096];
    for (;;) {
      const ssize_t n = ::read(kfd, kb, sizeof kb);
      if (n < 0 && errno == EINTR) continue;
      if (n <= 0) break;
      key_pem.append(kb, static_cast<std::size_t>(n));
    }
    ::close(kfd);
    OPENSSL_cleanse(kb, sizeof kb);
  }
  std::shared_ptr<SSL_CTX> ctx(SSL_CTX_new(TLS_server_method()), SSL_CTX_free);
  if (!ctx) return Error{ErrorCode::ResourceExhausted, "admin: SSL_CTX_new"};
  SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx.get(), TLS1_3_VERSION);
  SSL_CTX_set_options(ctx.get(), SSL_OP_NO_RENEGOTIATION | SSL_OP_NO_TICKET);
  SSL_CTX_set_num_tickets(ctx.get(), 0);
  SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_OFF);
  if (SSL_CTX_use_certificate_chain_file(ctx.get(), o.cert.c_str()) != 1)
    return Error{ErrorCode::InvalidArgument, "admin: cannot load the certificate"};
  {
    std::unique_ptr<BIO, decltype(&BIO_free)> kbio(BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size())), BIO_free);
    std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> pk(
        kbio ? PEM_read_bio_PrivateKey(kbio.get(), nullptr, nullptr, nullptr) : nullptr, EVP_PKEY_free);
    OPENSSL_cleanse(key_pem.data(), key_pem.size());
    if (!pk || SSL_CTX_use_PrivateKey(ctx.get(), pk.get()) != 1)
      return Error{ErrorCode::InvalidArgument, "admin: cannot load the private key"};
  }
  if (SSL_CTX_check_private_key(ctx.get()) != 1) return Error{ErrorCode::InvalidArgument, "admin: key does not match the certificate"};
  if (SSL_CTX_load_verify_locations(ctx.get(), o.ca.c_str(), nullptr) != 1)
    return Error{ErrorCode::InvalidArgument, "admin: cannot load the CA"};
  if (STACK_OF(X509_NAME)* names = SSL_load_client_CA_file(o.ca.c_str())) SSL_CTX_set_client_CA_list(ctx.get(), names);
  SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
  SSL_CTX_set_verify_depth(ctx.get(), 4);
  ERR_clear_error();
  return ctx;
}

}  // namespace

BIO* new_nosigpipe_socket_bio(int fd) {
  BIO* bio = BIO_new(nosig_method());
  if (bio) BIO_set_fd(bio, fd, BIO_NOCLOSE);  // the caller keeps the fd
  return bio;
}

Expected<TicketRequest> parse_ticket_request(const std::string& body) {
  const Error bad{ErrorCode::InvalidArgument, "admin: malformed request body"};
  Json j{body};
  TicketRequest r;
  bool have_class = false, have_classes = false, have_rail = false, have_count = false;
  if (!j.eat('{')) return bad;
  if (!j.eat('}')) {
    for (;;) {
      std::string key;
      if (!j.str(key) || !j.eat(':')) return bad;
      if (key == "class" && !have_class) {
        std::string v;
        fabric::EpClass c;
        if (!j.str(v) || !class_of(v, c)) return bad;
        r.classes.push_back(c);
        have_class = true;
      } else if (key == "classes" && !have_classes) {
        if (!j.eat('[')) return bad;
        for (bool first = true;; first = false) {
          if (!first && !j.eat(',')) break;
          if (first && j.eat(']')) return bad;  // empty list
          std::string v;
          fabric::EpClass c;
          if (!j.str(v) || !class_of(v, c)) return bad;
          if (std::find(r.classes.begin(), r.classes.end(), c) != r.classes.end() || r.classes.size() >= 3) return bad;
          r.classes.push_back(c);
        }
        if (!j.eat(']')) return bad;
        have_classes = true;
      } else if (key == "rail" && !have_rail) {
        std::uint32_t v;
        if (!j.num(v) || v > 255) return bad;
        r.rail = static_cast<std::uint8_t>(v);
        have_rail = true;
      } else if (key == "count" && !have_count) {
        if (!j.num(r.count)) return bad;
        have_count = true;
      } else {
        return bad;  // unknown or duplicate field
      }
      if (j.eat(',')) continue;
      if (!j.eat('}')) return bad;
      break;
    }
  }
  j.ws();
  if (j.i != body.size()) return bad;
  if (have_class == have_classes) return bad;  // exactly one of the two forms
  if (r.count < 1 || r.count > AdminHttps::kMaxCount) return bad;
  return r;
}

AdminHttps::AdminHttps(int fd, std::uint16_t port, AdminOptions o, std::shared_ptr<SSL_CTX> ctx, telemetry::Registry& reg)
    : lfd_(fd), port_(port), opt_(std::move(o)), reg_(reg), ctx_(std::move(ctx)) {
  ttl_s_.store(opt_.ttl_s);
  max_conns_.store(std::max<std::uint32_t>(1, opt_.max_conns));
  drain_ms_.store(opt_.drain_ms);
  lab_rbac_.set(opt_.lab_rbac);
  tls_fail_ = &reg_.counter("miracache_admin_tls_fail_total", "Admin TLS handshakes that failed or timed out.");
}

Expected<std::unique_ptr<AdminHttps>> AdminHttps::start(const AdminOptions& o, telemetry::Registry& reg) {
  if (o.listen.empty()) return std::unique_ptr<AdminHttps>();
  const auto colon = o.listen.rfind(':');
  if (colon == std::string::npos) return Error{ErrorCode::InvalidArgument, "admin: listen wants host:port"};
  const std::string host = o.listen.substr(0, colon);
  auto port = parse_port(o.listen.substr(colon + 1), /*allow_zero=*/true);
  if (!port) return Error{ErrorCode::InvalidArgument, "admin: bad port"};
  const CredSigs sigs = cred_sigs(o);  // BEFORE the load: a change after it is seen by the next check
  auto ctx = make_ctx(o);
  if (!ctx) return ctx.error();
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.empty() ? nullptr : host.c_str(), std::to_string(*port).c_str(), &hints, &res) != 0 || !res)
    return Error{ErrorCode::InvalidArgument, "admin: cannot resolve listen address"};
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    ::freeaddrinfo(res);
    return Error{ErrorCode::ResourceExhausted, "admin: socket"};
  }
  int one = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  net::set_nonblock_cloexec(fd);
  const bool bound = ::bind(fd, res->ai_addr, res->ai_addrlen) == 0 && ::listen(fd, 16) == 0;
  ::freeaddrinfo(res);
  if (!bound) {
    ::close(fd);
    return Error{ErrorCode::Busy, "admin: cannot bind or listen"};
  }
  sockaddr_in sa{};
  socklen_t sl = sizeof sa;
  (void)::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &sl);
  std::unique_ptr<AdminHttps> a(new AdminHttps(fd, ntohs(sa.sin_port), o, std::move(*ctx), reg));
  a->cred_sig_ = sigs;
  a->acceptor_ = std::thread([p = a.get()] { p->accept_loop(); });  // lint:server-runtime
  return a;
}

AdminHttps::~AdminHttps() { stop(); }

void AdminHttps::stop() {
  if (stop_.exchange(true)) return;
  if (acceptor_.joinable()) acceptor_.join();
  reap(true);
  if (lfd_ >= 0) ::close(lfd_);
  lfd_ = -1;
  if (opt_.audit) opt_.audit->flush_all();  // the last second's coalesced denials
}

AdminHttps::CredSigs AdminHttps::cred_sigs(const AdminOptions& o) {
  CredSigs s{};
  const std::string* paths[3] = {&o.cert, &o.key, &o.ca};
  for (int i = 0; i < 3; ++i) {
    struct stat st {};
    if (::stat(paths[i]->c_str(), &st) != 0) continue;  // missing: size stays -1
#ifdef __APPLE__
    const std::int64_t m = st.st_mtimespec.tv_sec * 1'000'000'000LL + st.st_mtimespec.tv_nsec;
#else
    const std::int64_t m = st.st_mtim.tv_sec * 1'000'000'000LL + st.st_mtim.tv_nsec;
#endif
    s[i] = FileSig{m, static_cast<std::int64_t>(st.st_size), static_cast<std::int64_t>(st.st_ino)};
  }
  return s;
}

// The 10 s stat check. A changed file is loaded as a whole (cert + key + ca); if it does not parse or the key does
// not match the certificate (a non-atomic replacement, a half-written file) the old material stays in use and the same
// check runs again at the next tick, because the failed signature is not remembered.
void AdminHttps::maybe_reload_credentials() {
  RealClock clock;
  const std::int64_t now = clock.now().count();
  if (now < next_cred_ns_) return;
  next_cred_ns_ = now + static_cast<std::int64_t>(opt_.cred_stat_ms) * 1'000'000;
  AdminOptions full;  // the running options (listen, ttl, max_conns, drain_ms, rbac): opt_ is written by reload_credentials
  CredSigs have;
  {
    std::lock_guard<std::mutex> g(ctx_mu_);
    full = opt_;
    have = cred_sig_;
  }
  if (cred_sigs(full) == have) return;
  if (auto st = reload_credentials(full); !st)
    log::write(log::Level::Warn, "admin", "credential reload rejected; keeping the old certificate", {{"err", st.error().context}});
  else
    log::write(log::Level::Info, "admin", "credentials reloaded (file change)");
}

Status AdminHttps::reload_credentials(const AdminOptions& o) {
  const CredSigs sigs = cred_sigs(o);
  auto c = make_ctx(o);
  if (!c) {
    reg_.counter("miracache_cred_reload_total", "Credential file reloads, by kind and result.",
                 {{"kind", "admin_tls"}, {"result", "rejected"}})
        .inc();
    return c.error();
  }
  reg_.counter("miracache_cred_reload_total", "Credential file reloads, by kind and result.",
               {{"kind", "admin_tls"}, {"result", "applied"}})
      .inc();
  std::lock_guard<std::mutex> g(ctx_mu_);
  cred_sig_ = sigs;
  ctx_ = std::move(*c);
  opt_.cert = o.cert;
  opt_.key = o.key;
  opt_.ca = o.ca;
  opt_.ttl_s = o.ttl_s;
  opt_.max_conns = o.max_conns;
  ttl_s_.store(o.ttl_s);
  max_conns_.store(std::max<std::uint32_t>(1, o.max_conns));
  drain_ms_.store(o.drain_ms);
  lab_rbac_.set(o.lab_rbac);  // SIGHUP: lab bindings change at once (bundle mode ignores them)
  return {};
}

std::shared_ptr<SSL_CTX> AdminHttps::ctx() const {
  std::lock_guard<std::mutex> g(ctx_mu_);
  return ctx_;
}

void AdminHttps::count(const char* path, int code) {
  reg_.counter("miracache_admin_requests_total", "Admin API requests, by path and status code.",
               {{"path", path}, {"code", std::to_string(code)}})
      .inc();
}

bool AdminHttps::audit_record(const control::AuditEntry& e) {
  if (opt_.audit) {
    if (opt_.audit->record(e)) return true;
    reg_.counter("miracache_audit_errors_total", "Audit entries that could not be written.").inc();
    return false;
  }
  if (opt_.audit_failed) {  // the signature gates bundles; the apply is logged to stderr only and counted
    log::write(log::Level::Warn, "audit", e.action,
               {{"actor", e.actor}, {"role", e.role}, {"target", e.target}, {"result", e.result}, {"reason", e.reason},
                {"generation", e.generation ? std::to_string(*e.generation) : std::string()}, {"audit_log", "unavailable"}});
    reg_.counter("miracache_audit_unlogged_total", "Audit entries only logged to stderr because the audit log is unavailable.",
                 {{"kind", "action"}})
        .inc();
  }
  return true;
}

void AdminHttps::audit_denied(const control::AuditEntry& e) {
  if (opt_.audit) {
    opt_.audit->deny(e);
  } else if (opt_.audit_failed) {
    reg_.counter("miracache_audit_unlogged_total", "Audit entries only logged to stderr because the audit log is unavailable.",
                 {{"kind", "denial"}})
        .inc();
  }
}

// Store thread (swap task) or the admin thread: the entries of an applied bundle.
void AdminHttps::write_apply_audit(const std::string& identity, const std::string& role, const PushOutcome& o) {
  auto make = [&](const char* action, const char* reason) {
    control::AuditEntry e;
    e.actor = identity;
    e.role = role;
    e.action = action;
    e.target = "bundle";
    e.result = "ok";
    e.reason = reason;
    e.generation = o.generation;
    return e;
  };
  control::AuditEntry e = make("bundle.push", "applied");
  if (o.sec_generation) e.detail.emplace_back("sec_generation", *o.sec_generation);
  e.detail.emplace_back("epoch", std::uint64_t{o.epoch});
  e.detail.emplace_back("applied_hash", o.applied_hash);
  e.detail.emplace_back("rbac_added", o.rbac_added);
  e.detail.emplace_back("rbac_removed", o.rbac_removed);
  e.detail.emplace_back("rbac_changed", o.rbac_changed);
  (void)audit_record(e);
  if (o.rbac_added + o.rbac_removed + o.rbac_changed + o.bindings_added + o.bindings_removed + o.bindings_changed != 0) {
    control::AuditEntry b = make("bindings.change", "applied");
    b.detail.emplace_back("rbac_added", o.rbac_added);
    b.detail.emplace_back("rbac_removed", o.rbac_removed);
    b.detail.emplace_back("rbac_changed", o.rbac_changed);
    b.detail.emplace_back("identities_added", o.bindings_added);
    b.detail.emplace_back("identities_removed", o.bindings_removed);
    b.detail.emplace_back("identities_changed", o.bindings_changed);
    (void)audit_record(b);
  }
}

void AdminHttps::reap(bool all) {
  for (auto it = workers_.begin(); it != workers_.end();) {
    if (all || (*it)->done.load()) {
      ::pthread_join((*it)->t, nullptr);  // workers_ only holds started threads
      if (auto ip = per_ip_.find((*it)->ip); ip != per_ip_.end() && --ip->second == 0) per_ip_.erase(ip);
      it = workers_.erase(it);
    } else {
      ++it;
    }
  }
}

void AdminHttps::budget_expired(int cause, const std::string& peer, int budget_ms) {
  static const char* const kCause[2] = {"handshake_timeout", "store_thread_busy"};
  reg_.counter("miracache_admin_budget_expired_total", "Admin requests that ran out of a server time budget, by cause.",
               {{"cause", kCause[cause]}})
      .inc();
  RealClock clock;
  const std::int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(clock.now()).count();
  std::int64_t last = last_expiry_log_ms_[cause].load();
  if (now_ms - last < 1000 || !last_expiry_log_ms_[cause].compare_exchange_strong(last, now_ms)) return;  // one line per second
  const char* msg = cause == 0 ? "admin request failed: TLS handshake did not finish within its budget (client slow, or this node's CPU is starved)"
                               : "admin request failed: the store thread did not pick it up within its budget (busy; answered 504)";
  log::write(log::Level::Warn, "admin", msg, {{"cause", kCause[cause]}, {"client", peer}, {"budget_ms", std::to_string(budget_ms)}});
}

void AdminHttps::reject(const char* reason) {
  reg_.counter("miracache_admin_conn_rejected_total", "Admin connections closed at accept without TLS, by reason.",
               {{"reason", reason}})
      .inc();
}

void AdminHttps::accept_loop() {
  net::block_all_signals();
  while (!stop_.load()) {
    reap(false);
    if (opt_.bundle) opt_.bundle->maybe_reload_trust();  // the 10 s trust-file stat check, off the store loop
    maybe_reload_credentials();                          // the same for cert, key and ca
    if (opt_.audit) opt_.audit->tick();  // write closed coalescing windows, fsync at most once a second
    pollfd p{lfd_, POLLIN, 0};
    if (net::poll_retry(&p, 1, kSliceMs) <= 0) continue;
    sockaddr_in peer{};
    socklen_t pl = sizeof peer;
    int fd = ::accept(lfd_, reinterpret_cast<sockaddr*>(&peer), &pl);
    if (fd < 0) continue;
    // A connection thread that finished while we sat in poll() still counts against the limits
    // until reaped; reap here so a client reconnecting right after a closed call is not refused per_ip.
    reap(false);
    net::set_nonblock_cloexec(fd);
    net::set_send_timeout(fd, 2000);
#ifdef SO_NOSIGPIPE
    {
      int on = 1;
      (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
    }
#endif
    // Over a limit: close at once. No TLS, no I/O, nothing else on this thread.
    if (workers_.size() >= max_conns_.load()) {
      reject("busy");
      ::close(fd);
      continue;
    }
    const std::uint32_t ip = peer.sin_addr.s_addr;
    char ipbuf[INET_ADDRSTRLEN] = "?";
    ::inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof ipbuf);
    const std::string peer_str = std::string(ipbuf) + ":" + std::to_string(ntohs(peer.sin_port));
    if (const auto it = per_ip_.find(ip); it != per_ip_.end() && it->second >= kMaxPerIp) {
      reject("per_ip");
      ::close(fd);
      continue;
    }
    auto w = std::make_unique<Worker>();
    w->ip = ip;
    Worker* raw = w.get();
    if (!net::spawn(raw->t, [this, raw, fd, peer_str] {
          net::block_all_signals();
          serve(fd, peer_str);
          ::close(fd);
          raw->done.store(true);
        })) {  // cannot start a thread: drop this connection, keep accepting
      reject("thread");
      ::close(fd);
      continue;
    }
    ++per_ip_[ip];
    workers_.push_back(std::move(w));
  }
}

bool AdminHttps::run_on_store(std::function<void(Server&)> task, const std::atomic<bool>& stop) {
  RealClock clock;
  auto t = std::make_shared<StoreTask>();
  t->fn = std::move(task);
  {
    std::lock_guard<std::mutex> g(q_mu_);
    tq_.push_back(t);
  }
  if (opt_.wakeup) opt_.wakeup();
  std::unique_lock<std::mutex> lk(t->m);
  const Nanos until = clock.now() + std::chrono::milliseconds(store_wait_ms());
  while (!t->done) {
    if (stop.load() || clock.now() >= until) return false;  // the task still runs when pump() gets to it
    t->cv.wait_for(lk, std::chrono::milliseconds(20), [&] { return t->done; });
  }
  return true;
}

std::size_t AdminHttps::pump(Server& srv) {
  std::deque<std::shared_ptr<Pending>> work;
  std::deque<std::shared_ptr<StoreTask>> tasks;
  {
    std::lock_guard<std::mutex> g(q_mu_);
    work.swap(q_);
    tasks.swap(tq_);
  }
  for (auto& t : tasks) {  // bundle swaps are persisted already: they run even if the waiter gave up
    t->fn(srv);
    std::lock_guard<std::mutex> g(t->m);
    t->done = true;
    t->cv.notify_all();
  }
  for (auto& p : work) {
    std::lock_guard<std::mutex> g(p->m);
    if (p->abandoned) continue;  // the waiter gave up: issue nothing
    p->ok = true;
    // Check the whole batch against the caps first, so a failure never leaves earlier classes live.
    const std::uint32_t total = p->req.count * static_cast<std::uint32_t>(p->req.classes.size());
    if (auto st = srv.check_issue_capacity(p->identity, total); !st) {
      p->ok = false;
      p->err = st.error();
    } else {
      for (auto cls : p->req.classes) {
        auto t = srv.issue_ticket(p->identity, cls, p->req.rail, p->req.count);
        if (!t) {  // not expected after the check (e.g. a bad rail): earlier classes expire unredeemed
          p->ok = false;
          p->err = t.error();
          p->out.clear();
          break;
        }
        for (const auto& tk : *t) p->out.emplace_back(cls, tk);
      }
    }
    p->done = true;
    p->cv.notify_all();
  }
  return work.size() + tasks.size();
}

void AdminHttps::serve(int fd, const std::string& peer) {
  RealClock clock;
  const std::atomic<bool>& stop = stop_;
  net::set_nonblock_cloexec(fd);
  auto cx = ctx();
  std::unique_ptr<SSL, decltype(&SSL_free)> ssl(SSL_new(cx.get()), SSL_free);
  if (!ssl) return;
  BIO* bio = new_nosigpipe_socket_bio(fd);
  if (!bio) return;
  SSL_set_bio(ssl.get(), bio, bio);  // the SSL owns the BIO; the fd stays ours
  SSL_set_accept_state(ssl.get());
  SSL* s = ssl.get();
  // Separate budgets: a short one for the handshake, then the request budget.
  const int hs_ms = opt_.handshake_ms_for_test > 0 ? static_cast<int>(opt_.handshake_ms_for_test) : kHandshakeMs;
  const long hs = io(s, fd, clock.now() + std::chrono::milliseconds(hs_ms), stop, [&] { return static_cast<long>(SSL_accept(s)); });
  if (hs <= 0) {
    tls_fail_->inc();
    if (hs == kTimeout && !stop.load()) budget_expired(0, peer, hs_ms);
    ERR_clear_error();
    return;
  }
  const Nanos deadline = clock.now() + std::chrono::milliseconds(kTimeoutMs);
  bool multi_san = false;
  const std::string identity = peer_identity(s, multi_san);

  // Request: head, then Content-Length bytes of body; all within kMaxRequestBytes.
  std::string req;
  char buf[16384];
  std::size_t head_end = std::string::npos;
  std::size_t want_body = 0;
  std::size_t max_req = kMaxRequestBytes;  // POST /v1/bundle raises it to head + kMaxEnvelopeBytes
  bool have_len = false;
  auto reply = [&](const char* path, int code, const char* reason, const std::string& body,
                   const char* ctype = "application/json") {
    count(path, code);
    (void)write_all(s, fd, clock.now() + std::chrono::milliseconds(1000), stop, response(code, reason, body, ctype));
    ERR_clear_error();
    (void)SSL_shutdown(s);
  };
  RouteId route = RouteId::Tickets;
  const char* label = "other";
  const RouteRule* rule = nullptr;
  std::string method, path, query;
  // The table that decides roles for this node (bundle mode: the applied bundle's; lab mode: [[admin.rbac]]).
  const RbacTable& roles = opt_.bundle ? opt_.bundle->rbac() : lab_rbac_;
  // Audit helpers: a denial is coalesced per (identity, action, result) per second; an action is written at once.
  auto audit_entry = [&](const std::string& actor, const std::string& role, const char* action, const std::string& target,
                         const char* result, const std::string& reason) {
    control::AuditEntry e;
    e.actor = actor;
    e.role = role;
    e.action = action;
    e.target = target;
    e.result = result;
    e.reason = reason;
    return e;
  };
  auto audit_deny = [&](const std::string& actor, const std::string& role, const char* action, const std::string& reason) {
    audit_denied(audit_entry(actor, role, action, "", "denied", reason));
  };
  for (;;) {
    if (head_end == std::string::npos) {
      head_end = req.find("\r\n\r\n");
      if (head_end != std::string::npos) {
        head_end += 4;
        // Request line and the two headers we care about.
        const auto eol = req.find("\r\n");
        const std::string line = req.substr(0, eol);
        const auto sp1 = line.find(' ');
        const auto sp2 = sp1 == std::string::npos ? sp1 : line.find(' ', sp1 + 1);
        if (sp2 == std::string::npos) return reply("other", 400, "Bad Request", err_body("bad request line"));
        method = line.substr(0, sp1);
        path = line.substr(sp1 + 1, sp2 - sp1 - 1);
        if (const auto q = path.find('?'); q != std::string::npos) {
          query = path.substr(q + 1);
          path.resize(q);
        }
        for (std::size_t pos = eol + 2; pos < head_end - 2;) {
          const auto e = req.find("\r\n", pos);
          const std::string h = lower(req.substr(pos, e - pos));
          pos = e + 2;
          if (h.rfind("transfer-encoding:", 0) == 0) return reply("other", 400, "Bad Request", err_body("chunked bodies are not supported"));
          if (h.rfind("content-length:", 0) == 0) {
            std::string v = h.substr(15);
            v.erase(0, v.find_first_not_of(" \t"));
            if (have_len || v.empty() || v.size() > 7 || v.find_first_not_of("0123456789") != std::string::npos)
              return reply("other", 400, "Bad Request", err_body("bad content-length"));
            want_body = static_cast<std::size_t>(std::atoi(v.c_str()));
            have_len = true;
          }
        }
        // The bundle routes exist only in bundle mode ([control] trust_keys); lab mode answers 404 as before.
        // The route table (rbac.h) decides. The bundle routes exist only in bundle mode.
        rule = find_route(method, path);
        if (!rule) {
          bool visible = false;  // a known path with another method is 405; one hidden in lab mode is 404
          for (const auto& r : route_table()) visible = visible || (path == r.path && (!r.bundle_mode_only || opt_.bundle));
          if (!visible) return reply("other", 404, "Not Found", err_body("not found"));
          const char* lbl = path == "/v1/bundle" ? "/v1/bundle" : path == "/v1/identity" ? "/v1/identity" : path == "/v1/drain" ? "/v1/drain"
                            : path == "/v1/drop_principal" ? "/v1/drop_principal" : "/v1/tickets";
          return reply(lbl, 405, "Method Not Allowed", err_body(path == "/v1/bundle" ? "POST or GET only" : path == "/v1/identity" ? "GET only" : "POST only"));
        }
        if (rule->bundle_mode_only && !opt_.bundle) return reply("other", 404, "Not Found", err_body("not found"));
        route = rule->id;
        label = rule->path;
        // Audit log configured but not open: refuse only the audited operator / security-admin mutations. Tickets,
        // identity and bundle keep working (the signature gates bundles; their entries go to stderr and a counter).
        if (opt_.audit_failed && (route == RouteId::Drain || route == RouteId::DropPrincipal))
          return reply(label, 503, "Service Unavailable", err_body("audit log unavailable"));
        // Every route needs a single spiffe identity; refuse before the body is read.
        const char* act = action_of(route);
        if (multi_san) {
          audit_deny("(ambiguous)", "none", act, "client certificate has more than one spiffe URI SAN");
          return reply(label, 403, "Forbidden", err_body("client certificate has more than one spiffe URI SAN"));
        }
        if (identity.empty()) {
          audit_deny("(none)", "none", act, "client certificate has no spiffe URI SAN");
          return reply(label, 403, "Forbidden", err_body("client certificate has no spiffe URI SAN"));
        }
        // role-gated routes. Bundle and identity need only the identity above (the signature is the gate).
        if (!roles.allows(identity, rule->need)) {
          const std::string msg = std::string("role ") + need_role(rule->need) + " required";
          audit_deny(identity, roles.label(identity), act, msg);
          return reply(label, 403, "Forbidden", err_body(msg.c_str()));
        }
        if (route == RouteId::BundlePost) max_req = head_end + control::kMaxEnvelopeBytes;
        if (head_end + want_body > max_req) return reply(label, 413, "Payload Too Large", err_body("request too large"));
      }
    }
    if (head_end != std::string::npos && req.size() >= head_end + want_body) break;
    if (req.size() >= max_req) return reply("other", 413, "Payload Too Large", err_body("request too large"));
    const long n = io(s, fd, deadline, stop, [&] {
      return static_cast<long>(SSL_read(s, buf, static_cast<int>(std::min(sizeof buf, max_req - req.size()))));
    });
    if (n == kTimeout) return reply("other", 408, "Request Timeout", err_body("read timeout"));
    if (n <= 0) return;
    req.append(buf, static_cast<std::size_t>(n));
  }
  const std::string role_label = roles.label(identity);
  // The bindings may have changed (a bundle applied) while the body was being read: decide again.
  if (!roles.allows(identity, rule->need)) {
    const std::string msg = std::string("role ") + need_role(rule->need) + " required";
    audit_deny(identity, role_label, action_of(route), msg);
    return reply(label, 403, "Forbidden", err_body(msg.c_str()));
  }
  if (route == RouteId::BundleGet || route == RouteId::BundlePost || route == RouteId::Identity) {
    // these routes need only an authenticated mTLS identity. The signature is the gate for pushes.
    BundleStore& bs = *opt_.bundle;  // never reassigned after start(), like `wakeup`
    HttpReply hr;
    if (route == RouteId::Identity) {
      hr = bs.identity();
    } else if (route == RouteId::BundleGet) {
      hr = bs.get_bundle(query);
    } else {
      if (query != "" && query != "dry_run=1") return reply(label, 400, "Bad Request", err_body("only ?dry_run=1 is accepted"));
      auto outcome = std::make_shared<PushOutcome>();
      if (query != "dry_run=1")
        outcome->on_applied = [this, identity, role_label](const PushOutcome& o) { write_apply_audit(identity, role_label, o); };
      hr = bs.push(std::string_view(req).substr(head_end, want_body), query == "dry_run=1",
                   [&](std::function<void(Server&)> task) { return run_on_store(std::move(task), stop); }, outcome);
      if (query != "dry_run=1") {
        // Rejected or failed: coalesced (a controller retry loop must not flood). Applied entries are written by the
        // swap task (on_applied), so a push that timed out (504) and applies later is still audited; a
        // "replaced" envelope is written here; "noop" changed nothing.
        const std::string result = reply_field(hr.body, "result");
        if (hr.code == 200 && result == "replaced") {
          control::AuditEntry e = audit_entry(identity, role_label, "bundle.push", "bundle", "ok", result);
          e.generation = outcome->generation;
          if (outcome->sec_generation) e.detail.emplace_back("sec_generation", *outcome->sec_generation);
          e.detail.emplace_back("epoch", std::uint64_t{outcome->epoch});
          e.detail.emplace_back("applied_hash", outcome->applied_hash);
          (void)audit_record(e);
        } else if (hr.code != 200) {
          control::AuditEntry e = audit_entry(identity, role_label, "bundle.push", "bundle", hr.code >= 500 ? "error" : "denied",
                                              reply_field(hr.body, "reason"));
          e.generation = outcome->generation;
          if (outcome->sec_generation) e.detail.emplace_back("sec_generation", *outcome->sec_generation);
          audit_denied(e);
        }
      }
    }
    return reply(label, hr.code, http_reason(hr.code), hr.body, hr.ctype.c_str());
  }
  if (route == RouteId::Drain) {
    std::optional<std::uint32_t> ms;
    if (!parse_drain_request(req.substr(head_end, want_body), ms))
      return reply(label, 400, "Bad Request", err_body("body is empty, {} or {\"drain_ms\":0..600000}"));
    struct Res {
      bool started = false, idle = false;
    };
    auto res = std::make_shared<Res>();
    const std::uint32_t drain_ms = ms ? *ms : drain_ms_.load();
    if (!run_on_store([res, drain_ms](Server& s) {
          res->started = s.admin_drain(drain_ms);
          res->idle = s.drain_idle();
        }, stop)) {
      if (stop.load()) return;
      return reply(label, 504, "Gateway Timeout", err_body("store thread busy"));
    }
    control::AuditEntry e = audit_entry(identity, role_label, "drain", "node", "ok", res->started ? "draining" : "already_draining");
    e.detail.emplace_back("drain_ms", std::uint64_t{drain_ms});
    const bool audited = audit_record(e);  // a failed append is told to the caller, not hidden
    return reply(label, 200, "OK",
                 std::string("{\"result\":\"") + (res->started ? "draining" : "already_draining") +
                     "\",\"drain_ms\":" + std::to_string(drain_ms) + ",\"idle\":" + (res->idle ? "true" : "false") +
                     (audited ? "" : ",\"audit_error\":true") + "}");
  }
  if (route == RouteId::DropPrincipal) {
    std::string name, when;
    std::int64_t secs = 0;
    if (!parse_drop_request(req.substr(head_end, want_body), name, when, secs))
      return reply(label, 400, "Bad Request", err_body("body is {\"name\":\"...\",\"drop_before\":\"YYYY-MM-DDTHH:MM:SSZ\"}"));
    auto st = std::make_shared<Status>();
    if (!run_on_store([st, name, secs](Server& s) { *st = s.drop_principal_local(name, secs); }, stop)) {
      if (stop.load()) return;
      return reply(label, 504, "Gateway Timeout", err_body("store thread busy"));
    }
    // The raise is made durable in the floor file (max-only, like a bundle's drop_before) BEFORE the 200, so a restart
    // loads it (load_persisted_drop_before) and pre-cutoff scopes keep missing. With no state_dir there is nowhere to
    // persist: the reply says "persisted":false.
    const bool can_persist = !opt_.state_dir.empty();
    bool persisted = true;
    if (*st && can_persist) {
      auto fs = control::FloorState::open(opt_.state_dir);
      persisted = fs && fs->raise_drop_before(name, secs);
    }
    const bool ok = *st && persisted;
    const char* why = *st ? (persisted ? "dropped" : "persist failed")
                          : st->error().code == ErrorCode::InvalidArgument ? "drop_before in the future" : "unknown principal";
    control::AuditEntry e = audit_entry(identity, role_label, "drop_principal", name, ok ? "ok" : "error", why);
    e.detail.emplace_back("drop_before", when);
    const bool audited = audit_record(e);
    if (!*st && st->error().code == ErrorCode::InvalidArgument)
      return reply(label, 400, "Bad Request", err_body("drop_before is later than now + 300 s"));
    if (!*st) return reply(label, 404, "Not Found", err_body("no such principal"));
    if (!persisted) return reply(label, 500, "Internal Server Error", err_body("applied but not persisted"));
    return reply(label, 200, "OK",
                 "{\"result\":\"ok\",\"name\":\"" + name + "\",\"drop_before\":\"" + when + "\",\"persisted\":" +
                     (can_persist ? "true" : "false") + (audited ? "" : ",\"audit_error\":true") + "}");
  }
  auto tr = parse_ticket_request(req.substr(head_end, want_body));
  if (!tr) return reply(label, 400, "Bad Request", err_body("malformed request body"));

  auto p = std::make_shared<Pending>();
  p->identity = identity;
  p->req = std::move(*tr);
  {
    std::lock_guard<std::mutex> g(q_mu_);
    q_.push_back(p);
  }
  if (opt_.wakeup) opt_.wakeup();  // never reassigned after start(): no race with reload
  bool timed_out = false;
  {
    std::unique_lock<std::mutex> lk(p->m);
    const Nanos until = clock.now() + std::chrono::milliseconds(store_wait_ms());
    // Sliced wait: stop() (called on the store thread, which then cannot pump) must not wait 1 s for us.
    while (!p->done) {
      if (stop.load() || clock.now() >= until) {
        p->abandoned = true;
        timed_out = true;
        break;
      }
      p->cv.wait_for(lk, std::chrono::milliseconds(20), [&] { return p->done; });
    }
  }
  // Reply only after p->m is released: pump() on the store thread must never wait for a TLS write.
  if (timed_out) {
    if (stop.load()) return;
    budget_expired(1, peer, store_wait_ms());
    return reply(label, 504, "Gateway Timeout", err_body("store thread busy"));
  }
  if (!p->ok) {
    // ticket refusals (403 / 429 / 503) are coalesced per (identity, action, result) per second.
    const char* why = p->err.code == ErrorCode::AccessDenied ? "identity not allowed"
                      : p->err.code == ErrorCode::ResourceExhausted ? "ticket limit reached"
                      : p->err.code == ErrorCode::Busy ? "node draining" : nullptr;
    if (why) audit_deny(identity, role_label, "tickets.issue", why);
    switch (p->err.code) {
      case ErrorCode::AccessDenied: return reply(label, 403, "Forbidden", err_body("identity not allowed"));
      case ErrorCode::ResourceExhausted: return reply(label, 429, "Too Many Requests", err_body("ticket limit reached"));
      case ErrorCode::Busy: return reply(label, 503, "Service Unavailable", err_body("node draining"));
      case ErrorCode::InvalidArgument: return reply(label, 400, "Bad Request", err_body("invalid class, rail or count"));
      default: return reply(label, 500, "Internal Server Error", err_body("internal error"));
    }
  }
  static const char* hex = "0123456789abcdef";
  std::string body = "{\"ttl_s\":" + std::to_string(ttl_s_.load()) + ",\"tickets\":[";
  bool first = true;
  for (const auto& [cls, tk] : p->out) {
    if (!first) body += ',';
    first = false;
    body += "{\"class\":\"";
    body += class_name(static_cast<std::uint8_t>(cls));
    body += "\",\"rail\":" + std::to_string(p->req.rail) + ",\"id\":\"";
    for (auto b : tk.id) {
      body += hex[b >> 4];
      body += hex[b & 15];
    }
    body += "\"}";
  }
  body += ']';
  if (opt_.node_id != 0) {
    body += ",\"node_id\":" + std::to_string(opt_.node_id);
    std::string h;  // hostnames are [A-Za-z0-9._-]; anything else is dropped rather than escaped
    for (char ch : opt_.hostname)
      if (std::isalnum(static_cast<unsigned char>(ch)) || ch == '.' || ch == '_' || ch == '-') h.push_back(ch);
    if (!h.empty()) body += ",\"hostname\":\"" + h.substr(0, 64) + "\"";
  }
  body += '}';
  reply(label, 200, "OK", body);
}

}  // namespace miracache::server
