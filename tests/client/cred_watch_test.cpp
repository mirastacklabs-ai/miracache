// SPDX-License-Identifier: Apache-2.0
// Client credential and secret rotation. [tls] cert/key/ca files are re-read by the stat check and new
// HTTPS connections use the new certificate; the secret file's new `current` kver reaches the provider. Any failure
// (non-atomic cert/key pair, half-written file, wrong mode) keeps the OLD material, is counted, and is retried.
// Certs come from deploy/examples/lab-certs.sh into a temp dir. Also run under the tsan preset (reload thread vs. traffic).
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "scope/engine_native.h"
#include "src/admin_http.h"
#include "src/cred_watch.h"

namespace miracache {
namespace {

namespace fs = std::filesystem;

struct Pki {
  std::string root, pki;
  Pki() {
    char t[] = "/tmp/mira-cw-XXXXXX";
    EXPECT_NE(::mkdtemp(t), nullptr);
    root = t;
    pki = root + "/pki";
    EXPECT_EQ(std::system((std::string("bash ") + MIRACACHE_LAB_CERTS_SH + " " + pki + " --nodes 1 --clients 1,2 >/dev/null").c_str()), 0);
  }
  ~Pki() { fs::remove_all(root); }
};
const Pki& pki() {
  static const Pki p;
  return p;
}

std::string fresh_dir(const char* tag) {
  std::string t = std::string("/tmp/mira-cw-") + tag + "-XXXXXX";
  std::vector<char> b(t.begin(), t.end());
  b.push_back('\0');
  EXPECT_NE(::mkdtemp(b.data()), nullptr);
  return b.data();
}

std::string hex_digest(X509* x) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned n = 0;
  X509_digest(x, EVP_sha256(), md, &n);
  std::string s;
  char b[3];
  for (unsigned i = 0; i < n; ++i) {
    std::snprintf(b, sizeof b, "%02x", md[i]);
    s += b;
  }
  return s;
}

// SHA-256 of the first certificate in a PEM file.
std::string file_digest(const std::string& pem) {
  FILE* f = std::fopen(pem.c_str(), "r");
  EXPECT_NE(f, nullptr);
  X509* x = PEM_read_X509(f, nullptr, nullptr, nullptr);
  std::fclose(f);
  EXPECT_NE(x, nullptr);
  std::string d = hex_digest(x);
  X509_free(x);
  return d;
}

void put_file(const std::string& path, const std::string& body, mode_t mode = 0600) {
  std::ofstream o(path, std::ios::binary | std::ios::trunc);
  o << body;
  o.close();
  ::chmod(path.c_str(), mode);
}
std::string slurp(const std::string& path) {
  std::ifstream i(path, std::ios::binary);
  return std::string((std::istreambuf_iterator<char>(i)), std::istreambuf_iterator<char>());
}
// tmp + rename: how mirctl and a certificate manager replace a file.
void replace_atomic(const std::string& path, const std::string& body, mode_t mode = 0600) {
  put_file(path + ".tmp", body, mode);
  ASSERT_EQ(::rename((path + ".tmp").c_str(), path.c_str()), 0);
}

// A fake admin listener: mTLS, answers 200 "ok" and remembers the digest of each client certificate it saw.
class FakeAdmin {
 public:
  FakeAdmin() {
    const auto& c = pki();
    ctx_ = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
    EXPECT_EQ(SSL_CTX_use_certificate_chain_file(ctx_, (c.pki + "/node-1.pem").c_str()), 1);
    EXPECT_EQ(SSL_CTX_use_PrivateKey_file(ctx_, (c.pki + "/node-1.key").c_str(), SSL_FILETYPE_PEM), 1);
    EXPECT_EQ(SSL_CTX_load_verify_locations(ctx_, (c.pki + "/ca.pem").c_str(), nullptr), 1);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    lfd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    EXPECT_EQ(::bind(lfd_, reinterpret_cast<sockaddr*>(&a), sizeof a), 0);
    EXPECT_EQ(::listen(lfd_, 16), 0);
    socklen_t l = sizeof a;
    ::getsockname(lfd_, reinterpret_cast<sockaddr*>(&a), &l);
    port_ = ntohs(a.sin_port);
    th_ = std::thread([this] { loop(); });
  }
  ~FakeAdmin() {
    stop_ = true;
    th_.join();
    ::close(lfd_);
    SSL_CTX_free(ctx_);
  }
  std::string addr() const { return "127.0.0.1:" + std::to_string(port_); }
  std::string last_client() {
    std::lock_guard lk(mu_);
    return last_;
  }

 private:
  void loop() {
    while (!stop_) {
      pollfd p{lfd_, POLLIN, 0};
      if (::poll(&p, 1, 20) <= 0) continue;
      int fd = ::accept(lfd_, nullptr, nullptr);
      if (fd < 0) continue;
      timeval tv{5, 0};
      ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
      ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
      SSL* ssl = SSL_new(ctx_);
      SSL_set_fd(ssl, fd);
      if (SSL_accept(ssl) == 1) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        X509* peer = SSL_get1_peer_certificate(ssl);
#else
        X509* peer = SSL_get_peer_certificate(ssl);
#endif
        if (peer) {
          std::lock_guard lk(mu_);
          last_ = hex_digest(peer);
          X509_free(peer);
        }
        char buf[2048];
        std::string req;
        while (req.find("\r\n\r\n") == std::string::npos) {
          const int n = SSL_read(ssl, buf, sizeof buf);
          if (n <= 0) break;
          req.append(buf, static_cast<std::size_t>(n));
        }
        const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        (void)SSL_write(ssl, resp.data(), static_cast<int>(resp.size()));
        SSL_shutdown(ssl);
      } else {
        ERR_clear_error();
      }
      SSL_free(ssl);
      ::close(fd);
    }
  }
  SSL_CTX* ctx_ = nullptr;
  int lfd_ = -1;
  unsigned short port_ = 0;
  std::atomic<bool> stop_{false};
  std::thread th_;
  std::mutex mu_;
  std::string last_;
};

// The client side of every TLS test: its own working copy of client-1's files.
struct TlsFixture {
  std::string dir = fresh_dir("tls");
  std::string cert = dir + "/c.pem", key = dir + "/c.key", ca = dir + "/ca.pem";
  std::string d1, d2;  // digests of client-1 and client-2
  TlsFixture() {
    const auto& p = pki().pki;
    put_file(cert, slurp(p + "/client-1.pem"), 0644);
    put_file(key, slurp(p + "/client-1.key"));
    put_file(ca, slurp(p + "/ca.pem"), 0644);
    d1 = file_digest(p + "/client-1.pem");
    d2 = file_digest(p + "/client-2.pem");
  }
  ~TlsFixture() { fs::remove_all(dir); }
  std::shared_ptr<HttpsClient> client(unsigned io_ms = 3000) {
    HttpsOptions ho;
    ho.cert = cert;
    ho.key = key;
    ho.ca = ca;
    ho.io_timeout_ms = io_ms;
    auto h = HttpsClient::create(std::move(ho));
    EXPECT_TRUE(h.has_value());
    return h ? *h : nullptr;
  }
  // One request; returns the client-cert digest the server saw ("" on failure).
  static std::string ask(HttpsClient& c, FakeAdmin& srv) {
    auto r = c.request(srv.addr(), "GET", "/x", "", "");
    if (!r || r->code != 200) return {};
    return srv.last_client();
  }
};

std::string secret_text(std::uint32_t current, std::initializer_list<std::pair<std::uint32_t, char>> kvers) {
  std::string s = "current = " + std::to_string(current) + "\n";
  for (auto [k, c] : kvers) s += std::to_string(k) + " = " + std::string(64, c) + "\n";
  return s;
}

RequestMeta meta_for() {
  RequestMeta m;
  m.engine = EngineKind::Vllm;
  m.ns.fill(7);
  m.roots.push_back({std::byte{1}, std::byte{2}, std::byte{3}});
  return m;
}

}  // namespace

// ---- TLS ------------------------------------------------------------------------------------------------------

TEST(CredReloadTls, AtomicRotationNewConnectionsUseNewCert) {
  TlsFixture f;
  FakeAdmin srv;
  // The pair lives behind a symlink, so swapping it is one atomic rename (a single file rename is atomic, two are not).
  const std::string v1 = f.dir + "/v1", v2 = f.dir + "/v2", cur = f.dir + "/cur";
  fs::create_directories(v1);
  fs::create_directories(v2);
  const auto& p = pki().pki;
  put_file(v1 + "/c.pem", slurp(p + "/client-1.pem"), 0644);
  put_file(v1 + "/c.key", slurp(p + "/client-1.key"));
  put_file(v2 + "/c.pem", slurp(p + "/client-2.pem"), 0644);
  put_file(v2 + "/c.key", slurp(p + "/client-2.key"));
  fs::create_directory_symlink(v1, cur);
  f.cert = cur + "/c.pem";
  f.key = cur + "/c.key";

  auto c1 = f.client();  // two users of the same files (tickets and bundle watcher in the real client)
  auto c2 = f.client();
  CredWatchOptions o;
  o.cert = f.cert;
  o.key = f.key;
  o.ca = f.ca;
  auto w = CredWatch::create(o, nullptr);
  ASSERT_TRUE(w.has_value());
  ASSERT_TRUE(*w);
  EXPECT_EQ(TlsFixture::ask(*c1, srv), f.d1);
  (*w)->check_now();
  EXPECT_EQ((*w)->count("client_tls", true), 0u);  // unchanged: no reload, no count

  fs::create_directory_symlink(v2, cur + ".tmp");
  fs::rename(cur + ".tmp", cur);
  (*w)->check_now();
  EXPECT_EQ((*w)->count("client_tls", true), 1u);
  EXPECT_EQ((*w)->count("client_tls", false), 0u);
  EXPECT_EQ(TlsFixture::ask(*c1, srv), f.d2);
  EXPECT_EQ(TlsFixture::ask(*c2, srv), f.d2);
  (*w)->check_now();
  EXPECT_EQ((*w)->count("client_tls", true), 1u);  // nothing changed since
}

TEST(CredReloadTls, NonAtomicPairKeepsOldUntilItMatches) {
  TlsFixture f;
  FakeAdmin srv;
  auto c = f.client();
  CredWatchOptions o;
  o.cert = f.cert;
  o.key = f.key;
  o.ca = f.ca;
  auto w = CredWatch::create(o, nullptr);
  ASSERT_TRUE(w.has_value() && *w);
  ASSERT_EQ(TlsFixture::ask(*c, srv), f.d1);

  const auto& p = pki().pki;
  replace_atomic(f.cert, slurp(p + "/client-2.pem"), 0644);  // new cert, old key: they do not match
  (*w)->check_now();
  EXPECT_EQ((*w)->count("client_tls", false), 1u);
  EXPECT_EQ(TlsFixture::ask(*c, srv), f.d1);  // the old pair still serves
  (*w)->check_now();                          // the failed signature is not remembered: retried
  EXPECT_EQ((*w)->count("client_tls", false), 2u);
  EXPECT_EQ(TlsFixture::ask(*c, srv), f.d1);

  replace_atomic(f.key, slurp(p + "/client-2.key"));  // the key arrives: the pair matches
  (*w)->check_now();
  EXPECT_EQ((*w)->count("client_tls", true), 1u);
  EXPECT_EQ(TlsFixture::ask(*c, srv), f.d2);
}

TEST(CredReloadTls, HalfWrittenKeyAndWrongModeKeepOld) {
  TlsFixture f;
  FakeAdmin srv;
  auto c = f.client();
  CredWatchOptions o;
  o.cert = f.cert;
  o.key = f.key;
  o.ca = f.ca;
  auto w = CredWatch::create(o, nullptr);
  ASSERT_TRUE(w.has_value() && *w);
  const std::string good_key = slurp(f.key);
  put_file(f.key, good_key.substr(0, good_key.size() / 2));  // truncated in place
  (*w)->check_now();
  EXPECT_EQ((*w)->count("client_tls", false), 1u);
  EXPECT_EQ(TlsFixture::ask(*c, srv), f.d1);
  replace_atomic(f.key, good_key, 0644);  // whole again but mode 0644: rejected
  (*w)->check_now();
  EXPECT_EQ((*w)->count("client_tls", false), 2u);
  EXPECT_EQ(TlsFixture::ask(*c, srv), f.d1);
  replace_atomic(f.key, good_key, 0600);  // fixed: applied (same cert, new key file)
  (*w)->check_now();
  EXPECT_EQ((*w)->count("client_tls", true), 1u);
  EXPECT_EQ(TlsFixture::ask(*c, srv), f.d1);
}

// ---- secret ---------------------------------------------------------------------------------------------------

TEST(CredReloadSecret, TruncatedFileKeepsOldThenAddKverSwitchesCurrent) {
  const std::string dir = fresh_dir("sec");
  const std::string path = dir + "/secret";
  put_file(path, secret_text(1, {{1, 'a'}}));
  auto prov = ReloadableEngineNativeProvider::from_file(path);
  ASSERT_TRUE(prov.has_value());
  EXPECT_EQ((*prov)->source_path(), path);
  CredWatchOptions o;
  o.secret_file = path;
  auto w = CredWatch::create(o, prov->get());
  ASSERT_TRUE(w.has_value() && *w);

  auto before = (*prov)->derive(meta_for());
  ASSERT_TRUE(before.has_value());
  EXPECT_EQ(before->kver, 1u);

  // Half-written file (the 64-hex line is cut short; also no `current` yet if the cut is early).
  const std::string full2 = secret_text(2, {{1, 'a'}, {2, 'b'}});
  put_file(path, full2.substr(0, full2.size() - 20));
  (*w)->check_now();
  EXPECT_EQ((*w)->count("secret", false), 1u);
  auto kept = (*prov)->derive(meta_for());
  ASSERT_TRUE(kept.has_value());
  EXPECT_EQ(kept->kver, 1u);
  EXPECT_EQ(std::memcmp(kept->scopes[0].b, before->scopes[0].b, 32), 0);
  (*w)->check_now();  // same bytes, retried
  EXPECT_EQ((*w)->count("secret", false), 2u);

  // `mirctl secret add-kver`: tmp + rename.
  replace_atomic(path, full2);
  (*w)->check_now();
  EXPECT_EQ((*w)->count("secret", true), 1u);
  auto after = (*prov)->derive(meta_for());
  ASSERT_TRUE(after.has_value());
  EXPECT_EQ(after->kver, 2u);
  EXPECT_EQ((*prov)->kver(), 2u);
  EXPECT_NE(std::memcmp(after->scopes[0].b, before->scopes[0].b, 32), 0);  // new kver: new scope ids, the old ones miss
  // The key material changed too: same raw key, different key_hash.
  const std::byte raw[3] = {std::byte{9}, std::byte{9}, std::byte{9}};
  auto h_old = before->keys->key_hash(raw);
  auto h_new = after->keys->key_hash(raw);
  ASSERT_TRUE(h_old.has_value() && h_new.has_value());
  EXPECT_NE(std::memcmp(h_old->b, h_new->b, 32), 0);
  // A ScopeKeys derived before the swap still works (it owns its key source).
  EXPECT_TRUE(before->keys->dek_for(raw).has_value());

  // A wrong-mode replacement is rejected, the new current stays.
  replace_atomic(path, secret_text(3, {{1, 'a'}, {2, 'b'}, {3, 'c'}}), 0644);
  (*w)->check_now();
  EXPECT_EQ((*w)->count("secret", false), 3u);
  EXPECT_EQ((*prov)->kver(), 2u);
  // `current` naming a kver that is not in the file: rejected.
  replace_atomic(path, secret_text(9, {{1, 'a'}, {2, 'b'}, {4, 'd'}}));
  (*w)->check_now();
  EXPECT_EQ((*w)->count("secret", false), 4u);
  EXPECT_EQ((*prov)->kver(), 2u);

  std::string m;
  (*w)->write_metrics(m);
  EXPECT_NE(m.find("miracache_cred_reload_total{kind=\"secret\",result=\"rejected\"} 4"), std::string::npos) << m;
  EXPECT_NE(m.find("miracache_cred_reload_total{kind=\"secret\",result=\"applied\"} 1"), std::string::npos) << m;
  EXPECT_EQ(m.find("aaaaaaaa"), std::string::npos);  // never key material
  fs::remove_all(dir);
}

TEST(CredReloadSecret, NothingToWatchGivesNull) {
  auto w = CredWatch::create(CredWatchOptions{}, nullptr);
  ASSERT_TRUE(w.has_value());
  EXPECT_FALSE(*w);
}

// ---- the reload thread under traffic (tsan) ----------------------------------------------------------------

TEST(CredReloadThread, RotationsWhileDerivingAndRequesting) {
  TlsFixture f;
  FakeAdmin srv;
  const std::string sdir = fresh_dir("thr");
  const std::string spath = sdir + "/secret";
  put_file(spath, secret_text(1, {{1, 'a'}}));
  auto prov = ReloadableEngineNativeProvider::from_file(spath);
  ASSERT_TRUE(prov.has_value());
  auto c = f.client();
  CredWatchOptions o;
  o.cert = f.cert;
  o.key = f.key;
  o.ca = f.ca;
  o.secret_file = spath;
  o.stat_ms = 10;
  auto w = CredWatch::create(o, prov->get());
  ASSERT_TRUE(w.has_value() && *w);
  (*w)->start();

  std::atomic<bool> stop{false};
  std::atomic<int> bad{0};
  std::thread deriver([&] {
    while (!stop) {
      auto k = (*prov)->derive(meta_for());
      if (!k || k->scopes.size() != 1) ++bad;
    }
  });
  std::thread requester([&] {
    while (!stop) {
      if (TlsFixture::ask(*c, srv).empty()) ++bad;  // a request never fails across a rotation
    }
  });

  const auto& p = pki().pki;
  for (int i = 0; i < 6; ++i) {
    const bool two = (i % 2) == 0;
    replace_atomic(f.cert, slurp(p + (two ? "/client-2.pem" : "/client-1.pem")), 0644);
    replace_atomic(f.key, slurp(p + (two ? "/client-2.key" : "/client-1.key")));
    replace_atomic(spath, secret_text(static_cast<std::uint32_t>(i + 2), {{1, 'a'}, {static_cast<std::uint32_t>(i + 2), 'b'}}));
    std::this_thread::sleep_for(std::chrono::milliseconds(60));
  }
  const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while ((*prov)->kver() != 7u && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  stop = true;
  deriver.join();
  requester.join();
  (*w)->stop();
  EXPECT_EQ(bad.load(), 0);
  EXPECT_EQ((*prov)->kver(), 7u);
  EXPECT_GE((*w)->count("secret", true), 1u);
  EXPECT_GE((*w)->count("client_tls", true), 1u);
  // The last rotation (i = 5) put client-1 back; the next connection presents it.
  EXPECT_EQ(TlsFixture::ask(*c, srv), f.d1);
  fs::remove_all(sdir);
}

}  // namespace miracache
