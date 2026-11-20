// SPDX-License-Identifier: Apache-2.0
// MB3a: the memory node's bundle routes over loopback HTTPS + mTLS (POST/GET /v1/bundle, GET /v1/identity),
// persistence of bundle.current and the floor in state_dir, start-up re-verify, dry run, and "reply only after
// the swap". Bundles are signed by the test-only signer (independent of the library under test).
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <future>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <gtest/gtest.h>

#include "control/bundle_test_util.h"
#include "control/floor_state.h"
#include "fabric/sim/sim_fabric.h"
#include "server/dyn_config.h"
#include "server/node_config.h"
#include "server/runtime/admin_https.h"
#include "server/runtime/bundle_store.h"
#include "server/server.h"
#include "util/clock.h"
#include "util/random.h"

namespace miracache::server {
namespace {

using namespace std::chrono_literals;
namespace tu = control::testutil;

// ---- PKI from the lab script (openssl CLI), once per test binary ---------------------------------
struct Certs {
  std::string root, pki;
  Certs() {
    char t[] = "/tmp/mira-bundle-XXXXXX";
    EXPECT_NE(::mkdtemp(t), nullptr);
    root = t;
    pki = root + "/pki";
    const std::string cmd = std::string("bash ") + MIRACACHE_LAB_CERTS_SH + " " + pki + " --nodes 1 --clients 1,2 >/dev/null";
    EXPECT_EQ(std::system(cmd.c_str()), 0);
    // "nosan": a client cert from the lab CA without any SAN (bundle routes must refuse it: X14, X20).
    const std::string ns =
        "cd " + pki +
        " && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out nosan.key 2>/dev/null"
        " && openssl req -new -key nosan.key -subj /CN=nosan -out nosan.csr 2>/dev/null"
        " && printf 'basicConstraints=CA:FALSE\\nkeyUsage=critical,digitalSignature\\nextendedKeyUsage=clientAuth\\n' > nosan.ext"
        " && openssl x509 -req -in nosan.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days 30 -extfile nosan.ext"
        " -out nosan.pem 2>/dev/null && chmod 600 nosan.key";
    EXPECT_EQ(std::system(ns.c_str()), 0);
  }
  ~Certs() { (void)std::system(("rm -rf " + root).c_str()); }
  Certs(const Certs&) = delete;
};
const Certs& certs() {
  static const Certs c;
  return c;
}

struct Https {
  bool connected = false;
  std::string raw;
  int code() const { return raw.rfind("HTTP/1.1 ", 0) == 0 ? std::atoi(raw.c_str() + 9) : 0; }
  std::string body() const {
    const auto p = raw.find("\r\n\r\n");
    return p == std::string::npos ? "" : raw.substr(p + 4);
  }
};

int tcp_connect(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
  EXPECT_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa), 0);
  timeval tv{8, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  return fd;
}

Https tls_call(std::uint16_t port, const std::string& who, const std::string& req) {
  const auto& c = certs();
  Https r;
  int fd = tcp_connect(port);
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  EXPECT_EQ(SSL_CTX_load_verify_locations(ctx, (c.pki + "/ca.pem").c_str(), nullptr), 1);
  if (!who.empty()) {
    EXPECT_EQ(SSL_CTX_use_certificate_file(ctx, (c.pki + "/" + who + ".pem").c_str(), SSL_FILETYPE_PEM), 1);
    EXPECT_EQ(SSL_CTX_use_PrivateKey_file(ctx, (c.pki + "/" + who + ".key").c_str(), SSL_FILETYPE_PEM), 1);
  }
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  SSL* ssl = SSL_new(ctx);
  BIO* bio = new_nosigpipe_socket_bio(fd);
  SSL_set_bio(ssl, bio, bio);
  if (SSL_connect(ssl) == 1) {
    r.connected = true;
    std::size_t off = 0;
    while (off < req.size()) {
      const int n = SSL_write(ssl, req.data() + off, static_cast<int>(req.size() - off));
      if (n <= 0) break;
      off += static_cast<std::size_t>(n);
    }
    if (off == req.size()) {
      char buf[16384];
      for (;;) {
        const int n = SSL_read(ssl, buf, sizeof buf);
        if (n <= 0) break;
        r.raw.append(buf, static_cast<std::size_t>(n));
      }
    }
  }
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  ::close(fd);
  ERR_clear_error();
  return r;
}

std::string http_req(const std::string& method, const std::string& path, const std::string& body = "") {
  return method + " " + path + " HTTP/1.1\r\nHost: x\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
}

std::string make_dir() {
  char t[] = "/tmp/mira-bstate-XXXXXX";
  EXPECT_NE(::mkdtemp(t), nullptr);
  return t;
}

std::string json_str(const std::string& j, const std::string& key) {
  std::smatch m;
  const std::regex re("\"" + key + "\":\"([^\"]*)\"");
  return std::regex_search(j, m, re) ? m[1].str() : std::string();
}
long long json_num(const std::string& j, const std::string& key) {
  std::smatch m;
  const std::regex re("\"" + key + "\":(-?[0-9]+)");
  return std::regex_search(j, m, re) ? std::stoll(m[1].str()) : -1;
}

double metric(Server& s, const std::string& name, const std::vector<std::string>& frags = {}) {
  std::string text;
  s.metrics().write_prometheus(text);
  double sum = 0;
  std::size_t pos = 0;
  while (pos < text.size()) {
    auto eol = text.find('\n', pos);
    if (eol == std::string::npos) eol = text.size();
    const std::string line = text.substr(pos, eol - pos);
    pos = eol + 1;
    if (line.rfind(name, 0) != 0 || (line.size() > name.size() && line[name.size()] != '{' && line[name.size()] != ' ')) continue;
    bool all = true;
    for (const auto& fr : frags) all = all && line.find(fr) != std::string::npos;
    if (all) sum += std::atof(line.c_str() + line.rfind(' ') + 1);
  }
  return sum;
}

std::string hex_sha(const std::string& s) {
  const auto d = tu::sha256(s);
  return tu::hex(d.data(), d.size());
}

store::StoreConfig store_cfg() {
  store::StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 1u << 20;
  c.principal_default.idle_ttl = std::chrono::seconds(1000);
  c.invalidate_per_s = 0;
  return c;
}

// One memory node (Server over SimFabric) with a bundle store and the admin listener. `restart()` rebuilds the
// BundleStore and admin on the same state_dir, as a process restart would.
struct Node {
  explicit Node(const std::string& state_dir_in = "", const std::string& trust_toml = tu::trust_toml(), bool bundle_mode = true)
      : rng(3), net(clock, rng, {}, {}), fab(net.add_node(1)) {
    owns_dir = state_dir_in.empty();
    state_dir = owns_dir ? make_dir() : state_dir_in;
    trust_path = state_dir + "/trust.toml";
    write_trust(trust_toml);
    ServerConfig sc;
    sc.store = store_cfg();
    sc.lab_identity = "lab";
    sc.lab_principal = 5;
    auto s = Server::create(sc, fab, clock, rng, exec);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
    mode = bundle_mode;
    (void)start_bundle_and_admin();
  }
  ~Node() {
    admin.reset();
    bundle.reset();
    if (owns_dir) (void)std::system(("rm -rf " + state_dir).c_str());
  }
  void write_trust(const std::string& t) {
    std::ofstream f(trust_path, std::ios::binary | std::ios::trunc);
    f << t;
  }
  Status start_bundle_and_admin() {
    admin.reset();
    bundle.reset();
    if (mode) {
      BundleStoreOptions bo;
      bo.state_dir = state_dir;
      bo.trust_path = trust_path;
      bo.node_id = server->node_id();
      bo.hostname = "hostA";
      bo.addr = "10.0.0.10:7471";
      bo.admin = "10.0.0.10:9465";
      bo.reg = &server->metrics();
      bo.snapshot = [s = server.get()] { return s->node_snapshot(); };
      bo.clock = &clock;
      bo.rails = {{"10.0.0.10:7471", "10.0.0.0/24", "roce"}};
      bo.dyn_base = server->dyn_base();
      auto b = BundleStore::open(std::move(bo));
      if (!b) return b.error();
      bundle = std::move(*b);
      bundle->set_rails_up(true);
      if (auto v = bundle->startup_view()) server->apply_bundle(*v);
    }
    const auto& c = certs();
    AdminOptions ao{"127.0.0.1:0", c.pki + "/node-1.pem", c.pki + "/node-1.key", c.pki + "/ca.pem", 300};
    ao.node_id = server->node_id();
    ao.hostname = "hostA";
    ao.bundle = bundle.get();
    ao.wakeup = [this] { queued = true; };
    auto a = AdminHttps::start(ao, server->metrics());
    EXPECT_TRUE(a && *a);
    if (a && *a) admin = std::move(*a);
    return {};
  }
  Status restart() { return start_bundle_and_admin(); }

  // Runs `fn` on a client thread while this (the store) thread answers the admin mailbox.
  template <typename F>
  auto run(F fn) {
    auto fut = std::async(std::launch::async, fn);
    while (fut.wait_for(2ms) != std::future_status::ready) admin->pump(*server);
    return fut.get();
  }
  Https call(const std::string& method, const std::string& path, const std::string& body = "",
             const std::string& who = "client-1") {
    const auto port = admin->port();
    return run([=] { return tls_call(port, who, http_req(method, path, body)); });
  }
  Https push(const std::string& env, bool dry = false) { return call("POST", dry ? "/v1/bundle?dry_run=1" : "/v1/bundle", env); }

  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& fab;
  InlineExecutor exec;
  std::unique_ptr<Server> server;
  std::unique_ptr<BundleStore> bundle;
  std::unique_ptr<AdminHttps> admin;
  std::string state_dir, trust_path;
  bool mode = true;
  bool owns_dir = false;
  std::atomic<bool> queued{false};  // set when the admin thread posted work for the store thread
};

std::string env_gen(std::uint64_t gen, std::uint32_t epoch = 7, std::uint64_t sec_gen = 5) {
  return tu::make_envelope(tu::sec_toml(sec_gen), tu::body_toml(gen, epoch, epoch - 1));
}

bool file_exists(const std::string& p) {
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0;
}

TEST(BundleRoutes, PushGetIdentity) {
  Node n;
  const std::string sec = tu::sec_toml(5), body = tu::body_toml(42, 7, 6);
  const std::string env = tu::make_envelope(sec, body);

  auto id0 = n.call("GET", "/v1/identity");
  ASSERT_EQ(id0.code(), 200) << id0.raw;
  EXPECT_EQ(json_num(id0.body(), "applied_generation"), 0);
  EXPECT_EQ(json_str(id0.body(), "hostname"), "hostA");
  EXPECT_EQ(json_str(id0.body(), "member_state"), "active");  // Y08 fields present (snapshot defaults before the first publish)
  EXPECT_EQ(json_num(id0.body(), "scopes"), 0);
  EXPECT_EQ(json_num(id0.body(), "bytes_used"), 0);
  EXPECT_EQ(json_num(id0.body(), "node_id"), static_cast<long long>(n.server->node_id()));
  EXPECT_EQ(n.call("GET", "/v1/bundle").code(), 404);  // nothing applied yet

  auto r = n.push(env);
  ASSERT_EQ(r.code(), 200) << r.raw;
  EXPECT_EQ(json_str(r.body(), "result"), "applied");
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);  // the swap happened before the reply
  EXPECT_EQ(n.server->applied_bundle().epoch, 7u);

  auto g = n.call("GET", "/v1/bundle");
  ASSERT_EQ(g.code(), 200);
  EXPECT_EQ(g.body(), env);
  EXPECT_EQ(n.call("GET", "/v1/bundle?after=42").code(), 304);
  EXPECT_EQ(n.call("GET", "/v1/bundle?after=43").code(), 304);
  auto g2 = n.call("GET", "/v1/bundle?after=41");
  EXPECT_EQ(g2.code(), 200);
  EXPECT_EQ(g2.body(), env);
  EXPECT_EQ(n.call("GET", "/v1/bundle?after=abc").code(), 400);
  EXPECT_EQ(n.call("GET", "/v1/bundle?bogus=1").code(), 400);

  auto id = n.call("GET", "/v1/identity");
  ASSERT_EQ(id.code(), 200);
  const std::string j = id.body();
  EXPECT_EQ(json_num(j, "applied_generation"), 42);
  EXPECT_EQ(json_num(j, "generation"), 42);
  EXPECT_EQ(json_num(j, "epoch"), 7);
  EXPECT_EQ(json_num(j, "sec_generation"), 5);
  EXPECT_EQ(json_str(j, "applied_hash"), hex_sha(body));
  EXPECT_EQ(json_str(j, "sec_hash"), hex_sha(sec));
  EXPECT_EQ(json_str(j, "key_id"), tu::key_id_hex(tu::publish_seed()));
  EXPECT_EQ(json_str(j, "sec_key_id"), tu::key_id_hex(tu::security_seed()));
  EXPECT_EQ(json_str(j, "addr"), "10.0.0.10:7471");

  EXPECT_EQ(metric(*n.server, "miracache_bundle_generation"), 42.0);
  EXPECT_EQ(metric(*n.server, "miracache_membership_epoch"), 7.0);
  EXPECT_EQ(metric(*n.server, "miracache_bundle_apply_total", {"result=\"applied\""}), 1.0);
  EXPECT_TRUE(file_exists(n.state_dir + "/bundle.current"));
  EXPECT_TRUE(file_exists(n.state_dir + "/bundle-floor"));
}

TEST(BundleRoutes, ReplayAfterRestartRejected) {
  Node n;
  ASSERT_EQ(n.push(env_gen(42)).code(), 200);
  ASSERT_EQ(n.push(env_gen(43, 8)).code(), 200);
  ASSERT_TRUE(n.restart());
  // The restart loaded bundle.current and applied it before serving.
  EXPECT_EQ(n.server->applied_bundle().generation, 43u);
  auto id = n.call("GET", "/v1/identity");
  EXPECT_EQ(json_num(id.body(), "applied_generation"), 43);
  EXPECT_NE(id.body().find("\"startup_unverified\":false"), std::string::npos);

  auto old = n.push(env_gen(42));  // replay of an older bundle
  EXPECT_EQ(old.code(), 409) << old.raw;
  EXPECT_EQ(json_str(old.body(), "reason"), "generation_lower");
  EXPECT_EQ(metric(*n.server, "miracache_bundle_reject_total", {"reason=\"generation_lower\""}), 1.0);

  // Equal generation, different body hash.
  auto eq = n.push(tu::make_envelope(tu::sec_toml(5), tu::body_toml(43, 8, 7, "[config.cluster.client]\nx = 1\n")));
  EXPECT_EQ(eq.code(), 409);
  EXPECT_EQ(json_str(eq.body(), "reason"), "equal_generation");

  // Epoch going backwards under a newer generation.
  auto eb = n.push(env_gen(44, 7));
  EXPECT_EQ(eb.code(), 409);
  EXPECT_EQ(json_str(eb.body(), "reason"), "epoch_backwards");

  // Idempotent re-push of the applied bytes: success, no apply.
  auto same = n.push(env_gen(43, 8));
  EXPECT_EQ(same.code(), 200);
  EXPECT_EQ(json_str(same.body(), "result"), "noop");
  EXPECT_EQ(n.call("GET", "/v1/identity").code(), 200);
}

TEST(BundleRoutes, SecGenerationRules) {
  Node n;
  ASSERT_EQ(n.push(env_gen(42, 7, 5)).code(), 200);
  auto lower = n.push(env_gen(43, 7, 4));
  EXPECT_EQ(lower.code(), 409);
  EXPECT_EQ(json_str(lower.body(), "reason"), "sec_generation_lower");
  // Same sec_generation but different sec bytes.
  auto other_sec = n.push(tu::make_envelope(tu::sec_toml(5, "2026-11-01T00:00:00Z"), tu::body_toml(43, 7, 6)));
  EXPECT_EQ(other_sec.code(), 409);
  EXPECT_EQ(json_str(other_sec.body(), "reason"), "sec_equal_generation");
}

TEST(BundleRoutes, StartupWithUnverifiableBundleKeepsServing) {
  const std::string dir = make_dir();
  {
    Node n(dir);
    ASSERT_EQ(n.push(env_gen(42)).code(), 200);
  }
  {  // corrupt bundle.current: flip one byte in the body
    std::string b;
    ASSERT_TRUE(tu::read_file(dir + "/bundle.current", b));
    b[b.size() - 3] ^= 1;
    std::ofstream(dir + "/bundle.current", std::ios::binary | std::ios::trunc) << b;
  }
  Node n(dir);
  ASSERT_TRUE(n.bundle);
  EXPECT_TRUE(n.bundle->startup_unverified());
  EXPECT_FALSE(n.bundle->startup_view());
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  EXPECT_EQ(metric(*n.server, "miracache_bundle_reject_total", {"reason=\"startup_unverified\""}), 1.0);
  EXPECT_EQ(metric(*n.server, "miracache_bundle_startup_unverified"), 1.0);
  // The node still answers (it keeps serving), reports no bundle, and alerts through the identity.
  auto id = n.call("GET", "/v1/identity");
  ASSERT_EQ(id.code(), 200);
  EXPECT_EQ(json_num(id.body(), "applied_generation"), 0);
  EXPECT_NE(id.body().find("\"startup_unverified\":true"), std::string::npos);
  EXPECT_EQ(n.call("GET", "/v1/bundle").code(), 404);
  // The floor survived: an older bundle is still refused, and a valid newer one supersedes the broken file.
  EXPECT_EQ(n.push(env_gen(41)).code(), 409);
  auto ok = n.push(env_gen(44, 8));
  ASSERT_EQ(ok.code(), 200) << ok.raw;
  EXPECT_EQ(n.server->applied_bundle().generation, 44u);
  // X11: the first successful apply clears the alert (identity flag and gauge).
  EXPECT_NE(n.call("GET", "/v1/identity").body().find("\"startup_unverified\":false"), std::string::npos);
  EXPECT_EQ(metric(*n.server, "miracache_bundle_startup_unverified"), 0.0);
  // A re-push of the floor generation also supersedes (equal hash, but this process never applied it).
  Node m(make_dir());
  ASSERT_EQ(m.push(env_gen(10)).code(), 200);
  m.write_trust(tu::trust_toml());
  std::ofstream(m.state_dir + "/bundle.current", std::ios::binary | std::ios::trunc) << "garbage";
  ASSERT_TRUE(m.restart());
  EXPECT_TRUE(m.bundle->startup_unverified());
  auto again = m.push(env_gen(10));
  EXPECT_EQ(again.code(), 200) << again.raw;
  EXPECT_EQ(json_str(again.body(), "result"), "applied");
  EXPECT_EQ(m.server->applied_bundle().generation, 10u);
}

// J03/H09: the node exempts a drop_before the floor already holds (not above its stored maximum), so a clock that
// stepped back (the stored value now looks like the future) does not make every publish fail at the dry run. A value
// above the stored maximum is still refused. The floor is seeded with a far-future value (year 2100).
TEST(BundleRoutes, StoredFutureDropBeforeIsExemptOnlyUpToTheFloorMaximum) {
  const std::string dir = make_dir();
  {
    auto fs = control::FloorState::open(dir);
    ASSERT_TRUE(fs.has_value());
    auto seed = control::open_bundle(tu::make_envelope(tu::sec_toml(5, "2100-01-01T00:00:00Z"), tu::body_toml(41, 7, 6)),
                                     control::parse_trust_keys(tu::trust_toml()).value());
    ASSERT_TRUE(seed.has_value());
    ASSERT_TRUE(fs->commit(*seed).has_value());
  }
  Node n(dir);
  auto env = [](std::uint64_t gen, std::uint64_t sec_gen, const std::string& drop) {
    return tu::make_envelope(tu::sec_toml(sec_gen, drop), tu::body_toml(gen, 7, 6));
  };
  // Unchanged stored value: dry run and real push are accepted although it is "in the future".
  EXPECT_EQ(n.push(env(42, 6, "2100-01-01T00:00:00Z"), /*dry=*/true).code(), 200);
  EXPECT_EQ(n.push(env(42, 6, "2100-01-01T00:00:00Z")).code(), 200);
  // Above the stored maximum: a real rewind or a typo, refused (fail-closed), in the dry run and the real push.
  auto above = n.push(env(43, 7, "2100-01-02T00:00:00Z"), /*dry=*/true);
  EXPECT_EQ(above.code(), 400) << above.raw;
  EXPECT_EQ(json_str(above.body(), "reason"), "schema");
  EXPECT_EQ(n.push(env(43, 7, "2100-01-02T00:00:00Z")).code(), 400);
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
  // Below the stored maximum (still in the future): already covered by the stored value, accepted.
  EXPECT_EQ(n.push(env(43, 7, "2099-06-01T00:00:00Z")).code(), 200);
  // A node that restarts accepts the same bundle again on its own clock (the floor survives).
  ASSERT_TRUE(n.restart());
  EXPECT_EQ(n.push(env(44, 8, "2100-01-01T00:00:00Z")).code(), 200);
}

TEST(BundleRoutes, DryRunAppliesNothing) {
  Node n;
  auto d = n.push(env_gen(42), /*dry=*/true);
  ASSERT_EQ(d.code(), 200) << d.raw;
  EXPECT_EQ(json_str(d.body(), "result"), "dry_run_ok");
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  EXPECT_FALSE(file_exists(n.state_dir + "/bundle.current"));
  EXPECT_FALSE(file_exists(n.state_dir + "/bundle-floor"));
  EXPECT_EQ(json_num(n.call("GET", "/v1/identity").body(), "applied_generation"), 0);
  EXPECT_EQ(n.call("GET", "/v1/bundle").code(), 404);
  // A dry run still verifies: a tampered bundle fails it, and a replay is refused against the floor.
  std::string bad = env_gen(42);
  bad[bad.size() - 5] ^= 1;
  EXPECT_EQ(n.push(bad, true).code(), 403);
  ASSERT_EQ(n.push(env_gen(42)).code(), 200);
  EXPECT_EQ(n.push(env_gen(41), true).code(), 409);
  EXPECT_EQ(n.push(env_gen(43, 8), true).code(), 200);
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
  EXPECT_EQ(n.call("POST", "/v1/bundle?dry_run=2", env_gen(43, 8)).code(), 400);
}

std::string rotated_trust() {  // a trust file with none of the keys that sign the test bundles
  const auto p = tu::public_key(tu::seed_from(0x41));
  return "[[key]]\npublic = \"" + tu::hex(p.data(), 32) + "\"\nroles = [\"publish\", \"security\"]\n";
}

bool identity_flag(Node& n, bool expect) {
  const auto b = n.call("GET", "/v1/identity").body();
  return b.find(std::string("\"startup_unverified\":") + (expect ? "true" : "false")) != std::string::npos;
}

TEST(BundleRoutes, ReplyOnlyAfterTheSwap) {
  Node n;
  const auto port = n.admin->port();
  const std::string env = env_gen(42);
  auto fut = std::async(std::launch::async, [=] { return tls_call(port, "client-1", http_req("POST", "/v1/bundle", env)); });
  // Wait until the admin thread has posted the swap (no timing margin): the store thread has not run it yet.
  for (int i = 0; i < 5000 && !n.queued; ++i) std::this_thread::sleep_for(2ms);
  ASSERT_TRUE(n.queued);
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  EXPECT_NE(fut.wait_for(0ms), std::future_status::ready);
  while (fut.wait_for(2ms) != std::future_status::ready) n.admin->pump(*n.server);
  const auto r = fut.get();
  EXPECT_EQ(r.code(), 200) << r.raw;
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
  std::string b;  // the persisted file is the pushed envelope
  ASSERT_TRUE(tu::read_file(n.state_dir + "/bundle.current", b));
  EXPECT_EQ(b, env);
}

TEST(BundleRoutes, SwapRunsBeforePushReturns) {  // deterministic: no HTTP, no timing
  Node n;
  bool swapped = false;
  auto r = n.bundle->push(env_gen(42), false, [&](std::function<void(Server&)> task) {
    EXPECT_EQ(n.server->applied_bundle().generation, 0u);  // nothing is applied before the task runs
    task(*n.server);
    swapped = true;
    return true;
  });
  EXPECT_TRUE(swapped);
  EXPECT_EQ(r.code, 200);
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
}

TEST(BundleRoutes, StoreThreadTimeoutIs504AndThePushIsPersisted) {
  Node n;
  const std::string env = env_gen(42);
  auto r = n.bundle->push(env, false, [](std::function<void(Server&)>) { return false; });
  EXPECT_EQ(r.code, 504);
  EXPECT_NE(r.body.find("apply_timeout"), std::string::npos);
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  EXPECT_EQ(metric(*n.server, "miracache_bundle_apply_total", {"result=\"apply_timeout\""}), 1.0);
  std::string b;
  ASSERT_TRUE(tu::read_file(n.state_dir + "/bundle.current", b));
  EXPECT_EQ(b, env);
  // Re-pushing the same bundle applies it (the floor is already there, this process has not applied it).
  auto again = n.push(env);
  EXPECT_EQ(again.code(), 200) << again.raw;
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
}

TEST(BundleRoutes, CrashBetweenFloorCommitAndRenameIsHealedAtStartup) {  // X02
  const std::string dir = make_dir();
  { Node n(dir); ASSERT_EQ(n.push(env_gen(42)).code(), 200); }
  const std::string env43 = env_gen(43, 8);
  {  // tmp written and fsynced, floor committed, then the process died before the rename
    auto tk = control::parse_trust_keys(tu::trust_toml());
    ASSERT_TRUE(tk);
    auto v = control::open_bundle(env43, *tk);
    ASSERT_TRUE(v);
    auto fs = control::FloorState::open(dir);
    ASSERT_TRUE(fs);
    ASSERT_TRUE(fs->commit(*v));
    std::ofstream(dir + "/bundle.current.tmp", std::ios::binary | std::ios::trunc) << env43;
  }
  {
    Node n(dir);
    EXPECT_FALSE(n.bundle->startup_unverified());
    EXPECT_EQ(n.server->applied_bundle().generation, 43u);
    std::string b;
    ASSERT_TRUE(tu::read_file(dir + "/bundle.current", b));
    EXPECT_EQ(b, env43);
    EXPECT_FALSE(file_exists(dir + "/bundle.current.tmp"));
  }
  {  // a tmp that does not match the floor is discarded
    std::ofstream(dir + "/bundle.current.tmp", std::ios::binary | std::ios::trunc) << env_gen(44, 9);
    Node n(dir);
    EXPECT_EQ(n.server->applied_bundle().generation, 43u);
    EXPECT_FALSE(file_exists(dir + "/bundle.current.tmp"));
  }
  std::system(("rm -rf " + dir).c_str());
}

TEST(BundleRoutes, RotatedOutKeyAtStartupAppliesWhenEqualToTheFloor) {  // X03 (exception) + X11
  const std::string dir = make_dir();
  const std::string sec = tu::sec_toml(5), body = tu::body_toml(42, 7, 6);
  { Node n(dir); ASSERT_EQ(n.push(tu::make_envelope(sec, body)).code(), 200); }
  Node n(dir, rotated_trust());
  ASSERT_TRUE(n.bundle->startup_view());
  EXPECT_TRUE(n.bundle->startup_unverified());
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
  EXPECT_EQ(metric(*n.server, "miracache_bundle_reject_total", {"reason=\"startup_unverified\""}), 1.0);
  EXPECT_EQ(metric(*n.server, "miracache_bundle_startup_unverified"), 1.0);
  EXPECT_EQ(json_num(n.call("GET", "/v1/identity").body(), "applied_generation"), 42);
  EXPECT_TRUE(identity_flag(n, true));
  // The next successful push (signed by the new key) clears the alert.
  const auto ns = tu::seed_from(0x41);
  auto r = n.push(tu::assemble(tu::sign_parts(sec, body, ns, ns)));
  ASSERT_EQ(r.code(), 200) << r.raw;
  EXPECT_TRUE(identity_flag(n, false));
  EXPECT_EQ(metric(*n.server, "miracache_bundle_startup_unverified"), 0.0);
  std::system(("rm -rf " + dir).c_str());
}

TEST(BundleRoutes, RotatedOutKeyThatDiffersFromTheFloorServesNothing) {  // X03 (other branches)
  const std::string dir = make_dir();
  std::string old42;
  {
    Node n(dir);
    ASSERT_EQ(n.push(env_gen(42)).code(), 200);
    ASSERT_TRUE(tu::read_file(dir + "/bundle.current", old42));
    ASSERT_EQ(n.push(env_gen(43, 8)).code(), 200);
  }
  std::ofstream(dir + "/bundle.current", std::ios::binary | std::ios::trunc) << old42;  // below the floor
  Node n(dir, rotated_trust());
  EXPECT_FALSE(n.bundle->startup_view());
  EXPECT_TRUE(n.bundle->startup_unverified());
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  std::system(("rm -rf " + dir).c_str());
}

TEST(BundleRoutes, StoredBundleThatFailsTheFloorCheckServesNothing) {  // X04
  const std::string dir = make_dir();
  { Node n(dir); ASSERT_EQ(n.push(env_gen(43, 8)).code(), 200); }
  // A correctly signed bundle above the floor generation but with an older epoch.
  std::ofstream(dir + "/bundle.current", std::ios::binary | std::ios::trunc) << env_gen(44, 7);
  Node n(dir);
  EXPECT_FALSE(n.bundle->startup_view());
  EXPECT_TRUE(n.bundle->startup_unverified());
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  EXPECT_EQ(metric(*n.server, "miracache_bundle_reject_total", {"reason=\"startup_unverified\""}), 1.0);
  std::system(("rm -rf " + dir).c_str());
}

TEST(BundleRoutes, SymlinksAreNeverFollowed) {  // X12
  const std::string dir = make_dir();
  { Node n(dir); ASSERT_EQ(n.push(env_gen(42)).code(), 200); }
  ASSERT_EQ(::rename((dir + "/bundle.current").c_str(), (dir + "/elsewhere").c_str()), 0);
  ASSERT_EQ(::symlink((dir + "/elsewhere").c_str(), (dir + "/bundle.current").c_str()), 0);
  {
    Node n(dir);  // a symlinked bundle.current is not read
    EXPECT_FALSE(n.bundle->startup_view());
    EXPECT_TRUE(n.bundle->startup_unverified());
  }
  // A symlink planted at the tmp name is removed, not written through.
  std::ofstream(dir + "/victim", std::ios::binary | std::ios::trunc) << "keep";
  ::unlink((dir + "/bundle.current").c_str());
  ASSERT_EQ(::symlink((dir + "/victim").c_str(), (dir + "/bundle.current.tmp").c_str()), 0);
  Node n(dir);
  ASSERT_EQ(n.push(env_gen(42)).code(), 200);
  std::string v;
  ASSERT_TRUE(tu::read_file(dir + "/victim", v));
  EXPECT_EQ(v, "keep");
  std::system(("rm -rf " + dir).c_str());
}

TEST(BundleRoutes, TrustFileChangeIsPickedUpByTheStatCheck) {  // X13
  Node n;
  n.write_trust(tu::trust_toml(/*single_key_both_roles=*/true));  // the security key is gone
  n.bundle->maybe_reload_trust();                                  // before 10 s nothing is re-read
  EXPECT_EQ(n.push(env_gen(42)).code(), 200);
  n.clock.advance_by(std::chrono::seconds(11));
  n.bundle->maybe_reload_trust();
  EXPECT_EQ(n.push(env_gen(43)).code(), 403);
}

TEST(BundleRoutes, CertWithoutSanIsRefusedOnBundleRoutes) {  // X14, X20
  Node n;
  EXPECT_EQ(n.call("GET", "/v1/identity", "", "nosan").code(), 403);
  EXPECT_EQ(n.call("GET", "/v1/bundle", "", "nosan").code(), 403);
  // Refused right after the head: a body that never arrives does not delay the answer.
  const auto port = n.admin->port();
  auto r = n.run([=] {
    return tls_call(port, "nosan", "POST /v1/bundle HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\n");
  });
  EXPECT_EQ(r.code(), 403);
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
}

TEST(BundleRoutes, PinRaisedAboveRotatedOutBundleServesNothing) {  // Y03
  const std::string dir = make_dir();
  { Node n(dir); ASSERT_EQ(n.push(env_gen(42)).code(), 200); }  // sec_generation 5
  {  // the pin equals the bundle's sec_generation: still applied (the X03 exception)
    Node n(dir, rotated_trust() + "min_sec_generation = 5\n");
    EXPECT_TRUE(n.bundle->startup_view());
  }
  {  // the pin is above it: no bundle
    Node n(dir, rotated_trust() + "min_sec_generation = 6\n");
    EXPECT_FALSE(n.bundle->startup_view());
    EXPECT_TRUE(n.bundle->startup_unverified());
    EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  }
  std::system(("rm -rf " + dir).c_str());
}

TEST(BundleRoutes, BundleModeRefusesRailsItCannotAdvertise) {  // Y12
  using fabric::RailAddr;
  auto ok = bundle_rails({RailAddr{"127.0.0.1", 7471}}, "roce");
  EXPECT_TRUE(ok.error.empty()) << ok.error;
  ASSERT_EQ(ok.rails.size(), 1u);
  EXPECT_EQ(ok.rails[0].addr, "127.0.0.1:7471");
  EXPECT_EQ(ok.rails[0].protocol, "roce");
  EXPECT_FALSE(ok.rails[0].subnet.empty());
  EXPECT_TRUE(bundle_rails({RailAddr{"127.0.0.1", 7471}}, "iwarp").error.empty());
  // A wildcard, a hostname and an address no interface owns have no subnet: refused, naming the rail.
  for (const char* host : {"", "0.0.0.0", "somehost.example", "203.0.113.77"}) {
    auto r = bundle_rails({RailAddr{"127.0.0.1", 7471}, RailAddr{host, 7472}}, "roce");
    EXPECT_FALSE(r.error.empty()) << host;
    EXPECT_NE(r.bad_rail.find(":7472"), std::string::npos) << r.bad_rail;
    EXPECT_TRUE(r.rails.empty());
  }
  // InfiniBand (or anything but roce/iwarp) is not a v1 transport.
  auto ib = bundle_rails({RailAddr{"127.0.0.1", 7471}}, "ib");
  EXPECT_NE(ib.error.find("roce and iwarp"), std::string::npos);
  EXPECT_FALSE(ib.bad_rail.empty());
  EXPECT_FALSE(bundle_rails({}, "roce").error.empty());  // no listen rail at all
}

TEST(BundleRoutes, IdentityListsRails) {  // X06
  Node n;
  const auto j = n.call("GET", "/v1/identity").body();
  EXPECT_NE(j.find("\"rails\":[{\"addr\":\"10.0.0.10:7471\",\"subnet\":\"10.0.0.0/24\",\"protocol\":\"roce\",\"up\":true}]"),
            std::string::npos)
      << j;
  EXPECT_EQ(rail_subnet(""), "");
  EXPECT_EQ(rail_subnet("0.0.0.0"), "");
  EXPECT_EQ(rail_subnet("not an address"), "");
  const auto lo = rail_subnet("127.0.0.1");
  EXPECT_EQ(lo.rfind("127.", 0), 0u) << lo;
  EXPECT_NE(lo.find('/'), std::string::npos);
}

// RL1: rails[] carries the server's real health, not a flag set once at start-up.
TEST(BundleRoutes, IdentityReportsRealRailHealth) {
  Node n;
  const auto pre = n.call("GET", "/v1/identity").body();  // not started: the start-up flag only
  EXPECT_NE(pre.find("\"up\":true}]"), std::string::npos) << pre;
  ASSERT_TRUE(n.server->start());
  const std::string ok = "\"protocol\":\"roce\",\"up\":true,\"port_state\":\"ACTIVE\",\"listener_ok\":true}]";
  EXPECT_NE(n.call("GET", "/v1/identity").body().find(ok), std::string::npos);
  n.fab.set_port_state_for_test("DOWN");
  n.server->refresh_rail_health();
  const auto down = n.call("GET", "/v1/identity").body();
  EXPECT_NE(down.find("\"up\":false,\"port_state\":\"DOWN\",\"listener_ok\":true}]"), std::string::npos) << down;
  n.fab.set_port_state_for_test("ACTIVE");
  n.fab.set_fatal_for_test(true);  // a fatal async event, port still ACTIVE
  n.server->refresh_rail_health();
  const auto fatal = n.call("GET", "/v1/identity").body();
  EXPECT_NE(fatal.find("\"up\":false,\"port_state\":\"ACTIVE\",\"listener_ok\":true}]"), std::string::npos) << fatal;
  n.fab.set_fatal_for_test(false);
  ASSERT_TRUE(n.fab.fail_rail(fabric::RailAddr{}));  // the listener is gone
  n.server->refresh_rail_health();
  const auto gone = n.call("GET", "/v1/identity").body();
  EXPECT_NE(gone.find("\"up\":false,\"port_state\":\"ACTIVE\",\"listener_ok\":false}]"), std::string::npos) << gone;
}

TEST(BundleRoutes, RejectsBadBundlesAndRequests) {
  Node n;
  std::string bad_sig = env_gen(42);
  const auto p = bad_sig.find("sig: ") + 5;
  bad_sig[p] = bad_sig[p] == 'a' ? 'b' : 'a';
  auto r1 = n.push(bad_sig);
  EXPECT_EQ(r1.code(), 403);
  EXPECT_EQ(json_str(r1.body(), "reason"), "bad_signature");
  EXPECT_EQ(n.push("not a bundle").code(), 400);
  // A security-only key signing as the publisher: role confusion is refused.
  auto swapped = tu::assemble(tu::sign_parts(tu::sec_toml(5), tu::body_toml(42), tu::security_seed(), tu::security_seed()));
  EXPECT_EQ(n.push(swapped).code(), 403);
  EXPECT_EQ(n.call("PUT", "/v1/bundle", "x").code(), 405);
  EXPECT_EQ(n.call("POST", "/v1/identity", "x").code(), 405);
  EXPECT_EQ(n.call("GET", "/v1/nope").code(), 404);
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  EXPECT_FALSE(file_exists(n.state_dir + "/bundle.current"));
  EXPECT_GE(metric(*n.server, "miracache_bundle_reject_total", {"reason=\"bad_signature\""}), 1.0);
  // No client certificate: the TLS layer refuses before any route runs.
  const auto port = n.admin->port();
  auto anon = n.run([=] { return tls_call(port, "", http_req("GET", "/v1/identity")); });
  EXPECT_NE(anon.code(), 200);
  // A bundle over 1 MiB is refused with 413 before it is read in full.
  auto huge = n.run([=] {
    return tls_call(port, "client-1", "POST /v1/bundle HTTP/1.1\r\nHost: x\r\nContent-Length: 2000000\r\n\r\n");
  });
  EXPECT_EQ(huge.code(), 413);
}

TEST(BundleRoutes, LabModeHasNoBundleRoutes) {
  Node n("", tu::trust_toml(), /*bundle_mode=*/false);
  EXPECT_EQ(n.call("GET", "/v1/identity").code(), 404);
  EXPECT_EQ(n.call("POST", "/v1/bundle", "x").code(), 404);
  EXPECT_EQ(n.call("POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}").code(), 403);  // ticket route untouched (identity unbound)
}

TEST(BundleRoutes, ReSignedEnvelopeReplacesWithoutApply) {
  // Key rotation (decision 4): a new valid signature over the same bytes replaces the stored envelope.
  const auto new_seed = tu::seed_from(0x41);
  const auto pub = tu::public_key(new_seed);
  Node n("", tu::trust_toml() + "\n[[key]]\npublic = \"" + tu::hex(pub.data(), 32) + "\"\nroles = [\"publish\"]\n");
  const std::string sec = tu::sec_toml(5), body = tu::body_toml(42, 7, 6);
  ASSERT_EQ(n.push(tu::make_envelope(sec, body)).code(), 200);
  EXPECT_EQ(json_str(n.call("GET", "/v1/identity").body(), "key_id"), tu::key_id_hex(tu::publish_seed()));
  const std::string resigned = tu::assemble(tu::sign_parts(sec, body, new_seed, tu::security_seed()));
  auto r = n.push(resigned);
  ASSERT_EQ(r.code(), 200) << r.raw;
  EXPECT_EQ(json_str(r.body(), "result"), "replaced");
  EXPECT_EQ(metric(*n.server, "miracache_bundle_apply_total", {"result=\"applied\""}), 1.0);  // no second apply
  EXPECT_EQ(json_str(n.call("GET", "/v1/identity").body(), "key_id"), tu::key_id_hex(new_seed));
  EXPECT_EQ(n.call("GET", "/v1/bundle").body(), resigned);
  // The persisted envelope is the new one.
  std::string b;
  ASSERT_TRUE(tu::read_file(n.state_dir + "/bundle.current", b));
  EXPECT_EQ(b, resigned);
}

TEST(BundleRoutes, TrustFileReloadKeepsOldKeysOnFailure) {
  Node n;
  n.write_trust("this is not toml [[");
  EXPECT_FALSE(n.bundle->reload_trust());
  EXPECT_EQ(metric(*n.server, "miracache_bundle_reject_total", {"reason=\"trust_file\""}), 1.0);
  EXPECT_EQ(n.push(env_gen(42)).code(), 200);  // the old keys still verify
  n.write_trust(tu::trust_toml(/*single_key_both_roles=*/true));
  EXPECT_TRUE(n.bundle->reload_trust());
  EXPECT_EQ(n.push(env_gen(43)).code(), 403);  // the security key is gone now: the old pair no longer verifies
}

// ---- HR1: config.cluster.memnode over the push route, and credential files (P13, P16, P39) ---------------------------
TEST(BundleRoutes, PushAppliesTheMemnodeConfigAndRejectsAStaticKey) {
  Node n;
  const std::string good = tu::make_envelope(tu::sec_toml(5), tu::body_toml(42, 7, 6, "\n[config.cluster.memnode.lease]\nttl_s = 4\nmax_s = 40\n"
                                                                                 "[config.cluster.memnode.quota]\nput_ops_per_s = 9\nfuture_knob = 1\n"));
  auto dry = n.push(good, /*dry=*/true);
  ASSERT_EQ(dry.code(), 200) << dry.raw;
  EXPECT_EQ(n.server->dyn()->lease_ttl, 30s);  // a dry run applies nothing
  auto ok = n.push(good);
  ASSERT_EQ(ok.code(), 200) << ok.raw;
  EXPECT_EQ(n.server->dyn()->lease_ttl, 4s);
  EXPECT_EQ(n.server->dyn()->put_ops_per_s, 9u);
  EXPECT_EQ(n.server->store().limits().lease_max, 40s);
  EXPECT_EQ(metric(*n.server, "miracache_config_reload_total", {"result=\"applied\""}), 1.0);
  // A STATIC key rejects the whole bundle, on the dry run and on the real push; the old snapshot and generation stay.
  const std::string bad = tu::make_envelope(tu::sec_toml(5), tu::body_toml(43, 8, 7, "\n[config.cluster.memnode.lease]\nttl_s = 9\n"
                                                                                 "[config.cluster.memnode.store]\nn_segments = 4\n"));
  auto bdry = n.push(bad, /*dry=*/true);
  EXPECT_EQ(bdry.code(), 400) << bdry.raw;
  EXPECT_NE(bdry.body().find("STATIC"), std::string::npos) << bdry.body();
  auto bpush = n.push(bad);
  EXPECT_EQ(bpush.code(), 400);
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
  EXPECT_EQ(n.server->dyn()->lease_ttl, 4s);
  EXPECT_EQ(metric(*n.server, "miracache_config_reload_total", {"result=\"rejected\""}), 2.0);  // the dry run and the real push
  EXPECT_EQ(metric(*n.server, "miracache_bundle_reject_total", {"reason=\"config\""}), 2.0);
  // An unknown key under a known section is ignored (rolling upgrade), counted at the swap.
  EXPECT_EQ(metric(*n.server, "miracache_config_unknown_keys_total"), 2.0);  // log_level (the fixture's) and future_knob
}

TEST(BundleRoutes, TrustFileFailureKeepsOldKeysCountsAndRetriesNextTick) {  // P39
  Node n;
  // The admin listener's accept loop runs the same 10 s trust check (AdminHttps::accept_loop, every poll slice), so after
  // the clock moves EITHER thread does the reload (exactly one: next_stat_ is claimed under the lock) and the count can
  // land a moment after our own call returns. Wait for it (real time, bounded) instead of reading it at once (gate
  // 2026-11-18, asan on 8 CPUs: read 0, the admin thread's reload still loading the file).
  auto reloads = [&](const char* result, double want) {
    const std::vector<std::string> sel = {"kind=\"trust_keys\"", std::string("result=\"") + result + "\""};
    const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (metric(*n.server, "miracache_cred_reload_total", sel) < want && std::chrono::steady_clock::now() < end)
      std::this_thread::sleep_for(std::chrono::milliseconds(2));
    return metric(*n.server, "miracache_cred_reload_total", sel);
  };
  n.write_trust("half written [[");
  n.clock.advance_by(11s);
  n.bundle->maybe_reload_trust();
  EXPECT_EQ(reloads("rejected", 1.0), 1.0);
  n.clock.advance_by(11s);  // the file did not change, the failed signature is not remembered: retried
  n.bundle->maybe_reload_trust();
  EXPECT_EQ(reloads("rejected", 2.0), 2.0);  // once per tick, whichever thread ran it
  EXPECT_EQ(n.push(env_gen(42)).code(), 200);  // the old keys still verify
  n.write_trust(tu::trust_toml());
  n.clock.advance_by(11s);
  n.bundle->maybe_reload_trust();
  EXPECT_EQ(reloads("applied", 1.0), 1.0);
}

TEST(BundleRoutes, AdminCertAndKeyReplacedNonAtomicallyKeepTheOldMaterialUntilTheyMatch) {  // P39
  const auto& c = certs();
  const std::string dir = make_dir();
  const std::string pki2 = dir + "/pki2";
  auto sh = [](const std::string& cmd) { EXPECT_EQ(std::system(cmd.c_str()), 0) << cmd; };
  sh("mkdir -p " + pki2 + " && cp " + c.pki + "/ca.pem " + c.pki + "/ca.key " + pki2 + "/ && bash " + MIRACACHE_LAB_CERTS_SH + " " +
     pki2 + " --nodes 2 --clients 1 >/dev/null");
  sh("cp " + c.pki + "/node-1.pem " + dir + "/cert.pem && cp " + c.pki + "/node-1.key " + dir + "/key.pem && cp " + c.pki +
     "/ca.pem " + dir + "/ca.pem && chmod 600 " + dir + "/key.pem");
  telemetry::Registry reg;
  AdminOptions ao{"127.0.0.1:0", dir + "/cert.pem", dir + "/key.pem", dir + "/ca.pem", 300};
  ao.cred_stat_ms = 30;
  auto a = AdminHttps::start(ao, reg);
  ASSERT_TRUE(a && *a);
  auto& rej = reg.counter("miracache_cred_reload_total", "Credential file reloads, by kind and result.", {{"kind", "admin_tls"}, {"result", "rejected"}});
  auto& app = reg.counter("miracache_cred_reload_total", "Credential file reloads, by kind and result.", {{"kind", "admin_tls"}, {"result", "applied"}});
  auto wait = [](auto&& pred) {
    for (int i = 0; i < 300 && !pred(); ++i) std::this_thread::sleep_for(10ms);
    return pred();
  };
  // Step 1 of a non-atomic rotation: the new certificate lands first. Its key is not there yet: key mismatch.
  sh("cp " + pki2 + "/node-2.pem " + dir + "/cert.pem");
  ASSERT_TRUE(wait([&] { return rej.value() >= 1; }));
  EXPECT_EQ(app.value(), 0u);
  EXPECT_TRUE(tls_call((*a)->port(), "client-1", http_req("GET", "/v1/identity")).connected);  // old material still serves
  const auto rejected_so_far = rej.value();
  ASSERT_TRUE(wait([&] { return rej.value() > rejected_so_far; }));  // the same mismatch is re-checked every tick
  // Step 2: the matching key arrives; the next tick takes the pair.
  sh("cp " + pki2 + "/node-2.key " + dir + "/key.pem && chmod 600 " + dir + "/key.pem");
  ASSERT_TRUE(wait([&] { return app.value() >= 1; }));
  // A truncated certificate is rejected too, and the pair in use stays.
  sh(": > " + dir + "/cert.pem");
  const auto r2 = rej.value();
  ASSERT_TRUE(wait([&] { return rej.value() > r2; }));
  EXPECT_EQ(app.value(), 1u);
  a->reset();
  sh("rm -rf " + dir);
}

TEST(BundleRoutes, NodeConfigControlSection) {
  auto ok = parse_node_config("[store]\nbacking = \"anon\"\n[admin]\nlisten = \"127.0.0.1:0\"\ncert = \"a\"\nkey = \"b\"\nca = \"c\"\n"
                              "[control]\ntrust_keys = \"/etc/miracache/trust.toml\"\n");
  ASSERT_TRUE(ok) << ok.error().context;
  EXPECT_EQ(ok->trust_keys, "/etc/miracache/trust.toml");
  EXPECT_FALSE(parse_node_config("[store]\nbacking = \"anon\"\n[control]\ntrust_keys = \"/x\"\n"));  // needs [admin]
  EXPECT_FALSE(parse_node_config("[store]\nbacking = \"anon\"\n[control]\nendpoints = []\n"));
  auto lab = parse_node_config("[store]\nbacking = \"anon\"\n");
  ASSERT_TRUE(lab);
  EXPECT_TRUE(lab->trust_keys.empty());
}

}  // namespace
}  // namespace miracache::server
