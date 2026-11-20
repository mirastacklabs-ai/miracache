// SPDX-License-Identifier: Apache-2.0
// Memory-node RBAC, audit wiring and the admin routes (RBAC and audit)
//   * the route table equals the plan; every route x every role (allowed, denied, no SAN);
//   * bundle / identity need only plain mTLS, also on a blank node;
//   * bindings follow the applied bundle; lab mode follows [[admin.rbac]] (SIGHUP);
//   * a denial flood is coalesced to about one entry per second;
//   * audit entries for bundle apply / rejection / ticket refusal / drain / drop_principal verify as a chain, carry
//     node ID + host + IP, and GET /v1/identity shows the anchor (audit_seq, audit_head);
//   * the audit log cannot be opened: the admin API is refused, the data plane serves;
//   * drop_principal leaves other principals alone and later scopes alive.
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <thread>

#include <openssl/err.h>
#include <openssl/ssl.h>

#include <gtest/gtest.h>

#include "control/audit.h"
#include "control/bundle_test_util.h"
#include "control/floor_state.h"
#include "fabric/sim/sim_fabric.h"
#include "server/node_config.h"
#include "server/runtime/admin_https.h"
#include "server/runtime/bundle_store.h"
#include "server/runtime/rbac.h"
#include "server/server.h"
#include "util/clock.h"
#include "util/random.h"

namespace miracache::server {
namespace {

using namespace std::chrono_literals;
namespace tu = control::testutil;

struct Certs {
  std::string root, pki;
  Certs() {
    char t[] = "/tmp/mira-rbac-XXXXXX";
    EXPECT_NE(::mkdtemp(t), nullptr);
    root = t;
    pki = root + "/pki";
    const std::string cmd = std::string("bash ") + MIRACACHE_LAB_CERTS_SH + " " + pki + " --nodes 1 --clients 1,2,3,4,5 >/dev/null";
    EXPECT_EQ(std::system(cmd.c_str()), 0);
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

// `mid`, when set, runs between the request head and its body.
Https tls_call(std::uint16_t port, const std::string& who, const std::string& req, const std::function<void()>& mid = nullptr) {
  const auto& c = certs();
  Https r;
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  ::inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
  EXPECT_EQ(::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa), 0);
  timeval tv{8, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  EXPECT_EQ(SSL_CTX_load_verify_locations(ctx, (c.pki + "/ca.pem").c_str(), nullptr), 1);
  EXPECT_EQ(SSL_CTX_use_certificate_file(ctx, (c.pki + "/" + who + ".pem").c_str(), SSL_FILETYPE_PEM), 1);
  EXPECT_EQ(SSL_CTX_use_PrivateKey_file(ctx, (c.pki + "/" + who + ".key").c_str(), SSL_FILETYPE_PEM), 1);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  SSL* ssl = SSL_new(ctx);
  BIO* bio = new_nosigpipe_socket_bio(fd);
  SSL_set_bio(ssl, bio, bio);
  if (SSL_connect(ssl) == 1) {
    r.connected = true;
    std::size_t off = 0;
    const std::size_t split = mid ? req.find("\r\n\r\n") + 4 : req.size();
    while (off < req.size()) {
      if (mid && off == split) mid();
      const int n = SSL_write(ssl, req.data() + off, static_cast<int>((off < split ? split : req.size()) - off));
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
  char t[] = "/tmp/mira-rbac-state-XXXXXX";
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

constexpr std::uint64_t kT0 = 1'700'000'000'000ULL;  // injected audit clock start, ms (a whole second)

// A sec section: principal "prod-llama" and "p5" (client-5, a plain principal with no role), then the given bindings.
std::string sec_with(std::uint64_t sec_gen, const std::vector<std::pair<std::string, std::string>>& bindings) {
  std::string s = "sec_generation = " + std::to_string(sec_gen) + "\n\n";
  s += "[[principals]]\nname = \"prod-llama\"\nidentities = [\"spiffe://prod/vllm-host-1\"]\nquota_bytes = 1073741824\nmax_scopes = 1000\n\n";
  s += "[[principals]]\nname = \"p5\"\nidentities = [\"spiffe://lab/client-5\"]\nquota_bytes = 1073741824\nmax_scopes = 1000\n";
  for (const auto& [id, role] : bindings) s += "\n[[rbac]]\nidentity = \"" + id + "\"\nroles = [\"" + role + "\"]\n";
  return s;
}
const std::vector<std::pair<std::string, std::string>> kBindings = {
    {"spiffe://lab/client-1", "viewer"},
    {"spiffe://lab/client-2", "operator"},
    {"spiffe://lab/client-3", "security-admin"},
    {"spiffe://lab/client-4", "scope-provider"},
};
std::string env(std::uint64_t gen, std::uint64_t sec_gen, const std::vector<std::pair<std::string, std::string>>& b = kBindings) {
  return tu::make_envelope(sec_with(sec_gen, b), tu::body_toml(gen, 7, 6));
}

struct Node {
  enum class Audit { Off, On, Broken };
  explicit Node(bool bundle_mode, Audit audit_mode = Audit::On, std::vector<RbacBinding> lab = {})
      : rng(3), net(clock, rng, {}, {}), fab(net.add_node(1)), mode(bundle_mode), audit_mode_(audit_mode), lab_rbac(std::move(lab)) {
    state_dir = make_dir();
    {
      std::ofstream f(state_dir + "/trust.toml", std::ios::binary);
      f << tu::trust_toml();
    }
    ServerConfig sc;
    sc.store = store_cfg();
    sc.store.node_id = 3141592653u;  // the node the test bundle lists as active
    sc.lab_identity = "lab";
    sc.lab_principal = 5;
    sc.ticket_max_per_identity = 4;
    sc.wall_unix_ns = [this] { return static_cast<std::int64_t>(kT0) * 1'000'000 + clock.now().count(); };
    auto s = Server::create(sc, fab, clock, rng, exec);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
    audit_dir = state_dir + "/audit";
    if (audit_mode_ == Audit::Broken) {  // a regular file where the directory should be
      std::ofstream f(audit_dir);
      f << "x";
    }
    start();
  }
  ~Node() {
    admin.reset();
    audit.reset();
    bundle.reset();
    (void)std::system(("rm -rf " + state_dir).c_str());
  }
  void start() {
    admin.reset();
    if (mode) {
      BundleStoreOptions bo;
      bo.state_dir = state_dir;
      bo.trust_path = state_dir + "/trust.toml";
      bo.node_id = server->node_id();
      bo.hostname = "hostA";
      bo.addr = "10.0.0.10:7471";
      bo.admin = "10.0.0.10:9465";
      bo.reg = &server->metrics();
      bo.snapshot = [s = server.get()] { return s->node_snapshot(); };
      bo.clock = &clock;
      bo.rails = {{"10.0.0.10:7471", "10.0.0.0/24", "roce"}};
      bo.audit_anchor = [this] {
        return audit ? audit->anchor() : std::make_pair(std::uint64_t{0}, std::string(64, '0'));
      };
      bo.wall_unix_s = [this] { return static_cast<std::int64_t>(kT0 / 1000) + clock.now().count() / 1'000'000'000LL; };
      auto b = BundleStore::open(std::move(bo));
      EXPECT_TRUE(b);
      bundle = std::move(*b);
      bundle->set_rails_up(true);
    }
    if (audit_mode_ != Audit::Off) {
      AdminAuditOptions ao;
      ao.dir = audit_dir;
      ao.node_id = server->node_id();
      ao.host = "hostA";
      ao.addr = "10.0.0.10:7471";
      ao.now_ms = [this] { return fake_ms.load(); };
      ao.write_fn = [this](int fd, const void* p, std::size_t n) -> long {
        if (fail_audit_writes.load()) {
          errno = EIO;
          return -1;
        }
        return static_cast<long>(::write(fd, p, n));
      };
      auto a = AdminAudit::open(std::move(ao));
      audit_open_ok = static_cast<bool>(a);
      if (a) audit = std::move(*a);
    }
    const auto& c = certs();
    AdminOptions o{"127.0.0.1:0", c.pki + "/node-1.pem", c.pki + "/node-1.key", c.pki + "/ca.pem", 300};
    o.node_id = server->node_id();
    o.hostname = "hostA";
    o.bundle = bundle.get();
    o.audit = audit.get();
    o.audit_failed = audit_mode_ != Audit::Off && !audit;
    o.lab_rbac = lab_rbac;
    o.state_dir = persist ? state_dir : std::string();
    o.wakeup = [] {};
    auto a = AdminHttps::start(o, server->metrics());
    EXPECT_TRUE(a && *a);
    if (a && *a) admin = std::move(*a);
  }
  template <typename F>
  auto run(F fn) {
    auto fut = std::async(std::launch::async, fn);
    while (fut.wait_for(2ms) != std::future_status::ready) {
      admin->pump(*server);
      server->run_once();
    }
    return fut.get();
  }
  Https call(const std::string& who, const std::string& method, const std::string& path, const std::string& body = "") {
    const auto port = admin->port();
    return run([=] { return tls_call(port, who, http_req(method, path, body)); });
  }
  // Writes every open coalescing window (as the shutdown hook does), then returns the audit lines.
  std::vector<std::string> lines() {
    if (audit) audit->flush_all();
    std::vector<std::string> out;
    for (const auto& f : control::list_audit_files(audit_dir)) {
      std::ifstream in(f, std::ios::binary);
      std::string l;
      while (std::getline(in, l)) out.push_back(l);
    }
    return out;
  }

  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& fab;
  InlineExecutor exec;
  std::unique_ptr<Server> server;
  std::unique_ptr<BundleStore> bundle;
  std::unique_ptr<AdminAudit> audit;
  std::unique_ptr<AdminHttps> admin;
  std::string state_dir, audit_dir;
  bool mode;
  bool audit_open_ok = false;
  Audit audit_mode_;
  std::vector<RbacBinding> lab_rbac;
  std::atomic<std::uint64_t> fake_ms{kT0};
  std::atomic<bool> fail_audit_writes{false};
  bool persist = true;  // false: the admin API has no state_dir (drop_principal cannot persist)
};

const char* const kViewer = "client-1";
const char* const kOperator = "client-2";
const char* const kSecAdmin = "client-3";
const char* const kScopeProv = "client-4";
const char* const kNoRole = "client-5";
const char* const kNoSan = "nosan";
const char* const kDropBody = "{\"name\":\"prod-llama\",\"drop_before\":\"2023-11-01T00:00:00Z\"}";

std::vector<std::string> with(const std::vector<std::string>& ls, const std::string& needle) {
  std::vector<std::string> out;
  for (const auto& l : ls)
    if (l.find(needle) != std::string::npos) out.push_back(l);
  return out;
}
long long total_count(const std::vector<std::string>& ls) {
  long long n = 0;
  for (const auto& l : ls) n += json_num(l, "count");
  return n;
}

// ---- the route table ------------------------------------------------------------------------------

TEST(Rbac, RouteTableEqualsDecision4) {
  struct Row {
    const char* method;
    const char* path;
    Need need;
    bool bundle_only;
  };
  const Row want[] = {
      {"POST", "/v1/tickets", Need::Principal, false},
      {"GET", "/v1/bundle", Need::Authenticated, true},
      {"POST", "/v1/bundle", Need::Authenticated, true},
      {"GET", "/v1/identity", Need::Authenticated, true},
      {"POST", "/v1/drain", Need::Operator, false},
      {"POST", "/v1/drop_principal", Need::SecurityAdmin, false},
  };
  const auto& t = route_table();
  ASSERT_EQ(t.size(), std::size(want));
  for (std::size_t i = 0; i < t.size(); ++i) {
    EXPECT_STREQ(t[i].method, want[i].method);
    EXPECT_STREQ(t[i].path, want[i].path);
    EXPECT_EQ(t[i].need, want[i].need) << t[i].path;
    EXPECT_EQ(t[i].bundle_mode_only, want[i].bundle_only) << t[i].path;
  }
  // The role semantics: viewer reads (no memory-node route), scope-provider grants nothing in v1, unknown grants nothing.
  for (const char* r : {"viewer", "scope-provider", "nonsense", ""}) {
    EXPECT_FALSE(role_grants(r, Need::Operator)) << r;
    EXPECT_FALSE(role_grants(r, Need::SecurityAdmin)) << r;
  }
  EXPECT_TRUE(role_grants("operator", Need::Operator));
  EXPECT_FALSE(role_grants("operator", Need::SecurityAdmin));
  EXPECT_TRUE(role_grants("security-admin", Need::SecurityAdmin));
  EXPECT_FALSE(role_grants("security-admin", Need::Operator));
}

// ---- role matrix ----------------------------------------------------------------------------------

TEST(Rbac, BundleAndIdentityNeedOnlyMtlsEvenOnABlankNode) {
  Node n(true);
  // Blank node: no bundle, no bindings. A certificate with a SAN reaches identity and the bundle push.
  for (const char* who : {kViewer, kOperator, kSecAdmin, kScopeProv, kNoRole}) {
    auto id = n.call(who, "GET", "/v1/identity");
    EXPECT_EQ(id.code(), 200) << who << " " << id.raw;
  }
  EXPECT_EQ(n.call(kNoSan, "GET", "/v1/identity").code(), 403);
  EXPECT_EQ(n.call(kNoSan, "POST", "/v1/bundle", env(42, 5)).code(), 403);
  // ... and the role-gated routes deny everyone (no bindings yet).
  for (const char* who : {kViewer, kOperator, kSecAdmin, kScopeProv, kNoRole}) {
    EXPECT_EQ(n.call(who, "POST", "/v1/drain").code(), 403) << who;
    EXPECT_EQ(n.call(who, "POST", "/v1/drop_principal", kDropBody).code(), 403) << who;
  }
  // The first push comes from an identity with NO role: the signature is the gate (no lock-out, no bootstrap case).
  auto r = n.call(kNoRole, "POST", "/v1/bundle", env(42, 5));
  ASSERT_EQ(r.code(), 200) << r.raw;
  EXPECT_EQ(json_str(r.body(), "result"), "applied");
}

TEST(Rbac, EveryRouteTimesEveryRole) {
  Node n(true);
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(42, 5)).code(), 200);
  const char* const all[] = {kViewer, kOperator, kSecAdmin, kScopeProv, kNoRole};

  // GET /v1/identity, GET /v1/bundle, POST /v1/bundle (dry run): authenticated is enough, whatever the role.
  for (const char* who : all) {
    EXPECT_EQ(n.call(who, "GET", "/v1/identity").code(), 200) << who;
    EXPECT_EQ(n.call(who, "GET", "/v1/bundle").code(), 200) << who;
    EXPECT_EQ(n.call(who, "POST", "/v1/bundle?dry_run=1", env(42, 5)).code(), 200) << who;
  }
  for (const char* p : {"/v1/identity", "/v1/bundle"}) EXPECT_EQ(n.call(kNoSan, "GET", p).code(), 403) << p;
  EXPECT_EQ(n.call(kNoSan, "POST", "/v1/bundle?dry_run=1", env(42, 5)).code(), 403);

  // POST /v1/tickets: the principal table decides, no role is needed (client-5 is a principal and has no role) ...
  auto t5 = n.call(kNoRole, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}");
  EXPECT_EQ(t5.code(), 200) << t5.raw;
  // ... and a role does not make a non-principal one.
  for (const char* who : {kViewer, kOperator, kSecAdmin}) {
    auto t = n.call(who, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}");
    EXPECT_EQ(t.code(), 403) << who;
    EXPECT_NE(t.body().find("identity not allowed"), std::string::npos) << who;
  }
  EXPECT_EQ(n.call(kNoSan, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}").code(), 403);

  // POST /v1/drop_principal: security-admin only.
  for (const char* who : {kViewer, kOperator, kScopeProv, kNoRole, kNoSan}) {
    auto r = n.call(who, "POST", "/v1/drop_principal", kDropBody);
    EXPECT_EQ(r.code(), 403) << who;
    if (std::string(who) != kNoSan) EXPECT_NE(r.body().find("role security-admin required"), std::string::npos) << who << r.body();
  }
  auto d = n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody);
  EXPECT_EQ(d.code(), 200) << d.raw;
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"nobody\",\"drop_before\":\"2023-11-01T00:00:00Z\"}").code(), 404);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"prod-llama\"}").code(), 400);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"prod-llama\",\"drop_before\":\"yesterday\"}").code(), 400);

  // POST /v1/drain: operator only (last: the drain latch refuses tickets afterwards).
  for (const char* who : {kViewer, kSecAdmin, kScopeProv, kNoRole, kNoSan}) {
    auto r = n.call(who, "POST", "/v1/drain");
    EXPECT_EQ(r.code(), 403) << who;
    if (std::string(who) != kNoSan) EXPECT_NE(r.body().find("role operator required"), std::string::npos) << who << r.body();
  }
  EXPECT_FALSE(n.server->draining());
  EXPECT_EQ(n.call(kOperator, "POST", "/v1/drain", "{\"drain_ms\":700000}").code(), 400);
  auto dr = n.call(kOperator, "POST", "/v1/drain", "{\"drain_ms\":1000}");
  ASSERT_EQ(dr.code(), 200) << dr.raw;
  EXPECT_EQ(json_str(dr.body(), "result"), "draining");
  EXPECT_TRUE(n.server->draining());
  EXPECT_EQ(json_str(n.call(kOperator, "POST", "/v1/drain").body(), "result"), "already_draining");  // idempotent
  EXPECT_EQ(n.call(kNoRole, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}").code(), 503);

  // Wrong methods are 405.
  EXPECT_EQ(n.call(kOperator, "GET", "/v1/drain").code(), 405);
  EXPECT_EQ(n.call(kSecAdmin, "GET", "/v1/drop_principal").code(), 405);
  EXPECT_EQ(n.call(kOperator, "POST", "/v1/identity").code(), 405);
  EXPECT_EQ(n.call(kOperator, "POST", "/v1/stats").code(), 404);  // route removed

  // Every denial and the metric.
  std::string m;
  n.server->metrics().write_prometheus(m);
  auto counted = [&](const char* path) {
    std::istringstream is(m);
    for (std::string l; std::getline(is, l);)
      if (l.rfind("miracache_admin_requests_total", 0) == 0 && l.find(std::string("path=\"") + path + "\"") != std::string::npos &&
          l.find("code=\"403\"") != std::string::npos)
        return true;
    return false;
  };
  EXPECT_TRUE(counted("/v1/drain")) << m;
  EXPECT_TRUE(counted("/v1/drop_principal"));
}

TEST(Rbac, LabModeFollowsAdminRbacAndSighup) {
  Node n(false, Node::Audit::Off, {{"spiffe://lab/client-2", {"operator"}}, {"spiffe://lab/client-3", {"security-admin"}}});
  // Lab mode keeps today's surface: no bundle routes.
  EXPECT_EQ(n.call(kOperator, "GET", "/v1/identity").code(), 404);
  EXPECT_EQ(n.call(kOperator, "POST", "/v1/bundle").code(), 404);
  EXPECT_EQ(n.call(kOperator, "GET", "/v1/bundle").code(), 404);
  EXPECT_EQ(n.call(kViewer, "POST", "/v1/drain").code(), 403);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drain").code(), 403);
  EXPECT_EQ(n.call(kOperator, "POST", "/v1/drop_principal", kDropBody).code(), 403);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody).code(), 200);  // lab: no bundle, any name
  // SIGHUP: new bindings at once, the old ones gone.
  AdminOptions o = n.admin->options();
  o.lab_rbac = {{"spiffe://lab/client-1", {"operator"}}};
  ASSERT_TRUE(n.admin->reload_credentials(o));
  EXPECT_EQ(n.call(kOperator, "POST", "/v1/drain").code(), 403);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody).code(), 403);
  EXPECT_EQ(n.call(kViewer, "POST", "/v1/drain").code(), 200);
  EXPECT_TRUE(n.server->draining());
}

TEST(Rbac, BindingsChangeWhenABundleIsApplied) {
  Node n(true);
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(42, 5)).code(), 200);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody).code(), 200);
  EXPECT_EQ(n.call(kViewer, "POST", "/v1/drop_principal", kDropBody).code(), 403);
  // sec_generation 6: client-3 loses the role, client-1 becomes security-admin.
  const std::vector<std::pair<std::string, std::string>> b2 = {{"spiffe://lab/client-1", "security-admin"},
                                                               {"spiffe://lab/client-2", "operator"}};
  auto r = n.call(kNoRole, "POST", "/v1/bundle", env(43, 6, b2));
  ASSERT_EQ(r.code(), 200) << r.raw;
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody).code(), 403);
  EXPECT_EQ(n.call(kViewer, "POST", "/v1/drop_principal", kDropBody).code(), 200);
  // An old table cannot come back over the floor (sec_generation 5 < 6): bindings stay.
  EXPECT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(44, 5)).code(), 409);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody).code(), 403);
  // The change is audited (counts, no secrets).
  auto ls = n.lines();
  auto bc = with(ls, "\"action\":\"bindings.change\"");
  ASSERT_EQ(bc.size(), 2u);  // first bundle (4 added) and the second (1 removed, 1 changed)
  EXPECT_EQ(json_num(bc[0], "rbac_added"), 4);
  EXPECT_EQ(json_num(bc[1], "rbac_removed"), 2);  // client-3 and client-4
  EXPECT_EQ(json_num(bc[1], "rbac_changed"), 1);  // client-1: viewer -> security-admin
}

// ---- audit ----------------------------------------------------------------------------------------

TEST(RbacAudit, EntriesVerifyCarryTheSourceAndShowInIdentity) {
  Node n(true);
  auto id0 = n.call(kViewer, "GET", "/v1/identity");
  ASSERT_EQ(id0.code(), 200);
  EXPECT_EQ(json_num(id0.body(), "audit_seq"), 0);
  EXPECT_EQ(json_str(id0.body(), "audit_head"), std::string(64, '0'));

  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(42, 5)).code(), 200);  // applied
  auto lower = n.call(kNoRole, "POST", "/v1/bundle", env(41, 5));            // rejected: generation below the floor
  ASSERT_EQ(lower.code(), 409) << lower.raw;
  EXPECT_EQ(n.call(kViewer, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}").code(), 403);  // refusal
  EXPECT_EQ(n.call(kNoSan, "POST", "/v1/drain").code(), 403);                                                    // no SAN
  EXPECT_EQ(n.call(kViewer, "POST", "/v1/drain").code(), 403);                                                   // role
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody).code(), 200);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"nobody\",\"drop_before\":\"2023-11-01T00:00:00Z\"}").code(), 404);
  EXPECT_EQ(n.call(kOperator, "POST", "/v1/drain", "{\"drain_ms\":2000}").code(), 200);

  const auto ls = n.lines();  // flushes the open windows
  ASSERT_FALSE(ls.empty());
  // The chain verifies, from the files on disk.
  const auto paths = control::list_audit_files(n.audit_dir);
  const auto v = control::audit_verify_paths(paths);
  ASSERT_TRUE(v.ok) << v.text();
  EXPECT_EQ(v.entries, ls.size());

  // Every entry carries node ID + hostname + IP (goal 10).
  const std::string src = "\"src\":{\"node_id\":" + std::to_string(n.server->node_id()) + ",\"host\":\"hostA\",\"addr\":\"10.0.0.10:7471\"}";
  for (const auto& l : ls) EXPECT_NE(l.find(src), std::string::npos) << l;

  // Bundle apply (generation, actor, role).
  auto ap = with(with(ls, "\"action\":\"bundle.push\""), "\"result\":\"ok\"");
  ASSERT_EQ(ap.size(), 1u);
  EXPECT_NE(ap[0].find("\"actor\":\"spiffe://lab/client-5\""), std::string::npos);
  EXPECT_NE(ap[0].find("\"role\":\"none\""), std::string::npos);
  EXPECT_EQ(json_num(ap[0], "generation"), 42);
  EXPECT_EQ(json_num(ap[0], "sec_generation"), 5);
  EXPECT_EQ(json_str(ap[0], "reason"), "applied");
  // Rejected push (reason from the reply).
  auto rj = with(with(ls, "\"action\":\"bundle.push\""), "\"result\":\"denied\"");
  ASSERT_EQ(rj.size(), 1u);
  EXPECT_EQ(json_num(rj[0], "generation"), 41);
  EXPECT_EQ(json_str(rj[0], "reason"), json_str(lower.body(), "reason"));
  EXPECT_FALSE(json_str(rj[0], "reason").empty());
  // Ticket refusal.
  auto tr = with(ls, "\"action\":\"tickets.issue\"");
  ASSERT_EQ(tr.size(), 1u);
  EXPECT_NE(tr[0].find("\"actor\":\"spiffe://lab/client-1\""), std::string::npos);
  EXPECT_NE(tr[0].find("\"result\":\"denied\""), std::string::npos);
  EXPECT_EQ(json_str(tr[0], "reason"), "identity not allowed");
  // Denied drains: one without a SAN, one for a role.
  auto dn = with(with(ls, "\"action\":\"drain\""), "\"result\":\"denied\"");
  ASSERT_EQ(dn.size(), 2u);
  // Drain and drop_principal.
  auto dr = with(with(ls, "\"action\":\"drain\""), "\"result\":\"ok\"");
  ASSERT_EQ(dr.size(), 1u);
  EXPECT_NE(dr[0].find("\"role\":\"operator\""), std::string::npos);
  EXPECT_EQ(json_str(dr[0], "reason"), "draining");
  auto dp = with(ls, "\"action\":\"drop_principal\"");
  ASSERT_EQ(dp.size(), 2u);
  EXPECT_NE(dp[0].find("\"target\":\"prod-llama\""), std::string::npos);
  EXPECT_NE(dp[0].find("\"result\":\"ok\""), std::string::npos);
  EXPECT_NE(dp[1].find("\"result\":\"error\""), std::string::npos);
  // Never in an entry: ticket ids, keys, payload.
  for (const auto& l : ls) {
    EXPECT_EQ(l.find("BEGIN"), std::string::npos);
    EXPECT_EQ(l.find("rkey"), std::string::npos);
  }

  // GET /v1/identity shows the anchor; the verifier accepts it, and detects a tail that is shorter.
  auto id = n.call(kViewer, "GET", "/v1/identity");
  ASSERT_EQ(id.code(), 200);
  EXPECT_EQ(static_cast<std::uint64_t>(json_num(id.body(), "audit_seq")), v.last_seq);
  EXPECT_EQ(json_str(id.body(), "audit_head"), v.head);
  const control::AuditAnchor anchor{v.last_seq, v.head};
  EXPECT_TRUE(control::audit_verify_paths(paths, &anchor).ok);
  const control::AuditAnchor ahead{v.last_seq + 1, v.head};
  EXPECT_FALSE(control::audit_verify_paths(paths, &ahead).ok);
}

TEST(RbacAudit, ADenialFloodIsCoalescedToAboutOneEntryPerSecond) {
  Node n(true);
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(42, 5)).code(), 200);
  const auto base = n.audit->seq();
  // Second S: 20 role denials from one identity, plus a 429 flood (client-5 holds 4 tickets, the cap).
  for (int i = 0; i < 20; ++i) ASSERT_EQ(n.call(kViewer, "POST", "/v1/drain").code(), 403);
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":4}").code(), 200);
  for (int i = 0; i < 15; ++i) ASSERT_EQ(n.call(kNoRole, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}").code(), 429);
  EXPECT_EQ(n.audit->seq(), base);  // nothing is written while the second is still open
  // Second S+1: 20 more denials.
  n.fake_ms += 1200;
  for (int i = 0; i < 20; ++i) ASSERT_EQ(n.call(kViewer, "POST", "/v1/drain").code(), 403);
  n.fake_ms += 1500;
  n.audit->tick();
  const auto ls = n.lines();
  auto dn = with(with(ls, "\"action\":\"drain\""), "\"result\":\"denied\"");
  ASSERT_EQ(dn.size(), 2u);  // one per second, not one per request
  EXPECT_EQ(json_num(dn[0], "count"), 20);
  EXPECT_EQ(json_num(dn[1], "count"), 20);
  EXPECT_NE(dn[0].find("role operator required"), std::string::npos);
  auto tk = with(ls, "\"action\":\"tickets.issue\"");
  ASSERT_EQ(tk.size(), 1u);
  EXPECT_EQ(json_num(tk[0], "count"), 15);
  EXPECT_EQ(json_str(tk[0], "reason"), "ticket limit reached");
  EXPECT_EQ(total_count(dn), 40);
  EXPECT_TRUE(control::audit_verify_paths(control::list_audit_files(n.audit_dir)).ok);
}

TEST(RbacAudit, CoalescerKeepsAnUnflushedWindowWhenTheSecondChanges) {
  control::AuditCoalescer co;
  control::AuditEntry e;
  e.actor = "spiffe://x/a";
  e.action = "drain";
  e.result = "denied";
  for (int i = 0; i < 7; ++i) co.add(e, kT0 + 100);   // second S
  for (int i = 0; i < 5; ++i) co.add(e, kT0 + 1100);  // second S+1, S was never flushed
  for (int i = 0; i < 3; ++i) co.add(e, kT0 + 2100);  // S+2
  auto out = co.flush(kT0 + 2200);                    // S and S+1 are closed
  ASSERT_EQ(out.size(), 2u);
  EXPECT_EQ(out[0].count + out[1].count, 12u);        // nothing lost
  auto rest = co.flush(kT0 + 2200, true);
  ASSERT_EQ(rest.size(), 1u);
  EXPECT_EQ(rest[0].count, 3u);
}

TEST(RbacAudit, OpenFailureRefusesOnlyTheAuditedMutationsAndTheRestKeepsServing) {
  Node n(true, Node::Audit::Broken);
  ASSERT_FALSE(n.audit_open_ok);
  ASSERT_TRUE(n.admin);
  // Tickets, identity and bundle keep working over HTTP (the signature gates bundles).
  EXPECT_EQ(n.call(kViewer, "GET", "/v1/identity").code(), 200);
  EXPECT_EQ(json_num(n.call(kViewer, "GET", "/v1/identity").body(), "audit_seq"), 0);
  EXPECT_EQ(n.call(kViewer, "GET", "/v1/bundle").code(), 404);  // nothing applied yet, but not refused
  auto bad = n.call(kNoSan, "GET", "/v1/identity");
  EXPECT_EQ(bad.code(), 403);  // still authenticated mTLS
  EXPECT_EQ(n.call(kViewer, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}").code(), 403);  // not a principal
  auto p = n.call(kNoRole, "POST", "/v1/bundle", env(42, 5));
  ASSERT_EQ(p.code(), 200) << p.raw;
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
  EXPECT_EQ(n.call(kNoRole, "GET", "/v1/bundle").code(), 200);
  EXPECT_EQ(n.call(kNoRole, "POST", "/v1/tickets", "{\"class\":\"fetch\",\"rail\":0,\"count\":1}").code(), 200);  // a principal
  // The audited operator / security-admin mutations are refused, whatever the role, and do nothing.
  for (const char* who : {kViewer, kOperator, kSecAdmin, kNoRole}) {
    EXPECT_EQ(n.call(who, "POST", "/v1/drain").code(), 503) << who;
    EXPECT_EQ(n.call(who, "POST", "/v1/drop_principal", kDropBody).code(), 503) << who;
  }
  EXPECT_FALSE(n.server->draining());
  // The bundle apply was counted as logged to stderr only.
  std::string m;
  n.server->metrics().write_prometheus(m);
  EXPECT_NE(m.find("miracache_audit_unlogged_total"), std::string::npos);
  // The data plane is untouched.
  EXPECT_TRUE(n.server->issue_ticket("spiffe://prod/vllm-host-1", fabric::EpClass::Control, 0, 1));
}

TEST(RbacAudit, ALateApplyAfter504IsStillAudited) {
  Node n(true);
  const auto port = n.admin->port();
  // The store thread does not pump: the push waits kStoreWaitMs and answers 504 apply_timeout.
  auto late = std::async(std::launch::async, [&] { return tls_call(port, kNoRole, http_req("POST", "/v1/bundle", env(42, 5))); });
  EXPECT_EQ(late.get().code(), 504);
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  EXPECT_TRUE(with(with(n.lines(), "\"action\":\"bundle.push\""), "\"result\":\"ok\"").empty());  // only the 504 error entry
  n.admin->pump(*n.server);  // the task still runs, now
  EXPECT_EQ(n.server->applied_bundle().generation, 42u);
  const auto ls = n.lines();
  auto ap = with(with(ls, "\"action\":\"bundle.push\""), "\"result\":\"ok\"");
  ASSERT_EQ(ap.size(), 1u);
  EXPECT_EQ(json_num(ap[0], "generation"), 42);
  EXPECT_NE(ap[0].find("\"actor\":\"spiffe://lab/client-5\""), std::string::npos);
  EXPECT_EQ(with(ls, "\"action\":\"bindings.change\"").size(), 1u);
}

TEST(RbacAudit, ABindingRevokedWhileTheBodyIsReadIsDenied) {
  Node n(true);
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(42, 5)).code(), 200);  // client-2 is operator
  const auto port = n.admin->port();
  std::promise<void> head_sent, go;
  auto go_f = go.get_future().share();
  auto fut = std::async(std::launch::async, [&] {
    return tls_call(port, kOperator, http_req("POST", "/v1/drain", "{}"), [&] {
      head_sent.set_value();
      go_f.wait();
    });
  });
  head_sent.get_future().wait();
  // While the drain body is "in flight" a new bundle drops client-2's binding.
  const std::vector<std::pair<std::string, std::string>> b2 = {{"spiffe://lab/client-3", "security-admin"}};
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(43, 6, b2)).code(), 200);
  go.set_value();
  while (fut.wait_for(2ms) != std::future_status::ready) n.admin->pump(*n.server);
  auto r = fut.get();
  EXPECT_EQ(r.code(), 403) << r.raw;
  EXPECT_FALSE(n.server->draining());
}

TEST(RbacAudit, AnchorShowsTheLastFsyncedEntry) {
  const std::string d = make_dir();
  std::atomic<bool> fsync_ok{false};
  AdminAuditOptions ao;
  ao.dir = d + "/audit";
  ao.node_id = 7;
  ao.host = "h";
  ao.addr = "10.0.0.1:1";
  ao.now_ms = [] { return kT0; };
  ao.fsync_fn = [&](int fd) { return fsync_ok.load() ? ::fsync(fd) : -1; };
  auto a = AdminAudit::open(std::move(ao));
  ASSERT_TRUE(a);
  control::AuditEntry e;
  e.actor = "local";
  e.role = "none";
  e.action = "x";
  e.result = "ok";
  ASSERT_TRUE((*a)->record(e));
  EXPECT_EQ((*a)->seq(), 1u);
  EXPECT_EQ((*a)->anchor().first, 0u);  // written but not durable: not an anchor
  EXPECT_EQ((*a)->anchor().second, std::string(64, '0'));
  fsync_ok = true;
  const auto an = (*a)->anchor();
  EXPECT_EQ(an.first, 1u);
  EXPECT_EQ(an.second, (*a)->head());
  (void)std::system(("rm -rf " + d).c_str());
}

TEST(RbacAudit, AFailedAppendIsToldToTheCaller) {
  Node n(true);
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(42, 5)).code(), 200);
  n.fail_audit_writes = true;
  auto r = n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody);
  ASSERT_EQ(r.code(), 200) << r.raw;
  EXPECT_NE(r.body().find("\"audit_error\":true"), std::string::npos);
  auto d = n.call(kOperator, "POST", "/v1/drain");
  ASSERT_EQ(d.code(), 200);
  EXPECT_NE(d.body().find("\"audit_error\":true"), std::string::npos);
  std::string m;
  n.server->metrics().write_prometheus(m);
  EXPECT_NE(m.find("miracache_audit_errors_total"), std::string::npos);
  n.fail_audit_writes = false;
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody).body().find("audit_error"), std::string::npos);
}

// ---- drop_principal under traffic -----------------------------------------------------------------

struct Fx {
  Fx() : rng(3), net(clock, rng, {}, {}), fab(net.add_node(1)) {
    ServerConfig sc;
    sc.store = store_cfg();
    sc.lab_identity = "spiffe://lab/old";
    sc.wall_unix_ns = [this] { return static_cast<std::int64_t>(kT0) * 1'000'000 + clock.now().count(); };
    auto s = Server::create(sc, fab, clock, rng, exec);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
  }
  void turn() {
    clock.advance_by(5ms);
    server->run_once();
  }
  void settle() {
    for (int i = 0; i < 200 && server->store().sweep_pending(); ++i) turn();
  }
  store::ScopeId sc(int i) {
    store::ScopeId s{};
    s[0] = static_cast<std::uint8_t>(i);
    return s;
  }
  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& fab;
  InlineExecutor exec;
  std::unique_ptr<Server> server;
};

TEST(RbacDrop, DropsOnePrincipalOnlyAndLaterScopesLive) {
  Fx f;
  control::BundleView v;
  v.body.generation = 1;
  v.body.epoch = 1;
  v.sec.sec_generation = 1;
  for (const char* name : {"prod", "other"}) {
    control::PrincipalView p;
    p.name = name;
    p.id = control::principal_id(name);
    p.identities = {std::string("spiffe://x/") + name};
    p.quota_bytes = 1 << 20;
    p.max_scopes = 100;
    v.sec.principals.push_back(p);
  }
  f.server->apply_bundle(v);
  const auto prod = control::principal_id("prod"), other = control::principal_id("other");
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(prod, f.sc(1), f.clock.now()));
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(other, f.sc(1), f.clock.now()));
  f.clock.advance_by(100s);
  const std::int64_t now_s = static_cast<std::int64_t>(kT0 / 1000) + 100;
  EXPECT_FALSE(f.server->drop_principal_local("nobody", now_s));  // not in the applied bundle
  ASSERT_TRUE(f.server->drop_principal_local("prod", now_s - 50));
  f.settle();
  EXPECT_FALSE(f.server->store().has_scope(prod, f.sc(1)));  // opened before the cutoff: gone
  EXPECT_TRUE(f.server->store().has_scope(other, f.sc(1)));  // another principal: untouched
  // Traffic after the drop: a new scope opens and lives, a lower drop_before changes nothing (monotonic).
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(prod, f.sc(2), f.clock.now()));
  ASSERT_TRUE(f.server->drop_principal_local("prod", now_s - 90));
  f.settle();
  EXPECT_TRUE(f.server->store().has_scope(prod, f.sc(2)));
  EXPECT_TRUE(f.server->store().has_scope(other, f.sc(1)));
}

TEST(RbacDrop, TheRaiseIsDurableAndSurvivesARestart) {
  Node n(true);
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(42, 5)).code(), 200);
  // kT0 = 2023-11-14T22:13:20Z; +50 s = 22:14:10Z.
  const std::string body = "{\"name\":\"prod-llama\",\"drop_before\":\"2023-11-14T22:14:10Z\"}";
  auto r = n.call(kSecAdmin, "POST", "/v1/drop_principal", body);
  ASSERT_EQ(r.code(), 200) << r.raw;
  // Durable before the 200: the floor file already holds it, with the bundle's floor fields intact.
  auto fs = control::FloorState::open(n.state_dir);
  ASSERT_TRUE(fs);
  auto fl = fs->load();
  ASSERT_TRUE(fl);
  ASSERT_EQ(fl->drop_before.count("prod-llama"), 1u);
  const std::int64_t cutoff = static_cast<std::int64_t>(kT0 / 1000) + 50;
  EXPECT_EQ(fl->drop_before["prod-llama"], cutoff);
  EXPECT_EQ(fl->generation, 42u);
  // Max-only: a lower value changes nothing; a unknown principal persists nothing.
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"prod-llama\",\"drop_before\":\"2023-11-14T22:13:30Z\"}").code(), 200);
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"nobody\",\"drop_before\":\"2023-11-14T22:14:10Z\"}").code(), 404);
  fl = fs->load();
  ASSERT_TRUE(fl);
  EXPECT_EQ(fl->drop_before["prod-llama"], cutoff);
  EXPECT_EQ(fl->drop_before.count("nobody"), 0u);
  // The audit entry is the same as before.
  auto dp = with(n.lines(), "\"action\":\"drop_principal\"");
  ASSERT_GE(dp.size(), 1u);
  EXPECT_NE(dp[0].find("\"result\":\"ok\""), std::string::npos);
  EXPECT_EQ(json_str(dp[0], "reason"), "dropped");

  // "Restart": a fresh Server on the same state_dir, a warm scope from before the cutoff, then the floor is loaded
  // by the helper main calls.
  Fx f;
  const auto pid = control::principal_id("prod-llama");
  control::BundleView v;
  v.body.generation = 1;
  v.body.epoch = 1;
  v.sec.sec_generation = 1;
  control::PrincipalView p;
  p.name = "prod-llama";
  p.id = pid;
  p.identities = {"spiffe://prod/vllm-host-1"};
  p.quota_bytes = 1 << 20;
  p.max_scopes = 100;
  v.sec.principals.push_back(p);
  f.server->apply_bundle(v);  // no drop_before in the bundle
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));  // opened before the cutoff
  f.clock.advance_by(100s);
  ASSERT_TRUE(load_persisted_drop_before(*f.server, n.state_dir));  // main's start-up helper
  f.settle();
  EXPECT_FALSE(f.server->store().has_scope(pid, f.sc(1)));  // still misses after the restart
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(2), f.clock.now()));
  f.settle();
  EXPECT_TRUE(f.server->store().has_scope(pid, f.sc(2)));  // opened after the cutoff: lives
}

TEST(RbacDrop, AFutureDropBeforeIsRefusedAndALaterRealDropWorks) {
  Node n(true);
  // A bundle with a drop_before ahead of the wall clock + 300 s is refused (schema), nothing applied or persisted.
  auto fut = n.call(kNoRole, "POST", "/v1/bundle", tu::make_envelope(tu::sec_toml(5, "2099-01-01T00:00:00Z"), tu::body_toml(42, 7, 6)));
  EXPECT_EQ(fut.code(), 400) << fut.raw;
  EXPECT_EQ(json_str(fut.body(), "reason"), "schema");
  EXPECT_EQ(n.server->applied_bundle().generation, 0u);
  // ... a past one is fine.
  ASSERT_EQ(n.call(kNoRole, "POST", "/v1/bundle", env(42, 5)).code(), 200);
  // The route refuses it too, with 400; the max-only floor stays untouched.
  auto bad = n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"prod-llama\",\"drop_before\":\"2099-01-01T00:00:00Z\"}");
  EXPECT_EQ(bad.code(), 400) << bad.raw;
  auto fl = control::FloorState::open(n.state_dir)->load();
  ASSERT_TRUE(fl);
  EXPECT_EQ(fl->drop_before.count("prod-llama"), 0u);
  // now + 301 s is over the skew, now + 300 s is not.
  const std::int64_t now_s = static_cast<std::int64_t>(kT0 / 1000);  // 2023-11-14T22:13:20Z
  EXPECT_EQ(n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"prod-llama\",\"drop_before\":\"2023-11-14T22:18:21Z\"}").code(), 400);
  (void)now_s;
  // A later REAL cutoff works and drops what it should (the future one did not poison the maximum).
  const auto pid = control::principal_id("prod-llama");
  ASSERT_TRUE(n.server->store().ensure_scope_for_root_put(pid, store::ScopeId{{1}}, n.clock.now()));
  n.clock.advance_by(100s);
  ASSERT_TRUE(n.server->store().ensure_scope_for_root_put(pid, store::ScopeId{{2}}, n.clock.now()));
  auto ok = n.call(kSecAdmin, "POST", "/v1/drop_principal", "{\"name\":\"prod-llama\",\"drop_before\":\"2023-11-14T22:14:10Z\"}");
  ASSERT_EQ(ok.code(), 200) << ok.raw;
  for (int i = 0; i < 200 && n.server->store().sweep_pending(); ++i) {
    n.clock.advance_by(5ms);
    n.server->run_once();
  }
  EXPECT_FALSE(n.server->store().has_scope(pid, store::ScopeId{{1}}));
  EXPECT_TRUE(n.server->store().has_scope(pid, store::ScopeId{{2}}));
}

TEST(RbacDrop, TheReplySaysWhenNothingWasPersisted) {
  Node n(false, Node::Audit::Off, {{"spiffe://lab/client-3", {"security-admin"}}});
  n.persist = false;
  n.start();
  auto r = n.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody);
  ASSERT_EQ(r.code(), 200) << r.raw;
  EXPECT_NE(r.body().find("\"persisted\":false"), std::string::npos);
  Node m(false, Node::Audit::Off, {{"spiffe://lab/client-3", {"security-admin"}}});
  auto r2 = m.call(kSecAdmin, "POST", "/v1/drop_principal", kDropBody);
  ASSERT_EQ(r2.code(), 200) << r2.raw;
  EXPECT_NE(r2.body().find("\"persisted\":true"), std::string::npos);
}

TEST(RbacDrop, StartUpFloorLoadHelper) {
  const std::string d = make_dir();
  Fx f;
  EXPECT_TRUE(load_persisted_drop_before(*f.server, ""));  // no state_dir: nothing to load
  EXPECT_TRUE(load_persisted_drop_before(*f.server, d));   // no floor file yet: nothing to load
  // A readable floor is applied.
  const auto pid = control::principal_id("prod");
  control::BundleView v;
  v.body.generation = 1;
  v.body.epoch = 1;
  v.sec.sec_generation = 1;
  control::PrincipalView p;
  p.name = "prod";
  p.id = pid;
  p.identities = {"spiffe://x/prod"};
  p.quota_bytes = 1 << 20;
  p.max_scopes = 100;
  v.sec.principals.push_back(p);
  f.server->apply_bundle(v);
  ASSERT_TRUE(f.server->store().ensure_scope_for_root_put(pid, f.sc(1), f.clock.now()));
  f.clock.advance_by(100s);
  ASSERT_TRUE(control::FloorState::open(d)->raise_drop_before("prod", static_cast<std::int64_t>(kT0 / 1000) + 50));
  ASSERT_TRUE(load_persisted_drop_before(*f.server, d));
  f.settle();
  EXPECT_FALSE(f.server->store().has_scope(pid, f.sc(1)));
  // A corrupt floor is an error (main refuses to start), never "no revocations".
  {
    std::ofstream bad(d + "/bundle-floor", std::ios::binary | std::ios::trunc);
    bad << "garbage\n";
  }
  auto st = load_persisted_drop_before(*f.server, d);
  EXPECT_FALSE(st);
  // So is an unreadable one (a directory in its place).
  ASSERT_EQ(::unlink((d + "/bundle-floor").c_str()), 0);
  ASSERT_EQ(::mkdir((d + "/bundle-floor").c_str(), 0700), 0);
  EXPECT_FALSE(load_persisted_drop_before(*f.server, d));
  (void)std::system(("rm -rf " + d).c_str());
}

TEST(RbacDrop, FloorRaiseIsMaxOnlyAndDoesNotBlockBundles) {
  const std::string d = make_dir();
  auto fs = control::FloorState::open(d);
  ASSERT_TRUE(fs);
  ASSERT_TRUE(fs->raise_drop_before("a", 100));
  ASSERT_TRUE(fs->raise_drop_before("a", 50));   // lower: nothing
  ASSERT_TRUE(fs->raise_drop_before("b", 7));
  auto fl = fs->load();
  ASSERT_TRUE(fl);
  EXPECT_EQ(fl->generation, 0u);  // still a blank floor for acceptance
  EXPECT_EQ(fl->drop_before["a"], 100);
  EXPECT_EQ(fl->drop_before["b"], 7);
  control::BundleView v;
  v.body.generation = 1;
  v.body.epoch = 1;
  v.sec.sec_generation = 1;
  control::PrincipalView p;
  p.name = "a";
  p.drop_before = 60;  // a bundle can only raise it
  v.sec.principals.push_back(p);
  ASSERT_TRUE(fs->commit(v));
  fl = fs->load();
  ASSERT_TRUE(fl);
  EXPECT_EQ(fl->generation, 1u);
  EXPECT_EQ(fl->drop_before["a"], 100);
  EXPECT_EQ(fl->drop_before["b"], 7);
  (void)std::system(("rm -rf " + d).c_str());
}

// ---- config ---------------------------------------------------------------------------------------

TEST(RbacConfig, AdminRbacAndAuditSections) {
  const std::string base = "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n";
  auto def = parse_node_config(base);
  ASSERT_TRUE(def);
  EXPECT_TRUE(def->admin_rbac.empty());
  EXPECT_TRUE(def->audit_dir.empty());
  EXPECT_EQ(def->audit_max_bytes, 64ull << 20);
  EXPECT_EQ(def->audit_max_total_bytes, 1ull << 30);
  auto ok = parse_node_config(base +
                              "[admin]\nlisten = \"0.0.0.0:9465\"\ncert = \"/c\"\nkey = \"/k\"\nca = \"/ca\"\n"
                              "[[admin.rbac]]\nidentity = \"spiffe://ops/alice\"\nroles = [\"operator\", \"viewer\"]\n"
                              "[[admin.rbac]]\nidentity = \"spiffe://ops/bob\"\nroles = [\"security-admin\"]\n"
                              "[audit]\ndir = \"/var/log/mira-audit\"\nmax_bytes = 1048576\nmax_total_bytes = 8388608\n");
  ASSERT_TRUE(ok) << ok.error().context;
  ASSERT_EQ(ok->admin_rbac.size(), 2u);
  EXPECT_EQ(ok->admin_rbac[0].first, "spiffe://ops/alice");
  EXPECT_EQ(ok->admin_rbac[0].second, (std::vector<std::string>{"operator", "viewer"}));
  EXPECT_EQ(ok->audit_dir, "/var/log/mira-audit");
  EXPECT_EQ(ok->audit_max_bytes, 1048576u);
  EXPECT_EQ(ok->audit_max_total_bytes, 8388608u);
  const std::string adm = base + "[admin]\nlisten = \"0.0.0.0:9465\"\ncert = \"/c\"\nkey = \"/k\"\nca = \"/ca\"\n";
  EXPECT_FALSE(parse_node_config(adm + "[[admin.rbac]]\nidentity = \"spiffe://a/b\"\nroles = [\"root\"]\n"));       // unknown role
  EXPECT_FALSE(parse_node_config(adm + "[[admin.rbac]]\nidentity = \"alice\"\nroles = [\"operator\"]\n"));          // not spiffe://
  EXPECT_FALSE(parse_node_config(adm + "[[admin.rbac]]\nidentity = \"spiffe://a/b\"\nroles = []\n"));               // no roles
  EXPECT_FALSE(parse_node_config(adm + "[[admin.rbac]]\nidentity = \"spiffe://a/b\"\nroles = [\"operator\"]\nx = 1\n"));
  EXPECT_FALSE(parse_node_config(adm + "[[admin.rbac]]\nidentity = \"spiffe://a/b\"\nroles = [\"operator\"]\n"
                                       "[[admin.rbac]]\nidentity = \"spiffe://a/b\"\nroles = [\"viewer\"]\n"));      // duplicate
  EXPECT_FALSE(parse_node_config(base + "[audit]\nbogus = 1\n"));
  EXPECT_FALSE(parse_node_config(base + "[audit]\nmax_bytes = 10\n"));
  EXPECT_FALSE(parse_node_config(base + "[audit]\nmax_bytes = 8192\nmax_total_bytes = 4096\n"));
}

}  // namespace
}  // namespace miracache::server
