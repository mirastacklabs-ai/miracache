// SPDX-License-Identifier: Apache-2.0
// Two processes (label `rdma`): the real mira-memnode binary with [admin] mTLS on and
// lab.identities set, and Client::open in this process with ONLY nodes[].admin (no ticket file).
// The client gets its tickets over mTLS, then stores and fetches over real verbs/rdma_cm.
// Certs come from deploy/examples/lab-certs.sh into a temp dir. Skips cleanly without an RDMA device.
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "fabric/verbs_cm/verbs_cm_fabric.h"
#include "free_port.h"
#include "src/client.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;

std::vector<std::string> devices() {
  const char* env = std::getenv("MIRACACHE_RDMA_DEVICES");
  std::stringstream ss(env != nullptr ? env : "rxe0,siw0");
  std::vector<std::string> out;
  for (std::string d; std::getline(ss, d, ',');)
    if (!d.empty()) out.push_back(d);
  return out;
}

class TestKeys final : public KeySource {
 public:
  Expected<Dek> dek_for(std::span<const std::byte> raw) const override {
    std::array<std::byte, 32> k;
    mix(raw, 0x11, k.data());
    return Dek(std::span<const std::byte, 32>(k));
  }
  Expected<KeyHash> key_hash(std::span<const std::byte> raw) const override {
    KeyHash h;
    std::array<std::byte, 32> k;
    mix(raw, 0x22, k.data());
    std::memcpy(h.b, k.data(), 32);
    return h;
  }

 private:
  static void mix(std::span<const std::byte> raw, int tag, std::byte* out) {
    for (int i = 0; i < 32; ++i) {
      std::uint64_t x = 1469598103934665603ull ^ static_cast<std::uint64_t>(7 * 131 + tag + i);
      for (auto b : raw) x = (x ^ static_cast<std::uint64_t>(b)) * 1099511628211ull;
      x ^= x >> 29;
      x *= 0x9E3779B97F4A7C15ull;
      out[i] = static_cast<std::byte>(x >> 56);
    }
  }
};

class NoProvider final : public ScopeProvider {
 public:
  Expected<ScopeKeys> derive(const RequestMeta&) const override { return Error{ErrorCode::Unsupported, "n/a"}; }
};


// GET http://127.0.0.1:port/path over a plain socket (the node's [telemetry] listener); "" on any failure.
std::string http_get(std::uint16_t port, const char* path) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return {};
  sockaddr_in a{};
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  ::inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
  std::string out;
  if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof a) == 0) {
    const std::string req = std::string("GET ") + path + " HTTP/1.0\r\nHost: x\r\n\r\n";
    if (::write(fd, req.data(), req.size()) == static_cast<ssize_t>(req.size())) {
      char b[4096];
      for (ssize_t n; (n = ::read(fd, b, sizeof b)) > 0;) out.append(b, static_cast<std::size_t>(n));
    }
  }
  ::close(fd);
  return out;
}

std::string slurp(const std::string& p) {
  std::ifstream f(p);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

Completion wait_for(Client& c, Ticket t) {
  std::array<Completion, 4> comp;
  for (int i = 0; i < 20000; ++i) {
    std::size_t n = c.poll(comp);
    for (std::size_t k = 0; k < n; ++k)
      if (comp[k].ticket == t) return std::move(comp[k]);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  ADD_FAILURE() << "no completion";
  return Completion{};
}

class AdminE2e : public ::testing::TestWithParam<std::string> {
 protected:
  void TearDown() override {
    if (pid_ > 0) {
      ::kill(pid_, SIGTERM);
      int st = 0;
      for (int i = 0; i < 100 && ::waitpid(pid_, &st, WNOHANG) == 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(50));
      if (::waitpid(pid_, &st, WNOHANG) == 0) {
        ::kill(pid_, SIGKILL);
        ::waitpid(pid_, &st, 0);
      }
    }
    if (!dir_.empty()) (void)std::system(("rm -rf " + dir_).c_str());
  }
  pid_t pid_ = -1;
  std::string dir_;
};

TEST_P(AdminE2e, ClientWithOnlyAdminPutsAndFetchesThroughTheRealMemnode) {
  const std::string dev = GetParam();
  std::string ip;
  {  // learn the device address (and skip when there is no device)
    fabric::VerbsOptions vo;
    vo.device = dev;
    auto f = fabric::VerbsCmFabric::open(vo);
    if (!f) GTEST_SKIP() << "no usable RDMA device: " << f.error().context;
    auto a = (*f)->device_ipv4();
    if (!a) GTEST_SKIP() << "device has no IPv4 address: " << a.error().context;
    ip = *a;
  }
  char t[] = "/tmp/mira-e2e-XXXXXX";
  ASSERT_NE(::mkdtemp(t), nullptr);
  dir_ = t;
  const std::string pki = dir_ + "/pki";
  ASSERT_EQ(std::system(("bash " + std::string(MIRACACHE_LAB_CERTS_SH) + " " + pki + " --nodes 1 --clients 1 >/dev/null").c_str()), 0);

  const std::uint16_t rdma_port = free_port(), admin_port = free_port(), tel_port = free_port();
  {
    std::ofstream f(dir_ + "/node.toml");
    f << "[node]\ndevice = \"" << dev << "\"\nlisten = [\"" << ip << ":" << rdma_port << "\"]\nstate_dir = \"" << dir_ << "/state\"\n"
      << "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\nn_segments = 4\n"
      << "max_scopes = 8\nmax_bytes = 8388608\n"
      << "[lab]\nprincipal = \"lab\"\nidentities = [\"spiffe://lab/client-1\"]\n"
      << "[admin]\nlisten = \"127.0.0.1:" << admin_port << "\"\ncert = \"" << pki << "/node-1.pem\"\nkey = \"" << pki
      << "/node-1.key\"\nca = \"" << pki << "/ca.pem\"\n"
      << "[telemetry]\nlisten = \"127.0.0.1:" << tel_port << "\"\n";
  }
  const std::string log = dir_ + "/memnode.log";
  pid_ = ::fork();
  ASSERT_GE(pid_, 0);
  if (pid_ == 0) {
    FILE* lf = std::freopen(log.c_str(), "w", stderr);
    (void)lf;
    ::execl(MIRA_MEMNODE_BIN, MIRA_MEMNODE_BIN, "--config", (dir_ + "/node.toml").c_str(), static_cast<char*>(nullptr));
    ::_exit(127);
  }
  bool up = false;
  for (int i = 0; i < 200 && !up; ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    const std::string l = slurp(log);
    up = l.find("listening") != std::string::npos;
    int st = 0;
    ASSERT_EQ(::waitpid(pid_, &st, WNOHANG), 0) << "mira-memnode exited early:\n" << l;
  }
  ASSERT_TRUE(up) << slurp(log);

  std::ostringstream toml;
  toml << "[scope]\nsecret_file = \"unused\"\n[[nodes]]\nrails = [\"" << ip << ":" << rdma_port << "\"]\n"
       << "admin = \"127.0.0.1:" << admin_port << "\"\nidentity = \"spiffe://lab/node-1\"\n"
       << "[tls]\ncert = \"" << pki << "/client-1.pem\"\nkey = \"" << pki << "/client-1.key\"\nca = \"" << pki << "/ca.pem\"\n"
       << "[fabric]\ndevice = \"" << dev << "\"\n[lab]\nstatic_membership = true\n";  // no ticket_file
  auto cfg = load_config(toml.str());
  ASSERT_TRUE(cfg) << cfg.error().context;
  EXPECT_TRUE(cfg->ticket_file.empty());
  NoProvider prov;
  auto cl = Client::open(*cfg, prov);
  ASSERT_TRUE(cl) << cl.error().context << "\n" << slurp(log);
  Client& c = **cl;

  ScopeKeys sk;
  ScopeId s{};
  s.b[0] = 1;
  s.b[31] = 0x5c;
  sk.scopes = {s};
  sk.keys = std::make_shared<TestKeys>();
  sk.kver = 1;
  const char* names[] = {"k0", "k1"};
  std::vector<Bytes> raw, data, out;
  std::vector<KeyRef> refs;
  const std::size_t sizes[] = {1000, 3 * 65536 + 5};
  for (int i = 0; i < 2; ++i) {
    raw.emplace_back(reinterpret_cast<const std::byte*>(names[i]), reinterpret_cast<const std::byte*>(names[i]) + 2);
    Bytes d(sizes[i]);
    for (std::size_t j = 0; j < d.size(); ++j) d[j] = static_cast<std::byte>((j * 31 + static_cast<std::size_t>(i) * 7 + 3) & 0xff);
    data.push_back(std::move(d));
    out.emplace_back(sizes[i], std::byte{0xAA});
  }
  for (int i = 0; i < 2; ++i) {
    KeyRef r;
    r.raw = raw[static_cast<std::size_t>(i)];
    if (i > 0) r.parent_raw = raw[static_cast<std::size_t>(i) - 1];
    r.chain_pos = static_cast<std::uint64_t>(i);
    refs.push_back(r);
  }
  std::vector<BufRef> pbufs, fbufs;
  for (auto& d : data) pbufs.push_back({std::span<std::byte>(d)});
  for (auto& o : out) fbufs.push_back({std::span<std::byte>(o)});
  auto sc = wait_for(c, c.store(sk, 0, refs, pbufs, std::chrono::seconds(10)));
  ASSERT_EQ(sc.status.size(), 2u);
  for (auto st : sc.status) EXPECT_EQ(st, KeyStatus::Committed);
  auto fc = wait_for(c, c.fetch(sk, 0, refs, fbufs, std::chrono::seconds(10)));
  ASSERT_EQ(fc.status.size(), 2u);
  for (std::size_t i = 0; i < 2; ++i) {
    EXPECT_EQ(fc.status[i], KeyStatus::Hit) << i;
    EXPECT_EQ(out[i], data[i]) << i;
  }
  const std::string metrics = c.metrics_text();
  EXPECT_NE(metrics.find("miracache_client_ticket_fetch_total{result=\"ok\"} 1"), std::string::npos) << metrics;
  // B11: the QP attribute readback gauges carry the node identity on both sides.
  const std::string node_m = http_get(tel_port, "/metrics");
  std::cerr << "NODE /metrics (miracache_qp_*):\n";
  for (const std::string& m : {node_m, metrics}) {
    std::istringstream is(m);
    for (std::string ln; std::getline(is, ln);)
      if (ln.rfind("miracache_qp_", 0) == 0) std::cerr << ln << "\n";
    std::cerr << "---- (client metrics follow / end)\n";
  }
  EXPECT_NE(node_m.find("miracache_qp_retry_count{node_id=\""), std::string::npos) << node_m;
  EXPECT_NE(node_m.find("role=\"passive\""), std::string::npos);
  EXPECT_NE(node_m.find("hostname=\""), std::string::npos);
  EXPECT_NE(metrics.find("miracache_qp_retry_count{"), std::string::npos);
  EXPECT_NE(metrics.find("role=\"active\""), std::string::npos);
  EXPECT_NE(metrics.find("node_id=\""), std::string::npos);
  {  // F3 (K08): the client's qp series carry the real node ID (never "unknown") and no unknown series is left exposed.
    std::istringstream is(metrics);
    int n = 0;
    for (std::string ln; std::getline(is, ln);)
      if (ln.rfind("miracache_qp_", 0) == 0) {
        ++n;
        EXPECT_EQ(ln.find("node_id=\"unknown\""), std::string::npos) << ln;
      }
    EXPECT_GT(n, 0);
  }
  c.shutdown();
}

INSTANTIATE_TEST_SUITE_P(Device, AdminE2e, ::testing::ValuesIn(devices()),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

}  // namespace
}  // namespace miracache
