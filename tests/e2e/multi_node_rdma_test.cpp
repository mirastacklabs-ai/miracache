// SPDX-License-Identifier: Apache-2.0
// Three mira-memnode processes (label `rdma`, one container, different ports) and one Client::open
// with three [[nodes]] (weights 1, 1, 2): static weighted-rendezvous placement end to end over real
// verbs/rdma_cm. Checks that every node holds exactly the scopes it owns (from its /metrics), that a
// killed node fails only its own scopes (and nothing hangs), and that a restarted node comes back.
// Certs from deploy/examples/lab-certs.sh. Skips cleanly without an RDMA device.
#include <arpa/inet.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "fabric/verbs_cm/verbs_cm_fabric.h"
#include "free_port.h"
#include "learned_ids.h"
#include "src/client.h"
#include "src/placement.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;
using std::chrono::milliseconds;
using std::chrono::seconds;

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


std::string slurp(const std::string& p) {
  std::ifstream f(p);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// GET /metrics from 127.0.0.1:port (plain HTTP); empty on failure.
std::string http_metrics(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_port = htons(port);
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) != 0) {
    ::close(fd);
    return {};
  }
  const char req[] = "GET /metrics HTTP/1.0\r\n\r\n";
  (void)!::write(fd, req, sizeof req - 1);
  std::string out;
  char buf[4096];
  for (ssize_t n; (n = ::read(fd, buf, sizeof buf)) > 0;) out.append(buf, static_cast<std::size_t>(n));
  ::close(fd);
  return out;
}

// Value of the sample line that starts with `series` (name and labels), or -1.
long metric(const std::string& raw, const std::string& series) {
  // Every memnode series carries the const label node_id="N" (plan 2B); name series by their own labels.
  static const std::regex lone("\\{node_id=\"[0-9]+\"\\}"), first("\\{node_id=\"[0-9]+\",");
  const std::string text = std::regex_replace(std::regex_replace(raw, lone, ""), first, "{");
  std::size_t p = 0;
  while ((p = text.find(series, p)) != std::string::npos) {
    if (p == 0 || text[p - 1] == '\n') {
      const std::size_t eol = text.find('\n', p);
      const std::string line = text.substr(p, eol - p);
      return std::strtol(line.c_str() + line.rfind(' ') + 1, nullptr, 10);
    }
    p += series.size();
  }
  return -1;
}

Completion wait_for(Client& c, Ticket t, seconds cap = seconds(30)) {
  std::array<Completion, 4> comp;
  const auto until = std::chrono::steady_clock::now() + cap;
  while (std::chrono::steady_clock::now() < until) {
    std::size_t n = c.poll(comp);
    for (std::size_t k = 0; k < n; ++k)
      if (comp[k].ticket == t) return std::move(comp[k]);
    std::this_thread::sleep_for(milliseconds(1));
  }
  ADD_FAILURE() << "no completion (hang)";
  return Completion{};
}

// R15 (review s11): open() retries a failed first build only inside its 2 s settle, so on a loaded tsan lane two slow
// admin handshakes in a row can leave a node pending at return with nothing wrong (its keepalive thread connects it
// shortly after). The open contract itself is tested strictly and deterministically in sim (WireOpen.*: every node up
// at return after one transient failure; the settle a bound). Here: wait up to `cap` for `want` nodes, with a WARN
// when open() returned with fewer, so a slow lane shows in the log instead of failing the test.
// B-2 (review s11): ctest hides a passing test's stderr, so every call also appends one line to $MIRA_R15_LOG when set
// (set per device by the RDMA test driver):  "R15 <test> late=<0|1> at_open=<n> want=<w> wait_ms=<ms> final=<n>".
// rdma_test.sh prints "R15 <dev>: late opens k/N, max wait X ms" and FAILS the device when (a) the max wait_ms is
// >= 5000 (half the default cap), or (b) more than half of the pass's opens were late (k > N/2, N >= 3): regressions
// where nodes connect slowly or routinely late (s11c review P2-2; nightly baseline 0/7 late, max 0 ms on rxe0 and siw0).
// One or two short late opens on a loaded tsan/siw lane stay green (the R15 case); no records at all fails (the
// accounting broke); a node still pending after `cap` fails the ASSERT at the call site, as before.
void r15_record(const char* late, std::size_t at_open, std::size_t want, long long wait_ms, std::size_t final_n) {
  const char* path = std::getenv("MIRA_R15_LOG");
  if (path == nullptr || *path == '\0') return;
  const ::testing::TestInfo* ti = ::testing::UnitTest::GetInstance()->current_test_info();
  std::string name = ti != nullptr ? std::string(ti->test_suite_name()) + "." + ti->name() : "unknown";
  for (char& ch : name)
    if (ch == ' ') ch = '_';
  if (FILE* f = std::fopen(path, "a")) {
    std::fprintf(f, "R15 %s late=%s at_open=%zu want=%zu wait_ms=%lld final=%zu\n", name.c_str(), late, at_open, want,
                 wait_ms, final_n);
    std::fclose(f);
  }
}

std::size_t nodes_connected_within(Client& c, std::size_t want, seconds cap = seconds(10)) {
  std::size_t n = c.nodes_connected();
  if (n >= want) {
    r15_record("0", n, want, 0, n);
    return n;
  }
  const std::size_t at_open = n;
  std::fprintf(stderr, "WARN R15: open() returned with %zu of %zu memory nodes connected; waiting up to %lld s\n", n,
               want, static_cast<long long>(cap.count()));
  const auto t0 = std::chrono::steady_clock::now();
  const auto until = t0 + cap;
  while ((n = c.nodes_connected()) < want && std::chrono::steady_clock::now() < until)
    std::this_thread::sleep_for(milliseconds(10));
  const long long waited = std::chrono::duration_cast<milliseconds>(std::chrono::steady_clock::now() - t0).count();
  std::fprintf(stderr, "WARN R15: %zu of %zu memory nodes connected after %lld ms\n", n, want, waited);
  r15_record("1", at_open, want, waited, n);
  return n;
}

constexpr int kNodes = 3;
constexpr int kScopes = 300;
constexpr std::size_t kLen = 2000;
const std::uint32_t kWeight[kNodes] = {1, 1, 2};

class MultiNodeE2e : public ::testing::TestWithParam<std::string> {
 protected:
  void TearDown() override {
    for (int i = 0; i < kNodes; ++i) stop(i, SIGTERM);
    if (!dir_.empty()) (void)std::system(("rm -rf " + dir_).c_str());
  }
  void stop(int i, int sig) {
    if (pid_[i] <= 0) return;
    ::kill(pid_[i], sig);
    int st = 0;
    for (int k = 0; k < 100 && ::waitpid(pid_[i], &st, WNOHANG) == 0; ++k) std::this_thread::sleep_for(milliseconds(50));
    if (::waitpid(pid_[i], &st, WNOHANG) == 0) {
      ::kill(pid_[i], SIGKILL);
      ::waitpid(pid_[i], &st, 0);
    }
    pid_[i] = -1;
  }
  bool start(int i) {  // node index 0..2, node id i + 1
    const std::string log = dir_ + "/memnode" + std::to_string(i + 1) + ".log";
    (void)std::remove(log.c_str());
    pid_[i] = ::fork();
    if (pid_[i] < 0) return false;
    if (pid_[i] == 0) {
      FILE* lf = std::freopen(log.c_str(), "w", stderr);
      (void)lf;
      const std::string cfg = dir_ + "/node" + std::to_string(i + 1) + ".toml";
      ::execl(MIRA_MEMNODE_BIN, MIRA_MEMNODE_BIN, "--config", cfg.c_str(), static_cast<char*>(nullptr));
      ::_exit(127);
    }
    for (int k = 0; k < 200; ++k) {
      std::this_thread::sleep_for(milliseconds(50));
      if (slurp(log).find("listening") != std::string::npos) return true;
      int st = 0;
      if (::waitpid(pid_[i], &st, WNOHANG) != 0) {
        pid_[i] = -1;
        ADD_FAILURE() << "mira-memnode " << i + 1 << " exited early:\n" << slurp(log);
        return false;
      }
    }
    ADD_FAILURE() << slurp(log);
    return false;
  }

  pid_t pid_[kNodes] = {-1, -1, -1};
  std::string dir_;
  std::uint16_t rdma_port_[kNodes], admin_port_[kNodes], metrics_port_[kNodes];
};

TEST_P(MultiNodeE2e, ThreeNodesPlaceKillOneAndRestartIt) {
  const std::string dev = GetParam();
  std::string ip;
  {
    fabric::VerbsOptions vo;
    vo.device = dev;
    auto f = fabric::VerbsCmFabric::open(vo);
    if (!f) GTEST_SKIP() << "no usable RDMA device: " << f.error().context;
    auto a = (*f)->device_ipv4();
    if (!a) GTEST_SKIP() << "device has no IPv4 address: " << a.error().context;
    ip = *a;
  }
  char t[] = "/tmp/mira-e2e3-XXXXXX";
  ASSERT_NE(::mkdtemp(t), nullptr);
  dir_ = t;
  const std::string pki = dir_ + "/pki";
  ASSERT_EQ(std::system(("bash " + std::string(MIRACACHE_LAB_CERTS_SH) + " " + pki + " --nodes 1,2,3 --clients 1 >/dev/null").c_str()), 0);

  for (int i = 0; i < kNodes; ++i) {
    rdma_port_[i] = free_port();
    admin_port_[i] = free_port();
    metrics_port_[i] = free_port();
    const std::string n = std::to_string(i + 1);
    std::ofstream f(dir_ + "/node" + n + ".toml");
    f << "[node]\ndevice = \"" << dev << "\"\nlisten = [\"" << ip << ":" << rdma_port_[i] << "\"]\nstate_dir = \"" << dir_ << "/state" << n << "\"\n"
      << "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\nn_segments = 4\n"
      << "max_scopes = 1000\nmax_bytes = 8388608\n"
      << "[lab]\nprincipal = \"lab\"\nidentities = [\"spiffe://lab/client-1\"]\n"
      << "[admin]\nlisten = \"127.0.0.1:" << admin_port_[i] << "\"\ncert = \"" << pki << "/node-" << n << ".pem\"\nkey = \"" << pki
      << "/node-" << n << ".key\"\nca = \"" << pki << "/ca.pem\"\n"
      << "[telemetry]\nlisten = \"127.0.0.1:" << metrics_port_[i] << "\"\n";
  }
  for (int i = 0; i < kNodes; ++i) ASSERT_TRUE(start(i));

  std::ostringstream toml;
  toml << "[scope]\nsecret_file = \"unused\"\n";
  for (int i = 0; i < kNodes; ++i)
    toml << "[[nodes]]\nweight = " << kWeight[i] << "\nrails = [\"" << ip << ":" << rdma_port_[i] << "\"]\n"
         << "admin = \"127.0.0.1:" << admin_port_[i] << "\"\nidentity = \"spiffe://lab/node-" << i + 1 << "\"\n";
  toml << "[tls]\ncert = \"" << pki << "/client-1.pem\"\nkey = \"" << pki << "/client-1.key\"\nca = \"" << pki << "/ca.pem\"\n"
       << "[fabric]\ndevice = \"" << dev << "\"\nkeepalive_ms = 100\nreconnect_min_ms = 50\nreconnect_max_ms = 500\n"
       << "[landing]\nsubpool_bytes = 8388608\n[lab]\nstatic_membership = true\n";
  auto cfg = load_config(toml.str());
  ASSERT_TRUE(cfg) << cfg.error().context;
  NoProvider prov;
  auto cl = Client::open(*cfg, prov);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  ASSERT_EQ(c.node_count(), 3u);
  // Q15: every node is up, so open() returns with all three connected (a first build that fails is retried inside the
  // open). R15: a loaded lane may still return with one pending (WARN); one still pending 10 s later is a regression.
  ASSERT_EQ(nodes_connected_within(c, 3), 3u) << "a memory node is still pending 10 s after open()";

  // Memory-node IDs are random (plan 2C): read the ones the client learned, as the client's placement uses them.
  std::vector<std::string> addrs;
  for (int i = 0; i < kNodes; ++i) addrs.push_back(ip + ":" + std::to_string(rdma_port_[i]));
  const std::vector<std::uint32_t> weights(std::begin(kWeight), std::end(kWeight));
  std::vector<PlaceNode> places = e2e::learned_places(c.metrics_text(), addrs, weights);
  for (const auto& p : places) ASSERT_NE(p.id, "0") << "the client did not learn every node id";
  ASSERT_TRUE(places[0].id != places[1].id && places[1].id != places[2].id && places[0].id != places[2].id);
  auto keys = std::make_shared<TestKeys>();
  auto scope_keys = [&](int s) {
    ScopeKeys sk;
    ScopeId id{};
    id.b[0] = static_cast<std::uint8_t>(s & 0xff);
    id.b[1] = static_cast<std::uint8_t>(s >> 8);
    id.b[31] = 0x5c;
    sk.scopes = {id};
    sk.keys = keys;
    sk.kver = 1;
    return sk;
  };
  auto owner = [&](int s) { return static_cast<int>(place_owner(places, std::span<const std::uint8_t, 32>(scope_keys(s).scopes[0].b))); };
  auto payload = [](int s) {
    Bytes d(kLen);
    for (std::size_t j = 0; j < d.size(); ++j) d[j] = static_cast<std::byte>((j * 31 + static_cast<std::size_t>(s) * 7 + 3) & 0xff);
    return d;
  };
  const std::byte name[2] = {std::byte{'k'}, std::byte{'0'}};
  KeyRef ref;
  ref.raw = std::span<const std::byte>(name, 2);
  const std::array<KeyRef, 1> refs{ref};

  int expect[kNodes] = {0, 0, 0};
  for (int s = 1; s <= kScopes; ++s) ++expect[owner(s)];
  for (int i = 0; i < kNodes; ++i) EXPECT_GT(expect[i], 20) << "node " << i + 1;

  auto put = [&](int s, KeyStatus want) {
    Bytes d = payload(s);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto sc = wait_for(c, c.store(scope_keys(s), 0, refs, pb, seconds(10)));
    ASSERT_EQ(sc.status.size(), 1u);
    EXPECT_EQ(sc.status[0], want) << "scope " << s;
  };
  auto look = [&](int s) {
    auto lc = wait_for(c, c.lookup(scope_keys(s), 0, refs, seconds(2)));
    return lc.status.size() == 1 ? lc.status[0] : KeyStatus::Timeout;
  };
  for (int s = 1; s <= kScopes; ++s) put(s, KeyStatus::Committed);
  for (int s = 1; s <= kScopes; ++s) EXPECT_EQ(look(s), KeyStatus::Hit) << s;
  for (int s = 1; s <= kScopes; s += 17) {  // data round trip on a sample
    Bytes out(kLen, std::byte{0xAA});
    std::vector<BufRef> fb{{std::span<std::byte>(out)}};
    auto fc = wait_for(c, c.fetch(scope_keys(s), 0, refs, fb, seconds(10)));
    ASSERT_EQ(fc.status.size(), 1u);
    EXPECT_EQ(fc.status[0], KeyStatus::Hit) << s;
    EXPECT_EQ(out, payload(s));
  }
  // Each node holds exactly the scopes it owns (one block per scope).
  int total = 0;
  for (int i = 0; i < kNodes; ++i) {
    const std::string m = http_metrics(metrics_port_[i]);
    ASSERT_FALSE(m.empty()) << "node " << i + 1;
    EXPECT_EQ(metric(m, "miracache_scope_open "), expect[i]) << "node " << i + 1;
    EXPECT_EQ(metric(m, "miracache_store_blocks{state=\"allocated\"}"), expect[i]) << "node " << i + 1;
    total += static_cast<int>(metric(m, "miracache_scope_open "));
  }
  EXPECT_EQ(total, kScopes);
  // The weight-2 node holds about half.
  EXPECT_NEAR(static_cast<double>(expect[2]) / kScopes, 0.5, 0.08);

  // ---- kill node 2: only its scopes fail, nothing hangs ----
  stop(1, SIGKILL);
  const auto down_by = std::chrono::steady_clock::now() + seconds(30);
  while (c.wire_port(1)->session() == WirePort::Session::Up && std::chrono::steady_clock::now() < down_by)
    std::this_thread::sleep_for(milliseconds(50));
  ASSERT_NE(c.wire_port(1)->session(), WirePort::Session::Up) << "client never noticed the dead node";
  const auto t0 = std::chrono::steady_clock::now();
  for (int s = 1; s <= kScopes; ++s) EXPECT_EQ(look(s), owner(s) == 1 ? KeyStatus::Miss : KeyStatus::Hit) << s;
  EXPECT_LT(std::chrono::steady_clock::now() - t0, seconds(10)) << "lookups of the dead node's scopes did not fail fast";
  for (int s = 1; s <= 30; ++s) {
    Bytes d = payload(s);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto sc = wait_for(c, c.store(scope_keys(s), 0, refs, pb, seconds(10)));
    ASSERT_EQ(sc.status.size(), 1u);
    if (owner(s) == 1) EXPECT_EQ(sc.status[0], KeyStatus::Refused) << s;
    else EXPECT_TRUE(sc.status[0] == KeyStatus::Committed || sc.status[0] == KeyStatus::Skipped) << s;  // already stored
  }

  // ---- r9b T04: restart node 2 WITHOUT deleting its state file (the anon store comes back empty, as hugetlbfs does
  // after a reboot): same ID, placement unchanged, its old keys miss, new puts land, no scope of a healthy node moves ----
  {
    ASSERT_TRUE(start(1));
    const auto back_by = std::chrono::steady_clock::now() + seconds(60);
    while (c.wire_port(1)->session() != WirePort::Session::Up && std::chrono::steady_clock::now() < back_by)
      std::this_thread::sleep_for(milliseconds(100));
    ASSERT_EQ(c.wire_port(1)->session(), WirePort::Session::Up) << "no reconnect after the restart";
    const std::vector<PlaceNode> same = e2e::learned_places(c.metrics_text(), addrs, weights);
    EXPECT_EQ(same[1].id, places[1].id) << "a restart that keeps the state file must keep the node id";
    for (int i = 0; i < kNodes; ++i) EXPECT_EQ(same[i].id, places[i].id) << "node " << i + 1;
    int moved = 0;
    for (int s = 1; s <= kScopes; ++s)
      moved += static_cast<int>(place_owner(same, std::span<const std::uint8_t, 32>(scope_keys(s).scopes[0].b))) != owner(s) ? 1 : 0;
    EXPECT_EQ(moved, 0) << "placement changed across a restart with the same id";
    // The healthy nodes' scopes still hit without being stored again (none moved); node 2's are empty.
    for (int s = 1; s <= kScopes; ++s) EXPECT_EQ(look(s), owner(s) == 1 ? KeyStatus::Miss : KeyStatus::Hit) << s;
    for (int s = 1; s <= kScopes; ++s)
      if (owner(s) == 1) put(s, KeyStatus::Committed);  // new puts land on the restarted node
    for (int s = 1; s <= kScopes; ++s) EXPECT_EQ(look(s), KeyStatus::Hit) << s;
    EXPECT_EQ(metric(http_metrics(metrics_port_[1]), "miracache_scope_open "), expect[1]);
    for (int i : {0, 2}) EXPECT_EQ(metric(http_metrics(metrics_port_[i]), "miracache_scope_open "), expect[i]) << "node " << i + 1;
    std::fprintf(stderr, "[T04] restart without delete: id %s kept, %d of %d scopes moved\n", same[1].id.c_str(), moved, kScopes);
    stop(1, SIGKILL);
    const auto down2 = std::chrono::steady_clock::now() + seconds(30);
    while (c.wire_port(1)->session() == WirePort::Session::Up && std::chrono::steady_clock::now() < down2)
      std::this_thread::sleep_for(milliseconds(50));
    ASSERT_NE(c.wire_port(1)->session(), WirePort::Session::Up) << "client never noticed the dead node";
  }

  // ---- replace node 2 (empty anon store, state file deleted = a new identity): reconnect recovers, new puts land ----
  std::filesystem::remove(dir_ + "/state2/node-id");
  ASSERT_TRUE(start(1));
  const auto up_by = std::chrono::steady_clock::now() + seconds(60);
  while (c.wire_port(1)->session() != WirePort::Session::Up && std::chrono::steady_clock::now() < up_by)
    std::this_thread::sleep_for(milliseconds(100));
  ASSERT_EQ(c.wire_port(1)->session(), WirePort::Session::Up) << "no reconnect after the restart";
  // The anon store came back empty with a NEW random ID, which the client adopted at the reconnect: the
  // node's share of the scopes is a different set now (rendezvous hashing moves about 1/N of the others).
  const auto old_id = places[1].id;
  places = e2e::learned_places(c.metrics_text(), addrs, weights);
  ASSERT_NE(places[1].id, "0");
  EXPECT_NE(places[1].id, old_id) << "a replaced node (state file deleted) should draw a new node id";
  int expect2[kNodes] = {0, 0, 0};
  for (int s = 1; s <= kScopes; ++s) ++expect2[owner(s)];
  for (int s = 1; s <= kScopes; ++s)
    if (owner(s) == 1) EXPECT_EQ(look(s), KeyStatus::Miss) << s;  // node 2 is empty now
  for (int s = 1; s <= kScopes; ++s) {  // fills the moved scopes too; the ones already on their owner are Skipped
    Bytes d = payload(s);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto sc = wait_for(c, c.store(scope_keys(s), 0, refs, pb, seconds(10)));
    ASSERT_EQ(sc.status.size(), 1u);
    EXPECT_TRUE(sc.status[0] == KeyStatus::Committed || sc.status[0] == KeyStatus::Skipped) << s;
  }
  for (int s = 1; s <= kScopes; ++s) EXPECT_EQ(look(s), KeyStatus::Hit) << s;
  const std::string m2 = http_metrics(metrics_port_[1]);
  EXPECT_EQ(metric(m2, "miracache_scope_open "), expect2[1]);
  c.shutdown();
}

INSTANTIATE_TEST_SUITE_P(Device, MultiNodeE2e, ::testing::ValuesIn(devices()),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });


// ---- A2.10: best-effort replicas end to end (rxe0 / siw0) ----
double pct(std::vector<double> v, double p) {
  if (v.empty()) return 0;
  std::sort(v.begin(), v.end());
  return v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))];
}
double ms_since(std::chrono::steady_clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - t0).count();
}

class ReplicaE2e : public MultiNodeE2e {};

TEST_P(ReplicaE2e, SecondReplicaKeepsTheCacheWhenThePrimaryIsKilled) {
  const std::string dev = GetParam();
  std::string ip;
  {
    fabric::VerbsOptions vo;
    vo.device = dev;
    auto f = fabric::VerbsCmFabric::open(vo);
    if (!f) GTEST_SKIP() << "no usable RDMA device: " << f.error().context;
    auto a = (*f)->device_ipv4();
    if (!a) GTEST_SKIP() << "device has no IPv4 address: " << a.error().context;
    ip = *a;
  }
  char t[] = "/tmp/mira-e2er-XXXXXX";
  ASSERT_NE(::mkdtemp(t), nullptr);
  dir_ = t;
  const std::string pki = dir_ + "/pki";
  ASSERT_EQ(std::system(("bash " + std::string(MIRACACHE_LAB_CERTS_SH) + " " + pki + " --nodes 1,2,3 --clients 1 >/dev/null").c_str()), 0);
  for (int i = 0; i < kNodes; ++i) {
    rdma_port_[i] = free_port();
    admin_port_[i] = free_port();
    metrics_port_[i] = free_port();
    const std::string n = std::to_string(i + 1);
    std::ofstream f(dir_ + "/node" + n + ".toml");
    f << "[node]\ndevice = \"" << dev << "\"\nlisten = [\"" << ip << ":" << rdma_port_[i] << "\"]\nstate_dir = \"" << dir_ << "/state" << n << "\"\n"
      << "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\nn_segments = 4\n"
      << "max_scopes = 1000\nmax_bytes = 16777216\n"
      << "[lab]\nprincipal = \"lab\"\nidentities = [\"spiffe://lab/client-1\"]\n"
      << "[admin]\nlisten = \"127.0.0.1:" << admin_port_[i] << "\"\ncert = \"" << pki << "/node-" << n << ".pem\"\nkey = \"" << pki
      << "/node-" << n << ".key\"\nca = \"" << pki << "/ca.pem\"\n"
      << "[telemetry]\nlisten = \"127.0.0.1:" << metrics_port_[i] << "\"\n";
  }
  for (int i = 0; i < kNodes; ++i) ASSERT_TRUE(start(i));

  auto open_client = [&](int replicas, const char* mode = "async") {
    std::ostringstream toml;
    toml << "[scope]\nsecret_file = \"unused\"\n";
    for (int i = 0; i < kNodes; ++i)
      toml << "[[nodes]]\nrails = [\"" << ip << ":" << rdma_port_[i] << "\"]\n"
           << "admin = \"127.0.0.1:" << admin_port_[i] << "\"\nidentity = \"spiffe://lab/node-" << i + 1 << "\"\n";
    toml << "[tls]\ncert = \"" << pki << "/client-1.pem\"\nkey = \"" << pki << "/client-1.key\"\nca = \"" << pki << "/ca.pem\"\n"
         << "[fabric]\ndevice = \"" << dev << "\"\nkeepalive_ms = 100\nreconnect_min_ms = 50\nreconnect_max_ms = 500\n"
         << "[landing]\nsubpool_bytes = 8388608\n[placement]\nreplicas = " << replicas << "\nreplica_mode = \"" << mode << "\"\n[lab]\nstatic_membership = true\n";
    auto cfg = load_config(toml.str());
    EXPECT_TRUE(cfg) << (cfg ? "" : cfg.error().context);
    static NoProvider prov;
    return cfg ? Client::open(*cfg, prov) : Expected<std::unique_ptr<Client>>(cfg.error());
  };
  auto c1 = open_client(1);
  ASSERT_TRUE(c1) << c1.error().context;
  Client& r1 = **c1;
  ASSERT_EQ(nodes_connected_within(r1, 3), 3u) << "a memory node is still pending 10 s after open()";

  // Random node IDs (plan 2C): the placement list is built from the IDs the client learned. The nodes stay up
  // until the SIGKILL below, so every client opened before it sees the same IDs.
  std::vector<std::string> addrs;
  for (int i = 0; i < kNodes; ++i) addrs.push_back(ip + ":" + std::to_string(rdma_port_[i]));
  const std::vector<PlaceNode> places = e2e::learned_places(r1.metrics_text(), addrs, {1, 1, 1});
  for (const auto& p : places) ASSERT_NE(p.id, "0") << "the client did not learn every node id";
  auto keys = std::make_shared<TestKeys>();
  auto scope_keys = [&](int s) {
    ScopeKeys sk;
    ScopeId id{};
    id.b[0] = static_cast<std::uint8_t>(s & 0xff);
    id.b[1] = static_cast<std::uint8_t>(s >> 8);
    id.b[31] = 0x5c;
    sk.scopes = {id};
    sk.keys = keys;
    sk.kver = 1;
    return sk;
  };
  auto order = [&](int s, std::size_t r) {
    return place_order(places, std::span<const std::uint8_t, 32>(scope_keys(s).scopes[0].b), r);
  };
  auto payload = [](int s) {
    Bytes d(kLen);
    for (std::size_t j = 0; j < d.size(); ++j) d[j] = static_cast<std::byte>((j * 31 + static_cast<std::size_t>(s) * 7 + 3) & 0xff);
    return d;
  };
  const std::byte name[2] = {std::byte{'k'}, std::byte{'0'}};
  KeyRef ref;
  ref.raw = std::span<const std::byte>(name, 2);
  const std::array<KeyRef, 1> refs{ref};
  constexpr int kN = 200;
  constexpr int kBase2 = 1000;  // scope ids of the R=2 async client
  constexpr int kBase3 = 2000;  // scope ids of the R=2 sync client (store latency only)

  auto put_all = [&](Client& c, int base, std::vector<double>& lat) {
    for (int s = base + 1; s <= base + kN; ++s) {
      Bytes d = payload(s);
      std::vector<BufRef> pb{{std::span<std::byte>(d)}};
      const auto t0 = std::chrono::steady_clock::now();
      auto sc = wait_for(c, c.store(scope_keys(s), 0, refs, pb, seconds(10)));
      lat.push_back(ms_since(t0));
      ASSERT_EQ(sc.status.size(), 1u);
      EXPECT_EQ(sc.status[0], KeyStatus::Committed) << "scope " << s;
    }
  };
  // Fetch every scope; counts hits, checks the bytes of every hit, returns the hit count.
  auto get_all = [&](Client& c, int base, std::vector<double>& lat, int only_primary /* -1 = all */) {
    int hits = 0, n = 0;
    for (int s = base + 1; s <= base + kN; ++s) {
      if (only_primary >= 0 && static_cast<int>(order(s, 1)[0]) != only_primary) continue;
      ++n;
      Bytes out(kLen, std::byte{0xAA});
      std::vector<BufRef> fb{{std::span<std::byte>(out)}};
      const auto t0 = std::chrono::steady_clock::now();
      auto fc = wait_for(c, c.fetch(scope_keys(s), 0, refs, fb, seconds(10)));
      lat.push_back(ms_since(t0));
      if (fc.status.size() == 1 && fc.status[0] == KeyStatus::Hit) {
        ++hits;
        EXPECT_EQ(out, payload(s)) << "scope " << s << ": hit with wrong bytes";
      }
    }
    return std::make_pair(hits, n);
  };

  std::vector<double> st1, st2, st3, f1a, f1b, f2a, f2b, f2prim;
  put_all(r1, 0, st1);
  const auto [h1a, n1a] = get_all(r1, 0, f1a, -1);
  r1.shutdown();
  c1->reset();
  {  // R=2 sync: the job waits for both legs. Only its store latency is measured (and its scopes counted below).
    auto cs = open_client(2, "sync");
    ASSERT_TRUE(cs) << cs.error().context;
    ASSERT_EQ(nodes_connected_within((**cs), 3), 3u) << "a memory node is still pending 10 s after open()";
    put_all(**cs, kBase3, st3);
    (**cs).shutdown();
  }
  // one client at a time: siw0 has few CQs
  auto c2 = open_client(2);
  ASSERT_TRUE(c2) << c2.error().context;
  Client& r2 = **c2;
  ASSERT_EQ(nodes_connected_within(r2, 3), 3u) << "a memory node is still pending 10 s after open()";
  put_all(r2, kBase2, st2);
  const auto drain0 = std::chrono::steady_clock::now();
  while (r2.replicator_pending() > 0 && std::chrono::steady_clock::now() < drain0 + seconds(30)) std::this_thread::sleep_for(milliseconds(1));
  EXPECT_EQ(r2.replicator_pending(), 0u) << "the replicator never drained";
  const double drain_ms = ms_since(drain0);
  // R=2: every node holds exactly the scopes whose replica set contains it.
  int want[kNodes] = {0, 0, 0}, want1[kNodes] = {0, 0, 0}, prim2 = 0;
  for (int s = 1; s <= kN; ++s) {
    for (auto i : order(kBase2 + s, 2)) ++want[i];
    for (auto i : order(kBase3 + s, 2)) ++want[i];
    ++want1[order(s, 1)[0]];
    prim2 += order(kBase2 + s, 1)[0] == 1;
  }
  for (int i = 0; i < kNodes; ++i) {
    std::string m;  // the node refreshes its gauges on a timer: wait for the final count
    for (int k = 0; k < 100; ++k) {
      m = http_metrics(metrics_port_[i]);
      if (metric(m, "miracache_scope_open ") == want[i] + want1[i]) break;
      std::this_thread::sleep_for(milliseconds(100));
    }
    ASSERT_FALSE(m.empty());
    EXPECT_EQ(metric(m, "miracache_scope_open "), want[i] + want1[i]) << "node " << i + 1;
  }
  ASSERT_GT(prim2, 20) << "too few scopes with node 2 as primary";

  const auto [h2a, n2a] = get_all(r2, kBase2, f2a, -1);
  EXPECT_EQ(h1a, n1a);
  EXPECT_EQ(h2a, n2a);

  stop(1, SIGKILL);  // SIGKILL node 2, the primary of `prim2` R=2 scopes
  const auto down_by = std::chrono::steady_clock::now() + seconds(30);
  while (r2.wire_port(1)->session() == WirePort::Session::Up && std::chrono::steady_clock::now() < down_by)
    std::this_thread::sleep_for(milliseconds(50));
  ASSERT_NE(r2.wire_port(1)->session(), WirePort::Session::Up) << "client never noticed the dead node";

  const auto [h2b, n2b] = get_all(r2, kBase2, f2b, -1);
  const auto [h2p, n2p] = get_all(r2, kBase2, f2prim, 1);  // only the scopes whose primary died
  EXPECT_EQ(h2b, n2b) << "a replicated scope was lost with one node down";
  EXPECT_EQ(h2p, n2p);
  EXPECT_EQ(n2p, prim2);
  // The failover is visible in the metrics.
  const std::string cm = r2.metrics_text();
  double failovers = 0;
  for (int i : {0, 2}) {
    const std::string series = "miracache_client_read_failover_total{node=\"" + addrs[static_cast<std::size_t>(i)] + "\"}";
    const long v = metric(cm, series);
    failovers += v < 0 ? 0 : static_cast<double>(v);
  }
  EXPECT_GE(failovers, prim2);
  // A store with the primary dead still commits (second replica only).
  {
    Bytes d = payload(9999);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    int s = 9999;
    for (; s < 10100 && order(s, 1)[0] != 1; ++s) {}
    auto sc = wait_for(r2, r2.store(scope_keys(s), 0, refs, pb, seconds(10)));
    ASSERT_EQ(sc.status.size(), 1u);
    EXPECT_EQ(sc.status[0], KeyStatus::Committed);
  }
  r2.shutdown();
  c2->reset();
  auto c1b = open_client(1);  // a fresh R=1 client reads what R=1 stored, with the node dead
  ASSERT_TRUE(c1b) << c1b.error().context;
  EXPECT_EQ((**c1b).nodes_connected(), 2u) << "the killed node is reported pending, the other two connected";
  const auto [h1b, n1b] = get_all(**c1b, 0, f1b, -1);
  EXPECT_LT(h1b, n1b);  // R=1 loses the dead node scopes
  (**c1b).shutdown();
  std::fprintf(stderr,
               "REPLICA-E2E dev=%s scopes=%d (R=2 primary on killed node: %d)\n"
               "  hit rate before kill: R=1 %d/%d  R=2 %d/%d\n"
               "  hit rate after  kill: R=1 %d/%d  R=2 %d/%d  (R=2 scopes whose primary died: %d/%d)\n"
               "  fetch ms  R=2 before p50=%.2f p99=%.2f | after p50=%.2f p99=%.2f | primary-died p50=%.2f p99=%.2f | R=1 before p50=%.2f p99=%.2f\n"
               "  store ms  R=1 p50=%.2f p99=%.2f | R=2 async p50=%.2f p99=%.2f | R=2 sync p50=%.2f p99=%.2f  (async replicator drained %d stores in %.1f ms after the last Completion)\n",
               dev.c_str(), kN, prim2, h1a, n1a, h2a, n2a, h1b, n1b, h2b, n2b, h2p, n2p, pct(f2a, .5), pct(f2a, .99), pct(f2b, .5),
               pct(f2b, .99), pct(f2prim, .5), pct(f2prim, .99), pct(f1a, .5), pct(f1a, .99), pct(st1, .5), pct(st1, .99), pct(st2, .5),
               pct(st2, .99), pct(st3, .5), pct(st3, .99), kN, drain_ms);
}

// Review r9 S03: store latency of large blocks. Every engine store of a replicated scope used to copy the block into
// a fresh zero-filled std::vector on the engine worker; the copy now comes from recycled, non-zeroed buffers. This
// measures the engine-visible store latency (submit -> Completion) at 1 MiB blocks for R=1, async R=2 and sync R=2 on
// the same three nodes, and prints the table (the numbers go to the run report; the test only checks that every store
// commits, since latency on soft RDMA is not a stable bound).
TEST_P(ReplicaE2e, StoreLatencyAtOneMiBBlocks) {
  const std::string dev = GetParam();
  std::string ip;
  {
    fabric::VerbsOptions vo;
    vo.device = dev;
    auto f = fabric::VerbsCmFabric::open(vo);
    if (!f) GTEST_SKIP() << "no usable RDMA device: " << f.error().context;
    auto a = (*f)->device_ipv4();
    if (!a) GTEST_SKIP() << "device has no IPv4 address: " << a.error().context;
    ip = *a;
  }
  constexpr std::size_t kBlock = std::size_t{1} << 20;
  constexpr int kBlocks = 50;
  char t[] = "/tmp/mira-e2er1m-XXXXXX";
  ASSERT_NE(::mkdtemp(t), nullptr);
  dir_ = t;
  const std::string pki = dir_ + "/pki";
  ASSERT_EQ(std::system(("bash " + std::string(MIRACACHE_LAB_CERTS_SH) + " " + pki + " --nodes 1,2,3 --clients 1 >/dev/null").c_str()), 0);
  for (int i = 0; i < kNodes; ++i) {
    rdma_port_[i] = free_port();
    admin_port_[i] = free_port();
    metrics_port_[i] = free_port();
    const std::string n = std::to_string(i + 1);
    std::ofstream f(dir_ + "/node" + n + ".toml");
    // 3 x 64 MiB segments with 4 MiB runs per node: room for the ~85 MiB each node holds in this test.
    f << "[node]\ndevice = \"" << dev << "\"\nlisten = [\"" << ip << ":" << rdma_port_[i] << "\"]\nstate_dir = \"" << dir_ << "/state" << n << "\"\n"
      << "[store]\nbacking = \"anon\"\nsegment_bytes = 67108864\nrun_bytes = 4194304\nmin_block_bytes = 4096\nn_segments = 3\n"
      << "max_scopes = 1000\nmax_bytes = 201326592\n"
      << "[lab]\nprincipal = \"lab\"\nidentities = [\"spiffe://lab/client-1\"]\n"
      << "[admin]\nlisten = \"127.0.0.1:" << admin_port_[i] << "\"\ncert = \"" << pki << "/node-" << n << ".pem\"\nkey = \"" << pki
      << "/node-" << n << ".key\"\nca = \"" << pki << "/ca.pem\"\n"
      << "[telemetry]\nlisten = \"127.0.0.1:" << metrics_port_[i] << "\"\n";
  }
  for (int i = 0; i < kNodes; ++i) ASSERT_TRUE(start(i));

  auto open_client = [&](int replicas, const char* mode) {
    std::ostringstream toml;
    toml << "[scope]\nsecret_file = \"unused\"\n";
    for (int i = 0; i < kNodes; ++i)
      toml << "[[nodes]]\nrails = [\"" << ip << ":" << rdma_port_[i] << "\"]\n"
           << "admin = \"127.0.0.1:" << admin_port_[i] << "\"\nidentity = \"spiffe://lab/node-" << i + 1 << "\"\n";
    toml << "[tls]\ncert = \"" << pki << "/client-1.pem\"\nkey = \"" << pki << "/client-1.key\"\nca = \"" << pki << "/ca.pem\"\n"
         << "[fabric]\ndevice = \"" << dev << "\"\nkeepalive_ms = 100\nreconnect_min_ms = 50\nreconnect_max_ms = 500\n"
         << "[landing]\nsubpool_bytes = 33554432\n[placement]\nreplicas = " << replicas << "\nreplica_mode = \"" << mode << "\"\n[lab]\nstatic_membership = true\n";
    auto cfg = load_config(toml.str());
    EXPECT_TRUE(cfg) << (cfg ? "" : cfg.error().context);
    static NoProvider prov;
    return cfg ? Client::open(*cfg, prov) : Expected<std::unique_ptr<Client>>(cfg.error());
  };
  auto keys = std::make_shared<TestKeys>();
  auto scope_keys = [&](int s) {
    ScopeKeys sk;
    ScopeId id{};
    id.b[0] = static_cast<std::uint8_t>(s & 0xff);
    id.b[1] = static_cast<std::uint8_t>(s >> 8);
    id.b[31] = 0x5d;
    sk.scopes = {id};
    sk.keys = keys;
    sk.kver = 1;
    return sk;
  };
  const std::byte name[2] = {std::byte{'k'}, std::byte{'1'}};
  KeyRef ref;
  ref.raw = std::span<const std::byte>(name, 2);
  const std::array<KeyRef, 1> refs{ref};
  Bytes block(kBlock);
  auto put_all = [&](Client& c, int base, std::vector<double>& lat) {
    for (int s = base + 1; s <= base + kBlocks; ++s) {
      for (std::size_t j = 0; j < block.size(); j += 4096) block[j] = static_cast<std::byte>((j / 4096 + static_cast<std::size_t>(s)) & 0xff);
      std::vector<BufRef> pb{{std::span<std::byte>(block)}};
      const auto t0 = std::chrono::steady_clock::now();
      auto sc = wait_for(c, c.store(scope_keys(s), 0, refs, pb, seconds(20)));
      lat.push_back(ms_since(t0));
      ASSERT_EQ(sc.status.size(), 1u);
      ASSERT_EQ(sc.status[0], KeyStatus::Committed) << "scope " << s;
    }
  };
  auto drain = [&](Client& c) {
    const auto d0 = std::chrono::steady_clock::now();
    while (c.replicator_pending() > 0 && std::chrono::steady_clock::now() < d0 + seconds(60)) std::this_thread::sleep_for(milliseconds(1));
    EXPECT_EQ(c.replicator_pending(), 0u);
  };
  std::vector<double> s1, sa, ss;
  {
    auto c = open_client(1, "async");
    ASSERT_TRUE(c) << c.error().context;
    ASSERT_EQ(nodes_connected_within((**c), 3), 3u) << "a memory node is still pending 10 s after open()";
    put_all(**c, 0, s1);
    (**c).shutdown();
  }
  {
    auto c = open_client(2, "async");
    ASSERT_TRUE(c) << c.error().context;
    ASSERT_EQ(nodes_connected_within((**c), 3), 3u) << "a memory node is still pending 10 s after open()";
    put_all(**c, 1000, sa);
    drain(**c);
    (**c).shutdown();
  }
  {
    auto c = open_client(2, "sync");
    ASSERT_TRUE(c) << c.error().context;
    ASSERT_EQ(nodes_connected_within((**c), 3), 3u) << "a memory node is still pending 10 s after open()";
    put_all(**c, 2000, ss);
    (**c).shutdown();
  }
  std::fprintf(stderr,
               "REPLICA-STORE-1MiB dev=%s blocks=%d x %zu bytes, 3 memory nodes\n"
               "  store ms  R=1 p50=%.2f p99=%.2f | R=2 async p50=%.2f p99=%.2f | R=2 sync p50=%.2f p99=%.2f\n",
               dev.c_str(), kBlocks, kBlock, pct(s1, .5), pct(s1, .99), pct(sa, .5), pct(sa, .99), pct(ss, .5), pct(ss, .99));
}


INSTANTIATE_TEST_SUITE_P(Device, ReplicaE2e, ::testing::ValuesIn(devices()),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

// ---- External memory nodes (the Docker end-to-end script): the memory nodes are already running (Docker containers);
// this test only plays the client. Skipped unless MIRA_EXT_RAILS is set. Environment:
//   MIRA_EXT_DEVICE  RDMA device of this host (default rxe0)    MIRA_EXT_IP     IPv4 of the nodes' rails
//   MIRA_EXT_RAILS   rdma ports, comma list, one per node       MIRA_EXT_ADMIN  admin ports (127.0.0.1), same order
//   MIRA_EXT_PKI     dir from lab-certs.sh (node-N / client-1 / ca.pem), node N = position in the lists
// Prints "[EXT] ops=N oracle=ok" when every stored payload reads back identical.
TEST(ExternalNodes, StoreLookupFetchAcrossRunningNodes) {
  const char* rails_env = std::getenv("MIRA_EXT_RAILS");
  if (rails_env == nullptr || *rails_env == '\0') GTEST_SKIP() << "MIRA_EXT_RAILS not set (set by the Docker end-to-end script)";
  auto split = [](const char* s) {
    std::vector<std::string> out;
    std::stringstream ss(s != nullptr ? s : "");
    for (std::string x; std::getline(ss, x, ',');)
      if (!x.empty()) out.push_back(x);
    return out;
  };
  const auto rails = split(rails_env), admins = split(std::getenv("MIRA_EXT_ADMIN"));
  ASSERT_FALSE(rails.empty());
  ASSERT_EQ(rails.size(), admins.size());
  const char* ip_env = std::getenv("MIRA_EXT_IP");
  const char* pki_env = std::getenv("MIRA_EXT_PKI");
  const char* dev_env = std::getenv("MIRA_EXT_DEVICE");
  ASSERT_TRUE(ip_env != nullptr && pki_env != nullptr) << "MIRA_EXT_IP and MIRA_EXT_PKI are required";
  const std::string ip = ip_env, pki = pki_env, dev = dev_env != nullptr ? dev_env : "rxe0";
  std::ostringstream toml;
  toml << "[scope]\nsecret_file = \"unused\"\n";
  // Bundle-mode nodes (the systemd acceptance script) refuse puts from a static-membership client (its epoch is 0):
  // MIRA_EXT_TRUST = the trust file and MIRA_EXT_CLIENT_STATE = a client state_dir open the client in bundle mode
  // ([control], endpoints = the admin addresses; MIRA_EXT_CONTROLLER optional, for client reports).
  const char* trust_env = std::getenv("MIRA_EXT_TRUST");
  const bool bundle_mode = trust_env != nullptr && *trust_env != '\0';
  if (bundle_mode) {
    const char* st = std::getenv("MIRA_EXT_CLIENT_STATE");
    ASSERT_TRUE(st != nullptr && *st != '\0') << "MIRA_EXT_TRUST needs MIRA_EXT_CLIENT_STATE";
    toml << "[control]\nendpoints = [";
    for (std::size_t i = 0; i < admins.size(); ++i) toml << (i ? ", " : "") << "\"127.0.0.1:" << admins[i] << "\"";
    toml << "]\n";
    if (const char* ctl = std::getenv("MIRA_EXT_CONTROLLER"); ctl != nullptr && *ctl != '\0') toml << "controller = \"" << ctl << "\"\n";
    toml << "trust_keys = \"" << trust_env << "\"\nstate_dir = \"" << st << "\"\n";
    (void)std::filesystem::create_directories(st);
  } else {
    for (std::size_t i = 0; i < rails.size(); ++i)
      toml << "[[nodes]]\nweight = 1\nrails = [\"" << ip << ":" << rails[i] << "\"]\nadmin = \"127.0.0.1:" << admins[i]
           << "\"\nidentity = \"spiffe://lab/node-" << i + 1 << "\"\n";
  }
  toml << "[tls]\ncert = \"" << pki << "/client-1.pem\"\nkey = \"" << pki << "/client-1.key\"\nca = \"" << pki << "/ca.pem\"\n"
       << "[fabric]\ndevice = \"" << dev << "\"\nkeepalive_ms = 100\nreconnect_min_ms = 50\nreconnect_max_ms = 500\n"
       << "[landing]\nsubpool_bytes = 8388608\n" << (bundle_mode ? "" : "[lab]\nstatic_membership = true\n");
  auto cfg = load_config(toml.str());
  ASSERT_TRUE(cfg) << cfg.error().context;
  NoProvider prov;
  auto cl = Client::open(*cfg, prov);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  ASSERT_EQ(c.node_count(), rails.size());

  constexpr int kExtScopes = 300;
  auto keys = std::make_shared<TestKeys>();
  // MIRA_EXT_SCOPE_SET (0..255): a second run against the same nodes uses fresh scopes (a store of a block the node
  // already holds is not "Committed").
  const char* set_env = std::getenv("MIRA_EXT_SCOPE_SET");
  const auto scope_set = static_cast<std::uint8_t>(set_env != nullptr ? std::atoi(set_env) : 0);
  auto scope_keys = [&](int s) {
    ScopeKeys sk;
    ScopeId id{};
    id.b[0] = static_cast<std::uint8_t>(s & 0xff);
    id.b[1] = static_cast<std::uint8_t>(s >> 8);
    id.b[2] = scope_set;
    id.b[31] = 0x5d;
    sk.scopes = {id};
    sk.keys = keys;
    sk.kver = 1;
    return sk;
  };
  auto payload = [](int s) {
    Bytes d(kLen);
    for (std::size_t j = 0; j < d.size(); ++j) d[j] = static_cast<std::byte>((j * 29 + static_cast<std::size_t>(s) * 11 + 5) & 0xff);
    return d;
  };
  const std::byte name[2] = {std::byte{'k'}, std::byte{'1'}};
  KeyRef ref;
  ref.raw = std::span<const std::byte>(name, 2);
  const std::array<KeyRef, 1> refs{ref};
  int ops = 0, bad = 0;
  for (int s = 1; s <= kExtScopes; ++s) {
    Bytes d = payload(s);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto sc = wait_for(c, c.store(scope_keys(s), 0, refs, pb, seconds(10)));
    ++ops;
    if (sc.status.size() != 1 || sc.status[0] != KeyStatus::Committed) ++bad;
  }
  for (int s = 1; s <= kExtScopes; ++s) {
    auto lc = wait_for(c, c.lookup(scope_keys(s), 0, refs, seconds(2)));
    ++ops;
    if (lc.status.size() != 1 || lc.status[0] != KeyStatus::Hit) ++bad;
    Bytes out(kLen, std::byte{0xAA});
    std::vector<BufRef> fb{{std::span<std::byte>(out)}};
    auto fc = wait_for(c, c.fetch(scope_keys(s), 0, refs, fb, seconds(10)));
    ++ops;
    if (fc.status.size() != 1 || fc.status[0] != KeyStatus::Hit || out != payload(s)) ++bad;
  }
  // Optional traffic loop (the systemd acceptance script): MIRA_EXT_LOOP_S seconds of fetch-then-restore rounds over the
  // same scopes while the caller restarts a node. A fetch that is not a Hit counts as a miss (the node is down or came
  // back cold) and the block is stored again; only wrong bytes or a hang are errors. The last round must be all hits:
  // the client reconnected to every node and the re-stored blocks are served again.
  if (const char* ls = std::getenv("MIRA_EXT_LOOP_S"); ls != nullptr && std::atoi(ls) > 0) {
    const auto end = std::chrono::steady_clock::now() + seconds(std::atoi(ls));
    long rounds = 0, hits = 0, misses = 0, restored = 0, not_stored = 0, corrupt = 0, last_hits = 0;
    std::fprintf(stderr, "[EXT-LOOP] start scopes=%d\n", kExtScopes);
    std::fflush(stderr);
    while (std::chrono::steady_clock::now() < end) {
      long round_hits = 0;
      for (int s = 1; s <= kExtScopes; ++s) {
        Bytes out(kLen, std::byte{0xAA});
        std::vector<BufRef> fb{{std::span<std::byte>(out)}};
        auto fc = wait_for(c, c.fetch(scope_keys(s), 0, refs, fb, seconds(10)));
        if (fc.status.size() == 1 && fc.status[0] == KeyStatus::Hit) {
          if (out == payload(s)) ++round_hits; else ++corrupt;
          continue;
        }
        ++misses;
        Bytes d = payload(s);
        std::vector<BufRef> pb{{std::span<std::byte>(d)}};
        auto sc = wait_for(c, c.store(scope_keys(s), 0, refs, pb, seconds(10)));
        if (sc.status.size() == 1 && sc.status[0] == KeyStatus::Committed) ++restored; else ++not_stored;
      }
      hits += round_hits;
      last_hits = round_hits;
      ++rounds;
    }
    const bool recovered = last_hits == kExtScopes;
    std::fprintf(stderr, "[EXT-LOOP] rounds=%ld hits=%ld misses=%ld restored=%ld not_stored=%ld corrupt=%ld last_round_hits=%ld/%d recovered=%s\n",
                 rounds, hits, misses, restored, not_stored, corrupt, last_hits, kExtScopes, recovered ? "yes" : "no");
    EXPECT_EQ(corrupt, 0) << "a fetch returned other bytes";
    EXPECT_TRUE(recovered) << "the last round was not all hits: the client did not get every node back";
  }
  c.shutdown();
  EXPECT_EQ(bad, 0) << "stores, lookups or fetches failed or returned other bytes";
  std::fprintf(stderr, "[EXT] ops=%d oracle=%s\n", ops, bad == 0 ? "ok" : "MISMATCH");
}

}  // namespace
}  // namespace miracache
