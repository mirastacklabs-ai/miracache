// SPDX-License-Identifier: Apache-2.0
// Reconnect under live traffic (label `rdma`): real mira-memnode processes, one Client::open, four
// client threads looping put / lookup / fetch over many scopes. A memnode is killed (SIGKILL or
// SIGTERM) mid-traffic and restarted on the same port with an empty cache. Checks:
//   * no op hangs: every op returns within its own deadline + kMargin;
//   * ops that START while the node is down fail cleanly (lookup/fetch miss, store refused or
//     timed out), and nothing ever returns wrong bytes;
//   * the session goes Up -> Down/Connecting, the metrics show it (session_up, reconnect_total,
//     reconnect_fail_total, connect attempts);
//   * after the restart the client is Up again by itself within kRecoverCap, new puts / fetches work;
//   * payloads are versioned (v0 before the restart, v1 after): a fetch that hits a restarted node's scope
//     must carry v1, a v0 hit would be a stale read from a cache that was emptied;
//   * (3 nodes) ops on the other nodes' scopes succeed 100% throughout (strict, accepted flake risk) and
//     their p99 latency over the outage window, and over the whole transition [kill, Up again], stays
//     within kP99Mul x the before-outage p99 (+ kP99Slack).
// Time budget (ctest TIMEOUT 240 s, tests/CMakeLists.txt): worst-case sum of the caps below is about
// 100 s: memnode start 3 x 5 s, fill <= kFillCap 20 s, baseline 2 s, detect <= 10 s, dwell 3 s, restart
// 5 s, recover <= 8 s, tail 2 s, post checks <= kPostCap 15 s, SIGTERM waits <= 3 x 5 s, cert gen few s.
// Certs from deploy/examples/lab-certs.sh. Skips cleanly without an RDMA device.
#include <arpa/inet.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <condition_variable>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

#include "fabric/verbs_cm/verbs_cm_fabric.h"
#include "free_port.h"
#include "learned_ids.h"
#include "src/client.h"
#include "src/placement.h"
#include "src/wire_port.h"

extern char** environ;

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;
using Clk = std::chrono::steady_clock;
using std::chrono::milliseconds;
using std::chrono::seconds;

// Honest bounds for rxe0 on a 2-CPU container where the memnodes, the client's keepalive threads and
// four traffic threads share the cores.
constexpr milliseconds kMargin{1000};        // an op returns within its deadline + this
constexpr milliseconds kFailFast{500};       // an op that starts while the node is down returns within this
constexpr seconds kDetectCap{10};            // client notices the dead node (measured: tens of ms; suspect path 3 x keepalive)
constexpr seconds kRecoverCap{8};            // restarted node -> Up again; measured on rxe0: 0.8-1.0 s (3 nodes), 2.4-4.1 s (1 node), so 2x headroom
constexpr seconds kFillCap{20}, kPostCap{15};  // whole fill phase / whole post-recovery check phase
constexpr double kP99Mul = 4.0;              // other nodes' p99 during the outage <= kP99Mul * before + kP99Slack
constexpr double kP99SlackUs = 20000.0;

constexpr milliseconds kPutTo{2000}, kLookTo{1000}, kFetchTo{2000};
constexpr int kThreads = 4;
constexpr std::size_t kLen = 2000;

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

// Sum of every sample of family `name` whose line contains `must` (e.g. node="2"); -1 if none.
double metric_sum(const std::string& text, const std::string& name, const std::string& must = {}) {
  double sum = 0;
  bool any = false;
  std::stringstream ss(text);
  for (std::string line; std::getline(ss, line);) {
    if (line.empty() || line[0] == '#') continue;
    if (line.compare(0, name.size(), name) != 0) continue;
    const char nx = line.size() > name.size() ? line[name.size()] : ' ';
    if (nx != '{' && nx != ' ') continue;
    if (!must.empty() && line.find(must) == std::string::npos) continue;
    sum += std::strtod(line.c_str() + line.rfind(' ') + 1, nullptr);
    any = true;
  }
  return any ? sum : -1;
}

enum Op { kPut = 0, kLook = 1, kFetch = 2 };
const char* op_name(int o) { return o == kPut ? "put" : o == kLook ? "lookup" : "fetch"; }

struct Rec {
  std::int64_t start_us = 0;  // since the test epoch
  std::int64_t lat_us = 0;
  int op = 0;
  int owner = 0;
  int scope = 0;
  KeyStatus st = KeyStatus::Miss;
  bool hang = false;
  bool bad_bytes = false;
  int ver = -1;  // fetch hit: the payload version it carried
};

class ReconnectTraffic : public ::testing::TestWithParam<std::tuple<std::string, int, int>> {  // device, nodes, signal
 protected:
  void TearDown() override {
    stop_watcher();  // Joined on every path, including an ASSERT_* that returned early
    stop_traffic();
    stop_dispatcher();
    if (cl_) cl_->shutdown();
    cl_.reset();
    for (int i = 0; i < kMaxNodes; ++i) stop(i, SIGTERM);
    if (!dir_.empty()) (void)std::system(("rm -rf " + dir_).c_str());
  }
  static constexpr int kMaxNodes = 3;

  void stop(int i, int sig) {
    if (pid_[i] <= 0) return;
    ::kill(pid_[i], sig);
    int st = 0;
    pid_t r = 0;
    for (int k = 0; k < 100 && (r = ::waitpid(pid_[i], &st, WNOHANG)) == 0; ++k) std::this_thread::sleep_for(milliseconds(50));
    last_stop_graceful_ = false;
    if (r == 0 && (r = ::waitpid(pid_[i], &st, WNOHANG)) == 0) {
      ::kill(pid_[i], SIGKILL);  // did not exit within 5 s of the signal
      ::waitpid(pid_[i], &st, 0);
    } else {
      last_stop_graceful_ = r > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0;  // exited by itself, status 0
    }
    pid_[i] = -1;
  }
  bool start(int i) {  // node index, node id i + 1
    const std::string log = dir_ + "/memnode" + std::to_string(i + 1) + ".log";
    (void)std::remove(log.c_str());
    // posix_spawn, not fork(): this process is multithreaded and holds live RDMA memory regions.
    const std::string cfg = dir_ + "/node" + std::to_string(i + 1) + ".toml";
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    char* argv[] = {const_cast<char*>(MIRA_MEMNODE_BIN), const_cast<char*>("--config"), const_cast<char*>(cfg.c_str()), nullptr};
    pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, MIRA_MEMNODE_BIN, &fa, nullptr, argv, environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) {
      ADD_FAILURE() << "posix_spawn(mira-memnode) failed: " << std::strerror(rc);
      return false;
    }
    pid_[i] = pid;
    for (int k = 0; k < 100; ++k) {  // 5 s
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

  // ---- scopes and payloads ----
  ScopeKeys scope_keys(int s) const {
    ScopeKeys sk;
    ScopeId id{};
    id.b[0] = static_cast<std::uint8_t>(s & 0xff);
    id.b[1] = static_cast<std::uint8_t>(s >> 8);
    id.b[31] = 0x5c;
    sk.scopes = {id};
    sk.keys = keys_;
    sk.kver = 1;
    return sk;
  }
  int owner(int s) const {
    return static_cast<int>(place_owner(places_, std::span<const std::uint8_t, 32>(scope_keys(s).scopes[0].b)));
  }
  // Byte 0 = the version (0 before the memnode restart, 1 after), the rest depends on scope and version.
  static Bytes payload(int s, int ver) {
    Bytes d(kLen);
    for (std::size_t j = 0; j < d.size(); ++j)
      d[j] = static_cast<std::byte>((j * 31 + static_cast<std::size_t>(s) * 7 + static_cast<std::size_t>(ver) * 101 + 3) & 0xff);
    d[0] = static_cast<std::byte>(ver);
    return d;
  }
  static int version_of(const Bytes& d) { return d.empty() ? -1 : static_cast<int>(d[0]); }

  // ---- one dispatcher thread polls the client; callers wait for their own ticket ----
  void start_dispatcher() {
    disp_run_ = true;
    disp_ = std::thread([this] {
      std::array<Completion, 8> comp;
      while (disp_run_) {
        const std::size_t n = cl_->poll(comp);
        if (n > 0) {
          std::lock_guard lk(mu_);
          for (std::size_t k = 0; k < n; ++k) done_[comp[k].ticket.id] = std::move(comp[k]);
          cv_.notify_all();
        } else {
          std::this_thread::sleep_for(std::chrono::microseconds(200));
        }
      }
    });
  }
  // Waits for the ticket; false = no completion within `cap` (a hang).
  bool await(Ticket t, Completion& out, milliseconds cap) {
    std::unique_lock lk(mu_);
    if (!cv_.wait_for(lk, cap, [&] { return done_.count(t.id) != 0; })) return false;
    out = std::move(done_[t.id]);
    done_.erase(t.id);
    return true;
  }

  // One op on scope s; fills the record. A fetch that hits must carry the exact payload.
  Rec run_op(int op, int s) {
    Rec r;
    r.op = op;
    r.scope = s;
    r.owner = owner(s);
    const std::byte name[2] = {std::byte{'k'}, std::byte{'0'}};
    KeyRef ref;
    ref.raw = std::span<const std::byte>(name, 2);
    const std::array<KeyRef, 1> refs{ref};
    // The client holds a BufRef into this buffer until the job is released; on a hang run_op returns
    // early, so the buffer is heap-owned and parked in quarantine_ (never freed while the Client lives).
    auto bufp = std::make_shared<Bytes>(op == kPut ? payload(s, version_.load()) : Bytes(kLen, std::byte{0xAA}));
    Bytes& buf = *bufp;
    std::vector<BufRef> bufs{{std::span<std::byte>(buf)}};
    const auto t0 = Clk::now();
    r.start_us = std::chrono::duration_cast<std::chrono::microseconds>(t0 - epoch_).count();
    Ticket t = op == kPut     ? cl_->store(scope_keys(s), 0, refs, bufs, kPutTo)
               : op == kLook  ? cl_->lookup(scope_keys(s), 0, refs, kLookTo)
                              : cl_->fetch(scope_keys(s), 0, refs, bufs, kFetchTo);
    Completion c;
    const milliseconds to = op == kPut ? kPutTo : op == kLook ? kLookTo : kFetchTo;
    if (!await(t, c, to + kMargin + seconds(5))) {
      r.hang = true;
      {
        std::lock_guard lk(mu_);
        quarantine_.push_back(bufp);
      }
      r.lat_us = std::chrono::duration_cast<std::chrono::microseconds>(Clk::now() - t0).count();
      return r;
    }
    r.lat_us = std::chrono::duration_cast<std::chrono::microseconds>(Clk::now() - t0).count();
    r.st = c.status.size() == 1 ? c.status[0] : KeyStatus::Aborted;
    if (op == kFetch && r.st == KeyStatus::Hit) {
      r.ver = version_of(buf);
      if (r.ver < 0 || r.ver > version_.load() || buf != payload(s, r.ver)) r.bad_bytes = true;
    }
    return r;
  }

  void start_traffic() {
    run_ = true;
    for (int t = 0; t < kThreads; ++t) {
      workers_.emplace_back([this, t] {
        std::uint64_t x = 0x9E3779B97F4A7C15ull * static_cast<std::uint64_t>(t + 1);
        for (std::uint64_t i = 0; run_; ++i) {
          x ^= x << 13;
          x ^= x >> 7;
          x ^= x << 17;
          const int s = 1 + static_cast<int>(x % static_cast<std::uint64_t>(scopes_));
          recs_[t].push_back(run_op(static_cast<int>(i % 3), s));
        }
      });
    }
  }
  void stop_traffic() {
    run_ = false;
    for (auto& w : workers_)
      if (w.joinable()) w.join();
    workers_.clear();
  }
  void start_watcher(std::size_t victim) {
    watch_ = true;
    watcher_ = std::thread([this, victim] {
      while (watch_) {
        const auto s = cl_->wire_port(victim)->session();
        if (s != WirePort::Session::Up) {
          std::int64_t exp = -1;
          down_seen_us_.compare_exchange_strong(exp, now_us());
          state_seen_ |= s == WirePort::Session::Down ? 1 : 2;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(500));
      }
    });
  }
  void stop_watcher() {
    watch_ = false;
    if (watcher_.joinable()) watcher_.join();
  }
  void stop_dispatcher() {
    disp_run_ = false;
    if (disp_.joinable()) disp_.join();
  }
  std::int64_t now_us() const { return std::chrono::duration_cast<std::chrono::microseconds>(Clk::now() - epoch_).count(); }

  static double pct(std::vector<std::int64_t> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return static_cast<double>(v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))]);
  }

  pid_t pid_[kMaxNodes] = {-1, -1, -1};
  bool last_stop_graceful_ = false;  // the last stop(): the process exited by itself with status 0 (no SIGKILL)
  std::string dir_;
  std::unique_ptr<Client> cl_;
  std::shared_ptr<TestKeys> keys_ = std::make_shared<TestKeys>();
  std::vector<PlaceNode> places_;      // the ids learned at open: classifies every op that ran before the restart
  std::vector<PlaceNode> places_new_;  // the ids after the restart (the anon store drew a new one), set once traffic stopped
  std::vector<std::string> addrs_;
  int scopes_ = 0;
  Clk::time_point epoch_ = Clk::now();
  std::mutex mu_;
  std::condition_variable cv_;
  std::map<std::uint64_t, Completion> done_;
  std::thread disp_;
  std::atomic<bool> disp_run_{false}, run_{false};
  std::vector<std::thread> workers_;
  std::vector<Rec> recs_[kThreads];
  std::atomic<int> version_{0};  // Payload version, bumped to 1 right before the memnode restart
  std::vector<std::shared_ptr<Bytes>> quarantine_;  // Buffers of ops that hung (guarded by mu_)
  std::thread watcher_;                              // Fixture member, joined in TearDown
  std::atomic<bool> watch_{false};
  std::atomic<std::int64_t> down_seen_us_{-1};
  std::atomic<int> state_seen_{0};  // bit0 Down, bit1 Connecting
};

TEST_P(ReconnectTraffic, KillMemnodeMidTrafficThenRestartIt) {
  const std::string dev = std::get<0>(GetParam());
  const int n_nodes = std::get<1>(GetParam());
  const int sig = std::get<2>(GetParam());
  const int victim = n_nodes == 1 ? 0 : 1;  // node id 2 of 3
  scopes_ = n_nodes == 1 ? 64 : 300;

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
  char t[] = "/tmp/mira-e2e-rt-XXXXXX";
  ASSERT_NE(::mkdtemp(t), nullptr);
  dir_ = t;
  const std::string pki = dir_ + "/pki";
  ASSERT_EQ(std::system(("bash " + std::string(MIRACACHE_LAB_CERTS_SH) + " " + pki + " --nodes 1,2,3 --clients 1 >/dev/null").c_str()), 0);

  std::uint16_t rdma_port[kMaxNodes], admin_port[kMaxNodes];
  for (int i = 0; i < n_nodes; ++i) {
    rdma_port[i] = free_port();
    admin_port[i] = free_port();
    const std::string n = std::to_string(i + 1);
    std::ofstream f(dir_ + "/node" + n + ".toml");
    // drain_ms: SIGTERM sends GOAWAY and waits for the sessions to leave, at most 2 s (stop() allows 5 s).
    f << "[node]\ndrain_ms = 2000\ndevice = \"" << dev << "\"\nlisten = [\"" << ip << ":" << rdma_port[i] << "\"]\nstate_dir = \"" << dir_ << "/state" << n << "\"\n"
      << "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\nn_segments = 4\n"
      << "max_scopes = 1000\nmax_bytes = 8388608\n"
      << "[lab]\nprincipal = \"lab\"\nidentities = [\"spiffe://lab/client-1\"]\n"
      << "[admin]\nlisten = \"127.0.0.1:" << admin_port[i] << "\"\ncert = \"" << pki << "/node-" << n << ".pem\"\nkey = \"" << pki
      << "/node-" << n << ".key\"\nca = \"" << pki << "/ca.pem\"\n"
      << "[telemetry]\nlisten = \"\"\n";
  }
  for (int i = 0; i < n_nodes; ++i) ASSERT_TRUE(start(i));

  std::ostringstream toml;
  toml << "[scope]\nsecret_file = \"unused\"\n";
  for (int i = 0; i < n_nodes; ++i) {
    toml << "[[nodes]]\nweight = 1\nrails = [\"" << ip << ":" << rdma_port[i] << "\"]\n"
         << "admin = \"127.0.0.1:" << admin_port[i] << "\"\nidentity = \"spiffe://lab/node-" << i + 1 << "\"\n";
    addrs_.push_back(ip + ":" + std::to_string(rdma_port[i]));
  }
  toml << "[tls]\ncert = \"" << pki << "/client-1.pem\"\nkey = \"" << pki << "/client-1.key\"\nca = \"" << pki << "/ca.pem\"\n"
       << "[fabric]\ndevice = \"" << dev << "\"\nkeepalive_ms = 100\nreconnect_min_ms = 50\nreconnect_max_ms = 500\n"
       << "[landing]\nsubpool_bytes = 8388608\n[lab]\nstatic_membership = true\n";
  auto cfg = load_config(toml.str());
  ASSERT_TRUE(cfg) << cfg.error().context;
  NoProvider prov;
  auto cl = Client::open(*cfg, prov);
  ASSERT_TRUE(cl) << cl.error().context;
  cl_ = std::move(*cl);
  ASSERT_EQ(cl_->node_count(), static_cast<std::size_t>(n_nodes));
  places_ = e2e::learned_places(cl_->metrics_text(), addrs_, std::vector<std::uint32_t>(addrs_.size(), 1));
  for (const auto& p : places_) ASSERT_NE(p.id, "0") << "the client did not learn every node id";
  const std::string vlabel = n_nodes == 1 ? std::string() : "node=\"" + addrs_[static_cast<std::size_t>(victim)] + "\"";

  epoch_ = Clk::now();
  start_dispatcher();
  // Fill every scope so that before the outage lookups and fetches hit.
  const auto fill_by = Clk::now() + kFillCap;
  for (int s = 1; s <= scopes_; ++s) {
    ASSERT_LT(Clk::now(), fill_by) << "fill phase exceeded " << kFillCap.count() << " s at scope " << s;
    Rec r = run_op(kPut, s);
    ASSERT_FALSE(r.hang);
    ASSERT_TRUE(r.st == KeyStatus::Committed || r.st == KeyStatus::Skipped) << "scope " << s << " status " << static_cast<int>(r.st);
  }
  ASSERT_EQ(metric_sum(cl_->metrics_text(), "miracache_client_session_up", vlabel), 1) << cl_->metrics_text();
  if (const char* np = std::getenv("MIRA_RT_PUT_LAT"); np && n_nodes == 1) {
    // Measurement hook (off by default): N sequential puts into fresh scopes (each commits), client-side
    // store() latency including the server's commit digest. N <= 900 (the node holds 1000 scopes).
    const int n = std::min(900, std::atoi(np));
    std::vector<std::int64_t> lat;
    for (int i = 0; i < n; ++i) {
      Rec r = run_op(kPut, 1000 + i);
      ASSERT_FALSE(r.hang);
      if (r.st == KeyStatus::Committed) lat.push_back(r.lat_us);
    }
    std::sort(lat.begin(), lat.end());
    if (!lat.empty())
      std::cout << "[PUTLAT] n=" << lat.size() << " p50_us=" << lat[lat.size() / 2] << " p99_us=" << lat[lat.size() * 99 / 100]
                << " max_us=" << lat.back() << "\n";
  }
  const std::uint64_t attempts0 = cl_->wire_port(static_cast<std::size_t>(victim))->connect_attempts();

  start_traffic();
  std::this_thread::sleep_for(seconds(2));  // baseline

  // ---- kill / stop the memnode mid-traffic ----
  const std::int64_t t_kill = now_us();
  start_watcher(static_cast<std::size_t>(victim));  // Member thread, joined in TearDown on every path
  stop(victim, sig);
  const std::int64_t t_stopped = now_us();
  if (sig == SIGTERM) {
    // A graceful drain is expected: GOAWAY went out, the client left, the process exited by itself with
    // status 0 inside drain_ms (+ margin), never needing the SIGKILL fallback. (Before the drain existed,
    // SIGTERM stopped the loop at once, which the old version of this test could not tell from a drain.)
    EXPECT_TRUE(last_stop_graceful_) << "memnode did not exit cleanly after SIGTERM";
    EXPECT_LT(t_stopped - t_kill, 3'000'000) << "drain took longer than drain_ms + margin";
    const std::string mlog = slurp(dir_ + "/memnode" + std::to_string(victim + 1) + ".log");
    EXPECT_NE(mlog.find("GOAWAY sent"), std::string::npos) << mlog;
    EXPECT_NE(mlog.find("drain complete"), std::string::npos) << "the client should have left on GOAWAY:\n" << mlog;
  }
  const auto detect_by = Clk::now() + kDetectCap;
  while (down_seen_us_.load() < 0 && Clk::now() < detect_by) std::this_thread::sleep_for(milliseconds(10));
  ASSERT_GE(down_seen_us_.load(), 0) << "client never noticed the dead node";
  const std::int64_t t_win0 = std::max(down_seen_us_.load(), t_stopped);
  std::cout << "[RT] signal=" << sig << " nodes=" << n_nodes << " detect_ms=" << (down_seen_us_.load() - t_kill) / 1000.0
            << " stop_returned_ms=" << (t_stopped - t_kill) / 1000.0 << "\n";

  // Outage dwell with traffic running: reconnect attempts fail against the dead port.
  std::this_thread::sleep_for(seconds(3));
  const std::string m_down = cl_->metrics_text();
  EXPECT_EQ(metric_sum(m_down, "miracache_client_session_up", vlabel), 0) << m_down;
  EXPECT_GE(metric_sum(m_down, "miracache_client_reconnect_total", vlabel), 1) << m_down;
  EXPECT_GE(metric_sum(m_down, "miracache_client_reconnect_fail_total", vlabel), 1) << m_down;
  EXPECT_GT(cl_->wire_port(static_cast<std::size_t>(victim))->connect_attempts(), attempts0);
  EXPECT_NE(cl_->wire_port(static_cast<std::size_t>(victim))->session(), WirePort::Session::Up);

  // ---- restart on the same port (empty cache; the state file is deleted, so it is a replaced node with a new ID) ----
  std::filesystem::remove(dir_ + "/state" + std::to_string(victim + 1) + "/node-id");
  const std::int64_t t_win1 = now_us();
  version_ = 1;  // Every put from here on carries v1; a v0 hit on the victim's scopes would be a stale read
  const std::int64_t t_bump = now_us();
  ASSERT_TRUE(start(victim));
  const std::int64_t t_listening = now_us();
  const auto up_by = Clk::now() + kRecoverCap;
  while (cl_->wire_port(static_cast<std::size_t>(victim))->session() != WirePort::Session::Up && Clk::now() < up_by)
    std::this_thread::sleep_for(milliseconds(5));
  const std::int64_t t_up = now_us();
  ASSERT_EQ(cl_->wire_port(static_cast<std::size_t>(victim))->session(), WirePort::Session::Up) << "no reconnect after the restart";
  stop_watcher();
  std::cout << "[RT] recovery_ms=" << (t_up - t_listening) / 1000.0 << " (memnode listening -> session Up, no reopen)\n";
  // No EXPECT_LT(recovery, kRecoverCap) here: the wait loop above already stops at kRecoverCap and the
  // ASSERT_EQ(Up) is the real check; the measured recovery_ms is printed for the report.
  // The watcher saw the session go Down AND pass through Connecting (not a tautology).
  EXPECT_EQ(state_seen_.load(), 3) << "Down and Connecting must both have been observed (bit0 Down, bit1 Connecting)";
  std::this_thread::sleep_for(seconds(2));  // traffic keeps running after recovery
  stop_traffic();
  // Plan 2C: the replaced node (state file deleted) drew a new random node id and the client adopted it at the reconnect, so
  // the scopes the victim owns now are a different set. Ops that ran before use the ids from the open.
  places_new_ = e2e::learned_places(cl_->metrics_text(), addrs_, std::vector<std::uint32_t>(addrs_.size(), 1));
  for (const auto& p : places_new_) ASSERT_NE(p.id, "0");
  auto owner_new = [&](int s) {
    return static_cast<int>(place_owner(places_new_, std::span<const std::uint8_t, 32>(scope_keys(s).scopes[0].b)));
  };

  // ---- post-recovery sync checks: new puts and fetches succeed, metrics show the recovery ----
  int vs = 0;
  const auto post_by = Clk::now() + kPostCap;
  for (int s = 1; s <= scopes_; ++s) {
    if (n_nodes > 1 && owner_new(s) != victim) continue;
    ASSERT_LT(Clk::now(), post_by) << "post-recovery checks exceeded " << kPostCap.count() << " s";
    ++vs;
    Rec p = run_op(kPut, s);
    EXPECT_TRUE(p.st == KeyStatus::Committed || p.st == KeyStatus::Skipped) << "put scope " << s << " " << static_cast<int>(p.st);
    Rec f = run_op(kFetch, s);
    EXPECT_EQ(f.st, KeyStatus::Hit) << "fetch scope " << s;
    EXPECT_FALSE(f.bad_bytes) << "scope " << s;
    EXPECT_EQ(f.ver, 1) << "scope " << s << ": the restarted node served data from before its restart";
  }
  EXPECT_GT(vs, 10);
  const std::string m_up = cl_->metrics_text();
  EXPECT_EQ(metric_sum(m_up, "miracache_client_session_up", vlabel), 1) << m_up;
  EXPECT_GE(metric_sum(m_up, "miracache_client_reconnect_total", vlabel), 1);
  std::cout << "[RT] metrics: reconnect_total=" << metric_sum(m_up, "miracache_client_reconnect_total", vlabel)
            << " reconnect_fail_total=" << metric_sum(m_up, "miracache_client_reconnect_fail_total", vlabel)
            << " connect_attempts=" << cl_->wire_port(static_cast<std::size_t>(victim))->connect_attempts() << " (was " << attempts0 << ")\n";
  stop_dispatcher();

  // ---- analyse the traffic records ----
  std::vector<Rec> all;
  for (auto& v : recs_) all.insert(all.end(), v.begin(), v.end());
  std::int64_t max_lat_all = 0, max_lat_win = 0;
  std::size_t win_victim = 0, win_other = 0, hangs = 0, bad = 0, over = 0, stale = 0;
  std::vector<std::int64_t> lat_before_other, lat_during_other, lat_trans_other;
  std::map<int, std::size_t> win_status[3];
  for (const Rec& r : all) {
    if (r.hang) ++hangs;
    if (r.bad_bytes) ++bad;
    const std::int64_t cap_us =
        std::chrono::duration_cast<std::chrono::microseconds>((r.op == kPut ? kPutTo : r.op == kLook ? kLookTo : kFetchTo) + kMargin).count();
    if (r.lat_us > cap_us) {
      ++over;
      ADD_FAILURE() << op_name(r.op) << " scope " << r.scope << " took " << r.lat_us / 1000.0 << " ms (cap " << cap_us / 1000.0 << ")";
    }
    max_lat_all = std::max(max_lat_all, r.lat_us);
    const bool in_win = r.start_us >= t_win0 && r.start_us < t_win1;
    const bool is_victim = r.owner == victim;
    if (in_win && is_victim) {
      ++win_victim;
      max_lat_win = std::max(max_lat_win, r.lat_us);
      ++win_status[r.op][static_cast<int>(r.st)];
      // started while the node is down: it must fail cleanly, quickly
      if (r.op == kPut)
        EXPECT_TRUE(r.st == KeyStatus::Refused || r.st == KeyStatus::Timeout || r.st == KeyStatus::Aborted) << "put " << r.scope << " st " << static_cast<int>(r.st);
      else
        EXPECT_TRUE(r.st == KeyStatus::Miss || r.st == KeyStatus::Timeout || r.st == KeyStatus::Aborted) << op_name(r.op) << " " << r.scope << " st " << static_cast<int>(r.st);
      EXPECT_LT(r.lat_us, std::chrono::duration_cast<std::chrono::microseconds>(kFailFast).count())
          << op_name(r.op) << " scope " << r.scope << " did not fail fast";
    }
    if (n_nodes > 1 && !is_victim) {
      if (in_win) ++win_other;
      // Other nodes' scopes succeed throughout (whole run). After the restart a scope whose owner changed with
      // the victim's new id is a cold miss by design: only the scopes that did not move are asserted from then on.
      const bool moved = r.start_us >= t_bump && owner_new(r.scope) != r.owner;
      if (r.op == kPut) EXPECT_TRUE(r.st == KeyStatus::Committed || r.st == KeyStatus::Skipped) << "other-node put " << r.scope << " st " << static_cast<int>(r.st);
      else if (moved) {}
      else if (r.op == kLook) EXPECT_EQ(r.st, KeyStatus::Hit) << "other-node lookup " << r.scope;
      else EXPECT_EQ(r.st, KeyStatus::Hit) << "other-node fetch " << r.scope;
      if (r.start_us < t_kill) lat_before_other.push_back(r.lat_us);
      else if (in_win) lat_during_other.push_back(r.lat_us);
      // The whole transition, kill -> Up again, includes detection and recovery (reconnect on the
      // victim's keepalive thread, restart of the process) which the outage window alone leaves out.
      if (r.start_us >= t_kill && r.start_us <= t_up) lat_trans_other.push_back(r.lat_us);
    }
    // A victim-owned fetch that started after the restart can only hit v1 data.
    if (is_victim && r.op == kFetch && r.st == KeyStatus::Hit && r.start_us >= t_bump && r.ver != 1) ++stale;
  }
  EXPECT_EQ(stale, 0u) << "a fetch served v0 data from a node whose cache was emptied by the restart";
  EXPECT_EQ(hangs, 0u);
  EXPECT_EQ(bad, 0u) << "a fetch returned wrong bytes";
  EXPECT_EQ(over, 0u);
  EXPECT_GT(win_victim, 30u) << "too little traffic hit the dead node's scopes during the outage";
  std::cout << "[RT] ops=" << all.size() << " outage_window_ms=" << (t_win1 - t_win0) / 1000.0 << " victim_ops_in_window=" << win_victim
            << " max_latency_ms_all=" << max_lat_all / 1000.0 << " max_latency_ms_victim_ops_in_window=" << max_lat_win / 1000.0 << "\n";
  for (int o = 0; o < 3; ++o) {
    std::cout << "[RT]   victim " << op_name(o) << " statuses in window:";
    for (auto& [k, v] : win_status[o]) std::cout << " " << k << "=" << v;  // 0 hit 1 miss 2 committed 3 skipped 4 refused 5 aborted 6 timeout
    std::cout << "\n";
  }
  if (n_nodes > 1) {
    ASSERT_GT(lat_before_other.size(), 200u);
    ASSERT_GT(lat_during_other.size(), 200u);
    const double b50 = pct(lat_before_other, 0.5), b99 = pct(lat_before_other, 0.99);
    const double d50 = pct(lat_during_other, 0.5), d99 = pct(lat_during_other, 0.99);
    ASSERT_GT(lat_trans_other.size(), 200u);
    const double t50 = pct(lat_trans_other, 0.5), t99 = pct(lat_trans_other, 0.99);
    const double bound = kP99Mul * b99 + kP99SlackUs;
    std::cout << "[RT] other nodes: before n=" << lat_before_other.size() << " p50_us=" << b50 << " p99_us=" << b99 << "; during outage n="
              << lat_during_other.size() << " p50_us=" << d50 << " p99_us=" << d99 << "; transition [kill,Up] n=" << lat_trans_other.size()
              << " p50_us=" << t50 << " p99_us=" << t99 << " max_us=" << pct(lat_trans_other, 1.0) << " (bound " << bound << " us)\n";
    // Honest bound: p99 over the outage window AND over the whole transition stays within kP99Mul x the
    // before-outage p99 plus kP99SlackUs (2 CPUs shared by memnodes, keepalive threads and 4 traffic threads).
    EXPECT_LE(d99, bound) << "other nodes' p99 degraded during the outage";
    EXPECT_LE(t99, bound) << "other nodes' p99 degraded across the kill -> recovery transition";
    EXPECT_GT(win_other, 200u);
  }
}

INSTANTIATE_TEST_SUITE_P(
    Device, ReconnectTraffic,
    ::testing::Combine(::testing::ValuesIn(devices()), ::testing::Values(1, 3), ::testing::Values(SIGKILL, SIGTERM)),
    [](const ::testing::TestParamInfo<std::tuple<std::string, int, int>>& i) {
      return std::get<0>(i.param) + "_" + std::to_string(std::get<1>(i.param)) + "node_" + (std::get<2>(i.param) == SIGKILL ? "SIGKILL" : "SIGTERM");
    });

}  // namespace
}  // namespace miracache
