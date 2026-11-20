// SPDX-License-Identifier: Apache-2.0
// Multi-rail end to end on rxe0 (label `rdma`).
//
// Real processes: mira-memnode x 3 in BUNDLE mode, each with TWO rails on rxe0 ([[node.rails]]: eth0's address and the lab's
// second address 10.98.0.1 from the lab RDMA setup script, one port per node) and the real Go mirctl publishing the bundle. One
// in-process C++ Client in bundle mode with `nodes[].admin` only: it learns the rails from each node's identity and takes one
// admin ticket per rail. Four traffic threads (fetch 256 KiB blocks cut into 64 KiB slices, plus puts and
// lookups) run under the FAULT oracle (tests/util/oracle.h).
//
// Windows (traffic never stops):
//   1 baseline      both rails up: both carry slices
//   2 rail down     the second rail's address is deleted (`ip addr del`, a real GID drop and QP errors through the flush path):
//                   the rail goes Suspect/Down, the other rail carries everything, slices on the lost rail are re-issued
//   3 rail restored the address comes back: the client rail reconnects on its own backoff and carries slices again
//   4 steady        both rails up again
// What it reports: per-rail READ bytes per window (miracache_client_fetch_rail_bytes_total), slices re-issued, oracle line,
// p50 / p99 per op kind per window, and every rail state transition the client showed (miracache_client_rail_state).
//
// The dev container has no NET_ADMIN, so the address changes go through the rail fault agent script running on the host
// (a shared directory <build>/rail-fault). Without a fresh agent heartbeat the test skips.
// WHAT THIS CANNOT PROVE: both rails are soft-RoCE on one device in one VM. Link speeds are equal, so the weighted spread is
// 1:1 by construction; there is no second NIC, no real link-down, no PFC / ECN, and the VM's CPU is the bottleneck, so
// the bytes and latencies only compare windows with each other. Real 2 x NIC runs are hardware-gated.
#include <arpa/inet.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "fabric/verbs_cm/verbs_cm_fabric.h"
#include "free_port.h"
#include "scope/engine_native.h"
#include "src/client.h"
#include "util/oracle.h"

extern char** environ;

namespace miracache {
namespace {

namespace fs = std::filesystem;
using Bytes = std::vector<std::byte>;
using Clk = std::chrono::steady_clock;
using std::chrono::milliseconds;
using std::chrono::seconds;
using testutil::Oracle;
using testutil::OracleMode;

constexpr int kThreads = 4;
constexpr int kNodes = 3;
constexpr int kScopes = 24;  // 6 per thread
constexpr int kSlots = 4;    // keys per scope: 96 blocks of 256 KiB = 24 MiB over three nodes
constexpr std::size_t kLen = 256 * 1024;
constexpr std::size_t kSlice = 64 * 1024;  // fabric.slice_bytes: four slices per block
constexpr milliseconds kPutTo{3000}, kLookTo{1000}, kFetchTo{3000};
constexpr milliseconds kMargin{1000};
constexpr std::size_t kPool = 8u << 20;
constexpr const char* kRail2Ip = "10.98.0.1";  // the lab RDMA setup script
// Rail 2's real subnet ([[node.rails]].subnet). Rail 1 leaves it to the node, which reports its address's /24. The client
// has one device (rxe0 carries both addresses) with no subnet: a wildcard, so it pairs both rails.
constexpr const char* kRail2Subnet = "10.98.0.0/24";

std::string slurp(const std::string& p) {
  std::ifstream f(p);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

struct Rec {
  std::int64_t start_us = 0, lat_us = 0;
  int op = 0;  // 0 put, 1 lookup, 2 fetch
  KeyStatus st = KeyStatus::Miss;
  bool hang = false, excused = false;
};
const char* op_name(int o) { return o == 0 ? "put" : o == 1 ? "lookup" : "fetch"; }

// The label value `name="..."` of a metrics line, or "".
std::string label_of(const std::string& line, const std::string& name) {
  const std::string k = name + "=\"";
  const auto p = line.find(k);
  if (p == std::string::npos) return {};
  const auto e = line.find('"', p + k.size());
  return line.substr(p + k.size(), e - p - k.size());
}

struct RailSample {
  std::string key;  // node label + rail + addr
  int rail = 0;
  double value = 0;
};
// Every sample of the family `name` (name{labels} value).
std::vector<RailSample> family(const std::string& text, const std::string& name) {
  std::vector<RailSample> out;
  std::istringstream in(text);
  for (std::string line; std::getline(in, line);) {
    if (line.rfind(name + "{", 0) != 0) continue;
    RailSample s;
    s.rail = std::atoi(label_of(line, "rail").c_str());
    s.key = "node " + label_of(line, "node_id") + " rail " + label_of(line, "rail") + " " + label_of(line, "addr");
    s.value = std::strtod(line.c_str() + line.rfind(' ') + 1, nullptr);
    out.push_back(s);
  }
  return out;
}

class MultiRailE2e : public ::testing::TestWithParam<std::string> {
 protected:
  void TearDown() override {
    stop_traffic();
    stop_sampler();
    disp_run_ = false;
    if (disp_.joinable()) disp_.join();
    if (rail_down_) fault("add");
    if (cl_) cl_->shutdown();
    cl_.reset();
    prov_.reset();
    for (int i = 0; i < kNodes; ++i) kill_proc(node_[i], SIGTERM);
    if (HasFailure() && !dir_.empty())
      for (int i = 0; i < kNodes; ++i) {
        const std::string s = slurp(tag("memnode", i + 1));
        std::fprintf(stderr, "---- memnode %d log (tail) ----\n%s\n", i + 1, s.substr(s.size() > 6000 ? s.size() - 6000 : 0).c_str());
      }
    if (!dir_.empty()) (void)std::system(("rm -rf " + dir_).c_str());
  }

  // ---- processes ----
  static pid_t spawn(const std::vector<std::string>& args, const std::string& log) {
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, STDOUT_FILENO, log.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    posix_spawn_file_actions_adddup2(&fa, STDOUT_FILENO, STDERR_FILENO);
    std::vector<char*> argv;
    for (const auto& a : args) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, argv[0], &fa, nullptr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    if (rc != 0) {
      ADD_FAILURE() << "posix_spawn(" << args[0] << ") failed: " << std::strerror(rc);
      return -1;
    }
    return pid;
  }
  static void kill_proc(pid_t& pid, int sig) {
    if (pid <= 0) return;
    ::kill(pid, sig);
    int st = 0;
    pid_t r = 0;
    for (int k = 0; k < 100 && (r = ::waitpid(pid, &st, WNOHANG)) == 0; ++k) std::this_thread::sleep_for(milliseconds(50));
    if (r == 0) {
      ::kill(pid, SIGKILL);
      ::waitpid(pid, &st, 0);
    }
    pid = -1;
  }
  static int wait_exit(pid_t pid, seconds cap) {
    const auto until = Clk::now() + cap;
    int st = 0;
    while (Clk::now() < until) {
      if (::waitpid(pid, &st, WNOHANG) == pid) return WIFEXITED(st) ? WEXITSTATUS(st) : 128 + WTERMSIG(st);
      std::this_thread::sleep_for(milliseconds(20));
    }
    ::kill(pid, SIGKILL);
    ::waitpid(pid, &st, 0);
    return -1;
  }
  int run_tool(const std::vector<std::string>& args, const std::string& log, seconds cap = seconds(90)) {
    pid_t pid = spawn(args, log);
    return pid < 0 ? -1 : wait_exit(pid, cap);
  }
  bool wait_log(const std::string& log, pid_t pid, const std::string& needle, seconds cap) {
    const auto until = Clk::now() + cap;
    while (Clk::now() < until) {
      if (slurp(log).find(needle) != std::string::npos) return true;
      int st = 0;
      if (::waitpid(pid, &st, WNOHANG) == pid) {
        ADD_FAILURE() << "process exited early (" << log << "):\n" << slurp(log);
        return false;
      }
      std::this_thread::sleep_for(milliseconds(50));
    }
    ADD_FAILURE() << "no '" << needle << "' in " << log << ":\n" << slurp(log);
    return false;
  }
  std::string tag(const char* what, int i) const { return dir_ + "/" + what + std::to_string(i) + ".log"; }
  std::string pki() const { return dir_ + "/pki"; }
  std::string admin(int i) const { return "127.0.0.1:" + std::to_string(admin_port_[i]); }

  // ---- the host-side fault agent ----
  static std::string fault_dir() { return MIRA_RAIL_FAULT_DIR; }
  // The agent writes a counter it bumps every loop (0.2 s); it is alive when the counter moves within 3 s. No
  // clock is compared (an mtime against this container's clock failed on host/VM skew).
  static bool agent_fresh() {
    const std::string hb = fault_dir() + "/agent";
    if (!fs::exists(hb)) return false;
    const std::string first = slurp(hb);
    const auto until = Clk::now() + seconds(3);
    while (Clk::now() < until) {
      std::this_thread::sleep_for(milliseconds(100));
      const std::string now = slurp(hb);
      if (!now.empty() && now != first) return true;
    }
    return false;
  }
  // "del" or "add" of the rail-2 address; true when the agent answered rc=0.
  bool fault(const std::string& op) {
    const std::string req = fault_dir() + "/req", ack = fault_dir() + "/ack";
    std::remove(ack.c_str());
    std::ofstream(req + ".tmp") << op;
    fs::rename(req + ".tmp", req);
    const auto until = Clk::now() + seconds(30);
    while (Clk::now() < until) {
      if (fs::exists(ack)) {
        const std::string a = slurp(ack);
        std::remove(ack.c_str());
        if (op == "del") rail_down_ = a.find("rc=0") != std::string::npos;
        if (op == "add") rail_down_ = false;
        return a.find("rc=0") != std::string::npos;
      }
      std::this_thread::sleep_for(milliseconds(50));
    }
    return false;
  }
  static bool has_addr(const char* want) {
    ifaddrs* list = nullptr;
    if (getifaddrs(&list) != 0) return false;
    bool found = false;
    for (ifaddrs* a = list; a != nullptr; a = a->ifa_next) {
      if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_INET) continue;
      char buf[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in*>(a->ifa_addr)->sin_addr, buf, sizeof buf) != nullptr && std::string(buf) == want) found = true;
    }
    freeifaddrs(list);
    return found;
  }

  // ---- bring-up ----
  bool start_node(int i) {
    node_[i] = spawn({MIRA_MEMNODE_BIN, "--config", dir_ + "/node" + std::to_string(i + 1) + ".toml"}, tag("memnode", i + 1));
    return node_[i] > 0 && wait_log(tag("memnode", i + 1), node_[i], "listening", seconds(15));
  }
  bool publish(const std::string& reason) {
    {
      std::ofstream f(dir_ + "/cluster.toml");
      f << "reason = \"" << reason << "\"\n";
      for (int i = 0; i < kNodes; ++i) f << "[[nodes]]\nadmin = \"" << admin(i) << "\"\nweight = 1\n";
      f << "[[principals]]\nname = \"lab\"\nidentities = [\"spiffe://lab/client-1\"]\nquota_bytes = 1073741824\nmax_scopes = 100000\n"
        << "[[rbac]]\nidentity = \"spiffe://lab/client-3\"\nroles = [\"operator\", \"security-admin\"]\n"
        << "[config.cluster.placement]\nreplicas = 1\n"
        << "[config.cluster.memnode.store]\nmax_scopes = 100000\nmax_bytes = 67108864\n"
        << "[config.cluster.memnode.lease]\nttl_s = 30\nmax_s = 60\nput_timeout_s = 12\n"
        << "[config.cluster.client.landing]\nsubpool_bytes = " << kPool << "\n"
        << "[config.cluster.client.fabric]\nslice_bytes = " << kSlice << "\n";
    }
    std::vector<std::string> pub{MIRCTL_BIN, "bundle", "publish", "--source", dir_ + "/cluster.toml", "--key", dir_ + "/key.seed", "--sec-key",
                                 dir_ + "/key.seed", "--trust", dir_ + "/trust.toml", "--cert", pki() + "/client-3.pem", "--tls-key",
                                 pki() + "/client-3.key", "--ca", pki() + "/ca.pem"};
    if (run_tool(pub, dir_ + "/publish.log") != 0) {
      ADD_FAILURE() << "mirctl bundle publish:\n" << slurp(dir_ + "/publish.log");
      return false;
    }
    return true;
  }

  bool bring_up(const std::string& dev) {
    if (!agent_fresh()) {
      skip_ = "no rail fault agent (host: the rail fault agent script, started on <build>/rail-fault); the container cannot run `ip addr del`";
      return false;
    }
    if (!has_addr(kRail2Ip)) {
      skip_ = std::string("the lab's second address ") + kRail2Ip + " is missing (the lab RDMA setup script)";
      return false;
    }
    {
      fabric::VerbsOptions vo;
      vo.device = dev;
      auto f = fabric::VerbsCmFabric::open(vo);
      if (!f) {
        skip_ = std::string("no usable RDMA device: ") + f.error().context;
        return false;
      }
      auto a = (*f)->device_ipv4();
      if (!a) {
        skip_ = std::string("device has no IPv4 address: ") + a.error().context;
        return false;
      }
      ip_ = *a;
      if (ip_ == kRail2Ip) {
        skip_ = "the device's first address is the lab's second one";
        return false;
      }
    }
    char t[] = "/tmp/mira-rl4-XXXXXX";
    if (::mkdtemp(t) == nullptr) return false;
    dir_ = t;
    if (std::system(("bash " + std::string(MIRACACHE_LAB_CERTS_SH) + " " + pki() + " --nodes 1,2,3 --clients 1,2,3 >/dev/null").c_str()) != 0) {
      ADD_FAILURE() << "lab-certs failed";
      return false;
    }
    if (run_tool({MIRCTL_BIN, "keys", "gen", "--out", dir_ + "/key.seed", "--roles", "publish,security"}, dir_ + "/keygen.log") != 0) {
      ADD_FAILURE() << "mirctl keys gen:\n" << slurp(dir_ + "/keygen.log");
      return false;
    }
    {
      const std::string out = slurp(dir_ + "/keygen.log");
      const auto p = out.find("[[key]]");
      if (p == std::string::npos) {
        ADD_FAILURE() << "no [[key]] in:\n" << out;
        return false;
      }
      std::ofstream(dir_ + "/trust.toml") << out.substr(p);
    }
    for (int i = 0; i < kNodes; ++i) {
      rdma_port_[i] = free_port();
      admin_port_[i] = free_port();
      metrics_port_[i] = free_port();
      const std::string n = std::to_string(i + 1);
      std::ofstream f(dir_ + "/node" + n + ".toml");
      // Two rails on one device: the legacy address (subnet derived: its /24) and the lab's second address, one port.
      f << "[node]\nstate_dir = \"" << dir_ << "/state" << n << "\"\n"
        << "[[node.rails]]\ndevice = \"" << dev << "\"\nlisten = \"" << ip_ << ":" << rdma_port_[i] << "\"\n"
        << "[[node.rails]]\ndevice = \"" << dev << "\"\nlisten = \"" << kRail2Ip << ":" << rdma_port_[i] << "\"\nsubnet = \"" << kRail2Subnet << "\"\n"
        << "[store]\nbacking = \"anon\"\nsegment_bytes = 16777216\nrun_bytes = 1048576\nmin_block_bytes = 4096\nn_segments = 4\n"
        << "[admin]\nlisten = \"127.0.0.1:" << admin_port_[i] << "\"\ncert = \"" << pki() << "/node-" << n << ".pem\"\nkey = \"" << pki()
        << "/node-" << n << ".key\"\nca = \"" << pki() << "/ca.pem\"\n"
        << "[telemetry]\nlisten = \"127.0.0.1:" << metrics_port_[i] << "\"\n"
        << "[control]\ntrust_keys = \"" << dir_ << "/trust.toml\"\n";
    }
    for (int i = 0; i < kNodes; ++i)
      if (!start_node(i)) return false;
    if (run_tool({MIRCTL_BIN, "secret", "gen", "--out", dir_ + "/secret"}, dir_ + "/secret.log") != 0) {
      ADD_FAILURE() << "mirctl secret gen:\n" << slurp(dir_ + "/secret.log");
      return false;
    }
    if (!publish("rl4 initial")) return false;

    std::ostringstream toml;
    toml << "[scope]\nsecret_file = \"" << dir_ << "/secret\"\n[control]\nendpoints = [";
    for (int i = 0; i < kNodes; ++i) toml << (i ? ", " : "") << "\"" << admin(i) << "\"";
    toml << "]\ntrust_keys = \"" << dir_ << "/trust.toml\"\nstate_dir = \"" << dir_ << "/clientstate\"\n"
         << "[tls]\ncert = \"" << pki() << "/client-1.pem\"\nkey = \"" << pki() << "/client-1.key\"\nca = \"" << pki() << "/ca.pem\"\n"
         << "[fabric]\nkeepalive_ms = 100\nreconnect_min_ms = 50\nreconnect_max_ms = 500\n[[fabric.devices]]\ndevice = \"" << dev << "\"\n"
         << "[landing]\nsubpool_bytes = " << kPool << "\n";
    (void)fs::create_directories(dir_ + "/clientstate");
    auto cfg = load_config(toml.str());
    if (!cfg) {
      ADD_FAILURE() << "client config: " << cfg.error().context;
      return false;
    }
    auto prov = ReloadableEngineNativeProvider::from_file(dir_ + "/secret");
    if (!prov) {
      ADD_FAILURE() << "secret provider: " << prov.error().context;
      return false;
    }
    prov_ = std::move(*prov);
    auto cl = Client::open(*cfg, *prov_);
    if (!cl) {
      ADD_FAILURE() << "bundle-mode Client::open: " << cl.error().context;
      return false;
    }
    cl_ = std::move(*cl);
    epoch_ = Clk::now();
    return true;
  }

  // ---- scopes, payloads, traffic ----
  Expected<ScopeKeys> scope_keys(int s) const {
    RequestMeta m;
    m.engine = EngineKind::Vllm;
    m.ns.fill(7);
    m.roots.push_back({std::byte{'r'}, static_cast<std::byte>(s & 0xff), static_cast<std::byte>(s >> 8)});
    return prov_->derive(m);
  }
  static Bytes payload(int s, int slot) {
    Bytes d(kLen);
    for (std::size_t j = 0; j < d.size(); ++j)
      d[j] = static_cast<std::byte>((j * 31 + static_cast<std::size_t>(s) * 7 + static_cast<std::size_t>(slot) * 13 + (j >> 12) * 5 + 3) & 0xff);
    return d;
  }
  std::int64_t now_us() const { return std::chrono::duration_cast<std::chrono::microseconds>(Clk::now() - epoch_).count(); }

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
  bool await(Ticket t, Completion& out, milliseconds cap) {
    std::unique_lock lk(mu_);
    if (!cv_.wait_for(lk, cap, [&] { return done_.count(t.id) != 0; })) return false;
    out = std::move(done_[t.id]);
    done_.erase(t.id);
    return true;
  }

  // One op on scope s/slot (scopes are owned by one thread, so ops on one key never overlap). The payload of a key is fixed.
  Rec run_op(int op, int s, int slot) {
    Rec r;
    r.op = op;
    auto sk = scope_keys(s);
    if (!sk) {
      oracle_->on_api_error("derive scope " + std::to_string(s) + ": " + sk.error().context);
      return r;
    }
    const std::string key = "scope" + std::to_string(s) + "/" + std::to_string(slot);
    const std::byte name[2] = {std::byte{'k'}, static_cast<std::byte>('0' + slot)};
    KeyRef ref;
    ref.raw = std::span<const std::byte>(name, 2);
    const std::array<KeyRef, 1> refs{ref};
    auto bufp = std::make_shared<Bytes>(op == 0 ? payload(s, slot) : Bytes(kLen, std::byte{0xAA}));
    std::vector<BufRef> bufs{{std::span<std::byte>(*bufp)}};
    if (op == 0) oracle_->begin_store(key, 1);
    const int gen0 = fault_gen_.load();
    const bool on0 = fault_on_.load();
    const auto t0 = Clk::now();
    r.start_us = std::chrono::duration_cast<std::chrono::microseconds>(t0 - epoch_).count();
    const milliseconds to = op == 0 ? kPutTo : op == 1 ? kLookTo : kFetchTo;
    Ticket t = op == 0   ? cl_->store(*sk, 0, refs, bufs, kPutTo)
               : op == 1 ? cl_->lookup(*sk, 0, refs, kLookTo)
                         : cl_->fetch(*sk, 0, refs, bufs, kFetchTo);
    Completion c;
    const bool got = await(t, c, to + kMargin + seconds(5));
    r.excused = on0 || fault_on_.load() || gen0 != fault_gen_.load();  // the op overlapped the rail outage
    r.lat_us = std::chrono::duration_cast<std::chrono::microseconds>(Clk::now() - t0).count();
    if (!got) {
      r.hang = true;
      {
        std::lock_guard lk(mu_);
        quarantine_.push_back(bufp);  // the client may still hold the BufRef
      }
      oracle_->on_missing_completion(key + " " + op_name(op));
      return r;
    }
    r.st = c.status.size() == 1 ? c.status[0] : KeyStatus::Aborted;
    if (op == 0) {
      if (r.st == KeyStatus::Committed) oracle_->end_store(key, 1, true);
      oracle_->on_store(key, r.st, r.excused, op_name(op));
    } else if (op == 1) {
      oracle_->on_store(key, r.st, r.excused, op_name(op));
    } else {
      // Hit bytes must be exactly the block (any slice from either rail, re-issued or not).
      std::optional<std::uint64_t> v;
      if (r.st == KeyStatus::Hit && *bufp == payload(s, slot)) v = 1;
      oracle_->on_fetch(key, r.st, v, r.excused);
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
          const int s = 1 + t + kThreads * static_cast<int>(x % static_cast<std::uint64_t>(kScopes / kThreads));  // s % 4 == t + 1 (mod 4)
          const int op = i % 10 == 0 ? 0 : i % 10 == 1 ? 1 : 2;  // 10% puts, 10% lookups, 80% fetches
          recs_[t].push_back(run_op(op, s, static_cast<int>((x >> 24) % kSlots)));
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
  void fill(seconds cap) {
    const auto until = Clk::now() + cap;
    for (int s = 1; s <= kScopes && Clk::now() < until; ++s)
      for (int slot = 0; slot < kSlots; ++slot)
        for (int tries = 0; tries < 20; ++tries) {
          if (run_op(0, s, slot).st == KeyStatus::Committed) break;
          std::this_thread::sleep_for(milliseconds(100));
        }
  }

  // ---- rails: the sampler records every state change; bytes per rail from the counters ----
  void start_sampler() {
    sample_run_ = true;
    sampler_ = std::thread([this] {
      std::map<std::string, double> last;
      while (sample_run_) {
        const std::string text = cl_->metrics_text();
        const auto states = family(text, "miracache_client_rail_state");
        {
          std::lock_guard lk(smu_);
          for (const auto& s : states) {
            auto it = last.find(s.key);
            if (it == last.end() || it->second != s.value) {
              transitions_.push_back({now_us(), s.key, it == last.end() ? -1 : static_cast<int>(it->second), static_cast<int>(s.value)});
              last[s.key] = s.value;
            }
          }
          cur_state_.clear();
          for (const auto& s : states) cur_state_[s.key] = static_cast<int>(s.value);
        }
        std::this_thread::sleep_for(milliseconds(100));
      }
    });
  }
  void stop_sampler() {
    sample_run_ = false;
    if (sampler_.joinable()) sampler_.join();
  }
  // Number of rail series of rail index `rail` whose state is `state` / total series of that rail.
  std::pair<int, int> rails_in(int rail, int state) {
    std::lock_guard lk(smu_);
    int n = 0, tot = 0;
    const std::string want = " rail " + std::to_string(rail) + " ";
    for (const auto& [k, v] : cur_state_)
      if (k.find(want) != std::string::npos) {
        ++tot;
        n += v == state;
      }
    return {n, tot};
  }
  std::map<int, double> rail_bytes() const {
    std::map<int, double> out;
    for (const auto& s : family(cl_->metrics_text(), "miracache_client_fetch_rail_bytes_total")) out[s.rail] += s.value;
    return out;
  }
  double reissued() const {
    double sum = 0;
    for (const auto& s : family(cl_->metrics_text(), "miracache_client_slices_reissued_total")) sum += s.value;
    return sum;
  }
  struct Snap {
    std::int64_t t_us = 0;
    std::map<int, double> bytes;
    double reissued = 0;
  };
  Snap snap() const { return {now_us(), rail_bytes(), reissued()}; }
  void rail_report(const char* label, const Snap& a, const Snap& b) {
    std::ostringstream o;
    o << "[multirail e2e] " << label << ": per-rail READ bytes";
    for (const auto& [r, v] : b.bytes) {
      const double d = v - (a.bytes.count(r) ? a.bytes.at(r) : 0.0);
      char buf[96];
      std::snprintf(buf, sizeof buf, " rail%d=%.2f MiB", r, d / 1048576.0);
      o << buf;
    }
    o << " | slices re-issued " << (b.reissued - a.reissued);
    std::fprintf(stderr, "%s\n", o.str().c_str());
  }
  static double delta(const Snap& a, const Snap& b, int rail) {
    return (b.bytes.count(rail) ? b.bytes.at(rail) : 0.0) - (a.bytes.count(rail) ? a.bytes.at(rail) : 0.0);
  }

  static double pct(std::vector<std::int64_t> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return static_cast<double>(v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))]) / 1000.0;  // ms
  }
  struct WinStat {
    std::size_t fetch_hits = 0, fetch_miss = 0, fetch_miss_unexcused = 0;
  };
  WinStat window_report(const std::string& label, std::int64_t from_us, std::int64_t to_us) {
    WinStat w;
    std::ostringstream o;
    o << "[multirail e2e] " << label << " (" << static_cast<double>(to_us - from_us) / 1e6 << " s):";
    std::map<std::string, std::size_t> by_status;
    for (int op = 0; op < 3; ++op) {
      std::vector<std::int64_t> lat;
      for (int t = 0; t < kThreads; ++t)
        for (const auto& r : recs_[t])
          if (r.op == op && r.start_us >= from_us && r.start_us < to_us) {
            lat.push_back(r.lat_us);
            ++by_status[std::string(op_name(op)) + ":" + to_string(r.st)];
            if (op == 2 && r.st == KeyStatus::Hit) ++w.fetch_hits;
            if (op == 2 && r.st == KeyStatus::Miss) {
              ++w.fetch_miss;
              w.fetch_miss_unexcused += r.excused ? 0 : 1;
            }
          }
      char b[160];
      std::snprintf(b, sizeof b, " %s n=%zu p50=%.2fms p99=%.2fms |", op_name(op), lat.size(), pct(lat, 0.5), pct(lat, 0.99));
      o << b;
    }
    o << " status{";
    for (const auto& [k, v] : by_status) o << k << "=" << v << " ";
    o << "}";
    std::fprintf(stderr, "%s\n", o.str().c_str());
    return w;
  }
  template <class P>
  bool until(P pred, seconds cap, int step_ms = 100) {
    const auto end = Clk::now() + cap;
    while (Clk::now() < end) {
      if (pred()) return true;
      std::this_thread::sleep_for(milliseconds(step_ms));
    }
    return pred();
  }
  void sleep_ms(int ms) { std::this_thread::sleep_for(milliseconds(ms)); }
  void print_transitions() {
    std::lock_guard lk(smu_);
    static const char* nm[] = {"down", "suspect", "up"};
    for (const auto& t : transitions_)
      std::fprintf(stderr, "[multirail e2e] +%.2fs %s: %s -> %s\n", static_cast<double>(t.t_us) / 1e6, t.key.c_str(),
                   t.from < 0 ? "(new)" : nm[t.from], nm[t.to]);
  }

  struct Trans {
    std::int64_t t_us;
    std::string key;
    int from, to;
  };

  std::string dir_, ip_, skip_;
  pid_t node_[kNodes] = {-1, -1, -1};
  std::uint16_t rdma_port_[kNodes] = {}, admin_port_[kNodes] = {}, metrics_port_[kNodes] = {};
  std::unique_ptr<Client> cl_;
  std::unique_ptr<ReloadableEngineNativeProvider> prov_;
  std::unique_ptr<Oracle> oracle_;
  Clk::time_point epoch_ = Clk::now();
  std::mutex mu_, smu_;
  std::condition_variable cv_;
  std::map<std::uint64_t, Completion> done_;
  std::thread disp_, sampler_;
  std::atomic<bool> disp_run_{false}, run_{false}, sample_run_{false}, fault_on_{false};
  std::atomic<int> fault_gen_{0};
  bool rail_down_ = false;
  std::vector<std::thread> workers_;
  std::vector<Rec> recs_[kThreads];
  std::vector<std::shared_ptr<Bytes>> quarantine_;
  std::vector<Trans> transitions_;
  std::map<std::string, int> cur_state_;
};

TEST_P(MultiRailE2e, TwoRailsLoseOneAndGetItBack) {
  oracle_ = std::make_unique<Oracle>(OracleMode::Fault);
  if (!bring_up(GetParam())) {
    if (!skip_.empty()) GTEST_SKIP() << skip_;
    FAIL() << "bring-up failed";
  }
  start_dispatcher();
  ASSERT_EQ(cl_->node_count(), static_cast<std::size_t>(kNodes));
  start_sampler();
  // Both rails of every node must come up (one admin ticket per rail, one control + fetch + ingest set per rail).
  ASSERT_TRUE(until([&] { return rails_in(0, 2) == std::make_pair(kNodes, kNodes) && rails_in(1, 2) == std::make_pair(kNodes, kNodes); }, seconds(30)))
      << "not every rail is up: " << cl_->metrics_text();
  fill(seconds(60));
  start_traffic();
  sleep_ms(2000);

  // ---- window 1: baseline, both rails up ----
  const Snap s0 = snap();
  sleep_ms(8000);
  const Snap s1 = snap();
  rail_report("window 1 baseline, both rails up", s0, s1);
  window_report("window 1 baseline", s0.t_us, s1.t_us);
  EXPECT_GT(delta(s0, s1, 0), 0.0) << "rail 0 carried no slices";
  EXPECT_GT(delta(s0, s1, 1), 0.0) << "rail 1 carried no slices";

  // ---- window 2: rail 2's address deleted ----
  fault_on_ = true;
  ++fault_gen_;
  ASSERT_TRUE(fault("del")) << "the fault agent could not delete " << kRail2Ip;
  const std::int64_t t_del = now_us();
  const bool seen_down = until([&] { return rails_in(1, 2).first == 0; }, seconds(30));
  const std::int64_t t_seen = now_us();
  const Snap sd0 = snap();
  sleep_ms(8000);
  const Snap sd1 = snap();
  rail_report("window 2 rail 1 down (from the first moment no rail-1 series was Up)", sd0, sd1);
  window_report("window 2 rail down", t_del, sd1.t_us);
  std::fprintf(stderr, "[multirail e2e] window 2: address deleted at +%.2fs, client showed rail 1 not Up after %.2fs (seen=%d)\n",
               static_cast<double>(t_del) / 1e6, static_cast<double>(t_seen - t_del) / 1e6, seen_down);
  EXPECT_TRUE(seen_down) << "the client never marked rail 1 down after its address was deleted";
  EXPECT_GT(delta(sd0, sd1, 0), 0.0) << "rail 0 carried nothing while rail 1 was down";
  EXPECT_LT(delta(sd0, sd1, 1), 1048576.0) << "rail 1 kept carrying slices while down";

  // ---- window 3: the address comes back ----
  ASSERT_TRUE(fault("add")) << "the fault agent could not restore " << kRail2Ip;
  const std::int64_t t_add = now_us();
  const bool back = until([&] { return rails_in(1, 2) == std::make_pair(kNodes, kNodes); }, seconds(60));
  const std::int64_t t_back = now_us();
  fault_on_ = false;
  ++fault_gen_;
  std::fprintf(stderr, "[multirail e2e] window 3: address restored at +%.2fs, every rail 1 Up again after %.2fs (back=%d)\n",
               static_cast<double>(t_add) / 1e6, static_cast<double>(t_back - t_add) / 1e6, back);
  EXPECT_TRUE(back) << "rail 1 did not come back Up within 60 s";
  const Snap sr0 = snap();
  window_report("window 3 restore", t_add, t_back);

  // ---- window 4: steady again ----
  sleep_ms(2000);
  const Snap sr1 = snap();
  sleep_ms(8000);
  const Snap sr2 = snap();
  rail_report("window 4 both rails up again", sr1, sr2);
  window_report("window 4 steady", sr1.t_us, sr2.t_us);
  rail_report("whole run", s0, sr2);
  EXPECT_GT(delta(sr1, sr2, 0), 0.0);
  EXPECT_GT(delta(sr1, sr2, 1), 0.0) << "rail 1 carried no slices after it came back";
  EXPECT_GT(delta(sr0, sr2, 1), 0.0);

  // ---- verdict ----
  stop_traffic();
  const std::int64_t t_end = now_us();
  const WinStat steady = window_report("misses outside the fault window", sr1.t_us, t_end);
  const std::string rep = oracle_->report();
  std::fprintf(stderr, "[multirail e2e] %s\n", rep.c_str());
  print_transitions();
  std::fprintf(stderr, "[multirail e2e] slices re-issued over the whole run: %.0f\n", reissued());
  EXPECT_EQ(oracle_->failed(), 0u) << rep;
  std::uint64_t hangs = 0;
  for (int t = 0; t < kThreads; ++t)
    for (const auto& r : recs_[t]) hangs += r.hang ? 1 : 0;
  EXPECT_EQ(hangs, 0u);
  EXPECT_GT(oracle_->total(), 500u) << "too little traffic to mean anything";
  EXPECT_GT(oracle_->count_of(KeyStatus::Hit), 0u);
  EXPECT_GT(steady.fetch_hits, 0u);
  EXPECT_EQ(steady.fetch_miss_unexcused, 0u) << "a fetch of a stored block missed with every rail healthy";
}

INSTANTIATE_TEST_SUITE_P(Device, MultiRailE2e, ::testing::Values(std::string("rxe0")),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

}  // namespace
}  // namespace miracache
