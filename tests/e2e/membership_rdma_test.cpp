// SPDX-License-Identifier: Apache-2.0
// Membership end to end on rxe0 / siw0 (label `rdma`). The exit criterion: add or drain a memory node under load with
// 0 failed operations.
//
// Real processes: mira-memnode x 3-4 in BUNDLE mode ([control] trust_keys, state_dir, admin mTLS), the real Go
// mira-controller (publishes, reconcile loop, API, failure detector) and mirctl (first publish and the operator
// commands node add / node drain), plus one in-process C++ Client opened in bundle mode ([control] endpoints /
// controller / trust_keys / state_dir), so the test also covers the bundle-mode open on real hardware and the
// client reports to the controller. Four traffic threads (put / lookup / fetch, versioned payloads) run through
// the oracle in tests/util/oracle.h.
//
// How the Go binaries are driven: the controller is a long-running helper PROCESS (it has to be SIGKILLed mid-push),
// mirctl is run as a child for the first publish (cluster.toml, then `mira-controller --recover-from` imports it into
// the controller's store) and for `node add` / `node drain` through the controller API. Both are built by the pinned
// toolchain (deploy/docker/go.sh) as the CMake target mira_go_tools.
//
// Cases (a test each):
//   JoinFourthNode        1. 3 nodes, R=2, add a 4th under traffic            STRICT oracle
//   DrainToRemoval        2. drain one node through every phase to removal    STRICT oracle
//   ControllerKilledMidPush 3. SIGKILL the controller mid-push: a node lags; clients push their envelope   FAULT
//   ControllerKilledMidJoin 4. SIGKILL the controller mid-join: the new node acked, the others lag        FAULT
//   ReplicasAcrossZones   5. R=2 over two zones: each scope has one replica per zone     STRICT oracle
//
// Making a node lag (cases 3 and 4): the node is SIGKILLed first (a connection to a stopped process would still buffer
// the request and apply it after the controller died), so the controller's push to it fails fast and the cluster is left at
// mixed generations; the node is restarted on its state_dir right after the controller is killed. The fault oracle's
// exception is applied per op: an op that overlapped the kill / restart window of that node is `excused`.
// Certs from deploy/examples/lab-certs.sh. Skips cleanly without an RDMA device.
#include <arpa/inet.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <netinet/in.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
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
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "fabric/verbs_cm/verbs_cm_fabric.h"
#include "free_port.h"
#include "src/client.h"
#include "util/oracle.h"

extern char** environ;

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;
using Clk = std::chrono::steady_clock;
using std::chrono::milliseconds;
using std::chrono::seconds;
using testutil::Oracle;
using testutil::OracleMode;

constexpr int kThreads = 4;
constexpr int kScopes = 400;
constexpr std::size_t kLen = 2000;
constexpr milliseconds kPutTo{2000}, kLookTo{1000}, kFetchTo{2000};
constexpr milliseconds kMargin{1000};

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

// GET /metrics from 127.0.0.1:port (plain HTTP) with a 2 s read timeout; empty on failure.
std::string http_metrics(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  timeval tv{2, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
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

// Value of the sample line that starts with `series` (name and labels, without the const node_id label), or -1.
long metric(const std::string& raw, const std::string& series) {
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

// Sum of every sample of the family `name` (any labels) in a client's metrics text.
double family_sum(const std::string& text, const std::string& name) {
  double sum = 0;
  std::istringstream in(text);
  for (std::string line; std::getline(in, line);) {
    if (line.rfind(name, 0) != 0 || line.size() <= name.size()) continue;
    const char c = line[name.size()];
    if (c != '{' && c != ' ') continue;
    sum += std::strtod(line.c_str() + line.rfind(' ') + 1, nullptr);
  }
  return sum;
}

struct Rec {
  std::int64_t start_us = 0, lat_us = 0;
  int op = 0;  // 0 put, 1 lookup, 2 fetch
  KeyStatus st = KeyStatus::Miss;
  bool hang = false;
};
const char* op_name(int o) { return o == 0 ? "put" : o == 1 ? "lookup" : "fetch"; }

class MembershipE2e : public ::testing::TestWithParam<std::string> {
 protected:
  static constexpr int kMaxNodes = 4;

  void TearDown() override {
    if (HasFailure() && !dir_.empty()) {  // the tool logs are the evidence for a membership failure
      for (const char* pat : {"add.log", "drain.log"}) {
        const std::string s = slurp(dir_ + "/" + pat);
        if (!s.empty()) std::fprintf(stderr, "---- %s ----\n%s\n", pat, s.c_str());
      }
      for (int k = 1; k <= ctl_starts_; ++k) {
        const std::string s = slurp(tag("controller", 0, k));
        std::fprintf(stderr, "---- controller start %d ----\n%.6000s\n", k, s.c_str());
      }
    }
    stop_traffic();
    disp_run_ = false;
    if (disp_.joinable()) disp_.join();
    if (cl_) cl_->shutdown();
    cl_.reset();
    kill_proc(ctl_, SIGTERM);
    for (int i = 0; i < kMaxNodes; ++i) kill_proc(node_[i], SIGTERM);
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
    last_exit_ok_ = r > 0 && WIFEXITED(st) && WEXITSTATUS(st) == 0;
    pid = -1;
  }
  // Runs a short-lived tool to its end; its exit code, or -1 on a timeout (killed).
  int run_tool(const std::vector<std::string>& args, const std::string& log, seconds cap = seconds(90)) {
    pid_t pid = spawn(args, log);
    if (pid < 0) return -1;
    return wait_exit(pid, cap);
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

  std::string tag(const char* what, int i, int gen) const { return dir_ + "/" + what + std::to_string(i) + "." + std::to_string(gen) + ".log"; }
  bool start_node(int i) {  // node index 0..3, cert node-(i+1)
    node_[i] = spawn({MIRA_MEMNODE_BIN, "--config", dir_ + "/node" + std::to_string(i + 1) + ".toml"}, tag("memnode", i + 1, ++starts_[i]));
    return node_[i] > 0 && wait_log(tag("memnode", i + 1, starts_[i]), node_[i], "listening", seconds(15));
  }
  // The generation node i's latest start loaded from its state_dir (the memnode logs "bundle.current loaded" before
  // "listening", i.e. before any client or controller can reach it), -1 if that start loaded no bundle.
  long start_gen(int i) const {
    const std::string log = slurp(tag("memnode", i + 1, starts_[i]));
    const auto p = log.find("msg=\"bundle.current loaded\"");
    if (p == std::string::npos) return -1;
    const auto eol = log.find('\n', p);
    const auto g = log.find(" generation=", p);
    if (g == std::string::npos || (eol != std::string::npos && g > eol)) return -1;
    return std::strtol(log.c_str() + g + 12, nullptr, 10);
  }
  void kill_node(int i, int sig) {
    kill_proc(node_[i], sig);
  }
  bool start_controller() {
    ctl_ = spawn({MIRA_CONTROLLER_BIN, "--store-dir", dir_ + "/ctl", "--trust-keys", dir_ + "/trust.toml", "--publish-key", dir_ + "/key.seed",
                  "--security-key", dir_ + "/key.seed", "--cert", pki() + "/client-2.pem", "--key", pki() + "/client-2.key", "--ca",
                  pki() + "/ca.pem", "--api-listen", "127.0.0.1:" + std::to_string(api_port_), "--api-cert", pki() + "/node-5.pem",
                  "--api-key", pki() + "/node-5.key", "--audit-dir", dir_ + "/ctl-audit", "--drain-continue", "6s", "--drain-max", "12s"},
                 tag("controller", 0, ++ctl_starts_));
    return ctl_ > 0 && wait_log(tag("controller", 0, ctl_starts_), ctl_, "reconcile loop running", seconds(30));
  }
  std::string pki() const { return dir_ + "/pki"; }
  std::string admin(int i) const { return "127.0.0.1:" + std::to_string(admin_port_[i]); }
  std::vector<std::string> mirctl_tls() const {
    return {"--cert", pki() + "/client-3.pem", "--tls-key", pki() + "/client-3.key", "--ca", pki() + "/ca.pem"};
  }
  std::vector<std::string> mirctl_node(const char* sub, int i, const std::string& extra_flag = {}, const std::string& extra_val = {}) const {
    std::vector<std::string> a{MIRCTL_BIN, "node", sub, "--controller", "127.0.0.1:" + std::to_string(api_port_)};
    for (auto& s : mirctl_tls()) a.push_back(s);
    if (!extra_flag.empty()) {
      a.push_back(extra_flag);
      a.push_back(extra_val);
    }
    a.push_back(admin(i));
    return a;
  }
  // Number of client identities the controller holds reports for (GET /v1/status "reports"), -1 if unreadable.
  long controller_reports() const {
    const std::string out = dir_ + "/status.json";
    const std::string cmd = "printf 'GET /v1/status HTTP/1.0\\r\\n\\r\\n' | timeout 8 openssl s_client -quiet -verify_quiet -CAfile " + pki() + "/ca.pem -cert " + pki() + "/client-3.pem -key " + pki() +
                            "/client-3.key -connect 127.0.0.1:" + std::to_string(api_port_) + " > " + out + " 2>/dev/null";
    (void)std::system(cmd.c_str());  // s_client may exit non-zero once the server closes
    const std::string j = slurp(out);
    const auto p = j.find("\"reports\":");
    return p == std::string::npos ? -1 : std::strtol(j.c_str() + p + 10, nullptr, 10);
  }
  long gen(int i) const { return metric(http_metrics(metrics_port_[i]), "miracache_bundle_generation"); }
  long scopes_open(int i) const { return metric(http_metrics(metrics_port_[i]), "miracache_scope_open "); }
  std::string dump_gens() const {
    std::ostringstream o;
    for (int i = 0; i < kMaxNodes; ++i) o << " n" << i + 1 << "=" << (node_[i] > 0 ? gen(i) : -2);
    return o.str();
  }

  // Brings up the cluster: `n_in` nodes in the first bundle (zones given or empty), all kMaxNodes memnodes running
  // (the ones past n_in are blank spares), then the controller (its store imported from node 1's bundle.current), then
  // the bundle-mode Client. Returns false (with a gtest failure or skip) when it cannot.
  bool bring_up(const std::string& dev, int n_in, const std::vector<std::string>& zones) {
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
    }
    char t[] = "/tmp/mira-mb11-XXXXXX";
    if (::mkdtemp(t) == nullptr) return false;
    dir_ = t;
    dev_ = dev;
    if (std::system(("bash " + std::string(MIRACACHE_LAB_CERTS_SH) + " " + pki() + " --nodes 1,2,3,4,5 --clients 1,2,3 >/dev/null").c_str()) != 0) {
      ADD_FAILURE() << "lab-certs failed";
      return false;
    }
    // One key with both roles; the trust file is what `mirctl keys gen` prints.
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
    for (int i = 0; i < kMaxNodes; ++i) {
      rdma_port_[i] = free_port();
      admin_port_[i] = free_port();
      metrics_port_[i] = free_port();
      const std::string n = std::to_string(i + 1);
      std::ofstream f(dir_ + "/node" + n + ".toml");
      f << "[node]\ndevice = \"" << dev << "\"\nlisten = [\"" << ip_ << ":" << rdma_port_[i] << "\"]\nstate_dir = \"" << dir_ << "/state" << n << "\"\n"
        << "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\nn_segments = 4\n"
        << ""
        << "[admin]\nlisten = \"127.0.0.1:" << admin_port_[i] << "\"\ncert = \"" << pki() << "/node-" << n << ".pem\"\nkey = \"" << pki()
        << "/node-" << n << ".key\"\nca = \"" << pki() << "/ca.pem\"\n"
        << "[telemetry]\nlisten = \"127.0.0.1:" << metrics_port_[i] << "\"\n"
        << "[control]\ntrust_keys = \"" << dir_ << "/trust.toml\"\n";
    }
    api_port_ = free_port();
    for (int i = 0; i < kMaxNodes; ++i)
      if (!start_node(i)) return false;

    // The operator's cluster.toml (intent only: IDs, hostnames and rails are learned from the nodes).
    {
      std::ofstream f(dir_ + "/cluster.toml");
      f << "reason = \"mb11 initial\"\n";
      for (int i = 0; i < n_in; ++i) {
        f << "[[nodes]]\nadmin = \"" << admin(i) << "\"\nweight = 1\n";
        if (!zones.empty()) f << "zone = \"" << zones[static_cast<std::size_t>(i)] << "\"\n";
      }
      f << "[[principals]]\nname = \"lab\"\nidentities = [\"spiffe://lab/client-1\"]\nquota_bytes = 1073741824\nmax_scopes = 100000\n"
        << "[[rbac]]\nidentity = \"spiffe://lab/client-3\"\nroles = [\"operator\", \"security-admin\"]\n"
        << "[[rbac]]\nidentity = \"spiffe://lab/client-2\"\nroles = [\"operator\"]\n"
        << "[config.cluster.placement]\nreplicas = 2\n"
        << "[config.cluster.memnode.store]\nmax_scopes = 100000\nmax_bytes = 16777216\n";  // class A: cluster config in bundle mode
    }
    std::vector<std::string> pub{MIRCTL_BIN, "bundle", "publish", "--source", dir_ + "/cluster.toml", "--key", dir_ + "/key.seed", "--sec-key",
                                 dir_ + "/key.seed", "--trust", dir_ + "/trust.toml"};
    for (auto& s : mirctl_tls()) pub.push_back(s);
    if (run_tool(pub, dir_ + "/publish.log") != 0) {
      ADD_FAILURE() << "mirctl bundle publish:\n" << slurp(dir_ + "/publish.log");
      return false;
    }
    // Hand the cluster to the controller: import node 1's bundle.current into its (blank) store, then run it.
    if (run_tool({MIRA_CONTROLLER_BIN, "--store-dir", dir_ + "/ctl", "--trust-keys", dir_ + "/trust.toml", "--cert", pki() + "/client-2.pem", "--key",
                  pki() + "/client-2.key", "--ca", pki() + "/ca.pem", "--recover-from", admin(0)},
                 dir_ + "/recover.log") != 0) {
      ADD_FAILURE() << "mira-controller --recover-from:\n" << slurp(dir_ + "/recover.log");
      return false;
    }
    if (!start_controller()) return false;

    std::ostringstream toml;
    toml << "[scope]\nsecret_file = \"unused\"\n[control]\nendpoints = [";
    for (int i = 0; i < n_in; ++i) toml << (i ? ", " : "") << "\"" << admin(i) << "\"";
    toml << "]\ncontroller = \"127.0.0.1:" << api_port_ << "\"\ntrust_keys = \"" << dir_ << "/trust.toml\"\nstate_dir = \"" << dir_ << "/clientstate\"\n"
         << "[tls]\ncert = \"" << pki() << "/client-1.pem\"\nkey = \"" << pki() << "/client-1.key\"\nca = \"" << pki() << "/ca.pem\"\n"
         << "[fabric]\ndevice = \"" << dev << "\"\nkeepalive_ms = 100\nreconnect_min_ms = 50\nreconnect_max_ms = 500\n"
         << "[landing]\nsubpool_bytes = 8388608\n";
    (void)std::filesystem::create_directories(dir_ + "/clientstate");
    auto cfg = load_config(toml.str());
    if (!cfg) {
      ADD_FAILURE() << "client config: " << cfg.error().context;
      return false;
    }
    NoProvider prov;
    auto cl = Client::open(*cfg, prov);
    if (!cl) {
      ADD_FAILURE() << "bundle-mode Client::open: " << cl.error().context;
      return false;
    }
    cl_ = std::move(*cl);
    epoch_ = Clk::now();
    return true;
  }

  // ---- scopes, payloads, traffic ----
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
  // Payload = 8-byte version, then bytes that depend on (scope, version): a Hit is decoded and compared in full.
  static Bytes payload(int s, std::uint64_t ver) {
    Bytes d(kLen);
    for (std::size_t j = 0; j < d.size(); ++j)
      d[j] = static_cast<std::byte>((j * 31 + static_cast<std::size_t>(s) * 7 + static_cast<std::size_t>(ver) * 101 + 3) & 0xff);
    for (int b = 0; b < 8; ++b) d[static_cast<std::size_t>(b)] = static_cast<std::byte>((ver >> (8 * b)) & 0xff);
    return d;
  }
  static std::optional<std::uint64_t> version_of(int s, const Bytes& d) {
    if (d.size() < 8) return std::nullopt;
    std::uint64_t v = 0;
    for (int b = 0; b < 8; ++b) v |= static_cast<std::uint64_t>(d[static_cast<std::size_t>(b)]) << (8 * b);
    if (d != payload(s, v)) return std::nullopt;
    return v;
  }
  static std::string key_name(int s) { return "scope" + std::to_string(s); }
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

  // One op on scope s (owned by the calling thread, so ops on one key never overlap). Records it and feeds the oracle.
  Rec run_op(int op, int s, int slot = 0) {
    Rec r;
    r.op = op;
    const std::string key = key_name(s) + "/" + std::to_string(slot);
    const std::byte name[2] = {std::byte{'k'}, static_cast<std::byte>('0' + slot)};
    KeyRef ref;
    ref.raw = std::span<const std::byte>(name, 2);
    const std::array<KeyRef, 1> refs{ref};
    // Content-addressed like the engines: a key always carries the same bytes (a join moves the owner set, so a re-put can
    // legitimately commit the same key on a new owner while an old owner still holds the first copy).
    const std::uint64_t ver = op == 0 ? 1 : 0;
    auto bufp = std::make_shared<Bytes>(op == 0 ? payload(s, ver) : Bytes(kLen, std::byte{0xAA}));
    std::vector<BufRef> bufs{{std::span<std::byte>(*bufp)}};
    const bool f0 = fault_on_.load();
    const int fg0 = fault_seq_.load();
    if (op == 0) oracle_->begin_store(key, ver);
    const auto t0 = Clk::now();
    r.start_us = std::chrono::duration_cast<std::chrono::microseconds>(t0 - epoch_).count();
    const milliseconds to = op == 0 ? kPutTo : op == 1 ? kLookTo : kFetchTo;
    Ticket t = op == 0   ? cl_->store(scope_keys(s), 0, refs, bufs, kPutTo)
               : op == 1 ? cl_->lookup(scope_keys(s), 0, refs, kLookTo)
                         : cl_->fetch(scope_keys(s), 0, refs, bufs, kFetchTo);
    Completion c;
    if (!await(t, c, to + kMargin + seconds(5))) {
      r.hang = true;
      {
        std::lock_guard lk(mu_);
        quarantine_.push_back(bufp);  // the client may still hold the BufRef
      }
      oracle_->on_missing_completion(key + " " + op_name(op));
      r.lat_us = std::chrono::duration_cast<std::chrono::microseconds>(Clk::now() - t0).count();
      return r;
    }
    r.lat_us = std::chrono::duration_cast<std::chrono::microseconds>(Clk::now() - t0).count();
    r.st = c.status.size() == 1 ? c.status[0] : KeyStatus::Aborted;
    const bool excused = f0 || fault_on_.load() || fg0 != fault_seq_.load();
    if (excused) ++excused_ops_;
    if (op == 0) {
      // A put that reports Skipped (stale epoch on one leg, another leg already stored) can leave the bytes on a replica, so its
      // version stays "in flight" (never erased); the bytes must still decode exactly, so a wrong or foreign Hit still fails.
      if (r.st == KeyStatus::Committed) oracle_->end_store(key, ver, true);
      oracle_->on_store(key, r.st, excused);
    } else if (op == 1) {
      oracle_->on_store(key, r.st, excused);  // a lookup carries no bytes: the status verdict is the same
    } else {
      oracle_->on_fetch(key, r.st, r.st == KeyStatus::Hit ? version_of(s, *bufp) : std::nullopt, excused);
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
          recs_[t].push_back(run_op(static_cast<int>(i % 3), s, static_cast<int>((x >> 24) % 4)));
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
  // Serial fill: every scope stored once before the measured phases.
  void fill(seconds cap) {
    const auto until = Clk::now() + cap;
    for (int s = 1; s <= kScopes && Clk::now() < until; ++s) {
      for (int tries = 0; tries < 20; ++tries) {
        Rec r = run_op(0, s);
        if (r.st == KeyStatus::Committed) break;
        std::this_thread::sleep_for(milliseconds(100));
      }
    }
  }

  static double pct(std::vector<std::int64_t> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return static_cast<double>(v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))]) / 1000.0;  // ms
  }
  // p50 / p99 per op kind over ops that STARTED in [from_us, to_us).
  void phase_report(const std::string& label, std::int64_t from_us, std::int64_t to_us) {
    std::ostringstream o;
    o << "[membership e2e] " << label << " (" << static_cast<double>(to_us - from_us) / 1e6 << " s):";
    std::size_t skipped_puts = 0;
    for (int op = 0; op < 3; ++op) {
      std::vector<std::int64_t> lat;
      for (int t = 0; t < kThreads; ++t)
        for (const auto& r : recs_[t])
          if (r.op == op && r.start_us >= from_us && r.start_us < to_us) {
            lat.push_back(r.lat_us);
            if (op == 0 && r.st == KeyStatus::Skipped) ++skipped_puts;
          }
      char b[160];
      std::snprintf(b, sizeof b, " %s n=%zu p50=%.2fms p99=%.2fms |", op_name(op), lat.size(), pct(lat, 0.5), pct(lat, 0.99));
      o << b;
    }
    o << " skipped_puts=" << skipped_puts;
    std::fprintf(stderr, "%s\n", o.str().c_str());
  }
  // Last start time of a Skipped put in [from_us, to_us) minus the first (the stale-epoch skip window), in seconds.
  double skip_window_s(std::int64_t from_us, std::int64_t to_us) {
    std::int64_t lo = INT64_MAX, hi = -1;
    for (int t = 0; t < kThreads; ++t)
      for (const auto& r : recs_[t])
        if (r.op == 0 && r.st == KeyStatus::Skipped && r.start_us >= from_us && r.start_us < to_us) {
          lo = std::min(lo, r.start_us);
          hi = std::max(hi, r.start_us);
        }
    return hi < 0 ? 0.0 : static_cast<double>(hi - lo) / 1e6;
  }
  void sleep_ms(int ms) { std::this_thread::sleep_for(milliseconds(ms)); }
  template <class P>
  bool until(P pred, seconds cap, int step_ms = 100) {
    const auto end = Clk::now() + cap;
    while (Clk::now() < end) {
      if (pred()) return true;
      sleep_ms(step_ms);
    }
    return pred();
  }

  void finish(OracleMode mode, const char* what) {
    stop_traffic();
    const std::string rep = oracle_->report();
    std::fprintf(stderr, "[membership e2e] %s %s excused_ops=%llu\n", what, rep.c_str(), static_cast<unsigned long long>(excused_ops_.load()));
    EXPECT_EQ(oracle_->failed(), 0u) << rep << (mode == OracleMode::Strict ? " (strict)" : " (fault)");
    std::uint64_t hangs = 0;
    for (int t = 0; t < kThreads; ++t)
      for (const auto& r : recs_[t]) hangs += r.hang ? 1 : 0;
    EXPECT_EQ(hangs, 0u);
    EXPECT_GT(oracle_->total(), 1000u) << "too little traffic to mean anything";
  }

  // Clean-up state shared by the cases.
  std::string dir_, ip_, dev_, skip_;
  pid_t node_[kMaxNodes] = {-1, -1, -1, -1};
  pid_t ctl_ = -1;
  int starts_[kMaxNodes] = {0, 0, 0, 0};
  int ctl_starts_ = 0;
  std::uint16_t rdma_port_[kMaxNodes] = {}, admin_port_[kMaxNodes] = {}, metrics_port_[kMaxNodes] = {}, api_port_ = 0;
  static inline bool last_exit_ok_ = false;
  std::unique_ptr<Client> cl_;
  std::shared_ptr<TestKeys> keys_ = std::make_shared<TestKeys>();
  std::unique_ptr<Oracle> oracle_;
  Clk::time_point epoch_ = Clk::now();
  std::mutex mu_;
  std::condition_variable cv_;
  std::map<std::uint64_t, Completion> done_;
  std::thread disp_;
  std::atomic<bool> disp_run_{false}, run_{false};
  std::vector<std::thread> workers_;
  std::vector<Rec> recs_[kThreads];
  std::atomic<std::uint64_t> next_ver_{1}, excused_ops_{0};
  std::atomic<bool> fault_on_{false};
  std::atomic<int> fault_seq_{0};
  std::vector<std::shared_ptr<Bytes>> quarantine_;
};

#define MB11_SETUP(n_in, zones, mode)                                    \
  oracle_ = std::make_unique<Oracle>(mode);                              \
  if (!bring_up(GetParam(), n_in, zones)) {                              \
    if (!skip_.empty()) GTEST_SKIP() << skip_;                           \
    FAIL() << "bring-up failed";                                         \
  }                                                                      \
  start_dispatcher();                                                    \
  ASSERT_EQ(cl_->node_count(), static_cast<std::size_t>(n_in));          \
  fill(seconds(40));                                                     \
  start_traffic();                                                       \
  sleep_ms(3000)

// ---- 1. add a 4th node under load (strict) ----
TEST_P(MembershipE2e, JoinFourthNode) {
  MB11_SETUP(3, std::vector<std::string>{}, OracleMode::Strict);
  const std::uint32_t e0 = cl_->membership_epoch();
  const std::int64_t t_base0 = now_us() - 2'500'000, t_cmd = now_us();
  const long g0 = gen(0);
  ASSERT_EQ(run_tool(mirctl_node("add", 3), dir_ + "/add.log"), 0) << slurp(dir_ + "/add.log");
  ASSERT_TRUE(until([&] { return cl_->membership_epoch() > e0 && cl_->node_count() == 4; }, seconds(30))) << "client never adopted the join";
  const std::int64_t t_done = now_us();
  sleep_ms(6000);
  const std::int64_t t_end = now_us();
  phase_report("case1 before add", t_base0, t_cmd);
  phase_report("case1 during add (mirctl start .. client on new epoch)", t_cmd, t_done);
  phase_report("case1 after add", t_done + 1'000'000, t_end);
  const double skip_s = skip_window_s(t_cmd, t_done + 1'000'000);
  std::fprintf(stderr, "[membership e2e] case1 stale-epoch skip window %.2f s; generation %ld -> %ld; epoch %u -> %u\n", skip_s, g0, gen(0), e0,
               cl_->membership_epoch());
  EXPECT_LE(skip_s, 5.0) << "puts skipped for longer than a join may take (plan: at most 2 s)";
  for (int i = 0; i < 4; ++i) EXPECT_EQ(gen(i), gen(0)) << "node " << i + 1 << dump_gens();
  EXPECT_GT(scopes_open(3), 0) << "the new node holds nothing after 6 s of traffic";
  const std::string cm = cl_->metrics_text();
  std::fprintf(stderr, "[membership e2e] case1 client put_skipped_total=%g; controller holds reports from %ld client identities\n",
               family_sum(cm, "miracache_client_put_skipped_total"), controller_reports());
  EXPECT_GE(controller_reports(), 1) << "the client sent no report to the controller";
  finish(OracleMode::Strict, "case1");
}

// ---- 2. drain one node to removal (strict) ----
TEST_P(MembershipE2e, DrainToRemoval) {
  MB11_SETUP(4, std::vector<std::string>{}, OracleMode::Strict);
  const std::uint32_t e0 = cl_->membership_epoch();
  const long g0 = gen(0);
  const std::int64_t t_base0 = now_us() - 2'500'000, t_cmd = now_us();
  ASSERT_EQ(run_tool(mirctl_node("drain", 1), dir_ + "/drain.log"), 0) << slurp(dir_ + "/drain.log");
  ASSERT_TRUE(until([&] { return cl_->membership_epoch() > e0; }, seconds(30))) << "client never adopted the drain epoch";
  const std::int64_t t_epoch = now_us();
  const long g_drain = gen(0);
  // Draining -> readonly (3 s) -> removed (<= 12 s, or earlier when empty): the node's own bundle generation is the witness.
  ASSERT_TRUE(until([&] { return gen(0) >= g0 + 3; }, seconds(60), 250)) << "drain did not run to the end:" << dump_gens();
  const std::int64_t t_removed = now_us();
  std::fprintf(stderr, "[membership e2e] case2 generations %ld (before) -> %ld (draining) -> %ld (removed)\n", g0, g_drain, gen(0));
  ASSERT_TRUE(until([&] { return cl_->node_count() <= 4; }, seconds(5)));
  sleep_ms(4000);
  const std::int64_t t_end = now_us();
  phase_report("case2 before drain", t_base0, t_cmd);
  phase_report("case2 draining + readonly", t_cmd, t_removed);
  phase_report("case2 after removal", t_removed + 1'000'000, t_end);
  std::fprintf(stderr, "[membership e2e] case2 stale-epoch skip window around the drain epoch %.2f s\n", skip_window_s(t_cmd, t_epoch + 1'000'000));
  // The operator stops the removed node: SIGTERM must exit 0 (the shutdown contract).
  kill_proc(node_[1], SIGTERM);
  EXPECT_TRUE(last_exit_ok_) << "the removed node did not exit 0 on SIGTERM";
  sleep_ms(3000);
  finish(OracleMode::Strict, "case2");
}


// ---- 3. controller killed mid-push (fault) ----
TEST_P(MembershipE2e, ControllerKilledMidPush) {
  MB11_SETUP(3, std::vector<std::string>{}, OracleMode::Fault);
  const std::uint32_t e0 = cl_->membership_epoch();
  const std::int64_t t_base0 = now_us() - 2'500'000;
  // An operator command that needs every node (`node drain`) is refused while one is unreachable, so the drain of node 2 is issued
  // with all nodes up (an epoch bump). The controller's own next step of that drain (draining -> readonly after drain.continue_ms,
  // 6 s here) TOLERATES an unreachable node: node 3 is killed just before it, so the step is pushed to nodes 1 and 2 only, and the
  // controller is SIGKILLed the instant node 1 holds it. Node 3 restarts on its state_dir at the older generation.
  ASSERT_EQ(run_tool(mirctl_node("drain", 1), dir_ + "/drain.log"), 0) << slurp(dir_ + "/drain.log");
  const long g0 = gen(0);  // the drain generation, held by every node
  sleep_ms(2500);
  const std::int64_t t_fault = now_us();
  ++fault_seq_;
  fault_on_ = true;
  kill_node(2, SIGKILL);
  ASSERT_TRUE(until([&] { return gen(0) > g0; }, seconds(20), 2)) << "the controller never pushed the readonly step";
  kill_proc(ctl_, SIGKILL);  // mid-push: node 3 was unreachable, the others have the step
  ASSERT_TRUE(start_node(2));
  // The lag is read from node 3's own start-up line, not its live gauge: the client's catch-up push (every reply
  // frame stamps the node's generation, and the first reply after the reconnect shows node 3 behind) may land within
  // milliseconds of "listening", before the test's first metrics sample (gauge already 3 of 3 at the sample).
  const long g_lag = start_gen(2);
  const long g_new = gen(0);
  std::fprintf(stderr, "[membership e2e] case3 controller killed at generation %ld; node 3 restarted from bundle.current at %ld (cluster %ld, node 3 now %ld)\n", g0,
               g_lag, g_new, gen(2));
  // Node 3 was dead for the whole readonly publish (the controller found it unreachable), so its bundle.current is the drain
  // generation exactly, and that is behind the cluster.
  EXPECT_EQ(g_lag, g0) << "a restarted node must serve from its bundle.current: " << slurp(tag("memnode", 3, starts_[2]));
  EXPECT_LT(g_lag, g_new) << "node 3 should lag: " << dump_gens();
  // No controller: clients push their envelope to the lagging node.
  const auto t_wait0 = Clk::now();
  ASSERT_TRUE(until([&] { return gen(2) >= g_new; }, seconds(30), 50)) << "the lagging node was not caught up by the clients:" << dump_gens();
  const double catch_up = std::chrono::duration<double>(Clk::now() - t_wait0).count();
  std::fprintf(stderr, "[membership e2e] case3 lagging node caught up by the client push in %.2f s with no controller (controller reconcile period 5 s)\n", catch_up);
  sleep_ms(3000);  // the restarted node 3 reconnects
  const std::int64_t t_back = now_us();
  fault_on_ = false;
  sleep_ms(5000);
  const std::int64_t t_end_nocontrol = now_us();
  phase_report("case3 before", t_base0, t_fault);
  phase_report("case3 fault window (node 3 down, controller killed, node 3 restarted)", t_fault, t_back);
  phase_report("case3 controller still dead, cluster at the new generation", t_back + 500'000, t_end_nocontrol);
  // The controller restarts and finishes the job.
  ASSERT_TRUE(start_controller());
  ASSERT_TRUE(until([&] { return gen(0) >= g_new && gen(1) >= g_new && gen(2) >= g_new; }, seconds(30))) << dump_gens();
  const std::uint32_t e1 = cl_->membership_epoch();
  std::fprintf(stderr, "[membership e2e] case3 after the controller restart:%s; client epoch %u -> %u\n", dump_gens().c_str(), e0, e1);
  EXPECT_GT(e1, e0) << "the client never adopted the new epoch";
  sleep_ms(2000);
  finish(OracleMode::Fault, "case3");
}

// ---- 4. controller killed mid-join (fault) ----
TEST_P(MembershipE2e, ControllerKilledMidJoin) {
  MB11_SETUP(3, std::vector<std::string>{}, OracleMode::Fault);
  const std::uint32_t e0 = cl_->membership_epoch();
  const long g0 = gen(0);
  const std::int64_t t_base0 = now_us() - 2'500'000, t_fault = now_us();
  // A join needs every node reachable (an unreachable node aborts the publish), so no node is down beforehand. The new node
  // acks first; the instant it holds the join generation the controller is SIGKILLed and node 3 with it (its copy of the
  // push, if not applied yet, dies with the process), then node 3 restarts on its state_dir. Whether the others had the push
  // already is a race (the controller fans out in parallel within milliseconds); the test reports which nodes lagged.
  pid_t add = spawn(mirctl_node("add", 3), dir_ + "/add.log");
  ASSERT_TRUE(until([&] { return gen(3) > g0; }, seconds(30), 1)) << "the new node never acked the join";
  ++fault_seq_;
  fault_on_ = true;
  kill_proc(ctl_, SIGKILL);
  kill_node(2, SIGKILL);
  (void)wait_exit(add, seconds(5));
  ASSERT_TRUE(start_node(2));
  std::fprintf(stderr, "[membership e2e] case4 node 3 restarted from bundle.current at generation %ld (cluster %ld)\n", gen(2), gen(3));
  const long g_new = gen(3);
  std::fprintf(stderr, "[membership e2e] case4 controller killed after the new node acked generation %ld (was %ld); at that point:%s\n", g_new, g0, dump_gens().c_str());
  const auto t_wait0 = Clk::now();
  auto all_at = [&] { return gen(0) >= g_new && gen(1) >= g_new && gen(2) >= g_new; };
  // If the race left every old node at G-1 and only the new node at G, no client has a source for G (their endpoints are the old
  // nodes), so the clients cannot push it; the restarted controller's reconcile loop (5 s) is what finishes the join.
  const bool by_clients = until(all_at, seconds(8), 50);
  std::fprintf(stderr, "[membership e2e] case4 laggers caught up by client push without a controller: %s (%.2f s)\n", by_clients ? "yes" : "no, the controller finishes it",
               std::chrono::duration<double>(Clk::now() - t_wait0).count());
  if (!by_clients) {
    ASSERT_TRUE(start_controller());
    ASSERT_TRUE(until(all_at, seconds(30), 50)) << "the restarted controller did not finish the join:" << dump_gens();
    std::fprintf(stderr, "[membership e2e] case4 restarted controller finished the join after %.2f s\n", std::chrono::duration<double>(Clk::now() - t_wait0).count());
  }
  ASSERT_TRUE(until([&] { return cl_->membership_epoch() > e0 && cl_->node_count() == 4; }, seconds(30))) << "client never adopted the join";
  sleep_ms(3000);  // the restarted node 3 reconnects
  const std::int64_t t_back = now_us();
  fault_on_ = false;
  sleep_ms(5000);
  const std::int64_t t_end = now_us();
  phase_report("case4 before", t_base0, t_fault);
  phase_report("case4 fault window (node 3 down, controller killed mid-join)", t_fault, t_back);
  phase_report("case4 controller dead, join live", t_back + 500'000, t_end);
  EXPECT_GT(scopes_open(3), 0) << "the joined node holds nothing";
  // The restarted controller finishes the join: it must show the node as a member (a second `node add` is idempotent or refused,
  // never a new generation that drops the node), and the cluster stays at one generation.
  if (ctl_ <= 0) ASSERT_TRUE(start_controller());
  sleep_ms(7000);  // one reconcile period (5 s) plus margin
  const std::string clog = slurp(tag("controller", 0, ctl_starts_));
  std::fprintf(stderr, "[membership e2e] case4 after the controller restart:%s; controller log lines about the join: %s\n", dump_gens().c_str(),
               clog.find("alert") != std::string::npos || clog.find("ALERT") != std::string::npos ? "ALERT present" : "no alert");
  for (int i = 1; i < 4; ++i) EXPECT_GE(gen(i), g_new) << "node " << i + 1;
  EXPECT_EQ(cl_->node_count(), 4u);
  finish(OracleMode::Fault, "case4");
}

// ---- 5. R=2 over two zones (strict) ----
TEST_P(MembershipE2e, ReplicasAcrossZones) {
  MB11_SETUP(4, (std::vector<std::string>{"za", "za", "zb", "zb"}), OracleMode::Strict);
  const std::int64_t t0 = now_us() - 2'500'000;
  sleep_ms(8000);
  const std::int64_t t1 = now_us();
  phase_report("case5 steady state, zones za,za,zb,zb", t0, t1);
  // Every scope has one replica per zone: a zone holds each scope at most once, so its open-scope total is <= the scopes stored
  // and (replicas are best effort) close to it.
  long za = scopes_open(0) + scopes_open(1), zb = scopes_open(2) + scopes_open(3);
  std::fprintf(stderr, "[membership e2e] case5 scopes open per node: %ld %ld | %ld %ld (zone za=%ld, zone zb=%ld, scopes=%d)\n", scopes_open(0), scopes_open(1),
               scopes_open(2), scopes_open(3), za, zb, kScopes);
  EXPECT_LE(za, kScopes) << "a scope has two replicas in zone za";
  EXPECT_LE(zb, kScopes) << "a scope has two replicas in zone zb";
  EXPECT_GE(za, kScopes * 9 / 10);
  EXPECT_GE(zb, kScopes * 9 / 10);
  // Then drain a zone-a node under the same traffic: the zone rule must keep holding for the survivors.
  const std::uint32_t e0 = cl_->membership_epoch();
  ASSERT_EQ(run_tool(mirctl_node("drain", 0), dir_ + "/drain.log"), 0) << slurp(dir_ + "/drain.log");
  ASSERT_TRUE(until([&] { return cl_->membership_epoch() > e0; }, seconds(30)));
  sleep_ms(4000);
  phase_report("case5 after draining a zone-za node", t1, now_us());
  finish(OracleMode::Strict, "case5");
}

INSTANTIATE_TEST_SUITE_P(Device, MembershipE2e, ::testing::ValuesIn(devices()),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

}  // namespace
}  // namespace miracache
