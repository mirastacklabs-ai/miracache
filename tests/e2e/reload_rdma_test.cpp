// SPDX-License-Identifier: Apache-2.0
// HR6: hot reload under load, end to end on rxe0 / siw0 (label `rdma`). The kver and certificate parts of the M2
// hot-reload exit: 0 failed operations by the oracle (tests/util/oracle.h,
// STRICT: every node and rail stays healthy) while the cluster is reconfigured under four traffic threads.
//
// Real processes: mira-memnode x 3 in BUNDLE mode ([control] trust_keys, state_dir, admin mTLS) and the real Go mirctl,
// which publishes every new bundle generation straight to the nodes (no controller: one writer per cluster, decision 13).
// One in-process C++ Client in bundle mode ([control] endpoints / trust_keys / state_dir, [tls] cert / key / ca,
// scope.secret_file) with a ReloadableEngineNativeProvider, so the client's CredWatch runs (HR4).
//
// Windows (one reload each, traffic never stops; each ends when the cluster shows the change):
//   1 lease_ttl_and_R      bundle: R 1 -> 2 (replica legs start) with memnode lease.ttl_s / max_s / put_timeout_s, then R 2 -> 1 and
//                          other lease values (class A on both sides; the nodes log the changed keys, the client adopts R)
//   2 subpool_bytes        bundle: landing.subpool_bytes 8 MiB -> 4 MiB (class B): every node is rebuilt, one at a time (HR3b)
//   3 client_certificate   the client's certificate and key are replaced (a new key, the same CA and identity) by one atomic
//                          symlink swap; CredWatch loads them; then a bundle and a class B rebuild only succeed over HTTPS
//                          connections made with the new certificate (the old one is no longer on disk)
//   4 kver                 `mirctl secret add-kver`: the provider's `current` becomes 2; new ops derive new scopes (the old
//                          ones are cold, a Miss is allowed), puts and gets under kver 2 work
//   2b fetch_qps (HR7)     bundle: fabric.fetch_qps 2 -> 4 -> 2 -> the open-time value (class B): each change rebuilds every
//                          node with that many fetch QPs per rail; miracache_client_rail_fetch_qps shows it on every rail
//                          of every node (the "QPs per rail" part of the M2 exit)
// Topology (HR7, multi-rail plan decision 11): every node serves TWO rails on the one device, the device's own IPv4 and
// RL1's lab address on the same netdev (the lab RDMA setup script: 10.98.0.1 for rxe0, 10.99.0.2 for siw0;
// MIRACACHE_RDMA_RAIL2=<ip> overrides), both labelled subnet kLabSubnet; the client's one device (fabric.devices) has no
// subnet (the wildcard), so it pairs both rails.
// Skips cleanly without an RDMA device. Certs from deploy/examples/lab-certs.sh.
#include <arpa/inet.h>
#include <fcntl.h>
#include <gtest/gtest.h>
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
#include <regex>
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
constexpr int kScopes = 100;
constexpr int kSlots = 16;  // keys per scope: 1600 keys of one 4 KiB block per kver, well inside the nodes' stores
constexpr std::size_t kLen = 2000;
constexpr milliseconds kPutTo{2000}, kLookTo{1000}, kFetchTo{2000};
constexpr milliseconds kMargin{1000};
constexpr std::size_t kPool0 = 8u << 20;  // [landing] subpool_bytes at open
// HR7: both rails of a node live on the one lab device, possibly in two IPv4 subnets (rxe0: eth0 and 10.98.0.0/24). The
// node rails carry one CIDR label (the bundle requires one); the client device has no subnet: the wildcard (run #219)
// pairs every rail of its protocol.
constexpr const char* kLabSubnet = "0.0.0.0/0";

std::vector<std::string> devices() {
  const char* env = std::getenv("MIRACACHE_RDMA_DEVICES");
  std::stringstream ss(env != nullptr ? env : "rxe0,siw0");
  std::vector<std::string> out;
  for (std::string d; std::getline(ss, d, ',');)
    if (!d.empty()) out.push_back(d);
  return out;
}

// The second rail's address on `dev`'s netdev (RL1's lab addresses), or empty when unknown (then one rail).
std::string rail2_ip(const std::string& dev) {
  if (const char* e = std::getenv("MIRACACHE_RDMA_RAIL2"); e != nullptr && *e != '\0') return e;
  if (dev == "rxe0") return "10.98.0.1";
  if (dev == "siw0") return "10.99.0.2";
  return {};
}

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
double family_sum(const std::string& text, const std::string& name, const std::string& must_contain = {}) {
  double sum = 0;
  std::istringstream in(text);
  for (std::string line; std::getline(in, line);) {
    if (line.rfind(name, 0) != 0 || line.size() <= name.size()) continue;
    const char c = line[name.size()];
    if (c != '{' && c != ' ') continue;
    if (!must_contain.empty() && line.find(must_contain) == std::string::npos) continue;
    sum += std::strtod(line.c_str() + line.rfind(' ') + 1, nullptr);
  }
  return sum;
}

struct Rec {
  std::int64_t start_us = 0, lat_us = 0;
  int op = 0;  // 0 put, 1 lookup, 2 fetch
  KeyStatus st = KeyStatus::Miss;
  bool hang = false;
  unsigned kver = 0;
};
const char* op_name(int o) { return o == 0 ? "put" : o == 1 ? "lookup" : "fetch"; }

class ReloadE2e : public ::testing::TestWithParam<std::string> {
 protected:
  void TearDown() override {
    stop_traffic();
    disp_run_ = false;
    if (disp_.joinable()) disp_.join();
    if (cl_) cl_->shutdown();
    cl_.reset();
    prov_.reset();
    for (int i = 0; i < kNodes; ++i) kill_proc(node_[i], SIGTERM);
    if (HasFailure() && !dir_.empty())
      for (int i = 0; i < kNodes; ++i) {
        const std::string s = slurp(tag("memnode", i + 1, starts_[i]));
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

  std::string tag(const char* what, int i, int gen) const { return dir_ + "/" + what + std::to_string(i) + "." + std::to_string(gen) + ".log"; }
  std::string pki() const { return dir_ + "/pki"; }
  std::string admin(int i) const { return "127.0.0.1:" + std::to_string(admin_port_[i]); }
  bool start_node(int i) {
    node_[i] = spawn({MIRA_MEMNODE_BIN, "--config", dir_ + "/node" + std::to_string(i + 1) + ".toml"}, tag("memnode", i + 1, ++starts_[i]));
    return node_[i] > 0 && wait_log(tag("memnode", i + 1, starts_[i]), node_[i], "listening", seconds(15));
  }
  long gen(int i) const { return metric(http_metrics(metrics_port_[i]), "miracache_bundle_generation"); }
  long cfg_gen(int i) const { return metric(http_metrics(metrics_port_[i]), "miracache_config_generation"); }

  // ---- bring-up: nodes, first bundle, secret file, client ----
  void write_cluster(const std::string& config_tables, const std::string& reason) {
    std::ofstream f(dir_ + "/cluster.toml");
    f << "reason = \"" << reason << "\"\n";
    for (int i = 0; i < kNodes; ++i) f << "[[nodes]]\nadmin = \"" << admin(i) << "\"\nweight = 1\n";
    f << "[[principals]]\nname = \"lab\"\nidentities = [\"spiffe://lab/client-1\"]\nquota_bytes = 1073741824\nmax_scopes = 100000\n"
      << "[[rbac]]\nidentity = \"spiffe://lab/client-3\"\nroles = [\"operator\", \"security-admin\"]\n"
      << "[[rbac]]\nidentity = \"spiffe://lab/client-2\"\nroles = [\"operator\"]\n"
      << config_tables;
  }
  std::vector<std::string> mirctl_tls() const { return {"--cert", pki() + "/client-3.pem", "--tls-key", pki() + "/client-3.key", "--ca", pki() + "/ca.pem"}; }

  // Publishes bundle generation N+1 with the given `config.*` tables (memory-node and client side in one bundle).
  bool publish(const std::string& config_tables, const std::string& reason) {
    write_cluster(config_tables, reason);
    std::vector<std::string> pub{MIRCTL_BIN, "bundle", "publish", "--source", dir_ + "/cluster.toml", "--key", dir_ + "/key.seed", "--sec-key",
                                 dir_ + "/key.seed", "--trust", dir_ + "/trust.toml"};
    for (auto& s : mirctl_tls()) pub.push_back(s);
    const std::string log = dir_ + "/publish" + std::to_string(++publishes_) + ".log";
    if (run_tool(pub, log) != 0) {
      ADD_FAILURE() << "mirctl bundle publish (" << reason << "):\n" << slurp(log);
      return false;
    }
    return true;
  }

  // The `config.*` tables of the cluster at this moment: placement (R), memory-node lease, an optional client table. The
  // client table is the whole `[config.cluster.client...]` text; an absent key means the open-time value.
  std::string tables(unsigned replicas, unsigned lease_ttl, unsigned lease_max, unsigned put_timeout, const std::string& client_tables) const {
    std::ostringstream t;
    t << "[config.cluster.placement]\nreplicas = " << replicas << "\n"
      << "[config.cluster.memnode.store]\nmax_scopes = 100000\nmax_bytes = 16777216\n"
      << "[config.cluster.memnode.lease]\nttl_s = " << lease_ttl << "\nmax_s = " << lease_max << "\nput_timeout_s = " << put_timeout << "\n"
      << client_tables;
    return t.str();
  }
  // Publish R / lease / client table; true when it was accepted by mirctl.
  bool publish_client(unsigned replicas, unsigned lease_ttl, const std::string& client_tables, const std::string& reason) {
    cur_r_ = replicas;
    cur_lease_ = lease_ttl;
    cur_client_ = client_tables;
    return publish(tables(replicas, lease_ttl, lease_ttl * 2, 12, client_tables), reason);
  }
  // The client's table with `landing.subpool_bytes` and the optional extra fabric keys.
  static std::string client_tbl(std::size_t subpool, const std::string& fabric_extra = {}) {
    return "[config.cluster.client.landing]\nsubpool_bytes = " + std::to_string(subpool) + "\n" +
           (fabric_extra.empty() ? "" : "[config.cluster.client.fabric]\n" + fabric_extra);
  }

  bool bring_up(const std::string& dev) {
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
    ip2_ = rail2_ip(dev);
    if (ip2_ == ip_) ip2_.clear();
    rails_ = ip2_.empty() ? 1 : 2;
    if (rails_ == 1) {  // G10: never run one rail silently
      if (dev == "rxe0" || dev == "siw0") {
        ADD_FAILURE() << "device " << dev << " must run two rails, but its second address is missing or equals the first ("
                      << ip_ << "); fix the lab addresses or set MIRACACHE_RDMA_RAIL2";
        return false;
      }
      std::fprintf(stderr, "[HR7] SKIP the 2-rail windows: device %s has no second rail address (set MIRACACHE_RDMA_RAIL2); "
                           "running one rail\n", dev.c_str());
    }
    char t[] = "/tmp/mira-hr6-XXXXXX";
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
      rdma_port2_[i] = free_port();
      admin_port_[i] = free_port();
      metrics_port_[i] = free_port();
      const std::string n = std::to_string(i + 1);
      std::ofstream f(dir_ + "/node" + n + ".toml");
      f << "[node]\nstate_dir = \"" << dir_ << "/state" << n << "\"\n"
        << "[[node.rails]]\ndevice = \"" << dev << "\"\nlisten = \"" << ip_ << ":" << rdma_port_[i] << "\"\nsubnet = \"" << kLabSubnet << "\"\n";
      if (rails_ == 2) f << "[[node.rails]]\ndevice = \"" << dev << "\"\nlisten = \"" << ip2_ << ":" << rdma_port2_[i] << "\"\nsubnet = \"" << kLabSubnet << "\"\n";
      f << "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\nn_segments = 4\n"
        << "[admin]\nlisten = \"127.0.0.1:" << admin_port_[i] << "\"\ncert = \"" << pki() << "/node-" << n << ".pem\"\nkey = \"" << pki()
        << "/node-" << n << ".key\"\nca = \"" << pki() << "/ca.pem\"\n"
        << "[telemetry]\nlisten = \"127.0.0.1:" << metrics_port_[i] << "\"\n"
        << "[control]\ntrust_keys = \"" << dir_ << "/trust.toml\"\n";
    }
    for (int i = 0; i < kNodes; ++i)
      if (!start_node(i)) return false;

    // The client's credentials live behind a symlink so a rotation is one atomic swap: cred/cur -> cred/v1.
    fs::create_directories(dir_ + "/cred/v1");
    for (const char* ext : {"pem", "key"}) fs::copy_file(pki() + "/client-1." + ext, dir_ + "/cred/v1/client-1." + ext);
    ::chmod((dir_ + "/cred/v1/client-1.key").c_str(), 0600);
    fs::create_directory_symlink(dir_ + "/cred/v1", dir_ + "/cred/cur");
    // The engine-native secret file (kver 1), as `mirctl secret gen` writes it.
    if (run_tool({MIRCTL_BIN, "secret", "gen", "--out", dir_ + "/secret"}, dir_ + "/secret.log") != 0) {
      ADD_FAILURE() << "mirctl secret gen:\n" << slurp(dir_ + "/secret.log");
      return false;
    }
    if (!publish_client(1, 30, client_tbl(kPool0), "hr6 initial")) return false;

    std::ostringstream toml;
    toml << "[scope]\nsecret_file = \"" << dir_ << "/secret\"\n[control]\nendpoints = [";
    for (int i = 0; i < kNodes; ++i) toml << (i ? ", " : "") << "\"" << admin(i) << "\"";
    toml << "]\ntrust_keys = \"" << dir_ << "/trust.toml\"\nstate_dir = \"" << dir_ << "/clientstate\"\n"
         << "[tls]\ncert = \"" << dir_ << "/cred/cur/client-1.pem\"\nkey = \"" << dir_ << "/cred/cur/client-1.key\"\nca = \"" << pki() << "/ca.pem\"\n"
         << "[fabric]\ndevices = [{ device = \"" << dev << "\" }]\nkeepalive_ms = 100\nreconnect_min_ms = 50\nreconnect_max_ms = 500\n"
         << "[landing]\nsubpool_bytes = " << kPool0 << "\n";
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
  // The scope of `s` under the provider's CURRENT kver: a new kver is a new scope id (the old ones are cold).
  Expected<ScopeKeys> scope_keys(int s) const {
    RequestMeta m;
    m.engine = EngineKind::Vllm;
    m.ns.fill(7);
    m.roots.push_back({std::byte{'r'}, static_cast<std::byte>(s & 0xff), static_cast<std::byte>(s >> 8)});
    return prov_->derive(m);
  }
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

  // One op on scope s (owned by the calling thread, so ops on one key never overlap). The oracle key carries the kver the
  // op's scope was derived under: the same raw key under another kver is another key.
  Rec run_op(int op, int s, int slot = 0) {
    Rec r;
    r.op = op;
    auto sk = scope_keys(s);
    if (!sk) {
      oracle_->on_api_error("derive scope " + std::to_string(s) + ": " + sk.error().context);
      return r;
    }
    r.kver = sk->kver;
    const std::string key = "scope" + std::to_string(s) + "/" + std::to_string(slot) + "@kv" + std::to_string(sk->kver);
    const std::byte name[2] = {std::byte{'k'}, static_cast<std::byte>('0' + slot)};
    KeyRef ref;
    ref.raw = std::span<const std::byte>(name, 2);
    const std::array<KeyRef, 1> refs{ref};
    const std::uint64_t ver = op == 0 ? 1 : 0;  // content-addressed: a key always carries the same bytes
    auto bufp = std::make_shared<Bytes>(op == 0 ? payload(s, ver) : Bytes(kLen, std::byte{0xAA}));
    std::vector<BufRef> bufs{{std::span<std::byte>(*bufp)}};
    if (op == 0) oracle_->begin_store(key, ver);
    const auto t0 = Clk::now();
    r.start_us = std::chrono::duration_cast<std::chrono::microseconds>(t0 - epoch_).count();
    const milliseconds to = op == 0 ? kPutTo : op == 1 ? kLookTo : kFetchTo;
    Ticket t = op == 0   ? cl_->store(*sk, 0, refs, bufs, kPutTo)
               : op == 1 ? cl_->lookup(*sk, 0, refs, kLookTo)
                         : cl_->fetch(*sk, 0, refs, bufs, kFetchTo);
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
    if (op == 0) {
      if (r.st == KeyStatus::Committed) oracle_->end_store(key, ver, true);
      oracle_->on_store(key, r.st, false, op_name(op));
    } else if (op == 1) {
      oracle_->on_store(key, r.st, false, op_name(op));  // a lookup carries no bytes: the status verdict is the same
    } else {
      oracle_->on_fetch(key, r.st, r.st == KeyStatus::Hit ? version_of(s, *bufp) : std::nullopt);
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
          recs_[t].push_back(run_op(static_cast<int>(i % 3), s, static_cast<int>((x >> 24) % kSlots)));
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
      for (int tries = 0; tries < 20; ++tries) {
        if (run_op(0, s).st == KeyStatus::Committed) break;
        std::this_thread::sleep_for(milliseconds(100));
      }
  }

  static double pct(std::vector<std::int64_t> v, double p) {
    if (v.empty()) return 0;
    std::sort(v.begin(), v.end());
    return static_cast<double>(v[std::min(v.size() - 1, static_cast<std::size_t>(p * static_cast<double>(v.size())))]) / 1000.0;  // ms
  }
  // Per-status counts and p50 / p99 per op kind over the ops that STARTED in [from_us, to_us).
  void window_report(const std::string& label, std::int64_t from_us, std::int64_t to_us) {
    std::ostringstream o;
    o << "[HR6] " << label << " (" << static_cast<double>(to_us - from_us) / 1e6 << " s):";
    std::map<std::string, std::size_t> by_status;
    for (int op = 0; op < 3; ++op) {
      std::vector<std::int64_t> lat;
      for (int t = 0; t < kThreads; ++t)
        for (const auto& r : recs_[t])
          if (r.op == op && r.start_us >= from_us && r.start_us < to_us) {
            lat.push_back(r.lat_us);
            ++by_status[to_string(r.st)];
          }
      char b[160];
      std::snprintf(b, sizeof b, " %s n=%zu p50=%.2fms p99=%.2fms |", op_name(op), lat.size(), pct(lat, 0.5), pct(lat, 0.99));
      o << b;
    }
    o << " status{";
    for (const auto& [k, v] : by_status) o << k << "=" << v << " ";
    o << "}";
    std::fprintf(stderr, "%s\n", o.str().c_str());
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

  // ---- what a window waits for ----
  // All three nodes run bundle generation `g` and the client applied the same configuration generation.
  bool converged(long g) {
    for (int i = 0; i < kNodes; ++i)
      if (gen(i) != g || cfg_gen(i) != g) return false;
    return cl_->dyn() && static_cast<long>(cl_->dyn()->generation) == g;
  }
  // Generation of the bundle mirctl just published (read from node 1).
  long newest() const { return gen(0); }
  // Every node runs `pool`; mtu and fetch_qps are the open-time values unless given (the device decides the mtu).
  bool wait_class_b(std::size_t pool, std::optional<std::uint32_t> mtu, std::optional<std::uint32_t> qps, seconds cap) {
    return until(
        [&] {
          if (cl_->rebuilding_slot() >= 0) return false;
          for (std::size_t s = 0; s < cl_->node_count(); ++s) {
            Client::SlotClassB b;
            if (!cl_->slot_class_b(s, b) || b.pool_bytes != pool || b.mtu != mtu.value_or(base_mtu_) || b.fetch_qps != qps.value_or(base_qps_)) return false;
          }
          return true;
        },
        cap);
  }
  // HR7: fetch QPs connected per "node_id/rail" (miracache_client_rail_fetch_qps; the series of learned IDs only).
  std::map<std::string, long> rail_qps() const {
    static const std::regex id_re("node_id=\"([0-9]+)\""), rail_re("rail=\"([0-9]+)\"");
    std::map<std::string, long> out;
    std::istringstream in(cl_->metrics_text());
    const std::string name = "miracache_client_rail_fetch_qps{";
    for (std::string line; std::getline(in, line);) {
      if (line.rfind(name, 0) != 0) continue;
      std::smatch id, rail;
      if (!std::regex_search(line, id, id_re) || !std::regex_search(line, rail, rail_re) || id[1] == "0") continue;
      out[id[1].str() + "/r" + rail[1].str()] = std::strtol(line.c_str() + line.rfind(' ') + 1, nullptr, 10);
    }
    return out;
  }
  bool rails_show(std::uint32_t qps) const {
    const auto m = rail_qps();
    if (m.size() != static_cast<std::size_t>(kNodes * rails_)) return false;
    for (const auto& [k, v] : m)
      if (v != static_cast<long>(qps)) return false;
    return true;
  }
  std::string rail_qps_text() const {
    std::string s;
    for (const auto& [k, v] : rail_qps()) s += (s.empty() ? "" : " ") + k + "=" + std::to_string(v);
    return s;
  }
  double legs_committed() const { return family_sum(cl_->metrics_text(), "miracache_client_replica_legs_total", "result=\"committed\""); }
  double cred(const char* kind, const char* result) const {
    return family_sum(cl_->metrics_text(), "miracache_cred_reload_total", std::string("kind=\"") + kind + "\",result=\"" + result + "\"");
  }
  bool node_logged(const std::string& needle) const {
    for (int i = 0; i < kNodes; ++i)
      if (slurp(tag("memnode", i + 1, starts_[i])).find(needle) == std::string::npos) return false;
    return true;
  }

  // Clean-up state.
  std::string dir_, ip_, ip2_, skip_;
  int rails_ = 1;  // rails per node (2 when the device has RL1's second lab address)
  pid_t node_[kNodes] = {-1, -1, -1};
  int starts_[kNodes] = {0, 0, 0};
  int publishes_ = 0;
  unsigned cur_r_ = 1, cur_lease_ = 30;
  std::uint32_t base_mtu_ = 0, base_qps_ = 0;  // the class B values the nodes run at open
  std::string cur_client_;
  std::uint16_t rdma_port_[kNodes] = {}, rdma_port2_[kNodes] = {}, admin_port_[kNodes] = {}, metrics_port_[kNodes] = {};
  std::unique_ptr<Client> cl_;
  std::unique_ptr<ReloadableEngineNativeProvider> prov_;
  std::unique_ptr<Oracle> oracle_;
  Clk::time_point epoch_ = Clk::now();
  std::mutex mu_;
  std::condition_variable cv_;
  std::map<std::uint64_t, Completion> done_;
  std::thread disp_;
  std::atomic<bool> disp_run_{false}, run_{false};
  std::vector<std::thread> workers_;
  std::vector<Rec> recs_[kThreads];
  std::vector<std::shared_ptr<Bytes>> quarantine_;
};

TEST_P(ReloadE2e, ReloadUnderTraffic) {
  oracle_ = std::make_unique<Oracle>(OracleMode::Strict);
  if (!bring_up(GetParam())) {
    if (!skip_.empty()) GTEST_SKIP() << skip_;
    FAIL() << "bring-up failed";
  }
  start_dispatcher();
  ASSERT_EQ(cl_->node_count(), static_cast<std::size_t>(kNodes));
  ASSERT_TRUE(until([&] { return converged(gen(0)); }, seconds(20))) << "client never adopted the first bundle's configuration";
  {
    Client::SlotClassB b;
    ASSERT_TRUE(cl_->slot_class_b(0, b));
    ASSERT_EQ(b.pool_bytes, kPool0);
    base_mtu_ = b.mtu;
    base_qps_ = b.fetch_qps;
  }
  ASSERT_TRUE(until([&] { return rails_show(base_qps_); }, seconds(20))) << "rails: " << rail_qps_text();
  std::fprintf(stderr, "[HR7] topology: %d rails per node (%s, %s); open-time fetch QPs per rail %u: %s\n", rails_, ip_.c_str(),
               ip2_.empty() ? "-" : ip2_.c_str(), base_qps_, rail_qps_text().c_str());
  fill(seconds(40));
  start_traffic();
  sleep_ms(3000);
  const std::int64_t t0 = now_us();

  // ---- window 1: lease TTL and R by bundle (class A, node side and client side) ----
  const double legs0 = legs_committed();
  ASSERT_TRUE(publish_client(2, 20, client_tbl(kPool0), "hr6 R=2 lease 20"));
  long g = newest();
  ASSERT_TRUE(until([&] { return converged(g); }, seconds(30))) << "gen " << g << " not applied everywhere";
  EXPECT_TRUE(node_logged("changed=")) << "every node logs the changed keys of the reload";
  ASSERT_TRUE(until([&] { return legs_committed() > legs0 + 20; }, seconds(30))) << "R = 2: no replica legs after the bundle";
  sleep_ms(2000);
  ASSERT_TRUE(publish_client(1, 45, client_tbl(kPool0), "hr6 R=1 lease 45"));
  g = newest();
  ASSERT_TRUE(until([&] { return converged(g); }, seconds(30)));
  sleep_ms(3000);
  const std::int64_t t1 = now_us();
  window_report("window 1 baseline (R=1, lease 30)", 2'000'000, t0);
  window_report("window 1 lease TTL and R by bundle", t0, t1);
  EXPECT_EQ(cl_->config_rejected(), 0u) << cl_->config_last_error();

  // ---- window 2: landing.subpool_bytes (class B): planned rebuild of every node ----
  const std::uint64_t rb0 = cl_->rebuilds_done();
  ASSERT_TRUE(publish_client(1, 45, client_tbl(4u << 20), "hr6 subpool 4 MiB"));
  g = newest();
  ASSERT_TRUE(until([&] { return converged(g); }, seconds(30)));
  ASSERT_TRUE(wait_class_b(4u << 20, std::nullopt, std::nullopt, seconds(90))) << "rebuilds " << cl_->rebuilds_done() << " failures " << cl_->rebuild_failures();
  EXPECT_EQ(cl_->rebuilds_done(), rb0 + kNodes);
  EXPECT_EQ(cl_->rebuild_failures(), 0u);
  sleep_ms(3000);
  const std::int64_t t2 = now_us();
  window_report("window 2 subpool_bytes 8 MiB -> 4 MiB, nodes rebuilt", t1, t2);

  // ---- window 2b (HR7): fabric.fetch_qps 2 -> 4 -> 2 -> open-time (class B): QPs per rail, live ----
  {
    std::uint32_t cur = base_qps_;
    std::int64_t from = now_us();
    auto step = [&](std::optional<std::uint32_t> q, const std::string& why) {
      const std::uint32_t want = q.value_or(base_qps_);
      const std::uint64_t rb = cl_->rebuilds_done();
      ASSERT_TRUE(publish_client(1, 45, client_tbl(4u << 20, q ? "fetch_qps = " + std::to_string(*q) + "\n" : ""), why));
      const long gq = newest();
      ASSERT_TRUE(until([&] { return converged(gq); }, seconds(30)));
      ASSERT_TRUE(wait_class_b(4u << 20, std::nullopt, want, seconds(90)))
          << why << ": rebuilds " << cl_->rebuilds_done() << " failures " << cl_->rebuild_failures();
      ASSERT_TRUE(until([&] { return rails_show(want); }, seconds(30))) << why << ": rails " << rail_qps_text();
      EXPECT_EQ(cl_->rebuilds_done(), rb + (want != cur ? kNodes : 0)) << why;
      EXPECT_EQ(cl_->rebuild_failures(), 0u) << why;
      sleep_ms(1500);  // traffic on the new QP count before the next step
      const std::int64_t to = now_us();
      std::fprintf(stderr, "[HR7] fetch_qps %u -> %u: rails %s\n", cur, want, rail_qps_text().c_str());
      window_report("window 2b " + why, from, to);
      from = to;
      cur = want;
    };
    step(2, "fetch_qps 2");
    if (HasFatalFailure()) return;
    step(4, "fetch_qps 4");
    if (HasFatalFailure()) return;
    step(2, "fetch_qps 2 again");
    if (HasFatalFailure()) return;
    step(std::nullopt, "fetch_qps open-time");
    if (HasFatalFailure()) return;
  }

  // ---- window 3: client certificate rotation ----
  {
    // A new key and certificate for the same identity and CA: lab-certs reuses a CA it finds in its output directory.
    fs::create_directories(dir_ + "/stage");
    fs::copy_file(pki() + "/ca.pem", dir_ + "/stage/ca.pem");
    fs::copy_file(pki() + "/ca.key", dir_ + "/stage/ca.key");
    ASSERT_EQ(std::system(("bash " + std::string(MIRACACHE_LAB_CERTS_SH) + " " + dir_ + "/stage --clients 1 >/dev/null").c_str()), 0);
    fs::create_directories(dir_ + "/cred/v2");
    for (const char* ext : {"pem", "key"}) fs::copy_file(dir_ + "/stage/client-1." + ext, dir_ + "/cred/v2/client-1." + ext);
    ::chmod((dir_ + "/cred/v2/client-1.key").c_str(), 0600);
    ASSERT_NE(slurp(dir_ + "/cred/v2/client-1.pem"), slurp(dir_ + "/cred/v1/client-1.pem")) << "the rotation must change the certificate";
  }
  const double tls_applied0 = cred("client_tls", "applied");
  fs::create_directory_symlink(dir_ + "/cred/v2", dir_ + "/cred/cur.tmp");
  fs::rename(dir_ + "/cred/cur.tmp", dir_ + "/cred/cur");  // one atomic swap of the pair
  const std::int64_t t_rot = now_us();
  ASSERT_TRUE(until([&] { return cred("client_tls", "applied") > tls_applied0; }, seconds(40))) << cl_->metrics_text();
  const std::int64_t t_rot_done = now_us();
  EXPECT_EQ(cred("client_tls", "rejected"), 0.0) << "an atomic swap is never half-loaded";
  fs::remove_all(dir_ + "/cred/v1");  // the old certificate is gone: only the new one can authenticate from here on
  // New HTTPS connections must carry the new certificate: a bundle (watcher fetch), then a class B rebuild (ticket requests).
  ASSERT_TRUE(publish_client(1, 40, client_tbl(4u << 20), "hr6 after cert rotation"));
  g = newest();
  ASSERT_TRUE(until([&] { return converged(g); }, seconds(60))) << "the client could not fetch the new bundle with the rotated certificate";
  const std::uint64_t rb1 = cl_->rebuilds_done();
  ASSERT_TRUE(publish_client(1, 40, client_tbl(8u << 20), "hr6 subpool 8 MiB with the new certificate"));
  g = newest();
  ASSERT_TRUE(until([&] { return converged(g); }, seconds(60)));
  ASSERT_TRUE(wait_class_b(8u << 20, std::nullopt, std::nullopt, seconds(90))) << "rebuilds " << cl_->rebuilds_done() << " failures " << cl_->rebuild_failures();
  EXPECT_EQ(cl_->rebuilds_done(), rb1 + kNodes) << "tickets were obtained with the new certificate";
  EXPECT_EQ(cl_->rebuild_failures(), 0u);
  sleep_ms(2000);
  const std::int64_t t3 = now_us();
  window_report("window 3 before the rotation took effect", t2, t_rot_done);
  window_report("window 3 after rotation (new bundle + rebuild over the new certificate)", t_rot_done, t3);
  std::fprintf(stderr, "[HR6] window 3 certificate: swapped at +%.1f s, loaded after %.1f s\n", static_cast<double>(t_rot - t2) / 1e6,
               static_cast<double>(t_rot_done - t_rot) / 1e6);

  // ---- window 4: kver rotation (mirctl secret add-kver) ----
  ASSERT_EQ(prov_->kver(), 1u);
  const double sec_applied0 = cred("secret", "applied");
  ASSERT_EQ(run_tool({MIRCTL_BIN, "secret", "add-kver", "--file", dir_ + "/secret"}, dir_ + "/addkver.log"), 0) << slurp(dir_ + "/addkver.log");
  const std::int64_t t_kv = now_us();
  ASSERT_TRUE(until([&] { return prov_->kver() == 2 && cred("secret", "applied") > sec_applied0; }, seconds(40))) << cl_->metrics_text();
  const std::int64_t t_kv_done = now_us();
  EXPECT_EQ(cred("secret", "rejected"), 0.0);
  sleep_ms(6000);
  const std::int64_t t4 = now_us();
  window_report("window 4 before the new kver is current", t3, t_kv_done);
  window_report("window 4 kver 2 current (old scopes cold)", t_kv_done, t4);
  std::uint64_t kv2_hits = 0, kv2_commits = 0;
  for (int t = 0; t < kThreads; ++t)
    for (const auto& r : recs_[t])
      if (r.kver == 2 && r.start_us >= t_kv_done) {
        kv2_hits += r.op == 2 && r.st == KeyStatus::Hit;
        kv2_commits += r.op == 0 && r.st == KeyStatus::Committed;
      }
  std::fprintf(stderr, "[HR6] window 4 kver loaded after %.1f s; ops under kver 2: committed puts=%llu, Hit fetches=%llu\n",
               static_cast<double>(t_kv_done - t_kv) / 1e6, static_cast<unsigned long long>(kv2_commits), static_cast<unsigned long long>(kv2_hits));
  EXPECT_GT(kv2_commits, 0u) << "no put committed under the new kver";
  EXPECT_GT(kv2_hits, 0u) << "no fetch hit under the new kver";

  // ---- verdict ----
  stop_traffic();
  const std::string rep = oracle_->report();
  std::fprintf(stderr, "[HR6] %s\n", rep.c_str());
  EXPECT_EQ(oracle_->failed(), 0u) << rep;
  std::uint64_t hangs = 0;
  for (int t = 0; t < kThreads; ++t)
    for (const auto& r : recs_[t]) hangs += r.hang ? 1 : 0;
  EXPECT_EQ(hangs, 0u);
  EXPECT_GT(oracle_->total(), 1000u) << "too little traffic to mean anything";
  EXPECT_GT(oracle_->count_of(KeyStatus::Hit), 0u);
  EXPECT_EQ(cl_->config_rejected(), 0u) << cl_->config_last_error();
  EXPECT_EQ(cl_->rebuild_failures(), 0u);
}

INSTANTIATE_TEST_SUITE_P(Device, ReloadE2e, ::testing::ValuesIn(devices()),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

}  // namespace
}  // namespace miracache
