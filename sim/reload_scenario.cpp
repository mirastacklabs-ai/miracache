// SPDX-License-Identifier: Apache-2.0
// Hot reload under load, in the simulator.
//
// One seed = one cluster of three real memory-node servers over SimFabric and one real bundle-mode Client (the rig of
// tests/client/reload_test.cpp, reduced), pipelined put / get traffic (four lanes, as the four traffic threads of the
// unit tests), and a random SEQUENCE of valid reloads at random points of the traffic. Each reload is one new bundle
// generation that carries, at random:
//   * R (config.cluster.placement.replicas, 1 or 2),
//   * a client table: class A keys (fabric.keepalive_ms, reconnect caps, watchdog, ticket_batch, slice_bytes,
//     deadline.put_max_ms, placement.replica_mode / replica_buffer_bytes / previous_view_ms / hint_entries) and class B
//     keys (landing.subpool_bytes, fabric.mtu, fabric.fetch_qps), which start a planned rebuild of every node, one at a
//     time, while the traffic runs (leases held across the swap),
//   * a memory-node table (config.cluster.memnode: lease ttl / max / put timeout, ticket ttl, retention, store max_bytes),
//   * a new kver: from that op on every lane derives its scopes (and keys) under the new key version, so the old
//     scopes are cold (the kver part of the rotation test; the real secret-file and certificate rotation run on rxe0 in
//     tests/e2e/reload_rdma_test.cpp, the sim has no TLS and no files).
// The servers apply the bundle on their own thread-of-control turn (drive), the client through apply_membership.
// QPs per rail, live: odd seeds run every memory node with two rails (two devices, distinct rkeys) and every client
// pair with two NICs; their first three reloads set fabric.fetch_qps 2, 4, 2, and after each the run waits (traffic
// running) until miracache_client_rail_fetch_qps shows that count on every rail of every node. A fetch_qps change is
// applied by the planned rebuild: the new pair opens rails x (1 + fetch_qps + 1) endpoints.
//
// The oracle is tests/util/oracle.h in STRICT mode (every node and rail healthy): Refused, Aborted, Timeout, a wrong
// byte or a job without a Completion is a failure. After the last reload the client must have settled: every node
// rebuilt to the final class B values, the final dyn generation applied, the servers on the final lease values, no
// rebuild failure, no QP closed with a WR outstanding.
//
// The run is not bit-reproducible (the client's own keepalive threads do the rebuilds), so there is no trace hash; a
// failing seed is reproduced with `--seed X`, and its operation sequence (the events and where they fall) is a pure
// function of the seed.
//
//   sim_reload --seeds N [--first S]    seeds S..S+N-1 (S defaults to 1)
//   sim_reload --seed X                 one seed, verbose
// Exit 0 = every seed clean; 1 = a seed failed; 2 = bad arguments.
#include <dirent.h>
#include <execinfo.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "control/bundle.h"
#include "fabric/sim/sim_fabric.h"
#include "runtime/pause.h"
#include "server/dyn_config.h"
#include "server/server.h"
#include "src/client.h"
#include "util/clock.h"
#include "util/executor.h"
#include "util/log.h"
#include "util/oracle.h"
#include "util/random.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;
using std::chrono::milliseconds;
using std::chrono::seconds;
using testutil::Oracle;
using testutil::OracleMode;

constexpr unsigned kServers = 3;
constexpr unsigned kSpares = 10;  // spare client NICs per node: one per planned rebuild (a seed has at most 8 class B reloads)
constexpr unsigned kLanes = 4;
constexpr std::size_t kPayload = 8192;
constexpr std::uint64_t kSpinCap = 20'000'000;  // idle polls (each yields the CPU) without the awaited completions before a job counts as lost
constexpr std::size_t kBaseSubpool = 16u << 20;  // ClientCoreOptions default
constexpr std::uint32_t kBaseMtu = 4096, kBaseQps = 1;  // the open-time values (WireOptions defaults: one fetch QP per rail)

// Evidence for a lost job. The image has no debugger, so every thread of the process prints its own stack:
// SIGUSR2 to one thread at a time, whose handler prints with backtrace_symbols_fd (no malloc once primed). Frames print
// as `sim_reload(+0xOFF)`; the first 2-3 are the handler and the signal trampoline. Resolve the others with
// `addr2line -i -f -C -e build/<preset>/sim/sim_reload <OFF-1>` (they are return addresses; OFF itself is the line
// after the call) from the same build. Under ThreadSanitizer a signal is handled at the thread's next interceptor, so a
// blocked or spinning thread may print late or not at all ("did not answer"): reproduce with the sim preset.
std::atomic<unsigned> g_stacks_printed{0};
void put_str(const char* s) { (void)!::write(2, s, std::strlen(s)); }
void print_own_stack(int) {
  const int saved_errno = errno;  // the interrupted thread may be between a failing call and its errno check
  void* frames[80];
  const int n = ::backtrace(frames, 80);
  char head[40] = "--- thread ";
  char digits[24];
  int k = 0;
  for (unsigned long t = static_cast<unsigned long>(::syscall(SYS_gettid)); k == 0 || t > 0; t /= 10) digits[k++] = static_cast<char>('0' + t % 10);
  std::size_t at = std::strlen(head);
  while (k > 0) head[at++] = digits[--k];
  head[at++] = '\n';
  head[at] = '\0';
  put_str(head);
  ::backtrace_symbols_fd(frames, n, 2);
  g_stacks_printed.fetch_add(1, std::memory_order_release);  // last: the sender waits for it (no lock to get stuck on)
  errno = saved_errno;
}
void dump_all_stacks() {
  static bool installed = false;
  if (!installed) {
    // backtrace() loads the unwinder (dlopen, malloc) on its first call: do that here, never inside a handler.
    void* prime[4];
    const int pn = ::backtrace(prime, 4);
    const int null_fd = ::open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (null_fd >= 0) {
      ::backtrace_symbols_fd(prime, pn, null_fd);
      ::close(null_fd);
    }
    struct sigaction sa {};
    sa.sa_handler = print_own_stack;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    // Left installed on purpose: a late (or TSan-deferred) SIGUSR2 must still print, never kill the process.
    if (::sigaction(SIGUSR2, &sa, nullptr) != 0) {
      std::fprintf(stderr, "--- cannot install the stack handler (errno %d)\n", errno);
      return;
    }
    installed = true;
  }
#if defined(__SANITIZE_THREAD__)
  std::fprintf(stderr, "--- ThreadSanitizer build: each stack is taken at the thread's next interceptor; a blocked or "
                       "spinning thread may be late or missing\n");
#endif
  DIR* d = ::opendir("/proc/self/task");
  if (d == nullptr) {
    std::fprintf(stderr, "--- cannot read /proc/self/task (errno %d): no thread stacks\n", errno);
    return;
  }
  unsigned threads = 0, answered = 0;
  std::string silent;
  while (dirent* e = ::readdir(d)) {
    if (e->d_name[0] == '.') continue;
    const long tid = std::atol(e->d_name);
    const unsigned before = g_stacks_printed.load(std::memory_order_acquire);
    if (::syscall(SYS_tgkill, ::getpid(), tid, SIGUSR2) != 0) continue;  // exited meanwhile (ESRCH)
    ++threads;
    // One thread at a time, so two stacks never interleave; a thread that does not answer within 2 s is named and skipped.
    bool ok = false;
    for (int waited = 0; waited < 2000 && !ok; ++waited) {
      ok = g_stacks_printed.load(std::memory_order_acquire) != before;
      if (!ok) pause_for(std::chrono::milliseconds(1));
    }
    if (ok) ++answered;
    else silent += (silent.empty() ? "" : " ") + std::to_string(tid);
  }
  ::closedir(d);
  std::fprintf(stderr, "--- end of thread stacks: %u of %u threads answered%s%s\n", answered, threads,
               silent.empty() ? "" : "; did not answer within 2 s: ", silent.c_str());
}

class CounterSalts final : public NonceSource {
 protected:
  Status fill(std::span<std::byte> out) override {
    const unsigned n = n_.fetch_add(1, std::memory_order_relaxed) + 1;
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::byte>(n * 37 + i * 5 + 1);
    return {};
  }
  std::atomic<unsigned> n_{0};
};

class TestKeys final : public KeySource {
 public:
  explicit TestKeys(unsigned kver) : kver_(kver) {}
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
  void mix(std::span<const std::byte> raw, int tag, std::byte* out) const {
    for (int i = 0; i < 32; ++i) {
      std::uint64_t x = 1469598103934665603ull ^ static_cast<std::uint64_t>(kver_ * 977 + 7 * 131 + tag + i);
      for (auto b : raw) x = (x ^ static_cast<std::uint64_t>(b)) * 1099511628211ull;
      x ^= x >> 29;
      x *= 0x9E3779B97F4A7C15ull;
      out[i] = static_cast<std::byte>(x >> 56);
    }
  }
  unsigned kver_;
};

// The scopes of a lane under key version `kver`: a new kver is a new scope id and a new key source.
ScopeKeys scope_keys(unsigned lane, unsigned kver) {
  ScopeKeys sk;
  ScopeId s{};
  s.b[0] = static_cast<std::uint8_t>(lane);
  s.b[1] = static_cast<std::uint8_t>(kver);
  s.b[31] = 0x5c;
  sk.scopes = {s};
  sk.keys = std::make_shared<TestKeys>(kver);
  sk.kver = kver;
  return sk;
}

// Versioned payload: 8 bytes of version, then a pattern derived from (lane, kver, version).
Bytes payload(unsigned lane, unsigned kver, std::uint64_t v) {
  Bytes b(kPayload);
  std::memcpy(b.data(), &v, 8);
  for (std::size_t i = 8; i < b.size(); ++i)
    b[i] = static_cast<std::byte>((i * 31 + static_cast<std::size_t>(lane) * 7 + kver * 3 + v * 13) & 0xff);
  return b;
}
std::optional<std::uint64_t> decode(unsigned lane, unsigned kver, const Bytes& b) {
  std::uint64_t v;
  std::memcpy(&v, b.data(), 8);
  return payload(lane, kver, v) == b ? std::optional<std::uint64_t>(v) : std::nullopt;
}

struct Chain {
  explicit Chain(const std::string& name) {
    raw.assign(reinterpret_cast<const std::byte*>(name.data()), reinterpret_cast<const std::byte*>(name.data()) + name.size());
    ref.raw = raw;
    ref.chain_pos = 0;
  }
  Bytes raw;
  KeyRef ref;
};

// Rail `r` (0 or 1) of memory node `id`: its listen address (the bundle rail and the client RailOpt).
fabric::RailAddr rail_addr(unsigned id, unsigned r) { return fabric::RailAddr{"10.0." + std::to_string(r) + "." + std::to_string(id), 7471}; }

server::ServerConfig server_cfg() {
  server::ServerConfig sc;
  auto& c = sc.store;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 4;
  c.gen_chunk = 1000;
  c.put_timeout = seconds(1000);
  c.lease_ttl = seconds(1000);
  c.lease_max = seconds(2000);
  c.invalidate_per_s = 0;
  c.principal_default.max_scopes = 64;
  c.principal_default.max_bytes = 8u << 20;
  c.principal_default.idle_ttl = seconds(100000);
  sc.lab_identity = "lab";
  sc.lab_principal = 5;
  return sc;
}

// Three running memory nodes (ids 1..3), a client NIC per node and spare NICs for planned rebuilds. With `rails`
// = 2 every node has two devices, one rail each (distinct rkeys per device), and every client pair two NICs (one per
// rail, distinct lkeys), both fresh for each rebuild.
struct World {
  World(std::uint64_t seed, unsigned rails_) : rails(rails_), rng(seed), net(clock, rng, {}, opts()), jit(seed * 7 + 99) {
    for (unsigned i = 1; i <= kServers; ++i) {
      sfab[i - 1] = &net.add_node(i);
      cfab[i - 1] = &net.add_node(10 + i);
      for (unsigned k = 0; k < kSpares; ++k) spare[i - 1][k] = &net.add_node(100 + (i - 1) * kSpares + k);
      if (rails == 2) {
        sfab1[i - 1] = &net.add_node(20 + i);
        sfab1[i - 1]->set_key_base_for_test(0x1000);
        cfab1[i - 1] = &net.add_node(30 + i);
        cfab1[i - 1]->set_key_base_for_test(0x5000);
        for (unsigned k = 0; k < kSpares; ++k) {
          spare1[i - 1][k] = &net.add_node(200 + (i - 1) * kSpares + k);
          spare1[i - 1][k]->set_key_base_for_test(0x5000);
        }
      }
    }
    for (unsigned i = 1; i <= kServers; ++i) {
      auto sc = server_cfg();
      sc.store.node_id = i;
      if (rails != 2) sc.rails = {fabric::RailAddr{"sim", static_cast<std::uint16_t>(7000 + i)}};  // the single-rail client dials this
      auto s = [&]() -> Expected<std::unique_ptr<server::Server>> {
        if (rails != 2) return server::Server::create(sc, *sfab[i - 1], clock, rng, sex);
        sc.rails = {rail_addr(i, 0), rail_addr(i, 1)};
        sc.rail_device = {0, 1};
        sc.device_names = {"sdev0", "sdev1"};
        return server::Server::create(sc, std::vector<fabric::Fabric*>{sfab[i - 1], sfab1[i - 1]}, clock, rng, sex);
      }();
      if (!s) {
        ok = false;
        err = std::string("server create: ") + s.error().context;
        return;
      }
      srv[i - 1] = std::move(*s);
      if (auto st = srv[i - 1]->start(); !st) {
        ok = false;
        err = std::string("server start: ") + st.error().context;
        return;
      }
    }
  }
  static fabric::SimOptions opts() {
    fabric::SimOptions o;
    o.slice_size = 2048;
    return o;
  }
  // One sim turn: step the network (or advance the clock when idle), apply queued bundles to the servers, run them.
  // Called by every thread that waits (the caller's poll and the client's own threads): srv_mu serialises it.
  void drive() {
    if (!net.step()) clock.advance_by(milliseconds(1));
    std::lock_guard lk(srv_mu);
    for (auto& [id, v] : to_apply) srv[id - 1]->apply_bundle(v);
    to_apply.clear();
    for (unsigned i = 0; i < kServers; ++i) srv[i]->run_once();
  }
  Expected<Client::NodeSpec> spec(const control::NodeView& nv) {
    const unsigned i = nv.node_id;
    Client::NodeSpec ns;
    fabric::Fabric* f = cfab[i - 1];
    const unsigned k = specs_made[i - 1].fetch_add(1);
    if (k > 0) {
      if (k > kSpares) return Error{ErrorCode::ResourceExhausted, "sim: no spare client fabric left"};
      f = spare[i - 1][k - 1];
    }
    ns.fab = f;
    if (rails == 2) {
      // one endpoint set per rail in one session; rail 1 goes through its own client NIC (fresh per rebuild).
      WireOptions::RailOpt r0, r1;
      r0.index = 0, r0.addr = rail_addr(i, 0), r0.route = i, r0.device = "cdev0";
      r1.index = 1, r1.addr = rail_addr(i, 1), r1.route = 20 + i, r1.device = "cdev1";
      r1.fab = k == 0 ? cfab1[i - 1] : spare1[i - 1][k - 1];
      ns.wopts.rail = r0.addr;
      ns.wopts.rails = {r0, r1};
      ns.wopts.rail_tickets = [this, i](fabric::EpClass cls, std::uint8_t rail) -> Expected<proto::Ticket> {
        auto t = srv[i - 1]->issue_ticket("lab", cls, rail, 1);
        if (!t) return t.error();
        return (*t)[0];
      };
    } else {
      ns.wopts.rail.host = "sim";
      ns.wopts.rail.port = static_cast<std::uint16_t>(7000 + i);
      ns.wopts.tickets = [this, i](fabric::EpClass cls) -> Expected<proto::Ticket> {
        auto t = srv[i - 1]->issue_ticket("lab", cls, 0, 1);
        if (!t) return t.error();
        return (*t)[0];
      };
    }
    ns.wopts.random = &jit;
    ns.wopts.keepalive_ms = 0;
    ns.wopts.rpc_timeout = std::chrono::hours(100);
    return ns;
  }
  void queue_apply(unsigned id, const control::BundleView& v) {
    std::lock_guard lk(srv_mu);
    to_apply.emplace_back(id, v);
  }
  std::uint64_t client_aborts_with_work() const {
    std::uint64_t n = 0;
    for (unsigned i = 0; i < kServers; ++i) {
      n += cfab[i]->aborts_with_work();
      for (unsigned k = 0; k < kSpares; ++k) n += spare[i][k]->aborts_with_work();
      if (rails != 2) continue;
      n += cfab1[i]->aborts_with_work();
      for (unsigned k = 0; k < kSpares; ++k) n += spare1[i][k]->aborts_with_work();
    }
    return n;
  }
  unsigned rails = 1;  // rails per memory node (2 on odd seeds)
  bool ok = true;
  std::string err;
  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  SeededRandom jit;
  fabric::SimFabric* sfab[kServers];
  fabric::SimFabric* cfab[kServers];
  fabric::SimFabric* spare[kServers][kSpares];
  fabric::SimFabric* sfab1[kServers] = {};  // rails == 2: each node's second device, the client's rail-1 NICs
  fabric::SimFabric* cfab1[kServers] = {};
  fabric::SimFabric* spare1[kServers][kSpares] = {};
  std::atomic<unsigned> specs_made[kServers] = {};
  InlineExecutor sex;
  InlineExecutor cex;
  CounterSalts salts;
  std::unique_ptr<server::Server> srv[kServers];
  std::mutex srv_mu;  // guards to_apply and the servers' turn
  std::vector<std::pair<unsigned, control::BundleView>> to_apply;
};

MembershipSnapPtr make_snap(std::uint64_t gen, unsigned replicas, const std::string& config_toml, unsigned rails) {
  auto s = std::make_shared<MembershipSnap>();
  auto& b = s->view.body;
  b.schema_version = 1;
  b.generation = gen;
  b.epoch = 1;
  b.previous_epoch = 0;
  b.replicas = replicas;
  b.replicas_present = true;
  for (unsigned id = 1; id <= kServers; ++id) {
    control::NodeView nv;
    nv.node_id = id;
    nv.hostname = "host" + std::to_string(id);
    nv.admin = "10.0.0." + std::to_string(id) + ":9465";
    nv.rails.push_back(control::RailView{"10.0.0." + std::to_string(id) + ":7471", "a", "roce"});
    if (rails == 2) nv.rails.push_back(control::RailView{"10.0.1." + std::to_string(id) + ":7471", "b", "roce"});
    nv.weight = 1;
    nv.state = control::MemberState::Active;
    b.nodes.push_back(std::move(nv));
  }
  b.config_toml = config_toml;
  // The principal binds identity "lab", the one the sim tickets are issued for (membership_test.cpp signed_snap).
  s->view.sec.sec_generation = 1;
  control::PrincipalView p;
  p.name = "lab";
  p.id = control::principal_id("lab");
  p.identities = {"lab"};
  p.quota_bytes = 1073741824;
  p.max_scopes = 1000;
  s->view.sec.principals.push_back(std::move(p));
  s->envelope = "envelope-gen-" + std::to_string(gen);
  return s;
}

// What one reload asks for, and what the cluster must show once it has settled.
struct Want {
  unsigned replicas = 1;
  std::size_t subpool = kBaseSubpool;
  std::uint32_t mtu = kBaseMtu, qps = kBaseQps;
  std::optional<unsigned> keepalive_ms;
  bool has_lease = false;
  unsigned lease_ttl = 0, lease_max = 0, put_timeout = 0;
};

struct Reload {
  std::uint64_t gen = 0;
  std::string toml;
  Want want;
  bool new_kver = false;
  bool class_b = false;
  std::string what;  // for the failure message
  bool hr7 = false;  // one of the 2-rail seeds' fetch_qps 2 -> 4 -> 2 steps: the run waits until every rail shows it
};

template <class T>
T pick(Random& r, std::initializer_list<T> v) {
  return *(v.begin() + r.below(v.size()));
}

// A random valid reload. `force_qps`: this reload sets fabric.fetch_qps to that value (the draws stay the same).
Reload make_reload(Random& r, std::uint64_t gen, std::optional<std::uint32_t> force_qps = std::nullopt) {
  Reload rl;
  rl.gen = gen;
  Want& w = rl.want;
  w.replicas = static_cast<unsigned>(1 + r.below(2));
  std::ostringstream t;
  t << "[cluster.placement]\nreplicas = " << w.replicas << "\n";
  // ---- client class A and C keys ----
  std::ostringstream fab, dl, pl;
  if (r.below(2)) {
    w.keepalive_ms = static_cast<unsigned>(10 + r.below(40));
    fab << "keepalive_ms = " << *w.keepalive_ms << "\n";
  }
  if (r.below(3) == 0) {
    const unsigned mn = static_cast<unsigned>(10 + r.below(40));
    fab << "reconnect_min_ms = " << mn << "\nreconnect_max_ms = " << mn + 50 + r.below(400) << "\nreconnect_connect_ms = " << 200 + r.below(800) << "\n";
  }
  if (r.below(3) == 0) fab << "watchdog_grace_ms = " << 5000 + r.below(15000) << "\n";
  if (r.below(3) == 0) fab << "ticket_batch = " << 1 + r.below(16) << "\n";
  if (r.below(2)) fab << "slice_bytes = " << pick<unsigned>(r, {4096, 8192, 65536, 1048576}) << "\n";
  unsigned put_max_chosen = 0;  // a bundle that sets put_max_ms must also carry put_timeout_s >= 4 x it
  if (r.below(2)) dl << "put_max_ms = " << (put_max_chosen = 60000 + static_cast<unsigned>(r.below(540000))) << "\n";
  if (r.below(2)) pl << "replica_mode = \"" << (r.below(2) ? "sync" : "async") << "\"\n";
  if (r.below(3) == 0) pl << "replica_buffer_bytes = " << pick<std::uint64_t>(r, {1, 65536, 1u << 20, 8u << 20}) << "\n";
  if (r.below(3) == 0) pl << "previous_view_ms = " << 1000 + r.below(120000) << "\n";
  if (r.below(3) == 0) pl << "hint_entries = " << r.below(64) << "\n";
  // ---- client class B keys: absent = the open-time value ----
  std::ostringstream land;
  if (r.below(3) == 0) {
    w.subpool = pick<std::size_t>(r, {4u << 20, 8u << 20, 12u << 20, 32u << 20});
    land << "subpool_bytes = " << w.subpool << "\n";
  }
  if (r.below(4) == 0) {
    w.mtu = pick<std::uint32_t>(r, {1024, 2048});
    fab << "mtu = " << w.mtu << "\n";
  }
  const bool qps_drawn = r.below(3) == 0;
  const std::uint32_t qps_pick = pick<std::uint32_t>(r, {2, 4});
  if (qps_drawn || force_qps) {  // the real per-rail fetch QP count changes at the planned rebuild
    w.qps = force_qps.value_or(qps_pick);
    fab << "fetch_qps = " << w.qps << "\n";
  }
  rl.hr7 = force_qps.has_value();
  rl.class_b = w.subpool != kBaseSubpool || w.mtu != kBaseMtu || w.qps != kBaseQps;
  if (!fab.str().empty()) t << "\n[cluster.client.fabric]\n" << fab.str();
  if (!dl.str().empty()) t << "\n[cluster.client.deadline]\n" << dl.str();
  if (!pl.str().empty()) t << "\n[cluster.client.placement]\n" << pl.str();
  if (!land.str().empty()) t << "\n[cluster.client.landing]\n" << land.str();
  // ---- memory-node class A keys ----
  if (r.below(2) || put_max_chosen != 0) {
    w.has_lease = true;
    w.lease_ttl = static_cast<unsigned>(60 + r.below(900));
    w.lease_max = w.lease_ttl + static_cast<unsigned>(r.below(1000));
    w.put_timeout = std::max(static_cast<unsigned>(60 + r.below(900)), (4 * put_max_chosen + 999) / 1000);
    t << "\n[cluster.memnode.lease]\nttl_s = " << w.lease_ttl << "\nmax_s = " << w.lease_max << "\nput_timeout_s = " << w.put_timeout << "\n";
  }
  if (r.below(3) == 0) t << "\n[cluster.memnode.ticket]\nttl_s = " << 60 + r.below(3000) << "\n";
  if (r.below(3) == 0) t << "\n[cluster.memnode.retention]\nidle_ttl_s = " << 50000 + r.below(50000) << "\n";
  if (r.below(3) == 0) t << "\n[cluster.memnode.store]\nmax_bytes = " << (8u << 20) + r.below(8u << 20) << "\n";
  if (r.below(5) == 0) t << "\n[cluster.memnode.limits]\nticket_max_per_identity = " << 100 + r.below(1000) << "\n";
  rl.new_kver = r.below(4) == 0;
  rl.toml = t.str();
  std::ostringstream wh;
  wh << "R=" << w.replicas << (rl.class_b ? " classB(pool=" + std::to_string(w.subpool >> 20) + "M mtu=" + std::to_string(w.mtu) + " qps=" + std::to_string(w.qps) + ")" : "")
     << (w.has_lease ? " lease=" + std::to_string(w.lease_ttl) + "/" + std::to_string(w.lease_max) : "") << (rl.new_kver ? " +kver" : "") << (rl.hr7 ? " (rail-count step)" : "");
  rl.what = wh.str();
  return rl;
}


struct Run {
  Run(std::uint64_t s, bool verbose_) : seed(s), verbose(verbose_), w(s, s % 2 == 1 ? 2 : 1), orc(OracleMode::Strict) {}
  ~Run() { cl.reset(); }  // the client's threads stop before the World they drive goes away

  bool open() {
    if (!w.ok) return fail(w.err);
    auto first = make_snap(1, 1, "", w.rails);
    for (unsigned id = 1; id <= kServers; ++id) w.srv[id - 1]->apply_bundle(first->view);
    Client::Env env;
    env.clock = &w.clock;
    env.executor = &w.cex;
    env.salts = &w.salts;
    env.drive = [this] { w.drive(); };
    env.replica_buffer_bytes = 8u << 20;
    // Store deadlines are clamped to put_max_ms of SIM time, which a waiting caller burns in milliseconds of real time.
    env.put_max_ms = 600000;
    env.set_crypto_workers = [](unsigned) {};
    Client::BundleOpen bo;
    bo.initial = std::move(first);
    bo.make_spec = [this](const control::NodeView& nv) { return w.spec(nv); };
    bo.push = [](const std::string&) -> Status { return {}; };  // the servers get every bundle straight from the harness
    bo.wake = [](std::uint32_t, const std::string&) {};
    bo.keepalive_ms = 10;
    bo.connect_wait_ms = 2000;
    bo.rebuild_jitter_ms = 200;
    bo.rebuild_drain_ms = 30000;
    RuntimeOptions ro;
    ro.workers = 2;
    auto c = Client::open_bundle(env, std::move(bo), {}, {}, ro);
    if (!c) return fail(std::string("open_bundle: ") + c.error().context);
    cl = std::move(*c);
    return true;
  }

  bool fail(const std::string& why) {
    if (failure.empty()) failure = why;
    return false;
  }

  // Waits for every ticket in `ts`: polls (the poll drives the sim) until all have completed.
  std::optional<std::map<std::uint64_t, Completion>> await(const std::vector<Ticket>& ts) {
    std::map<std::uint64_t, Completion> got;
    std::set<std::uint64_t> want;
    for (auto& t : ts) want.insert(t.id);
    for (std::uint64_t spin = 0; got.size() < want.size(); ++spin) {
      if (spin > kSpinCap) {
        // Evidence for a lost job, lock-free facts first: the metrics below take the registry lock and run
        // callback gauges, so a lost job that is a lock deadlock could hang there; everything else is printed by then.
        std::fprintf(stderr, "seed %llu LOST JOB: sim_now=%lld ms rebuilding_slot=%ld rebuilds_done=%llu rebuild_failures=%llu waiting=%zu got=%zu\n",
                     (unsigned long long)seed, (long long)(w.clock.now().count() / 1'000'000), cl->rebuilding_slot(),
                     (unsigned long long)cl->rebuilds_done(), (unsigned long long)cl->rebuild_failures(), want.size(), got.size());
        // Frozen or moving? Sim time in ns and the workers' job-loop turns, 200 ms of real time apart.
        const long long t0 = static_cast<long long>(w.clock.now().count());
        const auto it0 = cl->pump_iterations();
        pause_for(std::chrono::milliseconds(200));
        const long long t1 = static_cast<long long>(w.clock.now().count());
        const auto it1 = cl->pump_iterations();
        std::fprintf(stderr, "seed %llu LOST JOB detail: sim_now %lld -> %lld ns, job-loop turns %llu -> %llu over 200 ms real%s%s\n",
                     (unsigned long long)seed, t0, t1, (unsigned long long)it0, (unsigned long long)it1,
                     t1 == t0 ? " (sim time frozen: no thread drives the sim)" : "",
                     it1 == it0 ? " (no worker is in a job loop: deadlocked there, or the job is not held by any worker; see the stacks)" : "");
        dump_all_stacks();
        std::fprintf(stderr, "%s\n", cl->metrics_text().c_str());
        return std::nullopt;
      }
      std::array<Completion, 8> buf;
      const std::size_t n = cl->poll(buf);
      if (n == 0) ::sched_yield();  // a spinning caller must not eat the CPU quota the client's worker threads need
      for (std::size_t i = 0; i < n; ++i)
        if (want.count(buf[i].ticket.id)) got[buf[i].ticket.id] = std::move(buf[i]);
    }
    return got;
  }

  // One traffic cycle: every lane stores a new key, then fetches it, and probes the previous-kver scope (a miss).
  bool cycle() {  // false = a job never completed (the seed is over)
    struct Op {
      unsigned lane;
      std::string key;
      std::uint64_t v;
      std::unique_ptr<Chain> ch;
      std::shared_ptr<Bytes> data;
      std::vector<BufRef> bufs;
      Ticket t;
    };
    std::vector<Op> puts(kLanes);
    std::vector<Ticket> ts;
    for (unsigned l = 0; l < kLanes; ++l) {
      Op& o = puts[l];
      o.lane = l;
      o.v = ++ver[l];
      o.key = "k" + std::to_string(l) + "_" + std::to_string(kver) + "_" + std::to_string(o.v);  // immutable: a key is stored once
      o.ch = std::make_unique<Chain>(o.key);
      o.data = std::make_shared<Bytes>(payload(l, kver, o.v));
      o.bufs = {{std::span<std::byte>(*o.data)}};
      orc.begin_store(o.key, o.v);
      o.t = cl->store(scope_keys(l, kver), 0, std::span<const KeyRef>(&o.ch->ref, 1), o.bufs, seconds(60));
      ts.push_back(o.t);
    }
    auto dn = await(ts);
    if (!dn) {
      for (auto& o : puts) {
        quarantine.push_back(o.data);
        orc.on_missing_completion("store " + o.key);
      }
      return false;
    }
    auto done = std::move(*dn);
    for (auto& o : puts) {
      const KeyStatus st = done.at(o.t.id).status.at(0);
      orc.end_store(o.key, o.v, st == KeyStatus::Committed);
      orc.on_store(o.key, st);
    }
    struct Get {
      unsigned lane;
      std::string key;
      unsigned kv;
      bool probe;
      std::unique_ptr<Chain> ch;
      std::shared_ptr<Bytes> out;
      std::vector<BufRef> bufs;
      Ticket t;
    };
    std::vector<Get> gets;
    for (unsigned l = 0; l < kLanes; ++l) {
      gets.push_back(Get{l, puts[l].key, kver, false, nullptr, nullptr, {}, {}});
      // Also re-read an OLDER committed key of this lane (R or the owner may have changed since): Miss or the exact bytes.
      if (ver[l] > 4) gets.push_back(Get{l, "k" + std::to_string(l) + "_" + std::to_string(kver) + "_" + std::to_string(ver[l] - 3), kver, false, nullptr, nullptr, {}, {}});
    }
    // The cold-scope probe: a key stored under the previous kver, read under the current one, must Miss.
    if (!old_key.empty()) gets.push_back(Get{0, old_key, kver, true, nullptr, nullptr, {}, {}});
    ts.clear();
    for (auto& g : gets) {
      g.ch = std::make_unique<Chain>(g.key);
      g.out = std::make_shared<Bytes>(kPayload, std::byte{0xAA});
      g.bufs = {{std::span<std::byte>(*g.out)}};
      g.t = cl->fetch(scope_keys(g.lane, g.kv), 0, std::span<const KeyRef>(&g.ch->ref, 1), g.bufs, seconds(60));
      ts.push_back(g.t);
    }
    dn = await(ts);
    if (!dn) {
      for (auto& g : gets) {
        quarantine.push_back(g.out);
        orc.on_missing_completion("fetch " + g.key);
      }
      return false;
    }
    done = std::move(*dn);
    for (auto& g : gets) {
      const KeyStatus st = done.at(g.t.id).status.at(0);
      if (g.probe) {
        // A Hit here has no decodable version under this kver: the oracle fails it as wrong bytes.
        orc.on_fetch(g.key, st, std::nullopt, false, "cold-scope probe under kver " + std::to_string(g.kv));
      } else {
        orc.on_fetch(g.key, st, st == KeyStatus::Hit ? decode(g.lane, g.kv, *g.out) : std::nullopt);
      }
    }
    ++cycles;
    return true;
  }

  // Publishes the reload: the servers through their queue (applied on their next turn), the client through the bundle path.
  void publish(const Reload& rl) {
    auto snap = make_snap(++pub_gen, rl.want.replicas, rl.toml, w.rails);
    for (unsigned id = 1; id <= kServers; ++id) w.queue_apply(id, snap->view);
    cl->apply_membership(snap);
    if (rl.new_kver) {
      old_key = "k0_" + std::to_string(kver) + "_" + std::to_string(ver[0]);  // the latest key of lane 0 under the old kver
      ++kver;
    }
    expect = rl.want;
    expect_gen = pub_gen;
    if (verbose) std::fprintf(stderr, "  [seed %llu] cycle %llu: gen %llu %s\n", (unsigned long long)seed, (unsigned long long)cycles, (unsigned long long)pub_gen, rl.what.c_str());
  }

  // miracache_client_config_pending_rebuild_keys: class B keys whose wanted value some node does not run yet (-1 = no series).
  long pending_keys() const {
    const std::string m = cl->metrics_text();
    const std::string name = "miracache_client_config_pending_rebuild_keys";
    for (std::size_t pos = 0; pos < m.size();) {
      std::size_t end = m.find('\n', pos);
      if (end == std::string::npos) end = m.size();
      if (m.compare(pos, name.size(), name) == 0 && (m[pos + name.size()] == ' ' || m[pos + name.size()] == '{'))
        return std::strtol(m.c_str() + m.rfind(' ', end) + 1, nullptr, 10);
      pos = end + 1;
    }
    return -1;
  }

  bool slots_run(const Want& e) {
    for (std::uint32_t id = 1; id <= kServers; ++id) {
      const long s = cl->slot_of(id);
      Client::SlotClassB b;
      if (s < 0 || !cl->slot_class_b(static_cast<std::size_t>(s), b)) return false;
      if (b.pool_bytes != e.subpool || b.mtu != e.mtu || b.fetch_qps != e.qps) return false;
    }
    return true;
  }

  // The fetch QPs connected on every rail of every node (miracache_client_rail_fetch_qps, the active pairs'), or
  // nullopt when they differ or a series is missing.
  std::optional<long> rail_qps() const {
    const std::string m = cl->metrics_text();
    const std::string name = "miracache_client_rail_fetch_qps{";
    std::optional<long> v;
    unsigned seen = 0;
    for (std::size_t pos = 0; pos < m.size();) {
      std::size_t end = m.find('\n', pos);
      if (end == std::string::npos) end = m.size();
      if (m.compare(pos, name.size(), name) == 0 && m.substr(pos, end - pos).find("node_id=\"0\"") == std::string::npos) {
        const long x = std::strtol(m.c_str() + m.rfind(' ', end) + 1, nullptr, 10);
        if (v && *v != x) return std::nullopt;
        v = x;
        ++seen;
      }
      pos = end + 1;
    }
    if (seen != kServers * w.rails) return std::nullopt;
    return v;
  }
  bool settled() {
    return cl->dyn() && cl->dyn()->generation == expect_gen && cl->rebuilding_slot() < 0 && slots_run(expect) && pending_keys() == 0 &&
           rail_qps() == static_cast<long>(expect.qps);
  }

  // The whole seed. Returns true when clean.
  bool go() {
    if (!open()) return false;
    SeededRandom pr(seed * 0x9E3779B97F4A7C15ull + 1);  // the plan is a pure function of the seed
    const unsigned n_cycles = 24 + static_cast<unsigned>(pr.below(40));
    unsigned n_events = 2 + static_cast<unsigned>(pr.below(6));  // at most 7: fewer spare NICs than that per node
    // 2-rail seeds: the first three reloads in time carry fabric.fetch_qps 2, 4, 2 (QPs per rail, live); the run
    // waits after each until every rail of every node shows that many fetch QPs, traffic running throughout.
    static constexpr std::uint32_t kHr7[] = {2, 4, 2};
    if (w.rails == 2) n_events = std::max(n_events, 3u);
    std::vector<Reload> rls;
    std::vector<unsigned> ats;
    for (unsigned e = 0; e < n_events; ++e) {
      const auto force = w.rails == 2 && e < 3 ? std::optional<std::uint32_t>(kHr7[e]) : std::nullopt;
      rls.push_back(make_reload(pr, 0, force));  // a node rebuilds at most once per reload: n_events <= 7 < kSpares
      unsigned at = static_cast<unsigned>(1 + pr.below(n_cycles));
      while (std::find(ats.begin(), ats.end(), at) != ats.end()) ++at;
      ats.push_back(at);
    }
    std::sort(ats.begin(), ats.end());  // reload e is published e-th
    std::map<unsigned, Reload> plan;  // cycle -> reload
    for (unsigned e = 0; e < n_events; ++e) plan.emplace(ats[e], std::move(rls[e]));
    bool alive = true;
    for (unsigned c = 0; alive && c <= n_cycles + n_events; ++c) {
      const auto it = plan.find(c);
      if (it != plan.end()) publish(it->second);
      alive = cycle();
      if (alive && it != plan.end() && it->second.hr7) {
        for (unsigned extra = 0; alive && extra < 4000 && !settled(); ++extra) alive = cycle();
        if (alive && !settled()) {
          fail("fetch_qps " + std::to_string(expect.qps) + " never showed on every rail");
          return finish();
        }
        if (alive) qps_seen.push_back(*rail_qps());
      }
    }
    // Settle: traffic continues until the client shows the last reload (rebuilds included).
    for (unsigned extra = 0; alive && extra < 4000; ++extra) {
      alive = cycle();
      if (alive && settled()) break;
    }
    for (int i = 0; alive && i < 6; ++i) alive = cycle();  // the servers have applied the last bundle by now
    if (!alive) fail("a job never completed (no Completion by the poll cap)");
    return finish();
  }

  bool finish() {
    if (!failure.empty()) return false;
    if (!cl->dyn() || cl->dyn()->generation != expect_gen) fail("client dyn generation " + std::to_string(cl->dyn() ? cl->dyn()->generation : 0) + " != " + std::to_string(expect_gen));
    if (cl->rebuilding_slot() >= 0 || !slots_run(expect)) fail("rebuilds did not settle to the final class B values");
    if (rail_qps() != static_cast<long>(expect.qps)) fail("the rails do not all show " + std::to_string(expect.qps) + " fetch QPs");
    if (w.rails == 2 && qps_seen != std::vector<long>{2, 4, 2}) fail("the 2 -> 4 -> 2 fetch QPs per rail were not all seen");
    if (pending_keys() != 0) fail("class B keys still pending: " + std::to_string(pending_keys()));
    if (cl->rebuild_failures() != 0) fail("rebuild_failures=" + std::to_string(cl->rebuild_failures()));
    if (cl->config_rejected() != 0) fail("a valid reload was rejected: " + cl->config_last_error());
    if (cl->membership_generation() != expect_gen) fail("membership generation " + std::to_string(cl->membership_generation()));
    if (w.client_aborts_with_work() != 0) fail("a client QP was closed with a WR outstanding");
    {
      std::lock_guard lk(w.srv_mu);
      for (unsigned i = 0; i < kServers; ++i) {
        const auto d = w.srv[i]->dyn();
        if (!d) {
          fail("server " + std::to_string(i + 1) + " has no dyn snapshot");
          continue;
        }
        const seconds lt = expect.has_lease ? seconds(expect.lease_ttl) : seconds(1000);
        const seconds lm = expect.has_lease ? seconds(expect.lease_max) : seconds(2000);
        if (d->lease_ttl != lt || d->lease_max != lm)
          fail("server " + std::to_string(i + 1) + " lease " + std::to_string(std::chrono::duration_cast<seconds>(d->lease_ttl).count()) + "/" +
               std::to_string(std::chrono::duration_cast<seconds>(d->lease_max).count()) +
               " != " + std::to_string(lt.count()) + "/" + std::to_string(lm.count()));
      }
    }
    if (orc.failed() != 0) fail(orc.report());
    if (orc.count_of(KeyStatus::Hit) == 0) fail("no Hit at all: " + orc.report());
    return failure.empty();
  }

  std::uint64_t seed;
  bool verbose;
  World w;
  std::unique_ptr<Client> cl;
  Oracle orc;
  std::string failure;
  std::uint64_t ver[kLanes] = {};
  unsigned kver = 1;
  std::uint64_t cycles = 0;
  std::string old_key;  // a key stored under the previous kver (the cold-scope probe)
  Want expect;
  std::uint64_t expect_gen = 1, pub_gen = 1;  // generations are numbered in publish order
  std::vector<std::shared_ptr<Bytes>> quarantine;  // buffers of lost jobs: the client may still hold them
  std::vector<long> qps_seen;  // fetch QPs per rail shown after each 2 -> 4 -> 2 step (2-rail seeds)
};

}  // namespace
}  // namespace miracache

int main(int argc, char** argv) {
  using miracache::Run;
  std::uint64_t first = 1, n = 0;
  bool verbose = false;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    auto num = [&](std::uint64_t& out) {
      if (i + 1 >= argc) return false;
      char* end = nullptr;
      out = std::strtoull(argv[++i], &end, 10);
      return end != nullptr && *end == '\0';
    };
    if (a == "--seeds") {
      if (!num(n) || n == 0) return 2;
    } else if (a == "--first") {
      if (!num(first) || first == 0) return 2;
    } else if (a == "--seed") {
      if (!num(first) || first == 0) return 2;
      n = 1;
      verbose = true;
    } else {
      std::fprintf(stderr, "usage: sim_reload --seeds N [--first S] | --seed X\n");
      return 2;
    }
  }
  if (n == 0) {
    std::fprintf(stderr, "usage: sim_reload --seeds N [--first S] | --seed X\n");
    return 2;
  }
  if (!verbose) miracache::log::set_sink_fd(::open("/dev/null", O_WRONLY));  // the nodes' and the client's reload log lines
  std::uint64_t bad = 0, ops = 0, hits = 0, misses = 0, committed = 0, skipped = 0, cycles = 0, oracle_failed = 0;
  std::uint64_t two_rail = 0, hr7_walked = 0;  // 2-rail seeds, and those whose every rail showed 2 -> 4 -> 2 fetch QPs
  for (std::uint64_t s = first; s < first + n; ++s) {
    Run r(s, verbose);
    const bool ok = r.go();
    ops += r.orc.total();
    hits += r.orc.count_of(miracache::KeyStatus::Hit);
    misses += r.orc.count_of(miracache::KeyStatus::Miss);
    committed += r.orc.count_of(miracache::KeyStatus::Committed);
    skipped += r.orc.count_of(miracache::KeyStatus::Skipped);
    cycles += r.cycles;
    oracle_failed += r.orc.failed();
    two_rail += r.w.rails == 2;
    hr7_walked += r.w.rails == 2 && r.qps_seen == std::vector<long>{2, 4, 2};
    if (verbose) std::fprintf(stderr, "seed %llu: %s\n", (unsigned long long)s, r.orc.report().c_str());
    if (!ok) {
      ++bad;
      std::fprintf(stderr, "seed %llu FAILED: %s\n", (unsigned long long)s, r.failure.c_str());
      if (bad >= 5) break;
    }
  }
  std::printf("2-rail seeds=%llu, fetch QPs per rail seen 2 -> 4 -> 2 on every node and rail: %llu\n", (unsigned long long)two_rail,
              (unsigned long long)hr7_walked);
  std::printf("%s: seeds=%llu failed=%llu ops=%llu hit=%llu miss=%llu committed=%llu skipped=%llu cycles=%llu failed_ops_by_oracle=%llu\n",
              bad == 0 ? "OK" : "FAIL", (unsigned long long)n, (unsigned long long)bad, (unsigned long long)ops, (unsigned long long)hits,
              (unsigned long long)misses, (unsigned long long)committed, (unsigned long long)skipped, (unsigned long long)cycles,
              (unsigned long long)oracle_failed);
  return bad == 0 ? 0 : 1;
}
