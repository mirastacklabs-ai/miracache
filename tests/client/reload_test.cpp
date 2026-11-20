// SPDX-License-Identifier: Apache-2.0
// HR2: client live configuration (hot-reload plan decisions 2-4). The bundle's config.cluster.client table is parsed over the
// open-time values and swapped in as one atomic snapshot. Real memory-node servers over SimFabric (the rig is the one of
// membership_test.cpp, copied: the two files build separately), 4-thread traffic with the strict oracle across every
// class A key, class B recorded as pending, unknown keys ignored and counted, bad values and STATIC keys rejected.
// HR3b (decision 6): a class B change rebuilds each node make-before-break (ClientRebuild.*): every later make_spec of a
// node gets a spare client NIC, the decrypt executor can be held to keep a job inside a pair, and Overlap samples the
// client endpoints and the server connections at every drive.
#include <gtest/gtest.h>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "fabric/sim/sim_fabric.h"
#include "server/server.h"
#include "control/bundle.h"
#include "control/bundle_test_util.h"
#include "control/trust_keys.h"
#include "proto/frame.h"
#include "proto/messages.h"
#include "src/client.h"
#include "src/placement.h"
#include "util/clock.h"
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
constexpr unsigned kServers = 6;
constexpr std::size_t kPayload = 8192;

class CounterSalts final : public NonceSource {
 protected:
  Status fill(std::span<std::byte> out) override {
    const unsigned n = n_.fetch_add(1, std::memory_order_relaxed) + 1;
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::byte>(n * 37 + i * 5 + 1);
    return {};
  }
  std::atomic<unsigned> n_{0};
};

// HR3b: the client's decrypt executor. Inline, unless a test holds it: then a fetch's decrypt waits (the job stays inside
// its pair, its lease held) until release() runs it on the test thread.
class GateExecutor final : public Executor {
 public:
  void post(std::function<void()> work, std::function<void()> done) override {
    {
      std::lock_guard lk(mu_);
      if (hold_) {
        q_.emplace_back(std::move(work), std::move(done));
        return;
      }
    }
    work();
    done();
  }
  void hold() {
    std::lock_guard lk(mu_);
    hold_ = true;
  }
  std::size_t held() {
    std::lock_guard lk(mu_);
    return q_.size();
  }
  void release() {
    std::deque<std::pair<std::function<void()>, std::function<void()>>> q;
    {
      std::lock_guard lk(mu_);
      hold_ = false;
      q.swap(q_);
    }
    for (auto& [w, d] : q) {
      w();
      d();
    }
  }

 private:
  std::mutex mu_;
  bool hold_ = false;
  std::deque<std::pair<std::function<void()>, std::function<void()>>> q_;
};

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

ScopeKeys scope_keys(int scope) {
  ScopeKeys sk;
  ScopeId s{};
  s.b[0] = static_cast<std::uint8_t>(scope);
  s.b[31] = 0x5c;
  sk.scopes = {s};
  sk.keys = std::make_shared<TestKeys>();
  sk.kver = 1;
  return sk;
}

// Versioned payload: 8 bytes of version, then a pattern derived from (scope, version).
Bytes payload(int scope, std::uint64_t v) {
  Bytes b(kPayload);
  std::memcpy(b.data(), &v, 8);
  for (std::size_t i = 8; i < b.size(); ++i) b[i] = static_cast<std::byte>((i * 31 + static_cast<std::size_t>(scope) * 7 + v * 13) & 0xff);
  return b;
}
std::optional<std::uint64_t> decode(int scope, const Bytes& b) {
  std::uint64_t v;
  std::memcpy(&v, b.data(), 8);
  return payload(scope, v) == b ? std::optional<std::uint64_t>(v) : std::nullopt;
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

// MB6b: stands in for MB4's epoch enforcement (the real server enforces it from MB4 on) at the client's side of the sim
// fabric. Per memory node it has an applied (epoch, bundle_gen_lo), stamps every frame it delivers to the client with
// them (decision 8: "every reply frame carries the node's epoch and bundle_gen_lo"), and answers a PUT_BEGIN whose frame
// epoch differs from the node's with StaleEpoch (retry 0 when the frame is lower, 50 ms when higher), or Draining when
// `draining` is set, without forwarding it to the server. Everything else passes through to the real server.
struct NodeStamp {
  std::atomic<std::uint32_t> epoch{0}, gen_lo{0};  // 0 = this node is not stamped / not enforced (lab mode)
  std::atomic<bool> draining{false};
  std::atomic<unsigned> stale_replies{0}, draining_replies{0}, put_begins_passed{0};
  void set(std::uint32_t e, std::uint32_t g) {
    epoch = e;
    gen_lo = g;
  }
};

class ShimFabric;
class ShimEndpoint final : public fabric::Endpoint {
 public:
  ShimEndpoint(ShimFabric& f, fabric::Endpoint* in) : f_(f), in_(in) {}
  fabric::EndpointId id() const override { return in_->id(); }
  Status post_send(fabric::Frame frame, fabric::WrTag tag) override;
  Status post_read(fabric::RemoteRef r, fabric::LocalRef l, fabric::WrTag t) override { return in_->post_read(r, l, t); }
  Status post_write(fabric::LocalRef l, fabric::RemoteRef r, fabric::WrTag t) override { return in_->post_write(l, r, t); }
  void abort() override { in_->abort(); }
  bool drained() const override { return in_->drained(); }
  fabric::EpState state() const override { return in_->state(); }
  fabric::ReadDepth read_depth() const override { return in_->read_depth(); }
  std::span<const std::byte> peer_private_data() const override { return in_->peer_private_data(); }
  fabric::Endpoint* inner() const { return in_; }

 private:
  ShimFabric& f_;
  fabric::Endpoint* in_;
};

class ShimFabric final : public fabric::Fabric {
 public:
  ShimFabric(fabric::Fabric& in, NodeStamp& st) : in_(in), st_(st) {}
  Expected<fabric::DeviceCaps> probe() override { return in_.probe(); }
  Expected<fabric::PdId> alloc_pd() override { return in_.alloc_pd(); }
  Status free_pd(fabric::PdId pd) override { return in_.free_pd(pd); }
  Expected<fabric::MemRegion> reg(std::span<std::byte> b, fabric::Access a, fabric::PdId pd) override { return in_.reg(b, a, pd); }
  Status dereg(const fabric::MemRegion& r) override { return in_.dereg(r); }
  Expected<fabric::Endpoint*> connect(const fabric::Peer& p, const fabric::ConnParams& cp) override {
    auto e = in_.connect(p, cp);
    if (!e) return e.error();
    std::lock_guard lk(mu_);
    eps_.push_back(std::make_unique<ShimEndpoint>(*this, *e));
    return eps_.back().get();
  }
  Status release(fabric::Endpoint* ep) override {
    auto* w = static_cast<ShimEndpoint*>(ep);
    Status s = in_.release(w->inner());
    if (!s) return s;
    std::lock_guard lk(mu_);
    for (auto it = eps_.begin(); it != eps_.end(); ++it)
      if (it->get() == w) {
        eps_.erase(it);
        break;
      }
    return {};
  }
  Status listen(fabric::AcceptFn f, const fabric::ListenParams& lp) override { return in_.listen(std::move(f), lp); }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget b) override {
    std::size_t n = in_.poll(out, b);
    for (std::size_t i = 0; i < n; ++i) {
      auto& c = out[i];
      if (!c.is_recv || c.op != fabric::CompletionOp::Recv) continue;
      stamp(c.frame.bytes);
    }
    std::lock_guard lk(mu_);
    while (n < out.size() && !synth_.empty()) {
      out[n++] = std::move(synth_.front());
      synth_.pop_front();
    }
    return n;
  }
  int wait_fd() override { return in_.wait_fd(); }

  // Called by ShimEndpoint::post_send: true = the frame was answered here (not forwarded).
  bool intercept(fabric::EndpointId ep, const fabric::Frame& frame) {
    auto fr = proto::decode_frame(frame.bytes);
    const std::uint32_t ne = st_.epoch.load();
    if (!fr || ne == 0 || fr->h.type != static_cast<std::uint16_t>(proto::Op::PUT_BEGIN)) return false;
    proto::WireStatus ws;
    std::uint32_t retry = 0;
    if (st_.draining.load()) {
      ws = proto::WireStatus::Draining;
      ++st_.draining_replies;
    } else if (fr->h.epoch != ne) {
      ws = proto::WireStatus::StaleEpoch;
      retry = fr->h.epoch > ne ? 50 : 0;
      ++st_.stale_replies;
    } else {
      ++st_.put_begins_passed;
      return false;
    }
    proto::FrameHeader h = fr->h;
    h.epoch = ne;
    h.bundle_gen_lo = st_.gen_lo.load();
    std::array<std::byte, 64> buf{};
    auto n = proto::encode_error_reply_frame(h, proto::ErrorReply{static_cast<std::uint16_t>(ws), retry}, buf);
    if (!n) return false;
    fabric::Completion c;
    c.endpoint = ep;
    c.is_recv = true;
    c.op = fabric::CompletionOp::Recv;
    c.bytes = static_cast<std::uint32_t>(*n);
    c.frame.bytes.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*n));
    std::lock_guard lk(mu_);
    synth_.push_back(std::move(c));
    return true;
  }

 private:
  void stamp(std::vector<std::byte>& bytes) {
    const std::uint32_t ne = st_.epoch.load();
    if (ne == 0) return;
    auto fr = proto::decode_frame(bytes);
    if (!fr) return;
    proto::FrameHeader h = fr->h;
    h.epoch = ne;
    h.bundle_gen_lo = st_.gen_lo.load();
    std::vector<std::byte> body(fr->body.begin(), fr->body.end());
    std::vector<std::byte> out(bytes.size());
    auto n = proto::encode_frame(h, body, out);
    if (n) bytes.assign(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(*n));
  }
  fabric::Fabric& in_;
  NodeStamp& st_;
  std::mutex mu_;
  std::vector<std::unique_ptr<ShimEndpoint>> eps_;
  std::deque<fabric::Completion> synth_;
};

Status ShimEndpoint::post_send(fabric::Frame frame, fabric::WrTag tag) {
  if (f_.intercept(in_->id(), frame)) return {};
  return in_->post_send(std::move(frame), tag);
}

// Memory nodes 1..kServers are all running; a bundle decides which ones the client knows.
struct World {
  explicit World(std::map<unsigned, unsigned> wrong_id = {}, bool shim_on = false, unsigned max_conns = 0)
      : rng(5), net(clock, rng, {}, opts()) {
    for (unsigned i = 1; i <= kServers; ++i) {
      sfab[i - 1] = &net.add_node(i);
      cfab[i - 1] = &net.add_node(10 + i);
      // HR3b: a planned rebuild asks make_spec for a fresh fabric (two pairs never share one); every later spec of a
      // node gets the next spare client NIC.
      for (unsigned k = 0; k < kSpares; ++k) spare[i - 1][k] = &net.add_node(100 + (i - 1) * kSpares + k);
      if (shim_on) shim[i - 1] = std::make_unique<ShimFabric>(*cfab[i - 1], stamps[i - 1]);
    }
    for (unsigned i = 1; i <= kServers; ++i) {
      auto sc = server_cfg();
      sc.rails = {fabric::RailAddr{"sim", static_cast<std::uint16_t>(7000 + i)}};  // where the client dials: the sim matches exactly (G08)
      if (max_conns) sc.max_conns_per_principal = max_conns;
      auto w = wrong_id.find(i);
      sc.store.node_id = w != wrong_id.end() ? w->second : i;
      auto s = server::Server::create(sc, *sfab[i - 1], clock, rng, sex);
      EXPECT_TRUE(s);
      srv[i - 1] = std::move(*s);
      EXPECT_TRUE(srv[i - 1]->start());
    }
  }
  static fabric::SimOptions opts() {
    fabric::SimOptions o;
    o.slice_size = 2048;
    return o;
  }
  // A wait on a frozen server ends at its sim-time deadline (WirePort, review w5 U2-26: no call-count cap any more).
  // The 100 us real-time cost of an idle step while a server is frozen is a throttle on the shared sim clock (see
  // wire_port_test MultiWorld); membership_test's World no longer needs it.
  void drive() {
    if (!net.step()) {
      clock.advance_by(milliseconds(1));
      for (unsigned i = 0; i < kServers; ++i)
        if (frozen[i]) {
          std::this_thread::sleep_for(std::chrono::microseconds(100));
          break;
        }
    }
    std::lock_guard lk(srv_mu);
    for (auto& [id, v] : to_apply) srv[id - 1]->apply_bundle(v);
    to_apply.clear();
    for (unsigned i = 0; i < kServers; ++i)
      if (!frozen[i]) srv[i]->run_once();
    if (on_drive) on_drive();  // in the client's sim turn, under srv_mu
  }
  Expected<Client::NodeSpec> spec(const control::NodeView& nv) {
    const unsigned i = nv.node_id;
    Client::NodeSpec ns;
    fabric::Fabric* f = cfab[i - 1];
    if (shim[i - 1]) {
      f = shim[i - 1].get();
    } else if (const unsigned k = specs_made[i - 1].fetch_add(1); k > 0) {
      if (k > kSpares) return Error{ErrorCode::ResourceExhausted, "test: no spare client fabric left"};
      f = spare[i - 1][k - 1];
    }
    ns.fab = f;
    ns.wopts.rail.host = "sim";
    ns.wopts.rail.port = static_cast<std::uint16_t>(7000 + i);
    ns.wopts.tickets = [this, i](fabric::EpClass cls) -> Expected<proto::Ticket> {
      auto t = srv[i - 1]->issue_ticket("lab", cls, 0, 1);
      if (!t) return t.error();
      return (*t)[0];
    };
    ns.wopts.random = &jit;
    ns.wopts.keepalive_ms = 0;
    ns.wopts.rpc_timeout = std::chrono::hours(100);  // a frozen server must hold a job inside, not time its RPC out
    return ns;
  }
  SimClock clock;
  SeededRandom rng, jit{99};
  fabric::SimNetwork net;
  fabric::SimFabric* sfab[kServers];
  fabric::SimFabric* cfab[kServers];
  NodeStamp stamps[kServers];
  std::unique_ptr<ShimFabric> shim[kServers];
  InlineExecutor sex;
  GateExecutor cex;  // the client's decrypts (inline unless a test holds them)
  static constexpr unsigned kSpares = 16;
  fabric::SimFabric* spare[kServers][kSpares];
  std::atomic<unsigned> specs_made[kServers] = {};
  std::function<void()> on_drive;  // HR3b tests: samples the sim each drive (set before traffic, cleared after)
  // The client NICs of node `id` (1-based): the first and the spares. In the sim turn only.
  std::size_t client_endpoints(unsigned id) const {
    std::size_t n = cfab[id - 1]->endpoint_count();
    for (unsigned k = 0; k < kSpares; ++k) n += spare[id - 1][k]->endpoint_count();
    return n;
  }
  // The sessions to node `id`: its client NICs that hold endpoints (each pair has its own). In the sim turn only.
  std::size_t client_sessions(unsigned id) const {
    std::size_t n = cfab[id - 1]->endpoint_count() > 0 ? 1 : 0;
    for (unsigned k = 0; k < kSpares; ++k) n += spare[id - 1][k]->endpoint_count() > 0 ? 1 : 0;
    return n;
  }
  std::uint64_t client_aborts_with_work() const {
    std::uint64_t n = 0;
    for (unsigned i = 0; i < kServers; ++i) {
      n += cfab[i]->aborts_with_work();
      for (unsigned k = 0; k < kSpares; ++k) n += spare[i][k]->aborts_with_work();
    }
    return n;
  }
  CounterSalts salts;
  std::unique_ptr<server::Server> srv[kServers];
  std::atomic<bool> frozen[kServers] = {};
  // A sim server is single-threaded (in production a POST /v1/bundle reaches Server::apply_bundle on the store thread),
  // and so is the sim network, which apply_bundle can write (a GOAWAY). A bundle for a server is queued here and applied
  // by drive() (which runs in the client's sim turn) before the servers' next run_once. srv_mu guards the queue and the
  // servers.
  std::mutex srv_mu;
  std::vector<std::pair<unsigned, control::BundleView>> to_apply;  // (node_id, bundle)
  void queue_apply(unsigned id, const control::BundleView& v) {  // caller holds srv_mu
    to_apply.emplace_back(id, v);
  }
};

MembershipSnapPtr make_snap(std::uint64_t gen, std::uint32_t epoch, std::vector<std::pair<unsigned, unsigned>> nodes,
                            unsigned replicas = 1, std::map<unsigned, std::string> admin_override = {},
                            std::map<unsigned, std::string> rail_override = {},
                            std::vector<std::pair<unsigned, unsigned>> previous = {}, std::set<unsigned> draining = {},
                            std::optional<std::uint32_t> previous_epoch = std::nullopt) {
  auto s = std::make_shared<MembershipSnap>();
  auto& b = s->view.body;
  b.schema_version = 1;
  b.generation = gen;
  b.epoch = epoch;
  b.previous_epoch = previous_epoch ? *previous_epoch : epoch - 1;
  b.replicas = replicas;
  b.replicas_present = true;
  for (auto [id, w] : previous) {
    control::PreviousNodeView pv;
    pv.node_id = id;
    pv.weight = w;
    b.previous.push_back(pv);
  }
  for (auto [id, w] : nodes) {
    control::NodeView nv;
    nv.node_id = id;
    nv.hostname = "host" + std::to_string(id);
    nv.admin = admin_override.count(id) ? admin_override[id] : "10.0.0." + std::to_string(id) + ":9465";
    nv.rails.push_back(control::RailView{rail_override.count(id) ? rail_override[id] : "10.0.0." + std::to_string(id) + ":7471",
                                         "a", "roce"});
    nv.weight = w;
    nv.state = draining.count(id) ? control::MemberState::Draining : control::MemberState::Active;
    b.nodes.push_back(std::move(nv));
  }
  s->envelope = "envelope-gen-" + std::to_string(gen);
  return s;
}

const control::TrustKeys& trust() {
  static const control::TrustKeys t = [] {
    auto k = control::parse_trust_keys(control::testutil::trust_toml());
    if (!k) std::abort();
    return std::move(*k);
  }();
  return t;
}


template <class P>
bool until(P pred, milliseconds cap = milliseconds(30000)) {
  const auto end = std::chrono::steady_clock::now() + cap;
  while (std::chrono::steady_clock::now() < end) {
    if (pred()) return true;
    std::this_thread::sleep_for(milliseconds(2));
  }
  return pred();
}

// G11: waits for `pred` while the simulation makes progress, for tests that real threads drive through a long sequence.
// A tight real-time window fails under a sanitizer on a loaded host (the same sim time costs many times more wall time),
// so this fails only on a real problem: the sim clock stood still for `stall` of real time (a hang), the sim ran
// `sim_cap` of virtual time without the condition (a livelock), or the `wall_cap` backstop (well inside ctest's TIMEOUT).
template <class P>
bool until_sim(const SimClock& clock, P pred, Nanos sim_cap = std::chrono::seconds(900),
               milliseconds stall = milliseconds(60000), milliseconds wall_cap = milliseconds(1200000)) {
  const auto wall_end = std::chrono::steady_clock::now() + wall_cap;
  const Nanos sim_end = clock.now() + sim_cap;
  Nanos last = clock.now();
  auto last_move = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() < wall_end && clock.now() < sim_end) {
    if (pred()) return true;
    const auto t = std::chrono::steady_clock::now();
    if (const Nanos s = clock.now(); s != last) {
      last = s;
      last_move = t;
    } else if (t - last_move >= stall) {
      break;
    }
    std::this_thread::sleep_for(milliseconds(2));
  }
  return pred();
}

// Shared completion poller: any thread may wait for its own ticket.
struct Waiter {
  explicit Waiter(Client& c) : cl(c) {}
  std::optional<Completion> wait(Ticket t, milliseconds cap = milliseconds(40000)) {
    const auto end = std::chrono::steady_clock::now() + cap;
    while (std::chrono::steady_clock::now() < end) {
      {
        std::lock_guard lk(mu);
        auto it = done.find(t.id);
        if (it != done.end()) {
          Completion c = std::move(it->second);
          done.erase(it);
          return c;
        }
        if (!polling) {
          polling = true;
          std::array<Completion, 8> buf;
          const std::size_t n = cl.poll(buf);
          for (std::size_t i = 0; i < n; ++i) done[buf[i].ticket.id] = std::move(buf[i]);
          polling = false;
          continue;
        }
      }
      std::this_thread::yield();
    }
    return std::nullopt;
  }
  Client& cl;
  std::mutex mu;
  bool polling = false;
  std::map<std::uint64_t, Completion> done;
};

struct Rig {
  explicit Rig(MembershipSnapPtr first, unsigned workers = 2, unsigned wait_ms = 2000, std::map<unsigned, unsigned> wrong = {},
               unsigned keepalive_ms = 0, bool bundle_servers = false, bool shim = false,
               std::function<void(Client::NodeSpec&, const control::NodeView&)> tweak = {},
               std::function<void(Client::BundleOpen&)> bo_tweak = {}, unsigned max_conns = 0)
      : w(std::move(wrong), shim, max_conns), bundle_servers_(bundle_servers), shim_(shim), tweak_(std::move(tweak)) {
    cur_epoch = first->view.body.epoch;
    cur_gen = first->generation();
    if (shim)  // every node of the first bundle runs it (they gave it to us)
      for (const auto& nv : first->view.body.nodes) w.stamps[nv.node_id - 1].set(cur_epoch, static_cast<std::uint32_t>(cur_gen));
    if (bundle_servers) {  // the servers of the first bundle already run it (bundle mode, MB3b apply)
      cur_env = first->envelope;
      for (const auto& nv : first->view.body.nodes) w.srv[nv.node_id - 1]->apply_bundle(first->view);
    }
    Client::Env env;
    env.clock = &w.clock;
    env.executor = &w.cex;
    env.salts = &w.salts;
    env.drive = [this] { w.drive(); };
    env.replica_buffer_bytes = 8u << 20;
    // As membership_test's rig (run #200): HR2 clamps store deadlines to put_max_ms (2.5 s of SIM time by default), which
    // the driving threads burn in milliseconds of real time while a job waits for its sim turn. The tests' own deadlines apply.
    env.put_max_ms = 600000;
    env.set_crypto_workers = [this](unsigned n) { crypto_workers = n; };
    Client::BundleOpen bo;
    bo.initial = std::move(first);
    bo.make_spec = [this](const control::NodeView& nv) -> Expected<Client::NodeSpec> {
      spec_calls.fetch_add(1);
      if (spec_fail.load()) return Error{ErrorCode::LinkDown, "test: make_spec fails"};
      auto ns = w.spec(nv);
      if (ns && tweak_) tweak_(*ns, nv);
      return ns;
    };
    bo.push = [this](const std::string& admin) -> Status {
      std::lock_guard lk(pm);
      pushes.push_back(admin);
      const unsigned id = static_cast<unsigned>(std::stoul(admin.substr(admin.rfind('.') + 1)));
      if (id_of_admin_connected) {
        const bool c = id_of_admin_connected(id);
        connected_at_push.push_back(c);
        first_push_connected.emplace(id, c);  // MB6b also pushes to lagging nodes: per node, its first push
      }
      if (fail_pushes > 0) {
        --fail_pushes;
        return Error{ErrorCode::LinkDown, "test: push fails"};
      }
      if (shim_) w.stamps[id - 1].set(cur_epoch, static_cast<std::uint32_t>(cur_gen));  // the node applied our envelope
      if (bundle_servers_) {  // MB3b servers: the pushed envelope is verified and applied, as the node's POST /v1/bundle would
        auto v = control::open_bundle(cur_env, trust());
        if (!v) return Error{ErrorCode::Corrupt, "test: pushed envelope does not verify"};
        std::lock_guard sl(w.srv_mu);
        w.queue_apply(id, *v);  // applied before the node's next run_once, so before it sees our first connect
        applied_at_push.emplace(id, v->body.generation);  // the first push to the node
      }
      return {};
    };
    bo.wake = [this](std::uint32_t lo, const std::string& admin) {
      std::lock_guard lk(wm);
      wakes.emplace_back(lo, admin);
    };
    bo.keepalive_ms = keepalive_ms;
    bo.connect_wait_ms = wait_ms;
    if (bo_tweak) bo_tweak(bo);
    RuntimeOptions ro;
    ro.workers = workers;
    auto c = Client::open_bundle(env, std::move(bo), {}, {}, ro);
    EXPECT_TRUE(c) << (c ? "" : c.error().context);
    if (c) {
      cl = std::move(*c);
      wt = std::make_unique<Waiter>(*cl);
      clp = cl.get();
      id_of_admin_connected = [this](unsigned id) {
        Client* c = clp.load();
        if (!c) return false;
        const long s = c->slot_of(id);
        return s >= 0 && c->wire_port(static_cast<std::size_t>(s)) != nullptr;
      };
    }
  }
  ~Rig() {  // the client's threads (the pusher calls the push hook) stop before the hook's state (pm, pushes) is destroyed
    clp = nullptr;
    wt.reset();
    cl.reset();
  }
  World w;
  std::unique_ptr<Client> cl;
  std::unique_ptr<Waiter> wt;
  std::mutex pm;
  std::vector<std::string> pushes;
  std::vector<bool> connected_at_push;
  std::map<unsigned, bool> first_push_connected;
  std::function<bool(unsigned)> id_of_admin_connected;
  std::atomic<Client*> clp{nullptr};  // the push hook (pusher thread) reads the client through this
  bool bundle_servers_ = false;
  bool shim_ = false;
  std::uint32_t cur_epoch = 0;      // shim: the client's newest bundle (what a push delivers)
  std::uint64_t cur_gen = 0;
  std::mutex wm;
  std::vector<std::pair<std::uint32_t, std::string>> wakes;  // the client lags: (reply bundle_gen_lo, replying admin)
  int fail_pushes = 0;
  std::atomic<bool> spec_fail{false};
  std::atomic<int> spec_calls{0};
  std::atomic<unsigned> crypto_workers{0};
  std::function<void(Client::NodeSpec&, const control::NodeView&)> tweak_;
  std::string cur_env;                                // bundle_servers: the envelope a push delivers
  std::map<unsigned, std::uint64_t> applied_at_push;  // bundle_servers: the node's applied generation right after the push
  void publish(const MembershipSnapPtr& s) {
    {
      std::lock_guard lk(pm);
      cur_env = s->envelope;
      cur_epoch = s->view.body.epoch;
      cur_gen = s->generation();
    }
    cl->apply_membership(s);
  }
};

// One put-then-get cycle of `scope` at version `v`, judged by the oracle.
void cycle(Rig& r, Oracle& o, int scope, std::uint64_t v) {
  const std::string key = "k" + std::to_string(scope) + "_" + std::to_string(v);  // immutable: a key is stored once
  Chain ch(key);
  auto sk = scope_keys(scope);
  Bytes data = payload(scope, v);
  std::vector<BufRef> pb{{std::span<std::byte>(data)}};
  o.begin_store(key, v);
  auto sc = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(60)));
  if (!sc) return o.on_missing_completion("store " + key);
  const KeyStatus st = sc->status.at(0);
  o.end_store(key, v, st == KeyStatus::Committed);
  o.on_store(key, st);
  Bytes out(kPayload, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  auto fc = r.wt->wait(r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, seconds(60)));
  if (!fc) return o.on_missing_completion("fetch " + key);
  const KeyStatus fs = fc->status.at(0);
  o.on_fetch(key, fs, fs == KeyStatus::Hit ? decode(scope, out) : std::nullopt);
  // Y19: also re-read an OLDER committed key. After a membership change its owner may be another node: a Miss is fine,
  // a Hit must still carry exactly that key's version (the stale-bytes rule).
  if (v > 3) {
    const std::uint64_t ov = v - 3;  // each pass stores v, v+1, v+2 in its 3 scopes: v-3 is this scope's previous key
    const std::string okey = "k" + std::to_string(scope) + "_" + std::to_string(ov);
    Chain och(okey);
    Bytes oout(kPayload, std::byte{0xAA});
    std::vector<BufRef> ob{{std::span<std::byte>(oout)}};
    auto oc = r.wt->wait(r.cl->fetch(sk, 0, std::span<const KeyRef>(&och.ref, 1), ob, seconds(60)));
    if (!oc) return o.on_missing_completion("re-fetch " + okey);
    const KeyStatus os = oc->status.at(0);
    o.on_fetch(okey, os, os == KeyStatus::Hit ? decode(scope, oout) : std::nullopt);
  }
}

// Four threads of traffic (3 scopes each) until stop.
struct Traffic {
  Traffic(Rig& rig, Oracle& orc) : r(rig), o(orc) {
    for (int t = 0; t < 4; ++t)
      th.emplace_back([this, t] {
        std::uint64_t v = 0;
        while (!stop.load()) {
          for (int s = 0; s < 3; ++s) cycle(r, o, t * 3 + s, ++v);
          ops.fetch_add(3);
        }
      });
  }
  void finish() {
    stop = true;
    for (auto& t : th) t.join();
    th.clear();
  }
  ~Traffic() { finish(); }
  Rig& r;
  Oracle& o;
  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> ops{0};
  std::vector<std::thread> th;
};

// Waits (real time, `cap`) until the traffic has done more than `n` more ops. s12 (CI pipeline 3080856180, asan lane: a
// 30 s wait timed out in ConnectionCapHitDuringTheOverlapLeavesTheOldPairServing, which takes 0.4-8 s locally): a timeout
// says where the time went: ops, the workers' job-loop turns, the keepalive ticks, sim time and rebuild failures over
// the wait.
void settle_traffic(Rig& r, Traffic& tr, std::uint64_t n, milliseconds cap = milliseconds(30000)) {
  const auto base = tr.ops.load();
  const auto it0 = r.cl->pump_iterations(), ka0 = r.cl->keepalive_ticks(), rf0 = r.cl->rebuild_failures();
  const auto sim0 = r.w.clock.now();
  const auto t0 = std::chrono::steady_clock::now();
  EXPECT_TRUE(until([&] { return tr.ops.load() > base + n; }, cap))
      << "settle(" << n << "): ops +" << tr.ops.load() - base << " in "
      << std::chrono::duration_cast<milliseconds>(std::chrono::steady_clock::now() - t0).count() << " ms real, "
      << std::chrono::duration_cast<milliseconds>(r.w.clock.now() - sim0).count() << " ms sim; job-loop turns +"
      << r.cl->pump_iterations() - it0 << ", keepalive ticks +" << r.cl->keepalive_ticks() - ka0
      << ", rebuild failures +" << r.cl->rebuild_failures() - rf0;
}


// ---- HR2 tests -------------------------------------------------------------------------------------------------

std::optional<long long> series(const std::string& text, const std::string& name, std::initializer_list<std::string> parts) {
  std::size_t pos = 0;
  while (pos < text.size()) {
    std::size_t end = text.find('\n', pos);
    if (end == std::string::npos) end = text.size();
    const std::string line = text.substr(pos, end - pos);
    pos = end + 1;
    if (line.rfind(name + "{", 0) != 0 && line.rfind(name + " ", 0) != 0) continue;
    bool all = true;
    for (const auto& p : parts) all = all && line.find(p) != std::string::npos;
    if (all) return std::stoll(line.substr(line.rfind(' ') + 1));
  }
  return std::nullopt;
}

// Sum of every series of `name` (all `node` labels).
long long sum_all(const std::string& text, const std::string& name) {
  long long t = 0;
  std::size_t pos = 0;
  while (pos < text.size()) {
    std::size_t end = text.find('\n', pos);
    if (end == std::string::npos) end = text.size();
    const std::string line = text.substr(pos, end - pos);
    pos = end + 1;
    if (line.rfind(name + "{", 0) == 0 || line.rfind(name + " ", 0) == 0) t += std::stoll(line.substr(line.rfind(' ') + 1));
  }
  return t;
}

// A bundle of nodes 1..3 whose `config` table has the given client part (rooted at `config`, as BodyView::config_toml).
MembershipSnapPtr cfg_snap(std::uint64_t gen, unsigned replicas, const std::string& client_toml, std::uint32_t bundle_unknown = 0) {
  auto s = std::make_shared<MembershipSnap>(*make_snap(gen, 1, {{1, 1}, {2, 1}, {3, 1}}, replicas));
  s->view.body.config_toml = "[cluster.placement]\nreplicas = " + std::to_string(replicas) + "\n\n" + client_toml;
  s->view.body.unknown_keys = bundle_unknown;
  return s;
}

std::uint64_t legs(const std::string& m, const char* result) {
  std::uint64_t t = 0;
  for (unsigned id = 1; id <= 3; ++id)
    t += static_cast<std::uint64_t>(series(m, "miracache_client_replica_legs_total", {"node=\"" + std::to_string(id) + "\"", std::string("result=\"") + result + "\""}).value_or(0));
  return t;
}

// ---- the key table and the parser (no client) ----

TEST(ClientDynParse, AbsentKeysTakeTheBaseAndEachClassIsParsed) {
  ClientDyn base;
  base.keepalive_ms = 1000;
  auto r = parse_client_dyn("", base, 7);
  ASSERT_TRUE(r.error.empty()) << r.error;
  EXPECT_EQ(r.dyn->keepalive_ms, 1000u);
  EXPECT_EQ(r.dyn->generation, 7u);
  EXPECT_TRUE(r.dyn->pending_rebuild.empty());

  const std::string t =
      "[cluster.client.fabric]\nkeepalive_ms = 250\nreconnect_min_ms = 20\nreconnect_max_ms = 900\nreconnect_connect_ms = 300\n"
      "watchdog_grace_ms = 5000\nticket_batch = 9\nslice_bytes = 65536\nmtu = 2048\nprotocol = \"roce\"\nfetch_qps = 4\n\n"
      "[cluster.client.deadline]\nput_max_ms = 1500\n\n"
      "[cluster.client.placement]\nreplica_mode = \"sync\"\nreplica_buffer_bytes = 1048576\nprevious_view_ms = 60000\nhint_entries = 17\n\n"
      "[cluster.client.crypto]\nworkers = 3\n\n[cluster.client.landing]\nsubpool_bytes = 8388608\n";
  r = parse_client_dyn(t, base, 8);
  ASSERT_TRUE(r.error.empty()) << r.error;
  const ClientDyn& d = *r.dyn;
  EXPECT_EQ(d.keepalive_ms, 250u);
  EXPECT_EQ(d.reconnect_min_ms, 20u);
  EXPECT_EQ(d.reconnect_max_ms, 900u);
  EXPECT_EQ(d.reconnect_connect_ms, 300u);
  EXPECT_EQ(d.watchdog_grace_ms, 5000u);
  EXPECT_EQ(d.ticket_batch, 9u);
  EXPECT_EQ(d.slice_bytes, 65536u);
  EXPECT_EQ(d.put_max_ms, 1500u);
  EXPECT_EQ(d.replica_mode, ReplicaMode::Sync);
  EXPECT_EQ(d.replica_buffer_bytes, 1048576u);
  EXPECT_EQ(d.previous_view_ms, 60000u);
  EXPECT_EQ(d.hint_entries, 17u);
  EXPECT_EQ(d.crypto_workers, 3u);
  // class B: wanted values recorded, listed as pending
  EXPECT_EQ(d.mtu, 2048u);
  EXPECT_EQ(d.protocol, FabricProtocol::Roce);
  EXPECT_EQ(d.fetch_qps, 4u);
  EXPECT_EQ(d.subpool_bytes, 8388608u);
  EXPECT_EQ(d.pending_rebuild, (std::vector<std::string>{"landing.subpool_bytes", "fabric.mtu", "fabric.protocol", "fabric.fetch_qps"}));
  EXPECT_TRUE(r.unknown.empty());
  // removing the keys again restores the base (and the pending list empties)
  r = parse_client_dyn("", base, 9);
  EXPECT_EQ(r.dyn->keepalive_ms, 1000u);
  EXPECT_TRUE(r.dyn->pending_rebuild.empty());
  // a wanted class B value equal to the running one is not pending
  r = parse_client_dyn("[cluster.client.fabric]\nmtu = 4096\n", base, 10);
  EXPECT_TRUE(r.dyn->pending_rebuild.empty());
}

TEST(ClientDynParse, UnknownKeysAreIgnoredAndListed) {
  ClientDyn base;
  auto r = parse_client_dyn(
      "[cluster.client.fabric]\nkeepalive_ms = 300\nfuture_knob = 1\n\n[cluster.client.future]\nx = 1\n\n[cluster.client]\nloose = 2\n", base, 2);
  ASSERT_TRUE(r.error.empty()) << r.error;
  EXPECT_EQ(r.dyn->keepalive_ms, 300u) << "the known key in the same table is applied";
  std::sort(r.unknown.begin(), r.unknown.end());
  EXPECT_EQ(r.unknown, (std::vector<std::string>{"fabric.future_knob", "future", "loose"}));
}

TEST(ClientDynParse, BadValuesStaticKeysAndCrossFieldRulesRejectTheWholeTable) {
  ClientDyn base;
  const char* bad[] = {
      "[cluster.client.fabric]\nkeepalive_ms = 0\n",                                    // 0 would turn reconnect off
      "[cluster.client.fabric]\nkeepalive_ms = 9\n",
      "[cluster.client.fabric]\nkeepalive_ms = \"fast\"\n",
      "[cluster.client.fabric]\nreconnect_min_ms = 500\nreconnect_max_ms = 100\n",       // max < min
      "[cluster.client.fabric]\nreconnect_max_ms = 50\n",                                // max < the base min (100)
      "[cluster.client.fabric]\nticket_batch = 65\n",
      "[cluster.client.fabric]\nslice_bytes = 5000\n",                                   // not a power of two
      "[cluster.client.fabric]\nslice_bytes = 2048\n",                                   // below 4 KiB
      "[cluster.client.fabric]\nmtu = 1500\n",
      "[cluster.client.fabric]\nprotocol = \"tcp\"\n",
      "[cluster.client.fabric]\nfetch_qps = 99\n",
      "[cluster.client.deadline]\nput_max_ms = 0\n",
      "[cluster.client.placement]\nreplica_mode = \"maybe\"\n",
      "[cluster.client.placement]\nreplica_buffer_bytes = -1\n",
      "[cluster.client.crypto]\nworkers = 0\n",
      "[cluster.client.landing]\nsubpool_bytes = 1048577\n",
      "[cluster.client.fabric]\ndevice = \"rxe0\"\n",                                    // STATIC keys
      "[cluster.client.fabric]\nprofiles_file = \"/x\"\n",
      "[cluster.client.fabric]\nread_depth = 8\n",                                      // G06: NIC operating point is local
      "[cluster.client.fabric]\nwindow_bytes = 1048576\n",
      "[cluster.client.deadline]\nput_max_ms = 3000\n",                                  // G06: 4 x 3000 > the default 10 s put_timeout
      "[cluster.client.deadline]\nput_max_ms = 1000\n\n[cluster.memnode.lease]\nput_timeout_s = 3\n",
      "[cluster.client.tls]\ncert = \"/x\"\n",
      "[cluster.client.scope]\nsecret_file = \"/x\"\n",
      "[cluster.client.control]\nendpoints = []\n",
  };
  for (const char* t : bad) {
    auto r = parse_client_dyn(std::string("[cluster.client.fabric]\nkeepalive_ms = 300\n\n") + t, base, 3);
    EXPECT_FALSE(r.error.empty()) << t;
    EXPECT_EQ(r.dyn, nullptr) << t;
  }
  // a bad value in a later table does not leak the earlier valid keys: the result has no snapshot at all
  auto r = parse_client_dyn("[cluster.client.fabric]\nkeepalive_ms = 300\n\n[cluster.client.crypto]\nworkers = 99\n", base, 3);
  EXPECT_FALSE(r.error.empty());
  EXPECT_NE(r.error.find("crypto.workers"), std::string::npos) << r.error;
  r = parse_client_dyn("[cluster.client.fabric\n", base, 3);
  EXPECT_FALSE(r.error.empty()) << "unparseable text";
  // G06: a static fabric key is refused BY NAME (never silently ignored), and put_max_ms may rise with put_timeout_s.
  r = parse_client_dyn("[cluster.client.fabric]\ninline_bytes = 64\n", base, 3);
  EXPECT_NE(r.error.find("fabric.inline_bytes is STATIC"), std::string::npos) << r.error;
  r = parse_client_dyn("[cluster.client.deadline]\nput_max_ms = 5000\n\n[cluster.memnode.lease]\nput_timeout_s = 20\n", base, 3);
  EXPECT_TRUE(r.error.empty()) << r.error;
  r = parse_client_dyn("[cluster.client.deadline]\nput_max_ms = 3000\n", base, 3);
  EXPECT_NE(r.error.find("put_timeout_s must be >= 4 x client deadline.put_max_ms"), std::string::npos) << r.error;
}

// The fail-slow breaker's table (class A): every key, the defaults when absent, and the rules that reject the table.
TEST(ClientDynParse, BreakerKeys) {
  ClientDyn base;
  auto d = parse_client_dyn("", base, 1);
  ASSERT_TRUE(d.error.empty()) << d.error;
  EXPECT_TRUE(d.dyn->breaker_enabled);
  EXPECT_EQ(d.dyn->breaker_window_ms, 10000u);
  EXPECT_EQ(d.dyn->breaker_probes, 3u);
  auto r = parse_client_dyn(
      "[cluster.client.breaker]\nenabled = false\nwindow_ms = 2000\nmin_ops = 7\nmin_misses = 2\nmiss_pct = 50\n"
      "p99_factor = 8\nfloor_us = 0\nopen_ms = 100\nopen_max_ms = 900\nprobes = 5\n",
      base, 2);
  ASSERT_TRUE(r.error.empty()) << r.error;
  EXPECT_TRUE(r.unknown.empty());
  EXPECT_FALSE(r.dyn->breaker_enabled);
  EXPECT_EQ(r.dyn->breaker_window_ms, 2000u);
  EXPECT_EQ(r.dyn->breaker_min_ops, 7u);
  EXPECT_EQ(r.dyn->breaker_min_misses, 2u);
  EXPECT_EQ(r.dyn->breaker_miss_pct, 50u);
  EXPECT_EQ(r.dyn->breaker_p99_factor, 8u);
  EXPECT_EQ(r.dyn->breaker_floor_us, 0u);
  EXPECT_EQ(r.dyn->breaker_open_ms, 100u);
  EXPECT_EQ(r.dyn->breaker_open_max_ms, 900u);
  EXPECT_EQ(r.dyn->breaker_probes, 5u);
  EXPECT_EQ(dyn_changed_keys(*d.dyn, *r.dyn),
            (std::vector<std::string>{"breaker.enabled", "breaker.window_ms", "breaker.min_ops", "breaker.min_misses",
                                      "breaker.miss_pct", "breaker.p99_factor", "breaker.floor_us", "breaker.open_ms",
                                      "breaker.open_max_ms", "breaker.probes"}));
  for (const char* bad : {"[cluster.client.breaker]\nenabled = 1\n", "[cluster.client.breaker]\nwindow_ms = 50\n",
                          "[cluster.client.breaker]\nmiss_pct = 0\n", "[cluster.client.breaker]\nmiss_pct = 101\n",
                          "[cluster.client.breaker]\np99_factor = 1\n", "[cluster.client.breaker]\nprobes = 0\n",
                          "[cluster.client.breaker]\nopen_ms = 5000\nopen_max_ms = 1000\n"}) {
    auto e = parse_client_dyn(bad, base, 3);
    EXPECT_FALSE(e.error.empty()) << bad;
    EXPECT_EQ(e.dyn, nullptr) << bad;
  }
}

TEST(ClientDynParse, ChangedKeysListNamesOnly) {
  ClientDyn a, b = a;
  b.keepalive_ms = 5;
  b.slice_bytes = 4096;
  b.mtu = 1024;
  EXPECT_EQ(dyn_changed_keys(a, b), (std::vector<std::string>{"fabric.keepalive_ms", "fabric.slice_bytes", "fabric.mtu"}));
  EXPECT_TRUE(dyn_changed_keys(a, a).empty());
}

// ---- the client under traffic ----

// Class A keys one after the other under 4-thread traffic and the strict oracle: 0 failed operations. Class B is
// recorded as pending, an unknown key is ignored and counted, a bad value (or a STATIC key) keeps the old snapshot.
TEST(ClientReload, ClassAKeysChangeBehaviourUnderTrafficWithZeroFailedOps) {
  std::mutex bm;
  std::vector<unsigned> batches;  // ticket_batch values the nodes' on_dyn hooks saw
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false,
        [&](Client::NodeSpec& ns, const control::NodeView&) {
          ns.on_dyn = [&](const ClientDyn& d) {
            std::lock_guard lk(bm);
            batches.push_back(d.ticket_batch);
          };
        });
  ASSERT_TRUE(r.cl);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) { settle_traffic(r, tr, n); };
  auto publish = [&](const MembershipSnapPtr& s) {
    r.publish(s);
    ASSERT_TRUE(until([&] { return r.cl->membership_generation() == s->generation(); }));
  };
  settle(20);
  const ClientDynPtr d0 = r.cl->dyn();
  ASSERT_TRUE(d0);
  EXPECT_EQ(d0->keepalive_ms, 20u);
  EXPECT_EQ(r.cl->config_applied(), 1u) << "the first bundle's table (empty) is applied at open";

  // R 1 -> 2 (async, buffer 8 MiB): the secondaries get replica legs. R lives in the placement snapshot only.
  EXPECT_EQ(legs(r.cl->metrics_text(), "committed"), 0u) << "R = 1: no replica legs";
  publish(cfg_snap(2, 2, ""));
  settle(30);
  ASSERT_TRUE(until([&] { return legs(r.cl->metrics_text(), "committed") > 0; })) << r.cl->metrics_text();
  EXPECT_EQ(r.cl->dyn()->generation, 2u);

  // replica_buffer_bytes (async): a bound smaller than any copy -> the replica legs are skipped_full, stores still commit
  const auto full0 = legs(r.cl->metrics_text(), "skipped_full");
  publish(cfg_snap(3, 2, "[cluster.client.placement]\nreplica_buffer_bytes = 1\n"));
  settle(30);
  EXPECT_GT(legs(r.cl->metrics_text(), "skipped_full"), full0) << "the new bound reached new stores";
  EXPECT_EQ(r.cl->dyn()->replica_buffer_bytes, 1u);

  // replica_mode sync ignores the async pool: every leg is waited for, none is skipped_full any more
  publish(cfg_snap(4, 2, "[cluster.client.placement]\nreplica_buffer_bytes = 1\nreplica_mode = \"sync\"\n"));
  settle(10);  // let the stores that started before the swap finish
  const auto full1 = legs(r.cl->metrics_text(), "skipped_full");
  const auto com1 = legs(r.cl->metrics_text(), "committed");
  settle(40);
  EXPECT_EQ(legs(r.cl->metrics_text(), "skipped_full"), full1) << "sync: no pool bound";
  EXPECT_GT(legs(r.cl->metrics_text(), "committed"), com1 + 20) << "sync: every store commits on both replicas";

  // back to async with the default bound, R 2 -> 1: the legs stop
  publish(cfg_snap(5, 1, ""));
  EXPECT_EQ(r.cl->dyn()->replica_mode, ReplicaMode::Async);
  settle(10);
  ASSERT_TRUE(until([&] { return r.cl->replicator_pending() == 0; }));
  const auto com2 = legs(r.cl->metrics_text(), "committed");
  settle(40);
  EXPECT_EQ(legs(r.cl->metrics_text(), "committed"), com2) << "R = 1 again: no replica legs";

  // slice_bytes: new fetches are cut into slices, then back to the default (one READ)
  const auto sl = [&] { return sum_all(r.cl->metrics_text(), "miracache_client_fetch_slices_total"); };
  EXPECT_EQ(sl(), 0);
  publish(cfg_snap(6, 1, "[cluster.client.fabric]\nslice_bytes = 4096\n"));
  settle(40);
  EXPECT_GT(sl(), 40) << "a block of 8 KiB + header is at least 3 slices of 4 KiB";
  publish(cfg_snap(7, 1, ""));
  settle(10);
  const auto sl1 = sl();
  settle(40);
  EXPECT_EQ(sl(), sl1) << "the default slice (1 MiB) does not cut an 8 KiB block";

  // keepalive_ms and ticket_batch: the node threads adopt them at their next tick
  publish(cfg_snap(8, 1, "[cluster.client.fabric]\nkeepalive_ms = 40\nticket_batch = 11\n"));
  for (std::size_t s = 0; s < 3; ++s) {
    const long slot = r.cl->slot_of(static_cast<std::uint32_t>(s + 1));
    ASSERT_GE(slot, 0);
    EXPECT_TRUE(until([&] { return r.cl->keepalive_period_ms(static_cast<std::size_t>(slot)) == 40; })) << "slot " << slot;
  }
  EXPECT_TRUE(until([&] {
    std::lock_guard lk(bm);
    return std::count(batches.begin(), batches.end(), 11u) >= 3;
  })) << "every node's ticket source was told";

  // crypto.workers (class C): handed to the executor hook
  publish(cfg_snap(9, 1, "[cluster.client.crypto]\nworkers = 2\n"));
  EXPECT_EQ(r.crypto_workers.load(), 2u);

  // reconnect caps, put_max_ms, watchdog, previous view and hints: the snapshot carries them
  publish(cfg_snap(10, 1,
                   "[cluster.client.fabric]\nreconnect_min_ms = 30\nreconnect_max_ms = 400\nreconnect_connect_ms = 250\nwatchdog_grace_ms = 7000\n"
                   "[cluster.client.deadline]\nput_max_ms = 1800\n[cluster.client.placement]\nprevious_view_ms = 120000\nhint_entries = 5\n"));
  {
    const auto d = r.cl->dyn();
    EXPECT_EQ(d->reconnect_min_ms, 30u);
    EXPECT_EQ(d->reconnect_max_ms, 400u);
    EXPECT_EQ(d->reconnect_connect_ms, 250u);
    EXPECT_EQ(d->watchdog_grace_ms, 7000u);
    EXPECT_EQ(d->put_max_ms, 1800u);
    EXPECT_EQ(d->previous_view_ms, 120000u);
    EXPECT_EQ(d->hint_entries, 5u);
  }
  settle(20);

  // class B: recorded as pending ("applied at next rebuild"), nothing running changes
  publish(cfg_snap(11, 1, "[cluster.client.fabric]\nmtu = 1024\nfetch_qps = 4\n[cluster.client.landing]\nsubpool_bytes = 8388608\n"));
  EXPECT_EQ(r.cl->dyn()->pending_rebuild, (std::vector<std::string>{"landing.subpool_bytes", "fabric.mtu", "fabric.fetch_qps"}));
  EXPECT_EQ(series(r.cl->metrics_text(), "miracache_client_config_pending_rebuild_keys", {}), 3);
  settle(20);

  // unknown keys: ignored and counted; the known ones in the same bundle still apply
  const auto unk0 = r.cl->config_unknown_keys();
  publish(cfg_snap(12, 1, "[cluster.client.fabric]\nkeepalive_ms = 50\nfuture_knob = 1\n[cluster.client.future]\nz = 1\n", /*bundle_unknown=*/2));
  EXPECT_EQ(r.cl->config_unknown_keys(), unk0 + 4) << "2 from the bundle parser, fabric.future_knob and future";
  EXPECT_EQ(r.cl->dyn()->keepalive_ms, 50u);
  EXPECT_EQ(series(r.cl->metrics_text(), "miracache_config_unknown_keys_total", {}), static_cast<long long>(unk0 + 4));

  // a bad value and a STATIC key: the old snapshot stays, the membership still applies, both are counted
  const ClientDynPtr keep = r.cl->dyn();
  const auto rej0 = r.cl->config_rejected();
  publish(cfg_snap(13, 1, "[cluster.client.fabric]\nkeepalive_ms = 60\nreconnect_min_ms = 900\nreconnect_max_ms = 10\n"));
  EXPECT_EQ(r.cl->dyn(), keep) << "same snapshot object";
  EXPECT_EQ(r.cl->config_rejected(), rej0 + 1);
  EXPECT_NE(r.cl->config_last_error().find("reconnect_max_ms"), std::string::npos) << r.cl->config_last_error();
  publish(cfg_snap(14, 1, "[cluster.client.fabric]\nkeepalive_ms = 60\ndevice = \"rxe0\"\n"));
  EXPECT_EQ(r.cl->dyn(), keep);
  EXPECT_EQ(r.cl->config_rejected(), rej0 + 2);
  EXPECT_NE(r.cl->config_last_error().find("STATIC"), std::string::npos) << r.cl->config_last_error();
  EXPECT_EQ(series(r.cl->metrics_text(), "miracache_config_reload_total", {"result=\"rejected\""}), static_cast<long long>(rej0 + 2));
  settle(20);

  // the next valid bundle applies again
  publish(cfg_snap(15, 1, "[cluster.client.fabric]\nkeepalive_ms = 60\n"));
  EXPECT_EQ(r.cl->dyn()->keepalive_ms, 60u);
  EXPECT_EQ(r.cl->dyn()->generation, 15u);
  EXPECT_EQ(series(r.cl->metrics_text(), "miracache_config_generation", {}), 15);
  settle(20);

  tr.finish();
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Hit), 0u) << o.report();
}

// The internal entry points apply_config / apply_config_toml (what a test or the bundle path calls).
TEST(ClientReload, ApplyConfigTomlAndApplyConfigAreOneAtomicSwap) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  const ClientDynPtr d0 = r.cl->dyn();
  ASSERT_TRUE(r.cl->apply_config_toml("[cluster.client.fabric]\nticket_batch = 6\n", 40));
  EXPECT_EQ(r.cl->dyn()->ticket_batch, 6u);
  EXPECT_EQ(d0->ticket_batch, 4u) << "a snapshot a job already holds never changes";
  EXPECT_FALSE(r.cl->apply_config_toml("[cluster.client.fabric]\nticket_batch = 0\n", 41));
  EXPECT_EQ(r.cl->dyn()->ticket_batch, 6u);
  auto next = std::make_shared<ClientDyn>(*r.cl->dyn());
  next->ticket_batch = 7;
  ASSERT_TRUE(r.cl->apply_config(next));
  EXPECT_EQ(r.cl->dyn()->ticket_batch, 7u);
}

// Readers never see a torn snapshot: many threads load while another swaps between two consistent snapshots (tsan).
TEST(ClientReload, SnapshotLoadsAreAtomicWhileSwapping) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  std::atomic<bool> stop{false};
  std::atomic<unsigned> torn{0};
  std::vector<std::thread> th;
  {
    auto n = std::make_shared<ClientDyn>(*r.cl->dyn());
    n->reconnect_min_ms = 10;
    n->reconnect_max_ms = 100;
    ASSERT_TRUE(r.cl->apply_config(n));
  }
  for (int i = 0; i < 4; ++i)
    th.emplace_back([&] {
      while (!stop.load()) {
        const auto d = r.cl->dyn();
        if (d->reconnect_max_ms != d->reconnect_min_ms * 10) ++torn;  // both fields come from one snapshot
      }
    });
  for (unsigned i = 0; i < 300; ++i) {
    auto n = std::make_shared<ClientDyn>(*r.cl->dyn());
    n->reconnect_min_ms = 10 + i % 7;
    n->reconnect_max_ms = n->reconnect_min_ms * 10;
    ASSERT_TRUE(r.cl->apply_config(n));
  }
  stop = true;
  for (auto& t : th) t.join();
  EXPECT_EQ(torn.load(), 0u);
}

// ---- HR3b: planned rebuild (class B, make-before-break) ----------------------------------------------------------

// Multi-rail decision 6: one session holds, per paired rail, 1 control + fetch_qps fetch + 1 ingest endpoints. These sim
// nodes have one rail.
constexpr unsigned session_eps(unsigned fetch_qps, unsigned rails = 1) { return rails * (2 + fetch_qps); }
// The connection-cap rule (hot-reload plan decision 6) for one client (stagger 1) over a sequence of fetch_qps values
// applied one after another: during each rebuild the client holds the old-size session and the new-size one.
template <std::size_t N>
constexpr unsigned overlap_cap(const unsigned (&qps)[N], unsigned rails = 1) {
  unsigned cap = session_eps(qps[0], rails);
  for (std::size_t i = 0; i + 1 < N; ++i) cap = std::max(cap, session_eps(qps[i], rails) + session_eps(qps[i + 1], rails));
  return cap;
}

// What the sim saw, sampled at every drive (in the client's sim turn): client endpoints per node, how many nodes had more
// than one session at once (a session = one client NIC with endpoints: a rebuild never shares one), the server's
// connections + admitted endpoints per node.
struct Overlap {
  std::atomic<std::size_t> max_eps{0}, max_doubled{0}, max_conns{0};
  std::atomic<std::size_t> conns[kServers] = {};
  explicit Overlap(World& world) : w_(world) {
    World& w = w_;
    std::lock_guard lk(w.srv_mu);
    w.on_drive = [this, &w] {
      std::size_t doubled = 0;
      for (unsigned id = 1; id <= 3; ++id) {
        const std::size_t e = w.client_endpoints(id);
        doubled += w.client_sessions(id) > 1 ? 1 : 0;
        max_eps.store(std::max(max_eps.load(), e));
        const std::size_t c = w.srv[id - 1]->n_conns() + w.srv[id - 1]->n_admitted();
        conns[id - 1].store(c);
        max_conns.store(std::max(max_conns.load(), c));
      }
      max_doubled.store(std::max(max_doubled.load(), doubled));
    };
  }
  ~Overlap() { detach(); }  // before the World's clients stop driving: never a dangling hook
  void detach() {
    World& w = w_;
    std::lock_guard lk(w.srv_mu);
    w.on_drive = nullptr;
  }
  World& w_;
};

// HR7: every node's rail 0 shows `want` fetch QPs connected (miracache_client_rail_fetch_qps, the active pair's).
bool rails_show_qps(Client& c, long long want) {
  const std::string m = c.metrics_text();
  for (const char* id : {"1", "2", "3"})
    if (series(m, "miracache_client_rail_fetch_qps", {std::string("node=\"") + id + "\"", "node_id=", "hostname=", "rail=\"0\""}) != want)
      return false;
  return true;
}

bool slots_run(Client& c, std::size_t pool, std::uint32_t mtu, std::uint32_t fetch_qps) {
  for (std::uint32_t id = 1; id <= 3; ++id) {
    const long s = c.slot_of(id);
    Client::SlotClassB b;
    if (s < 0 || !c.slot_class_b(static_cast<std::size_t>(s), b)) return false;
    if (b.pool_bytes != pool || b.mtu != mtu || b.fetch_qps != fetch_qps) return false;
  }
  return true;
}

void fast_rebuilds(Client::BundleOpen& bo, unsigned jitter_ms = 200, unsigned drain_ms = 30000) {
  bo.rebuild_jitter_ms = jitter_ms;
  bo.rebuild_drain_ms = drain_ms;
}

int scope_of_node(std::size_t want) {  // a scope node `want` (0-based in {1,2,3}) owns with R = 1
  for (int s = 0; s < 64; ++s) {
    std::vector<PlaceNode> v{PlaceNode{"1"}, PlaceNode{"2"}, PlaceNode{"3"}};
    auto sk = scope_keys(s);
    if (place_owner(v, std::span<const std::uint8_t, 32>(sk.scopes[0].b)) == want) return s;
  }
  return -1;
}

// A class B change under 4-thread traffic rebuilds every node, one at a time, with 0 failed operations by the strict
// oracle, through R = 1, R = 2 sync and R = 2 async (replica legs and the replicator pin pairs too). HR7: fabric.fetch_qps
// goes 1 (open) -> 4 -> 2 -> 1 and each pair really runs that many fetch QPs. The server's connection cap is exactly the
// rule's minimum for one client over that sequence (the largest old-size + new-size session pair: 6 + 4 = 10 endpoints):
// every overlap fits, nothing is refused.
TEST(ClientRebuild, ClassBChangeRebuildsEveryNodeUnderTrafficWithZeroFailedOps) {
  static constexpr unsigned kQps[] = {1, 4, 2, 1};
  constexpr unsigned kCap = overlap_cap(kQps);
  static_assert(kCap == 10);
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, {},
        [](Client::BundleOpen& bo) { fast_rebuilds(bo); }, /*max_conns=*/kCap);
  ASSERT_TRUE(r.cl);
  Overlap ov(r.w);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) {
    const auto base = tr.ops.load();
    EXPECT_TRUE(until_sim(r.w.clock, [&] { return tr.ops.load() > base + n; }));
  };
  auto publish = [&](const MembershipSnapPtr& s) {
    r.publish(s);
    ASSERT_TRUE(until_sim(r.w.clock, [&] { return r.cl->membership_generation() == s->generation(); }));
  };
  const std::size_t pool0 = 16u << 20;  // ClientCoreOptions default (the Rig's)
  ASSERT_TRUE(slots_run(*r.cl, pool0, 4096, kQps[0]));
  ASSERT_TRUE(until_sim(r.w.clock, [&] { return rails_show_qps(*r.cl, kQps[0]); })) << r.cl->metrics_text();
  settle(20);

  // 1. landing.subpool_bytes, fabric.mtu, fabric.fetch_qps at R = 1
  publish(cfg_snap(2, 1, "[cluster.client.fabric]\nmtu = 2048\nfetch_qps = 4\n[cluster.client.landing]\nsubpool_bytes = 8388608\n"));
  ASSERT_TRUE(until_sim(r.w.clock, [&] { return slots_run(*r.cl, 8u << 20, 2048, kQps[1]) && r.cl->rebuilding_slot() < 0; }))
      << "rebuilds " << r.cl->rebuilds_done() << " failures " << r.cl->rebuild_failures();
  ASSERT_TRUE(until_sim(r.w.clock, [&] { return rails_show_qps(*r.cl, kQps[1]); })) << r.cl->metrics_text();
  EXPECT_EQ(r.cl->rebuilds_done(), 3u);
  EXPECT_EQ(series(r.cl->metrics_text(), "miracache_client_config_pending_rebuild_keys", {}), 0);
  EXPECT_EQ(series(r.cl->metrics_text(), "miracache_client_rebuilds_total", {"result=\"ok\""}), 3);
  {  // the landing pool series read the new cores
    const auto m = r.cl->metrics_text();
    for (const char* id : {"1", "2", "3"}) {
      const auto used = series(m, "miracache_client_landing_pool_bytes", {std::string("node=\"") + id + "\"", "state=\"used\""});
      const auto fr = series(m, "miracache_client_landing_pool_bytes", {std::string("node=\"") + id + "\"", "state=\"free\""});
      ASSERT_TRUE(used && fr) << m;
      EXPECT_EQ(*used + *fr, 8 << 20) << "node " << id;
    }
  }
  settle(40);
  for (unsigned i = 0; i < 3; ++i)
    EXPECT_EQ(ov.conns[i].load(), session_eps(kQps[1])) << "node " << i + 1 << ": the old session ended, the new one has 4 fetch QPs";

  // 2. R = 2 sync (every store waits for both legs), another subpool and fetch_qps
  publish(cfg_snap(3, 2, "[cluster.client.placement]\nreplica_mode = \"sync\"\n[cluster.client.fabric]\nmtu = 2048\nfetch_qps = 2\n"
                         "[cluster.client.landing]\nsubpool_bytes = 4194304\n"));
  ASSERT_TRUE(until_sim(r.w.clock, [&] { return slots_run(*r.cl, 4u << 20, 2048, kQps[2]) && r.cl->rebuilding_slot() < 0; }));
  ASSERT_TRUE(until_sim(r.w.clock, [&] { return rails_show_qps(*r.cl, kQps[2]); })) << r.cl->metrics_text();
  settle(40);
  for (unsigned i = 0; i < 3; ++i) EXPECT_EQ(ov.conns[i].load(), session_eps(kQps[2])) << "node " << i + 1;

  // 3. R = 2 async (the replicator's legs), back to the open-time values
  publish(cfg_snap(4, 2, ""));
  ASSERT_TRUE(until_sim(r.w.clock, [&] { return slots_run(*r.cl, pool0, 4096, kQps[3]) && r.cl->rebuilding_slot() < 0; }));
  ASSERT_TRUE(until_sim(r.w.clock, [&] { return rails_show_qps(*r.cl, kQps[3]); })) << r.cl->metrics_text();
  settle(40);
  for (unsigned i = 0; i < 3; ++i) EXPECT_EQ(ov.conns[i].load(), session_eps(kQps[3])) << "node " << i + 1;
  ASSERT_TRUE(until_sim(r.w.clock, [&] { return legs(r.cl->metrics_text(), "committed") > 0; }));
  tr.finish();
  ov.detach();

  EXPECT_EQ(r.cl->rebuilds_done(), 9u);
  EXPECT_EQ(r.cl->rebuild_failures(), 0u) << "the cap covers one extra session of the new size";
  EXPECT_LE(ov.max_eps.load(), kCap) << "two sessions at most per node";
  EXPECT_EQ(ov.max_doubled.load(), 1u) << "one node at a time";
  EXPECT_LE(ov.max_conns.load(), kCap);
  EXPECT_EQ(r.w.client_aborts_with_work(), 0u) << "no old QP was closed with a WR outstanding";
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Hit), 0u) << o.report();
}

// The old pair serves the job it holds across the swap (its lease too) and is closed only after that job is done; new
// jobs run on the new pair meanwhile, and no other node starts its rebuild while this one has two connections.
TEST(ClientRebuild, OldPairIsRetiredOnlyAfterItsLastPinnedJob) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, {},
        [](Client::BundleOpen& bo) { fast_rebuilds(bo, 0, 100000000); });
  ASSERT_TRUE(r.cl);
  Overlap ov(r.w);
  const int scope = scope_of_node(1);
  ASSERT_GE(scope, 0);
  const auto slot2 = static_cast<std::size_t>(r.cl->slot_of(2));
  auto sk = scope_keys(scope);
  Chain ch("held");
  Bytes data = payload(scope, 7);
  std::vector<BufRef> pb{{std::span<std::byte>(data)}};
  auto stc = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(60)));
  ASSERT_TRUE(stc);
  ASSERT_EQ(stc->status.at(0), KeyStatus::Committed);

  const std::shared_ptr<const void> pair0 = r.cl->slot_pair_for_test(slot2);
  ASSERT_TRUE(pair0);
  r.w.cex.hold();  // the fetch's decrypt waits: the job stays inside node 2's pair with its lease
  Bytes out(kPayload, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  Ticket held = r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, std::chrono::hours(100));
  ASSERT_TRUE(until([&] { return r.w.cex.held() > 0; }));
  ASSERT_EQ(r.cl->slot_jobs_inside(slot2), 1);

  r.publish(cfg_snap(2, 1, "[cluster.client.landing]\nsubpool_bytes = 8388608\n"));
  ASSERT_TRUE(until([&] { return r.cl->slot_pair_for_test(slot2) != pair0; }, milliseconds(60000))) << "node 2 swapped";
  EXPECT_EQ(r.cl->rebuilding_slot(), static_cast<long>(slot2)) << "node 2 holds the token while the old pair retires";
  // New jobs go to the new pair: a store and a lookup on node 2 work although the old pair is held.
  Chain ch2("after");
  Bytes d2 = payload(scope, 8);
  std::vector<BufRef> pb2{{std::span<std::byte>(d2)}};
  auto s2 = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ch2.ref, 1), pb2, seconds(60)));
  ASSERT_TRUE(s2);
  EXPECT_EQ(s2->status.at(0), KeyStatus::Committed);
  auto l2 = r.wt->wait(r.cl->lookup(sk, 0, std::span<const KeyRef>(&ch.ref, 1), seconds(60)));
  ASSERT_TRUE(l2);
  EXPECT_EQ(l2->status.at(0), KeyStatus::Hit);
  // For a while (many retire ticks): the old pair is still open, the token stays with node 2.
  const auto t0 = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - t0 < milliseconds(300)) {
    ASSERT_GE(pair0.use_count(), 3) << "the node's old_pair, the held job and this copy";
    ASSERT_EQ(r.cl->slot_jobs_inside(slot2), 1);
    ASSERT_EQ(r.cl->rebuilding_slot(), static_cast<long>(slot2));
    std::this_thread::sleep_for(milliseconds(5));
  }
  EXPECT_EQ(ov.conns[1].load(), 2 * session_eps(1)) << "two sessions to node 2 during the overlap";

  r.w.cex.release();  // the held job finishes on the pair it pinned
  auto fc = r.wt->wait(held);
  ASSERT_TRUE(fc);
  EXPECT_EQ(fc->status.at(0), KeyStatus::Hit);
  EXPECT_EQ(decode(scope, out), std::optional<std::uint64_t>(7));
  ASSERT_TRUE(until([&] { return pair0.use_count() == 1; })) << "the node let go of the old pair";
  ASSERT_TRUE(until([&] { return slots_run(*r.cl, 8u << 20, 4096, 1) && r.cl->rebuilding_slot() < 0; }, milliseconds(60000)))
      << "the other nodes went next";
  EXPECT_EQ(r.cl->rebuilds_done(), 3u);
  // Ops on node 2 drive the sim (and its clock: the server sweeps dead connections at its tick) until the server has
  // ended the old session.
  for (int i = 0; i < 5000 && ov.conns[1].load() != session_eps(1); ++i) {
    auto lc = r.wt->wait(r.cl->lookup(sk, 0, std::span<const KeyRef>(&ch.ref, 1), seconds(60)));
    ASSERT_TRUE(lc);
    ASSERT_EQ(lc->status.at(0), KeyStatus::Hit);
  }
  EXPECT_EQ(ov.conns[1].load(), session_eps(1)) << "the old session (and its lease) is gone on the server";
  EXPECT_EQ(ov.max_doubled.load(), 1u);
  EXPECT_EQ(r.w.client_aborts_with_work(), 0u);
  ov.detach();
}

// At the drain deadline an old pair that still has a job inside goes Down (§3.7): the server ends that session; the job
// leaves once its decrypt is done, and only then is the pair closed.
TEST(ClientRebuild, DrainDeadlineEndsTheOldSessionOfABusyPair) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, {},
        [](Client::BundleOpen& bo) { fast_rebuilds(bo, 0, 300); });
  ASSERT_TRUE(r.cl);
  Overlap ov(r.w);
  const int scope = scope_of_node(1);
  ASSERT_GE(scope, 0);
  const auto slot2 = static_cast<std::size_t>(r.cl->slot_of(2));
  auto sk = scope_keys(scope);
  Chain ch("drained");
  Bytes data = payload(scope, 3);
  std::vector<BufRef> pb{{std::span<std::byte>(data)}};
  auto stc = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(60)));
  ASSERT_TRUE(stc);
  ASSERT_EQ(stc->status.at(0), KeyStatus::Committed);
  const std::shared_ptr<const void> pair0 = r.cl->slot_pair_for_test(slot2);
  r.w.cex.hold();
  Bytes out(kPayload, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  Ticket held = r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, std::chrono::hours(100));
  ASSERT_TRUE(until([&] { return r.w.cex.held() > 0; }));
  r.publish(cfg_snap(2, 1, "[cluster.client.landing]\nsubpool_bytes = 8388608\n"));
  ASSERT_TRUE(until([&] { return r.cl->slot_pair_for_test(slot2) != pair0; }, milliseconds(60000)));
  ASSERT_TRUE(until([&] { return ov.conns[1].load() == session_eps(1); }, milliseconds(60000))) << "the drain ended the old session";
  EXPECT_GE(pair0.use_count(), 3) << "not closed: the job is still inside";
  EXPECT_EQ(r.cl->rebuilding_slot(), static_cast<long>(slot2));
  // F09: the held token is visible (slot, node identity) and its age grows while the job stays inside.
  const std::string tok = "miracache_client_rebuild_token_held_seconds";
  const std::initializer_list<std::string> who{"slot=\"" + std::to_string(slot2) + "\"", "node_id=\"2\"", "hostname=", "addr="};
  ASSERT_TRUE(until([&] { return series(r.cl->metrics_text(), tok, who).value_or(0) >= 1; }, milliseconds(120000)))
      << r.cl->metrics_text();
  r.w.cex.release();
  auto fc = r.wt->wait(held);
  ASSERT_TRUE(fc) << "the drained job completes";
  ASSERT_TRUE(until([&] { return pair0.use_count() == 1; }));
  ASSERT_TRUE(until([&] { return slots_run(*r.cl, 8u << 20, 4096, 1) && r.cl->rebuilding_slot() < 0; }, milliseconds(60000)));
  EXPECT_EQ(series(r.cl->metrics_text(), tok, who), 0) << "given back";
  auto ac = r.wt->wait(r.cl->lookup(sk, 0, std::span<const KeyRef>(&ch.ref, 1), seconds(60)));
  ASSERT_TRUE(ac);
  EXPECT_EQ(ac->status.at(0), KeyStatus::Hit) << "the new pair serves node 2";
  ov.detach();
}

// A rebuild that cannot build (make_spec fails, or the server's connection cap refuses the new session) keeps the old
// pair active and serving: 0 failed operations, retried with backoff, never two sessions over the cap.
TEST(ClientRebuild, AFailedBuildKeepsTheOldPairServing) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, {},
        [](Client::BundleOpen& bo) { fast_rebuilds(bo, 50); });
  ASSERT_TRUE(r.cl);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) { settle_traffic(r, tr, n); };
  settle(20);
  r.spec_fail = true;
  r.publish(cfg_snap(2, 1, "[cluster.client.landing]\nsubpool_bytes = 8388608\n"));
  ASSERT_TRUE(until([&] { return r.cl->rebuild_failures() >= 3; }, milliseconds(60000)));
  settle(40);
  EXPECT_EQ(r.cl->rebuilds_done(), 0u);
  EXPECT_TRUE(slots_run(*r.cl, 16u << 20, 4096, 1)) << "the old pairs stay";
  EXPECT_EQ(series(r.cl->metrics_text(), "miracache_client_config_pending_rebuild_keys", {}), 1);
  EXPECT_GE(series(r.cl->metrics_text(), "miracache_client_rebuilds_total", {"result=\"failed\""}).value_or(0), 3);
  r.spec_fail = false;  // the retry goes through
  ASSERT_TRUE(until([&] { return slots_run(*r.cl, 8u << 20, 4096, 1) && r.cl->rebuilding_slot() < 0; }, milliseconds(60000)));
  settle(30);
  tr.finish();
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Hit), 0u) << o.report();
}

// G01: a ticket cache sized as AdminTicketSource sizes it: prepare() refills a class below max(2, need) by
// max(batch, need) (need: fetch_qps for fetch, 1 otherwise; capped at 2 x that), and a build only draws from the
// cache. Each spec (each planned rebuild) gets a fresh one, as make_spec's fresh admin source.
struct CappedTickets {
  std::mutex mu;
  unsigned batch = 4, need = 1;
  unsigned left[3] = {0, 0, 0};
  void prepare() {
    std::lock_guard lk(mu);
    for (int i = 0; i < 3; ++i) {
      const unsigned nd = i == static_cast<int>(fabric::EpClass::Fetch) ? need : 1;
      const unsigned count = std::max(batch, nd), mark = std::max(2u, nd), cap = std::max(2 * count, mark);
      if (left[i] < mark) left[i] += std::min(count, cap - left[i]);
    }
  }
  bool take(fabric::EpClass c) {
    std::lock_guard lk(mu);
    unsigned& l = left[static_cast<int>(c)];
    if (l == 0) return false;
    --l;
    return true;
  }
};
void capped_tickets(Client::NodeSpec& ns, const control::NodeView&) {
  auto c = std::make_shared<CappedTickets>();
  auto inner = ns.wopts.tickets;
  ns.wopts.tickets = [c, inner](fabric::EpClass cls) -> Expected<proto::Ticket> {
    if (!c->take(cls)) return Error{ErrorCode::NotFound, "test: no cached ticket"};
    return inner(cls);
  };
  ns.wopts.prepare = [c] { c->prepare(); };
  ns.wopts.ticket_need = [c](std::uint32_t n) {
    std::lock_guard lk(c->mu);
    c->need = n;
  };
  ns.on_dyn = [c](const ClientDyn& d) {
    std::lock_guard lk(c->mu);
    c->batch = d.ticket_batch;
  };
}

// G01: a bundle that raises fabric.fetch_qps above the ticket batch (1 -> 8, ticket_batch 4: the shipped E810 iWARP
// value) rebuilds every node. The fresh ticket source of a rebuild learns the new fetch_qps and the live batch before
// its first refill; before the fix it held 4 fetch tickets, every rebuild failed and the old pairs stayed forever.
TEST(ClientRebuild, FetchQpsAboveTheTicketBatchRebuildsWithEnoughTickets) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, capped_tickets,
        [](Client::BundleOpen& bo) { fast_rebuilds(bo, 50); });
  ASSERT_TRUE(r.cl);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) { settle_traffic(r, tr, n, milliseconds(120000)); };
  settle(20);
  r.publish(cfg_snap(2, 1, "[cluster.client.fabric]\nfetch_qps = 8\n"));
  ASSERT_TRUE(until([&] { return slots_run(*r.cl, 16u << 20, 4096, 8) && r.cl->rebuilding_slot() < 0; }, milliseconds(120000)))
      << "rebuild failures: " << r.cl->rebuild_failures();
  EXPECT_EQ(r.cl->rebuild_failures(), 0u);
  EXPECT_EQ(r.cl->rebuilds_done(), 3u);
  ASSERT_TRUE(until([&] { return rails_show_qps(*r.cl, 8); })) << r.cl->metrics_text();
  settle(30);
  tr.finish();
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Hit), 0u) << o.report();
}

// G09 (review G07, Q6): a planned rebuild whose new pair hits a LOCAL device limit (the overlap is where a CQ/QP limit is
// most likely) is counted in miracache_client_endpoint_build_failures_total{cause="local_resource"} with the node's
// identity, as a first build is; the old pair keeps serving and the rebuild goes through once the device has room.
TEST(ClientRebuild, LocalResourceFailureOfARebuildIsCountedByCause) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, {},
        [](Client::BundleOpen& bo) { fast_rebuilds(bo, 50); });
  ASSERT_TRUE(r.cl);
  for (auto* f : r.w.spare[0]) f->inject_local_failure("ibv_create_cq");  // every fresh client NIC of node 1
  r.publish(cfg_snap(2, 1, "[cluster.client.landing]\nsubpool_bytes = 8388608\n"));
  const std::initializer_list<std::string> who{"node_id=\"1\"", "hostname=", "addr=", "rail=\"0\"", "cause=\"local_resource\""};
  ASSERT_TRUE(until([&] {
    return series(r.cl->metrics_text(), "miracache_client_endpoint_build_failures_total", who).value_or(0) >= 2;
  }, milliseconds(120000))) << r.cl->metrics_text();
  EXPECT_GE(r.cl->rebuild_failures(), 2u);
  EXPECT_FALSE(series(r.cl->metrics_text(), "miracache_client_endpoint_build_failures_total", {"node_id=\"2\""}).has_value());
  for (auto* f : r.w.spare[0]) f->inject_local_failure(nullptr);
  ASSERT_TRUE(until([&] { return slots_run(*r.cl, 8u << 20, 4096, 1) && r.cl->rebuilding_slot() < 0; }, milliseconds(120000)));
}

// H06: a planned rebuild fails (local device limit), then its change is reverted before a retry succeeds. The failure's
// open entry is settled when the pending rebuild is withdrawn (one "withdrawn" line, no "recovered" line), so the next
// failure of the same cause (the change published again) is logged again instead of being swallowed.
TEST(ClientRebuild, WithdrawnRebuildSettlesItsFailureSoTheNextOneIsLogged) {
  char tmpl[] = "/tmp/mira-h06-XXXXXX";
  const int lfd = ::mkstemp(tmpl);
  ASSERT_GE(lfd, 0);
  auto text = [&] {
    std::string t;
    char buf[4096];
    ssize_t n;
    ::lseek(lfd, 0, SEEK_SET);
    while ((n = ::read(lfd, buf, sizeof buf)) > 0) t.append(buf, static_cast<std::size_t>(n));
    return t;
  };
  auto count = [&](const std::string& msg) {
    const std::string t = text();
    std::size_t c = 0, at = 0;
    while (at < t.size()) {
      const std::size_t eol = std::min(t.find('\n', at), t.size());
      const std::string line = t.substr(at, eol - at);
      if (line.find(msg) != std::string::npos && line.find("node_id=1 ") != std::string::npos) ++c;
      at = eol + 1;
    }
    return c;
  };
  const std::string failed = "memory-node endpoint build failed", withdrawn = "planned rebuild withdrawn",
                    recovered = "memory-node endpoint build recovered";
  log::set_sink_fd(lfd);
  {
    Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, {},
          [](Client::BundleOpen& bo) { fast_rebuilds(bo, 50); });
    ASSERT_TRUE(r.cl);
    for (auto* f : r.w.spare[0]) f->inject_local_failure("ibv_create_cq");  // every fresh client NIC of node 1
    r.publish(cfg_snap(2, 1, "[cluster.client.landing]\nsubpool_bytes = 8388608\n"));
    EXPECT_TRUE(until([&] { return count(failed) >= 1; }, milliseconds(120000))) << text();
    r.publish(cfg_snap(3, 1, ""));  // reverted: the pending rebuild is withdrawn
    EXPECT_TRUE(until([&] { return count(withdrawn) >= 1; }, milliseconds(120000))) << text();
    EXPECT_EQ(count(failed), 1u);
    EXPECT_EQ(count(recovered), 0u) << "nothing recovered: the rebuild was withdrawn";
    r.publish(cfg_snap(4, 1, "[cluster.client.landing]\nsubpool_bytes = 8388608\n"));  // the same change again
    EXPECT_TRUE(until([&] { return count(failed) >= 2; }, milliseconds(120000)))
        << "the next failure of the same cause is logged again\n" << text();
    for (auto* f : r.w.spare[0]) f->inject_local_failure(nullptr);
    EXPECT_TRUE(until([&] { return slots_run(*r.cl, 8u << 20, 4096, 1) && r.cl->rebuilding_slot() < 0; }, milliseconds(120000)));
    EXPECT_EQ(count(withdrawn), 1u);
    EXPECT_EQ(count(recovered), 1u) << "one recovery line, for the rebuild that went through";
  }
  log::set_sink_fd(2);
  ::close(lfd);
  ::unlink(tmpl);
}

// R09 (review s11): a planned rebuild fails (local device limit on its fresh NIC) while the old pair keeps serving; the
// old pair's session then reconnects (its rail 0 comes up again, Q03's filtered recovery). Before: that reconnect
// closed the rebuild's entry with a false "recovered ... via session reconnect" line. Now the entry stays the rebuild's:
// no recovery line, and withdrawing the rebuild settles it.
TEST(ClientRebuild, OldPairReconnectDoesNotCloseAPendingRebuildsFailure) {
  char tmpl[] = "/tmp/mira-r09-XXXXXX";
  const int lfd = ::mkstemp(tmpl);
  ASSERT_GE(lfd, 0);
  auto text = [&] {
    std::string t;
    char buf[4096];
    ssize_t n;
    ::lseek(lfd, 0, SEEK_SET);
    while ((n = ::read(lfd, buf, sizeof buf)) > 0) t.append(buf, static_cast<std::size_t>(n));
    return t;
  };
  auto count = [&](const std::string& msg) {
    const std::string t = text();
    std::size_t c = 0, at = 0;
    while (at < t.size()) {
      const std::size_t eol = std::min(t.find('\n', at), t.size());
      const std::string line = t.substr(at, eol - at);
      if (line.find(msg) != std::string::npos && line.find("node_id=1 ") != std::string::npos) ++c;
      at = eol + 1;
    }
    return c;
  };
  const std::string failed = "memory-node endpoint build failed", withdrawn = "planned rebuild withdrawn",
                    recovered = "memory-node endpoint build recovered",
                    in_service = "planned rebuild: new connection in service";
  log::set_sink_fd(lfd);
  // Restores the log sink and removes the temp file on every exit path (an ASSERT returns early). Declared before the Rig
  // scope, so it runs after the Rig (and its threads) are gone.
  struct SinkGuard {
    int fd;
    const char* path;
    ~SinkGuard() {
      log::set_sink_fd(2);
      ::close(fd);
      ::unlink(path);
    }
  } sink_guard{lfd, tmpl};
  {
    Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, {},
          [](Client::BundleOpen& bo) { fast_rebuilds(bo, 50); });
    ASSERT_TRUE(r.cl);
    const long s1 = r.cl->slot_of(1);
    ASSERT_GE(s1, 0);
    for (auto* f : r.w.spare[0]) f->inject_local_failure("ibv_create_cq");  // every fresh client NIC of node 1
    r.publish(cfg_snap(2, 1, "[cluster.client.landing]\nsubpool_bytes = 8388608\n"));
    EXPECT_TRUE(until([&] { return count(failed) >= 1; }, milliseconds(120000))) << text();
    WirePort* p = r.cl->wire_port(static_cast<std::size_t>(s1));  // the old pair: the rebuild never went through
    ASSERT_NE(p, nullptr);
    const std::uint64_t downs = p->session_down_count();
    // The old session ends; it reconnects on its own (working) NIC. The sim is single-threaded and the client's keepalive
    // threads run (keepalive_ms = 20), so the abort happens in the client's sim turn (drive(), under srv_mu), not on the
    // test thread (run #277: tsan saw this abort's write of SimEndpoint::aborted_ race a keepalive ping's can_post()).
    std::atomic<bool> aborted{false};
    {
      std::lock_guard lk(r.w.srv_mu);
      r.w.on_drive = [&] {
        if (aborted.load()) return;
        if (fabric::Endpoint* ep = p->endpoint(fabric::EpClass::Control)) ep->abort();
        aborted.store(true);
      };
    }
    EXPECT_TRUE(until([&] { return aborted.load(); }, milliseconds(120000)));
    {
      std::lock_guard lk(r.w.srv_mu);
      r.w.on_drive = nullptr;
    }
    EXPECT_TRUE(until([&] { return p->session_down_count() > downs && p->session_up(); }, milliseconds(120000)));
    // The reconnect's on_rails_up has run (run #297; was a 100 ms real-time sleep): node 1's keepalive thread flips the
    // session Up and then calls on_rails_up in the same reconnect step; only after that step returns does a later tick
    // PING on this port (the reconnect sends none, and no traffic runs here to probe a suspect rail). So a PING counted
    // after Up was seen proves the step, and with it on_rails_up, is over.
    const std::uint64_t pings_up = p->pings_sent();
    ASSERT_TRUE(until([&] { return p->pings_sent() > pings_up; }, milliseconds(120000)))
        << "node 1's keepalive thread never ticked again after the reconnect\n" << text();
    EXPECT_EQ(count(recovered), 0u) << "the old pair's reconnect closed the pending rebuild's failure\n" << text();
    r.publish(cfg_snap(3, 1, ""));  // reverted: the pending rebuild is withdrawn and settles its entry
    EXPECT_TRUE(until([&] { return count(withdrawn) >= 1; }, milliseconds(120000))) << text();
    EXPECT_EQ(count(recovered), 0u) << text();
    // Node 1's rebuild never went through: its old pair still serves and no "in service" line names it. Node-scoped on
    // purpose (run #294): the class B change rebuilt nodes 2 and 3 and the revert rebuilds them back, on their own
    // keepalive threads, so the client-wide rebuilds_done() can move at any time during this test.
    EXPECT_EQ(count(in_service), 0u) << text();
    EXPECT_EQ(r.cl->wire_port(static_cast<std::size_t>(s1)), p);
    for (auto* f : r.w.spare[0]) f->inject_local_failure(nullptr);
  }
}

TEST(ClientRebuild, ConnectionCapHitDuringTheOverlapLeavesTheOldPairServing) {
  // max_conns_per_principal = 3: room for exactly one session per node, none for the overlap.
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, /*keepalive_ms=*/20, false, false, {},
        [](Client::BundleOpen& bo) { fast_rebuilds(bo, 50); }, /*max_conns=*/session_eps(1));
  ASSERT_TRUE(r.cl);
  Overlap ov(r.w);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) { settle_traffic(r, tr, n); };
  settle(20);
  r.publish(cfg_snap(2, 1, "[cluster.client.fabric]\nfetch_qps = 4\n"));
  ASSERT_TRUE(until([&] { return r.cl->rebuild_failures() >= 3; }, milliseconds(60000)));
  settle(60);
  tr.finish();
  ov.detach();
  EXPECT_EQ(r.cl->rebuilds_done(), 0u);
  EXPECT_TRUE(slots_run(*r.cl, 16u << 20, 4096, 1)) << "every node keeps its old pair";
  EXPECT_LE(ov.max_conns.load(), session_eps(1));
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Hit), 0u) << o.report();
}

}  // namespace
}  // namespace miracache
