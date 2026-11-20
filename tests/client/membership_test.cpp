// SPDX-License-Identifier: Apache-2.0
// MB6a: client node slots driven by bundles (membership plan decision 9). Real memory-node servers over SimFabric,
// bundles built in memory (no signatures: the watcher's job, MB5). Checks add, retire (waits for jobs_inside, slot
// reuse), re-weight and R under 4-thread traffic with the strict oracle, the stage-before-swap push order, the
// HELLO_ACK ID check, and the oracle helper itself.
#include <gtest/gtest.h>

#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cerrno>
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
#include "server/dyn_config.h"
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
  std::atomic<bool> drop_put_done{false};  // run #200: the node commits, its PUT_DONE never reaches the client
  std::atomic<unsigned> stale_replies{0}, draining_replies{0}, put_begins_passed{0}, put_done_dropped{0};
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
    std::size_t kept = 0;
    for (std::size_t i = 0; i < n; ++i) {
      auto& c = out[i];
      if (c.is_recv && c.op == fabric::CompletionOp::Recv) {
        if (st_.drop_put_done.load()) {
          auto fr = proto::decode_frame(c.frame.bytes);
          if (fr && fr->h.type == static_cast<std::uint16_t>(proto::Op::PUT_DONE)) {
            ++st_.put_done_dropped;
            continue;
          }
        }
        stamp(c.frame.bytes);
      }
      if (kept != i) out[kept] = std::move(c);
      ++kept;
    }
    n = kept;
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
  static inline bool single_listener_any_address = false;  // RailChangeQuietsTheOldIdentitySeries only (G08)
  explicit World(std::map<unsigned, unsigned> wrong_id = {}, bool shim_on = false) : rng(5), net(clock, rng, {}, opts()) {
    for (unsigned i = 1; i <= kServers; ++i) {
      sfab[i - 1] = &net.add_node(i);
      sfab[i - 1]->set_single_listener_takes_any_address_for_test(single_listener_any_address);
      cfab[i - 1] = &net.add_node(10 + i);
      if (shim_on) shim[i - 1] = std::make_unique<ShimFabric>(*cfab[i - 1], stamps[i - 1]);
    }
    for (unsigned i = 1; i <= kServers; ++i) {
      auto sc = server_cfg();
      sc.rails = {fabric::RailAddr{"sim", static_cast<std::uint16_t>(7000 + i)}};  // where the client dials: the sim matches exactly (G08)
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
  // A wait on a frozen server ends at its sim-time deadline (WirePort, review w5 U2-26: no call-count cap), so a job
  // held on one (rpc_timeout = 100 h of sim time) stays inside until the test unfreezes the server, on any build.
  void drive() {
    if (!net.step()) clock.advance_by(milliseconds(1));
    std::lock_guard lk(srv_mu);
    for (auto& [id, v] : to_apply) srv[id - 1]->apply_bundle(v);
    to_apply.clear();
    for (unsigned i = 0; i < kServers; ++i)
      if (!frozen[i]) srv[i]->run_once();
  }
  Expected<Client::NodeSpec> spec(const control::NodeView& nv) {
    const unsigned i = nv.node_id;
    Client::NodeSpec ns;
    ns.fab = shim[i - 1] ? static_cast<fabric::Fabric*>(shim[i - 1].get()) : static_cast<fabric::Fabric*>(cfab[i - 1]);
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
  InlineExecutor sex, cex;
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

// A really signed envelope (test keys), parsed back through open_bundle: what a memory node's POST /v1/bundle sees.
// The principal binds identity "lab", the one the sim tickets are issued for.
MembershipSnapPtr signed_snap(std::uint64_t gen, std::uint32_t epoch, std::vector<std::pair<unsigned, unsigned>> nodes,
                              unsigned replicas = 1, std::vector<unsigned> previous = {}, std::set<unsigned> draining = {}) {
  std::string sec = "sec_generation = 1\n\n[[principals]]\nname = \"lab\"\nidentities = [\"lab\"]\nquota_bytes = 1073741824\n"
                    "max_scopes = 1000\n\n[[rbac]]\nidentity = \"spiffe://ops/alice\"\nroles = [\"security-admin\"]\n";
  std::string body = "schema_version = 1\ngeneration = " + std::to_string(gen) +
                     "\ncreated_at = \"2026-11-12T09:00:00Z\"\nauthor = \"spiffe://ops/alice\"\nreason = \"test\"\n\n[membership]\nepoch = " +
                     std::to_string(epoch) + "\nprevious_epoch = " + std::to_string(epoch - 1) + "\n\n";
  for (auto [id, w] : nodes) {
    const std::string n = std::to_string(id);
    body += "[[membership.nodes]]\nnode_id = " + n + "\nhostname = \"host" + n + "\"\nadmin = \"10.0.0." + n +
            ":9465\"\nrails = [{ addr = \"10.0.0." + n + ":7471\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }]\nweight = " +
            std::to_string(w) + "\nstate = \"" + (draining.count(id) ? "draining" : "active") + "\"\n\n";
  }
  for (unsigned id : previous) body += "[[membership.previous]]\nnode_id = " + std::to_string(id) + "\nweight = 1\n\n";
  body += "[config.cluster.placement]\nreplicas = " + std::to_string(replicas) + "\n";
  const std::string env = control::testutil::assemble(control::testutil::sign_parts(sec, body));
  auto v = control::open_bundle(env, trust());
  if (!v) std::abort();
  auto s = std::make_shared<MembershipSnap>();
  s->view = std::move(*v);
  s->envelope = env;
  return s;
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
               std::function<void(Client::BundleOpen&)> bo_tweak = {}, Nanos open_settle = Nanos{0},
               unsigned lane_cap = 0)
      : w(std::move(wrong), shim), bundle_servers_(bundle_servers), shim_(shim), tweak_(std::move(tweak)) {
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
    // Run #200: the traffic gives every store a 60 s (sim) deadline, but HR2 clamps store deadlines to put_max_ms
    // (2.5 s by default). Sim time races ahead while a job waits for its sim turn (four traffic threads plus the
    // keepalive and slot threads all drive the clock), so 2.5 s of sim time can pass in ~2.5 ms of real time and a
    // healthy store timed out (strict-oracle "timeout"/"aborted", about 1 run in 40). The tests' own deadlines apply.
    env.put_max_ms = 600000;
    env.open_settle = open_settle;  // Q15
    Client::BundleOpen bo;
    bo.initial = std::move(first);
    bo.make_spec = [this](const control::NodeView& nv) -> Expected<Client::NodeSpec> {
      spec_calls.fetch_add(1);
      if (spec_fail.load()) return Error{ErrorCode::LinkDown, "test: make_spec fails"};
      if (spec_local_fail.load()) {  // Q6: the node's fabric open fails at the local CQ (siw0 at its device limit)
        fabric::last_local_failure() =
            spec_provider_call.load()
                ? fabric::LocalFailure{"ibv_create_cq", spec_errno.load(), "siw0", -1}
                : fabric::LocalFailure{"completion queue budget exhausted (cq_depth)", 0, "siw0", -1, /*provider_call=*/false};
        return Error{ErrorCode::ResourceExhausted, "ibv_create_cq"};
      }
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
    ro.lane_cap = lane_cap;
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
  std::atomic<bool> spec_local_fail{false};
  std::atomic<int> spec_errno{ENOMEM};  // L12: 0 = a provider that fails without setting errno (libsiw)
  std::atomic<bool> spec_provider_call{true};  // Q07: false = the fabric's own cq_depth budget refused (no verbs call)
  std::atomic<int> spec_calls{0};
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
  // Failure context: the membership generation and the sim / real time an op took.
  auto ctx_of = [&r](Nanos s0, std::chrono::steady_clock::time_point r0, std::uint64_t g0) {
    const auto sim_ms = std::chrono::duration_cast<milliseconds>(r.w.clock.now() - s0).count();
    const auto real_us = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now() - r0).count();
    return "gen=" + std::to_string(g0) + ".." + std::to_string(r.cl->membership_generation()) + " sim_ms=" +
           std::to_string(sim_ms) + " real_us=" + std::to_string(real_us) + " sim_at=" +
           std::to_string(std::chrono::duration_cast<milliseconds>(s0).count());
  };
  o.begin_store(key, v);
  Nanos s0 = r.w.clock.now();
  auto r0 = std::chrono::steady_clock::now();
  std::uint64_t g0 = r.cl->membership_generation();
  auto sc = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(60)));
  if (!sc) return o.on_missing_completion("store " + key);
  const KeyStatus st = sc->status.at(0);
  o.end_store(key, v, st == KeyStatus::Committed);
  o.on_store(key, st, false, ctx_of(s0, r0, g0));
  Bytes out(kPayload, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  s0 = r.w.clock.now(), r0 = std::chrono::steady_clock::now(), g0 = r.cl->membership_generation();
  auto fc = r.wt->wait(r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, seconds(60)));
  if (!fc) return o.on_missing_completion("fetch " + key);
  const KeyStatus fs = fc->status.at(0);
  o.on_fetch(key, fs, fs == KeyStatus::Hit ? decode(scope, out) : std::nullopt, false, ctx_of(s0, r0, g0));
  // Y19: also re-read an OLDER committed key. After a membership change its owner may be another node: a Miss is fine,
  // a Hit must still carry exactly that key's version (the stale-bytes rule). Run #200: a traffic thread gives its
  // scopes the versions v, v+1, v+2 in turn, so this scope's previous key is v - 3 (v - 2 was never stored here: the
  // re-read was always a Miss and checked nothing).
  if (v > 3) {
    const std::uint64_t ov = v - 3;
    const std::string okey = "k" + std::to_string(scope) + "_" + std::to_string(ov);
    Chain och(okey);
    Bytes oout(kPayload, std::byte{0xAA});
    std::vector<BufRef> ob{{std::span<std::byte>(oout)}};
    s0 = r.w.clock.now(), r0 = std::chrono::steady_clock::now(), g0 = r.cl->membership_generation();
    auto oc = r.wt->wait(r.cl->fetch(sk, 0, std::span<const KeyRef>(&och.ref, 1), ob, seconds(60)));
    if (!oc) return o.on_missing_completion("re-fetch " + okey);
    const KeyStatus os = oc->status.at(0);
    o.on_fetch(okey, os, os == KeyStatus::Hit ? decode(scope, oout) : std::nullopt, false, "re-read " + ctx_of(s0, r0, g0));
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

std::optional<long long> series(const std::string& text, const std::string& name, std::initializer_list<std::string> parts);

TEST(MembershipSlots, AddReweightRetireAndSlotReuseUnderTraffic) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  EXPECT_EQ(r.cl->node_count(), 3u);
  EXPECT_EQ(r.cl->membership_generation(), 1u);
  EXPECT_TRUE(r.pushes.empty()) << "the open pushes nothing: those nodes gave us the bundle";
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) {
    const auto base = tr.ops.load();
    EXPECT_TRUE(until([&] { return tr.ops.load() > base + n; }));
  };
  settle(20);

  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));  // add node 4
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  EXPECT_EQ(r.cl->node_count(), 4u);
  {
    std::lock_guard lk(r.pm);
    ASSERT_EQ(r.pushes.size(), 1u);
    EXPECT_EQ(r.pushes[0], "10.0.0.4:9465");
    ASSERT_EQ(r.connected_at_push.size(), 1u);
    EXPECT_FALSE(r.connected_at_push[0]) << "the envelope must reach the added node before its first connection";
  }
  const long slot4 = r.cl->slot_of(4);
  ASSERT_GE(slot4, 0);
  EXPECT_NE(r.cl->wire_port(static_cast<std::size_t>(slot4)), nullptr) << "published only after the node is Up";
  settle(20);

  r.cl->apply_membership(make_snap(3, 3, {{1, 3}, {2, 1}, {3, 1}, {4, 1}}));  // re-weight node 1
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 3; }));
  EXPECT_EQ(r.cl->membership_epoch(), 3u);
  settle(20);

  const long slot2 = r.cl->slot_of(2);
  ASSERT_GE(slot2, 0);
  r.cl->apply_membership(make_snap(4, 4, {{1, 3}, {3, 1}, {4, 1}}));  // retire node 2
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 4; }));
  ASSERT_TRUE(until([&] { return r.cl->slot_of(2) < 0; })) << "the retired slot must be torn down";
  EXPECT_EQ(r.cl->node_count(), 3u);
  settle(20);

  r.cl->apply_membership(make_snap(5, 5, {{1, 3}, {3, 1}, {4, 1}, {5, 1}}));  // add node 5: reuses node 2's slot
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 5; }));
  EXPECT_EQ(r.cl->slot_of(5), slot2) << "a freed slot is reused";
  settle(20);
  tr.finish();
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Hit), 0u) << o.report();
  EXPECT_NE(r.cl->metrics_text().find("miracache_client_put_skipped_total{reason=\"stale_epoch\"}"), std::string::npos);
}

TEST(MembershipSlots, RetireWaitsForJobsInsideAndReviveKeepsTheSlot) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  // A scope owned by node 2 (probe with a fetch: placement is decided by the snapshot; find one by trying).
  int scope = -1;
  for (int s = 0; s < 64 && scope < 0; ++s) {
    PlaceNode a{"1"}, b{"2"}, c{"3"};
    std::vector<PlaceNode> v{a, b, c};
    auto sk = scope_keys(s);
    if (place_owner(v, std::span<const std::uint8_t, 32>(sk.scopes[0].b)) == 1) scope = s;
  }
  ASSERT_GE(scope, 0);
  const long slot2 = r.cl->slot_of(2);
  ASSERT_GE(slot2, 0);
  r.w.frozen[1] = true;  // node 2 stops answering: a job on it stays inside
  Chain ch("held");
  auto sk = scope_keys(scope);
  Bytes out(kPayload);
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  Ticket held = r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, std::chrono::hours(100));
  ASSERT_TRUE(until([&] { return r.cl->slot_jobs_inside(static_cast<std::size_t>(slot2)) > 0; }));

  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {3, 1}}));  // node 2 retires
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  std::this_thread::sleep_for(milliseconds(200));
  EXPECT_EQ(r.cl->slot_of(2), slot2) << "the slot is kept while a job is inside";
  EXPECT_TRUE(r.cl->slot_retiring(static_cast<std::size_t>(slot2)));
  EXPECT_GT(r.cl->slot_jobs_inside(static_cast<std::size_t>(slot2)), 0);
  // New jobs for that scope no longer go to node 2.
  auto sc = r.wt->wait(r.cl->lookup(sk, 0, std::span<const KeyRef>(&ch.ref, 1), seconds(60)));
  ASSERT_TRUE(sc);
  EXPECT_NE(sc->status.at(0), KeyStatus::Timeout);

  r.cl->apply_membership(make_snap(3, 3, {{1, 1}, {2, 1}, {3, 1}}));  // back before the teardown: revived in place
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 3; }));
  EXPECT_EQ(r.cl->slot_of(2), slot2);
  EXPECT_FALSE(r.cl->slot_retiring(static_cast<std::size_t>(slot2)));

  r.cl->apply_membership(make_snap(4, 4, {{1, 1}, {3, 1}}));  // gone again
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 4; }));
  r.cl->cancel(held);
  r.w.frozen[1] = false;  // the server answers: the cancelled job leaves (a cancel does not cut a wire wait short)
  ASSERT_TRUE(r.wt->wait(held));
  ASSERT_TRUE(until([&] { return r.cl->slot_of(2) < 0; })) << "freed once the job left";
}

// s12 (tpu-sync cross-check C1, review P2-6): the bundle-mode lane (lane_of's bundle branch: the first node of the
// bundle's owner set). Node 2 stops answering and holds every fetch sent to it; with the production runtime for 3 nodes
// (6 workers, lane_cap 2) only 2 of them run and a lookup for node 1 still completes. `old` (2 workers, no lanes): the
// lookup waits behind the held fetches.
void bundle_frozen_node(bool old) {
  const RuntimeOptions prod = Client::runtime_for_nodes(3);
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), old ? 2u : prod.workers, 2000, {}, 0, false, false, {}, {}, Nanos{0},
        old ? 0u : prod.lane_cap);
  ASSERT_TRUE(r.cl);
  std::vector<int> on2;
  int on1 = -1;
  std::vector<PlaceNode> v{PlaceNode{"1"}, PlaceNode{"2"}, PlaceNode{"3"}};
  for (int s = 0; s < 512 && (on2.size() < 4 || on1 < 0); ++s) {
    auto sk = scope_keys(s);
    const auto o = place_owner(v, std::span<const std::uint8_t, 32>(sk.scopes[0].b));
    if (o == 1 && on2.size() < 4) on2.push_back(s);
    else if (o == 0 && on1 < 0) on1 = s;
  }
  ASSERT_EQ(on2.size(), 4u);
  ASSERT_GE(on1, 0);
  const long slot2 = r.cl->slot_of(2);
  ASSERT_GE(slot2, 0);
  r.w.frozen[1] = true;
  Chain ch("held");
  std::vector<Bytes> outs(on2.size(), Bytes(kPayload));
  std::vector<Ticket> held;
  for (std::size_t i = 0; i < on2.size(); ++i) {
    std::vector<BufRef> fb{{std::span<std::byte>(outs[i])}};
    held.push_back(r.cl->fetch(scope_keys(on2[i]), 0, std::span<const KeyRef>(&ch.ref, 1), fb, std::chrono::hours(100)));
  }
  ASSERT_TRUE(until([&] { return r.cl->slot_jobs_inside(static_cast<std::size_t>(slot2)) >= 2; }));
  std::this_thread::sleep_for(milliseconds(100));  // give a wrongly admitted third job time to get inside
  if (!old) EXPECT_EQ(r.cl->slot_jobs_inside(static_cast<std::size_t>(slot2)), 2) << "the frozen node's lane ran more than its cap";
  auto sk1 = scope_keys(on1);
  const Ticket t1 = r.cl->lookup(sk1, 0, std::span<const KeyRef>(&ch.ref, 1), seconds(60));
  auto lc = r.wt->wait(t1, milliseconds(old ? 1500 : 20000));
  if (old) {
    EXPECT_FALSE(lc) << "the old runtime no longer stalls: this test has lost its teeth";
  } else {
    ASSERT_TRUE(lc) << "a lookup for healthy node 1 waited behind the frozen node's fetches";
    EXPECT_EQ(lc->status.at(0), KeyStatus::Miss);  // nothing stored there: a prompt miss, not a timeout
  }
  for (auto t : held) r.cl->cancel(t);
  r.w.frozen[1] = false;  // the server answers: the cancelled jobs leave (a cancel does not cut a wire wait short)
  for (auto t : held) EXPECT_TRUE(r.wt->wait(t));
  if (old) EXPECT_TRUE(r.wt->wait(t1));
}

TEST(MembershipLanes, FrozenNodeHoldsOnlyItsLaneInBundleMode) { bundle_frozen_node(false); }
TEST(MembershipLanes, WithoutLanesAFrozenNodeStallsBundleModeLookups) { bundle_frozen_node(true); }

// HR3a (hot-reload plan decision 6): a job pins the node's pair once and uses only that pair for its whole life. With
// the job inside, the node's pointer is moved aside (as a planned rebuild will move it to a new pair): new jobs see no
// pair and fail fast, while the held job finishes on the pair it pinned, with the right bytes, and lets it go.
TEST(MembershipSlots, AJobPinsOnePairForItsWholeLife) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  int scope = -1;
  for (int s = 0; s < 64 && scope < 0; ++s) {
    std::vector<PlaceNode> v{PlaceNode{"1"}, PlaceNode{"2"}, PlaceNode{"3"}};
    auto sk = scope_keys(s);
    if (place_owner(v, std::span<const std::uint8_t, 32>(sk.scopes[0].b)) == 1) scope = s;
  }
  ASSERT_GE(scope, 0);
  const long slot2l = r.cl->slot_of(2);
  ASSERT_GE(slot2l, 0);
  const auto slot2 = static_cast<std::size_t>(slot2l);
  auto sk = scope_keys(scope);
  Chain ch("pinned");
  Bytes data = payload(scope, 7);
  std::vector<BufRef> pb{{std::span<std::byte>(data)}};
  auto stc = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(60)));
  ASSERT_TRUE(stc);
  ASSERT_EQ(stc->status.at(0), KeyStatus::Committed);

  const std::shared_ptr<const void> pair = r.cl->slot_pair_for_test(slot2);
  ASSERT_TRUE(pair);
  EXPECT_EQ(pair.use_count(), 2) << "idle: the node and this copy";
  r.w.frozen[1] = true;  // node 2 stops answering: the fetch stays inside
  Bytes out(kPayload, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  Ticket held = r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, std::chrono::hours(100));
  ASSERT_TRUE(until([&] { return r.cl->slot_jobs_inside(slot2) > 0; }));
  EXPECT_EQ(r.cl->slot_jobs_inside(slot2), 1) << "counted on the node's pair";
  EXPECT_EQ(pair.use_count(), 3) << "the job pins the pair";

  std::shared_ptr<const void> aside = r.cl->detach_pair_for_test(slot2);
  ASSERT_EQ(aside, pair);
  EXPECT_EQ(r.cl->slot_pair_for_test(slot2), nullptr);
  EXPECT_EQ(r.cl->slot_jobs_inside(slot2), 0) << "the node has no pair now; the job counts on its own";
  const std::uint64_t ff = r.cl->fast_failed_jobs();
  auto lc = r.wt->wait(r.cl->lookup(sk, 0, std::span<const KeyRef>(&ch.ref, 1), seconds(60)));
  ASSERT_TRUE(lc);
  EXPECT_EQ(lc->status.at(0), KeyStatus::Miss) << "a new job sees the node's pointer, not the held job's pair";
  EXPECT_EQ(r.cl->fast_failed_jobs(), ff + 1);

  r.w.frozen[1] = false;  // the held job finishes on the pair it pinned
  auto fc = r.wt->wait(held);
  ASSERT_TRUE(fc);
  EXPECT_EQ(fc->status.at(0), KeyStatus::Hit);
  EXPECT_EQ(decode(scope, out), std::optional<std::uint64_t>(7));
  EXPECT_EQ(pair.use_count(), 2) << "the job let go: `pair` and `aside` are the only copies";
  ASSERT_TRUE(r.cl->reattach_pair_for_test(slot2, std::move(aside)));
  EXPECT_EQ(r.cl->slot_pair_for_test(slot2), pair);
  EXPECT_EQ(pair.use_count(), 2) << "back to the node and this copy";
  EXPECT_EQ(r.cl->slot_jobs_inside(slot2), 0);
  Bytes again(kPayload, std::byte{0xAA});
  std::vector<BufRef> ab{{std::span<std::byte>(again)}};
  auto ac = r.wt->wait(r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), ab, seconds(60)));
  ASSERT_TRUE(ac);
  EXPECT_EQ(ac->status.at(0), KeyStatus::Hit);
  EXPECT_EQ(decode(scope, again), std::optional<std::uint64_t>(7));
}

TEST(MembershipSlots, EnvelopePushIsRetriedBeforeTheFirstConnect) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, /*wait_ms=*/60000);
  ASSERT_TRUE(r.cl);
  r.fail_pushes = 2;
  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  std::lock_guard lk(r.pm);
  ASSERT_EQ(r.pushes.size(), 3u);
  for (bool c : r.connected_at_push) EXPECT_FALSE(c) << "no connection to the added node before its push succeeded";
  EXPECT_NE(r.cl->wire_port(static_cast<std::size_t>(r.cl->slot_of(4))), nullptr);
}

TEST(MembershipSlots, HelloAckIdMismatchExcludesTheNode) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}}), 2, 2000, /*wrong=*/{{2, 9}});  // server 2 says it is node 9
  ASSERT_TRUE(r.cl);
  const long s2 = r.cl->slot_of(2);
  ASSERT_GE(s2, 0);
  EXPECT_EQ(r.cl->wire_port(static_cast<std::size_t>(s2)), nullptr);
  const std::string m = r.cl->metrics_text();
  EXPECT_NE(m.find("miracache_client_node_id_mismatch_total{node=\"2\"} 1"), std::string::npos) << m;
}

TEST(MembershipSlots, MoreThanKMaxNodesIsNotApplied) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  std::vector<std::pair<unsigned, unsigned>> many;
  for (unsigned i = 1; i <= Client::kMaxNodes + 1; ++i) many.push_back({i, 1});
  r.cl->apply_membership(make_snap(2, 2, many));
  std::this_thread::sleep_for(milliseconds(1200));
  EXPECT_EQ(r.cl->membership_generation(), 1u);
  EXPECT_EQ(r.cl->node_count(), 3u);
}

TEST(MembershipSlots, ReplicasFromTheBundleSurviveARetire) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}, /*R=*/2));
  ASSERT_TRUE(r.cl);
  Oracle o(OracleMode::Strict);
  for (int s = 0; s < 6; ++s) cycle(r, o, s, 1);
  ASSERT_TRUE(until([&] { return r.cl->replicator_pending() == 0; }));
  const std::string m = r.cl->metrics_text();
  EXPECT_NE(m.find("miracache_client_replica_legs_total"), std::string::npos);
  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}}, /*R=*/2));  // node 4 retires, its replicator joins
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  ASSERT_TRUE(until([&] { return r.cl->slot_of(4) < 0; }));
  for (int s = 0; s < 6; ++s) cycle(r, o, s, 2);
  EXPECT_EQ(o.failed(), 0u) << o.report();
}

// Y04: the same node_id at another admin address is rebuilt in a new slot; the old slot retires and is freed.
TEST(MembershipSlots, ChangedAdminRebuildsTheNodeInANewSlot) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  const long old2 = r.cl->slot_of(2);
  ASSERT_GE(old2, 0);
  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}}, 1, {{2, "10.9.9.2:9465"}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  const long new2 = r.cl->slot_of(2);
  ASSERT_GE(new2, 0);
  EXPECT_NE(new2, old2) << "a new wire for the new address";
  {
    std::lock_guard lk(r.pm);
    ASSERT_EQ(r.pushes.size(), 1u);
    EXPECT_EQ(r.pushes[0], "10.9.9.2:9465");
  }
  ASSERT_TRUE(until([&] { return r.cl->slots_in_use() == 3; })) << "the old slot is freed";
  EXPECT_FALSE(r.cl->slot_retiring(static_cast<std::size_t>(old2)));
  EXPECT_EQ(r.cl->slot_of(2), new2);
  // Review w3b Z05: the old and the new slot share their series here (same rail, so the same labels); the old slot's
  // teardown leaves the new slot's identity and pool series alone.
  const std::string m = r.cl->metrics_text();
  EXPECT_EQ(series(m, "miracache_client_node_info", {"node_id=\"2\""}), 1) << m;
  EXPECT_GT(series(m, "miracache_client_landing_pool_bytes", {"state=\"free\"", "node=\"2\""}).value_or(0), 0) << m;
  Oracle o(OracleMode::Strict);
  for (int s = 0; s < 6; ++s) cycle(r, o, s, 1);
  EXPECT_EQ(o.failed(), 0u) << o.report();
}

// Y06: a node whose make_spec fails is kept pending and retried on the manager tick (no new generation needed).
TEST(MembershipSlots, NodeLeftOutByAFailingMakeSpecIsRetried) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  r.spec_fail = true;
  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  EXPECT_LT(r.cl->slot_of(4), 0);
  r.spec_fail = false;
  ASSERT_TRUE(until([&] { return r.cl->slot_of(4) >= 0; })) << "retried without a new bundle";
  ASSERT_TRUE(until([&] { return r.cl->wire_port(static_cast<std::size_t>(r.cl->slot_of(4))) != nullptr; }));
}

// Y11 (real threads): keepalive threads on; add, retire and re-add (a new incarnation of the same node) under traffic.
TEST(MembershipSlots, RealSlotThreadsAddRetireReAddUnderTraffic) {
  // connect_wait_ms counts sim time, which the four traffic threads drive fast, while the added node is built by its
  // real-time slot thread: a 2 s wait could end before the node is Up on an optimised build (published anyway -> its
  // stores Refused). The wait ends as soon as the node is Up, so a long one costs nothing.
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, /*wait_ms=*/600000, {}, /*keepalive_ms=*/3);
  ASSERT_TRUE(r.cl);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) {
    const auto base = tr.ops.load();
    EXPECT_TRUE(until([&] { return tr.ops.load() > base + n; }));
  };
  settle(20);
  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  settle(20);
  r.cl->apply_membership(make_snap(3, 3, {{1, 1}, {3, 1}, {4, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 3; }));
  ASSERT_TRUE(until([&] { return r.cl->slot_of(2) < 0; }));
  settle(20);
  r.cl->apply_membership(make_snap(4, 4, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));  // node 2 again
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 4; }));
  ASSERT_GE(r.cl->slot_of(2), 0);
  ASSERT_TRUE(until([&] { return r.cl->wire_port(static_cast<std::size_t>(r.cl->slot_of(2))) != nullptr; }));
  settle(20);
  tr.finish();
  EXPECT_EQ(o.failed(), 0u) << o.report();
}

// Run #200 regression (the wrong_bytes_unknown of RealSlotThreadsAddRetireReAddUnderTraffic): a store whose deadline
// passes while its PUT_COMMIT is out ends Timeout/Aborted, yet the node may have committed it. A later fetch then hits
// exactly the bytes put under that key: the product promise (those bytes or a miss) holds, and the oracle must count
// the store's own failure only, never a "wrong bytes" Hit. Deterministic: the shim drops every PUT_DONE.
TEST(MembershipSlots, AStoreThatTimesOutMayStillHaveCommitted) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, /*shim=*/true);
  ASSERT_TRUE(r.cl);
  EXPECT_EQ(r.cl->dyn()->put_max_ms, 600000u) << "the rig's stores keep their own deadlines";
  for (auto& st : r.w.stamps) st.drop_put_done = true;
  Oracle o(OracleMode::Strict);
  const int scope = 3;
  const std::string key = "k3_7";
  Chain ch(key);
  auto sk = scope_keys(scope);
  Bytes data = payload(scope, 7);
  std::vector<BufRef> pb{{std::span<std::byte>(data)}};
  o.begin_store(key, 7);
  auto sc = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(5)));
  ASSERT_TRUE(sc);
  const KeyStatus st = sc->status.at(0);
  EXPECT_TRUE(st == KeyStatus::Timeout || st == KeyStatus::Aborted) << to_string(st);
  o.end_store(key, 7, st == KeyStatus::Committed);
  o.on_store(key, st);
  unsigned dropped = 0;
  for (auto& s : r.w.stamps) dropped += s.put_done_dropped.load();
  EXPECT_GE(dropped, 1u) << "the node answered the commit";
  for (auto& s : r.w.stamps) s.drop_put_done = false;
  Bytes out(kPayload, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  auto fc = r.wt->wait(r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, seconds(60)));
  ASSERT_TRUE(fc);
  EXPECT_EQ(fc->status.at(0), KeyStatus::Hit) << "the node committed the store the client timed out";
  EXPECT_EQ(decode(scope, out), std::optional<std::uint64_t>(7)) << "exactly the bytes put under the key";
  o.on_fetch(key, fc->status.at(0), fc->status.at(0) == KeyStatus::Hit ? decode(scope, out) : std::nullopt);
  EXPECT_EQ(o.failed(), 1u) << o.report();  // the store's own Timeout/Aborted, nothing else
  EXPECT_EQ(o.reason_count("wrong_bytes_unknown"), 0u) << o.report();
}

// Y11: the servers run in bundle mode (MB3b apply_bundle). The push delivers a verifiable envelope; the added node has
// applied it before the client's first connection to it.
TEST(MembershipSlots, AddedBundleModeServerHasTheEnvelopeBeforeTheFirstConnect) {
  Rig r(signed_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, /*bundle_servers=*/true);
  ASSERT_TRUE(r.cl);
  {
    std::lock_guard sl(r.w.srv_mu);
    EXPECT_EQ(r.w.srv[3]->applied_bundle().generation, 0u) << "node 4 has no bundle yet";
  }
  r.publish(signed_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  {
    std::lock_guard lk(r.pm);
    ASSERT_EQ(r.applied_at_push.count(4), 1u);
    EXPECT_EQ(r.applied_at_push[4], 2u);
    // MB6b: nodes 1-3 lag (generation 1) and may be pushed too; the added node's first push came before its connect.
    ASSERT_EQ(r.first_push_connected.count(4), 1u);
    EXPECT_FALSE(r.first_push_connected[4]);
  }
  {
    std::lock_guard sl(r.w.srv_mu);
    EXPECT_EQ(r.w.srv[3]->bundle_view()->body.epoch, 2u);
  }
  Oracle o(OracleMode::Strict);
  for (int s = 0; s < 8; ++s) cycle(r, o, s, 1);
  for (int s = 0; s < 8; ++s) cycle(r, o, s, 2);
  EXPECT_EQ(o.failed(), 0u) << o.report();
}

// The value of the first series `name{...}` whose line contains every one of `parts` (nullopt: none).
std::optional<long long> series(const std::string& text, const std::string& name, std::initializer_list<std::string> parts) {
  std::size_t pos = 0;
  while (pos < text.size()) {
    std::size_t end = text.find('\n', pos);
    if (end == std::string::npos) end = text.size();
    const std::string line = text.substr(pos, end - pos);
    pos = end + 1;
    if (line.rfind(name + "{", 0) != 0) continue;
    bool all = true;
    for (const auto& p : parts) all = all && line.find(p) != std::string::npos;
    if (all) return std::stoll(line.substr(line.rfind(' ') + 1));
  }
  return std::nullopt;
}
std::size_t count_of(const std::string& text, const std::string& what) {
  std::size_t n = 0;
  for (std::size_t p = text.find(what); p != std::string::npos; p = text.find(what, p + 1)) ++n;
  return n;
}
// The log lines written while it lives (log::set_sink_fd to a temporary file).
struct LogCapture {
  LogCapture() : f(std::tmpfile()) {
    if (f) log::set_sink_fd(fileno(f));
  }
  ~LogCapture() {
    log::set_sink_fd(2);
    if (f) std::fclose(f);
  }
  std::string text() const {
    std::string s;
    if (!f) return s;
    char buf[4096];
    for (off_t off = 0;;) {
      const ssize_t k = pread(fileno(f), buf, sizeof buf, off);
      if (k <= 0) break;
      s.append(buf, static_cast<std::size_t>(k));
      off += k;
    }
    return s;
  }
  std::FILE* f;
};
// A scope whose owner in the view {1, 2, 3} (equal weights) is node `id`.
int scope_owned_by(unsigned id) {
  std::vector<PlaceNode> v{PlaceNode{"1"}, PlaceNode{"2"}, PlaceNode{"3"}};
  for (int s = 0; s < 256; ++s) {
    auto sk = scope_keys(s);
    if (place_owner(v, std::span<const std::uint8_t, 32>(sk.scopes[0].b)) == id - 1) return s;
  }
  return -1;
}

// Review w3b Z01: a production ticket source has no ticket until prepare() ran (draw() never touches the network). The
// open must prepare each node of the first bundle before its first build, or every initial build fails.
TEST(MembershipSlots, BundleOpenPreparesTicketsBeforeTheFirstBuild) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}}), 2, 2000, {}, 0, false, false, [](Client::NodeSpec& ns, const control::NodeView&) {
    auto ready = std::make_shared<std::atomic<bool>>(false);
    ns.wopts.tickets = [ready, inner = std::move(ns.wopts.tickets)](fabric::EpClass cls) -> Expected<proto::Ticket> {
      if (!ready->load()) return Error{ErrorCode::NotFound, "test: no cached ticket"};
      return inner(cls);
    };
    ns.wopts.prepare = [ready] { ready->store(true); };
  });
  ASSERT_TRUE(r.cl);
  for (unsigned id : {1u, 2u}) {
    const long s = r.cl->slot_of(id);
    ASSERT_GE(s, 0);
    EXPECT_NE(r.cl->wire_port(static_cast<std::size_t>(s)), nullptr) << "node " << id << " is up after the open";
  }
  Oracle o(OracleMode::Strict);
  for (int s = 0; s < 4; ++s) cycle(r, o, s, 1);
  EXPECT_EQ(o.failed(), 0u) << o.report();
}

// Review w3b Z04: the bundle is authoritative for the hostname: node_info carries it even while the node's own
// hostname source (the admin ticket answer) has nothing yet.
TEST(MembershipSlots, IdentitySeriesCarriesTheBundleHostname) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}}), 2, 2000, {}, 0, false, false, [](Client::NodeSpec& ns, const control::NodeView&) {
    ns.hostname = [] { return std::string(); };  // like the admin ticket source before its first answer
  });
  ASSERT_TRUE(r.cl);
  const std::string m = r.cl->metrics_text();
  for (unsigned id : {1u, 2u}) {
    const std::string n = std::to_string(id);
    EXPECT_EQ(series(m, "miracache_client_node_info", {"node_id=\"" + n + "\"", "hostname=\"host" + n + "\""}), 1) << m;
  }
}

// Review w3b Z02: after a rebuild (Y04) the old slot retires. Its address comes up inside the retire window (a held job
// pins the old snapshot): it must not run its first build, and once it is torn down the node's landing pool series reads
// the new slot's pool (asan: no read of a freed pool).
TEST(MembershipSlots, RetiringOldSlotRunsNoFirstBuildAndThePoolSeriesSurvivesItsTeardown) {
  auto old_up = std::make_shared<std::atomic<bool>>(false);
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, false,
        [old_up](Client::NodeSpec& ns, const control::NodeView& nv) {
          if (nv.admin != "10.0.0.2:9465") return;
          ns.wopts.tickets = [old_up, inner = std::move(ns.wopts.tickets)](fabric::EpClass cls) -> Expected<proto::Ticket> {
            if (!old_up->load()) return Error{ErrorCode::LinkDown, "test: the old address is down"};
            return inner(cls);
          };
        });
  ASSERT_TRUE(r.cl);
  const long old2 = r.cl->slot_of(2), slot1 = r.cl->slot_of(1);
  ASSERT_GE(old2, 0);
  ASSERT_GE(slot1, 0);
  ASSERT_EQ(r.cl->wire_port(static_cast<std::size_t>(old2)), nullptr) << "the old address is down at the open";
  // A job held on frozen node 1 keeps the generation-1 snapshot, which pins every slot it names (the old slot too).
  const int scope = scope_owned_by(1);
  ASSERT_GE(scope, 0);
  r.w.frozen[0] = true;
  Chain ch("held");
  auto sk = scope_keys(scope);
  Bytes out(kPayload);
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  Ticket held = r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, std::chrono::hours(100));
  ASSERT_TRUE(until([&] { return r.cl->slot_jobs_inside(static_cast<std::size_t>(slot1)) > 0; }));

  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}}, 1, {{2, "10.9.9.2:9465"}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  const long new2 = r.cl->slot_of(2);
  ASSERT_GE(new2, 0);
  ASSERT_NE(new2, old2);
  ASSERT_NE(r.cl->wire_port(static_cast<std::size_t>(new2)), nullptr);
  EXPECT_TRUE(r.cl->slot_retiring(static_cast<std::size_t>(old2))) << "pinned by the held job's snapshot";

  old_up->store(true);  // the old address comes up inside the retire window
  for (int k = 0; k < 400 && !r.cl->wire_port(static_cast<std::size_t>(old2)); ++k) r.cl->keepalive_tick();
  EXPECT_EQ(r.cl->wire_port(static_cast<std::size_t>(old2)), nullptr) << "a retiring slot runs no first build";

  r.cl->cancel(held);
  r.w.frozen[0] = false;  // the server answers: the cancelled job leaves (a cancel does not cut a wire wait short)
  ASSERT_TRUE(r.wt->wait(held));
  ASSERT_TRUE(until([&] { return r.cl->slots_in_use() == 3 && !r.cl->slot_retiring(static_cast<std::size_t>(old2)); }));
  const std::string m = r.cl->metrics_text();  // asan: reads only live pools
  const auto free2 = series(m, "miracache_client_landing_pool_bytes", {"state=\"free\"", "node=\"2\""});
  ASSERT_TRUE(free2) << m;
  EXPECT_GT(*free2, 0) << "the series reads the new slot's pool";
  Oracle o(OracleMode::Strict);
  for (int s = 0; s < 6; ++s) cycle(r, o, s, 1);
  EXPECT_EQ(o.failed(), 0u) << o.report();
}

// Review w3b Z05: after a rail change the old slot's identity series (old addr) goes to 0 at its teardown; the new
// slot's series is 1.
TEST(MembershipSlots, RailChangeQuietsTheOldIdentitySeries) {
  // The rail address changes to one the sim server cannot listen on: this test opts into the single-listener wildcard.
  struct Reset { Reset() { World::single_listener_any_address = true; } ~Reset() { World::single_listener_any_address = false; } } reset;
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, false, [](Client::NodeSpec& ns, const control::NodeView& nv) {
    const std::string& a = nv.rails.at(0).addr;  // the label addr follows the bundle (the sim routes by node ID)
    ns.wopts.rail.host = a.substr(0, a.rfind(':'));
    ns.wopts.rail.port = static_cast<std::uint16_t>(std::stoul(a.substr(a.rfind(':') + 1)));
  });
  ASSERT_TRUE(r.cl);
  const long old2 = r.cl->slot_of(2);
  ASSERT_GE(old2, 0);
  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}}, 1, {}, {{2, "10.9.9.2:7471"}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  ASSERT_NE(r.cl->slot_of(2), old2);
  ASSERT_TRUE(until([&] { return r.cl->slots_in_use() == 3 && !r.cl->slot_retiring(static_cast<std::size_t>(old2)); }));
  const std::string m = r.cl->metrics_text();
  EXPECT_EQ(series(m, "miracache_client_node_info", {"node_id=\"2\"", "addr=\"10.0.0.2:7471\""}), 0) << m;
  EXPECT_EQ(series(m, "miracache_client_node_info", {"node_id=\"2\"", "addr=\"10.9.9.2:7471\""}), 1) << m;
  EXPECT_GT(series(m, "miracache_client_landing_pool_bytes", {"state=\"free\"", "node=\"2\""}).value_or(0), 0) << m;
}

// Review w3b Z06: a node whose make_spec keeps failing is retried with exponential backoff (not every 200 ms), its error
// is logged once (on change), and the generation that left it out still logs "membership applied".
TEST(MembershipSlots, PendingNodeBacksOffAndLogsOnlyOnChange) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  std::string logs;
  int calls = 0;
  {
    LogCapture lc;
    r.spec_fail = true;
    const int before = r.spec_calls.load();
    r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
    ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
    std::this_thread::sleep_for(milliseconds(3000));
    calls = r.spec_calls.load() - before;
    logs = lc.text();
  }
  EXPECT_GE(calls, 2) << "retried without a new bundle";
  EXPECT_LE(calls, 6) << "backoff 200, 400, 800, 1600 ms: at most ~5 attempts in 3 s (a fixed 200 ms retry makes ~15)";
  EXPECT_EQ(count_of(logs, "cannot set up a bundle node"), 1u) << logs;
  bool applied2 = false;
  for (std::size_t p = logs.find("membership applied"); p != std::string::npos; p = logs.find("membership applied", p + 1)) {
    const std::size_t e = logs.find('\n', p);
    applied2 = applied2 || logs.substr(p, e - p).find("generation=2") != std::string::npos;
  }
  EXPECT_TRUE(applied2) << "a generation that leaves a node out is still logged as applied\n" << logs;
  r.spec_fail = false;
  ASSERT_TRUE(until([&] { return r.cl->slot_of(4) >= 0; }));
  ASSERT_TRUE(until([&] { return r.cl->wire_port(static_cast<std::size_t>(r.cl->slot_of(4))) != nullptr; }));
}

// ---- MB6b: epoch stamping and stale-epoch handling (the shim above plays MB4's server rules) ----

// One store of a fresh key into `scope`; the status of the only key.
KeyStatus put_one(Rig& r, int scope, const std::string& key, std::uint64_t v = 1) {
  Chain ch(key);
  auto sk = scope_keys(scope);
  Bytes data = payload(scope, v);
  std::vector<BufRef> pb{{std::span<std::byte>(data)}};
  auto sc = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(60)));
  return sc ? sc->status.at(0) : KeyStatus::Timeout;
}

std::uint64_t series_value(const std::string& text, const std::string& series) {
  const auto p = text.find(series + " ");
  if (p == std::string::npos) return 0;
  return std::stoull(text.substr(p + series.size() + 1));
}
std::uint64_t skipped(Rig& r, const char* reason) {
  return series_value(r.cl->metrics_text(), std::string("miracache_client_put_skipped_total{reason=\"") + reason + "\"}");
}

// ---- Q6: a LOCAL device resource failure (siw0 at its CQ limit on the 4th node) ----

// The log lines of `logs` that contain `what`.
std::vector<std::string> lines_with(const std::string& logs, const std::string& what) {
  std::vector<std::string> out;
  for (std::size_t p = logs.find(what); p != std::string::npos; p = logs.find(what, p + 1)) {
    const std::size_t b = logs.rfind('\n', p);
    const std::size_t e = logs.find('\n', p);
    out.push_back(logs.substr(b == std::string::npos ? 0 : b + 1, (e == std::string::npos ? logs.size() : e) - (b == std::string::npos ? 0 : b + 1)));
  }
  return out;
}
// A scope whose owner in the view {1, 2, 3, 4} (equal weights) is node `id`.
int scope_owned_by4(unsigned id) {
  std::vector<PlaceNode> v{PlaceNode{"1"}, PlaceNode{"2"}, PlaceNode{"3"}, PlaceNode{"4"}};
  for (int s = 0; s < 256; ++s) {
    auto sk = scope_keys(s);
    if (place_owner(v, std::span<const std::uint8_t, 32>(sk.scopes[0].b)) == id - 1) return s;
  }
  return -1;
}
constexpr const char* kLocalLine = "the LOCAL RDMA device refused a resource";
constexpr const char* kRecovered = "memory-node endpoint build recovered";

// The node's client device refuses its endpoint (the sim fault hook: connect fails as ibv_create_cq with ENOMEM would,
// before any remote contact). One clear line (call, errno, hint, node ID + hostname + addr, rail, device), a counter
// per attempt, the node stays pending (no wire) with the build backoff while the other nodes serve; once the fault
// clears the node comes up and logs one recovery line.
TEST(MembershipSlots, LocalDeviceResourceFailureIsLoggedOnceCountedAndRecovers) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, /*wait_ms=*/300);
  ASSERT_TRUE(r.cl);
  fabric::SimFabric& dev4 = *r.w.cfab[3];
  std::string logs;
  long s4 = -1;
  std::uint64_t attempts = 0;
  {
    LogCapture lc;
    dev4.inject_local_failure("ibv_create_cq", ENOMEM);
    r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
    ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
    s4 = r.cl->slot_of(4);
    ASSERT_GE(s4, 0);
    for (int k = 0; k < 2000 && dev4.local_failures() < 3; ++k) {
      r.w.clock.advance_by(milliseconds(10));
      r.cl->keepalive_tick();
    }
    attempts = dev4.local_failures();
    ASSERT_GE(attempts, 3u) << "retried with the build backoff";
    EXPECT_EQ(r.cl->wire_port(static_cast<std::size_t>(s4)), nullptr) << "pending while its device refuses";
    const std::string m = r.cl->metrics_text();
    EXPECT_EQ(series(m, "miracache_client_endpoint_build_failures_total",
                     {"node_id=\"4\"", "hostname=\"host4\"", "addr=\"sim:7004\"", "rail=\"0\"", "cause=\"local_resource\""}),
              static_cast<long long>(attempts))
        << m;
    EXPECT_FALSE(series(m, "miracache_client_endpoint_build_failures_total", {"node_id=\"1\""}).has_value()) << m;
    // The other nodes serve.
    for (unsigned id = 1; id <= 3; ++id) {
      const int s = scope_owned_by4(id);
      ASSERT_GE(s, 0);
      EXPECT_EQ(put_one(r, s, "q6-" + std::to_string(id)), KeyStatus::Committed) << "node " << id;
    }
    logs = lc.text();
  }
  const auto ln = lines_with(logs, kLocalLine);
  ASSERT_EQ(ln.size(), 1u) << "logged once, not per attempt\n" << logs;
  for (const char* f : {"level=error", "node_id=4", "hostname=host4", "addr=sim:7004", "rail=0", "device=sim",
                        "cause=local_resource", "call=ibv_create_cq", "errno=\"ENOMEM", "hint=\"local RDMA device resource limit"})
    EXPECT_NE(ln[0].find(f), std::string::npos) << f << "\n" << ln[0];
  EXPECT_EQ(count_of(logs, kRecovered), 0u);
  // The fault clears: the node comes up and logs one recovery line; the counter stops.
  {
    LogCapture lc;
    dev4.inject_local_failure(nullptr);
    // The other nodes keep the sim network busy (a drive steps it without moving the clock): move time by hand past the
    // build backoff (5 s at most).
    for (int k = 0; k < 2000 && !r.cl->wire_port(static_cast<std::size_t>(s4)); ++k) {
      r.w.clock.advance_by(milliseconds(10));
      r.cl->keepalive_tick();
    }
    ASSERT_NE(r.cl->wire_port(static_cast<std::size_t>(s4)), nullptr) << lc.text();
    for (int k = 0; k < 20; ++k) r.cl->keepalive_tick();
    logs = lc.text();
  }
  const auto rec = lines_with(logs, kRecovered);
  ASSERT_EQ(rec.size(), 1u) << logs;
  for (const char* f : {"node_id=4", "hostname=host4", "addr=sim:7004", "failed_before=local_resource@rail0"})
    EXPECT_NE(rec[0].find(f), std::string::npos) << f << "\n" << rec[0];
  EXPECT_EQ(count_of(logs, kLocalLine), 0u);
  EXPECT_EQ(dev4.local_failures(), attempts);
  EXPECT_EQ(put_one(r, scope_owned_by4(4), "q6-4"), KeyStatus::Committed);
}

// The siw0 case as it happens in production: the node's fabric open (make_spec) fails at the local ibv_create_cq, so
// the bundle node stays pending (no slot) with its set-up backoff. The Q6 line replaces the generic pending line.
TEST(MembershipSlots, LocalDeviceLimitInNodeSetUpIsLoggedOnceAndRecovers) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  std::string logs;
  int calls = 0;
  {
    LogCapture lc;
    r.spec_local_fail = true;
    const int before = r.spec_calls.load();
    r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
    ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
    ASSERT_TRUE(until([&] { return r.spec_calls.load() - before >= 3; }, milliseconds(10000)));
    calls = r.spec_calls.load() - before;
    EXPECT_LT(r.cl->slot_of(4), 0) << "pending";
    const std::string m = r.cl->metrics_text();
    const auto v = series(m, "miracache_client_endpoint_build_failures_total",
                          {"node_id=\"4\"", "hostname=\"host4\"", "addr=\"10.0.0.4:7471\"", "rail=\"0\"", "cause=\"local_resource\""});
    ASSERT_TRUE(v.has_value()) << m;
    EXPECT_GE(*v, calls - 1) << m;  // per attempt (the membership thread may be inside one more)
    EXPECT_LE(*v, calls) << m;
    logs = lc.text();
  }
  const auto ln = lines_with(logs, kLocalLine);
  ASSERT_EQ(ln.size(), 1u) << logs;
  for (const char* f : {"node_id=4", "hostname=host4", "addr=10.0.0.4:7471", "rail=0", "device=siw0", "call=ibv_create_cq",
                        "errno=\"ENOMEM", "hint="})
    EXPECT_NE(ln[0].find(f), std::string::npos) << f << "\n" << ln[0];
  EXPECT_EQ(count_of(logs, "cannot set up a bundle node"), 0u) << "one line, not two\n" << logs;
  {
    LogCapture lc;
    r.spec_local_fail = false;
    ASSERT_TRUE(until([&] { return r.cl->slot_of(4) >= 0; }));
    ASSERT_TRUE(until([&] { return r.cl->wire_port(static_cast<std::size_t>(r.cl->slot_of(4))) != nullptr; }));
    ASSERT_TRUE(until([&] { return count_of(lc.text(), kRecovered) >= 1; }));
    logs = lc.text();
  }
  EXPECT_EQ(count_of(logs, kRecovered), 1u) << logs;
  EXPECT_NE(lines_with(logs, kRecovered).at(0).find("failed_before=local_resource@rail0"), std::string::npos) << logs;
}
std::size_t pushes_to(Rig& r, unsigned id) {
  std::lock_guard lk(r.pm);
  return static_cast<std::size_t>(std::count(r.pushes.begin(), r.pushes.end(), "10.0.0." + std::to_string(id) + ":9465"));
}

TEST(MembershipEpoch, FramesCarryTheClientsEpochAndGeneration) {
  Rig r(make_snap(7, 3, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, /*shim=*/true);
  ASSERT_TRUE(r.cl);
  // The shim nodes run exactly the client's (epoch 3, generation 7): a put passes through and commits.
  EXPECT_EQ(put_one(r, 0, "stamped-0"), KeyStatus::Committed);
  EXPECT_EQ(r.w.stamps[0].stale_replies + r.w.stamps[1].stale_replies + r.w.stamps[2].stale_replies, 0u);
  EXPECT_GE(r.w.stamps[0].put_begins_passed + r.w.stamps[1].put_begins_passed + r.w.stamps[2].put_begins_passed, 1u);
  // A node one epoch ahead refuses a put stamped with ours.
  for (auto& s : r.w.stamps) s.set(4, 8);
  KeyStatus st = KeyStatus::Committed;
  for (int s = 0; s < 6 && st != KeyStatus::Skipped; ++s) st = put_one(r, s, "stamped-1-" + std::to_string(s));
  EXPECT_EQ(st, KeyStatus::Skipped);
  EXPECT_GE(r.w.stamps[0].stale_replies + r.w.stamps[1].stale_replies + r.w.stamps[2].stale_replies, 1u);
}

// Decision 8, "the node lags": the client moved to epoch 2; the nodes are still on epoch 1 and answer StaleEpoch. The put is
// Skipped (not failed, no retry), the client pushes its envelope to that node ONCE, and the node accepts afterwards.
TEST(MembershipEpoch, StaleEpochSkipsAndPushesTheLaggingNodeOnce) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, /*shim=*/true);
  ASSERT_TRUE(r.cl);
  r.publish(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  EXPECT_EQ(put_one(r, 0, "lag-first"), KeyStatus::Skipped) << "StaleEpoch is a skip, not a failure";
  EXPECT_GE(skipped(r, "stale_epoch"), 1u);
  EXPECT_EQ(skipped(r, "draining"), 0u);
  // The push comes from the pusher thread; afterwards every node that was pushed accepts roots at epoch 2.
  ASSERT_TRUE(until([&] { return pushes_to(r, 1) + pushes_to(r, 2) + pushes_to(r, 3) >= 1; }));
  int committed = 0;
  for (int s = 0; s < 40 && committed < 6; ++s) {
    const KeyStatus st = put_one(r, s, "lag-" + std::to_string(s));
    EXPECT_TRUE(st == KeyStatus::Skipped || st == KeyStatus::Committed) << "scope " << s;
    committed += st == KeyStatus::Committed;
    std::this_thread::sleep_for(milliseconds(20));
  }
  EXPECT_GE(committed, 1) << "a node that got the envelope accepts roots again";
  for (int s = 0; s < 40; ++s) (void)put_one(r, s, "again-" + std::to_string(s));
  for (unsigned id = 1; id <= 3; ++id) EXPECT_LE(pushes_to(r, id), 1u) << "once per success per (node, generation): node " << id;
  std::lock_guard lk(r.wm);
  EXPECT_TRUE(r.wakes.empty()) << "the client is not behind";
}

// Decision 8 / Q11: a reply whose bundle_gen_lo is below the client's triggers the push too, with equal epochs (no StaleEpoch).
TEST(MembershipEpoch, LowerReplyGenerationTriggersTheSamePush) {
  Rig r(make_snap(5, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, /*shim=*/true);
  ASSERT_TRUE(r.cl);
  r.w.stamps[1].set(1, 4);  // node 2: same epoch, one generation behind
  Oracle o(OracleMode::Strict);
  for (int s = 0; s < 30 && pushes_to(r, 2) == 0; ++s) cycle(r, o, s, 1);
  ASSERT_TRUE(until([&] { return pushes_to(r, 2) >= 1; })) << "no scope reached node 2?";
  ASSERT_TRUE(until([&] { return r.w.stamps[1].gen_lo.load() == 5; }));
  for (int v = 2; v < 6; ++v)
    for (int s = 0; s < 30; ++s) cycle(r, o, s, v);
  EXPECT_EQ(pushes_to(r, 2), 1u);
  EXPECT_EQ(pushes_to(r, 1) + pushes_to(r, 3), 0u);
  EXPECT_EQ(r.w.stamps[1].stale_replies.load(), 0u) << "equal epochs: no StaleEpoch involved";
  EXPECT_EQ(o.failed(), 0u) << o.report();
}

// Decision 8, "the client lags": a node on a higher epoch answers StaleEpoch (and carries a higher bundle_gen_lo). The put is
// Skipped, the watcher is woken with the replying node's admin address, and the client pushes nothing.
TEST(MembershipEpoch, ClientBehindWakesTheFetchFromTheReplyingNode) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, /*shim=*/true);
  ASSERT_TRUE(r.cl);
  r.w.stamps[0].set(2, 2);
  bool skipped_one = false;
  for (int s = 0; s < 30; ++s) {
    const KeyStatus st = put_one(r, s, "behind-" + std::to_string(s));
    EXPECT_TRUE(st == KeyStatus::Skipped || st == KeyStatus::Committed);
    skipped_one = skipped_one || st == KeyStatus::Skipped;
  }
  EXPECT_TRUE(skipped_one);
  EXPECT_GE(skipped(r, "stale_epoch"), 1u);
  {
    std::lock_guard lk(r.wm);
    ASSERT_FALSE(r.wakes.empty());
    for (const auto& [lo, admin] : r.wakes) {
      EXPECT_EQ(lo, 2u);
      EXPECT_EQ(admin, "10.0.0.1:9465") << "the fetch goes to the node that replied";
    }
  }
  std::lock_guard lk(r.pm);
  EXPECT_TRUE(r.pushes.empty());
}

// A failing push backs off (1 s, 2 s, 4 s ...): no storm. When the admin comes back the push succeeds.
TEST(MembershipEpoch, FailingPushBacksOffThenSucceeds) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, /*shim=*/true);
  ASSERT_TRUE(r.cl);
  r.fail_pushes = 1000000;
  r.publish(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
  const auto end = std::chrono::steady_clock::now() + milliseconds(2500);
  for (int s = 0; std::chrono::steady_clock::now() < end; ++s) {
    const KeyStatus st = put_one(r, s % 30, "storm-" + std::to_string(s));
    EXPECT_EQ(st, KeyStatus::Skipped);
  }
  for (unsigned id = 1; id <= 3; ++id) EXPECT_LE(pushes_to(r, id), 3u) << "backoff 1 s, 2 s, ...: node " << id;
  EXPECT_GE(pushes_to(r, 1) + pushes_to(r, 2) + pushes_to(r, 3), 1u);
  { std::lock_guard lk(r.pm); r.fail_pushes = 0; }
  bool ok = false;
  for (int s = 0; s < 400 && !ok; ++s) {
    ok = put_one(r, s % 30, "heal-" + std::to_string(s)) == KeyStatus::Committed;
    if (!ok) std::this_thread::sleep_for(milliseconds(50));
  }
  EXPECT_TRUE(ok) << "after the admin recovers the push lands and roots are accepted";
}

// Draining (member state, not the session latch) refuses roots: Skipped, reason "draining"; the session stays up.
TEST(MembershipEpoch, DrainingIsSkippedAndTheSessionStaysUp) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, /*shim=*/true);
  ASSERT_TRUE(r.cl);
  r.w.stamps[0].draining = true;
  Oracle o(OracleMode::Strict);
  for (int v = 1; v <= 3; ++v)
    for (int s = 0; s < 12; ++s) cycle(r, o, s, v);
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GE(skipped(r, "draining"), 1u);
  EXPECT_EQ(skipped(r, "stale_epoch"), 0u);
  const long slot = r.cl->slot_of(1);
  ASSERT_GE(slot, 0);
  ASSERT_NE(r.cl->wire_port(static_cast<std::size_t>(slot)), nullptr);
  EXPECT_TRUE(r.cl->wire_port(static_cast<std::size_t>(slot))->session_up()) << "reads and continuations keep working";
  EXPECT_FALSE(r.cl->wire_port(static_cast<std::size_t>(slot))->goaway_received());
}

// The strict oracle over epoch changes under 4-thread traffic: every put is Committed or Skipped, never failed; every node ends
// up with the client's envelope through the client's own pushes.
TEST(MembershipEpoch, EpochChangesUnderTrafficFailNothing) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, /*shim=*/true);
  ASSERT_TRUE(r.cl);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) {
    const auto base = tr.ops.load();
    EXPECT_TRUE(until([&] { return tr.ops.load() > base + n; }));
  };
  settle(20);
  for (std::uint32_t e = 2; e <= 3; ++e) {
    r.publish(make_snap(e, e, {{1, 1}, {2, 1}, {3, 1}}));
    ASSERT_TRUE(until([&] { return r.cl->membership_epoch() == e; }));
    ASSERT_TRUE(until([&] {
      return r.w.stamps[0].epoch.load() == e && r.w.stamps[1].epoch.load() == e && r.w.stamps[2].epoch.load() == e;
    })) << "the client pushes its envelope to every lagging node, epoch " << e;
    settle(30);
  }
  tr.finish();
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Committed), 0u) << o.report();
  // (Whether a put met a stale node first is a race: a lookup reply can reveal the lag and start the push before.)
  for (unsigned id = 1; id <= 3; ++id) EXPECT_LE(pushes_to(r, id), 2u) << "one push per generation: node " << id;
}

// ---- MB7: previous view, hints, client reports ----

// The owner set (node IDs, best first) of `scope` in a view of `ids` with R replicas.
std::vector<unsigned> owners_in(int scope, const std::vector<unsigned>& ids, unsigned R = 1) {
  View v;
  v.epoch = 1;
  for (unsigned id : ids) v.nodes.push_back(PlaceNode{std::to_string(id), 1, ""});
  auto sk = scope_keys(scope);
  std::vector<unsigned> out;
  for (std::size_t k : owner_set(v, std::span<const std::uint8_t, 32>(sk.scopes[0].b), R)) out.push_back(static_cast<unsigned>(std::stoul(v.nodes[k].id)));
  return out;
}

// Scopes whose owner (R = 1) differs between the two views (`moved`) and scopes whose owner is the same (`stable`).
struct Split {
  std::vector<int> moved, stable;
};
Split split_scopes(const std::vector<unsigned>& before, const std::vector<unsigned>& after, std::size_t nmoved = 6, std::size_t nstable = 4) {
  Split s;
  for (int sc = 0; sc < 256 && (s.moved.size() < nmoved || s.stable.size() < nstable); ++sc) {
    const bool same = owners_in(sc, before)[0] == owners_in(sc, after)[0];
    if (same && s.stable.size() < nstable) s.stable.push_back(sc);
    if (!same && s.moved.size() < nmoved) s.moved.push_back(sc);
  }
  return s;
}

// One fetch of `key` (version v) in `scope`; the status of the only key, and whether the bytes are exactly that version.
KeyStatus get_one(Rig& r, int scope, const std::string& key, std::uint64_t v = 1) {
  Chain ch(key);
  auto sk = scope_keys(scope);
  Bytes out(kPayload, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  auto fc = r.wt->wait(r.cl->fetch(sk, 0, std::span<const KeyRef>(&ch.ref, 1), fb, seconds(60)));
  if (!fc) return KeyStatus::Timeout;
  const KeyStatus s = fc->status.at(0);
  if (s == KeyStatus::Hit) EXPECT_EQ(out, payload(scope, v)) << key;
  return s;
}

// A continuation store: `name` at chain position `pos` under `parent`.
KeyStatus put_cont(Rig& r, int scope, const std::string& name, const std::string& parent, std::uint64_t pos, std::uint64_t v = 1) {
  Bytes raw(reinterpret_cast<const std::byte*>(name.data()), reinterpret_cast<const std::byte*>(name.data()) + name.size());
  Bytes praw(reinterpret_cast<const std::byte*>(parent.data()), reinterpret_cast<const std::byte*>(parent.data()) + parent.size());
  KeyRef ref;
  ref.raw = raw;
  ref.parent_raw = praw;
  ref.chain_pos = pos;
  auto sk = scope_keys(scope);
  Bytes data = payload(scope, v);
  std::vector<BufRef> pb{{std::span<std::byte>(data)}};
  auto sc = r.wt->wait(r.cl->store(sk, 0, std::span<const KeyRef>(&ref, 1), pb, seconds(60)));
  return sc ? sc->status.at(0) : KeyStatus::Timeout;
}

std::uint64_t hint_event(Rig& r, const char* ev) {
  return series_value(r.cl->metrics_text(), std::string("miracache_client_hint_total{event=\"") + ev + "\"}");
}
std::uint64_t prev_hits(Rig& r) { return series_value(r.cl->metrics_text(), "\nmiracache_client_previous_view_read_hit_total"); }
std::uint64_t prev_stores(Rig& r) { return series_value(r.cl->metrics_text(), "\nmiracache_client_previous_view_store_total"); }

// Epoch 1 on nodes 1-3 holds the data; epoch 2 adds node 4 (previous view = nodes 1-3). Returns the scopes that moved.
struct JoinedRig {
  explicit JoinedRig(unsigned R_ = 1, std::function<void(Client::BundleOpen&)> bo = {})
      : R(R_), r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}, R_), 2, 2000, {}, 0, false, false, {}, std::move(bo)) {}
  void store_all() {
    ASSERT_TRUE(r.cl);
    sp = split_scopes({1, 2, 3}, {1, 2, 3, 4});
    for (int s : sp.moved) ASSERT_EQ(put_one(r, s, "a" + std::to_string(s)), KeyStatus::Committed);
    for (int s : sp.stable) ASSERT_EQ(put_one(r, s, "a" + std::to_string(s)), KeyStatus::Committed);
    ASSERT_TRUE(until([&] { return r.cl->replicator_pending() == 0; }));
  }
  void join(bool with_previous = true) {
    r.publish(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}, R, {}, {}, with_previous ? std::vector<std::pair<unsigned, unsigned>>{{1, 1}, {2, 1}, {3, 1}} : std::vector<std::pair<unsigned, unsigned>>{}));
    ASSERT_TRUE(until([&] { return r.cl->membership_epoch() == 2; }));
    ASSERT_TRUE(until([&] { return r.cl->slot_of(4) >= 0 && r.cl->wire_port(static_cast<std::size_t>(r.cl->slot_of(4))) != nullptr; }));
  }
  unsigned R;
  Rig r;
  Split sp;
};

TEST(MembershipPrevious, ReadsAfterAnEpochChangeHitOldDataThroughThePreviousView) {
  JoinedRig j;
  j.store_all();
  j.join();
  auto& r = j.r;
  for (int s : j.sp.stable) EXPECT_EQ(get_one(r, s, "a" + std::to_string(s)), KeyStatus::Hit) << "scope " << s;
  EXPECT_EQ(r.cl->hint_count(), 0u) << "the current owner holds these: no hint";
  ASSERT_GE(j.sp.moved.size(), 3u);
  for (int s : j.sp.moved) EXPECT_EQ(get_one(r, s, "a" + std::to_string(s)), KeyStatus::Hit) << "scope " << s;
  EXPECT_EQ(r.cl->hint_count(), j.sp.moved.size()) << "a hit on the previous set sets the hint";
  EXPECT_EQ(prev_hits(r), j.sp.moved.size());
  EXPECT_EQ(hint_event(r, "set"), j.sp.moved.size());
  for (int s : j.sp.moved) EXPECT_EQ(get_one(r, s, "a" + std::to_string(s)), KeyStatus::Hit) << "hinted read, scope " << s;
  EXPECT_EQ(prev_hits(r), 2 * j.sp.moved.size());
  EXPECT_EQ(r.cl->hint_count(), j.sp.moved.size());
}

TEST(MembershipPrevious, WithoutAPreviousViewTheMovedDataMisses) {
  JoinedRig j;
  j.store_all();
  j.join(/*with_previous=*/false);
  for (int s : j.sp.moved) EXPECT_EQ(get_one(j.r, s, "a" + std::to_string(s)), KeyStatus::Miss) << "scope " << s;
  EXPECT_EQ(j.r.cl->hint_count(), 0u);
}

TEST(MembershipPrevious, HintDropsOnAKeys0MissAndFallsThroughInTheSameJobAndOnARootStore) {
  JoinedRig j;
  j.store_all();
  j.join();
  auto& r = j.r;
  const int s = j.sp.moved.at(0);
  const std::string a = "a" + std::to_string(s), n = "n" + std::to_string(s);
  ASSERT_EQ(get_one(r, s, a), KeyStatus::Hit);
  ASSERT_EQ(r.cl->hint_count(), 1u);
  // A root store drops the hint; the batch goes to the current owner (node 4).
  ASSERT_EQ(put_one(r, s, n), KeyStatus::Committed);
  EXPECT_EQ(r.cl->hint_count(), 0u);
  EXPECT_EQ(hint_event(r, "drop_root"), 1u);
  // Hint again, then read the key that lives only at the current set: keys[0] misses at the hinted previous set, the hint
  // is dropped and the SAME job finds it at the current set.
  ASSERT_EQ(get_one(r, s, a), KeyStatus::Hit);
  ASSERT_EQ(r.cl->hint_count(), 1u);
  EXPECT_EQ(get_one(r, s, n), KeyStatus::Hit);
  EXPECT_EQ(r.cl->hint_count(), 0u);
  EXPECT_EQ(hint_event(r, "drop_miss"), 1u);
  // A key stored nowhere: the hinted read misses, drops the hint, falls through and misses again (no error status).
  ASSERT_EQ(get_one(r, s, a), KeyStatus::Hit);
  EXPECT_EQ(get_one(r, s, "never" + std::to_string(s)), KeyStatus::Miss);
  EXPECT_EQ(r.cl->hint_count(), 0u);
  EXPECT_EQ(hint_event(r, "drop_miss"), 2u);
}

TEST(MembershipPrevious, ContinuationRefusedAtTheCurrentSetFallsThroughToThePreviousSet) {
  JoinedRig j;
  j.store_all();
  j.join();
  auto& r = j.r;
  const int s = j.sp.moved.at(0);
  const std::string a = "a" + std::to_string(s);
  // No hint: the current owner (node 4) does not know the parent -> Refused there -> the previous set takes it, same job.
  EXPECT_EQ(put_cont(r, s, a + ".1", a, 1), KeyStatus::Committed);
  EXPECT_EQ(prev_stores(r), 1u);
  EXPECT_EQ(r.cl->hint_count(), 1u) << "a continuation that landed on the previous set sets the hint";
  // Hinted: the next continuation goes straight to the previous set.
  EXPECT_EQ(put_cont(r, s, a + ".2", a + ".1", 2), KeyStatus::Committed);
  EXPECT_EQ(prev_stores(r), 1u);
  // The whole chain reads back from the previous set.
  Chain c0(a);
  Bytes raw1(a.size() + 2), raw2(a.size() + 2);
  std::memcpy(raw1.data(), (a + ".1").data(), a.size() + 2);
  std::memcpy(raw2.data(), (a + ".2").data(), a.size() + 2);
  KeyRef k[3] = {c0.ref, {raw1, c0.raw, 1}, {raw2, raw1, 2}};
  auto sk = scope_keys(s);
  Bytes o0(kPayload), o1(kPayload), o2(kPayload);
  std::vector<BufRef> fb{{std::span<std::byte>(o0)}, {std::span<std::byte>(o1)}, {std::span<std::byte>(o2)}};
  auto fc = r.wt->wait(r.cl->fetch(sk, 0, std::span<const KeyRef>(k, 3), fb, seconds(60)));
  ASSERT_TRUE(fc);
  for (int i = 0; i < 3; ++i) EXPECT_EQ(fc->status.at(static_cast<std::size_t>(i)), KeyStatus::Hit) << i;
  // A root store re-roots the chain at the current set and drops the hint.
  EXPECT_EQ(put_one(r, s, "m" + std::to_string(s)), KeyStatus::Committed);
  EXPECT_EQ(r.cl->hint_count(), 0u);
}

TEST(MembershipPrevious, HintsAreVoidWhenThePreviousEpochChanges) {
  JoinedRig j;
  j.store_all();
  j.join();
  auto& r = j.r;
  for (int s : j.sp.moved) ASSERT_EQ(get_one(r, s, "a" + std::to_string(s)), KeyStatus::Hit);
  ASSERT_EQ(r.cl->hint_count(), j.sp.moved.size());
  // Two epochs on: the previous view is epoch 2's. The old owners are no longer reachable by the previous set.
  r.publish(make_snap(3, 3, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}, 1, {}, {}, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_epoch() == 3; }));
  EXPECT_EQ(r.cl->hint_count(), 0u) << "re-root after two epochs: every hint is void";
  for (int s : j.sp.moved) EXPECT_EQ(get_one(r, s, "a" + std::to_string(s)), KeyStatus::Miss) << "scope " << s;
}

// Q08 / P31 with R = 1: node 3 drains (still serves reads), then leaves `nodes` without an epoch bump. Hints that pointed at it
// are dropped at the retire; reads of its chains miss on the current set and the filtered previous set is empty (no error).
TEST(MembershipPrevious, DrainToRemovalWithR1MissesWithoutRefusedAndDropsTheHints) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  std::vector<int> own3;
  for (int s = 0; s < 256 && own3.size() < 6; ++s)
    if (owners_in(s, {1, 2, 3})[0] == 3) own3.push_back(s);
  ASSERT_EQ(own3.size(), 6u);
  for (int s : own3) ASSERT_EQ(put_one(r, s, "a" + std::to_string(s)), KeyStatus::Committed);
  r.publish(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}}, 1, {}, {}, {{1, 1}, {2, 1}, {3, 1}}, /*draining=*/{3}));
  ASSERT_TRUE(until([&] { return r.cl->membership_epoch() == 2; }));
  for (int s : own3) EXPECT_EQ(get_one(r, s, "a" + std::to_string(s)), KeyStatus::Hit) << "a draining node still serves reads, scope " << s;
  EXPECT_EQ(r.cl->hint_count(), own3.size());
  // Leave: absent from `nodes`, same epoch and the same previous view (it still lists node 3).
  r.publish(make_snap(3, 2, {{1, 1}, {2, 1}}, 1, {}, {}, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 3; }));
  ASSERT_TRUE(until([&] { return r.cl->slot_of(3) < 0; }));
  EXPECT_EQ(r.cl->hint_count(), 0u) << "retiring a node drops every hint";
  EXPECT_EQ(hint_event(r, "drop_retire"), own3.size());
  for (int s : own3) EXPECT_EQ(get_one(r, s, "a" + std::to_string(s)), KeyStatus::Miss) << "scope " << s;
  EXPECT_EQ(r.cl->hint_count(), 0u);
  // A chain whose parent lived on the removed node: the continuation is Refused (parent gone), exactly as the oracle says.
  EXPECT_EQ(put_cont(r, own3[0], "a" + std::to_string(own3[0]) + ".1", "a" + std::to_string(own3[0]), 1), KeyStatus::Refused);
}

// R = 2: a hinted continuation runs on BOTH replicas of the previous set (and not on the new node).
TEST(MembershipPrevious, R2HintedContinuationReachesBothPreviousReplicas) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}, 2));
  ASSERT_TRUE(r.cl);
  int s = -1;
  for (int sc = 0; sc < 512 && s < 0; ++sc)
    if (owners_in(sc, {1, 2, 3, 4}, 2)[0] == 4) s = sc;  // the new node is the primary: the current set misses first
  ASSERT_GE(s, 0);
  const auto prev = owners_in(s, {1, 2, 3}, 2);
  ASSERT_EQ(prev.size(), 2u);
  const std::string a = "a" + std::to_string(s);
  ASSERT_EQ(put_one(r, s, a), KeyStatus::Committed);
  ASSERT_TRUE(until([&] { return r.cl->replicator_pending() == 0; }));
  r.publish(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}, 2, {}, {}, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(until([&] { return r.cl->membership_epoch() == 2; }));
  ASSERT_TRUE(until([&] { return r.cl->slot_of(4) >= 0 && r.cl->wire_port(static_cast<std::size_t>(r.cl->slot_of(4))) != nullptr; }));
  ASSERT_EQ(get_one(r, s, a), KeyStatus::Hit);
  ASSERT_EQ(r.cl->hint_count(), 1u);
  auto committed = [&](unsigned id) {
    return series_value(r.cl->metrics_text(), "miracache_client_replica_legs_total{node=\"" + std::to_string(id) + "\",result=\"committed\"}");
  };
  std::map<unsigned, std::uint64_t> before;
  for (unsigned id = 1; id <= 4; ++id) before[id] = committed(id);
  ASSERT_EQ(put_cont(r, s, a + ".1", a, 1), KeyStatus::Committed);
  ASSERT_TRUE(until([&] { return r.cl->replicator_pending() == 0; }));
  ASSERT_TRUE(until([&] { return committed(prev[0]) + committed(prev[1]) >= before[prev[0]] + before[prev[1]] + 2; }));
  EXPECT_EQ(committed(prev[0]), before[prev[0]] + 1);
  EXPECT_EQ(committed(prev[1]), before[prev[1]] + 1);
  EXPECT_EQ(committed(4), before[4]) << "the new node never saw the continuation";
  EXPECT_EQ(prev_stores(r), 0u) << "it was a hinted store, not a fall-through";
}

// "0 failed operations" by the strict oracle: a join and a drain to removal (R = 1) under 4-thread traffic, against servers that
// enforce the epoch rules (MB4), with the previous view carrying reads across each change.
TEST(MembershipPrevious, JoinAndDrainToRemovalUnderTrafficFailNothing) {
  Rig r(signed_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, /*bundle_servers=*/true);
  ASSERT_TRUE(r.cl);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) {
    const auto base = tr.ops.load();
    EXPECT_TRUE(until([&] { return tr.ops.load() > base + n; }));
  };
  settle(20);
  r.publish(signed_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}, 1, {1, 2, 3}));  // join
  ASSERT_TRUE(until([&] { return r.cl->membership_epoch() == 2; }));
  settle(40);
  r.publish(signed_snap(3, 3, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}, 1, {1, 2, 3, 4}, {4}));  // drain node 4
  ASSERT_TRUE(until([&] { return r.cl->membership_epoch() == 3; }));
  settle(40);
  r.publish(signed_snap(4, 3, {{1, 1}, {2, 1}, {3, 1}}, 1, {1, 2, 3, 4}));  // node 4 leaves: no epoch bump
  ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 4; }));
  ASSERT_TRUE(until([&] { return r.cl->slot_of(4) < 0; }));
  settle(40);
  tr.finish();
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Committed), 0u) << o.report();
}

// ---- client reports ----
struct ReportSink {
  std::mutex mu;
  std::vector<std::string> bodies;
  std::atomic<bool> fail{false};
  Status take(const std::string& b) {
    if (fail.load()) return Error{ErrorCode::LinkDown, "test: controller unreachable"};
    std::lock_guard lk(mu);
    bodies.push_back(b);
    return {};
  }
  std::size_t count() {
    std::lock_guard lk(mu);
    return bodies.size();
  }
};

TEST(MembershipReports, BodyGoldenAndAnUnreachableRailIsReportedFalse) {
  ReportSink sink;
  Rig r(make_snap(7, 3, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, false,
        [](Client::NodeSpec& ns, const control::NodeView& nv) {
          if (nv.node_id == 3) ns.wopts.tickets = [](fabric::EpClass) -> Expected<proto::Ticket> { return Error{ErrorCode::LinkDown, "test: no ticket"}; };
        },
        [&](Client::BundleOpen& bo) {
          bo.send_report = [&sink](const std::string& b) { return sink.take(b); };
          bo.report_ms = 0;  // by hand
        });
  ASSERT_TRUE(r.cl);
  ASSERT_TRUE(r.cl->send_report_now());
  ASSERT_EQ(sink.count(), 1u);
  EXPECT_EQ(sink.bodies[0],
            "{\"generation\":7,\"nodes\":["
            "{\"node_id\":1,\"rails\":[{\"addr\":\"10.0.0.1:7471\",\"reachable\":true}]},"
            "{\"node_id\":2,\"rails\":[{\"addr\":\"10.0.0.2:7471\",\"reachable\":true}]},"
            "{\"node_id\":3,\"rails\":[{\"addr\":\"10.0.0.3:7471\",\"reachable\":false}]}],"
            "\"aead_fail_delta\":0}");
  EXPECT_EQ(r.cl->reports_sent(), 1u);
  // A failed send is counted and does not throw; the next one goes out.
  sink.fail = true;
  EXPECT_FALSE(r.cl->send_report_now());
  EXPECT_EQ(r.cl->reports_failed(), 1u);
  sink.fail = false;
  EXPECT_TRUE(r.cl->send_report_now());
  EXPECT_EQ(sink.count(), 2u);
}

TEST(MembershipReports, SentEveryReportMsAndNeverWithoutAController) {
  EXPECT_EQ(Client::BundleOpen{}.report_ms, 2000u) << "decision 9: one report every 2 s";
  ReportSink sink;
  {
    Rig r(make_snap(1, 1, {{1, 1}, {2, 1}}), 2, 2000, {}, 0, false, false, {}, [&](Client::BundleOpen& bo) {
      bo.send_report = [&sink](const std::string& b) { return sink.take(b); };
      bo.report_ms = 50;
    });
    ASSERT_TRUE(r.cl);
    ASSERT_TRUE(until([&] { return sink.count() >= 3; }));
    const auto t0 = std::chrono::steady_clock::now();
    const std::size_t n0 = sink.count();
    std::this_thread::sleep_for(milliseconds(600));
    const std::size_t n = sink.count() - n0;
    const auto ms = std::chrono::duration_cast<milliseconds>(std::chrono::steady_clock::now() - t0).count();
    EXPECT_LE(n, static_cast<std::size_t>(ms / 50 + 2)) << "no faster than the period";
    EXPECT_GE(n, 3u) << "and it keeps going";
  }
  Rig none(make_snap(1, 1, {{1, 1}, {2, 1}}));
  ASSERT_TRUE(none.cl);
  EXPECT_FALSE(none.cl->send_report_now()) << "no [control] controller: no reports";
  std::this_thread::sleep_for(milliseconds(100));
  EXPECT_EQ(none.cl->reports_sent(), 0u);
}

// ---- review w5 ----

// One fetch of the roots `names` (versions `vs`) in `scope`: each status, and for every Hit the oracle check that the buffer
// holds exactly that key's bytes (U2-01: never a Hit over zeroed or another node's bytes).
std::vector<KeyStatus> fetch_roots(Rig& r, int scope, const std::vector<std::string>& names, const std::vector<std::uint64_t>& vs) {
  std::vector<Chain> ch;
  ch.reserve(names.size());
  for (const auto& n : names) ch.emplace_back(n);
  std::vector<KeyRef> refs;
  for (auto& c : ch) refs.push_back(c.ref);
  std::vector<Bytes> out(names.size(), Bytes(kPayload, std::byte{0xAA}));
  std::vector<BufRef> fb;
  for (auto& o : out) fb.push_back({std::span<std::byte>(o)});
  auto fc = r.wt->wait(r.cl->fetch(scope_keys(scope), 0, std::span<const KeyRef>(refs), fb, seconds(60)));
  if (!fc) return {};
  for (std::size_t i = 0; i < names.size(); ++i)
    if (fc->status.at(i) == KeyStatus::Hit) EXPECT_EQ(decode(scope, out[i]), std::optional<std::uint64_t>(vs[i])) << names[i];
  return fc->status;
}

// U2-01 (P0): the current owner misses keys[0] but hits keys[1]; the previous-set node then runs (it writes every
// buffer) and misses keys[0] too. The job must report that node's statuses (keys[1] Miss), not the current node's Hit
// over the bytes the previous node left (zeros). Variant: the previous node hits keys[0] and misses keys[1].
TEST(MembershipPrevious, FallbackReadReportsTheStatusesOfTheNodeThatWroteTheBuffers) {
  JoinedRig j;
  j.store_all();
  auto& r = j.r;
  ASSERT_GE(j.sp.moved.size(), 2u);
  const int s1 = j.sp.moved.at(0), s2 = j.sp.moved.at(1);
  ASSERT_EQ(put_one(r, s2, "p0_" + std::to_string(s2), 1), KeyStatus::Committed);  // epoch 1: on the previous owner
  j.join();
  // Case 1: k1 only at the current owner (node 4); k0 nowhere.
  const std::string k0 = "x0_" + std::to_string(s1), k1 = "x1_" + std::to_string(s1);
  ASSERT_EQ(put_one(r, s1, k1, 2), KeyStatus::Committed);
  auto st = fetch_roots(r, s1, {k0, k1}, {1, 2});
  ASSERT_EQ(st.size(), 2u);
  EXPECT_EQ(st[0], KeyStatus::Miss);
  EXPECT_EQ(st[1], KeyStatus::Miss) << "the previous node rewrote the buffers after the current node's hit";
  EXPECT_EQ(r.cl->hint_count(), 0u) << "keys[0] hit nowhere: no hint";
  // Case 2: k0 only at the previous owner, k1 only at the current one.
  const std::string q0 = "p0_" + std::to_string(s2), q1 = "q1_" + std::to_string(s2);
  ASSERT_EQ(put_one(r, s2, q1, 2), KeyStatus::Committed);
  st = fetch_roots(r, s2, {q0, q1}, {1, 2});
  ASSERT_EQ(st.size(), 2u);
  EXPECT_EQ(st[0], KeyStatus::Hit) << "found through the previous view";
  EXPECT_EQ(st[1], KeyStatus::Miss) << "the previous node does not hold keys[1]";
}

// U2-25: a hint tagged with a previous epoch other than the snapshot's is void on the next read (void_epoch), dropped,
// and the read goes to the current set.
TEST(MembershipPrevious, StaleTaggedHintIsVoidOnTheNextRead) {
  JoinedRig j;
  j.store_all();
  j.join();
  auto& r = j.r;
  const int s = j.sp.stable.at(0);
  r.cl->set_hint_for_test(scope_keys(s), 0, /*prev_epoch=*/77);
  ASSERT_EQ(r.cl->hint_count(), 1u);
  EXPECT_EQ(get_one(r, s, "a" + std::to_string(s)), KeyStatus::Hit);
  EXPECT_EQ(hint_event(r, "void_epoch"), 1u);
  EXPECT_EQ(r.cl->hint_count(), 0u);
  EXPECT_EQ(prev_hits(r), 0u) << "a void hint sends nothing to the previous set";
}

// U2-14: aead_fail_delta per node label: a retired node's failures do not hide new ones on another node, and a revived
// node reports only the failures of its new incarnation.
TEST(MembershipReports, AeadDeltaIsPerNodeAndSurvivesARetireAndARevive) {
  ReportSink sink;
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, false, {}, [&](Client::BundleOpen& bo) {
    bo.send_report = [&sink](const std::string& b) { return sink.take(b); };
    bo.report_ms = 0;
  });
  ASSERT_TRUE(r.cl);
  auto delta = [&]() -> long long {
    const std::string b = r.cl->report_body();
    const auto p = b.find("\"aead_fail_delta\":");
    return p == std::string::npos ? -1 : std::stoll(b.substr(p + 18));
  };
  r.cl->add_aead_failures_for_test(3, 5);
  EXPECT_EQ(delta(), 5);
  ASSERT_TRUE(r.cl->send_report_now());  // accepted: node 3's 5 are reported
  EXPECT_EQ(delta(), 0);
  r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}}));  // node 3 retires
  ASSERT_TRUE(until([&] { return r.cl->slot_of(3) < 0; }));
  r.cl->add_aead_failures_for_test(1, 3);
  EXPECT_EQ(delta(), 3) << "the retired node's count must not hide node 1's new failures";
  ASSERT_TRUE(r.cl->send_report_now());
  r.cl->apply_membership(make_snap(3, 3, {{1, 1}, {2, 1}, {3, 1}}));  // node 3 back: a new incarnation
  ASSERT_TRUE(until([&] { return r.cl->slot_of(3) >= 0 && r.cl->membership_generation() == 3; }));
  EXPECT_EQ(delta(), 0) << "a revived node starts fresh";
  r.cl->add_aead_failures_for_test(3, 1);
  EXPECT_EQ(delta(), 1);
  sink.fail = true;
  EXPECT_FALSE(r.cl->send_report_now());
  EXPECT_EQ(delta(), 1) << "a failed send keeps the delta";
}

// U2-27: a report send in flight holds no state lock (report_body answers at once), and shutdown cuts it short.
TEST(MembershipReports, ASlowSendBlocksNeitherTheStateNorShutdown) {
  std::atomic<bool> in_send{false}, cancelled{false};
  auto r = std::make_unique<Rig>(make_snap(1, 1, {{1, 1}, {2, 1}}), 2, 2000, std::map<unsigned, unsigned>{}, 0, false, false,
                                 std::function<void(Client::NodeSpec&, const control::NodeView&)>{},
                                 [&](Client::BundleOpen& bo) {
                                   bo.send_report = [&](const std::string&) -> Status {
                                     in_send = true;
                                     for (int i = 0; i < 2000 && !cancelled.load(); ++i) std::this_thread::sleep_for(milliseconds(5));
                                     return Error{ErrorCode::Timeout, "test: cut short"};
                                   };
                                   bo.cancel_reports = [&] { cancelled = true; };
                                   bo.report_ms = 20;
                                 });
  ASSERT_TRUE(r->cl);
  ASSERT_TRUE(until([&] { return in_send.load(); }));
  const auto t0 = std::chrono::steady_clock::now();
  EXPECT_NE(r->cl->report_body().find("aead_fail_delta"), std::string::npos);
  EXPECT_LT(std::chrono::steady_clock::now() - t0, milliseconds(500)) << "report_body waited for the send";
  const auto t1 = std::chrono::steady_clock::now();
  r.reset();  // shutdown: cancel_reports, then the reporter joins
  EXPECT_TRUE(cancelled.load());
  EXPECT_LT(std::chrono::steady_clock::now() - t1, seconds(5)) << "the send was cut short";
}

// ---- review w4: the real Client against real MB4 bundle-mode servers ----

// What the controller does before the clients learn a bundle: the memory nodes `ids` apply it (POST /v1/bundle).
void servers_apply(Rig& r, const MembershipSnapPtr& s, std::initializer_list<unsigned> ids) {
  std::lock_guard sl(r.w.srv_mu);
  for (unsigned id : ids) r.w.queue_apply(id, s->view);  // applied at the next drive step (in the sim turn)
}

// Review w4 V08: a memory node removed from the membership sends GOAWAY(Epoch). A store the client still routes there
// (its view is older) is Skipped, both while the session is still Up and on the not-Up fast path, never Refused.
TEST(MembershipEpochServers, RemovedNodeSkipsStoresInsteadOfRefusing) {
  Rig r(signed_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, /*bundle_servers=*/true);
  ASSERT_TRUE(r.cl);
  const int scope = scope_owned_by(2);
  ASSERT_GE(scope, 0);
  auto skipped = [&](const char* why) {
    return series(r.cl->metrics_text(), "miracache_client_put_skipped_total", {std::string("reason=\"") + why + "\""})
        .value_or(0);
  };
  servers_apply(r, signed_snap(2, 2, {{1, 1}, {3, 1}}), {2});  // node 2 learns first that it is out: GOAWAY(Epoch)
  // Path 1 (U2-25): the session is still Up when the PUT_BEGIN goes out: the node answers it (StaleEpoch: it is on
  // epoch 2), or its GOAWAY(Epoch) cuts the wait short (V08: put_begin) -> Skipped either way, counted once, no fast path.
  const long long stale0 = skipped("stale_epoch"), drain_first = skipped("draining");
  const std::uint64_t fast_first = r.cl->fast_failed_jobs();
  EXPECT_EQ(put_one(r, scope, "rm_first"), KeyStatus::Skipped);
  EXPECT_EQ(skipped("stale_epoch") - stale0 + skipped("draining") - drain_first, 1) << "path 1: one skip";
  EXPECT_EQ(r.cl->fast_failed_jobs(), fast_first) << "path 1 is not the fast path";
  // The GOAWAY(Epoch) takes the session down and marks the node removed.
  const long s2 = r.cl->slot_of(2);
  ASSERT_GE(s2, 0);
  ASSERT_TRUE(until([&] {
    (void)put_one(r, scope, "rm_probe");  // the client reads the GOAWAY while it talks to the node
    WirePort* p = r.cl->wire_port(static_cast<std::size_t>(s2));
    return p && p->removed_from_membership() && !p->session_up();
  }));
  // Path 2: the not-Up fast path of a removed node -> Skipped (draining), never Refused.
  std::map<KeyStatus, int> seen;
  const long long drain0 = skipped("draining");
  const std::uint64_t fast0 = r.cl->fast_failed_jobs();
  for (int k = 0; k < 20; ++k) seen[put_one(r, scope, "rm_" + std::to_string(k))]++;
  EXPECT_EQ(seen[KeyStatus::Skipped], 20) << "refused " << seen[KeyStatus::Refused] << " aborted " << seen[KeyStatus::Aborted];
  EXPECT_EQ(r.cl->fast_failed_jobs(), fast0 + 20) << "path 2: the not-Up fast path";
  EXPECT_EQ(skipped("draining"), drain0 + 20);
}

// Review w4 V07 (+ V08, V12): a real Client in bundle mode and real MB4 servers under 4-thread traffic, strict oracle.
// Epoch changes (a join), a drain, a removal that the node learns before the client (GOAWAY), and a slot gap: a node the
// servers place on has no slot on the client, so roots the client sends elsewhere are SKIPped as not an owner.
TEST(MembershipEpochServers, EpochsDrainRemovalAndSlotGapUnderTrafficStrict) {
  Rig r(signed_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 60000, {}, 0, /*bundle_servers=*/true);
  ASSERT_TRUE(r.cl);
  Oracle o(OracleMode::Strict);
  Traffic tr(r, o);
  auto settle = [&](std::uint64_t n) {
    const auto base = tr.ops.load();
    EXPECT_TRUE(until([&] { return tr.ops.load() > base + n; }));
  };
  auto step = [&](const MembershipSnapPtr& s, std::initializer_list<unsigned> first, std::initializer_list<unsigned> rest) {
    servers_apply(r, s, first);
    settle(20);  // the client is behind these nodes for a while (StaleEpoch / GOAWAY under traffic)
    servers_apply(r, s, rest);
    r.publish(s);
    ASSERT_TRUE(until([&] { return r.cl->membership_generation() == s->generation(); }));
    settle(20);
  };
  settle(20);
  // 1. Epoch change: node 4 joins (new node first, then the others, then the client).
  step(signed_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}), {4}, {1, 2, 3});
  // 2. Drain: node 2 refuses new roots (Draining skips), keeps serving reads.
  step(signed_snap(3, 3, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}, 1, {}, {2}), {1, 2, 3, 4}, {});
  // 3. Removal of node 2 (drained), and of active node 3, which learns it before anyone else: GOAWAY(Epoch) while the
  //    client still routes roots to it (V08).
  step(signed_snap(4, 4, {{1, 1}, {4, 1}}), {3}, {1, 2, 4});
  ASSERT_TRUE(until([&] { return r.cl->slot_of(2) < 0 && r.cl->slot_of(3) < 0; }));
  // 4. Slot gap (V12): node 5 joins on the servers, but the client cannot set it up (make_spec fails): its view lacks
  //    node 5, the servers' owner sets include it.
  r.spec_fail = true;
  {
    LogCapture lc;
    servers_apply(r, signed_snap(5, 5, {{1, 1}, {4, 1}, {5, 1}}), {5, 1, 4});
    r.publish(signed_snap(5, 5, {{1, 1}, {4, 1}, {5, 1}}));
    ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 5; }));
    settle(60);
    EXPECT_EQ(count_of(lc.text(), "bundle nodes have no slot"), 1u) << "logged once per generation";
  }
  tr.finish();
  EXPECT_EQ(o.failed(), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Committed), 0u) << o.report();
  EXPECT_GT(o.count_of(KeyStatus::Skipped), 0u) << o.report();
  const std::string m = r.cl->metrics_text();
  EXPECT_GT(series(m, "miracache_client_put_skipped_total", {"reason=\"not_owner\""}).value_or(0), 0) << m;
  {
    std::lock_guard sl(r.w.srv_mu);  // the servers count the not-owner skips (V09)
    long long n = 0;
    std::string sm;
    for (unsigned id : {1u, 4u}) {
      std::string t;
      r.w.srv[id - 1]->metrics().write_prometheus(t);
      n += series(t, "miracache_put_epoch_refused_total", {"reason=\"not_owner\""}).value_or(0);
      sm += t;
    }
    EXPECT_GT(n, 0) << sm;
  }
}

// ---- fail-slow: the per-node circuit breaker (spec §10 "Slow memory node", failure-matrix row 22) ----
// Real memory nodes over the sim fabric; a node is made slow with SimNetwork::set_link_delay (every work request between
// the client and that node is delivered `extra` later). One worker and the test thread's own traffic: one op at a time,
// so the shared sim clock moves only for the op that runs (a slow op never stretches a healthy one). The breaker keys
// are set through the bundle's table path (apply_config_toml) and scaled to the test: a window of 8 s of sim time with
// 2 s buckets, at least 8 ops and 3 deadline misses (20 %) in it, p99 4x the other nodes' median, open 200 ms, 2 probes.
constexpr const char* kBrkToml =
    "[cluster.client.breaker]\nwindow_ms = 8000\nmin_ops = 8\nmin_misses = 3\nmiss_pct = 20\np99_factor = 4\n"
    "floor_us = 1000\nopen_ms = 200\nopen_max_ms = 1600\nprobes = 2\n";
struct BrkRig {
  explicit BrkRig(unsigned replicas, const char* toml = kBrkToml)
      : snap(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}, replicas)), r(snap, /*workers=*/1) {
    if (r.cl) EXPECT_TRUE(r.cl->apply_config_toml(toml, 1));
  }
  std::vector<std::uint32_t> owners(int s) const {
    const auto sk = scope_keys(s);
    return Client::OwnerSetForTest(snap->view.body, std::span<const std::uint8_t, 32>(sk.scopes[0].b));
  }
  static std::string key(int s, std::uint64_t v) { return "b" + std::to_string(s) + "_" + std::to_string(v); }
  KeyStatus store(int s, std::uint64_t v) {
    const std::string k = key(s, v);
    Chain ch(k);
    Bytes d = payload(s, v);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    o.begin_store(k, v);
    auto c = r.wt->wait(r.cl->store(scope_keys(s), 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(60)));
    if (!c) {
      o.on_missing_completion("store " + k);
      return KeyStatus::Aborted;
    }
    const KeyStatus st = c->status.at(0);
    o.end_store(k, v, st == KeyStatus::Committed);
    o.on_store(k, st);
    return st;
  }
  // Version `v` of scope `s` with a `deadline`; `took` = sim time, `zero` = the buffer came back all zero.
  KeyStatus fetch(int s, std::uint64_t v, milliseconds deadline, Nanos* took = nullptr, bool* zero = nullptr) {
    const std::string k = key(s, v);
    Chain ch(k);
    Bytes out(kPayload, std::byte{0xAA});
    std::vector<BufRef> fb{{std::span<std::byte>(out)}};
    const Nanos t0 = r.w.clock.now();
    auto c = r.wt->wait(r.cl->fetch(scope_keys(s), 0, std::span<const KeyRef>(&ch.ref, 1), fb, deadline));
    if (!c) {
      o.on_missing_completion("fetch " + k);
      return KeyStatus::Aborted;
    }
    if (took) *took = r.w.clock.now() - t0;
    if (zero) *zero = std::all_of(out.begin(), out.end(), [](std::byte x) { return x == std::byte{0}; });
    const KeyStatus fs = c->status.at(0);
    o.on_fetch(k, fs, fs == KeyStatus::Hit ? decode(s, out) : std::nullopt);
    return fs;
  }
  int state(unsigned id) const {
    const long s = r.cl->slot_of(id);
    return s < 0 ? -1 : r.cl->breaker_state(static_cast<std::size_t>(s));
  }
  long long m(const char* name, unsigned id, const char* reason = nullptr) const {
    const std::string n = "node=\"" + std::to_string(id) + "\"";
    if (reason) return series(r.cl->metrics_text(), name, {n, std::string("reason=\"") + reason + "\""}).value_or(-1);
    return series(r.cl->metrics_text(), name, {n}).value_or(-1);
  }
  // Every op between the client and node `id` is delivered `extra` later (0 = healthy). Called between ops: no job runs.
  void slow(unsigned id, Nanos extra) { r.w.net.set_link_delay(id, 10 + id, extra); }
  MembershipSnapPtr snap;
  Rig r;
  Oracle o{OracleMode::Strict};
};

// Node 3 turns slow while its session stays Up: its reads miss their deadline, its stores commit late. The breaker trips
// (reason "slow"), and from then on node 3's scopes miss at once with zeroed buffers and its stores are Skipped (never
// failed); the other nodes are untouched; the client report says "breaker":"open". A half-open probe while the node is
// still slow re-opens it (reason "probe_failed", open time doubled); after recovery two good probes close it and node 3
// serves its old data again. Strict oracle: 0 failed ops.
TEST(Breaker, SlowNodeTripsItsReadsMissFastItsStoresSkipAndProbesCloseItAfterRecovery) {
  BrkRig b(/*replicas=*/1);
  ASSERT_TRUE(b.r.cl);
  std::vector<int> on3, others;
  for (int s = 1; s <= 24; ++s) (b.owners(s)[0] == 3 ? on3 : others).push_back(s);
  ASSERT_GE(on3.size(), 2u);
  ASSERT_GE(others.size(), 4u);
  for (int s = 1; s <= 24; ++s) {
    ASSERT_EQ(b.store(s, 1), KeyStatus::Committed) << s;
    ASSERT_EQ(b.fetch(s, 1, milliseconds(60)), KeyStatus::Hit) << s;
  }
  EXPECT_EQ(b.state(3), 0);
  EXPECT_EQ(b.m("miracache_client_breaker_state", 3), 0);
  // F08 (goal 10): the breaker series carry the node's ID, hostname and address, as the rail series.
  EXPECT_EQ(series(b.r.cl->metrics_text(), "miracache_client_breaker_state", {"node=\"3\"", "node_id=\"3\"", "hostname=", "addr="}), 0)
      << b.r.cl->metrics_text();
  EXPECT_EQ(series(b.r.cl->metrics_text(), "miracache_client_breaker_trips_total",
                   {"node=\"3\"", "node_id=\"3\"", "hostname=", "addr=", "reason=\"slow\""}),
            0);

  b.slow(3, milliseconds(100));  // a fetch (60 ms deadline) misses; a store (60 s) commits after ~0.6 s
  std::uint64_t v = 1;
  for (int round = 0; round < 12 && b.state(3) != 1; ++round) {
    ++v;
    for (int s = 1; s <= 24 && b.state(3) != 1; ++s) {
      b.store(s, v);
      b.fetch(s, v, milliseconds(60));
    }
  }
  ASSERT_EQ(b.state(3), 1) << b.r.cl->metrics_text();
  EXPECT_EQ(b.state(1), 0);
  EXPECT_EQ(b.state(2), 0);
  EXPECT_EQ(b.m("miracache_client_breaker_trips_total", 3, "slow"), 1);
  EXPECT_EQ(b.m("miracache_client_breaker_trips_total", 1, "slow"), 0);
  EXPECT_EQ(b.m("miracache_client_breaker_state", 3), 1);
  const std::string body = b.r.cl->report_body();
  EXPECT_NE(body.find("{\"node_id\":3,\"rails\":[{\"addr\":\"10.0.0.3:7471\",\"reachable\":true}],\"breaker\":\"open\"}"),
            std::string::npos) << body;
  EXPECT_EQ(count_of(body, "breaker"), 1u) << body;

  // Open: node 3's scopes answer at once; the other nodes serve as before.
  const auto fast0 = b.r.cl->breaker_fast_jobs();
  ++v;
  for (int s : on3) {
    Nanos took{0};
    bool zero = false;
    EXPECT_EQ(b.fetch(s, 1, milliseconds(60), &took, &zero), KeyStatus::Miss) << s;
    EXPECT_TRUE(zero) << "a miss zeroes the engine's buffer";
    EXPECT_LT(took, milliseconds(2)) << "an open breaker answers at once";
    EXPECT_EQ(b.store(s, v), KeyStatus::Skipped) << s;
  }
  EXPECT_EQ(b.r.cl->breaker_fast_jobs(), fast0 + 2 * on3.size());
  for (int s : others) {
    EXPECT_EQ(b.store(s, v), KeyStatus::Committed) << s;
    EXPECT_EQ(b.fetch(s, v, milliseconds(60)), KeyStatus::Hit) << s;
  }

  // Half-open while still slow: the probe misses its deadline and the breaker re-opens (400 ms now).
  b.r.w.clock.advance_by(milliseconds(250));
  EXPECT_EQ(b.fetch(on3[0], 1, milliseconds(60)), KeyStatus::Miss);
  EXPECT_EQ(b.state(3), 1);
  EXPECT_EQ(b.m("miracache_client_breaker_trips_total", 3, "probe_failed"), 1);

  // Recovery: after the doubled open time two good probes close it, and node 3 serves its old data again.
  b.slow(3, Nanos{0});
  b.r.w.clock.advance_by(milliseconds(450));
  for (int i = 0; i < 2; ++i) EXPECT_EQ(b.fetch(on3[0], 1, milliseconds(60)), KeyStatus::Hit) << "probe " << i;
  EXPECT_EQ(b.state(3), 0);
  EXPECT_EQ(b.m("miracache_client_breaker_state", 3), 0);
  EXPECT_EQ(count_of(b.r.cl->report_body(), "breaker"), 0u);
  ++v;
  for (int s : on3) {
    EXPECT_EQ(b.store(s, v), KeyStatus::Committed) << s;
    EXPECT_EQ(b.fetch(s, v, milliseconds(60)), KeyStatus::Hit) << s;
  }
  EXPECT_EQ(b.m("miracache_client_breaker_trips_total", 3, "slow"), 1);
  EXPECT_EQ(b.o.failed(), 0u) << b.o.report();
}

// Slow within its deadlines (stores and 5 s fetches on node 3 take long but finish in time) and two deadline misses (fewer
// than min_misses): no trip, nothing fast-failed, and the node serves on as it recovers.
TEST(Breaker, ABrieflySlowNodeOrOneSlowWithinItsDeadlinesDoesNotTrip) {
  BrkRig b(/*replicas=*/1);
  ASSERT_TRUE(b.r.cl);
  std::vector<int> on3;
  for (int s = 1; s <= 24; ++s)
    if (b.owners(s)[0] == 3) on3.push_back(s);
  ASSERT_GE(on3.size(), 2u);
  for (int s = 1; s <= 24; ++s) {
    ASSERT_EQ(b.store(s, 1), KeyStatus::Committed) << s;
    ASSERT_EQ(b.fetch(s, 1, milliseconds(60)), KeyStatus::Hit) << s;
  }
  b.slow(3, milliseconds(100));
  for (int s = 1; s <= 24; ++s) {
    EXPECT_EQ(b.store(s, 2), KeyStatus::Committed) << s;
    EXPECT_EQ(b.fetch(s, 2, milliseconds(5000)), KeyStatus::Hit) << s;
  }
  EXPECT_EQ(b.fetch(on3[0], 2, milliseconds(60)), KeyStatus::Miss);  // two deadline misses
  EXPECT_EQ(b.fetch(on3[1], 2, milliseconds(60)), KeyStatus::Miss);
  b.slow(3, Nanos{0});
  b.r.w.clock.advance_by(milliseconds(300));  // what was posted while slow lands (RC: a new post never overtakes it)
  for (std::uint64_t v = 3; v <= 5; ++v)
    for (int s = 1; s <= 24; ++s) {
      EXPECT_EQ(b.store(s, v), KeyStatus::Committed) << s;
      EXPECT_EQ(b.fetch(s, v, milliseconds(60)), KeyStatus::Hit) << s;
    }
  for (unsigned id = 1; id <= 3; ++id) {
    EXPECT_EQ(b.state(id), 0) << id;
    EXPECT_EQ(b.m("miracache_client_breaker_trips_total", id, "slow"), 0) << id;
  }
  EXPECT_EQ(b.r.cl->breaker_fast_jobs(), 0u);
  EXPECT_EQ(b.o.failed(), 0u) << b.o.report();
}

// R = 2 (async): node 3 slow trips its breaker on the reads it is primary for; then those reads fail over to the other
// replica and hit, and stores whose set holds node 3 commit on the other node (node 3's leg skipped_down).
TEST(Breaker, ReplicasRouteAroundAnOpenNode) {
  // Open for a minute of sim time: no half-open probe while the test checks the routing.
  BrkRig b(/*replicas=*/2,
           "[cluster.client.breaker]\nwindow_ms = 8000\nmin_ops = 8\nmin_misses = 3\nmiss_pct = 20\np99_factor = 4\n"
           "floor_us = 1000\nopen_ms = 60000\nopen_max_ms = 60000\nprobes = 2\n");
  ASSERT_TRUE(b.r.cl);
  std::vector<int> p3, with3;
  for (int s = 1; s <= 24; ++s) {
    const auto o = b.owners(s);
    ASSERT_EQ(o.size(), 2u);
    if (o[0] == 3) p3.push_back(s);
    if (o[0] == 3 || o[1] == 3) with3.push_back(s);
  }
  ASSERT_GE(p3.size(), 2u);
  for (int s = 1; s <= 24; ++s) ASSERT_EQ(b.store(s, 1), KeyStatus::Committed) << s;
  ASSERT_TRUE(until([&] { return b.r.cl->replicator_pending() == 0; }));
  for (int s = 1; s <= 24; ++s) ASSERT_EQ(b.fetch(s, 1, milliseconds(60)), KeyStatus::Hit) << s;

  b.slow(3, milliseconds(100));
  for (int round = 0; round < 30 && b.state(3) != 1; ++round)
    for (int s = 1; s <= 24 && b.state(3) != 1; ++s) b.fetch(s, 1, milliseconds(60));
  ASSERT_EQ(b.state(3), 1) << b.r.cl->metrics_text();
  for (int s : p3) EXPECT_EQ(b.fetch(s, 1, milliseconds(60)), KeyStatus::Hit) << "scope " << s << " is read from its replica";
  long long failover = 0;
  for (unsigned id : {1u, 2u}) failover += std::max(0LL, b.m("miracache_client_read_failover_total", id));
  EXPECT_GE(failover, static_cast<long long>(p3.size()));
  const std::string before = b.r.cl->metrics_text();
  const long long skipped0 = series(before, "miracache_client_replica_legs_total", {"node=\"3\"", "result=\"skipped_down\""}).value_or(0);
  for (int s : with3) EXPECT_EQ(b.store(s, 2), KeyStatus::Committed) << s;
  ASSERT_TRUE(until([&] { return b.r.cl->replicator_pending() == 0; }));
  const long long skipped1 =
      series(b.r.cl->metrics_text(), "miracache_client_replica_legs_total", {"node=\"3\"", "result=\"skipped_down\""}).value_or(0);
  EXPECT_EQ(skipped1 - skipped0, static_cast<long long>(with3.size())) << "node 3's leg of every store went around it";
  for (int s : with3) EXPECT_EQ(b.fetch(s, 2, milliseconds(60)), KeyStatus::Hit) << s;
  EXPECT_EQ(b.o.failed(), 0u) << b.o.report();
}

// QT2: a put the node throttles (an Ok ack whose entries say SKIP, with retry_after_ms > 0) is Skipped and counted as
// put_skipped{reason="throttled"}; an idempotent re-put (Skipped, no retry_after) is not.
TEST(MembershipEpoch, ThrottledPutsAreSkippedAndCountedAsThrottled) {
  Rig r(make_snap(1, 1, {{1, 1}}), /*workers=*/1);
  ASSERT_TRUE(r.cl);
  auto put = [&](const std::string& k, int s) {
    Chain ch(k);
    Bytes d = payload(s, 1);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto c = r.wt->wait(r.cl->store(scope_keys(s), 0, std::span<const KeyRef>(&ch.ref, 1), pb, seconds(60)));
    return c ? c->status.at(0) : KeyStatus::Aborted;
  };
  EXPECT_EQ(put("t0", 1), KeyStatus::Committed);
  EXPECT_EQ(put("t0", 1), KeyStatus::Skipped) << "already stored";
  EXPECT_EQ(skipped(r, "throttled"), 0u);
  {
    std::lock_guard lk(r.w.srv_mu);  // the sim server runs in the client's sim turns (drive), under srv_mu
    auto d = std::make_shared<server::DynConfig>(*r.w.srv[0]->dyn());
    d->put_ops_per_s = 1;  // one put a second
    r.w.srv[0]->apply_dyn(d, "test");
  }
  unsigned committed = 0, skips = 0;
  for (int i = 1; i <= 5; ++i) {
    const KeyStatus st = put("t" + std::to_string(i), 1);
    committed += st == KeyStatus::Committed;
    skips += st == KeyStatus::Skipped;
  }
  EXPECT_LE(committed, 1u);
  EXPECT_GE(skips, 4u);
  EXPECT_EQ(skipped(r, "throttled"), skips);
}

// ---- the oracle helper ----
TEST(Oracle, StrictAndFaultVerdicts) {
  using testutil::status_failure;
  for (auto s : {KeyStatus::Hit, KeyStatus::Miss, KeyStatus::Committed, KeyStatus::Skipped})
    EXPECT_EQ(status_failure(s, OracleMode::Strict), nullptr);
  for (auto s : {KeyStatus::Refused, KeyStatus::Aborted, KeyStatus::Timeout}) {
    EXPECT_NE(status_failure(s, OracleMode::Strict, true), nullptr) << "strict has no exception";
    EXPECT_NE(status_failure(s, OracleMode::Fault, false), nullptr);
  }
  EXPECT_EQ(status_failure(KeyStatus::Refused, OracleMode::Fault, true), nullptr);
  EXPECT_EQ(status_failure(KeyStatus::Timeout, OracleMode::Fault, true), nullptr);
  EXPECT_EQ(status_failure(KeyStatus::Aborted, OracleMode::Fault, true), nullptr);  // Q1 option A
  EXPECT_NE(status_failure(KeyStatus::Aborted, OracleMode::Fault, false), nullptr);  // never for a healthy node
}


TEST(Oracle, ExcusedAbortedIsCountedApart) {
  Oracle o(OracleMode::Fault);
  o.on_store("k", KeyStatus::Aborted, /*excused=*/true);
  o.on_store("k", KeyStatus::Aborted, /*excused=*/true);
  o.on_fetch("k", KeyStatus::Timeout, std::nullopt, /*excused=*/true);
  EXPECT_EQ(o.failed(), 0u);
  EXPECT_EQ(o.excused_count(KeyStatus::Aborted), 2u);
  EXPECT_EQ(o.excused_count(KeyStatus::Timeout), 1u);
  o.on_store("k", KeyStatus::Aborted, /*excused=*/false);  // a healthy node's Aborted is still a failure
  EXPECT_EQ(o.failed(), 1u);
  EXPECT_EQ(o.excused_count(KeyStatus::Aborted), 2u);
  EXPECT_NE(o.report().find("excused{refused=0,timeout=1,aborted=2}"), std::string::npos) << o.report();
  Oracle st(OracleMode::Strict);
  st.on_store("k", KeyStatus::Aborted, /*excused=*/true);  // strict has no exception
  EXPECT_EQ(st.failed(), 1u);
  EXPECT_EQ(st.excused_count(KeyStatus::Aborted), 0u);
}
TEST(Oracle, WrongBytesAndParentRules) {
  Oracle o(OracleMode::Fault);
  o.begin_store("a", 1);
  o.end_store("a", 1, true);
  o.on_fetch("a", KeyStatus::Hit, 1);
  EXPECT_EQ(o.failed(), 0u);
  o.begin_store("a", 2);
  o.on_fetch("a", KeyStatus::Hit, 2);  // a store in flight may be seen
  EXPECT_EQ(o.failed(), 0u);
  o.end_store("a", 2, true);
  o.on_fetch("a", KeyStatus::Hit, 1);  // stale
  o.on_fetch("a", KeyStatus::Hit, std::nullopt);
  EXPECT_EQ(o.failed(), 2u);
  o.on_fetch("a", KeyStatus::Refused, std::nullopt, /*excused=*/true);
  EXPECT_EQ(o.failed(), 2u);
  o.on_continuation("b", "p", KeyStatus::Refused);  // parent not seen gone
  EXPECT_EQ(o.failed(), 3u);
  o.note_parent_gone("p");
  o.on_continuation("b", "p", KeyStatus::Refused);
  EXPECT_EQ(o.failed(), 3u);
  o.on_missing_completion("x");
  o.on_unreleased_buffers("y");
  o.on_api_error("z");
  EXPECT_EQ(o.failed(), 6u);
  EXPECT_EQ(o.reason_count("no_completion"), 1u);
  EXPECT_NE(o.report().find("failed=6"), std::string::npos);
}

// Run #200: a store that ended without Committed has an unknown outcome. Its bytes may be seen until a newer committed
// version supersedes them; a version never submitted for the key is still wrong.
TEST(Oracle, AStoreWithoutAnAnswerMayStillHaveLanded) {
  Oracle o(OracleMode::Strict);
  o.begin_store("a", 1);
  o.end_store("a", 1, false);  // e.g. Timeout while PUT_COMMIT was out
  o.on_fetch("a", KeyStatus::Hit, 1);
  EXPECT_EQ(o.failed(), 0u) << o.report();
  o.on_fetch("a", KeyStatus::Hit, 9);  // never submitted for "a"
  EXPECT_EQ(o.reason_count("wrong_bytes_unknown"), 1u);
  o.begin_store("a", 2);
  o.end_store("a", 2, true);
  o.on_fetch("a", KeyStatus::Hit, 2);
  o.on_fetch("a", KeyStatus::Hit, 1);  // superseded by the committed 2: stale
  EXPECT_EQ(o.reason_count("wrong_bytes_stale"), 1u);
  o.begin_store("a", 3);
  o.end_store("a", 3, false);
  o.on_fetch("a", KeyStatus::Hit, 3);  // newer than the last committed: may have landed
  EXPECT_EQ(o.failed(), 2u) << o.report();
  EXPECT_NE(o.report().find("failure: a: wrong_bytes_unknown [fetch got_v=9"), std::string::npos) << o.report();
}


// L12 (review s9b): a provider that returns NULL without setting errno (libsiw, ring mmap failure) is logged as
// errno=none with a note, never as a stale errno; the cause is still local_resource.
TEST(MembershipSlots, LocalDeviceFailureWithoutErrnoIsLoggedAsNone) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  std::string logs;
  {
    LogCapture lc;
    r.spec_errno = 0;
    r.spec_local_fail = true;
    const int before = r.spec_calls.load();
    r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
    ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
    ASSERT_TRUE(until([&] { return r.spec_calls.load() - before >= 2; }, milliseconds(10000)));
    logs = lc.text();
  }
  const auto ln = lines_with(logs, kLocalLine);
  ASSERT_EQ(ln.size(), 1u) << logs;
  for (const char* f : {"cause=local_resource", "call=ibv_create_cq", "errno=none", "errno_note=\"the provider set no errno\""})
    EXPECT_NE(ln[0].find(f), std::string::npos) << f << "\n" << ln[0];
  r.spec_local_fail = false;
}

// Q07 (review s10): the fabric's own cq_depth budget refusal involves no provider call: the line names the budget and
// prints no errno and no errno_note (they would describe a verbs call that never happened).
TEST(MembershipSlots, FabricBudgetRefusalIsLoggedWithoutErrno) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}));
  ASSERT_TRUE(r.cl);
  std::string logs;
  {
    LogCapture lc;
    r.spec_provider_call = false;
    r.spec_local_fail = true;
    const int before = r.spec_calls.load();
    r.cl->apply_membership(make_snap(2, 2, {{1, 1}, {2, 1}, {3, 1}, {4, 1}}));
    ASSERT_TRUE(until([&] { return r.cl->membership_generation() == 2; }));
    ASSERT_TRUE(until([&] { return r.spec_calls.load() - before >= 2; }, milliseconds(10000)));
    logs = lc.text();
  }
  r.spec_local_fail = false;
  const auto ln = lines_with(logs, kLocalLine);
  ASSERT_EQ(ln.size(), 1u) << logs;
  for (const char* f : {"cause=local_resource", "call=\"completion queue budget exhausted (cq_depth)\"",
                        "limit=\"the fabric's own budget (no provider call)\"", "hostname=host4"})
    EXPECT_NE(ln[0].find(f), std::string::npos) << f << "\n" << ln[0];
  EXPECT_EQ(ln[0].find("errno"), std::string::npos) << ln[0];
}

// Q03 / Q09 (review s10): a session reconnect (link loss, not a rail rejoin) that the LOCAL device refuses is counted per
// attempt and logged once; when the reconnect takes, one recovery line closes the entry, so the next outage with the
// same (node, rail, cause) is logged again: fail -> recover -> fail = 2 error lines and 1 recovery line. Every line and
// series carries the node ID, hostname and address.
TEST(MembershipSlots, SessionReconnectLocalFailureIsLoggedRecoveredAndLoggedAgain) {
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, /*wait_ms=*/300);
  ASSERT_TRUE(r.cl);
  const long s3 = r.cl->slot_of(3);
  ASSERT_GE(s3, 0);
  fabric::SimFabric& dev3 = *r.w.cfab[2];
  auto tick = [&] {
    r.w.clock.advance_by(milliseconds(10));
    r.cl->keepalive_tick();
  };
  WirePort* p = r.cl->wire_port(static_cast<std::size_t>(s3));
  ASSERT_NE(p, nullptr);
  ASSERT_TRUE(p->session_up());
  // The link to node 3 breaks, then returns while the local device refuses: the reconnects fail locally.
  auto fail_reconnects = [&] {
    p->endpoint(fabric::EpClass::Control)->abort();
    r.w.net.set_link(3, 13, false);
    for (int k = 0; k < 2000 && p->session_up(); ++k) tick();
    ASSERT_FALSE(p->session_up());
    const auto before = dev3.local_failures();
    dev3.inject_local_failure("ibv_create_cq", ENOMEM);
    r.w.net.set_link(3, 13, true);
    for (int k = 0; k < 4000 && dev3.local_failures() < before + 3; ++k) tick();
    ASSERT_GE(dev3.local_failures(), before + 3) << "the reconnect retried with its backoff";
    EXPECT_FALSE(p->session_up());
  };
  auto recover = [&] {
    dev3.inject_local_failure(nullptr);
    for (int k = 0; k < 4000 && !p->session_up(); ++k) tick();
    ASSERT_TRUE(p->session_up());
    for (int k = 0; k < 5; ++k) tick();
  };
  std::string logs;
  {
    LogCapture lc;
    fail_reconnects();
    recover();
    fail_reconnects();
    logs = lc.text();
  }
  const auto ln = lines_with(logs, kLocalLine);
  ASSERT_EQ(ln.size(), 2u) << "one line per outage, not per attempt\n" << logs;
  for (const auto& l : ln)
    for (const char* f : {"level=error", "node_id=3", "hostname=host3", "addr=sim:7003", "rail=0", "device=sim",
                          "cause=local_resource", "call=ibv_create_cq", "errno=\"ENOMEM"})
      EXPECT_NE(l.find(f), std::string::npos) << f << "\n" << l;
  const auto rec = lines_with(logs, kRecovered);
  ASSERT_EQ(rec.size(), 1u) << logs;
  for (const char* f : {"node_id=3", "hostname=host3", "addr=sim:7003", "via=\"session reconnect\"",
                        "failed_before=local_resource@rail0"})
    EXPECT_NE(rec[0].find(f), std::string::npos) << f << "\n" << rec[0];
  EXPECT_LT(logs.find(kLocalLine), logs.find(kRecovered)) << "fail, recover, fail";
  EXPECT_LT(logs.find(kRecovered), logs.rfind(kLocalLine)) << "fail, recover, fail";
  const std::string m = r.cl->metrics_text();
  EXPECT_EQ(series(m, "miracache_client_endpoint_build_failures_total",
                   {"node_id=\"3\"", "hostname=\"host3\"", "addr=\"sim:7003\"", "rail=\"0\"", "cause=\"local_resource\""}),
            static_cast<long long>(dev3.local_failures()))
      << "every refused attempt is counted\n" << m;
  // The device has room again: the second outage closes with its own recovery line.
  {
    LogCapture lc;
    recover();
    logs = lc.text();
  }
  EXPECT_EQ(lines_with(logs, kRecovered).size(), 1u) << logs;
  EXPECT_EQ(count_of(logs, kLocalLine), 0u);
}

// ---- Q15 in bundle mode (run #271): the open contract of the static open (Env::open_settle) -------------------------
// Node `id`'s ticket draws fail `fails` times (an open-time admin fetch that failed under load), then work.
std::function<void(Client::NodeSpec&, const control::NodeView&)> draws_fail(unsigned id, std::shared_ptr<std::atomic<int>> fails) {
  return [id, fails](Client::NodeSpec& ns, const control::NodeView& nv) {
    if (nv.node_id != id) return;
    ns.wopts.tickets = [fails, inner = std::move(ns.wopts.tickets)](fabric::EpClass cls) -> Expected<proto::Ticket> {
      if (fails->load() > 0) {
        fails->fetch_sub(1);
        return Error{ErrorCode::LinkDown, "admin: connect failed"};
      }
      return inner(cls);
    };
  };
}

// Before: the bundle open built each node once; node 2's failed first build left it pending behind a successful open.
TEST(MembershipSlots, BundleOpenRetriesANodeWhoseFirstBuildFailedInsideTheOpen) {
  auto fails = std::make_shared<std::atomic<int>>(1);
  LogCapture cap;
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, false, draws_fail(2, fails), {}, seconds(2));
  ASSERT_TRUE(r.cl);
  EXPECT_EQ(fails->load(), 0) << "the first build of node 2 did fail";
  const long s2 = r.cl->slot_of(2);
  ASSERT_GE(s2, 0);
  EXPECT_NE(r.cl->wire_port(static_cast<std::size_t>(s2)), nullptr) << "node 2 is still pending after a successful open";
  EXPECT_EQ(r.cl->nodes_connected(), 3u);
  const std::string logs = cap.text();
  EXPECT_EQ(count_of(logs, "client open: every memory node connected"), 1u) << logs;
  EXPECT_NE(logs.find("connected=\"3 of 3\""), std::string::npos) << logs;
}

// R20 (review s11): every node's first build fails (one transient admin failure each). Before: the bundle open failed
// at once (up == 0 returned before the settle); now they are retried in the settle like one of N-1.
TEST(MembershipSlots, BundleOpenRetriesEveryNodeWhenAllFirstBuildsFail) {
  std::vector<std::shared_ptr<std::atomic<int>>> fails;
  for (int i = 0; i < 3; ++i) fails.push_back(std::make_shared<std::atomic<int>>(1));
  auto tw = [fails](Client::NodeSpec& ns, const control::NodeView& nv) {
    for (unsigned id = 1; id <= 3; ++id) draws_fail(id, fails[id - 1])(ns, nv);
  };
  LogCapture cap;
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, false, tw, {}, seconds(2));
  ASSERT_TRUE(r.cl) << cap.text();
  for (auto& f : fails) EXPECT_EQ(f->load(), 0) << "every first build did fail";
  EXPECT_EQ(r.cl->nodes_connected(), 3u) << cap.text();
  EXPECT_EQ(count_of(cap.text(), "client open: every memory node connected"), 1u) << cap.text();
}

// A node still down after the settle: the open succeeds with the others and says so in one WARN naming it.
TEST(MembershipSlots, BundleOpenReportsANodeStillDownAfterTheSettle) {
  auto fails = std::make_shared<std::atomic<int>>(1 << 30);
  LogCapture cap;
  Rig r(make_snap(1, 1, {{1, 1}, {2, 1}, {3, 1}}), 2, 2000, {}, 0, false, false, draws_fail(3, fails), {}, milliseconds(300));
  ASSERT_TRUE(r.cl);
  EXPECT_EQ(r.cl->node_count(), 3u);
  EXPECT_EQ(r.cl->nodes_connected(), 2u);
  const std::string logs = cap.text();
  const auto at = logs.find("client open: some memory nodes are pending");
  ASSERT_NE(at, std::string::npos) << logs;
  const std::string line = logs.substr(at, logs.find('\n', at) - at);
  EXPECT_NE(line.find("2 of 3"), std::string::npos) << line;
  EXPECT_NE(line.find("node_id=3 hostname=host3"), std::string::npos) << line;
  EXPECT_EQ(count_of(logs, "client open: some memory nodes are pending"), 1u);
  EXPECT_LT(fails->load(), (1 << 30) - 1) << "the open retried node 3 within the settle";
}

}  // namespace
}  // namespace miracache
