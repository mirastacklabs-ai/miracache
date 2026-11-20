// SPDX-License-Identifier: Apache-2.0
// MB4 scenario: three real memory-node Servers over SimFabric, a controller that walks them through joins, drains,
// read-only, removals, failures and re-adds (epoch + 1 on every view change, none at leave), applying each bundle to
// the nodes in a random order with random lag, and a client that sends PUT_BEGINs and LOOKUPs at random nodes with
// frame epochs that are right, behind or ahead. An independent oracle (owner_set over view_from_bundle, as the client
// computes it) predicts every reply: StaleEpoch (and its retry), Draining, SKIP, accept. Checked on every reply: the
// node's epoch and bundle generation stamp. After every step: Server::check_invariants (RootPutAtReplica,
// NoPutOnReadOnly ghosts). A node that applies a bundle without itself must send exactly one GOAWAY; a removed node
// that is listed again must accept roots again (P08). R = 1 and R = 2.
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "control/bundle.h"
#include "control/view.h"
#include "fabric/sim/sim_fabric.h"
#include "scenario.h"
#include "server/server.h"
#include "util/clock.h"
#include "util/crc32c.h"
#include "util/executor.h"
#include "util/random.h"

namespace miracache::sim {
namespace {

using namespace miracache::server;
using control::MemberState;
using proto::Op;
using proto::WireStatus;

constexpr int kNodes = 3;
constexpr int kScopes = 8;
constexpr int kSteps = 140;
constexpr const char* kIdentity = "spiffe://p/a";

struct Reply {
  proto::FrameHeader h;
  std::vector<std::byte> body;
  bool error() const { return (h.flags & proto::flag::ERROR) != 0; }
  WireStatus status() const {
    auto e = proto::decode_error_reply(h, body);
    return e ? static_cast<WireStatus>(e->status) : WireStatus::Corrupt;
  }
  std::uint32_t retry() const {
    auto e = proto::decode_error_reply(h, body);
    return e ? e->retry_after_ms : 0;
  }
};

enum class Out : std::uint8_t { Accept, Skip, Stale, Draining };

store::StoreConfig store_cfg() {
  store::StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.principal_default.max_scopes = 64;
  c.principal_default.max_bytes = 8u << 20;
  c.principal_default.idle_ttl = std::chrono::seconds(100000);
  c.invalidate_per_s = 0;
  return c;
}

class Scenario {
 public:
  Scenario(std::uint64_t seed, std::uint32_t r)
      : r_(r), rng_(seed * 0x9e3779b97f4a7c15ull + r), net_(clock_, rng_, {}, {}), cli_(net_.add_node(10)) {
    cbuf_.assign(1 << 16, std::byte{0});
    cmr_ = cli_.reg(cbuf_, fabric::Access::LocalWrite).value();
    for (int i = 0; i < kNodes; ++i) {
      fabs_[i] = &net_.add_node(static_cast<fabric::NodeId>(i + 1));
      ServerConfig sc;
      sc.store = store_cfg();
      sc.goaway_drain_ms = 777;
      do sc.store.node_id = static_cast<std::uint32_t>(1 + rng_.below(0xfffffff0ull));  // fixed, seeded: placement depends on it
      while (std::find(ids_.begin(), ids_.begin() + i, sc.store.node_id) != ids_.begin() + i);
      auto s = Server::create(sc, *fabs_[i], clock_, rng_, exec_, &ticket_rng_);
      if (!s) { fail("server create"); return; }
      srv_[i] = std::move(*s);
      if (!srv_[i]->start()) { fail("server start"); return; }
      ids_[i] = srv_[i]->node_id();
      for (int j = 0; j < i; ++j)
        if (ids_[j] == ids_[i]) { fail("node id collision"); return; }
    }
    // The first bundle: every node active, epoch 1, applied everywhere before any traffic.
    for (auto& n : ctl_) n = {true, MemberState::Active};
    publish(/*view_change=*/false);
    for (int i = 0; i < kNodes; ++i) push(i);
    for (int i = 0; i < kNodes; ++i) {
      auto c = connect(i, fabric::EpClass::Control);
      auto g = connect(i, fabric::EpClass::Ingest);
      if (!c || !g) { fail("connect"); return; }
      cep_[i] = *c;
      iep_[i] = *g;
      hello(cep_[i], fabric::EpClass::Control);
      hello(iep_[i], fabric::EpClass::Ingest);
    }
  }

  MembershipResult run() {
    for (int step = 0; step < kSteps && res_.ok; ++step) {
      const auto roll = rng_.below(100);
      if (roll < 12) controller_action();
      else if (roll < 22) catch_up();
      else if (roll < 24) latch();
      else if (roll < 34) lookup_op();
      else put_op();
      for (int i = 0; i < kNodes && res_.ok; ++i)
        if (auto s = srv_[i]->check_invariants(); !s) fail(std::string("invariant: ") + s.error().context);
      clock_.advance_by(std::chrono::milliseconds(1 + rng_.below(5)));
    }
    return res_;
  }

 private:
  struct Ctl {
    bool listed = true;
    MemberState st = MemberState::Active;
  };
  struct Committed {
    std::set<int> keys;
    int tail = 0, depth = 0;
  };

  void fail(const std::string& why) {
    if (res_.ok) {
      res_.ok = false;
      res_.failure = why;
    }
  }
  void fold(std::uint64_t v) { res_.trace_hash = (res_.trace_hash ^ v) * 1099511628211ull; }

  // ---- controller ----------------------------------------------------------------------------------------
  int n_active() const {
    int n = 0;
    for (const auto& c : ctl_) n += c.listed && c.st == MemberState::Active;
    return n;
  }
  void publish(bool view_change) {
    if (view_change) ++epoch_;
    ++gen_;
    latest_ = control::BundleView{};
    latest_.body.generation = gen_;
    latest_.body.epoch = epoch_;
    latest_.body.previous_epoch = epoch_ > 1 ? epoch_ - 1 : 0;
    latest_.body.replicas = r_;
    latest_.sec.sec_generation = 1;
    control::PrincipalView p;
    p.name = "p";
    p.id = control::principal_id("p");
    p.identities = {kIdentity};
    p.quota_bytes = 24u << 20;
    p.max_scopes = 64;
    latest_.sec.principals.push_back(p);
    for (int i = 0; i < kNodes; ++i) {
      if (!ctl_[i].listed) continue;
      control::NodeView n;
      n.node_id = ids_[i];
      n.hostname = "h" + std::to_string(i);
      n.admin = "10.0.0." + std::to_string(i + 1) + ":9465";
      n.rails.push_back({"10.0.0.1:7471", "a", "roce"});
      n.state = ctl_[i].st;
      latest_.body.nodes.push_back(n);
    }
    ++res_.stats.bundles;
  }
  void controller_action() {
    struct Act {
      int kind, node;
    };
    std::vector<Act> acts;
    for (int i = 0; i < kNodes; ++i) {
      const auto& c = ctl_[i];
      if (!c.listed || c.st != MemberState::Active) acts.push_back({0, i});            // (re-)add / activate: epoch + 1
      if (c.listed && c.st == MemberState::Active && n_active() > 1) {
        acts.push_back({1, i});                                                        // drain: epoch + 1
        acts.push_back({4, i});                                                        // failure: gone, epoch + 1
      }
      if (c.listed && c.st == MemberState::Draining) acts.push_back({2, i});          // read-only: same epoch
      if (c.listed && (c.st == MemberState::Draining || c.st == MemberState::Readonly)) acts.push_back({3, i});  // leave: same epoch
    }
    acts.push_back({5, 0});  // republish
    const Act a = acts[rng_.below(acts.size())];
    auto& c = ctl_[a.node];
    bool vc = false;
    switch (a.kind) {
      case 0: c.listed = true; c.st = MemberState::Active; vc = true; break;
      case 1: c.st = MemberState::Draining; vc = true; break;
      case 2: c.st = MemberState::Readonly; break;
      case 3: c.listed = false; break;
      case 4: c.listed = false; vc = true; break;
      default: break;
    }
    publish(vc);
    fold(0xC0 + static_cast<std::uint64_t>(a.kind) * 16 + static_cast<std::uint64_t>(a.node));
    // Apply to each node with probability 1/2, in a random order; the rest lag until a catch-up.
    std::array<int, kNodes> order{0, 1, 2};
    for (int i = kNodes - 1; i > 0; --i) std::swap(order[i], order[rng_.below(static_cast<std::uint64_t>(i) + 1)]);
    for (int i : order)
      if (rng_.below(2) == 0) push(i);
  }
  void catch_up() {
    std::vector<int> lag;
    for (int i = 0; i < kNodes; ++i)
      if (applied_[i].body.generation < gen_) lag.push_back(i);
    if (!lag.empty()) push(lag[rng_.below(lag.size())]);
  }
  MemberState member_of(const control::BundleView& b, std::uint32_t id, bool& present) const {
    for (const auto& n : b.body.nodes)
      if (n.node_id == id) {
        present = true;
        return n.state;
      }
    present = false;
    return MemberState::Active;
  }
  void push(int i) {
    if (applied_[i].body.generation >= gen_) return;
    bool was_present = true, now_present = true;
    member_of(applied_[i], ids_[i], was_present);
    member_of(latest_, ids_[i], now_present);
    const int goaways_before = goaways_[i];
    srv_[i]->apply_bundle(latest_);
    applied_[i] = latest_;
    pump();
    const bool removed_now = was_present && !now_present;
    if (goaways_[i] - goaways_before != (removed_now ? 1 : 0))
      return fail("node " + std::to_string(i) + ": expected " + (removed_now ? "one" : "no") + " GOAWAY on a bundle that " +
                  (removed_now ? "removes" : "keeps") + " it");
    if (removed_now) ++res_.stats.goaways;
    if (!now_present) was_removed_[i] = true;
    ++res_.stats.pushes;
    fold(0xB0 + static_cast<std::uint64_t>(i) * 4096 + applied_[i].body.generation);
  }
  void latch() {
    const int i = static_cast<int>(rng_.below(kNodes));
    if (latched_[i]) return;
    latched_[i] = true;
    srv_[i]->begin_drain(proto::GoawayReason::Shutdown, 100000);
    pump();
    fold(0xD0 + static_cast<std::uint64_t>(i));
  }

  // ---- oracle --------------------------------------------------------------------------------------------
  MemberState state_of(int i, bool& present) const { return member_of(applied_[i], ids_[i], present); }
  bool owns(int i, const store::ScopeId& sc) const {
    const auto v = control::view_from_bundle(applied_[i].body);
    for (auto k : owner_set(v, std::span<const std::uint8_t, 32>(sc), r_))
      if (v.nodes[k].id == std::to_string(ids_[i])) return true;
    return false;
  }
  Out expect_put(int i, std::uint32_t fe, bool root, const store::ScopeId& sc, std::uint32_t& retry) const {
    const std::uint32_t ne = applied_[i].body.epoch;
    retry = 0;
    if (fe != ne) {
      retry = fe > ne ? 50 : 0;
      return Out::Stale;
    }
    bool present = false;
    const MemberState st = state_of(i, present);
    if (!present || st == MemberState::Readonly) return Out::Draining;
    if (!root) return Out::Accept;
    if (st != MemberState::Active || latched_[i]) return Out::Draining;
    return owns(i, sc) ? Out::Accept : Out::Skip;
  }

  // ---- client --------------------------------------------------------------------------------------------
  static store::ScopeId scope_of(int s) {
    store::ScopeId sc{};
    sc[0] = static_cast<std::uint8_t>(s);
    sc[1] = static_cast<std::uint8_t>(s * 13 + 5);
    sc[31] = 0x6d;
    return sc;
  }
  static std::array<std::uint8_t, 32> key_of(int k) {
    std::array<std::uint8_t, 32> a{};
    a[0] = static_cast<std::uint8_t>(k);
    a[1] = static_cast<std::uint8_t>(k >> 8);
    a[31] = 0xa1;
    return a;
  }
  void check_stamp(int i, const Reply& r, const char* what) {
    if (r.h.epoch != applied_[i].body.epoch ||
        r.h.bundle_gen_lo != static_cast<std::uint32_t>(applied_[i].body.generation))
      fail(std::string(what) + ": reply stamp (" + std::to_string(r.h.epoch) + "," + std::to_string(r.h.bundle_gen_lo) +
           ") != node's (" + std::to_string(applied_[i].body.epoch) + "," + std::to_string(applied_[i].body.generation) + ")");
  }
  std::uint32_t pick_epoch(int i) {
    const std::uint32_t ne = applied_[i].body.epoch;
    switch (rng_.below(8)) {
      case 0: return epoch_;            // the controller's latest (ahead when the node lags)
      case 1: return ne > 0 ? ne - 1 : 0;
      case 2: return ne + 1;
      default: return ne;
    }
  }
  void put_op() {
    const int i = static_cast<int>(rng_.below(kNodes));
    const int s = static_cast<int>(rng_.below(kScopes));
    const auto sc = scope_of(s);
    auto& cm = committed_[i][s];
    const bool root = cm.tail == 0 || rng_.below(100) < 55;
    const int k = ++next_key_;
    const std::uint32_t fe = pick_epoch(i);
    std::uint32_t retry = 0;
    const Out want = expect_put(i, fe, root, sc, retry);

    auto m = std::make_unique<proto::PutBegin>();
    std::memcpy(m->scope_id, sc.data(), 32);
    m->n = 1;
    std::memcpy(m->e[0].key_hash, key_of(k).data(), 32);
    if (!root) std::memcpy(m->e[0].parent_hash, key_of(cm.tail).data(), 16);
    m->e[0].chain_pos = root ? 0 : static_cast<std::uint16_t>(cm.depth);
    m->e[0].stored_len = 4096;
    send(iep_[i], Op::PUT_BEGIN, static_cast<std::uint64_t>(k), *m,
         [](const proto::PutBegin& x, std::span<std::byte> o) { return proto::encode_put_begin(x, o); }, fe);
    Reply r = take(iep_[i]);
    if (!res_.ok) return;
    check_stamp(i, r, "PUT_BEGIN");
    Out got;
    if (r.error()) {
      got = r.status() == WireStatus::StaleEpoch ? Out::Stale : r.status() == WireStatus::Draining ? Out::Draining : Out::Accept;
      if (r.status() != WireStatus::StaleEpoch && r.status() != WireStatus::Draining) return fail("unexpected PUT_BEGIN error status");
      if (got == Out::Stale && r.retry() != retry) return fail("StaleEpoch retry " + std::to_string(r.retry()) + " != " + std::to_string(retry));
    } else {
      auto a = proto::decode_put_begin_ack(r.h, r.body);
      if (!a || a->status != 0 || a->n != 1) return fail("PUT_BEGIN_ACK shape");
      got = a->e[0].status == 1 ? Out::Accept : Out::Skip;
      if (got == Out::Accept) commit(i, s, k, root, *a, fe);
    }
    if (got != want)
      return fail("node " + std::to_string(i) + " frame epoch " + std::to_string(fe) + " node epoch " +
                  std::to_string(applied_[i].body.epoch) + (root ? " root" : " child") + ": got " + std::to_string(static_cast<int>(got)) +
                  " want " + std::to_string(static_cast<int>(want)) + " (0 accept, 1 skip, 2 stale, 3 draining)");
    fold(0xA0 + static_cast<std::uint64_t>(got) + 8 * static_cast<std::uint64_t>(i) + 64 * (root ? 1 : 0));
    switch (got) {
      case Out::Accept:
        if (root) {
          ++res_.stats.root_accepted;
          if (was_removed_[i]) ++res_.stats.readded_accepts;
        } else {
          ++res_.stats.child_accepted;
        }
        break;
      case Out::Skip: ++res_.stats.skipped; break;
      case Out::Stale: ++res_.stats.stale; break;
      case Out::Draining: ++res_.stats.draining; break;
    }
  }
  void commit(int i, int s, int k, bool root, const proto::PutBeginAck& a, std::uint32_t fe) {
    const auto data = std::vector<std::byte>(4096, static_cast<std::byte>(k & 0xff));
    std::memcpy(cbuf_.data(), data.data(), data.size());
    const auto& e = a.e[0];
    const auto& mr = a.mr[e.mr_index];
    const std::uint64_t t = ++tag_;
    if (!iep_[i]->post_write({cmr_.lkey, cbuf_.data(), 4096}, {mr.rkey, mr.addr + e.offset, 4096}, t)) return fail("write post");
    pump();
    if (!tags_.count(t) || !tags_[t]) return fail("write completion");
    proto::PutCommit c;
    c.put_id = a.put_id;
    c.n = 1;
    c.e[0] = proto::CommitEntry{0, crc32c(data), data.size()};
    send(iep_[i], Op::PUT_COMMIT, 999, c, [](const proto::PutCommit& x, std::span<std::byte> o) { return proto::encode_put_commit(x, o); }, fe);
    Reply r = take(iep_[i]);
    if (!res_.ok) return;
    if (r.error()) return fail("PUT_COMMIT refused");
    auto& cm = committed_[i][s];
    if (root) cm.tail = cm.depth = 0;  // a new chain in this scope at this node (older blocks stay)
    cm.keys.insert(k);
    cm.tail = k;
    ++cm.depth;
    ++res_.stats.commits;
  }
  void lookup_op() {
    const int i = static_cast<int>(rng_.below(kNodes));
    const int s = static_cast<int>(rng_.below(kScopes));
    const auto& cm = committed_[i][s];
    const int k = cm.keys.empty() || rng_.below(4) == 0 ? ++next_key_ : *std::next(cm.keys.begin(), static_cast<long>(rng_.below(cm.keys.size())));
    auto m = std::make_unique<proto::Lookup>();
    const auto sc = scope_of(s);
    std::memcpy(m->scope_id, sc.data(), 32);
    m->n = 1;
    std::memcpy(m->key_hash[0].data(), key_of(k).data(), 32);
    send(cep_[i], Op::LOOKUP, 7, *m, [](const proto::Lookup& x, std::span<std::byte> o) { return proto::encode_lookup(x, o); },
         static_cast<std::uint32_t>(rng_.below(9)));  // any frame epoch: lookups are never checked
    Reply r = take(cep_[i]);
    if (!res_.ok) return;
    check_stamp(i, r, "LOOKUP");
    if (r.error()) return fail("LOOKUP refused (never checked against the epoch)");
    auto d = proto::decode_lookup_ack(r.h, r.body);
    if (!d) return fail("LOOKUP_ACK shape");
    const bool hit = d->e[0].status == 1, want = cm.keys.count(k) != 0;
    if (hit != want) return fail("LOOKUP hit/miss differs from what was committed at the node");
    ++res_.stats.lookups;
    fold(0xE0 + (hit ? 1 : 0));
  }

  // ---- plumbing ------------------------------------------------------------------------------------------
  void pump() {
    for (int quiet = 0; quiet < 3;) {
      net_.run_until_idle();
      std::size_t w = 0;
      for (auto& s : srv_) w += s->run_once();
      quiet = w ? 0 : quiet + 1;
    }
    net_.run_until_idle();
    collect();
  }
  void collect() {
    std::array<fabric::Completion, 32> out;
    for (;;) {
      const std::size_t n = cli_.poll(out);
      if (!n) break;
      for (std::size_t j = 0; j < n; ++j) {
        auto& c = out[j];
        if (c.is_recv) {
          auto fr = proto::decode_frame(c.frame.bytes);
          if (!fr) return fail("undecodable reply");
          Reply rp{fr->h, std::vector<std::byte>(fr->body.begin(), fr->body.end())};
          if (fr->h.type == static_cast<std::uint16_t>(Op::GOAWAY)) {
            for (int i = 0; i < kNodes; ++i)
              if (cep_[i] && cep_[i]->id() == c.endpoint) {
                auto g = proto::decode_goaway(rp.h, rp.body);
                if (!g) return fail("GOAWAY shape");
                if (g->reason == static_cast<std::uint32_t>(proto::GoawayReason::Epoch)) {
                  ++goaways_[i];
                  if (g->drain_ms != 777) return fail("GOAWAY drain_ms");
                } else {
                  ++shutdown_goaways_;
                }
              }
            continue;
          }
          if (fr->h.type == static_cast<std::uint16_t>(Op::SEG_TABLE)) continue;
          inbox_[c.endpoint].push_back(std::move(rp));
        } else if (c.op == fabric::CompletionOp::Write || c.op == fabric::CompletionOp::Read) {
          tags_[c.tag] = c.status;
        }
      }
    }
  }
  Expected<fabric::Endpoint*> connect(int i, fabric::EpClass cls) {
    auto tk = srv_[i]->issue_ticket(kIdentity, cls, 0, 1);
    if (!tk) return tk.error();
    fabric::ConnParams cp;
    cp.cls = cls;
    std::span<std::byte> out(cp.ticket.data(), 20);
    if (!proto::encode_ticket((*tk)[0], out)) return Error{ErrorCode::InvalidArgument, "ticket"};
    cp.ticket_len = 20;
    return cli_.connect(fabric::Peer{static_cast<fabric::NodeId>(i + 1)}, cp);
  }
  template <typename Msg, typename Enc>
  void send(fabric::Endpoint* ep, Op op, std::uint64_t rid, const Msg& m, Enc enc, std::uint32_t epoch = 0) {
    std::array<std::byte, 8192> body{}, frame{};
    auto bn = enc(m, std::span<std::byte>(body));
    if (!bn) return fail("encode");
    auto h = proto::header_for(op, rid);
    h.epoch = epoch;
    auto fn = proto::encode_frame(h, std::span<const std::byte>(body.data(), *bn), frame);
    if (!fn) return fail("encode frame");
    fabric::Frame f;
    f.bytes.assign(frame.begin(), frame.begin() + static_cast<std::ptrdiff_t>(*fn));
    if (!ep->post_send(std::move(f), 0)) fail("post_send");
  }
  Reply take(fabric::Endpoint* ep) {
    pump();
    auto& q = inbox_[ep->id()];
    if (q.empty()) {
      fail("no reply");
      return {};
    }
    Reply r = std::move(q.front());
    q.pop_front();
    return r;
  }
  void hello(fabric::Endpoint* ep, fabric::EpClass cls) {
    proto::Hello h;
    h.cls = static_cast<std::uint8_t>(cls);
    std::memset(h.conn_id, 1, 16);
    send(ep, Op::HELLO, 1, h, [](const proto::Hello& m, std::span<std::byte> o) { return proto::encode_hello(m, o); });
    Reply a = take(ep);
    if (res_.ok && a.h.type != static_cast<std::uint16_t>(Op::HELLO_ACK)) fail("HELLO_ACK");
  }

  std::uint32_t r_;
  SimClock clock_;
  SeededRandom rng_;
  SeededRandom ticket_rng_{7};
  fabric::SimNetwork net_;
  fabric::SimFabric& cli_;
  InlineExecutor exec_;
  std::array<fabric::SimFabric*, kNodes> fabs_{};
  std::array<std::unique_ptr<Server>, kNodes> srv_;
  std::array<std::uint32_t, kNodes> ids_{};
  std::array<fabric::Endpoint*, kNodes> cep_{}, iep_{};
  std::array<Ctl, kNodes> ctl_{};
  std::array<control::BundleView, kNodes> applied_;
  control::BundleView latest_;
  std::uint64_t gen_ = 0;
  std::uint32_t epoch_ = 1;
  std::array<int, kNodes> goaways_{};
  std::array<bool, kNodes> latched_{}, was_removed_{};
  int shutdown_goaways_ = 0;
  std::array<std::array<Committed, kScopes>, kNodes> committed_;
  int next_key_ = 0;
  std::map<fabric::EndpointId, std::deque<Reply>> inbox_;
  std::map<std::uint64_t, Status> tags_;
  std::vector<std::byte> cbuf_;
  fabric::MemRegion cmr_;
  std::uint64_t tag_ = 0;
  MembershipResult res_;
};

}  // namespace

MembershipResult run_membership_scenario(std::uint64_t seed, std::uint32_t replicas) {
  Scenario s(seed, replicas);
  return s.run();
}

}  // namespace miracache::sim
