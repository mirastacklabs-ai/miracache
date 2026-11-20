// SPDX-License-Identifier: Apache-2.0
// Randomized multi-client scenario over the whole store (Arena, SlabAllocator, Store,
// MrManager, PutPath) with every invariant checked after every step.
//
// Clients: 4 clients over 3 principals (scope ids are shared across principals, so a wrong
// principal must always MISS), plus a ghost principal that owns nothing. Events: root and
// chained PUTs (implicit scope open) with writes that land late and out of order, early
// COMMIT (iWARP CQE is not placement), torn/corrupt payloads, cancel, abandon, endpoint
// down; LOOKUP then a sliced fetch with state-word re-check (the client-side seq check);
// RENEW/RELEASE/abandoned leases/session end; INVALIDATE with right, stale and wrong
// generations; scope and principal drops; LRU eviction at the scope and byte caps; reaping;
// clock jumps that expire leases and scopes; partial MR registration; delayed and reordered
// digest completions; a rogue writer replaying old rkeys and wild keys.
// Content is the "AEAD stand-in": the payload is the 8-byte tag of (principal, scope, key,
// incarnation) repeated, so any wrong-key, wrong-incarnation or torn read differs.
// Server invariants come from the store; client-side ones from RefModel.
#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "fabric/sim/sim_fabric.h"
#include "fabric/sim/sim_network.h"
#include "ref_model.h"
#include "scenario.h"
#include "store/mr_manager.h"
#include "store/put.h"
#include "store/restart.h"
#include "util/buggify.h"
#include "util/crc32c.h"

namespace miracache::sim {
bool g_store_trace = false;
namespace {

using namespace store;
using std::chrono::seconds;

constexpr int kScopes = 4, kChains = 3, kPos = 8;
constexpr std::uint32_t kSlice = 2048;

ScopeId sid(int i) {
  ScopeId s{};
  s[0] = static_cast<std::uint8_t>(i + 1);
  s[31] = 0x5c;
  return s;
}
KeyHash kh(int id) {
  KeyHash k{};
  k[0] = static_cast<std::uint8_t>(id + 1);
  k[31] = 0xa1;
  return k;
}
KeyHash parent_of(int id) { return id % kPos == 0 ? KeyHash{} : kh(id - 1); }

struct Client {
  PrincipalId p;
  SessionId sess;
  fabric::EndpointId ep;
};
struct Landing {
  int put;
  std::uint32_t rkey;
  std::byte* dst;
  std::vector<std::byte> data;
};
enum class Mode { Honest, Early, Corrupt, Cancel, Abandon, Down };
// Model view of a put at the server (what a client can know). Writing: certainly live and
// WRITING. Digesting: certainly live until its PUT_DONE. DigestAborted: cancelled or endpoint
// down while digesting; the server frees it silently when the digest completes, so it may or
// may not still count against the endpoint. Ended: gone (commit done, cancel, timeout, down).
enum class PSt { Writing, Digesting, DigestAborted, Ended };
struct PutOp {
  int client = 0, scope = 0;
  Mode mode = Mode::Honest;
  std::vector<PutKey> keys;
  std::vector<int> ids;
  PutBeginAck ack;
  std::vector<std::vector<std::byte>> intended;
  std::vector<std::byte*> dst;
  std::vector<std::uint64_t> inst;
  PSt st = PSt::Writing;
  bool commit_sent = false, finished = false;
  int pending = 0;
};
struct Fetch {
  int client;
  int scope;
  int id;
  LookupEntry e;
  std::uint64_t pre = 0;
  std::vector<std::byte> buf;
  std::uint32_t got = 0;
  int phase = 0;  // 0 pre-state, 1 data, 2 post-state
  bool scribbled = false;
  std::uint64_t inst = 0;  // the key incarnation the HIT named
};
struct LeaseRec {
  SessionId sess;
  LeaseId id;
  Nanos granted;
  bool abandoned = false;  // never released or renewed again: expiry must reclaim it
  Nanos expiry{0};         // from the grant or the last successful RENEW (0: known gone)
};

class DeferredExecutor final : public Executor {
 public:
  void post(std::function<void()> work, std::function<void()> done) override {
    work();  // the extent is fenced by now
    q.push_back(std::move(done));
  }
  std::deque<std::function<void()>> q;
};

// Serves a copy of the media (a crash snapshot) as a persistent backing.
class SnapBacking final : public Backing {
 public:
  explicit SnapBacking(std::vector<std::vector<std::byte>>& segs) : segs_(segs) {}
  Expected<std::span<std::byte>> map(std::uint32_t seg, std::size_t len) override {
    if (seg >= segs_.size() || segs_[seg].size() != len) return Error{ErrorCode::InvalidArgument, "snap: segment"};
    return std::span<std::byte>(segs_[seg]);
  }
  Status sync(std::uint32_t, std::size_t, std::size_t) override { return {}; }
  BackingKind kind() const noexcept override { return BackingKind::File; }

 private:
  std::vector<std::vector<std::byte>>& segs_;
};

struct World {
  explicit World(std::uint64_t seed)
      : seed(seed), rng(seed * 0x9e3779b97f4a7c15ull + 7), net_rng(seed + 99), net(clock, net_rng, {}), srv(net.add_node(1)) {}

  std::uint64_t seed;
  SeededRandom rng, net_rng;
  SeededRandom crash_rng{0};  // when to take a crash snapshot; separate, so the scenario trace is unchanged
  SimClock clock;
  fabric::SimNetwork net;
  fabric::SimFabric& srv;
  StoreConfig cfg;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
  std::unique_ptr<MrManager> mrs;
  DeferredExecutor exec;
  std::unique_ptr<PutPath> puts;
  RefModel model;
  bool roomy = false;
  bool roomy_caps = false;  // production-size limits, so > 4 concurrent puts per endpoint happen
  std::vector<Client> clients;
  std::vector<PutOp> ops;
  std::vector<Landing> landings;
  std::vector<Fetch> fetches;
  std::vector<LeaseRec> leases;
  std::map<PutId, int> op_of_put;  // accepted put id -> index in ops
  std::vector<std::array<int, 3>> recent;  // (client, scope, chain) of recent commits
  std::map<std::uint64_t, std::uint64_t> gen_owner;  // GenerationsUnique over time: gen -> tag
  std::uint64_t inst_counter = 0, trace = 0xcbf29ce484222325ull;
  std::string fail;
  ScenarioStats st;

  void mixin(std::uint64_t v) { trace = (trace ^ mix64(v)) * 0x100000001b3ull; }
  template <class... A>
  void tr(const char* f, A... a) const {
    if (g_store_trace) std::fprintf(stderr, f, a...);
  }
  void bad(const std::string& m) {
    if (fail.empty()) fail = m;
  }
  PrincipalId principal_of(int c) const { return c < 0 ? 9 : clients[static_cast<std::size_t>(c)].p; }
  Nanos now() const { return clock.now(); }

  bool setup() {
    cfg.segment_bytes = 8u << 20;
    cfg.run_bytes = 64u << 10;
    cfg.min_block_bytes = 4096;
    cfg.n_segments = 2;
    cfg.gen_chunk = 1000;
    // A scope region (in the alignment gap of segment 0: the geometry, and so every trace, is unchanged) so the
    // store keeps scope records and a crash snapshot can be re-opened (crash_check).
    cfg.scope_records = 512;
    crash_rng = SeededRandom(seed ^ 0xc7a5c4ull);
    roomy = seed % 3 == 0;
    cfg.invalidate_per_s = roomy || rng.chance(0.5) ? 0 : 2;
    cfg.principal_default.idle_ttl = roomy ? seconds(400) : seconds(60);
    cfg.principal_default.max_scopes = roomy ? 8 : 2;
    cfg.principal_default.max_bytes = roomy ? (8u << 20) : (40u << 10);
    // Small caps so the sim reaches them: per-endpoint in-flight puts and per-session leases.
    // Seeds divisible by 6 (half the roomy ones) keep the default caps instead, so many
    // concurrent puts per endpoint are simulated too. Both draws always happen: the RNG stream, and
    // so every other seed's trace, is unchanged.
    const auto ep_cap = 2 + static_cast<std::uint32_t>(rng.below(3));
    const auto lease_cap = 3 + static_cast<std::uint32_t>(rng.below(4));
    roomy_caps = roomy && seed % 2 == 0;
    cfg.max_puts_per_endpoint = roomy_caps ? StoreConfig{}.max_puts_per_endpoint : ep_cap;
    cfg.max_leases_per_session = roomy_caps ? StoreConfig{}.max_leases_per_session : lease_cap;
    auto a = Arena::open(cfg);
    if (!a) return false;
    arena = std::move(*a);
    if (arena->layout().scope.reserved_runs != 0) return false;
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
    model = RefModel(cfg.principal_default.idle_ttl);
    auto pd = srv.alloc_pd();
    if (!pd) return false;
    mrs = std::make_unique<MrManager>(srv, *arena, fabric::PdId{}, *pd);
    store->set_readable([this](std::uint32_t seg) { return mrs->readable(seg); });
    puts = std::make_unique<PutPath>(*store, *slab, *mrs, *arena, clock, exec, [this](const PutDoneResult& r) {
      ++st.timeouts;
      mixin(r.put_id);
      if (auto it = op_of_put.find(r.put_id); it != op_of_put.end()) ops[static_cast<std::size_t>(it->second)].st = PSt::Ended;
    });
    for (int i = 0; i < 4; ++i) clients.push_back({static_cast<PrincipalId>(1 + i % 3), static_cast<SessionId>(100 + i), static_cast<fabric::EndpointId>(500 + i)});
    if (rng.chance(0.5))
      while (mrs->step_registration().value()) {}
    return true;
  }

  // ---- PUT ----------------------------------------------------------------------------
  void put_start() {
    PutOp op;
    op.client = static_cast<int>(rng.below(clients.size()));
    op.scope = static_cast<int>(rng.below(kScopes));
    const int chain = static_cast<int>(rng.below(kChains));
    const PrincipalId p = principal_of(op.client);
    int a = 0;
    if (rng.chance(0.5)) {  // extend: first position not yet visible, or a random (orphan) one
      for (int pos = 0; pos < kPos; ++pos)
        if (!model.find(p, sid(op.scope), kh(chain * kPos + pos))) { a = pos; break; }
      if (rng.chance(0.1)) a = static_cast<int>(rng.below(kPos));
    }
    const int n = 1 + static_cast<int>(rng.below(static_cast<std::uint64_t>(std::min(3, kPos - a))));
    static const std::uint64_t lens[] = {4096, 4096, 8192, 5000};
    PutBeginReq q;
    q.principal = p;
    q.scope = sid(op.scope);
    for (int i = 0; i < n; ++i) {
      const int id = chain * kPos + a + i;
      PutKey k;
      k.key = kh(id);
      k.parent = parent_of(id);
      k.chain_pos = static_cast<std::uint64_t>(a + i);
      k.stored_len = lens[rng.below(4)];
      op.keys.push_back(k);
      op.ids.push_back(id);
      q.keys.push_back(k);
    }
    const std::uint64_t m = rng.below(100);
    op.mode = m < 55 ? Mode::Honest : m < 75 ? Mode::Early : m < 85 ? Mode::Corrupt : m < 90 ? Mode::Cancel : m < 95 ? Mode::Abandon : Mode::Down;
    settle_aborted();
    const std::size_t certain = live_puts(op.client);
    const std::size_t possible = certain + digest_aborted_puts(op.client);  // upper bound of the server's count
    op.ack = puts->put_begin(clients[static_cast<std::size_t>(op.client)].ep, q);
    mixin(op.ack.put_id * 31 + static_cast<std::uint64_t>(op.ack.status));
    if (certain >= cfg.max_puts_per_endpoint) {  // per-endpoint cap: the server must refuse (cap checked before quota)
      ++st.ep_cap_hits;
      if (op.ack.put_id != 0) return bad("per-endpoint put cap: PUT_BEGIN accepted with the endpoint at its cap");
    }
    // The other side: on a roomy seed (no quota or capacity pressure, scopes to spare) a root put
    // with the endpoint certainly below its cap has no reason to be refused, so an over-strict cap fails.
    if (roomy && possible < cfg.max_puts_per_endpoint && parent_is_root(q.keys[0].parent)) {
      ++st.below_cap_checks;
      if (op.ack.status == BeginStatus::Refused) return bad("per-endpoint put cap: PUT_BEGIN refused below the cap on a roomy seed");
    }
    if (op.ack.put_id == 0) { ++st.refused; return; }
    ++st.puts;
    const int idx = static_cast<int>(ops.size());
    op_of_put[op.ack.put_id] = idx;
    op.intended.resize(n);
    op.dst.assign(n, nullptr);
    op.inst.assign(n, 0);
    bool junked = false;
    for (int i = 0; i < n; ++i) {
      const BeginEntry& e = op.ack.entries[i];
      if (!e.accept) continue;
      const MrRef& mr = op.ack.mr[e.mr_index];
      op.inst[i] = ++inst_counter;
      op.intended[i] = payload_of(tag_of(p, q.scope, op.keys[i].key, op.inst[i]), op.keys[i].stored_len);
      op.dst[i] = reinterpret_cast<std::byte*>(mr.addr + e.offset);
      std::vector<std::byte> wire = op.intended[i];
      if (op.mode == Mode::Corrupt && !junked) {  // torn client: bytes differ from the CRC it sends
        junked = true;
        for (auto& b : wire) b = static_cast<std::byte>(rng.next_u64());
      }
      const std::size_t pieces = 1 + rng.below(3);
      const std::size_t step = std::max<std::size_t>(1, (wire.size() + pieces - 1) / pieces);
      for (std::size_t off = 0; off < wire.size(); off += step) {
        const std::size_t len = std::min(step, wire.size() - off);
        landings.push_back({idx, mr.rkey, op.dst[i] + off, std::vector<std::byte>(wire.begin() + static_cast<long>(off), wire.begin() + static_cast<long>(off + len))});
        ++op.pending;
      }
    }
    const int c = op.client;
    ops.push_back(std::move(op));
    st.max_ep_puts = std::max<std::uint64_t>(st.max_ep_puts, live_puts(c));
  }

  // Puts of client `c` that are certainly counted against its endpoint.
  std::size_t live_puts(int c) const {
    std::size_t n = 0;
    for (const auto& o : ops)
      if (o.client == c && (o.st == PSt::Writing || o.st == PSt::Digesting)) ++n;
    return n;
  }
  // Cancelled/downed digesting puts of client `c` that the server may still count.
  std::size_t digest_aborted_puts(int c) const {
    std::size_t n = 0;
    for (const auto& o : ops)
      if (o.client == c && o.st == PSt::DigestAborted) ++n;
    return n;
  }
  // With the digest queue empty, every cancelled/downed digesting put has been freed.
  void settle_aborted() {
    if (!exec.q.empty()) return;
    for (auto& o : ops)
      if (o.st == PSt::DigestAborted) o.st = PSt::Ended;
  }
  void endpoint_down(int c) {
    puts->on_endpoint_down(clients[static_cast<std::size_t>(c)].ep);
    for (auto& o : ops) {
      if (o.client != c) continue;
      if (o.st == PSt::Writing) o.st = PSt::Ended;
      else if (o.st == PSt::Digesting) o.st = PSt::DigestAborted;
    }
  }

  // Expected answer for a COMMIT or CANCEL of `put_id` sent on client `c`'s endpoint: UnknownPut
  // unless the put is certainly live on that very endpoint. Returns -1 when the model cannot tell.
  int expect_unknown(int c, int owner_op, bool cancel) const {
    if (owner_op < 0) return 1;  // an id the server never issued
    const PutOp& o = ops[static_cast<std::size_t>(owner_op)];
    if (o.client != c) return 1;  // another endpoint's put id looks unknown
    switch (o.st) {
      case PSt::Writing: return 0;
      case PSt::Digesting: return cancel ? 0 : 1;  // commit twice is unknown; cancel aborts the digesting put
      case PSt::DigestAborted: return cancel ? -1 : 1;
      case PSt::Ended: return 1;
    }
    return -1;
  }

  // Commit/cancel of an id the server may no longer know (or never knew, or that another endpoint
  // owns): the answer is UnknownPut and nothing else changes. Own-endpoint cancel of a digesting put
  // is a real cancel.
  void unknown_probe() {
    const bool cancel = rng.chance(0.5);
    int owner = -1;
    PutId id = (~PutId{0}) - rng.below(1000);  // never issued
    if (!ops.empty() && rng.chance(0.8)) {
      owner = static_cast<int>(rng.below(ops.size()));
      id = ops[static_cast<std::size_t>(owner)].ack.put_id;
    }
    int c = static_cast<int>(rng.below(clients.size()));
    if (owner >= 0 && rng.chance(0.6)) c = ops[static_cast<std::size_t>(owner)].client;
    const int want = expect_unknown(c, owner, cancel);
    // A commit of a certainly-live own put would be a real commit: not a probe.
    if (want == 0 && !cancel) return;
    if (want == 0 && ops[static_cast<std::size_t>(owner)].st == PSt::Writing) return;  // do not cancel live writers here
    ++st.unknown_probes;
    auto got = std::make_shared<std::pair<bool, CommitStatus>>(false, CommitStatus::Ok);
    const fabric::EndpointId ep = clients[static_cast<std::size_t>(c)].ep;
    auto cb = [got](const PutDoneResult& r) { *got = {true, r.status}; };
    if (cancel) {
      puts->put_cancel(ep, id, cb);
    } else {
      PutCommitReq q;
      q.put_id = id;
      puts->put_commit(ep, q, cb);
    }
    mixin(id * 3 + cancel + (got->first ? 7 + static_cast<std::uint64_t>(got->second) : 0));
    // Distinct messages per case, so each sim tooth can name the oracle that must catch it.
    const bool foreign = owner >= 0 && c != ops[static_cast<std::size_t>(owner)].client;
    if (want >= 0 && (!got->first || (got->second == CommitStatus::UnknownPut) != (want == 1)))
      return bad(want != 1 ? "UnknownPut: cancel of a live own put answered UnknownPut"
                 : foreign ? "UnknownPut: commit/cancel of a foreign put id was not answered UnknownPut"
                           : "UnknownPut: commit/cancel of an unknown or ended put id was not answered UnknownPut");
    if (cancel && want == 0 && owner >= 0) ops[static_cast<std::size_t>(owner)].st = PSt::DigestAborted;
  }

  // One WRITE lands (or is rejected because its MR is gone: the fence working).
  void land(std::size_t li) {
    Landing l = std::move(landings[li]);
    landings.erase(landings.begin() + static_cast<long>(li));
    fabric::MemRegion m;
    m.rkey = l.rkey;
    if (l.put >= 0) --ops[static_cast<std::size_t>(l.put)].pending;
    if (mrs->is_live_write(m)) {
      std::memcpy(l.dst, l.data.data(), l.data.size());
      ++st.writes_landed;
    } else {
      ++st.writes_rejected;
    }
    mixin(l.rkey);
  }

  void on_done(int idx, const PutDoneResult& r) {
    PutOp& op = ops[static_cast<std::size_t>(idx)];
    op.finished = true;
    mixin(r.put_id * 7 + static_cast<std::uint64_t>(r.status));
    if (r.status == CommitStatus::Ok) op.st = PSt::Ended;  // PUT_DONE: the put is gone (Malformed leaves it WRITING)
    if (r.status != CommitStatus::Ok) return;
    const PrincipalId p = principal_of(op.client);
    for (const auto& e : r.e) {
      mixin(e.key_index * 16u + e.status * 4u + e.reason);
      if (e.status != static_cast<std::uint8_t>(proto::DoneStatus::Committed)) {
        ++st.aborted;
        continue;
      }
      ++st.commits;
      tr("  COMMIT p=%llu scope=%d id=%d\n", (unsigned long long)p, op.scope, op.ids[e.key_index]);
      recent.push_back({op.client, op.scope, op.ids[e.key_index] / kPos});
      if (recent.size() > 24) recent.erase(recent.begin());
      const auto i = e.key_index;
      if (std::memcmp(op.dst[i], op.intended[i].data(), op.intended[i].size()) != 0)
        return bad("committed block bytes differ from what the client sent (fence/digest hole)");
      if (std::string m = model.commit(p, sid(op.scope), op.keys[i].key, op.keys[i].parent, op.inst[i], op.keys[i].stored_len, now()); !m.empty())
        return bad(m);
    }
  }

  void put_step() {
    std::vector<int> live;
    for (std::size_t i = 0; i < ops.size(); ++i)
      if (!ops[i].finished && !ops[i].commit_sent) live.push_back(static_cast<int>(i));
    if (live.empty()) return;
    const int idx = live[rng.below(live.size())];
    PutOp& op = ops[static_cast<std::size_t>(idx)];
    const Client& c = clients[static_cast<std::size_t>(op.client)];
    std::vector<std::size_t> mine;
    for (std::size_t i = 0; i < landings.size(); ++i)
      if (landings[i].put == idx) mine.push_back(i);
    if (!mine.empty() && (rng.chance(0.6) || op.mode == Mode::Honest)) return land(mine[rng.below(mine.size())]);
    mixin(1000 + static_cast<std::uint64_t>(op.mode));
    switch (op.mode) {
      case Mode::Abandon: op.commit_sent = true; return;  // the put timeout reaps it
      case Mode::Down: op.commit_sent = true; endpoint_down(op.client); return;
      case Mode::Cancel: {
        op.commit_sent = true;
        const bool was_live = op.st == PSt::Writing;
        auto got = std::make_shared<std::pair<bool, CommitStatus>>(false, CommitStatus::Ok);
        puts->put_cancel(c.ep, op.ack.put_id, [got](const PutDoneResult& r) { *got = {true, r.status}; });
        if (!got->first || (got->second == CommitStatus::UnknownPut) == was_live)
          return bad(was_live ? "cancel of a live put answered UnknownPut" : "cancel of an ended put was not UnknownPut");
        if (was_live) op.st = PSt::Ended;
        return;
      }
      default: break;
    }
    PutCommitReq q;
    q.put_id = op.ack.put_id;
    for (std::size_t i = 0; i < op.keys.size(); ++i)
      if (op.ack.entries[i].accept) q.e.push_back({static_cast<std::uint16_t>(i), crc32c(op.intended[i]), op.keys[i].stored_len});
    op.commit_sent = true;
    const bool was_live = op.st == PSt::Writing;
    auto got = std::make_shared<std::pair<bool, CommitStatus>>(false, CommitStatus::Ok);
    puts->put_commit(c.ep, q, [this, idx, got](const PutDoneResult& r) {
      *got = {true, r.status};
      on_done(idx, r);
    });
    // A commit of a put the model knows is gone must be answered UnknownPut at once; a live one never.
    if (!was_live && (!got->first || got->second != CommitStatus::UnknownPut))
      return bad("commit of an ended put was not answered UnknownPut");
    if (was_live && got->first && got->second == CommitStatus::UnknownPut) return bad("commit of a live put answered UnknownPut");
    if (was_live && !got->first) ops[static_cast<std::size_t>(idx)].st = PSt::Digesting;
  }

  // ---- LOOKUP / fetch -----------------------------------------------------------------
  void lookup() {
    int ci = rng.chance(0.04) ? -1 : static_cast<int>(rng.below(clients.size()));
    int scope = static_cast<int>(rng.below(kScopes));
    int chain = static_cast<int>(rng.below(kChains));
    if (!recent.empty() && rng.chance(0.75)) {  // mostly look up what was recently stored
      const auto& r = recent[rng.below(recent.size())];
      scope = r[1], chain = r[2];
      if (ci >= 0 && rng.chance(0.9)) ci = r[0];
    }
    const PrincipalId p = principal_of(ci);
    const int n = 1 + static_cast<int>(rng.below(4));
    LookupReq q;
    q.principal = p;
    q.scope = sid(scope);
    std::vector<int> ids;
    for (int i = 0; i < n; ++i) {
      ids.push_back(chain * kPos + i);
      q.keys.push_back(kh(ids.back()));
    }
    const SessionId sess = ci < 0 ? 999 : clients[static_cast<std::size_t>(ci)].sess;
    // Per-session lease cap: with this many leases certainly alive the ack must be all-MISS, lease 0.
    std::size_t alive = 0;
    for (const auto& l : leases)
      if (l.sess == sess && l.expiry > now()) ++alive;
    const bool capped = alive >= cfg.max_leases_per_session;
    const LookupAck ack = store->lookup(sess, q);
    if (ack.entries.size() != q.keys.size()) return bad("LOOKUP entry count");
    if (capped) {
      ++st.lease_cap_hits;
      if (ack.lease != 0) return bad("lease cap: LOOKUP granted a lease with the session at its cap");
      for (const auto& e : ack.entries)
        if (e.hit) return bad("lease cap: LOOKUP returned a HIT with the session at its cap");
    }
    bool any = false;
    for (int i = 0; i < n; ++i) {
      const LookupEntry& e = ack.entries[static_cast<std::size_t>(i)];
      mixin(e.hit * 1000003ull + e.gen * 31 + e.offset);
      if (!e.hit) {
        ++st.misses;
        tr("  MISS p=%llu scope=%d id=%d\n", (unsigned long long)p, scope, ids[static_cast<std::size_t>(i)]);
        if (mrs->registration_complete() && !capped) {  // a capped MISS says nothing about the key
          if (roomy && model.must_hit(p, q.scope, q.keys[static_cast<std::size_t>(i)], now()))
            return bad("spurious MISS of a committed, recently used key");
          model.miss(p, q.scope, q.keys[static_cast<std::size_t>(i)]);
        }
        continue;
      }
      any = true;
      ++st.hits;
      tr("  HIT p=%llu scope=%d id=%d gen=%llu slot=%llu\n", (unsigned long long)p, scope, ids[static_cast<std::size_t>(i)],
         (unsigned long long)e.gen, (unsigned long long)e.gen_slot);
      if (std::string m = model.hit(p, q.scope, q.keys[static_cast<std::size_t>(i)], e.gen, now()); !m.empty()) return bad(m);
      const RefModel::Key* mk = model.find(p, q.scope, q.keys[static_cast<std::size_t>(i)]);
      const std::uint64_t tag = tag_of(p, q.scope, q.keys[static_cast<std::size_t>(i)], mk->inst);
      auto [it, fresh] = gen_owner.emplace(e.gen, tag);
      if (!fresh && it->second != tag) return bad("GenerationsUnique: one generation names two incarnations");
      if (e.stored_len != mk->len) return bad("LOOKUP stored_len differs from what was put");
      fetches.push_back({ci, scope, ids[static_cast<std::size_t>(i)], e, 0, std::vector<std::byte>(e.stored_len), 0, 0, false, mk->inst});
    }
    if (any != (ack.lease != 0)) return bad("lease granted iff there is a hit");
    if (any) {
      if (ack.lease_expiry <= now()) return bad("lease already expired");
      leases.push_back({sess, ack.lease, now(), false, ack.lease_expiry});
    }
  }

  void fetch_step() {
    if (fetches.empty()) return;
    const std::size_t fi = rng.below(std::min<std::size_t>(fetches.size(), 3));  // oldest first
    Fetch& f = fetches[fi];
    const PrincipalId p = principal_of(f.client);
    const ScopeId s = sid(f.scope);
    const std::uint64_t want = proto::pack_state_gen(proto::BlockState::Committed, f.e.gen);
    if (f.phase == 0) {
      f.pre = arena->state_gen().load(f.e.gen_slot);
      f.phase = 1;
    } else if (f.phase == 1) {
      const std::uint32_t len = std::min<std::uint64_t>(kSlice, f.e.stored_len - f.got);
      std::memcpy(f.buf.data() + f.got, arena->block(f.e.seg_id, f.e.offset + f.got, len).data(), len);
      if (rng.chance(0.03)) {  // rogue writer on the landing buffer
        f.buf[rng.below(f.buf.size())] = static_cast<std::byte>(rng.next_u64());
        f.scribbled = true;
      }
      f.got += len;
      if (f.got == f.e.stored_len) f.phase = 2;
    } else {
      const std::uint64_t post = arena->state_gen().load(f.e.gen_slot);
      const bool seq_ok = f.pre == want && post == want;
      tr("  FETCH-END p=%llu scope=%d id=%d gen=%llu pre=%llx post=%llx want=%llx in_model=%d\n", (unsigned long long)p,
         f.scope, f.id, (unsigned long long)f.e.gen, (unsigned long long)f.pre, (unsigned long long)post,
         (unsigned long long)want, model.find(p, s, kh(f.id)) != nullptr);
      const RefModel::Key* mk = model.find(p, s, kh(f.id));
      // The bytes must be those of the incarnation the HIT named. That incarnation may be
      // current, or removed only by a MISS (lapse/eviction; see RefModel::miss).
      const bool current = mk != nullptr && mk->inst == f.inst;
      const bool lapsed = model.lapsed(p, s, kh(f.id), f.inst);
      const bool match = f.buf == payload_of(tag_of(p, s, kh(f.id), f.inst), f.e.stored_len);
      mixin(seq_ok * 4 + (match && current) * 2 + f.scribbled);  // keeps the pinned goldens valid
      if (seq_ok && !f.scribbled) {
        if (!current && !lapsed) return bad("seq check passed for a key that was removed (stale generation read)");
        if (!match) return bad("seq check passed but the bytes are wrong (torn/wrong-key read)");
      }
      if (match && !f.scribbled && !seq_ok) ++st.miss_seq;
      else if (!match || f.scribbled) ++st.miss_aead;
      if (match && seq_ok && !f.scribbled) ++st.fetch_hits;
      fetches.erase(fetches.begin() + static_cast<long>(fi));
    }
  }

  // ---- leases, invalidate, drops, time, nemesis -----------------------------------------
  void lease_op() {
    std::vector<std::size_t> open;
    for (std::size_t i = 0; i < leases.size(); ++i)
      if (!leases[i].abandoned) open.push_back(i);
    if (open.empty()) return;
    const std::size_t i = open[rng.below(open.size())];
    const LeaseRec l = leases[i];
    switch (rng.below(4)) {
      case 0: {
        auto r = store->renew(l.sess, l.id);
        mixin(r.has_value());
        leases[i].expiry = r ? *r : Nanos{0};
        if (r && *r > now() + cfg.lease_ttl) bad("RENEW beyond lease_ttl");
        if (r && *r > l.granted + cfg.lease_max) bad("RENEW beyond lease_max");
        break;
      }
      case 1: (void)store->release(l.sess, l.id); leases.erase(leases.begin() + static_cast<long>(i)); break;
      case 2: leases[i].abandoned = true; break;
      default: end_session(l.sess);
    }
  }

  void end_session(SessionId s) {
    store->on_session_end(s);
    leases.erase(std::remove_if(leases.begin(), leases.end(), [&](const LeaseRec& x) { return x.sess == s; }), leases.end());
  }

  void invalidate() {
    const int ci = static_cast<int>(rng.below(clients.size()));
    const PrincipalId p = principal_of(ci);
    const int scope = static_cast<int>(rng.below(kScopes));
    const int id = static_cast<int>(rng.below(kChains * kPos));
    const RefModel::Key* mk = model.find(p, sid(scope), kh(id));
    std::uint64_t gen = rng.next_u64() & 0xffff;
    if (mk != nullptr && mk->gen != 0 && rng.chance(0.8)) gen = mk->gen;
    Status r = store->invalidate(p, sid(scope), kh(id), gen);
    tr("  INVALIDATE p=%llu scope=%d id=%d gen=%llu model_gen=%llu -> %s\n", (unsigned long long)p, scope, id,
       (unsigned long long)gen, (unsigned long long)(mk ? mk->gen : 0), r ? "OK" : "ERR");
    mixin(r.has_value() * 5 + gen);
    if (r) {
      model.invalidate(p, sid(scope), kh(id), gen);
      ++st.invalidates;
    }
  }

  void drop() {
    const PrincipalId p = principal_of(static_cast<int>(rng.below(clients.size())));
    if (rng.chance(0.8)) {
      const int scope = static_cast<int>(rng.below(kScopes));
      tr("  DROP_SCOPE p=%llu scope=%d\n", (unsigned long long)p, scope);
      store->drop_scope(p, sid(scope));
      model.drop_scope(p, sid(scope));
    } else {
      tr("  DROP_PRINCIPAL p=%llu\n", (unsigned long long)p);
      store->drop_principal(p, Nanos{INT64_MAX / 2});
      model.drop_principal(p);
    }
    ++st.drops;
  }

  void advance() {
    const std::uint64_t r = rng.below(100);
    clock.advance_by(r < 90 ? Nanos{static_cast<std::int64_t>(rng.below(1'500'000'000))}
                     : r < 99 ? seconds(10 + static_cast<std::int64_t>(rng.below(30)))
                              : seconds(130 + static_cast<std::int64_t>(rng.below(60))));
  }

  void stray() {  // rogue writer: old rkeys replayed and wild rkeys; a live MR is the client's own
    if (!landings.empty() && rng.chance(0.5)) {
      Landing l = landings[rng.below(landings.size())];
      l.put = -1;
      for (auto& b : l.data) b = static_cast<std::byte>(rng.next_u64());
      landings.push_back(std::move(l));
    } else if (!ops.empty()) {  // write after the put ended, through its old rkey
      const PutOp& o = ops[rng.below(ops.size())];
      for (std::size_t i = 0; o.finished && i < o.dst.size(); ++i)
        if (o.dst[i] != nullptr) {
          landings.push_back({-1, o.ack.mr[o.ack.entries[i].mr_index].rkey, o.dst[i], std::vector<std::byte>(64, std::byte{0xEE})});
          break;
        }
    }
  }

  void release_exec() {
    if (exec.q.empty()) return;
    const std::size_t i = rng.below(exec.q.size());
    auto d = std::move(exec.q[i]);
    exec.q.erase(exec.q.begin() + static_cast<long>(i));
    d();
  }

  void evict() {
    const auto freed = store->evict(4096 * (1 + rng.below(8)));
    tr("  EVICT freed=%llu\n", (unsigned long long)freed);
    mixin(freed);
  }

// ---- Crash check -------------------------------------------------------------------
  // A crash at this instant: the media (Anon segments, the scope region in segment 0's slack) are copied, a new
  // Arena / SlabAllocator / Store open over the copy and run the restart scan (unclean: every extent re-verified).
  // Safety: every adopted block was a live COMMITTED block (same slot, generation, key, length, owner) of a scope
  // that was not doomed; nothing in flight, ZOMBIE, freed or dropped comes back. Retention: every committed block of
  // a live scope whose scope_id one principal holds (and no 16 B key-prefix sharing) is adopted. Generations: the
  // next one issued after the restart is above every live one. Uses its own RNG and changes nothing in the live
  // store, so the scenario trace is unchanged.
  void crash_check() {
    std::vector<std::vector<std::byte>> media(cfg.n_segments);
    for (std::uint32_t s = 0; s < cfg.n_segments; ++s) {
      auto sp = arena->segment(s);
      media[s].assign(sp.begin(), sp.end());
    }
    auto a = Arena::open(cfg, std::make_unique<SnapBacking>(media));
    if (!a) return bad(std::string("crash: re-open failed: ") + a.error().context);
    if ((*a)->fresh() || (*a)->was_clean()) return bad("crash: re-open saw a blank or clean store");
    SimClock clk2(now());
    SeededRandom r2(seed + 4242);
    SlabAllocator slab2(**a);
    Store st2(**a, slab2, clk2, r2);
    auto rep = restart_scan(**a, slab2, st2);
    if (!rep) return bad(std::string("crash: restart scan failed: ") + rep.error().context);
    if (!rep->verified) return bad("crash: an unclean restart must re-verify every extent");
    if (auto s = st2.check_invariants(); !s) return bad(std::string("crash: restored store: ") + s.error().context);
    if (auto s = slab2.check_invariants(); !s) return bad(std::string("crash: restored slab: ") + s.error().context);
    struct Live {
      Extent e;
      std::uint64_t len;
      bool zombie;
      PrincipalId p;
      ScopeId s;
      KeyHash k;
    };
    std::map<std::uint64_t, Live> live;
    std::uint64_t max_gen = 0;
    store->for_each_owned_block([&](const Extent& e, std::uint64_t len, bool z, PrincipalId p, const ScopeId& s, const KeyHash& k) {
      live.emplace(e.gen_slot, Live{e, len, z, p, s, k});
      max_gen = std::max(max_gen, e.gen);
    });
    std::map<ScopeId, std::set<PrincipalId>> holders;
    std::set<std::pair<PrincipalId, ScopeId>> doomed;
    store->for_each_scope([&](PrincipalId p, const ScopeId& s, bool d) {
      holders[s].insert(p);
      if (d) doomed.insert({p, s});
    });
    std::set<std::pair<PrincipalId, ScopeId>> shared_prefix;
    {
      std::map<std::pair<PrincipalId, ScopeId>, std::set<KeyHash>> pfx;
      for (const auto& [slot, l] : live)
        if (!l.zombie && !pfx[{l.p, l.s}].insert(parent_prefix(l.k)).second) shared_prefix.insert({l.p, l.s});
    }
    std::set<std::uint64_t> adopted;
    st2.for_each_owned_block([&](const Extent& e, std::uint64_t len, bool z, PrincipalId p, const ScopeId& s, const KeyHash& k) {
      adopted.insert(e.gen_slot);
      auto it = live.find(e.gen_slot);
      if (z || it == live.end() || it->second.zombie || it->second.e.gen != e.gen || it->second.e.off != e.off ||
          it->second.len != len || it->second.p != p || it->second.s != s || it->second.k != k)
        bad("crash: adopted a block that was not live and committed");
      else if (doomed.count({p, s}))
        bad("crash: adopted a block of a doomed scope");
    });
    for (const auto& [slot, l] : live)
      if (!l.zombie && !doomed.count({l.p, l.s}) && holders[l.s].size() == 1 && !shared_prefix.count({l.p, l.s}) &&
          !adopted.count(slot))
        bad("crash: a committed block of a live scope was not adopted");
    if ((*a)->gens().next() <= max_gen) bad("crash: a generation after the restart is not above every live one");
    ++st.crash_checks;
    st.crash_adopted += rep->adopted_blocks;
  }
  // ---- invariants -----------------------------------------------------------------------
  void check(bool full) {
    auto chk = [&](const Status& s) {
      if (!s) bad(std::string(s.error().context));
    };
    chk(store->check_invariants());
    chk(slab->check_invariants());
    chk(mrs->check_invariants());
    if (full) chk(puts->check_invariants());
    // GenerationsUnique: no two live blocks share a generation.
    std::set<std::uint64_t> gens;
    store->for_each_block([&](const Extent& e, std::uint64_t, bool) {
      if (!gens.insert(e.gen).second) bad("GenerationsUnique: two live blocks share a generation");
    });
    // NoLeaseLeak: the store never holds more leases than the clients could still hold.
    std::size_t could = 0;
    for (const auto& l : leases)
      if (l.granted + cfg.lease_max > now()) ++could;
    if (store->n_leases() > could) bad("NoLeaseLeak: store holds leases no client can still hold");
  }

  void step() {
    const std::uint64_t r = rng.below(100);
    mixin(r);
    tr("[t=%lld] step r=%llu\n", (long long)now().count(), (unsigned long long)r);
    if (r < 7) put_start();
    else if (r < 37) put_step();
    else if (r < 47) release_exec();
    else if (r < 59) lookup();
    else if (r < 71) fetch_step();
    else if (r < 75) lease_op();
    else if (r < 79) invalidate();
    else if (r < 80 && rng.chance(0.5)) drop();
    else if (r < 82 && !roomy) evict();
    else if (r < 90) advance();
    else if (r < 93) (void)mrs->step_registration();
    else if (r < 96) stray();
    else if (r < 97) {
      endpoint_down(static_cast<int>(rng.below(clients.size())));
    } else if (r < 98) {
      end_session(clients[rng.below(clients.size())].sess);
    } else if (r < 99) {
      unknown_probe();
    } else {
      land_any();
    }
    store->tick();
    puts->tick();
  }
  void land_any() {
    if (!landings.empty()) land(rng.below(landings.size()));
  }

  void drain() {
    while (!exec.q.empty()) release_exec();
    clock.advance_by(cfg.put_timeout + seconds(1));
    store->tick();
    puts->tick();
    while (!exec.q.empty()) release_exec();
    while (mrs->step_registration().value()) {}
    check(true);
    // Tear everything down; nothing may leak.
    for (int p = 1; p <= 3; ++p) store->drop_principal(static_cast<PrincipalId>(p), Nanos{INT64_MAX / 2});
    clock.advance_by(cfg.lease_max + seconds(1));
    store->tick();
    for (int i = 0; i < 1000000 && store->sweep_pending(); ++i) store->sweep_step();  // the drops are incremental
    puts->tick();
    check(true);
    if (store->n_leases() != 0) bad("NoLeaseLeak: leases left after lease_max");
    if (store->n_zombies() != 0) bad("zombies left after every lease ended");
    if (puts->n_puts() != 0 || puts->n_limbo() != 0 || mrs->live_write_mrs() != 0) bad("put state or write MR left after the put timeout");
    for (const auto& c : slab->class_stats())
      if (c.allocated != 0) bad("slab leak: blocks still allocated with nothing committed");
  }
};

}  // namespace

StoreScenarioResult run_store_scenario(std::uint64_t seed, std::uint32_t full_every) {
  World w(seed);
  StoreScenarioResult res;
  if (!w.setup()) {
    res.ok = false;
    res.failure = "setup failed";
    return res;
  }
  const std::uint32_t steps = 300 + static_cast<std::uint32_t>(w.rng.below(200));
  for (std::uint32_t i = 0; i < steps && w.fail.empty(); ++i) {
    w.step();
    if (w.fail.empty()) w.check(full_every != 0 && i % full_every == 0);
    if (w.fail.empty() && (w.crash_rng.below(40) == 0 || i + 1 == steps)) w.crash_check();
    if (!w.fail.empty()) w.fail += " (step " + std::to_string(i) + ")";
  }
  if (w.fail.empty()) w.drain();
  res.ok = w.fail.empty();
  res.failure = w.fail;
  res.trace_hash = w.trace;
  res.stats = w.st;
  return res;
}

}  // namespace miracache::sim
