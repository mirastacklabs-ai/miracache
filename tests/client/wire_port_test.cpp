// SPDX-License-Identifier: Apache-2.0
// Client wire port against the real memory-node server (server::Server) over SimFabric, end to
// end through wire v0 frames: tickets, HELLO, SEG_TABLE, LOOKUP/RENEW/RELEASE/INVALIDATE, the
// PUT path (BEGIN -> RDMA WRITE -> COMMIT on the same QP) and RDMA READ fetch.
#include <gtest/gtest.h>

#include <unistd.h>

#include <fstream>
#include <sstream>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <map>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <vector>

#include "fabric/sim/sim_fabric.h"
#include "server/server.h"
#include "src/client.h"
#include "src/client_core.h"
#include "src/placement.h"
#include "src/wire_port.h"
#include "util/clock.h"
#include "util/log.h"
#include "util/random.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;
using std::chrono::milliseconds;
using std::chrono::seconds;
constexpr std::uint64_t kSeg = 1u << 16;

class CounterSalts final : public NonceSource {
 protected:
  Status fill(std::span<std::byte> out) override {
    // Atomic: two nodes building on their own threads share one salt source (a plain counter was a tsan race).
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

struct Chain {
  Chain(const std::string& prefix, std::size_t n) {
    for (std::size_t i = 0; i < n; ++i) {
      std::string s = prefix + std::to_string(i);
      raw.emplace_back(reinterpret_cast<const std::byte*>(s.data()),
                       reinterpret_cast<const std::byte*>(s.data()) + s.size());
    }
    for (std::size_t i = 0; i < n; ++i) {
      KeyRef r;
      r.raw = raw[i];
      if (i > 0) r.parent_raw = raw[i - 1];
      r.chain_pos = i;
      refs.push_back(r);
    }
  }
  std::vector<Bytes> raw;
  std::vector<KeyRef> refs;
};

Bytes payload(std::size_t n, int seed) {
  Bytes v(n);
  for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::byte>((i * 31 + static_cast<std::size_t>(seed) * 7 + 3) & 0xff);
  return v;
}
bool all_zero(const Bytes& b) {
  for (auto x : b)
    if (x != std::byte{0}) return false;
  return true;
}

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
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 8u << 20;
  c.principal_default.idle_ttl = seconds(100000);
  c.node_id = 1;  // HELLO_ACK node_id must equal the client's nodes[].id (WireOptions::node)
  sc.lab_identity = "lab";
  sc.lab_principal = 5;
  return sc;
}

struct Res {
  bool done = false, released = false;
  std::vector<KeyStatus> st;
};

struct World {
  explicit World(fabric::SimOptions so = {}, std::uint64_t seed = 1, std::function<std::int64_t()> wall = {})
      : rng(seed), net(clock, rng, {}, so), srv_fab(net.add_node(1)), cli(net.add_node(2)) {
    auto cfg = server_cfg();
    cfg.wall_unix_ns = std::move(wall);  // FM1: a test-controlled wall clock (null = the real one)
    auto s = server::Server::create(cfg, srv_fab, clock, rng, sex);
    EXPECT_TRUE(s);
    server = std::move(*s);
    EXPECT_TRUE(server->start());
  }

  // One server step + one network event (idle: virtual time moves).
  void drive() {
    if (!net.step()) clock.advance_by(milliseconds(1));
    server->run_once();
  }

  // Lets fire-and-forget frames (RELEASE) reach the server.
  void settle() {
    for (int i = 0; i < 64; ++i) drive();
  }

  WireOptions wire_opts() {
    WireOptions wo;
    wo.node = 1;
    wo.tickets = [this](fabric::EpClass cls) -> Expected<proto::Ticket> {
      auto t = server->issue_ticket("lab", cls, 0, 1);
      if (!t) return t.error();
      return (*t)[0];
    };
    wo.drive = [this] { drive(); };
    wo.random = &jit;
    return wo;
  }

  Status open(WireOptions wo, ClientCoreOptions o = {}) {
    port = std::make_unique<WirePort>(cli, clock, salts, std::move(wo));
    auto c = ClientCore::create(port->fabric(), *port, clock, cex, salts, o);
    if (!c) return c.error();
    core = std::move(*c);
    return {};
  }
  Status open() { return open(wire_opts()); }

  Notify notify(Res& r) {
    return Notify{[&r](Ticket, std::span<const KeyStatus> s) { r.done = true, r.st.assign(s.begin(), s.end()); },
                  [&r](Ticket) { r.released = true; }};
  }
  template <class P>
  bool spin(P pred, int cap = 400000) {
    for (int i = 0; i < cap; ++i) {
      core->pump();
      if (pred()) return true;
      drive();
    }
    return false;
  }
  std::vector<KeyStatus> put(const ScopeKeys& sk, const Chain& ch, std::vector<Bytes>& data) {
    std::vector<BufRef> bufs;
    for (auto& d : data) bufs.push_back({std::span<std::byte>(d)});
    Res r;
    core->submit_store(sk, 0, ch.refs, bufs, clock.now() + seconds(5), notify(r));
    EXPECT_TRUE(spin([&] { return r.released; }));
    return r.st;
  }
  std::vector<KeyStatus> fetch(const ScopeKeys& sk, const Chain& ch, std::vector<Bytes>& out) {
    std::vector<BufRef> bufs;
    for (auto& d : out) bufs.push_back({std::span<std::byte>(d)});
    Res r;
    core->submit_fetch(sk, 0, ch.refs, bufs, clock.now() + seconds(5), notify(r));
    EXPECT_TRUE(spin([&] { return r.released; }));
    return r.st;
  }
  void check() {
    auto s = core->check_invariants();
    EXPECT_TRUE(s) << s.error().context;
    auto a = server->check_invariants();
    EXPECT_TRUE(a) << a.error().context;
  }

  SimClock clock;
  SeededRandom rng;
  SeededRandom jit{99};
  fabric::SimNetwork net;
  fabric::SimFabric& srv_fab;
  fabric::SimFabric& cli;
  InlineExecutor sex, cex;
  CounterSalts salts;
  std::unique_ptr<server::Server> server;
  std::unique_ptr<WirePort> port;
  std::unique_ptr<ClientCore> core;
};

fabric::SimOptions sliced(std::uint32_t slice, bool iwarp) {
  fabric::SimOptions o;
  o.slice_size = slice;
  o.iwarp_early_write_cqe = iwarp;
  return o;
}

store::ScopeId store_scope(const ScopeKeys& sk) {
  store::ScopeId o;
  std::memcpy(o.data(), sk.scopes[0].b, 32);
  return o;
}
store::KeyHash store_key(const ScopeKeys& sk, const Bytes& raw) {
  auto h = sk.keys->key_hash(raw);
  store::KeyHash o;
  std::memcpy(o.data(), h->b, 32);
  return o;
}

TEST(WirePort, PutLookupFetchRoundTripAndMiss) {
  for (bool iwarp : {false, true}) {
    World w(sliced(1024, iwarp), 11);
    ASSERT_TRUE(w.open());
    EXPECT_EQ(w.server->n_conns(), 3u);  // control + fetch + ingest, one session
    EXPECT_GE(w.port->table_gen(), 1u);
    auto sk = scope_keys(1);
    const std::size_t sizes[] = {1, kSeg, kSeg * 3 + kSeg / 2};
    Chain ch("k", 3);
    std::vector<Bytes> data, out;
    for (int i = 0; i < 3; ++i) {
      data.push_back(payload(sizes[i], i));
      out.emplace_back(sizes[i], std::byte{0xAA});
    }
    for (auto s : w.put(sk, ch, data)) EXPECT_EQ(s, KeyStatus::Committed);
    w.check();
    auto fs = w.fetch(sk, ch, out);
    for (int i = 0; i < 3; ++i) {
      EXPECT_EQ(fs[i], KeyStatus::Hit) << i << " iwarp=" << iwarp;
      EXPECT_EQ(out[i], data[i]) << i;
    }
    EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
    w.settle();
    EXPECT_EQ(w.server->store().n_leases(), 0u);  // RELEASE took effect
    for (auto s : w.put(sk, ch, data)) EXPECT_EQ(s, KeyStatus::Skipped);  // idempotent re-put
    // A miss zeroes the buffer.
    Chain none("nokey", 2);
    std::vector<Bytes> o2{Bytes(5000, std::byte{0xAA}), Bytes(100, std::byte{0xAA})};
    auto ms = w.fetch(sk, none, o2);
    EXPECT_EQ(ms[0], KeyStatus::Miss);
    EXPECT_TRUE(all_zero(o2[0]) && all_zero(o2[1]));
    w.check();
  }
}

TEST(WirePort, InvalidateDropsTheBlock) {
  World w;
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(9000, 1)}, out{Bytes(9000, std::byte{0xAA})};
  ASSERT_EQ(w.put(sk, ch, data)[0], KeyStatus::Committed);
  ASSERT_EQ(w.fetch(sk, ch, out)[0], KeyStatus::Hit);

  store::LookupReq q;
  q.scope = store_scope(sk);
  q.keys = {store_key(sk, ch.raw[0])};
  auto ack = w.port->lookup(q);
  ASSERT_EQ(ack.entries.size(), 1u);
  ASSERT_TRUE(ack.entries[0].hit);
  ASSERT_NE(ack.lease, 0u);
  EXPECT_TRUE(w.port->renew(ack.lease));
  EXPECT_TRUE(w.port->release(ack.lease));
  // Wrong generation: a no-op that still succeeds; the block stays.
  EXPECT_TRUE(w.port->invalidate(q.scope, q.keys[0], ack.entries[0].gen + 1));
  out[0].assign(9000, std::byte{0xAA});
  EXPECT_EQ(w.fetch(sk, ch, out)[0], KeyStatus::Hit);
  EXPECT_TRUE(w.port->invalidate(q.scope, q.keys[0], ack.entries[0].gen));
  out[0].assign(9000, std::byte{0xAA});
  EXPECT_EQ(w.fetch(sk, ch, out)[0], KeyStatus::Miss);
  EXPECT_TRUE(all_zero(out[0]));
  // STATS round trip on the control endpoint.
  EXPECT_TRUE(w.port->stats(0));
  w.check();
}

TEST(WirePort, TicketReuseAndClassMismatchRefused) {
  World w;
  // One ticket per class, then the fetch endpoint replays the control ticket's id.
  proto::Ticket first{};
  bool have = false;
  WireOptions wo = w.wire_opts();
  wo.ticket_attempts = 2;
  wo.tickets = [&](fabric::EpClass cls) -> Expected<proto::Ticket> {
    if (cls == fabric::EpClass::Control) {
      auto t = w.server->issue_ticket("lab", cls, 0, 1);
      first = (*t)[0], have = true;
      return first;
    }
    return first;  // already redeemed by the control endpoint
  };
  auto s = w.open(std::move(wo));
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::AccessDenied);
  EXPECT_TRUE(have);
  // An unknown identity cannot get a ticket at all, so nothing connects.
  WireOptions wo2 = w.wire_opts();
  wo2.tickets = [&](fabric::EpClass cls) -> Expected<proto::Ticket> {
    auto t = w.server->issue_ticket("stranger", cls, 0, 1);
    if (!t) return t.error();
    return (*t)[0];
  };
  auto s2 = w.open(std::move(wo2));
  ASSERT_FALSE(s2);
  EXPECT_EQ(s2.error().code, ErrorCode::AccessDenied);
}

// The COMMIT rides the ingest QP after the WRITEs. With slicing and early iWARP write CQEs, a
// COMMIT that raced the placement would fail the server digest; so every put commits.
TEST(WirePort, CommitOrderedAfterWritesAcrossSeeds) {
  for (std::uint64_t seed = 1; seed <= 8; ++seed) {
    World w(sliced(512, seed % 2 == 0), seed);
    ASSERT_TRUE(w.open());
    auto sk = scope_keys(1);
    Chain ch("k", 4);
    std::vector<Bytes> data, out;
    for (std::size_t i = 0; i < 4; ++i) {
      data.push_back(payload(1 + w.rng.below(kSeg * 3), static_cast<int>(i)));
      out.emplace_back(data.back().size(), std::byte{0xAA});
    }
    for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed) << seed;
    auto fs = w.fetch(sk, ch, out);
    for (std::size_t i = 0; i < 4; ++i) {
      EXPECT_EQ(fs[i], KeyStatus::Hit) << seed;
      EXPECT_EQ(out[i], data[i]) << seed;
    }
    w.check();
  }
}

// Cut the link at every step of a put: the job must always end (no hang), nothing may report
// bytes that were not committed, and later work fails cleanly.
// The 60 cut points run as 6 blocks of 10 (ctest runs the blocks in parallel; the cuts are independent worlds with their
// own seeds). Block 0 holds cut 0, where the link dies right after submit, so it must abort at least one key.
class EndpointDropMidPut : public ::testing::TestWithParam<int> {};

TEST_P(EndpointDropMidPut, FailsCleanly) {
  std::uint64_t aborted = 0, committed = 0;
  for (int cut = GetParam() * 10; cut < GetParam() * 10 + 10; ++cut) {
    World w(sliced(1024, false), 100 + static_cast<std::uint64_t>(cut));
    ASSERT_TRUE(w.open());
    auto sk = scope_keys(1);
    Chain ch("k", 2);
    std::vector<Bytes> data{payload(kSeg * 2, 1), payload(kSeg, 2)};
    std::vector<BufRef> bufs;
    for (auto& d : data) bufs.push_back({std::span<std::byte>(d)});
    Res r;
    w.core->submit_store(sk, 0, ch.refs, bufs, w.clock.now() + seconds(5), w.notify(r));
    for (int i = 0; i < cut && !r.released; ++i) {
      w.core->pump();
      w.drive();
    }
    w.net.set_link(1, 2, false);
    ASSERT_TRUE(w.spin([&] { return r.released; })) << "hang at cut " << cut;
    for (auto s : r.st) (s == KeyStatus::Committed ? committed : aborted) += 1;
    EXPECT_EQ(w.core->pool_bytes_in_use(), 0u) << cut;
    if (r.st.size() == 2 && r.st[0] != KeyStatus::Committed) EXPECT_NE(r.st[1], KeyStatus::Committed) << cut;
    // The control or ingest endpoint is gone: a new put and a fetch fail without hanging.
    std::vector<Bytes> out{Bytes(kSeg * 2, std::byte{0xAA}), Bytes(kSeg, std::byte{0xAA})};
    Res f;
    std::vector<BufRef> fb;
    for (auto& d : out) fb.push_back({std::span<std::byte>(d)});
    w.core->submit_fetch(sk, 0, ch.refs, fb, w.clock.now() + seconds(5), w.notify(f));
    ASSERT_TRUE(w.spin([&] { return f.released; })) << cut;
    for (std::size_t i = 0; i < 2; ++i)
      if (f.st[i] != KeyStatus::Hit) EXPECT_TRUE(all_zero(out[i]));
  }
  if (GetParam() == 0) EXPECT_GT(aborted, 0u);
  EXPECT_GT(aborted + committed, 0u) << "block " << GetParam() << " ran no key to an end";  // s11c review P3-7
}
INSTANTIATE_TEST_SUITE_P(Blocks, EndpointDropMidPut, ::testing::Range(0, 6));

TEST(WirePort, GoawayMakesLaterWorkFailCleanly) {
  World w;
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(4000, 1)}, out{Bytes(4000, std::byte{0xAA})};
  ASSERT_EQ(w.put(sk, ch, data)[0], KeyStatus::Committed);
  w.server->goaway(proto::GoawayReason::Shutdown, 100);
  ASSERT_TRUE(w.spin([&] { return w.port->goaway_received(); }));
  EXPECT_EQ(w.fetch(sk, ch, out)[0], KeyStatus::Miss);  // lookups fail: the engine recomputes
  EXPECT_TRUE(all_zero(out[0]));
  Chain c2("z", 1);
  EXPECT_EQ(w.put(sk, c2, data)[0], KeyStatus::Refused);
}

// Rogue writer scribbling committed extents while fetches are in flight: every fetch is an
// exact HIT or a MISS with a zeroed buffer, through the wire port. AEAD misses INVALIDATE.
TEST(WirePort, SeededRogueWriterNeverYieldsWrongBytes) {
  std::uint64_t hits = 0, misses = 0, scribbles = 0;
  for (std::uint64_t seed = 1; seed <= 6; ++seed) {
    World w(sliced(512, seed % 2 == 0), seed);
    ASSERT_TRUE(w.open());
    auto sk = scope_keys(1);
    const std::size_t n = 6;
    Chain ch("k", n);
    std::vector<Bytes> data;
    for (std::size_t i = 0; i < n; ++i) data.push_back(payload(1 + w.rng.below(kSeg * 3), static_cast<int>(i)));
    for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed) << seed;
    w.check();
    for (int round = 0; round < 6; ++round) {
      std::vector<Bytes> out;
      for (auto& d : data) out.emplace_back(d.size(), std::byte{0xAA});
      std::vector<BufRef> bufs;
      for (auto& o : out) bufs.push_back({std::span<std::byte>(o)});
      Res r;
      w.core->submit_fetch(sk, 0, ch.refs, bufs, w.clock.now() + seconds(5), w.notify(r));
      std::vector<store::Extent> exts;
      w.server->store().for_each_block([&](const store::Extent& e, std::uint64_t, bool) { exts.push_back(e); });
      for (int i = 0; i < 400000 && !r.released; ++i) {
        w.core->pump();
        if (r.released) break;
        if (round >= 2 && !exts.empty() && w.rng.below(40) == 0) {
          const auto& e = exts[w.rng.below(exts.size())];
          auto blk = w.server->arena().block(e.seg, e.off, e.len);
          blk[w.rng.below(blk.size())] ^= std::byte{0x5a};
          ++scribbles;
        }
        w.drive();
      }
      ASSERT_TRUE(r.released) << seed;
      ASSERT_TRUE(r.done);
      for (std::size_t i = 0; i < n; ++i) {
        if (r.st[i] == KeyStatus::Hit) {
          ++hits;
          EXPECT_EQ(out[i], data[i]) << "wrong bytes: seed " << seed << " round " << round << " key " << i;
        } else {
          ++misses;
          EXPECT_EQ(r.st[i], KeyStatus::Miss);
          EXPECT_TRUE(all_zero(out[i])) << "unzeroed miss: seed " << seed << " key " << i;
        }
      }
      EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
      w.settle();
      EXPECT_EQ(w.server->store().n_leases(), 0u);
    }
  }
  EXPECT_GT(hits, 0u);
  EXPECT_GT(misses, 0u);
  EXPECT_GT(scribbles, 0u);
}

// Facade: Client::open_wire over the sim, worker threads drive the core.
TEST(WireClient, OpenWireFacadeStoreThenFetch) {
  World w(sliced(2048, true), 21);
  Client::Env env;
  env.fab = &w.cli;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  auto cl = Client::open_wire(env, w.wire_opts());
  ASSERT_TRUE(cl);
  Client& c = **cl;
  ASSERT_NE(c.wire_port(), nullptr);
  auto sk = scope_keys(1);
  Chain ch("k", 2);
  std::vector<Bytes> data{payload(kSeg, 2), payload(kSeg * 2 + 5, 3)};
  std::vector<Bytes> out;
  for (auto& d : data) out.emplace_back(d.size(), std::byte{0xAA});
  std::vector<BufRef> pbufs, fbufs;
  for (auto& d : data) pbufs.push_back({std::span<std::byte>(d)});
  for (auto& o : out) fbufs.push_back({std::span<std::byte>(o)});
  auto wait = [&](Ticket t) {
    std::array<Completion, 4> comp;
    // Wall-clock bound, not an iteration count: yields finish fast when ctest -j2 starves the workers.
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion";
    return Completion{};
  };
  auto sc = wait(c.store(sk, 0, ch.refs, pbufs, seconds(5)));
  for (auto s : sc.status) EXPECT_EQ(s, KeyStatus::Committed);
  auto fc = wait(c.fetch(sk, 0, ch.refs, fbufs, seconds(5)));
  for (auto s : fc.status) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(out[0], data[0]);
  EXPECT_EQ(out[1], data[1]);
  c.shutdown();
}

// ---- Fake memory node: scripted replies for failure-mode tests (review r3 W/S findings) ------
// Speaks just enough wire v0 over a SimFabric node: HELLO (+ initial SEG_TABLE), PING -> PONG,
// and a per-frame hook for everything else. `silent` ignores every frame except HELLO.
struct Fake {
  struct Rx {
    fabric::EndpointId ep;
    fabric::EpClass cls;
    proto::FrameHeader h;
    Bytes body;
  };
  explicit Fake(fabric::SimFabric& f) : fab(f) {
    auto pd = fab.alloc_pd();
    pd_ = *pd;
    seg.assign(64 * 1024, std::byte{0});
    arr.assign(8 * 1024, std::byte{0});
    tiny.assign(8, std::byte{0});
    seg_mr = *fab.reg(seg, fabric::Access::RemoteRead, pd_);
    arr_mr = *fab.reg(arr, fabric::Access::RemoteRead, pd_);
    tiny_mr = *fab.reg(tiny, fabric::Access::RemoteRead, pd_);
    fabric::ListenParams lp;
    lp.admit = [this](std::span<const std::byte> priv) -> Expected<fabric::Admission> {
      auto t = proto::decode_ticket(priv);
      if (!t) return Error{ErrorCode::AccessDenied, "fake: bad ticket"};
      return fabric::Admission{static_cast<fabric::EpClass>(t->cls), pd_};
    };
    EXPECT_TRUE(fab.listen([this](fabric::Endpoint* e) { eps[e->id()] = e; }, lp));
  }

  void send(fabric::EndpointId id, proto::Op op, std::uint64_t rid, std::span<const std::byte> body) {
    std::array<std::byte, proto::kMaxFrameSize> buf{};
    auto n = proto::encode_frame(proto::header_for(op, rid), body, buf);
    ASSERT_TRUE(n.has_value());
    fabric::Frame f;
    f.bytes.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*n));
    ASSERT_TRUE(eps.at(id)->post_send(std::move(f), 0));
  }
  proto::SegTable table(std::uint32_t gen, bool tiny_array = false) const {
    proto::SegTable t;
    t.n = 1;
    t.table_gen = gen;
    t.e[0].seg_id = 0;
    t.e[0].base = reinterpret_cast<std::uint64_t>(seg_mr.addr);
    t.e[0].len = seg_mr.len;
    t.e[0].rkey[0] = seg_mr.rkey;
    const auto& a = tiny_array ? tiny_mr : arr_mr;
    t.sg_base = reinterpret_cast<std::uint64_t>(a.addr);
    t.sg_slots = a.len / 8;
    t.sg_rkey[0] = a.rkey;
    return t;
  }
  void send_table(fabric::EndpointId id, const proto::SegTable& t) {
    auto body = std::make_unique<std::array<std::byte, proto::kMaxBodyLen>>();
    auto n = proto::encode_seg_table(t, *body);
    ASSERT_TRUE(n.has_value());
    send(id, proto::Op::SEG_TABLE, 0, std::span<const std::byte>(body->data(), *n));
  }
  fabric::EndpointId ep_of(fabric::EpClass c) const {
    for (auto& [id, cl] : cls)
      if (cl == c) return id;
    return 0;
  }
  std::size_t count(proto::Op op) const {
    std::size_t n = 0;
    for (auto& r : seen) n += r.h.type == static_cast<std::uint16_t>(op);
    return n;
  }

  void step() {
    std::array<fabric::Completion, 32> out;
    const std::size_t n = fab.poll(out, {});
    for (std::size_t i = 0; i < n; ++i) {
      auto& c = out[i];
      if (!c.is_recv) continue;
      auto fr = proto::decode_frame(c.frame.bytes);
      if (!fr) continue;
      const auto op = static_cast<proto::Op>(fr->h.type);
      if (op == proto::Op::HELLO) {
        auto m = proto::decode_hello(fr->h, fr->body);
        if (!m) continue;
        if (ignore_hello) continue;
        cls[c.endpoint] = static_cast<fabric::EpClass>(m->cls);
        hello_mtu = m->mtu;
        hello_proto = m->proto;
        std::array<std::byte, proto::kMaxBodyLen> body{};
        auto ack = *m;
        ack.tlvs = {};
        ack.node_id = node_id;
        auto k = proto::encode_hello_ack(ack, body);
        send(c.endpoint, proto::Op::HELLO_ACK, fr->h.request_id, std::span<const std::byte>(body.data(), *k));
        send_table(c.endpoint, table(1));
        continue;
      }
      if (silent) continue;
      seen.push_back(Rx{c.endpoint, cls[c.endpoint], fr->h, Bytes(fr->body.begin(), fr->body.end())});
      if (op == proto::Op::PING) {
        send(c.endpoint, proto::Op::PONG, fr->h.request_id, fr->body);
        continue;
      }
      if (hook) hook(*this, seen.back());
    }
  }

  fabric::SimFabric& fab;
  fabric::PdId pd_;
  std::map<fabric::EndpointId, fabric::Endpoint*> eps;
  std::map<fabric::EndpointId, fabric::EpClass> cls;
  std::vector<Rx> seen;
  std::function<void(Fake&, const Rx&)> hook;
  bool silent = false;
  bool ignore_hello = false;     // a memnode that accepts connections but never answers HELLO
  std::uint32_t node_id = 1;     // HELLO_ACK node_id (the client's WireOptions::node is 1)
  std::uint32_t hello_mtu = 0;   // what the last HELLO carried
  std::uint8_t hello_proto = 0;
  Bytes seg, arr, tiny;
  fabric::MemRegion seg_mr, arr_mr, tiny_mr;
};

// Forwards to another Fabric and counts failed READ completions.
class CountingFabric final : public fabric::Fabric {
 public:
  explicit CountingFabric(fabric::Fabric& in) : in_(in) {}
  Expected<fabric::DeviceCaps> probe() override { return in_.probe(); }
  Expected<fabric::PdId> alloc_pd() override { return in_.alloc_pd(); }
  Status free_pd(fabric::PdId pd) override { return in_.free_pd(pd); }
  Expected<fabric::MemRegion> reg(std::span<std::byte> b, fabric::Access a, fabric::PdId pd) override { return in_.reg(b, a, pd); }
  Status dereg(const fabric::MemRegion& r) override { return in_.dereg(r); }
  Expected<fabric::Endpoint*> connect(const fabric::Peer& p, const fabric::ConnParams& c) override { return in_.connect(p, c); }
  Status release(fabric::Endpoint* e) override { return in_.release(e); }
  Status listen(fabric::AcceptFn f, const fabric::ListenParams& lp) override { return in_.listen(std::move(f), lp); }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget b) override {
    const std::size_t n = in_.poll(out, b);
    for (std::size_t i = 0; i < n; ++i)
      if (out[i].op == fabric::CompletionOp::Read && !out[i].status) ++failed_reads;
    return n;
  }
  int wait_fd() override { return in_.wait_fd(); }
  unsigned failed_reads = 0;

 private:
  fabric::Fabric& in_;
};

struct FW {
  FW() : rng(3), net(clock, rng, {}, {}), fake_fab(net.add_node(1)), cli(net.add_node(2)), fake(fake_fab) {}
  void drive() {
    if (!net.step()) clock.advance_by(milliseconds(1));
    fake.step();
    if (after_step) after_step();
  }
  std::function<void()> after_step;  // runs at the end of every drive() (a test's scripted delivery)
  WireOptions opts() {
    WireOptions wo;
    wo.node = 1;
    wo.tickets = [](fabric::EpClass cls) -> Expected<proto::Ticket> {
      proto::Ticket t;
      t.cls = static_cast<std::uint8_t>(cls);
      return t;
    };
    wo.drive = [this] { drive(); };
    wo.random = &jit;
    wo.keepalive_ms = 0;
    wo.rpc_timeout = rpc_timeout;
    return wo;
  }
  Nanos rpc_timeout = seconds(5);
  Status open_core() {
    port = std::make_unique<WirePort>(cli, clock, salts, opts());
    counting = std::make_unique<CountingFabric>(port->fabric());
    auto c = ClientCore::create(*counting, *port, clock, cex, salts, {});
    if (!c) return c.error();
    core = std::move(*c);
    return {};
  }
  void open_port() {
    port = std::make_unique<WirePort>(cli, clock, salts, opts());
    ASSERT_TRUE(port->hello());
  }
  Notify notify(Res& r) {
    return Notify{[&r](Ticket, std::span<const KeyStatus> s) { r.done = true, r.st.assign(s.begin(), s.end()); },
                  [&r](Ticket) { r.released = true; }};
  }
  // Fetches one key with a relative deadline; returns the virtual time spent.
  Nanos fetch_one(Res& r, Bytes& out, Nanos deadline) {
    auto sk = scope_keys(1);
    Chain ch("fw", 1);
    std::vector<BufRef> bufs{{std::span<std::byte>(out)}};
    const Nanos t0 = clock.now();
    core->submit_fetch(sk, 0, ch.refs, bufs, t0 + deadline, notify(r));
    for (int i = 0; i < 100000 && !r.released; ++i) {
      core->pump();
      drive();
    }
    EXPECT_TRUE(r.released);
    return clock.now() - t0;
  }
  void pump_port(int rounds = 200) {
    for (int i = 0; i < rounds; ++i) {
      std::array<fabric::Completion, 8> buf;
      port->fabric().poll(buf, {});
      drive();
    }
  }
  // Answers a LOOKUP with a scripted ack (n_override 0 = same n as the request).
  static void reply_lookup(Fake& f, const Fake::Rx& rx, std::uint64_t lease, std::uint16_t n_override, std::uint64_t stored_len,
                           bool hit, std::uint64_t gen_slot = 0) {
    auto q = proto::decode_lookup(rx.h, rx.body);
    ASSERT_TRUE(q.has_value());
    auto a = std::make_unique<proto::LookupAck>();
    a->lease_id = lease;
    a->ttl_ms = 60000;
    a->n = n_override ? n_override : q->n;
    for (std::size_t i = 0; hit && i < a->n; ++i) {
      a->e[i].status = 1;
      a->e[i].stored_len = stored_len;
      a->e[i].gen = 1;
      a->e[i].gen_slot = gen_slot;
    }
    auto body = std::make_unique<std::array<std::byte, proto::kMaxBodyLen>>();
    auto k = proto::encode_lookup_ack(*a, *body);
    ASSERT_TRUE(k.has_value());
    f.send(rx.ep, proto::Op::LOOKUP_ACK, rx.h.request_id, std::span<const std::byte>(body->data(), *k));
  }

  SimClock clock;
  SeededRandom rng;
  SeededRandom jit{5};
  fabric::SimNetwork net;
  fabric::SimFabric& fake_fab;
  fabric::SimFabric& cli;
  Fake fake;
  InlineExecutor cex;
  CounterSalts salts;
  std::unique_ptr<WirePort> port;
  std::unique_ptr<CountingFabric> counting;
  std::unique_ptr<ClientCore> core;
};

store::LookupReq one_key_req() {
  store::LookupReq q;
  q.scope.fill(0x42);
  store::KeyHash k;
  k.fill(0x17);
  q.keys.push_back(k);
  return q;
}

// W01: control RPCs honour the job deadline; a dead control plane costs ~deadline once, later
// jobs fail fast, and everything recovers when the server answers again.
TEST(WireFailure, UnansweredLookupHonoursJobDeadlineThenFailsFastThenRecovers) {
  FW w;
  w.rpc_timeout = milliseconds(50);  // R02: only a wait that used the whole rpc_timeout makes control suspect
  ASSERT_TRUE(w.open_core());
  w.fake.hook = [](Fake& f, const Fake::Rx& rx) {
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::LOOKUP)) FW::reply_lookup(f, rx, 0, 0, 0, false);
  };
  w.fake.silent = true;
  Bytes out(4000, std::byte{0xAA});
  Res r1;
  const Nanos e1 = w.fetch_one(r1, out, seconds(2));
  EXPECT_LT(e1, milliseconds(120)) << "first job must give up at rpc_timeout (50 ms here), not at its 2 s deadline";
  ASSERT_EQ(r1.st.size(), 1u);
  EXPECT_NE(r1.st[0], KeyStatus::Hit);
  EXPECT_TRUE(w.port->control_suspect());
  Res r2;
  const Nanos e2 = w.fetch_one(r2, out, seconds(2));
  EXPECT_LT(e2, milliseconds(20)) << "control is suspect: the second job must not wait";
  EXPECT_EQ(r2.st[0], KeyStatus::Miss);
  // RENEW is fire-and-forget: it never waits, even on a silent server.
  const Nanos t0 = w.clock.now();
  (void)w.port->renew(123);
  EXPECT_LT(w.clock.now() - t0, milliseconds(5));
  // The server answers again: any frame (PONG) clears suspect and the next job's LOOKUP goes out.
  w.fake.silent = false;
  for (int i = 0; i < 4000 && w.port->control_suspect(); ++i) {
    w.core->pump();
    w.drive();
  }
  EXPECT_FALSE(w.port->control_suspect());
  const std::size_t lookups = w.fake.count(proto::Op::LOOKUP);
  Res r3;
  const Nanos e3 = w.fetch_one(r3, out, seconds(2));
  EXPECT_LT(e3, milliseconds(50));
  EXPECT_GT(w.fake.count(proto::Op::LOOKUP), lookups);
  EXPECT_EQ(r3.st[0], KeyStatus::Miss);
}

// G12: a single-rail port sends at most one PING per keepalive period, however often it ticks (a node's thread ticks
// every 5 ms while it waits on a planned rebuild); keepalive_ms 0 keeps the old "every tick".
TEST(WireFailure, SingleRailPingsOncePerKeepalivePeriod) {
  FW w;
  auto wo = w.opts();
  wo.keepalive_ms = 100;
  w.port = std::make_unique<WirePort>(w.cli, w.clock, w.salts, std::move(wo));
  ASSERT_TRUE(w.port->hello());
  const auto p0 = w.port->pings_sent();
  for (int i = 0; i < 18; ++i) {  // 18 ticks 5 ms apart: 90 ms, inside one period
    w.port->keepalive();
    w.clock.advance_by(milliseconds(5));
  }
  EXPECT_EQ(w.port->pings_sent(), p0 + 1) << "one PING in the first period";
  w.clock.advance_by(milliseconds(10));  // the period is over
  w.port->keepalive();
  w.port->keepalive();
  EXPECT_EQ(w.port->pings_sent(), p0 + 2);
  w.port->release_endpoints();
}

// S01/S02 (client part): an idle client polls on keepalive ticks, so five unsolicited
// SEG_TABLE pushes (a 2-slot fetch endpoint on real NICs) are consumed, and PINGs are answered.
// (SimFabric has no receive-slot limit: "consumed" is what the idle poll changes.)
TEST(WireFailure, IdleKeepaliveConsumesUnsolicitedPushes) {
  FW w;
  ASSERT_TRUE(w.open_core());
  ASSERT_EQ(w.port->table_gen(), 1u);
  const auto fetch_id = w.fake.ep_of(fabric::EpClass::Fetch);
  ASSERT_NE(fetch_id, 0u);
  w.fake.send_table(fetch_id, w.fake.table(2));
  for (int i = 0; i < 50; ++i) w.drive();
  EXPECT_EQ(w.port->table_gen(), 1u) << "without a poll the push sits unconsumed";
  for (std::uint32_t g = 2; g <= 6; ++g) {
    if (g > 2) w.fake.send_table(fetch_id, w.fake.table(g));
    for (int i = 0; i < 50; ++i) w.drive();
    w.port->keepalive();  // what the Client's keepalive thread does under core_mu
    w.core->pump();
    EXPECT_EQ(w.port->table_gen(), g) << "push " << g << " not consumed by the idle client";
  }
  EXPECT_TRUE(w.port->healthy());
  EXPECT_GE(w.port->pings_sent(), 5u);
  for (int i = 0; i < 50; ++i) w.drive();
  w.port->keepalive();
  EXPECT_GE(w.port->pongs_received(), 5u);
}

// S01: the Client's keepalive thread PINGs at the configured period and shuts down cleanly.
TEST(WireClient, KeepaliveThreadPingsAtConfiguredRate) {
  FW w;
  Client::Env env;
  env.fab = &w.cli;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  // G12: the port sends one PING per keepalive period of ITS clock, so that clock follows real time here (an idle
  // Up node's thread drives the sim once per tick (R12, env.drive_when_up below), which moves the SimClock by at most
  // 1 ms a tick: with that clock nearly every tick would fall inside the first period).
  // Q13: the sim (network, SimClock) is single-threaded by contract. The test thread used to call w.clock.advance_to
  // itself while the keepalive thread posted PINGs: SimEndpoint::submit reads net.now() twice, and an advance between
  // the reads made `due - now` negative and tripped MIRACACHE_CHECK(delay >= 0) in SimNetwork::schedule(). Now nothing
  // moves the SimClock during the run; the client (port, keepalive) gets its own clock that follows real time.
  struct FollowClock final : Clock {
    explicit FollowClock(Nanos base) : base_(base), real0_(std::chrono::steady_clock::now()) {}
    Nanos now() const override {
      return base_ + std::chrono::duration_cast<Nanos>(std::chrono::steady_clock::now() - real0_);
    }
    Nanos base_;
    std::chrono::steady_clock::time_point real0_;
  } follow(w.clock.now());
  env.clock = &follow;
  env.drive = [&] { w.drive(); };
  env.drive_when_up = true;  // R12: this test thread never touches the sim while the client runs
  auto wo = w.opts();
  wo.keepalive_ms = 20;
  auto cl = Client::open_wire(env, wo);
  ASSERT_TRUE(cl);
  // From here only the keepalive thread touches the sim (try_lock on the core lock); this thread only waits.
  std::this_thread::sleep_for(milliseconds(400));
  const auto sent = (*cl)->wire_port()->pings_sent();
  EXPECT_GE(sent, 5u);
  EXPECT_LE(sent, 25u);
  EXPECT_GE((*cl)->keepalive_ticks(), 5u);
  // R12 (review s11): the PONGs come back. The idle Up node's keepalive tick drives the sim itself (the test thread may
  // not, Q13), so its PINGs reach the server and the answers arrive. Polled (A-2): a slow tsan run may not have the
  // first PONG back after the fixed 400 ms above.
  const auto pong_cap = std::chrono::steady_clock::now() + seconds(5);
  while ((*cl)->wire_port()->pongs_received() < 1u && std::chrono::steady_clock::now() < pong_cap)
    std::this_thread::sleep_for(milliseconds(5));
  EXPECT_GE((*cl)->wire_port()->pongs_received(), 1u);
  (*cl)->shutdown();
  const auto after = (*cl)->wire_port()->pings_sent();
  std::this_thread::sleep_for(milliseconds(60));
  EXPECT_EQ((*cl)->wire_port()->pings_sent(), after) << "keepalive thread must be stopped by shutdown";
}

TEST(WireClient, KeepaliveZeroStartsNoThread) {
  FW w;
  Client::Env env;
  env.fab = &w.cli;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  auto cl = Client::open_wire(env, w.opts());  // keepalive_ms = 0
  ASSERT_TRUE(cl);
  std::this_thread::sleep_for(milliseconds(100));
  EXPECT_EQ((*cl)->keepalive_ticks(), 0u);
}

// W02: a smaller array in a newer SEG_TABLE (arriving between the lookup and the data READ
// completion) must not send the seq READ past the new array: miss, endpoint stays healthy.
TEST(WireFailure, SeqReadRechecksGenSlotAgainstCurrentArray) {
  FW w;
  ASSERT_TRUE(w.open_core());
  const std::uint64_t stored = layout(4000, 16)->stored_len;
  w.fake.hook = [stored](Fake& f, const Fake::Rx& rx) {
    if (rx.h.type != static_cast<std::uint16_t>(proto::Op::LOOKUP)) return;
    FW::reply_lookup(f, rx, 0, 0, stored, true, /*gen_slot=*/5);
    f.send_table(f.ep_of(fabric::EpClass::Control), f.table(2, /*tiny_array=*/true));  // 1-slot array
  };
  Bytes out(4000, std::byte{0xAA});
  Res r;
  w.fetch_one(r, out, seconds(2));
  EXPECT_EQ(r.st[0], KeyStatus::Miss);
  EXPECT_EQ(w.counting->failed_reads, 0u) << "the seq READ went past the new, smaller array";
  auto s = w.core->check_invariants();
  EXPECT_TRUE(s) << (s ? "" : s.error().context);
}

// W03: a decoded LOOKUP_ACK that is rejected still has its lease RELEASEd.
TEST(WireFailure, RejectedLookupAckReleasesTheLease) {
  FW w;
  w.open_port();
  w.fake.hook = [](Fake& f, const Fake::Rx& rx) {
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::LOOKUP)) FW::reply_lookup(f, rx, 77, /*n=*/2, 0, false);
  };
  auto ack = w.port->lookup(one_key_req());  // ack has 2 entries for 1 key
  EXPECT_TRUE(ack.entries.empty());
  w.pump_port();
  ASSERT_EQ(w.fake.count(proto::Op::RELEASE), 1u);
  for (auto& rx : w.fake.seen)
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::RELEASE))
      EXPECT_EQ(proto::decode_release(rx.h, rx.body)->lease_id, 77u);
}

// W05: stored_len >= 4 GiB is a malformed reply: miss, lease released, no INVALIDATE.
TEST(WireFailure, HugeStoredLenIsAMalformedReplyNotAHit) {
  FW w;
  w.open_port();
  w.fake.hook = [](Fake& f, const Fake::Rx& rx) {
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::LOOKUP))
      FW::reply_lookup(f, rx, 78, 0, std::uint64_t{1} << 33, true);
  };
  auto ack = w.port->lookup(one_key_req());
  EXPECT_TRUE(ack.entries.empty());
  w.pump_port();
  EXPECT_EQ(w.fake.count(proto::Op::RELEASE), 1u);
  EXPECT_EQ(w.fake.count(proto::Op::INVALIDATE), 0u);
}

// W06: presence probes send LOOKUP flags=0 and never RELEASE.
TEST(WireFailure, ProbeSendsNoLeaseAndNoRelease) {
  FW w;
  ASSERT_TRUE(w.open_core());
  w.fake.hook = [](Fake& f, const Fake::Rx& rx) {
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::LOOKUP)) FW::reply_lookup(f, rx, 0, 0, 4096, true);
  };
  auto sk = scope_keys(1);
  Chain ch("pr", 1);
  std::vector<KeyStatus> st;
  w.core->probe(sk, 0, ch.refs, w.clock.now() + seconds(2),
                [&](Ticket, std::span<const KeyStatus> s) { st.assign(s.begin(), s.end()); });
  ASSERT_EQ(st.size(), 1u);
  EXPECT_EQ(st[0], KeyStatus::Hit);
  w.pump_port();
  ASSERT_EQ(w.fake.count(proto::Op::LOOKUP), 1u);
  for (auto& rx : w.fake.seen)
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::LOOKUP))
      EXPECT_EQ(proto::decode_lookup(rx.h, rx.body)->flags, 0u);
  EXPECT_EQ(w.fake.count(proto::Op::RELEASE), 0u);
}

// W04: a SEG_TABLE with a segment id beyond the clamp is malformed and ignored.
TEST(WireFailure, OversizedSegIdTableIsRejected) {
  FW w;
  w.open_port();
  ASSERT_EQ(w.port->table_gen(), 1u);
  auto bad = w.fake.table(9);
  bad.e[0].seg_id = 5000;
  EXPECT_FALSE(WirePort::info_from_seg_table(bad, 1));
  w.fake.send_table(w.fake.ep_of(fabric::EpClass::Control), bad);
  w.pump_port(50);
  EXPECT_EQ(w.port->table_gen(), 1u);
  auto good = w.fake.table(10);
  good.e[0].seg_id = 4095;
  w.fake.send_table(w.fake.ep_of(fabric::EpClass::Control), good);
  w.pump_port(50);
  EXPECT_EQ(w.port->table_gen(), 10u);
}

// W07: PUT_DONE counts only from the ingest endpoint; a duplicate live put_id is refused.
TEST(WireFailure, PutDoneOnlyFromIngestAndDuplicateCommitRefused) {
  FW w;
  w.open_port();
  fabric::ConnParams cp;
  cp.cls = fabric::EpClass::Ingest;
  ASSERT_TRUE(w.port->fabric().connect(fabric::Peer{1}, cp));
  std::vector<store::PutDoneResult> first, second;
  store::PutCommitReq q;
  q.put_id = 5;
  q.e.push_back({0, 1, 4096});
  w.port->put_commit(q, [&](const store::PutDoneResult& r) { first.push_back(r); });
  w.port->put_commit(q, [&](const store::PutDoneResult& r) { second.push_back(r); });
  w.pump_port(20);
  ASSERT_EQ(second.size(), 1u);
  EXPECT_EQ(second[0].status, store::CommitStatus::UnknownPut);
  EXPECT_TRUE(first.empty()) << "the first commit must keep its slot";
  proto::PutDone d;
  d.put_id = 5;
  d.n = 1;
  d.e[0] = {0, static_cast<std::uint8_t>(proto::DoneStatus::Committed), 0};
  std::array<std::byte, proto::kMaxBodyLen> body{};
  auto n = proto::encode_put_done(d, body);
  ASSERT_TRUE(n.has_value());
  w.fake.send(w.fake.ep_of(fabric::EpClass::Control), proto::Op::PUT_DONE, 1, std::span<const std::byte>(body.data(), *n));
  w.pump_port(50);
  EXPECT_TRUE(first.empty()) << "PUT_DONE from the control endpoint must be ignored";
  w.fake.send(w.fake.ep_of(fabric::EpClass::Ingest), proto::Op::PUT_DONE, 1, std::span<const std::byte>(body.data(), *n));
  w.pump_port(50);
  ASSERT_EQ(first.size(), 1u);
  EXPECT_EQ(first[0].status, store::CommitStatus::Ok);
}

TEST(WireClient, OpenWithoutTicketFileIsInvalidNotUnsupported) {
  auto cfg = load_config(R"(
[scope]
secret_file = "x"
[[nodes]]
rails = ["10.0.0.1:7100"]
[lab]
static_membership = true
)");
  ASSERT_TRUE(cfg);
  EXPECT_TRUE(cfg->ticket_file.empty());
  class NoProvider final : public ScopeProvider {
   public:
    Expected<ScopeKeys> derive(const RequestMeta&) const override {
      return Error{ErrorCode::Unsupported, "n/a"};
    }
  } p;
  auto c = Client::open(*cfg, p);
  ASSERT_FALSE(c);
  EXPECT_EQ(c.error().code, ErrorCode::InvalidArgument);
}

// ---- reconnect, split LOOKUPs, HELLO identity, no-driver waits ---------------------------------
// A fabric that steps the sim on every poll and hands out an fd that never fires; counts both.
class SteppingFabric final : public fabric::Fabric {
 public:
  SteppingFabric(fabric::Fabric& in, std::function<void()> step) : in_(in), step_(std::move(step)) {
    EXPECT_EQ(::pipe(fds_), 0);
  }
  ~SteppingFabric() override {
    ::close(fds_[0]);
    ::close(fds_[1]);
  }
  Expected<fabric::DeviceCaps> probe() override { return in_.probe(); }
  Expected<fabric::PdId> alloc_pd() override { return in_.alloc_pd(); }
  Status free_pd(fabric::PdId pd) override { return in_.free_pd(pd); }
  Expected<fabric::MemRegion> reg(std::span<std::byte> b, fabric::Access a, fabric::PdId pd) override { return in_.reg(b, a, pd); }
  Status dereg(const fabric::MemRegion& r) override { return in_.dereg(r); }
  Expected<fabric::Endpoint*> connect(const fabric::Peer& p, const fabric::ConnParams& c) override {
    // Tests: a peer that swallows the SYN. The hook sleeps (up to c.timeout) and returns true.
    if (block_connect && block_connect(c)) return Error{ErrorCode::Timeout, "test: connect blackholed"};
    return in_.connect(p, c);
  }
  std::function<bool(const fabric::ConnParams&)> block_connect;
  Status release(fabric::Endpoint* e) override { return in_.release(e); }
  Status listen(fabric::AcceptFn f, const fabric::ListenParams& lp) override { return in_.listen(std::move(f), lp); }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget b) override {
    ++polls;
    step_();
    std::size_t n = in_.poll(out, b);
    if (drop_completion) {  // tests: completions that never arrive
      std::size_t k = 0;
      for (std::size_t i = 0; i < n; ++i)
        if (!drop_completion(out[i])) {
          if (k != i) out[k] = std::move(out[i]);
          ++k;
        }
      n = k;
    }
    return n;
  }
  std::function<bool(const fabric::Completion&)> drop_completion;
  int wait_fd() override {
    ++arms;
    return fds_[0];
  }
  std::atomic<std::uint64_t> polls{0}, arms{0};

 private:
  fabric::Fabric& in_;
  std::function<void()> step_;
  int fds_[2] = {-1, -1};
};


// Value of one metric line ("name{labels} value") in a Prometheus text; -1 when absent.
double metric(const std::string& text, const std::string& series) {
  const auto at = ("\n" + text).find("\n" + series + " ");  // a sample line, not "# HELP name ..."
  if (at == std::string::npos) return -1;
  return std::atof(text.c_str() + at + series.size() + 1);
}

// Drives the keepalive (what the Client's thread does) until the session is Up and the core
// has re-bound; `cap` loop turns (each at least one virtual millisecond).
template <class W>
bool reconnect_until_up(W& w, int cap = 20000) {
  for (int i = 0; i < cap; ++i) {
    w.port->keepalive();
    w.core->pump();
    w.drive();
    if (w.port->session_up()) {
      w.core->pump();
      return true;
    }
  }
  return false;
}

std::vector<Bytes> filled(const std::vector<Bytes>& like, std::byte v) {
  std::vector<Bytes> o;
  for (auto& b : like) o.emplace_back(b.size(), v);
  return o;
}

TEST(WireReconnect, KillFetchEndpointFailsInFlightFastThenReconnectsAndHits) {
  World w(sliced(1024, false), 31);
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  Chain ch("k", 4);
  std::vector<Bytes> data;
  for (int i = 0; i < 4; ++i) data.push_back(payload(kSeg + static_cast<std::size_t>(i) * 100, i));
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);
  {
    auto out = filled(data, std::byte{0xAA});
    for (auto s : w.fetch(sk, ch, out)) ASSERT_EQ(s, KeyStatus::Hit);
  }
  ASSERT_TRUE(w.port->session_up());
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_session_up"), 1);

  // A fetch whose READs are posted but not completed, then the fetch endpoint dies.
  auto out = filled(data, std::byte{0xAA});
  std::vector<BufRef> bufs;
  for (auto& o : out) bufs.push_back({std::span<std::byte>(o)});
  Res r;
  const Nanos t0 = w.clock.now();
  w.core->submit_fetch(sk, 0, ch.refs, bufs, t0 + seconds(5), w.notify(r));
  ASSERT_NE(w.port->endpoint(fabric::EpClass::Fetch), nullptr);
  w.port->endpoint(fabric::EpClass::Fetch)->abort();
  ASSERT_TRUE(w.spin([&] { return r.done; }));
  EXPECT_LT(w.clock.now() - t0, milliseconds(10)) << "in-flight jobs must fail when the session drops, not at their deadline";
  for (auto s : r.st) EXPECT_EQ(s, KeyStatus::Miss);
  ASSERT_TRUE(w.spin([&] { return r.released; }));
  for (auto& o : out) EXPECT_TRUE(all_zero(o));
  EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
  EXPECT_FALSE(w.port->session_up());

  // While Down a new fetch and put fail at once (no RPC: the server sees no LOOKUP/PUT_BEGIN).
  const Nanos t1 = w.clock.now();
  auto out2 = filled(data, std::byte{0xAA});
  for (auto s : w.fetch(sk, ch, out2)) EXPECT_EQ(s, KeyStatus::Miss);
  Chain c2("z", 1);
  std::vector<Bytes> d2{payload(4000, 9)};
  for (auto s : w.put(sk, c2, d2)) EXPECT_EQ(s, KeyStatus::Refused);
  EXPECT_LT(w.clock.now() - t1, milliseconds(10));

  ASSERT_TRUE(reconnect_until_up(w));
  EXPECT_EQ(w.port->connect_attempts(), 1u);
  auto out3 = filled(data, std::byte{0xAA});
  for (auto s : w.fetch(sk, ch, out3)) EXPECT_EQ(s, KeyStatus::Hit);
  for (std::size_t i = 0; i < data.size(); ++i) EXPECT_EQ(out3[i], data[i]);
  const auto text = w.core->metrics_text();
  EXPECT_EQ(metric(text, "miracache_client_reconnect_total{reason=\"ep_error\"}"), 1);
  EXPECT_EQ(metric(text, "miracache_client_reconnect_fail_total"), 0);
  EXPECT_EQ(metric(text, "miracache_client_session_up"), 1);
  w.check();
}

TEST(WireReconnect, InFlightPutIsRefusedWhenIngestDies) {
  World w(sliced(1024, false), 32);
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  Chain ch("k", 2);
  std::vector<Bytes> data{payload(kSeg * 2, 1), payload(kSeg, 2)};
  std::vector<BufRef> bufs;
  for (auto& d : data) bufs.push_back({std::span<std::byte>(d)});
  Res r;
  const Nanos t0 = w.clock.now();
  w.core->submit_store(sk, 0, ch.refs, bufs, t0 + seconds(5), w.notify(r));
  w.port->endpoint(fabric::EpClass::Ingest)->abort();
  ASSERT_TRUE(w.spin([&] { return r.done; }));
  EXPECT_LT(w.clock.now() - t0, milliseconds(10));
  for (auto s : r.st) EXPECT_EQ(s, KeyStatus::Refused);
  ASSERT_TRUE(w.spin([&] { return r.released; }));
  EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
  ASSERT_TRUE(reconnect_until_up(w));
  for (auto s : w.put(sk, ch, data)) EXPECT_TRUE(s == KeyStatus::Committed || s == KeyStatus::Skipped);
}

// r6 A1: the GOAWAY drain_ms is a deadline, not the first delay. A GOAWAY from a node that keeps
// serving (Upgrade, no drain) is followed by a normal-backoff reconnect, well before a long hint.
TEST(WireReconnect, GoawayReconnectsWithNormalBackoffNotAfterTheHint) {
  World w(sliced(1024, false), 33);
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(4000, 1)};
  ASSERT_EQ(w.put(sk, ch, data)[0], KeyStatus::Committed);
  w.server->goaway(proto::GoawayReason::Upgrade, 30000);
  ASSERT_TRUE(w.spin([&] { return !w.port->session_up(); }));
  const Nanos t_down = w.clock.now();
  ASSERT_TRUE(reconnect_until_up(w));
  const Nanos waited = w.clock.now() - t_down;
  EXPECT_LE(waited, milliseconds(150)) << "first attempt after reconnect_min_ms (100, jittered), not the 30 s hint";
  EXPECT_EQ(w.port->connect_attempts(), 1u);
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_reconnect_total{reason=\"goaway\"}"), 1);
  std::vector<Bytes> out{Bytes(4000, std::byte{0xAA})};
  EXPECT_EQ(w.fetch(sk, ch, out)[0], KeyStatus::Hit);
  EXPECT_EQ(out[0], data[0]);
}

// Replaces the World's memnode with a fresh one on the same fabric node (a restart: empty store).
void restart_server(World& w) {
  w.server.reset();
  auto s = server::Server::create(server_cfg(), w.srv_fab, w.clock, w.rng, w.sex);
  ASSERT_TRUE(s);
  w.server = std::move(*s);
  ASSERT_TRUE(w.server->start());
}

// r6 A1 + A8: SIGTERM with a 60 s drain window; the draining node refuses connects (no ticket
// redeemed), so the client backs off; the node restarts after 2 s, long before drain_ms. The client
// is back within the backoff bound (reconnect_max_ms = 5 s by default), not after 60 s.
TEST(WireReconnect, NodeRestartedBeforeDrainMsIsFoundWithinTheBackoffBound) {
  World w(sliced(1024, false), 35);
  ASSERT_TRUE(w.open());
  w.server->begin_drain(proto::GoawayReason::Shutdown, 60000);
  ASSERT_TRUE(w.spin([&] { return !w.port->session_up(); }));
  const Nanos t_down = w.clock.now();
  while (w.clock.now() - t_down < seconds(2)) {
    w.port->keepalive();
    w.core->pump();
    w.drive();
    ASSERT_FALSE(w.port->session_up()) << "a draining node admits no new session";
  }
  const auto refused = w.port->connect_attempts();
  EXPECT_GE(refused, 2u);
  EXPECT_LE(refused, 6u) << "backoff from reconnect_min_ms (100 ms doubling), not a retry storm";
  restart_server(w);
  const Nanos t_restart = w.clock.now();
  ASSERT_TRUE(reconnect_until_up(w, 400000));
  EXPECT_LE(w.clock.now() - t_restart, milliseconds(5000) + milliseconds(50)) << "within reconnect_max_ms";
  EXPECT_LT(w.clock.now() - t_down, seconds(10));
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_reconnect_total{reason=\"goaway\"}"), 1);
}

// r6 A3/A9: the drain starts while a reconnect attempt is in flight. `at_conns` = 3: all endpoints are
// admitted and control already said HELLO, so the late GOAWAY arrives inside connect_all() while the
// ingest HELLO joins the existing session. `at_conns` = 1: control's HELLO is still out, so it starts
// a new session and is answered Draining. Either way the attempt counts as failed: the session never
// flips Up (and so never Down again with the streak reset), the drain deadline is kept, and the next
// attempts back off instead of retrying at reconnect_min_ms.
void drain_while_connecting(std::size_t at_conns) {
  SCOPED_TRACE(at_conns);
  World w(sliced(1024, false), 36);
  int tickets = 0;
  bool armed = false, drained = false;
  WireOptions wo = w.wire_opts();
  auto inner_tickets = wo.tickets;
  wo.tickets = [&, inner_tickets](fabric::EpClass cls) {
    ++tickets;
    return inner_tickets(cls);
  };
  wo.drive = [&] {
    // Checked before the step: the HELLO just posted on the newest endpoint has not reached the server.
    if (armed && !drained && w.port->session() == WirePort::Session::Connecting && w.server->n_conns() == at_conns) {
      drained = true;
      w.server->begin_drain(proto::GoawayReason::Shutdown, 3000);
    }
    w.drive();
  };
  ASSERT_TRUE(w.open(wo));
  w.port->endpoint(fabric::EpClass::Control)->abort();  // the session goes down (EpError)
  ASSERT_TRUE(w.spin([&] { return !w.port->session_up(); }));
  w.settle();  // the server reaps the old endpoints
  ASSERT_EQ(w.server->n_conns(), 0u);
  armed = true;
  tickets = 0;
  bool ever_up = false;
  const Nanos t0 = w.clock.now();
  while (w.clock.now() - t0 < milliseconds(2500)) {  // inside the 3 s drain window
    w.port->keepalive();
    ever_up = ever_up || w.port->session_up();
    w.core->pump();
    w.drive();
  }
  ASSERT_TRUE(drained) << "the drain must have started mid-attempt";
  EXPECT_FALSE(ever_up) << "a GOAWAY inside connect_all() must fail the attempt, not flip Up then Down";
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_reconnect_total{reason=\"goaway\"}"), 0);
  const auto attempts = w.port->connect_attempts();
  EXPECT_LE(attempts, 6u) << "backoff keeps growing through the drain";
  EXPECT_LE(tickets, 3 + static_cast<int>(attempts)) << "one ticket per refused attempt, three only for the one in flight";
}

TEST(WireReconnect, LateHelloGoawayWhileConnectingFailsTheAttemptWithoutAFlap) { drain_while_connecting(3); }
TEST(WireReconnect, DrainingHelloReplyWhileConnectingFailsTheAttempt) { drain_while_connecting(1); }

TEST(WireReconnect, MemnodeDownThreeSecondsBacksOffThenRecovers) {
  World w(sliced(1024, false), 34);
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  Chain ch("k", 2);
  std::vector<Bytes> data{payload(4000, 1), payload(5000, 2)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);
  w.port->endpoint(fabric::EpClass::Control)->abort();  // the node crashes
  w.net.set_link(1, 2, false);
  const Nanos t0 = w.clock.now();
  std::uint64_t turns = 0;
  while (w.clock.now() - t0 < seconds(3)) {
    w.port->keepalive();
    w.core->pump();
    w.drive();
    ++turns;
  }
  EXPECT_FALSE(w.port->session_up());
  const auto attempts = w.port->connect_attempts();
  EXPECT_GE(attempts, 3u);
  EXPECT_LE(attempts, 12u) << "attempts must back off (100 ms doubling, jittered), not spin; loop turns " << turns;
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_reconnect_fail_total"), static_cast<double>(attempts));
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_session_up"), 0);
  w.net.set_link(1, 2, true);
  ASSERT_TRUE(reconnect_until_up(w, 40000));
  auto out = filled(data, std::byte{0xAA});
  for (auto s : w.fetch(sk, ch, out)) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(out[0], data[0]);
}

// r8 N06: go_down -> on_down_tickets (the admin ticket source's reset_backoff in Client::open) fires once
// per Up -> Down, never on a failed reconnect attempt, and again on the next Up -> Down.
TEST(WireReconnect, OnDownTicketsFiresOncePerSessionLoss) {
  World w(sliced(1024, false), 34);
  int resets = 0;
  WireOptions wo = w.wire_opts();
  wo.on_down_tickets = [&resets] { ++resets; };
  ASSERT_TRUE(w.open(std::move(wo)));
  EXPECT_EQ(resets, 0);
  for (int round = 1; round <= 2; ++round) {
    SCOPED_TRACE(round);
    const auto attempts0 = w.port->connect_attempts();
    w.port->endpoint(fabric::EpClass::Control)->abort();  // the node crashes
    w.net.set_link(1, 2, false);
    const Nanos t0 = w.clock.now();
    while (w.clock.now() - t0 < seconds(2)) {
      w.port->keepalive();
      w.core->pump();
      w.drive();
    }
    EXPECT_FALSE(w.port->session_up());
    EXPECT_GE(w.port->connect_attempts() - attempts0, 2u) << "failed attempts happened in the down window";
    EXPECT_EQ(resets, round) << "one call per Up -> Down, none per failed attempt";
    w.net.set_link(1, 2, true);
    ASSERT_TRUE(reconnect_until_up(w, 40000));
    EXPECT_EQ(resets, round) << "coming back up does not call it";
  }
}

// Control suspect for 3 keepalive periods with no frame tears the session down (reason=suspect).
TEST(WireReconnect, SuspectControlForThreePeriodsGoesDownAndComesBack) {
  FW w;
  w.rpc_timeout = milliseconds(50);
  auto wo = w.opts();
  wo.keepalive_ms = 100;
  w.port = std::make_unique<WirePort>(w.cli, w.clock, w.salts, wo);
  auto c = ClientCore::create(w.port->fabric(), *w.port, w.clock, w.cex, w.salts, {});
  ASSERT_TRUE(c);
  w.core = std::move(*c);
  w.fake.silent = true;
  Bytes out(4000, std::byte{0xAA});
  Res r1;
  w.fetch_one(r1, out, seconds(2));  // the unanswered LOOKUP (full rpc_timeout) makes control suspect
  ASSERT_TRUE(w.port->control_suspect());
  const Nanos t_suspect = w.clock.now();
  EXPECT_TRUE(w.port->session_up()) << "one timeout is not enough";
  for (int i = 0; i < 100000 && w.port->session_up(); ++i) {
    w.port->keepalive();
    w.core->pump();
    w.drive();
    w.clock.advance_by(milliseconds(5));  // PINGs are events too: without this the 3 periods never pass
  }
  ASSERT_FALSE(w.port->session_up());
  EXPECT_GE(w.clock.now() - t_suspect, milliseconds(300) - milliseconds(60));
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_reconnect_total{reason=\"suspect\"}"), 1);
  w.fake.silent = false;  // HELLO is always answered; the new session is healthy
  ASSERT_TRUE(reconnect_until_up(w));
  EXPECT_FALSE(w.port->control_suspect());
}

// Shutdown while an attempt waits for a HELLO_ACK that never comes joins promptly.
TEST(WireReconnect, ShutdownDuringConnectingJoinsCleanly) {
  FW w;
  std::atomic<int> cmd{0};
  std::atomic<bool> blocking{false};
  // Everything below runs under the client lock only: the fabric's poll() is where the "crash"
  // happens, and drive behaves like a real wait afterwards (1 ms of wall time and of virtual
  // time per call, the sim is never stepped, so the HELLO_ACK is lost).
  SteppingFabric sf(w.cli, [&] {
    if (cmd.exchange(0) == 1) {
      w.fake.ignore_hello = true;
      for (auto& [id, ep] : w.fake.eps) ep->abort();
      blocking = true;
    }
  });
  Client::Env env;
  env.fab = &sf;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] {
    if (blocking) {
      std::this_thread::sleep_for(milliseconds(1));
      w.clock.advance_by(milliseconds(1));
    } else {
      w.drive();
    }
  };
  auto wo = w.opts();
  wo.keepalive_ms = 20;
  wo.rpc_timeout = std::chrono::hours(1);
  auto cl = Client::open_wire(env, wo);
  ASSERT_TRUE(cl);
  cmd = 1;
  const auto until = std::chrono::steady_clock::now() + seconds(10);
  while (std::chrono::steady_clock::now() < until &&
         (*cl)->wire_port()->session() != WirePort::Session::Connecting)
    std::this_thread::sleep_for(milliseconds(5));
  ASSERT_EQ((*cl)->wire_port()->session(), WirePort::Session::Connecting);
  const auto t0 = std::chrono::steady_clock::now();
  (*cl)->shutdown();
  EXPECT_LT(std::chrono::steady_clock::now() - t0, milliseconds(500)) << "shutdown must not wait out the HELLO";
  EXPECT_GE((*cl)->wire_port()->connect_attempts(), 1u);
}

// nodes.id must equal HELLO_ACK node_id: a mismatch is a config error, not a retry storm.
TEST(WireReconnect, NodeIdMismatchIsRefusedAndBacksOffAtTheMax) {
  {
    FW w;
    w.fake.node_id = 9;
    w.port = std::make_unique<WirePort>(w.cli, w.clock, w.salts, w.opts());
    auto h = w.port->hello();
    ASSERT_FALSE(h);
    EXPECT_EQ(h.error().code, ErrorCode::InvalidArgument);
    EXPECT_NE(std::string(h.error().context).find("node_id"), std::string::npos) << h.error().context;
  }
  FW w;
  ASSERT_TRUE(w.open_core());
  w.fake.node_id = 9;  // the node behind this address was replaced by a different one
  for (auto& [id, ep] : w.fake.eps) ep->abort();
  const Nanos t0 = w.clock.now();
  while (w.clock.now() - t0 < seconds(4)) {
    w.port->keepalive();
    w.core->pump();
    w.drive();
  }
  EXPECT_FALSE(w.port->session_up());
  EXPECT_EQ(w.port->connect_attempts(), 1u) << "a config error must not be retried every 100 ms";
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_reconnect_fail_total"), 1);
  EXPECT_GE(w.port->reconnect_wait_ms(), 500u);  // ~reconnect_max_ms (5 s) after the attempt at ~0.1 s, minus the 4 s waited
  while (w.clock.now() - t0 < seconds(6)) {
    w.port->keepalive();
    w.core->pump();
    w.drive();
  }
  EXPECT_EQ(w.port->connect_attempts(), 2u) << "the retry comes at the max backoff, not sooner";
}

TEST(WireClient, HelloCarriesConfiguredMtuAndProto) {
  FW w;
  auto wo = w.opts();
  wo.mtu = 2048;
  wo.wire_proto = 2;
  w.port = std::make_unique<WirePort>(w.cli, w.clock, w.salts, wo);
  ASSERT_TRUE(w.port->hello());
  EXPECT_EQ(w.fake.hello_mtu, 2048u);
  EXPECT_EQ(w.fake.hello_proto, 2u);
}

// LOOKUPs over 128 keys are split client-side; before, the tail came back MISS.
TEST(WirePort, LookupOver128KeysIsSplitAndConcatenated) {
  World w(sliced(1024, false), 35);
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  constexpr std::size_t kN = 300;
  Chain ch("big", kN);
  std::vector<Bytes> data;
  for (std::size_t i = 0; i < kN; ++i) data.push_back(payload(100 + i % 7, static_cast<int>(i)));
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);
  auto out = filled(data, std::byte{0xAA});
  auto fs = w.fetch(sk, ch, out);
  ASSERT_EQ(fs.size(), kN);
  std::size_t hits = 0;
  for (std::size_t i = 0; i < kN; ++i) {
    hits += fs[i] == KeyStatus::Hit;
    if (fs[i] == KeyStatus::Hit) EXPECT_EQ(out[i], data[i]) << i;
  }
  EXPECT_EQ(hits, kN);
  std::vector<KeyStatus> pst;
  bool pdone = false;
  w.core->probe(sk, 0, ch.refs, w.clock.now() + seconds(5), [&](Ticket, std::span<const KeyStatus> s) {
    pst.assign(s.begin(), s.end());
    pdone = true;
  });
  ASSERT_TRUE(pdone);
  ASSERT_EQ(pst.size(), kN);
  for (auto s : pst) EXPECT_EQ(s, KeyStatus::Hit);
  w.check();
}

// Without a driver the wait for a reply used to call poll() back to back for the whole
// rpc_timeout (100% of a core). It must arm wait_fd and sleep on it (bounded) instead.
TEST(WireFailure, NoDriverWaitBlocksOnTheFabricFdInsteadOfSpinning) {
  SimClock sclock;
  SeededRandom rng(3);
  fabric::SimNetwork net(sclock, rng, {}, {});
  fabric::SimFabric& fake_fab = net.add_node(1);
  fabric::SimFabric& cli = net.add_node(2);
  Fake fake(fake_fab);
  SteppingFabric sf(cli, [&] {
    net.step();
    fake.step();
  });
  RealClock wall;
  CounterSalts salts;
  WireOptions wo;
  wo.node = 1;
  wo.tickets = [](fabric::EpClass cls) -> Expected<proto::Ticket> {
    proto::Ticket t;
    t.cls = static_cast<std::uint8_t>(cls);
    return t;
  };
  wo.rpc_timeout = milliseconds(200);
  wo.keepalive_ms = 0;
  WirePort port(sf, wall, salts, wo);  // no drive: the real-NIC shape
  ASSERT_TRUE(port.hello());
  fake.silent = true;
  sf.polls = 0;
  const auto t0 = std::chrono::steady_clock::now();
  auto st = port.stats(0);  // never answered
  const auto elapsed = std::chrono::steady_clock::now() - t0;
  EXPECT_FALSE(st);
  EXPECT_GE(elapsed, milliseconds(150));
  EXPECT_GT(sf.arms.load(), 0u) << "the wait must arm the completion fd";
  EXPECT_LT(sf.polls.load(), 1000u) << "poll() turns during a 200 ms idle wait (a spin does 10^5+)";
}

// Control SEND/RECV failures are counted in rdma_errors_total (they used to only kill the endpoint).
TEST(WireFailure, ControlEndpointErrorsAreCountedInRdmaErrors) {
  World w(sliced(1024, false), 36);
  ASSERT_TRUE(w.open());
  EXPECT_EQ(metric(w.core->metrics_text(), "miracache_client_rdma_errors_total{kind=\"flush\"}"), 0);
  w.port->keepalive();  // a PING on control is in flight ...
  w.port->endpoint(fabric::EpClass::Control)->abort();  // ... when the endpoint dies: its SEND flushes
  for (int i = 0; i < 20; ++i) {
    w.core->pump();
    w.drive();
  }
  EXPECT_GT(metric(w.core->metrics_text(), "miracache_client_rdma_errors_total{kind=\"flush\"}"), 0);
}

// ---- review r4 -------------------------------------------------------------------------------
// R02: a control RPC cut short by the job's own (tiny) deadline says nothing about the server.
TEST(WireFailure, ShortDeadlineTimeoutDoesNotMakeControlSuspect) {
  FW w;  // rpc_timeout 5 s
  ASSERT_TRUE(w.open_core());
  w.fake.hook = [](Fake& f, const Fake::Rx& rx) {
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::LOOKUP)) FW::reply_lookup(f, rx, 0, 0, 0, false);
  };
  w.fake.silent = true;
  Bytes out(4000, std::byte{0xAA});
  Res r1;
  w.fetch_one(r1, out, milliseconds(1));  // the LOOKUP is cut short at 1 ms
  EXPECT_FALSE(w.port->control_suspect()) << "a deadline-bound timeout must not set suspect";
  w.fake.silent = false;
  const std::size_t lookups = w.fake.count(proto::Op::LOOKUP);
  Res r2;
  w.fetch_one(r2, out, seconds(2));
  EXPECT_GT(w.fake.count(proto::Op::LOOKUP), lookups) << "the next job must send its LOOKUP, not fail fast";
}

// R02: while suspect, a reply that already arrived is read before the call fails fast.
TEST(WireFailure, FailFastReadsALateReplyFirst) {
  FW w;
  w.rpc_timeout = milliseconds(50);
  w.open_port();
  w.fake.hook = [](Fake& f, const Fake::Rx& rx) {
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::LOOKUP)) FW::reply_lookup(f, rx, 0, 0, 0, false);
  };
  w.fake.silent = true;
  EXPECT_TRUE(w.port->lookup(one_key_req()).entries.empty());  // full rpc_timeout: suspect
  ASSERT_TRUE(w.port->control_suspect());
  w.fake.silent = false;
  (void)w.port->lookup(one_key_req());  // fails fast, sends the rate-limited probe PING
  for (int i = 0; i < 64; ++i) w.drive();  // the PONG lands in the CQ; nobody has polled it
  const std::size_t lookups = w.fake.count(proto::Op::LOOKUP);
  (void)w.port->lookup(one_key_req());
  EXPECT_FALSE(w.port->control_suspect());
  EXPECT_GT(w.fake.count(proto::Op::LOOKUP), lookups) << "the late PONG must be read before failing fast";
}

// Q15 (B) (run #293): a reply that lands in the client's CQ in the very drive tick that reaches rpc_timeout is taken by
// the last non-blocking poll, not dropped as "no reply" (and, being taken, it is not RELEASEd as a late ack either).
TEST(WireFailure, ReplyLandingInTheDeadlineTickIsTakenNotTimedOut) {
  FW w;
  w.rpc_timeout = milliseconds(50);
  w.open_port();
  std::optional<Fake::Rx> held;  // the LOOKUP, answered only once the clock reaches the deadline
  Nanos held_at{-1};             // the sim time the LOOKUP reached the fake node
  w.fake.hook = [&held, &held_at, &w](Fake&, const Fake::Rx& rx) {
    if (rx.h.type != static_cast<std::uint16_t>(proto::Op::LOOKUP)) return;
    held = rx;
    held_at = w.clock.now();
  };
  // s11c review P3-4: the reply goes out once the clock reaches held_at + rpc_timeout. lookup() starts its rpc_timeout
  // (t0) before its LOOKUP reaches the fake, so t0 <= held_at and that tick is at or past lookup()'s own deadline.
  // (Measured: the sim's delivery moves the clock by a few µs between the call and held_at, so a deadline taken before
  // the call could fall short of t0 + rpc_timeout.)
  bool sent = false;
  w.after_step = [&] {
    if (sent || !held || w.clock.now() < held_at + w.rpc_timeout) return;
    sent = true;
    FW::reply_lookup(w.fake, *held, 77, 0, 4096, true);
    w.net.run_until_idle();  // the ack is in the client's CQ before wait_until checks the deadline
  };
  const store::LookupAck a = w.port->lookup(one_key_req());
  ASSERT_TRUE(sent) << "the scripted reply must go out in the deadline tick";
  // lookup() returned with the reply at a time >= held_at + rpc_timeout >= t0 + rpc_timeout: past its own deadline, where
  // only the last non-blocking poll can take a reply (without Q15 (B) it is "no reply"). A reply taken by an ordinary
  // slice before the deadline would fail this.
  EXPECT_GE(w.clock.now(), held_at + w.rpc_timeout) << "the reply must be taken at lookup()'s deadline, by the last poll";
  ASSERT_EQ(a.entries.size(), 1u) << "the reply was in the CQ at the deadline: it must be used, not a timeout";
  EXPECT_TRUE(a.entries[0].hit);
  EXPECT_EQ(a.lease, 77u);
  EXPECT_FALSE(w.port->control_suspect()) << "an answered RPC must not make control suspect";
  w.after_step = nullptr;
  w.pump_port(64);
  EXPECT_EQ(w.fake.count(proto::Op::RELEASE), 0u) << "the ack was taken once, not also handled as a late reply";
}

// s11c review P3-5: the control endpoint dies in the very drive tick that reaches rpc_timeout; the last poll files its
// flush. That is an abort (endpoint down), not a full timeout of a live server: control must not be marked suspect.
TEST(WireFailure, EndpointDyingInTheDeadlineTickIsAnAbortNotASuspectTimeout) {
  FW w;
  w.rpc_timeout = milliseconds(50);
  w.open_port();
  bool held = false;  // the LOOKUP is never answered
  Nanos held_at{-1};  // >= lookup()'s t0 (as in the Q15 (B) test above): held_at + rpc_timeout is at or past its deadline
  w.fake.hook = [&held, &held_at, &w](Fake&, const Fake::Rx& rx) {
    if (rx.h.type != static_cast<std::uint16_t>(proto::Op::LOOKUP)) return;
    held = true;
    held_at = w.clock.now();
  };
  bool killed = false;
  w.after_step = [&] {
    if (killed || !held || w.clock.now() < held_at + w.rpc_timeout) return;
    killed = true;
    w.port->endpoint(fabric::EpClass::Control)->abort();
    w.net.run_until_idle();  // the flush is in the client's CQ before wait_until checks the deadline
  };
  EXPECT_TRUE(w.port->lookup(one_key_req()).entries.empty());
  ASSERT_TRUE(killed) << "the endpoint must die in the deadline tick";
  EXPECT_GE(w.clock.now(), held_at + w.rpc_timeout) << "lookup() must have reached its deadline (the last poll's case)";
  EXPECT_FALSE(w.port->control_suspect()) << "an endpoint that died in the last poll is an abort, not a suspect timeout";
  w.after_step = nullptr;
}

// R04: a LOOKUP_ACK that arrives after its waiter gave up has its lease RELEASEd.
TEST(WireFailure, LateLookupAckReleasesItsLease) {
  FW w;
  w.rpc_timeout = milliseconds(50);
  w.open_port();
  std::optional<Fake::Rx> held;
  w.fake.hook = [&](Fake&, const Fake::Rx& rx) {
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::LOOKUP)) held = rx;  // no reply yet
  };
  EXPECT_TRUE(w.port->lookup(one_key_req()).entries.empty());  // times out
  ASSERT_TRUE(held.has_value());
  FW::reply_lookup(w.fake, *held, /*lease=*/55, 0, 0, false);  // the late ack
  w.pump_port();
  ASSERT_EQ(w.fake.count(proto::Op::RELEASE), 1u);
  for (auto& rx : w.fake.seen)
    if (rx.h.type == static_cast<std::uint16_t>(proto::Op::RELEASE))
      EXPECT_EQ(proto::decode_release(rx.h, rx.body)->lease_id, 55u);
  EXPECT_EQ(w.port->late_acks_released(), 1u);
}

// R01: a node that swallows connects. Jobs must fail at once (not wait behind the reconnect),
// the reconnect must give up after reconnect_connect_ms, shutdown must not wait it out, and the
// client must recover when the node comes back.
struct Blackhole {
  explicit Blackhole(unsigned connect_ms = 800) : w(sliced(1024, false), 41) {
    sf = std::make_unique<SteppingFabric>(w.cli, [this] {
      if (cut.exchange(false) && cl) {
        cl->wire_port()->endpoint(fabric::EpClass::Control)->abort();  // the node crashes ...
        w.net.set_link(1, 2, false);                                   // ... and its address goes dark
      }
    });
    sf->block_connect = [this](const fabric::ConnParams& cp) {
      if (!dark) return false;
      if (heal.exchange(false)) {
        dark = false;
        w.net.set_link(1, 2, true);
        return false;
      }
      ++blocked;
      std::this_thread::sleep_for(std::min<Nanos>(cp.timeout, seconds(5)));
      return true;
    };
    env.fab = sf.get();
    env.clock = &rc;  // wall clock: the test thread submits while the keepalive thread steps the (non-atomic) SimClock
    env.executor = &w.cex;
    env.salts = &w.salts;
    env.drive = [this] { w.drive(); };
    auto wo = w.wire_opts();
    wo.keepalive_ms = 20;
    wo.reconnect_min_ms = 20;
    wo.reconnect_max_ms = 100;
    wo.reconnect_connect_ms = connect_ms;
    auto c = Client::open_wire(env, wo);
    EXPECT_TRUE(c);
    if (c) cl = std::move(*c);
  }
  Completion wait(Ticket t, seconds cap = seconds(20)) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + cap;
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = cl->poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion";
    return Completion{};
  }
  template <class P>
  bool until(P pred, seconds cap = seconds(20)) {
    const auto end = std::chrono::steady_clock::now() + cap;
    while (std::chrono::steady_clock::now() < end) {
      if (pred()) return true;
      std::this_thread::sleep_for(milliseconds(2));
    }
    return false;
  }
  void go_dark() {
    dark = true;
    cut = true;
    ASSERT_TRUE(until([&] { return cl->wire_port()->session() != WirePort::Session::Up; }));
    ASSERT_TRUE(until([&] { return blocked.load() > 0; })) << "a reconnect attempt must be running (blocked in connect)";
  }
  World w;
  RealClock rc;
  std::unique_ptr<SteppingFabric> sf;
  Client::Env env;
  std::unique_ptr<Client> cl;
  std::atomic<bool> cut{false}, dark{false}, heal{false};
  std::atomic<int> blocked{0};
};

TEST(WireReconnect, BlackholedNodeFailsJobsAtOnceAndRecoversWhenItReturns) {
  Blackhole b;
  ASSERT_TRUE(b.cl);
  auto sk = scope_keys(1);
  Chain ch("k", 2);
  std::vector<Bytes> data{payload(kSeg, 1), payload(kSeg + 100, 2)};
  auto out = filled(data, std::byte{0xAA});
  std::vector<BufRef> pbufs, fbufs;
  for (auto& d : data) pbufs.push_back({std::span<std::byte>(d)});
  for (auto& o : out) fbufs.push_back({std::span<std::byte>(o)});
  for (auto s : b.wait(b.cl->store(sk, 0, ch.refs, pbufs, seconds(5))).status) ASSERT_EQ(s, KeyStatus::Committed);

  b.go_dark();
  // A reconnect attempt is blocked in connect() right now; a 300 ms fetch must not wait behind it.
  const auto t0 = std::chrono::steady_clock::now();
  auto fc = b.wait(b.cl->fetch(sk, 0, ch.refs, fbufs, milliseconds(300)));
  const auto fetch_ms = std::chrono::duration_cast<milliseconds>(std::chrono::steady_clock::now() - t0);
  EXPECT_LT(fetch_ms, milliseconds(350)) << "job waited behind the reconnect";
  for (auto s : fc.status) EXPECT_EQ(s, KeyStatus::Miss);
  const auto t1 = std::chrono::steady_clock::now();
  auto pc = b.wait(b.cl->store(sk, 0, ch.refs, pbufs, milliseconds(300)));
  EXPECT_LT(std::chrono::steady_clock::now() - t1, milliseconds(350));
  for (auto s : pc.status) EXPECT_EQ(s, KeyStatus::Refused);
  EXPECT_GE(b.cl->fast_failed_jobs(), 2u);
  EXPECT_GE(b.cl->wire_port()->connect_attempts(), 1u);

  // The node comes back: the very next attempt connects and the data is still there.
  b.heal = true;
  ASSERT_TRUE(b.until([&] { return b.cl->wire_port()->session_up(); })) << "no recovery after the node returned";
  for (auto& o : out) std::fill(o.begin(), o.end(), std::byte{0xAA});  // in place: fbufs point into `out`
  for (auto s : b.wait(b.cl->fetch(sk, 0, ch.refs, fbufs, seconds(5))).status) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(out[0], data[0]);
  b.cl->shutdown();
}

// ---- A2.2: several memory nodes, static weighted-rendezvous placement ---------------------------
// Three memory nodes (sim ids 1..3), one client fabric node per memory node. keepalive_ms = 0 and one
// worker keep the (non-thread-safe) sim single-threaded; the test ticks the keepalive by hand.
struct MultiWorld {
  explicit MultiWorld(unsigned up) : rng(5), net(clock, rng, {}, sliced(2048, false)) {
    for (unsigned i = 1; i <= 3; ++i) {
      sfab[i - 1] = &net.add_node(i);
      cfab[i - 1] = &net.add_node(10 + i);
    }
    for (unsigned i = 1; i <= up; ++i) start(i);
  }
  void start(unsigned i, unsigned node_id = 0) {
    auto sc = server_cfg();
    sc.rails = {fabric::RailAddr{"10.0.0." + std::to_string(i), 7471}};  // learn_spec dials this; a spec with no address takes the first listener (G08)
    sc.store.node_id = node_id != 0 ? node_id : i;  // != i: HELLO_ACK node_id differs from the client's nodes[].id
    sc.store.principal_default.max_scopes = 64;
    auto s = server::Server::create(sc, *sfab[i - 1], clock, rng, sex);
    ASSERT_TRUE(s);
    srv[i - 1] = std::move(*s);
    ASSERT_TRUE(srv[i - 1]->start());
  }
  void drive() {
    const bool progressed = net.step();
    if (!progressed) {
      clock.advance_by(milliseconds(1));
      // A wait on a frozen server ends at its sim-time deadline (WirePort, review w5 U2-26: no call-count cap). But the
      // sim clock is shared: a waiter on a frozen node advances it on every idle call, so on a fast build it burns
      // through the other jobs' deadlines (an engine store's 5 s, a hung leg's 5 s rpc_timeout) before they get their
      // turns (WireReplicas.AsyncHungReplica... and AsyncShutdownDrains... failed under load without this). While a
      // node is frozen an idle step therefore also costs 100 us of real time: a throttle on the shared clock, not a
      // cap. (membership_test's World needs none: its held jobs are the only waiters.)
      // s12: also while a test holds a leg stuck some other way (dropped completions, `stuck_leg`): that leg spins the
      // shared clock too, and without the throttle it ran 3 s of sim time in ~11 ms of real time on a loaded VM, past
      // a healthy leg's 2 s deadline before that leg's thread got the CPU (gate 2026-11-16, WatchdogForceFailsAStuck-
      // LegOnTheReplicator: the engine's store on the healthy primary came back Timeout).
      bool throttle = stuck_leg.load();
      for (unsigned i = 0; i < 3 && !throttle; ++i) throttle = frozen[i].load();
      if (throttle) std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
    {  // review r9 S01: count the calls and the idle advances (1 ms of virtual time each) of every calling thread
      std::lock_guard lk(thr_mu);
      auto& c = by_thread[std::this_thread::get_id()];
      ++c.calls;
      if (!progressed) ++c.idle;
    }
    for (unsigned i = 0; i < 3; ++i)
      if (srv[i] && !frozen[i]) srv[i]->run_once();
  }
  struct ThreadCount {
    std::uint64_t calls = 0, idle = 0;
  };
  std::mutex thr_mu;
  std::map<std::thread::id, ThreadCount> by_thread;
  std::map<std::thread::id, ThreadCount> thread_counts() {
    std::lock_guard lk(thr_mu);
    return by_thread;
  }
  std::atomic<bool> frozen[3] = {false, false, false};  // a server that stops answering
  std::atomic<bool> stuck_leg{false};  // a test holds a leg stuck without freezing a server: throttle idle steps too
  Client::NodeSpec spec(unsigned i, std::uint32_t weight = 1) {
    Client::NodeSpec ns;
    ns.fab = cfab[i - 1];
    ns.weight = weight;
    ns.wopts.node = i;
    ns.wopts.tickets = [this, i](fabric::EpClass cls) -> Expected<proto::Ticket> {
      if (!srv[i - 1]) return Error{ErrorCode::NotFound, "node down"};
      auto t = srv[i - 1]->issue_ticket("lab", cls, 0, 1);
      if (!t) return t.error();
      return (*t)[0];
    };
    ns.wopts.random = &jit;
    ns.wopts.keepalive_ms = 0;
    return ns;
  }
  SimClock clock;
  SeededRandom rng, jit{99};
  fabric::SimNetwork net;
  fabric::SimFabric* sfab[3];
  fabric::SimFabric* cfab[3];
  InlineExecutor sex, cex;
  CounterSalts salts;
  std::unique_ptr<server::Server> srv[3];
};

// One tick of the keepalive threads plus one virtual millisecond: the other nodes' pings keep the sim
// network busy, so drive() alone would hardly move the clock.
void tick_ms(Client& c, MultiWorld& w) {
  c.keepalive_tick();
  w.clock.advance_by(milliseconds(1));
}

unsigned owner_of(int scope, const std::vector<PlaceNode>& nodes) {
  auto sk = scope_keys(scope);
  return static_cast<unsigned>(std::stoul(nodes[place_owner(nodes, std::span<const std::uint8_t, 32>(sk.scopes[0].b))].id));
}

TEST(WirePlacement, OneNodeDownFailsOnlyItsScopesFastAndRecovers) {
  MultiWorld w(/*up=*/2);  // node 3 is unreachable at open
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
  RuntimeOptions ro;
  ro.workers = 1;
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  ASSERT_TRUE(cl) << cl.error().context;  // node 3 down must not fail the open
  Client& c = **cl;
  ASSERT_EQ(c.node_count(), 3u);
  EXPECT_NE(c.wire_port(0), nullptr);
  EXPECT_NE(c.wire_port(1), nullptr);
  EXPECT_EQ(c.wire_port(2), nullptr);

  const std::vector<PlaceNode> nodes{{"1", 1}, {"2", 1}, {"3", 1}};
  auto wait = [&](Ticket t) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion (hang)";
    return Completion{};
  };
  constexpr int kScopes = 60;
  unsigned per_node[4] = {0, 0, 0, 0};
  Chain ch("k", 1);
  auto put_all = [&](bool node3_up) {
    for (int s = 1; s <= kScopes; ++s) {
      const unsigned o = owner_of(s, nodes);
      std::vector<Bytes> data{payload(5000, s)};
      std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
      auto sk = scope_keys(s);
      auto sc = wait(c.store(sk, 0, ch.refs, pb, seconds(5)));
      ASSERT_EQ(sc.status.size(), 1u);
      if (o == 3 && !node3_up) EXPECT_EQ(sc.status[0], KeyStatus::Refused) << s;
      else if (node3_up && o != 3) EXPECT_EQ(sc.status[0], KeyStatus::Skipped) << s;  // second round: already stored
      else EXPECT_EQ(sc.status[0], KeyStatus::Committed) << s;
    }
  };
  for (int s = 1; s <= kScopes; ++s) ++per_node[owner_of(s, nodes)];
  for (unsigned i = 1; i <= 3; ++i) EXPECT_GT(per_node[i], 5u) << "node " << i;  // the test spreads over all three

  put_all(false);
  EXPECT_GE(c.fast_failed_jobs(), per_node[3]);
  for (int s = 1; s <= kScopes; ++s) {
    auto sk = scope_keys(s);
    std::vector<Bytes> out{Bytes(5000, std::byte{0xAA})};
    std::vector<BufRef> fb{{std::span<std::byte>(out[0])}};
    auto fc = wait(c.fetch(sk, 0, ch.refs, fb, seconds(5)));
    ASSERT_EQ(fc.status.size(), 1u);
    if (owner_of(s, nodes) == 3) EXPECT_EQ(fc.status[0], KeyStatus::Miss) << s;
    else {
      EXPECT_EQ(fc.status[0], KeyStatus::Hit) << s;
      EXPECT_EQ(out[0], payload(5000, s));
    }
  }
  // Probes (lookup) follow the same owner.
  for (int s = 1; s <= kScopes; ++s) {
    auto sk = scope_keys(s);
    auto lc = wait(c.lookup(sk, 0, ch.refs, seconds(5)));
    ASSERT_EQ(lc.status.size(), 1u);
    EXPECT_EQ(lc.status[0], owner_of(s, nodes) == 3 ? KeyStatus::Miss : KeyStatus::Hit) << s;
  }

  // Node 3 comes up: its keepalive thread (here: a manual tick) connects it like a reconnect.
  w.start(3);
  for (int i = 0; i < 200000 && !c.wire_port(2); ++i) tick_ms(c, w);
  ASSERT_NE(c.wire_port(2), nullptr);
  put_all(true);
  for (int s = 1; s <= kScopes; ++s) {
    auto sk = scope_keys(s);
    std::vector<Bytes> out{Bytes(5000, std::byte{0xAA})};
    std::vector<BufRef> fb{{std::span<std::byte>(out[0])}};
    auto fc = wait(c.fetch(sk, 0, ch.refs, fb, seconds(5)));
    ASSERT_EQ(fc.status.size(), 1u);
    EXPECT_EQ(fc.status[0], KeyStatus::Hit) << s;
    EXPECT_EQ(out[0], payload(5000, s));
  }
  // Per-node metrics carry the node label; single registry, one family per name.
  const std::string m = c.metrics_text();
  EXPECT_NE(m.find("miracache_client_session_up{node=\"3\"} 1"), std::string::npos) << m;
  EXPECT_NE(m.find("miracache_client_session_up{node=\"1\"} 1"), std::string::npos);
  c.shutdown();
}

// ---- Plan 2C: node IDs are learned from HELLO_ACK ---------------------------------------------
// A spec in learn mode: wopts.node = 0 (production), the sim routes by wopts.route, and the rail is the
// address the client labels and logs.
Client::NodeSpec learn_spec(MultiWorld& w, unsigned i) {
  auto ns = w.spec(i);
  ns.wopts.route = i;
  ns.wopts.node = 0;
  ns.wopts.rail = fabric::RailAddr{"10.0.0." + std::to_string(i), 7471};
  return ns;
}

std::string slurp_file(const std::string& p) {
  std::ifstream f(p);
  std::stringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// s12 (tpu-sync cross-check C1): node 3 stops answering (frozen: its LOOKUPs are never answered), so every fetch sent to
// it holds a runtime worker until the fetch's deadline. Submits 4 such fetches, then one to healthy node 1, and returns
// the healthy fetch's status and how many of node 3's fetches had completed before it. The stuck fetches get a long
// (sim) deadline so the healthy one can never lose the race by sim-clock speed alone.
std::pair<KeyStatus, int> healthy_fetch_behind_frozen_node(const RuntimeOptions& ro) {
  MultiWorld w(3);
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  EXPECT_TRUE(cl) << (cl ? "" : cl.error().context);
  if (!cl) return {KeyStatus::Aborted, -1};
  Client& c = **cl;
  const std::vector<PlaceNode> nodes{{"1", 1}, {"2", 1}, {"3", 1}};
  std::vector<int> on3;
  int on1 = 0;
  for (int s = 1; s < 1000 && (on3.size() < 4 || on1 == 0); ++s) {
    const unsigned o = owner_of(s, nodes);
    if (o == 3 && on3.size() < 4) on3.push_back(s);
    else if (o == 1 && on1 == 0) on1 = s;
  }
  EXPECT_EQ(on3.size(), 4u);
  std::map<std::uint64_t, Completion> got;
  auto wait = [&](Ticket t) {
    const auto until = std::chrono::steady_clock::now() + seconds(120);
    while (std::chrono::steady_clock::now() < until) {
      std::array<Completion, 8> comp;
      const std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k) got[comp[k].ticket.id] = comp[k];
      if (auto it = got.find(t.id); it != got.end()) return it->second;
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion (hang)";
    return Completion{};
  };
  Chain ch("k", 1);
  Bytes d = payload(5000, on1);
  std::vector<BufRef> pb{{std::span<std::byte>(d)}};
  auto sc = wait(c.store(scope_keys(on1), 0, ch.refs, pb, seconds(5)));
  EXPECT_TRUE(!sc.status.empty() && sc.status[0] == KeyStatus::Committed);

  w.frozen[2] = true;
  std::vector<Bytes> outs(on3.size() + 1, Bytes(5000, std::byte{0xAA}));
  std::vector<Ticket> t3;
  for (std::size_t i = 0; i < on3.size(); ++i) {
    std::vector<BufRef> fb{{std::span<std::byte>(outs[i])}};
    t3.push_back(c.fetch(scope_keys(on3[i]), 0, ch.refs, fb, seconds(30)));
  }
  // The stuck fetches are running once their workers drive the (idle) sim clock forward.
  const Nanos frozen_at = w.clock.now();
  const auto real_cap = std::chrono::steady_clock::now() + seconds(30);
  while (w.clock.now() < frozen_at + milliseconds(20) && std::chrono::steady_clock::now() < real_cap)
    std::this_thread::yield();
  std::vector<BufRef> hb{{std::span<std::byte>(outs.back())}};
  const Completion hc = wait(c.fetch(scope_keys(on1), 0, ch.refs, hb, seconds(120)));
  int before = 0;
  for (auto t : t3) before += got.count(t.id) ? 1 : 0;
  for (auto t : t3) {
    auto f = wait(t);
    EXPECT_TRUE(!f.status.empty() && f.status[0] == KeyStatus::Miss);  // the frozen node never answered: a miss, not an error
  }
  w.frozen[2] = false;
  c.shutdown();
  if (hc.status.empty()) return {KeyStatus::Aborted, before};
  if (hc.status[0] == KeyStatus::Hit) EXPECT_EQ(outs.back(), payload(5000, on1));
  return {hc.status[0], before};
}

TEST(WirePlacement, FrozenNodeHoldsOnlyItsOwnWorkersAndHealthyNodesRunAtOnce) {
  const RuntimeOptions prod = Client::runtime_for_nodes(3);
  EXPECT_EQ(prod.workers, 6u);
  EXPECT_EQ(prod.lane_cap, 2u);
  EXPECT_EQ(Client::runtime_for_nodes(1).workers, 2u);  // one node: the old runtime exactly
  EXPECT_EQ(Client::runtime_for_nodes(1).lane_cap, 0u);
  EXPECT_EQ(Client::runtime_for_nodes(200).workers, 64u);
  auto [st, before] = healthy_fetch_behind_frozen_node(prod);
  EXPECT_EQ(st, KeyStatus::Hit);
  EXPECT_EQ(before, 0) << "the healthy node's fetch waited for the frozen node's jobs";
  // Teeth: the pre-s12 runtime (2 workers, no lanes) shows the stall: the healthy fetch runs only after node 3's
  // first two fetches gave their workers back at their deadline.
  RuntimeOptions old;
  old.workers = 2;
  auto [st2, before2] = healthy_fetch_behind_frozen_node(old);
  EXPECT_EQ(st2, KeyStatus::Hit);
  EXPECT_GE(before2, 2) << "the old runtime no longer stalls: this test has lost its teeth";
}

TEST(WireLearnedIds, UnreachedNodeOwnsNoScopesAndLearnedIdsJoinLater) {
  MultiWorld w(/*up=*/0);
  w.start(1, 1001);
  w.start(2, 1002);  // node 3 is unreachable at open
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  std::vector<Client::NodeSpec> specs{learn_spec(w, 1), learn_spec(w, 2), learn_spec(w, 3)};
  RuntimeOptions ro;
  ro.workers = 1;
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  EXPECT_EQ(c.wire_port(0)->node_id(), 1001u);
  EXPECT_EQ(c.wire_port(1)->node_id(), 1002u);
  EXPECT_EQ(c.wire_port(2), nullptr);
  auto wait = [&](Ticket t) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion (hang)";
    return Completion{};
  };
  constexpr int kScopes = 60;
  Chain ch("k", 1);
  auto put_all = [&](const char* what) {
    for (int s = 1; s <= kScopes; ++s) {
      std::vector<Bytes> data{payload(5000, s)};
      std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
      auto sc = wait(c.store(scope_keys(s), 0, ch.refs, pb, seconds(5)));
      ASSERT_EQ(sc.status.size(), 1u);
      EXPECT_TRUE(sc.status[0] == KeyStatus::Committed || sc.status[0] == KeyStatus::Skipped) << what << " scope " << s;
    }
  };
  put_all("node 3 unreached");  // none refused: the unreached node owns no scopes
  EXPECT_EQ(c.fast_failed_jobs(), 0u);
  std::string m = c.metrics_text();
  EXPECT_NE(m.find("miracache_client_node_info{node=\"10.0.0.1:7471\",node_id=\"1001\""), std::string::npos) << m;
  EXPECT_NE(m.find("node_id=\"1002\""), std::string::npos);
  EXPECT_EQ(m.find("node_id=\"1003\""), std::string::npos);
  // H08: series lines of `family` (no HELP/TYPE) whose labels contain `needle`.
  auto stale = [](const std::string& text, const std::string& family, const std::string& needle) {
    std::size_t n = 0, at = 0;
    while (at < text.size()) {
      const std::size_t eol = std::min(text.find('\n', at), text.size());
      const std::string line = text.substr(at, eol - at);
      if (line.rfind(family + "{", 0) == 0 && line.find(needle) != std::string::npos) ++n;
      at = eol + 1;
    }
    return n;
  };
  EXPECT_GT(stale(m, "miracache_client_breaker_state", "node_id=\"unknown\""), 0u) << "node 3's ID is not known yet\n" << m;
  // The placement is exactly rendezvous over the two learned ids.
  const std::vector<PlaceNode> two{{"1001", 1}, {"1002", 1}};
  std::vector<unsigned> held;
  for (int s = 1; s <= kScopes; ++s) {
    auto sk = scope_keys(s);
    held.push_back(static_cast<unsigned>(place_owner(two, std::span<const std::uint8_t, 32>(sk.scopes[0].b))));
  }
  // Node 3 comes up: its keepalive tick builds it, learns 1003 and publishes it to placement.
  w.start(3, 1003);
  for (int i = 0; i < 200000 && !c.wire_port(2); ++i) tick_ms(c, w);
  ASSERT_NE(c.wire_port(2), nullptr);
  EXPECT_EQ(c.wire_port(2)->node_id(), 1003u);
  m = c.metrics_text();
  EXPECT_NE(m.find("node_id=\"1003\""), std::string::npos) << m;
  // H08: once the ID is learned, the "unknown" breaker series (and any rail series of ID 0) are gone, not left at 0.
  EXPECT_EQ(stale(m, "miracache_client_breaker_state", "node_id=\"unknown\""), 0u) << m;
  EXPECT_EQ(stale(m, "miracache_client_breaker_trips_total", "node_id=\"unknown\""), 0u) << m;
  EXPECT_EQ(stale(m, "miracache_client_rail_state", "node_id=\"0\""), 0u) << m;
  EXPECT_EQ(stale(m, "miracache_client_slices_reissued_total", "node_id=\"0\""), 0u) << m;
  EXPECT_GT(stale(m, "miracache_client_breaker_state", "node_id=\"1003\""), 0u) << m;
  // F3 (K09, S2): no series of any node keeps an unknown/0 ID or an empty hostname once every ID is learned.
  for (const char* fam : {"miracache_client_rail_state", "miracache_read_window", "miracache_client_rail_fetch_qps",
                          "miracache_client_fetch_rail_bytes_total", "miracache_client_slices_reissued_total",
                          "miracache_client_rail_unpaired", "miracache_client_breaker_state",
                          "miracache_client_breaker_trips_total"}) {
    EXPECT_EQ(stale(m, fam, "node_id=\"unknown\""), 0u) << fam << "\n" << m;
    EXPECT_EQ(stale(m, fam, "node_id=\"0\""), 0u) << fam << "\n" << m;
    EXPECT_EQ(stale(m, fam, "hostname=\"\""), 0u) << fam << "\n" << m;
    EXPECT_EQ(stale(m, fam, "hostname=\"unknown\""), 0u) << fam << "\n" << m;  // F5: HELLO_ACK named the node
  }
  // F5: static/lab mode has no admin source; the hostname comes in HELLO_ACK (here the sim nodes' own log::hostname()).
  // node_info never says "" or "unknown", and the series that did are gone once the hostname is known.
  for (const char* id : {"1001", "1002", "1003"}) {
    std::size_t both = 0;
    std::istringstream is(m);
    for (std::string line; std::getline(is, line);)
      if (line.rfind("miracache_client_node_info{", 0) == 0 && line.find("node_id=\"" + std::string(id) + "\"") != std::string::npos &&
          line.find("hostname=\"" + log::hostname() + "\"") != std::string::npos)
        ++both;
    EXPECT_EQ(both, 1u) << id << "\n" << m;
  }
  EXPECT_EQ(stale(m, "miracache_client_node_info", "hostname=\"unknown\""), 0u) << m;
  EXPECT_EQ(stale(m, "miracache_client_node_info", "hostname=\"\""), 0u) << m;
  put_all("node 3 joined");
  // Some scopes moved to node 3, and all of them are served.
  std::size_t on3 = 0;
  const std::vector<PlaceNode> three{{"1001", 1}, {"1002", 1}, {"1003", 1}};
  for (int s = 1; s <= kScopes; ++s) {
    auto sk = scope_keys(s);
    on3 += place_owner(three, std::span<const std::uint8_t, 32>(sk.scopes[0].b)) == 2;
    std::vector<Bytes> out{Bytes(5000, std::byte{0xAA})};
    std::vector<BufRef> fb{{std::span<std::byte>(out[0])}};
    auto fc = wait(c.fetch(sk, 0, ch.refs, fb, seconds(5)));
    ASSERT_EQ(fc.status.size(), 1u);
    EXPECT_EQ(fc.status[0], KeyStatus::Hit) << s;
    EXPECT_EQ(out[0], payload(5000, s));
  }
  EXPECT_GT(on3, 5u);
  c.shutdown();
}

TEST(WireLearnedIds, DuplicateIdExcludesTheLaterNodeAndNamesBothAddresses) {
  char tmpl[] = "/tmp/mira-dupid-XXXXXX";
  const int lfd = ::mkstemp(tmpl);
  ASSERT_GE(lfd, 0);
  log::set_sink_fd(lfd);
  MultiWorld w(/*up=*/0);
  w.start(1, 1001);
  w.start(2, 1001);  // a cloned store: the same id as node 1
  w.start(3, 1003);
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  std::vector<Client::NodeSpec> specs{learn_spec(w, 1), learn_spec(w, 2), learn_spec(w, 3)};
  RuntimeOptions ro;
  ro.workers = 1;
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  ASSERT_TRUE(cl) << cl.error().context;  // the open succeeds with the other two
  Client& c = **cl;
  EXPECT_NE(c.wire_port(0), nullptr);
  EXPECT_EQ(c.wire_port(1), nullptr) << "the duplicate must not be built";
  EXPECT_NE(c.wire_port(2), nullptr);
  for (int i = 0; i < 300; ++i) tick_ms(c, w);  // retries stay refused (and are logged once)
  EXPECT_EQ(c.wire_port(1), nullptr);
  const std::string m = c.metrics_text();
  EXPECT_NE(m.find("miracache_client_node_id_conflicts_total{node=\"10.0.0.2:7471\"} "), std::string::npos) << m;
  EXPECT_EQ(m.find("miracache_client_node_id_conflicts_total{node=\"10.0.0.2:7471\"} 0"), std::string::npos) << m;
  // Stores all succeed (the excluded node owns nothing) and none is refused.
  auto wait = [&](Ticket t) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion (hang)";
    return Completion{};
  };
  Chain ch("k", 1);
  for (int s = 1; s <= 30; ++s) {
    std::vector<Bytes> data{payload(5000, s)};
    std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
    auto sc = wait(c.store(scope_keys(s), 0, ch.refs, pb, seconds(5)));
    ASSERT_EQ(sc.status.size(), 1u);
    EXPECT_EQ(sc.status[0], KeyStatus::Committed) << s;
  }
  c.shutdown();
  log::set_sink_fd(2);
  const std::string logtext = slurp_file(tmpl);
  ::close(lfd);
  ::unlink(tmpl);
  EXPECT_NE(logtext.find("duplicate node id 1001: 10.0.0.2:7471 and 10.0.0.1:7471 report the same ID; 10.0.0.2:7471 is excluded"),
            std::string::npos)
      << logtext;
  EXPECT_NE(logtext.find("comp=client"), std::string::npos);
  EXPECT_NE(logtext.find("client_host="), std::string::npos);
  EXPECT_NE(logtext.find("addr=10.0.0.2:7471"), std::string::npos);
  // Logged once per ID, not once per retry.
  const auto first = logtext.find("duplicate node id");
  EXPECT_EQ(logtext.find("duplicate node id", first + 1), std::string::npos) << logtext;
}

// ---- A2.10: best-effort replicas (placement.replicas = 2 over three nodes) ----------------------
// Value of the series `name` whose label set contains every string of `parts` (0 if absent).
double metric_value(const std::string& text, const std::string& name, std::initializer_list<std::string> parts) {
  std::size_t pos = 0;
  while (pos < text.size()) {
    std::size_t eol = text.find('\n', pos);
    if (eol == std::string::npos) eol = text.size();
    const std::string line = text.substr(pos, eol - pos);
    pos = eol + 1;
    if (line.rfind(name + "{", 0) != 0) continue;
    bool all = true;
    for (const auto& p : parts) all = all && line.find(p) != std::string::npos;
    if (all) return std::stod(line.substr(line.rfind(' ') + 1));
  }
  return 0;
}
// Review r9 S05 (+ S09). Two memory nodes come back with new IDs. Node 2's reconnect learns its new ID from the HELLO
// and then fails (its fetch ticket is withheld); node 1's reconnect completes and publishes placement. Node 2 is not Up,
// so it must stay in placement under its OLD ID: a publish by another node must not expose the ID it has only learned.
// The identity series follow: the old ID reads 1 until the node is back in placement, the new one reads 0 until then.
TEST(WireLearnedIds, TwoInterleavedReconnectsWithNewIdsPublishEachIdOnlyWhenItsSessionIsUp) {
  MultiWorld w(/*up=*/0);
  w.start(1, 1001);
  w.start(2, 1002);
  w.start(3, 1003);
  std::atomic<bool> block2{false};
  auto s2 = learn_spec(w, 2);
  auto base = s2.wopts.tickets;
  s2.wopts.tickets = [&block2, base](fabric::EpClass cls) -> Expected<proto::Ticket> {
    if (block2.load() && cls != fabric::EpClass::Control) return Error{ErrorCode::NotFound, "test: ticket withheld"};
    return base(cls);
  };
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  std::vector<Client::NodeSpec> specs{learn_spec(w, 1), std::move(s2), learn_spec(w, 3)};
  RuntimeOptions ro;
  ro.workers = 1;
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  auto wait = [&](Ticket t) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion (hang)";
    return Completion{};
  };
  auto crash = [&](unsigned i) {
    w.srv[i - 1].reset();
    c.wire_port(i - 1)->endpoint(fabric::EpClass::Control)->abort();
    for (int k = 0; k < 4000 && c.wire_port(i - 1)->session_up(); ++k) tick_ms(c, w);
    ASSERT_FALSE(c.wire_port(i - 1)->session_up());
  };
  auto gauge = [&](const char* id) { return metric_value(c.metrics_text(), "miracache_client_node_info", {std::string("node_id=\"") + id + "\""}); };
  EXPECT_EQ(gauge("1002"), 1);
  crash(1);
  crash(2);
  block2 = true;
  w.start(2, 2002);  // a replaced node: new ID
  for (int i = 0; i < 20000 && c.metrics_text().find("node_id=\"2002\"") == std::string::npos; ++i) tick_ms(c, w);
  ASSERT_NE(c.metrics_text().find("node_id=\"2002\""), std::string::npos) << "node 2 never learned its new ID";
  EXPECT_FALSE(c.wire_port(1)->session_up());
  w.start(1, 2001);
  for (int i = 0; i < 20000 && !c.wire_port(0)->session_up(); ++i) tick_ms(c, w);
  ASSERT_TRUE(c.wire_port(0)->session_up()) << "node 1 did not reconnect";
  EXPECT_FALSE(c.wire_port(1)->session_up());
  // Placement now: node 1 under 2001 (its session is Up), node 2 still under 1002, node 3 under 1003.
  const std::vector<PlaceNode> right{{"2001", 1}, {"1002", 1}, {"1003", 1}}, wrong{{"2001", 1}, {"2002", 1}, {"1003", 1}};
  auto key_of = [](int s) { return scope_keys(s); };
  std::vector<int> moved;  // owned by a live node under `right`, by node 2 under `wrong`
  for (int s = 1; s <= 600 && moved.size() < 3; ++s) {
    auto sk = key_of(s);
    const std::span<const std::uint8_t, 32> b(sk.scopes[0].b);
    if (place_owner(right, b) != 1 && place_owner(wrong, b) == 1) moved.push_back(s);
  }
  ASSERT_GE(moved.size(), 2u);
  Chain ch("k", 1);
  for (int s : moved) {
    std::vector<Bytes> data{payload(5000, s)};
    std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
    auto sc = wait(c.store(scope_keys(s), 0, ch.refs, pb, seconds(5)));
    ASSERT_EQ(sc.status.size(), 1u);
    EXPECT_EQ(sc.status[0], KeyStatus::Committed) << "scope " << s << " went to the node that is still down (its learned ID was published early)";
  }
  EXPECT_EQ(gauge("1002"), 1);  // S09: node 2 is still in placement under its old ID
  EXPECT_EQ(gauge("2002"), 0);  //      and the new series waits for the publish
  EXPECT_EQ(gauge("2001"), 1);
  EXPECT_EQ(gauge("1001"), 0);
  // r9b T06: node 3 comes back under 1002, the ID node 2 still has in placement (node 2 is down and has learned 2002).
  // The duplicate check must count the published ID too: node 2 leaves placement and node 3 takes 1002. Before the fix
  // both were in placement under 1002, and the scopes the tie gave to node 2 were refused.
  auto gauge_of = [&](unsigned i, const char* id) {
    return metric_value(c.metrics_text(), "miracache_client_node_info",
                        {"node=\"10.0.0." + std::to_string(i) + ":7471\"", std::string("node_id=\"") + id + "\""});
  };
  crash(3);
  w.start(3, 1002);
  for (int i = 0; i < 20000 && !c.wire_port(2)->session_up(); ++i) tick_ms(c, w);
  ASSERT_TRUE(c.wire_port(2)->session_up()) << "node 3 did not reconnect";
  EXPECT_FALSE(c.wire_port(1)->session_up());
  EXPECT_EQ(gauge_of(3, "1002"), 1);
  EXPECT_EQ(gauge_of(2, "1002"), 0) << "node 2 kept 1002 in placement while node 3 published it too";
  EXPECT_EQ(metric_value(c.metrics_text(), "miracache_client_node_id_conflicts_total", {"node=\"10.0.0.3:7471\""}), 0);
  for (int s = 1; s <= 40; ++s) {
    std::vector<Bytes> data{payload(5000, s)};
    std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
    auto sc = wait(c.store(scope_keys(s), 0, ch.refs, pb, seconds(5)));
    ASSERT_EQ(sc.status.size(), 1u);
    EXPECT_TRUE(sc.status[0] == KeyStatus::Committed || sc.status[0] == KeyStatus::Skipped)  // Skipped: stored before
        << "scope " << s << " went to node 2 (down) under the duplicate 1002";
  }
  // Node 2's ticket comes back: the reconnect completes and only now does the new ID join placement.
  block2 = false;
  for (int i = 0; i < 40000 && !c.wire_port(1)->session_up(); ++i) tick_ms(c, w);
  ASSERT_TRUE(c.wire_port(1)->session_up());
  EXPECT_EQ(gauge("2002"), 1);
  EXPECT_EQ(gauge_of(2, "1002"), 0);
  EXPECT_EQ(gauge_of(3, "1002"), 1);
  for (int s : moved) {
    std::vector<Bytes> data{payload(5000, s)};
    std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
    auto sc = wait(c.store(scope_keys(s), 0, ch.refs, pb, seconds(5)));
    ASSERT_EQ(sc.status.size(), 1u);
    EXPECT_EQ(sc.status[0], KeyStatus::Committed) << "scope " << s << " (now owned by node 2 under its new ID)";
  }
  c.shutdown();
}

struct RepOpts {
  ReplicaMode mode = ReplicaMode::Sync;  // the round-1 tests are about the leg loop; async tests ask for it
  std::size_t buf = 256u << 20;
  std::function<fabric::Fabric*(fabric::Fabric&)> wrap3;  // wraps node 3's client fabric (drop completions)
  std::array<const char*, 3> zones{"", "", ""};            // nodes[].zone ("" = none)
  Nanos watchdog{0};                                       // 0 = default
};

struct RepRig {
  using Opts = RepOpts;
  RepRig(unsigned up, unsigned replicas, Opts o = Opts()) : w(0) {
    for (unsigned i = 1; i <= 3; ++i)
      if (up & (1u << (i - 1))) w.start(i);
    env.clock = &w.clock;
    env.executor = &w.cex;
    env.salts = &w.salts;
    env.drive = [this] { w.drive(); };
    env.replicas = replicas;
    env.replica_mode = o.mode;
    env.replica_buffer_bytes = o.buf;
    if (o.watchdog != Nanos{0}) env.watchdog_grace = o.watchdog;
    std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
    if (o.wrap3) specs[2].fab = o.wrap3(*w.cfab[2]);
    for (std::size_t i = 0; i < 3; ++i) specs[i].zone = nodes[i].zone = o.zones[i];
    RuntimeOptions ro;
    ro.workers = 1;
    auto c = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
    EXPECT_TRUE(c) << (c ? "" : c.error().context);
    if (c) cl = std::move(*c);
    reps = replicas;
  }
  ~RepRig() {
    if (cl) cl->shutdown();
  }
  Completion wait(Ticket t) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = cl->poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion (hang)";
    return Completion{};
  }
  // 0-based node indices of the replica set of `scope`, best first.
  std::vector<std::size_t> set_of(int scope) const {
    auto sk = scope_keys(scope);
    return place_order(nodes, std::span<const std::uint8_t, 32>(sk.scopes[0].b), reps);
  }
  // Waits for the async replicator to finish its legs (sync: nothing is ever pending).
  // Run #269: bounded in SIM time, not real time. Every leg ends on the sim clock: at its deadline (store deadlines are
  // clamped to deadline.put_max_ms, 2.5 s after the submit) or at the watchdog (deadline + grace). A leg on a frozen node
  // is then the only thread that drives the sim, one idle 1 ms step per call, and each step runs the healthy servers'
  // run_once (a full tick) plus the 100 us throttle: about 4 ms of real time per step in asan on an idle VM, so its 2.5 s
  // took ~10 s and, CPU-bound, over 30 s under load. The old 30 s real bound then failed with nothing wrong (pending 1,
  // 8 KiB in use). The wait now ends at now + put_max + grace + 2 s of sim time (the latest a queued leg can end), or
  // when the sim clock has not moved for 30 s of real time (nothing drives it: a leg that never ran, a lost wakeup).
  void settle() {
    const Nanos sim_until = w.clock.now() + milliseconds(env.put_max_ms) + env.watchdog_grace + seconds(2);
    Nanos last = w.clock.now();
    auto still_since = std::chrono::steady_clock::now();
    while (cl->replicator_pending() > 0 && w.clock.now() < sim_until) {
      const Nanos t = w.clock.now();
      const auto real = std::chrono::steady_clock::now();
      if (t != last) {
        last = t;
        still_since = real;
      } else if (real - still_since > seconds(30)) {
        break;
      }
      std::this_thread::yield();
    }
    EXPECT_EQ(cl->replicator_pending(), 0u);
    EXPECT_EQ(cl->replica_buffer_in_use(), 0u);
  }
  KeyStatus put(int scope, const Chain& ch, int seed, std::size_t len = 5000) {
    Bytes d = payload(len, seed);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto c = wait(cl->store(scope_keys(scope), 0, ch.refs, pb, seconds(5)));
    EXPECT_EQ(c.status.size(), 1u);
    std::fill(d.begin(), d.end(), std::byte{0xEE});  // the engine's buffer is free at the Completion: scribble on it
    settle();  // async: the replica legs run after the Completion, from the replicator's own copy
    return c.status.empty() ? KeyStatus::Aborted : c.status[0];
  }
  // fetch; `exact` says the bytes equal payload(len, seed).
  KeyStatus get(int scope, const Chain& ch, int seed, bool* exact = nullptr, std::size_t len = 5000) {
    Bytes out(len, std::byte{0xAA});
    std::vector<BufRef> fb{{std::span<std::byte>(out)}};
    auto c = wait(cl->fetch(scope_keys(scope), 0, ch.refs, fb, seconds(5)));
    EXPECT_EQ(c.status.size(), 1u);
    if (exact) *exact = out == payload(len, seed);
    return c.status.empty() ? KeyStatus::Aborted : c.status[0];
  }
  KeyStatus look(int scope, const Chain& ch) {
    auto c = wait(cl->lookup(scope_keys(scope), 0, ch.refs, seconds(5)));
    EXPECT_EQ(c.status.size(), 1u);
    return c.status.empty() ? KeyStatus::Aborted : c.status[0];
  }
  // A crash: the server is gone and the client's session notices.
  void kill(unsigned i) {
    w.srv[i - 1].reset();
    cl->wire_port(i - 1)->endpoint(fabric::EpClass::Control)->abort();
    for (int k = 0; k < 4000 && cl->wire_port(i - 1)->session_up(); ++k) tick_ms(*cl, w);
    ASSERT_FALSE(cl->wire_port(i - 1)->session_up());
  }
  double m(const char* name, unsigned node, const char* result = nullptr) {
    const std::string t = cl->metrics_text();
    const std::string n = "node=\"" + std::to_string(node) + "\"";
    return result ? metric_value(t, name, {n, std::string("result=\"") + result + "\""}) : metric_value(t, name, {n});
  }
  MultiWorld w;
  Client::Env env;
  std::unique_ptr<Client> cl;
  unsigned reps = 1;
  std::vector<PlaceNode> nodes{{"1", 1}, {"2", 1}, {"3", 1}};
};

TEST(WireReplicas, StoreLandsOnBothAndFetchSurvivesThePrimaryDying) {
  RepRig r(/*up=*/7, /*replicas=*/2);
  ASSERT_TRUE(r.cl);
  constexpr int kScopes = 30;
  Chain ch("k", 1), ch2("n", 1);
  unsigned in_set[3] = {0, 0, 0}, primary3 = 0, with3 = 0;
  for (int s = 1; s <= kScopes; ++s) {
    const auto set = r.set_of(s);
    ASSERT_EQ(set.size(), 2u);
    ASSERT_NE(set[0], set[1]);
    for (auto i : set) ++in_set[i];
    primary3 += set[0] == 2;
    with3 += set[0] == 2 || set[1] == 2;
    EXPECT_EQ(r.put(s, ch, s), KeyStatus::Committed) << s;
  }
  ASSERT_GT(primary3, 3u);  // the test spreads over all nodes
  for (unsigned n = 1; n <= 3; ++n) {  // every block was written exactly once per replica node
    EXPECT_EQ(r.m("miracache_client_put_ops_total", n, "committed"), in_set[n - 1]) << n;
    EXPECT_EQ(r.m("miracache_client_replica_legs_total", n, "committed"), in_set[n - 1]) << n;
    EXPECT_EQ(r.m("miracache_client_replica_legs_total", n, "skipped_down"), 0) << n;
  }
  for (int s = 1; s <= kScopes; ++s) {
    bool exact = false;
    EXPECT_EQ(r.get(s, ch, s, &exact), KeyStatus::Hit) << s;
    EXPECT_TRUE(exact) << s;
  }
  for (unsigned n = 1; n <= 3; ++n) EXPECT_EQ(r.m("miracache_client_read_failover_total", n), 0);

  r.kill(3);  // SIGKILL of node 3: the primary of `primary3` scopes
  double failovers = 0;
  for (int s = 1; s <= kScopes; ++s) {
    bool exact = false;
    EXPECT_EQ(r.get(s, ch, s, &exact), KeyStatus::Hit) << s;  // the second replica has it, with exact bytes
    EXPECT_TRUE(exact) << s;
    EXPECT_EQ(r.look(s, ch), KeyStatus::Hit) << s;
  }
  for (unsigned n = 1; n <= 3; ++n) failovers += r.m("miracache_client_read_failover_total", n);
  EXPECT_EQ(failovers, 2.0 * primary3);  // one fetch and one lookup per scope whose primary is down

  // A store with node 3 down goes to the other replica only.
  for (int s = 1; s <= kScopes; ++s) {
    EXPECT_EQ(r.put(s, ch2, 100 + s), KeyStatus::Committed) << s;
    bool exact = false;
    EXPECT_EQ(r.get(s, ch2, 100 + s, &exact), KeyStatus::Hit) << s;
    EXPECT_TRUE(exact) << s;
  }
  EXPECT_EQ(r.m("miracache_client_replica_legs_total", 3, "skipped_down"), with3);
  EXPECT_EQ(r.m("miracache_client_replica_legs_total", 3, "committed"), in_set[2]);  // unchanged since the first round
}

TEST(WireReplicas, BothReplicasDownIsRefusedAndMissNeverAThirdNode) {
  RepRig r(/*up=*/1, /*replicas=*/2);  // only node 1 is up; nodes 2 and 3 are unreachable
  ASSERT_TRUE(r.cl);
  Chain ch("k", 1);
  int dead = 0, half = 0;
  for (int s = 1; s <= 40; ++s) {
    const auto set = r.set_of(s);
    if (set[0] != 0 && set[1] != 0) {  // set {2,3}: no node of the set is up
      ++dead;
      EXPECT_EQ(r.put(s, ch, s), KeyStatus::Refused) << s;
      EXPECT_EQ(r.get(s, ch, s), KeyStatus::Miss) << s;
      EXPECT_EQ(r.look(s, ch), KeyStatus::Miss) << s;
    } else {  // node 1 is in the set: its leg alone carries the store
      ++half;
      EXPECT_EQ(r.put(s, ch, s), KeyStatus::Committed) << s;
      bool exact = false;
      EXPECT_EQ(r.get(s, ch, s, &exact), KeyStatus::Hit) << s;
      EXPECT_TRUE(exact) << s;
    }
  }
  EXPECT_GT(dead, 3);
  EXPECT_GT(half, 3);
  EXPECT_EQ(r.m("miracache_client_put_ops_total", 1, "committed"), half);  // node 1 got nothing from a "third node" scope
}

// Sync mode: the job waits for every leg. Node 3 starts down, so the first store lands only on the other
// replica; when node 3 returns, the same store is a quick "already stored" on that replica (Skipped) and a
// full commit on node 3, and the merge says Committed (no grace cancel).
struct SlowLeg {
  SlowLeg() : r(/*up=*/3, /*replicas=*/2) {
    if (!r.cl) return;
    for (int s = 1; s < 200 && scope < 0; ++s) {
      const auto set = r.set_of(s);
      if (set[1] == 2) scope = s, first = static_cast<unsigned>(set[0]) + 1;
    }
    EXPECT_GE(scope, 0);
    EXPECT_EQ(r.put(scope, ch, 7, 200000), KeyStatus::Committed);  // node 3 is down: one leg
    EXPECT_EQ(r.m("miracache_client_replica_legs_total", 3, "skipped_down"), 1);
    r.w.start(3);
    for (int i = 0; i < 200000 && !r.cl->wire_port(2); ++i) tick_ms(*r.cl, r.w);
    EXPECT_NE(r.cl->wire_port(2), nullptr);
    for (int i = 0; i < 200000 && !r.cl->wire_port(2)->session_up(); ++i) tick_ms(*r.cl, r.w);
  }
  RepRig r;
  int scope = -1;
  unsigned first = 0;  // node id of the first replica
  Chain ch{"k", 1};
};

TEST(WireReplicas, SyncJobWaitsForTheSlowLegAndHoldsExactBytes) {
  SlowLeg t;
  ASSERT_TRUE(t.r.cl);
  ASSERT_GE(t.scope, 0);
  EXPECT_EQ(t.r.put(t.scope, t.ch, 7, 200000), KeyStatus::Committed);  // merge: node 3 committed
  EXPECT_EQ(t.r.m("miracache_client_replica_legs_total", 3, "committed"), 1);
  EXPECT_EQ(t.r.m("miracache_client_replica_legs_total", 3, "cancelled"), 0);
  t.r.kill(t.first);
  bool exact = false;
  EXPECT_EQ(t.r.get(t.scope, t.ch, 7, &exact, 200000), KeyStatus::Hit);  // served by node 3 alone
  EXPECT_TRUE(exact);
  EXPECT_EQ(t.r.m("miracache_client_read_failover_total", 3), 1);
}

TEST(WireReplicas, SyncJobCancelledByTheCallerCancelsEveryLegAndReleasesTheBuffers) {
  RepRig r(/*up=*/7, /*replicas=*/2);
  ASSERT_TRUE(r.cl);
  Chain ch("k", 1);
  Bytes d = payload(200000, 4);
  std::vector<BufRef> pb{{std::span<std::byte>(d)}};
  const Ticket t = r.cl->store(scope_keys(5), 0, ch.refs, pb, seconds(5));
  r.cl->cancel(t);
  auto c = r.wait(t);  // Completion = buffers released on every leg
  ASSERT_EQ(c.status.size(), 1u);
  EXPECT_NE(c.status[0], KeyStatus::Hit);
  std::fill(d.begin(), d.end(), std::byte{0});
  EXPECT_EQ(r.put(6, ch, 1), KeyStatus::Committed);  // the client is healthy afterwards
}

// ---- async mode ----
RepRig::Opts async_opts() {
  RepRig::Opts o;
  o.mode = ReplicaMode::Async;
  return o;
}

TEST(WireReplicas, AsyncStoreLandsOnBothFromTheReplicatorsCopyAndSurvivesThePrimaryDying) {
  RepRig r(/*up=*/7, /*replicas=*/2, async_opts());
  ASSERT_TRUE(r.cl);
  constexpr int kScopes = 30;
  Chain ch("k", 1);
  unsigned in_set[3] = {0, 0, 0}, primary3 = 0;
  for (int s = 1; s <= kScopes; ++s) {
    const auto set = r.set_of(s);
    for (auto i : set) ++in_set[i];
    primary3 += set[0] == 2;
    EXPECT_EQ(r.put(s, ch, s), KeyStatus::Committed) << s;  // put() scribbles on the buffer at the Completion
  }
  ASSERT_GT(primary3, 3u);
  for (unsigned n = 1; n <= 3; ++n) {
    EXPECT_EQ(r.m("miracache_client_put_ops_total", n, "committed"), in_set[n - 1]) << n;
    EXPECT_EQ(r.m("miracache_client_replica_legs_total", n, "committed"), in_set[n - 1]) << n;
    EXPECT_EQ(r.m("miracache_client_replica_legs_total", n, "skipped_full"), 0) << n;
  }
  r.kill(3);
  for (int s = 1; s <= kScopes; ++s) {
    bool exact = false;
    EXPECT_EQ(r.get(s, ch, s, &exact), KeyStatus::Hit) << s;
    EXPECT_TRUE(exact) << s;  // the replica holds the bytes of the copy taken before the engine's leg started
  }
}

// Review r9 S01. The old version measured the shared virtual clock, which the hung leg's own RPC wait drives by 1 ms per
// idle call: it measured replicator spin, not a stall. The rig now counts the idle advances of every calling thread; an
// engine store that waited for the hung replica would sit in drive() on the worker thread until the 60 s job timeout
// (60000 idle advances), one that does not needs a few dozen. The bound is on the WORKER's own count.
TEST(WireReplicas, AsyncHungReplicaNeverStallsTheEngineStore) {
  RepRig r(/*up=*/7, /*replicas=*/2, async_opts());
  ASSERT_TRUE(r.cl);
  std::vector<int> sc;  // scopes whose replica (second node) is node 3, the primary being up
  for (int s = 1; s < 400 && sc.size() < 6; ++s)
    if (r.set_of(s)[1] == 2) sc.push_back(s);
  ASSERT_EQ(sc.size(), 6u);
  Chain ch("k", 1);
  auto put60 = [&](int scope, int seed) {
    Bytes d = payload(5000, seed);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto c = r.wait(r.cl->store(scope_keys(scope), 0, ch.refs, pb, seconds(60)));  // a long virtual job timeout
    EXPECT_EQ(c.status.size(), 1u);
    EXPECT_TRUE(!c.status.empty() && c.status[0] == KeyStatus::Committed);
  };
  put60(sc[0], 1);  // everything healthy
  r.settle();
  // Find the engine worker: the only thread that drives while a fetch (never a replicator job) runs.
  const auto before = r.w.thread_counts();
  bool exact = false;
  EXPECT_EQ(r.get(sc[0], ch, 1, &exact), KeyStatus::Hit);
  std::thread::id worker;
  int moved = 0;
  for (const auto& [tid, c] : r.w.thread_counts()) {
    auto it = before.find(tid);
    if (c.calls > (it == before.end() ? 0 : it->second.calls)) worker = tid, ++moved;
  }
  ASSERT_EQ(moved, 1) << "could not single out the engine worker thread";
  auto idle_of = [&] {
    const auto m = r.w.thread_counts();
    auto it = m.find(worker);
    return it == m.end() ? std::uint64_t{0} : it->second.idle;
  };

  r.w.frozen[2] = true;  // node 3 stops answering: its control endpoint hangs, the replica legs cannot finish
  std::uint64_t worst = 0;
  for (std::size_t i = 1; i < sc.size(); ++i) {
    const auto i0 = idle_of();
    put60(sc[i], static_cast<int>(i) + 1);
    if (i == 1) {
      // r9b T05: the engine store completed while node 3's replica leg is still pending (queued or running). A worker
      // that blocked (future, condvar) on the replicator would drive nothing and pass the idle bound, but its store
      // would complete only after the hung leg ended: node 3 would then show a second leg result already.
      EXPECT_GE(r.cl->replicator_pending(), 1u) << "the store waited for the replica leg";
      double n3 = 0;
      for (const char* res : {"committed", "refused", "cancelled", "skipped_down", "skipped_full"})
        n3 += r.m("miracache_client_replica_legs_total", 3, res);
      EXPECT_EQ(n3, 1) << "node 3's leg of the hung store already ended when the store completed";
    }
    worst = std::max(worst, idle_of() - i0);
  }
  std::fprintf(stderr, "hung replica: worst engine-store idle advances on the worker thread (of 5 stores) = %llu\n",
               static_cast<unsigned long long>(worst));
  EXPECT_LT(worst, 500u) << "an engine store waited for the hung replica (a stall is ~60000 idle advances)";
  r.settle();  // the hung legs end on their own deadline: nothing is left behind
  EXPECT_EQ(r.m("miracache_client_replica_legs_total", 3, "committed"), 1);  // only the healthy one
  // The hung copies ended as refused (timed out), expired in the queue behind the stuck head (cancelled), skipped for
  // a full share (skipped_full) or, once node 3's session fell over, skipped_down.
  EXPECT_EQ(r.m("miracache_client_replica_legs_total", 3, "refused") + r.m("miracache_client_replica_legs_total", 3, "skipped_down") +
                r.m("miracache_client_replica_legs_total", 3, "cancelled") + r.m("miracache_client_replica_legs_total", 3, "skipped_full"),
            5);
}

// Review r9 S02. Node 3 hangs; the copies queued for it must not use up the pool the healthy node 2 needs. With the old
// single global counter, hung copies could use the whole pool and made node 2's replicas skipped_full. Now a node holds at most
// its share (a third of the pool: one copy here), so node 2's replicas keep committing.
TEST(WireReplicas, AsyncOneFrozenNodeDoesNotStarveTheOtherNodesReplicas) {
  RepRig::Opts o = async_opts();
  o.buf = 3 * 8192;  // three copies of the test block (5000 bytes, counted at its 8 KiB size class, r9b T10); a third per node
  RepRig r(/*up=*/7, /*replicas=*/2, o);
  ASSERT_TRUE(r.cl);
  std::vector<int> hung, ok;  // hung: replica = node 3; ok: primary node 1, replica node 2
  for (int s = 1; s < 3000 && (hung.size() < 16 || ok.size() < 6); ++s) {
    const auto set = r.set_of(s);
    if (set[1] == 2 && hung.size() < 16) hung.push_back(s);
    else if (set[0] == 0 && set[1] == 1 && ok.size() < 6) ok.push_back(s);
  }
  ASSERT_EQ(hung.size(), 16u);
  ASSERT_EQ(ok.size(), 6u);
  Chain ch("k", 1);
  auto put120 = [&](int scope, int seed) {
    Bytes d = payload(5000, seed);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto c = r.wait(r.cl->store(scope_keys(scope), 0, ch.refs, pb, seconds(120)));  // clamped to put_max_ms (2.5 s sim)
    ASSERT_EQ(c.status.size(), 1u);
    EXPECT_EQ(c.status[0], KeyStatus::Committed) << scope;
  };
  r.w.frozen[2] = true;
  for (std::size_t i = 0; i < hung.size(); ++i) put120(hung[i], static_cast<int>(i) + 1);
  // Node 2's replica legs (the engine leg is node 1's) all commit while node 3's legs are stuck. Each is awaited before
  // the next store, so node 2's own share (one copy) is free again.
  const double base2 = r.m("miracache_client_replica_legs_total", 2, "committed");  // engine legs of the hung-group stores
  for (std::size_t i = 0; i < ok.size(); ++i) {
    put120(ok[i], 100 + static_cast<int>(i));
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (r.m("miracache_client_replica_legs_total", 2, "committed") < base2 + static_cast<double>(i + 1) &&
           std::chrono::steady_clock::now() < until)
      std::this_thread::yield();
  }
  EXPECT_EQ(r.m("miracache_client_replica_legs_total", 2, "committed"), base2 + 6);
  EXPECT_EQ(r.m("miracache_client_replica_legs_total", 2, "skipped_full"), 0) << "a hung node used up the pool of the healthy ones";
  std::fprintf(stderr, "frozen node 3: skipped_full=%g (held to its share)\n",
               r.m("miracache_client_replica_legs_total", 3, "skipped_full"));
  r.settle();
  // Everything is accounted for on node 3 too (no copy leaked).
  double n3 = 0;
  for (const char* res : {"committed", "refused", "cancelled", "skipped_down", "skipped_full"})
    n3 += r.m("miracache_client_replica_legs_total", 3, res);
  EXPECT_EQ(n3, 16);
  for (std::size_t i = 0; i < ok.size(); ++i) {
    bool exact = false;
    EXPECT_EQ(r.get(ok[i], ch, 100 + static_cast<int>(i), &exact), KeyStatus::Hit);
    EXPECT_TRUE(exact);
  }
}

TEST(WireReplicas, AsyncPoolFullSkipsTheReplicaAndCountsIt) {
  RepRig::Opts o = async_opts();
  o.buf = 4096;  // smaller than one 5000-byte block (8 KiB class)
  RepRig r(/*up=*/7, /*replicas=*/2, o);
  ASSERT_TRUE(r.cl);
  Chain ch("k", 1);
  const auto set = r.set_of(3);
  EXPECT_EQ(r.put(3, ch, 3), KeyStatus::Committed);
  EXPECT_EQ(r.m("miracache_client_replica_legs_total", static_cast<unsigned>(set[1]) + 1, "skipped_full"), 1);
  EXPECT_EQ(r.m("miracache_client_put_ops_total", static_cast<unsigned>(set[1]) + 1, "committed"), 0);
  EXPECT_EQ(r.m("miracache_client_put_ops_total", static_cast<unsigned>(set[0]) + 1, "committed"), 1);
  r.settle();
}

TEST(WireReplicas, AsyncWithBufferZeroIsReplicasOff) {
  RepRig::Opts o = async_opts();
  o.buf = 0;
  RepRig r(/*up=*/7, /*replicas=*/2, o);
  ASSERT_TRUE(r.cl);
  Chain ch("k", 1);
  for (int s = 1; s <= 12; ++s) EXPECT_EQ(r.put(s, ch, s), KeyStatus::Committed);
  double committed = 0;
  for (unsigned n = 1; n <= 3; ++n) committed += r.m("miracache_client_put_ops_total", n, "committed");
  EXPECT_EQ(committed, 12);  // one copy per block
}

TEST(WireReplicas, AsyncShutdownDrainsTheReplicatorBeforeTheNodesGo) {
  RepRig r(/*up=*/7, /*replicas=*/2, async_opts());
  ASSERT_TRUE(r.cl);
  Chain ch("k", 1);
  int n3 = 0;
  r.w.frozen[2] = true;
  for (int s = 1; s < 400 && n3 < 6; ++s) {
    if (r.set_of(s)[1] != 2) continue;
    Bytes d = payload(5000, s);
    std::vector<BufRef> pb{{std::span<std::byte>(d)}};
    auto c = r.wait(r.cl->store(scope_keys(s), 0, ch.refs, pb, seconds(5)));
    ASSERT_EQ(c.status.size(), 1u);
    EXPECT_EQ(c.status[0], KeyStatus::Committed);
    ++n3;
  }
  ASSERT_EQ(n3, 6);
  r.cl->shutdown();  // legs queued behind the hung one are dropped, the running one is cancelled and force-failed
  EXPECT_EQ(r.cl->replicator_pending(), 0u);
  EXPECT_EQ(r.cl->replica_buffer_in_use(), 0u);
  double legs = 0;
  for (const char* res : {"committed", "refused", "cancelled"}) legs += r.m("miracache_client_replica_legs_total", 3, res);
  EXPECT_EQ(legs, n3);  // every replica leg is accounted for
}

// (c) The per-leg watchdog. A leg whose WRITE completion never arrives is force-failed at its job's deadline +
// grace, like a single-node job; the other leg's result is unaffected, in both modes.
// (The deadline is 2 s of virtual time: the stuck leg spins the shared virtual clock, so a short one could expire the healthy leg.)
void wd_leg_test(ReplicaMode mode) {
  std::unique_ptr<SteppingFabric> dropper;
  RepRig::Opts o;
  o.mode = mode;
  o.watchdog = seconds(1);
  o.wrap3 = [&](fabric::Fabric& in) -> fabric::Fabric* {
    dropper = std::make_unique<SteppingFabric>(in, [] {});
    return dropper.get();
  };
  RepRig r(/*up=*/7, /*replicas=*/2, o);
  ASSERT_TRUE(r.cl);
  int scope = -1;
  for (int s = 1; s < 400 && scope < 0; ++s)
    if (r.set_of(s)[1] == 2) scope = s;
  ASSERT_GE(scope, 0);
  Chain ch("k", 1);
  dropper->drop_completion = [](const fabric::Completion& x) { return x.op == fabric::CompletionOp::Write; };
  r.w.stuck_leg = true;  // the stuck leg spins the shared clock: throttle it like a frozen node's waiters
  Bytes d = payload(5000, 9);
  std::vector<BufRef> pb{{std::span<std::byte>(d)}};
  auto c = r.wait(r.cl->store(scope_keys(scope), 0, ch.refs, pb, seconds(2)));
  ASSERT_EQ(c.status.size(), 1u);
  EXPECT_EQ(c.status[0], KeyStatus::Committed);  // the first leg committed; the stuck leg cannot veto it
  r.settle();
  EXPECT_EQ(r.cl->watchdog_trips(), 1u) << "the stuck leg must trip the watchdog exactly once";
  EXPECT_EQ(r.m("miracache_client_replica_legs_total", 3, "committed"), 0);
  dropper->drop_completion = nullptr;
  r.w.stuck_leg = false;
  // The trip took node 3's session down; it reconnects and the client keeps working.
  for (int i = 0; i < 200000 && !r.cl->wire_port(2)->session_up(); ++i) tick_ms(*r.cl, r.w);
  ASSERT_TRUE(r.cl->wire_port(2)->session_up());
  EXPECT_EQ(r.put(scope + 1000, ch, 2), KeyStatus::Committed);
}
TEST(WireReplicas, WatchdogForceFailsAStuckLegInSyncMode) { wd_leg_test(ReplicaMode::Sync); }
TEST(WireReplicas, WatchdogForceFailsAStuckLegOnTheReplicator) { wd_leg_test(ReplicaMode::Async); }

// ---- zones ----
TEST(WireReplicas, ZonesKeepEveryReplicaSetAcrossZonesAndTheOwnerIsUnchanged) {
  RepRig::Opts o = async_opts();
  o.zones = {"a", "a", "b"};  // nodes 1 and 2 share a zone
  RepRig r(/*up=*/7, /*replicas=*/2, o);
  ASSERT_TRUE(r.cl);
  const std::vector<PlaceNode> plain{{"1", 1}, {"2", 1}, {"3", 1}};
  Chain ch("k", 1);
  for (int s = 1; s <= 30; ++s) {
    auto sk = scope_keys(s);
    const auto set = r.set_of(s);
    ASSERT_EQ(set.size(), 2u);
    EXPECT_TRUE(set[0] == 2 || set[1] == 2) << "a set must contain node 3 (the only node outside zone a)";
    EXPECT_EQ(set[0], place_owner(plain, std::span<const std::uint8_t, 32>(sk.scopes[0].b)));  // zones never move the owner
    EXPECT_EQ(r.put(s, ch, s), KeyStatus::Committed);
  }
  r.kill(3);  // the whole of zone b: zone a's nodes still hold a copy of every scope whose owner is in a
  int hits = 0, owner3 = 0;
  for (int s = 1; s <= 30; ++s) {
    owner3 += r.set_of(s)[0] == 2;
    bool exact = false;
    if (r.get(s, ch, s, &exact) == KeyStatus::Hit) {
      ++hits;
      EXPECT_TRUE(exact);
    }
  }
  EXPECT_EQ(hits, 30);  // owners in zone a stay up; scopes owned by node 3 fail over to their zone-a replica
  EXPECT_GT(owner3, 3);
}

TEST(WireReplicas, OpenRejectsBadZones) {
  MultiWorld w(3);
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  env.replicas = 2;
  {  // every replica needs its own zone: R=2 in one zone is a config error
    std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
    for (auto& s : specs) s.zone = "a";
    auto c = Client::open_wire_nodes(env, std::move(specs));
    ASSERT_FALSE(c);
    EXPECT_EQ(c.error().code, ErrorCode::InvalidArgument);
  }
  {  // all nodes or none
    std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
    specs[0].zone = "a";
    specs[1].zone = "b";
    EXPECT_FALSE(Client::open_wire_nodes(env, std::move(specs)));
  }
}

TEST(WireReplicas, OpenRejectsTooFewNodesForTheReplicaCount) {
  MultiWorld w(2);
  SimClock& clock = w.clock;
  Client::Env env;
  env.clock = &clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  env.replicas = 2;  // two nodes: needs three
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2)};
  auto c = Client::open_wire_nodes(env, std::move(specs));
  ASSERT_FALSE(c);
  EXPECT_EQ(c.error().code, ErrorCode::InvalidArgument);
  env.replicas = 4;
  std::vector<Client::NodeSpec> specs2{w.spec(1), w.spec(2), w.spec(3)};
  EXPECT_FALSE(Client::open_wire_nodes(env, std::move(specs2)));
}

// N10: the build inside Client::open keeps the fabric default connect timeout; the later builds of a node
// that was unreachable at open (its keepalive thread) use the short one, like a reconnect: a blackholed
// address may not hold the keepalive thread for the default connect time.
TEST(WirePlacement, BackgroundBuildsOfAnUnreachableNodeUseTheShortConnectTimeout) {
  MultiWorld w(/*up=*/3);
  SteppingFabric dark3(*w.cfab[2], [] {});
  std::mutex mu;
  std::vector<fabric::ConnParams> seen;  // connect attempts that reached node 3's fabric
  dark3.block_connect = [&](const fabric::ConnParams& cp) {
    std::lock_guard lk(mu);
    seen.push_back(cp);
    return true;  // swallowed (a real blackhole would sleep up to cp.timeout)
  };
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  auto s3 = w.spec(3);
  s3.fab = &dark3;
  s3.wopts.reconnect_connect_ms = 250;
  s3.wopts.reconnect_min_ms = 1;
  s3.wopts.reconnect_max_ms = 2;
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), std::move(s3)};
  auto cl = Client::open_wire_nodes(env, std::move(specs));
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  EXPECT_EQ(c.wire_port(2), nullptr);
  const Nanos until = w.clock.now() + milliseconds(100);  // virtual time moves slowly (only when a tick finds nothing to do)
  for (int i = 0; i < 200000 && w.clock.now() < until; ++i) tick_ms(c, w);  // the later builds, from the keepalive path
  c.shutdown();
  std::lock_guard lk(mu);
  ASSERT_GE(seen.size(), 2u);  // one at open, at least one more from the keepalive ticks
  // Q01: the build inside Client::open keeps the fabric default; only the keepalive-thread builds are short.
  EXPECT_EQ(seen[0].timeout, fabric::ConnParams{}.timeout);
  for (std::size_t i = 1; i < seen.size(); ++i) EXPECT_EQ(seen[i].timeout, milliseconds(250)) << "background build " << i;
}

TEST(WirePlacement, OpenFailsWhenNoNodeIsReachable) {
  MultiWorld w(/*up=*/0);
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2)};
  auto cl = Client::open_wire_nodes(env, std::move(specs));
  EXPECT_FALSE(cl);
}

TEST(WireReconnect, ShutdownDuringABlockedConnectIsPrompt) {
  Blackhole b(/*connect_ms=*/1000);
  ASSERT_TRUE(b.cl);
  b.go_dark();
  const auto t0 = std::chrono::steady_clock::now();
  b.cl->shutdown();
  EXPECT_LT(std::chrono::steady_clock::now() - t0, milliseconds(1500)) << "~Client must not wait out a connect";
}


// ---- r5 (Q02/Q04/Q05): background builds, half-dead peers, stuck jobs --------------------------------
struct BuildSetup {
  explicit BuildSetup(unsigned up) : w(up) {
    env.clock = &w.clock;
    env.executor = &w.cex;
    env.salts = &w.salts;
    env.drive = [this] { w.drive(); };
  }
  Client::NodeSpec bg_spec(unsigned i, fabric::Fabric* fab, unsigned connect_ms = 250) {
    auto s = w.spec(i);
    s.fab = fab;
    s.wopts.reconnect_connect_ms = connect_ms;
    s.wopts.reconnect_min_ms = 1;
    s.wopts.reconnect_max_ms = 2;
    s.wopts.rpc_timeout = seconds(30);  // far above the short background cap
    return s;
  }
  Expected<std::unique_ptr<Client>> open(std::vector<Client::NodeSpec> specs) {
    RuntimeOptions ro;
    ro.workers = 1;
    return Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  }
  MultiWorld w;
  Client::Env env;
};

// Q02: a background build (memnode unreachable at open) uses the short connect on ALL three endpoints:
// the earlier endpoints connect, then the address of `blocked` is blackholed. N10: once with fetch
// blackholed, once with ingest (control and fetch accepted), so the ingest connect is observed too.
TEST(WireBuild, BackgroundBuildUsesTheShortConnectOnEveryEndpoint) {
  for (const fabric::EpClass blocked : {fabric::EpClass::Fetch, fabric::EpClass::Ingest}) {
    SCOPED_TRACE(blocked == fabric::EpClass::Fetch ? "fetch blackholed" : "ingest blackholed");
    BuildSetup b(/*up=*/1);  // memnode 2 is not started: unreachable at open
    SteppingFabric half(*b.w.cfab[1], [] {});
    std::mutex mu;
    std::vector<std::pair<fabric::EpClass, Nanos>> seen;
    half.block_connect = [&](const fabric::ConnParams& cp) {
      std::lock_guard lk(mu);
      seen.emplace_back(cp.cls, cp.timeout);
      return cp.cls == blocked;  // the endpoints before it are accepted, this one is swallowed
    };
    auto cl = b.open({b.bg_spec(1, b.w.cfab[0]), b.bg_spec(2, &half)});
    ASSERT_TRUE(cl) << cl.error().context;
    Client& c = **cl;
    b.w.start(2);
    for (int i = 0; i < 200000; ++i) {
      tick_ms(c, b.w);
      std::lock_guard lk(mu);
      if (std::any_of(seen.begin(), seen.end(), [&](auto& p) { return p.first == blocked; })) break;
    }
    {
      std::lock_guard lk(mu);
      ASSERT_FALSE(seen.empty()) << "virtual now " << b.w.clock.now().count() << " ns, c.wire_port(1)=" << (c.wire_port(1) != nullptr);
      bool saw_blocked = false, saw_fetch = false;
      for (const auto& [cls, to] : seen) {
        saw_blocked |= cls == blocked;
        saw_fetch |= cls == fabric::EpClass::Fetch;
        EXPECT_EQ(to, milliseconds(250)) << "endpoint class " << static_cast<int>(cls) << " must use reconnect_connect_ms";
      }
      EXPECT_TRUE(saw_blocked);
      EXPECT_TRUE(saw_fetch);
    }
    EXPECT_EQ(c.wire_port(1), nullptr);
    c.shutdown();
  }
}


// Q01: the first Client::open build keeps the fabric default connect timeout (reconnect_connect_ms is
// for builds and reconnects that run on the keepalive thread).
TEST(WireBuild, FirstOpenKeepsTheDefaultConnectTimeout) {
  BuildSetup b(/*up=*/2);
  SteppingFabric f1(*b.w.cfab[1], [] {});
  std::mutex mu;
  std::vector<Nanos> seen;
  f1.block_connect = [&](const fabric::ConnParams& cp) {
    std::lock_guard lk(mu);
    seen.push_back(cp.timeout);
    return false;
  };
  auto cl = b.open({b.bg_spec(1, b.w.cfab[0]), b.bg_spec(2, &f1)});
  ASSERT_TRUE(cl) << cl.error().context;
  (**cl).shutdown();
  std::lock_guard lk(mu);
  ASSERT_EQ(seen.size(), 3u);  // control, fetch, ingest
  for (auto t : seen) EXPECT_EQ(t, fabric::ConnParams{}.timeout);
}

// Q02: a HELLO to a memnode that accepted the control connect but never answers is cut at the short RPC
// cap (not rpc_timeout = 30 s), and a shutdown during it aborts the build at once.
struct HelloBlackhole : BuildSetup {
  HelloBlackhole()
      : BuildSetup(1), half(*w.cfab[1], [this] {
          if (armed.load() && ctl_seen.load() && !w.frozen[1].exchange(true)) frozen_at = w.clock.now();
          if (on_poll) on_poll();
        }) {
    half.block_connect = [this](const fabric::ConnParams& cp) {
      if (cp.cls == fabric::EpClass::Control) ctl_seen = true;
      return false;
    };
    auto c = open({bg_spec(1, w.cfab[0]), bg_spec(2, &half)});
    EXPECT_TRUE(c);
    if (c) cl = std::move(*c);
    w.start(2);
    ctl_seen = false;
    armed = true;  // from now on: control connect OK, then the server goes silent
  }
  SteppingFabric half;
  std::unique_ptr<Client> cl;
  std::atomic<bool> armed{false}, ctl_seen{false};
  Nanos frozen_at{0};
  std::function<void()> on_poll;
};

TEST(WireBuild, BackgroundHelloIsCutAtTheShortRpcCap) {
  HelloBlackhole h;
  ASSERT_TRUE(h.cl);
  for (int i = 0; i < 200000 && h.frozen_at == Nanos{0}; ++i) tick_ms(*h.cl, h.w);
  ASSERT_NE(h.frozen_at, Nanos{0});
  const Nanos took = h.w.clock.now() - h.frozen_at;
  EXPECT_LE(took, seconds(3)) << "a background HELLO must give up at the short cap, not rpc_timeout";
  EXPECT_EQ(h.cl->wire_port(1), nullptr);
  h.cl->shutdown();
}

TEST(WireBuild, ShutdownAbortsABackgroundBuildInFlight) {
  HelloBlackhole h;
  ASSERT_TRUE(h.cl);
  Nanos shut_at{0};
  h.on_poll = [&] {
    if (h.frozen_at != Nanos{0} && shut_at == Nanos{0} && h.w.clock.now() - h.frozen_at >= milliseconds(50)) {
      shut_at = h.w.clock.now();
      h.cl->shutdown();  // what stop_keepalive on another thread does
    }
  };
  for (int i = 0; i < 200000 && shut_at == Nanos{0}; ++i) tick_ms(*h.cl, h.w);
  ASSERT_NE(shut_at, Nanos{0});
  const Nanos end = h.w.clock.now();
  EXPECT_LE(end - shut_at, milliseconds(200)) << "the build must notice the abort, not wait out the HELLO";
  h.on_poll = nullptr;
}

// Q04: a memnode that fails HELLO (server node_id != nodes[].id) must not leak endpoints across the
// first-build retries, and the retries back off.
TEST(WireBuild, FailedFirstBuildsReleaseTheirEndpointsAndBackOff) {
  BuildSetup b(/*up=*/1);
  b.w.start(2, /*node_id=*/9);  // HELLO_ACK says 9, the client expects 2
  SteppingFabric f2(*b.w.cfab[1], [] {});
  std::atomic<int> connects{0};
  f2.block_connect = [&](const fabric::ConnParams& cp) {
    if (cp.cls == fabric::EpClass::Control) ++connects;
    return false;
  };
  auto s2 = b.bg_spec(2, &f2);
  s2.wopts.reconnect_min_ms = 50;
  s2.wopts.reconnect_max_ms = 400;
  auto cl = b.open({b.bg_spec(1, b.w.cfab[0]), std::move(s2)});
  ASSERT_TRUE(cl) << cl.error().context;  // memnode 1 is fine
  Client& c = **cl;
  EXPECT_EQ(c.wire_port(1), nullptr);
  const std::size_t base = b.w.cfab[1]->endpoint_count();
  EXPECT_EQ(base, 0u) << "the failed build at open left endpoints behind";
  const Nanos until = b.w.clock.now() + milliseconds(1500);
  for (int i = 0; i < 200000 && b.w.clock.now() < until; ++i) tick_ms(c, b.w);
  EXPECT_EQ(b.w.cfab[1]->endpoint_count(), base) << "endpoints grew across failed first builds";
  EXPECT_LE(connects.load(), 8) << "first-build retries must back off (1500 ms virtual, an id mismatch retries every 200-400 ms)";
  EXPECT_GE(connects.load(), 2);
  c.shutdown();
}

// Q05: a job whose completion never arrives is force-failed after deadline + grace, so jobs_inside
// drains and shutdown returns.
TEST(WireBuild, WatchdogForceFailsAJobWhoseCompletionNeverArrives) {
  BuildSetup b(/*up=*/1);
  SteppingFabric dropper(*b.w.cfab[0], [] {});
  b.env.watchdog_grace = seconds(1);  // virtual time, a lot of drive steps per second of it
  auto cl = b.open({b.bg_spec(1, &dropper)});
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  auto wait = [&](Ticket t, seconds cap) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + cap;
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion: the stuck job was never force-failed";
    return Completion{};
  };
  Chain ch("k", 1);
  auto sk = scope_keys(1);
  std::vector<Bytes> data{payload(5000, 1)};
  std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
  auto sc = wait(c.store(sk, 0, ch.refs, pb, seconds(5)), seconds(20));
  ASSERT_EQ(sc.status.size(), 1u);
  ASSERT_EQ(sc.status[0], KeyStatus::Committed);

  dropper.drop_completion = [](const fabric::Completion& x) { return x.op == fabric::CompletionOp::Read; };
  std::vector<Bytes> out{Bytes(5000, std::byte{0xAA})};
  std::vector<BufRef> fb{{std::span<std::byte>(out[0])}};
  auto fc = wait(c.fetch(sk, 0, ch.refs, fb, milliseconds(100)), seconds(30));
  ASSERT_EQ(fc.status.size(), 1u);
  EXPECT_NE(fc.status[0], KeyStatus::Hit);
  EXPECT_EQ(c.watchdog_trips(), 1u);

  // Q02: the trip took the session down; it reconnects and the same key hits again (the dropped READ's
  // endpoint drained, so its quarantined spans came back and the pool is not exhausted).
  dropper.drop_completion = nullptr;  // the worker is idle: the fetch above was released
  WirePort* wp = c.wire_port(0);
  ASSERT_NE(wp, nullptr);
  for (int i = 0; i < 200000 && !wp->session_up(); ++i) tick_ms(c, b.w);
  ASSERT_TRUE(wp->session_up()) << "no reconnect after the watchdog trip";
  EXPECT_GE(wp->session_down_count(), 1u);
  for (int round = 0; round < 3; ++round) {
    std::vector<Bytes> again{Bytes(5000, std::byte{0xAA})};
    std::vector<BufRef> ab{{std::span<std::byte>(again[0])}};
    auto hc = wait(c.fetch(sk, 0, ch.refs, ab, seconds(5)), seconds(20));
    ASSERT_EQ(hc.status.size(), 1u);
    EXPECT_EQ(hc.status[0], KeyStatus::Hit) << "round " << round;
    EXPECT_EQ(again[0], data[0]);
  }
  EXPECT_EQ(c.watchdog_trips(), 1u);
  EXPECT_EQ(metric(c.metrics_text(), "miracache_client_quarantined_bytes"), 0);

  std::atomic<bool> closed{false};
  std::thread t([&] {
    c.shutdown();
    closed = true;
  });
  const auto until = std::chrono::steady_clock::now() + seconds(20);
  while (!closed && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(milliseconds(5));
  if (!closed) {
    ADD_FAILURE() << "shutdown hangs behind the stuck job";
    std::_Exit(1);  // the worker pool would join forever
  }
  t.join();
}


// ---- r5b (N01-N05): metrics unbind, watchdog quarantine, per-node build abort ---------------------------

// N01: a build whose control endpoint connects but whose link dies before the HELLO reply fails after
// ClientCore::init bound its metrics into the port and (through on_metrics) the ticket source. Both outlive
// the dead core: nothing may keep its ClientMetrics. The on_metrics/prepare pair below is what the admin
// ticket source does (wire_open.cpp): prepare() writes the cache gauge before every keepalive build.
// Under asan the old code fails here with heap-use-after-free.
TEST(WireBuild, FailedBuildUnbindsItsMetricsFromPortAndTicketSource) {
  BuildSetup b(/*up=*/2);
  std::atomic<bool> cut_armed{false}, cut_done{false};
  SteppingFabric f2(*b.w.cfab[1], [&] {
    if (cut_armed.exchange(false)) b.w.net.set_link(2, 12, false), cut_done = true;  // control is connected, HELLO is in flight
  });
  f2.block_connect = [&](const fabric::ConnParams& cp) {
    if (cut_done) return true;  // the link is down: later connects fail at once
    if (cp.cls == fabric::EpClass::Control) cut_armed = true;
    return false;
  };
  ClientMetrics* held = nullptr;
  int binds = 0, prepares = 0, gauge_writes = 0;
  auto s2 = b.bg_spec(2, &f2);
  s2.wopts.rpc_timeout = milliseconds(300);  // the open-time HELLO (not background) waits at most this
  s2.wopts.on_metrics = [&](ClientMetrics* m) {
    held = m;
    binds += m != nullptr;
  };
  s2.wopts.prepare = [&] {
    ++prepares;
    if (held) held->ticket_cache[0]->set(7), ++gauge_writes;  // a dangling pointer here is the N01 bug
  };
  auto cl = b.open({b.bg_spec(1, b.w.cfab[0]), std::move(s2)});
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  EXPECT_EQ(c.wire_port(1), nullptr) << "node 2 must have failed its first build";
  EXPECT_GE(binds, 1) << "the failed build never bound its metrics: the test does not reach the N01 path";
  EXPECT_EQ(held, nullptr) << "the failed build left its ClientMetrics bound";
  for (int i = 0; i < 200000 && prepares < 3; ++i) tick_ms(c, b.w);  // keepalive builds: prepare, bind, fail
  EXPECT_GE(prepares, 3);
  EXPECT_EQ(held, nullptr);
  EXPECT_EQ(gauge_writes, 0);
  c.shutdown();
}

// Completions the test holds back (a wedged QP that has not flushed yet). While a completion of an
// endpoint is held the endpoint is not drained, so the fabric refuses to release it (as verbs would).
class HoldingFabric final : public fabric::Fabric {
 public:
  explicit HoldingFabric(fabric::Fabric& in) : in_(in) {}
  Expected<fabric::DeviceCaps> probe() override { return in_.probe(); }
  Expected<fabric::PdId> alloc_pd() override { return in_.alloc_pd(); }
  Status free_pd(fabric::PdId pd) override { return in_.free_pd(pd); }
  Expected<fabric::MemRegion> reg(std::span<std::byte> b, fabric::Access a, fabric::PdId pd) override { return in_.reg(b, a, pd); }
  Status dereg(const fabric::MemRegion& r) override { return in_.dereg(r); }
  Expected<fabric::Endpoint*> connect(const fabric::Peer& p, const fabric::ConnParams& c) override { return in_.connect(p, c); }
  Status release(fabric::Endpoint* e) override {
    if (stuck.count(e->id())) return Error{ErrorCode::Busy, "test: this endpoint lost a flush and never drains"};
    for (const auto& h : held)
      if (h.endpoint == e->id()) return Error{ErrorCode::Busy, "test: a completion of this endpoint is still held"};
    ++released;
    return in_.release(e);
  }
  Status listen(fabric::AcceptFn f, const fabric::ListenParams& lp) override { return in_.listen(std::move(f), lp); }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget b) override {
    if (step) step();
    std::size_t n = 0;
    if (deliver) {  // the held completions come out first, in order
      while (n < out.size() && !held.empty()) {
        out[n++] = std::move(held.front());
        held.pop_front();
      }
      if (held.empty()) deliver = false;
    }
    std::size_t m = in_.poll(out.subspan(n), b);
    std::size_t k = n;
    for (std::size_t i = n; i < n + m; ++i) {
      if (hold && hold(out[i])) {
        held.push_back(std::move(out[i]));
        continue;
      }
      if (k != i) out[k] = std::move(out[i]);
      ++k;
    }
    return k;
  }
  int wait_fd() override { return in_.wait_fd(); }
  std::function<bool(const fabric::Completion&)> hold;
  std::function<void()> step;
  std::deque<fabric::Completion> held;
  std::set<fabric::EndpointId> stuck;  // Q01: endpoints whose completion is gone for good
  bool deliver = false;
  int released = 0;

 private:
  fabric::Fabric& in_;
};

struct HoldWorld {
  HoldWorld() : hf(w.cli) {
    w.port = std::make_unique<WirePort>(hf, w.clock, w.salts, w.wire_opts());
    auto c = ClientCore::create(w.port->fabric(), *w.port, w.clock, w.cex, w.salts, {});
    EXPECT_TRUE(c);
    if (c) w.core = std::move(*c);
  }
  // keepalive + pump + drive until `pred` (the Client keepalive thread and a worker, single-threaded)
  template <class P>
  bool tick_until(P pred, int cap = 40000) {
    for (int i = 0; i < cap; ++i) {
      w.port->keepalive();
      w.core->pump();
      if (pred()) return true;
      w.drive();
    }
    return false;
  }
  ~HoldWorld() {  // the core and port use hf: they go first
    w.core.reset();
    w.port.reset();
  }
  double m(const std::string& series) { return metric(w.core->metrics_text(), series); }
  World w;
  HoldingFabric hf;
};

bool is_read(const fabric::Completion& c) { return !c.is_recv && c.op == fabric::CompletionOp::Read; }

// N02: a force-failed fetch whose READ completion never came keeps its spans out of the pool until the
// wedged endpoint is aborted, drained and reaped. The test holds the READ completion, so the endpoint
// cannot drain; meanwhile it scribbles over the quarantined spans on every poll (a late DMA landing at any
// time). The session reconnects and new fetches still hit with the right bytes: no span was reused. Then
// the late completion is delivered, the endpoint is reaped and the spans come back.
TEST(WireWatchdog, ForceFailQuarantinesSpansUntilTheWedgedEndpointIsReaped) {
  HoldWorld h;
  ASSERT_TRUE(h.w.core);
  World& w = h.w;
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(5000, 3)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);

  h.hf.hold = is_read;
  Bytes out(5000, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  Res r;
  const Nanos deadline = w.clock.now() + milliseconds(100);
  const Ticket t = w.core->submit_fetch(sk, 0, ch.refs, fb, deadline, w.notify(r));
  ASSERT_TRUE(w.spin([&] { return w.clock.now() > deadline + milliseconds(50); }));
  ASSERT_FALSE(h.hf.held.empty()) << "the READ completion must be held";
  EXPECT_FALSE(r.released) << "the READ is still outstanding";
  const std::uint64_t downs = w.port->session_down_count();
  EXPECT_GE(w.core->force_fail(t), 1u);
  EXPECT_TRUE(w.spin([&] { return r.released; }));
  ASSERT_EQ(r.st.size(), 1u);
  EXPECT_EQ(r.st[0], KeyStatus::Timeout);
  EXPECT_TRUE(all_zero(out)) << "a force-failed fetch must leave the engine buffer zeroed";
  EXPECT_GT(w.core->quarantined_bytes(), 0u);
  EXPECT_EQ(w.core->pool_bytes_in_use(), w.core->quarantined_bytes());
  EXPECT_EQ(h.m("miracache_client_watchdog_trips_total"), 1);
  EXPECT_EQ(h.m("miracache_client_quarantined_bytes"), static_cast<double>(w.core->quarantined_bytes()));
  // The trip marked the fetch endpoint dead: the session went Down (and every endpoint was aborted).
  EXPECT_EQ(w.port->session_down_count(), downs + 1);
  EXPECT_FALSE(w.port->session_up());

  h.hf.hold = nullptr;  // new READs complete normally; the old one stays held
  const std::size_t qb = w.core->quarantined_bytes();
  std::vector<std::span<std::byte>> q = w.core->quarantined_spans();
  ASSERT_FALSE(q.empty());
  h.hf.step = [&] {
    for (auto s : q) std::memset(s.data(), 0xEE, s.size());
  };
  ASSERT_TRUE(h.tick_until([&] { return w.port->session_up(); })) << "no reconnect after the trip";
  for (int round = 0; round < 3; ++round) {
    Bytes o(5000, std::byte{0xAA});
    std::vector<Bytes> outs{o};
    auto st = w.fetch(sk, ch, outs);
    ASSERT_EQ(st.size(), 1u);
    EXPECT_EQ(st[0], KeyStatus::Hit) << "round " << round << ": a quarantined span was handed out again";
    EXPECT_EQ(outs[0], data[0]);
    for (int i = 0; i < 20; ++i) w.port->keepalive(), w.core->pump(), w.drive();  // reap attempts
    EXPECT_EQ(w.core->quarantined_bytes(), qb) << "released before the wedged endpoint was reaped";
  }

  h.hf.step = nullptr;  // the late DMA has landed; its completion arrives now
  h.hf.deliver = true;
  ASSERT_TRUE(h.tick_until([&] { return w.core->quarantined_bytes() == 0; })) << "quarantine never released after the reap";
  EXPECT_TRUE(h.hf.held.empty());
  EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
  EXPECT_EQ(h.m("miracache_client_quarantined_bytes"), 0);
  w.check();
}

// N05: the late READ completion arrives right after force_fail, while the job still waits for its decrypt
// task (fetch_on_cqe's abandoned-op guard): no crash, the buffer is zeroed, the pool accounting is exact.
TEST(WireWatchdog, LateReadCompletionAfterForceFailIsIgnored) {
  HoldWorld h;
  ASSERT_TRUE(h.w.core);
  World& w = h.w;
  auto sk = scope_keys(2);
  Chain ch("late", 2);
  std::vector<Bytes> data{payload(5000, 5), payload(9000, 6)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);

  h.hf.hold = is_read;
  std::vector<Bytes> out{Bytes(5000, std::byte{0xAA}), Bytes(9000, std::byte{0xAA})};
  std::vector<BufRef> fb{{std::span<std::byte>(out[0])}, {std::span<std::byte>(out[1])}};
  Res r;
  const Nanos deadline = w.clock.now() + milliseconds(100);
  const Ticket t = w.core->submit_fetch(sk, 0, ch.refs, fb, deadline, w.notify(r));
  ASSERT_TRUE(w.spin([&] { return w.clock.now() > deadline + milliseconds(50); }));
  ASSERT_EQ(h.hf.held.size(), 2u);
  EXPECT_EQ(w.core->force_fail(t), 2u);
  const std::size_t qb = w.core->quarantined_bytes();
  EXPECT_GT(qb, 0u);
  h.hf.hold = nullptr;
  h.hf.deliver = true;  // the very next poll hands the late completions to the core
  EXPECT_TRUE(w.spin([&] { return r.released; }));
  EXPECT_TRUE(h.hf.held.empty());
  for (auto s : r.st) EXPECT_EQ(s, KeyStatus::Timeout);
  for (auto& o : out) EXPECT_TRUE(all_zero(o));
  EXPECT_EQ(w.core->quarantined_bytes(), qb) << "a late completion must not release a quarantined span";
  EXPECT_EQ(w.core->pool_bytes_in_use(), qb);
  ASSERT_TRUE(h.tick_until([&] { return w.port->session_up() && w.core->quarantined_bytes() == 0; }));
  EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
  std::vector<Bytes> again{Bytes(5000), Bytes(9000)};
  for (auto s : w.fetch(sk, ch, again)) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(again[1], data[1]);
  w.check();
}

// N05/N08: store variant. One WRITE of a two-key batch never completes: force_fail quarantines only its
// span and gives the completed WRITE's span back at once. (The put_cancel it sends is usually flushed by
// the ingest abort that follows, Q07; the server's put TTL frees the put then. Not asserted.)
TEST(WireWatchdog, StoreForceFailReleasesCompletedWritesAndQuarantinesTheRest) {
  HoldWorld h;
  ASSERT_TRUE(h.w.core);
  World& w = h.w;
  auto sk = scope_keys(3);
  Chain ch("w", 2);
  std::vector<Bytes> data{payload(5000, 7), payload(5000, 8)};
  h.hf.hold = [](const fabric::Completion& c) {
    return !c.is_recv && c.op == fabric::CompletionOp::Write && ((c.tag >> 2) & 0x3fffffff) == 0;  // key 0 only
  };
  std::vector<BufRef> pb{{std::span<std::byte>(data[0])}, {std::span<std::byte>(data[1])}};
  Res r;
  const Nanos deadline = w.clock.now() + milliseconds(100);
  const Ticket t = w.core->submit_store(sk, 0, ch.refs, pb, deadline, w.notify(r));
  ASSERT_TRUE(w.spin([&] { return w.clock.now() > deadline + milliseconds(50); }));
  ASSERT_EQ(h.hf.held.size(), 1u) << "key 0's WRITE completion must be held";
  EXPECT_FALSE(r.released);
  const std::size_t before = w.core->pool_bytes_in_use();
  EXPECT_EQ(w.core->force_fail(t), 1u);
  EXPECT_TRUE(r.released);
  for (auto s : r.st) EXPECT_EQ(s, KeyStatus::Timeout);
  EXPECT_GT(w.core->quarantined_bytes(), 0u);
  EXPECT_LT(w.core->quarantined_bytes(), before) << "the completed WRITE's span must not be quarantined";
  EXPECT_EQ(w.core->pool_bytes_in_use(), w.core->quarantined_bytes()) << "N08: completed-WRITE span leaked";
  EXPECT_FALSE(w.port->session_up()) << "the trip marks the ingest endpoint dead";
  h.hf.hold = nullptr;
  h.hf.deliver = true;
  ASSERT_TRUE(h.tick_until([&] { return w.port->session_up() && w.core->quarantined_bytes() == 0; }));
  EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
  for (auto s : w.put(sk, ch, data)) EXPECT_TRUE(s == KeyStatus::Committed || s == KeyStatus::Skipped);
  w.settle();
  w.check();
}

// ---- r5c (Q01/Q02/Q06): per-session quarantine release, the untested force_fail paths ----------------

// Submits a fetch whose READ completions the HoldingFabric holds, and runs until it is past its deadline.
Ticket held_fetch(HoldWorld& h, const ScopeKeys& sk, const Chain& ch, std::vector<BufRef>& fb, Res& r) {
  h.hf.hold = is_read;
  const Nanos deadline = h.w.clock.now() + milliseconds(100);
  const Ticket t = h.w.core->submit_fetch(sk, 0, ch.refs, fb, deadline, h.w.notify(r));
  EXPECT_TRUE(h.w.spin([&] { return h.w.clock.now() > deadline + milliseconds(50); }));
  EXPECT_FALSE(h.hf.held.empty()) << "the READ completion must be held";
  EXPECT_FALSE(r.released);
  return t;
}

// Q01: trip 1's READ completion is lost for good, so its fetch endpoint never drains and the fabric never
// releases it. That must hold back only trip 1's spans: trip 2, on the next session, gets its spans back
// once its own endpoints are reaped. The old single `reaped_down` counter never moved past trip 1.
TEST(WireWatchdog, NeverDrainingZombieHoldsBackOnlyItsOwnTrip) {
  HoldWorld h;
  ASSERT_TRUE(h.w.core);
  World& w = h.w;
  auto sk = scope_keys(4);
  Chain ch("z", 1);
  std::vector<Bytes> data{payload(5000, 9)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);

  Bytes out1(5000, std::byte{0xAA});
  std::vector<BufRef> fb1{{std::span<std::byte>(out1)}};
  Res r1;
  const Ticket t1 = held_fetch(h, sk, ch, fb1, r1);
  EXPECT_GE(w.core->force_fail(t1), 1u);
  ASSERT_TRUE(w.spin([&] { return r1.released; }));
  const std::size_t qb1 = w.core->quarantined_bytes();
  ASSERT_GT(qb1, 0u);
  for (const auto& c : h.hf.held) h.hf.stuck.insert(c.endpoint);  // the flush is lost: never drains
  h.hf.held.clear();
  h.hf.hold = nullptr;
  ASSERT_TRUE(h.tick_until([&] { return w.port->session_up(); })) << "no reconnect after trip 1";
  for (int i = 0; i < 50; ++i) w.port->keepalive(), w.core->pump(), w.drive();
  EXPECT_EQ(w.core->quarantined_bytes(), qb1) << "trip 1's spans came back while its endpoint can still DMA";

  Bytes out2(5000, std::byte{0xAA});
  std::vector<BufRef> fb2{{std::span<std::byte>(out2)}};
  Res r2;
  const Ticket t2 = held_fetch(h, sk, ch, fb2, r2);
  const std::uint64_t downs = w.port->session_down_count();
  EXPECT_GE(w.core->force_fail(t2), 1u);
  EXPECT_EQ(w.port->session_down_count(), downs + 1) << "trip 2 takes its own session down";
  ASSERT_TRUE(w.spin([&] { return r2.released; }));
  EXPECT_GT(w.core->quarantined_bytes(), qb1);
  h.hf.hold = nullptr;
  h.hf.deliver = true;  // trip 2's completion arrives late: its endpoints drain and are reaped
  ASSERT_TRUE(h.tick_until([&] { return w.port->session_up() && w.core->quarantined_bytes() == qb1; }))
      << "Q01: trip 1's never-draining endpoint blocks the release of trip 2's spans";
  EXPECT_EQ(w.core->pool_bytes_in_use(), qb1);
  EXPECT_EQ(h.m("miracache_client_watchdog_trips_total"), 2);
  EXPECT_EQ(h.m("miracache_client_quarantined_bytes"), static_cast<double>(qb1));
  std::vector<Bytes> again{Bytes(5000)};
  for (auto s : w.fetch(sk, ch, again)) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(again[0], data[0]);
  w.check();
}

// Q02: the session already went Down (here: control died) while the fetch's READ completion was missing.
// The job (timed out at its deadline already) stays reported as is; the later force_fail still quarantines
// the outstanding READ's spans, does not take the (new) session down again, and the spans come back once the
// old endpoints are reaped.
TEST(WireWatchdog, ForceFailAfterTheSessionWentDownQuarantinesWithoutAnotherDown) {
  HoldWorld h;
  ASSERT_TRUE(h.w.core);
  World& w = h.w;
  auto sk = scope_keys(5);
  Chain ch("d", 1);
  std::vector<Bytes> data{payload(5000, 10)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);

  Bytes out(5000, std::byte{0xAA});
  std::vector<BufRef> fb{{std::span<std::byte>(out)}};
  Res r;
  const Ticket t = held_fetch(h, sk, ch, fb, r);
  const std::uint64_t downs = w.port->session_down_count();
  w.port->endpoint_wedged(fabric::EpClass::Control);  // the session ends for another reason first
  w.core->pump();
  EXPECT_EQ(w.port->session_down_count(), downs + 1);
  ASSERT_TRUE(r.done);
  ASSERT_EQ(r.st.size(), 1u);
  EXPECT_EQ(r.st[0], KeyStatus::Timeout);  // its deadline passed before the session ended
  EXPECT_FALSE(r.released) << "the held READ is still outstanding";
  EXPECT_GE(w.core->force_fail(t), 1u);
  EXPECT_EQ(w.port->session_down_count(), downs + 1) << "force_fail on an ended session must not go Down again";
  ASSERT_TRUE(w.spin([&] { return r.released; }));
  EXPECT_EQ(r.st[0], KeyStatus::Timeout);
  EXPECT_TRUE(all_zero(out));
  EXPECT_GT(w.core->quarantined_bytes(), 0u);
  EXPECT_EQ(h.m("miracache_client_watchdog_trips_total"), 1);
  h.hf.hold = nullptr;
  h.hf.deliver = true;
  ASSERT_TRUE(h.tick_until([&] { return w.port->session_up() && w.core->quarantined_bytes() == 0; }));
  EXPECT_EQ(w.port->session_down_count(), downs + 1);
  EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
  std::vector<Bytes> again{Bytes(5000)};
  for (auto s : w.fetch(sk, ch, again)) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(again[0], data[0]);
  w.check();
}

// Q02: two stuck jobs of one session trip back to back. The first takes the session down; the second sees
// it already ended (one Down in all), and both jobs' spans stay quarantined until that session is reaped.
TEST(WireWatchdog, TwoTripsInOneSessionGoDownOnceAndReleaseBoth) {
  HoldWorld h;
  ASSERT_TRUE(h.w.core);
  World& w = h.w;
  auto sk = scope_keys(6);
  Chain ch("two", 2);
  std::vector<Bytes> data{payload(5000, 11), payload(7000, 12)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);

  h.hf.hold = is_read;
  std::vector<Bytes> out{Bytes(5000, std::byte{0xAA}), Bytes(7000, std::byte{0xAA})};
  std::vector<BufRef> fa{{std::span<std::byte>(out[0])}}, fb{{std::span<std::byte>(out[1])}};
  std::vector<KeyRef> ka{ch.refs[0]}, kb{ch.refs[1]};
  Res ra, rb;
  const Nanos deadline = w.clock.now() + milliseconds(100);
  const Ticket ta = w.core->submit_fetch(sk, 0, ka, fa, deadline, w.notify(ra));
  const Ticket tb = w.core->submit_fetch(sk, 0, kb, fb, deadline, w.notify(rb));
  ASSERT_TRUE(w.spin([&] { return w.clock.now() > deadline + milliseconds(50); }));
  ASSERT_EQ(h.hf.held.size(), 2u) << "both jobs' READ completions must be held";
  const std::uint64_t downs = w.port->session_down_count();
  EXPECT_GE(w.core->force_fail(ta), 1u);
  const std::size_t qa = w.core->quarantined_bytes();
  EXPECT_GE(w.core->force_fail(tb), 1u);
  EXPECT_GT(w.core->quarantined_bytes(), qa);
  EXPECT_EQ(w.port->session_down_count(), downs + 1) << "two trips of one session: one Down";
  EXPECT_EQ(h.m("miracache_client_watchdog_trips_total"), 2);
  ASSERT_TRUE(w.spin([&] { return ra.released && rb.released; }));
  for (auto& o : out) EXPECT_TRUE(all_zero(o));
  h.hf.hold = nullptr;
  h.hf.deliver = true;
  ASSERT_TRUE(h.tick_until([&] { return w.port->session_up() && w.core->quarantined_bytes() == 0; }));
  EXPECT_EQ(w.core->pool_bytes_in_use(), 0u);
  std::vector<Bytes> again{Bytes(5000), Bytes(7000)};
  for (auto s : w.fetch(sk, ch, again)) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(again, data);
  w.check();
}

// Q02/Q06: a Client is destroyed while a span is still quarantined behind an endpoint that never drains
// (the READ completion is held forever). Teardown must give every other endpoint back to the fabric before
// the core unmaps its landing pool, and leave only the stuck one, aborted (ERR: no DMA), in the fabric.
// The old teardown released none: the live session's three endpoints stayed registered. asan: nothing
// lands in the unmapped pool while the network keeps running afterwards.
TEST(WireWatchdog, ClientDestroyWithQuarantinedSpansReleasesEndpointsFirst) {
  BuildSetup b(/*up=*/1);
  HoldingFabric hf(*b.w.cfab[0]);
  b.env.watchdog_grace = seconds(1);
  auto cl = b.open({b.bg_spec(1, &hf)});
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  auto wait = [&](Ticket t) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + seconds(30);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion";
    return Completion{};
  };
  Chain ch("q", 1);
  auto sk = scope_keys(7);
  std::vector<Bytes> data{payload(5000, 13)};
  std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
  auto sc = wait(c.store(sk, 0, ch.refs, pb, seconds(5)));
  ASSERT_EQ(sc.status.size(), 1u);
  ASSERT_EQ(sc.status[0], KeyStatus::Committed);

  hf.hold = is_read;  // set before the submit: the worker sees it through the request queue
  std::vector<Bytes> out{Bytes(5000, std::byte{0xAA})};
  std::vector<BufRef> fb{{std::span<std::byte>(out[0])}};
  auto fc = wait(c.fetch(sk, 0, ch.refs, fb, milliseconds(100)));
  ASSERT_EQ(fc.status.size(), 1u);
  EXPECT_NE(fc.status[0], KeyStatus::Hit);
  ASSERT_EQ(c.watchdog_trips(), 1u);
  hf.hold = nullptr;  // the worker is idle; the held completion stays held (never delivered)
  ASSERT_EQ(hf.held.size(), 1u);
  WirePort* wp = c.wire_port(0);
  ASSERT_NE(wp, nullptr);
  for (int i = 0; i < 200000 && !wp->session_up(); ++i) tick_ms(c, b.w);
  ASSERT_TRUE(wp->session_up());
  EXPECT_GT(metric(c.metrics_text(), "miracache_client_quarantined_bytes"), 0);
  EXPECT_GE(b.w.cfab[0]->endpoint_count(), 4u) << "the new session's three endpoints plus the stuck one";

  cl->reset();  // ~Client with the span still quarantined
  EXPECT_EQ(b.w.cfab[0]->endpoint_count(), 1u) << "Q06: teardown must release every endpoint that can drain";
  for (int i = 0; i < 2000; ++i) b.w.drive();
  EXPECT_EQ(hf.held.size(), 1u);
}

// N03 + N05 (cross-thread abort): two memnodes accept the control connect and then go silent, so both
// nodes' keepalive threads sit in a background HELLO at the same time. shutdown() on the test thread must
// abort both builds (one `building` per node), not only the last one that registered. Each node lives in
// its own sim world, touched only by its own keepalive thread (env.drive is unset: real time).
struct DarkWorld {
  explicit DarkWorld(unsigned id, bool dark) : dark(dark), rng(id), net(clock, rng, {}, sliced(2048, false)), sfab(net.add_node(id)), cfab(net.add_node(10 + id)),
                                    fab(cfab, [this] { step(); }) {
    auto sc = server_cfg();
    sc.store.node_id = id;
    auto s = server::Server::create(sc, sfab, clock, rng, sex);
    EXPECT_TRUE(s);
    srv = std::move(*s);
    EXPECT_TRUE(srv->start());
    fab.block_connect = [this](const fabric::ConnParams& cp) {
      if (!armed) return true;  // fails at once (Timeout) without touching the sim
      if (cp.cls == fabric::EpClass::Control) ctl_seen = true;
      return false;
    };
  }
  void step() {
    if (dark && ctl_seen) silent = true;  // the control connect went through; from now on the server never answers
    if (!net.step()) clock.advance_by(milliseconds(1));
    if (!silent) srv->run_once();
  }
  Client::NodeSpec spec(unsigned id) {
    Client::NodeSpec ns;
    ns.fab = &fab;
    ns.wopts.node = id;
    ns.wopts.tickets = [this](fabric::EpClass cls) -> Expected<proto::Ticket> {
      auto t = srv->issue_ticket("lab", cls, 0, 1);
      if (!t) return t.error();
      return (*t)[0];
    };
    ns.wopts.keepalive_ms = 20;
    ns.wopts.reconnect_min_ms = 1;
    ns.wopts.reconnect_max_ms = 2;
    ns.wopts.reconnect_connect_ms = 250;
    ns.wopts.rpc_timeout = seconds(30);  // background HELLO: capped at 2 s
    return ns;
  }
  bool dark;
  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& sfab;
  fabric::SimFabric& cfab;
  InlineExecutor sex;
  std::unique_ptr<server::Server> srv;
  SteppingFabric fab;
  std::atomic<bool> armed{false}, ctl_seen{false}, silent{false};
};

TEST(WireBuild, ShutdownAbortsTheBackgroundBuildsOfEveryDarkNode) {
  DarkWorld up(1, false), d2(2, true), d3(3, true);
  up.armed = true;
  RealClock rc;
  InlineExecutor cex;
  CounterSalts salts;
  Client::Env env;
  env.clock = &rc;
  env.executor = &cex;
  env.salts = &salts;
  RuntimeOptions ro;
  ro.workers = 1;
  std::vector<Client::NodeSpec> specs{up.spec(1), d2.spec(2), d3.spec(3)};
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  ASSERT_NE(c.wire_port(0), nullptr);
  ASSERT_EQ(c.wire_port(1), nullptr);
  ASSERT_EQ(c.wire_port(2), nullptr);
  d2.armed = true;
  d3.armed = true;
  const auto until = std::chrono::steady_clock::now() + seconds(10);
  while (!(d2.silent && d3.silent) && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(milliseconds(2));
  ASSERT_TRUE(d2.silent && d3.silent) << "both dark nodes must be building (control connected, HELLO unanswered)";
  std::this_thread::sleep_for(milliseconds(100));  // both keepalive threads are inside their HELLO wait now
  const auto t0 = std::chrono::steady_clock::now();
  c.shutdown();
  const auto took = std::chrono::steady_clock::now() - t0;
  EXPECT_LT(took, milliseconds(1000)) << "shutdown waited for a background HELLO (2 s cap): one build was not aborted";
  EXPECT_EQ(c.wire_port(1), nullptr);
  EXPECT_EQ(c.wire_port(2), nullptr);
}

// ---- FM1 (run #203): spec §10 failure matrix, rows with no earlier test -------------------------------------------
// The failure matrix maps every row to its test; the three below close rows that had none.

// §10 "Ticket or certificate expiry during a partition": existing QPs keep working, new connects fail (counted as
// miracache_ticket_reject_total{reason="expired"}), and the node is reachable again as soon as fresh tickets flow.
TEST(FailureMatrix, TicketExpiryDuringPartitionKeepsOpenSessionAndRefusesStaleConnects) {
  World w(sliced(1024, false), 51);
  std::map<fabric::EpClass, std::vector<proto::Ticket>> stash;  // issued now, redeemed 300+ s later
  for (auto cls : {fabric::EpClass::Control, fabric::EpClass::Fetch, fabric::EpClass::Ingest}) {
    auto t = w.server->issue_ticket("lab", cls, 0, 4);
    ASSERT_TRUE(t);
    stash[cls] = *t;
  }
  bool stale = false;
  auto wo = w.wire_opts();
  wo.tickets = [&](fabric::EpClass cls) -> Expected<proto::Ticket> {
    if (stale) {
      auto& v = stash[cls];
      if (v.empty()) return Error{ErrorCode::NotFound, "stash empty"};
      auto t = v.back();
      v.pop_back();
      return t;
    }
    auto t = w.server->issue_ticket("lab", cls, 0, 1);
    if (!t) return t.error();
    return (*t)[0];
  };
  ASSERT_TRUE(w.open(std::move(wo)));
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(3000, 1)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);

  // Longer than ticket_ttl (300 s) with the management path gone: the open session never notices.
  for (int sec = 0; sec < 310; ++sec) {
    w.clock.advance_by(seconds(1));
    for (int i = 0; i < 4; ++i) {
      w.port->keepalive();
      w.core->pump();
      w.drive();
    }
  }
  ASSERT_TRUE(w.port->session_up());
  {
    auto out = filled(data, std::byte{0xAA});
    for (auto s : w.fetch(sk, ch, out)) EXPECT_EQ(s, KeyStatus::Hit);
    EXPECT_EQ(out[0], data[0]);
  }

  // The link flaps; the only tickets on hand are expired, so the reconnect is refused and counted.
  stale = true;
  w.port->endpoint(fabric::EpClass::Control)->abort();
  w.net.set_link(1, 2, false);
  w.net.set_link(1, 2, true);
  const Nanos t0 = w.clock.now();
  while (w.clock.now() - t0 < seconds(2)) {
    w.port->keepalive();
    w.core->pump();
    w.drive();
  }
  EXPECT_FALSE(w.port->session_up());
  std::string text;
  w.server->metrics().write_prometheus(text);
  // The sweep (50 ms) purges expired tickets, so a late redeem is usually "unknown"; "expired" is the same refusal caught
  // between expiry and sweep. Either way it is counted.
  EXPECT_GE(metric_value(text, "miracache_ticket_reject_total", {"reason=\"expired\""}) +
                metric_value(text, "miracache_ticket_reject_total", {"reason=\"unknown\""}),
            1.0)
      << text;

  // Fresh tickets (management path back): the node returns and the data is still there.
  stale = false;
  ASSERT_TRUE(reconnect_until_up(w, 100000));
  auto out = filled(data, std::byte{0xAA});
  for (auto s : w.fetch(sk, ch, out)) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(out[0], data[0]);
}

// §10 "Switch loss": two of three nodes drop at once. Their scopes miss at once (no per-request timeout), the third node
// is unaffected, and everything returns when the switch does.
TEST(FailureMatrix, SwitchLossTwoOfThreeNodesMissAtOnceAndTheThirdIsUnaffected) {
  MultiWorld w(/*up=*/3);
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
  RuntimeOptions ro;
  ro.workers = 1;
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  const std::vector<PlaceNode> nodes{{"1", 1}, {"2", 1}, {"3", 1}};
  auto wait = [&](Ticket t) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion (hang)";
    return Completion{};
  };
  constexpr int kScopes = 45;
  Chain ch("k", 1);
  unsigned lost = 0;
  for (int s = 1; s <= kScopes; ++s) {
    std::vector<Bytes> data{payload(4000, s)};
    std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
    auto sc = wait(c.store(scope_keys(s), 0, ch.refs, pb, seconds(5)));
    ASSERT_EQ(sc.status.size(), 1u);
    ASSERT_EQ(sc.status[0], KeyStatus::Committed) << s;
    lost += owner_of(s, nodes) != 3;
  }
  ASSERT_GT(lost, 5u);

  for (unsigned i : {1u, 2u}) {  // the switch under nodes 1 and 2 dies: connections break, the addresses go dark
    c.wire_port(i - 1)->endpoint(fabric::EpClass::Control)->abort();
    w.net.set_link(i, 10 + i, false);
  }
  for (int i = 0; i < 200000 && (c.wire_port(0)->session_up() || c.wire_port(1)->session_up()); ++i) tick_ms(c, w);
  ASSERT_FALSE(c.wire_port(0)->session_up());
  ASSERT_FALSE(c.wire_port(1)->session_up());
  ASSERT_TRUE(c.wire_port(2)->session_up());

  const Nanos t0 = w.clock.now();
  const auto ff0 = c.fast_failed_jobs();
  for (int s = 1; s <= kScopes; ++s) {
    std::vector<Bytes> out{Bytes(4000, std::byte{0xAA})};
    std::vector<BufRef> fb{{std::span<std::byte>(out[0])}};
    auto fc = wait(c.fetch(scope_keys(s), 0, ch.refs, fb, seconds(5)));
    ASSERT_EQ(fc.status.size(), 1u);
    if (owner_of(s, nodes) == 3) {
      EXPECT_EQ(fc.status[0], KeyStatus::Hit) << s;
      EXPECT_EQ(out[0], payload(4000, s));
    } else {
      EXPECT_EQ(fc.status[0], KeyStatus::Miss) << s;  // a fast-failed job never touched the buffer
    }
  }
  EXPECT_GE(c.fast_failed_jobs() - ff0, lost);
  EXPECT_LT(w.clock.now() - t0, seconds(1)) << "misses must not wait for a per-request deadline (5 s here)";

  for (unsigned i : {1u, 2u}) w.net.set_link(i, 10 + i, true);  // the switch returns
  for (int i = 0; i < 400000 && !(c.wire_port(0)->session_up() && c.wire_port(1)->session_up()); ++i) tick_ms(c, w);
  ASSERT_TRUE(c.wire_port(0)->session_up());
  ASSERT_TRUE(c.wire_port(1)->session_up());
  for (int s = 1; s <= kScopes; ++s) {
    std::vector<Bytes> out{Bytes(4000, std::byte{0xAA})};
    std::vector<BufRef> fb{{std::span<std::byte>(out[0])}};
    auto fc = wait(c.fetch(scope_keys(s), 0, ch.refs, fb, seconds(5)));
    ASSERT_EQ(fc.status.size(), 1u);
    EXPECT_EQ(fc.status[0], KeyStatus::Hit) << s;
    EXPECT_EQ(out[0], payload(4000, s));
  }
  c.shutdown();
}

// §10 "Slow memory node (fail-slow)": a node that stops answering costs its own scopes one deadline each, never the
// other nodes' scopes; when it answers again its scopes hit again.
TEST(FailureMatrix, FailSlowNodeCostsOnlyItsOwnScopesTheirDeadline) {
  MultiWorld w(/*up=*/3);
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
  RuntimeOptions ro;
  ro.workers = 1;
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  const std::vector<PlaceNode> nodes{{"1", 1}, {"2", 1}, {"3", 1}};
  auto wait = [&](Ticket t) {
    std::array<Completion, 4> comp;
    const auto until = std::chrono::steady_clock::now() + seconds(20);
    while (std::chrono::steady_clock::now() < until) {
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k];
      std::this_thread::yield();
    }
    ADD_FAILURE() << "no completion (hang)";
    return Completion{};
  };
  constexpr int kScopes = 30;
  Chain ch("k", 1);
  for (int s = 1; s <= kScopes; ++s) {
    std::vector<Bytes> data{payload(4000, s)};
    std::vector<BufRef> pb{{std::span<std::byte>(data[0])}};
    auto sc = wait(c.store(scope_keys(s), 0, ch.refs, pb, seconds(5)));
    ASSERT_EQ(sc.status[0], KeyStatus::Committed) << s;
  }
  auto fetch_all = [&](bool node3_answers) {
    for (int s = 1; s <= kScopes; ++s) {
      std::vector<Bytes> out{Bytes(4000, std::byte{0xAA})};
      std::vector<BufRef> fb{{std::span<std::byte>(out[0])}};
      const Nanos t0 = w.clock.now();
      auto fc = wait(c.fetch(scope_keys(s), 0, ch.refs, fb, milliseconds(200)));
      const Nanos took = w.clock.now() - t0;
      ASSERT_EQ(fc.status.size(), 1u);
      if (owner_of(s, nodes) == 3 && !node3_answers) {
        EXPECT_EQ(fc.status[0], KeyStatus::Miss) << s;
        EXPECT_TRUE(all_zero(out[0])) << s;
        EXPECT_LT(took, seconds(2)) << "a fail-slow node must cost at most about one deadline";
      } else {
        EXPECT_EQ(fc.status[0], KeyStatus::Hit) << s;
        EXPECT_EQ(out[0], payload(4000, s));
        EXPECT_LT(took, milliseconds(50)) << "scope " << s << " is on a healthy node";
      }
    }
  };
  w.frozen[2] = true;
  fetch_all(false);
  w.frozen[2] = false;
  // Node 3 answers again (its session may have been torn down meanwhile): it is back after the keepalive reconnects it.
  for (int i = 0; i < 400000 && !c.wire_port(2)->session_up(); ++i) tick_ms(c, w);
  ASSERT_TRUE(c.wire_port(2)->session_up());
  fetch_all(true);
  c.shutdown();
}

// §10 "AEAD failure on a stable block": a miss with a zeroed buffer, INVALIDATE drops the block (a repeat store is
// Committed again, not Skipped) and the re-put block hits.
TEST(FailureMatrix, AeadMissSendsInvalidateAndTheNextStoreRePuts) {
  World w(sliced(1024, false), 53);
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(3000, 7)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);
  std::vector<store::Extent> exts;
  w.server->store().for_each_block([&](const store::Extent& e, std::uint64_t, bool) { exts.push_back(e); });
  ASSERT_EQ(exts.size(), 1u);
  auto blk = w.server->arena().block(exts[0].seg, exts[0].off, exts[0].len);
  for (std::size_t q : {blk.size() / 4, blk.size() / 2, blk.size() * 3 / 4}) blk[q] ^= std::byte{0x5a};  // a stray writer
  auto out = filled(data, std::byte{0xAA});
  EXPECT_EQ(w.fetch(sk, ch, out)[0], KeyStatus::Miss);
  EXPECT_TRUE(all_zero(out[0]));
  w.settle();
  EXPECT_GE(metric(w.core->metrics_text(), "miracache_client_invalidate_sent_total"), 1.0);
  auto st = w.put(sk, ch, data);
  EXPECT_EQ(st[0], KeyStatus::Committed) << "the corrupt block must be gone, not Skipped";
  out = filled(data, std::byte{0xAA});
  EXPECT_EQ(w.fetch(sk, ch, out)[0], KeyStatus::Hit);
  EXPECT_EQ(out[0], data[0]);
  w.check();
}

// §10 "Clock jump": the wall clock (used for logs, audit and drop_before only) jumps back and forward by years; leases,
// tickets and data are driven by the monotonic clock and notice nothing.
TEST(FailureMatrix, WallClockJumpsDoNotTouchLeasesTicketsOrData) {
  std::atomic<std::int64_t> wall{1'800'000'000LL * 1'000'000'000LL};
  World w(sliced(1024, false), 52, [&] { return wall.load(); });
  std::map<fabric::EpClass, std::vector<proto::Ticket>> stash;  // issued before the jumps, redeemed after them
  for (auto cls : {fabric::EpClass::Control, fabric::EpClass::Fetch, fabric::EpClass::Ingest}) {
    auto t = w.server->issue_ticket("lab", cls, 0, 2);
    ASSERT_TRUE(t);
    stash[cls] = *t;
  }
  bool use_stash = true;
  auto wo = w.wire_opts();
  wo.tickets = [&](fabric::EpClass cls) -> Expected<proto::Ticket> {
    if (use_stash) {
      auto& v = stash[cls];
      if (v.empty()) return Error{ErrorCode::NotFound, "stash empty"};
      auto t = v.back();
      v.pop_back();
      return t;
    }
    auto t = w.server->issue_ticket("lab", cls, 0, 1);
    if (!t) return t.error();
    return (*t)[0];
  };
  const std::int64_t year = 365LL * 86400 * 1'000'000'000LL;
  wall -= 3 * year;  // jump back before the first connect: pre-issued tickets must still redeem
  ASSERT_TRUE(w.open(std::move(wo)));
  auto sk = scope_keys(1);
  Chain ch("k", 2);
  std::vector<Bytes> data{payload(3000, 1), payload(4000, 2)};
  for (auto s : w.put(sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);
  for (std::int64_t jump : {10 * year, -20 * year, 40 * year}) {
    wall += jump;
    w.clock.advance_by(seconds(2));
    w.settle();
    ASSERT_TRUE(w.port->session_up());
    auto out = filled(data, std::byte{0xAA});
    for (auto s : w.fetch(sk, ch, out)) EXPECT_EQ(s, KeyStatus::Hit);
    EXPECT_EQ(out[0], data[0]);
    EXPECT_EQ(out[1], data[1]);
    w.settle();
    EXPECT_EQ(w.server->store().n_leases(), 0u) << "leases are released on the monotonic schedule";
  }
  // A reconnect with the second pre-issued set after the jumps still redeems.
  w.port->endpoint(fabric::EpClass::Control)->abort();
  ASSERT_TRUE(reconnect_until_up(w, 100000));
  use_stash = false;
  auto out = filled(data, std::byte{0xAA});
  for (auto s : w.fetch(sk, ch, out)) EXPECT_EQ(s, KeyStatus::Hit);
  w.check();
}

// ---- Review s9 K03/K04: block size limit from HELLO_ACK, local refusal, loud refusals --------------------------------
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
std::size_t occurrences(const std::string& text, const std::string& what) {
  std::size_t n = 0;
  for (std::size_t p = text.find(what); p != std::string::npos; p = text.find(what, p + 1)) ++n;
  return n;
}

// J08 (review s8 wave15, fixed in run #267): a failure entry (node, rail, cause) a planned rebuild opened and another
// attempt (a rail rejoin) then failed with too. Withdrawing the rebuild settles only the rebuild's share: the entry stays
// open while the rejoin still owns it, so the rejoin's next failure is not logged as a new "first failure" and no
// "withdrawn" line claims it settled. Before the fix the settle erased the entry (a "withdrawn" line) and the next
// rejoin failure logged a second first-failure line. (Driven through the Client's hooks: the end-to-end path needs a
// bundle-mode multi-rail rig; the bookkeeping is what J08 changed.)
TEST(WireClient, WithdrawnRebuildKeepsAFailureEntryAnotherAttemptStillOwns) {
  FW w;
  Client::Env env;
  env.fab = &w.cli;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&] { w.drive(); };
  auto cl = Client::open_wire(env, w.opts());  // keepalive_ms = 0: no keepalive thread, the hooks run alone
  ASSERT_TRUE(cl);
  const std::string failed = "memory-node endpoint build failed", withdrawn = "planned rebuild withdrawn";
  LogCapture cap;
  fabric::clear_local_failure();  // no local device failure on record: the cause is "connect"
  const Error e{ErrorCode::LinkDown, "test: connect refused"};
  (*cl)->test_endpoint_failure(0, 1, e, /*rebuild=*/true);  // the planned rebuild's build fails on rail 1: logged
  EXPECT_EQ(occurrences(cap.text(), failed), 1u) << cap.text();
  (*cl)->test_endpoint_failure(0, 1, e, /*rebuild=*/false);  // a rail 1 rejoin fails the same way: same entry, no line
  EXPECT_EQ(occurrences(cap.text(), failed), 1u);
  EXPECT_EQ((*cl)->test_settle_rebuild_failures(0), 0u) << "the rejoin still owns the entry: nothing closed";
  EXPECT_EQ(occurrences(cap.text(), withdrawn), 0u) << cap.text();
  (*cl)->test_endpoint_failure(0, 1, e, /*rebuild=*/false);  // the rejoin fails again
  EXPECT_EQ(occurrences(cap.text(), failed), 1u) << "a second first-failure line for an entry that never closed\n"
                                                 << cap.text();
  // Control: an entry only the rebuild owns is closed by the settle (H06), with its one line.
  (*cl)->test_endpoint_failure(0, 0, e, /*rebuild=*/true);
  EXPECT_EQ(occurrences(cap.text(), failed), 2u);
  EXPECT_EQ((*cl)->test_settle_rebuild_failures(0), 1u);
  EXPECT_EQ(occurrences(cap.text(), withdrawn), 1u) << cap.text();
}

// K03: the node's run_bytes arrives in HELLO_ACK; a block whose stored form (payload + 64 B header + 16 B per 64 KiB
// segment) is longer is refused here, before any PUT_BEGIN is sent (the node never sees it), with the batch aborted as
// the node would have; K04: counted per reason with the node's identity and logged once per minute.
TEST(WirePort, OversizedPutIsRefusedLocallyCountedAndLoggedOnce) {
  World w;
  ASSERT_TRUE(w.open());
  ASSERT_EQ(w.port->max_stored_block(), 256u << 10);  // server_cfg() run_bytes
  auto sk = scope_keys(1);
  const std::size_t too_big = 256u << 10;              // stored 256 KiB + 64 + 4 x 16 > run_bytes
  const std::size_t fits = (256u << 10) - 64 - 4 * 16;  // stored exactly run_bytes
  LogCapture cap;
  Chain big("big", 1);
  std::vector<Bytes> d1{payload(too_big, 1)};
  auto st = w.put(sk, big, d1);
  ASSERT_EQ(st.size(), 1u);
  EXPECT_EQ(st[0], KeyStatus::Aborted);
  EXPECT_EQ(w.port->put_refusals(), 1u);
  EXPECT_EQ(w.server->puts().n_puts(), 0u);
  std::string srv;
  w.server->metrics().write_prometheus(srv);
  EXPECT_EQ(srv.find("miracache_put_too_large_total"), std::string::npos) << "no PUT_BEGIN reached the node";
  Chain big2("big2-", 1);
  for (auto s : w.put(sk, big2, d1)) EXPECT_EQ(s, KeyStatus::Aborted);
  EXPECT_EQ(w.port->put_refusals(), 2u);
  const std::string text = w.core->metrics_text();
  EXPECT_EQ(metric_value(text, "miracache_client_put_refused_total", {"reason=\"too_large\"", "node_id=\"1\"", "addr=\""}), 2);
  const std::string log = cap.text();
  EXPECT_EQ(occurrences(log, "PUT_BEGIN refused locally"), 1u) << log;  // rate-limited: one line per minute
  EXPECT_NE(log.find("node_id=1"), std::string::npos) << log;
  EXPECT_NE(log.find("hostname=" + log::hostname()), std::string::npos) << log;  // F5: HELLO_ACK named the node
  EXPECT_NE(log.find("addr="), std::string::npos) << log;
  EXPECT_NE(log.find("stored_len=" + std::to_string(too_big + 64 + 4 * 16)), std::string::npos) << log;
  EXPECT_NE(log.find("max_stored_block_bytes=262144"), std::string::npos) << log;
  Chain ok("ok", 1);
  std::vector<Bytes> d2{payload(fits, 2)};
  for (auto s : w.put(sk, ok, d2)) EXPECT_EQ(s, KeyStatus::Committed);
  EXPECT_EQ(w.port->put_refusals(), 2u);
  w.check();
}

// K03: an older node sends no TLV 0x0003: the limit is unknown (0), the PUT_BEGIN goes out. K04: the node's Malformed
// error reply (what a node refuses a too-large block with) is no longer silent: counted with reason "malformed", logged
// with the wire status, once per minute.
TEST(WireFailure, MalformedPutBeginReplyIsCountedAndLogged) {
  FW w;
  w.fake.hook = [](Fake& f, const Fake::Rx& rx) {
    if (rx.h.type != static_cast<std::uint16_t>(proto::Op::PUT_BEGIN)) return;
    std::array<std::byte, proto::kMaxFrameSize> buf{};
    auto n = proto::encode_error_reply_frame(rx.h, proto::ErrorReply{static_cast<std::uint16_t>(proto::WireStatus::Malformed), 0}, buf);
    ASSERT_TRUE(n.has_value());
    fabric::Frame fr;
    fr.bytes.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(*n));
    ASSERT_TRUE(f.eps.at(rx.ep)->post_send(std::move(fr), 0));
  };
  ASSERT_TRUE(w.open_core());
  for (int i = 0; i < 200; ++i) w.drive(), w.core->pump();
  EXPECT_EQ(w.port->max_stored_block(), 0u) << "no TLV: unknown";
  auto sk = scope_keys(1);
  LogCapture cap;
  for (int round = 0; round < 3; ++round) {
    Chain ch("m" + std::to_string(round) + "-", 1);
    Bytes d = payload(1000, round);
    std::vector<BufRef> bufs{{std::span<std::byte>(d)}};
    Res r;
    w.core->submit_store(sk, 0, ch.refs, bufs, w.clock.now() + seconds(5), w.notify(r));
    for (int i = 0; i < 100000 && !r.released; ++i) w.core->pump(), w.drive();
    ASSERT_TRUE(r.released);
    ASSERT_EQ(r.st.size(), 1u);
    EXPECT_EQ(r.st[0], KeyStatus::Aborted);
  }
  EXPECT_EQ(w.fake.count(proto::Op::PUT_BEGIN), 3u);
  EXPECT_EQ(w.port->put_refusals(), 3u);
  EXPECT_EQ(metric_value(w.core->metrics_text(), "miracache_client_put_refused_total", {"reason=\"malformed\""}), 3);
  const std::string log = cap.text();
  EXPECT_EQ(occurrences(log, "PUT_BEGIN refused by the memory node"), 1u) << log;
  EXPECT_NE(log.find("wire_status=2"), std::string::npos) << log;
  EXPECT_NE(log.find("max_stored_block_bytes=unknown"), std::string::npos) << log;
  EXPECT_NE(log.find("hostname=unknown"), std::string::npos) << "a node that sends no hostname TLV is unknown\n" << log;
}

// ---- F3 (K06, K09, S2) ----------------------------------------------------------------------------------------------
// Number of series lines of `family` whose labels contain `needle`.
std::size_t series_with(const std::string& text, const std::string& family, const std::string& needle) {
  std::size_t n = 0, at = 0;
  while (at < text.size()) {
    const std::size_t eol = std::min(text.find('\n', at), text.size());
    const std::string line = text.substr(at, eol - at);
    if (line.rfind(family + "{", 0) == 0 && line.find(needle) != std::string::npos) ++n;
    at = eol + 1;
  }
  return n;
}

// K06: one rail and fetch_qps = 1 is the non-mux path: the READ bytes that landed still count per rail.
TEST(WireTelemetry, SingleRailFetchCountsRailBytes) {
  World w(sliced(1024, false), 11);
  ASSERT_TRUE(w.open());
  auto sk = scope_keys(1);
  Chain ch("k", 2);
  std::vector<Bytes> data{payload(kSeg, 1), payload(3000, 2)}, out{Bytes(kSeg, std::byte{0xAA}), Bytes(3000, std::byte{0xAA})};
  for (auto s : w.put(sk, ch, data)) EXPECT_EQ(s, KeyStatus::Committed);
  EXPECT_EQ(metric_value(w.core->metrics_text(), "miracache_client_fetch_rail_bytes_total", {"rail=\"0\""}), 0);
  for (auto s : w.fetch(sk, ch, out)) EXPECT_EQ(s, KeyStatus::Hit);
  EXPECT_EQ(out[0], data[0]);
  const double bytes = metric_value(w.core->metrics_text(), "miracache_client_fetch_rail_bytes_total", {"rail=\"0\""});
  EXPECT_GE(bytes, static_cast<double>(kSeg + 3000)) << w.core->metrics_text();
  EXPECT_EQ(w.port->rail_read_bytes(0), static_cast<std::uint64_t>(bytes));
  // K20: the lend-check count is exported (and stays 0 here).
  EXPECT_NE(w.core->metrics_text().find("miracache_client_lend_violations_total 0"), std::string::npos) << w.core->metrics_text();
}

// K09 + S2: learn mode on one node. After HELLO no rail or breaker series keeps node_id "unknown"/"0" or an empty
// hostname; the series carry the learned ID and the hostname HELLO_ACK brought (F5).
TEST(WireTelemetry, LearnedIdLeavesNoUnknownRailSeriesAndRebindStartsFresh) {
  World w(sliced(1024, false), 11);
  WireOptions wo = w.wire_opts();
  wo.node = 0;   // learn mode
  wo.route = 1;  // the sim peer to dial
  Status os = w.open(std::move(wo));
  ASSERT_TRUE(os) << os.error().context;
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(5000, 1)}, out{Bytes(5000, std::byte{0xAA})};
  for (auto s : w.put(sk, ch, data)) EXPECT_EQ(s, KeyStatus::Committed);
  for (auto s : w.fetch(sk, ch, out)) EXPECT_EQ(s, KeyStatus::Hit);
  const std::string m = w.core->metrics_text();
  for (const char* fam : {"miracache_client_rail_state", "miracache_read_window", "miracache_client_rail_fetch_qps",
                          "miracache_client_fetch_rail_bytes_total", "miracache_client_slices_reissued_total",
                          "miracache_client_rail_unpaired", "miracache_client_breaker_state",
                          "miracache_client_breaker_trips_total"}) {
    EXPECT_EQ(series_with(m, fam, "node_id=\"unknown\""), 0u) << fam << "\n" << m;
    EXPECT_EQ(series_with(m, fam, "node_id=\"0\""), 0u) << fam << "\n" << m;
    EXPECT_EQ(series_with(m, fam, "hostname=\"\""), 0u) << fam << "\n" << m;
  }
  // F5: HELLO_ACK names the node (TLV 0x0004): the rail series carry its hostname, none says "unknown".
  for (const char* fam : {"miracache_client_rail_state", "miracache_read_window", "miracache_client_rail_fetch_qps",
                          "miracache_client_fetch_rail_bytes_total", "miracache_client_slices_reissued_total",
                          "miracache_client_rail_unpaired", "miracache_client_breaker_state",
                          "miracache_client_breaker_trips_total"})
    EXPECT_EQ(series_with(m, fam, "hostname=\"unknown\""), 0u) << fam << "\n" << m;
  EXPECT_EQ(series_with(m, "miracache_client_rail_state", "hostname=\"" + log::hostname() + "\""), 1u) << m;
  EXPECT_GT(series_with(m, "miracache_client_rail_state", "node_id=\""), 0u);
  EXPECT_GT(metric_value(m, "miracache_client_fetch_rail_bytes_total", {"rail=\"0\""}), 0);

  // Rebind to a fresh registry (the old one is hidden-before-null'd, g_node forgotten): its series are made afresh.
  ClientMetrics mx2;
  w.port->bind_metrics(&mx2);
  std::string t;
  mx2.reg.write_prometheus(t);
  EXPECT_EQ(series_with(t, "miracache_client_rail_state", "node_id=\"unknown\""), 0u) << t;
  EXPECT_EQ(series_with(t, "miracache_client_rail_state", "node_id=\"0\""), 0u) << t;
  EXPECT_EQ(series_with(t, "miracache_client_rail_state", "rail=\"0\""), 1u) << t;
  w.port->bind_metrics(&w.core->metrics());
}

// L03: the hostname of a HELLO_ACK is learned only after the boot-nonce / node-ID checks accept it. A HELLO_ACK whose
// node ID is not the expected one is rejected and must not relabel the node.
TEST(WireTelemetry, RejectedHelloAckDoesNotLearnItsHostname) {
  World w(sliced(1024, false), 12);
  WireOptions wo = w.wire_opts();
  wo.node = 99;  // the sim node answers with another ID
  wo.route = 1;
  std::atomic<int> learned{0};
  wo.on_node_hostname = [&learned](const std::string&) { learned.fetch_add(1); };
  Status os = w.open(std::move(wo));
  EXPECT_FALSE(os) << "the node-ID mismatch must fail the open";
  EXPECT_EQ(learned.load(), 0) << "a rejected HELLO_ACK taught a hostname";
}

// Control for the test above: an accepted HELLO_ACK does teach it.
TEST(WireTelemetry, AcceptedHelloAckLearnsItsHostname) {
  World w(sliced(1024, false), 13);
  WireOptions wo = w.wire_opts();
  wo.node = 0;  // learn mode
  wo.route = 1;
  std::atomic<int> learned{0};
  wo.on_node_hostname = [&learned](const std::string&) { learned.fetch_add(1); };
  Status os = w.open(std::move(wo));
  ASSERT_TRUE(os) << os.error().context;
  EXPECT_GE(learned.load(), 1);
}

// ---- Q15 (review s10): Client::open with a node whose first build fails --------------------------------------------
// Node 2's first ticket draw finds the cache empty (siw0 under load: the open-time admin fetch had failed), the rest
// work. Without the open-time retry the open returned with node 2 pending (the caller saw node id 0 for it, or placed
// scopes without it); with Env::open_settle it is retried inside the open and every node is connected at return.
Client::NodeSpec first_draw_fails(MultiWorld& w, unsigned i, std::shared_ptr<std::atomic<int>> fails) {
  Client::NodeSpec ns = w.spec(i);
  ns.wopts.tickets = [inner = ns.wopts.tickets, fails](fabric::EpClass cls) -> Expected<proto::Ticket> {
    if (fails->load() > 0) {
      fails->fetch_sub(1);
      return Error{ErrorCode::LinkDown, "admin: connect failed"};  // what draw() now says after a failed fetch
    }
    return inner(cls);
  };
  return ns;
}
Expected<std::unique_ptr<Client>> open_three(MultiWorld& w, std::vector<Client::NodeSpec> specs, Nanos settle) {
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  env.drive = [&w] { w.drive(); };
  env.open_settle = settle;
  RuntimeOptions ro;
  ro.workers = 1;
  return Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
}

TEST(WireOpen, NodeWhoseFirstBuildFailsIsRetriedInsideTheOpen) {
  MultiWorld w(/*up=*/3);
  auto fails = std::make_shared<std::atomic<int>>(1);
  std::vector<Client::NodeSpec> specs;
  specs.push_back(w.spec(1));
  specs.push_back(first_draw_fails(w, 2, fails));
  specs.push_back(w.spec(3));
  LogCapture cap;
  auto cl = open_three(w, std::move(specs), std::chrono::seconds(2));
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  EXPECT_EQ(fails->load(), 0) << "the first build of node 2 did fail";
  EXPECT_NE(c.wire_port(1), nullptr) << "node 2 is still pending after a successful open";
  EXPECT_EQ(c.nodes_connected(), 3u);
  const std::string logs = cap.text();
  EXPECT_NE(logs.find("client open: every memory node connected"), std::string::npos) << logs;
  EXPECT_NE(logs.find("error=\"admin: connect failed\""), std::string::npos) << "the failure names its cause\n" << logs;
  c.shutdown();
}

// (B)-shaped: node 2 does not answer during its first build (frozen: the set-up waits run out, "wire: no reply"), then
// answers again within the settle. The open retries it and returns with every node connected.
TEST(WireOpen, NodeThatAnswersLateIsRetriedInsideTheOpen) {
  MultiWorld w(/*up=*/3);
  w.frozen[1] = true;
  Client::Env env;
  env.clock = &w.clock;
  env.executor = &w.cex;
  env.salts = &w.salts;
  std::optional<Nanos> thaw;
  env.drive = [&] {
    w.drive();
    if (w.frozen[1] && !thaw && w.clock.now() > seconds(1)) thaw = w.clock.now() + seconds(5);  // after its first wait
    if (w.frozen[1] && thaw && w.clock.now() >= *thaw) w.frozen[1] = false;
  };
  env.open_settle = std::chrono::seconds(10);
  RuntimeOptions ro;
  ro.workers = 1;
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
  LogCapture cap;
  auto cl = Client::open_wire_nodes(env, std::move(specs), {}, {}, ro);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  EXPECT_FALSE(w.frozen[1].load()) << "node 2 was answering again before the open returned";
  EXPECT_EQ(c.nodes_connected(), 3u) << cap.text();
  EXPECT_NE(cap.text().find("memory-node endpoint build failed"), std::string::npos) << "its first build did fail\n"
                                                                                     << cap.text();
  c.shutdown();
}

// The open contract when a node stays down: the open succeeds with the others (availability), and says so: one WARN
// naming the pending node, and nodes_connected() below node_count().
TEST(WireOpen, NodeStillDownAfterTheSettleIsReportedPending) {
  MultiWorld w(/*up=*/2);  // node 3 is down for the whole open
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
  LogCapture cap;
  auto cl = open_three(w, std::move(specs), std::chrono::milliseconds(300));
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  EXPECT_EQ(c.wire_port(2), nullptr);
  EXPECT_EQ(c.node_count(), 3u);
  EXPECT_EQ(c.nodes_connected(), 2u);
  const std::string logs = cap.text();
  const auto at = logs.find("client open: some memory nodes are pending");
  ASSERT_NE(at, std::string::npos) << logs;
  const std::string line = logs.substr(at, logs.find('\n', at) - at);
  EXPECT_NE(line.find("2 of 3"), std::string::npos) << line;
  EXPECT_NE(line.find("node_id=3"), std::string::npos) << line;
  EXPECT_EQ(occurrences(logs, "client open: some memory nodes are pending"), 1u);
  // It joins when it comes up (the keepalive path, as before).
  w.start(3);
  for (int k = 0; k < 20000 && c.nodes_connected() < 3; ++k) tick_ms(c, w);
  EXPECT_EQ(c.nodes_connected(), 3u);
  c.shutdown();
}

// R14 (review s11): open_settle is a bound. Nodes 2 and 3 black-hole for the whole open (they stop answering). The
// first round is the same with or without the settle (deterministic sim), so the open with a 2 s settle must return
// within that first round + 2 s (+ a few ms of drive steps). Before the fix every pending node started one more retry
// near the end of the settle and ran its full connect + HELLO caps (seconds) past it.
Nanos blackhole_open_time(Nanos settle, std::size_t* connected) {
  MultiWorld w(/*up=*/3);
  w.frozen[1] = true;
  w.frozen[2] = true;
  const Nanos t0 = w.clock.now();
  auto cl = open_three(w, {w.spec(1), w.spec(2), w.spec(3)}, settle);
  const Nanos took = w.clock.now() - t0;
  EXPECT_TRUE(cl) << (cl ? "" : cl.error().context);
  if (!cl) return took;
  *connected = (*cl)->nodes_connected();
  (*cl)->shutdown();
  return took;
}
TEST(WireOpen, SettleIsABoundWhenTwoOfThreeNodesBlackhole) {
  std::size_t up0 = 9, up = 9;
  const Nanos first_round = blackhole_open_time(Nanos{0}, &up0);
  const Nanos settle = std::chrono::seconds(2);
  const Nanos with_settle = blackhole_open_time(settle, &up);
  EXPECT_EQ(up0, 1u);
  EXPECT_EQ(up, 1u);
  const auto ms = [](Nanos d) { return std::chrono::duration_cast<std::chrono::milliseconds>(d).count(); };
  EXPECT_GT(with_settle, first_round + std::chrono::milliseconds(500)) << "the settle did retry";
  EXPECT_LE(with_settle, first_round + settle + std::chrono::milliseconds(50))
      << "open() ran " << ms(with_settle) << " ms; first round " << ms(first_round) << " ms + settle 2000 ms";
}

// R20 (review s11): a transient failure on EVERY node (each node's first ticket draw fails) is retried inside the
// settle like one on N-1 nodes; before the fix the open failed at once. Without a settle it still fails (one round).
TEST(WireOpen, AllNodesFailingTheirFirstBuildAreRetriedInsideTheOpen) {
  for (const Nanos settle : {Nanos{0}, Nanos{std::chrono::seconds(2)}}) {
    MultiWorld w(/*up=*/3);
    std::vector<Client::NodeSpec> specs;
    std::vector<std::shared_ptr<std::atomic<int>>> fails;
    for (unsigned i = 1; i <= 3; ++i) {
      fails.push_back(std::make_shared<std::atomic<int>>(1));
      specs.push_back(first_draw_fails(w, i, fails.back()));
    }
    LogCapture cap;
    auto cl = open_three(w, std::move(specs), settle);
    if (settle == Nanos{0}) {
      EXPECT_FALSE(cl) << "one round, every node down: the open fails";
      continue;
    }
    ASSERT_TRUE(cl) << cl.error().context << "\n" << cap.text();
    for (auto& f : fails) EXPECT_EQ(f->load(), 0) << "every first build did fail";
    EXPECT_EQ((*cl)->nodes_connected(), 3u) << cap.text();
    EXPECT_NE(cap.text().find("client open: every memory node connected"), std::string::npos) << cap.text();
    (*cl)->shutdown();
  }
}

// R19 (review s11): node 2's ticket source backs off after a failed admin fetch (its cache is empty until `ready`).
// With tickets_ready_at the settle waits for it: ONE failed build is counted (the first round's), and the retry at
// `ready` connects. Control (the behaviour before the fix): without the hook the settle retried on the 100 ms build
// backoff and every retry failed on the cached admin error, inflating the counter.
double settle_failures(bool hook, std::size_t* connected) {
  MultiWorld w(/*up=*/3);
  const Nanos ready = w.clock.now() + std::chrono::milliseconds(900);
  Client::NodeSpec ns = w.spec(2);
  ns.wopts.tickets = [inner = ns.wopts.tickets, ready, &w](fabric::EpClass cls) -> Expected<proto::Ticket> {
    if (w.clock.now() < ready) return Error{ErrorCode::LinkDown, "admin: connect failed"};  // the cached admin error
    return inner(cls);
  };
  if (hook) ns.wopts.tickets_ready_at = [ready, &w] { return w.clock.now() < ready ? ready : Nanos{0}; };
  auto cl = open_three(w, {w.spec(1), std::move(ns), w.spec(3)}, std::chrono::seconds(2));
  EXPECT_TRUE(cl) << (cl ? "" : cl.error().context);
  if (!cl) return -1;
  *connected = (*cl)->nodes_connected();
  const double v = metric_value((*cl)->metrics_text(), "miracache_client_endpoint_build_failures_total",
                                {"node_id=\"2\"", "cause=\"connect\""});
  (*cl)->shutdown();
  return v;
}
TEST(WireOpen, SettleWaitsForTheTicketSourceSoTheFailureCounterStaysHonest) {
  std::size_t up = 0, up_ctl = 0;
  EXPECT_EQ(settle_failures(/*hook=*/true, &up), 1.0);
  EXPECT_EQ(up, 3u);
  EXPECT_GT(settle_failures(/*hook=*/false, &up_ctl), 2.0) << "control: retries on the cached error are counted";
  EXPECT_EQ(up_ctl, 3u);
}

// B-1 (review s11): a retry the end of the settle would cut short is no verdict on the node. Node 2's ticket source is
// ready only 300 ms before the settle ends (2 s settle, so a 500 ms floor) and node 2 is slow (frozen: it does not
// answer). Before the fix the retry started with 300 ms left, ran into `until` and was booked as a second build failure
// against the node (counter, streak, doubled backoff); now it does not start and only the first round's real failure
// counts. The node joins through the keepalive once it answers.
TEST(WireOpen, SettleRetryCutShortByTheDeadlineIsNoBuildFailure) {
  MultiWorld w(/*up=*/3);
  w.frozen[1] = true;
  const Nanos settle = std::chrono::seconds(2);
  auto ready = std::make_shared<std::optional<Nanos>>();
  Client::NodeSpec ns = w.spec(2);
  ns.wopts.tickets = [inner = ns.wopts.tickets, ready, &w](fabric::EpClass cls) -> Expected<proto::Ticket> {
    if (!*ready || w.clock.now() < **ready) return Error{ErrorCode::LinkDown, "admin: connect failed"};
    return inner(cls);
  };
  // Asked first at the start of the settle (the first round never asks): ready 300 ms before the settle ends.
  ns.wopts.tickets_ready_at = [ready, settle, &w] {
    if (!*ready) *ready = w.clock.now() + settle - std::chrono::milliseconds(300);
    return w.clock.now() < **ready ? **ready : Nanos{0};
  };
  LogCapture cap;
  auto cl = open_three(w, {w.spec(1), std::move(ns), w.spec(3)}, settle);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  ASSERT_TRUE(ready->has_value()) << "the settle asked the ticket source";
  const auto fails = [&] {
    const std::string m = c.metrics_text();
    return metric_value(m, "miracache_client_endpoint_build_failures_total", {"node_id=\"2\"", "cause=\"connect\""}) +
           metric_value(m, "miracache_client_endpoint_build_failures_total", {"node_id=\"2\"", "cause=\"hello\""});
  };
  EXPECT_EQ(fails(), 1.0) << "only the first round's failure counts\n" << cap.text();
  EXPECT_EQ(c.nodes_connected(), 2u);
  w.frozen[1] = false;
  for (int k = 0; k < 20000 && c.nodes_connected() < 3; ++k) tick_ms(c, w);
  EXPECT_EQ(c.nodes_connected(), 3u) << cap.text();
  c.shutdown();
}

// Review s9b L08: the engine's start-up block size check says how many of the nodes it covered ("2 of 3"), and a node
// that connects after it is checked when its session comes up (an ERROR naming it when the block does not fit).
TEST(WireOpen, BlockSizeCheckCoversNodesThatConnectLater) {
  MultiWorld w(/*up=*/2);
  std::vector<Client::NodeSpec> specs{w.spec(1), w.spec(2), w.spec(3)};
  auto cl = open_three(w, std::move(specs), Nanos{0});
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  const std::uint64_t too_big = 256u << 10;  // stored 256 KiB + 64 + 4 x 16 > run_bytes (server_cfg)
  LogCapture cap;
  std::size_t checked = 9;
  EXPECT_NE(c.block_size_problem(too_big, &checked), "");
  EXPECT_EQ(checked, 2u);
  {
    const std::string logs = cap.text();
    const auto at = logs.find("engine block size checked against the memory nodes");
    ASSERT_NE(at, std::string::npos) << logs;
    EXPECT_NE(logs.find("2 of 3", at), std::string::npos) << logs;
  }
  const std::string late = "memory node that connected after the start-up block size check cannot store an engine block";
  EXPECT_EQ(cap.text().find(late), std::string::npos);
  w.start(3);
  for (int k = 0; k < 20000 && c.nodes_connected() < 3; ++k) tick_ms(c, w);
  ASSERT_EQ(c.nodes_connected(), 3u);
  const std::string logs = cap.text();
  const auto at = logs.find(late);
  ASSERT_NE(at, std::string::npos) << logs;
  const std::string line = logs.substr(at, logs.find('\n', at) - at);
  EXPECT_NE(line.find("node_id=3"), std::string::npos) << line;
  EXPECT_NE(line.find("block_bytes=262144"), std::string::npos) << line;
  c.shutdown();
}

// ---- R16: the send-queue cap (sq_depth) is backpressure, never a miss ------------------------------------------------
// A fabric whose QPs refuse a post past `cap` outstanding send-queue work requests (SEND + READ + WRITE) with
// ResourceExhausted, as VerbsCmFabric::post_wr does at sq_depth since run #270. The sim fabric has no such limit.
class SqCapFabric final : public fabric::Fabric {
 public:
  SqCapFabric(fabric::Fabric& in, std::size_t cap) : in_(in), cap_(cap) {}
  class Ep final : public fabric::Endpoint {
   public:
    Ep(SqCapFabric& f, fabric::Endpoint* e) : in(e), f_(f) {}
    fabric::EndpointId id() const override { return in->id(); }
    Status post_send(fabric::Frame fr, fabric::WrTag t) override {
      return gate([&] { return in->post_send(std::move(fr), t); });
    }
    Status post_read(fabric::RemoteRef r, fabric::LocalRef l, fabric::WrTag t) override {
      return gate([&] { return in->post_read(r, l, t); });
    }
    Status post_write(fabric::LocalRef l, fabric::RemoteRef r, fabric::WrTag t) override {
      return gate([&] { return in->post_write(l, r, t); });
    }
    void abort() override { in->abort(); }
    bool drained() const override { return in->drained(); }
    fabric::EpState state() const override { return in->state(); }
    fabric::ReadDepth read_depth() const override { return in->read_depth(); }
    std::span<const std::byte> peer_private_data() const override { return in->peer_private_data(); }
    std::string peer_addr() const override { return in->peer_addr(); }
    fabric::Endpoint* in;

   private:
    template <class F>
    Status gate(F post) {
      std::size_t& n = f_.out_[in->id()];
      if (n >= f_.cap_) {
        ++f_.refused;
        return Error{ErrorCode::ResourceExhausted, "test: send queue full (sq_depth)"};
      }
      Status s = post();
      if (s) f_.peak = std::max(f_.peak, ++n);
      return s;
    }
    SqCapFabric& f_;
  };
  Expected<fabric::DeviceCaps> probe() override { return in_.probe(); }
  Expected<fabric::PdId> alloc_pd() override { return in_.alloc_pd(); }
  Status free_pd(fabric::PdId pd) override { return in_.free_pd(pd); }
  Expected<fabric::MemRegion> reg(std::span<std::byte> b, fabric::Access a, fabric::PdId pd) override { return in_.reg(b, a, pd); }
  Status dereg(const fabric::MemRegion& r) override { return in_.dereg(r); }
  Expected<fabric::Endpoint*> connect(const fabric::Peer& p, const fabric::ConnParams& c) override {
    auto e = in_.connect(p, c);
    if (!e) return e.error();
    eps_.push_back(std::make_unique<Ep>(*this, *e));
    return static_cast<fabric::Endpoint*>(eps_.back().get());
  }
  Status release(fabric::Endpoint* e) override {
    auto it = std::find_if(eps_.begin(), eps_.end(), [e](const auto& w) { return w.get() == e; });
    if (it == eps_.end()) return in_.release(e);
    Status s = in_.release((*it)->in);
    if (s) eps_.erase(it);
    return s;
  }
  Status listen(fabric::AcceptFn f, const fabric::ListenParams& lp) override { return in_.listen(std::move(f), lp); }
  std::size_t poll(std::span<fabric::Completion> out, fabric::PollBudget b) override {
    const std::size_t n = in_.poll(out, b);
    for (std::size_t i = 0; i < n; ++i) {
      const auto& c = out[i];
      if (c.is_recv || c.op == fabric::CompletionOp::Recv || c.op == fabric::CompletionOp::CqError) continue;
      auto it = out_.find(c.endpoint);
      if (it != out_.end() && it->second > 0) --it->second;
    }
    return n;
  }
  int wait_fd() override { return in_.wait_fd(); }
  fabric::FabricHealth health() override { return in_.health(); }
  std::size_t refused = 0, peak = 0;

 private:
  fabric::Fabric& in_;
  std::size_t cap_;
  std::map<fabric::EndpointId, std::size_t> out_;
  std::vector<std::unique_ptr<Ep>> eps_;
};

// R16: many tiny blocks in one store and one fetch, over QPs whose send queue holds 8 work requests. Before the fix a
// post past the cap failed the key (puts Aborted, fetches a silent Miss); now it waits for a completion: every key is
// committed and hits, and miracache_client_sq_full_total{node_id, hostname, rail, addr} counts the waits.
// fetch_qps 1 = the single-rail path (ClientCore maps the refusal); 2 = the mux, with its own cap below the provider's
// (no refusal reaches the provider) or with no cap configured (the mux maps the provider's refusal).
void sq_cap_case(std::uint32_t fetch_qps, bool mux_cap) {
  SCOPED_TRACE("fetch_qps=" + std::to_string(fetch_qps) + " mux_cap=" + std::to_string(mux_cap));
  std::unique_ptr<SqCapFabric> capped;  // declared first: it outlives the port that posts through it
  World w(sliced(1024, false), 21);
  capped = std::make_unique<SqCapFabric>(w.cli, 8);
  WireOptions wo = w.wire_opts();
  wo.fetch_qps = fetch_qps;
  wo.window_bytes = 16u << 20;
  if (fetch_qps > 1) wo.sq_depth = mux_cap ? 8 : 0;
  w.port = std::make_unique<WirePort>(*capped, w.clock, w.salts, std::move(wo));
  auto c = ClientCore::create(w.port->fabric(), *w.port, w.clock, w.cex, w.salts, {});
  ASSERT_TRUE(c);
  w.core = std::move(*c);
  auto sk = scope_keys(1);
  constexpr std::size_t kN = 96;
  Chain ch("sq", kN);
  std::vector<Bytes> data, out;
  for (std::size_t i = 0; i < kN; ++i) {
    data.push_back(payload(100 + i, static_cast<int>(i)));
    out.emplace_back(100 + i, std::byte{0xAA});
  }
  auto ps = w.put(sk, ch, data);
  ASSERT_EQ(ps.size(), kN);
  std::size_t committed = 0, hits = 0;
  for (std::size_t i = 0; i < kN; ++i) committed += ps[i] == KeyStatus::Committed;
  EXPECT_EQ(committed, kN);
  auto fs = w.fetch(sk, ch, out);
  ASSERT_EQ(fs.size(), kN);
  for (std::size_t i = 0; i < kN; ++i) {
    hits += fs[i] == KeyStatus::Hit;
    EXPECT_EQ(out[i], data[i]) << i;
  }
  EXPECT_EQ(hits, kN);
  EXPECT_LE(capped->peak, 8u);
  if (fetch_qps > 1 && mux_cap) EXPECT_EQ(capped->refused, 0u);  // the mux's own cap leaves the provider's untouched
  const std::string m = w.core->metrics_text();
  const double waits = metric_value(m, "miracache_client_sq_full_total", {"node_id=\"1\"", "rail=\"0\"", "addr="});
  EXPECT_GT(waits, 0) << m;
  EXPECT_EQ(static_cast<double>(w.port->rail_sq_full(0)), waits);
  w.check();
}
TEST(WireBackpressure, SendQueueCapSingleRailWaitsInsteadOfMissing) { sq_cap_case(1, false); }
TEST(WireBackpressure, SendQueueCapMuxOwnCapWaitsInsteadOfMissing) { sq_cap_case(2, true); }
TEST(WireBackpressure, SendQueueCapMuxProviderRefusalWaitsInsteadOfMissing) { sq_cap_case(2, false); }
}  // namespace
}  // namespace miracache
