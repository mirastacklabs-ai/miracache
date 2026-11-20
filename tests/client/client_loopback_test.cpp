// SPDX-License-Identifier: Apache-2.0
// A1.6 L3: Client facade + ClientCore against the real store on SimFabric (LoopbackPort).
// Control calls are direct; DATA moves over simulated RDMA READ/WRITE with slicing and early
// iWARP write CQEs. Everything is deterministic (seeded) except the facade tests, which use
// the runtime's worker threads.
#include <gtest/gtest.h>
#include <poll.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <thread>
#include <memory>
#include <vector>

#include "src/client.h"
#include "src/client_core.h"
#include "src/loopback_port.h"
#include "util/clock.h"
#include "util/random.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;
using std::chrono::milliseconds;
using std::chrono::seconds;

constexpr std::uint64_t kSeg = 1u << 16;  // segment_log2 = 16

class CounterSalts final : public NonceSource {
 public:
  std::atomic<bool> fail{false};  // make sealing fail (salt draw error)

 protected:
  Status fill(std::span<std::byte> out) override {
    if (fail.load()) return Error{ErrorCode::Unsupported, "test: salt source down"};
    ++n_;
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::byte>(n_ * 37 + i * 5 + 1);
    return {};
  }
  unsigned n_ = 0;
};

class TestKeys final : public KeySource {
 public:
  explicit TestKeys(std::uint8_t salt) : salt_(salt) {}
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
      std::uint64_t x = 1469598103934665603ull ^ static_cast<std::uint64_t>(salt_ * 131 + tag + i);
      for (auto b : raw) x = (x ^ static_cast<std::uint64_t>(b)) * 1099511628211ull;
      x ^= x >> 29;
      x *= 0x9E3779B97F4A7C15ull;
      out[i] = static_cast<std::byte>(x >> 56);
    }
  }
  std::uint8_t salt_;
};

ScopeKeys scope_keys(int scope, std::uint8_t salt = 7) {
  ScopeKeys sk;
  ScopeId s{};
  s.b[0] = static_cast<std::uint8_t>(scope);
  s.b[31] = 0x5c;
  sk.scopes = {s};
  sk.keys = std::make_shared<TestKeys>(salt);
  sk.kver = 1;
  return sk;
}

// A chain of keys k0 (root), k1 (parent k0), ...
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

store::StoreConfig store_cfg() {
  store::StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 4;
  c.gen_chunk = 1000;
  c.put_timeout = seconds(1000);
  c.lease_ttl = seconds(1000);
  c.lease_max = seconds(2000);
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 8u << 20;
  c.principal_default.idle_ttl = seconds(100000);
  return c;
}

struct Res {
  bool done = false, released = false;
  int done_seq = 0, rel_seq = 0;
  std::vector<KeyStatus> st;
};

struct World {
  explicit World(fabric::SimOptions so = {}, std::uint64_t seed = 1)
      : rng(seed), net(clock, rng, {}, so), srv(net.add_node(1)) {
    auto s = LoopbackServer::create(srv, clock, rng, store_cfg());
    EXPECT_TRUE(s);
    server = std::move(*s);
  }
  struct Cl {
    fabric::SimFabric* fab = nullptr;
    std::unique_ptr<LoopbackPort> port;
    std::unique_ptr<ClientCore> core;
  };
  Cl& add_client(store::PrincipalId p, fabric::NodeId node, ClientCoreOptions o = {}) {
    auto c = std::make_unique<Cl>();
    c->fab = &net.add_node(node);
    c->port = std::make_unique<LoopbackPort>(*server, p, 100 + p, [this] { net.run_until_idle(); });
    auto core = ClientCore::create(*c->fab, *c->port, clock, ex, salts, o);
    EXPECT_TRUE(core);
    c->core = std::move(*core);
    clients.push_back(std::move(c));
    return *clients.back();
  }
  Notify notify(Res& r) {
    return Notify{[this, &r](Ticket, std::span<const KeyStatus> s) {
                    r.done = true, r.done_seq = ++seq, r.st.assign(s.begin(), s.end());
                  },
                  [this, &r](Ticket) { r.released = true, r.rel_seq = ++seq; }};
  }
  // Pump + step the network until `pred`; advances virtual time when the network is idle.
  template <class P>
  bool spin(Cl& c, P pred, int cap = 400000) {
    for (int i = 0; i < cap; ++i) {
      c.core->pump();
      if (pred()) return true;
      if (!net.step()) clock.advance_by(milliseconds(1));
    }
    return false;
  }
  // Store a chain; returns the statuses.
  std::vector<KeyStatus> put(Cl& c, const ScopeKeys& sk, const Chain& ch, std::vector<Bytes>& data) {
    std::vector<BufRef> bufs;
    for (auto& d : data) bufs.push_back({std::span<std::byte>(d)});
    Res r;
    c.core->submit_store(sk, 0, ch.refs, bufs, clock.now() + seconds(5), notify(r));
    EXPECT_TRUE(spin(c, [&] { return r.released; }));
    return r.st;
  }
  std::vector<KeyStatus> fetch(Cl& c, const ScopeKeys& sk, const Chain& ch, std::vector<Bytes>& out) {
    std::vector<BufRef> bufs;
    for (auto& d : out) bufs.push_back({std::span<std::byte>(d)});
    Res r;
    c.core->submit_fetch(sk, 0, ch.refs, bufs, clock.now() + seconds(5), notify(r));
    EXPECT_TRUE(spin(c, [&] { return r.released; }));
    EXPECT_LE(r.done_seq, r.rel_seq);
    return r.st;
  }
  void check(Cl& c, bool puts_too = true) {
    auto s = c.core->check_invariants();
    EXPECT_TRUE(s) << s.error().context;
    auto a = server->store().check_invariants();
    EXPECT_TRUE(a) << a.error().context;
    auto b = server->slab().check_invariants();
    EXPECT_TRUE(b) << b.error().context;
    auto m = server->mrs().check_invariants();
    EXPECT_TRUE(m) << m.error().context;
    if (puts_too) {
      auto p = server->puts().check_invariants();
      EXPECT_TRUE(p) << p.error().context;
    }
  }

  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& srv;
  std::unique_ptr<LoopbackServer> server;
  InlineExecutor ex;
  CounterSalts salts;
  std::vector<std::unique_ptr<Cl>> clients;
  int seq = 0;
};

fabric::SimOptions sliced(std::uint32_t slice, bool iwarp) {
  fabric::SimOptions o;
  o.slice_size = slice;
  o.iwarp_early_write_cqe = iwarp;
  return o;
}

TEST(ClientLoopback, PutThenFetchIsByteIdentical) {
  for (bool iwarp : {false, true}) {
    World w(sliced(1024, iwarp), 11);
    auto& c = w.add_client(1, 2);
    auto sk = scope_keys(1);
    const std::size_t sizes[] = {1, kSeg, kSeg * 3 + kSeg / 2};
    Chain ch("k", 3);
    std::vector<Bytes> data, out;
    for (int i = 0; i < 3; ++i) {
      data.push_back(payload(sizes[i], i));
      out.emplace_back(sizes[i], std::byte{0xAA});
    }
    auto ps = w.put(c, sk, ch, data);
    ASSERT_EQ(ps.size(), 3u);
    for (auto s : ps) EXPECT_EQ(s, KeyStatus::Committed);
    w.check(c);
    auto fs = w.fetch(c, sk, ch, out);
    for (int i = 0; i < 3; ++i) {
      EXPECT_EQ(fs[i], KeyStatus::Hit) << i << " iwarp=" << iwarp;
      EXPECT_EQ(out[i], data[i]) << i;
    }
    EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
    EXPECT_EQ(w.server->store().n_leases(), 0u);
    w.check(c);
    // Re-put is idempotent: SKIPPED.
    auto again = w.put(c, sk, ch, data);
    for (auto s : again) EXPECT_EQ(s, KeyStatus::Skipped);
  }
}

TEST(ClientLoopback, UnknownKeyMissesAndZeroesBuffer) {
  World w;
  auto& c = w.add_client(1, 2);
  Chain ch("nokey", 2);
  std::vector<Bytes> out{Bytes(5000, std::byte{0xAA}), Bytes(100, std::byte{0xAA})};
  auto fs = w.fetch(c, scope_keys(1), ch, out);
  EXPECT_EQ(fs[0], KeyStatus::Miss);
  EXPECT_EQ(fs[1], KeyStatus::Miss);
  EXPECT_TRUE(all_zero(out[0]));
  EXPECT_TRUE(all_zero(out[1]));
  w.check(c);
}

TEST(ClientLoopback, OtherPrincipalOrScopeNeverHits) {
  World w;
  auto& a = w.add_client(1, 2);
  auto& b = w.add_client(2, 3);
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(9000, 1)}, out{Bytes(9000, std::byte{0xAA})};
  ASSERT_EQ(w.put(a, sk, ch, data)[0], KeyStatus::Committed);
  EXPECT_EQ(w.fetch(a, sk, ch, out)[0], KeyStatus::Hit);
  // Other principal, same scope id and keys: a miss.
  out[0].assign(9000, std::byte{0xAA});
  EXPECT_EQ(w.fetch(b, sk, ch, out)[0], KeyStatus::Miss);
  EXPECT_TRUE(all_zero(out[0]));
  // Same principal, a different scope: a miss.
  out[0].assign(9000, std::byte{0xAA});
  EXPECT_EQ(w.fetch(a, scope_keys(2), ch, out)[0], KeyStatus::Miss);
  EXPECT_TRUE(all_zero(out[0]));
  w.check(a);
}

TEST(ClientLoopback, TimeoutReportsAtOnceAndFreesBuffersOnlyAfterDrain) {
  World w(sliced(1024, false), 5);
  auto& c = w.add_client(1, 2);
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(kSeg * 2, 3)}, out{Bytes(kSeg * 2, std::byte{0xAA})};
  ASSERT_EQ(w.put(c, sk, ch, data)[0], KeyStatus::Committed);
  Res r;
  std::vector<BufRef> bufs{{std::span<std::byte>(out[0])}};
  c.core->submit_fetch(sk, 0, ch.refs, bufs, w.clock.now() + Nanos{1}, w.notify(r));
  EXPECT_EQ(w.server->store().n_leases(), 1u);
  w.clock.advance_by(Nanos{10});
  c.core->pump();  // no network progress yet: the READ is still in flight
  ASSERT_TRUE(r.done);
  EXPECT_EQ(r.st[0], KeyStatus::Timeout);
  EXPECT_FALSE(r.released);
  EXPECT_GT(c.core->pool_bytes_in_use(), 0u);
  EXPECT_EQ(w.server->store().n_leases(), 1u);
  ASSERT_TRUE(w.spin(c, [&] { return r.released; }));
  EXPECT_LT(r.done_seq, r.rel_seq);
  EXPECT_TRUE(all_zero(out[0]));
  EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
  EXPECT_EQ(w.server->store().n_leases(), 0u);
  w.check(c);
}

TEST(ClientLoopback, CancelCompletesOnlyAfterDrain) {
  World w(sliced(1024, false), 6);
  auto& c = w.add_client(1, 2);
  auto sk = scope_keys(1);
  Chain ch("k", 1);
  std::vector<Bytes> data{payload(kSeg * 2, 4)}, out{Bytes(kSeg * 2, std::byte{0xAA})};
  ASSERT_EQ(w.put(c, sk, ch, data)[0], KeyStatus::Committed);
  Res r;
  std::vector<BufRef> bufs{{std::span<std::byte>(out[0])}};
  Ticket t = c.core->submit_fetch(sk, 0, ch.refs, bufs, w.clock.now() + seconds(5), w.notify(r));
  c.core->cancel(t);
  c.core->pump();
  EXPECT_FALSE(r.done);  // reads are still in flight
  EXPECT_FALSE(r.released);
  ASSERT_TRUE(w.spin(c, [&] { return r.released; }));
  ASSERT_TRUE(r.done);
  EXPECT_EQ(r.st[0], KeyStatus::Aborted);
  EXPECT_LT(r.done_seq, r.rel_seq);
  EXPECT_TRUE(all_zero(out[0]));
  EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
  EXPECT_EQ(w.server->store().n_leases(), 0u);
  w.check(c);
}

TEST(ClientLoopback, ProbeTakesNoLease) {
  World w;
  auto& c = w.add_client(1, 2);
  auto sk = scope_keys(1);
  Chain ch("k", 2);
  std::vector<Bytes> data{payload(3000, 1)};
  Chain root("k", 1);
  ASSERT_EQ(w.put(c, sk, root, data)[0], KeyStatus::Committed);
  std::vector<KeyStatus> st;
  c.core->probe(sk, 0, ch.refs, w.clock.now() + seconds(1),
                [&](Ticket, std::span<const KeyStatus> s) { st.assign(s.begin(), s.end()); });
  ASSERT_EQ(st.size(), 2u);
  EXPECT_EQ(st[0], KeyStatus::Hit);
  EXPECT_EQ(st[1], KeyStatus::Miss);
  EXPECT_EQ(w.server->store().n_leases(), 0u);
  EXPECT_EQ(c.core->jobs_live(), 0u);
  // A fetch, by contrast, holds one lease while it runs.
  std::vector<Bytes> out{Bytes(3000, std::byte{0})};
  std::vector<BufRef> bufs{{std::span<std::byte>(out[0])}};
  Res r;
  c.core->submit_fetch(sk, 0, root.refs, bufs, w.clock.now() + seconds(5), w.notify(r));
  EXPECT_EQ(w.server->store().n_leases(), 1u);
  ASSERT_TRUE(w.spin(c, [&] { return r.released; }));
  EXPECT_EQ(w.server->store().n_leases(), 0u);
}

TEST(ClientLoopback, RefusedWithRetryZeroDropsTheStore) {
  World w;
  auto& c = w.add_client(1, 2);
  auto sk = scope_keys(1);
  Chain ch("k", 6);
  // Start mid-chain: no root, so the scope is unknown and PUT_BEGIN is REFUSED, retry 0.
  std::vector<KeyRef> refs(ch.refs.begin() + 1, ch.refs.end());
  std::vector<Bytes> data;
  for (int i = 0; i < 5; ++i) data.push_back(payload(4096, i));
  std::vector<BufRef> bufs;
  for (auto& d : data) bufs.push_back({std::span<std::byte>(d)});
  Res r;
  c.core->submit_store(sk, 0, refs, bufs, w.clock.now() + seconds(5), w.notify(r));
  ASSERT_TRUE(w.spin(c, [&] { return r.released; }));
  ASSERT_EQ(r.st.size(), 5u);
  for (auto s : r.st) EXPECT_EQ(s, KeyStatus::Refused);
  EXPECT_FALSE(w.server->store().has_scope(1, [&] {
    store::ScopeId s{};
    std::memcpy(s.data(), sk.scopes[0].b, 32);
    return s;
  }()));
  EXPECT_EQ(w.server->store().bytes_used(1), 0u);
  w.check(c);
}

// Seeded scenario: slicing + early iWARP CQEs + a rogue writer scribbling committed extents
// while fetches are in flight. Every fetch is an exact HIT or a MISS with a zeroed buffer.
TEST(ClientLoopback, SeededRogueWriterNeverYieldsWrongBytes) {
  std::uint64_t hits = 0, misses = 0, scribbles = 0;
  for (std::uint64_t seed = 1; seed <= 12; ++seed) {
    World w(sliced(512, seed % 2 == 0), seed);
    auto& c = w.add_client(1, 2);
    auto sk = scope_keys(1);
    const std::size_t n = 6;
    Chain ch("k", n);
    std::vector<Bytes> data;
    for (std::size_t i = 0; i < n; ++i) data.push_back(payload(1 + w.rng.below(kSeg * 3), static_cast<int>(i)));
    auto ps = w.put(c, sk, ch, data);
    for (auto s : ps) ASSERT_EQ(s, KeyStatus::Committed) << seed;
    w.check(c);  // CommittedIntact holds before the rogue writer starts

    for (int round = 0; round < 6; ++round) {
      std::vector<Bytes> out;
      for (auto& d : data) out.emplace_back(d.size(), std::byte{0xAA});
      std::vector<BufRef> bufs;
      for (auto& o : out) bufs.push_back({std::span<std::byte>(o)});
      Res r;
      c.core->submit_fetch(sk, 0, ch.refs, bufs, w.clock.now() + seconds(5), w.notify(r));
      std::vector<store::Extent> exts;
      w.server->store().for_each_block(
          [&](const store::Extent& e, std::uint64_t, bool) { exts.push_back(e); });
      for (int i = 0; i < 400000 && !r.released; ++i) {
        c.core->pump();
        if (r.released) break;
        // Rogue: occasionally flip a byte somewhere in a random committed block.
        if (round >= 2 && !exts.empty() && w.rng.below(40) == 0) {
          const auto& e = exts[w.rng.below(exts.size())];
          auto blk = w.server->arena().block(e.seg, e.off, e.len);
          blk[w.rng.below(blk.size())] ^= std::byte{0x5a};
          ++scribbles;
        }
        if (!w.net.step()) w.clock.advance_by(milliseconds(1));
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
      EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
      EXPECT_EQ(w.server->store().n_leases(), 0u);
      w.check(c, /*puts_too=*/false);  // puts.check_invariants re-CRCs committed blocks
    }
  }
  EXPECT_GT(hits, 0u);
  EXPECT_GT(misses, 0u);
  EXPECT_GT(scribbles, 0u);
  RecordProperty("hits", static_cast<int>(hits));
  RecordProperty("misses", static_cast<int>(misses));
  RecordProperty("scribbles", static_cast<int>(scribbles));
}

// Facade over Runtime: real worker threads drive the core; the test waits on the eventfd.
TEST(ClientFacade, StoreThenFetchThroughRuntime) {
  World w(sliced(2048, true), 21);
  fabric::SimFabric& cf = w.net.add_node(2);
  LoopbackPort port(*w.server, 1, 101, [&] { w.net.run_until_idle(); });
  Client::Env env;
  env.fab = &cf;
  env.port = &port;
  env.clock = &w.clock;
  env.executor = &w.ex;
  env.salts = &w.salts;
  env.drive = [&] {
    if (!w.net.step()) w.clock.advance_by(milliseconds(1));
  };
  auto cl = Client::open_loopback(env);
  ASSERT_TRUE(cl);
  Client& c = **cl;
  auto sk = scope_keys(1);
  Chain ch("k", 3);
  std::vector<Bytes> data{payload(1, 1), payload(kSeg, 2), payload(kSeg * 3 + kSeg / 2, 3)};
  std::vector<Bytes> out;
  for (auto& d : data) out.emplace_back(d.size(), std::byte{0xAA});
  std::vector<BufRef> pbufs, fbufs;
  for (auto& d : data) pbufs.push_back({std::span<std::byte>(d)});
  for (auto& o : out) fbufs.push_back({std::span<std::byte>(o)});

  auto wait = [&](Ticket t) {
    for (int i = 0; i < 2000; ++i) {
      std::array<Completion, 8> comp;
      std::size_t n = c.poll(comp);
      for (std::size_t k = 0; k < n; ++k)
        if (comp[k].ticket == t) return comp[k].status;
      pollfd pfd{c.eventfd(), POLLIN, 0};
      ::poll(&pfd, 1, 10);
    }
    return std::vector<KeyStatus>{};
  };
  auto ps = wait(c.store(sk, 0, ch.refs, pbufs, seconds(5)));
  ASSERT_EQ(ps.size(), 3u);
  for (auto s : ps) EXPECT_EQ(s, KeyStatus::Committed);
  auto ls = wait(c.lookup(sk, 0, ch.refs, seconds(5)));
  ASSERT_EQ(ls.size(), 3u);
  for (auto s : ls) EXPECT_EQ(s, KeyStatus::Hit);
  auto fs = wait(c.fetch(sk, 0, ch.refs, fbufs, seconds(5)));
  ASSERT_EQ(fs.size(), 3u);
  for (int i = 0; i < 3; ++i) {
    EXPECT_EQ(fs[i], KeyStatus::Hit);
    EXPECT_EQ(out[i], data[i]);
  }
  // A cancelled fetch completes (ABORTED or a finished HIT) with zeroed or exact buffers.
  std::vector<Bytes> out2;
  for (auto& d : data) out2.emplace_back(d.size(), std::byte{0xAA});
  std::vector<BufRef> b2;
  for (auto& o : out2) b2.push_back({std::span<std::byte>(o)});
  Ticket t = c.fetch(sk, 0, ch.refs, b2, seconds(5));
  c.cancel(t);
  auto cs = wait(t);
  ASSERT_EQ(cs.size(), 3u);
  for (int i = 0; i < 3; ++i) {
    if (cs[i] == KeyStatus::Hit) EXPECT_EQ(out2[i], data[i]);
    else EXPECT_TRUE(all_zero(out2[i]) || out2[i] == Bytes(data[i].size(), std::byte{0xAA}))
        << "cancelled before start leaves the buffer untouched; after start it is zeroed";
  }
}

// ---- fix round 1 (review-store-s1s5-client-l3-r1: Q03/Q04/Q11-Q15) --------------------

// ServerPort decorator: mutate the server's acks and/or lose PUT_DONE, like a broken peer.
class FaultPort final : public ServerPort {
 public:
  explicit FaultPort(ServerPort& in) : in_(in) {}
  std::function<void(store::LookupAck&)> mut_lookup;
  std::function<void(store::PutBeginAck&)> mut_begin;
  std::atomic<bool> drop_commit{false};
  std::atomic<bool> removed{false};  // review w5 U2-24: the node's GOAWAY said Epoch (removed from the membership)
  std::atomic<int> commits{0}, cancels{0};
  std::vector<store::PutDoneFn> held;  // the dropped PUT_DONE callbacks

  bool removed_from_membership() const override { return removed.load(); }
  Expected<ServerInfo> hello() override { return in_.hello(); }
  void connected(fabric::EpClass c, fabric::Endpoint* e) override { in_.connected(c, e); }
  store::LookupAck lookup(const store::LookupReq& q) override {
    auto a = in_.lookup(q);
    if (mut_lookup) mut_lookup(a);
    return a;
  }
  Status renew(store::LeaseId l) override { return in_.renew(l); }
  Status release(store::LeaseId l) override { return in_.release(l); }
  store::PutBeginAck put_begin(const store::PutBeginReq& q) override {
    auto a = in_.put_begin(q);
    if (mut_begin) mut_begin(a);
    return a;
  }
  void put_commit(const store::PutCommitReq& q, store::PutDoneFn done) override {
    ++commits;
    if (drop_commit) {
      held.push_back(std::move(done));
      return;
    }
    in_.put_commit(q, std::move(done));
  }
  void put_cancel(store::PutId id, store::PutDoneFn done) override {
    ++cancels;
    in_.put_cancel(id, std::move(done));
  }

 private:
  ServerPort& in_;
};

struct FaultClient {
  FaultClient(World& w, fabric::NodeId node = 2, ClientCoreOptions o = {})
      : lp(*w.server, 1, 101, [&w] { w.net.run_until_idle(); }), fp(lp) {
    fab = &w.net.add_node(node);
    auto c = ClientCore::create(*fab, fp, w.clock, w.ex, w.salts, o);
    EXPECT_TRUE(c);
    core = std::move(*c);
  }
  template <class P>
  bool spin(World& w, P pred, int cap = 400000) {
    for (int i = 0; i < cap; ++i) {
      core->pump();
      if (pred()) return true;
      if (!w.net.step()) w.clock.advance_by(milliseconds(1));
    }
    return false;
  }
  fabric::SimFabric* fab = nullptr;
  LoopbackPort lp;
  FaultPort fp;
  std::unique_ptr<ClientCore> core;
};

struct StoreJob {
  StoreJob(const std::string& prefix, std::size_t n, std::size_t len = 100) : ch(prefix, n) {
    for (std::size_t i = 0; i < n; ++i) {
      data.push_back(payload(len, static_cast<int>(i)));
      bufs.push_back({std::span<std::byte>(data.back())});
    }
  }
  Chain ch;
  std::vector<Bytes> data;
  std::vector<BufRef> bufs;
};

void expect_all(const std::vector<KeyStatus>& st, std::size_t n, KeyStatus want) {
  ASSERT_EQ(st.size(), n);
  for (auto s : st) EXPECT_EQ(s, want);
}

// Q03: a local batch failure must abort every key of the batch at once, not wait for the deadline.
// Review w5 U2-24: on a node that left the membership, only what the session loss cut short becomes Skipped. A refusal
// the node ANSWERED (retry 0, e.g. "parent unknown") stays Refused, so the client can fall through to the previous set;
// a key aborted locally (here: the landing pool is full) is a skip.
TEST(ClientFix, RemovedNodeKeepsAnsweredRefusalsAndSkipsTheRest) {
  {
    World w;
    FaultClient c(w);
    c.fp.removed = true;
    c.fp.mut_begin = [](store::PutBeginAck& a) {
      a.status = store::BeginStatus::Refused;
      a.retry_after_ms = 0;
      a.skip = store::BeginSkip::None;
    };
    StoreJob sj("ref", 1);
    Res r;
    c.core->submit_store(scope_keys(1), 0, sj.ch.refs, sj.bufs, w.clock.now() + seconds(5), w.notify(r));
    ASSERT_TRUE(c.spin(w, [&] { return r.released; }));
    expect_all(r.st, 1, KeyStatus::Refused);
  }
  {
    World w;
    ClientCoreOptions o;
    o.pool_bytes = 4096;  // one sealed block fits: the second key aborts locally
    FaultClient c(w, 2, o);
    c.fp.removed = true;
    StoreJob sj("abt", 2);
    Res r;
    c.core->submit_store(scope_keys(1), 0, sj.ch.refs, sj.bufs, w.clock.now() + seconds(5), w.notify(r));
    ASSERT_TRUE(c.spin(w, [&] { return r.released; }));
    expect_all(r.st, 2, KeyStatus::Skipped);
  }
}

TEST(ClientFix, Q03PoolExhaustionAbortsPromptly) {
  World w;
  ClientCoreOptions o;
  o.pool_bytes = 4096;  // room for one sealed block, so the second acquire fails
  FaultClient c(w, 2, o);
  StoreJob sj("k", 2);
  Res r;
  const Nanos t0 = w.clock.now();
  c.core->submit_store(scope_keys(1), 0, sj.ch.refs, sj.bufs, t0 + seconds(5), w.notify(r));
  ASSERT_TRUE(c.spin(w, [&] { return r.released; }));
  expect_all(r.st, 2, KeyStatus::Aborted);
  EXPECT_LT(w.clock.now() - t0, seconds(1));  // no deadline wait
  EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
  EXPECT_TRUE(c.core->check_invariants());
  EXPECT_TRUE(w.server->puts().check_invariants());
  EXPECT_EQ(c.fp.cancels.load(), 1);
}

TEST(ClientFix, Q03SealFailureAbortsPromptly) {
  World w;
  FaultClient c(w);
  StoreJob sj("k", 3);
  w.salts.fail = true;
  Res r;
  const Nanos t0 = w.clock.now();
  c.core->submit_store(scope_keys(1), 0, sj.ch.refs, sj.bufs, t0 + seconds(5), w.notify(r));
  ASSERT_TRUE(c.spin(w, [&] { return r.released; }));
  expect_all(r.st, 3, KeyStatus::Aborted);
  EXPECT_LT(w.clock.now() - t0, seconds(1));
  EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
  EXPECT_TRUE(w.server->puts().check_invariants());
}

// Q04: server-supplied MR index / extent are bounds-checked; a bad ack aborts the batch.
TEST(ClientFix, Q04BadMrExtentIsProtocolError) {
  struct Case {
    const char* name;
    std::function<void(store::PutBeginAck&)> mut;
  };
  const Case cases[] = {
      {"index out of range", [](store::PutBeginAck& a) { a.entries[1].mr_index = 7; }},
      {"empty mr", [](store::PutBeginAck& a) { a.mr.clear(); }},
      {"extent past mr end", [](store::PutBeginAck& a) { a.entries[0].offset = a.mr[a.entries[0].mr_index].len - 1; }},
      {"offset wraps", [](store::PutBeginAck& a) { a.entries[0].offset = ~std::uint64_t{0}; }},
  };
  for (const auto& cs : cases) {
    World w;
    FaultClient c(w);
    c.fp.mut_begin = cs.mut;
    StoreJob sj("k", 2);
    Res r;
    const Nanos t0 = w.clock.now();
    c.core->submit_store(scope_keys(1), 0, sj.ch.refs, sj.bufs, t0 + seconds(5), w.notify(r));
    ASSERT_TRUE(c.spin(w, [&] { return r.released; })) << cs.name;
    expect_all(r.st, 2, KeyStatus::Aborted);
    EXPECT_LT(w.clock.now() - t0, seconds(1)) << cs.name;
    EXPECT_EQ(c.core->pool_bytes_in_use(), 0u) << cs.name;
    EXPECT_TRUE(c.core->check_invariants()) << cs.name;
    EXPECT_TRUE(w.server->puts().check_invariants()) << cs.name;
  }
}

// Q11: a lost PUT_DONE must not hang the job; the deadline completes it and buffers are released.
TEST(ClientFix, Q11LostPutDoneTimesOutAndReleases) {
  World w;
  FaultClient c(w);
  c.fp.drop_commit = true;
  StoreJob sj("k", 2);
  Res r;
  const Nanos t0 = w.clock.now();
  c.core->submit_store(scope_keys(1), 0, sj.ch.refs, sj.bufs, t0 + milliseconds(50), w.notify(r));
  ASSERT_TRUE(c.spin(w, [&] { return r.released; }));
  expect_all(r.st, 2, KeyStatus::Timeout);
  EXPECT_EQ(c.fp.commits.load(), 1);
  EXPECT_EQ(c.fp.cancels.load(), 1);
  EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
  EXPECT_EQ(c.core->jobs_live(), 0u);
  // The late PUT_DONE hits a finished job: it must be a harmless no-op (no dangling Job*).
  ASSERT_EQ(c.fp.held.size(), 1u);
  c.fp.held[0](store::PutDoneResult{});
  c.core->pump();
  EXPECT_EQ(c.core->jobs_live(), 0u);
  EXPECT_TRUE(w.server->puts().check_invariants());
}

TEST(ClientFix, Q11CancelWhileCommittingCompletesAborted) {
  World w;
  FaultClient c(w);
  c.fp.drop_commit = true;
  StoreJob sj("k", 2);
  Res r;
  Ticket t = c.core->submit_store(scope_keys(1), 0, sj.ch.refs, sj.bufs, w.clock.now() + seconds(5), w.notify(r));
  ASSERT_TRUE(c.spin(w, [&] { return c.fp.commits.load() == 1; }));
  EXPECT_FALSE(r.released);
  c.core->cancel(t);
  c.core->pump();
  ASSERT_TRUE(r.released);
  expect_all(r.st, 2, KeyStatus::Aborted);
  EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
}

// Q12: server-supplied lookup extents that would wrap a naive `a + b > len` check are misses.
TEST(ClientFix, Q12WrappingLookupValuesAreMisses) {
  for (int variant = 0; variant < 2; ++variant) {
    World w;
    FaultClient c(w);
    StoreJob sj("k", 1, 5000);
    Res pr;
    c.core->submit_store(scope_keys(1), 0, sj.ch.refs, sj.bufs, w.clock.now() + seconds(5), w.notify(pr));
    ASSERT_TRUE(c.spin(w, [&] { return pr.released; }));
    ASSERT_EQ(pr.st[0], KeyStatus::Committed);
    c.fp.mut_lookup = [variant](store::LookupAck& a) {
      ASSERT_FALSE(a.entries.empty());
      auto& e = a.entries[0];
      if (variant == 0) e.offset = ~std::uint64_t{0} - e.stored_len + 1;  // offset + stored_len == 0
      else e.gen_slot = (std::uint64_t{1} << 61) - 1;                      // (gen_slot + 1) * 8 == 0
    };
    Bytes out(5000, std::byte{0xAA});
    std::vector<BufRef> fb{{std::span<std::byte>(out)}};
    Res r;
    c.core->submit_fetch(scope_keys(1), 0, sj.ch.refs, fb, w.clock.now() + seconds(5), w.notify(r));
    ASSERT_TRUE(c.spin(w, [&] { return r.released; }));
    expect_all(r.st, 1, KeyStatus::Miss);
    EXPECT_TRUE(all_zero(out));
    EXPECT_EQ(c.core->pool_bytes_in_use(), 0u);
    EXPECT_TRUE(c.core->check_invariants()) << "bad READ drove an endpoint into error, variant " << variant;
  }
}

// Facade harness: workers drive the core; `drive` and the clock are test-controlled.
class AtomicClock final : public Clock {
 public:
  Nanos now() const override { return Nanos{ns_.load()}; }
  void advance_by(Nanos d) { ns_ += d.count(); }

 private:
  std::atomic<std::int64_t> ns_{0};
};

struct FacadeHarness {
  explicit FacadeHarness(unsigned workers, std::function<void()> drive, bool atomic_clock = false)
      : w(), cf(w.net.add_node(2)), lp(*w.server, 1, 101, [this] { w.net.run_until_idle(); }), fp(lp) {
    Client::Env env;
    env.fab = &cf;
    env.port = &fp;
    env.clock = atomic_clock ? static_cast<const Clock*>(&aclock) : static_cast<const Clock*>(&w.clock);
    env.executor = &w.ex;
    env.salts = &w.salts;
    env.drive = std::move(drive);
    RuntimeOptions ro;
    ro.workers = workers;
    auto c = Client::open_loopback(env, {}, ro);
    EXPECT_TRUE(c);
    cl = std::move(*c);
  }
  // Waits for ticket `t` (real time bound ~20 s). Empty result = not completed.
  std::vector<KeyStatus> wait(Ticket t) {
    for (int i = 0; i < 2000; ++i) {
      std::array<Completion, 8> comp;
      std::size_t n = cl->poll(comp);
      for (std::size_t k = 0; k < n; ++k) got[comp[k].ticket.id] = std::move(comp[k].status);
      auto it = got.find(t.id);
      if (it != got.end()) return it->second;
      pollfd pfd{cl->eventfd(), POLLIN, 0};
      ::poll(&pfd, 1, 10);
    }
    return {};
  }
  std::map<std::uint64_t, std::vector<KeyStatus>> got;  // completions of other tickets seen meanwhile
  World w;
  AtomicClock aclock;
  fabric::SimFabric& cf;
  LoopbackPort lp;
  FaultPort fp;
  std::unique_ptr<Client> cl;
};

// Q11 (facade): the worker must not hang on a lost PUT_DONE.
TEST(ClientFix, Q11FacadeWorkerExitsOnLostPutDone) {
  FacadeHarness* hp = nullptr;
  FacadeHarness h(1, [&hp] {
    if (!hp->w.net.step()) hp->w.clock.advance_by(milliseconds(1));
  });
  hp = &h;
  h.fp.drop_commit = true;
  StoreJob sj("k", 2);
  auto st = h.wait(h.cl->store(scope_keys(1), 0, sj.ch.refs, sj.bufs, milliseconds(50)));
  expect_all(st, 2, KeyStatus::Timeout);
  // The single worker is free again: a following request is served.
  h.fp.drop_commit = false;
  StoreJob sj2("m", 1);
  expect_all(h.wait(h.cl->store(scope_keys(1), 0, sj2.ch.refs, sj2.bufs, seconds(5))), 1, KeyStatus::Committed);
}

// A store stuck in Backoff (PUT_BEGIN refused, long retry): no RDMA, no clock movement.
void stall_store_in_backoff(FaultPort& fp) {
  fp.mut_begin = [](store::PutBeginAck& a) {
    a.status = store::BeginStatus::Refused;
    a.retry_after_ms = 600000;
  };
}

// Q13: an idle worker must not busy-spin.
TEST(ClientFix, Q13IdleWorkerDoesNotSpin) {
  FacadeHarness h(1, {}, /*atomic_clock=*/true);
  stall_store_in_backoff(h.fp);
  StoreJob sj("k", 1);
  Ticket t = h.cl->store(scope_keys(1), 0, sj.ch.refs, sj.bufs, seconds(600));
  std::this_thread::sleep_for(milliseconds(150));
  const std::uint64_t it = h.cl->pump_iterations();
  EXPECT_GT(it, 0u);
  EXPECT_LT(it, 2000u) << "worker spun " << it << " pump turns in 150 ms of idleness";
  h.cl->cancel(t);  // wakes the worker promptly
  expect_all(h.wait(t), 1, KeyStatus::Aborted);
}

// Q14: the timeout runs from submit(), not from worker pickup.
TEST(ClientFix, Q14TimeoutCountsFromSubmit) {
  std::atomic<bool> go{false};
  FacadeHarness* hp = nullptr;
  FacadeHarness h(1,
                  [&] {
                    if (go && !hp->w.net.step()) hp->w.clock.advance_by(milliseconds(1));
                  },
                  /*atomic_clock=*/true);
  hp = &h;
  StoreJob a("a", 1), b("b", 1);
  Ticket ta = h.cl->store(scope_keys(1), 0, a.ch.refs, a.bufs, seconds(1));
  while (h.cl->pump_iterations() == 0) std::this_thread::yield();  // A is running, its writes parked
  Ticket tb = h.cl->store(scope_keys(1), 0, b.ch.refs, b.bufs, seconds(1));  // queued behind A
  h.aclock.advance_by(seconds(2));  // both deadlines have passed
  go = true;
  expect_all(h.wait(ta), 1, KeyStatus::Timeout);
  expect_all(h.wait(tb), 1, KeyStatus::Timeout);  // pre-fix: deadline restarted at pickup -> Committed
}

// Q15: requests that the runtime completes ABORTED without run() must not leak.
TEST(ClientFix, Q15AbortedWithoutRunDoesNotLeakReq) {
  {
    FacadeHarness h(1, {}, true);
    h.cl->shutdown();
    StoreJob sj("k", 1);
    expect_all(h.wait(h.cl->store(scope_keys(1), 0, sj.ch.refs, sj.bufs, seconds(5))), 1, KeyStatus::Aborted);
    EXPECT_EQ(h.cl->pending_requests(), 0u);
  }
}

TEST(ClientFix, Q15CancelledWhileQueuedDoesNotLeakReq) {
  {
    // Cancelled while still queued behind a running job.
    FacadeHarness h(1, {}, true);
    stall_store_in_backoff(h.fp);
    StoreJob a("a", 1), b("b", 1);
    Ticket ta = h.cl->store(scope_keys(1), 0, a.ch.refs, a.bufs, seconds(600));
    Ticket tb = h.cl->store(scope_keys(1), 0, b.ch.refs, b.bufs, seconds(600));
    h.cl->cancel(tb);
    h.cl->cancel(ta);
    expect_all(h.wait(ta), 1, KeyStatus::Aborted);
    expect_all(h.wait(tb), 1, KeyStatus::Aborted);
    EXPECT_EQ(h.cl->pending_requests(), 0u);
  }
}

TEST(ClientFacade, WireOpenRejectsAnEmptyConfig) {  // Client::open is the wire client now (wire_port_test.cpp)
  struct NullProvider final : ScopeProvider {
    Expected<ScopeKeys> derive(const RequestMeta&) const override { return Error{ErrorCode::Unsupported, "x"}; }
  } p;
  auto r = Client::open(ClientConfig{}, p);
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, ErrorCode::InvalidArgument);
}

// ---- A3.5 M2: client metrics ---------------------------------------------------------

// Value of the exposition line that starts with `series` (name{labels}), or -1.
double series(const std::string& text, const std::string& s) {
  const std::string all = "\n" + text, needle = "\n" + s + " ";
  auto p = all.find(needle);
  if (p == std::string::npos) return -1;
  return std::stod(all.substr(p + needle.size(), 40));
}

TEST(ClientMetrics, RoundTripMovesExactlyTheExpectedCounters) {
  World w(sliced(1024, false), 21);
  auto& c = w.add_client(1, 2);
  auto sk = scope_keys(1);
  const std::string t0 = c.core->metrics_text();
  EXPECT_EQ(series(t0, "miracache_client_put_ops_total{result=\"committed\"}"), 0);
  EXPECT_EQ(series(t0, "miracache_client_inflight{op=\"fetch\"}"), 0);

  Chain ch("k", 3);
  const std::size_t sizes[] = {1, kSeg, kSeg * 2 + 5};
  std::vector<Bytes> data, out;
  std::uint64_t total = 0;
  for (int i = 0; i < 3; ++i) {
    data.push_back(payload(sizes[i], i));
    out.emplace_back(sizes[i], std::byte{0xAA});
    total += sizes[i];
  }
  for (auto s : w.put(c, sk, ch, data)) ASSERT_EQ(s, KeyStatus::Committed);
  for (auto s : w.fetch(c, sk, ch, out)) ASSERT_EQ(s, KeyStatus::Hit);
  Chain miss("nokey", 2);
  std::vector<Bytes> mout{Bytes(100, std::byte{0}), Bytes(200, std::byte{0})};
  for (auto s : w.fetch(c, sk, miss, mout)) ASSERT_EQ(s, KeyStatus::Miss);
  for (auto s : w.put(c, sk, ch, data)) ASSERT_EQ(s, KeyStatus::Skipped);
  std::vector<KeyStatus> pst;
  c.core->probe(sk, 0, ch.refs, w.clock.now() + seconds(5), [&](Ticket, std::span<const KeyStatus> s) { pst.assign(s.begin(), s.end()); });
  ASSERT_EQ(pst.size(), 3u);

  const std::string t = c.core->metrics_text();
  auto v = [&](const char* s) { return series(t, s); };
  EXPECT_EQ(v("miracache_client_put_ops_total{result=\"committed\"}"), 3);
  EXPECT_EQ(v("miracache_client_put_ops_total{result=\"skipped\"}"), 3);
  EXPECT_EQ(v("miracache_client_put_ops_total{result=\"error\"}"), 0);
  EXPECT_EQ(v("miracache_client_put_bytes_total{result=\"committed\"}"), static_cast<double>(total));
  EXPECT_EQ(v("miracache_client_fetch_ops_total{result=\"hit\"}"), 3);
  EXPECT_EQ(v("miracache_client_fetch_ops_total{result=\"miss\"}"), 2);
  EXPECT_EQ(v("miracache_client_fetch_ops_total{result=\"error\"}"), 0);
  EXPECT_EQ(v("miracache_client_fetch_bytes_total{result=\"hit\"}"), static_cast<double>(total));
  EXPECT_EQ(v("miracache_client_fetch_bytes_total{result=\"miss\"}"), 300);
  EXPECT_EQ(v("miracache_client_lookup_keys_total{result=\"hit\"}"), 3);
  EXPECT_EQ(v("miracache_client_lookup_keys_total{result=\"miss\"}"), 0);
  EXPECT_EQ(v("miracache_client_crypto_bytes_total{dir=\"encrypt\"}"), static_cast<double>(total));
  EXPECT_EQ(v("miracache_client_crypto_bytes_total{dir=\"decrypt\"}"), static_cast<double>(total));
  EXPECT_EQ(v("miracache_client_aead_fail_total"), 0);
  EXPECT_EQ(v("miracache_client_validate_fail_total{kind=\"seq\"}"), 0);
  EXPECT_EQ(v("miracache_client_validate_fail_total{kind=\"hdr\"}"), 0);
  EXPECT_EQ(v("miracache_client_invalidate_sent_total"), 0);
  EXPECT_EQ(v("miracache_client_inflight{op=\"fetch\"}"), 0);
  EXPECT_EQ(v("miracache_client_inflight{op=\"put\"}"), 0);
  EXPECT_EQ(v("miracache_client_landing_pool_bytes{state=\"used\"}"), 0);
  EXPECT_GT(v("miracache_client_landing_pool_bytes{state=\"free\"}"), 0);
  // One observation per job in the total stage; lease_wait once per fetch job with candidates.
  EXPECT_EQ(v("miracache_client_fetch_seconds_count{stage=\"total\"}"), 2);
  EXPECT_EQ(v("miracache_client_fetch_seconds_count{stage=\"lease_wait\"}"), 2);
  EXPECT_EQ(v("miracache_client_fetch_seconds_count{stage=\"read\"}"), 3);
  EXPECT_EQ(v("miracache_client_fetch_seconds_count{stage=\"decrypt\"}"), 3);
  EXPECT_EQ(v("miracache_client_put_seconds_count{stage=\"total\"}"), 2);
  EXPECT_EQ(v("miracache_client_put_seconds_count{stage=\"encrypt\"}"), 3);
  EXPECT_EQ(v("miracache_client_put_seconds_count{stage=\"write\"}"), 1);
  EXPECT_EQ(v("miracache_client_put_seconds_count{stage=\"commit\"}"), 1);
  for (const char* k : {"retry_exc", "rnr", "flush", "access", "other"})
    EXPECT_EQ(v((std::string("miracache_client_rdma_errors_total{kind=\"") + k + "\"}").c_str()), 0) << k;
  // No label value ever names a scope, key or session.
  EXPECT_EQ(t.find("nokey"), std::string::npos);
  EXPECT_EQ(t.find("scope="), std::string::npos);
}

TEST(ClientMetrics, ConcurrentCountersAreExact) {
  ClientMetrics m;
  constexpr int kThreads = 6, kIters = 20000;
  std::atomic<bool> stop{false};
  std::thread scraper([&] {
    while (!stop.load()) {
      std::string s;
      m.reg.write_prometheus(s);
    }
  });
  std::vector<std::thread> ts;
  for (int i = 0; i < kThreads; ++i)
    ts.emplace_back([&] {
      for (int k = 0; k < kIters; ++k) {
        m.fetch_ops[ClientMetrics::kFHit]->inc();
        m.fetch_bytes[ClientMetrics::kFHit]->inc(3);
        m.inflight[0]->add(1);
        m.inflight[0]->add(-1);
        m.fetch_s[ClientMetrics::kFTotal]->observe_ns(1500);
      }
    });
  for (auto& t : ts) t.join();
  stop = true;
  scraper.join();
  EXPECT_EQ(m.fetch_ops[ClientMetrics::kFHit]->value(), std::uint64_t{kThreads} * kIters);
  EXPECT_EQ(m.fetch_bytes[ClientMetrics::kFHit]->value(), std::uint64_t{kThreads} * kIters * 3);
  EXPECT_EQ(m.inflight[0]->value(), 0);
  EXPECT_EQ(m.fetch_s[ClientMetrics::kFTotal]->count(), std::uint64_t{kThreads} * kIters);
}

}  // namespace
}  // namespace miracache
