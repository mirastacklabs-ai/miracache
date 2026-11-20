// SPDX-License-Identifier: Apache-2.0
// MR manager and put path (A1.4 S4) on SimFabric, including sliced placement and the
// iWARP early WRITE CQE (a CQE is not placement).
#include <array>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "fabric/sim/sim_fabric.h"
#include "store/mr_manager.h"
#include "store/put.h"
#include "util/crc32c.h"

namespace miracache::store {
namespace {

using std::chrono::seconds;
using fabric::Completion;
using fabric::Endpoint;
using fabric::SimOptions;

StoreConfig cfg() {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.put_timeout = seconds(10);
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 1u << 20;
  c.principal_default.idle_ttl = seconds(1000);
  return c;
}

ScopeId sid(int i) {
  ScopeId s{};
  s[0] = static_cast<std::uint8_t>(i);
  s[31] = 0x5c;
  return s;
}
KeyHash kh(int i) {
  KeyHash k{};
  k[0] = static_cast<std::uint8_t>(i);
  k[31] = 0xa1;
  return k;
}
KeyHash parent_of(int i) {
  KeyHash k{};
  if (i != 0) k[0] = static_cast<std::uint8_t>(i), k[31] = 0xa1;
  return k;
}

// Deferred executor: work runs at post (extent bytes are fenced by then), done runs when
// the test or scenario releases it, in random order for the scenario.
class DeferredExecutor final : public Executor {
 public:
  void post(std::function<void()> work, std::function<void()> done) override {
    work();
    q.push_back(std::move(done));
  }
  bool run_one(Random* rng = nullptr) {
    if (q.empty()) return false;
    const std::size_t i = rng ? static_cast<std::size_t>(rng->below(q.size())) : 0;
    auto d = std::move(q[i]);
    q.erase(q.begin() + static_cast<std::ptrdiff_t>(i));
    d();
    return true;
  }
  void run_all() { while (run_one()) {} }
  std::deque<std::function<void()>> q;
};

struct Fx {
  explicit Fx(SimOptions so = {}, std::uint64_t seed = 1, bool auto_register = true)
      : rng(seed), net(clock, rng, {}, so), srv(net.add_node(1)), cli(net.add_node(2)) {
    auto a = Arena::open(cfg());
    EXPECT_TRUE(a);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
    ingest_pd = srv.alloc_pd().value();
    mrs = std::make_unique<MrManager>(srv, *arena, fabric::PdId{}, ingest_pd);
    store->set_readable([this](std::uint32_t seg) { return mrs->readable(seg); });
    puts = std::make_unique<PutPath>(*store, *slab, *mrs, *arena, clock, exec,
                                     [this](const PutDoneResult& r) { notified.push_back(r); });
    fabric::ListenParams lp;
    lp.allow_unauthenticated_for_test = true;
    lp.accept_class = fabric::EpClass::Ingest;
    lp.accept_pd = ingest_pd;
    EXPECT_TRUE(srv.listen([this](Endpoint* e) { accepted.push_back(e); }, lp));
    cbuf.assign(16384, std::byte{0});
    cmr = cli.reg(cbuf, fabric::Access::LocalWrite).value();
    if (auto_register) register_all();
    connect();
  }
  void register_all() { while (mrs->step_registration().value()) {} }
  // New connection; returns the SERVER-side endpoint id (the put's endpoint).
  fabric::EndpointId connect() {
    fabric::ConnParams cp;
    cp.cls = fabric::EpClass::Ingest;
    cep = cli.connect(fabric::Peer{1}, cp).value();
    ep = accepted.back()->id();
    return ep;
  }
  // WRITE payload to the entry's slot. Returns the completion status once delivered.
  Status write(const PutBeginAck& ack, std::size_t entry, const std::vector<std::byte>& data, bool wait = true) {
    const auto& e = ack.entries[entry];
    const auto& m = ack.mr[e.mr_index];
    std::memcpy(cbuf.data(), data.data(), data.size());
    ++tag;
    Status st = cep->post_write({cmr.lkey, cbuf.data(), static_cast<std::uint32_t>(data.size())},
                                {m.rkey, m.addr + e.offset, static_cast<std::uint32_t>(data.size())}, tag);
    if (!st || !wait) return st;
    return wait_tag(tag);
  }
  Status wait_tag(std::uint64_t t) {
    std::array<Completion, 8> out;
    for (;;) {
      std::size_t n = cli.poll(out);
      for (std::size_t i = 0; i < n; ++i)
        if (out[i].tag == t && !out[i].is_recv) return out[i].status;
      if (!net.step()) return Error{ErrorCode::Timeout, "no completion"};
    }
  }
  PutBeginAck begin(PrincipalId p, int scope, std::vector<PutKey> keys) {
    PutBeginReq q;
    q.principal = p;
    q.scope = sid(scope);
    q.keys = std::move(keys);
    return puts->put_begin(ep, q);
  }
  static PutKey key(int k, int parent, std::uint64_t len, std::uint64_t pos = 0) {
    PutKey pk;
    pk.key = kh(k);
    pk.parent = parent_of(parent);
    pk.chain_pos = pos;
    pk.stored_len = len;
    return pk;
  }
  static std::vector<std::byte> payload(std::size_t n, int seed) {
    std::vector<std::byte> v(n);
    for (std::size_t i = 0; i < n; ++i) v[i] = static_cast<std::byte>((i * 31 + static_cast<std::size_t>(seed)) & 0xff);
    return v;
  }
  PutDoneResult commit(PutId id, const std::vector<CommitEntry>& e, fabric::EndpointId from = 0) {
    PutDoneResult res;
    bool called = false;
    puts->put_commit(from ? from : ep, {id, e}, [&](const PutDoneResult& r) { res = r, called = true; });
    exec.run_all();
    EXPECT_TRUE(called);
    return res;
  }
  std::uint64_t allocated() {
    std::uint64_t n = 0;
    for (auto& c : slab->class_stats()) n += c.allocated;
    return n;
  }
  void inv() {
    auto s1 = store->check_invariants();
    ASSERT_TRUE(s1) << s1.error().context;
    auto s2 = slab->check_invariants();
    ASSERT_TRUE(s2) << s2.error().context;
    auto s3 = puts->check_invariants();
    ASSERT_TRUE(s3) << s3.error().context;
  }
  std::uint64_t lookup_hits(PrincipalId p, int scope, std::vector<int> ks) {
    LookupReq q;
    q.principal = p;
    q.scope = sid(scope);
    for (int k : ks) q.keys.push_back(kh(k));
    auto ack = store->lookup(7, q);
    std::uint64_t n = 0;
    for (auto& e : ack.entries) n += e.hit;
    return n;
  }

  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& srv;
  fabric::SimFabric& cli;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
  fabric::PdId ingest_pd;
  std::unique_ptr<MrManager> mrs;
  DeferredExecutor exec;
  std::unique_ptr<PutPath> puts;
  std::vector<PutDoneResult> notified;
  std::vector<Endpoint*> accepted;
  Endpoint* cep = nullptr;
  fabric::EndpointId ep = 0;
  std::vector<std::byte> cbuf;
  fabric::MemRegion cmr;
  std::uint64_t tag = 0;
};

SimOptions sliced(std::uint32_t slice, bool iwarp) {
  SimOptions o;
  o.slice_size = slice;
  o.iwarp_early_write_cqe = iwarp;
  return o;
}

// Puts one block of `len` bytes to completion. Returns the done entry status.
bool put_one(Fx& fx, PrincipalId p, int scope, int k, int parent, std::size_t len) {
  auto ack = fx.begin(p, scope, {Fx::key(k, parent, len)});
  if (ack.status != BeginStatus::Ok || !ack.entries[0].accept) return false;
  auto data = Fx::payload(len, k);
  EXPECT_TRUE(fx.write(ack, 0, data));
  fx.net.run_until_idle();
  auto res = fx.commit(ack.put_id, {{0, crc32c(data), len}});
  return res.status == CommitStatus::Ok && res.e.size() == 1 && res.e[0].status == 0;
}

TEST(MrManager, RegistersStepwiseAndLookupsMissOutsideThePrefix) {
  Fx fx({}, 1, /*auto_register=*/false);
  EXPECT_TRUE(fx.store->ensure_scope_for_root_put(1, sid(1), fx.clock.now()));
  EXPECT_FALSE(fx.mrs->readable(0));
  EXPECT_TRUE(put_one(fx, 1, 1, 1, 0, 5000));  // putting needs no fetch MRs
  EXPECT_EQ(fx.lookup_hits(1, 1, {1}), 0u);     // nothing registered: MISS
  EXPECT_TRUE(fx.mrs->step_registration().value());
  EXPECT_EQ(fx.mrs->registered_segments(), 1u);
  EXPECT_TRUE(fx.mrs->readable(0) == false);    // array MR not there yet
  EXPECT_EQ(fx.lookup_hits(1, 1, {1}), 0u);
  EXPECT_TRUE(fx.mrs->step_registration().value());
  EXPECT_FALSE(fx.mrs->readable(1) && !fx.mrs->array_registered());
  EXPECT_EQ(fx.mrs->registered_segments(), 2u);
  EXPECT_FALSE(fx.mrs->registration_complete());
  EXPECT_EQ(fx.lookup_hits(1, 1, {1}), 0u);
  EXPECT_TRUE(fx.mrs->step_registration().value());
  EXPECT_TRUE(fx.mrs->registration_complete());
  EXPECT_FALSE(fx.mrs->step_registration().value());
  EXPECT_EQ(fx.lookup_hits(1, 1, {1}), 1u);
  EXPECT_TRUE(fx.mrs->check_invariants());
  fx.inv();
}

TEST(MrManager, PrefixGatesPerSegment) {
  Fx fx({}, 1, false);
  // Fill until a block lands in segment 1, then expose only segment 0 + array is impossible
  // (array last), so check readable() directly on the prefix.
  EXPECT_TRUE(fx.mrs->step_registration().value());
  EXPECT_NE(fx.mrs->segment_mr(0), nullptr);
  EXPECT_EQ(fx.mrs->segment_mr(1), nullptr);
  EXPECT_EQ(fx.mrs->array_mr(), nullptr);
}

TEST(Put, HappyPathSlicedAndEarlyCqe) {
  for (bool iwarp : {false, true}) {
    Fx fx(sliced(1024, iwarp), 3);
    EXPECT_TRUE(put_one(fx, 1, 1, 1, 0, 6000)) << iwarp;
    EXPECT_EQ(fx.lookup_hits(1, 1, {1}), 1u);
    EXPECT_EQ(fx.mrs->live_write_mrs(), 0u);
    fx.inv();
  }
}

TEST(Put, WriteAfterFenceGetsAccessError) {
  Fx fx(sliced(1024, true), 5);
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  auto data = Fx::payload(4096, 1);
  ASSERT_TRUE(fx.write(ack, 0, data));
  fx.net.run_until_idle();
  // Commit; the executor holds the digest, so the put sits in DIGESTING with the MR fenced.
  PutDoneResult res;
  fx.puts->put_commit(fx.ep, {ack.put_id, {{0, crc32c(data), 4096}}}, [&](const PutDoneResult& r) { res = r; });
  EXPECT_EQ(fx.mrs->live_write_mrs(), 0u);
  fx.inv();
  auto evil = Fx::payload(4096, 99);
  Status st = fx.write(ack, 0, evil);
  EXPECT_FALSE(st);
  EXPECT_EQ(st.error().code, ErrorCode::AccessDenied);
  fx.exec.run_all();
  ASSERT_EQ(res.e.size(), 1u);
  EXPECT_EQ(res.e[0].status, static_cast<std::uint8_t>(proto::DoneStatus::Committed));
  fx.inv();  // CommittedIntact: the late write never landed
}

TEST(Put, CrcMismatchAbortsWithDigestAndFrees) {
  Fx fx;
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 5000)});
  auto data = Fx::payload(5000, 1);
  ASSERT_TRUE(fx.write(ack, 0, data));
  fx.net.run_until_idle();
  auto res = fx.commit(ack.put_id, {{0, crc32c(data) ^ 1u, 5000}});
  ASSERT_EQ(res.e.size(), 1u);
  EXPECT_EQ(res.e[0].status, static_cast<std::uint8_t>(proto::DoneStatus::Aborted));
  EXPECT_EQ(res.e[0].reason, static_cast<std::uint8_t>(proto::DoneReason::Digest));
  EXPECT_EQ(fx.allocated(), 0u);
  EXPECT_EQ(fx.lookup_hits(1, 1, {1}), 0u);
  fx.inv();
}

TEST(Put, RePutIsSkip) {
  Fx fx;
  EXPECT_TRUE(put_one(fx, 1, 1, 1, 0, 4096));
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 4096), Fx::key(2, 1, 4096, 1)});
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  EXPECT_FALSE(ack.entries[0].accept);
  EXPECT_TRUE(ack.entries[1].accept);
  auto again = fx.begin(1, 1, {Fx::key(2, 1, 4096, 1)});  // in flight: SKIP too
  EXPECT_FALSE(again.entries[0].accept);
  EXPECT_EQ(again.put_id, 0u);
  fx.puts->put_cancel(fx.ep, ack.put_id, [](const PutDoneResult&) {});
  auto all_skip = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
  EXPECT_EQ(all_skip.status, BeginStatus::Ok);
  EXPECT_EQ(all_skip.put_id, 0u);
  EXPECT_TRUE(all_skip.mr.empty());
  fx.inv();
}

TEST(Put, NonRootOnUnknownScopeRefusedRetryZero) {
  Fx fx;
  auto ack = fx.begin(1, 9, {Fx::key(2, 1, 4096, 1)});
  EXPECT_EQ(ack.status, BeginStatus::Refused);
  EXPECT_EQ(ack.retry_after_ms, 0u);
  EXPECT_FALSE(fx.store->has_scope(1, sid(9)));
  EXPECT_EQ(fx.allocated(), 0u);
  // A root put opens the scope; another principal's same scope id stays unknown.
  auto root = fx.begin(1, 9, {Fx::key(1, 0, 4096)});
  EXPECT_EQ(root.status, BeginStatus::Ok);
  EXPECT_TRUE(fx.store->has_scope(1, sid(9)));
  auto other = fx.begin(2, 9, {Fx::key(3, 1, 4096, 1)});
  EXPECT_EQ(other.status, BeginStatus::Refused);
  EXPECT_EQ(other.retry_after_ms, 0u);
  fx.inv();
}

TEST(Put, CommitLengthMismatchIsMalformedAndPutSurvives) {
  Fx fx;
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 5000)});
  auto data = Fx::payload(5000, 1);
  ASSERT_TRUE(fx.write(ack, 0, data));
  fx.net.run_until_idle();
  auto bad = fx.commit(ack.put_id, {{0, crc32c(data), 4999}});
  EXPECT_EQ(bad.status, CommitStatus::Malformed);
  EXPECT_EQ(fx.puts->n_puts(), 1u);
  auto wrong_idx = fx.commit(ack.put_id, {{1, crc32c(data), 5000}});
  EXPECT_EQ(wrong_idx.status, CommitStatus::Malformed);
  auto ok = fx.commit(ack.put_id, {{0, crc32c(data), 5000}});
  EXPECT_EQ(ok.status, CommitStatus::Ok);
  EXPECT_EQ(ok.e[0].status, static_cast<std::uint8_t>(proto::DoneStatus::Committed));
  fx.inv();
}

TEST(Put, CommitFromAnotherEndpointRejected) {
  Fx fx;
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
  auto data = Fx::payload(4096, 1);
  ASSERT_TRUE(fx.write(ack, 0, data));
  fx.net.run_until_idle();
  const auto first = fx.ep;
  const auto second = fx.connect();
  ASSERT_NE(first, second);
  auto res = fx.commit(ack.put_id, {{0, crc32c(data), 4096}}, second);
  EXPECT_EQ(res.status, CommitStatus::UnknownPut);
  fx.puts->put_cancel(second, ack.put_id, [&](const PutDoneResult& r) { res = r; });
  EXPECT_EQ(res.status, CommitStatus::UnknownPut);
  EXPECT_EQ(fx.puts->n_puts(), 1u);
  EXPECT_EQ(fx.mrs->live_write_mrs(), 1u);
  auto ok = fx.commit(ack.put_id, {{0, crc32c(data), 4096}}, first);
  EXPECT_EQ(ok.e[0].status, static_cast<std::uint8_t>(proto::DoneStatus::Committed));
  fx.inv();
}

TEST(Put, TimeoutAbortsAndFrees) {
  Fx fx;
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 4096), Fx::key(2, 1, 8192, 1)});
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  EXPECT_GT(fx.allocated(), 0u);
  fx.clock.advance_by(seconds(5));
  fx.puts->tick();
  EXPECT_EQ(fx.puts->n_puts(), 1u);
  fx.clock.advance_by(seconds(6));
  fx.puts->tick();
  EXPECT_EQ(fx.puts->n_puts(), 0u);
  EXPECT_EQ(fx.allocated(), 0u);
  EXPECT_EQ(fx.mrs->live_write_mrs(), 0u);
  ASSERT_EQ(fx.notified.size(), 1u);
  EXPECT_EQ(fx.notified[0].e.size(), 2u);
  EXPECT_EQ(fx.notified[0].e[0].reason, static_cast<std::uint8_t>(proto::DoneReason::Timeout));
  // The slot is free again: the same key can be put.
  EXPECT_TRUE(put_one(fx, 1, 1, 1, 0, 4096));
  fx.inv();
}

TEST(Put, EndpointDownAbortsItsPutsIncludingDigesting) {
  Fx fx;
  auto a1 = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
  auto a2 = fx.begin(1, 1, {Fx::key(2, 1, 4096, 1)});
  auto data = Fx::payload(4096, 2);
  ASSERT_TRUE(fx.write(a2, 0, data));
  fx.net.run_until_idle();
  bool called = false;
  fx.puts->put_commit(fx.ep, {a2.put_id, {{0, crc32c(data), 4096}}}, [&](const PutDoneResult&) { called = true; });
  fx.puts->on_endpoint_down(fx.ep);
  EXPECT_EQ(fx.mrs->live_write_mrs(), 0u);
  fx.exec.run_all();
  EXPECT_FALSE(called);
  EXPECT_EQ(fx.puts->n_puts(), 0u);
  EXPECT_EQ(fx.allocated(), 0u);
  EXPECT_EQ(fx.lookup_hits(1, 1, {1, 2}), 0u);
  (void)a1;
  fx.inv();
}

TEST(Put, CancelFrees) {
  Fx fx;
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
  PutDoneResult res;
  fx.puts->put_cancel(fx.ep, ack.put_id, [&](const PutDoneResult& r) { res = r; });
  EXPECT_EQ(res.e[0].reason, static_cast<std::uint8_t>(proto::DoneReason::Cancel));
  EXPECT_EQ(fx.allocated(), 0u);
  EXPECT_EQ(fx.mrs->live_write_mrs(), 0u);
  fx.inv();
}

// Seeded random scenario: begins, partial/corrupt writes, commits (maybe wrong), cancels,
// time, endpoint churn and delayed digests; every invariant after every step.
TEST(Put, RandomScenarioKeepsInvariants) {
  for (std::uint64_t seed = 1; seed <= 12; ++seed) {
    Fx fx(sliced(512, seed % 2 == 0), seed);
    Random& r = fx.rng;
    struct Live {
      PutBeginAck ack;
      std::vector<std::vector<std::byte>> data;
      std::vector<std::size_t> key_of;  // entry index per accepted ext
      fabric::EndpointId ep;
      bool committed = false;
    };
    std::vector<Live> live;
    int next_key = 1;
    for (int step = 0; step < 400; ++step) {
      switch (r.below(8)) {
        case 0: {  // begin
          const int scope = 1 + static_cast<int>(r.below(3));
          const std::size_t nk = 1 + r.below(3);
          std::vector<PutKey> ks;
          for (std::size_t i = 0; i < nk; ++i) {
            const int k = r.chance(0.2) && next_key > 1 ? 1 + static_cast<int>(r.below(static_cast<std::uint64_t>(next_key - 1))) : next_key++;
            ks.push_back(Fx::key(k, i == 0 && r.chance(0.7) ? 0 : 1, 1 + r.below(9000), i));
          }
          auto ack = fx.begin(1 + r.below(2), scope, ks);
          if (ack.status == BeginStatus::Ok && ack.put_id != 0) {
            Live l;
            l.ack = ack;
            l.ep = fx.ep;
            for (std::size_t i = 0; i < ks.size(); ++i) {
              l.data.push_back(Fx::payload(ks[i].stored_len, step + static_cast<int>(i)));
              l.key_of.push_back(i);
            }
            live.push_back(std::move(l));
          }
          break;
        }
        case 1:
        case 2: {  // write
          if (live.empty()) break;
          auto& l = live[r.below(live.size())];
          const std::size_t i = r.below(l.ack.entries.size());
          if (l.ack.entries[i].accept) {
            auto d = l.data[i];
            if (r.chance(0.1)) d[r.below(d.size())] ^= std::byte{1};
            (void)fx.write(l.ack, i, d, /*wait=*/false);
          }
          break;
        }
        case 3: {  // commit (sometimes with a wrong CRC), digest completes later
          if (live.empty()) break;
          auto& l = live[r.below(live.size())];
          std::vector<CommitEntry> es;
          for (std::size_t i = 0; i < l.ack.entries.size(); ++i)
            if (l.ack.entries[i].accept) {
              auto sz = l.data[i].size();
              es.push_back({static_cast<std::uint16_t>(i), crc32c(l.data[i]) ^ (r.chance(0.1) ? 1u : 0u), sz});
            }
          fx.puts->put_commit(l.ep, {l.ack.put_id, es}, [](const PutDoneResult&) {});
          break;
        }
        case 4: {  // cancel
          if (live.empty()) break;
          auto& l = live[r.below(live.size())];
          fx.puts->put_cancel(l.ep, l.ack.put_id, [](const PutDoneResult&) {});
          break;
        }
        case 5:
          fx.clock.advance_by(std::chrono::milliseconds(r.below(4000)));
          fx.puts->tick();
          fx.store->tick();
          break;
        case 6:
          if (r.chance(0.1)) {
            fx.puts->on_endpoint_down(fx.ep);
            fx.connect();
          } else {
            fx.exec.run_one(&r);
          }
          break;
        default:
          fx.net.step();
          break;
      }
      fx.inv();
      if (::testing::Test::HasFatalFailure()) return;
    }
    fx.net.run_until_idle();
    fx.exec.run_all();
    fx.clock.advance_by(seconds(60));
    fx.puts->tick();
    EXPECT_EQ(fx.puts->n_puts(), 0u) << seed;
    EXPECT_EQ(fx.mrs->live_write_mrs(), 0u) << seed;
    fx.inv();
  }
}

// ---- S5: doomed puts and the mixed reclaim scenario ----

TEST(PutDoomed, DroppedScopeKeepsMrUntilCommitThenAbortedDoomed) {
  Fx fx;
  ASSERT_TRUE(put_one(fx, 1, 1, 1, 0, 4096));
  auto ack = fx.begin(1, 1, {Fx::key(2, 1, 4096, 1)});
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  ASSERT_TRUE(ack.entries[0].accept);
  EXPECT_EQ(fx.store->drop_scope(1, sid(1)), 1u);
  EXPECT_EQ(fx.mrs->live_write_mrs(), 1u);  // the write MR survives the drop
  auto data = Fx::payload(4096, 2);
  EXPECT_TRUE(fx.write(ack, 0, data));  // the client can still write
  fx.net.run_until_idle();
  fx.inv();
  auto res = fx.commit(ack.put_id, {{0, crc32c(data), 4096}});
  ASSERT_EQ(res.e.size(), 1u);
  EXPECT_EQ(res.e[0].status, static_cast<std::uint8_t>(proto::DoneStatus::Aborted));
  EXPECT_EQ(res.e[0].reason, static_cast<std::uint8_t>(proto::DoneReason::Doomed));
  EXPECT_EQ(fx.mrs->live_write_mrs(), 0u);
  EXPECT_EQ(fx.allocated(), 0u);
  fx.inv();
}

TEST(PutDoomed, RecreatedScopeDoomsOlderPut) {
  Fx fx;
  ASSERT_TRUE(put_one(fx, 1, 1, 1, 0, 4096));
  auto ack = fx.begin(1, 1, {Fx::key(2, 1, 4096, 1)});
  ASSERT_TRUE(ack.entries[0].accept);
  fx.store->drop_scope(1, sid(1));
  ASSERT_TRUE(put_one(fx, 1, 1, 3, 0, 4096));  // same scope id, new incarnation
  auto data = Fx::payload(4096, 2);
  EXPECT_TRUE(fx.write(ack, 0, data));
  fx.net.run_until_idle();
  auto res = fx.commit(ack.put_id, {{0, crc32c(data), 4096}});
  EXPECT_EQ(res.e[0].reason, static_cast<std::uint8_t>(proto::DoneReason::Doomed));
  fx.inv();
}

TEST(PutDoomed, InvalidatedParentDoomsChildPut) {
  Fx fx;
  ASSERT_TRUE(put_one(fx, 1, 1, 1, 0, 4096));
  auto ack = fx.begin(1, 1, {Fx::key(2, 1, 4096, 1)});
  ASSERT_TRUE(ack.entries[0].accept);
  LookupReq q;
  q.principal = 1;
  q.scope = sid(1);
  q.keys = {kh(1)};
  auto la = fx.store->lookup(7, q);
  ASSERT_TRUE(la.entries[0].hit);
  ASSERT_TRUE(fx.store->invalidate(1, sid(1), kh(1), la.entries[0].gen));
  fx.store->on_session_end(7);
  auto data = Fx::payload(4096, 2);
  EXPECT_TRUE(fx.write(ack, 0, data));
  fx.net.run_until_idle();
  auto res = fx.commit(ack.put_id, {{0, crc32c(data), 4096}});
  EXPECT_EQ(res.e[0].reason, static_cast<std::uint8_t>(proto::DoneReason::Doomed));
  EXPECT_EQ(fx.lookup_hits(1, 1, {1, 2}), 0u);
  fx.inv();
}

// Puts, lookups, invalidates, drops, evictions, session ends and lease expiry; every
// invariant (including NoOrphanTail and zombie accounting) after every step.
TEST(PutReclaim, RandomScenarioKeepsInvariants) {
  for (std::uint64_t seed = 1; seed <= 12; ++seed) {
    Fx fx({}, seed);
    Random& r = fx.rng;
    int next_key = 1;
    std::vector<std::pair<SessionId, LeaseId>> leases;
    for (int step = 0; step < 500; ++step) {
      const PrincipalId p = 1 + r.below(2);
      const int scope = 1 + static_cast<int>(r.below(3));
      switch (r.below(10)) {
        case 0:
        case 1:
        case 2: {  // put a block (root or child of a committed key)
          int parent = 0;
          for (int t = 0; t < 4 && next_key > 1; ++t) {
            const int c = 1 + static_cast<int>(r.below(static_cast<std::uint64_t>(next_key - 1)));
            if (fx.store->has_key(p, sid(scope), kh(c))) {
              parent = c;
              break;
            }
          }
          put_one(fx, p, scope, next_key++, parent, 1 + r.below(9000));
          break;
        }
        case 3: {  // lookup
          LookupReq q;
          q.principal = p;
          q.scope = sid(scope);
          for (int i = 0; i < 4 && next_key > 1; ++i)
            q.keys.push_back(kh(1 + static_cast<int>(r.below(static_cast<std::uint64_t>(next_key - 1)))));
          const SessionId sess = 1 + r.below(3);
          auto ack = fx.store->lookup(sess, q);
          if (ack.lease) leases.push_back({sess, ack.lease});
          break;
        }
        case 4: {  // invalidate with the right or a wrong generation
          if (next_key == 1) break;
          const int k = 1 + static_cast<int>(r.below(static_cast<std::uint64_t>(next_key - 1)));
          LookupReq q;
          q.principal = p;
          q.scope = sid(scope);
          q.keys = {kh(k)};
          auto la = fx.store->lookup(9, q);
          std::uint64_t gen = la.entries[0].hit ? la.entries[0].gen : 1;
          if (la.lease) (void)fx.store->release(9, la.lease);
          if (r.chance(0.2)) gen += 1;
          fx.clock.advance_by(std::chrono::milliseconds(150));
          (void)fx.store->invalidate(p, sid(scope), kh(k), gen);
          break;
        }
        case 5:
          if (r.chance(0.5)) fx.store->drop_scope(p, sid(scope));
          else fx.store->drop_principal(p, fx.clock.now() - seconds(r.below(100)));
          break;
        case 6:
          fx.store->evict(1 + r.below(20000));
          break;
        case 7:
          if (!leases.empty()) {
            const auto [s, l] = leases[r.below(leases.size())];
            if (r.chance(0.5)) (void)fx.store->release(s, l);
            else (void)fx.store->renew(s, l);
          } else {
            fx.store->on_session_end(1 + r.below(3));
          }
          break;
        case 8:
          if (r.chance(0.2)) fx.store->on_session_end(1 + r.below(3));
          fx.clock.advance_by(seconds(r.below(200)));
          fx.puts->tick();
          fx.store->tick();
          break;
        default:
          fx.net.step();
          break;
      }
      fx.inv();
      if (::testing::Test::HasFatalFailure()) return;
    }
    for (SessionId s = 1; s <= 3; ++s) fx.store->on_session_end(s);
    fx.clock.advance_by(seconds(100000));
    fx.puts->tick();
    fx.store->tick();
    EXPECT_EQ(fx.store->n_zombies(), 0u) << seed;
    EXPECT_EQ(fx.store->n_leases(), 0u) << seed;
    EXPECT_EQ(fx.allocated(), 0u) << seed;
    fx.inv();
  }
}

// ---- fix round 1 (Q01, Q02, Q05-Q08, Q16, Q19) --------------------------------------------

// Puts a block without writing it: the arena starts zeroed, so the zero-payload CRC matches.
bool put_zero(Fx& fx, PrincipalId p, int scope, int k, std::size_t len) {
  auto ack = fx.begin(p, scope, {Fx::key(k, 0, len)});
  if (ack.status != BeginStatus::Ok || !ack.entries[0].accept) return false;
  auto res = fx.commit(ack.put_id, {{0, crc32c(std::vector<std::byte>(len)), len}});
  return res.status == CommitStatus::Ok && res.e.size() == 1 && res.e[0].status == 0;
}

TEST(PutFix, HugeOrOversizedStoredLenIsMalformedNotRetryable) {  // Q01, Q06
  Fx fx;
  const std::uint64_t run = cfg().run_bytes;
  for (std::uint64_t huge : {~std::uint64_t{0}, ~std::uint64_t{0} - 4095, run + 1}) {
    auto ack = fx.begin(1, 1, {Fx::key(1, 0, huge)});
    EXPECT_EQ(ack.status, BeginStatus::Malformed) << huge;
    EXPECT_EQ(ack.put_id, 0u);
  }
  EXPECT_EQ(fx.puts->n_puts(), 0u);
  EXPECT_EQ(fx.store->inflight_bytes(1), 0u);
  EXPECT_TRUE(put_zero(fx, 1, 1, 1, run));  // exactly one run is fine
  fx.inv();
}

// s12 (tpu-sync cross-check C6): a stored_len below the 64 B extent header can never be a valid block, and the restart
// scan discards such a header as corrupt: refused at PUT_BEGIN. 64 passes the door (the node cannot see the extent's own
// minimum at PUT_BEGIN; a too-short extent fails AEAD at the client's first read and is invalidated).
TEST(PutFix, StoredLenBelowTheExtentHeaderIsMalformed) {
  Fx fx;
  for (std::uint64_t tiny : {std::uint64_t{0}, std::uint64_t{1}, std::uint64_t{63}}) {
    auto ack = fx.begin(1, 1, {Fx::key(1, 0, tiny)});
    EXPECT_EQ(ack.status, BeginStatus::Malformed) << tiny;
    EXPECT_EQ(ack.put_id, 0u);
  }
  EXPECT_EQ(fx.puts->n_puts(), 0u);
  EXPECT_TRUE(put_zero(fx, 1, 1, 1, 64));
  fx.inv();
}

TEST(PutFix, TruncatedSixteenByteParentResolves) {  // Q02
  Fx fx;
  PutKey a = Fx::key(1, 0, 4096), b = Fx::key(2, 0, 4096, 1);
  b.parent = {};
  std::copy(a.key.begin(), a.key.begin() + 16, b.parent.begin());  // wire form: 16 bytes, zero padded
  ASSERT_NE(b.parent, a.key);
  auto ack = fx.begin(1, 1, {a, b});
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  const auto d1 = Fx::payload(4096, 1), d2 = Fx::payload(4096, 2);
  ASSERT_TRUE(fx.write(ack, 0, d1));
  ASSERT_TRUE(fx.write(ack, 1, d2));
  fx.net.run_until_idle();
  auto res = fx.commit(ack.put_id, {{0, crc32c(d1), 4096}, {1, crc32c(d2), 4096}});
  ASSERT_EQ(res.e.size(), 2u);
  EXPECT_EQ(res.e[0].status, static_cast<std::uint8_t>(proto::DoneStatus::Committed));
  EXPECT_EQ(res.e[1].status, static_cast<std::uint8_t>(proto::DoneStatus::Committed));
  fx.inv();
}

TEST(PutFix, SkippedKeyStaysInflightWhenAnotherPutEnds) {  // Q05
  for (int how = 0; how < 3; ++how) {  // cancel, commit, endpoint down
    Fx fx;
    const auto ep_a = fx.ep;
    auto a = fx.begin(1, 1, {Fx::key(1, 0, 4096)});  // put A holds K
    ASSERT_TRUE(a.entries[0].accept);
    const auto ep_b = how == 2 ? fx.connect() : fx.ep;
    auto b = fx.begin(1, 1, {Fx::key(1, 0, 4096), Fx::key(2, 1, 4096, 1)});
    ASSERT_FALSE(b.entries[0].accept);
    ASSERT_TRUE(b.entries[1].accept);
    if (how == 0) {
      fx.puts->put_cancel(ep_b, b.put_id, [](const PutDoneResult&) {});
    } else if (how == 1) {
      const auto d = Fx::payload(4096, 2);
      ASSERT_TRUE(fx.write(b, 1, d));
      fx.net.run_until_idle();
      fx.commit(b.put_id, {{1, crc32c(d), 4096}});
    } else {
      fx.puts->on_endpoint_down(ep_b);
    }
    auto c = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
    EXPECT_FALSE(c.entries[0].accept) << "how " << how;  // A still owns K
    EXPECT_EQ(c.put_id, 0u);
    fx.puts->put_cancel(ep_a, a.put_id, [](const PutDoneResult&) {});
    auto d2 = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
    EXPECT_TRUE(d2.entries[0].accept) << "how " << how;  // free once A ended
    fx.inv();
  }
}

TEST(PutFix, FullArenaEvictsCommittedUnleasedBlocksAndRetriesOnce) {  // Q07
  Fx fx;
  const std::size_t run = cfg().run_bytes;
  for (int p = 1; p <= 80; ++p) EXPECT_TRUE(put_zero(fx, p, 1, 1, run)) << "principal " << p;
  EXPECT_LE(fx.allocated(), 2u * 15u);  // bounded by the arena: older blocks were evicted
  fx.inv();
}

TEST(PutFix, InflightQuotaPerPrincipalAndPerEndpoint) {  // Q08
  Fx fx;
  const std::size_t run = cfg().run_bytes;  // principal max_bytes = 1 MiB = 4 runs
  for (int i = 1; i <= 4; ++i) ASSERT_EQ(fx.begin(1, 1, {Fx::key(i, 0, run)}).status, BeginStatus::Ok) << i;
  auto over = fx.begin(1, 1, {Fx::key(5, 0, run)});
  EXPECT_EQ(over.status, BeginStatus::Refused);
  EXPECT_GT(over.retry_after_ms, 0u);
  EXPECT_EQ(fx.store->inflight_bytes(1), 4 * run);
  auto other = fx.begin(2, 1, {Fx::key(1, 0, 4096)});  // another principal is unaffected
  EXPECT_EQ(other.status, BeginStatus::Ok);
  fx.puts->put_cancel(fx.ep, other.put_id, [](const PutDoneResult&) {});
  fx.clock.advance_by(seconds(11));  // timeout releases the quota
  fx.puts->tick();
  EXPECT_EQ(fx.store->inflight_bytes(1), 0u);
  // Commit converts the reservation into committed bytes.
  auto a = fx.begin(1, 2, {Fx::key(1, 0, 4096)});
  ASSERT_EQ(a.status, BeginStatus::Ok);
  const auto d = Fx::payload(4096, 1);
  ASSERT_TRUE(fx.write(a, 0, d));
  fx.net.run_until_idle();
  EXPECT_EQ(fx.store->inflight_bytes(1), 4096u);
  fx.commit(a.put_id, {{0, crc32c(d), 4096}});
  EXPECT_EQ(fx.store->inflight_bytes(1), 0u);
  EXPECT_EQ(fx.store->bytes_used(1), 4096u);
  fx.inv();

  // Per-endpoint cap on concurrent puts.
  Fx fe;
  const auto cap = cfg().max_puts_per_endpoint;
  for (std::uint32_t i = 1; i <= cap; ++i)
    ASSERT_EQ(fe.begin(1 + i % 7, 1, {Fx::key(static_cast<int>(i), 0, 4096)}).status, BeginStatus::Ok) << i;
  EXPECT_EQ(fe.begin(1, 2, {Fx::key(200, 0, 4096)}).status, BeginStatus::Refused);
  EXPECT_EQ(fe.puts->n_puts(), cap);
  fe.inv();
}

TEST(PutFix, HopelessReservationRefusedWithoutEvicting) {  // T01 (review r3 scenario, scaled 16 MiB -> 1 MiB)
  Fx fx;
  const std::size_t blk = 64u << 10;
  for (int k = 1; k <= 6; ++k) ASSERT_TRUE(put_zero(fx, 1, 1, k, blk)) << k;  // 384 KiB committed
  for (int k = 11; k <= 20; ++k) ASSERT_EQ(fx.begin(1, 1, {Fx::key(k, 0, blk)}).status, BeginStatus::Ok) << k;  // 640 KiB in flight
  ASSERT_EQ(fx.store->bytes_used(1), 6 * blk);
  ASSERT_EQ(fx.store->inflight_bytes(1), 10 * blk);
  // 512 KiB can never fit next to 640 KiB that cannot be reclaimed: refuse, evict nothing.
  auto big = fx.begin(1, 1, {Fx::key(30, 0, 256u << 10), Fx::key(31, 0, 256u << 10)});
  EXPECT_EQ(big.status, BeginStatus::Refused);
  EXPECT_EQ(fx.store->bytes_used(1), 6 * blk) << "committed blocks were evicted for a put that was refused anyway";
  EXPECT_EQ(fx.store->inflight_bytes(1), 10 * blk);
  // A put that does fit by evicting still works (256 KiB needs 128 KiB of the committed leaves).
  EXPECT_EQ(fx.begin(1, 1, {Fx::key(32, 0, 256u << 10)}).status, BeginStatus::Ok);
  EXPECT_LT(fx.store->bytes_used(1), 6 * blk);
  fx.inv();
}

TEST(PutFix, LeasedBytesKeptIncrementally) {  // S01: T01 refusal counts leased blocks without scanning all keys
  Fx fx;
  const std::size_t len = 128u << 10;
  for (int k = 1; k <= 8; ++k) ASSERT_TRUE(put_zero(fx, 1, 1, k, len)) << k;  // 1 MiB: the cap
  ASSERT_EQ(fx.store->bytes_used(1), 8 * len);
  EXPECT_EQ(fx.lookup_hits(1, 1, {1, 2, 3, 4, 5}), 5u);  // 640 KiB leased (lease stays: ttl not reached)
  fx.inv();                                                // check_invariants recomputes leased_bytes
  // 512 KiB needs 128 KiB of the unleased 384 KiB... 1 MiB cap - 640 KiB leased = 384 KiB < 512 KiB: refuse, evict nothing.
  auto big = fx.begin(1, 1, {Fx::key(30, 0, 256u << 10), Fx::key(31, 0, 256u << 10)});
  EXPECT_EQ(big.status, BeginStatus::Refused);
  EXPECT_EQ(fx.store->bytes_used(1), 8 * len) << "unleased blocks were evicted for a put that was refused anyway";
  // Something that fits by evicting unleased leaves works.
  EXPECT_EQ(fx.begin(1, 1, {Fx::key(32, 0, 128u << 10)}).status, BeginStatus::Ok);
  fx.inv();
}

TEST(PutFix, ForeignEndpointCannotProbePutIds) {  // Q16
  Fx fx;
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
  const auto second = fx.connect();
  PutDoneResult foreign, unknown;
  fx.puts->put_cancel(second, ack.put_id, [&](const PutDoneResult& r) { foreign = r; });
  fx.puts->put_cancel(second, ack.put_id + 1000, [&](const PutDoneResult& r) { unknown = r; });
  EXPECT_EQ(foreign.status, unknown.status);
  EXPECT_EQ(foreign.status, CommitStatus::UnknownPut);
  EXPECT_EQ(fx.puts->n_puts(), 1u);
}

TEST(PutFix, TimeoutNotificationCarriesEndpoint) {  // Q19
  Fx fx;
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, 4096)});
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  fx.clock.advance_by(seconds(11));
  fx.puts->tick();
  ASSERT_EQ(fx.notified.size(), 1u);
  EXPECT_EQ(fx.notified[0].ep, fx.ep);
  EXPECT_EQ(fx.notified[0].put_id, ack.put_id);
}

// Fills the arena with 128 KiB blocks (2 per run), one principal per 8 blocks (quota 1 MiB), and
// leases every even block, so every run holds a leased block and none can be freed whole.
// Returns the number of blocks stored; key i+1 of scope 1 belongs to principal i/8+1.
int fill_runs_each_with_a_leased_block(Fx& fx) {
  const std::size_t len = cfg().run_bytes / 2;
  int n = 0;
  while (n < 200 && (fx.slab->free_runs() > 0 || n % 2 != 0) &&
         put_zero(fx, static_cast<PrincipalId>(n / 8 + 1), 1, n + 1, len))
    ++n;
  for (int i = 0; i < n; i += 2) EXPECT_EQ(fx.lookup_hits(static_cast<PrincipalId>(i / 8 + 1), 1, {i + 1}), 1u);
  return n;
}

TEST(PutEvict, NoFreeableRunEvictsNothingAndRefusesLonger) {  // R05
  Fx fx;
  const int n = fill_runs_each_with_a_leased_block(fx);
  ASSERT_GE(n, 20);
  std::vector<std::uint64_t> before;
  for (PrincipalId p = 1; p <= static_cast<PrincipalId>((n - 1) / 8 + 1); ++p) before.push_back(fx.store->bytes_used(p));
  // A different size class needs a whole run; the unleased 128 KiB blocks sit beside leased ones.
  auto ack = fx.begin(99, 1, {Fx::key(1, 0, 8192)});
  EXPECT_EQ(ack.status, BeginStatus::Refused);
  EXPECT_EQ(ack.retry_after_ms, 1000u);
  for (int i = 0; i < n; ++i)
    EXPECT_TRUE(fx.store->has_key(static_cast<PrincipalId>(i / 8 + 1), sid(1), kh(i + 1))) << "block " << i + 1 << " was evicted";
  for (PrincipalId p = 1; p <= before.size(); ++p) EXPECT_EQ(fx.store->bytes_used(p), before[p - 1]);
  EXPECT_EQ(fx.store->inflight_bytes(99), 0u);
  fx.inv();
}

TEST(PutEvict, EvictionNeverDoomsThePutsOwnChain) {  // R06
  Fx fx;
  const std::size_t run = cfg().run_bytes;
  ASSERT_TRUE(put_zero(fx, 1, 1, 1, run));  // the parent: the LRU-oldest block of the arena
  int p = 2;
  while (p < 200 && fx.slab->free_runs() > 0 && put_zero(fx, static_cast<PrincipalId>(p), 1, 1, run)) ++p;  // fill the arena
  ASSERT_GE(p, 8);
  auto ack = fx.begin(1, 1, {Fx::key(2, 1, run, 1)});  // child of key 1
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  ASSERT_TRUE(ack.entries[0].accept);
  EXPECT_TRUE(fx.store->has_key(1, sid(1), kh(1))) << "the put's resolved parent was evicted";
  // (the client buffer is smaller than a run: commit the zero payload, as put_zero does)
  auto res = fx.commit(ack.put_id, {{0, crc32c(std::vector<std::byte>(run)), run}});
  ASSERT_EQ(res.e.size(), 1u);
  EXPECT_EQ(res.e[0].status, static_cast<std::uint8_t>(proto::DoneStatus::Committed));
  fx.inv();
}

TEST(PutEvict, EvictionNeverTakesASkippedKeyOfTheBatch) {  // R06
  Fx fx;
  const std::size_t run = cfg().run_bytes;
  ASSERT_TRUE(put_zero(fx, 1, 1, 1, run));
  int p = 2;
  while (p < 200 && fx.slab->free_runs() > 0 && put_zero(fx, static_cast<PrincipalId>(p), 1, 1, run)) ++p;
  auto ack = fx.begin(1, 1, {Fx::key(1, 0, run), Fx::key(2, 1, run, 1)});  // key 1 is SKIP
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  EXPECT_FALSE(ack.entries[0].accept);
  EXPECT_TRUE(ack.entries[1].accept);
  EXPECT_TRUE(fx.store->has_key(1, sid(1), kh(1)));
  fx.inv();
}

TEST(PutFix, ZeroPrefixKeyAndKeyEqualToItsParentPrefixAreMalformed) {  // R12
  Fx fx;
  PutKey zero = Fx::key(1, 0, 4096);
  zero.key = {};
  zero.key[31] = 7;  // first 16 bytes all zero
  EXPECT_EQ(fx.begin(1, 1, {zero}).status, BeginStatus::Malformed);
  PutKey self = Fx::key(3, 3, 4096);  // parent prefix == own prefix
  EXPECT_EQ(fx.begin(1, 1, {self}).status, BeginStatus::Malformed);
  PutKey ok = Fx::key(1, 0, 4096), self2 = Fx::key(2, 1, 4096, 1);
  self2.key = ok.key;
  self2.key[20] = 9;  // same 16 B prefix as key 1, different tail
  EXPECT_EQ(fx.begin(1, 1, {ok, self2}).status, BeginStatus::Malformed);
  EXPECT_EQ(fx.puts->n_puts(), 0u);
  EXPECT_EQ(fx.store->inflight_bytes(1), 0u);
  EXPECT_EQ(fx.begin(1, 1, {ok}).status, BeginStatus::Ok);
  fx.inv();
}

TEST(PutQuota, CommittedPlusInflightStaysWithinMaxBytesByEvictingOwnLeaves) {  // R13
  Fx fx;
  const std::size_t run = cfg().run_bytes;  // principal max_bytes = 4 runs
  ASSERT_TRUE(put_zero(fx, 2, 1, 1, run));  // another principal's block must never be touched
  for (int k = 1; k <= 4; ++k) ASSERT_TRUE(put_zero(fx, 1, 1, k, run));
  EXPECT_EQ(fx.store->bytes_used(1), 4 * run);
  auto ack = fx.begin(1, 1, {Fx::key(5, 0, run)});
  ASSERT_EQ(ack.status, BeginStatus::Ok);
  EXPECT_LE(fx.store->bytes_used(1) + fx.store->zombie_bytes(1) + fx.store->inflight_bytes(1), 4 * run);
  EXPECT_FALSE(fx.store->has_key(1, sid(1), kh(1)));  // its own LRU-oldest leaf made room
  EXPECT_TRUE(fx.store->has_key(2, sid(1), kh(1)));
  EXPECT_EQ(fx.store->bytes_used(2), run);
  // Everything left is leased: nothing to evict, so the next reservation is refused.
  for (int k = 2; k <= 4; ++k) ASSERT_EQ(fx.lookup_hits(1, 1, {k}), 1u);
  auto over = fx.begin(1, 1, {Fx::key(6, 0, run)});
  EXPECT_EQ(over.status, BeginStatus::Refused);
  EXPECT_GT(over.retry_after_ms, 0u);
  for (int k = 2; k <= 4; ++k) EXPECT_TRUE(fx.store->has_key(1, sid(1), kh(k)));
  EXPECT_TRUE(fx.store->has_key(2, sid(1), kh(1)));
  fx.inv();
}

}  // namespace
}  // namespace miracache::store
