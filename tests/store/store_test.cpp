// SPDX-License-Identifier: Apache-2.0
// Store tests (A1.4 S3): scopes, index, leases. Seeded loops, no external property library.
#include <map>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include "store/store.h"
#include "util/clock.h"
#include "util/random.h"

namespace miracache::store {
namespace {

using std::chrono::seconds;

StoreConfig cfg() {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.lease_ttl = seconds(30);
  c.lease_max = seconds(100);
  c.reap_grace = Nanos{0};  // these tests model reaping at exactly idle_ttl (S5 adds the grace)
  c.principal_default.max_scopes = 3;
  c.principal_default.max_bytes = 5 * 4096;
  c.principal_default.idle_ttl = seconds(40);
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

struct Fx {
  explicit Fx(const StoreConfig& c = cfg(), std::uint64_t seed = 1) : rng(seed) {
    auto a = Arena::open(c);
    EXPECT_TRUE(a);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
  }
  // Allocates one block and commits it (test-only stand-in for the S4 put path).
  Status put(PrincipalId p, int s, int k, std::uint64_t len = 4096, Extent* out = nullptr) {
    const std::uint64_t lens[] = {len};
    auto r = slab->alloc_batch(lens);
    EXPECT_TRUE(r);
    Status st = store->commit_block(p, sid(s), kh(k), KeyHash{}, (*r)[0], len);
    if (!st) slab->free((*r)[0]);
    if (st && out) *out = (*r)[0];
    return st;
  }
  Status root(PrincipalId p, int s) { return store->ensure_scope_for_root_put(p, sid(s), clock.now()); }
  LookupAck look(PrincipalId p, int s, std::vector<int> ks, SessionId sess = 7) {
    LookupReq q;
    q.principal = p;
    q.scope = sid(s);
    for (int k : ks) q.keys.push_back(kh(k));
    return store->lookup(sess, q);
  }
  void inv() { auto st = store->check_invariants(); ASSERT_TRUE(st) << st.error().context; }
  std::uint64_t allocated() {
    std::uint64_t n = 0;
    for (auto& c : slab->class_stats()) n += c.allocated;
    return n;
  }
  SimClock clock;
  SeededRandom rng;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
};

TEST(StoreScopes, LookupNeverCreatesAndMissesAreIdentical) {
  Fx f;
  auto unknown = f.look(1, 1, {1, 2});
  EXPECT_EQ(unknown.lease, 0u);
  EXPECT_FALSE(f.store->has_scope(1, sid(1)));
  EXPECT_EQ(f.store->n_scopes(1), 0u);

  ASSERT_TRUE(f.root(1, 1));
  ASSERT_TRUE(f.put(1, 1, 1));
  auto own = f.look(1, 1, {1, 2});
  EXPECT_TRUE(own.entries[0].hit);
  EXPECT_FALSE(own.entries[1].hit);
  EXPECT_NE(own.lease, 0u);

  auto foreign = f.look(2, 1, {1, 2});  // principal 2 asks for principal 1's scope
  EXPECT_EQ(foreign.lease, 0u);
  EXPECT_EQ(foreign.entries, unknown.entries);
  EXPECT_EQ(foreign.lease_expiry, unknown.lease_expiry);
  EXPECT_EQ(f.store->n_scopes(2), 0u);  // and it did not create one

  f.clock.advance_by(seconds(41));  // idle TTL passed, tick not yet run
  auto expired = f.look(1, 1, {1, 2});
  EXPECT_EQ(expired.lease, 0u);
  EXPECT_EQ(expired.entries, unknown.entries);
  f.inv();
  f.store->tick();
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  f.inv();
}

TEST(StoreScopes, SameScopeIdSeparatePerPrincipal) {
  Fx f;
  ASSERT_TRUE(f.root(1, 1));
  ASSERT_TRUE(f.root(2, 1));
  ASSERT_TRUE(f.put(1, 1, 5));
  EXPECT_FALSE(f.look(2, 1, {5}).entries[0].hit);
  ASSERT_TRUE(f.put(2, 1, 5));  // same key under the other principal: no clash
  EXPECT_TRUE(f.look(2, 1, {5}).entries[0].hit);
  f.inv();
}

TEST(StoreScopes, CommitNeedsScopeAndKeyIsUnique) {
  Fx f;
  EXPECT_EQ(f.put(1, 1, 1).error().code, ErrorCode::AccessDenied);
  ASSERT_TRUE(f.root(1, 1));
  ASSERT_TRUE(f.put(1, 1, 1));
  EXPECT_EQ(f.put(1, 1, 1).error().code, ErrorCode::Aborted);
  EXPECT_EQ(f.allocated(), 1u);  // the duplicate was freed by the caller
  f.inv();
}

TEST(StoreScopes, CapEvictsOnlyOwnLeastRecentlyUsed) {
  Fx f;  // max_scopes = 3
  for (int s = 1; s <= 3; ++s) {
    ASSERT_TRUE(f.root(1, s));
    ASSERT_TRUE(f.put(1, s, 1));
    f.clock.advance_by(seconds(1));
  }
  ASSERT_TRUE(f.root(2, 1));
  ASSERT_TRUE(f.put(2, 1, 1));
  f.look(1, 1, {1});  // a hit renews scope 1; scope 2 is now the oldest
  f.clock.advance_by(seconds(1));
  ASSERT_TRUE(f.root(1, 4));  // at the cap: evicts scope 2 of principal 1
  EXPECT_FALSE(f.store->has_scope(1, sid(2)));
  EXPECT_TRUE(f.store->has_scope(1, sid(1)));
  EXPECT_TRUE(f.store->has_scope(1, sid(3)));
  EXPECT_TRUE(f.store->has_scope(1, sid(4)));
  EXPECT_TRUE(f.look(2, 1, {1}).entries[0].hit);  // principal 2 untouched
  EXPECT_EQ(f.store->n_scopes(2), 1u);
  ASSERT_TRUE(f.put(1, 4, 1));  // commit renews scope 4 and 3 becomes the oldest
  ASSERT_TRUE(f.root(1, 5));
  EXPECT_FALSE(f.store->has_scope(1, sid(3)));
  EXPECT_TRUE(f.store->has_scope(1, sid(1)));
  f.inv();
}

TEST(StoreScopes, ByteCapEvictsOwnOtherScopes) {
  Fx f;  // max_bytes = 5 blocks
  ASSERT_TRUE(f.root(1, 1));
  ASSERT_TRUE(f.root(1, 2));
  ASSERT_TRUE(f.root(2, 1));
  ASSERT_TRUE(f.put(2, 1, 1));
  for (int k = 0; k < 3; ++k) ASSERT_TRUE(f.put(1, 1, k));
  f.clock.advance_by(seconds(1));
  for (int k = 0; k < 2; ++k) ASSERT_TRUE(f.put(1, 2, k));
  f.clock.advance_by(seconds(1));
  ASSERT_TRUE(f.put(1, 2, 2));  // 6th block: scope 1 (oldest) goes
  EXPECT_FALSE(f.store->has_scope(1, sid(1)));
  EXPECT_TRUE(f.store->has_scope(1, sid(2)));
  EXPECT_TRUE(f.store->has_scope(2, sid(1)));
  EXPECT_EQ(f.store->bytes_used(1), 3 * 4096u);
  f.inv();
}

TEST(StoreLeases, RenewCappedAtMaxAndReleaseDrops) {
  Fx f;
  ASSERT_TRUE(f.root(1, 1));
  ASSERT_TRUE(f.put(1, 1, 1));
  auto a = f.look(1, 1, {1});
  EXPECT_EQ(a.lease_expiry, seconds(30));
  for (int i = 0; i < 3; ++i) {
    f.clock.advance_by(seconds(25));
    ASSERT_TRUE(f.store->renew(7, a.lease));
    f.store->tick();
    f.inv();
  }
  f.clock.advance_by(seconds(20));  // t = 95 s
  auto r = f.store->renew(7, a.lease);
  ASSERT_TRUE(r);
  EXPECT_EQ(*r, seconds(100));  // granted 0 + lease_max
  f.clock.advance_by(seconds(5));
  EXPECT_EQ(f.store->renew(7, a.lease).error().code, ErrorCode::NotFound);  // expired at 100
  EXPECT_EQ(f.store->n_leases(), 0u);

  ASSERT_TRUE(f.root(1, 1));  // the scope idled out meanwhile
  ASSERT_TRUE(f.put(1, 1, 1));
  auto b = f.look(1, 1, {1});
  ASSERT_NE(b.lease, 0u);
  EXPECT_EQ(f.store->renew(8, b.lease).error().code, ErrorCode::NotFound);  // other session
  EXPECT_EQ(f.store->release(8, b.lease).error().code, ErrorCode::NotFound);
  ASSERT_TRUE(f.store->release(7, b.lease));
  EXPECT_EQ(f.store->release(7, b.lease).error().code, ErrorCode::NotFound);
  f.inv();
}

TEST(StoreLeases, OneLeaseCoversAllHitsAndExpiresInTick) {
  Fx f;
  ASSERT_TRUE(f.root(1, 1));
  for (int k = 0; k < 3; ++k) ASSERT_TRUE(f.put(1, 1, k));
  auto a = f.look(1, 1, {0, 1, 9, 2});
  EXPECT_FALSE(a.entries[2].hit);
  EXPECT_EQ(f.store->n_leases(), 1u);
  f.clock.advance_by(seconds(30));
  f.store->tick();
  EXPECT_EQ(f.store->n_leases(), 0u);
  f.inv();
}

TEST(StoreLeases, ZombieLifecycleAcrossEvictionAndExpiry) {
  Fx f;
  ASSERT_TRUE(f.root(1, 1));
  Extent e0, e1;
  ASSERT_TRUE(f.put(1, 1, 0, 4096, &e0));
  ASSERT_TRUE(f.put(1, 1, 1, 4096, &e1));
  auto a = f.look(1, 1, {0});
  const auto& sg = f.arena->state_gen();
  // Cap eviction while leased: scope goes, leased block turns ZOMBIE, other is freed.
  for (int s = 2; s <= 4; ++s) {
    f.clock.advance_by(seconds(1));
    ASSERT_TRUE(f.root(1, s));
  }
  EXPECT_FALSE(f.store->has_scope(1, sid(1)));
  EXPECT_EQ(f.store->n_zombies(), 1u);
  EXPECT_EQ(sg.state(e0.gen_slot), proto::BlockState::Zombie);
  EXPECT_EQ(sg.generation(e0.gen_slot), e0.gen);
  EXPECT_EQ(sg.state(e1.gen_slot), proto::BlockState::Free);
  EXPECT_EQ(f.allocated(), 1u);  // the zombie memory is still held
  f.inv();
  // RENEW on the zombie lease still succeeds; LOOKUP now misses.
  f.clock.advance_by(seconds(10));
  ASSERT_TRUE(f.store->renew(7, a.lease));
  EXPECT_FALSE(f.look(1, 1, {0}).entries[0].hit);
  f.inv();
  // Last release frees it.
  ASSERT_TRUE(f.store->release(7, a.lease));
  EXPECT_EQ(f.store->n_zombies(), 0u);
  EXPECT_EQ(sg.state(e0.gen_slot), proto::BlockState::Free);
  EXPECT_EQ(f.allocated(), 0u);
  f.inv();

  // Idle expiry while leased: tick reaps the scope, lease expiry then frees the block.
  ASSERT_TRUE(f.put(1, 2, 0));
  auto b = f.look(1, 2, {0});
  f.clock.advance_by(seconds(29));
  ASSERT_TRUE(f.store->renew(7, b.lease));  // lease to t+59 s
  f.clock.advance_by(seconds(11));          // scope idle 40 s
  f.store->tick();
  EXPECT_FALSE(f.store->has_scope(1, sid(2)));
  EXPECT_EQ(f.store->n_zombies(), 1u);
  f.inv();
  f.clock.advance_by(seconds(30));
  f.store->tick();
  EXPECT_EQ(f.store->n_zombies(), 0u);
  EXPECT_EQ(f.allocated(), 0u);
  f.inv();
}

TEST(StoreScopes, ReuseOfExpiredScopeStartsEmpty) {
  Fx f;
  ASSERT_TRUE(f.root(1, 1));
  ASSERT_TRUE(f.put(1, 1, 1));
  f.clock.advance_by(seconds(41));
  ASSERT_TRUE(f.root(1, 1));  // expired but not ticked: reaped, fresh scope
  EXPECT_FALSE(f.look(1, 1, {1}).entries[0].hit);
  EXPECT_EQ(f.allocated(), 0u);
  f.inv();
}

// ---- model test against a plain std::map reference -------------------------------------

struct MScope {
  std::int64_t last = 0;
  std::uint64_t seq = 0;
  std::uint64_t bytes = 0;
  std::map<int, LookupEntry> keys;
  std::map<int, std::uint64_t> lens;  // extent bytes per key
};
struct MPrin {
  std::map<int, MScope> scopes;
  std::uint64_t next_seq = 1, bytes = 0;
};
struct MLease {
  SessionId sess;
  std::int64_t granted, expiry;
  std::vector<std::array<std::uint64_t, 3>> held;  // {gen_slot, principal, extent bytes} per hit
};

struct Model {
  explicit Model(const StoreConfig& c) : c(c) {}
  bool expired(const MScope& s, std::int64_t now) const {
    return now - s.last >= c.principal_default.idle_ttl.count();
  }
  void evict(MPrin& p, int s) {
    p.bytes -= p.scopes.at(s).bytes;
    p.scopes.erase(s);
  }
  int oldest(const MPrin& p, int except = -1) const {
    int best = -1;
    for (const auto& [id, s] : p.scopes)
      if (id != except && (best < 0 || s.seq < p.scopes.at(best).seq)) best = id;
    return best;
  }
  void touch(MPrin& p, MScope& s, std::int64_t now) { s.seq = p.next_seq++; s.last = now; }
  void ensure(int pid, int s, std::int64_t now) {
    MPrin& p = prin[pid];
    auto it = p.scopes.find(s);
    if (it != p.scopes.end() && expired(it->second, now)) { evict(p, s); it = p.scopes.end(); }
    if (it == p.scopes.end()) {
      while (p.scopes.size() >= c.principal_default.max_scopes) evict(p, oldest(p));
      MScope n;
      n.seq = p.next_seq++;
      n.last = now;
      p.scopes[s] = n;
    } else {
      touch(p, it->second, now);
    }
  }
  bool commit(int pid, int s, int k, const LookupEntry& e, std::uint64_t len, std::int64_t now, ErrorCode& code) {
    auto pit = prin.find(pid);
    if (pit == prin.end()) { code = ErrorCode::AccessDenied; return false; }
    MPrin& p = pit->second;
    auto it = p.scopes.find(s);
    if (it != p.scopes.end() && expired(it->second, now)) { evict(p, s); it = p.scopes.end(); }
    if (it == p.scopes.end()) { code = ErrorCode::AccessDenied; return false; }
    if (it->second.keys.count(k)) { code = ErrorCode::Aborted; return false; }
    // Zombies (leased blocks no longer mapped) still count; nothing is evicted when even
    // evicting every unleased block of the other scopes cannot make room (Q09, Q17).
    const std::uint64_t zb = zombie_bytes(pid);
    if (p.bytes + zb + len > c.principal_default.max_bytes) {
      std::uint64_t reclaim = 0;
      for (const auto& [id, os] : p.scopes)
        if (id != s)
          for (const auto& [k2, e2] : os.keys)
            if (!is_held(e2.gen_slot)) reclaim += os.lens.at(k2);
      if (p.bytes + zb + len > c.principal_default.max_bytes + reclaim) { code = ErrorCode::ResourceExhausted; return false; }
    }
    while (p.bytes + zombie_bytes(pid) + len > c.principal_default.max_bytes) {
      int v = oldest(p, s);
      if (v < 0) { code = ErrorCode::ResourceExhausted; return false; }
      evict(p, v);
    }
    MScope& sc = it->second;
    sc.keys[k] = e;
    sc.lens[k] = len;
    sc.bytes += len;
    p.bytes += len;
    touch(p, sc, now);
    return true;
  }
  bool is_held(std::uint64_t slot) const {
    for (const auto& [id, l] : leases)
      for (const auto& h : l.held)
        if (h[0] == slot) return true;
    return false;
  }
  std::uint64_t zombie_bytes(int pid) const {
    std::set<std::uint64_t> live, seen;
    auto pit = prin.find(pid);
    if (pit != prin.end())
      for (const auto& [id, s] : pit->second.scopes)
        for (const auto& [k, e] : s.keys) live.insert(e.gen_slot);
    std::uint64_t z = 0;
    for (const auto& [id, l] : leases)
      for (const auto& h : l.held)
        if (h[1] == static_cast<std::uint64_t>(pid) && !live.count(h[0]) && seen.insert(h[0]).second) z += h[2];
    return z;
  }
  void tick(std::int64_t now) {
    for (auto& [pid, p] : prin) {
      for (bool again = true; again;) {
        again = false;
        for (auto& [id, s] : p.scopes)
          if (expired(s, now)) { evict(p, id); again = true; break; }
      }
    }
    for (auto it = leases.begin(); it != leases.end();)
      it = it->second.expiry <= now ? leases.erase(it) : std::next(it);
  }
  StoreConfig c;
  std::map<int, MPrin> prin;
  std::map<LeaseId, MLease> leases;
};

class StoreModel : public ::testing::TestWithParam<std::uint64_t> {};

TEST_P(StoreModel, RandomOpsAgreeWithReference) {
  const StoreConfig c = cfg();
  Fx f(c, GetParam() * 7919 + 3);
  Model m(c);
  SeededRandom r(GetParam());
  std::vector<LeaseId> known;
  for (int step = 0; step < 4000; ++step) {
    const std::int64_t now = f.clock.now().count();
    const int p = 1 + static_cast<int>(r.below(3));
    const int s = static_cast<int>(r.below(6));
    const int k = static_cast<int>(r.below(5));
    switch (r.below(8)) {
      case 0:
        ASSERT_TRUE(f.root(p, s));
        m.ensure(p, s, now);
        break;
      case 1:
      case 2: {
        const std::uint64_t len = 1 + r.below(4096);
        const std::uint64_t lens[] = {len};
        auto a = f.slab->alloc_batch(lens);
        ASSERT_TRUE(a);
        const Extent& e = (*a)[0];
        Status st = f.store->commit_block(p, sid(s), kh(k), KeyHash{}, e, len);
        LookupEntry me{true, e.seg, e.off, len, e.gen, e.gen_slot};
        ErrorCode code{};
        const bool ok = m.commit(p, s, k, me, e.len, now, code);
        ASSERT_EQ(st.has_value(), ok) << "step " << step;
        if (!ok) {
          ASSERT_EQ(st.error().code, code);
          f.slab->free(e);
        }
        break;
      }
      case 3:
      case 4: {
        std::vector<int> ks = {k, (k + 1) % 5, (k + 3) % 5};
        const SessionId sess = 1 + r.below(2);
        auto ack = f.look(p, s, ks, sess);
        std::vector<LookupEntry> want(ks.size());
        bool any = false;
        std::vector<std::array<std::uint64_t, 3>> held;
        auto pit = m.prin.find(p);
        if (pit != m.prin.end()) {
          auto sit = pit->second.scopes.find(s);
          if (sit != pit->second.scopes.end() && !m.expired(sit->second, now)) {
            for (std::size_t i = 0; i < ks.size(); ++i) {
              auto h = sit->second.keys.find(ks[i]);
              if (h != sit->second.keys.end()) {
                want[i] = h->second;
                any = true;
                held.push_back({h->second.gen_slot, static_cast<std::uint64_t>(p), sit->second.lens.at(ks[i])});
              }
            }
            if (any) m.touch(pit->second, sit->second, now);
          }
        }
        ASSERT_EQ(ack.entries, want) << "step " << step;
        ASSERT_EQ(ack.lease != 0, any);
        if (any) {
          m.leases[ack.lease] = {static_cast<SessionId>(sess), now, now + c.lease_ttl.count(), held};
          known.push_back(ack.lease);
        }
        break;
      }
      case 5: {
        if (known.empty()) break;
        LeaseId id = known[r.below(known.size())];
        const SessionId sess = 1 + r.below(2);
        auto res = f.store->renew(sess, id);
        auto it = m.leases.find(id);
        bool ok = it != m.leases.end() && it->second.sess == sess;
        if (ok && it->second.expiry <= now) { m.leases.erase(it); ok = false; }
        ASSERT_EQ(res.has_value(), ok) << "step " << step;
        if (ok) {
          it->second.expiry = std::max(it->second.expiry, std::min(now + c.lease_ttl.count(), it->second.granted + c.lease_max.count()));
          ASSERT_EQ(res->count(), it->second.expiry);
        }
        break;
      }
      case 6: {
        if (known.empty()) break;
        LeaseId id = known[r.below(known.size())];
        const SessionId sess = 1 + r.below(2);
        auto st = f.store->release(sess, id);
        auto it = m.leases.find(id);
        const bool ok = it != m.leases.end() && it->second.sess == sess;
        ASSERT_EQ(st.has_value(), ok) << "step " << step;
        if (ok) m.leases.erase(it);
        break;
      }
      case 7:
        f.clock.advance_by(std::chrono::milliseconds(r.below(12000)));
        f.store->tick();
        m.tick(f.clock.now().count());
        break;
    }
    ASSERT_EQ(f.store->n_leases(), m.leases.size()) << "step " << step;
    for (int pid = 1; pid <= 3; ++pid) {
      ASSERT_EQ(f.store->n_scopes(pid), m.prin[pid].scopes.size()) << "step " << step;
      ASSERT_EQ(f.store->bytes_used(pid), m.prin[pid].bytes) << "step " << step;
    }
    f.inv();
    if (::testing::Test::HasFatalFailure()) return;
  }
  // Drain: everything expires, nothing leaks.
  f.clock.advance_by(seconds(1000));
  f.store->tick();
  EXPECT_EQ(f.store->n_leases(), 0u);
  EXPECT_EQ(f.store->n_zombies(), 0u);
  EXPECT_EQ(f.allocated(), 0u);
  EXPECT_TRUE(f.slab->check_invariants());
}

INSTANTIATE_TEST_SUITE_P(Seeds, StoreModel, ::testing::Range<std::uint64_t>(1, 21));

// ---- fix round 1 (Q02, Q09, Q17, Q18) ------------------------------------------------------

TEST(StoreFix, AmbiguousSixteenBytePrefixDoomsChildOnlyWhenNotExactlyOne) {  // Q02
  Fx f;
  ASSERT_TRUE(f.root(1, 1));
  auto commit = [&](const KeyHash& key, const KeyHash& parent) {
    const std::uint64_t lens[] = {4096};
    auto r = f.slab->alloc_batch(lens);
    EXPECT_TRUE(r);
    Status st = f.store->commit_block(1, sid(1), key, parent, (*r)[0], 4096);
    if (!st) f.slab->free((*r)[0]);
    return st;
  };
  KeyHash a = kh(1), b = kh(1);
  b[31] = 0xb2;  // same 16-byte prefix, different tail
  ASSERT_TRUE(commit(a, KeyHash{}));
  KeyHash wire{};
  std::copy(a.begin(), a.begin() + 16, wire.begin());
  EXPECT_TRUE(commit(kh(2), wire));  // exactly one key has this prefix: resolves
  ASSERT_TRUE(commit(b, KeyHash{}));
  auto amb = commit(kh(3), wire);  // two live keys share the prefix: parent treated as gone
  ASSERT_FALSE(amb);
  EXPECT_EQ(amb.error().code, ErrorCode::AccessDenied);
  f.inv();
  // Invalidating one of the pair removes the prefix's subtree without looping.
  ASSERT_TRUE(f.store->invalidate(1, sid(1), a, f.look(1, 1, {1}).entries[0].gen));
  f.inv();
}

TEST(StoreFix, LeaseCapPerSessionAndZombieBytesCountAgainstQuota) {  // Q09
  StoreConfig c = cfg();
  c.max_leases_per_session = 2;
  Fx f(c);
  ASSERT_TRUE(f.root(1, 1));
  ASSERT_TRUE(f.put(1, 1, 1));
  ASSERT_TRUE(f.put(1, 1, 2));
  auto l1 = f.look(1, 1, {1}, 5), l2 = f.look(1, 1, {2}, 5);
  EXPECT_NE(l1.lease, 0u);
  EXPECT_NE(l2.lease, 0u);
  auto l3 = f.look(1, 1, {1, 2}, 5);  // over the cap: all MISS, no lease (wire-v0 valid)
  EXPECT_EQ(l3.lease, 0u);
  EXPECT_FALSE(l3.entries[0].hit);
  EXPECT_EQ(f.store->n_session_leases(5), 2u);
  EXPECT_NE(f.look(1, 1, {1}, 6).lease, 0u);  // other sessions are unaffected
  ASSERT_TRUE(f.store->release(5, l1.lease));
  EXPECT_NE(f.look(1, 1, {1}, 5).lease, 0u);
  f.inv();
  // Zombie bytes stay charged: scope 1 (2 leased blocks) is dropped, 8 KiB of the 20 KiB quota.
  EXPECT_EQ(f.store->drop_scope(1, sid(1)), 1u);
  EXPECT_EQ(f.store->zombie_bytes(1), 8192u);
  ASSERT_TRUE(f.root(1, 2));
  for (int k = 1; k <= 3; ++k) EXPECT_TRUE(f.put(1, 2, k)) << k;  // 12 KiB + 8 KiB = 20 KiB
  EXPECT_FALSE(f.put(1, 2, 4));
  f.inv();
  f.store->on_session_end(5);
  f.store->on_session_end(6);
  EXPECT_EQ(f.store->zombie_bytes(1), 0u);
  EXPECT_TRUE(f.put(1, 2, 4));
  f.inv();
}

TEST(StoreFix, FailingCommitDoesNotEvictOtherScopes) {  // Q17
  Fx f;  // max_bytes = 5 blocks
  ASSERT_TRUE(f.root(1, 1));
  ASSERT_TRUE(f.put(1, 1, 1));
  ASSERT_TRUE(f.root(1, 2));
  for (int k = 1; k <= 4; ++k) ASSERT_TRUE(f.put(1, 2, k));
  auto big = f.put(1, 2, 9, 8192);  // 16 + 8 KiB > 20 KiB even if scope 1 went
  ASSERT_FALSE(big);
  EXPECT_EQ(big.error().code, ErrorCode::ResourceExhausted);
  EXPECT_TRUE(f.store->has_scope(1, sid(1)));
  EXPECT_TRUE(f.look(1, 1, {1}).entries[0].hit);
  EXPECT_EQ(f.store->bytes_used(1), 5 * 4096u);
  f.inv();
}

TEST(StoreFix, PrincipalStateIsNotCreatedByNoopsAndReapedWhenEmpty) {  // Q18
  Fx f;
  EXPECT_TRUE(f.store->invalidate(42, sid(1), kh(1), 1));
  EXPECT_EQ(f.store->n_principals(), 0u);
  EXPECT_EQ(f.look(43, 1, {1}).lease, 0u);
  EXPECT_EQ(f.store->n_principals(), 0u);
  ASSERT_TRUE(f.root(1, 1));
  EXPECT_EQ(f.store->n_principals(), 1u);
  f.clock.advance_by(seconds(100));
  f.store->tick();  // scope reaped, nothing else held
  EXPECT_EQ(f.store->n_scopes(1), 0u);
  EXPECT_EQ(f.store->n_principals(), 0u);
  f.inv();
}

}  // namespace
}  // namespace miracache::store
