// SPDX-License-Identifier: Apache-2.0
// A3.1 warm restart: the restart scan (store/restart.h) over a File-backed store re-opened in a new "process"
// (Arena, SlabAllocator, Store destroyed and rebuilt over the same files), after a clean shutdown or a crash.
#include <cstring>
#include <filesystem>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <unistd.h>

#include "proto/server_header.h"
#include "store/restart.h"
#include "util/crc32c.h"

namespace miracache::store {
namespace {

using std::chrono::seconds;

class TempDir {
 public:
  TempDir() {
    std::string t = ::testing::TempDir() + "/mira-restart-XXXXXX";
    path_ = ::mkdtemp(t.data()) ? t : std::string();
  }
  ~TempDir() {
    std::error_code ec;
    if (!path_.empty()) std::filesystem::remove_all(path_, ec);
  }
  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

ScopeId sid(int i) {
  ScopeId s{};
  s[0] = static_cast<std::uint8_t>(i);
  s[31] = 0x5c;
  return s;
}
KeyHash kh(int i) {
  KeyHash k{};
  k[0] = static_cast<std::uint8_t>(i);
  k[1] = static_cast<std::uint8_t>(i >> 8);
  k[31] = 0xa1;
  return k;
}

StoreConfig cfg(const std::string& dir) {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.node_id = 9;
  c.backing = BackingKind::File;
  c.dir = dir;
  c.principal_default.max_scopes = 64;
  c.principal_default.max_bytes = std::uint64_t{64} << 20;
  c.principal_default.idle_ttl = seconds(600);
  return c;
}

// One memory-node "process" over the store files.
struct Node {
  Node(const StoreConfig& c, Nanos start) : clock(start), rng(3) {
    auto a = Arena::open(c);
    EXPECT_TRUE(a) << (a ? "" : a.error().context);
    arena = std::move(*a);
    slab = std::make_unique<SlabAllocator>(*arena);
    store = std::make_unique<Store>(*arena, *slab, clock, rng);
  }
  RestartReport scan(bool verify = false) {
    RestartOptions o;
    o.verify_extents = verify;
    auto r = restart_scan(*arena, *slab, *store, o);
    EXPECT_TRUE(r);
    return r ? *r : RestartReport{};
  }
  // A put as the put path does it: alloc (WRITING), the client's bytes, digest, commit, then the header.
  Extent put(PrincipalId p, int s, int k, int parent = -1, std::uint64_t len = 5000, bool commit = true) {
    const KeyHash key = kh(k);
    const KeyHash par = parent < 0 ? KeyHash{} : parent_prefix(kh(parent));
    if (parent < 0) EXPECT_TRUE(store->ensure_scope_for_root_put(p, sid(s), clock.now()));
    const std::uint64_t lens[] = {len};
    auto r = slab->alloc_batch(lens, p);
    EXPECT_TRUE(r);
    const Extent e = (*r)[0];
    auto bytes = arena->block(e.seg, e.off, len);
    for (std::size_t i = 0; i < bytes.size(); ++i) bytes[i] = static_cast<std::byte>((i * 31 + static_cast<std::size_t>(k)) & 0xff);
    if (!commit) return e;  // in flight: WRITING, no header
    proto::ServerHeader h;
    h.stored_len = len;
    const ScopeId sc = sid(s);
    std::memcpy(h.scope_id, sc.data(), 32);
    std::memcpy(h.key_hash, key.data(), 32);
    std::memcpy(h.parent_hash, par.data(), 16);
    h.payload_crc = crc32c(bytes);
    EXPECT_TRUE(store->commit_block(p, sc, key, par, e, len));
    slab->write_header(e, h);
    return e;
  }
  LookupAck look(PrincipalId p, int s, std::vector<int> ks) {
    LookupReq q;
    q.principal = p;
    q.scope = sid(s);
    for (int k : ks) q.keys.push_back(kh(k));
    return store->lookup(7, q);
  }
  int hits(PrincipalId p, int s, std::vector<int> ks) {
    int n = 0;
    for (const auto& e : look(p, s, ks).entries) n += e.hit;
    return n;
  }
  void inv() {
    auto a = store->check_invariants();
    EXPECT_TRUE(a) << a.error().context;
    auto b = slab->check_invariants();
    EXPECT_TRUE(b) << b.error().context;
  }
  SimClock clock;
  SeededRandom rng;
  std::unique_ptr<Arena> arena;
  std::unique_ptr<SlabAllocator> slab;
  std::unique_ptr<Store> store;
};

constexpr PrincipalId kA = 11, kB = 22;

TEST(Restart, FreshStoreScansNothing) {
  TempDir td;
  Node n(cfg(td.path()), Nanos{0});
  EXPECT_TRUE(n.arena->fresh());
  EXPECT_FALSE(n.scan().ran);
  ASSERT_NE(n.arena->scope_table(), nullptr);  // a persistent store has a scope region
}

TEST(Restart, CleanRestartAdoptsEverythingCommitted) {
  TempDir td;
  const auto c = cfg(td.path());
  std::vector<Extent> before;
  std::uint64_t bytes_a = 0, bytes_b = 0;
  {
    Node n(c, seconds(100));
    before.push_back(n.put(kA, 1, 1));
    before.push_back(n.put(kA, 1, 2, 1));
    before.push_back(n.put(kA, 1, 3, 2, 70000));  // another size class
    before.push_back(n.put(kB, 2, 4));
    before.push_back(n.put(kB, 3, 5, -1, 4096));
    bytes_a = n.store->bytes_used(kA);
    bytes_b = n.store->bytes_used(kB);
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  Node n(c, seconds(110));
  EXPECT_TRUE(n.arena->was_clean());
  const auto r = n.scan();
  EXPECT_TRUE(r.ran);
  EXPECT_TRUE(r.clean);
  EXPECT_FALSE(r.verified);  // a clean restart trusts the fenced commit
  EXPECT_EQ(r.adopted_blocks, 5u);
  EXPECT_EQ(r.discarded_total(), 0u);
  EXPECT_EQ(r.scopes_resumed, 3u);
  EXPECT_EQ(n.store->bytes_used(kA), bytes_a);
  EXPECT_EQ(n.store->bytes_used(kB), bytes_b);
  EXPECT_EQ(n.store->n_scopes(kA), 1u);
  EXPECT_EQ(n.store->n_scopes(kB), 2u);
  auto ack = n.look(kA, 1, {1, 2, 3});
  for (std::size_t i = 0; i < 3; ++i) {
    ASSERT_TRUE(ack.entries[i].hit);
    EXPECT_EQ(ack.entries[i].gen, before[i].gen);
    EXPECT_EQ(ack.entries[i].offset, before[i].off);
    EXPECT_EQ(ack.entries[i].seg_id, before[i].seg);
  }
  EXPECT_EQ(n.hits(kB, 2, {4}), 1);
  EXPECT_EQ(n.hits(kB, 3, {5}), 1);
  EXPECT_EQ(n.hits(kA, 2, {4}), 0);  // deny by default: B's scope stays invisible to A
  n.inv();
  // The chain index resumed: the root is not a leaf, the tail is; a child put continues the chain.
  n.put(kA, 1, 6, 3);
  EXPECT_EQ(n.hits(kA, 1, {6}), 1);
  n.inv();
}

TEST(Restart, UncleanRestartDiscardsInFlightPutAndVerifiesExtents) {
  TempDir td;
  const auto c = cfg(td.path());
  Extent inflight, corrupt;
  {
    Node n(c, seconds(1));
    n.put(kA, 1, 1);
    n.put(kA, 1, 2, 1);
    corrupt = n.put(kA, 1, 3);  // a second root in the scope
    inflight = n.put(kA, 1, 4, 2, 5000, false);  // WRITING when the process dies
    // A wild write into a committed extent before the crash: an unclean restart re-verifies every extent.
    n.arena->block(corrupt.seg, corrupt.off, 1)[0] ^= std::byte{0xff};
    // no shutdown_clean: a crash
  }
  Node n(c, seconds(2));
  EXPECT_FALSE(n.arena->was_clean());
  const auto r = n.scan();
  EXPECT_TRUE(r.verified);
  EXPECT_EQ(r.adopted_blocks, 2u);
  EXPECT_EQ(r.discarded[static_cast<std::size_t>(DiscardReason::Digest)], 1u);
  EXPECT_EQ(n.hits(kA, 1, {1, 2}), 2);
  EXPECT_EQ(n.hits(kA, 1, {3, 4}), 0);
  EXPECT_EQ(n.arena->state_gen().state(inflight.gen_slot), proto::BlockState::Free);
  EXPECT_EQ(n.arena->state_gen().state(corrupt.gen_slot), proto::BlockState::Free);
  n.inv();
  // The in-flight key can be put again, and the discarded header is gone for good (a second restart agrees).
  n.put(kA, 1, 4, 2);
  ASSERT_TRUE(n.arena->shutdown_clean());
  n.store.reset();
  n.slab.reset();
  n.arena.reset();
  Node m(c, seconds(3));
  const auto r2 = m.scan();
  EXPECT_EQ(r2.adopted_blocks, 3u);
  EXPECT_EQ(r2.discarded_total(), 0u);
  EXPECT_EQ(m.hits(kA, 1, {1, 2, 4}), 3);
}

TEST(Restart, CleanRestartTrustsCommitUnlessVerifyRequested) {
  TempDir td;
  const auto c = cfg(td.path());
  {
    Node n(c, seconds(1));
    const Extent e = n.put(kA, 1, 1);
    n.arena->block(e.seg, e.off + 100, 1)[0] ^= std::byte{1};
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  {
    Node n(c, seconds(2));
    EXPECT_EQ(n.scan(/*verify=*/true).discarded[static_cast<std::size_t>(DiscardReason::Digest)], 1u);
  }
}

TEST(Restart, CorruptHeaderDiscardsBlockAndItsTail) {
  TempDir td;
  const auto c = cfg(td.path());
  {
    Node n(c, seconds(1));
    n.put(kA, 1, 1);
    const Extent mid = n.put(kA, 1, 2, 1);
    n.put(kA, 1, 3, 2);
    n.put(kA, 1, 7);  // an unrelated root survives
    n.slab->header_slot(mid.seg, mid.gen_slot)[40] ^= std::byte{0x10};  // hdr CRC fails
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  Node n(c, seconds(2));
  const auto r = n.scan();
  EXPECT_EQ(r.adopted_blocks, 2u);
  EXPECT_EQ(r.discarded[static_cast<std::size_t>(DiscardReason::Header)], 1u);
  EXPECT_EQ(r.discarded[static_cast<std::size_t>(DiscardReason::Orphan)], 1u);  // NoOrphanTail
  EXPECT_EQ(n.hits(kA, 1, {1, 7}), 2);
  EXPECT_EQ(n.hits(kA, 1, {2, 3}), 0);
  n.inv();
}

TEST(Restart, GenerationsStayUniqueAcrossRestarts) {
  TempDir td;
  const auto c = cfg(td.path());
  std::set<std::uint64_t> seen;
  std::uint64_t max_gen = 0;
  for (int round = 0; round < 4; ++round) {
    Node n(c, seconds(10 + round));
    n.scan();
    for (int i = 0; i < 20; ++i) {
      const Extent e = n.put(kA, 100 + round * 20 + i, 1);
      EXPECT_TRUE(seen.insert(e.gen).second) << "generation reused: " << e.gen;
      EXPECT_GT(e.gen, max_gen);
      max_gen = e.gen;
    }
    if (round % 2 == 0) ASSERT_TRUE(n.arena->shutdown_clean());  // alternate clean and crash
    EXPECT_LE(max_gen, n.arena->superblock().gen_hwm);
  }
}

TEST(Restart, ScopesResumeWithOpenedAtSoDropBeforeStillApplies) {
  TempDir td;
  const auto c = cfg(td.path());
  {
    Node n(c, seconds(100));
    n.put(kA, 1, 1);  // opened at 100 s
    n.clock.advance_by(seconds(50));
    n.put(kA, 2, 2);  // opened at 150 s
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  Node n(c, seconds(200));
  const auto r = n.scan();
  EXPECT_EQ(r.scopes_resumed, 2u);
  // The floor's drop_before is applied after the scan (Server::load_drop_before_floor): 120 s kills scope 1 only.
  n.store->set_drop_cutoff(kA, Nanos(seconds(120)).count());
  EXPECT_EQ(n.hits(kA, 1, {1}), 0);
  EXPECT_EQ(n.hits(kA, 2, {2}), 1);
  for (int i = 0; i < 10; ++i) {
    n.clock.advance_by(seconds(1));
    n.store->tick();
  }
  EXPECT_FALSE(n.store->has_scope(kA, sid(1)));
  n.inv();
}

TEST(Restart, IdleTtlCountsTheDowntime) {
  TempDir td;
  auto c = cfg(td.path());
  c.principal_default.idle_ttl = seconds(60);
  {
    Node n(c, seconds(100));
    n.put(kA, 1, 1);
    n.clock.advance_by(seconds(50));
    n.put(kA, 2, 2);  // last used at 150 s
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  Node n(c, seconds(170));  // 70 s after scope 1 was last used, 20 s after scope 2
  n.scan();
  EXPECT_EQ(n.hits(kA, 1, {1}), 0);  // idle past its TTL: expired
  EXPECT_EQ(n.hits(kA, 2, {2}), 1);
}

TEST(Restart, MaxTtlCountsFromOpenedAt) {
  TempDir td;
  auto c = cfg(td.path());
  c.max_ttl = seconds(100);
  {
    Node n(c, seconds(100));
    n.put(kA, 1, 1);
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  Node n(c, seconds(150));
  n.scan();
  EXPECT_EQ(n.hits(kA, 1, {1}), 1);
  n.clock.advance_by(seconds(60));  // 110 s after opened_at
  EXPECT_EQ(n.hits(kA, 1, {1}), 0);
}

// Spec §10 "Clock jump": the wall clock is read once per run (the offset); a step between two runs is read as
// downtime. Forward: a long gap expires the scope (a miss, never wrong bytes). Backward: the scope is not expired early,
// its idle time is clamped at zero, and it lives at most the stored last_used + TTL on the new clock.
TEST(Restart, WallClockStepBetweenRunsIsDowntimeNotACrash) {
  TempDir td;
  auto c = cfg(td.path());
  c.principal_default.idle_ttl = seconds(60);
  {
    Node n(c, seconds(1000));
    n.put(kA, 1, 1);  // last used at 1000 s
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  {  // clock stepped back by 900 s: the scope is not expired, and no negative idle time wraps around
    Node n(c, seconds(100));
    n.scan();
    EXPECT_EQ(n.hits(kA, 1, {1}), 1);  // touched at 100 s
    n.clock.advance_by(seconds(61));
    EXPECT_EQ(n.hits(kA, 1, {1}), 0);  // idle again for a full TTL: expired
    n.inv();
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  {  // F06: the stored last_used (1000 s) is in the future of the new clock: clamped to now, so the idle TTL is not extended
    Node n(c, seconds(1000));
    n.scan();
    n.put(kA, 3, 3);
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  {
    Node n(c, seconds(100));
    n.scan();
    n.clock.advance_by(seconds(61));  // no touch in between: from 100 s, not from 1000 s
    EXPECT_EQ(n.hits(kA, 3, {3}), 0);
    n.inv();
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  {
    Node n(c, seconds(1000));
    n.scan();
    n.put(kA, 2, 2);
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  Node n(c, seconds(100000));  // stepped forward by a day: counted as downtime
  n.scan();
  EXPECT_EQ(n.hits(kA, 2, {2}), 0);
  n.inv();
}

TEST(Restart, DroppedEvictedAndInvalidatedBlocksNeverComeBack) {
  TempDir td;
  const auto c = cfg(td.path());
  {
    Node n(c, seconds(1));
    n.put(kA, 1, 1);
    n.put(kA, 1, 2, 1);
    n.put(kA, 2, 3);
    n.put(kA, 3, 4);
    n.put(kA, 4, 5);
    n.put(kA, 4, 6, 5);
    // Scope 1: dropped while a lease pins its root (ZOMBIE: header cleared at once).
    ASSERT_TRUE(n.look(kA, 1, {1}).lease != 0);
    EXPECT_EQ(n.store->drop_scope(kA, sid(1)), 1u);
    // Scope 2: doomed by drop_principal, its blocks not yet swept when the process dies (record DRAINING).
    EXPECT_EQ(n.store->drop_principal(kA, seconds(2)), 3u);  // scopes 2, 3, 4 (opened before 2 s)
    n.clock.advance_by(seconds(5));
    // INVALIDATE: a poisoned block of a live scope.
    n.put(kA, 9, 9);
    n.put(kA, 9, 10, 9);
    const auto ack = n.look(kA, 9, {10});
    ASSERT_TRUE(ack.entries[0].hit);
    ASSERT_TRUE(n.store->invalidate(kA, sid(9), kh(10), ack.entries[0].gen));
    // crash
  }
  Node n(c, seconds(10));
  const auto r = n.scan();
  EXPECT_EQ(r.scopes_resumed, 1u);  // scope 9 only
  EXPECT_EQ(r.adopted_blocks, 1u);  // 9's root
  EXPECT_EQ(r.scopes_draining, 3u);
  EXPECT_EQ(n.hits(kA, 1, {1, 2}), 0);
  EXPECT_EQ(n.hits(kA, 2, {3}), 0);
  EXPECT_EQ(n.hits(kA, 4, {5, 6}), 0);
  EXPECT_EQ(n.hits(kA, 9, {9}), 1);
  EXPECT_EQ(n.hits(kA, 9, {10}), 0);
  n.inv();
}

TEST(Restart, SameScopeIdUnderTwoPrincipalsIsNotAttributed) {
  TempDir td;
  const auto c = cfg(td.path());
  {
    Node n(c, seconds(1));
    n.put(kA, 1, 1);
    n.put(kB, 1, 2);  // B opens its own (B, scope 1)
    n.put(kB, 5, 3);
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  Node n(c, seconds(2));
  const auto r = n.scan();
  // The header carries no principal: blocks of a scope_id two principals hold cannot be attributed, so they go.
  EXPECT_EQ(r.discarded[static_cast<std::size_t>(DiscardReason::SharedScopeId)], 2u);
  ASSERT_EQ(r.shared_scopes.size(), 1u);
  EXPECT_EQ(r.shared_scopes[0].blocks, 2u);
  EXPECT_EQ(r.shared_scopes[0].principals, (std::vector<PrincipalId>{kA, kB}));
  EXPECT_FALSE(r.shared_scopes[0].torn_record);
  EXPECT_EQ(r.adopted_blocks, 1u);
  EXPECT_EQ(n.hits(kA, 1, {1}), 0);
  EXPECT_EQ(n.hits(kB, 1, {2}), 0);
  EXPECT_EQ(n.hits(kB, 5, {3}), 1);
  n.inv();
}

// F01 (crash order): P (kA) has scope 1 DRAINING with blocks still on media, P' (kB) holds the same scope_id OPEN. A
// scan killed at any point must leave a state in which the next scan still adopts nothing for the shared scope_id.
void shared_scope_crash(RestartOptions::Stage stop_at) {
  TempDir td;
  const auto c = cfg(td.path());
  {
    Node n(c, seconds(1));
    n.put(kA, 1, 1);
    n.put(kA, 1, 2, 1);
    n.put(kB, 1, 3);
    n.put(kB, 7, 4);  // an unrelated scope that must survive every scan
    EXPECT_EQ(n.store->drop_principal(kA, seconds(2)), 1u);  // A's scope 1 doomed (DRAINING); its blocks not swept yet
    // crash
  }
  {  // a scan killed at the stage boundary
    Node n(c, seconds(2));
    RestartOptions o;
    o.stop_after = [&](RestartOptions::Stage s) { return s == stop_at; };
    auto r = restart_scan(*n.arena, *n.slab, *n.store, o);
    ASSERT_FALSE(r);
    EXPECT_EQ(r.error().code, ErrorCode::Aborted);
    // crash again
  }
  Node n(c, seconds(3));
  const auto r = n.scan();
  EXPECT_EQ(n.hits(kB, 1, {3}), 0);
  EXPECT_EQ(n.hits(kB, 1, {1, 2}), 0);  // A's doomed blocks never show up under B
  EXPECT_EQ(n.hits(kA, 1, {1}), 0);
  EXPECT_EQ(r.adopted_blocks, 1u);  // scope 7 only
  EXPECT_EQ(n.hits(kB, 7, {4}), 1);
  n.inv();
}

TEST(Restart, CrashAfterScopeRecordsLoadedNeverAdoptsDoomedBlocksIntoTheOtherPrincipal) {
  shared_scope_crash(RestartOptions::Stage::RecordsLoaded);
}
TEST(Restart, CrashAfterHeaderPassNeverAdoptsDoomedBlocksIntoTheOtherPrincipal) {
  shared_scope_crash(RestartOptions::Stage::HeadersScanned);
}

// F01 (torn record): the in-place rewrite of A's record was cut short (CRC fails); B holds the same scope_id OPEN.
TEST(Restart, TornRecordCountsAsAnOwnerOfItsScopeId) {
  TempDir td;
  const auto c = cfg(td.path());
  {
    Node n(c, seconds(1));
    n.put(kA, 1, 1);
    n.put(kB, 1, 2);
    n.put(kB, 5, 3);
    // crash; A's record for scope 1 is torn: its last_used / CRC words are half-written
    auto& sb = n.arena->superblock();
    bool torn = false;
    for (std::uint32_t i = 0; i < n.arena->layout().scope.records && !torn; ++i) {
      auto rec = n.arena->block(0, sb.scope_off + proto::scope_record_offset(i), proto::kScopeRecordSize);
      std::uint32_t p = 0;
      std::memcpy(&p, rec.data(), 4);
      if (p == kA && std::to_integer<int>(rec[proto::scr::scope_id]) == 1) {
        rec[proto::scr::crc] ^= std::byte{0x5a};
        torn = true;
      }
    }
    ASSERT_TRUE(torn);
  }
  Node n(c, seconds(2));
  const auto r = n.scan();
  EXPECT_EQ(r.scope_records_corrupt, 1u);
  EXPECT_EQ(r.discarded[static_cast<std::size_t>(DiscardReason::SharedScopeId)], 2u);
  EXPECT_EQ(r.adopted_blocks, 1u);  // B's scope 5
  EXPECT_EQ(n.hits(kB, 1, {2}), 0);
  EXPECT_EQ(n.hits(kA, 1, {1}), 0);
  EXPECT_EQ(n.hits(kB, 5, {3}), 1);
  ASSERT_EQ(r.shared_scopes.size(), 1u);
  EXPECT_TRUE(r.shared_scopes[0].torn_record);
  EXPECT_EQ(r.shared_scopes[0].blocks, 2u);
  n.inv();
}

// H05: a torn record whose principal reads as zero (a torn first write): nothing can be attributed, so the scan comes
// back cold, reports the slot and counts the blocks under TornRecord (not plain Scope).
TEST(Restart, TornRecordWithZeroPrincipalRestartsColdAndIsReported) {
  TempDir td;
  const auto c = cfg(td.path());
  std::uint32_t torn_slot = 0;
  {
    Node n(c, seconds(1));
    n.put(kA, 1, 1);
    n.put(kB, 5, 3);
    auto& sb = n.arena->superblock();
    bool torn = false;
    for (std::uint32_t i = 0; i < n.arena->layout().scope.records && !torn; ++i) {
      auto rec = n.arena->block(0, sb.scope_off + proto::scope_record_offset(i), proto::kScopeRecordSize);
      std::uint32_t p = 0;
      std::memcpy(&p, rec.data(), 4);
      if (p == kA) {
        std::memset(rec.data() + proto::scr::principal_id, 0, 4);
        rec[proto::scr::crc] ^= std::byte{0x5a};
        torn = true;
        torn_slot = i;
      }
    }
    ASSERT_TRUE(torn);
  }
  Node n(c, seconds(2));
  const auto r = n.scan();
  EXPECT_EQ(r.scope_records_corrupt, 1u);
  ASSERT_EQ(r.blind_record_slots.size(), 1u);
  EXPECT_EQ(r.blind_record_slots[0], torn_slot);
  EXPECT_EQ(r.adopted_blocks, 0u);
  EXPECT_EQ(r.scopes_resumed, 0u);
  EXPECT_EQ(r.discarded[static_cast<std::size_t>(DiscardReason::TornRecord)], 2u);
  EXPECT_EQ(r.discarded[static_cast<std::size_t>(DiscardReason::Scope)], 0u);
  EXPECT_STREQ(discard_reason_name(DiscardReason::TornRecord), "torn_record");
  EXPECT_EQ(n.hits(kB, 5, {3}), 0);
  n.inv();
}

// F05: a CRC-valid record with a time beyond year 2262 (ms * 1e6 overflows int64) must not be undefined behaviour.
TEST(Restart, HugePersistedTimesDoNotOverflow) {
  TempDir td;
  const auto c = cfg(td.path());
  {
    Node n(c, seconds(1));
    n.put(kA, 1, 1);
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  {
    Node n(c, seconds(2));
    ScopeTable* t = n.arena->scope_table();
    ASSERT_NE(t, nullptr);
    bool done = false;
    t->load([&](std::uint32_t slot, const proto::ScopeRecord& r) {
      proto::ScopeRecord w = r;
      w.opened_at_ms = w.last_used_ms = ~std::uint64_t{0} >> 1;
      w.expires_at_ms = 0;
      t->write(slot, w);
      done = true;
      return true;
    });
    ASSERT_TRUE(done);
    ASSERT_TRUE(n.arena->shutdown_clean());
  }
  Node n(c, seconds(3));
  n.scan();  // UBSan: no signed overflow
  EXPECT_EQ(n.hits(kA, 1, {1}), 1);  // clamped to now, so neither expired nor immortal
  n.inv();
}


TEST(Restart, ScopeTableFullRefusesNewScopes) {
  TempDir td;
  auto c = cfg(td.path());
  c.scope_records = 2;
  Node n(c, seconds(1));
  EXPECT_TRUE(n.store->ensure_scope_for_root_put(kA, sid(1), n.clock.now()));
  EXPECT_TRUE(n.store->ensure_scope_for_root_put(kA, sid(2), n.clock.now()));
  EXPECT_FALSE(n.store->ensure_scope_for_root_put(kA, sid(3), n.clock.now()));
  EXPECT_EQ(n.store->drop_scope(kA, sid(1)), 1u);  // the record is released with the scope
  EXPECT_TRUE(n.store->ensure_scope_for_root_put(kA, sid(3), n.clock.now()));
  EXPECT_EQ(n.store->n_persisted_scopes(), 2u);
}

TEST(Restart, ScopeRegionPlacement) {
  TempDir td;
  Node n(cfg(td.path()), Nanos{0});
  const auto& sr = n.arena->layout().scope;
  EXPECT_GT(sr.records, 0u);
  EXPECT_EQ(n.arena->superblock().scope_off, sr.off);
  EXPECT_EQ(n.arena->superblock().scope_len, sr.len);
  // The alignment gap between the header table and the data holds it: no capacity lost.
  const auto& sl = n.arena->layout().seg;
  EXPECT_GE(sr.off, sl.hdr_table_off + sl.hdr_table_bytes());
  EXPECT_LE(sr.off + sr.len, sl.data_off);
  EXPECT_EQ(sr.reserved_runs, 0u);
  EXPECT_EQ(n.slab->total_runs(), 2 * sl.n_runs);
  {  // Too large for the gap and the slack: the tail runs of segment 0 are reserved, and adoption still works.
    TempDir td2;
    auto big = cfg(td2.path());
    big.scope_records = 10000;  // 704 KiB
    {
      Node b(big, seconds(1));
      EXPECT_EQ(b.arena->layout().scope.reserved_runs, 3u);
      EXPECT_EQ(b.slab->total_runs(), 2 * sl.n_runs - 3);
      EXPECT_EQ(b.arena->layout().scope.off + b.arena->layout().scope.len, sl.segment_bytes);
      for (int i = 0; i < 12; ++i) b.put(kA, i + 1, 1);
      b.inv();
      ASSERT_TRUE(b.arena->shutdown_clean());
    }
    Node b(big, seconds(2));
    EXPECT_EQ(b.scan().adopted_blocks, 12u);
    b.inv();
  }
  // Anon (volatile): no region, nothing reserved.
  StoreConfig anon = cfg(td.path());
  anon.backing = BackingKind::Anon;
  anon.dir.clear();
  auto a = Arena::open(anon);
  ASSERT_TRUE(a);
  EXPECT_EQ((*a)->scope_table(), nullptr);
  EXPECT_EQ((*a)->layout().scope.reserved_runs, 0u);
}

}  // namespace
}  // namespace miracache::store
