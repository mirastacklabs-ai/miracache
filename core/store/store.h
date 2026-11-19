// SPDX-License-Identifier: Apache-2.0
// Scope table, block map, leases and LOOKUP/RENEW/RELEASE (A1.4 S3, design rev 5.1).
//
// Scopes are implicit and keyed by (principal, scope_id). One is created only by a root
// PUT_BEGIN of an authenticated principal (ensure_scope_for_root_put); LOOKUP never creates
// one. A principal cannot see another principal's scope: the lookup is a MISS, the same
// as for an unknown or expired scope. Each principal has caps (PrincipalPolicy); at the
// scope cap its least-recently-used scope is evicted, never another principal's.
//
// A block removed while leased turns ZOMBIE (memory intact, the seq check rejects the
// read) and is freed at the last release. Leases: one per LOOKUP covering all its hits.
//
// The scope table lives in memory; A3.1 mirrors every implicit scope into the persisted scope
// table (store/scope_table.h, proto/scope_record.h) so the restart scan (store/restart.h) can
// resume it. Single-threaded (store thread). All containers are ordered and keyed by value.
//
// Memory per scope (64-bit libstdc++, empty scope): table node ~160 B (node header 32 +
// ScopeId 32 + ScopeRec 72, malloc-rounded) + LRU node 80 B = about 240 B. Each block adds
// one key node (~96 B) and one BlockInfo node (~128 B).
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <vector>

#include "store/arena.h"
#include "store/reclaim.h"
#include "store/slab.h"
#include "store/store_metrics.h"
#include "util/clock.h"
#include "util/expected.h"
#include "util/random.h"

namespace miracache::store {

using PrincipalId = std::uint64_t;
using SessionId = std::uint64_t;
using LeaseId = std::uint64_t;
using ScopeId = std::array<std::uint8_t, 32>;
using KeyHash = std::array<std::uint8_t, 32>;

// The wire and header parent_hash is the first 16 bytes of the parent key (frozen format).
// A parent is identified by that prefix: an all-zero prefix is the chain root; otherwise it
// resolves to the scope's live key with that prefix, only if exactly one exists (ambiguity
// is treated as parent gone).
inline constexpr std::size_t kParentHashBytes = 16;
inline KeyHash parent_prefix(const KeyHash& k) {
  KeyHash o{};
  for (std::size_t i = 0; i < kParentHashBytes; ++i) o[i] = k[i];
  return o;
}
inline bool parent_is_root(const KeyHash& k) {
  for (std::size_t i = 0; i < kParentHashBytes; ++i)
    if (k[i] != 0) return false;
  return true;
}

struct LookupReq {
  PrincipalId principal = 0;
  ScopeId scope{};
  std::vector<KeyHash> keys;
};

// All-zero entry (hit == false) is the MISS (D5).
struct LookupEntry {
  bool hit = false;
  std::uint32_t seg_id = 0;
  std::uint64_t offset = 0;
  std::uint64_t stored_len = 0;
  std::uint64_t gen = 0;
  std::uint64_t gen_slot = 0;
  friend bool operator==(const LookupEntry&, const LookupEntry&) = default;
};

struct LookupAck {
  LeaseId lease = 0;  // 0 when there is no hit
  Nanos lease_expiry{0};
  std::vector<LookupEntry> entries;  // one per requested key, in order
};

class Store {
 public:
  Store(Arena& arena, SlabAllocator& slab, const Clock& clock, Random& rng);

  // Overrides the config default for one principal. Takes effect on the next operation.
  void set_policy(PrincipalId p, const PrincipalPolicy& pol);
  // HR1 (hot reload class A): the live limits, store thread only, effective on the next operation. Granted leases keep
  // their expiry; the invariant check uses the highest lease_max ever set. `def` replaces the default principal policy
  // (principals with a bundle policy are re-derived by the caller through set_policy).
  struct Limits {
    Nanos lease_ttl{std::chrono::seconds(30)};
    Nanos lease_max{std::chrono::seconds(300)};
    std::uint32_t invalidate_per_s = 10;
    PrincipalPolicy def;
  };
  void set_limits(const Limits& l);
  Limits limits() const { return Limits{lease_ttl_, lease_max_, invalidate_per_s_, default_policy_}; }
  // The policy in force for `p` (its bundle policy, else the default). For tests and diagnostics.
  const PrincipalPolicy& policy(PrincipalId p) const { return policy_for(p); }
  // Optional counters (null = none); the pointee must outlive the store.
  void set_metrics(const StoreMetrics* m) { mx_ = m; }

  // Hook for the S4 put path: PUT_BEGIN at the chain root (parent_hash == 0). Creates the
  // scope if absent (evicting the principal's LRU scope at the cap) and renews it.
  // ResourceExhausted if max_scopes is 0.
  Status ensure_scope_for_root_put(PrincipalId p, const ScopeId& s, Nanos now);

  // Registers a committed block (state becomes COMMITTED). The scope must exist
  // (AccessDenied otherwise). Errors leave the extent with the caller to free:
  // Aborted = key already committed (UniqueKey), ResourceExhausted = over max_bytes.
  // May evict the principal's other LRU scopes to make room. Renews the scope.
  // A non-root block whose parent is not committed in the scope is refused (AccessDenied,
  // NoOrphanTail). `begun_epoch` is scope_epoch() when the put began: a scope created after
  // that (the original was dropped mid-flight) dooms the put (AccessDenied).
  Status commit_block(PrincipalId p, const ScopeId& s, const KeyHash& key, const KeyHash& parent,
                      const Extent& e, std::uint64_t stored_len, std::uint64_t begun_epoch = ~std::uint64_t{0});
  std::uint64_t scope_epoch() const { return epoch_; }

  // INVALIDATE(key, gen): drops the block and its whole subtree. A wrong generation, an
  // unknown key or scope is a no-op that still returns OK. ResourceExhausted when the
  // principal's token bucket (StoreConfig::invalidate_per_s, 0 = unlimited) is empty.
  Status invalidate(PrincipalId p, const ScopeId& s, const KeyHash& key, std::uint64_t gen);
  // Drops one scope (at once, admin) / every scope of `p` OPENED before `drop_before` (P15: opened_at, not last_used).
  // drop_principal is incremental: those scopes are unlinked at once (lookups miss, commits refuse) and their blocks
  // are freed under the sweep budget (leased blocks turn ZOMBIE). Returns the number of scopes marked.
  std::size_t drop_scope(PrincipalId p, const ScopeId& s);
  std::size_t drop_principal(PrincipalId p, Nanos drop_before);
  // ---- QT1: retention and the one eviction budget (decision 3). Hot-reloadable; they take effect on the next turn. ----
  // max_ttl 0 = none. A non-zero value shorter than the age of existing scopes expires them (bounded per turn).
  void set_retention(Nanos max_ttl);
  // Budget: bytes freed per second (burst = one second), blocks per turn, and the pressure watermarks in percent.
  void set_evict(std::uint64_t bytes_per_s, std::uint32_t blocks_per_turn, std::uint32_t high_pct, std::uint32_t low_pct);
  bool pressure() const { return pressure_; }
  // (committed + zombie + in-flight) / registered capacity, in parts per million.
  std::uint64_t occupancy_ppm() const;
  // Blocks still to be freed in expired or dropped scopes (doomed).
  std::uint64_t evict_backlog_blocks() const { return doomed_blocks_; }
  // Estimated ms until the draining scope (expired or dropped, still holding blocks) is empty at the sweep rate; 0 if
  // the scope is not draining. A root put on it is refused with this retry_after (U2-08).
  std::uint32_t drain_retry_ms(PrincipalId p, const ScopeId& s) const;
  // ---- MB3b hooks, now the one budget: Store::tick calls sweep_step once per turn. ----
  // `drop_before` (P15/C19), monotonic per principal and in the Clock domain: a scope whose `opened_ns` is below
  // the principal's cutoff is dead. Lookups of it miss at once, a root put refuses until it is empty, and its
  // blocks are freed incrementally by sweep_step(). The maximum only rises; calling again re-arms the sweep.
  void set_drop_cutoff(PrincipalId p, std::int64_t cutoff_ns);
  std::optional<std::int64_t> drop_cutoff(PrincipalId p) const;
  // One budgeted turn of work, at most min(max_blocks, sweep_blocks_per_turn) blocks and while the bytes credit
  // (sweep_bytes_per_s, refilled by Clock time) is positive; the remainder resumes next turn. Victim order (§6.5):
  // 1. expired / dropped scopes (doomed, leaf first), 2. drop_before-dead scopes (bounded scan), 3. principals over
  // their cap (own LRU leaves), 4. under pressure (occupancy above high_pct until low_pct) the global LRU leaves.
  // Returns the blocks removed.
  std::size_t sweep_step(std::size_t max_blocks = ~std::size_t{0});
  bool sweep_pending() const { return sweep_pending_ || !doomed_principals_.empty() || pressure_; }
  static constexpr std::size_t kSweepBlocks = 64;  // per call, and per reserve_inflight / commit_block call

  // Releases every lease held by the session.
  void on_session_end(SessionId session);
  // Evicts unleased leaf blocks, least recently used first, until at least `bytes_wanted`
  // extent bytes were freed or no candidate is left. Returns the bytes freed.
  std::uint64_t evict(std::uint64_t bytes_wanted);
  // Evict-on-full (R05/R06): frees ONE slab run, the LRU-oldest (by its newest block) whose every
  // allocated block is a committed, unleased, non-zombie block and whose chains lie wholly inside
  // the run, so the run returns to the pool and can be re-carved for any class. `protect` are keys
  // (or 16 B parent prefixes) of scope (p, s) that the running PUT_BEGIN depends on: a run holding
  // one is not a candidate. Returns the bytes freed; 0 = no such run, nothing was evicted.
  std::uint64_t evict_one_run(PrincipalId p, const ScopeId& s, std::span<const KeyHash> protect);

  LookupAck lookup(SessionId session, const LookupReq& req);
  // Extends the lease to min(now + lease_ttl, granted + lease_max). Returns the new expiry.
  // NotFound for an unknown, foreign-session or expired lease. Succeeds when blocks are ZOMBIE.
  Expected<Nanos> renew(SessionId session, LeaseId lease);
  Status release(SessionId session, LeaseId lease);

  // S4 hooks. has_key: a COMMITTED block with this key exists in a live scope (idempotent
  // put SKIP). set_readable: lookups return a MISS for blocks whose segment fails the
  // predicate (outside the registered MR prefix). for_each_block visits every block,
  // zombies included.
  bool has_key(PrincipalId p, const ScopeId& s, const KeyHash& key) const;
  // The wire carries parent_hash truncated to 16 B (spec 5.2). Returns the full key of the
  // committed block in the scope whose first 16 B equal `prefix`; nullopt if there is none
  // or the prefix is ambiguous. Ordered-map prefix scan, O(log n).
  std::optional<KeyHash> resolve_parent(PrincipalId p, const ScopeId& s, std::span<const std::uint8_t, 16> prefix) const;
  void set_readable(std::function<bool(std::uint32_t seg)> pred) { readable_ = std::move(pred); }
  void for_each_block(const std::function<void(const Extent&, std::uint64_t stored_len, bool zombie)>& fn) const;

  // Expires leases, marks scopes idle for idle_ttl + reap_grace (or older than max_ttl) as doomed (lookups MISS from
  // idle_ttl / max_ttl on), then runs one sweep_step: the blocks of doomed scopes are freed incrementally. A root
  // PUT_BEGIN on an expired, not yet reaped scope drops its old blocks and opens it afresh (new opened_at).
  void tick();

  // LeaseSafety, DenyByDefault, UniqueKey, NoLeaseLeak (as of the last tick), NoOrphanTail,
  // chain index and ZOMBIE accounting. Ok or Corrupt.
  Status check_invariants() const;

  // Introspection.
  std::size_t n_scopes(PrincipalId p) const;
  std::uint64_t bytes_used(PrincipalId p) const;
  std::size_t n_leases() const { return leases_.size(); }
  std::size_t n_zombies() const;
  bool has_scope(PrincipalId p, const ScopeId& s) const;
  std::size_t n_principals() const { return principals_.size(); }
  std::uint64_t zombie_bytes(PrincipalId p) const;
  std::uint64_t inflight_bytes(PrincipalId p) const;
  std::size_t n_session_leases(SessionId s) const;

  // One quota (R13): committed + zombie + in-flight bytes <= max_bytes. A reservation that would
  // exceed it first evicts the principal's OWN unleased leaf blocks (LRU, never another
  // principal's, never `protect`ed ones of `scope`), then refuses (ResourceExhausted; blocks
  // already evicted stay evicted, except that bytes eviction can never reclaim (zombie + in-flight
  // + leased + protected) are summed first and a hopeless reservation is refused with NO
  // evictions, T01). T03, known limitation: only the CURRENT put's keys/parents are protected;
  // a different put still in flight can lose its committed parents to this eviction and end
  // Doomed after writing all its bytes (the client recomputes). Released when the put ends or its digest finishes (commit then
  // charges the bytes as committed).
  Status reserve_inflight(PrincipalId p, std::uint64_t bytes, const ScopeId* scope = nullptr,
                          std::span<const KeyHash> protect = {});
  void release_inflight(PrincipalId p, std::uint64_t bytes);

  // ---- SC1 scrub pin hook (core/store/scrub.h). A pin is an internal lease owned by the scrubber (lease count + 1,
  // no session, no expiry): drop/evict/INVALIDATE turn a pinned block ZOMBIE and it is freed at the last unpin.
  struct ScrubTarget {
    Extent e;
    std::uint64_t stored_len = 0;
  };
  // Pins the first committed, unpinned block with gen_slot >= `cursor` and advances `cursor` past it. At the end of the
  // store returns nullopt and resets `cursor` to 0 (the next call starts a new cycle).
  std::optional<ScrubTarget> scrub_pin_next(std::uint64_t& cursor);
  // Releases one pin. `corrupt` and the block still committed at generation `gen`: drops it and its subtree through the
  // INVALIDATE path (no rate limit); returns true then. A block that went ZOMBIE meanwhile is just unpinned.
  bool scrub_unpin(std::uint64_t gen_slot, std::uint64_t gen, bool corrupt);
  std::size_t n_scrub_pins() const { return scrub_pins_.size(); }

  // QT2 (decision 4): PUT_BEGIN admission for ONE key of `bytes` stored bytes. The ops bucket takes 1, the bytes
  // bucket admits while its balance is positive and may go into debt (P22). Returns 0 = admitted (charged), else the
  // retry_after_ms until it would be, and `*kind` (0 = ops, 1 = bytes) says which bucket said no; nothing is charged
  // then. put_unadmit returns the charge of admitted keys whose put was refused later. Limits come from the
  // principal's policy (0 = unlimited).
  std::uint32_t put_admit(PrincipalId p, std::uint64_t bytes, int* kind = nullptr);
  void put_unadmit(PrincipalId p, std::uint64_t ops, std::uint64_t bytes);

  // ---- A3.1 warm restart. Scope records (arena_.scope_table(), when the store has one) carry wall-clock ms; the store
  // runs on Clock ns. wall_ns = clock_ns + wall_offset. The owner sets it once, before the restart scan (default 0: the
  // records then hold Clock ms, which is right for tests that keep one Clock across a restart).
  void set_wall_offset_ns(std::int64_t off) { wall_offset_ns_ = off; }
  std::int64_t wall_offset_ns() const { return wall_offset_ns_; }
  // Called by the restart scan only, on an empty store, before any other call.
  struct RestoredScope {
    PrincipalId principal = 0;
    ScopeId scope{};
    std::int64_t opened_ns = 0, last_used_ns = 0;  // Clock domain
    std::uint32_t rec_slot = ~std::uint32_t{0};    // the scope table slot that now belongs to this scope
  };
  // All scopes at once: epochs follow opened_at, the LRU follows last_used. The scopes resume OPEN; the usual rules
  // (idle TTL, max_ttl, drop_before, caps) apply from the next operation on.
  void restore_scopes(std::vector<RestoredScope> scopes);
  // One committed block of a restored scope, parents before children (the parent, if any, is the unique key with
  // prefix `parent_pfx`). Sets the state word to (COMMITTED, e.gen).
  void restore_block(PrincipalId p, const ScopeId& s, const KeyHash& key, const KeyHash& parent_pfx, const Extent& e,
                     std::uint64_t stored_len);
  // Scopes whose record lives in the scope table (tests).
  std::size_t n_persisted_scopes() const;
  // Sim / tests: every block with its owner, and every scope record (doomed ones included).
  void for_each_owned_block(const std::function<void(const Extent&, std::uint64_t stored_len, bool zombie, PrincipalId,
                                                     const ScopeId&, const KeyHash& key)>& fn) const;
  void for_each_scope(const std::function<void(PrincipalId, const ScopeId&, bool doomed)>& fn) const;

 private:
  struct ScopeRec {
    std::int64_t last_used_ns = 0;
    std::uint64_t seq = 0;    // key in the principal's LRU map
    std::uint64_t bytes = 0;
    std::uint64_t leased_bytes = 0;  // mapped blocks of this scope with leases > 0, kept incrementally (QT2)
    std::map<KeyHash, std::uint64_t> keys;  // key_hash -> gen_slot of the COMMITTED block
    std::map<KeyHash, std::set<KeyHash>> children;  // parent_prefix -> children (zero = roots)
    std::uint64_t epoch = 0;                         // creation order, for doomed puts
    std::int64_t opened_ns = 0;                      // Clock time of the implicit open (drop_before compares this)
    KeyHash drop_cursor{};                           // sweep_step resume point inside keys
    std::size_t drop_noleaf = 0;                     // non-leaves scanned in a row since the last removal (Z08)
    bool doomed = false;  // expired or dropped: unlinked from the LRU and the open index, blocks freed by sweep_step
    EvictReason doom_why = EvictReason::Ttl;
    std::uint32_t rec_slot = ~std::uint32_t{0};  // A3.1: scope table slot (none: in memory only)
    std::int64_t rec_used_ns = 0;                // last_used_ns as last written to the record
  };
  struct PState {
    TokenBucket inval;
    PutBucket put_ops, put_bytes;  // QT2: PUT_BEGIN admission
    std::map<ScopeId, ScopeRec> scopes;
    std::map<std::uint64_t, ScopeId> lru;  // seq -> scope, oldest first (live scopes only; doomed ones are out)
    std::map<std::uint64_t, ScopeId> by_open;  // epoch (= opened order) -> scope, live scopes only (max_ttl)
    std::set<ScopeId> doomed;
    std::uint64_t bytes = 0;
    std::uint64_t next_seq = 1;
    std::uint64_t inflight = 0;      // reserved by live puts
    std::uint64_t zombie_bytes = 0;  // ZOMBIE blocks pinned by leases; count against max_bytes
    std::uint64_t leased_bytes = 0;  // mapped (non-zombie) blocks with leases > 0; kept incrementally (S01)
    BlockLru ev;  // this principal's evictable leaves (see Store::ev_lru_)
  };
  struct BlockInfo {
    Extent e;
    std::uint64_t stored_len = 0;
    KeyHash parent{};
    KeyHash key{};
    ScopeId scope{};
    PrincipalId principal = 0;
    std::uint32_t leases = 0;
    bool zombie = false;
  };
  struct Lease {
    SessionId session = 0;
    Nanos granted{0}, expiry{0};
    std::vector<std::uint64_t> slots;  // one entry per hit (duplicates allowed)
  };

  const PrincipalPolicy& policy_for(PrincipalId p) const;
  // A3.1 scope record upkeep: written at open, rewritten when last_used moved by >= 1 s (or `force`), DRAINING when the
  // scope is doomed, cleared when it is erased (its blocks are then never resumed after a crash).
  void persist_drain(PrincipalId p, const ScopeId& s, ScopeRec& r);
  void persist_touch(PrincipalId p, const ScopeId& s, ScopeRec& r, bool force = false);
  void persist_close(ScopeRec& r);
  std::uint64_t wall_ms(std::int64_t clock_ns) const;
  bool expired(PrincipalId p, const ScopeRec& r, Nanos now) const;
  void evict_scope(PState& ps, std::map<ScopeId, ScopeRec>::iterator it, EvictReason why);
  void drop_block(std::uint64_t slot);  // ZOMBIE if leased, else freed
  void drop_subtree(PState& ps, ScopeRec& r, const KeyHash& key);  // key and all its descendants, children first
  // Removes one key from a scope (map, chain index, bytes) and drops its block.
  std::uint64_t remove_key(PState& ps, ScopeRec& r, const KeyHash& key, EvictReason why);
  bool reapable(PrincipalId p, const ScopeRec& r, Nanos now) const;
  bool dead(PrincipalId p, const ScopeRec& r) const {
    if (r.doomed) return true;
    auto c = drop_cutoff_.find(p);
    return c != drop_cutoff_.end() && r.opened_ns < c->second;
  }
  // Removes up to `budget` blocks of a scope, leaves first (children before parents); returns how many. When
  // `credit` is given the bytes freed are debited from it and the loop also stops once it is not positive.
  std::size_t drop_scope_blocks(PState& ps, ScopeRec& r, std::size_t budget, EvictReason why = EvictReason::Drop,
                                std::int64_t* credit = nullptr);
  // Unlinks a scope from the LRU and the open index and queues its blocks for sweep_step.
  void doom_scope(PrincipalId p, PState& ps, std::map<ScopeId, ScopeRec>::iterator it, EvictReason why);
  void refill_credit(Nanos now);
  // QT2 (U2-09): evictions done inside a put-path call (commit_block, reserve_inflight, a reopen, max_scopes) are charged
  // to the same budget as the sweep: `n` blocks to the per-turn counter, `bytes` to the bytes credit. sweep_step gets
  // what is left of the turn.
  void charge_call(std::size_t n, std::uint64_t bytes) {
    turn_used_ += n;
    credit_ -= static_cast<std::int64_t>(std::min<std::uint64_t>(bytes, INT64_MAX / 2));
  }
  // Frees up to `budget` blocks of this principal's doomed (and drop_before-dead) scopes first, so a cap never costs a
  // live scope while dead blocks wait (U2-04). Erasing an empty record counts as one unit (U2-16). Returns the units used.
  std::size_t drain_doomed(PrincipalId p, PState& ps, std::size_t budget);
  std::uint64_t total_used() const;
  void update_pressure();
  std::size_t sweep_doomed(std::size_t max_blocks);
  std::size_t sweep_flagged(std::size_t max_blocks);
  std::size_t sweep_pressure(std::size_t max_blocks);
  void drop_lease(std::map<LeaseId, Lease>::iterator it);
  // Evictable-leaf index (R14): committed, unleased, non-zombie blocks with no child, kept in the
  // recency order of lru_ so the evictor never rescans. Call after any change to a block's
  // leases, zombie flag, or children.
  void refresh_evictable(std::uint64_t slot);
  void refresh_prefix(const ScopeRec& r, const KeyHash& pfx);  // blocks whose 16 B prefix is pfx
  void forget_block(std::map<std::uint64_t, BlockInfo>::iterator it);  // erase + run index
  std::set<std::uint64_t> protected_slots(PrincipalId p, const ScopeId& s, std::span<const KeyHash> protect) const;

  Arena& arena_;
  SlabAllocator& slab_;
  const Clock& clock_;
  Random& rng_;
  std::map<PrincipalId, PState> principals_;
  std::map<PrincipalId, PrincipalPolicy> policies_;
  std::map<PrincipalId, std::int64_t> drop_cutoff_;  // MB3b: drop_before in the Clock domain, max-only
  bool sweep_pending_ = false;
  std::set<PrincipalId> doomed_principals_;  // principals that may hold doomed scopes (stale entries are dropped lazily)
  std::uint64_t doomed_blocks_ = 0;          // blocks still held by doomed scopes
  bool pressure_ = false;                    // occupancy crossed high_pct and has not yet fallen to low_pct
  Nanos lease_ttl_{0}, lease_max_{0}, lease_max_ceiling_{0};
  std::uint32_t invalidate_per_s_ = 0;
  PrincipalPolicy default_policy_;
  Nanos max_ttl_{0};
  std::uint64_t sweep_bytes_per_s_ = 0;
  std::size_t sweep_blocks_ = 0;
  std::uint32_t high_pct_ = 0, low_pct_ = 0;
  std::int64_t credit_ = 0;       // sweep bytes credit; may go negative (one block of debt)
  std::int64_t credit_ns_ = -1;   // Clock time of the last refill, -1 = not started (the first turn has a full burst)
  bool sweep_started_ = false;    // cursor valid
  PrincipalId sweep_p_ = 0;       // sweep_step cursor: next scope to look at
  ScopeId sweep_s_{};
  std::uint64_t pass_work_ = 0;   // blocks removed since the pass began
  std::size_t turn_used_ = 0;     // blocks removed by put-path calls since the last sweep_step (one "turn")
  std::optional<std::uint64_t> used_hint_;  // tick(): occupancy bytes computed once per tick
  std::map<std::uint64_t, BlockInfo> blocks_;  // by gen_slot; includes zombies
  std::map<LeaseId, Lease> leases_;
  std::map<std::uint64_t, std::uint32_t> scrub_pins_;  // SC1: gen_slot -> pins (each counted in BlockInfo::leases)
  std::map<SessionId, std::uint32_t> session_leases_;
  std::set<std::pair<std::int64_t, LeaseId>> lease_expiry_;
  BlockLru lru_;  // COMMITTED blocks only
  BlockLru ev_lru_;  // evictable leaves of all principals (subset of lru_, same order)
  std::map<std::uint32_t, std::set<std::uint64_t>> run_blocks_;  // slab run -> slots in blocks_
  std::uint64_t epoch_ = 0;
  Nanos last_tick_{0};
  bool tick_capped_ = false;  // the last tick left expired scopes unmarked (per-tick cap): the reap invariant is waived
  std::function<bool(std::uint32_t)> readable_;
  const StoreMetrics* mx_ = nullptr;
  std::int64_t wall_offset_ns_ = 0;  // A3.1
  void count_evict(EvictReason why, std::uint64_t bytes, std::uint64_t blocks) const {
    if (!mx_) return;
    bump(mx_->evict_bytes[static_cast<std::size_t>(why)], bytes);
    bump(mx_->evict_blocks[static_cast<std::size_t>(why)], blocks);
  }
};

}  // namespace miracache::store
