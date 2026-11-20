// SPDX-License-Identifier: Apache-2.0
#include "store/store.h"

#include <algorithm>

#include "proto/scope_record.h"
#include "util/buggify.h"
#include "util/check.h"

namespace miracache::store {

namespace {
Error corrupt(const char* what) { return Error{ErrorCode::Corrupt, what}; }

// Number of keys (capped at 2) whose first 16 bytes equal `prefix`'s (ordered prefix lookup).
std::size_t prefix_matches(const std::map<KeyHash, std::uint64_t>& keys, const KeyHash& prefix) {
  std::size_t n = 0;
  for (auto it = keys.lower_bound(prefix); it != keys.end() && n < 2; ++it) {
    if (parent_prefix(it->first) != prefix) break;
    ++n;
  }
  return n;
}
}  // namespace

Store::Store(Arena& arena, SlabAllocator& slab, const Clock& clock, Random& rng)
    : arena_(arena), slab_(slab), clock_(clock), rng_(rng) {
  MIRACACHE_CHECK(arena_.config().validate().has_value());
  const StoreConfig& c = arena_.config();
  max_ttl_ = c.max_ttl;
  sweep_bytes_per_s_ = c.sweep_bytes_per_s;
  sweep_blocks_ = c.sweep_blocks_per_turn;
  high_pct_ = c.high_pct;
  low_pct_ = c.low_pct;
  lease_ttl_ = c.lease_ttl;
  lease_max_ = lease_max_ceiling_ = c.lease_max;
  invalidate_per_s_ = c.invalidate_per_s;
  default_policy_ = c.principal_default;
  // 0 = computed (the loader's rule): this node's n_segments x segment_bytes.
  if (default_policy_.max_bytes == 0) default_policy_.max_bytes = static_cast<std::uint64_t>(c.segment_bytes) * c.n_segments;
}

void Store::set_retention(Nanos max_ttl) {
  MIRACACHE_CHECK(max_ttl >= Nanos{0});
  max_ttl_ = max_ttl;
}

void Store::set_evict(std::uint64_t bytes_per_s, std::uint32_t blocks_per_turn, std::uint32_t high_pct,
                      std::uint32_t low_pct) {
  MIRACACHE_CHECK(bytes_per_s > 0 && blocks_per_turn > 0 && low_pct > 0 && low_pct < high_pct && high_pct <= 100);
  sweep_bytes_per_s_ = bytes_per_s;
  sweep_blocks_ = blocks_per_turn;
  high_pct_ = high_pct;
  low_pct_ = low_pct;
  credit_ = std::min<std::int64_t>(credit_, static_cast<std::int64_t>(std::min<std::uint64_t>(bytes_per_s, INT64_MAX)));
}

void Store::set_limits(const Limits& l) {
  MIRACACHE_CHECK(l.lease_ttl > Nanos{0} && l.lease_max >= l.lease_ttl);
  MIRACACHE_CHECK(l.def.max_scopes > 0 && l.def.max_bytes > 0 && l.def.idle_ttl > Nanos{0});
  lease_ttl_ = l.lease_ttl;
  lease_max_ = l.lease_max;
  lease_max_ceiling_ = std::max(lease_max_ceiling_, l.lease_max);
  invalidate_per_s_ = l.invalidate_per_s;
  default_policy_ = l.def;
  sweep_pending_ = true;  // a cap cut converges through sweep_step
}

std::uint64_t Store::total_used() const {
  std::uint64_t used = 0;
  for (const auto& [p, ps] : principals_) used += ps.bytes + ps.zombie_bytes + ps.inflight;
  return used;
}

std::uint64_t Store::occupancy_ppm() const {
  const std::uint64_t used = used_hint_ ? *used_hint_ : total_used();
  const std::uint64_t cap = std::uint64_t{slab_.total_runs()} * arena_.config().run_bytes;
  if (cap == 0) return 0;
  return static_cast<std::uint64_t>(static_cast<unsigned __int128>(used) * 1'000'000 / cap);
}

void Store::refill_credit(Nanos now) {
  const std::int64_t burst = static_cast<std::int64_t>(std::min<std::uint64_t>(sweep_bytes_per_s_, INT64_MAX));
  if (credit_ns_ < 0) {
    credit_ = burst;  // the first turn has a full second's worth
  } else if (now.count() > credit_ns_) {
    const std::uint64_t dt = static_cast<std::uint64_t>(now.count() - credit_ns_);
    if (dt >= 1'000'000'000) {
      credit_ = burst;  // a second or more: a full burst, any debt repaid (unsigned arithmetic only: no __muloti4)
    } else {
      using u128 = unsigned __int128;
      const u128 add = static_cast<u128>(sweep_bytes_per_s_) * dt / 1'000'000'000;
      if (credit_ >= 0) {
        const u128 sum = static_cast<u128>(credit_) + add;
        credit_ = sum >= static_cast<u128>(burst) ? burst : static_cast<std::int64_t>(sum);
      } else {  // a debt is repaid by the time that passed
        const u128 debt = static_cast<u128>(-credit_);
        credit_ = add >= debt ? static_cast<std::int64_t>(std::min<u128>(add - debt, static_cast<u128>(burst)))
                              : -static_cast<std::int64_t>(debt - add);
      }
    }
  }
  if (now.count() > credit_ns_) credit_ns_ = now.count();
}

void Store::update_pressure() {
  const std::uint64_t cap = std::uint64_t{slab_.total_runs()} * arena_.config().run_bytes;
  if (cap == 0) return;
  const std::uint64_t used = used_hint_ ? *used_hint_ : total_used();
  const unsigned __int128 u100 = static_cast<unsigned __int128>(used) * 100;
  if (!pressure_ && u100 > static_cast<unsigned __int128>(cap) * high_pct_) pressure_ = true;
  else if (pressure_ && u100 <= static_cast<unsigned __int128>(cap) * low_pct_) pressure_ = false;
}

void Store::set_policy(PrincipalId p, const PrincipalPolicy& pol) {
  MIRACACHE_CHECK(pol.max_scopes > 0 && pol.max_bytes > 0 && pol.idle_ttl > Nanos{0});
  policies_[p] = pol;
  sweep_pending_ = true;  // a cap cut converges through sweep_step
}

const PrincipalPolicy& Store::policy_for(PrincipalId p) const {
  auto it = policies_.find(p);
  return it != policies_.end() ? it->second : default_policy_;
}

bool Store::expired(PrincipalId p, const ScopeRec& r, Nanos now) const {
  if (max_ttl_ > Nanos{0} && now.count() - r.opened_ns >= max_ttl_.count()) return true;  // retention counts from opened_at
  return now.count() - r.last_used_ns >= policy_for(p).idle_ttl.count();
}

void Store::drop_block(std::uint64_t slot) {
  auto it = blocks_.find(slot);
  MIRACACHE_CHECK(it != blocks_.end());
  BlockInfo& b = it->second;
  lru_.erase(slot);
  ev_lru_.erase(slot);
  principals_.at(b.principal).ev.erase(slot);
  if (b.leases > 0) {
    b.zombie = true;
    PState& zp = principals_.at(b.principal);
    zp.zombie_bytes += b.e.len;
    zp.leased_bytes -= b.e.len;  // no longer mapped
    if (auto sc = zp.scopes.find(b.scope); sc != zp.scopes.end()) sc->second.leased_bytes -= b.e.len;
    if (!MIRACACHE_TEETH_ON(SkipSeq))  // TEETH: skip the seq flip
      arena_.state_gen().store(slot, proto::BlockState::Zombie, b.e.gen);
    slab_.clear_header(b.e);  // out of the index: never resumed after a crash
  } else {
    slab_.free(b.e);
    forget_block(it);
  }
}

void Store::forget_block(std::map<std::uint64_t, BlockInfo>::iterator it) {
  const std::uint32_t run = slab_.run_of(it->second.e);
  auto rb = run_blocks_.find(run);
  MIRACACHE_CHECK(rb != run_blocks_.end() && rb->second.erase(it->first) == 1);
  if (rb->second.empty()) run_blocks_.erase(rb);
  blocks_.erase(it);
}

void Store::refresh_evictable(std::uint64_t slot) {
  const BlockInfo& b = blocks_.at(slot);
  PState& ps = principals_.at(b.principal);
  bool want = !b.zombie && b.leases == 0;
  if (want) {
    const ScopeRec& r = ps.scopes.at(b.scope);
    want = r.children.find(parent_prefix(b.key)) == r.children.end();  // leaf: the tail of its chain
  }
  if (want) {
    const std::uint64_t seq = lru_.seq_of(slot);
    MIRACACHE_CHECK(seq != 0);
    ev_lru_.insert_at(slot, seq);
    ps.ev.insert_at(slot, seq);
  } else {
    ev_lru_.erase(slot);
    ps.ev.erase(slot);
  }
}

void Store::refresh_prefix(const ScopeRec& r, const KeyHash& pfx) {
  if (parent_is_root(pfx)) return;
  for (auto it = r.keys.lower_bound(pfx); it != r.keys.end() && parent_prefix(it->first) == pfx; ++it)
    refresh_evictable(it->second);
}

std::set<std::uint64_t> Store::protected_slots(PrincipalId p, const ScopeId& s, std::span<const KeyHash> protect) const {
  std::set<std::uint64_t> out;
  auto pit = principals_.find(p);
  if (pit == principals_.end()) return out;
  auto sit = pit->second.scopes.find(s);
  if (sit == pit->second.scopes.end()) return out;
  const auto& keys = sit->second.keys;
  for (const KeyHash& x : protect) {
    const KeyHash pfx = parent_prefix(x);
    if (parent_is_root(pfx)) continue;
    for (auto it = keys.lower_bound(pfx); it != keys.end() && parent_prefix(it->first) == pfx; ++it)
      out.insert(it->second);
  }
  return out;
}

bool Store::reapable(PrincipalId p, const ScopeRec& r, Nanos now) const {
  return now.count() - r.last_used_ns >= policy_for(p).idle_ttl.count() + arena_.config().reap_grace.count();
}

std::uint64_t Store::remove_key(PState& ps, ScopeRec& r, const KeyHash& key, EvictReason why) {
  auto kit = r.keys.find(key);
  MIRACACHE_CHECK(kit != r.keys.end());
  const std::uint64_t slot = kit->second;
  const BlockInfo& b = blocks_.at(slot);
  const std::uint64_t len = b.e.len;
  auto cit = r.children.find(b.parent);
  if (cit != r.children.end()) {
    cit->second.erase(key);
    if (cit->second.empty()) r.children.erase(cit);
  }
  const KeyHash parent = b.parent;
  r.drop_noleaf = 0;  // the scope changed: a leaf may exist again (drop_scope_blocks)
  if (r.doomed) --doomed_blocks_;
  r.bytes -= len;
  ps.bytes -= len;
  r.keys.erase(kit);
  count_evict(why, len, 1);
  drop_block(slot);
  refresh_prefix(r, parent);  // the parent may have become a leaf
  return len;
}

Status Store::invalidate(PrincipalId p, const ScopeId& s, const KeyHash& key, std::uint64_t gen) {
  auto ignored = [this]() -> Status {
    if (mx_) bump(mx_->invalidate_ignored);
    return {};
  };
  const Nanos now = clock_.now();
  auto pit = principals_.find(p);
  if (pit == principals_.end()) return ignored();  // no state: nothing to invalidate, nothing to create
  PState& ps = pit->second;
  if (!ps.inval.take(invalidate_per_s_, now))
    return Error{ErrorCode::ResourceExhausted, "store: invalidate rate"};
  auto sit = ps.scopes.find(s);
  if (sit == ps.scopes.end() || expired(p, sit->second, now)) return ignored();
  ScopeRec& r = sit->second;
  auto kit = r.keys.find(key);
  if (kit == r.keys.end() || blocks_.at(kit->second).e.gen != gen) return ignored();
  drop_subtree(ps, r, key);
  if (mx_) bump(mx_->invalidate_dropped);
  return {};
}

void Store::drop_subtree(PState& ps, ScopeRec& r, const KeyHash& key) {
  std::vector<KeyHash> order{key};  // pre-order; children are removed before parents
  std::set<KeyHash> visited{key};   // prefix-shared keys can make the child index cyclic
  for (std::size_t i = 0; i < order.size(); ++i) {
    auto c = r.children.find(parent_prefix(order[i]));
    if (c == r.children.end()) continue;
    for (const KeyHash& ch : c->second)
      if (visited.insert(ch).second) order.push_back(ch);
  }
  for (auto it = order.rbegin(); it != order.rend(); ++it) remove_key(ps, r, *it, EvictReason::Invalidate);
}

// ---- Scrub pins (internal leases owned by the scrubber; see scrub.h) ----
std::optional<Store::ScrubTarget> Store::scrub_pin_next(std::uint64_t& cursor) {
  for (auto it = blocks_.lower_bound(cursor); it != blocks_.end(); ++it) {
    BlockInfo& b = it->second;
    if (b.zombie || scrub_pins_.count(it->first)) continue;
    PState& ps = principals_.at(b.principal);
    ScopeRec& r = ps.scopes.at(b.scope);
    if (b.leases++ == 0) ps.leased_bytes += b.e.len, r.leased_bytes += b.e.len;
    ++scrub_pins_[it->first];
    refresh_evictable(it->first);  // pinned: not evictable
    cursor = it->first + 1;
    return ScrubTarget{b.e, b.stored_len};
  }
  cursor = 0;  // end of the store: the next call starts a new cycle
  return std::nullopt;
}

bool Store::scrub_unpin(std::uint64_t slot, std::uint64_t gen, bool corrupt) {
  auto b = blocks_.find(slot);
  MIRACACHE_CHECK(b != blocks_.end() && b->second.leases > 0);
  auto pin = scrub_pins_.find(slot);
  MIRACACHE_CHECK(pin != scrub_pins_.end());
  if (--pin->second == 0) scrub_pins_.erase(pin);
  const PrincipalId owner = b->second.principal;
  const ScopeId scope = b->second.scope;
  const KeyHash key = b->second.key;
  if (b->second.leases == 1 && !b->second.zombie) {
    PState& lp = principals_.at(owner);
    lp.leased_bytes -= b->second.e.len;
    lp.scopes.at(scope).leased_bytes -= b->second.e.len;
  }
  const bool alive = !b->second.zombie && b->second.e.gen == gen;
  if (--b->second.leases == 0 && b->second.zombie) {
    principals_.at(owner).zombie_bytes -= b->second.e.len;
    slab_.free(b->second.e);
    forget_block(b);
  } else if (b->second.leases == 0 && !b->second.zombie) {
    refresh_evictable(slot);
  }
  if (!corrupt || !alive) return false;
  PState& ps = principals_.at(owner);
  auto sit = ps.scopes.find(scope);
  if (sit == ps.scopes.end() || sit->second.doomed) return false;  // already being dropped
  if (auto k = sit->second.keys.find(key); k == sit->second.keys.end() || k->second != slot) return false;
  drop_subtree(ps, sit->second, key);  // the INVALIDATE path, without the per-principal rate limit
  if (ps.bytes + ps.zombie_bytes > policy_for(owner).max_bytes) sweep_pending_ = true;
  return true;
}

std::size_t Store::drop_scope(PrincipalId p, const ScopeId& s) {
  auto pit = principals_.find(p);
  if (pit == principals_.end()) return 0;
  auto it = pit->second.scopes.find(s);
  if (it == pit->second.scopes.end()) return 0;
  evict_scope(pit->second, it, EvictReason::Drop);
  return 1;
}

std::size_t Store::drop_principal(PrincipalId p, Nanos drop_before) {
  auto pit = principals_.find(p);
  if (pit == principals_.end()) return 0;
  PState& ps = pit->second;
  std::size_t n = 0;
  // Compared with opened_at. Incremental: the scopes are doomed now (lookups miss, commits refuse) and their
  // blocks are freed under the sweep budget.
  for (auto it = ps.scopes.begin(); it != ps.scopes.end(); ++it) {
    if (!it->second.doomed && it->second.opened_ns < drop_before.count()) {
      doom_scope(p, ps, it, EvictReason::Drop);
      ++n;
    }
  }
  return n;
}

void Store::doom_scope(PrincipalId p, PState& ps, std::map<ScopeId, ScopeRec>::iterator it, EvictReason why) {
  ScopeRec& r = it->second;
  if (r.doomed) return;
  r.doomed = true;
  r.doom_why = why;
  ps.lru.erase(r.seq);
  ps.by_open.erase(r.epoch);
  ps.doomed.insert(it->first);
  persist_drain(p, it->first, r);  // a crash from here on never resumes its blocks
  doomed_principals_.insert(p);
  doomed_blocks_ += r.keys.size();
}

// ---- drop_before by opened_at, incremental; cap-cut convergence ---------------------------------
void Store::set_drop_cutoff(PrincipalId p, std::int64_t cutoff_ns) {
  auto [it, inserted] = drop_cutoff_.emplace(p, cutoff_ns);
  if (!inserted && cutoff_ns > it->second) it->second = cutoff_ns;
  sweep_pending_ = true;  // also on an unchanged value: a straggler committed into a dead scope is swept again
}

std::optional<std::int64_t> Store::drop_cutoff(PrincipalId p) const {
  auto it = drop_cutoff_.find(p);
  if (it == drop_cutoff_.end()) return std::nullopt;
  return it->second;
}

std::size_t Store::drop_scope_blocks(PState& ps, ScopeRec& r, std::size_t budget, EvictReason why,
                                     std::int64_t* credit) {
  std::size_t n = 0;
  std::size_t visited = 0;
  const std::size_t scan_cap = budget * 8 + 64;
  auto more = [&] { return n < budget && (credit == nullptr || *credit > 0); };
  auto rm = [&](const KeyHash& k) {
    const std::uint64_t len = remove_key(ps, r, k, why);
    if (credit) *credit -= static_cast<std::int64_t>(len);
    ++n;
  };
  // The cursor always names the next key to scan (a capped call resumes after what it scanned, or a long
  // chain never progresses), and r.drop_noleaf counts the non-leaves scanned in a row, across calls, since the
  // scope last gained or lost a key (remove_key and commit_block reset it). Each key is counted once per
  // wrap, so reaching keys.size() means a whole wrap found no leaf.
  auto it = r.keys.lower_bound(r.drop_cursor);
  while (more() && !r.keys.empty() && r.drop_noleaf < r.keys.size()) {
    if (it == r.keys.end()) it = r.keys.begin();
    if (++visited > scan_cap) break;
    KeyHash cur = it->first;
    if (r.children.find(parent_prefix(cur)) != r.children.end()) {  // has a child: not a leaf yet
      ++r.drop_noleaf;
      ++it;
      r.drop_cursor = it == r.keys.end() ? KeyHash{} : it->first;
      continue;
    }
    for (;;) {  // remove the leaf, then its parent if that became a leaf, while the budget lasts
      const KeyHash par = blocks_.at(r.keys.at(cur)).parent;
      rm(cur);
      if (!more() || parent_is_root(par)) break;
      auto pk = r.keys.lower_bound(par);
      if (pk == r.keys.end() || parent_prefix(pk->first) != par) break;
      cur = pk->first;
      if (r.children.find(parent_prefix(cur)) != r.children.end()) break;
    }
    r.drop_cursor = cur;
    it = r.keys.lower_bound(r.drop_cursor);
  }
  if (more() && !r.keys.empty() && r.drop_noleaf >= r.keys.size()) {
    // No leaf anywhere (a cyclic child index from prefix-shared keys), proven by a whole wrap, never by a capped
    // scan: the scope is dead and unreadable, so the chain order no longer matters; remove in key order.
    while (more() && !r.keys.empty()) rm(r.keys.begin()->first);
  }
  return n;
}

// Doomed scopes (expired by TTL or dropped): their blocks, leaf first, under the budget.
std::size_t Store::sweep_doomed(std::size_t max_blocks) {
  std::size_t used = 0;
  while (!doomed_principals_.empty()) {
    const PrincipalId p = *doomed_principals_.begin();
    auto pit = principals_.find(p);
    if (pit == principals_.end() || pit->second.doomed.empty()) {
      doomed_principals_.erase(doomed_principals_.begin());
      continue;
    }
    if (used >= max_blocks || credit_ <= 0) break;  // record erasures count too
    PState& ps = pit->second;
    auto sit = ps.scopes.find(*ps.doomed.begin());
    MIRACACHE_CHECK(sit != ps.scopes.end() && sit->second.doomed);
    if (!sit->second.keys.empty()) {

      used += drop_scope_blocks(ps, sit->second, max_blocks - used, sit->second.doom_why, &credit_);
    }
    if (!sit->second.keys.empty()) break;  // budget spent inside this scope: resume here next turn
    evict_scope(ps, sit, sit->second.doom_why);  // no keys left: only the record goes
    ++used;                                      // an erased record counts against the turn budget
  }
  return used;
}

// Pressure: global LRU leaves, block level, from high_pct down to low_pct.
std::size_t Store::sweep_pressure(std::size_t max_blocks) {
  if (!pressure_) return 0;
  const std::uint64_t cap = std::uint64_t{slab_.total_runs()} * arena_.config().run_bytes;
  std::uint64_t used_bytes = used_hint_ ? *used_hint_ : total_used();  // once per tick
  std::size_t used = 0;
  while (used < max_blocks && credit_ > 0) {
    if (static_cast<unsigned __int128>(used_bytes) * 100 <= static_cast<unsigned __int128>(cap) * low_pct_) {
      pressure_ = false;
      return used;
    }
    auto slot = ev_lru_.oldest();
    if (!slot) {  // nothing evictable (leased, in flight, interior): stop; the next tick looks again
      pressure_ = false;
      return used;
    }
    const BlockInfo& b = blocks_.at(*slot);
    PState& ps = principals_.at(b.principal);
    const std::uint64_t len = remove_key(ps, ps.scopes.at(b.scope), b.key, EvictReason::Pressure);
    used_bytes -= len;  // an evictable block is unleased, so its bytes are freed, not zombied
    credit_ -= static_cast<std::int64_t>(len);
    ++used;
  }
  return used;
}

std::size_t Store::sweep_step(std::size_t max_blocks) {
  refill_credit(clock_.now());
  // The turn's block budget is shared with the evictions the put path did since the last turn.
  const std::size_t spent = turn_used_;
  turn_used_ = 0;
  if (!sweep_pending()) return 0;
  max_blocks = std::min(max_blocks, sweep_blocks_ > spent ? sweep_blocks_ - spent : std::size_t{0});
  if (credit_ <= 0 || max_blocks == 0) return 0;
  std::size_t used = sweep_doomed(max_blocks);
  if (sweep_pending_) used += sweep_flagged(max_blocks - used);
  if (used > 0 && pressure_ && used_hint_) used_hint_ = total_used();  // earlier work freed bytes: do not over-evict
  used += sweep_pressure(max_blocks - used);
  return used;
}

// drop_before-dead scopes (a bounded scan with a resume cursor), then principals over a cap cut.
std::size_t Store::sweep_flagged(std::size_t max_blocks) {
  constexpr std::size_t kScanScopes = 256;
  std::size_t used = 0;
  std::size_t scanned = 0;
  auto pit = principals_.lower_bound(sweep_started_ ? sweep_p_ : PrincipalId{0});
  bool pass_done = false;
  while (true) {
    if (pit == principals_.end()) {
      pass_done = true;
      break;
    }
    if (scanned >= kScanScopes || used >= max_blocks || credit_ <= 0) {
      if (!(sweep_started_ && pit->first == sweep_p_)) {  // resume at this principal, not at the one before
        sweep_started_ = true;
        sweep_p_ = pit->first;
        sweep_s_ = ScopeId{};
      }
      break;
    }
    PState& ps = pit->second;
    if (drop_cutoff_.find(pit->first) == drop_cutoff_.end()) {
      ++pit;
      sweep_started_ = false;
      continue;
    }
    auto sit = sweep_started_ && pit->first == sweep_p_ ? ps.scopes.lower_bound(sweep_s_) : ps.scopes.begin();
    while (sit != ps.scopes.end() && scanned < kScanScopes && used < max_blocks && credit_ > 0) {
      ++scanned;
      if (sit->second.doomed || !dead(pit->first, sit->second)) {  // doomed ones are sweep_doomed's
        ++sit;
        continue;
      }
      used += drop_scope_blocks(ps, sit->second, max_blocks - used, EvictReason::Drop, &credit_);
      if (sit->second.keys.empty()) {
        auto nxt = std::next(sit);
        evict_scope(ps, sit, EvictReason::Drop);  // no keys left: only the record goes
        sit = nxt;
      } else {
        break;  // budget spent inside this scope: resume here
      }
    }
    if (sit != ps.scopes.end()) {
      sweep_started_ = true;
      sweep_p_ = pit->first;
      sweep_s_ = sit->first;
      break;
    }
    ++pit;
    sweep_started_ = false;
  }
  // Principals over their cap (a cap cut): their own LRU leaves, oldest first.
  for (auto& [p, ps] : principals_) {
    if (used >= max_blocks || credit_ <= 0) break;
    const std::uint64_t cap = policy_for(p).max_bytes;
    while (used < max_blocks && credit_ > 0 && ps.bytes + ps.zombie_bytes > cap) {
      auto slot = ps.ev.oldest();
      if (!slot) break;  // only leased / zombie / non-leaf blocks left: nothing evictable now
      const BlockInfo& b = blocks_.at(*slot);
      credit_ -= static_cast<std::int64_t>(remove_key(ps, ps.scopes.at(b.scope), b.key, EvictReason::Cap));
      ++used;
    }
  }
  pass_work_ += used;
  if (pass_done) {  // a whole pass: if it found nothing to do, the sweep is idle until re-armed
    if (pass_work_ == 0) sweep_pending_ = false;
    pass_work_ = 0;
    sweep_started_ = false;
  }
  return used;
}

void Store::on_session_end(SessionId session) {
  std::vector<LeaseId> ids;
  for (const auto& [id, l] : leases_)
    if (l.session == session) ids.push_back(id);
  for (LeaseId id : ids) drop_lease(leases_.find(id));
}

std::uint64_t Store::evict(std::uint64_t bytes_wanted) {
  std::uint64_t freed = 0;
  while (freed < bytes_wanted) {
    auto slot = ev_lru_.oldest();  // unleased leaves only: no rescan
    if (!slot) break;
    const BlockInfo& b = blocks_.at(*slot);
    PState& ps = principals_.at(b.principal);
    freed += remove_key(ps, ps.scopes.at(b.scope), b.key, EvictReason::Pressure);
  }
  return freed;
}

std::uint64_t Store::evict_one_run(PrincipalId p, const ScopeId& s, std::span<const KeyHash> protect) {
  const std::set<std::uint64_t> prot = protected_slots(p, s, protect);
  const std::set<std::uint64_t>* best = nullptr;
  std::uint64_t best_newest = 0;
  for (const auto& [run, slots] : run_blocks_) {
    if (slab_.run_used(run) != slots.size()) continue;  // holds in-flight (WRITING) blocks too
    std::uint64_t newest = 0;
    bool ok = true;
    for (std::uint64_t slot : slots) {
      const BlockInfo& b = blocks_.at(slot);
      if (b.zombie || b.leases > 0 || prot.count(slot)) { ok = false; break; }
      const ScopeRec& r = principals_.at(b.principal).scopes.at(b.scope);
      if (auto c = r.children.find(parent_prefix(b.key)); c != r.children.end())
        for (const KeyHash& ch : c->second)  // a child outside the run would be orphaned
          if (!slots.count(r.keys.at(ch))) { ok = false; break; }
      if (!ok) break;
      newest = std::max(newest, lru_.seq_of(slot));
    }
    if (ok && (best == nullptr || newest < best_newest)) best = &slots, best_newest = newest;
  }
  if (best == nullptr) return 0;
  std::set<std::uint64_t> todo = *best;  // remove_key edits run_blocks_
  std::uint64_t freed = 0;
  while (!todo.empty()) {
    std::vector<std::uint64_t> leaves;  // tails first: children go before their parents
    for (std::uint64_t slot : todo) {
      const BlockInfo& b = blocks_.at(slot);
      const ScopeRec& r = principals_.at(b.principal).scopes.at(b.scope);
      if (r.children.find(parent_prefix(b.key)) == r.children.end()) leaves.push_back(slot);
    }
    if (leaves.empty()) leaves.assign(todo.begin(), todo.end());  // prefix-sharing cycle: all go anyway
    for (std::uint64_t slot : leaves) {
      const BlockInfo& b = blocks_.at(slot);
      PState& ps = principals_.at(b.principal);
      freed += remove_key(ps, ps.scopes.at(b.scope), b.key, EvictReason::Pressure);
      todo.erase(slot);
    }
  }
  return freed;
}

void Store::evict_scope(PState& ps, std::map<ScopeId, ScopeRec>::iterator it, EvictReason why) {
  count_evict(why, it->second.bytes, it->second.keys.size());
  for (const auto& [k, slot] : it->second.keys) drop_block(slot);
  ps.bytes -= it->second.bytes;
  if (it->second.doomed) {
    doomed_blocks_ -= it->second.keys.size();
    ps.doomed.erase(it->first);
  } else {
    ps.lru.erase(it->second.seq);
    ps.by_open.erase(it->second.epoch);
  }
  persist_close(it->second);
  ps.scopes.erase(it);
}

void Store::drop_lease(std::map<LeaseId, Lease>::iterator it) {
  // Blocks became evictable; a principal still over a cap cut converges again. A lease comes from one lookup
  // in one scope, so its slots share one principal: checking each principal when its run of slots ends keeps this
  // hot path allocation-free and stays exact if slots ever mix principals (a principal's accounting only
  // changes through its own slots, and its last slot always ends a run).
  auto rearm = [this](PrincipalId p) {
    auto pit = principals_.find(p);
    if (pit != principals_.end() && pit->second.bytes + pit->second.zombie_bytes > policy_for(p).max_bytes) sweep_pending_ = true;
  };
  bool any = false;
  PrincipalId run_p = 0;
  for (std::uint64_t slot : it->second.slots) {
    auto b = blocks_.find(slot);
    MIRACACHE_CHECK(b != blocks_.end() && b->second.leases > 0);
    if (any && b->second.principal != run_p) rearm(run_p);
    any = true;
    run_p = b->second.principal;
    if (b->second.leases == 1 && !b->second.zombie) {
      PState& lp = principals_.at(b->second.principal);
      lp.leased_bytes -= b->second.e.len;
      lp.scopes.at(b->second.scope).leased_bytes -= b->second.e.len;
    }
    if (--b->second.leases == 0 && b->second.zombie) {
      principals_.at(b->second.principal).zombie_bytes -= b->second.e.len;
      slab_.free(b->second.e);
      forget_block(b);
    } else if (b->second.leases == 0 && !b->second.zombie) {
      refresh_evictable(slot);
    }
  }
  if (any) rearm(run_p);
  if (auto sl = session_leases_.find(it->second.session); sl != session_leases_.end() && --sl->second == 0)
    session_leases_.erase(sl);
  lease_expiry_.erase({it->second.expiry.count(), it->first});
  leases_.erase(it);
}

std::size_t Store::drain_doomed(PrincipalId p, PState& ps, std::size_t budget) {
  std::size_t n = 0;
  // drop_before-dead scopes are the oldest opened: doom them (O(1) each) so they drain with the others.
  if (drop_cutoff_.count(p)) {
    for (std::size_t scanned = 0; scanned < kSweepBlocks && !ps.by_open.empty(); ++scanned) {
      auto sit = ps.scopes.find(ps.by_open.begin()->second);
      if (!dead(p, sit->second)) break;
      doom_scope(p, ps, sit, EvictReason::Drop);
    }
  }
  while (n < budget && !ps.doomed.empty()) {
    auto sit = ps.scopes.find(*ps.doomed.begin());
    MIRACACHE_CHECK(sit != ps.scopes.end() && sit->second.doomed);
    const EvictReason why = sit->second.doom_why;
    if (!sit->second.keys.empty()) n += drop_scope_blocks(ps, sit->second, budget - n, why);
    if (!sit->second.keys.empty()) break;
    evict_scope(ps, sit, why);
    ++n;
  }
  return n;
}

std::uint32_t Store::drain_retry_ms(PrincipalId p, const ScopeId& s) const {
  auto pit = principals_.find(p);
  if (pit == principals_.end()) return 0;
  auto sit = pit->second.scopes.find(s);
  if (sit == pit->second.scopes.end() || sit->second.keys.empty()) return 0;
  if (!dead(p, sit->second) && !expired(p, sit->second, clock_.now())) return 0;
  // One turn per sweep_blocks_per_turn blocks; a turn is about 100 ms (the node's tick). At least 50 ms, at most 5 s.
  const std::uint64_t turns = (sit->second.keys.size() + sweep_blocks_ - 1) / sweep_blocks_;
  return static_cast<std::uint32_t>(std::clamp<std::uint64_t>(turns * 100, 50, 5000));
}

Status Store::ensure_scope_for_root_put(PrincipalId p, const ScopeId& s, Nanos now) {
  const PrincipalPolicy& pol = policy_for(p);
  PState& ps = principals_[p];
  std::size_t evicted = 0;  // charged to the turn budget on every exit
  const std::uint64_t bytes_before = ps.bytes;
  struct Charge {
    Store& st;
    PState& ps;
    std::uint64_t before;
    std::size_t& n;
    ~Charge() { st.charge_call(n, before > ps.bytes ? before - ps.bytes : 0); }
  } charge{*this, ps, bytes_before, evicted};
  auto it = ps.scopes.find(s);
  if (it != ps.scopes.end() && (dead(p, it->second) || expired(p, it->second, now))) {
    // Reopen of a dropped (drop_before) or expired (idle TTL, max_ttl) scope that is not yet reaped: the old
    // blocks go (bounded per call, leased ones turn ZOMBIE) and the put is refused (drain_retry_ms says when to come
    // back) until none are left; then a fresh record with a new opened_at replaces it.
    ScopeRec& old = it->second;
    const EvictReason why = old.doomed ? old.doom_why : dead(p, old) ? EvictReason::Drop : EvictReason::Ttl;
    evicted += drop_scope_blocks(ps, old, kSweepBlocks, why);
    if (!old.keys.empty()) {
      if (!old.doomed && why == EvictReason::Ttl) doom_scope(p, ps, it, why);  // out of the LRU; the sweep finishes it
      return Error{ErrorCode::ResourceExhausted, "store: scope is being dropped"};
    }
    evict_scope(ps, it, why);
    it = ps.scopes.end();
  }
  if (it == ps.scopes.end()) {
    // Bounded. Live scopes (the LRU) are counted, so a doomed one no longer holds a slot. A victim that fits in
    // what is left of this call's 64-block budget goes whole; a larger one is only doomed (O(1)): it leaves the LRU
    // and the sweep frees its blocks under the one budget.
    std::size_t budget = kSweepBlocks;
    while (ps.lru.size() >= pol.max_scopes) {
      if (ps.lru.empty()) return Error{ErrorCode::ResourceExhausted, "store: max_scopes"};
      auto victim = ps.scopes.find(ps.lru.begin()->second);
      const std::size_t nkeys = victim->second.keys.size();
      if (nkeys <= budget) {
        budget -= nkeys;
        evicted += nkeys;
        evict_scope(ps, victim, EvictReason::Cap);
      } else {
        doom_scope(p, ps, victim, EvictReason::Cap);
      }
    }
    // A scope that cannot have a record is refused, never opened in memory only: after a crash its blocks would
    // be indistinguishable from those of another principal's scope with the same scope_id.
    std::uint32_t rec = ScopeTable::kNone;
    if (ScopeTable* t = arena_.scope_table()) {
      if (p == 0 || p > 0xffffffffu) return Error{ErrorCode::ResourceExhausted, "store: principal id cannot be persisted"};
      rec = t->alloc();
      if (rec == ScopeTable::kNone) return Error{ErrorCode::ResourceExhausted, "store: scope table full"};
    }
    it = ps.scopes.emplace(s, ScopeRec{}).first;
    it->second.rec_slot = rec;
    it->second.seq = ps.next_seq++;
    it->second.epoch = ++epoch_;
    ps.by_open.emplace(it->second.epoch, s);
    it->second.opened_ns = now.count();
    if (mx_) bump(mx_->scope_opened);
    it->second.last_used_ns = now.count();
    ps.lru.emplace(it->second.seq, s);
    persist_touch(p, s, it->second, true);
    return {};
  }
  ps.lru.erase(it->second.seq);
  it->second.seq = ps.next_seq++;
  it->second.last_used_ns = now.count();
  ps.lru.emplace(it->second.seq, s);
  persist_touch(p, s, it->second);
  return {};
}

Status Store::commit_block(PrincipalId p, const ScopeId& s, const KeyHash& key, const KeyHash& parent,
                           const Extent& e, std::uint64_t stored_len, std::uint64_t begun_epoch) {
  const Nanos now = clock_.now();
  const PrincipalPolicy& pol = policy_for(p);
  auto pit = principals_.find(p);
  if (pit == principals_.end()) return Error{ErrorCode::AccessDenied, "store: no scope"};
  PState& ps = pit->second;
  auto it = ps.scopes.find(s);
  if (it != ps.scopes.end() && !it->second.doomed && expired(p, it->second, now)) {
    doom_scope(p, ps, it, EvictReason::Ttl);  // never a whole-scope free in one call; the sweep frees it
  }
  if (it == ps.scopes.end()) return Error{ErrorCode::AccessDenied, "store: no scope"};
  if (dead(p, it->second)) return Error{ErrorCode::AccessDenied, "store: scope dropped mid-put"};  // drop_before
  if (it->second.epoch > begun_epoch) return Error{ErrorCode::AccessDenied, "store: scope dropped mid-put"};
  const KeyHash pfx = parent_prefix(parent);
  if (!parent_is_root(parent) && prefix_matches(it->second.keys, pfx) != 1)
    return Error{ErrorCode::AccessDenied, "store: parent gone"};  // absent, or ambiguous prefix
  if (it->second.keys.count(key)) return Error{ErrorCode::Aborted, "store: key exists"};
  // Check the quota BEFORE evicting anything: bytes that cannot be reclaimed (this scope,
  // zombies, leased blocks of other scopes) must leave room, else fail without side effects.
  if (ps.bytes + ps.zombie_bytes + e.len > pol.max_bytes) {
    // O(1), never a walk over the blocks (a lookup-latency risk at the cap). Exact: the unleased bytes outside the
    // target scope = (principal bytes - scope bytes) - (principal leased bytes - scope leased bytes), both kept incrementally.
    const std::uint64_t reclaimable = (ps.bytes - it->second.bytes) - (ps.leased_bytes - it->second.leased_bytes);
    if (ps.bytes + ps.zombie_bytes + e.len > pol.max_bytes + reclaimable)
      return Error{ErrorCode::ResourceExhausted, "store: max_bytes"};
  }
  std::size_t evicted_blocks = 0;  // a cap cut must not evict the whole overage in one call
  const std::uint64_t bytes_before = ps.bytes;
  auto full = [&]() -> Status {
    charge_call(evicted_blocks, bytes_before > ps.bytes ? bytes_before - ps.bytes : 0);
    return Error{ErrorCode::ResourceExhausted, "store: max_bytes"};
  };
  if (ps.bytes + ps.zombie_bytes + e.len > pol.max_bytes) {
    // Dead blocks (expired or dropped scopes) go first, inside the same 64-block bound; live scopes only after.
    evicted_blocks += drain_doomed(p, ps, kSweepBlocks);
  }
  while (ps.bytes + ps.zombie_bytes + e.len > pol.max_bytes) {
    if (evicted_blocks >= kSweepBlocks) return full();
    // Oldest scope other than the target.
    auto v = ps.lru.begin();
    if (v != ps.lru.end() && v->second == s) ++v;
    if (v == ps.lru.end()) return full();
    auto victim = ps.scopes.find(v->second);
    // Block granular. A victim that fits in what is left of this call's 64 goes whole (as before);
    // a larger one loses its leaves (tail first) up to the bound and stays, still the oldest, for the next call.
    const std::size_t room = kSweepBlocks - evicted_blocks;
    const std::size_t got = drop_scope_blocks(ps, victim->second, room, EvictReason::Cap);
    evicted_blocks += got;
    if (victim->second.keys.empty()) evict_scope(ps, victim, EvictReason::Cap);
    else if (got == 0) return full();  // no progress possible (no leaf found): do not spin
  }
  charge_call(evicted_blocks, bytes_before > ps.bytes ? bytes_before - ps.bytes : 0);
  ScopeRec& r = it->second;
  BlockInfo b;
  b.e = e;
  b.stored_len = stored_len;
  b.parent = pfx;
  b.key = key;
  b.scope = s;
  b.principal = p;
  MIRACACHE_CHECK(blocks_.emplace(e.gen_slot, b).second);
  run_blocks_[slab_.run_of(e)].insert(e.gen_slot);
  r.keys.emplace(key, e.gen_slot);
  r.drop_noleaf = 0;  // a key inserted behind the drop cursor may be a leaf; never fall back to key order
  r.children[pfx].insert(key);
  lru_.touch(e.gen_slot);
  refresh_evictable(e.gen_slot);
  refresh_prefix(r, pfx);  // the parent is no longer a leaf
  r.bytes += e.len;
  ps.bytes += e.len;
  arena_.state_gen().store(e.gen_slot, proto::BlockState::Committed, e.gen);
  ps.lru.erase(r.seq);
  r.seq = ps.next_seq++;
  r.last_used_ns = now.count();
  ps.lru.emplace(r.seq, s);
  persist_touch(p, s, r);
  return {};
}

bool Store::has_key(PrincipalId p, const ScopeId& s, const KeyHash& key) const {
  auto pit = principals_.find(p);
  if (pit == principals_.end()) return false;
  auto sit = pit->second.scopes.find(s);
  if (sit == pit->second.scopes.end() || expired(p, sit->second, clock_.now()) || dead(p, sit->second)) return false;
  return sit->second.keys.count(key) != 0;
}

std::optional<KeyHash> Store::resolve_parent(PrincipalId p, const ScopeId& s,
                                             std::span<const std::uint8_t, 16> prefix) const {
  auto pit = principals_.find(p);
  if (pit == principals_.end()) return std::nullopt;
  auto sit = pit->second.scopes.find(s);
  if (sit == pit->second.scopes.end() || expired(p, sit->second, clock_.now())) return std::nullopt;
  const auto& keys = sit->second.keys;
  const KeyHash pfx = [&] { KeyHash lo{}; std::copy(prefix.begin(), prefix.end(), lo.begin()); return lo; }();
  if (prefix_matches(keys, pfx) != 1) return std::nullopt;  // none or ambiguous: parent gone
  return keys.lower_bound(pfx)->first;
}

void Store::for_each_block(const std::function<void(const Extent&, std::uint64_t, bool)>& fn) const {
  for (const auto& [slot, b] : blocks_) fn(b.e, b.stored_len, b.zombie);
}

LookupAck Store::lookup(SessionId session, const LookupReq& req) {
  const Nanos now = clock_.now();
  LookupAck ack;
  ack.entries.resize(req.keys.size());
  auto pit = principals_.find(req.principal);
  if (pit == principals_.end()) return ack;
  PState& ps = pit->second;
  auto sit = ps.scopes.find(req.scope);
  if (sit == ps.scopes.end() || expired(req.principal, sit->second, now) || dead(req.principal, sit->second)) return ack;
  ScopeRec& r = sit->second;
  // Per-session lease cap: over the cap the ack is all-MISS with lease 0. A MISS is always
  // valid on wire v0 (the client recomputes), and no hit is ever returned without a lease.
  if (auto sl = session_leases_.find(session);
      sl != session_leases_.end() &&  // no-wrap compare: count >= max (teeth: max + 1)
      std::uint64_t{sl->second} >= std::uint64_t{arena_.config().max_leases_per_session} + (MIRACACHE_TEETH_ON(LeaseCapLax) ? 1u : 0u))
    return ack;
  Lease lease;
  for (std::size_t i = 0; i < req.keys.size(); ++i) {
    auto k = r.keys.find(req.keys[i]);
    if (k == r.keys.end()) continue;
    BlockInfo& b = blocks_.at(k->second);
    if (readable_ && !readable_(b.e.seg)) continue;  // not covered by a registered MR: MISS
    LookupEntry& en = ack.entries[i];
    en.hit = true;
    en.seg_id = b.e.seg;
    en.offset = b.e.off;
    en.stored_len = b.stored_len;
    en.gen = b.e.gen;
    en.gen_slot = b.e.gen_slot;
    if (b.leases++ == 0) ps.leased_bytes += b.e.len, r.leased_bytes += b.e.len;
    lru_.touch(b.e.gen_slot);
    refresh_evictable(b.e.gen_slot);  // leased: not evictable
    lease.slots.push_back(b.e.gen_slot);
  }
  if (lease.slots.empty()) return ack;
  ps.lru.erase(r.seq);
  r.seq = ps.next_seq++;
  r.last_used_ns = now.count();
  ps.lru.emplace(r.seq, req.scope);
  persist_touch(req.principal, req.scope, r);
  LeaseId id;
  do { id = rng_.next_u64(); } while (id == 0 || leases_.count(id));
  lease.session = session;
  lease.granted = now;
  lease.expiry = now + lease_ttl_;
  ack.lease = id;
  ack.lease_expiry = lease.expiry;
  lease_expiry_.emplace(lease.expiry.count(), id);
  leases_.emplace(id, std::move(lease));
  ++session_leases_[session];
  return ack;
}

Expected<Nanos> Store::renew(SessionId session, LeaseId id) {
  const Nanos now = clock_.now();
  auto it = leases_.find(id);
  if (it == leases_.end() || it->second.session != session) return Error{ErrorCode::NotFound, "store: lease"};
  Lease& l = it->second;
  if (l.expiry <= now) {
    drop_lease(it);
    if (mx_) bump(mx_->lease_expired);
    return Error{ErrorCode::NotFound, "store: lease expired"};
  }
  Nanos ne = std::min(now + lease_ttl_, l.granted + lease_max_);
  if (ne > l.expiry) {
    lease_expiry_.erase({l.expiry.count(), id});
    l.expiry = ne;
    lease_expiry_.emplace(ne.count(), id);
  }
  return l.expiry;
}

Status Store::release(SessionId session, LeaseId id) {
  auto it = leases_.find(id);
  if (it == leases_.end() || it->second.session != session) return Error{ErrorCode::NotFound, "store: lease"};
  drop_lease(it);
  return {};
}

void Store::tick() {
  const Nanos now = clock_.now();
  while (!lease_expiry_.empty() && lease_expiry_.begin()->first <= now.count()) {
    drop_lease(leases_.find(lease_expiry_.begin()->second));
    if (mx_) bump(mx_->lease_expired);
  }
  // Reaping at block granularity: an expired scope is only marked here (unlinked, lookups miss); its
  // blocks are freed by the budgeted sweep below. Marking is cheap but capped per tick, the rest next tick.
  constexpr std::size_t kMarkPerTick = 1024;
  std::size_t marked = 0;
  tick_capped_ = false;
  for (auto& [p, ps] : principals_) {
    while (!ps.lru.empty()) {
      auto it = ps.scopes.find(ps.lru.begin()->second);
      if (!reapable(p, it->second, now)) break;
      if (marked >= kMarkPerTick) { tick_capped_ = true; break; }
      doom_scope(p, ps, it, EvictReason::Ttl);
      ++marked;
    }
    while (max_ttl_ > Nanos{0} && !ps.by_open.empty()) {  // older than max_ttl since opened_at: no grace
      auto it = ps.scopes.find(ps.by_open.begin()->second);
      if (now.count() - it->second.opened_ns < max_ttl_.count()) break;
      if (marked >= kMarkPerTick) { tick_capped_ = true; break; }
      doom_scope(p, ps, it, EvictReason::Ttl);
      ++marked;
    }
  }
  used_hint_ = total_used();  // once per tick
  update_pressure();
  const std::size_t swept = sweep_step();
  if (swept > 0) used_hint_ = total_used();  // the gauge reports the state after this turn's work
  if (mx_) {
    if (mx_->occupancy_ratio_ppm) mx_->occupancy_ratio_ppm->set(static_cast<std::int64_t>(occupancy_ppm()));
    if (mx_->evict_backlog_blocks) mx_->evict_backlog_blocks->set(static_cast<std::int64_t>(doomed_blocks_));
  }
  // Drop per-principal state that holds nothing (no scopes, reservations or zombies).
  for (auto it = principals_.begin(); it != principals_.end();) {
    const PState& ps = it->second;
    it = ps.scopes.empty() && ps.inflight == 0 && ps.zombie_bytes == 0 ? principals_.erase(it) : std::next(it);
  }
  used_hint_.reset();
  last_tick_ = now;
}

std::uint64_t Store::zombie_bytes(PrincipalId p) const {
  auto it = principals_.find(p);
  return it == principals_.end() ? 0 : it->second.zombie_bytes;
}
std::uint64_t Store::inflight_bytes(PrincipalId p) const {
  auto it = principals_.find(p);
  return it == principals_.end() ? 0 : it->second.inflight;
}
std::size_t Store::n_session_leases(SessionId s) const {
  auto it = session_leases_.find(s);
  return it == session_leases_.end() ? 0 : it->second;
}

Status Store::reserve_inflight(PrincipalId p, std::uint64_t bytes, const ScopeId* scope,
                               std::span<const KeyHash> protect) {
  const std::uint64_t cap = policy_for(p).max_bytes;
  const Error full{ErrorCode::ResourceExhausted, "store: max_bytes"};
  if (bytes > cap) return full;
  auto it = principals_.find(p);
  if (it == principals_.end()) {
    principals_[p].inflight = bytes;
    return {};
  }
  PState& ps = it->second;
  auto over = [&] {
    const std::uint64_t used = ps.bytes + ps.zombie_bytes + ps.inflight;
    return used > cap || bytes > cap - used;
  };
  if (over()) {  // free the principal's own unleased leaves, LRU first; never others' blocks
    const std::set<std::uint64_t> prot = scope ? protected_slots(p, *scope, protect) : std::set<std::uint64_t>{};
    {  // bytes eviction can never reclaim (zombies, reservations, leased and protected blocks).
       // If even those leave no room, refuse now: evicting would destroy data for nothing.
       // (Ancestors of leased blocks are also stuck; not counted, so this errs towards trying.)
      // Leased bytes are kept incrementally; only the protect set is walked (O(protect)).
      std::uint64_t fixed = ps.zombie_bytes + ps.inflight + ps.leased_bytes;
      for (std::uint64_t slot : prot)
        if (const BlockInfo& b = blocks_.at(slot); b.leases == 0) fixed += b.e.len;
      if (fixed > cap || bytes > cap - fixed) return full;
    }
    std::size_t removed = 0;  // bounded per call; the rest converges through sweep_step()
    const std::uint64_t bytes_before = ps.bytes;
    auto charge = [&] { charge_call(removed, bytes_before > ps.bytes ? bytes_before - ps.bytes : 0); };
    removed += drain_doomed(p, ps, kSweepBlocks);  // dead blocks before any live scope loses data
    while (over()) {
      if (removed >= kSweepBlocks) {
        sweep_pending_ = true;
        charge();
        return full;  // refuse this put; blocks already evicted stay evicted
      }
      auto slot = ps.ev.first_if([&](std::uint64_t sl) { return prot.count(sl) == 0; });
      if (!slot) {
        charge();
        return full;
      }
      const BlockInfo& b = blocks_.at(*slot);
      remove_key(ps, ps.scopes.at(b.scope), b.key, EvictReason::Cap);
      ++removed;
    }
    charge();
  }
  ps.inflight += bytes;
  return {};
}

void Store::release_inflight(PrincipalId p, std::uint64_t bytes) {
  auto it = principals_.find(p);
  MIRACACHE_CHECK(it != principals_.end() && it->second.inflight >= bytes);
  it->second.inflight -= bytes;
}

std::uint32_t Store::put_admit(PrincipalId p, std::uint64_t bytes, int* kind) {
  const PrincipalPolicy& pol = policy_for(p);
  if (pol.put_ops_per_s == 0 && pol.put_bytes_per_s == 0) return 0;
  PState& ps = principals_[p];
  const Nanos now = clock_.now();
  if (std::uint32_t ms = ps.put_ops.admit(pol.put_ops_per_s, 1, false, now)) {
    if (kind) *kind = 0;
    return ms;
  }
  if (std::uint32_t ms = ps.put_bytes.admit(pol.put_bytes_per_s, bytes, true, now)) {
    ps.put_ops.refund(pol.put_ops_per_s, 1);
    if (kind) *kind = 1;
    return ms;
  }
  return 0;
}

void Store::put_unadmit(PrincipalId p, std::uint64_t ops, std::uint64_t bytes) {
  auto it = principals_.find(p);
  if (it == principals_.end()) return;
  const PrincipalPolicy& pol = policy_for(p);
  it->second.put_ops.refund(pol.put_ops_per_s, ops);
  it->second.put_bytes.refund(pol.put_bytes_per_s, bytes);
}

std::size_t Store::n_scopes(PrincipalId p) const {
  auto it = principals_.find(p);
  return it == principals_.end() ? 0 : it->second.scopes.size();
}
std::uint64_t Store::bytes_used(PrincipalId p) const {
  auto it = principals_.find(p);
  return it == principals_.end() ? 0 : it->second.bytes;
}
std::size_t Store::n_zombies() const {
  std::size_t n = 0;
  for (const auto& [slot, b] : blocks_) n += b.zombie;
  return n;
}
bool Store::has_scope(PrincipalId p, const ScopeId& s) const {
  auto it = principals_.find(p);
  return it != principals_.end() && it->second.scopes.count(s) != 0;
}

Status Store::check_invariants() const {
  const auto& sg = arena_.state_gen();
  // UniqueKey + DenyByDefault: every live block is reachable from exactly one scope of
  // its own principal; each scope sits under the principal that created it.
  std::set<std::uint64_t> seen;
  std::uint64_t doomed_total = 0;
  for (const auto& [p, ps] : principals_) {
    std::uint64_t pbytes = 0;
    if (ps.lru.size() + ps.doomed.size() != ps.scopes.size()) return corrupt("lru size");
    if (ps.by_open.size() != ps.lru.size()) return corrupt("open index size");
    std::size_t ndoomed = 0;
    for (const auto& [sid, r] : ps.scopes) {
      if (r.doomed) {
        ++ndoomed;
        if (!ps.doomed.count(sid)) return corrupt("doomed index");
        if (!doomed_principals_.count(p)) return corrupt("doomed principals index");
      } else {
        auto l = ps.lru.find(r.seq);
        if (l == ps.lru.end() || l->second != sid) return corrupt("lru entry");
        auto o = ps.by_open.find(r.epoch);
        if (o == ps.by_open.end() || o->second != sid) return corrupt("open index entry");
        if (!tick_capped_ &&
            r.last_used_ns + policy_for(p).idle_ttl.count() + arena_.config().reap_grace.count() <= last_tick_.count())
          return corrupt("expired scope not reaped");
      }
      std::uint64_t sbytes = 0;
      std::size_t nchild = 0;
      for (const auto& [par, kids] : r.children) {
        if (kids.empty()) return corrupt("chain index: empty child set");
        for (const KeyHash& c : kids) {
          auto ck = r.keys.find(c);
          if (ck == r.keys.end() || blocks_.at(ck->second).parent != par) return corrupt("chain index: stale child");
          ++nchild;
        }
      }
      if (nchild != r.keys.size()) return corrupt("chain index: size");
      for (const auto& [k, slot] : r.keys) {
        if (blocks_.count(slot) && !parent_is_root(blocks_.at(slot).parent) &&
            prefix_matches(r.keys, blocks_.at(slot).parent) == 0)
          return corrupt("NoOrphanTail: committed block without parent");
        if (!lru_.contains(slot)) return corrupt("block LRU missing");
        if (!seen.insert(slot).second) return corrupt("UniqueKey: slot in two keys");
        auto b = blocks_.find(slot);
        if (b == blocks_.end()) return corrupt("scope key without block");
        if (b->second.principal != p) return corrupt("DenyByDefault: foreign block");
        if (b->second.zombie) return corrupt("zombie still mapped");
        if (sg.load(slot) != proto::pack_state_gen(proto::BlockState::Committed, b->second.e.gen))
          return corrupt("mapped block not COMMITTED");
        sbytes += b->second.e.len;
      }
      if (sbytes != r.bytes) return corrupt("scope bytes");
      std::uint64_t slb = 0;
      for (const auto& [k, slot] : r.keys)
        if (const BlockInfo& b = blocks_.at(slot); b.leases > 0) slb += b.e.len;
      if (slb != r.leased_bytes) return corrupt("scope leased bytes");
      pbytes += sbytes;
    }
    if (pbytes != ps.bytes) return corrupt("principal bytes");
    if (ndoomed != ps.doomed.size()) return corrupt("doomed index size");
    for (const auto& [sid, r] : ps.scopes) doomed_total += r.doomed ? r.keys.size() : 0;
    std::uint64_t lb = 0;
    for (const auto& [sid, r] : ps.scopes)
      for (const auto& [k, slot] : r.keys)
        if (const BlockInfo& b = blocks_.at(slot); b.leases > 0) lb += b.e.len;
    if (lb != ps.leased_bytes) return corrupt("leased bytes");
  }
  if (doomed_total != doomed_blocks_) return corrupt("doomed block count");
  // LeaseSafety: lease counts match, leased blocks are neither free nor reused.
  std::map<std::uint64_t, std::uint32_t> counts;
  for (const auto& [id, l] : leases_) {
    if (l.expiry.count() <= last_tick_.count()) return corrupt("NoLeaseLeak: expired lease");
    if (l.expiry > l.granted + lease_max_ceiling_) return corrupt("lease beyond max");
    if (lease_expiry_.count({l.expiry.count(), id}) == 0) return corrupt("lease expiry index");
    for (std::uint64_t slot : l.slots) ++counts[slot];
  }
  for (const auto& [slot, n] : scrub_pins_) counts[slot] += n;  // scrub pins count as leases
  if (lease_expiry_.size() != leases_.size()) return corrupt("lease expiry index size");
  {
    std::map<SessionId, std::uint32_t> per_session;
    for (const auto& [id, l] : leases_) ++per_session[l.session];
    if (per_session != session_leases_) return corrupt("session lease counts");
    std::map<PrincipalId, std::uint64_t> zb;
    for (const auto& [slot, b] : blocks_)
      if (b.zombie) zb[b.principal] += b.e.len;
    for (const auto& [p, ps] : principals_) {
      auto z = zb.find(p);
      if (ps.zombie_bytes != (z == zb.end() ? 0 : z->second)) return corrupt("zombie bytes");
      zb.erase(p);
    }
    for (const auto& [p, n] : zb)
      if (n != 0) return corrupt("zombie bytes without principal");
  }
  if (lru_.size() != seen.size()) return corrupt("block LRU size");
  for (const auto& [slot, b] : blocks_) {
    auto c = counts.find(slot);
    const std::uint32_t want = c == counts.end() ? 0 : c->second;
    if (b.leases != want) return corrupt("LeaseSafety: lease count");
    if (b.zombie) {
      if (b.leases == 0) return corrupt("unleased zombie");
      if (sg.load(slot) != proto::pack_state_gen(proto::BlockState::Zombie, b.e.gen)) return corrupt("zombie state word");
      if (lru_.contains(slot)) return corrupt("zombie in block LRU");
    } else if (!seen.count(slot)) {
      return corrupt("orphan block");
    }
    if (b.leases > 0 && (sg.state(slot) == proto::BlockState::Free || sg.generation(slot) != b.e.gen))
      return corrupt("LeaseSafety: leased block free or reused");
  }
  // Evictable-leaf indexes equal the recomputed set, in lru_ order; run index covers blocks_.
  {
    std::size_t want = 0, per_principal = 0, indexed = 0;
    for (const auto& [slot, b] : blocks_) {
      if (b.zombie) {
        if (ev_lru_.contains(slot)) return corrupt("evictable index: zombie");
        continue;
      }
      auto pit = principals_.find(b.principal);
      if (pit == principals_.end()) return corrupt("evictable index: principal");
      auto sit = pit->second.scopes.find(b.scope);
      if (sit == pit->second.scopes.end()) return corrupt("evictable index: scope");
      const bool ev = b.leases == 0 && sit->second.children.find(parent_prefix(b.key)) == sit->second.children.end();
      if (ev != ev_lru_.contains(slot) || ev != pit->second.ev.contains(slot)) return corrupt("evictable index: membership");
      if (ev && (ev_lru_.seq_of(slot) != lru_.seq_of(slot) || pit->second.ev.seq_of(slot) != lru_.seq_of(slot)))
        return corrupt("evictable index: order");
      want += ev;
    }
    for (const auto& [p, ps] : principals_) per_principal += ps.ev.size();
    if (ev_lru_.size() != want || per_principal != want) return corrupt("evictable index: size");
    for (const auto& [run, slots] : run_blocks_) {
      for (std::uint64_t slot : slots) {
        auto b = blocks_.find(slot);
        if (b == blocks_.end() || slab_.run_of(b->second.e) != run) return corrupt("run index: stale");
      }
      indexed += slots.size();
    }
    if (indexed != blocks_.size()) return corrupt("run index: size");
  }
  return {};
}

// ---- Scope records and the warm-restart hooks ----
std::uint64_t Store::wall_ms(std::int64_t clock_ns) const {
  const __int128 w = static_cast<__int128>(clock_ns) + wall_offset_ns_;
  return w <= 0 ? 0 : static_cast<std::uint64_t>(w / 1'000'000);
}

// A doomed scope keeps its record, marked DRAINING, until its last block is gone (evict_scope releases it). The restart
// scan resumes no DRAINING scope and discards its blocks, and still counts it as an owner of its scope_id, so blocks
// of another principal's scope with the same scope_id are never attributed to the wrong owner.
void Store::persist_drain(PrincipalId p, const ScopeId& s, ScopeRec& r) {
  ScopeTable* t = arena_.scope_table();
  if (t == nullptr || r.rec_slot == ScopeTable::kNone) return;
  proto::ScopeRecord rec;
  rec.principal_id = static_cast<std::uint32_t>(p);
  rec.mode = proto::kScopeModeImplicit;
  rec.state = proto::kScopeDraining;
  std::copy(s.begin(), s.end(), rec.scope_id.begin());
  rec.opened_at_ms = wall_ms(r.opened_ns);
  rec.last_used_ms = wall_ms(r.last_used_ns);
  rec.expires_at_ms = rec.last_used_ms;
  t->write(r.rec_slot, rec);
}

void Store::persist_touch(PrincipalId p, const ScopeId& s, ScopeRec& r, bool force) {
  ScopeTable* t = arena_.scope_table();
  if (t == nullptr || r.rec_slot == ScopeTable::kNone || r.doomed) return;
  // spec 6.1: last_used may be written back lazily (LRU order after a crash is approximate, never unsafe).
  if (!force && r.last_used_ns - r.rec_used_ns < 1'000'000'000) return;
  proto::ScopeRecord rec;
  rec.principal_id = static_cast<std::uint32_t>(p);
  rec.mode = proto::kScopeModeImplicit;
  rec.state = proto::kScopeOpen;
  std::copy(s.begin(), s.end(), rec.scope_id.begin());
  rec.opened_at_ms = wall_ms(r.opened_ns);
  rec.last_used_ms = wall_ms(r.last_used_ns);
  rec.expires_at_ms = rec.last_used_ms + static_cast<std::uint64_t>(policy_for(p).idle_ttl.count() / 1'000'000);
  t->write(r.rec_slot, rec);
  r.rec_used_ns = r.last_used_ns;
}

void Store::persist_close(ScopeRec& r) {
  ScopeTable* t = arena_.scope_table();
  if (t == nullptr || r.rec_slot == ScopeTable::kNone) return;
  t->release(r.rec_slot);
  r.rec_slot = ScopeTable::kNone;
}

std::size_t Store::n_persisted_scopes() const {
  std::size_t n = 0;
  for (const auto& [p, ps] : principals_)
    for (const auto& [s, r] : ps.scopes) n += r.rec_slot != ScopeTable::kNone;
  return n;
}

void Store::restore_scopes(std::vector<RestoredScope> v) {
  auto key = [](const RestoredScope& x) { return std::make_pair(x.principal, x.scope); };
  // A wall clock that stepped back during the downtime puts the persisted times in the future, which would extend the
  // idle TTL and max_ttl by the skew: never later than now.
  const std::int64_t now_ns = clock_.now().count();
  for (auto& x : v) x.opened_ns = std::min(x.opened_ns, now_ns), x.last_used_ns = std::min(x.last_used_ns, now_ns);
  std::sort(v.begin(), v.end(), [&](const RestoredScope& a, const RestoredScope& b) {
    return a.opened_ns != b.opened_ns ? a.opened_ns < b.opened_ns : key(a) < key(b);
  });
  for (const auto& x : v) {  // epochs (and so by_open) in opened_at order
    PState& ps = principals_[x.principal];
    auto [it, inserted] = ps.scopes.emplace(x.scope, ScopeRec{});
    MIRACACHE_CHECK(inserted);
    ScopeRec& r = it->second;
    r.epoch = ++epoch_;
    ps.by_open.emplace(r.epoch, x.scope);
    r.opened_ns = x.opened_ns;
    r.last_used_ns = x.last_used_ns;
    r.rec_slot = x.rec_slot;
    r.rec_used_ns = x.last_used_ns;
  }
  std::sort(v.begin(), v.end(), [&](const RestoredScope& a, const RestoredScope& b) {
    return a.last_used_ns != b.last_used_ns ? a.last_used_ns < b.last_used_ns : key(a) < key(b);
  });
  for (const auto& x : v) {  // the per-principal LRU in last_used order
    PState& ps = principals_.at(x.principal);
    ScopeRec& r = ps.scopes.at(x.scope);
    r.seq = ps.next_seq++;
    ps.lru.emplace(r.seq, x.scope);
  }
  sweep_pending_ = true;  // a principal over a cap (or a drop_before loaded later) converges through sweep_step
}

void Store::restore_block(PrincipalId p, const ScopeId& s, const KeyHash& key, const KeyHash& parent_pfx,
                          const Extent& e, std::uint64_t stored_len) {
  PState& ps = principals_.at(p);
  ScopeRec& r = ps.scopes.at(s);
  MIRACACHE_CHECK(!r.keys.count(key));
  BlockInfo b;
  b.e = e;
  b.stored_len = stored_len;
  b.parent = parent_pfx;
  b.key = key;
  b.scope = s;
  b.principal = p;
  MIRACACHE_CHECK(blocks_.emplace(e.gen_slot, b).second);
  run_blocks_[slab_.run_of(e)].insert(e.gen_slot);
  r.keys.emplace(key, e.gen_slot);
  r.children[parent_pfx].insert(key);
  lru_.touch(e.gen_slot);
  refresh_evictable(e.gen_slot);
  refresh_prefix(r, parent_pfx);
  r.bytes += e.len;
  ps.bytes += e.len;
  arena_.state_gen().store(e.gen_slot, proto::BlockState::Committed, e.gen);
}

void Store::for_each_owned_block(const std::function<void(const Extent&, std::uint64_t, bool, PrincipalId, const ScopeId&,
                                                          const KeyHash&)>& fn) const {
  for (const auto& [slot, b] : blocks_) fn(b.e, b.stored_len, b.zombie, b.principal, b.scope, b.key);
}

void Store::for_each_scope(const std::function<void(PrincipalId, const ScopeId&, bool)>& fn) const {
  for (const auto& [p, ps] : principals_)
    for (const auto& [s, r] : ps.scopes) fn(p, s, r.doomed);
}

}  // namespace miracache::store
