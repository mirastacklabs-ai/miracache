// SPDX-License-Identifier: Apache-2.0
// Reclaim helpers for the store: the per-principal INVALIDATE token bucket and
// the block LRU used by the evictor. Pure data structures; time comes from the caller.
#pragma once

#include <algorithm>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <utility>

#include "util/clock.h"

namespace miracache::store {

// Integer token bucket: capacity = burst = rate_per_s tokens, refilled continuously.
// rate_per_s == 0 means unlimited.
class TokenBucket {
 public:
  bool take(std::uint32_t rate_per_s, Nanos now) {
    if (rate_per_s == 0) return true;
    constexpr std::uint64_t kOne = 1'000'000'000;  // one token, in nano-tokens
    const std::uint64_t cap = std::uint64_t{rate_per_s} * kOne;
    if (!init_) {
      init_ = true;
      tokens_ = cap;
      last_ns_ = now.count();
    } else {
      const std::int64_t el = now.count() - last_ns_;
      if (el >= 1'000'000'000) {
        tokens_ = cap;
      } else if (el > 0) {
        tokens_ = std::min<std::uint64_t>(cap, tokens_ + static_cast<std::uint64_t>(el) * rate_per_s);
      }
      if (el > 0) last_ns_ = now.count();
    }
    if (tokens_ < kOne) return false;
    tokens_ -= kOne;
    return true;
  }

 private:
  bool init_ = false;
  std::uint64_t tokens_ = 0;
  std::int64_t last_ns_ = 0;
};

// Put admission bucket: `rate` units per second, burst = one second's worth, refilled
// continuously from the caller's clock. rate == 0 means unlimited. With `allow_debt` a cost is admitted while the
// balance is positive and the balance may go negative, so a cost larger than one second's budget is still
// admitted once the debt is repaid; without it the cost must fit the balance. Not used for INVALIDATE.
class PutBucket {
 public:
  // 0 = admitted (and charged). Otherwise the milliseconds until the same cost would be admitted (>= 1).
  std::uint32_t admit(std::uint64_t rate, std::uint64_t cost, bool allow_debt, Nanos now) {
    if (rate == 0) return 0;
    refill(rate, now);
    const Wide need = allow_debt ? Wide{1} : Wide{cost} * kUnit;
    if (tokens_ >= need) {
      tokens_ -= Wide{cost} * kUnit;
      return 0;
    }
    const Wide per_ms = Wide{rate} * 1'000'000;
    const Wide ms = ((need - tokens_) + per_ms - 1) / per_ms;
    return ms > 0xFFFFFFFFu ? 0xFFFFFFFFu : static_cast<std::uint32_t>(ms < 1 ? 1 : ms);
  }
  // Returns a charge that was admitted but not used (the put was refused later).
  void refund(std::uint64_t rate, std::uint64_t cost) {
    if (rate == 0 || !init_) return;
    tokens_ += Wide{cost} * kUnit;
    const Wide cap = Wide{rate} * kUnit;
    if (tokens_ > cap) tokens_ = cap;
  }

 private:
  using Wide = __int128;
  static constexpr Wide kUnit = 1'000'000'000;  // one unit, in nano-units
  void refill(std::uint64_t rate, Nanos now) {
    const Wide cap = Wide{rate} * kUnit;
    if (!init_) {
      init_ = true;
      tokens_ = cap;
      last_ns_ = now.count();
      return;
    }
    const std::int64_t el = now.count() - last_ns_;
    if (el > 0) {
      tokens_ += Wide{el} * rate;
      last_ns_ = now.count();
    }
    if (tokens_ > cap) tokens_ = cap;  // also when the rate was lowered
  }
  bool init_ = false;
  Wide tokens_ = 0;  // nano-units; negative = debt
  std::int64_t last_ns_ = 0;
};

// Recency order over block slots, oldest first.
class BlockLru {
 public:
  void touch(std::uint64_t slot) {
    erase(slot);
    const std::uint64_t s = next_++;
    seq_[slot] = s;
    order_.emplace(s, slot);
  }
  void erase(std::uint64_t slot) {
    auto it = seq_.find(slot);
    if (it == seq_.end()) return;
    order_.erase({it->second, slot});
    seq_.erase(it);
  }
  // Recency position of a slot (0 = absent); insert_at places a slot at a given position, so a
  // sub-index (leaf-only) keeps the order of the full LRU.
  std::uint64_t seq_of(std::uint64_t slot) const {
    auto it = seq_.find(slot);
    return it == seq_.end() ? 0 : it->second;
  }
  void insert_at(std::uint64_t slot, std::uint64_t seq) {
    erase(slot);
    seq_[slot] = seq;
    order_.emplace(seq, slot);
  }
  // Oldest slot, if any.
  std::optional<std::uint64_t> oldest() const {
    if (order_.empty()) return std::nullopt;
    return order_.begin()->second;
  }
  bool contains(std::uint64_t slot) const { return seq_.count(slot) != 0; }
  std::size_t size() const { return seq_.size(); }
  // Oldest slot satisfying `pred`.
  template <class Pred>
  std::optional<std::uint64_t> first_if(Pred pred) const {
    for (const auto& [s, slot] : order_)
      if (pred(slot)) return slot;
    return std::nullopt;
  }

 private:
  std::uint64_t next_ = 1;
  std::map<std::uint64_t, std::uint64_t> seq_;  // slot -> seq
  std::set<std::pair<std::uint64_t, std::uint64_t>> order_;
};

}  // namespace miracache::store
