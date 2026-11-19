// SPDX-License-Identifier: Apache-2.0
// Rate limit for a WARN line that can repeat on a hot path (review s9 K04/K10): the first event of a key is logged at
// once, then at most one line per `interval` per key; the events dropped in between are counted and handed to the next
// line that passes (log them as "suppressed"). Time comes from the caller's Clock (spec 14.3). At most `max_keys` keys
// are tracked; the events of further keys share one overflow key, so a flood of distinct keys stays bounded too.
// L09 (review s9b): a new key that finds the table full first evicts the stale slots, so the keys of later principals
// get their own slot again. Stale: the slot's interval is over and no dropped event is pending (forgetting it loses
// nothing: its next event would pass with 0), or the key has been idle a whole further interval with dropped events
// pending (a key that never comes back must not hold its slot forever). While the table stays full the sweep runs at
// most once per earliest possible expiry, not per event.
// R11 (review s11): the dropped count of an evicted slot is not lost: it moves to the overflow slot, whose next line
// carries it, so the "suppressed" counts the lines report add up to every dropped event. The overflow slot does not
// count against `max_keys` (a new key that freed a slot gets it).
// Not thread-safe: the owner serializes the calls (its event-loop thread or a mutex).
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include "util/clock.h"

namespace miracache {

class LogLimiter {
 public:
  explicit LogLimiter(Nanos interval, std::size_t max_keys = 256) : interval_(interval), max_keys_(max_keys) {}

  // nullopt: drop this event (counted). Otherwise log it now; the value is the number of events of this key dropped
  // since the last line that passed (0 on the first one).
  std::optional<std::uint64_t> admit(const std::string& key, Nanos now) {
    auto it = slots_.find(key);
    if (it == slots_.end()) {
      if (own_keys() >= max_keys_) evict_stale(now);
      const std::string& k = own_keys() < max_keys_ ? key : kOverflow;
      it = slots_.try_emplace(k).first;
    }
    Slot& s = it->second;
    if (s.seen && now < s.next) {
      ++s.dropped;
      return std::nullopt;
    }
    s.seen = true;
    s.next = now + interval_;
    const std::uint64_t d = s.dropped;
    s.dropped = 0;
    return d;
  }
  std::size_t keys() const { return slots_.size(); }

 private:
  struct Slot {
    bool seen = false;
    Nanos next{0};
    std::uint64_t dropped = 0;
  };
  Nanos stale_at(const Slot& s) const { return s.dropped == 0 ? s.next : s.next + interval_; }
  std::size_t own_keys() const { return slots_.size() - slots_.count(kOverflow); }
  // L09. A slot's stale time only moves later (a drop: next + interval; a pass: next >= now + interval) and a new slot's
  // is at least now + interval, so while the table stays full nothing turns stale before `sweep_at_`.
  void evict_stale(Nanos now) {
    if (now < sweep_at_) return;
    Nanos earliest = now + interval_;
    std::uint64_t moved = 0;  // R11: the dropped events of the evicted slots
    for (auto it = slots_.begin(); it != slots_.end();) {
      const Nanos at = stale_at(it->second);
      if (now >= at) {
        moved += it->second.dropped;
        it = slots_.erase(it);
        continue;
      }
      if (at < earliest) earliest = at;
      ++it;
    }
    if (moved > 0) {  // the overflow slot's next line reports them (a new one may pass at once: next = now)
      auto [o, fresh] = slots_.try_emplace(kOverflow);
      if (fresh) {
        o->second.seen = true;
        o->second.next = now;  // stale at now + interval (>= earliest's bound): the sweep_at_ argument holds
      }
      o->second.dropped += moved;
    }
    sweep_at_ = own_keys() < max_keys_ ? Nanos{0} : earliest;
  }
  inline static const std::string kOverflow = "\x01overflow";
  Nanos interval_;
  std::size_t max_keys_;
  Nanos sweep_at_{0};
  std::map<std::string, Slot> slots_;
};

}  // namespace miracache
