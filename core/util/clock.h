// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>

#include "util/check.h"
namespace miracache {

using Nanos = std::chrono::nanoseconds;

// All time in core/ flows through Clock (spec 14.3). now() is monotonic.
class Clock {
 public:
  virtual ~Clock() = default;
  virtual Nanos now() const = 0;
};

// Wall-clock time (UNIX epoch, nanoseconds). For log timestamps only: never for ordering or
// timeouts (those use Clock). Lives here because this file is the one place allowed to read time.
std::int64_t wall_unix_ns();

class RealClock final : public Clock {
 public:
  Nanos now() const override;
};

// Virtual time; only moves when told to.
class SimClock final : public Clock {
 public:
  explicit SimClock(Nanos start = Nanos{0}) : now_(start.count()) {}
  Nanos now() const override { return Nanos{now_.load(std::memory_order_relaxed)}; }
  // Time never goes backwards; earlier targets are ignored.
  void advance_to(Nanos t) {
    std::int64_t cur = now_.load(std::memory_order_relaxed);
    while (t.count() > cur && !now_.compare_exchange_weak(cur, t.count(), std::memory_order_relaxed)) {}
  }
  // A negative delta is a contract violation (traps): time never goes backwards.
  void advance_by(Nanos d) {
    MIRACACHE_CHECK(d >= Nanos{0});
    now_.fetch_add(d.count(), std::memory_order_relaxed);
  }

 private:
  // Atomic so a test thread can read the virtual time while a client thread drives the simulation.
  std::atomic<std::int64_t> now_;
};

}  // namespace miracache
