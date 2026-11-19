// SPDX-License-Identifier: Apache-2.0
// SC1: the background scrubber (spec 6.5, review P28). A cursor walks the committed blocks in gen_slot order, and for
// each one recomputes the CRC32C of the stored extent and compares it with the header's payload_crc; a mismatch drops
// the block and its subtree through the INVALIDATE path.
//
// Threading: step() and every `done` run on the store thread; only the CRC runs on the Executor (the ingest workers
// in production). The block is PINNED while it is checked (Store::scrub_pin_next: an internal lease), so evict, drop
// and INVALIDATE turn it ZOMBIE (memory intact, never reused) and it is freed at unpin. Rate: a bytes/s credit
// (burst = one second, one block of debt allowed, like the sweep) and at most `blocks_per_turn` (16) blocks per step.
//
// Lifetime: destroy the Scrubber before the Store; `done`s that run after that do nothing. stop() ends picking; the
// executor must still be drained (in_flight() == 0) before the arena is unmapped.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>

#include "store/arena.h"
#include "store/store.h"
#include "store/store_metrics.h"
#include "util/clock.h"
#include "util/executor.h"

namespace miracache::store {

class Scrubber {
 public:
  static constexpr std::uint32_t kBlocksPerTurn = 16;
  static constexpr std::size_t kMaxInFlight = 64;

  // `on_corrupt` runs on the store thread for each block that failed (the server logs node ID / host / addr there).
  Scrubber(Store& store, Arena& arena, Executor& exec, const Clock& clock, const StoreMetrics* mx = nullptr,
           std::function<void(const Extent&)> on_corrupt = {});
  ~Scrubber();
  Scrubber(const Scrubber&) = delete;
  Scrubber& operator=(const Scrubber&) = delete;

  // Store thread. 0 = off. Takes effect on the next step.
  void set_rate(std::uint64_t bytes_per_s, std::uint32_t blocks_per_turn = kBlocksPerTurn);
  // Store thread, once per turn. Returns the blocks picked.
  std::size_t step();
  // No further picks. In-flight checks still finish through the executor.
  void stop() { stopped_ = true; }
  bool stopped() const { return stopped_; }
  std::size_t in_flight() const { return in_flight_; }

  std::uint64_t checked() const { return checked_; }
  std::uint64_t failed() const { return failed_; }
  std::uint64_t bytes() const { return bytes_; }
  std::uint64_t cycles() const { return cycles_; }

 private:
  struct Shared {
    Store* store = nullptr;
    Scrubber* self = nullptr;
  };
  void finish(const Extent& e, std::uint64_t stored_len, bool corrupt);

  Store& store_;
  Arena& arena_;
  Executor& exec_;
  const Clock& clock_;
  const StoreMetrics* mx_;
  std::function<void(const Extent&)> on_corrupt_;
  std::shared_ptr<Shared> sh_;
  std::uint64_t rate_ = 0;
  std::uint32_t per_turn_ = kBlocksPerTurn;
  std::int64_t credit_ = 0;
  std::int64_t last_ns_ = -1;
  std::int64_t cycle_start_ns_ = -1;
  std::uint64_t cursor_ = 0;
  bool stopped_ = false;
  std::size_t in_flight_ = 0;
  std::uint64_t checked_ = 0, failed_ = 0, bytes_ = 0, cycles_ = 0;
};

}  // namespace miracache::store
