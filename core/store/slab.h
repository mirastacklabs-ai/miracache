// SPDX-License-Identifier: Apache-2.0
// Slab allocator. Runs (run_bytes, from the arena layout) are formatted on demand
// for one block size class; a class is the exact block length round4K(stored_len), created
// on first use. At most kMaxClasses exact classes are live, and one owner (principal) may create
// at most max_exact_classes_per_owner; beyond either limit a request is served from its fixed
// ladder rung class (never refused for classes others created). A class with no runs is
// dropped, and a run whose blocks are all free returns to the free-run pool.
//
// alloc_batch is all-or-nothing. Blocks of one class in a batch are adjacent when a run
// can hold them side by side (a batch has at most kMaxBatch extents). Each block gets a
// fresh generation, and (WRITING, gen) is stored in the state_gen array before alloc_batch
// returns, hence before any header is written. The header is written only at commit and
// cleared at free (and when a block turns ZOMBIE), so a valid header on media means "committed
// and live"; the restart scan (restart.h) relies on it. The on-media run table is not written:
// RunEntry.block_log2 cannot express round4K classes, so the scan infers each run's class from
// its headers and re-forms the run with adopt_run / adopt_block. The last
// ScopeRegionLayout::reserved_runs runs of segment 0 hold the scope region: never formatted.
// Single-threaded: only the store thread calls in.
#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <vector>

#include "proto/server_header.h"
#include "store/arena.h"
#include "util/expected.h"

namespace miracache::store {

struct Extent {
  std::uint32_t seg = 0;
  std::uint64_t off = 0;       // byte offset in the segment
  std::uint64_t len = 0;       // block bytes (the class size)
  std::uint64_t gen_slot = 0;  // global state_gen slot
  std::uint64_t gen = 0;
  friend bool operator==(const Extent&, const Extent&) = default;
};

struct ClassStats {
  std::uint64_t len = 0;
  std::uint32_t runs = 0;
  std::uint64_t blocks = 0, allocated = 0, free = 0;
};

class SlabAllocator {
 public:
  // Cap on live EXACT size classes. Ladder-rung classes (fixed, <= ~2 log2(run/min) of them) are
  // outside it, so a request is never refused for size classes created by other owners.
  static constexpr std::size_t kMaxClasses = 64;
  static constexpr std::size_t kMaxBatch = 4;

  explicit SlabAllocator(Arena& arena);
  // Live StoreConfig::max_exact_classes_per_owner (store thread; existing classes stay, new exact ones obey it).
  void set_max_exact_classes_per_owner(std::uint32_t n) { max_exact_per_owner_ = n; }

  // `stored_lens` (1..kMaxBatch entries): the client extent bytes of each block. Result is
  // in input order. ResourceExhausted leaves the allocator and the state array untouched.
  // `owner` (a principal id; 0 = anonymous) is charged for exact classes it creates, at most
  // StoreConfig::max_exact_classes_per_owner; beyond that, or at kMaxClasses, the request is
  // served from the ladder rung class.
  Expected<std::vector<Extent>> alloc_batch(std::span<const std::uint64_t> stored_lens, std::uint64_t owner = 0);
  // Sets the slot to (Free, gen) and returns the block. Freeing a block twice, or one that
  // was not allocated here, is a caller bug (trap).
  void free(const Extent& e);

  // Writes the 128 B server header for e at its header slot via proto::encode, forcing
  // generation = e.gen. Call after alloc_batch, before committing.
  void write_header(const Extent& e, proto::ServerHeader h);
  // Zeroes the 128 B header slot of e (magic first). free() calls it; so does the store when a block turns ZOMBIE.
  void clear_header(const Extent& e);
  // The 128 B header slot of global slot `gen_slot` (in segment `seg`).
  std::span<std::byte> header_slot(std::uint32_t seg, std::uint64_t gen_slot) const;

  // ---- Restart scan (restart.h). Run ids are global (seg * runs_per_seg + run). ----
  // Formats an unformatted run for class `cls` (created if absent: a ladder value is a rung class, else an exact class
  // charged to `owner`). False if the run is reserved or formatted for another class, or the exact-class cap is hit.
  bool adopt_run(std::uint32_t run, std::uint64_t cls, std::uint64_t owner);
  // Marks block `block` of an adopted run used and returns its extent with generation `gen` (the state word is the
  // caller's). The block must be free.
  Extent adopt_block(std::uint32_t run, std::uint32_t block, std::uint64_t gen);
  std::uint64_t run_class(std::uint32_t run) const { return runs_.at(run).cls; }
  bool run_reserved(std::uint32_t run) const { return runs_.at(run).reserved; }
  // Blocks per run of a class of `cls` bytes.
  std::uint32_t per_run(std::uint64_t cls) const;

  // Block bytes for a request of `stored_len` before any class cap: round4K(max(len,1)).
  std::uint64_t exact_len(std::uint64_t stored_len) const;
  // Smallest fixed ladder rung >= len: rungs are min_block * 2^i and 1.5x that (granule-aligned),
  // up to run_bytes. Requires len <= run_bytes.
  std::uint64_t ladder_len(std::uint64_t len) const;

  // Run id of an allocated extent, and the number of allocated blocks in a run (evictor: a run
  // whose every allocated block is evictable can be freed whole and re-carved for any class).
  std::uint32_t run_of(const Extent& e) const;
  std::uint32_t run_used(std::uint32_t run) const;

  std::vector<ClassStats> class_stats() const;
  std::size_t n_classes() const { return classes_.size(); }
  std::uint32_t free_runs() const { return static_cast<std::uint32_t>(free_runs_.size()); }
  std::uint32_t total_runs() const { return static_cast<std::uint32_t>(runs_.size()) - reserved_; }  // data runs
  // Internal consistency (counts, bitmaps, pool). Ok or Corrupt.
  Status check_invariants() const;

 private:
  struct Run {
    std::uint32_t seg = 0, idx = 0;
    std::uint64_t cls = 0;  // 0 = unformatted
    std::vector<std::uint8_t> used;
    std::uint32_t n_free = 0;
    bool reserved = false;  // holds the scope region
  };
  struct Class {
    std::uint32_t per_run = 0;
    std::set<std::uint32_t> runs;  // global run ids
    std::uint64_t free = 0;
    std::uint64_t owner = 0;  // creator, for exact classes
    bool rung = false;        // ladder rung class: not counted against any budget
  };
  struct Pick {
    std::uint32_t run, block;
  };

  Expected<std::uint64_t> class_for(std::uint64_t stored_len, std::uint64_t owner, std::vector<std::uint64_t>& created);
  bool place(std::uint64_t cls, std::size_t n, std::vector<Pick>& out);
  void take(std::uint32_t run, std::uint32_t block);
  void give(std::uint32_t run, std::uint32_t block);
  Extent extent_of(const Pick& p, std::uint64_t cls) const;

  Arena& arena_;
  std::uint32_t runs_per_seg_;
  std::uint64_t run_bytes_, min_block_;
  std::uint32_t max_exact_per_owner_;
  std::vector<Run> runs_;
  std::uint32_t reserved_ = 0;
  std::set<std::uint32_t> free_runs_;
  std::map<std::uint64_t, Class> classes_;
};

}  // namespace miracache::store
