// SPDX-License-Identifier: Apache-2.0
// The persisted scope table (spec 6.1) over the scope region of segment 0: a 16 B "MIRS" header
// and `records` 72 B ScopeRecords (proto/scope_record.h, frozen storage v0). The Store writes a record when an
// implicit scope opens, rewrites it (lazily) as last_used moves, and clears it when the scope is doomed or erased, so
// after a crash a record is OPEN only for a scope that was live. The restart scan (restart.h) reads it back.
// Single-threaded (store thread). Writes are plain stores into the MAP_SHARED pages: they survive a process crash.
#pragma once

#include <cstdint>
#include <functional>
#include <span>
#include <vector>

#include "proto/scope_record.h"
#include "util/expected.h"

namespace miracache::store {

class ScopeTable {
 public:
  static constexpr std::uint32_t kNone = ~std::uint32_t{0};

  // `region` is the whole scope region (header + records).
  ScopeTable(std::span<std::byte> region, std::uint32_t records) : region_(region), records_(records) {}

  // Blank format: header written, every record zeroed (check-before-write, so untouched pages stay untouched).
  Status format();
  // Re-open: Corrupt if the header does not decode or declares another record count (the caller re-formats).
  Status check_header() const;
  // Visits every non-free record that decodes. `keep` returns true to keep the slot (the caller now owns it), false to
  // clear it. A corrupt record (CRC) is counted; `torn` (optional) sees its raw bytes and returns true to keep the slot
  // (the caller then owns it and releases it later), otherwise it is cleared. Builds the free list. Returns the corrupt
  // count.
  std::uint64_t load(const std::function<bool(std::uint32_t slot, const proto::ScopeRecord&)>& keep,
                     const std::function<bool(std::uint32_t slot, std::span<const std::byte>)>& torn = {});

  // A free slot, or kNone when the table is full (the store then refuses the new scope, ensure_scope_for_root_put).
  std::uint32_t alloc();
  void write(std::uint32_t slot, const proto::ScopeRecord& r);
  // Clears the record (72 zero bytes) and returns the slot to the free list.
  void release(std::uint32_t slot);

  std::uint32_t records() const { return records_; }
  std::uint32_t used() const { return records_ - static_cast<std::uint32_t>(free_.size()); }

 private:
  std::span<std::byte> rec(std::uint32_t slot) const;
  void clear(std::uint32_t slot);

  std::span<std::byte> region_;
  std::uint32_t records_;
  std::vector<std::uint32_t> free_;  // a stack; the lowest slots are handed out first after load/format
};

}  // namespace miracache::store
