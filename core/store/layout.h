// SPDX-License-Identifier: Apache-2.0
// In-memory offsets of one segment, derived from the on-media structures in
// proto/storage_layout.h (which owns the superblock, SegmentMeta, RunEntry and the slot
// rule; nothing here redefines them).
//
//   [0, 8192)                 two superblock copies (meaningful in segment 0 only)
//   [8192, 8256)              SegmentMeta, padded to one 4 KiB page
//   run_table_off             n_runs x RunEntry (8 B), padded to 4 KiB
//   hdr_table_off             n_runs x 4096 slots x 128 B block headers. The slot rule fixes
//                             4096 slots per run whatever the run size, so for runs with
//                             fewer blocks the table is sparse (untouched pages cost nothing).
//   data_off                  n_runs x run_bytes of block data, aligned to min(run, 2 MiB)
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "proto/scope_record.h"
#include "proto/storage_layout.h"
#include "util/expected.h"

namespace miracache::store {

inline constexpr std::size_t kPage = 4096;
inline constexpr std::size_t kHeaderSlotBytes = 128;
inline constexpr std::size_t kSuperblockRegionBytes = 2 * proto::kSuperblockSize;
inline constexpr std::size_t kSegmentMetaOff = kSuperblockRegionBytes;
inline constexpr std::size_t kRunTableOffMin = kSegmentMetaOff + kPage;

constexpr std::uint64_t align_up(std::uint64_t v, std::uint64_t a) { return (v + a - 1) / a * a; }

struct Region {
  const char* name;
  std::uint64_t off, len;
};

struct SegmentLayout {
  std::uint64_t segment_bytes = 0;
  std::uint64_t run_bytes = 0;
  std::uint32_t n_runs = 0;
  std::uint64_t run_table_off = 0;
  std::uint64_t hdr_table_off = 0;
  std::uint64_t data_off = 0;

  constexpr std::uint64_t run_table_bytes() const { return align_up(std::uint64_t{n_runs} * proto::kRunEntrySize, kPage); }
  constexpr std::uint64_t hdr_table_bytes() const {
    return std::uint64_t{n_runs} * proto::kSlotsPerRun * kHeaderSlotBytes;
  }
  constexpr std::uint64_t slots() const { return std::uint64_t{n_runs} * proto::kSlotsPerRun; }

  constexpr std::uint64_t run_data_off(std::uint32_t run) const { return data_off + run * run_bytes; }
  constexpr std::uint64_t run_entry_off(std::uint32_t run) const { return run_table_off + run * proto::kRunEntrySize; }
  constexpr std::uint64_t header_off(std::uint32_t run, std::uint32_t block) const {
    return proto::header_offset(hdr_table_off, run, block);
  }
  // Byte offset of block `block` of a run formatted with 2^block_log2-byte blocks.
  constexpr std::uint64_t block_off(std::uint32_t run, std::uint32_t block, std::uint8_t block_log2) const {
    return run_data_off(run) + (std::uint64_t{block} << block_log2);
  }

  constexpr std::array<Region, 5> regions() const {
    return {{{"superblocks", 0, kSuperblockRegionBytes},
             {"segment_meta", kSegmentMetaOff, proto::kSegmentMetaSize},
             {"run_table", run_table_off, run_table_bytes()},
             {"hdr_table", hdr_table_off, hdr_table_bytes()},
             {"data", data_off, std::uint64_t{n_runs} * run_bytes}}};
  }
};

// Largest run count whose tables and data fit in `segment_bytes`.
inline Expected<SegmentLayout> compute_segment_layout(std::uint64_t segment_bytes, std::uint64_t run_bytes) {
  if (run_bytes == 0 || (run_bytes & (run_bytes - 1)) != 0 || run_bytes > (std::uint64_t{1} << proto::kRunLog2))
    return Error{ErrorCode::InvalidArgument, "layout: run_bytes"};
  const std::uint64_t data_align = run_bytes < (2u << 20) ? run_bytes : (2u << 20);
  for (std::uint64_t n = segment_bytes / run_bytes; n >= 1; --n) {
    SegmentLayout l;
    l.segment_bytes = segment_bytes;
    l.run_bytes = run_bytes;
    l.n_runs = static_cast<std::uint32_t>(n);
    l.run_table_off = kRunTableOffMin;
    l.hdr_table_off = l.run_table_off + l.run_table_bytes();
    l.data_off = align_up(l.hdr_table_off + l.hdr_table_bytes(), data_align < kPage ? kPage : data_align);
    if (l.data_off + n * run_bytes <= segment_bytes) return l;
  }
  return Error{ErrorCode::InvalidArgument, "layout: segment too small for one run"};
}

// A3.1: the persisted scope region (spec 6.1, proto/scope_record.h) lives in segment 0, in the first of: (1) the
// alignment gap between the header table and the data runs (no capacity lost), (2) the slack after the last run, (3)
// the last `reserved_runs` runs of segment 0, which the slab then never formats. records == 0: no region (volatile).
struct ScopeRegionLayout {
  std::uint32_t records = 0;
  std::uint64_t off = 0, len = 0;  // in segment 0; len >= scope_region_size(records), page aligned
  std::uint32_t reserved_runs = 0;
};

inline Expected<ScopeRegionLayout> compute_scope_region(const SegmentLayout& l, std::uint32_t records) {
  ScopeRegionLayout r;
  if (records == 0) return r;
  const std::uint64_t need = align_up(proto::kScopeRegionHeaderSize + std::uint64_t{records} * proto::kScopeRecordSize, kPage);
  if (need >= l.segment_bytes) return Error{ErrorCode::InvalidArgument, "layout: scope region larger than segment 0"};
  r.records = records;
  const std::uint64_t gap = align_up(l.hdr_table_off + l.hdr_table_bytes(), kPage);
  if (gap + need <= l.data_off) {
    r.off = gap;
    r.len = need;
    return r;
  }
  r.off = (l.segment_bytes - need) / kPage * kPage;
  r.len = l.segment_bytes - r.off;
  const std::uint64_t data_end = l.data_off + std::uint64_t{l.n_runs} * l.run_bytes;
  if (r.off < data_end) r.reserved_runs = static_cast<std::uint32_t>((data_end - r.off + l.run_bytes - 1) / l.run_bytes);
  if (r.reserved_runs >= l.n_runs || r.off < l.data_off)
    return Error{ErrorCode::InvalidArgument, "layout: scope region leaves no data run in segment 0"};
  return r;
}

struct StoreLayout {
  SegmentLayout seg;
  std::uint32_t n_segments = 0;
  ScopeRegionLayout scope;  // A3.1

  constexpr std::uint64_t sg_slots() const { return std::uint64_t{n_segments} * seg.slots(); }
  // Global state_gen slot (slot rule from proto).
  constexpr std::uint64_t gen_slot(std::uint32_t s, std::uint32_t run, std::uint32_t block) const {
    return proto::gen_slot(s, seg.n_runs, run, block);
  }
};

}  // namespace miracache::store
