// SPDX-License-Identifier: Apache-2.0
// Persistent layout (plan section 2): superblock (two 4096 B copies at offsets 0 and
// 4096 of segment 0), SegmentMeta (64 B), RunEntry (8 B) and the slot rule.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "util/expected.h"

namespace miracache::proto {

inline constexpr std::size_t kSuperblockSize = 4096;
inline constexpr std::uint8_t kSuperblockMagic[8] = {'M', 'I', 'R', 'A', 'S', 'B', 0, 0};
inline constexpr std::uint32_t kLayoutVersion = 0;
inline constexpr std::uint8_t kRunLog2 = 28;
inline constexpr std::uint32_t kSlotsPerRun = 4096;  // fixed (supersedes the A1.4 slot rule)

namespace sb {
inline constexpr std::size_t magic = 0, layout_version = 8, format_epoch = 12, seq = 16,
                             node_id = 24, owner_pid = 28, gen_hwm = 32, bundle_gen = 40,
                             segment_size = 48, n_segments = 56, clean_shutdown = 60,
                             run_log2 = 61, z62 = 62, sg_off = 64, sg_slots = 72,
                             scope_off = 80, scope_len = 88, min_block_log2 = 96, z97 = 97, crc = 4092;
}
static_assert(sb::z97 + 3995 == sb::crc && sb::crc + 4 == kSuperblockSize);

struct Superblock {
  std::uint32_t layout_version = kLayoutVersion;
  std::uint32_t format_epoch = 0;
  std::uint64_t seq = 0;
  std::uint32_t node_id = 0;
  std::uint32_t owner_pid = 0;
  std::uint64_t gen_hwm = 0;
  std::uint64_t bundle_gen = 0;
  std::uint64_t segment_size = 0;
  std::uint32_t n_segments = 0;
  std::uint8_t clean_shutdown = 0;  // 0 or 1
  std::uint8_t run_log2 = kRunLog2;  // must be 28
  std::uint64_t sg_off = 0;
  std::uint64_t sg_slots = 0;
  std::uint64_t scope_off = 0;
  std::uint64_t scope_len = 0;
  // s12 (tpu-sync cross-check C2): log2 of store.min_block_bytes at format time (12..28). The restart scan infers each
  // run's block size from it, so a warm start under another value is refused (a STATIC change). 0 = written before
  // s12 (the byte was reserved zero): the arena re-formats such a store once.
  std::uint8_t min_block_log2 = 0;
};

// Fails with InvalidArgument for clean_shutdown > 1, run_log2 != 28, layout_version != 0 or a min_block_log2 that is
// neither 0 nor 12..28.
Status encode(const Superblock& s, std::span<std::byte, kSuperblockSize> out);

// Order: magic, crc (Corrupt), layout_version != 0 (Unsupported: refuse to start),
// then z fields / run_log2 / clean_shutdown (Corrupt).
Expected<Superblock> decode_superblock(std::span<const std::byte, kSuperblockSize> in);

// Picks the copy with a valid CRC and the highest seq (copy 0 on a tie). If neither
// decodes, returns the error of copy 0. `first` / `second` are the two on-disk copies.
Expected<Superblock> choose_superblock(std::span<const std::byte, kSuperblockSize> first,
                                       std::span<const std::byte, kSuperblockSize> second);

// ---- SegmentMeta (64 B, "MIRM") ----
inline constexpr std::size_t kSegmentMetaSize = 64;
inline constexpr std::uint8_t kSegmentMetaMagic[4] = {'M', 'I', 'R', 'M'};
namespace sm {
inline constexpr std::size_t magic = 0, layout_version = 4, z6 = 6, seg_id = 8, n_runs = 12,
                             run_table_off = 16, hdr_table_off = 24, data_off = 32,
                             format_epoch = 40, z44 = 44, crc = 60;
}
static_assert(sm::z44 + 16 == sm::crc && sm::crc + 4 == kSegmentMetaSize);

struct SegmentMeta {
  std::uint16_t layout_version = 0;
  std::uint32_t seg_id = 0;
  std::uint32_t n_runs = 0;
  std::uint64_t run_table_off = 0;
  std::uint64_t hdr_table_off = 0;
  std::uint64_t data_off = 0;
  std::uint32_t format_epoch = 0;
};
Status encode(const SegmentMeta& m, std::span<std::byte, kSegmentMetaSize> out);
// magic, crc (Corrupt), layout_version != 0 (Unsupported), z (Corrupt).
Expected<SegmentMeta> decode_segment_meta(std::span<const std::byte, kSegmentMetaSize> in);

// ---- RunEntry (8 B) ----
inline constexpr std::size_t kRunEntrySize = 8;
namespace re { inline constexpr std::size_t block_log2 = 0, z1 = 1, n_blocks = 4; }
static_assert(re::n_blocks + 4 == kRunEntrySize);
struct RunEntry {
  std::uint8_t block_log2 = 0;  // 0 = unformatted, else 16..28
  std::uint32_t n_blocks = 0;   // <= 4096
};
Status encode(const RunEntry& r, std::span<std::byte, kRunEntrySize> out);
Expected<RunEntry> decode_run_entry(std::span<const std::byte, kRunEntrySize> in);

// ---- Slot rule ----
// gen_slot = (seg * runs_per_seg + run) * 4096 + block. Header bytes live at
// hdr_table_off + local_slot * 128 where local_slot = run * 4096 + block.
constexpr std::uint64_t gen_slot(std::uint64_t seg, std::uint64_t runs_per_seg,
                                 std::uint64_t run, std::uint64_t block) {
  return (seg * runs_per_seg + run) * kSlotsPerRun + block;
}
constexpr std::uint64_t header_offset(std::uint64_t hdr_table_off, std::uint64_t run,
                                      std::uint64_t block) {
  return hdr_table_off + (run * kSlotsPerRun + block) * 128;
}

}  // namespace miracache::proto
