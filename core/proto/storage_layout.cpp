// SPDX-License-Identifier: Apache-2.0
#include "proto/storage_layout.h"

#include <algorithm>
#include <cstring>

#include "proto/le.h"
#include "util/crc32c.h"

namespace miracache::proto {
namespace {

bool zero(std::span<const std::byte> b, std::size_t off, std::size_t n) {
  return std::all_of(b.begin() + off, b.begin() + off + n, [](std::byte v) { return v == std::byte{0}; });
}

}  // namespace

Status encode(const Superblock& s, std::span<std::byte, kSuperblockSize> out) {
  if (s.layout_version != kLayoutVersion) return Error{ErrorCode::InvalidArgument, "superblock: layout_version"};
  if (s.clean_shutdown > 1) return Error{ErrorCode::InvalidArgument, "superblock: clean_shutdown"};
  if (s.run_log2 != kRunLog2) return Error{ErrorCode::InvalidArgument, "superblock: run_log2"};
  if (s.min_block_log2 != 0 && (s.min_block_log2 < 12 || s.min_block_log2 > kRunLog2))
    return Error{ErrorCode::InvalidArgument, "superblock: min_block_log2"};
  std::span<std::byte> b = out;
  std::fill(b.begin(), b.end(), std::byte{0});
  put_bytes(b, sb::magic, kSuperblockMagic);
  put_le<std::uint32_t>(b, sb::layout_version, s.layout_version);
  put_le<std::uint32_t>(b, sb::format_epoch, s.format_epoch);
  put_le<std::uint64_t>(b, sb::seq, s.seq);
  put_le<std::uint32_t>(b, sb::node_id, s.node_id);
  put_le<std::uint32_t>(b, sb::owner_pid, s.owner_pid);
  put_le<std::uint64_t>(b, sb::gen_hwm, s.gen_hwm);
  put_le<std::uint64_t>(b, sb::bundle_gen, s.bundle_gen);
  put_le<std::uint64_t>(b, sb::segment_size, s.segment_size);
  put_le<std::uint32_t>(b, sb::n_segments, s.n_segments);
  put_le<std::uint8_t>(b, sb::clean_shutdown, s.clean_shutdown);
  put_le<std::uint8_t>(b, sb::run_log2, s.run_log2);
  put_le<std::uint64_t>(b, sb::sg_off, s.sg_off);
  put_le<std::uint64_t>(b, sb::sg_slots, s.sg_slots);
  put_le<std::uint64_t>(b, sb::scope_off, s.scope_off);
  put_le<std::uint64_t>(b, sb::scope_len, s.scope_len);
  put_le<std::uint8_t>(b, sb::min_block_log2, s.min_block_log2);
  put_le<std::uint32_t>(b, sb::crc, crc32c(b.first(sb::crc)));
  return {};
}

Expected<Superblock> decode_superblock(std::span<const std::byte, kSuperblockSize> in) {
  std::span<const std::byte> b = in;
  std::uint8_t magic[8];
  get_bytes(b, sb::magic, magic);
  if (std::memcmp(magic, kSuperblockMagic, sizeof magic) != 0) return Error{ErrorCode::Corrupt, "superblock: magic"};
  if (get_le<std::uint32_t>(b, sb::crc) != crc32c(b.first(sb::crc))) return Error{ErrorCode::Corrupt, "superblock: crc"};
  Superblock s;
  s.layout_version = get_le<std::uint32_t>(b, sb::layout_version);
  if (s.layout_version != kLayoutVersion) return Error{ErrorCode::Unsupported, "superblock: layout_version"};
  s.format_epoch = get_le<std::uint32_t>(b, sb::format_epoch);
  s.seq = get_le<std::uint64_t>(b, sb::seq);
  s.node_id = get_le<std::uint32_t>(b, sb::node_id);
  s.owner_pid = get_le<std::uint32_t>(b, sb::owner_pid);
  s.gen_hwm = get_le<std::uint64_t>(b, sb::gen_hwm);
  s.bundle_gen = get_le<std::uint64_t>(b, sb::bundle_gen);
  s.segment_size = get_le<std::uint64_t>(b, sb::segment_size);
  s.n_segments = get_le<std::uint32_t>(b, sb::n_segments);
  s.clean_shutdown = get_le<std::uint8_t>(b, sb::clean_shutdown);
  s.run_log2 = get_le<std::uint8_t>(b, sb::run_log2);
  s.sg_off = get_le<std::uint64_t>(b, sb::sg_off);
  s.sg_slots = get_le<std::uint64_t>(b, sb::sg_slots);
  s.scope_off = get_le<std::uint64_t>(b, sb::scope_off);
  s.scope_len = get_le<std::uint64_t>(b, sb::scope_len);
  s.min_block_log2 = get_le<std::uint8_t>(b, sb::min_block_log2);
  if (s.clean_shutdown > 1) return Error{ErrorCode::Corrupt, "superblock: clean_shutdown"};
  if (s.run_log2 != kRunLog2) return Error{ErrorCode::Corrupt, "superblock: run_log2"};
  if (s.min_block_log2 != 0 && (s.min_block_log2 < 12 || s.min_block_log2 > kRunLog2))
    return Error{ErrorCode::Corrupt, "superblock: min_block_log2"};
  if (!zero(b, sb::z62, 2) || !zero(b, sb::z97, sb::crc - sb::z97)) return Error{ErrorCode::Corrupt, "superblock: z"};
  return s;
}

Expected<Superblock> choose_superblock(std::span<const std::byte, kSuperblockSize> first,
                                       std::span<const std::byte, kSuperblockSize> second) {
  auto a = decode_superblock(first);
  auto c = decode_superblock(second);
  if (a && c) return c->seq > a->seq ? *c : *a;
  if (a) return *a;
  if (c) return *c;
  return a.error();
}

Status encode(const SegmentMeta& m, std::span<std::byte, kSegmentMetaSize> out) {
  if (m.layout_version != kLayoutVersion) return Error{ErrorCode::InvalidArgument, "segment meta: layout_version"};
  std::span<std::byte> b = out;
  std::fill(b.begin(), b.end(), std::byte{0});
  put_bytes(b, sm::magic, kSegmentMetaMagic);
  put_le<std::uint16_t>(b, sm::layout_version, m.layout_version);
  put_le<std::uint32_t>(b, sm::seg_id, m.seg_id);
  put_le<std::uint32_t>(b, sm::n_runs, m.n_runs);
  put_le<std::uint64_t>(b, sm::run_table_off, m.run_table_off);
  put_le<std::uint64_t>(b, sm::hdr_table_off, m.hdr_table_off);
  put_le<std::uint64_t>(b, sm::data_off, m.data_off);
  put_le<std::uint32_t>(b, sm::format_epoch, m.format_epoch);
  put_le<std::uint32_t>(b, sm::crc, crc32c(b.first(sm::crc)));
  return {};
}

Expected<SegmentMeta> decode_segment_meta(std::span<const std::byte, kSegmentMetaSize> in) {
  std::span<const std::byte> b = in;
  std::uint8_t magic[4];
  get_bytes(b, sm::magic, magic);
  if (std::memcmp(magic, kSegmentMetaMagic, sizeof magic) != 0) return Error{ErrorCode::Corrupt, "segment meta: magic"};
  if (get_le<std::uint32_t>(b, sm::crc) != crc32c(b.first(sm::crc))) return Error{ErrorCode::Corrupt, "segment meta: crc"};
  SegmentMeta m;
  m.layout_version = get_le<std::uint16_t>(b, sm::layout_version);
  if (m.layout_version != kLayoutVersion) return Error{ErrorCode::Unsupported, "segment meta: layout_version"};
  if (!zero(b, sm::z6, 2) || !zero(b, sm::z44, 16)) return Error{ErrorCode::Corrupt, "segment meta: z"};
  m.seg_id = get_le<std::uint32_t>(b, sm::seg_id);
  m.n_runs = get_le<std::uint32_t>(b, sm::n_runs);
  m.run_table_off = get_le<std::uint64_t>(b, sm::run_table_off);
  m.hdr_table_off = get_le<std::uint64_t>(b, sm::hdr_table_off);
  m.data_off = get_le<std::uint64_t>(b, sm::data_off);
  m.format_epoch = get_le<std::uint32_t>(b, sm::format_epoch);
  return m;
}

static bool run_ok(std::uint8_t log2, std::uint32_t n) {
  return (log2 == 0 || (log2 >= 16 && log2 <= 28)) && n <= kSlotsPerRun;
}

Status encode(const RunEntry& r, std::span<std::byte, kRunEntrySize> out) {
  if (!run_ok(r.block_log2, r.n_blocks)) return Error{ErrorCode::InvalidArgument, "run entry"};
  std::span<std::byte> b = out;
  std::fill(b.begin(), b.end(), std::byte{0});
  put_le<std::uint8_t>(b, re::block_log2, r.block_log2);
  put_le<std::uint32_t>(b, re::n_blocks, r.n_blocks);
  return {};
}

Expected<RunEntry> decode_run_entry(std::span<const std::byte, kRunEntrySize> in) {
  std::span<const std::byte> b = in;
  RunEntry r;
  r.block_log2 = get_le<std::uint8_t>(b, re::block_log2);
  r.n_blocks = get_le<std::uint32_t>(b, re::n_blocks);
  if (!zero(b, re::z1, 3) || !run_ok(r.block_log2, r.n_blocks)) return Error{ErrorCode::Corrupt, "run entry"};
  return r;
}

}  // namespace miracache::proto
