// SPDX-License-Identifier: Apache-2.0
// Storage v0 persisted scope table: one 72 B ScopeRecord per implicit scope keyed by
// (principal_id, scope_id), preceded by a 16 B region header ("MIRS"). The region lives
// at superblock.scope_off / scope_len. All fields little-endian, CRC32C-protected.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "proto/wire.h"
#include "util/expected.h"

namespace miracache::proto {

// ---- ScopeRecord (72 B, 8-byte aligned) ----
inline constexpr std::size_t kScopeRecordSize = 72;
// kScopeIdSize (32) comes from wire.h: the same scope_id as on the wire.
namespace scr {
inline constexpr std::size_t principal_id = 0, mode = 4, state = 5, z6 = 6, scope_id = 8,
                             opened_at_ms = 40, expires_at_ms = 48, last_used_ms = 56,
                             z64 = 64, crc = 68;
}
static_assert(scr::z6 + 2 == scr::scope_id && scr::scope_id + kScopeIdSize == scr::opened_at_ms);
static_assert(scr::last_used_ms + 8 == scr::z64 && scr::z64 + 4 == scr::crc);
static_assert(scr::crc + 4 == kScopeRecordSize && kScopeRecordSize % 8 == 0);

inline constexpr std::uint8_t kScopeModeImplicit = 0;  // others reserved
inline constexpr std::uint8_t kScopeFree = 0, kScopeOpen = 1, kScopeDraining = 2;

struct ScopeRecord {
  std::uint32_t principal_id = 0;  // != 0 unless the slot is free
  std::uint8_t mode = kScopeModeImplicit;
  std::uint8_t state = kScopeFree;
  std::array<std::uint8_t, kScopeIdSize> scope_id{};
  std::uint64_t opened_at_ms = 0;
  std::uint64_t expires_at_ms = 0;
  std::uint64_t last_used_ms = 0;
};

// A free slot (state 0) must have every other field zero and is written as 72 zero
// bytes (crc included). Otherwise: mode known, state in {1,2}, principal_id != 0.
// Violations fail with InvalidArgument.
Status encode(const ScopeRecord& r, std::span<std::byte, kScopeRecordSize> out);

// All-zero bytes decode to a free slot. Otherwise: crc (Corrupt), then z fields, mode,
// state, principal_id (all Corrupt; a non-zero record with state 0 is Corrupt).
Expected<ScopeRecord> decode_scope_record(std::span<const std::byte, kScopeRecordSize> in);

// ---- Scope region header (16 B, "MIRS") ----
// {magic[4], layout_version u16 = 0, record_size u16 = 72, n_records u32, crc u32 @12}
inline constexpr std::size_t kScopeRegionHeaderSize = 16;
inline constexpr std::uint8_t kScopeRegionMagic[4] = {'M', 'I', 'R', 'S'};
inline constexpr std::uint16_t kScopeLayoutVersion = 0;
inline constexpr std::uint32_t kDefaultMaxScopeRecords = 4u * 1024 * 1024;  // 4 Mi per node
namespace srh {
inline constexpr std::size_t magic = 0, layout_version = 4, record_size = 6, n_records = 8,
                             crc = 12;
}
static_assert(srh::crc + 4 == kScopeRegionHeaderSize && kScopeRegionHeaderSize % 8 == 0);

struct ScopeRegionHeader {
  std::uint16_t layout_version = kScopeLayoutVersion;
  std::uint16_t record_size = static_cast<std::uint16_t>(kScopeRecordSize);
  std::uint32_t n_records = 0;  // >= 1
};
// InvalidArgument for layout_version != 0, record_size != 72 or n_records == 0.
Status encode(const ScopeRegionHeader& h, std::span<std::byte, kScopeRegionHeaderSize> out);
// magic, crc (Corrupt), layout_version != 0 (Unsupported), record_size != 72 or
// n_records == 0 (Corrupt).
Expected<ScopeRegionHeader> decode_scope_region_header(
    std::span<const std::byte, kScopeRegionHeaderSize> in);

// Region size in bytes (value for superblock.scope_len): header + n * 72. At the default
// 4 Mi records: 301,989,904 B (288 MiB + 16 B). The caller aligns scope_off.
constexpr std::uint64_t scope_region_size(std::uint32_t max_scope_records) {
  return kScopeRegionHeaderSize + std::uint64_t{max_scope_records} * kScopeRecordSize;
}
// Byte offset of record `i` from the start of the region.
constexpr std::uint64_t scope_record_offset(std::uint64_t i) {
  return kScopeRegionHeaderSize + i * kScopeRecordSize;
}
// True if a region of `scope_len` bytes can hold all the records the header declares.
constexpr bool scope_region_fits(const ScopeRegionHeader& h, std::uint64_t scope_len) {
  return scope_len >= scope_region_size(h.n_records);
}

}  // namespace miracache::proto
