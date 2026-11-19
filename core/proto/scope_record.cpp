// SPDX-License-Identifier: Apache-2.0
#include "proto/scope_record.h"

#include <algorithm>
#include <cstring>

#include "proto/le.h"
#include "util/crc32c.h"

namespace miracache::proto {
namespace {

bool zero(std::span<const std::byte> b, std::size_t off, std::size_t n) {
  return std::all_of(b.begin() + off, b.begin() + off + n, [](std::byte v) { return v == std::byte{0}; });
}

bool is_free_content(const ScopeRecord& r) {
  return r.principal_id == 0 && r.mode == 0 && r.opened_at_ms == 0 && r.expires_at_ms == 0 &&
         r.last_used_ms == 0 &&
         std::all_of(r.scope_id.begin(), r.scope_id.end(), [](std::uint8_t v) { return v == 0; });
}

}  // namespace

Status encode(const ScopeRecord& r, std::span<std::byte, kScopeRecordSize> out) {
  std::span<std::byte> b = out;
  if (r.state == kScopeFree) {
    if (!is_free_content(r)) return Error{ErrorCode::InvalidArgument, "scope record: free slot not zero"};
    std::fill(b.begin(), b.end(), std::byte{0});
    return {};
  }
  if (r.state > kScopeDraining) return Error{ErrorCode::InvalidArgument, "scope record: state"};
  if (r.mode != kScopeModeImplicit) return Error{ErrorCode::InvalidArgument, "scope record: mode"};
  if (r.principal_id == 0) return Error{ErrorCode::InvalidArgument, "scope record: principal_id"};
  std::fill(b.begin(), b.end(), std::byte{0});
  put_le<std::uint32_t>(b, scr::principal_id, r.principal_id);
  put_le<std::uint8_t>(b, scr::mode, r.mode);
  put_le<std::uint8_t>(b, scr::state, r.state);
  std::memcpy(b.data() + scr::scope_id, r.scope_id.data(), kScopeIdSize);
  put_le<std::uint64_t>(b, scr::opened_at_ms, r.opened_at_ms);
  put_le<std::uint64_t>(b, scr::expires_at_ms, r.expires_at_ms);
  put_le<std::uint64_t>(b, scr::last_used_ms, r.last_used_ms);
  put_le<std::uint32_t>(b, scr::crc, crc32c(b.first(scr::crc)));
  return {};
}

Expected<ScopeRecord> decode_scope_record(std::span<const std::byte, kScopeRecordSize> in) {
  std::span<const std::byte> b = in;
  ScopeRecord r;
  if (zero(b, 0, kScopeRecordSize)) return r;  // free slot
  if (get_le<std::uint32_t>(b, scr::crc) != crc32c(b.first(scr::crc))) return Error{ErrorCode::Corrupt, "scope record: crc"};
  if (!zero(b, scr::z6, 2) || !zero(b, scr::z64, 4)) return Error{ErrorCode::Corrupt, "scope record: z"};
  r.principal_id = get_le<std::uint32_t>(b, scr::principal_id);
  r.mode = get_le<std::uint8_t>(b, scr::mode);
  r.state = get_le<std::uint8_t>(b, scr::state);
  if (r.mode != kScopeModeImplicit) return Error{ErrorCode::Corrupt, "scope record: mode"};
  if (r.state != kScopeOpen && r.state != kScopeDraining) return Error{ErrorCode::Corrupt, "scope record: state"};
  if (r.principal_id == 0) return Error{ErrorCode::Corrupt, "scope record: principal_id"};
  std::memcpy(r.scope_id.data(), b.data() + scr::scope_id, kScopeIdSize);
  r.opened_at_ms = get_le<std::uint64_t>(b, scr::opened_at_ms);
  r.expires_at_ms = get_le<std::uint64_t>(b, scr::expires_at_ms);
  r.last_used_ms = get_le<std::uint64_t>(b, scr::last_used_ms);
  return r;
}

Status encode(const ScopeRegionHeader& h, std::span<std::byte, kScopeRegionHeaderSize> out) {
  if (h.layout_version != kScopeLayoutVersion) return Error{ErrorCode::InvalidArgument, "scope region: layout_version"};
  if (h.record_size != kScopeRecordSize) return Error{ErrorCode::InvalidArgument, "scope region: record_size"};
  if (h.n_records == 0) return Error{ErrorCode::InvalidArgument, "scope region: n_records"};
  std::span<std::byte> b = out;
  std::fill(b.begin(), b.end(), std::byte{0});
  put_bytes(b, srh::magic, kScopeRegionMagic);
  put_le<std::uint16_t>(b, srh::layout_version, h.layout_version);
  put_le<std::uint16_t>(b, srh::record_size, h.record_size);
  put_le<std::uint32_t>(b, srh::n_records, h.n_records);
  put_le<std::uint32_t>(b, srh::crc, crc32c(b.first(srh::crc)));
  return {};
}

Expected<ScopeRegionHeader> decode_scope_region_header(std::span<const std::byte, kScopeRegionHeaderSize> in) {
  std::span<const std::byte> b = in;
  std::uint8_t magic[4];
  get_bytes(b, srh::magic, magic);
  if (std::memcmp(magic, kScopeRegionMagic, sizeof magic) != 0) return Error{ErrorCode::Corrupt, "scope region: magic"};
  if (get_le<std::uint32_t>(b, srh::crc) != crc32c(b.first(srh::crc))) return Error{ErrorCode::Corrupt, "scope region: crc"};
  ScopeRegionHeader h;
  h.layout_version = get_le<std::uint16_t>(b, srh::layout_version);
  if (h.layout_version != kScopeLayoutVersion) return Error{ErrorCode::Unsupported, "scope region: layout_version"};
  h.record_size = get_le<std::uint16_t>(b, srh::record_size);
  h.n_records = get_le<std::uint32_t>(b, srh::n_records);
  if (h.record_size != kScopeRecordSize || h.n_records == 0) return Error{ErrorCode::Corrupt, "scope region: fields"};
  return h;
}

}  // namespace miracache::proto
