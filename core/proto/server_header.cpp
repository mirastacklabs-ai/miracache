// SPDX-License-Identifier: Apache-2.0
#include "proto/server_header.h"

#include <cstring>

#include "proto/le.h"
#include "proto/extent_header.h"
#include "util/crc32c.h"

namespace miracache::proto {
namespace {

constexpr std::size_t kHdrCrcOff = 124;

// CRC32C over bytes 0..123 (generation is immutable, so it is covered).
std::uint32_t header_crc(std::span<const std::byte> b) { return crc32c(b.first(kHdrCrcOff)); }

}  // namespace

void encode(const ServerHeader& h, std::span<std::byte, kServerHeaderSize> out) {
  std::span<std::byte> b = out;
  put_bytes(b, 0, h.magic);
  put_le<std::uint16_t>(b, 4, h.hdr_version);
  put_le<std::uint16_t>(b, 6, h.flags);
  put_le<std::uint64_t>(b, 8, h.generation);
  put_le<std::uint64_t>(b, 16, h.stored_len);
  put_bytes(b, 24, h.scope_id);
  put_bytes(b, 56, h.key_hash);
  put_bytes(b, 88, h.parent_hash);
  put_le<std::uint64_t>(b, 104, h.chain_pos);
  put_le<std::uint32_t>(b, 112, h.writer_id);
  put_le<std::uint32_t>(b, 116, h.format_epoch);
  put_le<std::uint32_t>(b, 120, h.payload_crc);
  put_le<std::uint32_t>(b, kHdrCrcOff, header_crc(b));
}

Expected<ServerHeader> decode_server_header(std::span<const std::byte, kServerHeaderSize> in) {
  std::span<const std::byte> b = in;
  ServerHeader h;
  get_bytes(b, 0, h.magic);
  if (std::memcmp(h.magic, kServerMagic, sizeof h.magic) != 0) {
    return Error{ErrorCode::Corrupt, "server header: bad magic"};
  }
  // Order matters: magic -> version -> CRC. The CRC layout is version-specific, so an
  // unknown version must be reported as such before its CRC is judged.
  h.hdr_version = get_le<std::uint16_t>(b, 4);
  if (h.hdr_version != kServerHeaderVersion) {
    return Error{ErrorCode::Unsupported, "server header: unknown version"};
  }
  h.hdr_crc = get_le<std::uint32_t>(b, kHdrCrcOff);
  if (h.hdr_crc != header_crc(b)) return Error{ErrorCode::Corrupt, "server header: bad hdr_crc"};
  h.flags = get_le<std::uint16_t>(b, 6);
  h.generation = get_le<std::uint64_t>(b, 8);
  if (!generation_valid(h.generation)) return Error{ErrorCode::Corrupt, "server header: bad generation"};
  h.stored_len = get_le<std::uint64_t>(b, 16);
  get_bytes(b, 24, h.scope_id);
  get_bytes(b, 56, h.key_hash);
  get_bytes(b, 88, h.parent_hash);
  h.chain_pos = get_le<std::uint64_t>(b, 104);
  h.writer_id = get_le<std::uint32_t>(b, 112);
  h.format_epoch = get_le<std::uint32_t>(b, 116);
  h.payload_crc = get_le<std::uint32_t>(b, 120);
  return h;
}

Status validate(const ServerHeader& h, std::uint64_t block_capacity) {
  if ((h.flags & ~kKnownServerFlags) != 0) return Error{ErrorCode::Corrupt, "server header: unknown flags"};
  if (h.stored_len > block_capacity) return Error{ErrorCode::Corrupt, "server header: stored_len > capacity"};
  if (h.stored_len < kExtentHeaderSize) {
    return Error{ErrorCode::Corrupt, "server header: stored_len < extent header"};
  }
  return {};
}

Status validate(const ServerHeader& s, const ExtentHeader& e, std::uint64_t block_capacity) {
  if (auto r = validate(s, block_capacity); !r) return r;
  if (auto r = validate(e, block_capacity); !r) return r;
  const auto need = min_stored_len(e);
  if (!need || s.stored_len < *need) return Error{ErrorCode::Corrupt, "stored_len < extent minimum"};
  return {};
}

}  // namespace miracache::proto
