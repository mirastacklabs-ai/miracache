// SPDX-License-Identifier: Apache-2.0
// Server block header (spec 5.4 r4): 128 bytes at the start of every block,
// written and read by the memory node. The client extent header (extent_header.h)
// and ciphertext follow it and are opaque to the server.
//
// Since r4 the header is IMMUTABLE after the put: the state/generation seqlock word
// lives in the server's in-memory array (state_gen.h), and the header carries only
// the generation, covered by hdr_crc.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "proto/extent_header.h"
#include "proto/state_gen.h"
#include "util/expected.h"

namespace miracache::proto {

inline constexpr std::size_t kServerHeaderSize = 128;
inline constexpr std::uint16_t kServerHeaderVersion = 0;
inline constexpr std::uint8_t kServerMagic[4] = {'M', 'I', 'R', 'H'};
// No flag bits are assigned in v0: any set bit is rejected by validate().
inline constexpr std::uint16_t kKnownServerFlags = 0;

// In-memory mirror of the wire layout; field order and sizes match the offsets
// below, so the struct is also the layout contract (checked by static_assert).
// encode()/decode() are the only way bytes are produced or consumed; they are
// explicit little-endian, so the struct is never memcpy'd to the wire.
struct ServerHeader {
  std::uint8_t magic[4] = {'M', 'I', 'R', 'H'};
  std::uint16_t hdr_version = kServerHeaderVersion;
  std::uint16_t flags = 0;
  std::uint64_t generation = 1;  // 1..2^56-1, immutable
  std::uint64_t stored_len = 0;
  std::uint8_t scope_id[32] = {};
  std::uint8_t key_hash[32] = {};
  std::uint8_t parent_hash[16] = {};  // truncated; zero = chain root
  std::uint64_t chain_pos = 0;
  std::uint32_t writer_id = 0;
  std::uint32_t format_epoch = 0;
  std::uint32_t payload_crc = 0;  // CRC32C of the ciphertext extent
  std::uint32_t hdr_crc = 0;      // CRC32C of bytes 0..123; set by encode()
};

static_assert(sizeof(ServerHeader) == kServerHeaderSize);
static_assert(alignof(ServerHeader) <= 8);
static_assert(kServerHeaderSize % 64 == 0);
static_assert(offsetof(ServerHeader, magic) == 0);
static_assert(offsetof(ServerHeader, hdr_version) == 4);
static_assert(offsetof(ServerHeader, flags) == 6);
static_assert(offsetof(ServerHeader, generation) == 8);
static_assert(offsetof(ServerHeader, stored_len) == 16);
static_assert(offsetof(ServerHeader, scope_id) == 24);
static_assert(offsetof(ServerHeader, key_hash) == 56);
static_assert(offsetof(ServerHeader, parent_hash) == 88);
static_assert(offsetof(ServerHeader, chain_pos) == 104);
static_assert(offsetof(ServerHeader, writer_id) == 112);
static_assert(offsetof(ServerHeader, format_epoch) == 116);
static_assert(offsetof(ServerHeader, payload_crc) == 120);
static_assert(offsetof(ServerHeader, hdr_crc) == 124);

// Serialises h; hdr_crc in h is ignored and recomputed over bytes 0..123.
void encode(const ServerHeader& h, std::span<std::byte, kServerHeaderSize> out);

// Syntax only. Checks, in order: magic, version, hdr_crc, generation range (1..2^56-1).
// Fails with Corrupt (bad magic, bad hdr_crc, bad generation) or Unsupported (version).
//
// SECURITY: hdr_crc is CRC32C. It detects accidental corruption only and is NOT
// authentication: anyone who can write the block can recompute it. Never trust a
// decoded header for anything but sizing, and always run validate() before using
// stored_len or any other field to index memory. Authenticity comes solely from the
// client's GCM tag over the extent (security.md).
Expected<ServerHeader> decode_server_header(std::span<const std::byte, kServerHeaderSize> in);

// Semantic bounds check for a decoded header, to be run before any field is used.
// block_capacity is the number of bytes available after the server header for the
// client extent. Rejects (Corrupt): unknown flag bits, stored_len > block_capacity, and
// stored_len < 64 (cannot hold the extent header; the block state is no longer in the
// header, so this applies to every header being validated for a read).
Status validate(const ServerHeader& h, std::uint64_t block_capacity);

// As above for the pair (server header, client extent header, e.g. after the extent
// header has been read): also checks stored_len >= 64 + plaintext_len + 16 bytes of
// GCM tag per segment (see validate(ExtentHeader) and min_stored_len()).
Status validate(const ServerHeader& s, const ExtentHeader& e, std::uint64_t block_capacity);

}  // namespace miracache::proto
