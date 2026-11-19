// SPDX-License-Identifier: Apache-2.0
// Client extent header (spec 5.4 r4): 64 bytes, opaque to the memory node.
// Segments follow it: ciphertext || 16-byte GCM tag. Crypto itself (security.md)
// is not implemented here; this file only fixes the layout.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "util/expected.h"

namespace miracache::proto {

inline constexpr std::size_t kExtentHeaderSize = 64;
inline constexpr std::uint8_t kExtentMagic[4] = {'M', 'I', 'R', 'C'};
inline constexpr std::uint8_t kCryptoVersion = 1;
inline constexpr std::uint8_t kMinLog2Segment = 16;  // 64 KiB
inline constexpr std::uint8_t kMaxLog2Segment = 20;  // 1 MiB
inline constexpr std::size_t kGcmTagSize = 16;

enum class CipherId : std::uint8_t { Aes256Gcm = 1, Aegis256 = 2 /* reserved */ };

struct ExtentHeader {
  std::uint8_t magic[4] = {'M', 'I', 'R', 'C'};
  std::uint8_t crypto_version = kCryptoVersion;
  std::uint8_t cipher_id = static_cast<std::uint8_t>(CipherId::Aes256Gcm);
  std::uint8_t log2_segment = kMinLog2Segment;
  std::uint8_t z7 = 0;  // reserved, must be zero
  std::uint32_t kver = 0;
  std::uint32_t z12 = 0;  // reserved, must be zero
  std::uint8_t block_salt[16] = {};  // 128 random bits per put, never deterministic
  std::uint64_t plaintext_len = 0;
  std::uint8_t reserved[24] = {};  // must be zero
};

static_assert(sizeof(ExtentHeader) == kExtentHeaderSize);
static_assert(offsetof(ExtentHeader, magic) == 0);
static_assert(offsetof(ExtentHeader, crypto_version) == 4);
static_assert(offsetof(ExtentHeader, cipher_id) == 5);
static_assert(offsetof(ExtentHeader, log2_segment) == 6);
static_assert(offsetof(ExtentHeader, z7) == 7);
static_assert(offsetof(ExtentHeader, kver) == 8);
static_assert(offsetof(ExtentHeader, z12) == 12);
static_assert(offsetof(ExtentHeader, block_salt) == 16);
static_assert(offsetof(ExtentHeader, plaintext_len) == 32);
static_assert(offsetof(ExtentHeader, reserved) == 40);
static_assert(alignof(ExtentHeader) <= 8);

// Fails with InvalidArgument if log2_segment is outside 16..20 or any reserved field (z7, z12, reserved) is non-zero.
Status encode(const ExtentHeader& h, std::span<std::byte, kExtentHeaderSize> out);

// Fails with Corrupt (magic, segment size, reserved fields) or Unsupported (version, cipher).
//
// SECURITY: the extent header carries no integrity check of its own and is attacker
// controlled until the GCM tag verifies; decoding is syntax only. Run validate()
// before using plaintext_len for any allocation or indexing.
Expected<ExtentHeader> decode_extent_header(std::span<const std::byte, kExtentHeaderSize> in);

// Smallest stored_len that can hold this extent: 64 + plaintext_len + 16 * segments,
// where segments = segment_count() (D17: an empty plaintext still has one segment). Corrupt on overflow or if
// log2_segment is out of range.
Expected<std::uint64_t> min_stored_len(const ExtentHeader& h);

// Bounds check: the extent described by h must fit in block_capacity bytes (and
// plaintext_len must not overflow the size computation). Fails with Corrupt.
Status validate(const ExtentHeader& h, std::uint64_t block_capacity);

inline constexpr std::size_t kAadSize = 80;
inline constexpr std::size_t kNonceSize = 12;

// D17: max(1, ceil(plaintext_len / 2^log2_segment)). log2 must be 16..20 (not checked here).
constexpr std::uint64_t segment_count(std::uint64_t plaintext_len, std::uint8_t log2_segment) {
  const std::uint64_t seg = std::uint64_t{1} << log2_segment;
  const std::uint64_t n = plaintext_len / seg + (plaintext_len % seg != 0 ? 1 : 0);
  return n == 0 ? 1 : n;
}

// D18: 80-byte AAD = ver u8, cipher u8, segment_log2 u8, 0 u8, kver u32 LE, scope_id[32],
// key_hash[32], plaintext_len u64 LE. Built from the caller's expectations (h is what the
// client expects, not what it read); only block_salt is taken from the block.
std::array<std::byte, kAadSize> build_aad(const ExtentHeader& h, const std::uint8_t (&scope_id)[32],
                                          const std::uint8_t (&key_hash)[32]);

// D16: STREAM nonce of segment i = 0^56 || u32 i (BIG-endian, the only BE field) || u8 last.
std::array<std::byte, kNonceSize> stream_nonce(std::uint32_t i, bool last);

}  // namespace miracache::proto
