// SPDX-License-Identifier: Apache-2.0
#include "proto/extent_header.h"

#include <algorithm>
#include <cstring>

#include "proto/le.h"

namespace miracache::proto {
namespace {

bool segment_ok(std::uint8_t log2) { return log2 >= kMinLog2Segment && log2 <= kMaxLog2Segment; }

bool all_zero(const std::uint8_t* p, std::size_t n) {
  return std::all_of(p, p + n, [](std::uint8_t v) { return v == 0; });
}

}  // namespace

Status encode(const ExtentHeader& h, std::span<std::byte, kExtentHeaderSize> out) {
  if (!segment_ok(h.log2_segment)) return Error{ErrorCode::InvalidArgument, "extent: log2_segment"};
  if (h.z7 != 0 || h.z12 != 0 || !all_zero(h.reserved, sizeof h.reserved)) {
    return Error{ErrorCode::InvalidArgument, "extent: reserved not zero"};
  }
  std::span<std::byte> b = out;
  put_bytes(b, 0, h.magic);
  put_le<std::uint8_t>(b, 4, h.crypto_version);
  put_le<std::uint8_t>(b, 5, h.cipher_id);
  put_le<std::uint8_t>(b, 6, h.log2_segment);
  put_le<std::uint8_t>(b, 7, 0);
  put_le<std::uint32_t>(b, 8, h.kver);
  put_le<std::uint32_t>(b, 12, 0);
  put_bytes(b, 16, h.block_salt);
  put_le<std::uint64_t>(b, 32, h.plaintext_len);
  put_bytes(b, 40, h.reserved);
  return {};
}

Expected<ExtentHeader> decode_extent_header(std::span<const std::byte, kExtentHeaderSize> in) {
  std::span<const std::byte> b = in;
  ExtentHeader h;
  get_bytes(b, 0, h.magic);
  if (std::memcmp(h.magic, kExtentMagic, sizeof h.magic) != 0) {
    return Error{ErrorCode::Corrupt, "extent: bad magic"};
  }
  h.crypto_version = get_le<std::uint8_t>(b, 4);
  if (h.crypto_version != kCryptoVersion) return Error{ErrorCode::Unsupported, "extent: version"};
  h.cipher_id = get_le<std::uint8_t>(b, 5);
  if (h.cipher_id != static_cast<std::uint8_t>(CipherId::Aes256Gcm) &&
      h.cipher_id != static_cast<std::uint8_t>(CipherId::Aegis256)) {
    return Error{ErrorCode::Unsupported, "extent: cipher_id"};
  }
  h.log2_segment = get_le<std::uint8_t>(b, 6);
  if (!segment_ok(h.log2_segment)) return Error{ErrorCode::Corrupt, "extent: log2_segment"};
  h.z7 = get_le<std::uint8_t>(b, 7);
  h.kver = get_le<std::uint32_t>(b, 8);
  h.z12 = get_le<std::uint32_t>(b, 12);
  get_bytes(b, 16, h.block_salt);
  h.plaintext_len = get_le<std::uint64_t>(b, 32);
  get_bytes(b, 40, h.reserved);
  if (h.z7 != 0 || h.z12 != 0 || !all_zero(h.reserved, sizeof h.reserved)) return Error{ErrorCode::Corrupt, "extent: reserved"};
  return h;
}

Expected<std::uint64_t> min_stored_len(const ExtentHeader& h) {
  if (!segment_ok(h.log2_segment)) return Error{ErrorCode::Corrupt, "extent: log2_segment"};
  const std::uint64_t segments = segment_count(h.plaintext_len, h.log2_segment);
  // segments <= 2^48 here, so segments * 16 cannot overflow; guard the sums.
  const std::uint64_t tags = segments * kGcmTagSize;
  std::uint64_t total = kExtentHeaderSize;
  if (h.plaintext_len > ~std::uint64_t{0} - total) return Error{ErrorCode::Corrupt, "extent: plaintext_len overflow"};
  total += h.plaintext_len;
  if (tags > ~std::uint64_t{0} - total) return Error{ErrorCode::Corrupt, "extent: plaintext_len overflow"};
  return total + tags;
}

Status validate(const ExtentHeader& h, std::uint64_t block_capacity) {
  const auto need = min_stored_len(h);
  if (!need) return need.error();
  if (*need > block_capacity) return Error{ErrorCode::Corrupt, "extent: plaintext_len exceeds block"};
  return {};
}

std::array<std::byte, kAadSize> build_aad(const ExtentHeader& h, const std::uint8_t (&scope_id)[32],
                                          const std::uint8_t (&key_hash)[32]) {
  std::array<std::byte, kAadSize> a{};
  std::span<std::byte> b = a;
  put_le<std::uint8_t>(b, 0, h.crypto_version);
  put_le<std::uint8_t>(b, 1, h.cipher_id);
  put_le<std::uint8_t>(b, 2, h.log2_segment);
  put_le<std::uint8_t>(b, 3, 0);
  put_le<std::uint32_t>(b, 4, h.kver);
  put_bytes(b, 8, scope_id);
  put_bytes(b, 40, key_hash);
  put_le<std::uint64_t>(b, 72, h.plaintext_len);
  return a;
}

std::array<std::byte, kNonceSize> stream_nonce(std::uint32_t i, bool last) {
  std::array<std::byte, kNonceSize> n{};  // bytes 0..6 stay zero
  for (int k = 0; k < 4; ++k) n[7 + k] = static_cast<std::byte>((i >> (8 * (3 - k))) & 0xff);
  n[11] = static_cast<std::byte>(last ? 1 : 0);
  return n;
}

}  // namespace miracache::proto
