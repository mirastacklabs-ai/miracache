// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <span>

namespace miracache {

// CRC32C (Castagnoli), reflected, init/xorout 0xFFFFFFFF.
// Chain by passing the previous result as 'seed': crc32c(b, crc32c(a)) == crc32c(a||b).
// TODO: SSE4.2 / ARMv8 CRC instruction path; this is the portable table version.
std::uint32_t crc32c(std::span<const std::byte> data, std::uint32_t seed = 0);

// Combines CRCs of adjacent pieces: given crc_a = crc32c(A) and crc_b = crc32c(B) (both
// seed 0), returns crc32c(A||B) without touching the bytes; len_b = |B|. O(log len_b).
std::uint32_t crc32c_combine(std::uint32_t crc_a, std::uint32_t crc_b, std::uint64_t len_b);

}  // namespace miracache
