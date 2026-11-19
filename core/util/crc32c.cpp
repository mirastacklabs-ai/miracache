// SPDX-License-Identifier: Apache-2.0
#include "util/crc32c.h"

#include <array>

namespace miracache {
namespace {

constexpr std::array<std::uint32_t, 256> make_table() {
  std::array<std::uint32_t, 256> t{};
  for (std::uint32_t i = 0; i < 256; ++i) {
    std::uint32_t c = i;
    for (int k = 0; k < 8; ++k) c = (c >> 1) ^ ((c & 1) ? 0x82F63B78u : 0u);
    t[i] = c;
  }
  return t;
}

constexpr auto kTable = make_table();

// GF(2) matrix helpers (zlib crc32_combine technique) for the reflected CRC32C polynomial.
std::uint32_t gf2_times(const std::uint32_t* mat, std::uint32_t vec) {
  std::uint32_t sum = 0;
  for (; vec != 0; vec >>= 1, ++mat)
    if (vec & 1) sum ^= *mat;
  return sum;
}

void gf2_square(std::uint32_t* sq, const std::uint32_t* mat) {
  for (int n = 0; n < 32; ++n) sq[n] = gf2_times(mat, mat[n]);
}

}  // namespace

std::uint32_t crc32c(std::span<const std::byte> data, std::uint32_t seed) {
  std::uint32_t c = ~seed;
  for (std::byte b : data) c = kTable[(c ^ static_cast<std::uint32_t>(b)) & 0xff] ^ (c >> 8);
  return ~c;
}

std::uint32_t crc32c_combine(std::uint32_t crc_a, std::uint32_t crc_b, std::uint64_t len_b) {
  if (len_b == 0) return crc_a;
  std::uint32_t even[32], odd[32];
  odd[0] = 0x82F63B78u;  // operator for one zero bit
  std::uint32_t row = 1;
  for (int n = 1; n < 32; ++n, row <<= 1) odd[n] = row;
  gf2_square(even, odd);  // two zero bits
  gf2_square(odd, even);  // four zero bits
  do {
    gf2_square(even, odd);  // first pass: one zero byte
    if (len_b & 1) crc_a = gf2_times(even, crc_a);
    len_b >>= 1;
    if (len_b == 0) break;
    gf2_square(odd, even);
    if (len_b & 1) crc_a = gf2_times(odd, crc_a);
    len_b >>= 1;
  } while (len_b != 0);
  return crc_a ^ crc_b;
}

}  // namespace miracache
