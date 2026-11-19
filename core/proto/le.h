// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <type_traits>

namespace miracache::proto {

// Debug-only bounds checks (overflow-safe); callers must pass in-range offsets.
#define MIRACACHE_LE_BOUNDS(buf, off, n) assert((off) <= (buf).size() && (n) <= (buf).size() - (off))

// Little-endian field access at a byte offset, independent of host endianness.
template <typename T>
void put_le(std::span<std::byte> buf, std::size_t off, T v) {
  static_assert(std::is_unsigned_v<T>);
  MIRACACHE_LE_BOUNDS(buf, off, sizeof(T));
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    buf[off + i] = static_cast<std::byte>((v >> (8 * i)) & 0xff);
  }
}

template <typename T>
T get_le(std::span<const std::byte> buf, std::size_t off) {
  static_assert(std::is_unsigned_v<T>);
  MIRACACHE_LE_BOUNDS(buf, off, sizeof(T));
  T v = 0;
  for (std::size_t i = 0; i < sizeof(T); ++i) {
    v |= static_cast<T>(static_cast<T>(buf[off + i]) << (8 * i));
  }
  return v;
}

template <std::size_t N>
void put_bytes(std::span<std::byte> buf, std::size_t off, const std::uint8_t (&src)[N]) {
  MIRACACHE_LE_BOUNDS(buf, off, N);
  std::memcpy(buf.data() + off, src, N);
}

template <std::size_t N>
void get_bytes(std::span<const std::byte> buf, std::size_t off, std::uint8_t (&dst)[N]) {
  MIRACACHE_LE_BOUNDS(buf, off, N);
  std::memcpy(dst, buf.data() + off, N);
}

}  // namespace miracache::proto
