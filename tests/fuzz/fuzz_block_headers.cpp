// SPDX-License-Identifier: Apache-2.0
// libFuzzer target: decoders and validators must never crash, and anything the
// decoders accept must re-encode to the same bytes.
// Input layout: byte 0 selects the header (even = server, odd = extent); the rest is
// copied into a zero-padded header-sized buffer, so any input length is useful.
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "proto/extent_header.h"
#include "proto/server_header.h"

using namespace miracache::proto;

namespace {

template <std::size_t N>
std::array<std::byte, N> load(const std::uint8_t* data, std::size_t size) {
  std::array<std::byte, N> in{};
  std::memcpy(in.data(), data, size < N ? size : N);
  return in;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const bool server = (data[0] & 1) == 0;
  ++data;
  --size;
  // Capacity derived from the input so validate() sees both fitting and oversized blocks.
  const std::uint64_t capacity = size * 1031ULL;
  if (server) {
    const auto in = load<kServerHeaderSize>(data, size);
    if (auto h = decode_server_header(in)) {
      std::array<std::byte, kServerHeaderSize> out;
      encode(*h, out);
      if (out != in) std::abort();
      (void)validate(*h, capacity);
    }
  } else {
    const auto in = load<kExtentHeaderSize>(data, size);
    if (auto h = decode_extent_header(in)) {
      std::array<std::byte, kExtentHeaderSize> out;
      if (!encode(*h, out) || out != in) std::abort();
      (void)validate(*h, capacity);
      ServerHeader s;
      s.stored_len = capacity;
      (void)validate(s, *h, capacity);
    }
  }
  return 0;
}
