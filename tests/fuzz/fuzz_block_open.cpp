// SPDX-License-Identifier: Apache-2.0
// libFuzzer target: open_begin/open_block on attacker-controlled block bytes must never
// crash, and on failure the engine buffer must be fully zeroed.
// Input: bytes 0..2 pick plaintext_len (0..~4 segments of 64 KiB) and kver; the rest is
// the stored block (zero extended / truncated by whatever the input provides).
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "crypto/block_codec.h"

using namespace miracache;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size < 3) return 0;
  static const Dek dek = [] {
    std::array<std::byte, 32> k{};
    k[0] = std::byte{1};
    return Dek(std::span<const std::byte, 32>(k));
  }();
  static GcmCtx gcm = [] {
    auto r = GcmCtx::create();
    return std::move(r.value());
  }();

  BlockMeta m{};
  m.kver = data[2] & 3;
  m.plaintext_len = (static_cast<std::uint64_t>(data[0]) | (static_cast<std::uint64_t>(data[1]) << 8)) * 5;
  m.segment_log2 = 16;
  const auto pool = std::as_bytes(std::span(data + 3, size - 3));

  auto oc = open_begin(dek, m, pool);
  if (!oc) return 0;
  std::vector<std::byte> out(m.plaintext_len, std::byte{0xAA});
  if (!open_block(gcm, *oc, pool, out)) {
    if (!std::all_of(out.begin(), out.end(), [](std::byte b) { return b == std::byte{0}; })) std::abort();
  }
  return 0;
}
