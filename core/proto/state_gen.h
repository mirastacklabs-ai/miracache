// SPDX-License-Identifier: Apache-2.0
// Block state + generation packed into the one 8-byte word that is mutated after
// commit (the seqlock word of the server's in-memory block array). Since spec r4 this
// word is NOT part of the on-block header: the header carries only the immutable
// generation (server_header.h).
#pragma once

#include <cstdint>

namespace miracache::proto {

enum class BlockState : std::uint8_t { Free = 0, Writing = 1, Committed = 2, Zombie = 3 };

inline constexpr std::uint64_t kMaxGeneration = (std::uint64_t{1} << 56) - 1;

// 0 is never a valid generation and the top 8 bits must be zero (plan D14).
constexpr bool generation_valid(std::uint64_t g) { return g != 0 && g <= kMaxGeneration; }

constexpr std::uint64_t pack_state_gen(BlockState s, std::uint64_t generation) {
  return (generation << 8) | static_cast<std::uint64_t>(s);
}
constexpr BlockState state_of(std::uint64_t state_gen) {
  return static_cast<BlockState>(state_gen & 0xff);
}
constexpr std::uint64_t generation_of(std::uint64_t state_gen) { return state_gen >> 8; }

}  // namespace miracache::proto
