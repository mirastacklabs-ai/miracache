// SPDX-License-Identifier: Apache-2.0
// Fault hooks for the simulator (A1.4 S6).
//
// 1. fire(): seeded fault coin for sim code (never called from core/ production paths).
// 2. Teeth: deliberate store bugs the simulator MUST detect. Each is a one-line hook in the
//    store marked MIRACACHE_TEETH_ON(name). They exist only when the build defines
//    MIRACACHE_TEETH (cmake -DMIRACACHE_TEETH=ON, the sim preset); otherwise on() is a
//    constexpr false and every hook folds away at compile time (zero cost, no state).
#pragma once

#include <cstdint>

#include "util/random.h"

namespace miracache::buggify {

enum class Teeth : std::uint8_t {
  None = 0,
  NoFence,             // fence() reports success but leaves the write MR registered
  SkipSeq,             // a removed-while-leased block keeps its COMMITTED state word
  CommitBeforeDigest,  // commit ignores the digest verdict
  ReuseGeneration,     // the allocator hands out an already-issued generation
  EndpointCapLax,      // the per-endpoint put cap admits one put too many
  LeaseCapLax,         // the per-session lease cap admits one lease too many
  UnknownPutOk,        // commit/cancel of an unknown put id answers Ok instead of UnknownPut
  ForeignPutId,        // commit/cancel ignore which endpoint carried PUT_BEGIN
};

inline bool fire(Random& rng, double p) { return rng.chance(p); }

#ifdef MIRACACHE_TEETH
inline constexpr bool kTeethBuilt = true;
inline Teeth& active_teeth() {
  static Teeth t = Teeth::None;
  return t;
}
inline void set_teeth(Teeth t) { active_teeth() = t; }
inline bool on(Teeth t) { return active_teeth() == t; }
#else
inline constexpr bool kTeethBuilt = false;
inline void set_teeth(Teeth) {}
constexpr bool on(Teeth) { return false; }
#endif

}  // namespace miracache::buggify

#define MIRACACHE_TEETH_ON(name) (::miracache::buggify::on(::miracache::buggify::Teeth::name))
