// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

namespace miracache {

// All randomness in core/ flows through Random (spec 14.3).
//
// SECURITY: Random is for simulation, jitter and test workloads ONLY. It is seedable,
// predictable and not cryptographically secure. It must NEVER be used to produce
// nonces, keys, key material or any security-relevant value; those come from a
// NonceSource / CSPRNG (util/nonce_source.h, security.md). RealRandom is not a CSPRNG
// either.
class Random {
 public:
  virtual ~Random() = default;
  virtual std::uint64_t next_u64() = 0;

  // Uniform in [0, bound). bound == 0 is a contract violation (traps). Rejection
  // sampling, no modulo bias.
  std::uint64_t below(std::uint64_t bound);
  // Uniform in [lo, hi] inclusive; lo > hi traps. The full range [0, 2^64-1] is valid.
  std::uint64_t between(std::uint64_t lo, std::uint64_t hi);
  // True with probability p (clamped to [0, 1]).
  bool chance(double p);
};

// xoshiro256** seeded through splitmix64. Same seed, same stream, on every platform.
class SeededRandom final : public Random {
 public:
  explicit SeededRandom(std::uint64_t seed);
  std::uint64_t next_u64() override;

 private:
  std::uint64_t s_[4];
};

// Non-deterministic; production only.
class RealRandom final : public Random {
 public:
  RealRandom();
  std::uint64_t next_u64() override { return gen_.next_u64(); }

 private:
  SeededRandom gen_;
};

}  // namespace miracache
