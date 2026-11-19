// SPDX-License-Identifier: Apache-2.0
#include "util/random.h"

#include <random>

#include "util/check.h"

namespace miracache {
namespace {

std::uint64_t splitmix64(std::uint64_t& x) {
  std::uint64_t z = (x += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

constexpr std::uint64_t rotl(std::uint64_t v, int k) { return (v << k) | (v >> (64 - k)); }

}  // namespace

std::uint64_t Random::below(std::uint64_t bound) {
  MIRACACHE_CHECK(bound > 0);
  const std::uint64_t limit = (~std::uint64_t{0}) - ((~std::uint64_t{0}) % bound) - 1;
  std::uint64_t r;
  do { r = next_u64(); } while (r > limit);
  return r % bound;
}

std::uint64_t Random::between(std::uint64_t lo, std::uint64_t hi) {
  MIRACACHE_CHECK(lo <= hi);
  const std::uint64_t span = hi - lo;
  if (span == ~std::uint64_t{0}) return next_u64();  // full range: span + 1 would wrap to 0
  return lo + below(span + 1);
}

bool Random::chance(double p) {
  if (p <= 0.0) return false;
  if (p >= 1.0) return true;
  return static_cast<double>(next_u64() >> 11) * 0x1.0p-53 < p;
}

SeededRandom::SeededRandom(std::uint64_t seed) {
  for (auto& w : s_) w = splitmix64(seed);
}

std::uint64_t SeededRandom::next_u64() {
  const std::uint64_t result = rotl(s_[1] * 5, 7) * 9;
  const std::uint64_t t = s_[1] << 17;
  s_[2] ^= s_[0];
  s_[3] ^= s_[1];
  s_[1] ^= s_[2];
  s_[0] ^= s_[3];
  s_[2] ^= t;
  s_[3] = rotl(s_[3], 45);
  return result;
}

RealRandom::RealRandom() : gen_([] {
  std::random_device rd;
  return (static_cast<std::uint64_t>(rd()) << 32) | rd();
}()) {}

}  // namespace miracache
