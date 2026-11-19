// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

namespace miracache {

// FNV-1a 64 over a stream of u64 words. Used for simulation event-trace hashes,
// where stability and speed matter and cryptographic strength does not.
class TraceHash {
 public:
  void mix(std::uint64_t word) {
    for (int i = 0; i < 8; ++i) {
      h_ = (h_ ^ ((word >> (8 * i)) & 0xff)) * 0x100000001b3ULL;
    }
  }
  std::uint64_t value() const { return h_; }

 private:
  std::uint64_t h_ = 0xcbf29ce484222325ULL;
};

}  // namespace miracache
