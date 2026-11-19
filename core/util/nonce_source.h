// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <array>
#include <cstddef>
#include <mutex>
#include <span>

#include "util/expected.h"

namespace miracache {

class NonceSource;

// Random per-block HKDF salt. Constructible only by NonceSource, so every salt in the
// system came from a (checked) source and never from Random or a literal.
struct BlockSalt {
  std::array<std::byte, 16> b;

 private:
  BlockSalt() = default;
  friend class NonceSource;
};

// CSPRNG-backed source of per-block salts. Do NOT satisfy this with Random (seedable,
// predictable by design). Injectable: simulation substitutes a labelled, test-only
// subclass overriding fill(). salt() rejects an all-zero draw and a repeat of the
// previous draw (stuck-RNG guard); both return Corrupt.
class NonceSource {
 public:
  virtual ~NonceSource() = default;
  Expected<BlockSalt> salt();

 protected:
  virtual Status fill(std::span<std::byte> out) = 0;

 private:
  std::mutex mu_;
  std::array<std::byte, 16> last_{};
  bool have_last_ = false;
};

// A random non-zero u32 from the CSPRNG (memory node IDs, plan 2C). Fails only if the CSPRNG does.
Expected<std::uint32_t> random_nonzero_u32();

// Production source: OpenSSL RAND_bytes (the only RAND_bytes call site in core/).
class OsNonceSource final : public NonceSource {
 protected:
  Status fill(std::span<std::byte> out) override;
};

}  // namespace miracache
