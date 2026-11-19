// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "store/config.h"
#include "util/expected.h"

namespace miracache::store {

// Maps one fixed-size region per segment. Mappings stay valid until the Backing is
// destroyed, which also releases any file locks.
class Backing {
 public:
  virtual ~Backing() = default;
  // Maps (creating if needed) segment `seg` with exactly `len` bytes. Idempotent per seg.
  virtual Expected<std::span<std::byte>> map(std::uint32_t seg, std::size_t len) = 0;
  // Makes [off, off+len) of segment `seg` durable (no-op where nothing persists).
  virtual Status sync(std::uint32_t seg, std::size_t off, std::size_t len) = 0;
  virtual BackingKind kind() const noexcept = 0;
};

// Anon: test-only, zero-filled, never persists. File / Hugetlbfs: dir/segment-NNNN.
std::unique_ptr<Backing> make_backing(const StoreConfig& cfg);

}  // namespace miracache::store
