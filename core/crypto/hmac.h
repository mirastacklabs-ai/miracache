// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <span>

#include "util/expected.h"

namespace miracache {

// HMAC-SHA256 (OpenSSL EVP_MAC) over the concatenation of `parts` (no copy, no separator).
Status hmac_sha256(std::span<const std::byte> key,
                   std::span<const std::span<const std::byte>> parts,
                   std::span<std::byte, 32> out);

}  // namespace miracache
