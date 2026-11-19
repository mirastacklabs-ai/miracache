// SPDX-License-Identifier: Apache-2.0
// SHA-256 and lower-case hex, the only hash and the only hex form the bundle envelope uses
// (membership plan decision 2, rules 4 and 7).
#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

namespace miracache::control {

using Sha256Digest = std::array<std::uint8_t, 32>;
using KeyId = std::array<std::uint8_t, 8>;  // first 8 bytes of SHA-256(raw public key)

Sha256Digest sha256(std::string_view bytes);

// Lower-case hex of `bytes` (2 characters per byte).
std::string to_hex(std::span<const std::uint8_t> bytes);

// Decodes exactly out.size() bytes from `hex`, which must be exactly 2 * out.size() characters
// of [0-9a-f]. Upper-case digits are rejected. Returns false on any deviation.
bool from_hex_lower(std::string_view hex, std::span<std::uint8_t> out);


}  // namespace miracache::control
