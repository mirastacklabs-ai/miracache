// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <span>

#include "crypto/secret.h"
#include "util/expected.h"
#include "util/nonce_source.h"

namespace miracache {

// RFC 5869 HKDF with SHA-256 (OpenSSL EVP_KDF "HKDF", extract-and-expand).
// okm.size() must be 1..255*32.
Status hkdf_sha256(std::span<const std::byte> ikm, std::span<const std::byte> salt,
                   std::span<const std::byte> info, std::span<std::byte> okm);

// Per-block key: HKDF-SHA256(ikm = dek, salt = block salt, info = "mira-blk-v1"
// (ASCII, no NUL), L = 32).
Expected<BlockKey> derive_block_key(const Dek& dek, const BlockSalt& salt);

// Open side: the salt was read from a block header (untrusted until the tag verifies).
Expected<BlockKey> derive_block_key(const Dek& dek, std::span<const std::byte, 16> salt);

}  // namespace miracache
