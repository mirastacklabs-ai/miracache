// SPDX-License-Identifier: Apache-2.0
#include "util/nonce_source.h"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <limits>

namespace miracache {

Expected<BlockSalt> NonceSource::salt() {
  BlockSalt s;
  Status st = fill(std::span<std::byte>(s.b));
  if (!st) return st.error();
  static const std::array<std::byte, 16> kZero{};
  std::lock_guard<std::mutex> lk(mu_);
  if (CRYPTO_memcmp(s.b.data(), kZero.data(), 16) == 0)
    return Error{ErrorCode::Corrupt, "nonce source returned all-zero salt"};
  if (have_last_ && CRYPTO_memcmp(s.b.data(), last_.data(), 16) == 0)
    return Error{ErrorCode::Corrupt, "nonce source repeated a salt"};
  last_ = s.b;
  have_last_ = true;
  return s;
}

Status OsNonceSource::fill(std::span<std::byte> out) {
  if (out.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    return Error{ErrorCode::InvalidArgument, "rand: too long"};
  if (RAND_bytes(reinterpret_cast<unsigned char*>(out.data()), static_cast<int>(out.size())) != 1)
    return Error{ErrorCode::Unsupported, "RAND_bytes failed"};
  return {};
}

Expected<std::uint32_t> random_nonzero_u32() {
  for (int i = 0; i < 8; ++i) {  // an all-zero draw has probability 2^-32; eight in a row means a broken CSPRNG
    std::uint32_t v = 0;
    if (RAND_bytes(reinterpret_cast<unsigned char*>(&v), sizeof v) != 1)
      return Error{ErrorCode::Unsupported, "RAND_bytes failed"};
    if (v != 0) return v;
  }
  return Error{ErrorCode::Corrupt, "RAND_bytes returned zero repeatedly"};
}

}  // namespace miracache
