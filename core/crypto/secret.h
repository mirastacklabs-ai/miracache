// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <openssl/crypto.h>

#include <array>
#include <cstddef>
#include <span>

namespace miracache {

// Fixed-size secret key material. Not copyable; move cleanses the source; the
// destructor cleanses (OPENSSL_cleanse is not optimised away).
template <std::size_t N>
class Secret {
 public:
  Secret() { OPENSSL_cleanse(b_.data(), N); }
  explicit Secret(std::span<const std::byte, N> src) {
    for (std::size_t i = 0; i < N; ++i) b_[i] = src[i];
  }
  Secret(const Secret&) = delete;
  Secret& operator=(const Secret&) = delete;
  Secret(Secret&& o) noexcept : b_(o.b_) { OPENSSL_cleanse(o.b_.data(), N); }
  Secret& operator=(Secret&& o) noexcept {
    if (this != &o) {
      b_ = o.b_;
      OPENSSL_cleanse(o.b_.data(), N);
    }
    return *this;
  }
  ~Secret() { OPENSSL_cleanse(b_.data(), N); }

  std::span<std::byte, N> bytes() { return std::span<std::byte, N>(b_); }
  std::span<const std::byte, N> bytes() const { return std::span<const std::byte, N>(b_); }

 private:
  std::array<std::byte, N> b_;
};

using Dek = Secret<32>;
using BlockKey = Secret<32>;

}  // namespace miracache
