// SPDX-License-Identifier: Apache-2.0
#include "control/sha256.h"

#include <openssl/evp.h>

#include "util/check.h"

namespace miracache::control {

Sha256Digest sha256(std::string_view bytes) {
  Sha256Digest out{};
  unsigned int n = 0;
  const int ok = EVP_Digest(bytes.data(), bytes.size(), out.data(), &n, EVP_sha256(), nullptr);
  MIRACACHE_CHECK(ok == 1 && n == out.size());
  return out;
}

std::string to_hex(std::span<const std::uint8_t> bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string s;
  s.reserve(bytes.size() * 2);
  for (const std::uint8_t b : bytes) {
    s.push_back(kDigits[b >> 4]);
    s.push_back(kDigits[b & 15]);
  }
  return s;
}

namespace {
int nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}
}  // namespace

bool from_hex_lower(std::string_view hex, std::span<std::uint8_t> out) {
  if (hex.size() != out.size() * 2) return false;
  for (std::size_t i = 0; i < out.size(); ++i) {
    const int hi = nibble(hex[2 * i]);
    const int lo = nibble(hex[2 * i + 1]);
    if (hi < 0 || lo < 0) return false;
    out[i] = static_cast<std::uint8_t>((hi << 4) | lo);
  }
  return true;
}

}  // namespace miracache::control
