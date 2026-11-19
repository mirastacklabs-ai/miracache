// SPDX-License-Identifier: Apache-2.0
#include "crypto/hmac.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <memory>

namespace miracache {
namespace {

struct MacCtxDeleter { void operator()(EVP_MAC_CTX* c) const { EVP_MAC_CTX_free(c); } };

// Fetched once and shared (EVP_MAC objects are thread-safe); intentionally never freed.
EVP_MAC* mac() {
  static EVP_MAC* m = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  return m;
}

}  // namespace

Status hmac_sha256(std::span<const std::byte> key,
                   std::span<const std::span<const std::byte>> parts,
                   std::span<std::byte, 32> out) {
  EVP_MAC* m = mac();
  if (m == nullptr) return Error{ErrorCode::Unsupported, "hmac: EVP_MAC_fetch failed"};
  std::unique_ptr<EVP_MAC_CTX, MacCtxDeleter> ctx(EVP_MAC_CTX_new(m));
  if (!ctx) return Error{ErrorCode::ResourceExhausted, "hmac: ctx alloc"};
  static const unsigned char kDummy = 0;
  char digest[] = "SHA256";
  OSSL_PARAM params[2];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest, 0);
  params[1] = OSSL_PARAM_construct_end();
  const auto* kp = key.empty() ? &kDummy : reinterpret_cast<const unsigned char*>(key.data());
  if (EVP_MAC_init(ctx.get(), kp, key.size(), params) != 1)
    return Error{ErrorCode::Unsupported, "hmac: init failed"};
  for (auto p : parts) {
    if (p.empty()) continue;
    if (EVP_MAC_update(ctx.get(), reinterpret_cast<const unsigned char*>(p.data()), p.size()) != 1)
      return Error{ErrorCode::Unsupported, "hmac: update failed"};
  }
  std::size_t n = 0;
  if (EVP_MAC_final(ctx.get(), reinterpret_cast<unsigned char*>(out.data()), &n, out.size()) != 1 ||
      n != 32)
    return Error{ErrorCode::Unsupported, "hmac: final failed"};
  return {};
}

}  // namespace miracache
