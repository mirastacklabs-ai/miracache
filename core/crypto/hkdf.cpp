// SPDX-License-Identifier: Apache-2.0
#include "crypto/hkdf.h"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <memory>

namespace miracache {
namespace {

struct KdfCtxDeleter { void operator()(EVP_KDF_CTX* c) const { EVP_KDF_CTX_free(c); } };

// Fetched once and shared (EVP_KDF objects are thread-safe); intentionally never freed.
EVP_KDF* kdf() {
  static EVP_KDF* k = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
  return k;
}

constexpr char kInfo[] = "mira-blk-v1";

}  // namespace

Status hkdf_sha256(std::span<const std::byte> ikm, std::span<const std::byte> salt,
                   std::span<const std::byte> info, std::span<std::byte> okm) {
  if (okm.empty() || okm.size() > 255 * 32) return Error{ErrorCode::InvalidArgument, "hkdf: bad okm length"};
  EVP_KDF* k = kdf();
  if (k == nullptr) return Error{ErrorCode::Unsupported, "hkdf: EVP_KDF_fetch failed"};
  std::unique_ptr<EVP_KDF_CTX, KdfCtxDeleter> ctx(EVP_KDF_CTX_new(k));
  if (!ctx) return Error{ErrorCode::ResourceExhausted, "hkdf: ctx alloc"};
  static const unsigned char kDummy = 0;  // non-null pointer for empty inputs
  auto ptr = [](std::span<const std::byte> s) -> void* {
    return s.empty() ? const_cast<unsigned char*>(&kDummy)
                     : static_cast<void*>(const_cast<std::byte*>(s.data()));
  };
  char digest[] = "SHA256";
  OSSL_PARAM params[5];
  params[0] = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0);
  params[1] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, ptr(ikm), ikm.size());
  params[2] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, ptr(salt), salt.size());
  params[3] = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, ptr(info), info.size());
  params[4] = OSSL_PARAM_construct_end();
  if (EVP_KDF_derive(ctx.get(), reinterpret_cast<unsigned char*>(okm.data()), okm.size(),
                     params) != 1)
    return Error{ErrorCode::Unsupported, "hkdf: derive failed"};
  return {};
}

Expected<BlockKey> derive_block_key(const Dek& dek, std::span<const std::byte, 16> salt) {
  BlockKey key;
  const auto info = std::as_bytes(std::span<const char>(kInfo, sizeof(kInfo) - 1));
  Status st = hkdf_sha256(dek.bytes(), salt, info, key.bytes());
  if (!st) return st.error();
  return key;
}

Expected<BlockKey> derive_block_key(const Dek& dek, const BlockSalt& salt) {
  return derive_block_key(dek, std::span<const std::byte, 16>(salt.b));
}

}  // namespace miracache
