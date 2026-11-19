// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>

#include "crypto/secret.h"
#include "util/expected.h"

typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

namespace miracache {

using ChunkHook = void (*)(void* arg, std::size_t chunk_index);  // test seam, null in prod

inline constexpr std::size_t kGcmTagLen = 16;
inline constexpr std::size_t kGcmChunk = 16 * 1024;  // single-fetch copy granule

// AES-256-GCM with 12-byte nonce and 16-byte tag. One GcmCtx per worker; not
// thread-safe. The EVP_CIPHER is fetched once at create(); each call re-inits key+IV.
class GcmCtx {
 public:
  static Expected<GcmCtx> create();
  GcmCtx(GcmCtx&&) noexcept;
  GcmCtx& operator=(GcmCtx&&) noexcept;
  GcmCtx(const GcmCtx&) = delete;
  GcmCtx& operator=(const GcmCtx&) = delete;
  ~GcmCtx();

  // ct_tag.size() must be pt.size() + 16. If crc_io != nullptr, *crc_io is advanced
  // (crc32c chaining) over the produced ciphertext||tag bytes.
  Status seal(const BlockKey& key, std::span<const std::byte, 12> nonce,
              std::span<const std::byte> aad, std::span<const std::byte> pt,
              std::span<std::byte> ct_tag, std::uint32_t* crc_io);

  // remote_ct_tag is memory a remote party may mutate at any time (the landing pool).
  // Every byte of it is read exactly once: the tag first, then ciphertext in 16 KiB
  // chunks into a private buffer, decrypting from the private copy. hook (if set) runs
  // after chunk i is copied and before the next is read. pt.size() must be
  // remote_ct_tag.size() - 16. On failure (Corrupt) pt is zeroed.
  Status open_single_fetch(const BlockKey& key, std::span<const std::byte, 12> nonce,
                           std::span<const std::byte> aad,
                           std::span<const std::byte> remote_ct_tag, std::span<std::byte> pt,
                           ChunkHook hook = nullptr, void* hook_arg = nullptr);

 private:
  GcmCtx() = default;
  EVP_CIPHER_CTX* ctx_ = nullptr;
  EVP_CIPHER* cipher_ = nullptr;
  std::unique_ptr<std::byte[]> buf_;  // kGcmChunk private copy
};

}  // namespace miracache
