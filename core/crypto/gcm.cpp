// SPDX-License-Identifier: Apache-2.0
#include "crypto/gcm.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#include <algorithm>
#include <climits>
#include <cstring>

#include "util/crc32c.h"

namespace miracache {
namespace {
inline unsigned char* u(std::byte* p) { return reinterpret_cast<unsigned char*>(p); }
inline const unsigned char* u(const std::byte* p) { return reinterpret_cast<const unsigned char*>(p); }
constexpr std::size_t kMaxPart = INT_MAX / 2;
}  // namespace

Expected<GcmCtx> GcmCtx::create() {
  GcmCtx g;
  g.cipher_ = EVP_CIPHER_fetch(nullptr, "AES-256-GCM", nullptr);
  g.ctx_ = EVP_CIPHER_CTX_new();
  g.buf_ = std::make_unique<std::byte[]>(kGcmChunk);
  if (g.cipher_ == nullptr || g.ctx_ == nullptr || !g.buf_)
    return Error{ErrorCode::ResourceExhausted, "gcm: init"};
  return g;
}

GcmCtx::GcmCtx(GcmCtx&& o) noexcept
    : ctx_(o.ctx_), cipher_(o.cipher_), buf_(std::move(o.buf_)) {
  o.ctx_ = nullptr;
  o.cipher_ = nullptr;
}

GcmCtx& GcmCtx::operator=(GcmCtx&& o) noexcept {
  if (this != &o) {
    EVP_CIPHER_CTX_free(ctx_);
    EVP_CIPHER_free(cipher_);
    ctx_ = o.ctx_;
    cipher_ = o.cipher_;
    buf_ = std::move(o.buf_);
    o.ctx_ = nullptr;
    o.cipher_ = nullptr;
  }
  return *this;
}

GcmCtx::~GcmCtx() {
  EVP_CIPHER_CTX_free(ctx_);
  EVP_CIPHER_free(cipher_);
}

Status GcmCtx::seal(const BlockKey& key, std::span<const std::byte, 12> nonce,
                    std::span<const std::byte> aad, std::span<const std::byte> pt,
                    std::span<std::byte> ct_tag, std::uint32_t* crc_io) {
  if (ct_tag.size() != pt.size() + kGcmTagLen || pt.size() > kMaxPart || aad.size() > kMaxPart)
    return Error{ErrorCode::InvalidArgument, "gcm seal: bad length"};
  int n = 0;
  if (EVP_EncryptInit_ex2(ctx_, cipher_, u(key.bytes().data()), u(nonce.data()), nullptr) != 1)
    return Error{ErrorCode::Unsupported, "gcm seal: init"};
  if (!aad.empty() && EVP_EncryptUpdate(ctx_, nullptr, &n, u(aad.data()), static_cast<int>(aad.size())) != 1)
    return Error{ErrorCode::Unsupported, "gcm seal: aad"};
  if (!pt.empty() &&
      EVP_EncryptUpdate(ctx_, u(ct_tag.data()), &n, u(pt.data()), static_cast<int>(pt.size())) != 1)
    return Error{ErrorCode::Unsupported, "gcm seal: update"};
  if (EVP_EncryptFinal_ex(ctx_, u(ct_tag.data()) + pt.size(), &n) != 1)
    return Error{ErrorCode::Unsupported, "gcm seal: final"};
  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_GET_TAG, kGcmTagLen, u(ct_tag.data()) + pt.size()) != 1)
    return Error{ErrorCode::Unsupported, "gcm seal: tag"};
  if (crc_io != nullptr) *crc_io = crc32c(ct_tag, *crc_io);
  return {};
}

Status GcmCtx::open_single_fetch(const BlockKey& key, std::span<const std::byte, 12> nonce,
                                 std::span<const std::byte> aad,
                                 std::span<const std::byte> remote_ct_tag,
                                 std::span<std::byte> pt, ChunkHook hook, void* hook_arg) {
  if (remote_ct_tag.size() < kGcmTagLen || pt.size() != remote_ct_tag.size() - kGcmTagLen ||
      pt.size() > kMaxPart || aad.size() > kMaxPart)
    return Error{ErrorCode::InvalidArgument, "gcm open: bad length"};
  const std::size_t ct_len = pt.size();
  auto fail = [&](const char* why) -> Status {
    OPENSSL_cleanse(pt.data(), pt.size());
    return Error{ErrorCode::Corrupt, why};
  };
  // Read the tag exactly once, into a local copy.
  unsigned char tag[kGcmTagLen];
  std::memcpy(tag, remote_ct_tag.data() + ct_len, kGcmTagLen);

  int n = 0;
  if (EVP_DecryptInit_ex2(ctx_, cipher_, u(key.bytes().data()), u(nonce.data()), nullptr) != 1)
    return fail("gcm open: init");
  if (!aad.empty() && EVP_DecryptUpdate(ctx_, nullptr, &n, u(aad.data()), static_cast<int>(aad.size())) != 1)
    return fail("gcm open: aad");
  std::size_t chunk_index = 0;
  for (std::size_t off = 0; off < ct_len; off += kGcmChunk, ++chunk_index) {
    const std::size_t len = std::min(kGcmChunk, ct_len - off);
    std::memcpy(buf_.get(), remote_ct_tag.data() + off, len);  // the only read of these bytes
    if (hook != nullptr) hook(hook_arg, chunk_index);
    if (EVP_DecryptUpdate(ctx_, u(pt.data()) + off, &n, u(buf_.get()), static_cast<int>(len)) != 1) {
      OPENSSL_cleanse(buf_.get(), len);
      return fail("gcm open: update");
    }
  }
  OPENSSL_cleanse(buf_.get(), std::min(kGcmChunk, ct_len));
  if (EVP_CIPHER_CTX_ctrl(ctx_, EVP_CTRL_AEAD_SET_TAG, kGcmTagLen, tag) != 1)
    return fail("gcm open: set tag");
  // Tag comparison happens inside Final (constant time in OpenSSL).
  if (EVP_DecryptFinal_ex(ctx_, u(pt.data()) + ct_len, &n) != 1) return fail("gcm open: tag mismatch");
  return {};
}

}  // namespace miracache
