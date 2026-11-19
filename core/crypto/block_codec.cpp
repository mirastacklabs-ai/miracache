// SPDX-License-Identifier: Apache-2.0
#include "crypto/block_codec.h"

#include <openssl/crypto.h>

#include <cstring>
#include <limits>

namespace miracache {
namespace {

proto::ExtentHeader header_of(const BlockMeta& m) {
  proto::ExtentHeader h;
  h.log2_segment = m.segment_log2;
  h.kver = m.kver;
  h.plaintext_len = m.plaintext_len;
  return h;
}

std::array<std::byte, proto::kAadSize> aad_of(const proto::ExtentHeader& h, const BlockMeta& m) {
  return proto::build_aad(h, m.scope_id.b, m.key_hash.b);
}

}  // namespace

Expected<Layout> layout(std::uint64_t plaintext_len, std::uint8_t log2) {
  if (log2 < proto::kMinLog2Segment || log2 > proto::kMaxLog2Segment)
    return Error{ErrorCode::InvalidArgument, "layout: segment_log2"};
  const std::uint64_t segs = proto::segment_count(plaintext_len, log2);
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  if (segs > std::numeric_limits<std::uint32_t>::max() ||
      plaintext_len > kMax - proto::kExtentHeaderSize - segs * proto::kGcmTagSize)
    return Error{ErrorCode::InvalidArgument, "layout: too large"};
  Layout l;
  l.segments = static_cast<std::uint32_t>(segs);
  l.plaintext_len = plaintext_len;
  l.segment_log2 = log2;
  l.stored_len = proto::kExtentHeaderSize + plaintext_len + segs * proto::kGcmTagSize;
  return l;
}

Expected<SealCtx> seal_begin(const Dek& dek, const BlockMeta& meta, NonceSource& ns,
                             std::span<std::byte> pool_hdr) {
  if (pool_hdr.size() < proto::kExtentHeaderSize)
    return Error{ErrorCode::InvalidArgument, "seal_begin: header span"};
  auto lay = layout(meta.plaintext_len, meta.segment_log2);
  if (!lay) return lay.error();
  auto salt = ns.salt();
  if (!salt) return salt.error();
  auto key = derive_block_key(dek, *salt);
  if (!key) return key.error();
  proto::ExtentHeader h = header_of(meta);
  std::memcpy(h.block_salt, salt->b.data(), 16);
  Status st = proto::encode(h, pool_hdr.first<proto::kExtentHeaderSize>());
  if (!st) return st.error();
  return SealCtx{std::move(*key), *lay, aad_of(h, meta)};
}

Status seal_segment(GcmCtx& gcm, const SealCtx& ctx, std::uint32_t i,
                    std::span<const std::byte> pt, std::span<std::byte> pool,
                    std::uint32_t* seg_crc) {
  if (i >= ctx.lay.segments || pt.size() != ctx.lay.pt_len(i) || pool.size() < ctx.lay.stored_len)
    return Error{ErrorCode::InvalidArgument, "seal_segment: bounds"};
  const auto nonce = proto::stream_nonce(i, i + 1 == ctx.lay.segments);
  std::uint32_t crc = 0;
  Status st = gcm.seal(ctx.key, nonce, ctx.aad, pt,
                       pool.subspan(ctx.lay.seg_off(i), ctx.lay.ct_len(i)), &crc);
  if (st && seg_crc != nullptr) *seg_crc = crc;
  return st;
}

Expected<OpenCtx> open_begin(const Dek& dek, const BlockMeta& expected,
                             std::span<const std::byte> pool) {
  auto lay = layout(expected.plaintext_len, expected.segment_log2);
  if (!lay) return lay.error();
  if (pool.size() < lay->stored_len) return Error{ErrorCode::Corrupt, "open_begin: short block"};
  std::array<std::byte, proto::kExtentHeaderSize> raw;
  std::memcpy(raw.data(), pool.data(), raw.size());  // header read exactly once
  auto h = proto::decode_extent_header(raw);
  if (!h) return Error{ErrorCode::Corrupt, "open_begin: header"};
  if (h->kver != expected.kver || h->plaintext_len != expected.plaintext_len ||
      h->log2_segment != expected.segment_log2)
    return Error{ErrorCode::Corrupt, "open_begin: header mismatch"};
  std::span<const std::byte, 16> salt(raw.data() + 16, 16);  // block_salt offset
  auto key = derive_block_key(dek, salt);
  if (!key) return key.error();
  // AAD from the caller's expectations; only the salt came from the block.
  return OpenCtx{std::move(*key), *lay, aad_of(header_of(expected), expected)};
}

Status open_segment(GcmCtx& gcm, const OpenCtx& ctx, std::uint32_t i,
                    std::span<const std::byte> pool, std::span<std::byte> engine_out,
                    ChunkHook hook, void* hook_arg) {
  auto bad = [&](const char* why) -> Status {
    OPENSSL_cleanse(engine_out.data(), engine_out.size());
    return Error{ErrorCode::Corrupt, why};
  };
  if (i >= ctx.lay.segments || engine_out.size() != ctx.lay.pt_len(i))
    return Error{ErrorCode::InvalidArgument, "open_segment: bounds"};
  if (pool.size() < ctx.lay.stored_len) return bad("open_segment: short block");
  const auto nonce = proto::stream_nonce(i, i + 1 == ctx.lay.segments);
  return gcm.open_single_fetch(ctx.key, nonce, ctx.aad,
                               pool.subspan(ctx.lay.seg_off(i), ctx.lay.ct_len(i)), engine_out,
                               hook, hook_arg);
}

Status open_block(GcmCtx& gcm, const OpenCtx& ctx, std::span<const std::byte> pool,
                  std::span<std::byte> engine_out) {
  if (engine_out.size() != ctx.lay.plaintext_len)
    return Error{ErrorCode::InvalidArgument, "open_block: engine size"};
  const std::uint64_t seg = std::uint64_t{1} << ctx.lay.segment_log2;
  for (std::uint32_t i = 0; i < ctx.lay.segments; ++i) {
    Status st = open_segment(gcm, ctx, i, pool,
                             engine_out.subspan(static_cast<std::uint64_t>(i) * seg, ctx.lay.pt_len(i)));
    if (!st) {
      OPENSSL_cleanse(engine_out.data(), engine_out.size());
      return st;
    }
  }
  return {};
}

}  // namespace miracache
