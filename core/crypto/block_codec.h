// SPDX-License-Identifier: Apache-2.0
// Block segmenter: seals/opens a whole block as STREAM segments.
// Stored block = 64 B extent header || segment 0 || ... (each segment: ciphertext || 16 B tag).
// Header, AAD and nonce layouts come from proto/extent_header.h; nothing is re-derived here.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "crypto/gcm.h"
#include "crypto/hkdf.h"
#include "crypto/secret.h"
#include "proto/extent_header.h"
#include "util/expected.h"
#include "util/nonce_source.h"

namespace miracache {

struct ScopeId { std::uint8_t b[32]; };
struct KeyHash { std::uint8_t b[32]; };

struct BlockMeta {
  std::uint32_t kver;
  ScopeId scope_id;
  KeyHash key_hash;
  std::uint64_t plaintext_len;
  std::uint8_t segment_log2;
};

// Geometry. Offsets are relative to the start of the stored block (header included).
struct Layout {
  std::uint32_t segments = 0;
  std::uint64_t stored_len = 0;
  std::uint64_t plaintext_len = 0;
  std::uint8_t segment_log2 = 0;

  std::uint64_t seg_off(std::uint32_t i) const {
    return proto::kExtentHeaderSize +
           static_cast<std::uint64_t>(i) * ((std::uint64_t{1} << segment_log2) + proto::kGcmTagSize);
  }
  // Plaintext bytes of segment i.
  std::uint64_t pt_len(std::uint32_t i) const {
    const std::uint64_t seg = std::uint64_t{1} << segment_log2;
    return i + 1 == segments ? plaintext_len - static_cast<std::uint64_t>(i) * seg : seg;
  }
  // Stored bytes of segment i (ciphertext || tag).
  std::uint64_t ct_len(std::uint32_t i) const { return pt_len(i) + proto::kGcmTagSize; }
};

// InvalidArgument if log2 is outside 16..20 or the sizes do not fit (u32 segments, u64 bytes).
Expected<Layout> layout(std::uint64_t plaintext_len, std::uint8_t segment_log2);

struct SealCtx {
  BlockKey key;
  Layout lay;
  std::array<std::byte, proto::kAadSize> aad;
};

// Draws a fresh salt (NonceSource rejects zero/repeat), derives the block key, writes the
// 64 B header to pool_hdr (>= 64 bytes) and returns the per-block context.
Expected<SealCtx> seal_begin(const Dek& dek, const BlockMeta& meta, NonceSource& ns,
                             std::span<std::byte> pool_hdr);

// Seals segment i (pt.size() == lay.pt_len(i)) into pool (the whole block, >= stored_len)
// at seg_off(i). *seg_crc = crc32c of that segment's ciphertext||tag (seed 0), for
// crc32c_combine.
Status seal_segment(GcmCtx& gcm, const SealCtx& ctx, std::uint32_t i,
                    std::span<const std::byte> pt, std::span<std::byte> pool,
                    std::uint32_t* seg_crc);

struct OpenCtx {
  BlockKey key;
  Layout lay;
  std::array<std::byte, proto::kAadSize> aad;
};

// Copies the 64 B header out of pool once, checks it against the caller's expectations
// (kver, plaintext_len, segment_log2, syntax) and that pool holds stored_len bytes.
// Any mismatch is Corrupt (Decision 6). Only the salt is taken from the block.
Expected<OpenCtx> open_begin(const Dek& dek, const BlockMeta& expected,
                             std::span<const std::byte> pool);

// Opens segment i from pool (whole block, remote-mutable) into engine_out
// (size lay.pt_len(i)). Each pool byte is read once. On failure engine_out is zeroed.
Status open_segment(GcmCtx& gcm, const OpenCtx& ctx, std::uint32_t i,
                    std::span<const std::byte> pool, std::span<std::byte> engine_out,
                    ChunkHook hook = nullptr, void* hook_arg = nullptr);

// Opens every segment; on any failure zeroes the whole engine_out (Decision 3a).
// engine_out.size() must equal lay.plaintext_len.
Status open_block(GcmCtx& gcm, const OpenCtx& ctx, std::span<const std::byte> pool,
                  std::span<std::byte> engine_out);

}  // namespace miracache
