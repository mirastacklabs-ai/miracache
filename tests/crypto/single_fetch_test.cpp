// SPDX-License-Identifier: Apache-2.0
// A1.5 S2: single-fetch under a mutating remote. Oracle: "OK => output == original
// plaintext" (Decision 3b). tests/ is not linted, so std::thread is allowed here.
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <thread>
#include <vector>

#include "crypto/block_codec.h"

#if defined(__SANITIZE_THREAD__)
#define MIRA_TSAN 1
#elif defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define MIRA_TSAN 1
#endif
#endif

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;

class CounterNonce final : public NonceSource {
 protected:
  Status fill(std::span<std::byte> out) override {
    std::memset(out.data(), 0x33, out.size());
    out[0] = static_cast<std::byte>(++n_);
    return {};
  }
  unsigned n_ = 0;
};

// One-segment block, log2 16 => 64 KiB plaintext = 4 hook chunks.
struct One {
  Dek dek = [] {
    std::array<std::byte, 32> k;
    for (int i = 0; i < 32; ++i) k[i] = static_cast<std::byte>(0xC0 + i);
    return Dek(std::span<const std::byte, 32>(k));
  }();
  BlockMeta meta = [] {
    BlockMeta m{};
    m.kver = 1;
    m.scope_id.b[0] = 9;
    m.key_hash.b[0] = 8;
    m.plaintext_len = 65536;
    m.segment_log2 = 16;
    return m;
  }();
  Bytes pt, block;
  OpenCtx oc{BlockKey(), Layout{}, {}};

  One() {
    pt.resize(65536);
    for (std::size_t i = 0; i < pt.size(); ++i) pt[i] = static_cast<std::byte>((i * 31 + (i >> 9)) & 0xff);
    CounterNonce ns;
    auto lay = layout(meta.plaintext_len, meta.segment_log2);
    block.resize(lay->stored_len);
    auto sc = seal_begin(dek, meta, ns, std::span<std::byte>(block).first(64));
    auto gcm = GcmCtx::create();
    EXPECT_TRUE(seal_segment(*gcm, *sc, 0, pt, block, nullptr).has_value());
    auto r = open_begin(dek, meta, block);
    oc = std::move(r.value());
  }
  std::size_t ct0() const { return oc.lay.seg_off(0); }
};

struct Mut {
  std::byte* target;      // byte to flip
  std::size_t at_chunk;   // flip right after this chunk was copied
};
void mut_hook(void* a, std::size_t idx) {
  auto* m = static_cast<Mut*>(a);
  if (idx == m->at_chunk) *m->target ^= std::byte{0x01};
}

// Oracle: success implies exact original; failure implies zeroed output.
::testing::AssertionResult oracle(const Status& st, const Bytes& out, const Bytes& orig) {
  if (st.has_value()) {
    if (out != orig) return ::testing::AssertionFailure() << "OK but output != original";
  } else {
    for (auto b : out)
      if (b != std::byte{0}) return ::testing::AssertionFailure() << "failed but output not zeroed";
  }
  return ::testing::AssertionSuccess();
}

// TEETH (test-only): a deliberately broken double-fetch open. Fetch 1 verifies the tag
// over the remote bytes; fetch 2 re-reads the remote ciphertext and decrypts it
// (GCM seal of the ciphertext under the same key/nonce yields the plaintext, as CTR is
// an involution), without verifying again. A mutation between the fetches yields OK +
// wrong output; the oracle must catch it.
Status open_double_fetch(GcmCtx& gcm, const OpenCtx& c, std::span<const std::byte> pool,
                         std::span<std::byte> out, ChunkHook hook, void* arg, bool yield_between) {
  const auto nonce = proto::stream_nonce(0, true);
  const auto remote = pool.subspan(c.lay.seg_off(0), c.lay.ct_len(0));
  Bytes scratch(out.size());
  Status st = gcm.open_single_fetch(c.key, nonce, c.aad, remote, scratch, hook, arg);
  if (!st) {
    std::fill(out.begin(), out.end(), std::byte{0});
    return st;
  }
  if (yield_between) std::this_thread::yield();
  Bytes ct(remote.begin(), remote.begin() + out.size());  // second fetch of the remote bytes
  Bytes tmp(out.size() + kGcmTagLen);
  Status s2 = gcm.seal(c.key, nonce, c.aad, ct, tmp, nullptr);
  if (!s2) return s2;
  std::copy_n(tmp.begin(), out.size(), out.begin());
  return {};
}

TEST(SingleFetch, DeterministicMutatorMatchesCopyState) {
  One f;
  auto gcm = GcmCtx::create();
  constexpr std::size_t kChunks = 4;
  // Flip a byte in chunk `c` right after chunk `k` is copied: it is already in the
  // private copy iff c <= k. (Hook for chunk k runs after chunk k was copied.)
  for (std::size_t k = 0; k < kChunks; ++k) {
    for (std::size_t c = 0; c < kChunks; ++c) {
      SCOPED_TRACE(testing::Message() << "hook after chunk " << k << ", flip chunk " << c);
      Bytes pool = f.block;
      Mut m{&pool[f.ct0() + c * kGcmChunk + 5], k};
      Bytes out(f.pt.size(), std::byte{0xAA});
      Status st = open_segment(*gcm, f.oc, 0, pool, out, mut_hook, &m);
      EXPECT_EQ(st.has_value(), c <= k);
      EXPECT_TRUE(oracle(st, out, f.pt));
      if (st.has_value()) EXPECT_EQ(out, f.pt);
    }
  }
}

TEST(SingleFetch, TagIsReadFirstAndOnce) {
  One f;
  auto gcm = GcmCtx::create();
  Bytes pool = f.block;
  // Flip the stored tag after the first chunk: tag was copied before any chunk.
  Mut m{&pool[f.ct0() + f.oc.lay.pt_len(0)], 0};
  Bytes out(f.pt.size());
  Status st = open_segment(*gcm, f.oc, 0, pool, out, mut_hook, &m);
  EXPECT_TRUE(st.has_value());
  EXPECT_EQ(out, f.pt);
}

TEST(SingleFetch, TeethDoubleFetchTripsOracle) {
  One f;
  auto gcm = GcmCtx::create();
  Bytes pool = f.block;
  // After the LAST chunk is copied (all verified bytes private), flip chunk 0 in the
  // pool. The broken variant re-reads it: OK with wrong plaintext.
  Mut m{&pool[f.ct0() + 5], 3};
  Bytes out(f.pt.size(), std::byte{0xAA});
  Status st = open_double_fetch(*gcm, f.oc, pool, out, mut_hook, &m, false);
  EXPECT_TRUE(st.has_value());
  EXPECT_FALSE(oracle(st, out, f.pt)) << "teeth: oracle failed to detect double fetch";
  // Control: the real single-fetch with the same mutation is exact.
  pool = f.block;
  Mut m2{&pool[f.ct0() + 5], 3};
  Bytes out2(f.pt.size(), std::byte{0xAA});
  Status st2 = open_segment(*gcm, f.oc, 0, pool, out2, mut_hook, &m2);
  EXPECT_TRUE(st2.has_value());
  EXPECT_EQ(out2, f.pt);
}

TEST(SingleFetch, ThreadedMutator) {
#ifdef MIRA_TSAN
  GTEST_SKIP() << "intentional data race; skipped under ThreadSanitizer";
#else
  One f;
  auto gcm = GcmCtx::create();
  Bytes pool = f.block;
  volatile std::uint8_t* p0 = reinterpret_cast<volatile std::uint8_t*>(&pool[f.ct0() + 5]);
  volatile std::uint8_t* p1 = reinterpret_cast<volatile std::uint8_t*>(&pool[f.ct0() + 3 * kGcmChunk + 9]);
  std::atomic<bool> stop{false};
  std::thread mutator([&] {
    while (!stop.load(std::memory_order_relaxed)) {
      *p0 = static_cast<std::uint8_t>(*p0 ^ 1);
      *p1 = static_cast<std::uint8_t>(*p1 ^ 1);
    }
  });
  constexpr int kIters = 20000;
  int ok = 0, fail = 0, violations = 0;
  Bytes out(f.pt.size());
  for (int i = 0; i < kIters; ++i) {
    std::fill(out.begin(), out.end(), std::byte{0xAA});
    Status st = open_segment(*gcm, f.oc, 0, pool, out);
    (st.has_value() ? ok : fail)++;
    if (!oracle(st, out, f.pt)) ++violations;
  }
  // Teeth: the double-fetch variant must trip the oracle under the same mutator.
  int teeth = 0, teeth_iters = 0;
  while (teeth == 0 && teeth_iters < 200000) {
    ++teeth_iters;
    std::fill(out.begin(), out.end(), std::byte{0xAA});
    Status st = open_double_fetch(*gcm, f.oc, pool, out, nullptr, nullptr, true);
    if (!oracle(st, out, f.pt)) ++teeth;
  }
  stop = true;
  mutator.join();
  EXPECT_EQ(violations, 0);
  EXPECT_GT(ok, 0) << "mutator never missed the window";
  EXPECT_GT(fail, 0) << "mutator never hit the window";
  EXPECT_GT(teeth, 0) << "teeth variant never tripped the oracle";
#endif
}

}  // namespace
}  // namespace miracache
