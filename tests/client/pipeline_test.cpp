// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <cstring>
#include <deque>
#include <optional>
#include <vector>

#include "client/decrypt_pipeline.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;

// Holds posted work until the test runs it, so ordering is observable.
class ManualExecutor final : public Executor {
 public:
  void post(std::function<void()> work, std::function<void()> done) override {
    q.emplace_back(std::move(work), std::move(done));
  }
  bool run_one() {
    if (q.empty()) return false;
    auto [w, d] = std::move(q.front());
    q.pop_front();
    w();
    d();
    return true;
  }
  void run_all() { while (run_one()) {} }
  std::deque<std::pair<std::function<void()>, std::function<void()>>> q;
};

class CounterSalts final : public NonceSource {
 protected:
  Status fill(std::span<std::byte> out) override {
    ++n_;
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<std::byte>(n_ * 31 + i + 1);
    return {};
  }
  unsigned n_ = 0;
};

struct Sealed {
  Dek dek;
  BlockMeta meta{};
  Bytes plain, stored;
};

Dek make_dek(int seed) {
  std::array<std::byte, 32> k;
  for (int i = 0; i < 32; ++i) k[i] = static_cast<std::byte>(seed * 17 + i);
  return Dek(std::span<const std::byte, 32>(k));
}

Sealed seal(int seed, std::uint64_t len, CounterSalts& ns) {
  Sealed s{make_dek(seed), {}, {}, {}};
  s.meta.kver = 3;
  for (int i = 0; i < 32; ++i) {
    s.meta.scope_id.b[i] = static_cast<std::uint8_t>(seed + i);
    s.meta.key_hash.b[i] = static_cast<std::uint8_t>(seed * 3 + i);
  }
  s.meta.plaintext_len = len;
  s.meta.segment_log2 = 16;
  s.plain.resize(len);
  for (std::size_t i = 0; i < len; ++i) s.plain[i] = static_cast<std::byte>(i * 5 + seed);
  auto lay = layout(len, 16).value();
  s.stored.assign(lay.stored_len, std::byte{0});
  auto sc = seal_begin(s.dek, s.meta, ns, s.stored).value();
  auto gcm = GcmCtx::create().value();
  for (std::uint32_t i = 0; i < lay.segments; ++i) {
    std::uint32_t crc = 0;
    EXPECT_TRUE(seal_segment(gcm, sc, i, std::span<const std::byte>(s.plain).subspan(i * 65536ull, lay.pt_len(i)),
                             s.stored, &crc).has_value());
  }
  return s;
}

PoolSpan span_of(Bytes& landing) {
  PoolSpan p;
  p.addr = landing.data();
  p.len = landing.size();
  return p;
}

constexpr std::uint64_t kLen = 3 * 65536 + 7;  // 4 segments

TEST(Classify, SeqFirst) {
  EXPECT_EQ(classify(true, true), FetchOutcome::Hit);
  EXPECT_EQ(classify(false, true), FetchOutcome::MissSeq);
  EXPECT_EQ(classify(false, false), FetchOutcome::MissSeq);
  EXPECT_EQ(classify(true, false), FetchOutcome::MissAead);
}

TEST(Pipeline, ReportsOnlyAfterSeqAndEveryTag) {
  CounterSalts ns;
  auto blk = seal(1, kLen, ns);
  ManualExecutor ex;
  DecryptPipeline p(ex, 8);
  Bytes landing = blk.stored, out(kLen, std::byte{0xEE});
  std::optional<FetchOutcome> got;
  auto id = p.start(blk.dek, blk.meta, span_of(landing), out, [&](FetchOutcome o) { got = o; });
  p.on_landed(id, 0, landing.size());
  EXPECT_EQ(ex.q.size(), 4u);
  ex.run_all();
  EXPECT_FALSE(got.has_value());  // all tags verified, seq still unknown
  p.on_seq(id, true);
  ASSERT_TRUE(got.has_value());
  EXPECT_EQ(*got, FetchOutcome::Hit);
  EXPECT_EQ(out, blk.plain);
}

TEST(Pipeline, SeqBeforeSegmentsStillWaitsForTags) {
  CounterSalts ns;
  auto blk = seal(2, kLen, ns);
  ManualExecutor ex;
  DecryptPipeline p(ex, 8);
  Bytes landing = blk.stored, out(kLen);
  std::optional<FetchOutcome> got;
  auto id = p.start(blk.dek, blk.meta, span_of(landing), out, [&](FetchOutcome o) { got = o; });
  p.on_seq(id, true);
  p.on_landed(id, 0, landing.size());
  EXPECT_FALSE(got.has_value());
  for (int i = 0; i < 3; ++i) { ex.run_one(); EXPECT_FALSE(got.has_value()); }
  ex.run_one();
  EXPECT_EQ(got, FetchOutcome::Hit);
}

TEST(Pipeline, DispatchesSegmentsOnlyOnceFullyLanded) {
  CounterSalts ns;
  auto blk = seal(3, kLen, ns);
  ManualExecutor ex;
  DecryptPipeline p(ex, 8);
  Bytes landing(blk.stored.size()), out(kLen);
  auto id = p.start(blk.dek, blk.meta, span_of(landing), out, [](FetchOutcome) {});
  const auto lay = layout(kLen, 16).value();
  auto land = [&](std::uint64_t off, std::uint64_t len) {
    std::memcpy(landing.data() + off, blk.stored.data() + off, len);
    p.on_landed(id, off, len);
  };
  land(lay.seg_off(1), lay.ct_len(1));  // body without the header: nothing yet
  EXPECT_EQ(ex.q.size(), 0u);
  land(0, 64);                          // header: segment 1 becomes ready
  EXPECT_EQ(ex.q.size(), 1u);
  land(lay.seg_off(0), lay.ct_len(0) - 1);  // one byte short
  EXPECT_EQ(ex.q.size(), 1u);
  land(lay.seg_off(0) + lay.ct_len(0) - 1, 1);
  EXPECT_EQ(ex.q.size(), 2u);
  ex.run_all();
}

TEST(Pipeline, BoundsInflightSegments) {
  CounterSalts ns;
  auto blk = seal(4, kLen, ns);
  ManualExecutor ex;
  DecryptPipeline p(ex, 2);
  Bytes landing = blk.stored, out(kLen);
  std::optional<FetchOutcome> got;
  auto id = p.start(blk.dek, blk.meta, span_of(landing), out, [&](FetchOutcome o) { got = o; });
  p.on_landed(id, 0, landing.size());
  EXPECT_EQ(ex.q.size(), 2u);
  ex.run_one();
  EXPECT_EQ(ex.q.size(), 2u);  // a slot freed, the next segment went out
  ex.run_all();
  p.on_seq(id, true);
  EXPECT_EQ(got, FetchOutcome::Hit);
  EXPECT_EQ(out, blk.plain);
}

TEST(Pipeline, SeqFailureIsMissSeqAndZeroesOutput) {
  CounterSalts ns;
  auto blk = seal(5, kLen, ns);
  ManualExecutor ex;
  DecryptPipeline p(ex, 8);
  Bytes landing = blk.stored, out(kLen, std::byte{0xEE});
  std::optional<FetchOutcome> got;
  auto id = p.start(blk.dek, blk.meta, span_of(landing), out, [&](FetchOutcome o) { got = o; });
  p.on_landed(id, 0, landing.size());
  ex.run_all();
  p.on_seq(id, false);
  EXPECT_EQ(got, FetchOutcome::MissSeq);
  for (auto b : out) ASSERT_EQ(b, std::byte{0});
}

TEST(Pipeline, TagFlipInAnySegmentIsMissAeadAndZeroesWholeBuffer) {
  CounterSalts ns;
  const auto lay = layout(kLen, 16).value();
  for (std::uint32_t victim = 0; victim < lay.segments; ++victim) {
    auto blk = seal(6, kLen, ns);
    ManualExecutor ex;
    DecryptPipeline p(ex, 2);
    Bytes landing = blk.stored, out(kLen, std::byte{0xEE});
    landing[lay.seg_off(victim) + lay.ct_len(victim) - 1] ^= std::byte{1};
    std::optional<FetchOutcome> got;
    auto id = p.start(blk.dek, blk.meta, span_of(landing), out, [&](FetchOutcome o) { got = o; });
    p.on_landed(id, 0, landing.size());
    p.on_seq(id, true);
    ex.run_all();
    ASSERT_TRUE(got.has_value());
    EXPECT_EQ(*got, FetchOutcome::MissAead) << victim;
    for (auto b : out) ASSERT_EQ(b, std::byte{0}) << victim;  // Decision 3a
  }
}

TEST(Pipeline, HeaderMismatchIsMissAead) {
  CounterSalts ns;
  auto blk = seal(7, kLen, ns);
  ManualExecutor ex;
  DecryptPipeline p(ex, 8);
  Bytes landing = blk.stored, out(kLen, std::byte{0xEE});
  BlockMeta wrong = blk.meta;
  wrong.kver += 1;  // Decision 6
  std::optional<FetchOutcome> got;
  auto id = p.start(blk.dek, wrong, span_of(landing), out, [&](FetchOutcome o) { got = o; });
  p.on_landed(id, 0, landing.size());
  EXPECT_FALSE(got.has_value());
  p.on_seq(id, true);
  EXPECT_EQ(got, FetchOutcome::MissAead);
  EXPECT_EQ(ex.q.size(), 0u);
  for (auto b : out) ASSERT_EQ(b, std::byte{0});
}

TEST(Pipeline, PerBlockDeksAndWrongDek) {
  CounterSalts ns;
  auto a = seal(8, 70000, ns), b = seal(9, 5000, ns);
  ManualExecutor ex;
  DecryptPipeline p(ex, 8);
  Bytes la = a.stored, lb = b.stored, oa(a.plain.size()), ob(b.plain.size()), oc(b.plain.size(), std::byte{0xEE});
  std::optional<FetchOutcome> ga, gb, gc;
  auto ia = p.start(a.dek, a.meta, span_of(la), oa, [&](FetchOutcome o) { ga = o; });
  auto ib = p.start(b.dek, b.meta, span_of(lb), ob, [&](FetchOutcome o) { gb = o; });
  Bytes lc = b.stored;  // same block, but the caller supplies the wrong DEK
  auto ic = p.start(a.dek, b.meta, span_of(lc), oc, [&](FetchOutcome o) { gc = o; });
  for (auto [id, n] : {std::pair{ia, la.size()}, {ib, lb.size()}, {ic, lc.size()}}) {
    p.on_landed(id, 0, n);
    p.on_seq(id, true);
  }
  ex.run_all();
  EXPECT_EQ(ga, FetchOutcome::Hit);
  EXPECT_EQ(gb, FetchOutcome::Hit);
  EXPECT_EQ(gc, FetchOutcome::MissAead);
  EXPECT_EQ(oa, a.plain);
  EXPECT_EQ(ob, b.plain);
}

}  // namespace
}  // namespace miracache
