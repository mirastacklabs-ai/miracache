// SPDX-License-Identifier: Apache-2.0
#include "client/decrypt_pipeline.h"

#include <algorithm>
#include <atomic>
#include <utility>

#include "util/check.h"

namespace miracache {

FetchOutcome classify(bool seq_ok, bool aead_ok) {
  if (!seq_ok) return FetchOutcome::MissSeq;
  return aead_ok ? FetchOutcome::Hit : FetchOutcome::MissAead;
}

namespace {
enum : std::uint8_t { kPending = 0, kQueued = 1 };
}

struct DecryptPipeline::Block {
  BlockId id = 0;
  Dek dek;
  BlockMeta expected{};
  PoolSpan span;
  std::span<std::byte> engine;
  std::function<void(FetchOutcome)> done;
  std::optional<OpenCtx> ctx;
  std::map<std::uint64_t, std::uint64_t> landed;  // start -> end, merged
  std::vector<std::uint8_t> state;                // per segment
  std::uint32_t outstanding = 0;                  // queued + running segments
  std::uint32_t completed = 0;
  bool failed = false;
  std::atomic<bool> bad{false};  // set by workers when a segment fails to open
  bool seq_known = false, seq_ok = false;
  bool finished = false;

  bool covered(std::uint64_t a, std::uint64_t b) const {
    auto it = landed.upper_bound(a);
    if (it == landed.begin()) return false;
    --it;
    return it->first <= a && it->second >= b;
  }
};

DecryptPipeline::DecryptPipeline(Executor& ex, std::uint32_t max_inflight_segments)
    : ex_(ex), max_inflight_(std::max<std::uint32_t>(1, max_inflight_segments)) {}

DecryptPipeline::~DecryptPipeline() = default;

void DecryptPipeline::set_chunk_hook(ChunkHook hook, void* arg) {
  std::lock_guard lk(mu_);
  hook_ = hook;
  hook_arg_ = arg;
}

BlockId DecryptPipeline::start(const Dek& dek, const BlockMeta& expected, PoolSpan landed,
                               std::span<std::byte> engine_out,
                               std::function<void(FetchOutcome)> done) {
  auto b = std::make_shared<Block>();
  b->dek = Dek(dek.bytes());  // own copy: the caller's DEK need not outlive the fetch
  b->expected = expected;
  b->span = landed;
  b->engine = engine_out;
  b->done = std::move(done);
  std::lock_guard lk(mu_);
  b->id = next_id_++;
  if (engine_out.size() != expected.plaintext_len) b->failed = true;
  blocks_.emplace(b->id, b);
  return b->id;
}

void DecryptPipeline::on_landed(BlockId id, std::uint64_t off, std::uint64_t len) {
  std::vector<Item> out;
  std::function<void(FetchOutcome)> cb;
  FetchOutcome oc = FetchOutcome::Hit;
  bool fin = false;
  {
    std::lock_guard lk(mu_);
    auto it = blocks_.find(id);
    if (it == blocks_.end()) return;
    Block& b = *it->second;
    if (b.finished || len == 0 || off >= b.span.len) return;
    std::uint64_t lo = off, hi = std::min<std::uint64_t>(off + len, b.span.len);
    // Merge [lo, hi) into the interval map.
    auto n = b.landed.upper_bound(lo);
    if (n != b.landed.begin()) {
      auto p = std::prev(n);
      if (p->second >= lo) {
        lo = p->first;
        hi = std::max(hi, p->second);
        n = b.landed.erase(p);
      }
    }
    while (n != b.landed.end() && n->first <= hi) {
      hi = std::max(hi, n->second);
      n = b.landed.erase(n);
    }
    b.landed.emplace(lo, hi);
    advance(b, out);
    fin = maybe_finish(b, cb, oc);
  }
  run(out);
  if (fin) cb(oc);
}

void DecryptPipeline::on_seq(BlockId id, bool seq_ok) {
  std::function<void(FetchOutcome)> cb;
  FetchOutcome oc = FetchOutcome::Hit;
  bool fin = false;
  {
    std::lock_guard lk(mu_);
    auto it = blocks_.find(id);
    if (it == blocks_.end()) return;
    Block& b = *it->second;
    b.seq_known = true;
    b.seq_ok = seq_ok;
    fin = maybe_finish(b, cb, oc);
  }
  if (fin) cb(oc);
}

void DecryptPipeline::advance(Block& b, std::vector<Item>& out) {
  if (b.finished || b.failed) return;
  if (!b.ctx) {
    if (!b.covered(0, proto::kExtentHeaderSize)) return;
    auto oc = open_begin(b.dek, b.expected,
                         std::span<const std::byte>(b.span.addr, static_cast<std::size_t>(b.span.len)));
    if (!oc) {
      b.failed = true;  // Decision 6: header mismatch is treated as tampering
      return;
    }
    b.ctx.emplace(std::move(oc).value());
    b.state.assign(b.ctx->lay.segments, kPending);
  }
  const Layout& lay = b.ctx->lay;
  // Locate the shared_ptr for queueing.
  auto sp = blocks_.find(b.id)->second;
  for (std::uint32_t i = 0; i < lay.segments; ++i) {
    if (b.state[i] != kPending) continue;
    const std::uint64_t so = lay.seg_off(i);
    if (!b.covered(so, so + lay.ct_len(i))) continue;
    b.state[i] = kQueued;
    ++b.outstanding;
    queue_.emplace_back(sp, i);
  }
  pump(out);
}

void DecryptPipeline::pump(std::vector<Item>& out) {
  while (inflight_ < max_inflight_ && !queue_.empty()) {
    out.push_back(std::move(queue_.front()));
    queue_.pop_front();
    ++inflight_;
  }
}

void DecryptPipeline::run(const std::vector<Item>& items) {
  ChunkHook hook;
  void* hook_arg;
  {
    std::lock_guard lk(mu_);
    hook = hook_;
    hook_arg = hook_arg_;
  }
  for (const auto& [blk, i] : items) {
    std::shared_ptr<Block> b = blk;
    const std::uint32_t seg = i;
    ex_.post(
        [b, seg, hook, hook_arg] {
          thread_local std::optional<GcmCtx> gcm;
          if (!gcm) {
            auto g = GcmCtx::create();
            if (!g) {
              b->bad.store(true);
              return;
            }
            gcm.emplace(std::move(*g));
          }
          const Layout& lay = b->ctx->lay;
          const std::uint64_t seg_bytes = std::uint64_t{1} << lay.segment_log2;
          auto out = b->engine.subspan(static_cast<std::size_t>(seg * seg_bytes),
                                       static_cast<std::size_t>(lay.pt_len(seg)));
          const auto pool = std::span<const std::byte>(b->span.addr, static_cast<std::size_t>(b->span.len));
          if (!open_segment(*gcm, *b->ctx, seg, pool, out, hook, hook_arg)) b->bad.store(true);
        },
        [this, b] { segment_done(b); });
  }
}

void DecryptPipeline::segment_done(const std::shared_ptr<Block>& b) {
  std::vector<Item> out;
  std::function<void(FetchOutcome)> cb;
  FetchOutcome oc = FetchOutcome::Hit;
  bool fin = false;
  {
    std::lock_guard lk(mu_);
    --inflight_;
    --b->outstanding;
    ++b->completed;
    if (b->bad.load()) b->failed = true;  // a failed segment fails the block
    if (b->failed) {
      for (auto it = queue_.begin(); it != queue_.end();) {
        if (it->first == b) {
          --b->outstanding;
          it = queue_.erase(it);
        } else {
          ++it;
        }
      }
    }
    pump(out);
    fin = maybe_finish(*b, cb, oc);
  }
  run(out);
  if (fin) cb(oc);
}

bool DecryptPipeline::maybe_finish(Block& b, std::function<void(FetchOutcome)>& cb, FetchOutcome& oc) {
  if (b.finished || !b.seq_known || b.outstanding != 0) return false;
  const bool all_done = b.ctx && b.completed == b.ctx->lay.segments;
  if (!b.failed && !all_done) return false;
  oc = classify(b.seq_ok, !b.failed);
  if (oc != FetchOutcome::Hit) std::fill(b.engine.begin(), b.engine.end(), std::byte{0});  // Decision 3a
  b.finished = true;
  cb = std::move(b.done);
  blocks_.erase(b.id);
  return true;
}

}  // namespace miracache
