// SPDX-License-Identifier: Apache-2.0
// Decrypt pipeline: turns landed ciphertext into verified plaintext. A segment is
// decrypted once all its bytes have landed (Spec gap 01:694). The outcome is reported only
// after the seq check AND every segment tag have resolved. On any failure the whole engine
// buffer is zeroed (Decision 3a). The DEK is an input per block (DEK_k from the KeySource);
// the pipeline never assumes one DEK per request.
#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <vector>

#include "client/landing_pool.h"
#include "crypto/block_codec.h"
#include "util/executor.h"

namespace miracache {

enum class FetchOutcome : std::uint8_t { Hit, MissSeq, MissAead };  // MissAead -> alert + INVALIDATE

// Seq is checked first (a torn/stale read is not evidence of tampering).
FetchOutcome classify(bool seq_ok, bool aead_ok);

using BlockId = std::uint64_t;

class DecryptPipeline {
 public:
  DecryptPipeline(Executor& ex, std::uint32_t max_inflight_segments);
  ~DecryptPipeline();

  // `landed` is the pool span the READ lands in (>= stored block length); engine_out
  // must be exactly expected.plaintext_len bytes and stay valid until `done` runs.
  // The DEK is copied. `done` runs exactly once, outside the pipeline lock.
  BlockId start(const Dek& dek, const BlockMeta& expected, PoolSpan landed,
                std::span<std::byte> engine_out, std::function<void(FetchOutcome)> done);
  // Bytes [off, off+len) of the span are now in place; dispatches fully covered segments.
  void on_landed(BlockId id, std::uint64_t off, std::uint64_t len);
  // Result of the seq/version check of the fetched block.
  void on_seq(BlockId id, bool seq_ok);

  // Test seam: called between 16 KiB chunk copies inside every segment open.
  void set_chunk_hook(ChunkHook hook, void* arg);

 private:
  struct Block;
  using Item = std::pair<std::shared_ptr<Block>, std::uint32_t>;

  void advance(Block& b, std::vector<Item>& out);  // mu_ held
  void pump(std::vector<Item>& out);               // mu_ held: move queue -> out while under cap
  void run(const std::vector<Item>& items);        // mu_ NOT held
  void segment_done(const std::shared_ptr<Block>& b);
  bool maybe_finish(Block& b, std::function<void(FetchOutcome)>& cb, FetchOutcome& oc);  // mu_ held

  Executor& ex_;
  std::uint32_t max_inflight_;
  std::mutex mu_;
  BlockId next_id_ = 1;
  std::uint32_t inflight_ = 0;
  std::map<BlockId, std::shared_ptr<Block>> blocks_;
  std::deque<Item> queue_;
  ChunkHook hook_ = nullptr;
  void* hook_arg_ = nullptr;
};

}  // namespace miracache
