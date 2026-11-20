// SPDX-License-Identifier: Apache-2.0
// Landing pool: remote-writable memory that RDMA READs land in. One sub-pool per
// (memory node, rail); each sub-pool is one MR registered in the given PD. Contents are
// untrusted until the decrypt pipeline has verified them.
#pragma once

#include <compare>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>

#include "fabric/fabric.h"
#include "util/expected.h"

namespace miracache {

struct SubpoolKey {
  fabric::NodeId node = 0;
  std::uint8_t rail = 0;
  auto operator<=>(const SubpoolKey&) const = default;
};

struct PoolSpan {
  SubpoolKey key;
  std::uint32_t gen = 0;
  std::uint64_t off = 0, len = 0;
  std::byte* addr = nullptr;
  std::uint32_t lkey = 0;
};

enum class PoolBacking : std::uint8_t { Huge1G, Huge2M, Thp, Anon };

inline constexpr std::size_t kPoolAlign = 4096;

class LandingPool {
 public:
  explicit LandingPool(fabric::Fabric& fab);
  ~LandingPool();
  LandingPool(const LandingPool&) = delete;
  LandingPool& operator=(const LandingPool&) = delete;

  // bytes is rounded up to kPoolAlign. Busy if the key exists.
  Status add_subpool(SubpoolKey key, fabric::PdId pd, std::size_t bytes);
  // Make-before-break: a new generation takes new acquires; the old one is freed after
  // its last span is released.
  Status resize_subpool(SubpoolKey key, std::size_t bytes);
  // First-fit, kPoolAlign-aligned. ResourceExhausted = backpressure.
  Expected<PoolSpan> acquire(SubpoolKey key, std::size_t len);
  // Caller guarantees the QP that wrote into the span is drained.
  void release(const PoolSpan& span);

  std::size_t bytes_in_use() const;
  PoolBacking backing() const;  // backing of the most recent mapping
  std::size_t live_generations(SubpoolKey key) const;

 private:
  struct Gen;
  struct Sub;
  std::unique_ptr<Gen> make_gen(std::uint32_t gen, fabric::PdId pd, std::size_t bytes, Status& st);
  void destroy_gen(Gen& g);

  fabric::Fabric& fab_;
  mutable std::mutex mu_;
  std::map<SubpoolKey, std::unique_ptr<Sub>> subs_;
  PoolBacking backing_ = PoolBacking::Anon;
};

}  // namespace miracache
