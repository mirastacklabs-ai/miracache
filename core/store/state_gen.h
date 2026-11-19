// SPDX-License-Identifier: Apache-2.0
// The server's in-memory block array: one 8-byte (state, generation) word per slot
// (word format in proto/state_gen.h). Fetch MRs / the array MR expose bytes() to NICs;
// the store thread is the only writer and uses one aligned 8 B atomic store.
#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <span>

#include "proto/state_gen.h"
#include "util/check.h"

namespace miracache::store {

class StateGenArray {
 public:
  explicit StateGenArray(std::uint64_t n_slots)
      : n_(n_slots), words_(new (std::align_val_t{4096}) std::uint64_t[n_slots]()) {}
  StateGenArray(const StateGenArray&) = delete;
  StateGenArray& operator=(const StateGenArray&) = delete;
  ~StateGenArray() { ::operator delete[](words_, std::align_val_t{4096}); }

  std::uint64_t size() const noexcept { return n_; }

  // Release store: header/data writes before it are visible to a reader that sees it.
  void store(std::uint64_t slot, proto::BlockState s, std::uint64_t gen) {
    MIRACACHE_CHECK(slot < n_);
    MIRACACHE_CHECK(gen <= proto::kMaxGeneration);
    std::atomic_ref<std::uint64_t>(words_[slot]).store(proto::pack_state_gen(s, gen), std::memory_order_release);
  }
  std::uint64_t load(std::uint64_t slot) const {
    MIRACACHE_CHECK(slot < n_);
    return std::atomic_ref<const std::uint64_t>(words_[slot]).load(std::memory_order_acquire);
  }
  proto::BlockState state(std::uint64_t slot) const { return proto::state_of(load(slot)); }
  std::uint64_t generation(std::uint64_t slot) const { return proto::generation_of(load(slot)); }

  std::span<std::byte> bytes() noexcept { return {reinterpret_cast<std::byte*>(words_), n_ * 8}; }
  std::span<const std::byte> bytes() const noexcept { return {reinterpret_cast<const std::byte*>(words_), n_ * 8}; }

 private:
  std::uint64_t n_;
  std::uint64_t* words_;
};

// Node-global generation counter (spec 6.1). The high-water mark is persisted through
// `persist` in chunks: before handing out a value above the stored mark, the mark is
// raised by `chunk`. A restart resumes above the stored mark, so no value is reissued.
class GenCounter {
 public:
  using PersistFn = Status (*)(void* ctx, std::uint64_t hwm);

  // `stored_hwm` is the mark read from the superblock (0 on a fresh node). The new
  // counter starts one extra chunk above it: a torn superblock write can leave the older
  // copy (one chunk behind) as the survivor, and this skip covers that case.
  GenCounter(std::uint64_t stored_hwm, std::uint64_t chunk, PersistFn fn, void* ctx)
      : cur_(stored_hwm == 0 ? 0 : stored_hwm + chunk), hwm_(cur_), chunk_(chunk), fn_(fn), ctx_(ctx) {
    MIRACACHE_CHECK(chunk_ > 0);
  }

  std::uint64_t next() {
    MIRACACHE_CHECK(cur_ < proto::kMaxGeneration);
    ++cur_;
    if (cur_ > hwm_) {
      std::uint64_t nh = cur_ + chunk_ - 1;
      if (nh > proto::kMaxGeneration) nh = proto::kMaxGeneration;
      MIRACACHE_CHECK(fn_(ctx_, nh).has_value());  // an unpersisted mark would break uniqueness
      hwm_ = nh;
    }
    return cur_;
  }
  std::uint64_t last() const noexcept { return cur_; }
  std::uint64_t high_water_mark() const noexcept { return hwm_; }

 private:
  std::uint64_t cur_, hwm_, chunk_;
  PersistFn fn_;
  void* ctx_;
};

}  // namespace miracache::store
