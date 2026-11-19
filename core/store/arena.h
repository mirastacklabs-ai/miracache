// SPDX-License-Identifier: Apache-2.0
// The memory node's arena: backing segments mapped, formatted (or re-opened from an
// existing superblock), the state_gen array, and the persisted generation counter.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "proto/storage_layout.h"
#include "store/backing.h"
#include "store/config.h"
#include "store/layout.h"
#include "store/node_state.h"
#include "store/scope_table.h"
#include "store/state_gen.h"
#include "util/expected.h"

namespace miracache::store {

class Arena {
 public:
  // Maps `cfg.n_segments` segments. With `cfg.state_dir` the identity comes from the state directory (node_state.h;
  // the directory is locked while the arena lives). All-zero media is formatted (fresh); otherwise the
  // newest valid superblock must match the configured geometry. `backing` defaults to
  // make_backing(cfg); pass one to inject a fake.
  static Expected<std::unique_ptr<Arena>> open(const StoreConfig& cfg, std::unique_ptr<Backing> backing = nullptr);

  ~Arena() = default;
  Arena(const Arena&) = delete;
  Arena& operator=(const Arena&) = delete;

  const StoreConfig& config() const noexcept { return cfg_; }
  const StoreLayout& layout() const noexcept { return layout_; }
  std::span<std::byte> segment(std::uint32_t seg) const { return segs_.at(seg); }
  std::span<std::byte> block(std::uint32_t seg, std::uint64_t off, std::uint64_t len) const;

  StateGenArray& state_gen() noexcept { return *sg_; }
  const StateGenArray& state_gen() const noexcept { return *sg_; }
  GenCounter& gens() noexcept { return *gens_; }

  bool fresh() const noexcept { return fresh_; }          // media was formatted by this open
  bool was_clean() const noexcept { return was_clean_; }  // previous owner shut down cleanly
  const proto::Superblock& superblock() const noexcept { return sb_; }
  // A3.1: the persisted scope table (null for a volatile store without a scope region).
  ScopeTable* scope_table() noexcept { return scopes_.get(); }

  // Marks the superblock clean. Without it a later open reports was_clean() == false.
  Status shutdown_clean();

 private:
  Arena() = default;
  Status write_superblock();  // bumps seq, writes the copy it selects, syncs it
  static Status persist_hwm(void* self, std::uint64_t hwm);

  StateDirLock lock_;  // r9b T02: <state_dir>/node-id.lock, held while the arena lives (declared first: released last)
  StoreConfig cfg_;
  StoreLayout layout_;
  std::unique_ptr<Backing> backing_;
  std::vector<std::span<std::byte>> segs_;
  std::unique_ptr<StateGenArray> sg_;
  std::unique_ptr<GenCounter> gens_;
  std::unique_ptr<ScopeTable> scopes_;
  proto::Superblock sb_;
  bool fresh_ = false;
  bool was_clean_ = false;
};

}  // namespace miracache::store
