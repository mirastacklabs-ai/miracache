// SPDX-License-Identifier: Apache-2.0
#include "store/mr_manager.h"

#include <algorithm>

#include "util/buggify.h"

namespace miracache::store {

using fabric::Access;
using fabric::MemRegion;

MrManager::MrManager(fabric::Fabric& f, Arena& a, fabric::PdId fetch_pd, fabric::PdId ingest_pd)
    : arena_(a) {
  devs_.push_back(Dev{&f, fetch_pd, ingest_pd, {}, std::nullopt});
}

MrManager::MrManager(std::vector<DeviceSpec> devices, Arena& a) : arena_(a) {
  for (const auto& d : devices) devs_.push_back(Dev{d.fabric, d.fetch_pd, d.ingest_pd, {}, std::nullopt});
}

MrManager::~MrManager() {
  for (const auto& [k, mr] : writes_) (void)devs_[mr.device].fabric->dereg(mr);
  for (auto& d : devs_) {
    if (d.array) (void)d.fabric->dereg(*d.array);
    for (const auto& mr : d.segs) (void)d.fabric->dereg(mr);
  }
}

// Q2: the only bytes a reader may READ: the formatted data runs. Never the superblocks, segment meta, run table, header
// table, the scope region or slack. Segment 0's reserved tail runs (where the scope region may sit, layout.h) are the
// LAST runs, so the data range stays contiguous: just shorter.
std::span<std::byte> MrManager::data_span(std::uint32_t seg) const {
  const auto& l = arena_.layout();
  const std::uint32_t runs = l.seg.n_runs - (seg == 0 ? l.scope.reserved_runs : 0);
  return arena_.segment(seg).subspan(l.seg.data_off, std::uint64_t{runs} * l.seg.run_bytes);
}

bool MrManager::registration_complete() const {
  for (const auto& d : devs_)
    if (!d.array) return false;
  return true;
}

std::uint32_t MrManager::registered_segments() const {
  std::size_t n = devs_.front().segs.size();
  for (const auto& d : devs_) n = std::min(n, d.segs.size());
  return static_cast<std::uint32_t>(n);
}

// A segment is readable only when it is registered on every device (and so has an rkey on every rail).
bool MrManager::readable(std::uint32_t seg) const { return registration_complete() && seg < registered_segments(); }

Expected<bool> MrManager::step_registration() {
  if (registration_complete()) return false;
  const std::uint32_t n = arena_.layout().n_segments;
  // Segment by segment: the device with the shortest prefix registers the next piece, so the common prefix grows.
  Dev* behind = nullptr;
  for (auto& d : devs_)
    if (d.segs.size() < n && (behind == nullptr || d.segs.size() < behind->segs.size())) behind = &d;
  if (behind != nullptr) {
    auto r = behind->fabric->reg(data_span(static_cast<std::uint32_t>(behind->segs.size())), Access::RemoteRead,
                                 behind->fetch_pd);
    if (!r) return r.error();
    r->device = static_cast<std::uint32_t>(behind - devs_.data());
    behind->segs.push_back(*r);
    return true;
  }
  for (auto& d : devs_) {
    if (d.array) continue;
    auto r = d.fabric->reg(arena_.state_gen().bytes(), Access::RemoteRead, d.fetch_pd);
    if (!r) return r.error();
    r->device = static_cast<std::uint32_t>(&d - devs_.data());
    d.array = *r;
    return true;
  }
  return false;
}

const MemRegion* MrManager::segment_mr(std::uint32_t seg, std::uint32_t device) const {
  return device < devs_.size() && seg < devs_[device].segs.size() ? &devs_[device].segs[seg] : nullptr;
}

MemRegion MrManager::segment_view(std::uint32_t seg, std::uint32_t device) const {
  MemRegion v = devs_[device].segs[seg];
  std::byte* base = arena_.segment(seg).data();
  v.len += static_cast<std::size_t>(v.addr - base);
  v.addr = base;
  return v;
}

const MemRegion* MrManager::array_mr(std::uint32_t device) const {
  return device < devs_.size() && devs_[device].array ? &*devs_[device].array : nullptr;
}

Expected<MemRegion> MrManager::register_write(std::span<std::byte> buf, std::uint32_t device) {
  if (device >= devs_.size()) return Error{ErrorCode::InvalidArgument, "mr: unknown device"};
  auto r = devs_[device].fabric->reg(buf, Access::RemoteWrite, devs_[device].ingest_pd);
  if (!r) return r.error();
  r->device = device;
  writes_.emplace(write_key(*r), *r);
  return *r;
}

Status MrManager::fence(const MemRegion& mr) {
  auto it = writes_.find(write_key(mr));
  if (it == writes_.end()) return Error{ErrorCode::NotFound, "mr: not a live write MR"};
  if (MIRACACHE_TEETH_ON(NoFence)) return {};  // TEETH: reports success, the MR stays registered
  if (Status st = devs_[it->second.device].fabric->dereg(it->second); !st) return st;
  writes_.erase(it);
  return {};
}

Status MrManager::check_invariants() const {
  for (const auto& d : devs_) {
    for (std::size_t i = 0; i < d.segs.size(); ++i) {
      const auto& mr = d.segs[i];
      if (mr.access != Access::RemoteRead) return Error{ErrorCode::Corrupt, "mr: fetch MR not read-only"};
      const auto want = data_span(static_cast<std::uint32_t>(i));
      if (mr.addr != want.data() || mr.len != want.size())
        return Error{ErrorCode::Corrupt, "mr: fetch MR is not exactly the segment's data runs"};
    }
    if (d.array && (d.array->access != Access::RemoteRead || d.segs.size() != arena_.layout().n_segments))
      return Error{ErrorCode::Corrupt, "mr: array MR before all segments or not read-only"};
  }
  for (const auto& [k, mr] : writes_)
    if (mr.access != Access::RemoteWrite) return Error{ErrorCode::Corrupt, "mr: write MR access"};
  return {};
}

}  // namespace miracache::store
