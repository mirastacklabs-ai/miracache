// SPDX-License-Identifier: Apache-2.0
#include "store/slab.h"

#include <algorithm>
#include <atomic>

#include "util/buggify.h"
#include "util/check.h"

namespace miracache::store {

SlabAllocator::SlabAllocator(Arena& arena)
    : arena_(arena),
      runs_per_seg_(arena.layout().seg.n_runs),
      run_bytes_(arena.layout().seg.run_bytes),
      min_block_(arena.config().min_block_bytes),
      max_exact_per_owner_(arena.config().max_exact_classes_per_owner) {
  const auto n = static_cast<std::uint32_t>(arena.layout().n_segments * runs_per_seg_);
  runs_.resize(n);
  const std::uint32_t reserved = arena.layout().scope.reserved_runs;  // the tail of segment 0
  for (std::uint32_t i = 0; i < n; ++i) {
    runs_[i].seg = i / runs_per_seg_;
    runs_[i].idx = i % runs_per_seg_;
    if (runs_[i].seg == 0 && runs_[i].idx >= runs_per_seg_ - reserved) {
      runs_[i].reserved = true;
      ++reserved_;
      continue;
    }
    free_runs_.insert(i);
  }
}

std::uint32_t SlabAllocator::per_run(std::uint64_t cls) const {
  return static_cast<std::uint32_t>(std::min<std::uint64_t>(proto::kSlotsPerRun, run_bytes_ / cls));
}

bool SlabAllocator::adopt_run(std::uint32_t rid, std::uint64_t cls, std::uint64_t owner) {
  if (rid >= runs_.size() || cls == 0 || cls > run_bytes_ || cls % min_block_ != 0) return false;
  Run& r = runs_[rid];
  if (r.reserved) return false;
  if (r.cls != 0) return r.cls == cls;
  if (!classes_.count(cls)) {
    const bool rung = ladder_len(cls) == cls;
    if (!rung) {
      std::size_t n_exact = 0;
      for (const auto& [len, c] : classes_) n_exact += c.rung ? 0 : 1;
      if (n_exact >= kMaxClasses) return false;
    }
    Class& c = classes_[cls];
    c.per_run = per_run(cls);
    c.owner = rung ? 0 : owner;
    c.rung = rung;
  }
  Class& c = classes_.at(cls);
  free_runs_.erase(rid);
  r.cls = cls;
  r.used.assign(c.per_run, 0);
  r.n_free = c.per_run;
  c.runs.insert(rid);
  c.free += c.per_run;
  return true;
}

Extent SlabAllocator::adopt_block(std::uint32_t rid, std::uint32_t block, std::uint64_t gen) {
  const Run& r = runs_.at(rid);
  MIRACACHE_CHECK(r.cls != 0 && block < r.used.size() && !r.used[block]);
  take(rid, block);
  Extent e = extent_of(Pick{rid, block}, r.cls);
  e.gen = gen;
  return e;
}

std::span<std::byte> SlabAllocator::header_slot(std::uint32_t seg, std::uint64_t gen_slot) const {
  const auto& l = arena_.layout();
  const std::uint64_t slot_in_seg = gen_slot - std::uint64_t{seg} * l.seg.slots();
  MIRACACHE_CHECK(slot_in_seg < l.seg.slots());
  return arena_.block(seg, l.seg.hdr_table_off + slot_in_seg * kHeaderSlotBytes, kHeaderSlotBytes);
}

void SlabAllocator::clear_header(const Extent& e) {
  auto h = header_slot(e.seg, e.gen_slot);
  // The magic goes first (one aligned 4 B store): a crash part-way leaves a slot the scan ignores.
  std::atomic_ref<std::uint32_t>(*reinterpret_cast<std::uint32_t*>(h.data())).store(0, std::memory_order_relaxed);
  std::fill(h.begin(), h.end(), std::byte{0});
}

std::uint64_t SlabAllocator::exact_len(std::uint64_t stored_len) const {
  // Overflow-safe: anything above a run is returned as is (class_for rejects it).
  if (stored_len > run_bytes_) return stored_len;
  return align_up(std::max<std::uint64_t>(stored_len, 1), min_block_);
}

std::uint64_t SlabAllocator::ladder_len(std::uint64_t len) const {
  std::uint64_t r = min_block_;
  for (;;) {
    if (r >= len || r >= run_bytes_) return r;
    const std::uint64_t h = align_up(r + r / 2, min_block_);
    if (h >= len && h <= run_bytes_) return h;
    r *= 2;
  }
}

Expected<std::uint64_t> SlabAllocator::class_for(std::uint64_t stored_len, std::uint64_t owner,
                                                 std::vector<std::uint64_t>& created) {
  const std::uint64_t exact = exact_len(stored_len);
  if (exact > run_bytes_) return Error{ErrorCode::InvalidArgument, "slab: block larger than a run"};
  if (classes_.count(exact)) return exact;
  const std::uint64_t rung = ladder_len(exact);
  std::size_t n_exact = 0, mine = 0;
  for (const auto& [len, c] : classes_) {
    if (c.rung) continue;
    ++n_exact;
    mine += c.owner == owner;
  }
  const bool exact_ok = exact != rung && n_exact < kMaxClasses && mine < max_exact_per_owner_;
  const std::uint64_t cls = exact_ok ? exact : rung;
  if (!classes_.count(cls)) {
    Class& c = classes_[cls];
    c.per_run = static_cast<std::uint32_t>(std::min<std::uint64_t>(proto::kSlotsPerRun, run_bytes_ / cls));
    c.owner = exact_ok ? owner : 0;
    c.rung = !exact_ok;
    created.push_back(cls);
  }
  return cls;
}

void SlabAllocator::take(std::uint32_t run, std::uint32_t block) {
  Run& r = runs_[run];
  MIRACACHE_CHECK(!r.used[block]);
  r.used[block] = 1;
  --r.n_free;
  --classes_.at(r.cls).free;
}

void SlabAllocator::give(std::uint32_t run, std::uint32_t block) {
  Run& r = runs_[run];
  MIRACACHE_CHECK(r.used[block]);
  r.used[block] = 0;
  ++r.n_free;
  Class& c = classes_.at(r.cls);
  ++c.free;
  if (r.n_free == c.per_run) {  // run empty: back to the pool; drop the class if it has no runs
    c.free -= c.per_run;
    c.runs.erase(run);
    const std::uint64_t cls = r.cls;
    r.cls = 0;
    r.used.clear();
    r.n_free = 0;
    free_runs_.insert(run);
    if (c.runs.empty()) classes_.erase(cls);
  }
}

bool SlabAllocator::place(std::uint64_t cls, std::size_t n, std::vector<Pick>& out) {
  Class& c = classes_.at(cls);
  if (n > c.per_run) {  // cannot sit side by side in one run; place singly
    for (std::size_t i = 0; i < n; ++i)
      if (!place(cls, 1, out)) return false;
    return true;
  }
  // 1. n adjacent free blocks in an already formatted run.
  for (std::uint32_t rid : c.runs) {
    const Run& r = runs_[rid];
    if (r.n_free < n) continue;
    std::uint32_t streak = 0;
    for (std::uint32_t b = 0; b < c.per_run; ++b) {
      streak = r.used[b] ? 0 : streak + 1;
      if (streak == n) {
        for (std::uint32_t k = b + 1 - static_cast<std::uint32_t>(n); k <= b; ++k) {
          take(rid, k);
          out.push_back({rid, k});
        }
        return true;
      }
    }
  }
  // 2. A fresh run.
  if (!free_runs_.empty()) {
    const std::uint32_t rid = *free_runs_.begin();
    free_runs_.erase(free_runs_.begin());
    Run& r = runs_[rid];
    r.cls = cls;
    r.used.assign(c.per_run, 0);
    r.n_free = c.per_run;
    c.runs.insert(rid);
    c.free += c.per_run;
    for (std::uint32_t k = 0; k < n; ++k) {
      take(rid, k);
      out.push_back({rid, k});
    }
    return true;
  }
  // 3. Scatter over free blocks (all-or-nothing).
  if (c.free < n) return false;
  std::size_t got = 0;
  for (std::uint32_t rid : std::vector<std::uint32_t>(c.runs.begin(), c.runs.end())) {
    for (std::uint32_t b = 0; b < c.per_run && got < n; ++b) {
      if (!runs_[rid].used[b]) {
        take(rid, b);
        out.push_back({rid, b});
        ++got;
      }
    }
    if (got == n) break;
  }
  return got == n;
}

Extent SlabAllocator::extent_of(const Pick& p, std::uint64_t cls) const {
  const Run& r = runs_[p.run];
  const auto& seg = arena_.layout().seg;
  Extent e;
  e.seg = r.seg;
  e.off = seg.run_data_off(r.idx) + std::uint64_t{p.block} * cls;
  e.len = cls;
  e.gen_slot = arena_.layout().gen_slot(r.seg, r.idx, p.block);
  return e;
}

Expected<std::vector<Extent>> SlabAllocator::alloc_batch(std::span<const std::uint64_t> stored_lens,
                                                              std::uint64_t owner) {
  if (stored_lens.empty() || stored_lens.size() > kMaxBatch)
    return Error{ErrorCode::InvalidArgument, "slab: batch size"};
  std::vector<std::uint64_t> cls(stored_lens.size());
  std::vector<std::uint64_t> created;
  std::vector<Pick> picked;
  auto rollback = [&] {
    for (std::size_t i = picked.size(); i-- > 0;) give(picked[i].run, picked[i].block);
    for (auto c : created)
      if (auto it = classes_.find(c); it != classes_.end() && it->second.runs.empty()) classes_.erase(it);
  };
  for (std::size_t i = 0; i < stored_lens.size(); ++i) {
    auto c = class_for(stored_lens[i], owner, created);
    if (!c) {
      rollback();
      return c.error();
    }
    cls[i] = *c;
  }
  // Group by class (ordered); remember which pick serves each input index.
  std::vector<std::size_t> pick_of(stored_lens.size());
  std::map<std::uint64_t, std::vector<std::size_t>> groups;
  for (std::size_t i = 0; i < cls.size(); ++i) groups[cls[i]].push_back(i);
  for (auto& [c, idxs] : groups) {
    const std::size_t before = picked.size();
    if (!place(c, idxs.size(), picked)) {
      rollback();
      return Error{ErrorCode::ResourceExhausted, "slab: out of blocks"};
    }
    for (std::size_t k = 0; k < idxs.size(); ++k) pick_of[idxs[k]] = before + k;
  }
  std::vector<Extent> out(stored_lens.size());
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = extent_of(picked[pick_of[i]], cls[i]);
    // TEETH: reissue the last generation.
    out[i].gen = (MIRACACHE_TEETH_ON(ReuseGeneration) && arena_.gens().last() > 0 && arena_.gens().last() % 3 == 0)
                     ? arena_.gens().last()
                     : arena_.gens().next();
    arena_.state_gen().store(out[i].gen_slot, proto::BlockState::Writing, out[i].gen);
  }
  return out;
}

void SlabAllocator::free(const Extent& e) {
  const auto& l = arena_.layout();
  MIRACACHE_CHECK(e.seg < l.n_segments && e.off >= l.seg.data_off);
  const std::uint64_t rel = e.off - l.seg.data_off;
  const auto ridx = static_cast<std::uint32_t>(rel / run_bytes_);
  MIRACACHE_CHECK(ridx < runs_per_seg_);
  const std::uint32_t rid = e.seg * runs_per_seg_ + ridx;
  const Run& r = runs_[rid];
  MIRACACHE_CHECK(r.cls == e.len && r.cls != 0 && (rel % run_bytes_) % e.len == 0);
  const auto block = static_cast<std::uint32_t>((rel % run_bytes_) / e.len);
  MIRACACHE_CHECK(block < r.used.size() && r.used[block]);
  MIRACACHE_CHECK(arena_.state_gen().generation(e.gen_slot) == e.gen);
  clear_header(e);  // before the slot can be reused, and before a crash could resurrect it
  arena_.state_gen().store(e.gen_slot, proto::BlockState::Free, e.gen);
  give(rid, block);
}

std::uint32_t SlabAllocator::run_of(const Extent& e) const {
  const auto& l = arena_.layout();
  MIRACACHE_CHECK(e.seg < l.n_segments && e.off >= l.seg.data_off);
  const auto ridx = static_cast<std::uint32_t>((e.off - l.seg.data_off) / run_bytes_);
  MIRACACHE_CHECK(ridx < runs_per_seg_);
  return e.seg * runs_per_seg_ + ridx;
}

std::uint32_t SlabAllocator::run_used(std::uint32_t run) const {
  const Run& r = runs_.at(run);
  return r.cls == 0 ? 0 : static_cast<std::uint32_t>(r.used.size()) - r.n_free;
}

void SlabAllocator::write_header(const Extent& e, proto::ServerHeader h) {
  const auto& l = arena_.layout();
  const std::uint64_t slot_in_seg = e.gen_slot - std::uint64_t{e.seg} * l.seg.slots();
  const std::uint64_t off = l.seg.hdr_table_off + slot_in_seg * kHeaderSlotBytes;
  MIRACACHE_CHECK(arena_.state_gen().generation(e.gen_slot) == e.gen);
  h.generation = e.gen;
  proto::encode(h, std::span<std::byte, proto::kServerHeaderSize>(
                       arena_.block(e.seg, off, kHeaderSlotBytes).data(), proto::kServerHeaderSize));
}

std::vector<ClassStats> SlabAllocator::class_stats() const {
  std::vector<ClassStats> v;
  for (const auto& [len, c] : classes_) {
    ClassStats s;
    s.len = len;
    s.runs = static_cast<std::uint32_t>(c.runs.size());
    s.blocks = std::uint64_t{s.runs} * c.per_run;
    s.free = c.free;
    s.allocated = s.blocks - s.free;
    v.push_back(s);
  }
  return v;
}

Status SlabAllocator::check_invariants() const {
  auto bad = [](const char* m) -> Status { return Error{ErrorCode::Corrupt, m}; };
  std::size_t n_exact = 0;
  for (const auto& [len, c] : classes_) n_exact += c.rung ? 0 : 1;
  if (n_exact > kMaxClasses) return bad("slab: class cap");
  std::size_t formatted = 0;
  for (const auto& [len, c] : classes_) {
    if (c.runs.empty()) return bad("slab: empty class kept");
    std::uint64_t f = 0;
    for (auto rid : c.runs) {
      const Run& r = runs_[rid];
      if (r.cls != len || r.used.size() != c.per_run) return bad("slab: run/class mismatch");
      std::uint32_t nf = 0;
      for (auto u : r.used) nf += u ? 0 : 1;
      if (nf != r.n_free || nf == c.per_run) return bad("slab: run count");
      f += nf;
      ++formatted;
    }
    if (f != c.free) return bad("slab: class free");
  }
  if (formatted + free_runs_.size() + reserved_ != runs_.size()) return bad("slab: run pool");
  for (const auto& r : runs_)
    if (r.reserved && r.cls != 0) return bad("slab: reserved run formatted");
  for (auto rid : free_runs_)
    if (runs_[rid].cls != 0) return bad("slab: free run formatted");
  return {};
}

}  // namespace miracache::store
