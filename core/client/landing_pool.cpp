// SPDX-License-Identifier: Apache-2.0
#include "client/landing_pool.h"

#include <sys/mman.h>

#include <iterator>
#include <vector>

#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB (21 << MAP_HUGE_SHIFT)
#endif
#ifndef MAP_HUGE_1GB
#define MAP_HUGE_1GB (30 << MAP_HUGE_SHIFT)
#endif
#ifndef MAP_HUGETLB
#define MAP_HUGETLB 0x40000
#endif

namespace miracache {
namespace {

constexpr std::size_t round_up(std::size_t n, std::size_t a) { return (n + a - 1) / a * a; }

struct Mapping {
  std::byte* p = nullptr;
  std::size_t len = 0;
  PoolBacking kind = PoolBacking::Anon;
};

// Decision 2: 1 GiB pages -> 2 MiB pages -> anon + MADV_HUGEPAGE -> plain anon.
Mapping map_pool(std::size_t bytes) {
  constexpr std::size_t k2M = std::size_t{2} << 20, k1G = std::size_t{1} << 30;
  const int base = MAP_PRIVATE | MAP_ANONYMOUS;
  if (bytes % k1G == 0) {
    void* p = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE, base | MAP_HUGETLB | MAP_HUGE_1GB, -1, 0);
    if (p != MAP_FAILED) return {static_cast<std::byte*>(p), bytes, PoolBacking::Huge1G};
  }
  if (bytes % k2M == 0) {
    void* p = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE, base | MAP_HUGETLB | MAP_HUGE_2MB, -1, 0);
    if (p != MAP_FAILED) return {static_cast<std::byte*>(p), bytes, PoolBacking::Huge2M};
  }
  void* p = ::mmap(nullptr, bytes, PROT_READ | PROT_WRITE, base, -1, 0);
  if (p == MAP_FAILED) return {};
  PoolBacking kind = PoolBacking::Anon;
#ifdef MADV_HUGEPAGE
  if (bytes % k2M == 0 && ::madvise(p, bytes, MADV_HUGEPAGE) == 0) kind = PoolBacking::Thp;
#endif
  return {static_cast<std::byte*>(p), bytes, kind};
}

}  // namespace

struct LandingPool::Gen {
  std::uint32_t id = 0;
  Mapping map;
  fabric::MemRegion mr;
  bool registered = false;
  std::map<std::uint64_t, std::uint64_t> free;  // off -> len, coalesced
  std::map<std::uint64_t, std::uint64_t> used;  // off -> rounded len
  std::size_t in_use = 0;
};

struct LandingPool::Sub {
  fabric::PdId pd;
  std::uint32_t next_gen = 1;
  std::vector<std::unique_ptr<Gen>> gens;  // back() is current
};

LandingPool::LandingPool(fabric::Fabric& fab) : fab_(fab) {}

LandingPool::~LandingPool() {
  for (auto& [k, s] : subs_)
    for (auto& g : s->gens) destroy_gen(*g);
}

void LandingPool::destroy_gen(Gen& g) {
  if (g.registered) static_cast<void>(fab_.dereg(g.mr));
  g.registered = false;
  if (g.map.p != nullptr) ::munmap(g.map.p, g.map.len);
  g.map.p = nullptr;
}

std::unique_ptr<LandingPool::Gen> LandingPool::make_gen(std::uint32_t id, fabric::PdId pd,
                                                        std::size_t bytes, Status& st) {
  bytes = round_up(bytes, kPoolAlign);
  auto g = std::make_unique<Gen>();
  g->id = id;
  g->map = map_pool(bytes);
  if (g->map.p == nullptr) {
    st = Error{ErrorCode::ResourceExhausted, "landing pool: mmap"};
    return nullptr;
  }
  auto mr = fab_.reg(std::span<std::byte>(g->map.p, g->map.len),
                     fabric::Access::LocalWrite | fabric::Access::RemoteWrite, pd);
  if (!mr) {
    ::munmap(g->map.p, g->map.len);
    st = mr.error();
    return nullptr;
  }
  g->mr = *mr;
  g->registered = true;
  g->free.emplace(0, g->map.len);
  backing_ = g->map.kind;
  return g;
}

Status LandingPool::add_subpool(SubpoolKey key, fabric::PdId pd, std::size_t bytes) {
  if (bytes == 0) return Error{ErrorCode::InvalidArgument, "landing pool: zero size"};
  std::lock_guard lk(mu_);
  if (subs_.count(key) != 0) return Error{ErrorCode::Busy, "landing pool: subpool exists"};
  auto sub = std::make_unique<Sub>();
  sub->pd = pd;
  Status st;
  auto g = make_gen(sub->next_gen++, pd, bytes, st);
  if (!g) return st;
  sub->gens.push_back(std::move(g));
  subs_.emplace(key, std::move(sub));
  return {};
}

Status LandingPool::resize_subpool(SubpoolKey key, std::size_t bytes) {
  if (bytes == 0) return Error{ErrorCode::InvalidArgument, "landing pool: zero size"};
  std::lock_guard lk(mu_);
  auto it = subs_.find(key);
  if (it == subs_.end()) return Error{ErrorCode::NotFound, "landing pool: no subpool"};
  Sub& s = *it->second;
  Status st;
  auto g = make_gen(s.next_gen++, s.pd, bytes, st);
  if (!g) return st;
  s.gens.push_back(std::move(g));
  // Retire older generations that are already idle.
  for (std::size_t i = 0; i + 1 < s.gens.size();) {
    if (s.gens[i]->used.empty()) {
      destroy_gen(*s.gens[i]);
      s.gens.erase(s.gens.begin() + static_cast<std::ptrdiff_t>(i));
    } else {
      ++i;
    }
  }
  return {};
}

Expected<PoolSpan> LandingPool::acquire(SubpoolKey key, std::size_t len) {
  if (len == 0) return Error{ErrorCode::InvalidArgument, "landing pool: zero length"};
  std::lock_guard lk(mu_);
  auto it = subs_.find(key);
  if (it == subs_.end()) return Error{ErrorCode::NotFound, "landing pool: no subpool"};
  Gen& g = *it->second->gens.back();
  const std::uint64_t need = round_up(len, kPoolAlign);
  for (auto f = g.free.begin(); f != g.free.end(); ++f) {
    if (f->second < need) continue;
    const std::uint64_t off = f->first, rest = f->second - need;
    g.free.erase(f);
    if (rest != 0) g.free.emplace(off + need, rest);
    g.used.emplace(off, need);
    g.in_use += need;
    return PoolSpan{key, g.id, off, len, g.map.p + off, g.mr.lkey};
  }
  return Error{ErrorCode::ResourceExhausted, "landing pool: full"};
}

void LandingPool::release(const PoolSpan& span) {
  std::lock_guard lk(mu_);
  auto it = subs_.find(span.key);
  if (it == subs_.end()) return;
  Sub& s = *it->second;
  for (std::size_t i = 0; i < s.gens.size(); ++i) {
    Gen& g = *s.gens[i];
    if (g.id != span.gen) continue;
    auto u = g.used.find(span.off);
    if (u == g.used.end()) return;  // double release
    std::uint64_t off = u->first, len = u->second;
    g.used.erase(u);
    g.in_use -= len;
    auto next = g.free.lower_bound(off);  // coalesce with neighbours
    if (next != g.free.end() && off + len == next->first) {
      len += next->second;
      next = g.free.erase(next);
    }
    if (next != g.free.begin()) {
      auto prev = std::prev(next);
      if (prev->first + prev->second == off) {
        off = prev->first;
        len += prev->second;
        g.free.erase(prev);
      }
    }
    g.free.emplace(off, len);
    if (g.used.empty() && i + 1 != s.gens.size()) {  // retired generation, now idle
      destroy_gen(g);
      s.gens.erase(s.gens.begin() + static_cast<std::ptrdiff_t>(i));
    }
    return;
  }
}

std::size_t LandingPool::bytes_in_use() const {
  std::lock_guard lk(mu_);
  std::size_t n = 0;
  for (const auto& [k, s] : subs_)
    for (const auto& g : s->gens) n += g->in_use;
  return n;
}

PoolBacking LandingPool::backing() const {
  std::lock_guard lk(mu_);
  return backing_;
}

std::size_t LandingPool::live_generations(SubpoolKey key) const {
  std::lock_guard lk(mu_);
  auto it = subs_.find(key);
  return it == subs_.end() ? 0 : it->second->gens.size();
}

}  // namespace miracache
