// SPDX-License-Identifier: Apache-2.0
#include "store/scope_table.h"

#include <algorithm>
#include <cstring>

#include "util/check.h"

namespace miracache::store {
namespace {
bool all_zero(std::span<const std::byte> b) {
  return std::all_of(b.begin(), b.end(), [](std::byte v) { return v == std::byte{0}; });
}
}  // namespace

std::span<std::byte> ScopeTable::rec(std::uint32_t slot) const {
  MIRACACHE_CHECK(slot < records_);
  return region_.subspan(proto::scope_record_offset(slot), proto::kScopeRecordSize);
}

void ScopeTable::clear(std::uint32_t slot) {
  auto b = rec(slot);
  if (!all_zero(b)) std::memset(b.data(), 0, b.size());
}

Status ScopeTable::format() {
  MIRACACHE_CHECK(region_.size() >= proto::scope_region_size(records_));
  for (std::size_t off = 0; off < region_.size(); off += 4096) {  // check-before-write, page by page
    auto page = region_.subspan(off, std::min<std::size_t>(4096, region_.size() - off));
    if (!all_zero(page)) std::memset(page.data(), 0, page.size());
  }
  proto::ScopeRegionHeader h;
  h.n_records = records_;
  if (auto st = proto::encode(h, std::span<std::byte, proto::kScopeRegionHeaderSize>(region_.data(), proto::kScopeRegionHeaderSize));
      !st)
    return st;
  free_.clear();
  for (std::uint32_t i = records_; i-- > 0;) free_.push_back(i);
  return {};
}

Status ScopeTable::check_header() const {
  auto h = proto::decode_scope_region_header(
      std::span<const std::byte, proto::kScopeRegionHeaderSize>(region_.data(), proto::kScopeRegionHeaderSize));
  if (!h) return h.error();
  if (h->n_records != records_ || !proto::scope_region_fits(*h, region_.size()))
    return Error{ErrorCode::Corrupt, "scope region: record count differs from config"};
  return {};
}

std::uint64_t ScopeTable::load(const std::function<bool(std::uint32_t, const proto::ScopeRecord&)>& keep,
                               const std::function<bool(std::uint32_t, std::span<const std::byte>)>& torn) {
  std::uint64_t corrupt = 0;
  free_.clear();
  std::vector<std::uint32_t> freed;
  for (std::uint32_t i = 0; i < records_; ++i) {
    auto b = rec(i);
    if (all_zero(b)) {
      freed.push_back(i);
      continue;
    }
    auto r = proto::decode_scope_record(std::span<const std::byte, proto::kScopeRecordSize>(b.data(), proto::kScopeRecordSize));
    if (!r) {  // spec 6.1: a record whose CRC fails is a free slot (once the caller has read whom it named)
      ++corrupt;
      if (torn && torn(i, std::span<const std::byte>(b.data(), b.size()))) continue;
    }
    if (!r || r->state == proto::kScopeFree || !keep(i, *r)) {
      clear(i);
      freed.push_back(i);
    }
  }
  for (auto it = freed.rbegin(); it != freed.rend(); ++it) free_.push_back(*it);
  return corrupt;
}

std::uint32_t ScopeTable::alloc() {
  if (free_.empty()) return kNone;
  const std::uint32_t s = free_.back();
  free_.pop_back();
  return s;
}

void ScopeTable::write(std::uint32_t slot, const proto::ScopeRecord& r) {
  auto b = rec(slot);
  MIRACACHE_CHECK(proto::encode(r, std::span<std::byte, proto::kScopeRecordSize>(b.data(), proto::kScopeRecordSize)).has_value());
}

void ScopeTable::release(std::uint32_t slot) {
  clear(slot);
  free_.push_back(slot);
}

}  // namespace miracache::store
