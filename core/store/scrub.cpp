// SPDX-License-Identifier: Apache-2.0
#include "store/scrub.h"

#include <algorithm>

#include "proto/server_header.h"
#include "util/crc32c.h"

namespace miracache::store {

Scrubber::Scrubber(Store& store, Arena& arena, Executor& exec, const Clock& clock, const StoreMetrics* mx,
                   std::function<void(const Extent&)> on_corrupt)
    : store_(store), arena_(arena), exec_(exec), clock_(clock), mx_(mx), on_corrupt_(std::move(on_corrupt)),
      sh_(std::make_shared<Shared>()) {
  sh_->store = &store_;
  sh_->self = this;
}

Scrubber::~Scrubber() {
  sh_->store = nullptr;  // late `done`s do nothing
  sh_->self = nullptr;
}

void Scrubber::set_rate(std::uint64_t bytes_per_s, std::uint32_t blocks_per_turn) {
  if (bytes_per_s != rate_) last_ns_ = -1;  // a changed rate restarts the credit with one burst
  rate_ = bytes_per_s;
  per_turn_ = std::clamp<std::uint32_t>(blocks_per_turn, 1, kBlocksPerTurn);
}

void Scrubber::finish(const Extent& e, std::uint64_t stored_len, bool corrupt) {
  ++checked_;
  bytes_ += stored_len;
  bump(mx_ ? mx_->scrub_checked : nullptr);
  bump(mx_ ? mx_->scrub_bytes : nullptr, stored_len);
  if (corrupt) {
    ++failed_;
    bump(mx_ ? mx_->scrub_failed : nullptr);
    if (on_corrupt_) on_corrupt_(e);
  }
  store_.scrub_unpin(e.gen_slot, e.gen, corrupt);
}

std::size_t Scrubber::step() {
  if (stopped_ || rate_ == 0) {
    last_ns_ = -1;
    return 0;
  }
  const std::int64_t now = clock_.now().count();
  const std::int64_t cap = static_cast<std::int64_t>(std::min<std::uint64_t>(rate_, INT64_MAX / 2));
  if (last_ns_ < 0) {
    credit_ = cap;  // the first turn has a full burst
  } else if (now > last_ns_) {
    using u128 = unsigned __int128;  // unsigned: a signed __int128 multiply needs __muloti4, which UBSan builds do not link
    const u128 add = static_cast<u128>(rate_) * static_cast<std::uint64_t>(now - last_ns_) / 1000000000;
    const std::int64_t add64 = static_cast<std::int64_t>(std::min<u128>(add, static_cast<u128>(cap)));
    credit_ = std::min<std::int64_t>(credit_ + add64, cap);  // credit_ >= -INT64_MAX/2, add64 <= cap: no overflow
  }
  last_ns_ = now;

  const auto& l = arena_.layout();
  std::size_t picked = 0;
  while (picked < per_turn_ && credit_ > 0 && in_flight_ < kMaxInFlight) {
    if (cursor_ == 0 && cycle_start_ns_ < 0) cycle_start_ns_ = now;
    auto t = store_.scrub_pin_next(cursor_);
    if (!t) {  // end of the store: one cycle done
      ++cycles_;
      if (mx_ && mx_->scrub_cycle_seconds && cycle_start_ns_ >= 0)
        mx_->scrub_cycle_seconds->set((now - cycle_start_ns_) / 1000000000);
      cycle_start_ns_ = -1;
      break;
    }
    ++picked;
    const Extent e = t->e;
    const std::uint64_t len = t->stored_len;
    credit_ -= static_cast<std::int64_t>(std::min<std::uint64_t>(len, INT64_MAX / 2));
    // The header (128 B) is read here, on the store thread; the bytes of the extent are read on the executor.
    const std::uint64_t hoff = l.seg.hdr_table_off + (e.gen_slot - std::uint64_t{e.seg} * l.seg.slots()) * kHeaderSlotBytes;
    auto hb = arena_.block(e.seg, hoff, kHeaderSlotBytes);
    auto h = proto::decode_server_header(std::span<const std::byte, proto::kServerHeaderSize>(hb.data(), proto::kServerHeaderSize));
    if (!h || h->generation != e.gen || h->stored_len != len || len > e.len) {
      finish(e, len, true);  // header unreadable or disagrees with the store: the block cannot be trusted
      continue;
    }
    struct Job {
      std::span<const std::byte> bytes;
      std::uint32_t want = 0, got = 0;
    };
    auto job = std::make_shared<Job>();
    job->bytes = arena_.block(e.seg, e.off, len);
    job->want = h->payload_crc;
    ++in_flight_;
    exec_.post([job] { job->got = crc32c(job->bytes); },
               [sh = sh_, job, e, len] {
                 if (!sh->store) return;  // the scrubber (and the store) are gone
                 if (sh->self) {
                   --sh->self->in_flight_;
                   sh->self->finish(e, len, job->got != job->want);
                 } else {
                   sh->store->scrub_unpin(e.gen_slot, e.gen, false);
                 }
               });
  }
  return picked;
}

}  // namespace miracache::store
