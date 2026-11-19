// SPDX-License-Identifier: Apache-2.0
#include "server/tickets.h"

#include <cstring>

namespace miracache::server {

Expected<std::vector<proto::Ticket>> TicketTable::issue(const std::string& identity, fabric::EpClass cls,
                                                        std::uint8_t rail, std::uint32_t count) {
  auto p = principals_.find(identity);
  if (!p) return p.error();
  if (count == 0 || count > 1024 || rail >= proto::kMaxRails)
    return Error{ErrorCode::InvalidArgument, "tickets: count or rail"};
  sweep();
  if (live_.size() + count > max_live_) return Error{ErrorCode::ResourceExhausted, "tickets: too many live"};
  if (live_for(identity) + count > max_per_identity_)
    return Error{ErrorCode::ResourceExhausted, "tickets: too many live for this identity"};
  std::vector<proto::Ticket> out;
  out.reserve(count);
  const Nanos exp = clock_.now() + ttl_;
  while (out.size() < count) {
    Id id{};
    for (std::size_t i = 0; i < 16; i += 8) {
      std::uint64_t v = rng_.next_u64();
      std::memcpy(id.data() + i, &v, 8);
    }
    if (live_.count(id)) continue;  // keeps ids unique
    live_[id] = Rec{*p, cls, rail, exp, identity};
    ++per_id_[identity];
    proto::Ticket t;
    t.cls = static_cast<std::uint8_t>(cls);
    std::memcpy(t.id, id.data(), 16);
    out.push_back(t);
  }
  return out;
}

Status TicketTable::check_capacity(const std::string& identity, std::uint32_t total) {
  auto p = principals_.find(identity);
  if (!p) return p.error();
  sweep();
  if (live_.size() + total > max_live_) return Error{ErrorCode::ResourceExhausted, "tickets: too many live"};
  if (live_for(identity) + total > max_per_identity_)
    return Error{ErrorCode::ResourceExhausted, "tickets: too many live for this identity"};
  return {};
}

Expected<TicketGrant> TicketTable::redeem(std::span<const std::byte> pd) {
  auto t = proto::decode_ticket(pd);
  if (!t) return Error{ErrorCode::AccessDenied, "tickets: malformed"};
  Id id;
  std::memcpy(id.data(), t->id, 16);
  auto it = live_.find(id);
  if (it == live_.end()) return Error{ErrorCode::AccessDenied, "tickets: unknown or used"};
  Rec r = it->second;
  live_.erase(it);  // single use, even when refused below
  forget(r);
  if (clock_.now() >= r.expiry) return Error{ErrorCode::Timeout, "tickets: expired"};
  if (static_cast<std::uint8_t>(r.cls) != t->cls) return Error{ErrorCode::AccessDenied, "tickets: class mismatch"};
  return TicketGrant{r.principal, r.cls, r.rail, id, r.identity};
}

void TicketTable::forget(const Rec& r) {
  auto it = per_id_.find(r.identity);
  if (it != per_id_.end() && --it->second == 0) per_id_.erase(it);
}

void TicketTable::sweep() {
  const Nanos now = clock_.now();
  for (auto it = live_.begin(); it != live_.end();) {
    if (now >= it->second.expiry) {
      forget(it->second);
      it = live_.erase(it);
    } else {
      ++it;
    }
  }
}

std::size_t TicketTable::remove_identity(const std::string& identity) {
  std::size_t n = 0;
  for (auto it = live_.begin(); it != live_.end();) {
    if (it->second.identity == identity) {
      forget(it->second);
      it = live_.erase(it);
      ++n;
    } else {
      ++it;
    }
  }
  principals_.remove(identity);
  return n;
}

}  // namespace miracache::server
