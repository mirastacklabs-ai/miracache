// SPDX-License-Identifier: Apache-2.0
// Connection tickets and the principal table (spec 3.3, 9.2; design/03 R22).
//
// A ticket is {class, random 128-bit id} (proto::Ticket, 20 B in the CM private data). The
// memory node holds no ticket key: IssueTicket records each id in memory as
// {identity, principal, class, rail, expiry}; the first connect that presents the id consumes
// it (single use). IssueTicket rejects an identity that is not in the principal table, so no
// connection exists without a principal. Ids come from the injected Random (RealRandom in
// production, seeded in the sim).
// Single-threaded: used from the store thread (admin calls are marshalled by the caller).
#pragma once

#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <string>
#include <vector>

#include "fabric/types.h"
#include "proto/messages.h"
#include "store/store.h"
#include "util/clock.h"
#include "util/expected.h"
#include "util/random.h"

namespace miracache::server {

// identity (mTLS SPIFFE ID, or the lab identity) -> principal.
class PrincipalTable {
 public:
  void add(const std::string& identity, store::PrincipalId p) { ids_[identity] = p; }
  Expected<store::PrincipalId> find(const std::string& identity) const {
    auto it = ids_.find(identity);
    if (it == ids_.end()) return Error{ErrorCode::AccessDenied, "tickets: identity not in principal table"};
    return it->second;
  }
  // Drops the binding. TicketTable::remove_identity also drops the identity's live tickets.
  bool remove(const std::string& identity) { return ids_.erase(identity) != 0; }
  // Every bound identity, ascending (bundle apply drops the ones the bundle no longer names).
  std::vector<std::string> identities() const {
    std::vector<std::string> v;
    v.reserve(ids_.size());
    for (const auto& [identity, p] : ids_) v.push_back(identity);
    return v;
  }
  std::size_t size() const { return ids_.size(); }
  // Distinct configured principal ids, ascending (bounded by the configuration).
  std::vector<store::PrincipalId> principal_ids() const {
    std::set<store::PrincipalId> s;
    for (const auto& [identity, p] : ids_) s.insert(p);
    return {s.begin(), s.end()};
  }

 private:
  std::map<std::string, store::PrincipalId> ids_;
};

struct TicketGrant {
  store::PrincipalId principal = 0;
  fabric::EpClass cls = fabric::EpClass::Control;
  std::uint8_t rail = 0;
  std::array<std::uint8_t, 16> id{};  // the ticket id (binds the accepted endpoint)
  std::string identity;               // who the ticket was issued to
};

class TicketTable {
 public:
  TicketTable(const Clock& clock, Random& rng, Nanos ttl = std::chrono::seconds(300), std::size_t max_live = 65536,
              std::size_t max_per_identity = 1024)
      : clock_(clock), rng_(rng), ttl_(ttl), max_live_(max_live), max_per_identity_(max_per_identity) {}

  // HR1: new tickets use the new TTL; live ones keep their expiry. Limits apply to the next issue().
  void set_limits(Nanos ttl, std::size_t max_per_identity) {
    ttl_ = ttl;
    max_per_identity_ = max_per_identity;
  }
  PrincipalTable& principals() { return principals_; }
  const PrincipalTable& principals() const { return principals_; }

  // IssueTicket(class, rail, count): AccessDenied for an unknown identity; InvalidArgument for
  // count 0 / rail >= 4; ResourceExhausted when too many tickets are live.
  Expected<std::vector<proto::Ticket>> issue(const std::string& identity, fabric::EpClass cls, std::uint8_t rail,
                                             std::uint32_t count);
  // The checks issue() makes up front, for `total` tickets in one batch (possibly several calls).
  Status check_capacity(const std::string& identity, std::uint32_t total);
  // Consumes the ticket carried in the CM private data. Malformed or unknown/reused ids are
  // AccessDenied; an expired ticket is consumed and refused with Timeout.
  Expected<TicketGrant> redeem(std::span<const std::byte> private_data);

  std::size_t live() const { return live_.size(); }
  void sweep();  // drops expired tickets
  std::size_t live_for(const std::string& identity) const {
    auto it = per_id_.find(identity);
    return it == per_id_.end() ? 0 : it->second;
  }
  // Drops every live ticket of `identity` and its principal binding. Returns the tickets dropped.
  std::size_t remove_identity(const std::string& identity);

 private:
  struct Rec {
    store::PrincipalId principal;
    fabric::EpClass cls;
    std::uint8_t rail;
    Nanos expiry;
    std::string identity;
  };
  using Id = std::array<std::uint8_t, 16>;
  void forget(const Rec& r);  // per-identity bookkeeping when a record leaves live_
  const Clock& clock_;
  Random& rng_;
  Nanos ttl_;
  std::size_t max_live_;
  std::size_t max_per_identity_;  // live tickets one identity may hold
  PrincipalTable principals_;
  std::map<Id, Rec> live_;
  std::map<std::string, std::size_t> per_id_;
};

}  // namespace miracache::server
