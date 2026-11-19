// SPDX-License-Identifier: Apache-2.0
#include "fabric/sim/sim_network.h"

#include <algorithm>

#include "fabric/sim/sim_fabric.h"

namespace miracache::fabric {

Status FaultConfig::validate() const {
  auto delay_ok = [](Nanos d) { return d >= Nanos{0} && d <= kMaxDelay; };
  auto prob_ok = [](double p) { return p >= 0.0 && p <= 1.0; };  // false for NaN
  if (!delay_ok(base_delay) || !delay_ok(jitter) || !delay_ok(drop_timeout) || !delay_ok(reorder_window)) {
    return Error{ErrorCode::InvalidArgument, "FaultConfig: delay outside [0, kMaxDelay]"};
  }
  if (!prob_ok(drop) || !prob_ok(reorder) || !prob_ok(duplicate_completion)) {
    return Error{ErrorCode::InvalidArgument, "FaultConfig: probability outside [0, 1]"};
  }
  if (reorder > 0.0 && ordered) {
    return Error{ErrorCode::InvalidArgument, "FaultConfig: reorder requires ordered = false"};
  }
  return {};
}

SimNetwork::SimNetwork(SimClock& clock, Random& rng, FaultConfig faults, SimOptions options)
    : clock_(clock), rng_(rng), faults_(faults), options_(options) {
  MIRACACHE_CHECK(faults_.validate().has_value());
  MIRACACHE_CHECK(options_.slice_size > 0);
  MIRACACHE_CHECK(options_.slice_window >= Nanos{0} && options_.slice_window <= FaultConfig::kMaxDelay);
}

std::uint64_t SimNetwork::roll_below(std::uint64_t bound) { return rng_.below(bound); }

SimNetwork::~SimNetwork() = default;

SimFabric& SimNetwork::add_node(NodeId id, std::size_t cq_capacity) {
  auto& slot = nodes_[id];
  if (!slot) slot = std::make_unique<SimFabric>(*this, id, cq_capacity);
  return *slot;
}

SimFabric* SimNetwork::node(NodeId id) {
  auto it = nodes_.find(id);
  return it == nodes_.end() ? nullptr : it->second.get();
}

std::uint64_t SimNetwork::link_key(NodeId a, NodeId b) {
  return (std::uint64_t{std::min(a, b)} << 32) | std::max(a, b);
}

void SimNetwork::set_link(NodeId a, NodeId b, bool up) {
  link_down_[link_key(a, b)] = !up;
  trace(0x4c494e4b /* LINK */, a, b, up);
}

bool SimNetwork::link_up(NodeId a, NodeId b) const {
  auto it = link_down_.find(link_key(a, b));
  return it == link_down_.end() || !it->second;
}

void SimNetwork::set_link_delay(NodeId a, NodeId b, Nanos extra) {
  MIRACACHE_CHECK(extra >= Nanos{0} && extra <= FaultConfig::kMaxDelay);
  if (extra == Nanos{0}) link_delay_.erase(link_key(a, b));
  else link_delay_[link_key(a, b)] = extra;
  trace(0x534c4f57 /* SLOW */, a, b, static_cast<std::uint64_t>(extra.count()));
}

Nanos SimNetwork::link_delay(NodeId a, NodeId b) const {
  if (link_delay_.empty()) return Nanos{0};
  auto it = link_delay_.find(link_key(a, b));
  return it == link_delay_.end() ? Nanos{0} : it->second;
}

SimNetwork::Fate SimNetwork::roll_fate() {
  Fate f{faults_.base_delay, rng_.chance(faults_.drop)};
  f.delay += Nanos{static_cast<std::int64_t>(rng_.below(static_cast<std::uint64_t>(faults_.jitter.count()) + 1))};
  if (!faults_.ordered && rng_.chance(faults_.reorder)) {
    f.delay += Nanos{static_cast<std::int64_t>(rng_.between(1, std::max<std::int64_t>(1, faults_.reorder_window.count())))};
  }
  if (f.dropped) f.delay = faults_.drop_timeout;
  return f;
}

bool SimNetwork::roll_duplicate() { return rng_.chance(faults_.duplicate_completion); }

void SimNetwork::schedule(Nanos delay, std::function<void()> fn) {
  MIRACACHE_CHECK(delay >= Nanos{0});
  events_.emplace(std::make_pair(clock_.now() + delay, event_seq_++), std::move(fn));
}

bool SimNetwork::step() {
  if (events_.empty()) return false;
  auto it = events_.begin();
  clock_.advance_to(it->first.first);
  auto fn = std::move(it->second);
  events_.erase(it);
  fn();
  return true;
}

void SimNetwork::run_until_idle() {
  while (step()) {}
}

void SimNetwork::trace(std::uint64_t kind, std::uint64_t a, std::uint64_t b, std::uint64_t c) {
  trace_.mix(static_cast<std::uint64_t>(clock_.now().count()));
  trace_.mix(kind);
  trace_.mix(a);
  trace_.mix(b);
  trace_.mix(c);
}

}  // namespace miracache::fabric
