// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <functional>
#include <map>
#include <memory>
#include <vector>

#include "fabric/types.h"
#include "util/clock.h"
#include "util/hash.h"
#include "util/random.h"

namespace miracache::fabric {

class SimFabric;

// Fault injection knobs. All probabilities are per work request.
//
// Semantics follow a reliable connection (RC):
//  - By default (ordered = true) work posted on one endpoint is delivered and
//    completed in post order; jitter only stretches the schedule.
//  - A drop is a transport failure: the lost request completes with Timeout after
//    drop_timeout, then the endpoint pair moves to the error state and every other
//    outstanding request on either side flushes with Aborted; new posts fail.
//  - Reordering is an explicit opt-in (ordered = false), for exercising consumers
//    that must tolerate out-of-order completion.
struct FaultConfig {
  Nanos base_delay{2000};
  Nanos jitter{1000};            // uniform extra delay in [0, jitter]
  double drop = 0.0;             // request lost: Timeout after drop_timeout, then pair -> ERR
  Nanos drop_timeout{1'000'000};
  bool ordered = true;           // false opts in to reordering (needs reorder > 0 to matter)
  double reorder = 0.0;          // extra delay in (0, reorder_window]; requires ordered = false
  Nanos reorder_window{20'000};
  double duplicate_completion = 0.0;  // completion is delivered twice

  static constexpr Nanos kMaxDelay{1'000'000'000'000};  // 1000 s; keeps time sums far from overflow

  // Delays in [0, kMaxDelay], probabilities in [0, 1] (NaN rejected), and reorder > 0
  // only when ordered is false. SimNetwork refuses (traps on) an invalid config.
  Status validate() const;
};

// Data-placement model (spec 13.1, 8.2: a CQE is not placement).
// An op larger than slice_size is placed slice by slice; each slice is its own scheduled
// event at a random delay in [0, slice_window], so slices land out of order and interleave
// with other ops on the same bytes (readers can see torn mixes). Ops of at most slice_size
// bytes are one atomic placement and draw no extra randomness.
struct SimOptions {
  std::uint32_t slice_size = 4096;
  Nanos slice_window{4000};
  // iWARP: a WRITE's CQE fires after a random number of slices (1..n) are placed; the
  // rest land later. RoCE (false): the CQE fires after the last slice.
  bool iwarp_early_write_cqe = false;
};

// The simulated wire: a virtual-time event queue plus the fault model.
// Single-threaded. Fully determined by (Random seed, FaultConfig, SimOptions, call sequence).
class SimNetwork {
 public:
  SimNetwork(SimClock& clock, Random& rng, FaultConfig faults, SimOptions options = {});
  ~SimNetwork();

  static constexpr std::size_t kDefaultCqCapacity = 4096;
  // cq_capacity bounds the node's completion queue; overflowing it is an error that
  // moves all of the node's endpoints to ERR (see SimFabric::poll).
  SimFabric& add_node(NodeId id, std::size_t cq_capacity = kDefaultCqCapacity);
  SimFabric* node(NodeId id);

  void set_link(NodeId a, NodeId b, bool up);
  bool link_up(NodeId a, NodeId b) const;
  // A slow link (fail-slow tests): every work request between a and b (either way) is delivered `extra` later, on top of
  // its fate. Draws no randomness, so a run without it is unchanged. extra in [0, kMaxDelay].
  void set_link_delay(NodeId a, NodeId b, Nanos extra);
  Nanos link_delay(NodeId a, NodeId b) const;

  struct Fate {
    Nanos delay;
    bool dropped;
  };
  Fate roll_fate();
  bool roll_duplicate();
  std::uint64_t roll_below(std::uint64_t bound);  // uniform in [0, bound); bound > 0
  const SimOptions& options() const { return options_; }

  // delay must be >= 0 (negative traps).
  void schedule(Nanos delay, std::function<void()> fn);
  // Runs the earliest event, advancing the clock to it. False if the queue is empty.
  bool step();
  void run_until_idle();

  const FaultConfig& faults() const { return faults_; }
  Nanos now() const { return clock_.now(); }
  EndpointId next_endpoint_id() { return ++endpoint_seq_; }

  // Every observable outcome is mixed in; equal hashes mean identical executions.
  void trace(std::uint64_t kind, std::uint64_t a, std::uint64_t b, std::uint64_t c);
  std::uint64_t trace_hash() const { return trace_.value(); }

 private:
  static std::uint64_t link_key(NodeId a, NodeId b);

  SimClock& clock_;
  Random& rng_;
  FaultConfig faults_;
  SimOptions options_;
  std::map<std::pair<Nanos, std::uint64_t>, std::function<void()>> events_;
  std::uint64_t event_seq_ = 0;
  EndpointId endpoint_seq_ = 0;
  std::map<NodeId, std::unique_ptr<SimFabric>> nodes_;
  std::map<std::uint64_t, bool> link_down_;
  std::map<std::uint64_t, Nanos> link_delay_;
  TraceHash trace_;
};

}  // namespace miracache::fabric
