// SPDX-License-Identifier: Apache-2.0
// Deterministic Executor for the simulator: work and done run as scheduled events on
// virtual time, at a Random delay.
#pragma once

#include <functional>
#include <utility>

#include "fabric/sim/sim_network.h"
#include "util/executor.h"
#include "util/random.h"

namespace miracache::sim {

class SimExecutor final : public Executor {
 public:
  SimExecutor(fabric::SimNetwork& net, Random& rng, std::uint64_t max_delay_ns = 3000)
      : net_(net), rng_(rng), max_delay_(max_delay_ns) {}

  void post(std::function<void()> work, std::function<void()> done) override {
    const Nanos d{static_cast<std::int64_t>(rng_.below(max_delay_ + 1))};
    net_.schedule(d, [w = std::move(work), dn = std::move(done)] {
      w();
      if (dn) dn();
    });
  }

 private:
  fabric::SimNetwork& net_;
  Random& rng_;
  std::uint64_t max_delay_;
};

}  // namespace miracache::sim
