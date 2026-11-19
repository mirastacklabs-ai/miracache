// SPDX-License-Identifier: Apache-2.0
#include "util/clock.h"

namespace miracache {

Nanos RealClock::now() const {
  return std::chrono::duration_cast<Nanos>(
      std::chrono::steady_clock::now().time_since_epoch());
}

std::int64_t wall_unix_ns() {
  return std::chrono::duration_cast<Nanos>(std::chrono::system_clock::now().time_since_epoch()).count();
}

}  // namespace miracache
