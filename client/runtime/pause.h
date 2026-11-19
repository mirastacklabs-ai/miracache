// SPDX-License-Identifier: Apache-2.0
// pause_for: sleeps a short real-time interval (a timed wait that nothing signals). Client runtime only:
// sleeping and condition variables are lint-restricted. The sim hand-off of client.cpp uses it to let another
// thread take its turn on the single-threaded simulated network.
#pragma once

#include <chrono>
#include <condition_variable>  // lint:client-runtime
#include <mutex>

namespace miracache {

inline void pause_for(std::chrono::microseconds d) {
  std::mutex m;
  std::condition_variable cv;  // lint:client-runtime
  std::unique_lock lk(m);
  cv.wait_for(lk, d);
}

}  // namespace miracache
