// SPDX-License-Identifier: Apache-2.0
// Small blocking helpers for the client runtime (threads are lint-restricted to client/runtime/).
//   pause_ms(ms)              sleeps without sleep_for (a condition variable nobody signals)
//   run_bounded(f, ms, out)   runs a blocking call (getaddrinfo) on a detached helper thread and
//                             waits at most `ms` for it; on timeout the helper is left to finish
//                             on its own (its state is shared, so nothing dangles). false = timed out.
#pragma once

#include <chrono>
#include <condition_variable>  // lint:client-runtime
#include <memory>
#include <mutex>
#include <thread>  // lint:client-runtime
#include <utility>

namespace miracache {

inline void pause_ms(unsigned ms) {
  std::mutex m;
  std::condition_variable cv;  // lint:client-runtime
  std::unique_lock lk(m);
  cv.wait_for(lk, std::chrono::milliseconds(ms), [] { return false; });
}

template <class R, class F>
bool run_bounded(F f, unsigned timeout_ms, R& out) {
  struct St {
    std::mutex m;
    std::condition_variable cv;  // lint:client-runtime
    bool done = false;
    R r{};
  };
  auto st = std::make_shared<St>();
  std::thread([st, f = std::move(f)]() mutable { R r = f(); { std::lock_guard lk(st->m); st->r = std::move(r); st->done = true; } st->cv.notify_all(); }).detach();  // lint:client-runtime
  std::unique_lock lk(st->m);
  if (!st->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] { return st->done; })) return false;
  out = std::move(st->r);
  return true;
}

}  // namespace miracache
