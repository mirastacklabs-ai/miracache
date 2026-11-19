// SPDX-License-Identifier: Apache-2.0
// KeepaliveThread: calls `tick` every `ms` milliseconds on one background thread until stop()
// (or destruction), which joins it. Client runtime only (threads are lint-restricted).
// From inside `tick` (or any thread) next_in(ms) shortens the NEXT wait and kick() asks for a
// tick right away; the wire client uses both to run reconnect attempts on their backoff clock.
#pragma once

#include <chrono>
#include <condition_variable>  // lint:client-runtime
#include <functional>
#include <mutex>
#include <thread>  // lint:client-runtime

namespace miracache {

class KeepaliveThread {
 public:
  KeepaliveThread() = default;
  ~KeepaliveThread() { stop(); }
  KeepaliveThread(const KeepaliveThread&) = delete;
  KeepaliveThread& operator=(const KeepaliveThread&) = delete;

  // No-op when ms == 0 or already started. `tick` must not call start/stop.
  void start(unsigned ms, std::function<void()> tick) {
    if (ms == 0 || th_.joinable()) return;
    {
      std::lock_guard lk(mu_);
      period_ = ms;
    }
    th_ = std::thread([this, tick = std::move(tick)] {  // lint:client-runtime
      std::unique_lock lk(mu_);
      while (!stop_) {
        const unsigned w = next_ms_ != 0 ? next_ms_ : period_;
        next_ms_ = 0;
        cv_.wait_for(lk, std::chrono::milliseconds(w), [&] { return stop_ || kick_; });
        if (stop_) break;
        kick_ = false;
        lk.unlock();
        tick();
        lk.lock();
      }
    });
  }
  void stop() {
    {
      std::lock_guard lk(mu_);
      stop_ = true;
    }
    cv_.notify_all();
    if (th_.joinable()) th_.join();
  }
  // A thread was started (and not yet stopped). For the owner's thread: start/stop are not synchronised with it.
  bool running() const { return th_.joinable(); }
  // The wait after the current tick lasts `ms` (0 = the regular period).
  void next_in(unsigned ms) {
    std::lock_guard lk(mu_);
    next_ms_ = ms;
  }
  // HR2: the regular period from the next wait on (0 is ignored: a started thread always has a period).
  void set_period(unsigned ms) {
    if (ms == 0) return;
    std::lock_guard lk(mu_);
    period_ = ms;
  }
  unsigned period() {
    std::lock_guard lk(mu_);
    return period_;
  }
  // Wakes the thread for an immediate tick.
  void kick() {
    {
      std::lock_guard lk(mu_);
      kick_ = true;
    }
    cv_.notify_all();
  }

 private:
  std::mutex mu_;
  std::condition_variable cv_;  // lint:client-runtime
  bool stop_ = false, kick_ = false;
  unsigned next_ms_ = 0;
  unsigned period_ = 0;
  std::thread th_;  // lint:client-runtime
};

}  // namespace miracache
