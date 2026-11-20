// SPDX-License-Identifier: Apache-2.0
// TaskThread: one background thread that runs queued tasks in order. It is also the JobControl of the tasks it
// runs: cancelled() is true once stop() was called, and wait_cancel_for() sleeps without spinning until then.
// stop() does not drop queued tasks: the thread still pops each one and runs it with cancelled() already true,
// so a task can release what it holds and count itself as cancelled; then the thread exits and stop() joins it.
// Client runtime only (threads are lint-restricted). Used by the replica replicator (client.cpp): never a
// Runtime worker.
#pragma once

#include <chrono>
#include <condition_variable>  // lint:client-runtime
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>  // lint:client-runtime

#include "runtime/runtime.h"

namespace miracache {

class TaskThread final : public JobControl {
 public:
  using Task = std::function<void(const JobControl&)>;

  TaskThread() : th_([this] { loop(); }) {}
  ~TaskThread() override { stop(); }
  TaskThread(const TaskThread&) = delete;
  TaskThread& operator=(const TaskThread&) = delete;

  // False (task not queued) once stop() was called.
  bool push(Task t) {
    {
      std::lock_guard lk(mu_);
      if (stop_) return false;
      q_.push_back(std::move(t));
      ++pending_;
    }
    cv_.notify_one();
    return true;
  }
  // Signals the stop without waiting: a caller with several threads signals all of them, then
  // joins each with stop(), so a hung task on one thread does not delay the stop signal of the others.
  void request_stop() noexcept {
    {
      std::lock_guard lk(mu_);
      stop_ = true;
    }
    cv_.notify_all();
  }
  void stop() noexcept {
    {
      std::lock_guard lk(mu_);
      stop_ = true;
    }
    cv_.notify_all();
    if (th_.joinable()) th_.join();
  }
  // Queued plus running tasks.
  std::size_t pending() const {
    std::lock_guard lk(mu_);
    return pending_;
  }

  bool cancelled() const noexcept override {
    std::lock_guard lk(mu_);
    return stop_;
  }
  bool wait_cancel_for(std::chrono::microseconds d) const noexcept override {
    std::unique_lock lk(mu_);
    cv_.wait_for(lk, d, [&] { return stop_; });
    return stop_;
  }

 private:
  void loop() {
    std::unique_lock lk(mu_);
    for (;;) {
      cv_.wait(lk, [&] { return stop_ || !q_.empty(); });
      if (q_.empty()) return;  // stopping and drained
      Task t = std::move(q_.front());
      q_.pop_front();
      lk.unlock();
      t(*this);
      t = nullptr;  // release what the task captured before it stops counting as pending
      lk.lock();
      --pending_;
    }
  }

  mutable std::mutex mu_;
  mutable std::condition_variable cv_;  // lint:client-runtime
  std::deque<Task> q_;
  bool stop_ = false;
  std::size_t pending_ = 0;
  // Last member: the thread starts running in the constructor.
  std::thread th_;  // lint:client-runtime
};

}  // namespace miracache
