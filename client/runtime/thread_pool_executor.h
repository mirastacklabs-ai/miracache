// SPDX-License-Identifier: Apache-2.0
// Production Executor: a resizable worker pool (crypto.workers is DYNAMIC). Lives in
// client/, outside the core/ determinism lint.
#pragma once

#include <condition_variable>  // lint:client-runtime
#include <cstddef>
#include <deque>
#include <mutex>
#include <thread>
#include <vector>

#include "util/executor.h"

namespace miracache {

class ThreadPoolExecutor final : public Executor {
 public:
  explicit ThreadPoolExecutor(std::size_t workers);
  ~ThreadPoolExecutor() override;  // drains queued work, then joins
  ThreadPoolExecutor(const ThreadPoolExecutor&) = delete;
  ThreadPoolExecutor& operator=(const ThreadPoolExecutor&) = delete;

  // `done` runs on the same worker right after `work`.
  void post(std::function<void()> work, std::function<void()> done) override;
  // Grows or shrinks (min 1). Shrinking joins the surplus workers after their current task.
  void set_workers(std::size_t n);
  std::size_t workers() const;

 private:
  struct Task {
    std::function<void()> work, done;
  };
  void loop(std::size_t index);

  mutable std::mutex mu_;
  std::condition_variable cv_;  // lint:client-runtime
  std::deque<Task> q_;
  std::size_t target_ = 0;
  bool stop_ = false;
  std::mutex resize_mu_;  // serialises set_workers / destructor
  std::vector<std::thread> threads_;  // lint:client-runtime
};

}  // namespace miracache
