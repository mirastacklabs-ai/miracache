// SPDX-License-Identifier: Apache-2.0
// Production Executor for the single-threaded store (A1.4 S7). `work` runs on a small worker
// pool; `done` is queued and runs ONLY inside drain_done(), which the store thread calls from
// its event loop. This is the stronger guarantee core/util/executor.h asks for: `done` always
// runs on the store thread, after `work` (the queue mutex gives the happens-before edge).
// Threads are allowed here only (lint marker `// lint:server-runtime`, like client/runtime/).
#pragma once

#include <condition_variable>  // lint:server-runtime
#include <cstddef>
#include <deque>
#include <functional>
#include <mutex>
#include <thread>
#include <vector>

#include "util/executor.h"

namespace miracache::server {

class StoreExecutor final : public Executor {
 public:
  explicit StoreExecutor(std::size_t workers = 2);
  ~StoreExecutor() override;
  StoreExecutor(const StoreExecutor&) = delete;
  StoreExecutor& operator=(const StoreExecutor&) = delete;

  // Any thread. Never runs a callback inline.
  void post(std::function<void()> work, std::function<void()> done) override;
  // Store thread only: runs the `done` callbacks of finished work, returns how many ran.
  // Callbacks may post() more work.
  std::size_t drain_done();
  // Work posted whose `done` has not run yet (queued + running + awaiting drain).
  std::size_t outstanding() const;
  // Optional: called (from a worker) after a `done` was queued, to wake the store loop.
  void set_wakeup(std::function<void()> fn);
  // Stops the workers after finishing queued work. Pending `done`s remain for drain_done().
  void stop();

 private:
  struct Job {
    std::function<void()> work, done;
  };
  void run();

  mutable std::mutex mu_;
  std::condition_variable cv_;  // lint:server-runtime
  std::deque<Job> jobs_;
  std::deque<std::function<void()>> finished_;
  std::size_t outstanding_ = 0;
  bool stopping_ = false;
  std::function<void()> wakeup_;
  std::vector<std::thread> workers_;  // lint:server-runtime
};

}  // namespace miracache::server
