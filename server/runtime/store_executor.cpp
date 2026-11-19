// SPDX-License-Identifier: Apache-2.0
#include "server/runtime/store_executor.h"

namespace miracache::server {

StoreExecutor::StoreExecutor(std::size_t workers) {
  if (workers == 0) workers = 1;
  for (std::size_t i = 0; i < workers; ++i) workers_.emplace_back([this] { run(); });  // lint:server-runtime
}

StoreExecutor::~StoreExecutor() { stop(); }

void StoreExecutor::stop() {
  {
    std::lock_guard<std::mutex> lk(mu_);
    stopping_ = true;
  }
  cv_.notify_all();
  for (auto& t : workers_)
    if (t.joinable()) t.join();
  workers_.clear();
}

void StoreExecutor::post(std::function<void()> work, std::function<void()> done) {
  {
    std::lock_guard<std::mutex> lk(mu_);
    jobs_.push_back(Job{std::move(work), std::move(done)});
    ++outstanding_;
  }
  cv_.notify_one();
}

void StoreExecutor::run() {
  for (;;) {
    Job j;
    {
      std::unique_lock<std::mutex> lk(mu_);
      cv_.wait(lk, [this] { return stopping_ || !jobs_.empty(); });
      if (jobs_.empty()) return;  // stopping and drained
      j = std::move(jobs_.front());
      jobs_.pop_front();
    }
    j.work();
    std::function<void()> wake;
    {
      std::lock_guard<std::mutex> lk(mu_);
      finished_.push_back(std::move(j.done));
      wake = wakeup_;
    }
    if (wake) wake();
  }
}

std::size_t StoreExecutor::drain_done() {
  std::size_t n = 0;
  for (;;) {
    std::function<void()> d;
    {
      std::lock_guard<std::mutex> lk(mu_);
      if (finished_.empty()) return n;
      d = std::move(finished_.front());
      finished_.pop_front();
    }
    if (d) d();  // outside the lock: callbacks may post()
    {
      std::lock_guard<std::mutex> lk(mu_);
      --outstanding_;
    }
    ++n;
  }
}

std::size_t StoreExecutor::outstanding() const {
  std::lock_guard<std::mutex> lk(mu_);
  return outstanding_;
}

void StoreExecutor::set_wakeup(std::function<void()> fn) {
  std::lock_guard<std::mutex> lk(mu_);
  wakeup_ = std::move(fn);
}

}  // namespace miracache::server
