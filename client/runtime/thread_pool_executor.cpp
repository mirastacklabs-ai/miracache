// SPDX-License-Identifier: Apache-2.0
#include "runtime/thread_pool_executor.h"

#include <algorithm>
#include <utility>

namespace miracache {

ThreadPoolExecutor::ThreadPoolExecutor(std::size_t workers) { set_workers(workers); }

ThreadPoolExecutor::~ThreadPoolExecutor() {
  std::lock_guard rk(resize_mu_);
  {
    std::lock_guard lk(mu_);
    stop_ = true;
  }
  cv_.notify_all();
  for (auto& t : threads_) t.join();
  threads_.clear();
}

void ThreadPoolExecutor::post(std::function<void()> work, std::function<void()> done) {
  {
    std::lock_guard lk(mu_);
    q_.push_back({std::move(work), std::move(done)});
  }
  cv_.notify_one();
}

std::size_t ThreadPoolExecutor::workers() const {
  std::lock_guard lk(mu_);
  return target_;
}

void ThreadPoolExecutor::set_workers(std::size_t n) {
  n = std::max<std::size_t>(1, n);
  std::lock_guard rk(resize_mu_);
  std::vector<std::thread> surplus;  // lint:client-runtime
  {
    std::lock_guard lk(mu_);
    if (stop_) return;
    target_ = n;
  }
  while (threads_.size() > n) {
    surplus.push_back(std::move(threads_.back()));
    threads_.pop_back();
  }
  cv_.notify_all();  // surplus workers see index >= target_ and exit
  for (auto& t : surplus) t.join();
  while (threads_.size() < n) {
    const std::size_t idx = threads_.size();
    threads_.emplace_back([this, idx] { loop(idx); });  // lint:client-runtime
  }
}

void ThreadPoolExecutor::loop(std::size_t index) {
  std::unique_lock lk(mu_);
  for (;;) {
    cv_.wait(lk, [&] { return stop_ || index >= target_ || !q_.empty(); });
    if (index >= target_) return;
    if (q_.empty()) {
      if (stop_) return;
      continue;
    }
    Task t = std::move(q_.front());
    q_.pop_front();
    lk.unlock();
    t.work();
    if (t.done) t.done();
    lk.lock();
  }
}

}  // namespace miracache
