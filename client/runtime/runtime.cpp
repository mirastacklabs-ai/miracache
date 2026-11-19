// SPDX-License-Identifier: Apache-2.0
#include "runtime/runtime.h"

#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <utility>

namespace miracache {

const char* to_string(KeyStatus s) noexcept {
  switch (s) {
    case KeyStatus::Hit: return "hit";
    case KeyStatus::Miss: return "miss";
    case KeyStatus::Committed: return "committed";
    case KeyStatus::Skipped: return "skipped";
    case KeyStatus::Refused: return "refused";
    case KeyStatus::Aborted: return "aborted";
    case KeyStatus::Timeout: return "timeout";
  }
  return "?";
}

struct Runtime::Slot final : JobControl {
  Runtime* rt = nullptr;
  Ticket ticket;
  Job job;
  std::atomic<bool> cancel_flag{false};
  std::atomic<bool> shutdown_flag{false};
  bool aborted = false;  // guarded by Runtime::mu_: report ABORTED whatever the backend said
  bool cancelled() const noexcept override {
    return cancel_flag.load(std::memory_order_acquire) ||
           shutdown_flag.load(std::memory_order_acquire);
  }
  bool wait_cancel_for(std::chrono::microseconds d) const noexcept override {
    std::unique_lock lk(rt->mu_);
    rt->ctl_cv_.wait_for(lk, d, [this] { return cancelled(); });
    return cancelled();
  }
};

Runtime::Runtime(Backend& backend, RuntimeOptions opts) : backend_(backend), lane_cap_(opts.lane_cap) {
  efd_ = ::eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
  const unsigned n = std::max(1u, opts.workers);
  workers_.reserve(n);
  for (unsigned i = 0; i < n; ++i) {
    workers_.emplace_back([this] { worker_loop(); });  // lint:client-runtime
  }
}

Runtime::~Runtime() {
  shutdown();
  if (efd_ >= 0) ::close(efd_);
}

// Caller holds mu_. Signals the eventfd on the empty -> non-empty transition.
void Runtime::push_completion_locked(Ticket t, std::vector<KeyStatus> st) noexcept {
  const bool was_empty = done_.empty();
  done_.push_back(Completion{t, std::move(st)});
  if (was_empty) {
    const std::uint64_t one = 1;
    [[maybe_unused]] auto r = ::write(efd_, &one, sizeof one);
  }
}

Ticket Runtime::submit(Job job) noexcept {
  std::lock_guard lk(mu_);
  const Ticket t{next_id_++};
  if (stopping_) {
    backend_.discarded(t, job);
    push_completion_locked(t, std::vector<KeyStatus>(job.keys.size(), KeyStatus::Aborted));
    return t;
  }
  auto slot = std::make_shared<Slot>();
  slot->rt = this;
  slot->ticket = t;
  slot->job = std::move(job);
  live_.emplace(t.id, slot);
  queue_.push_back(std::move(slot));
  work_cv_.notify_one();
  return t;
}

std::size_t Runtime::poll(std::span<Completion> out) noexcept {
  std::lock_guard lk(mu_);
  std::size_t n = 0;
  while (n < out.size() && !done_.empty()) {
    out[n++] = std::move(done_.front());
    done_.pop_front();
  }
  if (n > 0 && done_.empty()) {
    std::uint64_t v;
    [[maybe_unused]] auto r = ::read(efd_, &v, sizeof v);
  }
  return n;
}

void Runtime::cancel(Ticket t) noexcept {
  std::lock_guard lk(mu_);
  auto it = live_.find(t.id);
  if (it == live_.end()) return;
  it->second->cancel_flag.store(true, std::memory_order_release);
  ctl_cv_.notify_all();
  if (lane_cap_ > 0) work_cv_.notify_all();  // a cancelled job queued behind a full lane is runnable now (discarded)
}

std::deque<std::shared_ptr<Runtime::Slot>>::iterator Runtime::runnable_locked() noexcept {
  if (lane_cap_ == 0) return queue_.begin();
  for (auto it = queue_.begin(); it != queue_.end(); ++it) {
    const Slot& s = **it;
    if (s.job.lane == kNoLane || s.cancelled()) return it;
    auto r = lane_running_.find(s.job.lane);
    if (r == lane_running_.end() || r->second < lane_cap_) return it;
  }
  return queue_.end();
}

void Runtime::worker_loop() noexcept {
  std::unique_lock lk(mu_);
  for (;;) {
    // At shutdown every live slot is cancelled (shutdown_flag), so anything queued is runnable and is drained.
    work_cv_.wait(lk, [this] { return (stopping_ && queue_.empty()) || runnable_locked() != queue_.end(); });
    if (queue_.empty()) return;  // stopping_ and nothing left to drain
    auto pick = runnable_locked();
    auto slot = std::move(*pick);
    queue_.erase(pick);
    std::vector<KeyStatus> st(slot->job.keys.size(), KeyStatus::Aborted);
    if (!slot->cancelled()) {
      const bool laned = lane_cap_ > 0 && slot->job.lane != kNoLane;
      if (laned) ++lane_running_[slot->job.lane];
      lk.unlock();
      backend_.run(slot->ticket, slot->job, *slot, st);
      lk.lock();
      if (laned) {
        auto r = lane_running_.find(slot->job.lane);
        if (r != lane_running_.end() && --r->second == 0) lane_running_.erase(r);
        work_cv_.notify_all();  // a job waiting for this lane may run now
      }
      st.resize(slot->job.keys.size(), KeyStatus::Aborted);
    } else {
      backend_.discarded(slot->ticket, slot->job);
    }
    if (slot->aborted) std::fill(st.begin(), st.end(), KeyStatus::Aborted);
    live_.erase(slot->ticket.id);
    push_completion_locked(slot->ticket, std::move(st));
  }
}

void Runtime::shutdown() noexcept {
  std::vector<std::thread> ws;  // lint:client-runtime
  {
    std::lock_guard lk(mu_);
    stopping_ = true;
    for (auto& entry : live_) {
      entry.second->aborted = true;
      entry.second->shutdown_flag.store(true, std::memory_order_release);
    }
    ws.swap(workers_);
    work_cv_.notify_all();
    ctl_cv_.notify_all();
  }
  // Workers drain the queue (cancelled jobs skip the backend), then exit.
  for (auto& w : ws) {
    if (w.joinable()) w.join();
  }
}

}  // namespace miracache
