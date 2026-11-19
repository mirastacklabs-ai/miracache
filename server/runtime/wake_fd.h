// SPDX-License-Identifier: Apache-2.0
// An eventfd the store loop polls next to the fabric fd. Worker threads (StoreExecutor `done`
// queued) and the signal handler call signal(); the loop calls clear() BEFORE it drains.
//
// No lost wakeup, in the order the loop uses:
//   1. clear()            -- consume any earlier signal
//   2. drain_done() ...   -- everything queued before step 1's clear is handled now
//   3. arm CQ, re-poll    -- (fabric side, see main.cpp)
//   4. poll({fabric, wake}, timeout)
// A worker does "push done; signal()". If the push happened before step 2 the drain sees it. If
// it happens after step 2, its signal() happens after step 1's clear(), so the counter is non-zero
// and level-triggered poll() in step 4 returns at once. The only cost of the reverse interleaving
// (push before the drain, signal after the clear) is one spurious wakeup. signal() is
// async-signal-safe (a write(2)).
#pragma once

#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <cstdint>
#include <vector>

namespace miracache::server {

class WakeFd {
 public:
  WakeFd() : fd_(::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC)) {}
  ~WakeFd() {
    if (fd_ >= 0) ::close(fd_);
  }
  WakeFd(const WakeFd&) = delete;
  WakeFd& operator=(const WakeFd&) = delete;

  bool ok() const { return fd_ >= 0; }
  int fd() const { return fd_; }
  void signal() const {
    const std::uint64_t one = 1;
    [[maybe_unused]] auto r = ::write(fd_, &one, sizeof one);  // a full counter (EAGAIN) is already "signalled"
  }
  void clear() const {
    std::uint64_t v;
    [[maybe_unused]] auto r = ::read(fd_, &v, sizeof v);  // EAGAIN when not signalled
  }

  // Waits up to timeout_ms for the fabric fd (may be < 0) or this eventfd. Returns the poll result.
  int wait(int fabric_fd, int timeout_ms) const {
    ::pollfd p[2] = {{fd_, POLLIN, 0}, {fabric_fd, POLLIN, 0}};
    return ::poll(p, fabric_fd >= 0 ? 2 : 1, timeout_ms);
  }

  // RL1: several fabrics (one per device): waits on the eventfd and every fabric fd >= 0 (at most 7 of them).
  int wait(const std::vector<int>& fabric_fds, int timeout_ms) const {
    ::pollfd p[8] = {{fd_, POLLIN, 0}};
    nfds_t n = 1;
    for (int f : fabric_fds)
      if (f >= 0 && n < 8) p[n++] = {f, POLLIN, 0};
    return ::poll(p, n, timeout_ms);
  }

 private:
  int fd_;
};

}  // namespace miracache::server
