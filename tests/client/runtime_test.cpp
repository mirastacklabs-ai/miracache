// SPDX-License-Identifier: Apache-2.0
#include "runtime/runtime.h"

#include <gtest/gtest.h>
#include <poll.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <mutex>
#include <set>
#include <thread>
#include <vector>

namespace miracache {
namespace {

// Even keys HIT, odd keys MISS. Optionally blocks until released; when cancelled it
// "drains" until `drain_released` before returning.
class FakeBackend final : public Backend {
 public:
  void run(Ticket, const Job& job, const JobControl& ctl,
           std::vector<KeyStatus>& st) noexcept override {
    started.fetch_add(1);
    if (gate) {
      std::unique_lock lk(mu);
      // The runtime cannot notify our cv, so poll the control with a short timeout.
      while (!gate_open && !ctl.cancelled()) cv.wait_for(lk, std::chrono::milliseconds(1));
      if (ctl.cancelled()) {
        cv.wait(lk, [&] { return drain_released; });
        for (auto& s : st) s = KeyStatus::Committed;  // runtime must override on shutdown
        return;
      }
    }
    for (std::size_t i = 0; i < job.keys.size(); ++i) {
      st[i] = job.keys[i] % 2 == 0 ? KeyStatus::Hit : KeyStatus::Miss;
    }
  }
  void open_gate() {
    std::lock_guard lk(mu);
    gate_open = true;
    cv.notify_all();
  }
  void release_drain() {
    std::lock_guard lk(mu);
    drain_released = true;
    cv.notify_all();
  }
  bool gate = false;
  std::atomic<int> started{0};
  std::mutex mu;
  std::condition_variable cv;
  bool gate_open = false;
  bool drain_released = false;
};

bool readable(int fd, int timeout_ms) {
  pollfd p{fd, POLLIN, 0};
  return ::poll(&p, 1, timeout_ms) == 1 && (p.revents & POLLIN);
}

// Upper bound on how long any test waits for completions. Deadline-based, not
// iteration-based: under CPU load each poll may return only a few completions.
constexpr auto kCollectTimeout = std::chrono::seconds(10);

// Waits (until kCollectTimeout) for `n` completions.
std::vector<Completion> collect(Runtime& rt, std::size_t n) {
  std::vector<Completion> all;
  const auto deadline = std::chrono::steady_clock::now() + kCollectTimeout;
  while (all.size() < n && std::chrono::steady_clock::now() < deadline) {
    Completion buf[16];
    const std::size_t got = rt.poll(buf);
    for (std::size_t k = 0; k < got; ++k) all.push_back(std::move(buf[k]));
    if (got == 0) readable(rt.eventfd(), 20);
  }
  return all;
}

TEST(Runtime, SubmitPollRoundTrip) {
  FakeBackend be;
  Runtime rt(be);
  const Ticket t = rt.submit(Job{JobKind::Lookup, {0, 1, 2}});
  ASSERT_NE(t.id, 0u);
  auto c = collect(rt, 1);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].ticket, t);
  EXPECT_EQ(c[0].status,
            (std::vector<KeyStatus>{KeyStatus::Hit, KeyStatus::Miss, KeyStatus::Hit}));
  Completion none[1];
  EXPECT_EQ(rt.poll(none), 0u);
}

TEST(Runtime, EventfdReadableWhilePendingAndDrains) {
  FakeBackend be;
  Runtime rt(be);
  EXPECT_FALSE(readable(rt.eventfd(), 0));
  rt.submit(Job{JobKind::Fetch, {2}});
  rt.submit(Job{JobKind::Fetch, {4}});
  ASSERT_TRUE(readable(rt.eventfd(), 2000));
  // Wait until both are queued, then take just one: still readable.
  for (int i = 0; i < 200; ++i) {
    be.mu.lock();
    const int s = be.started.load();
    be.mu.unlock();
    if (s == 2) break;
    readable(rt.eventfd(), 10);
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  const auto deadline = std::chrono::steady_clock::now() + kCollectTimeout;
  Completion one[1];
  std::size_t n = 0;
  while (n < 1 && std::chrono::steady_clock::now() < deadline) {
    n = rt.poll(one);
    if (!n) std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  ASSERT_EQ(n, 1u);
  // Second may or may not be done yet; drain everything.
  std::size_t total = 1;
  while (total < 2 && std::chrono::steady_clock::now() < deadline) {
    total += rt.poll(one);
    if (total < 2) std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  ASSERT_EQ(total, 2u);
  EXPECT_FALSE(readable(rt.eventfd(), 0));
}

TEST(Runtime, ConcurrentSubmittersOnePoller) {
  FakeBackend be;
  RuntimeOptions o;
  o.workers = 4;
  Runtime rt(be, o);
  constexpr int kThreads = 8, kPer = 200;
  std::vector<std::vector<Ticket>> tickets(kThreads);
  std::vector<std::thread> subs;
  for (int t = 0; t < kThreads; ++t) {
    subs.emplace_back([&, t] {
      for (int i = 0; i < kPer; ++i) {
        tickets[t].push_back(rt.submit(Job{JobKind::Lookup, {static_cast<std::uint64_t>(i)}}));
      }
    });
  }
  auto got = collect(rt, kThreads * kPer);
  for (auto& s : subs) s.join();
  ASSERT_EQ(got.size(), static_cast<std::size_t>(kThreads * kPer));
  std::set<std::uint64_t> issued, seen;
  for (auto& v : tickets)
    for (auto t : v) EXPECT_TRUE(issued.insert(t.id).second) << "duplicate ticket";
  for (auto& c : got) EXPECT_TRUE(seen.insert(c.ticket.id).second) << "duplicate completion";
  EXPECT_EQ(issued, seen);
}

TEST(Runtime, CancelCompletesOnlyAfterBackendDrained) {
  FakeBackend be;
  be.gate = true;
  Runtime rt(be);
  const Ticket t = rt.submit(Job{JobKind::Fetch, {1, 2}});
  while (be.started.load() == 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  rt.cancel(t);
  EXPECT_FALSE(readable(rt.eventfd(), 100));  // backend is still draining
  Completion buf[1];
  EXPECT_EQ(rt.poll(buf), 0u);
  be.release_drain();
  auto c = collect(rt, 1);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].ticket, t);
  EXPECT_EQ(c[0].status.size(), 2u);
}

TEST(Runtime, ShutdownAbortsInFlightAndQueued) {
  FakeBackend be;
  be.gate = true;
  RuntimeOptions o;
  o.workers = 1;
  Runtime rt(be, o);
  const Ticket running = rt.submit(Job{JobKind::Fetch, {1, 2, 3}});
  const Ticket queued = rt.submit(Job{JobKind::Fetch, {4}});
  while (be.started.load() == 0) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  be.release_drain();
  rt.shutdown();
  auto c = collect(rt, 2);
  ASSERT_EQ(c.size(), 2u);
  for (auto& x : c) {
    ASSERT_TRUE(x.ticket == running || x.ticket == queued);
    EXPECT_EQ(x.status.size(), x.ticket == running ? 3u : 1u);
    for (auto s : x.status) EXPECT_EQ(s, KeyStatus::Aborted);
  }
  // Submit after shutdown completes immediately as ABORTED.
  rt.submit(Job{JobKind::Store, {7}});
  auto late = collect(rt, 1);
  ASSERT_EQ(late.size(), 1u);
  EXPECT_EQ(late[0].status, std::vector<KeyStatus>{KeyStatus::Aborted});
}

TEST(Runtime, ShortSpanReturnsRestLaterInOrder) {
  FakeBackend be;
  RuntimeOptions o;
  o.workers = 1;  // single worker: completion order == submit order
  Runtime rt(be, o);
  std::vector<Ticket> ts;
  for (int i = 0; i < 5; ++i) ts.push_back(rt.submit(Job{JobKind::Lookup, {0}}));
  std::vector<Ticket> order;
  const auto deadline = std::chrono::steady_clock::now() + kCollectTimeout;
  while (order.size() < 5 && std::chrono::steady_clock::now() < deadline) {
    Completion buf[2];
    const std::size_t n = rt.poll(buf);
    EXPECT_LE(n, 2u);
    for (std::size_t i = 0; i < n; ++i) order.push_back(buf[i].ticket);
    if (n == 0) readable(rt.eventfd(), 50);
  }
  EXPECT_EQ(order, ts);
  EXPECT_FALSE(readable(rt.eventfd(), 0));
}

// ---- lanes ----
// Jobs of lane 0 block (a memory node that stopped answering) until the gate opens or they are cancelled; every
// other job runs at once. Counts how many lane-0 jobs ran at the same time.
class LaneBackend final : public Backend {
 public:
  void run(Ticket, const Job& job, const JobControl& ctl, std::vector<KeyStatus>& st) noexcept override {
    if (job.lane == 0) {
      std::unique_lock lk(mu);
      max_lane0 = std::max(max_lane0, ++running_lane0);
      ++started_lane0;
      while (!gate_open && !ctl.cancelled()) cv.wait_for(lk, std::chrono::milliseconds(1));
      --running_lane0;
    }
    for (auto& s : st) s = KeyStatus::Hit;
  }
  void open_gate() {
    std::lock_guard lk(mu);
    gate_open = true;
  }
  int started() {
    std::lock_guard lk(mu);
    return started_lane0;
  }
  std::mutex mu;
  std::condition_variable cv;
  bool gate_open = false;
  int running_lane0 = 0, max_lane0 = 0, started_lane0 = 0;
};

Job lane_job(std::uint32_t lane, std::uint64_t key = 0) {
  Job j{JobKind::Fetch, {key}};
  j.lane = lane;
  return j;
}

void wait_started(LaneBackend& be, int n) {
  const auto until = std::chrono::steady_clock::now() + kCollectTimeout;
  while (be.started() < n && std::chrono::steady_clock::now() < until) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  ASSERT_EQ(be.started(), n);
}

TEST(RuntimeLanes, AStuckLaneHoldsOnlyItsCapAndOtherLanesRunAtOnce) {
  LaneBackend be;
  RuntimeOptions o;
  o.workers = 4;
  o.lane_cap = 2;
  Runtime rt(be, o);
  std::vector<Ticket> stuck;
  for (int i = 0; i < 5; ++i) stuck.push_back(rt.submit(lane_job(0, i)));
  wait_started(be, 2);
  const Ticket other = rt.submit(lane_job(1));
  const Ticket free_job = rt.submit(lane_job(kNoLane));
  auto c = collect(rt, 2);
  ASSERT_EQ(c.size(), 2u) << "jobs of another lane waited behind the stuck one";
  for (auto& x : c) EXPECT_TRUE(x.ticket == other || x.ticket == free_job);
  EXPECT_EQ(be.started(), 2) << "a queued job of the full lane took a worker";
  be.open_gate();
  auto rest = collect(rt, stuck.size());
  ASSERT_EQ(rest.size(), stuck.size());
  for (auto& x : rest) EXPECT_EQ(x.status, std::vector<KeyStatus>{KeyStatus::Hit});
  std::lock_guard lk(be.mu);
  EXPECT_EQ(be.max_lane0, 2) << "lane 0 ran more than its cap at once";
}

// The runtime without lanes (2 workers, no lanes): two stuck jobs take every worker and the healthy job waits. This is the
// stall the lanes remove; if it no longer shows here, the test above has lost its teeth.
TEST(RuntimeLanes, WithoutLanesTwoStuckJobsStarveEveryoneElse) {
  LaneBackend be;
  Runtime rt(be);  // the defaults: 2 workers, lane_cap 0
  rt.submit(lane_job(0, 1));
  rt.submit(lane_job(0, 2));
  wait_started(be, 2);
  rt.submit(lane_job(1));
  EXPECT_FALSE(readable(rt.eventfd(), 100)) << "the healthy job ran although both workers were stuck";
  be.open_gate();
  EXPECT_EQ(collect(rt, 3).size(), 3u);
}

TEST(RuntimeLanes, CancelOfAJobQueuedBehindAFullLaneCompletesAtOnce) {
  LaneBackend be;
  RuntimeOptions o;
  o.workers = 2;
  o.lane_cap = 1;
  Runtime rt(be, o);
  rt.submit(lane_job(0, 1));
  wait_started(be, 1);
  const Ticket queued = rt.submit(lane_job(0, 2));
  EXPECT_FALSE(readable(rt.eventfd(), 50));
  rt.cancel(queued);
  auto c = collect(rt, 1);
  ASSERT_EQ(c.size(), 1u);
  EXPECT_EQ(c[0].ticket, queued);
  EXPECT_EQ(c[0].status, std::vector<KeyStatus>{KeyStatus::Aborted});
  EXPECT_EQ(be.started(), 1);
  be.open_gate();
  EXPECT_EQ(collect(rt, 1).size(), 1u);
}

TEST(RuntimeLanes, ShutdownDrainsAFullLaneWithoutHanging) {
  LaneBackend be;
  RuntimeOptions o;
  o.workers = 2;
  o.lane_cap = 1;
  Runtime rt(be, o);
  for (int i = 0; i < 4; ++i) rt.submit(lane_job(0, i));
  wait_started(be, 1);
  rt.shutdown();  // the running job sees cancelled(); the queued ones are discarded
  auto c = collect(rt, 4);
  ASSERT_EQ(c.size(), 4u);
  for (auto& x : c) EXPECT_EQ(x.status, std::vector<KeyStatus>{KeyStatus::Aborted});
}

}  // namespace
}  // namespace miracache
