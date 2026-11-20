// SPDX-License-Identifier: Apache-2.0
// StoreExecutor contract: `work` on pool threads, `done` only inside drain_done() on the
// calling (store) thread, always after its own `work`. Run under tsan (preset tsan).
#include <algorithm>
#include <atomic>
#include <chrono>
#include <set>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "server/runtime/store_executor.h"
#include "server/runtime/wake_fd.h"

namespace miracache::server {
namespace {

TEST(StoreExecutor, DoneAlwaysOnStoreThreadAfterWork) {
  StoreExecutor ex(4);
  const auto store_thread = std::this_thread::get_id();
  constexpr int kJobs = 2000;
  std::vector<int> slot(kJobs, 0);  // plain ints: work writes, done reads (tsan checks the edge)
  std::vector<std::thread::id> worker_ids(kJobs);
  int done_count = 0;
  bool wrong_thread = false, before_work = false;
  for (int i = 0; i < kJobs; ++i) {
    ex.post(
        [&, i] {
          worker_ids[i] = std::this_thread::get_id();
          slot[i] = i + 1;
        },
        [&, i] {
          if (std::this_thread::get_id() != store_thread) wrong_thread = true;
          if (slot[i] != i + 1) before_work = true;
          ++done_count;  // unsynchronised on purpose: only the store thread touches it
        });
    if (i % 64 == 0) ex.drain_done();  // interleave posting and draining
  }
  while (ex.outstanding() != 0) {
    ex.drain_done();
    std::this_thread::yield();
  }
  EXPECT_EQ(done_count, kJobs);
  EXPECT_FALSE(wrong_thread);
  EXPECT_FALSE(before_work);
  std::set<std::thread::id> ws(worker_ids.begin(), worker_ids.end());
  EXPECT_FALSE(ws.count(store_thread));  // work never ran on the store thread
}

TEST(StoreExecutor, DoneNeverRunsInsidePost) {
  StoreExecutor ex(1);
  bool ran = false;
  ex.post([] {}, [&] { ran = true; });
  EXPECT_FALSE(ran);  // not inline, not until drain_done
  while (ex.outstanding() != 0) ex.drain_done();
  EXPECT_TRUE(ran);
}

TEST(StoreExecutor, DoneMayPostMoreWork) {
  StoreExecutor ex(2);
  int chain = 0;
  std::function<void()> step = [&] {
    if (++chain < 50) ex.post([] {}, step);
  };
  ex.post([] {}, step);
  while (ex.outstanding() != 0) ex.drain_done();
  EXPECT_EQ(chain, 50);
}

TEST(StoreExecutor, StopFinishesQueuedWork) {
  StoreExecutor ex(2);
  std::atomic<int> worked{0};
  int done = 0;
  for (int i = 0; i < 100; ++i) ex.post([&] { ++worked; }, [&] { ++done; });
  ex.stop();
  ex.drain_done();
  EXPECT_EQ(worked.load(), 100);
  EXPECT_EQ(done, 100);
}

// A `done` queued by a worker wakes a loop that sleeps in poll() on the WakeFd: it is processed within
// milliseconds, far below the 5 s poll timeout (this is what replaced the 1 ms poll in mira-memnode).
TEST(StoreExecutor, DoneWakesTheLoopWithoutWaitingForTheTimeout) {
  StoreExecutor ex(2);
  WakeFd wake;
  ASSERT_TRUE(wake.ok());
  ex.set_wakeup([&wake] { wake.signal(); });
  using clk = std::chrono::steady_clock;
  std::int64_t worst_us = 0;
  for (int i = 0; i < 20; ++i) {
    wake.clear();
    ASSERT_EQ(ex.drain_done(), 0u);
    bool ran = false;
    const auto t0 = clk::now();
    ex.post([] {}, [&] { ran = true; });
    // Loop shape from main.cpp: wait (long timeout), then clear, then drain.
    EXPECT_EQ(wake.wait(-1, 5000), 1);
    wake.clear();
    EXPECT_EQ(ex.drain_done(), 1u);
    EXPECT_TRUE(ran);
    worst_us = std::max<std::int64_t>(worst_us, std::chrono::duration_cast<std::chrono::microseconds>(clk::now() - t0).count());
  }
  EXPECT_LT(worst_us, 500'000) << "worst wake latency us";  // generous for a loaded box; the point is "not 5 s"
  ex.stop();
}

// No lost wakeup: a signal between clear() and poll() makes poll return at once.
TEST(StoreExecutor, SignalAfterClearIsNotLost) {
  WakeFd wake;
  wake.clear();
  wake.signal();
  EXPECT_EQ(wake.wait(-1, 5000), 1);
  wake.clear();
  EXPECT_EQ(wake.wait(-1, 20), 0);  // cleared: times out
}

}  // namespace
}  // namespace miracache::server
