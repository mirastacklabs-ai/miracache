// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>

#include <atomic>

#include "runtime/thread_pool_executor.h"

namespace miracache {
namespace {

TEST(ThreadPoolExecutor, RunsWorkThenDone) {
  std::atomic<int> work{0}, done{0};
  {
    ThreadPoolExecutor ex(3);
    for (int i = 0; i < 500; ++i) {
      ex.post([&] { work.fetch_add(1); }, [&] {
        EXPECT_GT(work.load(), 0);
        done.fetch_add(1);
      });
    }
  }  // destructor drains the queue
  EXPECT_EQ(work.load(), 500);
  EXPECT_EQ(done.load(), 500);
}

TEST(ThreadPoolExecutor, SetWorkersWhilePosting) {
  std::atomic<int> n{0};
  ThreadPoolExecutor ex(2);
  EXPECT_EQ(ex.workers(), 2u);
  for (int round = 0; round < 6; ++round) {
    for (int i = 0; i < 100; ++i) ex.post([&] { n.fetch_add(1); }, nullptr);
    ex.set_workers(round % 2 == 0 ? 6 : 1);
    EXPECT_EQ(ex.workers(), round % 2 == 0 ? 6u : 1u);
  }
  ex.set_workers(0);  // clamped to 1
  EXPECT_EQ(ex.workers(), 1u);
  std::atomic<bool> last{false};
  ex.post([] {}, [&] { last = true; });
  while (!last.load()) std::this_thread::yield();
  // Queue is FIFO and drained by the surviving worker(s); wait for everything.
  while (n.load() != 600) std::this_thread::yield();
  EXPECT_EQ(n.load(), 600);
}

}  // namespace
}  // namespace miracache
