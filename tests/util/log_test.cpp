// SPDX-License-Identifier: Apache-2.0
#include <gtest/gtest.h>
#include <unistd.h>

#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "util/log.h"
#include "util/log_limiter.h"

using namespace miracache;

namespace {
// Collects what log::write sends to fd 2 replacement: a pipe read to the end.
struct Capture {
  int fds[2];
  Capture() {
    EXPECT_EQ(::pipe(fds), 0);
    log::set_sink_fd(fds[1]);
  }
  std::string finish() {
    log::set_sink_fd(2);
    ::close(fds[1]);
    std::string out;
    char buf[4096];
    for (ssize_t n; (n = ::read(fds[0], buf, sizeof buf)) > 0;) out.append(buf, static_cast<std::size_t>(n));
    ::close(fds[0]);
    return out;
  }
};
}  // namespace

TEST(Log, LineHasIdentityFieldsInOrder) {
  log::set_identity({7, "hostA", "10.0.0.10:7471"});
  const std::string l = log::format_line(1700000000123456789LL, log::Level::Info, "memnode", "listening",
                                         {{"port", "9464"}});
  EXPECT_EQ(l,
            "ts=2023-11-14T22:13:20.123Z level=info comp=memnode node_id=7 host=hostA addr=10.0.0.10:7471 "
            "msg=\"listening\" port=9464\n");
}

TEST(Log, UnsetNodeIdAndAddrAreLeftOut) {
  log::set_identity({0, "h", ""});
  const std::string l = log::format_line(0, log::Level::Warn, "c", "m");
  EXPECT_EQ(l, "ts=1970-01-01T00:00:00.000Z level=warn comp=c host=h msg=\"m\"\n");
}

TEST(Log, QuotesAndEscapes) {
  log::set_identity({1, "h", ""});
  const std::string l = log::format_line(0, log::Level::Error, "c", "say \"hi\"\nnow",
                                         {{"a", "x y"}, {"b", ""}, {"c", "k=v"}, {"d", "plain"}, {"e", "back\\slash"}});
  EXPECT_NE(l.find("msg=\"say \\\"hi\\\"\\nnow\""), std::string::npos) << l;
  EXPECT_NE(l.find(" a=\"x y\""), std::string::npos) << l;
  EXPECT_NE(l.find(" b=\"\""), std::string::npos) << l;
  EXPECT_NE(l.find(" c=\"k=v\""), std::string::npos) << l;
  EXPECT_NE(l.find(" d=plain"), std::string::npos) << l;
  EXPECT_NE(l.find(" e=\"back\\\\slash\""), std::string::npos) << l;
  EXPECT_EQ(l.find('\n'), l.size() - 1) << "exactly one newline, at the end";
}

TEST(Log, ConcurrentLinesStayWhole) {
  log::set_identity({3, "h", "a:1"});
  Capture cap;
  constexpr int kThreads = 8, kLines = 200;
  std::vector<std::thread> ts;
  // The pipe buffer is 64 KiB: read concurrently so the writers never block on a full pipe.
  std::string out;
  std::thread reader([&] {
    char buf[4096];
    for (ssize_t n; (n = ::read(cap.fds[0], buf, sizeof buf)) > 0;) out.append(buf, static_cast<std::size_t>(n));
  });
  for (int t = 0; t < kThreads; ++t)
    ts.emplace_back([t] {
      for (int i = 0; i < kLines; ++i)
        log::write(log::Level::Info, "test", "line", {{"t", std::to_string(t)}, {"i", std::to_string(i)}});
    });
  for (auto& th : ts) th.join();
  log::set_sink_fd(2);
  ::close(cap.fds[1]);
  reader.join();
  ::close(cap.fds[0]);
  std::istringstream in(out);
  std::string line;
  std::set<std::string> seen;
  while (std::getline(in, line)) {
    EXPECT_EQ(line.rfind("ts=", 0), 0u) << line;
    EXPECT_NE(line.find(" node_id=3 host=h addr=a:1 msg=\"line\" t="), std::string::npos) << line;
    seen.insert(line.substr(line.find(" t=")));
  }
  EXPECT_EQ(seen.size(), static_cast<std::size_t>(kThreads * kLines));
}

TEST(Log, WritefFormats) {
  log::set_identity({1, "h", ""});
  Capture cap;
  log::writef(log::Level::Info, "c", "n=%d s=%s", 5, "x");
  const std::string out = cap.finish();
  EXPECT_NE(out.find("msg=\"n=5 s=x\"\n"), std::string::npos) << out;
}

// Review s9 K04/K10: the first event of a key passes, then one per interval per key, carrying the count dropped since;
// keys are bounded (further keys share one overflow slot while every tracked slot is live).
TEST(LogLimiter, FirstPassesThenOnePerIntervalWithTheDroppedCount) {
  using std::chrono::seconds;
  LogLimiter l(seconds(60), 2);
  ASSERT_TRUE(l.admit("a", seconds(0)).has_value());
  EXPECT_EQ(*l.admit("b", seconds(1)), 0u);  // another key: its own first line
  EXPECT_FALSE(l.admit("a", seconds(10)).has_value());
  // Two keys are tracked and both are inside their interval: "c" and "d" share the overflow slot.
  EXPECT_TRUE(l.admit("c", seconds(20)).has_value());
  EXPECT_FALSE(l.admit("d", seconds(21)).has_value());
  EXPECT_EQ(l.keys(), 3u);
  EXPECT_FALSE(l.admit("a", seconds(59)).has_value());
  auto again = l.admit("a", seconds(60));
  ASSERT_TRUE(again.has_value());
  EXPECT_EQ(*again, 2u);
  EXPECT_FALSE(l.admit("a", seconds(61)).has_value());
}

// L09 (review s9b): a full table evicts stale slots for a new key instead of sending it to the overflow slot forever.
// Stale: interval over with nothing dropped (lossless), or idle one more interval with drops pending. A key with drops
// inside that extra interval keeps its slot and its count. Time is the caller's (no clock read).
TEST(LogLimiter, FullTableEvictsStaleSlotsForNewKeys) {
  using std::chrono::seconds;
  LogLimiter l(seconds(60), 2);
  ASSERT_TRUE(l.admit("p1", seconds(0)).has_value());
  ASSERT_TRUE(l.admit("p2", seconds(0)).has_value());
  EXPECT_FALSE(l.admit("p2", seconds(5)).has_value());  // p2 holds one dropped event
  // At 70 s p1 is stale (interval over, nothing pending); p2 is not (its drop is kept until 120 s).
  auto p3 = l.admit("p3", seconds(70));
  ASSERT_TRUE(p3.has_value());
  EXPECT_EQ(*p3, 0u);
  EXPECT_EQ(l.keys(), 2u) << "p3 took p1's slot, no overflow slot";
  EXPECT_FALSE(l.admit("p3", seconds(71)).has_value()) << "p3 has its own slot and interval";
  // p4 at 80 s: p2 (pending until 120 s) and p3 (until 190 s) are live: overflow.
  ASSERT_TRUE(l.admit("p4", seconds(80)).has_value());
  EXPECT_EQ(l.keys(), 3u);
  // p2 comes back inside its extra interval: it still has its slot and reports its dropped event.
  auto p2 = l.admit("p2", seconds(90));
  ASSERT_TRUE(p2.has_value());
  EXPECT_EQ(*p2, 1u);
  // At 200 s every slot is stale: a new key gets its own slot (the old overflow slot went too).
  auto p5 = l.admit("p5", seconds(200));
  ASSERT_TRUE(p5.has_value());
  EXPECT_EQ(*p5, 0u);
  // R11 (review s11): p3's pending dropped event (71 s) was not forgotten: it moved to a new overflow slot.
  EXPECT_EQ(l.keys(), 2u) << "p5 and the overflow slot holding p3's dropped event";
  EXPECT_EQ(*l.admit("p6", seconds(201)), 0u) << "the overflow slot does not take p6's place";
  auto ov = l.admit("p7", seconds(202));  // the table is full again: p7 shares the overflow slot, whose line carries it
  ASSERT_TRUE(ov.has_value());
  EXPECT_EQ(*ov, 1u) << "the evicted slot's dropped event is reported, not lost";
  EXPECT_EQ(l.keys(), 3u);
  // A flood of distinct keys stays bounded.
  for (int k = 0; k < 1000; ++k) (void)l.admit("flood" + std::to_string(k), seconds(201));
  EXPECT_LE(l.keys(), 3u);
}
