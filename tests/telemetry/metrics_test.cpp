// SPDX-License-Identifier: Apache-2.0
// Metrics library (A3.5 M1): golden exposition text, histogram bucket edges, exact totals under
// concurrency (run under tsan in CI).
#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "telemetry/metrics.h"

namespace miracache::telemetry {
namespace {

TEST(Metrics, GoldenExposition) {
  Registry r;
  r.counter("t_requests_total", "Requests.", {{"op", "get"}}).inc(3);
  r.counter("t_requests_total", "Requests.", {{"op", "put"}}).inc(5);
  r.gauge("t_conn", "Connections.").set(-2);
  r.callback_gauge("t_cb", "Callback \\ value\nline", {}, [] { return std::int64_t{7}; });
  auto& h = r.histogram("t_seconds", "Latency.", {{"kind", "a\"b"}});
  h.observe_ns(500);         // le 1e-06
  h.observe_ns(1500);        // le 2e-06
  h.observe_ns(9000000000);  // +Inf (> 8.388608 s)
  r.gauge("t_info", "Info.", {{"version", "0.0.1"}, {"git_sha", "abc"}}).set(1);

  const std::string want =
      "# HELP t_requests_total Requests.\n"
      "# TYPE t_requests_total counter\n"
      "t_requests_total{op=\"get\"} 3\n"
      "t_requests_total{op=\"put\"} 5\n"
      "# HELP t_conn Connections.\n"
      "# TYPE t_conn gauge\n"
      "t_conn -2\n"
      "# HELP t_cb Callback \\\\ value\\nline\n"
      "# TYPE t_cb gauge\n"
      "t_cb 7\n"
      "# HELP t_seconds Latency.\n"
      "# TYPE t_seconds histogram\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"1e-06\"} 1\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"2e-06\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"4e-06\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"8e-06\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"1.6e-05\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"3.2e-05\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"6.4e-05\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.000128\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.000256\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.000512\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.001024\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.002048\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.004096\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.008192\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.016384\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.032768\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.065536\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.131072\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.262144\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"0.524288\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"1.048576\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"2.097152\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"4.194304\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"8.388608\"} 2\n"
      "t_seconds_bucket{kind=\"a\\\"b\",le=\"+Inf\"} 3\n"
      "t_seconds_sum{kind=\"a\\\"b\"} 9.000002\n"
      "t_seconds_count{kind=\"a\\\"b\"} 3\n"
      "# HELP t_info Info.\n"
      "# TYPE t_info gauge\n"
      "t_info{version=\"0.0.1\",git_sha=\"abc\"} 1\n";
  std::string got;
  r.write_prometheus(got);
  EXPECT_EQ(got, want);
  std::string again;  // deterministic
  r.write_prometheus(again);
  EXPECT_EQ(again, got);
}

TEST(Metrics, DuplicateRegistrationReturnsSameChild) {
  Registry r;
  auto& a = r.counter("t_x_total", "X.", {{"k", "v"}});
  auto& b = r.counter("t_x_total", "X.", {{"k", "v"}});
  EXPECT_EQ(&a, &b);
  EXPECT_EQ(r.n_families(), 1u);
}

// H08: a hidden child leaves the exposition but stays valid; registering its labels again brings it back.
TEST(Metrics, HiddenChildIsNotExportedAndComesBackWhenRegisteredAgain) {
  Registry r;
  auto& old_g = r.gauge("t_state", "S.", {{"node_id", "unknown"}});
  auto& new_g = r.gauge("t_state", "S.", {{"node_id", "7"}});
  auto& old_c = r.counter("t_trips_total", "T.", {{"node_id", "unknown"}});
  old_g.set(3);
  new_g.set(2);
  old_c.inc();
  r.hide(&old_g);
  r.hide(&old_c);
  r.hide(static_cast<const Gauge*>(nullptr));
  std::string out;
  r.write_prometheus(out);
  EXPECT_EQ(out.find("node_id=\"unknown\""), std::string::npos) << out;
  EXPECT_NE(out.find("t_state{node_id=\"7\"} 2"), std::string::npos) << out;
  old_g.set(5);  // still a live object
  old_c.inc();
  EXPECT_EQ(&r.gauge("t_state", "S.", {{"node_id", "unknown"}}), &old_g);
  out.clear();
  r.write_prometheus(out);
  EXPECT_NE(out.find("t_state{node_id=\"unknown\"} 5"), std::string::npos) << out;
  EXPECT_EQ(out.find("t_trips_total{node_id=\"unknown\"}"), std::string::npos) << "only the re-registered child is back";
}

TEST(Metrics, HistogramBucketEdges) {
  EXPECT_EQ(Histogram::bucket_of(0), 0u);
  EXPECT_EQ(Histogram::bucket_of(1), 0u);
  for (std::size_t k = 0; k < Histogram::kFinite; ++k) {
    const std::uint64_t edge = Histogram::edge_ns(k);
    EXPECT_EQ(Histogram::bucket_of(edge), k) << "k=" << k;  // le is inclusive
    EXPECT_EQ(Histogram::bucket_of(edge + 1), k + 1) << "k=" << k;
    if (k > 0) EXPECT_EQ(Histogram::bucket_of(edge - 1), k) << "k=" << k;
  }
  EXPECT_EQ(Histogram::edge_ns(0), 1000u);
  EXPECT_EQ(Histogram::edge_ns(23), 8388608000u);
  EXPECT_EQ(Histogram::bucket_of(~std::uint64_t{0}), Histogram::kFinite);  // +Inf
}

TEST(Metrics, ConcurrentExactTotals) {
  Registry r;
  auto& c = r.counter("t_c_total", "C.");
  auto& g = r.gauge("t_g", "G.");
  auto& h = r.histogram("t_h_seconds", "H.");
  constexpr int kThreads = 8;
  constexpr int kAdds = 50000;
  std::vector<std::thread> ts;
  for (int t = 0; t < kThreads; ++t)
    ts.emplace_back([&] {
      for (int i = 0; i < kAdds; ++i) {
        c.inc();
        g.add(2);
        h.observe_ns(static_cast<std::uint64_t>(i % 4) * 1000);  // 0, 1000, 2000, 3000 ns
      }
    });
  std::string scraped;
  for (int i = 0; i < 20; ++i) {  // scrape while writers run (tsan: no race)
    scraped.clear();
    r.write_prometheus(scraped);
  }
  for (auto& t : ts) t.join();
  const std::uint64_t n = std::uint64_t{kThreads} * kAdds;
  EXPECT_EQ(c.value(), n);
  EXPECT_EQ(g.value(), static_cast<std::int64_t>(2 * n));
  EXPECT_EQ(h.count(), n);
  EXPECT_EQ(h.sum_ns(), n / 4 * (0 + 1000 + 2000 + 3000));
  EXPECT_EQ(h.bucket(0), n / 2);  // 0 and 1000 ns
  EXPECT_EQ(h.bucket(1), n / 4);  // 2000 ns
  EXPECT_EQ(h.bucket(2), n / 4);  // 3000 ns
}

TEST(Metrics, ConstLabelsComeFirstOnEverySeries) {
  Registry r;
  r.counter("c_total", "C.").inc(2);                             // registered before the const labels
  r.set_const_labels({{"node_id", "7"}});
  r.gauge("g", "G.", {{"state", "a"}}).set(3);
  r.histogram("h_seconds", "H.").observe_ns(1000);
  std::string got;
  r.write_prometheus(got);
  EXPECT_NE(got.find("c_total{node_id=\"7\"} 2\n"), std::string::npos) << got;
  EXPECT_NE(got.find("g{node_id=\"7\",state=\"a\"} 3\n"), std::string::npos) << got;
  EXPECT_NE(got.find("h_seconds_bucket{node_id=\"7\",le=\"1e-06\"} 1\n"), std::string::npos) << got;
  EXPECT_NE(got.find("h_seconds_sum{node_id=\"7\"} "), std::string::npos) << got;
  EXPECT_NE(got.find("h_seconds_count{node_id=\"7\"} 1\n"), std::string::npos) << got;
}

}  // namespace
}  // namespace miracache::telemetry
