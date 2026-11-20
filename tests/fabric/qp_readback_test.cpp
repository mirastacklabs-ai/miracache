// SPDX-License-Identifier: Apache-2.0
// B11: QP attribute readback compare/format/once/metrics logic, no hardware.
#include "fabric/verbs_cm/qp_readback.h"

#include <gtest/gtest.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <string>

#include "util/log.h"

namespace miracache::fabric {
namespace {

struct Capture {
  Capture() {
    f = std::tmpfile();
    log::set_sink_fd(fileno(f));
  }
  ~Capture() {
    log::set_sink_fd(2);
    std::fclose(f);
  }
  std::string text() {
    std::fflush(f);
    std::string s;
    std::rewind(f);
    char b[512];
    std::size_t n;
    while ((n = std::fread(b, 1, sizeof b, f)) > 0) s.append(b, n);
    return s;
  }
  std::FILE* f;
};

size_t count(const std::string& s, const std::string& needle) {
  size_t n = 0;
  for (size_t p = s.find(needle); p != std::string::npos; p = s.find(needle, p + 1)) ++n;
  return n;
}

const QpSite kSite{"active", "rxe0", "1", "10.0.0.7"};

TEST(QpReadback, CompareOnlyWhatConfigAskedFor) {
  QpAttrs got{19, 7, 6, 12, 4096};
  EXPECT_TRUE(qp_compare(got, {}).empty());
  EXPECT_TRUE(qp_compare(got, {19, 7, 6}).empty());
  QpExpect want;
  want.ack_timeout_exp = 14;
  want.rnr_retry = 6;
  const auto m = qp_compare(got, want);
  ASSERT_EQ(m.size(), 1u);
  EXPECT_STREQ(m[0].attr, "ack_timeout_exp");
  EXPECT_EQ(m[0].expected, 14u);
  EXPECT_EQ(m[0].actual, 19u);
}

TEST(QpReadback, MtuAndFormat) {
  EXPECT_EQ(qp_mtu_bytes(1), 256u);
  EXPECT_EQ(qp_mtu_bytes(3), 1024u);
  EXPECT_EQ(qp_mtu_bytes(5), 4096u);
  EXPECT_EQ(qp_mtu_bytes(0), 0u);
  EXPECT_EQ(qp_mtu_bytes(9), 0u);
  EXPECT_EQ(qp_format({19, 7, 6, 12, 4096}),
            "ack_timeout_exp=19 (2.15s) retry_count=7 rnr_retry=6 min_rnr_timer=12 path_mtu=4096");
  EXPECT_EQ(qp_format({0, 0, 0, 0, 0}).substr(0, 28), "ack_timeout_exp=0 (none) ret");
}

TEST(QpReadback, ClaimOncePerSite) {
  QpReadback r;
  EXPECT_TRUE(r.claim(kSite));
  EXPECT_FALSE(r.claim(kSite));
  QpSite other = kSite;
  other.addr = "10.0.1.7";
  EXPECT_TRUE(r.claim(other));
  other.role = "passive";
  EXPECT_TRUE(r.claim(other));
}

TEST(QpReadback, LogsInfoAndWarnsOnMismatchAndCountsIt) {
  Capture cap;
  telemetry::Registry reg;
  QpReadback r;
  r.set_metrics(&reg, {{"node_id", "7"}, {"hostname", "memA"}});
  QpAttrs got{18, 7, 6, 0, 1024};
  QpExpect want;
  want.ack_timeout_exp = 19;
  want.retry_count = 7;
  r.report(kSite, &got, 0, want);
  const std::string t = cap.text();
  EXPECT_EQ(count(t, "level=info"), 1u);
  EXPECT_EQ(count(t, "level=warn"), 1u);
  EXPECT_NE(t.find("addr=10.0.0.7"), std::string::npos);
  EXPECT_NE(t.find("node_id=7"), std::string::npos);
  EXPECT_NE(t.find("hostname=memA"), std::string::npos);
  EXPECT_NE(t.find("device=rxe0"), std::string::npos);
  EXPECT_NE(t.find("expected=19"), std::string::npos);
  EXPECT_NE(t.find("actual=18"), std::string::npos);
  std::string out;
  reg.write_prometheus(out);
  EXPECT_NE(out.find("miracache_qp_ack_timeout_exp{"), std::string::npos);
  EXPECT_NE(out.find("miracache_qp_path_mtu_bytes{"), std::string::npos);
  EXPECT_NE(out.find("attr=\"ack_timeout_exp\"} 1"), std::string::npos);
  EXPECT_NE(out.find("attr=\"retry_count\"} 0"), std::string::npos);
}

TEST(QpReadback, QueryFailureWarnsOnceAndCounts) {
  Capture cap;
  telemetry::Registry reg;
  QpReadback r;
  r.set_metrics(&reg, {});
  ASSERT_TRUE(r.claim(kSite));
  r.report(kSite, nullptr, EINVAL, {});
  EXPECT_FALSE(r.claim(kSite));  // later QPs of the rail do not retry or re-warn
  const std::string t = cap.text();
  EXPECT_EQ(count(t, "level=warn"), 1u);
  EXPECT_EQ(count(t, "level=info"), 0u);
  std::string out;
  reg.write_prometheus(out);
  EXPECT_NE(out.find("miracache_qp_query_fail_total{"), std::string::npos);
  EXPECT_NE(out.find("} 1"), std::string::npos);
  EXPECT_EQ(out.find("miracache_qp_retry_count"), std::string::npos);
}

TEST(QpReadback, ReportBeforeBindIsPublishedAtBindOnce) {
  Capture cap;
  telemetry::Registry reg;
  QpReadback r;
  QpAttrs got{19, 7, 6, 0, 4096};
  QpExpect want;
  want.retry_count = 3;  // mismatch
  r.report(kSite, &got, 0, want);
  std::string out;
  reg.write_prometheus(out);
  EXPECT_TRUE(out.empty());
  r.set_metrics(&reg, {});
  r.set_metrics(&reg, {});  // rebinding the same registry must not double count
  out.clear();
  reg.write_prometheus(out);
  EXPECT_NE(out.find("attr=\"retry_count\"} 1"), std::string::npos);
  r.set_metrics(nullptr, {});
}

// F3 (K07): claim -> set_metrics -> report. The bind between claim and report must not publish zeros.
TEST(QpReadback, ClaimBindReportPublishesRealValues) {
  Capture cap;
  telemetry::Registry reg;
  QpReadback r;
  ASSERT_TRUE(r.claim(kSite));
  r.set_metrics(&reg, {});
  std::string out;
  reg.write_prometheus(out);
  EXPECT_TRUE(out.empty()) << "a claimed site with no report publishes nothing: " << out;
  QpAttrs got{19, 7, 6, 12, 4096};
  QpExpect want;
  want.retry_count = 3;  // mismatch
  r.report(kSite, &got, 0, want);
  out.clear();
  reg.write_prometheus(out);
  EXPECT_NE(out.find("miracache_qp_retry_count{role=\"active\",device=\"rxe0\",port=\"1\",addr=\"10.0.0.7\"} 7"), std::string::npos) << out;
  EXPECT_NE(out.find("miracache_qp_ack_timeout_exp{role=\"active\",device=\"rxe0\",port=\"1\",addr=\"10.0.0.7\"} 19"), std::string::npos);
  EXPECT_NE(out.find("attr=\"retry_count\"} 1"), std::string::npos) << "the mismatch is counted";
  r.set_metrics(nullptr, {});
}

// F3 (K07): report -> set_metrics (the order that always worked) stays correct.
TEST(QpReadback, ReportThenBindPublishesRealValues) {
  Capture cap;
  telemetry::Registry reg;
  QpReadback r;
  ASSERT_TRUE(r.claim(kSite));
  QpAttrs got{19, 7, 6, 12, 4096};
  r.report(kSite, &got, 0, {});
  r.set_metrics(&reg, {});
  std::string out;
  reg.write_prometheus(out);
  EXPECT_NE(out.find("miracache_qp_path_mtu_bytes{role=\"active\",device=\"rxe0\",port=\"1\",addr=\"10.0.0.7\"} 4096"), std::string::npos) << out;
  r.set_metrics(nullptr, {});
}

// F3 (K08): the labels change when the client learns the node ID: the "unknown" series is hidden, the new one carries
// the real values and the mismatch counts (once, not doubled).
TEST(QpReadback, RebindWithLearnedIdHidesUnknownSeries) {
  Capture cap;
  telemetry::Registry reg;
  QpReadback r;
  const telemetry::Labels unk{{"node_id", "unknown"}, {"hostname", "unknown"}};
  r.set_metrics(&reg, unk);
  ASSERT_TRUE(r.claim(kSite));
  QpAttrs got{19, 7, 6, 12, 4096};
  QpExpect want;
  want.retry_count = 3;
  r.report(kSite, &got, 0, want);
  std::string out;
  reg.write_prometheus(out);
  EXPECT_NE(out.find("node_id=\"unknown\""), std::string::npos);
  r.set_metrics(&reg, {{"node_id", "7"}, {"hostname", "memnode-a"}});
  r.set_metrics(&reg, {{"node_id", "7"}, {"hostname", "memnode-a"}});  // same labels again: no change
  out.clear();
  reg.write_prometheus(out);
  EXPECT_EQ(out.find("node_id=\"unknown\""), std::string::npos) << out;
  EXPECT_NE(out.find("miracache_qp_retry_count{role=\"active\",device=\"rxe0\",port=\"1\",addr=\"10.0.0.7\",node_id=\"7\",hostname=\"memnode-a\"} 7"),
            std::string::npos)
      << out;
  EXPECT_NE(out.find("node_id=\"7\",hostname=\"memnode-a\",attr=\"retry_count\"} 1"), std::string::npos) << out;
  r.set_metrics(nullptr, {});
}

// F3 (K19): the passive side leaves retry_count unset (its retry_cnt comes from the client's REQ): no mismatch.
TEST(QpReadback, PassiveRetryCountNotCompared) {
  QpExpect passive;  // retry_count unset, as VerbsCmFabric::readback_qp builds it for the passive side
  passive.rnr_retry = 6;
  EXPECT_TRUE(qp_compare(QpAttrs{0, 1, 6, 0, 4096}, passive).empty());
  QpExpect active = passive;
  active.retry_count = 7;
  EXPECT_EQ(qp_compare(QpAttrs{0, 1, 6, 0, 4096}, active).size(), 1u);
}

// L06: a report made while the identity says "unknown" is logged again, once, when the node ID and hostname are learned.
TEST(QpReadback, UnknownIdentityLineIsRepeatedOnceWithTheRealOne) {
  Capture cap;
  telemetry::Registry reg;
  QpReadback r;
  r.set_metrics(&reg, {{"node_id", "unknown"}, {"hostname", "unknown"}});
  QpAttrs got{18, 7, 6, 0, 1024};
  r.report(kSite, &got, 0, {});
  std::string t = cap.text();
  EXPECT_EQ(count(t, "level=info"), 1u);
  EXPECT_EQ(count(t, "node_id=unknown"), 1u);
  r.set_metrics(&reg, {{"node_id", "7"}, {"hostname", "memA"}});
  r.set_metrics(&reg, {{"node_id", "7"}, {"hostname", "memA"}});  // same labels again: no third line
  t = cap.text();
  EXPECT_EQ(count(t, "level=info"), 2u) << t;
  EXPECT_EQ(count(t, "node_id=7"), 1u) << t;
  EXPECT_EQ(count(t, "hostname=memA"), 1u) << t;
  EXPECT_EQ(count(t, "identity=learned"), 1u) << t;
  r.set_metrics(nullptr, {});
}

// L06: with the identity known at readback time there is one line and no repeat on a later bind.
TEST(QpReadback, KnownIdentityLineIsNotRepeated) {
  Capture cap;
  telemetry::Registry reg;
  QpReadback r;
  r.set_metrics(&reg, {{"node_id", "7"}, {"hostname", "memA"}});
  QpAttrs got{18, 7, 6, 0, 1024};
  r.report(kSite, &got, 0, {});
  r.set_metrics(&reg, {{"node_id", "7"}, {"hostname", "memA"}});
  r.set_metrics(nullptr, {{"node_id", "7"}, {"hostname", "memA"}});
  EXPECT_EQ(count(cap.text(), "level=info"), 1u) << cap.text();
}

// L06: the failure WARN is repeated too, and a relabel to another unknown does not repeat anything.
TEST(QpReadback, QueryFailureWarnRepeatedWhenIdentityLearned) {
  Capture cap;
  QpReadback r;
  r.set_metrics(nullptr, {{"node_id", "unknown"}, {"hostname", "unknown"}});
  r.report(kSite, nullptr, EINVAL, {});
  r.set_metrics(nullptr, {{"node_id", "7"}, {"hostname", "unknown"}});
  EXPECT_EQ(count(cap.text(), "level=warn"), 1u) << cap.text();
  r.set_metrics(nullptr, {{"node_id", "7"}, {"hostname", "memA"}});
  EXPECT_EQ(count(cap.text(), "level=warn"), 2u) << cap.text();
  EXPECT_EQ(count(cap.text(), "node_id=7"), 1u);
}

// L07 (review s9b): labels A -> B -> A give back A's (hidden) counter series; it is shown again with the count it had,
// not counted a second time. Holds for the mismatch counter and the query-failure counter.
TEST(QpReadback, RelabelBackToEarlierLabelsDoesNotCountTwice) {
  Capture cap;
  telemetry::Registry reg;
  const telemetry::Labels a{{"node_id", "7"}, {"hostname", "memA"}}, b{{"node_id", "8"}, {"hostname", "memB"}};
  QpReadback r;
  r.set_metrics(&reg, a);
  ASSERT_TRUE(r.claim(kSite));
  QpAttrs got{19, 7, 6, 12, 4096};
  QpExpect want;
  want.retry_count = 3;
  r.report(kSite, &got, 0, want);
  const QpSite fsite{"active", "rxe0", "2", "10.0.0.8"};
  ASSERT_TRUE(r.claim(fsite));
  r.report(fsite, nullptr, EINVAL, {});
  r.set_metrics(&reg, b);
  r.set_metrics(&reg, a);
  std::string out;
  reg.write_prometheus(out);
  EXPECT_NE(out.find("node_id=\"7\",hostname=\"memA\",attr=\"retry_count\"} 1\n"), std::string::npos) << out;
  EXPECT_EQ(out.find("node_id=\"8\""), std::string::npos) << "B's series are hidden again\n" << out;
  EXPECT_NE(out.find("miracache_qp_query_fail_total{role=\"active\",device=\"rxe0\",port=\"2\",addr=\"10.0.0.8\",node_id=\"7\","
                     "hostname=\"memA\"} 1\n"),
            std::string::npos)
      << out;
  r.set_metrics(&reg, b);
  out.clear();
  reg.write_prometheus(out);
  EXPECT_NE(out.find("node_id=\"8\",hostname=\"memB\",attr=\"retry_count\"} 1\n"), std::string::npos) << out;
  r.set_metrics(nullptr, {});
}

}  // namespace
}  // namespace miracache::fabric
