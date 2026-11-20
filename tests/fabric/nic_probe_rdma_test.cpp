// SPDX-License-Identifier: Apache-2.0
// Live NIC-probe tests (label `rdma`): rxe0 must report RoCE v2, siw0 iWARP, both usable.
// MIRACACHE_RDMA_DEVICES (comma list) overrides the device list like the main rdma suite.
#include <gtest/gtest.h>

#include <cstdlib>
#include <sstream>
#include <string>
#include <vector>

#include "fabric/probe/nic_probe.h"

using namespace miracache;
using namespace miracache::fabric::probe;
using miracache::fabric::protocol::Protocol;

namespace {

std::vector<std::string> devices() {
  const char* env = std::getenv("MIRACACHE_RDMA_DEVICES");
  std::stringstream ss(env != nullptr ? env : "rxe0,siw0");
  std::vector<std::string> out;
  for (std::string d; std::getline(ss, d, ',');) {
    if (!d.empty()) out.push_back(d);
  }
  return out;
}

class NicProbeRdmaTest : public ::testing::TestWithParam<std::string> {};

INSTANTIATE_TEST_SUITE_P(Device, NicProbeRdmaTest, ::testing::ValuesIn(devices()),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

}  // namespace

TEST_P(NicProbeRdmaTest, ReportsProtocolAndVerdict) {
  auto r = probe_device(GetParam());
  if (!r) {
    if (r.error().code == ErrorCode::NotFound) GTEST_SKIP() << "no usable RDMA device " << GetParam();
    FAIL() << "probe_device: " << r.error().context;
  }
  const NicFacts& f = *r;
  std::cout << to_table({f}) << to_json({f});

  const bool is_siw = GetParam().rfind("siw", 0) == 0;
  EXPECT_EQ(f.device, GetParam());
  EXPECT_EQ(f.protocol, is_siw ? Protocol::IWarp : Protocol::RoCE);
  EXPECT_EQ(f.transport, is_siw ? "iwarp" : "ib");
  ASSERT_FALSE(f.ports.empty());
  EXPECT_EQ(f.ports[0].state, "active");
  EXPECT_EQ(f.ports[0].link_layer, "ethernet");
  EXPECT_GT(f.ports[0].active_mtu, 0u);
  EXPECT_GE(f.limits.max_qp_rd_atom, kReadDepthFloor);
  EXPECT_GE(f.limits.max_qp_init_rd_atom, kReadDepthFloor);
  EXPECT_GT(f.limits.max_mr, 0u);
  EXPECT_GT(f.limits.max_mr_size, 0u);
  EXPECT_GT(f.limits.max_qp, 0u);
  EXPECT_GT(f.limits.max_cq, 0u);
  EXPECT_GT(f.limits.max_sge, 0u);
  EXPECT_NE(f.limits.page_size_cap, 0u);
  EXPECT_NE(f.node_guid, 0u);
  if (!is_siw) {
    // RoCE v2 with an IPv4-mapped GID (the container network is IPv4).
    bool v2_v4 = false;
    for (const auto& g : f.ports[0].gids) v2_v4 |= (g.type == "roce-v2" && g.ipv4_mapped);
    EXPECT_TRUE(v2_v4);
  }
  // Trials never abort and always give a definite answer for MWs; dma-buf is never tried.
  EXPECT_NE(f.mw_type1.result, Trial::NotTried);
  EXPECT_NE(f.mw_type2.result, Trial::NotTried);
  EXPECT_EQ(f.dmabuf.result, Trial::NotTried);
  if (is_siw) {
    EXPECT_EQ(f.mw_type1.result, Trial::Unsupported);  // R/13 1: siw has no MW
    EXPECT_EQ(f.mw_type2.result, Trial::Unsupported);
  }

  const Verdict v = evaluate(f);
  EXPECT_TRUE(v.usable) << (v.reasons.empty() ? "" : v.reasons[0]);
}

TEST_P(NicProbeRdmaTest, UnknownDeviceIsNotFound) {
  auto r = probe_device("does_not_exist0");
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, ErrorCode::NotFound);
}
