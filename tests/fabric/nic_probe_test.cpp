// SPDX-License-Identifier: Apache-2.0
// Unit tests for the NIC probe verdict and renderers on fixture attribute sets (no hardware).
// Provenance per fixture: [D] documented (R/13 capability matrix, kernel/rdma-core source),
// [A] assumed (typical value, to be replaced by a real capture).
#include <gtest/gtest.h>

#include <algorithm>

#include "fabric/probe/nic_probe.h"

using namespace miracache::fabric::probe;
using miracache::fabric::protocol::Protocol;

namespace {

GidEntry gid(std::uint32_t i, const char* text, const char* type, bool v4) { return {i, text, type, v4}; }

PortFacts eth_port(std::uint32_t mbps, std::vector<GidEntry> gids) {
  PortFacts p;
  p.state = "active";
  p.link_layer = "ethernet";
  p.speed_mbps = mbps;
  p.active_mtu = 4096;
  p.max_mtu = 4096;
  p.gids = std::move(gids);
  return p;
}

// ConnectX-6 Dx, RoCE v2 (mlx5). [D] protocol, MW 1+2B, dma-buf yes, ODP yes, max_mr_size ~unlimited
// (R/13 1). [A] part id 4125, rd_atom 16/16 (R/13 marks "~16 [E]"), max_qp/max_cq/max_mr/sge values.
NicFacts cx6dx() {
  NicFacts f;
  f.device = "mlx5_0";
  f.driver = "mlx5_core";
  f.vendor_id = 0x02c9;
  f.vendor_part_id = 4125;
  f.fw_version = "22.35.1012";
  f.node_guid = 0x0c42a10003a1b2c3ULL;
  f.transport = "ib";
  f.protocol = Protocol::RoCE;
  f.ports.push_back(eth_port(100000, {gid(0, "fe80::e42:a1ff:fea1:b2c3", "roce-v1", false),
                                      gid(1, "fe80::e42:a1ff:fea1:b2c3", "roce-v2", false),
                                      gid(2, "::ffff:10.0.0.5", "roce-v1", true),
                                      gid(3, "::ffff:10.0.0.5", "roce-v2", true)}));
  f.limits = {131072, 16777216, 16777216, 30, 30, 32768, 4194303, 16777216,
              ~0ULL, 0xfffffffffffff000ULL, 16, 16};
  f.odp = true;
  f.mw_type1 = {Trial::Supported, {}};
  f.mw_type2 = {Trial::Supported, {}};
  f.dmabuf = {Trial::NotTried, "no dma-buf source available"};
  return f;
}

// E810 in RoCE v2 mode (irdma). [D] IRD 127 / ORD 255 -> reported 127 for both (assumed capped),
// max_mr_size 32 TB, MW type 1 only on Gen2 (type 2B Gen3 only), no ODP (R/13 1). [A] part id.
NicFacts e810_roce() {
  NicFacts f;
  f.device = "rocep94s0f0";
  f.driver = "ice";
  f.vendor_id = 0x8086;
  f.vendor_part_id = 0x1593;
  f.fw_version = "4.40 0x8001c8fb";
  f.node_guid = 0xb6d6a3fffe11aa01ULL;
  f.transport = "ib";
  f.protocol = Protocol::RoCE;
  f.ports.push_back(eth_port(100000, {gid(0, "fe80::b6d6:a3ff:fe11:aa01", "roce-v1", false),
                                      gid(1, "fe80::b6d6:a3ff:fe11:aa01", "roce-v2", false),
                                      gid(2, "::ffff:10.1.0.9", "roce-v2", true)}));
  f.limits = {1048575, 1048575, 4194303, 13, 13, 32768, 4194303, 262144,
              0x200000000000ULL, 0x0000000000fff000ULL, 127, 127};
  f.odp = false;
  f.mw_type1 = {Trial::Supported, {}};
  f.mw_type2 = {Trial::Unsupported, "Operation not supported"};
  f.dmabuf = {Trial::NotTried, "no dma-buf source available"};
  return f;
}

// E810 in iWARP mode. [D] transport iwarp, single GID entry (protocol_rules gid_policy), same
// IRD/ORD source as above. [A] part id, fw, one-entry GID shown as the interface's IPv4.
NicFacts e810_iwarp() {
  NicFacts f = e810_roce();
  f.device = "iwp94s0f0";
  f.transport = "iwarp";
  f.protocol = Protocol::IWarp;
  f.ports[0].gids = {gid(0, "::ffff:10.1.0.9", "ib", true)};
  f.mw_type2 = {Trial::Unsupported, "Operation not supported"};
  return f;
}

// rxe (soft-RoCE). [D] rd_atom 128, MW 1+2B, ODP yes (R/13 1). [A] max_mr_size 2 GiB
// (RXE_MAX_MR_SIZE), vendor/part 0, max_qp 131072, speed 2.5 Gb/s reported as 1x code 1.
NicFacts rxe() {
  NicFacts f;
  f.device = "rxe0";
  f.driver = "";
  f.fw_version = "0.0.0";
  f.node_guid = 0x0202020000030405ULL;
  f.transport = "ib";
  f.protocol = Protocol::RoCE;
  f.ports.push_back(eth_port(2500, {gid(0, "fe80::42:acff:fe11:2", "roce-v2", false),
                                    gid(1, "::ffff:172.17.0.2", "roce-v2", true)}));
  f.ports[0].active_mtu = 1024;
  f.limits = {131072, 32768, 32768, 32, 32, 16384, 32767, 32768,
              1ULL << 31, 0xfffff000ULL, 128, 128};
  f.odp = true;
  f.mw_type1 = {Trial::Supported, {}};
  f.mw_type2 = {Trial::Supported, {}};
  f.dmabuf = {Trial::NotTried, "no dma-buf source available"};
  return f;
}

// siw (soft-iWARP). [D] rd_atom/init 128 (SIW_MAX_IRD/ORD_QP), no MW (R/13 1), iWARP.
// [A] vendor id 0x626d74, part 1, max_mr_size ULLONG_MAX, max_qp 65536.
NicFacts siw() {
  NicFacts f;
  f.device = "siw0";
  f.vendor_id = 0x626d74;
  f.vendor_part_id = 1;
  f.fw_version = "";
  f.node_guid = 0x0202020000030406ULL;
  f.transport = "iwarp";
  f.protocol = Protocol::IWarp;
  f.ports.push_back(eth_port(1000, {gid(0, "::ffff:172.17.0.2", "ib", true)}));
  f.limits = {65536, 65536, 65536, 6, 6, 16384, 32767, 65536, ~0ULL, 0xfffff000ULL, 128, 128};
  f.odp = false;
  f.mw_type1 = {Trial::Unsupported, "Function not implemented"};
  f.mw_type2 = {Trial::Unsupported, "Function not implemented"};
  f.dmabuf = {Trial::NotTried, "no dma-buf source available"};
  return f;
}

bool has_reason(const Verdict& v, const std::string& needle) {
  return std::any_of(v.reasons.begin(), v.reasons.end(),
                     [&](const std::string& r) { return r.find(needle) != std::string::npos; });
}
bool has_warning(const Verdict& v, const std::string& needle) {
  return std::any_of(v.warnings.begin(), v.warnings.end(),
                     [&](const std::string& r) { return r.find(needle) != std::string::npos; });
}

}  // namespace

TEST(NicProbe, FixturesAreUsable) {
  for (const NicFacts& f : {cx6dx(), e810_roce(), e810_iwarp(), rxe(), siw()}) {
    const Verdict v = evaluate(f);
    EXPECT_TRUE(v.usable) << f.device << ": " << (v.reasons.empty() ? "" : v.reasons[0]);
    EXPECT_TRUE(v.reasons.empty());
  }
}

TEST(NicProbe, MemoryWindowWarningsFollowTrialsNotIdentity) {
  EXPECT_FALSE(has_warning(evaluate(cx6dx()), "memory windows"));
  EXPECT_FALSE(has_warning(evaluate(e810_roce()), "memory windows"));  // type 1 is enough
  EXPECT_TRUE(has_warning(evaluate(siw()), "memory windows"));
  NicFacts liar = cx6dx();  // a bnxt_re-style device: flags say yes, the trial says no
  liar.mw_type1 = liar.mw_type2 = {Trial::Unsupported, "Operation not supported"};
  EXPECT_TRUE(has_warning(evaluate(liar), "memory windows"));
}

TEST(NicProbe, DmabufNotTriedIsOnlyAWarning) {
  const Verdict v = evaluate(cx6dx());
  EXPECT_TRUE(v.usable);
  EXPECT_TRUE(has_warning(v, "dma-buf"));
}

TEST(NicProbe, InfiniBandRefused) {
  NicFacts f = cx6dx();
  f.protocol = Protocol::InfiniBand;
  f.ports[0].link_layer = "infiniband";
  const Verdict v = evaluate(f);
  EXPECT_FALSE(v.usable);
  EXPECT_TRUE(has_reason(v, "InfiniBand"));
}

TEST(NicProbe, UnknownProtocolRefused) {
  NicFacts f = rxe();
  f.protocol = Protocol::Unknown;
  EXPECT_FALSE(evaluate(f).usable);
}

TEST(NicProbe, ReadDepthFloor) {
  NicFacts f = cx6dx();
  f.limits.max_qp_rd_atom = kReadDepthFloor - 1;
  Verdict v = evaluate(f);
  EXPECT_FALSE(v.usable);
  EXPECT_TRUE(has_reason(v, "max_qp_rd_atom"));
  f = cx6dx();
  f.limits.max_qp_init_rd_atom = 0;
  v = evaluate(f);
  EXPECT_FALSE(v.usable);
  EXPECT_TRUE(has_reason(v, "max_qp_init_rd_atom"));
  f = cx6dx();
  f.limits.max_qp_rd_atom = f.limits.max_qp_init_rd_atom = kReadDepthFloor;  // at the floor is fine
  EXPECT_TRUE(evaluate(f).usable);
}

TEST(NicProbe, PortMustBeActive) {
  NicFacts f = rxe();
  f.ports[0].state = "down";
  const Verdict v = evaluate(f);
  EXPECT_FALSE(v.usable);
  EXPECT_TRUE(has_reason(v, "ACTIVE"));
  f.ports.clear();
  EXPECT_FALSE(evaluate(f).usable);
}

TEST(NicProbe, RoceNeedsRoceV2Gid) {
  NicFacts f = e810_roce();
  f.ports[0].gids = {gid(0, "fe80::1", "roce-v1", false)};
  const Verdict v = evaluate(f);
  EXPECT_FALSE(v.usable);
  EXPECT_TRUE(has_reason(v, "RoCE v2 GID"));
  // iWARP has no RoCE GIDs and must not be judged by them.
  EXPECT_TRUE(evaluate(e810_iwarp()).usable);
}

TEST(NicProbe, SmallMrSizeWarns) {
  NicFacts f = rxe();
  f.limits.max_mr_size = 1ULL << 20;
  const Verdict v = evaluate(f);
  EXPECT_TRUE(v.usable);
  EXPECT_TRUE(has_warning(v, "max_mr_size"));
}

TEST(NicProbe, JsonShapeIsStableAndVersioned) {
  const std::string j = to_json({rxe(), siw()});
  EXPECT_EQ(j.rfind("{\"schema\":\"miracache.nicprobe\",\"schema_version\":1,\"devices\":[{\"device\":\"rxe0\"", 0), 0u);
  for (const char* key : {"\"driver\"", "\"vendor_id\"", "\"vendor_part_id\"", "\"node_guid\":\"0202:0200:0003:0405\"",
                          "\"fw_version\"", "\"transport\":\"ib\"", "\"protocol\":\"roce-v2\"", "\"protocol\":\"iwarp\"",
                          "\"ports\"", "\"gids\"", "\"ipv4_mapped\":true", "\"max_qp_rd_atom\":128",
                          "\"max_qp_init_rd_atom\":128", "\"max_mr\"", "\"max_mr_size\"", "\"max_qp\"", "\"max_cq\"",
                          "\"max_sge\"", "\"page_size_cap\"", "\"odp\":true", "\"mw_type1\":{\"result\":\"supported\"",
                          "\"mw_type1\":{\"result\":\"unsupported\"", "\"dmabuf\":{\"result\":\"not tried\"",
                          "\"verdict\":{\"usable\":true,\"reasons\":[]"}) {
    EXPECT_NE(j.find(key), std::string::npos) << key;
  }
  EXPECT_EQ(std::count(j.begin(), j.end(), '{'), std::count(j.begin(), j.end(), '}'));
  EXPECT_EQ(std::count(j.begin(), j.end(), '['), std::count(j.begin(), j.end(), ']'));
  EXPECT_EQ(j, to_json({rxe(), siw()}));  // deterministic
}

TEST(NicProbe, JsonEscapesStrings) {
  NicFacts f = rxe();
  f.fw_version = "a\"b\\c\n";
  EXPECT_NE(to_json({f}).find("\"fw_version\":\"a\\\"b\\\\c\\n\""), std::string::npos);
}

TEST(NicProbe, TableMentionsKeyFacts) {
  const std::string t = to_table({cx6dx(), siw()});
  for (const char* s : {"== mlx5_0 ==", "ib -> roce-v2", "iwarp -> iwarp", "mw type 1", "dma-buf mr", "not tried", "usable",
                        "YES", "rd_atom (IRD) 16", "::ffff:10.0.0.5 roce-v2 (ipv4)"}) {
    EXPECT_NE(t.find(s), std::string::npos) << s;
  }
}
