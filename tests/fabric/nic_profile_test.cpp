// SPDX-License-Identifier: Apache-2.0
// A3.3 NIC profile registry: parse, match, clamp, override, log. Golden probe fixtures (no hardware).
// Provenance per fixture: [D] documented (R/13, rdma-core, kernel), [A] assumed typical value, to be
// replaced by a real capture (spec 13.6). The profile values themselves are checked against
// profiles/nic-profiles.toml, which is the source of truth.
#include <gtest/gtest.h>

#include <unistd.h>

#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

#include "fabric/probe/nic_probe.h"
#include "fabric/profile/nic_profile.h"
#include "util/log.h"

using namespace miracache::fabric;
using namespace miracache::fabric::profile;
using miracache::fabric::probe::NicFacts;
using miracache::fabric::protocol::Protocol;

namespace {

probe::PortFacts eth_port(std::uint32_t active_mtu) {
  probe::PortFacts p;
  p.state = "active";
  p.link_layer = "ethernet";
  p.speed_mbps = 100000;
  p.active_mtu = active_mtu;
  p.max_mtu = 4096;
  return p;
}

// ConnectX-6 Dx, RoCE v2. [A] part id 4125, fw 22.35.1012, rd_atom 16/16.
NicFacts cx6dx() {
  NicFacts f;
  f.device = "mlx5_0";
  f.driver = "mlx5_core";
  f.vendor_id = 0x02c9;
  f.vendor_part_id = 4125;
  f.fw_version = "22.35.1012";
  f.transport = "ib";
  f.protocol = Protocol::RoCE;
  f.ports.push_back(eth_port(4096));
  f.limits.max_qp_rd_atom = 16;
  f.limits.max_qp_init_rd_atom = 16;
  return f;
}

// ConnectX-7. [A] part id 4129, fw 28.39.1002.
NicFacts cx7() {
  NicFacts f = cx6dx();
  f.vendor_part_id = 4129;
  f.fw_version = "28.39.1002";
  return f;
}

// E810 RoCE v2. [D] IRD 127 / ORD 255 reported as 127 (assumed capped); [A] part 0x1593, fw "4.40 0x8001c8fb".
NicFacts e810_roce() {
  NicFacts f;
  f.device = "rocep94s0f0";
  f.driver = "ice";
  f.vendor_id = 0x8086;
  f.vendor_part_id = 0x1593;
  f.fw_version = "4.40 0x8001c8fb";
  f.transport = "ib";
  f.protocol = Protocol::RoCE;
  f.ports.push_back(eth_port(4096));
  f.limits.max_qp_rd_atom = 127;
  f.limits.max_qp_init_rd_atom = 127;
  return f;
}

NicFacts e810_iwarp() {
  NicFacts f = e810_roce();
  f.device = "iwp94s0f0";
  f.transport = "iwarp";
  f.protocol = Protocol::IWarp;
  return f;
}

// rxe over a 1500-byte netdev: active MTU 1024. [D] vendor/part 0, no driver, fw "0.0.0".
NicFacts rxe() {
  NicFacts f;
  f.device = "rxe0";
  f.fw_version = "0.0.0";
  f.transport = "ib";
  f.protocol = Protocol::RoCE;
  f.ports.push_back(eth_port(1024));
  f.limits.max_qp_rd_atom = 128;
  f.limits.max_qp_init_rd_atom = 128;
  return f;
}

// siw. [A] vendor 0x626d74, part 1.
NicFacts siw() {
  NicFacts f;
  f.device = "siw0";
  f.vendor_id = 0x626d74;
  f.vendor_part_id = 1;
  f.transport = "iwarp";
  f.protocol = Protocol::IWarp;
  f.ports.push_back(eth_port(1024));
  f.limits.max_qp_rd_atom = 128;
  f.limits.max_qp_init_rd_atom = 128;
  return f;
}

// A RoCE NIC the registry has never heard of (a bnxt_re-like part).
NicFacts unknown_roce() {
  NicFacts f = cx6dx();
  f.device = "bnxt_re0";
  f.driver = "bnxt_en";
  f.vendor_id = 0x14e4;
  f.vendor_part_id = 0x1750;
  f.fw_version = "219.0.0";
  return f;
}

const Registry& builtin() {
  auto r = builtin_registry();
  EXPECT_TRUE(r) << (r ? "" : r.error().context);
  return **r;
}

Selection pick(const NicFacts& f, const Overrides& ov = {}) {
  auto s = select(builtin(), f, ov);
  EXPECT_TRUE(s) << (s ? "" : s.error().context);
  return s ? *s : Selection{};
}

// A minimal valid registry text; tests splice breakages into it.
const char* kMini = R"(
schema = 1
registry_version = "t"
[[profile]]
id = "generic-roce"
tier = 0
verified = false
warn = "unprofiled"
[profile.match]
transport = "roce"
[profile.loss_handling]
require_any = ["pfc_ecn"]
[profile.op]
fetch_qps = 2
slice_bytes = 262144
window_bytes = 1048576
read_depth = 4
[[profile]]
id = "generic-iwarp"
tier = 0
verified = false
warn = "unprofiled"
[profile.match]
transport = "iwarp"
[profile.loss_handling]
require_any = ["tcp"]
[profile.op]
read_depth = 4
window_bytes = 1048576
slice_bytes = 262144
)";

std::string with(const std::string& from, const std::string& to) {
  std::string t = kMini;
  const auto p = t.find(from);
  EXPECT_NE(p, std::string::npos) << from;
  if (p != std::string::npos) t.replace(p, from.size(), to);
  return t;
}

}  // namespace

TEST(NicProfile, BuiltinParsesAndHasTheRequiredEntries) {
  const Registry& r = builtin();
  EXPECT_EQ(r.schema, 1);
  for (const char* id : {"mlx5-cx6dx-roce", "mlx5-cx7-roce", "irdma-e810-roce", "irdma-e810-iwarp", "rxe", "siw",
                         "generic-roce", "generic-iwarp"}) {
    bool found = false;
    for (const auto& p : r.profiles) found = found || p.id == id;
    EXPECT_TRUE(found) << id;
  }
}

TEST(NicProfile, EveryBuiltinOperatingPointIsValid) {
  // Round-trips each profile through select() on a fixture it matches: check_op runs on the result.
  for (const NicFacts& f : {cx6dx(), cx7(), e810_roce(), e810_iwarp(), rxe(), siw(), unknown_roce()}) {
    auto s = select(builtin(), f);
    ASSERT_TRUE(s) << f.device << ": " << (s ? "" : s.error().context);
    EXPECT_GE(s->op.window_bytes, s->op.slice_bytes);
    EXPECT_LE(s->op.window_bytes / s->op.slice_bytes, s->op.read_depth);
  }
}

TEST(NicProfile, RepoFileMatchesTheBuiltinCopy) {
  auto file = load_registry_file(MIRACACHE_PROFILES_FILE);
  ASSERT_TRUE(file) << file.error().context;
  EXPECT_EQ(file->version, builtin().version);
  EXPECT_EQ(file->profiles.size(), builtin().profiles.size());
}

TEST(NicProfile, GoldenMatches) {
  struct Case {
    NicFacts f;
    const char* id;
    bool verified, unprofiled;
  };
  const Case cases[] = {
      {cx6dx(), "mlx5-cx6dx-roce", false, false}, {cx7(), "mlx5-cx7-roce", false, false},
      {e810_roce(), "irdma-e810-roce", false, false}, {e810_iwarp(), "irdma-e810-iwarp", false, false},
      {rxe(), "rxe", true, false},                  {siw(), "siw", true, false},
      {unknown_roce(), "generic-roce", false, true},
  };
  for (const auto& c : cases) {
    Selection s = pick(c.f);
    EXPECT_EQ(s.profile_id, c.id) << c.f.device;
    EXPECT_EQ(s.verified, c.verified) << c.f.device;
    EXPECT_EQ(s.unprofiled, c.unprofiled) << c.f.device;
  }
}

TEST(NicProfile, UnknownNicFallsBackToGenericByTransport) {
  NicFacts roce = unknown_roce();
  Selection a = pick(roce);
  EXPECT_EQ(a.profile_id, "generic-roce");
  EXPECT_EQ(a.op.read_depth, 4u);       // spec 4.2: the unknown-NIC read depth is 4
  EXPECT_EQ(a.op.slice_bytes, 262144u); // spec 4.3 generic
  EXPECT_FALSE(a.warn.empty());
  NicFacts iw = unknown_roce();
  iw.protocol = Protocol::IWarp;
  iw.transport = "iwarp";
  EXPECT_EQ(pick(iw).profile_id, "generic-iwarp");
}

TEST(NicProfile, SpecValuesForTier1) {
  Selection cx = pick(cx6dx());
  EXPECT_EQ(cx.op.fetch_qps, 4u);
  EXPECT_EQ(cx.op.slice_bytes, 1048576u);
  EXPECT_EQ(cx.op.read_depth, 16u);
  EXPECT_EQ(cx.op.inline_bytes, 220u);
  Selection iw = pick(e810_iwarp());
  EXPECT_EQ(iw.op.fetch_qps, 8u);
  EXPECT_EQ(iw.op.read_depth, 32u);
}

TEST(NicProfile, ProtocolDecidesBetweenTwoModesOfOneNic) {
  EXPECT_EQ(pick(e810_roce()).profile_id, "irdma-e810-roce");
  EXPECT_EQ(pick(e810_iwarp()).profile_id, "irdma-e810-iwarp");
}

TEST(NicProfile, InfinibandOrUnknownProtocolIsRefused) {
  NicFacts f = cx6dx();
  f.protocol = Protocol::Unknown;
  auto s = select(builtin(), f);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, miracache::ErrorCode::Unsupported);
}

TEST(NicProfile, MostSpecificWinsAndTiesGoToTheFirst) {
  const std::string two = std::string(kMini) + R"(
[[profile]]
id = "a-driver"
tier = 1
verified = true
[profile.match]
driver = ["mlx5_core"]
transport = "roce"
[profile.loss_handling]
require_any = ["pfc_ecn"]
[profile.op]
read_depth = 8
window_bytes = 1048576
slice_bytes = 262144
[[profile]]
id = "b-driver-part"
tier = 1
verified = true
[profile.match]
driver = ["mlx5_core"]
part_id = [4125]
[profile.loss_handling]
require_any = ["pfc_ecn"]
[profile.op]
read_depth = 8
window_bytes = 1048576
slice_bytes = 262144
[[profile]]
id = "c-same-score-as-a"
tier = 1
verified = true
[profile.match]
driver = ["mlx5_core"]
vendor_id = [0x02c9]
[profile.loss_handling]
require_any = ["pfc_ecn"]
[profile.op]
read_depth = 8
window_bytes = 1048576
slice_bytes = 262144
)";
  auto r = parse_registry(two);
  ASSERT_TRUE(r) << r.error().context;
  // b: driver 2 + part 2 = 4. a: 2 + 1 = 3. c: 2 + 1 = 3. generic: 1.
  EXPECT_EQ(select(*r, cx6dx())->profile_id, "b-driver-part");
  NicFacts other = cx6dx();
  other.vendor_part_id = 9999;  // a and c tie at 3: the earlier wins
  EXPECT_EQ(select(*r, other)->profile_id, "a-driver");
}

TEST(NicProfile, FirmwareCheck) {
  EXPECT_EQ(check_firmware("22.35.1012", "22.31.0"), FwStatus::Ok);
  EXPECT_EQ(check_firmware("22.31.0", "22.31.0"), FwStatus::Ok);
  EXPECT_EQ(check_firmware("22.30.9", "22.31.0"), FwStatus::BelowMin);
  EXPECT_EQ(check_firmware("22.31", "22.31.0"), FwStatus::Ok);
  EXPECT_EQ(check_firmware("4.40 0x8001c8fb", "4.40"), FwStatus::Ok);
  EXPECT_EQ(check_firmware("4.2 0x1", "4.40"), FwStatus::BelowMin);
  EXPECT_EQ(check_firmware("", "22.31.0"), FwStatus::Unknown);
  EXPECT_EQ(check_firmware("abc", "22.31.0"), FwStatus::Unknown);
  EXPECT_EQ(check_firmware("22.31.0", ""), FwStatus::NotChecked);
  NicFacts old = cx6dx();
  old.fw_version = "20.1.1";
  EXPECT_EQ(pick(old).fw, FwStatus::BelowMin);
  EXPECT_EQ(pick(cx6dx()).fw, FwStatus::Ok);
  EXPECT_EQ(pick(rxe()).fw, FwStatus::NotChecked);
}

TEST(NicProfile, ProbeClampsTheOperatingPoint) {
  NicFacts f = cx6dx();
  f.ports[0].active_mtu = 1024;
  f.limits.max_qp_init_rd_atom = 8;
  Selection s = pick(f);
  EXPECT_EQ(s.op.mtu, 1024u);
  EXPECT_EQ(s.op.read_depth, 8u);
  EXPECT_EQ(s.op.window_bytes, 8u * s.op.slice_bytes);  // follows the depth
  EXPECT_EQ(s.profile_op.read_depth, 16u);              // the profile as written is kept
  EXPECT_FALSE(s.notes.empty());
}

TEST(NicProfile, ConfigBeatsProfileBeatsDefault) {
  Overrides ov;
  ov.read_depth = 4;
  ov.ack_timeout_exp = 12;
  ov.retry_count = 3;
  ov.inline_bytes = 64;
  ov.mtu = 2048;
  Selection s = pick(cx6dx(), ov);
  EXPECT_EQ(s.op.read_depth, 4u);
  EXPECT_EQ(s.op.ack_timeout_exp, 12);
  EXPECT_EQ(s.op.retry_count, 3);
  EXPECT_EQ(s.op.inline_bytes, 64u);
  EXPECT_EQ(s.op.mtu, 2048u);
  EXPECT_EQ(s.op.fetch_qps, 4u);  // not overridden: the profile's value
  EXPECT_EQ(s.op.window_bytes, 4u * s.op.slice_bytes);
  // No profile value left unset: the built-in default is the rxe point (the pre-registry behaviour).
  Selection r = pick(rxe());
  OperatingPoint d = builtin_default();
  EXPECT_EQ(r.op.read_depth, d.read_depth);
  EXPECT_EQ(r.op.ack_timeout_exp, d.ack_timeout_exp);
  EXPECT_EQ(r.op.retry_count, d.retry_count);
  EXPECT_EQ(r.op.rnr_retry_count, d.rnr_retry_count);
  EXPECT_EQ(r.op.mtu, 1024u);  // clamped to the port, below the default 4096
}

TEST(NicProfile, ParserIsStrict) {
  EXPECT_TRUE(parse_registry(kMini));
  EXPECT_FALSE(parse_registry("not toml ["));
  EXPECT_FALSE(parse_registry(""));
  EXPECT_FALSE(parse_registry(with("schema = 1", "schema = 2")));
  EXPECT_FALSE(parse_registry(with("schema = 1", "schema = 1\nbogus = 1")));                    // unknown top key
  EXPECT_FALSE(parse_registry(with("tier = 0\nverified = false\nwarn", "tier = 0\nverified = false\nbogus = 1\nwarn")));  // unknown profile key
  EXPECT_FALSE(parse_registry(with("fetch_qps = 2", "fetch_qps = 2\nbogus = 1")));              // unknown op key
  EXPECT_FALSE(parse_registry(with("transport = \"roce\"", "transport = \"roce\"\nbogus = 1")));  // unknown match key
  EXPECT_FALSE(parse_registry(with("[profile.match]\ntransport = \"roce\"", "[profile.match]")));  // empty match
  EXPECT_FALSE(parse_registry(with("verified = false\nwarn = \"unprofiled\"\n[profile.match]\ntransport = \"roce\"",
                                   "warn = \"unprofiled\"\n[profile.match]\ntransport = \"roce\"")));  // verified missing
  EXPECT_FALSE(parse_registry(with("fetch_qps = 2", "fetch_qps = 0")));
  EXPECT_FALSE(parse_registry(with("fetch_qps = 2", "fetch_qps = \"two\"")));
  EXPECT_FALSE(parse_registry(with("slice_bytes = 262144\nwindow_bytes = 1048576\nread_depth = 4", "slice_bytes = 3000\nwindow_bytes = 6000\nread_depth = 4")));
  EXPECT_FALSE(parse_registry(with("read_depth = 4\n[[profile]]", "read_depth = 2\n[[profile]]")));  // window > depth * slice
  EXPECT_FALSE(parse_registry(with("fetch_qps = 2", "fetch_qps = 2\nack_timeout_exp = 20")));
  EXPECT_FALSE(parse_registry(with("fetch_qps = 2", "fetch_qps = 2\nrnr_retry_count = 7")));  // 7 = retry forever
  EXPECT_FALSE(parse_registry(with("fetch_qps = 2", "fetch_qps = 2\nmtu = 1500")));
  EXPECT_FALSE(parse_registry(with("require_any = [\"pfc_ecn\"]", "require_any = [\"magic\"]")));
  EXPECT_FALSE(parse_registry(with("require_any = [\"pfc_ecn\"]", "require_any = []")));
  EXPECT_FALSE(parse_registry(with("id = \"generic-roce\"", "id = \"generic-iwarp\"")));  // duplicate id
  EXPECT_FALSE(parse_registry(with("id = \"generic-roce\"", "id = \"Bad Id\"")));
  EXPECT_FALSE(parse_registry(with("transport = \"roce\"", "transport = \"ib\"")));
  EXPECT_FALSE(parse_registry(with("transport = \"roce\"", "transport = \"roce\"\nvendor_id = [-1]")));
  // Without a transport-only fallback for both transports the registry is refused.
  EXPECT_FALSE(parse_registry(with("[profile.match]\ntransport = \"roce\"", "[profile.match]\ntransport = \"roce\"\ndriver = [\"x\"]")));
  EXPECT_FALSE(parse_registry(std::string(kMaxRegistryBytes + 1, '#')));
}

TEST(NicProfile, FuzzedInputNeverCrashes) {
  const std::string base = kMini;
  std::uint64_t x = 0x9e3779b97f4a7c15ULL;
  auto rnd = [&] {
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    return x;
  };
  for (std::size_t cut = 0; cut <= base.size(); cut += 7) (void)parse_registry(base.substr(0, cut));
  const std::string charset = "[]=\".-_ \n\\0123456789abz{}#,";
  for (int i = 0; i < 400; ++i) {
    std::string t = base;
    for (int k = 0; k < 1 + static_cast<int>(rnd() % 6); ++k) t[rnd() % t.size()] = charset[rnd() % charset.size()];
    (void)parse_registry(t);
  }
  for (int i = 0; i < 100; ++i) {  // pure noise
    std::string t(static_cast<std::size_t>(rnd() % 300), '\0');
    for (auto& c : t) c = static_cast<char>(rnd());
    (void)parse_registry(t);
  }
  SUCCEED();
}

TEST(NicProfile, MissingFileIsAnErrorNotAFallback) {
  auto r = load_registry_file("/nonexistent/nic-profiles.toml");
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, miracache::ErrorCode::NotFound);
}

TEST(NicProfile, LogLineCarriesIdentityAndProfile) {
  char path[] = "/tmp/nicprofile_log_XXXXXX";
  const int fd = mkstemp(path);
  ASSERT_GE(fd, 0);
  miracache::log::set_sink_fd(fd);
  miracache::log::set_identity({7, "hostA", "10.0.0.5:7471"});
  log_selection(pick(unknown_roce()), unknown_roce());
  miracache::log::set_sink_fd(2);
  miracache::log::set_identity({});
  std::ifstream in(path);
  std::stringstream ss;
  ss << in.rdbuf();
  ::close(fd);
  ::unlink(path);
  const std::string out = ss.str();
  EXPECT_NE(out.find("node_id=7"), std::string::npos) << out;
  EXPECT_NE(out.find("host=hostA"), std::string::npos) << out;
  EXPECT_NE(out.find("addr=10.0.0.5:7471"), std::string::npos) << out;
  EXPECT_NE(out.find("profile=generic-roce"), std::string::npos) << out;
  EXPECT_NE(out.find("verified=false"), std::string::npos) << out;
  EXPECT_NE(out.find("unprofiled NIC"), std::string::npos) << out;  // the warning line
}

TEST(NicProfile, RenderersMentionTheMatch) {
  Selection s = pick(cx6dx());
  EXPECT_NE(selection_to_text(s).find("mlx5-cx6dx-roce"), std::string::npos);
  const std::string j = selection_to_json(s);
  EXPECT_NE(j.find("\"id\":\"mlx5-cx6dx-roce\""), std::string::npos);
  EXPECT_NE(j.find("\"verified\":false"), std::string::npos);
  EXPECT_NE(j.find("\"fetch_qps\":4"), std::string::npos);
}
