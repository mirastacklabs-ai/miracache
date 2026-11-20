// SPDX-License-Identifier: Apache-2.0
// The memory node's live configuration. The key table (server/dyn_config.h): class A keys parse from the bundle's
// config.cluster.memnode (+ the node override) and from the local TOML on SIGHUP into the SAME snapshot; STATIC and stale
// keys reject the whole table and the old snapshot stays; unknown keys are ignored and counted; node-local keys are
// recorded as pending. Server::apply_dyn swaps every key at once on the store thread, and an op after the swap sees it.
#include <algorithm>
#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <thread>

#include <gtest/gtest.h>

#include "control/bundle.h"
#include "fabric/sim/sim_fabric.h"
#include "server/dyn_config.h"
#include "server/node_config.h"
#include "server/server.h"
#include "util/clock.h"
#include "util/executor.h"
#include "util/random.h"

namespace miracache::server {
namespace {

using namespace std::chrono_literals;

const char* kBase = "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\n";

// All class A keys, once, in the file layout (the bundle table uses the same section.key names). The [store] ones are
// separate: the file's [store] table also carries the STATIC keys, so they are appended to it.
const char* kStoreDyn = R"(invalidate_per_s = 33
max_scopes = 77
max_bytes = 1048576
max_exact_classes_per_owner = 5
)";
const char* kRest = R"(
[lease]
ttl_s = 7
max_s = 70
put_timeout_s = 12
[ticket]
ttl_s = 120
[limits]
ticket_max_per_identity = 99
admit_timeout_s = 4
hello_deadline_s = 3
idle_timeout_s = 200
max_conns_per_principal = 11
max_leases_per_principal = 555
[retention]
idle_ttl_s = 900
max_ttl_s = 3600
[evict]
sweep_bytes_per_s = 4194304
sweep_blocks_per_turn = 16
high_pct = 90
low_pct = 70
[quota]
put_ops_per_s = 500
put_bytes_per_s = 1000000
)";

DynConfig base() {  // like Server's start-up snapshot: max_bytes is already resolved
  DynConfig d;
  d.max_bytes = std::uint64_t{1} << 30;
  return d;
}
std::string all_bundle() { return std::string("[store]\n") + kStoreDyn + kRest; }

std::string cluster(const std::string& toml_sections) {  // "[lease]\nttl_s=1" -> config.cluster.memnode.lease ...
  std::string out, line;
  std::size_t pos = 0;
  while (pos < toml_sections.size()) {
    auto eol = toml_sections.find('\n', pos);
    if (eol == std::string::npos) eol = toml_sections.size();
    line = toml_sections.substr(pos, eol - pos);
    pos = eol + 1;
    if (!line.empty() && line[0] == '[') out += "[cluster.memnode." + line.substr(1) + "\n";
    else out += line + "\n";
  }
  return out;
}

// ---- parsing ------------------------------------------------------------------------------------------------------
TEST(DynConfig, EveryClassAKeyParsesFromTheBundleTable) {
  auto r = parse_memnode_dyn(cluster(all_bundle()), base(), "", 9);
  ASSERT_TRUE(r.dyn) << r.error;
  const DynConfig& d = *r.dyn;
  EXPECT_EQ(d.lease_ttl, 7s);
  EXPECT_EQ(d.lease_max, 70s);
  EXPECT_EQ(d.put_timeout, 12s);
  EXPECT_EQ(d.ticket_ttl, 120s);
  EXPECT_EQ(d.ticket_max_per_identity, 99u);
  EXPECT_EQ(d.admit_timeout, 4s);
  EXPECT_EQ(d.hello_deadline, 3s);
  EXPECT_EQ(d.idle_timeout, 200s);
  EXPECT_EQ(d.max_conns_per_principal, 11u);
  EXPECT_EQ(d.max_leases_per_principal, 555u);
  EXPECT_EQ(d.invalidate_per_s, 33u);
  EXPECT_EQ(d.max_scopes, 77u);
  EXPECT_EQ(d.max_bytes, 1048576u);
  EXPECT_EQ(d.max_exact_classes_per_owner, 5u);
  EXPECT_EQ(d.idle_ttl, 900s);
  EXPECT_EQ(d.max_ttl, 3600s);
  EXPECT_EQ(d.sweep_bytes_per_s, 4194304u);
  EXPECT_EQ(d.sweep_blocks_per_turn, 16u);
  EXPECT_EQ(d.high_pct, 90u);
  EXPECT_EQ(d.low_pct, 70u);
  EXPECT_EQ(d.put_ops_per_s, 500u);
  EXPECT_EQ(d.put_bytes_per_s, 1000000u);
  EXPECT_EQ(d.generation, 9u);
  EXPECT_TRUE(r.unknown.empty());
  EXPECT_EQ(dyn_changed_keys(base(), d).size(), 22u);  // every key above differs from the defaults
}

TEST(DynConfig, BundleAndSighupGiveTheSameSnapshot) {
  auto file = parse_node_config(std::string(kBase) + kStoreDyn + kRest);
  ASSERT_TRUE(file) << file.error().context;
  // The file's [store] table carries both static and dynamic keys; the dynamic ones are the same names in the bundle.
  const DynConfig from_file = dyn_from_server_config(file->server);
  auto r = parse_memnode_dyn(cluster(all_bundle()), base(), "", 0);
  ASSERT_TRUE(r.dyn) << r.error;
  EXPECT_TRUE(dyn_changed_keys(from_file, *r.dyn).empty());
  // And the SIGHUP plan applies exactly that snapshot (lab mode), or only drain_ms (bundle mode).
  auto plan = plan_sighup(*file, *file, base(), /*bundle_mode=*/false);
  ASSERT_TRUE(plan.dyn);
  EXPECT_TRUE(dyn_changed_keys(*plan.dyn, *r.dyn).empty());
  auto bplan = plan_sighup(*file, *file, base(), /*bundle_mode=*/true);
  ASSERT_TRUE(bplan.dyn);
  EXPECT_TRUE(dyn_changed_keys(*bplan.dyn, base()).empty());
}

// Push validation (BundleStore::push) and apply (Server::apply_bundle_config) both take the admin from
// bundle_node_admin, so an override validated at push is the one applied.
TEST(DynConfig, BundleNodeAdminSharedByPushAndApply) {
  control::BodyView body;
  control::NodeView a, b;
  a.node_id = 7;
  a.admin = "10.0.0.10:9465";
  b.node_id = 8;
  b.admin = "10.0.0.11:9465";
  body.nodes = {a, b};
  EXPECT_EQ(bundle_node_admin(body, 7), "10.0.0.10:9465");  // (a) listed
  EXPECT_EQ(bundle_node_admin(body, 9), "");                // (b) not listed: no fallback to the local admin
  const std::string cfg = "[node.\"10.0.0.10:9465\".memnode.lease]\nttl_s = 9\n";
  auto listed = parse_memnode_dyn(cfg, base(), bundle_node_admin(body, 7), 1);
  ASSERT_TRUE(listed.dyn) << listed.error;
  EXPECT_EQ(listed.dyn->lease_ttl, 9s);
  auto unlisted = parse_memnode_dyn(cfg, base(), bundle_node_admin(body, 9), 1);
  ASSERT_TRUE(unlisted.dyn);
  EXPECT_NE(unlisted.dyn->lease_ttl, 9s);
}

TEST(DynConfig, NodeOverrideWinsKeyByKey) {
  const std::string cfg = "[cluster.memnode.lease]\nttl_s = 5\nmax_s = 50\n[cluster.memnode.quota]\nput_ops_per_s = 10\n"
                          "[node.\"10.0.0.10:9465\".memnode.lease]\nttl_s = 9\n"
                          "[node.\"10.0.0.99:9465\".memnode.lease]\nttl_s = 1\n";
  auto mine = parse_memnode_dyn(cfg, base(), "10.0.0.10:9465", 1);
  ASSERT_TRUE(mine.dyn) << mine.error;
  EXPECT_EQ(mine.dyn->lease_ttl, 9s);       // the override
  EXPECT_EQ(mine.dyn->lease_max, 50s);      // the cluster value stays
  EXPECT_EQ(mine.dyn->put_ops_per_s, 10u);
  auto other = parse_memnode_dyn(cfg, base(), "10.0.0.11:9465", 1);
  ASSERT_TRUE(other.dyn);
  EXPECT_EQ(other.dyn->lease_ttl, 5s);
}

TEST(DynConfig, AbsentKeysTakeTheBase) {
  DynConfig b = base();
  b.lease_ttl = 11s;
  b.lease_max = 111s;
  auto r = parse_memnode_dyn(cluster("[quota]\nput_ops_per_s = 3\n"), b, "", 2);
  ASSERT_TRUE(r.dyn);
  EXPECT_EQ(r.dyn->lease_ttl, 11s);  // removing a key from the bundle restores the start-up value
  auto none = parse_memnode_dyn("", b, "", 3);
  ASSERT_TRUE(none.dyn);
  EXPECT_TRUE(dyn_changed_keys(b, *none.dyn).empty());
  EXPECT_EQ(none.dyn->generation, 3u);
}

// One rule: an absent store.max_bytes is 0 in the loaded config and resolves to n_segments x segment_bytes of this
// node (dyn_from_server_config, Server::create); an explicit value wins. (max_scopes keeps its code default.)
TEST(DynConfig, MaxBytesDefaultsToTheBackingSize) {
  auto def = parse_node_config(kBase + std::string("n_segments = 8\n"));
  ASSERT_TRUE(def.has_value());
  EXPECT_EQ(def->server.store.principal_default.max_bytes, 0u);  // computed later, not by the loader
  EXPECT_EQ(dyn_from_server_config(def->server).max_bytes, std::uint64_t{8} * 4194304);
  EXPECT_EQ(DynConfig{}.max_bytes, 0u);
  auto set = parse_node_config(kBase + std::string("n_segments = 8\nmax_bytes = 1048576\n"));
  ASSERT_TRUE(set.has_value());
  EXPECT_EQ(set->server.store.principal_default.max_bytes, 1048576u);
  EXPECT_EQ(dyn_from_server_config(set->server).max_bytes, 1048576u);
}

TEST(DynConfig, StaticKeysRejectTheWholeTable) {
  for (const char* s : {"[store]\nsegment_bytes = 1\n", "[store]\nn_segments = 2\n", "[store]\ndir = \"/x\"\n",
                        "[store]\nbacking = \"file\"\n", "[store]\nrun_bytes = 1\n", "[store]\nrequire_1g = true\n",
                        "[store]\nmax_puts_per_endpoint = 1\n", "[node]\nlisten = [\"a:1\"]\n", "[node]\nstate_dir = \"/x\"\n",
                        "[node]\ndevice = \"x\"\n", "[control]\ntrust_keys = \"x\"\n", "[executor]\nworkers = 1\n",
                        "[nic]\nprofiles_file = \"x\"\n"}) {
    auto r = parse_memnode_dyn(cluster(std::string("[lease]\nttl_s = 5\n") + s), base(), "", 1);
    EXPECT_FALSE(r.dyn) << s;  // the valid lease key next to it is NOT applied either
    EXPECT_NE(r.error.find("STATIC"), std::string::npos) << s << " -> " << r.error;
  }
}

TEST(DynConfig, StaleFlatNamesAreErrorsThatNameTheNewKey) {
  struct { const char* old_key; const char* new_key; } stale[] = {
      {"max_ttl_s = 5", "retention.max_ttl_s"},        {"scope_idle_ttl_s = 5", "retention.idle_ttl_s"},
      {"sweep_bytes_per_s = 5", "evict.sweep_bytes_per_s"}, {"sweep_blocks_per_turn = 5", "evict.sweep_blocks_per_turn"},
      {"high_pct = 90", "evict.high_pct"},             {"low_pct = 5", "evict.low_pct"},
      {"put_ops_per_s = 5", "quota.put_ops_per_s"},    {"put_bytes_per_s = 5", "quota.put_bytes_per_s"}};
  for (const auto& s : stale) {
    auto r = parse_memnode_dyn(cluster(std::string("[store]\n") + s.old_key + "\n"), base(), "", 1);
    EXPECT_FALSE(r.dyn) << s.old_key;
    EXPECT_NE(r.error.find(s.new_key), std::string::npos) << r.error;
    auto f = parse_node_config(std::string(kBase) + s.old_key + "\n");  // the local file: same rule
    ASSERT_FALSE(f) << s.old_key;
    EXPECT_NE(std::string(f.error().context).find(s.new_key), std::string::npos) << f.error().context;
  }
}

TEST(DynConfig, UnknownKeysAreIgnoredAndReported) {
  auto r = parse_memnode_dyn(cluster("[lease]\nttl_s = 6\nfuture_knob = 1\n[futuristic]\nx = 1\n"), base(), "", 1);
  ASSERT_TRUE(r.dyn) << r.error;
  EXPECT_EQ(r.dyn->lease_ttl, 6s);
  ASSERT_EQ(r.unknown.size(), 2u);
  // The local file is the operator's own: unknown keys stay errors there.
  EXPECT_FALSE(parse_node_config(std::string(kBase) + "[lease]\nfuture_knob = 1\n"));
}

TEST(DynConfig, NodeLocalKeysAreRecordedAsPending) {
  auto r = parse_memnode_dyn(cluster("[node]\ndrain_ms = 100\n[admin]\nlisten = \"0.0.0.0:1\"\n[telemetry]\nlisten = \"x\"\n"),
                             base(), "", 1);
  ASSERT_TRUE(r.dyn) << r.error;
  EXPECT_EQ(r.dyn->drain_ms, 5000u);  // not applied from the bundle
  ASSERT_EQ(r.dyn->pending.size(), 3u);
  EXPECT_NE(std::find(r.dyn->pending.begin(), r.dyn->pending.end(), "node.drain_ms"), r.dyn->pending.end());
}

TEST(DynConfig, BadValuesAndCrossFieldRulesReject) {
  for (const char* s : {"[lease]\nttl_s = 0\n", "[lease]\nttl_s = 100\nmax_s = 10\n", "[lease]\nttl_s = \"x\"\n",
                        "[lease]\nttl_s = -1\n", "[limits]\nadmit_timeout_s = 400\n", "[evict]\nlow_pct = 95\nhigh_pct = 90\n",
                        "[evict]\nhigh_pct = 100\n", "[evict]\nsweep_bytes_per_s = 0\n", "[store]\nmax_scopes = 0\n",
                        "[retention]\nmax_ttl_s = -5\n", "[quota]\nput_ops_per_s = 1.5\n"}) {
    auto r = parse_memnode_dyn(cluster(s), base(), "", 1);
    EXPECT_FALSE(r.dyn) << s;
    EXPECT_FALSE(r.error.empty());
  }
  EXPECT_TRUE(parse_memnode_dyn(cluster("[retention]\nmax_ttl_s = 0\n[quota]\nput_ops_per_s = 0\n"), base(), "", 1).dyn);  // 0 = off
  EXPECT_FALSE(parse_memnode_dyn("not toml [[", base(), "", 1).dyn);
}

TEST(DynConfig, BundleModeRefusesClassAKeysInTheLocalFile) {
  const std::string ctl = "[admin]\nlisten = \"127.0.0.1:0\"\ncert = \"a\"\nkey = \"b\"\nca = \"c\"\n[control]\ntrust_keys = \"/t\"\n";
  EXPECT_TRUE(parse_node_config(std::string(kBase) + ctl));
  auto bad = parse_node_config(std::string(kBase) + ctl + "[lease]\nttl_s = 5\n");
  ASSERT_FALSE(bad);
  EXPECT_NE(std::string(bad.error().context).find("lease.ttl_s is cluster config in bundle mode"), std::string::npos)
      << bad.error().context;
  EXPECT_FALSE(parse_node_config(std::string(kBase) + ctl + "[quota]\nput_ops_per_s = 1\n"));
  EXPECT_TRUE(parse_node_config(std::string(kBase) + ctl + "[node]\ndrain_ms = 10\n"));  // node-local, allowed
}

TEST(DynConfig, FileSectionsAndCrossFieldRules) {
  EXPECT_FALSE(parse_node_config(std::string(kBase) + "[evict]\nhigh_pct = 80\nlow_pct = 85\n"));
  EXPECT_FALSE(parse_node_config(std::string(kBase) + "[lease]\nttl_s = 50\nmax_s = 5\n"));
  EXPECT_FALSE(parse_node_config(std::string(kBase) + "[retention]\nmax_ttl_s = -1\n"));
  auto def = parse_node_config(kBase);
  ASSERT_TRUE(def);
  EXPECT_EQ(def->server.store.max_ttl, 0s);
  EXPECT_EQ(def->server.store.principal_default.idle_ttl, 1800s);
}

TEST(DynConfig, SighupRejectsAStaticChangeAndKeepsTheSnapshot) {
  auto boot = parse_node_config(std::string(kBase) + "[lease]\nttl_s = 5\n");
  auto fresh_ok = parse_node_config(std::string(kBase) + "[lease]\nttl_s = 8\n[quota]\nput_ops_per_s = 4\n");
  auto fresh_static = parse_node_config(std::string(kBase) + "[lease]\nttl_s = 8\n[node]\nlisten = [\"10.0.0.1:7471\"]\n");
  auto fresh_seg = parse_node_config("[store]\nbacking = \"anon\"\nsegment_bytes = 8388608\nrun_bytes = 262144\nmin_block_bytes = 4096\n");
  ASSERT_TRUE(boot && fresh_ok && fresh_static && fresh_seg);
  const DynConfig cur = dyn_from_server_config(boot->server);
  auto ok = plan_sighup(*boot, *fresh_ok, cur, false);
  ASSERT_TRUE(ok.dyn);
  EXPECT_EQ(ok.dyn->lease_ttl, 8s);
  EXPECT_EQ(ok.dyn->put_ops_per_s, 4u);
  auto st = plan_sighup(*boot, *fresh_static, cur, false);
  EXPECT_FALSE(st.dyn);
  ASSERT_EQ(st.static_changed.size(), 1u);
  EXPECT_EQ(st.static_changed[0], "node.listen");
  auto seg = plan_sighup(*boot, *fresh_seg, cur, false);
  EXPECT_FALSE(seg.dyn);
  EXPECT_EQ(seg.static_changed[0], "store.segment_bytes");
}

// ---- Server: the swap ---------------------------------------------------------------------------------------------
store::StoreConfig store_cfg() {
  store::StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 2;
  c.gen_chunk = 1000;
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 1u << 20;
  c.principal_default.idle_ttl = std::chrono::seconds(10000);
  c.invalidate_per_s = 0;
  return c;
}

struct Fx {
  explicit Fx(const std::function<void(ServerConfig&)>& tweak = {}) : rng(3), net(clock, rng, {}, {}), fab(net.add_node(1)) {
    ServerConfig sc;
    sc.store = store_cfg();
    sc.lab_identity = "spiffe://lab/c";
    if (tweak) tweak(sc);
    auto s = Server::create(sc, fab, clock, rng, exec);
    EXPECT_TRUE(s) << (s ? "" : s.error().context);
    server = std::move(*s);
    self = server->node_id();
  }
  control::BundleView bundle(std::uint64_t gen, const std::string& config_toml, std::uint64_t quota = 1u << 20) {
    control::BundleView v;
    v.body.generation = gen;
    v.body.epoch = static_cast<std::uint32_t>(gen);
    v.sec.sec_generation = gen;
    control::PrincipalView p;
    p.name = "prod";
    p.id = control::principal_id("prod");
    p.identities = {"spiffe://prod/a"};
    p.quota_bytes = quota;
    p.max_scopes = 100;
    v.sec.principals.push_back(p);
    control::NodeView n;
    n.node_id = self;
    n.hostname = "h";
    n.admin = "10.0.0.10:9465";
    n.rails.push_back({"10.0.0.1:7471", "a", "roce"});
    n.weight = 1;
    n.state = control::MemberState::Active;
    v.body.nodes.push_back(n);
    v.body.config_toml = config_toml;
    return v;
  }
  double metric(const std::string& name, const std::string& frag = "") {
    std::string text;
    server->metrics().write_prometheus(text);
    double sum = 0;
    std::size_t pos = 0;
    while (pos < text.size()) {
      auto eol = text.find('\n', pos);
      if (eol == std::string::npos) eol = text.size();
      const std::string line = text.substr(pos, eol - pos);
      pos = eol + 1;
      if (line.rfind(name, 0) != 0 || line.find(frag) == std::string::npos) continue;
      sum += std::stod(line.substr(line.rfind(' ') + 1));
    }
    return sum;
  }
  SimClock clock;
  SeededRandom rng;
  fabric::SimNetwork net;
  fabric::SimFabric& fab;
  InlineExecutor exec;
  std::unique_ptr<Server> server;
  std::uint32_t self = 0;
};

TEST(DynServer, BundleConfigSwapsEveryClassAKeyAtOnce) {
  Fx f;
  ASSERT_TRUE(f.server->dyn());
  EXPECT_EQ(f.server->dyn()->lease_ttl, 30s);
  const std::string toml = "[cluster.memnode.lease]\nttl_s = 4\nmax_s = 40\nput_timeout_s = 11\n"
                           "[cluster.memnode.ticket]\nttl_s = 100\n[cluster.memnode.limits]\nticket_max_per_identity = 7\n"
                           "[cluster.memnode.store]\ninvalidate_per_s = 3\nmax_exact_classes_per_owner = 2\n"
                           "[cluster.memnode.retention]\nidle_ttl_s = 500\nmax_ttl_s = 900\n"
                           "[cluster.memnode.evict]\nsweep_bytes_per_s = 4096\nsweep_blocks_per_turn = 2\nhigh_pct = 80\nlow_pct = 60\n"
                           "[cluster.memnode.quota]\nput_ops_per_s = 9\nput_bytes_per_s = 8192\n";
  f.server->apply_bundle(f.bundle(1, toml));
  const auto lim = f.server->store().limits();
  EXPECT_EQ(lim.lease_ttl, 4s);
  EXPECT_EQ(lim.lease_max, 40s);
  EXPECT_EQ(lim.invalidate_per_s, 3u);
  EXPECT_EQ(lim.def.idle_ttl, 500s);
  EXPECT_EQ(lim.def.put_ops_per_s, 9u);
  EXPECT_EQ(lim.def.put_bytes_per_s, 8192u);
  EXPECT_EQ(f.server->puts().put_timeout(), 11s);
  EXPECT_EQ(f.server->dyn()->generation, 1u);
  EXPECT_EQ(f.server->dyn()->max_ttl, 900s);
  EXPECT_EQ(f.metric("miracache_config_reload_total", "applied"), 1.0);
  EXPECT_EQ(f.metric("miracache_config_generation"), 1.0);
  // A bundle principal's policy follows the new default (idle TTL and put buckets) but keeps its quota cap.
  const auto pid = control::principal_id("prod");
  EXPECT_EQ(f.server->store().policy(pid).idle_ttl, 500s);
  EXPECT_EQ(f.server->store().policy(pid).put_ops_per_s, 9u);
  EXPECT_EQ(f.server->store().policy(pid).max_bytes, f.server->principal_cap_bytes(pid));
  // The next ticket uses the new TTL / per-identity limit.
  auto t = f.server->issue_ticket("spiffe://prod/a", fabric::EpClass::Control, 0, 8);
  ASSERT_FALSE(t);  // 8 > ticket_max_per_identity (7)
  EXPECT_TRUE(f.server->issue_ticket("spiffe://prod/a", fabric::EpClass::Control, 0, 7));
  // Generation 2 drops every key: the start-up values come back.
  f.server->apply_bundle(f.bundle(2, ""));
  EXPECT_EQ(f.server->store().limits().lease_ttl, 30s);
  EXPECT_EQ(f.server->puts().put_timeout(), 10s);
  EXPECT_EQ(f.server->store().policy(pid).put_ops_per_s, 0u);
}

TEST(DynServer, RejectedTableKeepsTheOldSnapshotAndCounts) {
  Fx f;
  f.server->apply_bundle(f.bundle(1, "[cluster.memnode.lease]\nttl_s = 4\n"));
  ASSERT_EQ(f.server->dyn()->lease_ttl, 4s);
  // Normally the admin thread rejects this bundle first; the swap-time check is the second line of defence.
  f.server->apply_bundle(f.bundle(2, "[cluster.memnode.lease]\nttl_s = 9\n[cluster.memnode.store]\nsegment_bytes = 1\n"));
  EXPECT_EQ(f.server->dyn()->lease_ttl, 4s);
  EXPECT_EQ(f.server->store().limits().lease_ttl, 4s);
  EXPECT_EQ(f.metric("miracache_config_reload_total", "rejected"), 1.0);
  EXPECT_EQ(f.server->applied_bundle().generation, 2u);  // membership still moved: only the config part was refused
}

TEST(DynServer, UnknownKeysIgnoredCountedAndNodeOverrideUsed) {
  Fx f;
  f.server->apply_bundle(f.bundle(1, "[cluster.memnode.lease]\nttl_s = 4\nnew_knob = 1\n"
                                     "[node.\"10.0.0.10:9465\".memnode.lease]\nttl_s = 6\n"));
  EXPECT_EQ(f.server->dyn()->lease_ttl, 6s);  // this node's admin address keys the override
  EXPECT_EQ(f.metric("miracache_config_unknown_keys_total"), 1.0);
  EXPECT_EQ(f.metric("miracache_config_reload_total", "rejected"), 0.0);
}

TEST(DynServer, SighupPathAppliesTheSameSnapshotAndOpsSeeItNext) {
  Fx f;
  const std::string base2 = std::string(kBase) + "n_segments = 2\n";  // the bundle node below has 2 x 4 MiB: max_bytes resolves to 8 MiB on both sides
  auto boot = parse_node_config(base2);
  auto fresh = parse_node_config(base2 + "[lease]\nttl_s = 5\nmax_s = 50\n[quota]\nput_ops_per_s = 2\n"
                                                      "[retention]\nidle_ttl_s = 77\n[node]\ndrain_ms = 250\n");
  ASSERT_TRUE(boot && fresh);
  auto plan = plan_sighup(*boot, *fresh, *f.server->dyn(), false);
  ASSERT_TRUE(plan.dyn);
  f.server->apply_dyn(plan.dyn, "sighup");
  EXPECT_EQ(f.server->store().limits().lease_ttl, 5s);
  EXPECT_EQ(f.server->store().limits().def.put_ops_per_s, 2u);
  EXPECT_EQ(f.server->store().limits().def.idle_ttl, 77s);
  EXPECT_EQ(f.server->dyn()->drain_ms, 250u);
  // The same values through a bundle give an identical snapshot.
  Fx g([](ServerConfig& c) { c.store.principal_default.max_bytes = 0; });  // unset: resolved like the file side
  g.server->apply_bundle(g.bundle(1, "[cluster.memnode.lease]\nttl_s = 5\nmax_s = 50\n[cluster.memnode.quota]\nput_ops_per_s = 2\n"
                                     "[cluster.memnode.retention]\nidle_ttl_s = 77\n"
                                     "[cluster.memnode.store]\ninvalidate_per_s = 10\nmax_scopes = 1024\n"));
  EXPECT_EQ(dyn_changed_keys(*f.server->dyn(), *g.server->dyn()), std::vector<std::string>{"node.drain_ms"});  // node-local only
  EXPECT_EQ(f.metric("miracache_config_reload_total", "applied"), 1.0);
}

// A ServerConfig with max_bytes == 0 is resolved by Server::create to this node's n_segments x segment_bytes, in the
// snapshot, the store's default policy and the principal cap (never 0).
TEST(DynServer, UnsetMaxBytesResolvesToTheBackingSize) {
  Fx f([](ServerConfig& c) { c.store.principal_default.max_bytes = 0; });
  const std::uint64_t backing = std::uint64_t{2} * (4u << 20);
  EXPECT_EQ(f.server->dyn()->max_bytes, backing);
  EXPECT_EQ(f.server->store().limits().def.max_bytes, backing);
}

// Under tsan: the admin and metrics threads read dyn() while the store thread swaps it.
TEST(DynServer, SnapshotIsReadableFromOtherThreadsWhileTheStoreThreadSwaps) {
  Fx f;
  std::atomic<bool> stop{false};
  std::atomic<std::uint64_t> reads{0};
  std::thread reader([&] {
    while (!stop.load()) {
      auto d = f.server->dyn();
      // Every snapshot is internally consistent: lease_max >= lease_ttl whichever generation it is.
      EXPECT_GE(d->lease_max, d->lease_ttl);
      reads.fetch_add(1);
    }
  });
  for (int i = 1; i <= 200; ++i) {
    const std::string ttl = std::to_string(1 + i % 20);
    f.server->apply_bundle(f.bundle(static_cast<std::uint64_t>(i), "[cluster.memnode.lease]\nttl_s = " + ttl + "\nmax_s = 100\n"));
  }
  stop = true;
  reader.join();
  EXPECT_GT(reads.load(), 0u);
  EXPECT_EQ(f.server->dyn()->generation, 200u);
}

TEST(DynServer, ClassBNodeLocalKeysArePendingNotApplied) {
  Fx f;
  f.server->apply_bundle(f.bundle(1, "[cluster.memnode.admin]\nlisten = \"0.0.0.0:1\"\n[cluster.memnode.telemetry]\nlisten = \"x\"\n"));
  EXPECT_EQ(f.server->dyn()->pending.size(), 2u);
  EXPECT_EQ(f.metric("miracache_config_pending_keys"), 2.0);
  EXPECT_EQ(f.metric("miracache_config_reload_total", "rejected"), 0.0);
}

// Limits.max_conns_per_principal not set -> 16 sessions x rails x (2 + fetch_qps), computed by the node.
TEST(DynConfig, DefaultMaxConnsIsComputedFromRailsAndProfile) {
  EXPECT_EQ(default_max_conns(1, 4), 96u);   // mlx5, one rail: 16 x 1 x 6
  EXPECT_EQ(default_max_conns(2, 4), 192u);  // two rails
  EXPECT_EQ(default_max_conns(2, 8), 320u);  // 16 x 2 x 10
  EXPECT_EQ(default_max_conns(0, 1), 48u);   // no rail list = one default listener
}

TEST(DynServer, UnsetMaxConnsResolvesAtCreateAndAnExplicitValueWins) {
  Fx one;  // ServerConfig{} leaves it 0 (unset): one default listener, fetch_qps 1 -> 16 x 1 x 3
  EXPECT_EQ(one.server->dyn()->max_conns_per_principal, default_max_conns(1, 1));
  Fx two([](ServerConfig& c) {
    c.rails = {fabric::RailAddr{"10.0.0.1", 7471}, fabric::RailAddr{"10.0.0.2", 7471}};
    c.fetch_qps = 4;
  });
  EXPECT_EQ(two.server->dyn()->max_conns_per_principal, 192u);
  Fx fixed([](ServerConfig& c) { c.max_conns_per_principal = 7; });
  EXPECT_EQ(fixed.server->dyn()->max_conns_per_principal, 7u);
}

// Limits.ticket_max_per_identity not set -> max(1024, 16 sessions x rails x (32 + 4 x max(4, fetch_qps))), the
// per-rail ticket inventory (2 x the cache caps of control, ingest and fetch at ticket_batch 4) for 16 sessions.
TEST(DynConfig, DefaultTicketMaxIsComputedFromRailsAndProfile) {
  EXPECT_EQ(default_ticket_max(1, 4), 1024u);   // 16 x 1 x 48 = 768: the floor
  EXPECT_EQ(default_ticket_max(1, 1), 1024u);   // fetch need below ticket_batch: as 4
  EXPECT_EQ(default_ticket_max(2, 4), 1536u);   // 16 x 2 x 48
  EXPECT_EQ(default_ticket_max(2, 16), 3072u);  // 16 x 2 x 96
  EXPECT_EQ(default_ticket_max(4, 16), 6144u);  // 16 x 4 x 96
  EXPECT_EQ(default_ticket_max(0, 16), 1536u);  // no rail list = one default listener
  EXPECT_EQ(default_ticket_max(4, 1000), default_ticket_max(4, 64));  // fetch need is clamped to 64 like the client
  // Each value covers 16 sessions of the client's worst case per rail: 2 x (2 x max(4,1) x 2 + 2 x max(4, q)).
  for (std::uint32_t q : {1u, 4u, 8u, 16u, 64u})
    for (std::size_t r : {std::size_t{1}, std::size_t{2}, std::size_t{4}}) {
      const std::uint64_t per_rail = 2 * (8 + 8 + 2 * std::max<std::uint64_t>(4, q));
      EXPECT_GE(default_ticket_max(r, q), 16 * r * per_rail) << "rails " << r << " fetch_qps " << q;
    }
}

TEST(DynServer, UnsetTicketMaxResolvesAtCreateAndAnExplicitValueWins) {
  Fx one;  // ServerConfig{} leaves it 0 (unset)
  EXPECT_EQ(one.server->dyn()->ticket_max_per_identity, default_ticket_max(1, 1));
  Fx two([](ServerConfig& c) {
    c.rails = {fabric::RailAddr{"10.0.0.1", 7471}, fabric::RailAddr{"10.0.0.2", 7471}};
    c.fetch_qps = 16;
  });
  EXPECT_EQ(two.server->dyn()->ticket_max_per_identity, 3072u);
  Fx fixed([](ServerConfig& c) { c.ticket_max_per_identity = 7; });
  EXPECT_EQ(fixed.server->dyn()->ticket_max_per_identity, 7u);
  // Lab SIGHUP of a file without the key keeps the computed default (not 0).
  auto boot = parse_node_config(kBase);
  ASSERT_TRUE(boot) << boot.error().context;
  EXPECT_EQ(boot->server.ticket_max_per_identity, 0u);
  const DynConfig cur = *one.server->dyn();
  auto p = plan_sighup(*boot, *boot, cur, false, 0, 1536);
  ASSERT_TRUE(p.dyn);
  EXPECT_EQ(p.dyn->ticket_max_per_identity, 1536u);
  auto keep = plan_sighup(*boot, *boot, cur, false);
  ASSERT_TRUE(keep.dyn);
  EXPECT_EQ(keep.dyn->ticket_max_per_identity, cur.ticket_max_per_identity);
}

// Rails, the admin.ca path and store.scope_records are STATIC; a SIGHUP that changes them keeps the snapshot.
TEST(DynConfig, SighupRefusesRailsAdminCaPathAndScopeRecordsChanges) {
  const std::string rails = std::string(kBase) + "[[node.rails]]\ndevice = \"d0\"\nlisten = \"10.0.0.1:7471\"\nsubnet = \"a\"\n";
  const std::string rails_dev = std::string(kBase) + "[[node.rails]]\ndevice = \"d1\"\nlisten = \"10.0.0.1:7471\"\nsubnet = \"a\"\n";
  const std::string rails_sub = std::string(kBase) + "[[node.rails]]\ndevice = \"d0\"\nlisten = \"10.0.0.1:7471\"\nsubnet = \"b\"\n";
  auto boot = parse_node_config(rails);
  ASSERT_TRUE(boot) << boot.error().context;
  const DynConfig cur = dyn_from_server_config(boot->server);
  for (const std::string* changed : {&rails_dev, &rails_sub}) {
    auto fresh = parse_node_config(*changed);
    ASSERT_TRUE(fresh);
    auto p = plan_sighup(*boot, *fresh, cur, false);
    EXPECT_FALSE(p.dyn);
    EXPECT_NE(std::find(p.static_changed.begin(), p.static_changed.end(), "node.rails"), p.static_changed.end());
  }
  const std::string admin = "[admin]\nlisten = \"127.0.0.1:1\"\ncert = \"/c\"\nkey = \"/k\"\nca = \"";
  auto a1 = parse_node_config(std::string(kBase) + admin + "/ca1\"\n");
  auto a2 = parse_node_config(std::string(kBase) + admin + "/ca2\"\n");
  ASSERT_TRUE(a1 && a2);
  auto same = plan_sighup(*a1, *a1, dyn_from_server_config(a1->server), false);
  EXPECT_TRUE(same.dyn);  // the contents of the same path reload
  auto ca = plan_sighup(*a1, *a2, dyn_from_server_config(a1->server), false);
  EXPECT_FALSE(ca.dyn);
  ASSERT_EQ(ca.static_changed.size(), 1u);
  EXPECT_EQ(ca.static_changed[0], "admin.ca");
  // store.scope_records is accepted in the node file (STATIC; 0 = auto).
  const std::string store1 = "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\nscope_records = 1024\n";
  const std::string store2 = "[store]\nbacking = \"anon\"\nsegment_bytes = 4194304\nrun_bytes = 262144\nmin_block_bytes = 4096\nscope_records = 2048\n";
  auto s1 = parse_node_config(store1);
  auto s2 = parse_node_config(store2);
  ASSERT_TRUE(s1 && s2);
  EXPECT_EQ(s1->server.store.scope_records, 1024u);
  auto sr = plan_sighup(*s1, *s2, dyn_from_server_config(s1->server), false);
  EXPECT_FALSE(sr.dyn);
  ASSERT_EQ(sr.static_changed.size(), 1u);
  EXPECT_EQ(sr.static_changed[0], "store.scope_records");
}

// A SIGHUP whose file does not set the key keeps the node's computed default, not 0.
TEST(DynConfig, SighupWithoutMaxConnsKeepsTheComputedDefault) {
  auto boot = parse_node_config(kBase);
  ASSERT_TRUE(boot);
  DynConfig cur = dyn_from_server_config(boot->server);
  cur.max_conns_per_principal = 192;
  EXPECT_EQ(plan_sighup(*boot, *boot, cur, false, 192).dyn->max_conns_per_principal, 192u);
  EXPECT_EQ(plan_sighup(*boot, *boot, cur, false).dyn->max_conns_per_principal, 192u);
  auto set = parse_node_config(std::string(kBase) + "[limits]\nmax_conns_per_principal = 5\n");
  ASSERT_TRUE(set);
  EXPECT_EQ(plan_sighup(*boot, *set, cur, false, 192).dyn->max_conns_per_principal, 5u);
}

// put_timeout >= 4 x deadline.put_max_ms, from the same bundle (client default 2500 ms).
TEST(DynConfig, PutTimeoutMustCoverFourPutMaxMs) {
  auto ok = parse_memnode_dyn("[cluster.memnode.lease]\nput_timeout_s = 10\n", base(), "", 1);
  EXPECT_TRUE(ok.dyn) << ok.error;
  auto low = parse_memnode_dyn("[cluster.memnode.lease]\nput_timeout_s = 9\n", base(), "", 1);
  EXPECT_FALSE(low.dyn);
  EXPECT_NE(low.error.find("put_timeout_s must be >= 4 x client deadline.put_max_ms"), std::string::npos) << low.error;
  auto big = parse_memnode_dyn("[cluster.memnode.lease]\nput_timeout_s = 10\n[cluster.client.deadline]\nput_max_ms = 5000\n", base(), "", 1);
  EXPECT_FALSE(big.dyn);
  auto both = parse_memnode_dyn("[cluster.memnode.lease]\nput_timeout_s = 20\n[cluster.client.deadline]\nput_max_ms = 5000\n", base(), "", 1);
  EXPECT_TRUE(both.dyn) << both.error;
}

}  // namespace
}  // namespace miracache::server
