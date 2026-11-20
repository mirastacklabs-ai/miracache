// SPDX-License-Identifier: Apache-2.0
#include "miracache/config.h"

#include <gtest/gtest.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <string>

namespace miracache {
namespace {

const char* kValid = R"([scope]
provider = "static"
secret_file = "/etc/miracache/secret"

[[nodes]]
rails = ["10.0.0.1:7471", "10.0.1.1:7471"]

[[nodes]]
rails = ["10.0.0.2:7471"]

[fabric]
protocol = "roce"

[landing]
subpool_bytes = 8388608

[crypto]
workers = 8

[lab]
static_membership = true
)";

// Valid text with one substring replaced.
std::string with(const std::string& from, const std::string& to) {
  std::string s = kValid;
  auto p = s.find(from);
  EXPECT_NE(p, std::string::npos) << from;
  s.replace(p, from.size(), to);
  return s;
}

void expect_invalid(const std::string& toml, const char* ctx_part) {
  auto r = load_config(toml);
  ASSERT_FALSE(r.has_value()) << toml;
  EXPECT_NE(std::strstr(r.error().context, ctx_part), nullptr) << r.error().context;
}

TEST(Config, ValidFull) {
  auto r = load_config(kValid);
  ASSERT_TRUE(r.has_value()) << r.error().context;
  EXPECT_EQ(r->provider, ScopeProviderKind::Static);
  EXPECT_EQ(r->secret_file, "/etc/miracache/secret");
  ASSERT_EQ(r->nodes.size(), 2u);
  EXPECT_EQ(r->nodes[0].rails.size(), 2u);
  EXPECT_EQ(r->nodes[0].rails[1], "10.0.1.1:7471");
  EXPECT_EQ(r->protocol, FabricProtocol::Roce);
  EXPECT_EQ(r->subpool_bytes, 8388608u);
  EXPECT_EQ(r->crypto_workers, 8u);
  EXPECT_TRUE(r->static_membership);
}

TEST(Config, DefaultsApply) {
  auto r = load_config(
      "[scope]\nsecret_file = \"/s\"\n[[nodes]]\nrails = [\"a:1\"]\n"
      "[lab]\nstatic_membership = true\n");
  ASSERT_TRUE(r.has_value()) << r.error().context;
  EXPECT_EQ(r->provider, ScopeProviderKind::Static);
  EXPECT_EQ(r->protocol, FabricProtocol::Auto);
  EXPECT_EQ(r->subpool_bytes, 64u << 20);
  EXPECT_EQ(r->crypto_workers, 4u);
}

TEST(Config, KeepaliveMs) {
  const std::string base = "[scope]\nsecret_file = \"/s\"\n[[nodes]]\nrails = [\"a:1\"]\n"
                           "[lab]\nstatic_membership = true\n[fabric]\n";
  auto d = load_config("[scope]\nsecret_file = \"/s\"\n[[nodes]]\nrails = [\"a:1\"]\n[lab]\nstatic_membership = true\n");
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->keepalive_ms, 1000u);
  // R03: 0 would switch off PING and reconnect for a wire client.
  auto off = load_config(base + "keepalive_ms = 0\n");
  ASSERT_FALSE(off.has_value());
  EXPECT_NE(std::string(off.error().context).find("keepalive_ms = 0"), std::string::npos) << off.error().context;
  // R01: reconnect connect timeout.
  EXPECT_EQ(d->reconnect_connect_ms, 1000u);
  auto rc = load_config(base + "reconnect_connect_ms = 250\n");
  ASSERT_TRUE(rc.has_value());
  EXPECT_EQ(rc->reconnect_connect_ms, 250u);
  for (const char* bad : {"reconnect_connect_ms = 0\n", "reconnect_connect_ms = 60001\n"})
    EXPECT_FALSE(load_config(base + bad).has_value()) << bad;
  // N04: watchdog grace override; unset (0) = derived from the QP retry exhaustion.
  EXPECT_EQ(d->watchdog_grace_ms, 0u);
  auto wg = load_config(base + "watchdog_grace_ms = 30000\n");
  ASSERT_TRUE(wg.has_value());
  EXPECT_EQ(wg->watchdog_grace_ms, 30000u);
  for (const char* bad : {"watchdog_grace_ms = 0\n", "watchdog_grace_ms = 600001\n", "watchdog_grace_ms = \"x\"\n"})
    EXPECT_FALSE(load_config(base + bad).has_value()) << bad;
  auto v = load_config(base + "keepalive_ms = 250\n");
  ASSERT_TRUE(v.has_value());
  EXPECT_EQ(v->keepalive_ms, 250u);
  for (const char* bad : {"keepalive_ms = 5\n", "keepalive_ms = -1\n", "keepalive_ms = 600001\n", "keepalive_ms = \"1\"\n"})
    EXPECT_FALSE(load_config(base + bad).has_value()) << bad;
}

TEST(Config, MtuAndReconnectBackoff) {
  const std::string base = "[scope]\nsecret_file = \"/s\"\n[[nodes]]\nrails = [\"a:1\"]\n"
                           "[lab]\nstatic_membership = true\n[fabric]\n";
  auto d = load_config(base + "protocol = \"auto\"\n");
  ASSERT_TRUE(d.has_value()) << d.error().context;
  EXPECT_EQ(d->mtu, 4096u);
  EXPECT_EQ(d->reconnect_min_ms, 100u);
  EXPECT_EQ(d->reconnect_max_ms, 5000u);
  auto v = load_config(base + "mtu = 1024\nreconnect_min_ms = 50\nreconnect_max_ms = 800\n");
  ASSERT_TRUE(v.has_value()) << v.error().context;
  EXPECT_EQ(v->mtu, 1024u);
  EXPECT_EQ(v->reconnect_min_ms, 50u);
  EXPECT_EQ(v->reconnect_max_ms, 800u);
  for (const char* bad : {"mtu = 1500\n", "mtu = \"4096\"\n", "reconnect_min_ms = 0\n", "reconnect_max_ms = 50\n",
                          "reconnect_min_ms = 200\nreconnect_max_ms = 100\n", "reconnect_max_ms = 600001\n"})
    EXPECT_FALSE(load_config(base + bad).has_value()) << bad;
}

TEST(Config, NicProfileKeysOverrideTheProfile) {
  const std::string base = "[scope]\nsecret_file = \"/s\"\n[[nodes]]\nrails = [\"a:1\"]\n"
                           "[lab]\nstatic_membership = true\n[fabric]\n";
  auto d = load_config(base + "protocol = \"auto\"\n");
  ASSERT_TRUE(d.has_value()) << d.error().context;
  EXPECT_FALSE(d->mtu_explicit);  // unset: the profile decides
  EXPECT_FALSE(d->read_depth.has_value());
  EXPECT_TRUE(d->profiles_file.empty());
  auto v = load_config(base + "mtu = 1024\nread_depth = 8\ninline_bytes = 64\nack_timeout_exp = 14\nretry_count = 3\n"
                              "rnr_retry_count = 5\nprofiles_file = \"/etc/miracache/p.toml\"\n");
  ASSERT_TRUE(v.has_value()) << v.error().context;
  EXPECT_TRUE(v->mtu_explicit);
  EXPECT_EQ(*v->read_depth, 8u);
  EXPECT_EQ(*v->inline_bytes, 64u);
  EXPECT_EQ(*v->ack_timeout_exp, 14);
  EXPECT_EQ(*v->retry_count, 3);
  EXPECT_EQ(*v->rnr_retry_count, 5);
  EXPECT_EQ(v->profiles_file, "/etc/miracache/p.toml");
  for (const char* bad : {"read_depth = 0\n", "read_depth = 256\n", "inline_bytes = 257\n", "ack_timeout_exp = 0\n",
                          "ack_timeout_exp = 20\n", "retry_count = 8\n", "rnr_retry_count = 7\n", "read_depth = \"8\"\n",
                          "profiles_file = \"\"\n", "profiles_file = 3\n"})
    EXPECT_FALSE(load_config(base + bad).has_value()) << bad;
}

TEST(Config, TextDetection) {
  // Leading '[' without newline is text (a syntax error here), not a path.
  auto r = load_config("[scope");
  ASSERT_FALSE(r.has_value());
  EXPECT_NE(std::strstr(r.error().context, "syntax"), nullptr);
  // A plain string is a path.
  auto p = load_config("/nonexistent/client.toml");
  ASSERT_FALSE(p.has_value());
  EXPECT_EQ(p.error().code, ErrorCode::NotFound);
}

TEST(Config, SyntaxError) { expect_invalid("[scope\nx=", "syntax"); }

TEST(Config, UnknownKeys) {
  expect_invalid(std::string(kValid) + "\n[extra]\na = 1\n", "unknown key");
  expect_invalid(with("workers = 8", "workers = 8\nworkerz = 1"), "unknown key");
  expect_invalid(with("protocol = \"roce\"", "protocol = \"roce\"\nprotocl = 1"), "unknown key");
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"10.0.0.2:7471\"]\nrail = 1"),
                 "unknown key");
  expect_invalid(with("provider = \"static\"", "provider = \"static\"\nsecret = \"x\""), "unknown key");
  expect_invalid(with("static_membership = true", "static_membership = true\nx = 1"), "unknown key");
  expect_invalid(with("subpool_bytes = 8388608", "subpool_bytes = 8388608\nq = 1"), "unknown key");
}

TEST(Config, Workers) {
  for (const char* v : {"0", "65", "-1"})
    expect_invalid(with("workers = 8", std::string("workers = ") + v), "crypto.workers");
  for (const char* v : {"1", "64"}) {
    auto r = load_config(with("workers = 8", std::string("workers = ") + v));
    EXPECT_TRUE(r.has_value()) << v;
  }
  expect_invalid(with("workers = 8", "workers = \"8\""), "crypto.workers");
}

TEST(Config, SubpoolBytes) {
  expect_invalid(with("8388608", "1048576000000000"), "subpool_bytes");  // > 64 GiB
  expect_invalid(with("8388608", "1044480"), "subpool_bytes");           // < 1 MiB
  expect_invalid(with("8388608", "0"), "subpool_bytes");
  expect_invalid(with("8388608", "-4096"), "subpool_bytes");
}

TEST(Config, SubpoolBoundsAndAlign) {
  EXPECT_TRUE(load_config(with("8388608", "1048576")).has_value());
  EXPECT_TRUE(load_config(with("8388608", "1052672")).has_value());  // 1 MiB + 4 KiB
  EXPECT_TRUE(load_config(with("8388608", "68719476736")).has_value());  // 64 GiB
  expect_invalid(with("8388608", "1048577"), "multiple of 4096");
  expect_invalid(with("8388608", "2000000"), "multiple of 4096");
}

TEST(Config, Protocol) {
  for (const char* v : {"auto", "roce", "iwarp"})
    EXPECT_TRUE(load_config(with("\"roce\"", std::string("\"") + v + "\"")).has_value()) << v;
  expect_invalid(with("\"roce\"", "\"tcp\""), "fabric.protocol");
  expect_invalid(with("\"roce\"", "\"ROCE\""), "fabric.protocol");
  expect_invalid(with("\"roce\"", "1"), "fabric.protocol");
}

TEST(Config, Provider) {
  expect_invalid(with("provider = \"static\"", "provider = \"gateway\""), "scope.provider");
  expect_invalid(with("provider = \"static\"", "provider = 3"), "scope.provider");
}

TEST(Config, ScopeRequired) {
  expect_invalid("[lab]\nstatic_membership = true\n", "[scope] is required");
  expect_invalid("[scope]\nprovider = \"static\"\n", "secret_file is required");
  expect_invalid(with("\"/etc/miracache/secret\"", "\"\""), "secret_file");
}

TEST(Config, NodeWeight) {
  auto r = load_config(kValid);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r->nodes[0].weight, 1u);  // default
  EXPECT_EQ(r->nodes[1].weight, 1u);
  auto w = load_config(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"10.0.0.2:7471\"]\nweight = 3"));
  ASSERT_TRUE(w.has_value()) << w.error().context;
  EXPECT_EQ(w->nodes[1].weight, 3u);
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"10.0.0.2:7471\"]\nweight = 0"), "nodes.weight");
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"10.0.0.2:7471\"]\nweight = -1"), "nodes.weight");
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"10.0.0.2:7471\"]\nweight = 1.5"), "nodes.weight");
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"10.0.0.2:7471\"]\nweight = \"2\""), "nodes.weight");
}

TEST(Config, Nodes) {
  // Plan 2C: nodes[].id was removed; any value (even a valid one) is the stale-key error.
  for (const char* v : {"1", "0", "4294967296", "\"b\""})
    expect_invalid(with("rails = [\"10.0.0.2:7471\"]", std::string("id = ") + v + "\nrails = [\"10.0.0.2:7471\"]"),
                   "node id was removed; node IDs are assigned automatically");
  // The same address on two nodes (or twice on one) is a config error.
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"10.0.0.1:7471\"]"), "duplicate nodes.rails address");
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"10.0.0.2:7471\", \"10.0.0.2:7471\"]"),
                 "duplicate nodes.rails address");
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = []"), "rails");
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [\"\"]"), "rails");
  expect_invalid(with("rails = [\"10.0.0.2:7471\"]", "rails = [1]"), "rails");
  expect_invalid("[scope]\nsecret_file = \"/s\"\n[lab]\nstatic_membership = true\n", "[[nodes]]");
}

TEST(Config, LabMode) {
  auto r = load_config(with("static_membership = true", "static_membership = false"));
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, ErrorCode::Unsupported);
  auto r2 = load_config("[scope]\nsecret_file = \"/s\"\n[[nodes]]\nrails=[\"a\"]\n");
  ASSERT_FALSE(r2.has_value());
  EXPECT_EQ(r2.error().code, ErrorCode::Unsupported);
  expect_invalid(with("static_membership = true", "static_membership = 1"), "lab.static_membership");
}

// ---- File loading and the secret-file mode check ----------------------------------------

struct TmpDir {
  std::string dir;
  TmpDir() {
    char t[] = "/tmp/mira_cfg_XXXXXX";
    dir = ::mkdtemp(t);
  }
  ~TmpDir() {
    std::string cmd = "rm -rf '" + dir + "'";
    int rc = std::system(cmd.c_str());
    (void)rc;
  }
  std::string write(const std::string& name, const std::string& body, mode_t mode) {
    std::string p = dir + "/" + name;
    { std::ofstream(p, std::ios::binary) << body; }
    ::chmod(p.c_str(), mode);
    return p;
  }
};

std::string cfg_for(const std::string& secret) {
  return "[scope]\nprovider = \"static\"\nsecret_file = \"" + secret +
         "\"\n[[nodes]]\nrails = [\"a:1\"]\n[lab]\nstatic_membership = true\n";
}

TEST(ConfigFile, LoadsFromPathWithSecret0600) {
  TmpDir d;
  std::string secret = d.write("secret", std::string(32, 'x'), 0600);
  std::string cfg = d.write("client.toml", cfg_for(secret), 0644);
  auto r = load_config(cfg);
  ASSERT_TRUE(r.has_value()) << r.error().context;
  EXPECT_EQ(r->secret_file, secret);
}

TEST(ConfigFile, SecretModeChecked) {
  TmpDir d;
  for (mode_t m : {mode_t{0644}, mode_t{0640}, mode_t{0660}, mode_t{0604}, mode_t{0400}, mode_t{0700}}) {
    std::string secret = d.write("secret", "k", m);
    auto s = check_secret_file(secret);
    ASSERT_FALSE(s.has_value()) << std::oct << m;
    EXPECT_EQ(s.error().code, ErrorCode::AccessDenied);
    std::string cfg = d.write("client.toml", cfg_for(secret), 0600);
    auto r = load_config(cfg);
    ASSERT_FALSE(r.has_value()) << std::oct << m;
    EXPECT_EQ(r.error().code, ErrorCode::AccessDenied);
  }
  std::string secret = d.write("secret", "k", 0600);
  EXPECT_TRUE(check_secret_file(secret).has_value());
}

TEST(ConfigFile, SecretMissingOrNotRegular) {
  TmpDir d;
  std::string cfg = d.write("client.toml", cfg_for(d.dir + "/nope"), 0600);
  auto r = load_config(cfg);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().code, ErrorCode::NotFound);
  auto s = check_secret_file(d.dir);  // a directory
  ASSERT_FALSE(s.has_value());
  EXPECT_EQ(s.error().code, ErrorCode::InvalidArgument);
}

TEST(ConfigFile, TomlTextSkipsFilesystemChecks) {
  // Same nonexistent secret path is fine for inline TOML.
  EXPECT_TRUE(load_config(cfg_for("/does/not/exist")).has_value());
}


// A2.10 [placement]
std::string with_nodes(int n, const std::string& placement) {
  std::string s = "[scope]\nprovider = \"static\"\nsecret_file = \"/s\"\n";
  for (int i = 1; i <= n; ++i) s += "[[nodes]]\nrails = [\"10.0.0." + std::to_string(i) + ":7471\"]\n";
  return s + placement + "[lab]\nstatic_membership = true\n";
}

TEST(ConfigPlacement, DefaultsAndValid) {
  auto d = load_config(kValid);
  ASSERT_TRUE(d.has_value());
  EXPECT_EQ(d->replicas, 1u);
  EXPECT_EQ(d->replica_mode, ReplicaMode::Async);
  EXPECT_EQ(d->replica_buffer_bytes, 256ull << 20);
  auto r = load_config(with_nodes(3, "[placement]\nreplicas = 2\nreplica_mode = \"sync\"\nreplica_buffer_bytes = 0\n"));
  ASSERT_TRUE(r.has_value()) << r.error().context;
  EXPECT_EQ(r->replicas, 2u);
  EXPECT_EQ(r->replica_mode, ReplicaMode::Sync);
  EXPECT_EQ(r->replica_buffer_bytes, 0u);
  auto r3 = load_config(with_nodes(4, "[placement]\nreplicas = 3\nreplica_mode = \"async\"\nreplica_buffer_bytes = 1048576\n"));
  ASSERT_TRUE(r3.has_value()) << r3.error().context;
  EXPECT_EQ(r3->replicas, 3u);
  EXPECT_EQ(r3->replica_mode, ReplicaMode::Async);
  EXPECT_EQ(r3->replica_buffer_bytes, 1048576u);
  EXPECT_TRUE(load_config(with_nodes(2, "[placement]\nreplicas = 1\n")).has_value());  // R=1 on any node count
}

TEST(ConfigPlacement, Errors) {
  expect_invalid(with_nodes(3, "[placement]\nreplicas = 4\n"), "placement.replicas must be 1..3");
  expect_invalid(with_nodes(3, "[placement]\nreplicas = 0\n"), "placement.replicas must be 1..3");
  expect_invalid(with_nodes(3, "[placement]\nreplicas = \"2\"\n"), "placement.replicas must be an integer");
  expect_invalid(with_nodes(2, "[placement]\nreplicas = 2\n"), "replicas = 2 needs at least 3");
  expect_invalid(with_nodes(3, "[placement]\nreplicas = 3\n"), "replicas = 3 needs at least 4");
  expect_invalid(with_nodes(3, "[placement]\nreplica_mode = \"fast\"\n"), "replica_mode must be \"async\" or \"sync\"");
  expect_invalid(with_nodes(3, "[placement]\nreplica_mode = 1\n"), "replica_mode must be a string");
  expect_invalid(with_nodes(3, "[placement]\nreplica_buffer_bytes = -1\n"), "replica_buffer_bytes must be 0..2^40");
  expect_invalid(with_nodes(3, "[placement]\nreplica_buffer_bytes = \"1\"\n"), "replica_buffer_bytes must be an integer");
  expect_invalid(with_nodes(3, "[placement]\nreplica_grace_ms = 10\n"), "unknown key");  // removed, never released
  expect_invalid(with_nodes(3, "[placement]\nreplicass = 2\n"), "unknown key");
}

std::string with_zones(const std::vector<std::string>& zones, const std::string& placement) {
  std::string s = "[scope]\nprovider = \"static\"\nsecret_file = \"/s\"\n";
  for (std::size_t i = 0; i < zones.size(); ++i) {
    s += "[[nodes]]\nrails = [\"10.0.0." + std::to_string(i + 1) + ":7471\"]\n";
    if (!zones[i].empty()) s += "zone = \"" + (zones[i] == "-" ? std::string() : zones[i]) + "\"\n";
  }
  return s + placement + "[lab]\nstatic_membership = true\n";
}

TEST(ConfigZones, ParsedAndValidated) {
  auto c = load_config(with_zones({"rack-1", "rack.2_b", "A3"}, "[placement]\nreplicas = 2\n"));
  ASSERT_TRUE(c.has_value()) << c.error().context;
  EXPECT_EQ(c->nodes[0].zone, "rack-1");
  EXPECT_EQ(c->nodes[1].zone, "rack.2_b");
  EXPECT_EQ(c->nodes[2].zone, "A3");
  auto none = load_config(with_nodes(3, "[placement]\nreplicas = 2\n"));
  ASSERT_TRUE(none.has_value());
  EXPECT_TRUE(none->nodes[0].zone.empty());
  EXPECT_TRUE(load_config(with_zones({"a", "a", "a"}, "")).has_value());  // R=1: zones do not matter
  expect_invalid(with_zones({"a", "b", ""}, ""), "zone must be set on every node or on none");
  expect_invalid(with_zones({"a", "a", "a"}, "[placement]\nreplicas = 2\n"), "replicas=2 needs nodes in at least 2 zones");
  expect_invalid(with_zones({"a", "a", "b", "b"}, "[placement]\nreplicas = 3\n"), "replicas=3 needs nodes in at least 3 zones");
  expect_invalid(with_zones({"a", "-", "b"}, ""), "nodes.zone must be 1..64");           // empty string
  expect_invalid(with_zones({"a b", "b", "c"}, ""), "nodes.zone must be 1..64");         // space
  expect_invalid(with_zones({"a/b", "b", "c"}, ""), "nodes.zone must be 1..64");         // slash
  expect_invalid(with_zones({std::string(65, 'z'), "b", "c"}, ""), "nodes.zone must be 1..64");
  EXPECT_TRUE(load_config(with_zones({std::string(64, 'z'), "b", "c"}, "")).has_value());
}
}  // namespace
}  // namespace miracache
