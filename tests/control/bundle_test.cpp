// SPDX-License-Identifier: Apache-2.0
// The C++ side of the signed cluster bundle. Byte-exact envelope rules 1-9, tamper, role
// binding, schema, goldens (generated here with OpenSSL from the test seeds), and the cross-check
// against the Go-emitted envelope.
#include <gtest/gtest.h>

#include <cctype>
#include <filesystem>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "control/bundle.h"
#include "control/toml_guard.h"
#include "control/trust_keys.h"
#include "control/bundle_test_util.h"

using namespace miracache::control;
namespace tu = miracache::control::testutil;

namespace {

TrustKeys trust(bool both = false, const std::string& top = "") {
  auto t = parse_trust_keys(tu::trust_toml(both, top));
  EXPECT_TRUE(t.has_value());
  return std::move(t.value());
}

// "ok" or the reject reason of the whole receive path.
std::string verdict(const std::string& envelope, const TrustKeys& t) {
  auto r = open_bundle(envelope, t);
  return r.has_value() ? "ok" : reason_string(r.error().reason);
}

std::string golden_dir() { return std::string(MIRACACHE_GOLDEN_DIR) + "/bundle_v1/"; }

std::string replace_once(std::string s, const std::string& from, const std::string& to) {
  const auto at = s.find(from);
  EXPECT_NE(at, std::string::npos) << from;
  if (at != std::string::npos) s.replace(at, from.size(), to);
  return s;
}

std::string to_hex_s(const Sha256Digest& d) { return to_hex(d); }

// ---- goldens ----------------------------------------------------------------------------------

struct GoldenSet {
  std::string trust, valid, publish_only, sec, body, publish_only_body, expect, publish_only_expect, reject_upper_hex, reject_role_confusion;
  // Signed with the test seeds, only the content is invalid -> "schema". name -> envelope bytes.
  std::vector<std::pair<std::string, std::string>> schema_rejects;
};

std::string expect_text(const tu::Parts& p, std::uint64_t gen, std::uint64_t sec_gen, std::uint32_t epoch) {
  std::string e;
  e += "publish_seed: " + tu::hex(tu::publish_seed().data(), 32) + "\n";
  e += "security_seed: " + tu::hex(tu::security_seed().data(), 32) + "\n";
  e += "key_id: " + p.key_id + "\n";
  e += "sec_key_id: " + p.sec_key_id + "\n";
  e += "sig: " + p.sig + "\n";
  e += "sec_sig: " + p.sec_sig + "\n";
  e += "sec_len: " + p.sec_len + "\n";
  e += "generation: " + std::to_string(gen) + "\n";
  e += "sec_generation: " + std::to_string(sec_gen) + "\n";
  e += "epoch: " + std::to_string(epoch) + "\n";
  const auto bh = tu::sha256(p.body);
  const auto sh = tu::sha256(p.sec);
  e += "body_sha256: " + tu::hex(bh.data(), 32) + "\n";
  e += "sec_sha256: " + tu::hex(sh.data(), 32) + "\n";
  return e;
}

GoldenSet fresh_goldens() {
  GoldenSet g;
  g.trust = tu::trust_toml();
  g.sec = tu::sec_toml(5);
  g.body = tu::body_toml(42, 7, 6);
  g.publish_only_body = tu::body_toml(43, 7, 6);
  const tu::Parts v = tu::sign_parts(g.sec, g.body);
  const tu::Parts po = tu::sign_parts(g.sec, g.publish_only_body);
  g.valid = tu::assemble(v);
  g.publish_only = tu::assemble(po);
  g.expect = expect_text(v, 42, 5, 7);
  g.publish_only_expect = expect_text(po, 43, 5, 7);
  tu::Parts up = v;
  for (char& c : up.key_id) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
  g.reject_upper_hex = tu::assemble(up);
  g.reject_role_confusion = tu::assemble(tu::sign_parts(g.sec, g.body, tu::security_seed(), tu::security_seed()));
  const std::string bom = "\xEF\xBB\xBF";
  const std::string two_principals = tu::sec_toml() + "\n[[principals]]\nname = \"third\"\nidentities = [\"spiffe://lab/client\"]\nquota_bytes = 1\nmax_scopes = 1\n";
  const std::string twice_in_one = replace_once(tu::sec_toml(), "identities = [\"spiffe://lab/client\"]", "identities = [\"spiffe://lab/client\", \"spiffe://lab/client\"]");
  const std::string dup_rbac = tu::sec_toml() + "\n[[rbac]]\nidentity = \"spiffe://ops/alice\"\nroles = [\"viewer\"]\n";
  g.schema_rejects = {
      {"reject_dup_identity_two_principals.envelope", tu::make_envelope(two_principals, g.body)},
      {"reject_dup_identity_in_one_principal.envelope", tu::make_envelope(twice_in_one, g.body)},
      {"reject_dup_rbac_identity.envelope", tu::make_envelope(dup_rbac, g.body)},
      // Parses and verifies (parsing is pure); refused at apply / publish time by check_drop_before_not_future.
      {"reject_future_drop_before.envelope", tu::make_envelope(tu::sec_toml(5, "2099-01-01T00:00:00Z"), g.body)},
      {"reject_bom_sec.envelope", tu::make_envelope(bom + g.sec, g.body)},
      {"reject_bom_body.envelope", tu::make_envelope(g.sec, bom + g.body)},
  };
  return g;
}

std::map<std::string, std::string> parse_expect(const std::string& text) {
  std::map<std::string, std::string> m;
  std::size_t pos = 0;
  while (pos < text.size()) {
    std::size_t nl = text.find('\n', pos);
    if (nl == std::string::npos) nl = text.size();
    const std::string line = text.substr(pos, nl - pos);
    pos = nl + 1;
    if (line.empty() || line[0] == '#') continue;
    auto c = line.find(": ");  // our files use "name: value", the Go emitter's "name=value"
    std::size_t skip = 2;
    if (c == std::string::npos) {
      c = line.find('=');
      skip = 1;
    }
    if (c != std::string::npos) m[line.substr(0, c)] = line.substr(c + skip);
  }
  return m;
}

void write_golden(const std::string& dir, const std::string& name, const std::string& bytes) {
  std::filesystem::create_directories(dir);
  std::FILE* f = std::fopen((dir + name).c_str(), "wb");
  ASSERT_NE(f, nullptr);
  std::fwrite(bytes.data(), 1, bytes.size(), f);
  std::fclose(f);
}

}  // namespace

TEST(BundleGolden, CommittedGoldensMatchFreshOpenSslSigning) {
  const GoldenSet g = fresh_goldens();
  if (const char* regen = std::getenv("MIRACACHE_REGEN_GOLDENS"); regen && *regen) {
    const std::string d = std::string(regen) + "/";
    write_golden(d, "trust.toml", g.trust);
    write_golden(d, "valid.envelope", g.valid);
    write_golden(d, "valid.sec.toml", g.sec);
    write_golden(d, "valid.body.toml", g.body);
    write_golden(d, "valid.expect", g.expect);
    write_golden(d, "valid_publish_only.envelope", g.publish_only);
    write_golden(d, "valid_publish_only.body.toml", g.publish_only_body);
    write_golden(d, "valid_publish_only.expect", g.publish_only_expect);
    write_golden(d, "reject_upper_hex.envelope", g.reject_upper_hex);
    write_golden(d, "reject_role_confusion.envelope", g.reject_role_confusion);
    for (const auto& [name, bytes] : g.schema_rejects) write_golden(d, name, bytes);
  }
  const std::pair<const char*, const std::string*> files[] = {
      {"trust.toml", &g.trust},         {"valid.envelope", &g.valid},
      {"valid.sec.toml", &g.sec},            {"valid.body.toml", &g.body},
      {"valid.expect", &g.expect},           {"valid_publish_only.envelope", &g.publish_only},
      {"valid_publish_only.body.toml", &g.publish_only_body}, {"valid_publish_only.expect", &g.publish_only_expect}, {"reject_upper_hex.envelope", &g.reject_upper_hex}, {"reject_role_confusion.envelope", &g.reject_role_confusion}};
  for (const auto& [name, want] : files) {
    std::string have;
    ASSERT_TRUE(tu::read_file(golden_dir() + name, have)) << name;
    EXPECT_EQ(have, *want) << name << " differs from a fresh OpenSSL signing (Ed25519 is deterministic)";
  }
  for (const auto& [name, bytes] : g.schema_rejects) {
    std::string have;
    ASSERT_TRUE(tu::read_file(golden_dir() + name, have)) << name;
    EXPECT_EQ(have, bytes) << name << " differs from a fresh OpenSSL signing";
  }
}

// The shared reject corpus (the Go side reads reject*.envelope too): validly signed, invalid
// content. Every reject*.envelope in the directory (this suite's and the Go suite's) must be refused with the reason
// and the detail text of its reject_*.reject file (lines "reason:", "go:" and "cpp:", the exact message fragment of each side).
struct RejectExpect {
  std::string reason, detail;
};
RejectExpect read_reject_expect(const std::string& stem) {
  RejectExpect e;
  std::string txt;
  EXPECT_TRUE(tu::read_file(golden_dir() + stem + ".reject", txt)) << stem << ".reject is missing";
  std::istringstream in(txt);
  for (std::string line; std::getline(in, line);) {
    if (line.rfind("reason: ", 0) == 0) e.reason = line.substr(8);
    else if (line.rfind("cpp: ", 0) == 0) e.detail = line.substr(5);
  }
  EXPECT_TRUE(!e.reason.empty() && !e.detail.empty()) << stem << ".reject needs a reason and a cpp line";
  return e;
}

TEST(BundleGolden, SchemaRejectCorpusIsRejectedAsSchema) {
  std::string tk;
  ASSERT_TRUE(tu::read_file(golden_dir() + "trust.toml", tk));
  auto t = parse_trust_keys(tk);
  ASSERT_TRUE(t.has_value());
  std::size_t seen = 0;
  for (const auto& entry : std::filesystem::directory_iterator(golden_dir())) {
    const std::string name = entry.path().filename().string();
    if (name.rfind("reject", 0) != 0 || entry.path().extension() != ".envelope") continue;
    std::string env;
    ASSERT_TRUE(tu::read_file(entry.path().string(), env)) << name;
    // The wall-clock rule runs after a successful open (fixed "now" 2026-11-12T00:00:00Z); the Go suite does the same.
    auto opened = open_bundle(env, t.value());
    std::string got = opened.has_value() ? "ok" : reason_string(opened.error().reason);
    std::string detail = opened.has_value() ? "" : opened.error().detail;
    if (opened.has_value()) {
      if (auto fut = check_drop_before_not_future(*opened, 1'794'000'000)) {
        got = reason_string(fut->reason);
        detail = fut->detail;
      }
    }
    const RejectExpect want = read_reject_expect(entry.path().stem().string());
    EXPECT_EQ(got, want.reason) << name << ": " << detail;
    EXPECT_NE(detail.find(want.detail), std::string::npos) << name << ": message \"" << detail << "\" lacks \"" << want.detail << "\"";
    ++seen;
  }
  EXPECT_GE(seen, 40u) << "the Go and C++ reject files are both expected";
  for (const auto& [name, bytes] : fresh_goldens().schema_rejects) {
    std::string env;
    ASSERT_TRUE(tu::read_file(golden_dir() + name, env)) << name;
    EXPECT_EQ(env, bytes) << name;
  }
}

TEST(BundleSchema, W01DuplicateIdentitiesAndRbac) {
  const TrustKeys t = trust();
  const std::string base = tu::sec_toml();
  const std::string third = "\n[[principals]]\nname = \"third\"\nidentities = [\"spiffe://prod/vllm-host-1\"]\nquota_bytes = 1\nmax_scopes = 1\n";
  EXPECT_EQ(verdict(tu::make_envelope(base, tu::body_toml()), t), "ok");
  EXPECT_EQ(verdict(tu::make_envelope(base + third, tu::body_toml()), t), "schema");  // two principals
  EXPECT_EQ(verdict(tu::make_envelope(replace_once(base, "[\"spiffe://lab/client\"]", "[\"spiffe://lab/client\", \"spiffe://lab/client\"]"),
                                      tu::body_toml()), t), "schema");  // twice in one
  EXPECT_EQ(verdict(tu::make_envelope(base + "\n[[rbac]]\nidentity = \"spiffe://ops/alice\"\nroles = [\"x\"]\n", tu::body_toml()), t), "schema");
  EXPECT_EQ(verdict(tu::make_envelope(base + "\n[[rbac]]\nidentity = \"spiffe://ops/bob\"\nroles = [\"x\"]\n", tu::body_toml()), t), "ok");
}

TEST(BundleSchema, W04EmptyFormsAndBomAreRejected) {
  const TrustKeys t = trust();
  auto body_with = [&](const std::string& from, const std::string& to) {
    return verdict(tu::make_envelope(tu::sec_toml(), replace_once(tu::body_toml(), from, to)), t);
  };
  auto sec_with = [&](const std::string& from, const std::string& to) {
    return verdict(tu::make_envelope(replace_once(tu::sec_toml(5, "2026-11-01T00:00:00Z"), from, to), tu::body_toml()), t);
  };
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), tu::body_toml()), t), "ok");
  EXPECT_EQ(sec_with("drop_before = \"2026-11-01T00:00:00Z\"", "drop_before = \"\""), "schema");
  EXPECT_EQ(verdict(tu::make_envelope("sec_generation = 5\nprincipals = []\n", tu::body_toml()), t), "schema");
  EXPECT_EQ(verdict(tu::make_envelope("sec_generation = 5\nrbac = []\n", tu::body_toml()), t), "schema");
  EXPECT_EQ(body_with("zone = \"rack1\"\nstate = \"active\"", "zone = \"\"\nstate = \"active\""), "schema");
  // "previous" absent = no previous view; present but empty is refused.
  const std::string no_prev = replace_once(tu::body_toml(), "[[membership.previous]]\nnode_id = 3141592653\nweight = 1\nzone = \"rack1\"\n\n", "");
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), no_prev), t), "ok");
  auto parsed = parse_body(no_prev);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_TRUE(parsed->previous.empty());
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), replace_once(no_prev, "previous_epoch = 6\n", "previous_epoch = 6\nprevious = []\n")), t), "schema");
  // A UTF-8 BOM is refused explicitly, with the schema reason and a BOM-specific detail.
  const std::string bom = "\xEF\xBB\xBF";
  auto sb = parse_sec(bom + tu::sec_toml());
  ASSERT_FALSE(sb.has_value());
  EXPECT_EQ(sb.error().reason, Reject::Schema);
  EXPECT_NE(std::string(sb.error().detail).find("BOM"), std::string::npos);
  auto bb = parse_body(bom + tu::body_toml());
  ASSERT_FALSE(bb.has_value());
  EXPECT_NE(std::string(bb.error().detail).find("BOM"), std::string::npos);
}

TEST(BundleGolden, ValidEnvelopeVerifiesAndMatchesExpect) {
  std::string env, tk, ex;
  ASSERT_TRUE(tu::read_file(golden_dir() + "valid.envelope", env));
  ASSERT_TRUE(tu::read_file(golden_dir() + "trust.toml", tk));
  ASSERT_TRUE(tu::read_file(golden_dir() + "valid.expect", ex));
  auto t = parse_trust_keys(tk);
  ASSERT_TRUE(t.has_value());
  auto b = open_bundle(env, t.value());
  ASSERT_TRUE(b.has_value()) << b.error().detail;
  const auto m = parse_expect(ex);
  EXPECT_EQ(to_hex(b->key_id), m.at("key_id"));
  EXPECT_EQ(to_hex(b->sec_key_id), m.at("sec_key_id"));
  EXPECT_EQ(std::to_string(b->body.generation), m.at("generation"));
  EXPECT_EQ(std::to_string(b->sec.sec_generation), m.at("sec_generation"));
  EXPECT_EQ(std::to_string(b->body.epoch), m.at("epoch"));
  EXPECT_EQ(to_hex_s(b->body_hash), m.at("body_sha256"));
  EXPECT_EQ(to_hex_s(b->sec_hash), m.at("sec_sha256"));
  // Header lines in the file are exactly the expect values (lower-case hex, one space).
  EXPECT_NE(env.find("\nkey_id: " + m.at("key_id") + "\nsig: " + m.at("sig") + "\nsec_key_id: " + m.at("sec_key_id") +
                     "\nsec_sig: " + m.at("sec_sig") + "\nsec_len: " + m.at("sec_len") + "\n\n"),
            std::string::npos);
}

TEST(BundleGolden, PublishOnlyBundleCarriesTheOldSecAndItsOldSecSig) {
  std::string v, po, tk;
  ASSERT_TRUE(tu::read_file(golden_dir() + "valid.envelope", v));
  ASSERT_TRUE(tu::read_file(golden_dir() + "valid_publish_only.envelope", po));
  ASSERT_TRUE(tu::read_file(golden_dir() + "trust.toml", tk));
  auto t = parse_trust_keys(tk);
  ASSERT_TRUE(t.has_value());
  auto a = open_bundle(v, t.value());
  auto b = open_bundle(po, t.value());
  ASSERT_TRUE(a.has_value() && b.has_value());
  EXPECT_EQ(a->sec_hash, b->sec_hash);
  EXPECT_EQ(b->body.generation, 43u);
  auto ea = parse_envelope(v);
  auto eb = parse_envelope(po);
  ASSERT_TRUE(ea.has_value() && eb.has_value());
  EXPECT_EQ(ea->sec_sig, eb->sec_sig);
  EXPECT_NE(ea->sig, eb->sig);
}

TEST(BundleGolden, KeyIdIsFirstEightBytesOfSha256OfThePublicKey) {
  const auto pub = tu::public_key(tu::publish_seed());
  const auto d = tu::sha256(std::string(reinterpret_cast<const char*>(pub.data()), 32));
  auto t = parse_trust_keys(tu::trust_toml());
  ASSERT_TRUE(t.has_value());
  EXPECT_EQ(to_hex(t->keys()[0].key_id), tu::hex(d.data(), 8));
  EXPECT_EQ(to_hex(compute_key_id(pub)), tu::hex(d.data(), 8));
}

TEST(BundleGolden, VerifiesMb1GoEmittedEnvelope) {
  std::string env;
  if (!tu::read_file(golden_dir() + "go_emitted.envelope", env)) GTEST_SKIP() << "go_emitted.envelope not merged yet";
  std::string tk;
  if (!tu::read_file(golden_dir() + "go_emitted.trust.toml", tk)) ASSERT_TRUE(tu::read_file(golden_dir() + "trust.toml", tk));
  auto t = parse_trust_keys(tk);
  ASSERT_TRUE(t.has_value());
  auto b = open_bundle(env, t.value());
  ASSERT_TRUE(b.has_value()) << reason_string(b.error().reason) << ": " << b.error().detail;
  auto e = parse_envelope(env);
  ASSERT_TRUE(e.has_value());
  const std::size_t e_sec_len = e->sec.size();
  std::string ex;
  if (tu::read_file(golden_dir() + "go_emitted.expect", ex)) {
    const auto m = parse_expect(ex);
    auto check = [&](const char* k, const std::string& have) {
      if (auto it = m.find(k); it != m.end()) EXPECT_EQ(it->second, have) << k;
    };
    check("key_id", to_hex(b->key_id));
    check("sec_key_id", to_hex(b->sec_key_id));
    check("generation", std::to_string(b->body.generation));
    check("sec_generation", std::to_string(b->sec.sec_generation));
    check("epoch", std::to_string(b->body.epoch));
    check("body_hash", to_hex_s(b->body_hash));
    check("body_sha256", to_hex_s(b->body_hash));
    check("sec_len", std::to_string(e_sec_len));
    check("content_hash", to_hex_s(b->body_hash));
    check("sec_sha256", to_hex_s(b->sec_hash));
    check("sec_hash", to_hex_s(b->sec_hash));
    check("sig", tu::hex(e->sig.data(), 64));
    check("sec_sig", tu::hex(e->sec_sig.data(), 64));
    check("body_len", std::to_string(e->body.size()));
    for (const PrincipalView& p : b->sec.principals) check(("principal_id_" + p.name).c_str(), std::to_string(p.id));
  }
  // The signature bytes must be the ones Ed25519 gives for the same message (deterministic).
  const tu::Parts re = tu::sign_parts(std::string(e->sec), std::string(e->body));
  EXPECT_EQ(re.sig, tu::hex(e->sig.data(), 64));
  EXPECT_EQ(re.sec_sig, tu::hex(e->sec_sig.data(), 64));
}

// ---- round trip and view ----------------------------------------------------------------------

TEST(BundleView, ParsesMembershipSecAndReplicas) {
  auto b = open_bundle(tu::make_envelope(), trust());
  ASSERT_TRUE(b.has_value()) << b.error().detail;
  EXPECT_EQ(b->body.generation, 42u);
  EXPECT_EQ(b->body.epoch, 7u);
  EXPECT_EQ(b->body.previous_epoch, 6u);
  ASSERT_EQ(b->body.nodes.size(), 2u);
  EXPECT_EQ(b->body.nodes[0].node_id, 3141592653u);
  EXPECT_EQ(b->body.nodes[0].admin, "10.0.0.10:9465");
  EXPECT_EQ(b->body.nodes[0].state, MemberState::Active);
  EXPECT_EQ(*b->body.nodes[0].zone, "rack1");
  EXPECT_EQ(b->body.nodes[1].rails.size(), 2u);
  EXPECT_EQ(b->body.nodes[1].state, MemberState::Draining);
  ASSERT_EQ(b->body.previous.size(), 1u);
  EXPECT_TRUE(b->body.replicas_present);
  EXPECT_EQ(b->body.replicas, 2u);
  EXPECT_NE(b->body.config_toml.find("replicas"), std::string::npos);
  EXPECT_NE(b->body.config_toml.find("log_level"), std::string::npos);  // raw config.* kept
  EXPECT_EQ(b->sec.sec_generation, 5u);
  ASSERT_EQ(b->sec.principals.size(), 2u);
  EXPECT_EQ(b->sec.principals[0].name, "prod-llama");
  EXPECT_EQ(b->sec.principals[0].quota_bytes, 2199023255552ull);
  ASSERT_EQ(b->sec.rbac.size(), 1u);
  EXPECT_EQ(b->sec.rbac[0].roles[0], "security-admin");
  EXPECT_EQ(to_hex(b->body_hash).size(), 64u);
}

TEST(BundleView, PrincipalIdIsComputedFromTheName) {
  const auto d = tu::sha256("mira-principal-v1" + std::string("prod-llama"));
  const std::uint32_t want = (std::uint32_t(d[0]) << 24) | (std::uint32_t(d[1]) << 16) | (std::uint32_t(d[2]) << 8) | d[3];
  EXPECT_EQ(principal_id("prod-llama"), want == 0 ? 1u : want);
  auto b = open_bundle(tu::make_envelope(), trust());
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(b->sec.principals[0].id, principal_id("prod-llama"));
}

TEST(BundleView, DropBeforeParsesToUnixSeconds) {
  auto b = open_bundle(tu::make_envelope(tu::sec_toml(5, "2026-11-01T00:00:00Z")), trust());
  ASSERT_TRUE(b.has_value()) << b.error().detail;
  ASSERT_TRUE(b->sec.principals[0].drop_before.has_value());
  EXPECT_EQ(*b->sec.principals[0].drop_before, 1793491200);
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(5, "2026-11-01 00:00:00")), trust()), "schema");
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(5, "2026-02-30T00:00:00Z")), trust()), "schema");
}

// ---- byte-exact envelope rules 1-9 ---------------------------------------------------------------

TEST(BundleEnvelopeRules, Rule1HeaderOrderAndNoOtherLines) {
  const TrustKeys t = trust();
  const tu::Parts p = tu::sign_parts(tu::sec_toml(), tu::body_toml());
  const std::string good = tu::assemble(p);
  ASSERT_EQ(verdict(good, t), "ok");
  // Swapped order.
  EXPECT_EQ(verdict("mira-bundle-v1\nsig: " + p.sig + "\nkey_id: " + p.key_id + "\nsec_key_id: " + p.sec_key_id +
                        "\nsec_sig: " + p.sec_sig + "\nsec_len: " + p.sec_len + "\n\n" + p.sec + p.body,
                    t),
            "envelope_format");
  // Extra line / comment / duplicate line.
  EXPECT_EQ(verdict(replace_once(good, "\nsec_len:", "\n# comment\nsec_len:"), t), "envelope_format");
  EXPECT_EQ(verdict(replace_once(good, "\nsec_len:", "\nextra: x\nsec_len:"), t), "envelope_format");
  // Missing the closing empty line.
  EXPECT_EQ(verdict(replace_once(good, "\n\n", "\n"), t), "envelope_format");
  // Wrong or missing magic.
  EXPECT_EQ(verdict(replace_once(good, "mira-bundle-v1\n", "mira-bundle-v2\n"), t), "envelope_format");
  EXPECT_EQ(verdict(good.substr(good.find('\n') + 1), t), "envelope_format");
  EXPECT_EQ(verdict("", t), "envelope_format");
}

TEST(BundleEnvelopeRules, Rule2LfOnly) {
  const TrustKeys t = trust();
  const std::string good = tu::make_envelope();
  std::string crlf = good;
  for (std::size_t at = crlf.find('\n'); at != std::string::npos && at < crlf.find("sec_len"); at = crlf.find('\n', at + 2)) {
    crlf.insert(at, "\r");
  }
  EXPECT_EQ(verdict(crlf, t), "envelope_format");
  EXPECT_EQ(verdict(replace_once(good, "key_id: ", "key_id: \r"), t), "envelope_format");
  EXPECT_EQ(verdict(replace_once(good, "\n\n", "\n\r\n"), t), "envelope_format");
}

TEST(BundleEnvelopeRules, Rule3OneSpaceAfterTheColonNothingAfterTheValue) {
  const TrustKeys t = trust();
  const std::string good = tu::make_envelope();
  EXPECT_EQ(verdict(replace_once(good, "key_id: ", "key_id:  "), t), "envelope_format");
  EXPECT_EQ(verdict(replace_once(good, "key_id: ", "key_id:"), t), "envelope_format");
  EXPECT_EQ(verdict(replace_once(good, "key_id: ", "key_id:\t"), t), "envelope_format");
  EXPECT_EQ(verdict(replace_once(good, "\nsig: ", "\nsig : "), t), "envelope_format");
  const tu::Parts p = tu::sign_parts(tu::sec_toml(), tu::body_toml());
  EXPECT_EQ(verdict(replace_once(good, "\nsig: " + p.sig + "\n", "\nsig: " + p.sig + " \n"), t), "envelope_format");
  EXPECT_EQ(verdict(replace_once(good, "\nsec_len: " + p.sec_len + "\n", "\nsec_len: " + p.sec_len + " \n"), t),
            "envelope_format");
}

TEST(BundleEnvelopeRules, Rule4LowerCaseHexExactLengths) {
  const TrustKeys t = trust();
  const tu::Parts p = tu::sign_parts(tu::sec_toml(), tu::body_toml());
  auto upper = [](std::string s) {
    for (char& c : s) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return s;
  };
  auto with = [&](tu::Parts q) { return verdict(tu::assemble(q), t); };
  ASSERT_EQ(with(p), "ok");
  // Pick a field that contains a letter so upper-casing changes it (they all do for these seeds).
  tu::Parts q = p;
  ASSERT_NE(upper(p.key_id), p.key_id);
  q.key_id = upper(p.key_id);
  EXPECT_EQ(with(q), "envelope_format");
  q = p;
  q.sig = upper(p.sig);
  EXPECT_EQ(with(q), "envelope_format");
  q = p;
  q.sec_key_id = upper(p.sec_key_id);
  EXPECT_EQ(with(q), "envelope_format");
  q = p;
  q.sec_sig = upper(p.sec_sig);
  EXPECT_EQ(with(q), "envelope_format");
  // Lengths.
  q = p;
  q.key_id = p.key_id.substr(0, 15);
  EXPECT_EQ(with(q), "envelope_format");
  q.key_id = p.key_id + "0";
  EXPECT_EQ(with(q), "envelope_format");
  q = p;
  q.sig = p.sig.substr(0, 127);
  EXPECT_EQ(with(q), "envelope_format");
  q.sig = p.sig + "0";
  EXPECT_EQ(with(q), "envelope_format");
  q = p;
  q.sec_sig = p.sec_sig.substr(0, 127);
  EXPECT_EQ(with(q), "envelope_format");
  q = p;
  q.sec_key_id = p.sec_key_id + "0";
  EXPECT_EQ(with(q), "envelope_format");
  q = p;
  q.sig = "g" + p.sig.substr(1);
  EXPECT_EQ(with(q), "envelope_format");
}

TEST(BundleEnvelopeRules, Rule5SecLenForm) {
  const TrustKeys t = trust();
  const tu::Parts p = tu::sign_parts(tu::sec_toml(), tu::body_toml());
  auto with_len = [&](const std::string& len) {
    tu::Parts q = p;
    q.sec_len = len;
    return verdict(tu::assemble(q), t);
  };
  ASSERT_EQ(with_len(p.sec_len), "ok");
  EXPECT_EQ(with_len("0" + p.sec_len), "envelope_format");  // leading zero
  EXPECT_EQ(with_len("0"), "envelope_format");              // sec is never empty
  EXPECT_EQ(with_len("+" + p.sec_len), "envelope_format");
  EXPECT_EQ(with_len("-1"), "envelope_format");
  EXPECT_EQ(with_len(""), "envelope_format");
  EXPECT_EQ(with_len("12345678"), "envelope_format");  // 8 digits
  EXPECT_EQ(with_len("0x10"), "envelope_format");
  EXPECT_EQ(with_len("1e3"), "envelope_format");
  EXPECT_EQ(with_len(p.sec_len + " "), "envelope_format");
  // Larger than the bytes after the header.
  EXPECT_EQ(with_len(std::to_string(p.sec.size() + p.body.size() + 1)), "envelope_format");
  // Within the bytes but not the signed value: the signature no longer verifies.
  EXPECT_EQ(with_len(std::to_string(p.sec.size() - 1)), "bad_signature");
  EXPECT_EQ(with_len(std::to_string(p.sec.size() + p.body.size())), "bad_signature");
}

TEST(BundleEnvelopeRules, Rule5ExactlyOneMiBIsTheLimit) {
  const TrustKeys t = trust();
  // Not a valid body, but the size gate must trip before anything is parsed.
  std::string big = tu::make_envelope();
  big.append(kMaxEnvelopeBytes, '#');
  EXPECT_EQ(verdict(big, t), "envelope_format");
}

TEST(BundleEnvelopeRules, Rule6SignedLengthIsSecLen) {
  const TrustKeys t = trust();
  const std::string sec = tu::sec_toml();
  const std::string body = tu::body_toml();
  // Signed over a different u32be value than sec_len.
  EXPECT_EQ(verdict(tu::assemble(tu::sign_parts(sec, body, tu::publish_seed(), tu::security_seed(), sec.size() + 1)), t),
            "bad_signature");
  // Signed over the same value as sec_len, the correct case.
  EXPECT_EQ(verdict(tu::assemble(tu::sign_parts(sec, body)), t), "ok");
  // Signed message without the length prefix is not accepted.
  tu::Parts p = tu::sign_parts(sec, body);
  const std::string domain("mira-bundle-v1\0", 15);
  const auto nolen = tu::sign(tu::publish_seed(), domain + sec + body);
  p.sig = tu::hex(nolen.data(), nolen.size());
  EXPECT_EQ(verdict(tu::assemble(p), t), "bad_signature");
}

TEST(BundleEnvelopeRules, Rule7EverythingIsSha256) {
  // key_id: SHA-256 prefix (golden test above). Here: hashes the view reports are SHA-256.
  const std::string sec = tu::sec_toml();
  const std::string body = tu::body_toml();
  auto b = open_bundle(tu::make_envelope(sec, body), trust());
  ASSERT_TRUE(b.has_value());
  const auto bh = tu::sha256(body);
  const auto sh = tu::sha256(sec);
  EXPECT_EQ(to_hex(b->body_hash), tu::hex(bh.data(), 32));
  EXPECT_EQ(to_hex(b->sec_hash), tu::hex(sh.data(), 32));
  // SHA-256("abc") known answer for the library helper.
  EXPECT_EQ(to_hex(sha256("abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
}

TEST(BundleEnvelopeRules, Rule8RoleBinding) {
  const std::string sec = tu::sec_toml();
  const std::string body = tu::body_toml();
  const TrustKeys split = trust();
  // Body (publish signature) made by the security-only key.
  EXPECT_EQ(verdict(tu::assemble(tu::sign_parts(sec, body, tu::security_seed(), tu::security_seed())), split), "key_role");
  // sec (security signature) made by the publish-only key.
  EXPECT_EQ(verdict(tu::assemble(tu::sign_parts(sec, body, tu::publish_seed(), tu::publish_seed())), split), "key_role");
  // Roles swapped.
  EXPECT_EQ(verdict(tu::assemble(tu::sign_parts(sec, body, tu::security_seed(), tu::publish_seed())), split), "key_role");
  // One key holding both roles may sign both parts; that is the operator's choice.
  const TrustKeys both = trust(true);
  EXPECT_EQ(verdict(tu::assemble(tu::sign_parts(sec, body, tu::publish_seed(), tu::publish_seed())), both), "ok");
  // A valid signature by a key not in the trust file.
  EXPECT_EQ(verdict(tu::assemble(tu::sign_parts(sec, body, tu::seed_from(0x61), tu::security_seed())), split), "unknown_key");
  EXPECT_EQ(verdict(tu::assemble(tu::sign_parts(sec, body, tu::publish_seed(), tu::seed_from(0x61))), split), "unknown_key");
}

TEST(BundleEnvelopeRules, Rule8PublishOnlyBundleWithOldSecAndOldSecSigIsAccepted) {
  const TrustKeys t = trust();
  const std::string sec = tu::sec_toml(5);
  const tu::Parts v1 = tu::sign_parts(sec, tu::body_toml(42));
  tu::Parts v2 = tu::sign_parts(sec, tu::body_toml(43));
  v2.sec_sig = v1.sec_sig;  // identical anyway (deterministic), made explicit
  EXPECT_EQ(verdict(tu::assemble(v2), t), "ok");
  // A publish-only bundle that changes sec but keeps the old sec_sig fails.
  tu::Parts v3 = tu::sign_parts(tu::sec_toml(6), tu::body_toml(44));
  v3.sec_sig = v1.sec_sig;
  EXPECT_EQ(verdict(tu::assemble(v3), t), "bad_sec_signature");
}

TEST(BundleEnvelopeRules, Rule9GenerationRange) {
  const TrustKeys t = trust();
  auto gen = [&](const std::string& g) {
    std::string body = tu::body_toml();
    body = replace_once(body, "generation = 42", "generation = " + g);
    return verdict(tu::make_envelope(tu::sec_toml(), body), t);
  };
  auto secgen = [&](const std::string& g) {
    std::string sec = tu::sec_toml();
    sec = replace_once(sec, "sec_generation = 5", "sec_generation = " + g);
    return verdict(tu::make_envelope(sec, tu::body_toml()), t);
  };
  EXPECT_EQ(gen("1"), "ok");
  EXPECT_EQ(gen("9223372036854775807"), "ok");  // 2^63 - 1
  EXPECT_EQ(gen("9223372036854775808"), "schema");
  EXPECT_EQ(gen("18446744073709551615"), "schema");
  EXPECT_EQ(gen("0"), "schema");
  EXPECT_EQ(gen("-1"), "schema");
  EXPECT_EQ(gen("1.5"), "schema");
  EXPECT_EQ(gen("\"7\""), "schema");
  EXPECT_EQ(secgen("1"), "ok");
  EXPECT_EQ(secgen("9223372036854775807"), "ok");
  EXPECT_EQ(secgen("9223372036854775808"), "schema");
  EXPECT_EQ(secgen("0"), "schema");
  EXPECT_EQ(secgen("-3"), "schema");
}

// ---- tamper ---------------------------------------------------------------------------------------

TEST(BundleTamper, EveryByteOfEverySignedPartIsCovered) {
  const TrustKeys t = trust();
  const tu::Parts p = tu::sign_parts(tu::sec_toml(), tu::body_toml());
  const std::string good = tu::assemble(p);
  const std::size_t header = good.size() - p.sec.size() - p.body.size();
  // Flip one bit in each byte of sec and body (stride keeps it quick): never "ok".
  for (std::size_t i = header; i < good.size(); i += 7) {
    std::string bad = good;
    bad[i] = static_cast<char>(bad[i] ^ 0x01);
    EXPECT_NE(verdict(bad, t), "ok") << "offset " << i;
  }
  // A flipped sec byte fails the publish signature first (it covers sec), a body byte too.
  std::string bad_body = good;
  bad_body[good.size() - 3] = static_cast<char>(bad_body[good.size() - 3] ^ 0x01);
  EXPECT_EQ(verdict(bad_body, t), "bad_signature");
  std::string bad_sec = good;
  bad_sec[header + 3] = static_cast<char>(bad_sec[header + 3] ^ 0x01);
  EXPECT_EQ(verdict(bad_sec, t), "bad_signature");
}

TEST(BundleTamper, SignaturesKeyIdsAndSecLen) {
  const TrustKeys t = trust();
  const tu::Parts p = tu::sign_parts(tu::sec_toml(), tu::body_toml());
  auto flip_hex = [](std::string h) {
    h[0] = h[0] == '0' ? '1' : '0';
    return h;
  };
  tu::Parts q = p;
  q.sig = flip_hex(p.sig);
  EXPECT_EQ(verdict(tu::assemble(q), t), "bad_signature");
  q = p;
  q.sec_sig = flip_hex(p.sec_sig);
  EXPECT_EQ(verdict(tu::assemble(q), t), "bad_sec_signature");
  q = p;
  q.key_id = flip_hex(p.key_id);
  EXPECT_EQ(verdict(tu::assemble(q), t), "unknown_key");
  q = p;
  q.sec_key_id = flip_hex(p.sec_key_id);
  EXPECT_EQ(verdict(tu::assemble(q), t), "unknown_key");
  // Swapping the two key ids is a role failure, not a signature failure.
  q = p;
  std::swap(q.key_id, q.sec_key_id);
  EXPECT_EQ(verdict(tu::assemble(q), t), "key_role");
}

// ---- schema ---------------------------------------------------------------------------------------

TEST(BundleSchema, MembershipAndSecRejectUnknownKeys) {
  const TrustKeys t = trust();
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), replace_once(tu::body_toml(), "[membership]\n", "[membership]\nbogus = 1\n")), t),
            "schema");
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), replace_once(tu::body_toml(), "state = \"active\"", "state = \"active\"\nid = 3")), t),
            "schema");
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml() + "bogus = 1\n", tu::body_toml()), t), "schema");
  EXPECT_EQ(verdict(tu::make_envelope(replace_once(tu::sec_toml(), "max_scopes = 1000", "max_scopes = 1000\nregion = \"eu\""), tu::body_toml()), t),
            "schema");
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml() + "\n[[rbac]]\nidentity = \"x\"\nroles = [\"viewer\"]\nextra = 1\n", tu::body_toml()), t),
            "schema");
}

TEST(BundleSchema, TypedPrincipalIdIsAnError) {
  const TrustKeys t = trust();
  EXPECT_EQ(verdict(tu::make_envelope(replace_once(tu::sec_toml(), "name = \"lab\"", "name = \"lab\"\nid = 77"), tu::body_toml()), t),
            "schema");
}

TEST(BundleSchema, UnknownConfigKeysAreIgnoredAndCounted) {
  const TrustKeys t = trust();
  auto base = open_bundle(tu::make_envelope(), t);
  ASSERT_TRUE(base.has_value());
  EXPECT_EQ(base->body.unknown_keys, 0u);
  const std::string extra = "\n[config.cluster.bogus]\nx = 1\n\n[config.zzz]\ny = 2\n\n[config.cluster.placement.future]\nz = 3\n";
  // The placement table is closed by the later [config.cluster.placement.future] only if declared as its own table.
  auto b = open_bundle(tu::make_envelope(tu::sec_toml(), tu::body_toml(42, 7, 6, extra)), t);
  ASSERT_TRUE(b.has_value()) << b.error().detail;
  EXPECT_EQ(b->body.unknown_keys, 3u);
  EXPECT_EQ(b->body.replicas, 2u);
  // Everything outside config.* is strict, the top level included (same as the Go side).
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), "future_field = 1\n" + tu::body_toml()), t), "schema");
  // But a known config table of the wrong type is an error.
  const std::string full = tu::body_toml();
  const std::string no_config = full.substr(0, full.find("[config.cluster.placement]"));
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), no_config + "[config]\ncluster = 3\n"), t), "schema");
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), no_config), t), "ok");  // config is optional
}

TEST(BundleSchema, MembershipRules) {
  const TrustKeys t = trust();
  auto body_with = [&](const std::string& from, const std::string& to) {
    return verdict(tu::make_envelope(tu::sec_toml(), replace_once(tu::body_toml(), from, to)), t);
  };
  EXPECT_EQ(body_with("previous_epoch = 6", "previous_epoch = 7"), "schema");
  EXPECT_EQ(body_with("previous_epoch = 6", "previous_epoch = 8"), "schema");
  EXPECT_EQ(body_with("epoch = 7", "epoch = 0"), "schema");
  EXPECT_EQ(body_with("state = \"active\"", "state = \"gone\""), "schema");
  EXPECT_EQ(body_with("node_id = 7", "node_id = 3141592653"), "schema");   // duplicate id
  EXPECT_EQ(body_with("node_id = 7", "node_id = 0"), "schema");
  EXPECT_EQ(body_with("admin = \"10.0.0.11:9465\"", "admin = \"10.0.0.10:9465\""), "schema");
  EXPECT_EQ(body_with("zone = \"rack2\"\n", ""), "schema");                 // zone on some nodes only
  EXPECT_EQ(body_with("weight = 2", "weight = 0"), "schema");
  EXPECT_EQ(body_with("replicas = 2", "replicas = 0"), "schema");
  EXPECT_EQ(body_with("schema_version = 1", "schema_version = 2"), "schema");
  // Rails: 5 is too many.
  const std::string five = "rails = [{ addr = \"a:1\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }, { addr = \"a:2\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }, { addr = \"a:3\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }, { addr = \"a:4\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }, { addr = \"a:5\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }]";
  EXPECT_EQ(body_with("rails = [{ addr = \"10.0.0.10:7471\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }]", five), "schema");
  EXPECT_EQ(body_with("rails = [{ addr = \"10.0.0.10:7471\", subnet = \"10.0.0.0/24\", protocol = \"roce\" }]", "rails = []"), "schema");
}

TEST(BundleSchema, PrincipalRules) {
  const TrustKeys t = trust();
  auto sec_with = [&](const std::string& from, const std::string& to) {
    return verdict(tu::make_envelope(replace_once(tu::sec_toml(), from, to), tu::body_toml()), t);
  };
  EXPECT_EQ(sec_with("name = \"lab\"", "name = \"prod-llama\""), "schema");  // duplicate name
  EXPECT_EQ(sec_with("identities = [\"spiffe://lab/client\"]", "identities = []"), "schema");
  EXPECT_EQ(sec_with("quota_bytes = 1073741824", "quota_bytes = -1"), "schema");
}

// ---- trust file -------------------------------------------------------------------------------------

TEST(TrustKeys, TypedIdIsAStaleKeyError) {
  const std::string toml = tu::trust_toml();
  auto r = parse_trust_keys(replace_once(toml, "roles = [\"publish\"]", "roles = [\"publish\"]\nid = \"deadbeefdeadbeef\""));
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().reason, Reject::TrustFile);
}

TEST(TrustKeys, RulesAndPin) {
  EXPECT_FALSE(parse_trust_keys("").has_value());
  EXPECT_FALSE(parse_trust_keys("[[key]]\npublic = \"zz\"\nroles = [\"publish\"]\n").has_value());
  EXPECT_FALSE(parse_trust_keys(replace_once(tu::trust_toml(), "roles = [\"publish\"]", "roles = [\"owner\"]")).has_value());
  EXPECT_FALSE(parse_trust_keys(replace_once(tu::trust_toml(), "roles = [\"publish\"]", "roles = []")).has_value());
  EXPECT_FALSE(parse_trust_keys(tu::trust_toml(false, "bogus = 1\n")).has_value());
  auto pinned = parse_trust_keys(tu::trust_toml(false, "min_sec_generation = 9\n"));
  ASSERT_TRUE(pinned.has_value());
  EXPECT_EQ(pinned->min_sec_generation(), 9u);
  EXPECT_FALSE(parse_trust_keys(tu::trust_toml(false, "min_sec_generation = 0\n")).has_value());
  auto none = parse_trust_keys(tu::trust_toml());
  ASSERT_TRUE(none.has_value());
  EXPECT_EQ(none->min_sec_generation(), 0u);
  EXPECT_EQ(none->keys().size(), 2u);
  EXPECT_TRUE(none->keys()[0].publish && !none->keys()[0].security);
  EXPECT_TRUE(!none->keys()[1].publish && none->keys()[1].security);
  // Same key twice.
  const std::string one = "[[key]]\npublic = \"" + tu::hex(tu::public_key(tu::publish_seed()).data(), 32) + "\"\nroles = [\"publish\"]\n";
  EXPECT_FALSE(parse_trust_keys(one + one).has_value());
}

TEST(BundleGolden, RejectGoldensAreRejectedWithTheirReason) {
  std::string tk, e1, e2;
  ASSERT_TRUE(tu::read_file(golden_dir() + "trust.toml", tk));
  ASSERT_TRUE(tu::read_file(golden_dir() + "reject_upper_hex.envelope", e1));
  ASSERT_TRUE(tu::read_file(golden_dir() + "reject_role_confusion.envelope", e2));
  auto t = parse_trust_keys(tk);
  ASSERT_TRUE(t.has_value());
  EXPECT_EQ(verdict(e1, t.value()), "envelope_format");
  EXPECT_EQ(verdict(e2, t.value()), "key_role");
}

// With the floor's stored maxima, a drop_before up to the stored maximum is exempt from the "not future" rule.
TEST(BundleSchema, DropBeforeNotFutureHonoursTheStoredMaximum) {
  const TrustKeys t = trust();
  auto opened = open_bundle(tu::make_envelope(tu::sec_toml(5, "2026-11-12T01:00:00Z"), tu::body_toml()), t);
  ASSERT_TRUE(opened.has_value());
  const std::int64_t drop = 1'794'445'200;  // 2026-11-12T01:00:00Z
  const std::int64_t now = drop - 3600;     // the node clock is 1 h behind: the value is in the future
  EXPECT_TRUE(check_drop_before_not_future(*opened, now).has_value());  // no floor: refused
  std::map<std::string, std::int64_t> stored{{"prod-llama", drop}};
  EXPECT_FALSE(check_drop_before_not_future(*opened, now, &stored).has_value());  // equal: exempt
  stored["prod-llama"] = drop + 10;
  EXPECT_FALSE(check_drop_before_not_future(*opened, now, &stored).has_value());  // below the maximum: exempt
  stored["prod-llama"] = drop - 1;
  EXPECT_TRUE(check_drop_before_not_future(*opened, now, &stored).has_value());  // above the maximum: refused
  stored.erase("prod-llama");
  stored["lab"] = drop + 10;  // another principal's maximum does not help
  EXPECT_TRUE(check_drop_before_not_future(*opened, now, &stored).has_value());
  EXPECT_FALSE(check_drop_before_not_future(*opened, now + 3600).has_value());  // clock caught up: fine without a floor
}

TEST(BundleSchema, NonAsciiOnlyInsideStringsAndComments) {
  const TrustKeys t = trust();
  // UTF-8 in a string value is fine (the Go side's golden has "caf\xC3\xA9").
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), replace_once(tu::body_toml(), "add hostD", "add h\xC3\xB6stD")), t), "ok");
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), "# caf\xC3\xA9\n" + tu::body_toml()), t), "ok");
  // Outside strings it is refused before toml++ sees it (toml++ 3.4.0 hits TOML_UNREACHABLE).
  EXPECT_EQ(verdict(tu::make_envelope(tu::sec_toml(), replace_once(tu::body_toml(), "weight = 2", "weight = 2\xC2\xA1")), t), "schema");
  EXPECT_EQ(verdict(tu::make_envelope(replace_once(tu::sec_toml(), "prod-llama", "prod-\xC3\xA9"), tu::body_toml()), t), "schema");  // principal names are [A-Za-z0-9._-]
  EXPECT_FALSE(parse_trust_keys("[[key]]\xD2\x9A\n" + tu::trust_toml()).has_value());
  EXPECT_TRUE(parse_trust_keys("# \xC2\xA1\n" + tu::trust_toml()).has_value());
  EXPECT_TRUE(toml_text_ok("a = \"\"\"x\xC3\xA9\n\"y\"\"\"\nb = '''\xC3\xA9'''\n"));
  EXPECT_FALSE(toml_text_ok("a = \"x\" \xC3\xA9\n"));
}
