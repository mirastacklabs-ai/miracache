// SPDX-License-Identifier: Apache-2.0
// Floor rules and the persisted, flock-guarded floor file.
#include <gtest/gtest.h>

#include <sys/stat.h>

#include <unistd.h>

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <string>
#include <thread>
#include <vector>

#include "control/bundle.h"
#include "control/floor_state.h"
#include "control/bundle_test_util.h"

using namespace miracache::control;
namespace tu = miracache::control::testutil;

namespace {

struct TempDir {
  std::string path;
  TempDir() {
    std::string tmpl = (std::filesystem::temp_directory_path() / "mira_floor_XXXXXX").string();
    std::vector<char> buf(tmpl.begin(), tmpl.end());
    buf.push_back('\0');
    if (!::mkdtemp(buf.data())) std::abort();
    path = buf.data();
  }
  ~TempDir() {
    std::error_code ec;
    std::filesystem::remove_all(path, ec);
  }
};

TrustKeys trust() { return parse_trust_keys(tu::trust_toml()).value(); }

BundleView bundle(std::uint64_t gen, std::uint32_t epoch, std::uint64_t sec_gen, const std::string& reason = "r",
                  const std::string& drop_before = "") {
  std::string body = tu::body_toml(gen, epoch, epoch - 1);
  body = body.substr(0, 0) + body;
  const auto at = body.find("reason = \"add hostD\"");
  body.replace(at, std::string("reason = \"add hostD\"").size(), "reason = \"" + reason + "\"");
  auto b = open_bundle(tu::make_envelope(tu::sec_toml(sec_gen, drop_before), body), trust());
  EXPECT_TRUE(b.has_value());
  return std::move(b.value());
}

std::string reject_of(const miracache::Expected<Verdict, BundleError>& r) {
  return r.has_value() ? (r.value() == Verdict::Apply ? "apply" : "replace") : reason_string(r.error().reason);
}

}  // namespace

TEST(FloorRules, BlankFloorAcceptsAnyValidBundle) {
  EXPECT_EQ(reject_of(check_against_floor(Floor{}, bundle(42, 7, 5), 0)), "apply");
  EXPECT_EQ(reject_of(check_against_floor(Floor{}, bundle(1, 1, 1), 0)), "apply");
}

TEST(FloorRules, GenerationRules) {
  TempDir d;
  auto fs = FloorState::open(d.path);
  ASSERT_TRUE(fs.has_value());
  const BundleView b42 = bundle(42, 7, 5);
  ASSERT_TRUE(fs->commit(b42).has_value());
  Floor f = fs->load().value();
  EXPECT_EQ(f.generation, 42u);
  EXPECT_EQ(f.body_hash, b42.body_hash);
  // Higher: apply.
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(43, 7, 5), 0)), "apply");
  // Equal generation and equal hash: replace, not apply (also for a bundle re-signed by another key pair).
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(42, 7, 5), 0)), "replace");
  // Equal generation, different hash.
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(42, 7, 5, "other reason"), 0)), "equal_generation");
  // Lower generation.
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(41, 7, 5), 0)), "generation_lower");
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(1, 7, 5), 0)), "generation_lower");
}

TEST(FloorRules, ReSignReplacesTheStoredEnvelopeWithoutAnApply) {
  // Same bytes, new valid signature (key rotation): both envelopes parse to the same hashes.
  const std::string sec = tu::sec_toml(5);
  const std::string body = tu::body_toml(42, 7, 6);
  const tu::Seed rotated = tu::seed_from(0x41);
  const std::string toml = "[[key]]\npublic = \"" + tu::hex(tu::public_key(tu::publish_seed()).data(), 32) +
                           "\"\nroles = [\"publish\"]\n[[key]]\npublic = \"" + tu::hex(tu::public_key(tu::security_seed()).data(), 32) +
                           "\"\nroles = [\"security\"]\n[[key]]\npublic = \"" + tu::hex(tu::public_key(rotated).data(), 32) +
                           "\"\nroles = [\"publish\"]\n";
  auto t = parse_trust_keys(toml);
  ASSERT_TRUE(t.has_value());
  auto a = open_bundle(tu::assemble(tu::sign_parts(sec, body)), t.value());
  auto b = open_bundle(tu::assemble(tu::sign_parts(sec, body, rotated)), t.value());
  ASSERT_TRUE(a.has_value() && b.has_value());
  EXPECT_NE(a->key_id, b->key_id);
  EXPECT_EQ(a->body_hash, b->body_hash);
  Floor f;
  f.generation = 42;
  f.body_hash = a->body_hash;
  f.sec_generation = 5;
  f.sec_hash = a->sec_hash;
  f.epoch = 7;
  EXPECT_EQ(reject_of(check_against_floor(f, b.value(), 0)), "replace");
}

TEST(FloorRules, EpochBackwardsIsRejected) {
  Floor f;
  f.generation = 42;
  f.epoch = 7;
  f.sec_generation = 5;
  f.sec_hash = bundle(43, 6, 5).sec_hash;
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(43, 6, 5), 0)), "epoch_backwards");
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(43, 7, 5), 0)), "apply");
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(43, 8, 5), 0)), "apply");
}

TEST(FloorRules, SecGenerationFloor) {
  TempDir d;
  auto fs = FloorState::open(d.path);
  ASSERT_TRUE(fs.has_value());
  ASSERT_TRUE(fs->commit(bundle(42, 7, 5)).has_value());
  const Floor f = fs->load().value();
  EXPECT_EQ(f.sec_generation, 5u);
  // A newer body carrying an older sec section.
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(50, 7, 4), 0)), "sec_generation_lower");
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(50, 7, 1), 0)), "sec_generation_lower");
  // Equal sec_generation: same sec bytes fine, different sec bytes rejected.
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(50, 7, 5), 0)), "apply");
  BundleView changed = bundle(50, 7, 5);
  changed.sec_hash[0] ^= 0xFF;
  EXPECT_EQ(reject_of(check_against_floor(f, changed, 0)), "sec_equal_generation");
  // Higher sec_generation: apply. Equal generation, same body, higher sec: rejected.
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(50, 7, 6), 0)), "apply");
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(42, 7, 6), 0)), "equal_generation");  // a new sec needs a new generation
}

TEST(FloorRules, PinnedMinSecGenerationAppliesOnABlankFloor) {
  const Floor blank;
  EXPECT_EQ(blank.effective_sec_floor(0), 0u);
  EXPECT_EQ(blank.effective_sec_floor(6), 6u);
  EXPECT_EQ(reject_of(check_against_floor(blank, bundle(42, 7, 5), 6)), "sec_generation_lower");
  EXPECT_EQ(reject_of(check_against_floor(blank, bundle(42, 7, 6), 6)), "apply");
  EXPECT_EQ(reject_of(check_against_floor(blank, bundle(42, 7, 9), 6)), "apply");
  // max(persisted, pinned): a persisted floor above the pin wins.
  Floor f;
  f.generation = 1;
  f.sec_generation = 8;
  f.sec_hash = bundle(42, 7, 8).sec_hash;
  EXPECT_EQ(f.effective_sec_floor(6), 8u);
  EXPECT_EQ(reject_of(check_against_floor(f, bundle(42, 7, 7), 6)), "sec_generation_lower");
  // And the pin wins over a lower persisted floor.
  f.sec_generation = 3;
  EXPECT_EQ(f.effective_sec_floor(6), 6u);
}

TEST(FloorRules, PinFromTrustFileIsUsed) {
  auto t = parse_trust_keys(tu::trust_toml(false, "min_sec_generation = 6\n"));
  ASSERT_TRUE(t.has_value());
  EXPECT_EQ(reject_of(check_against_floor(Floor{}, bundle(42, 7, 5), t->min_sec_generation())), "sec_generation_lower");
}

TEST(FloorFile, MaxOnlyAndPersistent) {
  TempDir d;
  {
    auto fs = FloorState::open(d.path + "/sub");  // created on demand, one level
    ASSERT_TRUE(fs.has_value());
    EXPECT_EQ(fs->load().value().generation, 0u);  // missing file = blank
    ASSERT_TRUE(fs->commit(bundle(50, 9, 7)).has_value());
    auto lower = fs->commit(bundle(42, 7, 5));  // lower numbers never lower the floor (and now lose)
    ASSERT_FALSE(lower.has_value());
    EXPECT_TRUE(lower.error().rejected);
    EXPECT_EQ(lower.error().reject.reason, Reject::GenerationLower);
    const Floor f = fs->load().value();
    EXPECT_EQ(f.generation, 50u);
    EXPECT_EQ(f.epoch, 9u);
    EXPECT_EQ(f.sec_generation, 7u);
    EXPECT_EQ(f.body_hash, bundle(50, 9, 7).body_hash);
    EXPECT_EQ(f.sec_hash, bundle(50, 9, 7).sec_hash);
  }
  auto again = FloorState::open(d.path + "/sub");  // a new process would see the same file
  ASSERT_TRUE(again.has_value());
  EXPECT_EQ(again->load().value().generation, 50u);
  struct stat st {};
  ASSERT_EQ(::stat((d.path + "/sub/bundle-floor").c_str(), &st), 0);
  EXPECT_EQ(st.st_mode & 0777, 0600u);
}

TEST(FloorFile, DropBeforeMaximaOnlyRise) {
  TempDir d;
  auto fs = FloorState::open(d.path);
  ASSERT_TRUE(fs.has_value());
  ASSERT_TRUE(fs->commit(bundle(42, 7, 5, "r", "2026-11-01T00:00:00Z")).has_value());
  EXPECT_EQ(fs->load().value().drop_before.at("prod-llama"), 1793491200);
  ASSERT_TRUE(fs->commit(bundle(43, 7, 6, "r", "2026-10-01T00:00:00Z")).has_value());  // earlier: kept at the max
  EXPECT_EQ(fs->load().value().drop_before.at("prod-llama"), 1793491200);
  ASSERT_TRUE(fs->commit(bundle(44, 7, 7, "r", "2026-12-01T00:00:00Z")).has_value());
  EXPECT_EQ(fs->load().value().drop_before.at("prod-llama"), 1796083200);
  ASSERT_TRUE(fs->commit(bundle(45, 7, 8)).has_value());  // dropped from the bundle: the maximum stays
  EXPECT_EQ(fs->load().value().drop_before.at("prod-llama"), 1796083200);
}

TEST(FloorFile, ConcurrentCommittersEndAtTheMaximum) {
  TempDir d;
  std::vector<BundleView> views;
  for (std::uint64_t g = 1; g <= 24; ++g) views.push_back(bundle(g, 7, 5));
  std::vector<std::thread> threads;
  for (int t = 0; t < 4; ++t) {
    threads.emplace_back([&, t] {
      auto fs = FloorState::open(d.path);  // each "process" opens its own handle
      ASSERT_TRUE(fs.has_value());
      for (std::size_t i = 0; i < views.size(); ++i) {
        const std::size_t k = (i + static_cast<std::size_t>(t) * 6) % views.size();
        auto r = fs->commit(views[k]);  // a lower generation than the floor loses
        ASSERT_TRUE(r.has_value() || (r.error().rejected && r.error().reject.reason == Reject::GenerationLower));
      }
    });
  }
  for (auto& th : threads) th.join();
  auto fs = FloorState::open(d.path);
  const Floor f = fs->load().value();
  EXPECT_EQ(f.generation, 24u);
  EXPECT_EQ(f.body_hash, views[23].body_hash);
}

TEST(FloorFile, CorruptFileIsAnErrorNeverBlank) {
  TempDir d;
  auto fs = FloorState::open(d.path);
  ASSERT_TRUE(fs.has_value());
  ASSERT_TRUE(fs->commit(bundle(42, 7, 5)).has_value());
  const std::string path = d.path + "/bundle-floor";
  std::string text;
  ASSERT_TRUE(tu::read_file(path, text));
  for (const std::string& bad : {std::string("garbage\n"), text.substr(0, text.size() / 2), text + "extra: 1\n",
                                text + "drop_before: zz 1\n"}) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    ASSERT_NE(f, nullptr);
    std::fwrite(bad.data(), 1, bad.size(), f);
    std::fclose(f);
    EXPECT_FALSE(fs->load().has_value()) << bad;
    EXPECT_FALSE(fs->commit(bundle(43, 7, 5)).has_value());
  }
}

TEST(FloorFile, SerializationRoundTrips) {
  Floor f;
  f.generation = 9223372036854775807ull;
  f.sec_generation = 3;
  f.epoch = 4294967295u;
  f.body_hash = sha256("a");
  f.sec_hash = sha256("b");
  f.drop_before["a name with spaces"] = -5;
  f.drop_before["x"] = 1793491200;
  auto g = parse_floor(serialize_floor(f));
  ASSERT_TRUE(g.has_value());
  EXPECT_EQ(g->generation, f.generation);
  EXPECT_EQ(g->epoch, f.epoch);
  EXPECT_EQ(g->drop_before, f.drop_before);
  EXPECT_EQ(g->body_hash, f.body_hash);
}

// ---- Floor rule cases ----------------------------------------------------------------------

TEST(FloorCommit, ReturnsTheVerdict) {
  TempDir d;
  auto fs = FloorState::open(d.path);
  ASSERT_TRUE(fs.has_value());
  auto a = fs->commit(bundle(42, 7, 5));
  ASSERT_TRUE(a.has_value());
  EXPECT_EQ(a.value(), Verdict::Apply);
  auto b = fs->commit(bundle(42, 7, 5));  // idempotent re-push
  ASSERT_TRUE(b.has_value());
  EXPECT_EQ(b.value(), Verdict::Replace);
  auto c = fs->commit(bundle(43, 7, 5));
  ASSERT_TRUE(c.has_value());
  EXPECT_EQ(c.value(), Verdict::Apply);
  // The trust-file pin is honoured under the lock too.
  auto p = fs->commit(bundle(44, 7, 5), 6);
  ASSERT_FALSE(p.has_value());
  EXPECT_EQ(p.error().reject.reason, Reject::SecGenerationLower);
  EXPECT_EQ(fs->load().value().generation, 43u);
}

TEST(FloorCommit, LoserOfTwoBodiesAtOneGenerationLearnsItLost) {
  TempDir d;
  const BundleView a = bundle(42, 7, 5, "body A");
  const BundleView b = bundle(42, 7, 5, "body B");
  auto p1 = FloorState::open(d.path);  // two "processes", both checked the blank floor
  auto p2 = FloorState::open(d.path);
  ASSERT_TRUE(p1.has_value() && p2.has_value());
  ASSERT_EQ(check_against_floor(p1->load().value(), a, 0).value(), Verdict::Apply);
  ASSERT_EQ(check_against_floor(p2->load().value(), b, 0).value(), Verdict::Apply);
  ASSERT_TRUE(p1->commit(a).has_value());
  auto lost = p2->commit(b);
  ASSERT_FALSE(lost.has_value());
  ASSERT_TRUE(lost.error().rejected);
  EXPECT_EQ(lost.error().reject.reason, Reject::EqualGeneration);
  EXPECT_EQ(p2->load().value().body_hash, a.body_hash);  // the file keeps the winner
}

TEST(FloorCommit, RacingThreadsExactlyOneWinsPerGeneration) {
  TempDir d;
  std::vector<BundleView> views;
  for (int i = 0; i < 8; ++i) views.push_back(bundle(42, 7, 5, "body " + std::to_string(i)));
  std::atomic<int> applied{0}, lost{0};
  std::vector<std::thread> threads;
  for (std::size_t i = 0; i < views.size(); ++i) {
    threads.emplace_back([&, i] {
      auto fs = FloorState::open(d.path);
      auto r = fs->commit(views[i]);
      if (r.has_value()) ++applied;
      else if (r.error().rejected && r.error().reject.reason == Reject::EqualGeneration) ++lost;
    });
  }
  for (auto& th : threads) th.join();
  EXPECT_EQ(applied.load(), 1);
  EXPECT_EQ(lost.load(), 7);
}

TEST(FloorCommit, EqualGenerationAndBodyWithHigherSecIsRejected) {
  TempDir d;
  auto fs = FloorState::open(d.path);
  ASSERT_TRUE(fs->commit(bundle(42, 7, 5)).has_value());
  auto r = fs->commit(bundle(42, 7, 6));
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().reject.reason, Reject::EqualGeneration);
  EXPECT_EQ(fs->load().value().sec_generation, 5u);
  ASSERT_TRUE(fs->commit(bundle(43, 7, 6)).has_value());  // a new generation carries the new sec
}

TEST(FloorFile, TmpFileIsReplacedNotFollowed) {
  TempDir d;
  auto fs = FloorState::open(d.path);
  ASSERT_TRUE(fs.has_value());
  const std::string victim = d.path + "/victim";
  {
    std::FILE* f = std::fopen(victim.c_str(), "wb");
    ASSERT_NE(f, nullptr);
    std::fputs("keep", f);
    std::fclose(f);
  }
  ASSERT_EQ(::symlink(victim.c_str(), (d.path + "/bundle-floor.tmp").c_str()), 0);  // planted symlink
  ASSERT_TRUE(fs->commit(bundle(42, 7, 5)).has_value());
  std::string text;
  ASSERT_TRUE(tu::read_file(victim, text));
  EXPECT_EQ(text, "keep");
  EXPECT_EQ(fs->load().value().generation, 42u);
  struct stat st {};
  EXPECT_NE(::lstat((d.path + "/bundle-floor.tmp").c_str(), &st), 0);  // renamed away, none left
  // A stale tmp regular file is replaced too.
  {
    std::FILE* f = std::fopen((d.path + "/bundle-floor.tmp").c_str(), "wb");
    ASSERT_NE(f, nullptr);
    std::fputs("stale", f);
    std::fclose(f);
  }
  ASSERT_TRUE(fs->commit(bundle(43, 7, 5)).has_value());
  EXPECT_EQ(fs->load().value().generation, 43u);
}

TEST(FloorFile, SymlinkedFloorFileIsNeverRead) {
  TempDir d;
  auto fs = FloorState::open(d.path);
  ASSERT_TRUE(fs->commit(bundle(42, 7, 5)).has_value());
  ASSERT_EQ(::rename((d.path + "/bundle-floor").c_str(), (d.path + "/real").c_str()), 0);
  ASSERT_EQ(::symlink((d.path + "/real").c_str(), (d.path + "/bundle-floor").c_str()), 0);
  EXPECT_FALSE(fs->load().has_value());  // O_NOFOLLOW: an error, never the blank floor
}
