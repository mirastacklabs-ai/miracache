// SPDX-License-Identifier: Apache-2.0
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <set>
#include <memory>
#include <string>
#include <vector>

#include <gtest/gtest.h>

#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "proto/storage_layout.h"
#include "store/arena.h"
#include "store/node_state.h"

namespace miracache::store {
namespace {

class TempDir {
 public:
  TempDir() {
    std::string t = ::testing::TempDir() + "/mira-store-XXXXXX";
    path_ = ::mkdtemp(t.data()) ? t : std::string();
  }
  ~TempDir() {
    std::error_code ec;
    if (!path_.empty()) std::filesystem::remove_all(path_, ec);
  }
  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

StoreConfig small_cfg() {
  StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 4;
  c.gen_chunk = 1000;
  c.node_id = 7;
  return c;
}

TEST(Arena, AnonOpenFormats) {
  auto a = Arena::open(small_cfg());
  ASSERT_TRUE(a);
  auto& ar = **a;
  EXPECT_TRUE(ar.fresh());
  EXPECT_EQ(ar.layout().n_segments, 4u);
  EXPECT_EQ(ar.state_gen().size(), ar.layout().sg_slots());
  EXPECT_EQ(ar.superblock().sg_slots, ar.layout().sg_slots());
  for (std::uint32_t s = 0; s < 4; ++s) EXPECT_EQ(ar.segment(s).size(), 4u << 20);
  // Metadata of every segment decodes and matches the layout.
  for (std::uint32_t s = 0; s < 4; ++s) {
    auto m = proto::decode_segment_meta(std::span<const std::byte, proto::kSegmentMetaSize>(
        ar.segment(s).data() + kSegmentMetaOff, proto::kSegmentMetaSize));
    ASSERT_TRUE(m);
    EXPECT_EQ(m->seg_id, s);
    EXPECT_EQ(m->data_off, ar.layout().seg.data_off);
  }
  // Block and header views stay inside the segment.
  auto l = ar.layout().seg;
  auto b = ar.block(3, l.block_off(l.n_runs - 1, 63, 12), 4096);
  EXPECT_EQ(b.size(), 4096u);
  EXPECT_EQ(b.data() + b.size(), ar.segment(3).data() + l.run_data_off(l.n_runs - 1) + l.run_bytes);
}

TEST(Arena, ProductionConfigRejectsAnon) {
  auto c = small_cfg();
  c.production = true;
  auto a = Arena::open(c);
  ASSERT_FALSE(a);
  EXPECT_EQ(a.error().code, ErrorCode::InvalidArgument);
}

TEST(Arena, GenerationsStrictlyIncreaseAndPersistInChunks) {
  auto a = Arena::open(small_cfg());
  ASSERT_TRUE(a);
  auto& g = (*a)->gens();
  const auto seq0 = (*a)->superblock().seq;
  EXPECT_EQ(g.next(), 1u);
  EXPECT_EQ((*a)->superblock().gen_hwm, 1000u);
  EXPECT_EQ((*a)->superblock().seq, seq0 + 1);
  std::uint64_t prev = 1;
  for (int i = 0; i < 2500; ++i) {
    auto n = g.next();
    ASSERT_EQ(n, prev + 1);
    prev = n;
    EXPECT_LE(n, (*a)->superblock().gen_hwm);
  }
  // 2501 values from chunk 1000: marks at 1000, 2000, 3000 -> 3 persists total.
  EXPECT_EQ((*a)->superblock().seq, seq0 + 3);
  EXPECT_EQ(g.high_water_mark(), 3000u);
  EXPECT_TRUE(proto::generation_valid(g.last()));
}

TEST(Arena, FileBackingGenerationsUniqueAcrossReopen) {
  TempDir td;
  ASSERT_FALSE(td.path().empty());
  auto cfg = small_cfg();
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();

  std::set<std::uint64_t> seen;
  std::uint64_t max_issued = 0;
  for (int round = 0; round < 4; ++round) {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
    EXPECT_EQ((*a)->fresh(), round == 0);
    if (round > 0) EXPECT_FALSE((*a)->was_clean());  // earlier rounds "crash": no shutdown_clean
    for (int i = 0; i < 1234 + round; ++i) {
      auto n = (*a)->gens().next();
      EXPECT_TRUE(seen.insert(n).second) << "generation reissued: " << n;
      EXPECT_GT(n, max_issued);
      max_issued = n;
    }
    EXPECT_GE((*a)->superblock().gen_hwm, max_issued);
    // Arena destroyed here without a clean shutdown (simulated crash).
  }
}

// s12 (tpu-sync cross-check C2): the restart scan infers each run's block size from min_block_bytes, so a warm start
// under another value is refused (STATIC), and the formatted value is recorded in the superblock.
TEST(Arena, MinBlockBytesIsRecordedAndAChangeIsRefused) {
  TempDir td;
  ASSERT_FALSE(td.path().empty());
  auto cfg = small_cfg();
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
    EXPECT_EQ((*a)->superblock().min_block_log2, 12);  // 4096
  }
  auto other = cfg;
  other.min_block_bytes = 8192;
  auto b = Arena::open(other);  // the computed scope region differs too: the min-block check names the real cause first
  ASSERT_FALSE(b);
  EXPECT_NE(std::string(b.error().context).find("min_block_bytes"), std::string::npos) << b.error().context;
  auto again = Arena::open(cfg);  // the store itself is untouched by the refusal
  ASSERT_TRUE(again) << (again ? "" : again.error().context);
  EXPECT_FALSE((*again)->fresh());
}

// A store from before s12 has 0 in that byte (reserved zero): it is re-formatted once, then recorded.
TEST(Arena, StoreWithoutRecordedMinBlockIsReformattedOnce) {
  TempDir td;
  ASSERT_FALSE(td.path().empty());
  auto cfg = small_cfg();
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
  }
  {  // rewrite both superblock copies as a pre-s12 store would have them
    const std::string seg0 = td.path() + "/segment-0000";
    std::FILE* f = std::fopen(seg0.c_str(), "r+b");
    ASSERT_NE(f, nullptr);
    for (long copy = 0; copy < 2; ++copy) {
      std::array<std::byte, proto::kSuperblockSize> buf{};
      ASSERT_EQ(std::fseek(f, copy * static_cast<long>(proto::kSuperblockSize), SEEK_SET), 0);
      ASSERT_EQ(std::fread(buf.data(), 1, buf.size(), f), buf.size());
      auto sb = proto::decode_superblock(buf);
      ASSERT_TRUE(sb);
      sb->min_block_log2 = 0;
      ASSERT_TRUE(proto::encode(*sb, buf));
      ASSERT_EQ(std::fseek(f, copy * static_cast<long>(proto::kSuperblockSize), SEEK_SET), 0);
      ASSERT_EQ(std::fwrite(buf.data(), 1, buf.size(), f), buf.size());
    }
    std::fclose(f);
  }
  auto b = Arena::open(cfg);
  ASSERT_TRUE(b) << (b ? "" : b.error().context);
  EXPECT_TRUE((*b)->fresh()) << "a store that does not record its minimum block size must start cold";
  EXPECT_EQ((*b)->superblock().min_block_log2, 12);
}

// Plan 2C: the node ID is drawn at random on a blank store, kept in the superblock on a File store
// (warm restart reads it back), and redrawn for a volatile (Anon) store, which is blank at every start.
TEST(Arena, NodeIdIsRandomAndSurvivesWarmRestart) {
  TempDir td;
  auto cfg = small_cfg();
  cfg.node_id = 0;  // production: no ID configured
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  std::uint32_t first = 0;
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
    first = (*a)->superblock().node_id;
    EXPECT_NE(first, 0u);
  }
  for (int i = 0; i < 2; ++i) {  // crash restart and clean restart alike
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    EXPECT_FALSE((*a)->fresh());
    EXPECT_EQ((*a)->superblock().node_id, first);
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  // Test hook: a configured ID that differs from the stored one is still refused.
  auto hook = cfg;
  hook.node_id = first + 1 == 0 ? 1 : first + 1;
  EXPECT_FALSE(Arena::open(hook));
  // Volatile store: a new random ID each start (the cache is gone, so is the identity).
  std::set<std::uint32_t> ids;
  auto anon = small_cfg();
  anon.node_id = 0;
  for (int i = 0; i < 4; ++i) {
    auto a = Arena::open(anon);
    ASSERT_TRUE(a);
    EXPECT_NE((*a)->superblock().node_id, 0u);
    ids.insert((*a)->superblock().node_id);
  }
  EXPECT_GT(ids.size(), 1u);
}


// ---- review r9 S04: the node ID lives in <state_dir>/node-id --------------------------------------------------
std::string slurp(const std::string& p) {
  std::FILE* f = std::fopen(p.c_str(), "rb");
  if (!f) return {};
  char buf[128];
  std::size_t n = std::fread(buf, 1, sizeof buf, f);
  std::fclose(f);
  return std::string(buf, n);
}
unsigned mode_of(const std::string& p) {
  struct stat st {};
  return ::stat(p.c_str(), &st) == 0 ? (st.st_mode & 0777u) : 0u;
}
void wipe_dir(const std::string& d) {
  for (const auto& e : std::filesystem::directory_iterator(d)) std::filesystem::remove_all(e.path());
}

TEST(ArenaStateFile, BlankStoreDrawsAndWritesFile0600AndAWipedStoreKeepsTheId) {
  TempDir td, st;
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  cfg.state_dir = st.path() + "/sub/state";  // created, mode 0700
  std::uint32_t first = 0;
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
    first = (*a)->superblock().node_id;
    ASSERT_NE(first, 0u);
    EXPECT_TRUE((*a)->fresh());
  }
  EXPECT_EQ(slurp(cfg.state_dir + "/node-id"), std::to_string(first) + "\n");
  EXPECT_EQ(mode_of(cfg.state_dir + "/node-id"), 0600u);
  EXPECT_EQ(mode_of(cfg.state_dir), 0700u);
  // The store is wiped (hugetlbfs after a reboot, a replaced disk): same identity, formatted fresh.
  wipe_dir(td.path());
  for (int i = 0; i < 2; ++i) {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
    EXPECT_EQ((*a)->superblock().node_id, first);
    EXPECT_EQ(!(*a)->fresh(), i == 1);  // the second start finds the store the first one formatted
  }
  // A volatile store is blank at every start and keeps the ID too.
  auto anon = small_cfg();
  anon.node_id = 0;
  anon.state_dir = cfg.state_dir;
  for (int i = 0; i < 3; ++i) {
    auto a = Arena::open(anon);
    ASSERT_TRUE(a);
    EXPECT_EQ((*a)->superblock().node_id, first);
  }
  // Deleting the file is the way to a new identity (the directory is initialised: a replacement, r9b T01).
  std::filesystem::remove(cfg.state_dir + "/node-id");
  auto a = Arena::open(anon);
  ASSERT_TRUE(a);
  EXPECT_NE((*a)->superblock().node_id, 0u);
  EXPECT_EQ(slurp(cfg.state_dir + "/node-id"), std::to_string((*a)->superblock().node_id) + "\n");
}

TEST(ArenaStateFile, MissingFileWithAPersistentStoreAdoptsTheStoresId) {
  TempDir td, st;
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  std::uint32_t id = 0;
  {  // an older memory node: no state file, the ID is in the superblock only
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    id = (*a)->superblock().node_id;
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  cfg.state_dir = st.path();
  auto a = Arena::open(cfg);
  ASSERT_TRUE(a) << (a ? "" : a.error().context);
  EXPECT_FALSE((*a)->fresh());  // the cache is kept
  EXPECT_TRUE((*a)->was_clean());
  EXPECT_EQ((*a)->superblock().node_id, id);
  EXPECT_EQ(slurp(st.path() + "/node-id"), std::to_string(id) + "\n");
}

TEST(ArenaStateFile, GarbageFileCountsAsMissing) {
  TempDir td, st;
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  std::uint32_t id = 0;
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    id = (*a)->superblock().node_id;
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  cfg.state_dir = st.path();
  for (const char* junk : {"", "abc\n", "0\n", "4294967296\n", "12 34\n"}) {
    std::filesystem::remove(st.path() + "/initialised");  // a never-initialised dir: the upgrade path adopts the store's ID
    std::FILE* f = std::fopen((st.path() + "/node-id").c_str(), "wb");
    ASSERT_NE(f, nullptr);
    std::fputs(junk, f);
    std::fclose(f);
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << junk;
    EXPECT_EQ((*a)->superblock().node_id, id) << junk;
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  // r9b T01: in an initialised dir an unreadable node-id counts as deleted: the node is replaced (new ID, reformatted).
  {
    std::FILE* f = std::fopen((st.path() + "/node-id").c_str(), "wb");
    ASSERT_NE(f, nullptr);
    std::fputs("junk\n", f);
    std::fclose(f);
  }
  auto a = Arena::open(cfg);
  ASSERT_TRUE(a);
  EXPECT_TRUE((*a)->fresh());
  EXPECT_NE((*a)->superblock().node_id, id);
}

TEST(ArenaStateFile, StoreOfAnotherIdentityIsReformattedNeverRefused) {
  TempDir td, st;
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  cfg.state_dir = st.path();
  std::uint32_t id = 0;
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    id = (*a)->superblock().node_id;
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  const std::uint32_t other = id == 77 ? 78 : 77;
  {  // another identity in the file: the store belongs to somebody else
    std::FILE* f = std::fopen((st.path() + "/node-id").c_str(), "wb");
    ASSERT_NE(f, nullptr);
    std::fprintf(f, "%u\n", other);
    std::fclose(f);
  }
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
    EXPECT_TRUE((*a)->fresh());  // reformatted as blank
    EXPECT_FALSE((*a)->was_clean());
    EXPECT_EQ((*a)->superblock().node_id, other);
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  auto a = Arena::open(cfg);  // and the next start is a normal warm one
  ASSERT_TRUE(a);
  EXPECT_FALSE((*a)->fresh());
  EXPECT_EQ((*a)->superblock().node_id, other);
  EXPECT_EQ(slurp(st.path() + "/node-id"), std::to_string(other) + "\n");
}

TEST(NodeStateFile, WriteIsAtomicAndReplacesAStaleTemp) {
  TempDir td;
  const std::string dir = td.path() + "/s";
  ASSERT_TRUE(prepare_state_dir(dir));
  ASSERT_TRUE(write_node_id_file(dir, 41));
  // A crash left a half-written temp file behind: the committed file is untouched and the next write replaces it.
  {
    std::FILE* f = std::fopen((dir + "/node-id.tmp").c_str(), "wb");
    ASSERT_NE(f, nullptr);
    std::fputs("999", f);
    std::fclose(f);
  }
  auto r = read_node_id_file(dir);
  ASSERT_TRUE(r);
  ASSERT_TRUE(r->has_value());
  EXPECT_EQ(**r, 41u);
  ASSERT_TRUE(write_node_id_file(dir, 42));
  r = read_node_id_file(dir);
  ASSERT_TRUE(r && r->has_value());
  EXPECT_EQ(**r, 42u);
  std::set<std::string> names;
  for (const auto& e : std::filesystem::directory_iterator(dir)) names.insert(e.path().filename().string());
  EXPECT_EQ(names, (std::set<std::string>{"node-id"}));  // no temp file left
  EXPECT_EQ(mode_of(dir + "/node-id"), 0600u);
  EXPECT_FALSE(write_node_id_file(dir, 0));
  auto none = read_node_id_file(td.path() + "/nope");
  ASSERT_TRUE(none);
  EXPECT_FALSE(none->has_value());
}

// ---- review r9b T01: replacing a node with a persistent store that still holds data -----------------------------------
TEST(ArenaStateFile, ReplacingANodeWithAFullStoreDrawsANewIdAndReformats) {
  TempDir td, st;
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  cfg.state_dir = st.path() + "/s";
  std::uint32_t first = 0;
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
    first = (*a)->superblock().node_id;
    EXPECT_TRUE((*a)->fresh());
    (void)(*a)->gens().next();
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  EXPECT_EQ(mode_of(cfg.state_dir + "/initialised"), 0600u);  // the directory is initialised
  {  // a restart keeps the store (and its data) and the ID
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    EXPECT_FALSE((*a)->fresh());
    EXPECT_TRUE((*a)->was_clean());
    EXPECT_EQ((*a)->superblock().node_id, first);
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  // Replacing the node: delete node-id. The store still holds the old identity's data; it must not be re-adopted.
  ASSERT_TRUE(std::filesystem::remove(cfg.state_dir + "/node-id"));
  std::uint32_t second = 0;
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a) << (a ? "" : a.error().context);
    second = (*a)->superblock().node_id;
    EXPECT_NE(second, 0u);
    EXPECT_NE(second, first) << "a replaced node must draw a new ID, not adopt the one in its store";
    EXPECT_TRUE((*a)->fresh()) << "the old identity's cache is reformatted";
    EXPECT_FALSE((*a)->was_clean());
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  EXPECT_EQ(slurp(cfg.state_dir + "/node-id"), std::to_string(second) + "\n");
  auto a = Arena::open(cfg);  // the next start is a normal warm one under the new ID
  ASSERT_TRUE(a);
  EXPECT_FALSE((*a)->fresh());
  EXPECT_EQ((*a)->superblock().node_id, second);
}

// ---- review r9b T02: one memory node per state_dir --------------------------------------------------------------------
TEST(ArenaStateFile, ASecondOpenOfOneStateDirFailsInThisProcessAndInAnother) {
  TempDir st;
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.state_dir = st.path();
  auto a = Arena::open(cfg);
  ASSERT_TRUE(a) << (a ? "" : a.error().context);
  const std::uint32_t id = (*a)->superblock().node_id;
  auto b = Arena::open(cfg);  // a second open in this process
  ASSERT_FALSE(b);
  EXPECT_EQ(b.error().code, ErrorCode::Busy);
  EXPECT_NE(std::string(b.error().context).find("state_dir"), std::string::npos);
  const pid_t pid = ::fork();  // a second memory node process on the same state_dir
  ASSERT_GE(pid, 0);
  if (pid == 0) {
    auto c = Arena::open(cfg);
    ::_exit(c ? 0 : c.error().code == ErrorCode::Busy ? 3 : 4);
  }
  int wst = 0;
  ASSERT_EQ(::waitpid(pid, &wst, 0), pid);
  ASSERT_TRUE(WIFEXITED(wst));
  EXPECT_EQ(WEXITSTATUS(wst), 3) << "the second process must fail with Busy";
  (*a).reset();  // the first one stops: the lock is free again
  auto c = Arena::open(cfg);
  ASSERT_TRUE(c) << (c ? "" : c.error().context);
  EXPECT_EQ((*c)->superblock().node_id, id);
}

// ---- review r9b T03: no symlink is followed, and an unsafe state_dir is refused ---------------------------------------
TEST(NodeStateFile, SymlinksAreNeverFollowedAndAnUnsafeDirIsRefused) {
  TempDir td;
  const std::string dir = td.path() + "/s", victim = td.path() + "/victim";
  ASSERT_TRUE(prepare_state_dir(dir));
  {
    std::FILE* f = std::fopen(victim.c_str(), "wb");
    ASSERT_NE(f, nullptr);
    std::fputs("keep", f);
    std::fclose(f);
  }
  // A planted tmp symlink: the write never goes through it.
  ASSERT_EQ(::symlink(victim.c_str(), (dir + "/node-id.tmp").c_str()), 0);
  ASSERT_TRUE(write_node_id_file(dir, 5));
  EXPECT_EQ(slurp(victim), "keep");
  auto r = read_node_id_file(dir);
  ASSERT_TRUE(r && r->has_value());
  EXPECT_EQ(**r, 5u);
  // A symlinked node-id or marker is refused, not read through.
  ASSERT_TRUE(std::filesystem::remove(dir + "/node-id"));
  ASSERT_EQ(::symlink(victim.c_str(), (dir + "/node-id").c_str()), 0);
  auto bad_read = read_node_id_file(dir);
  ASSERT_FALSE(bad_read);
  EXPECT_EQ(bad_read.error().code, ErrorCode::AccessDenied);
  ASSERT_EQ(::symlink(victim.c_str(), (dir + "/initialised").c_str()), 0);
  EXPECT_FALSE(state_dir_initialised(dir));
  EXPECT_EQ(slurp(victim), "keep");

  // A group- or world-writable state_dir is refused, and the memory node does not start on it.
  const std::string open_dir = td.path() + "/open";
  ASSERT_TRUE(prepare_state_dir(open_dir));
  for (unsigned mode : {0770u, 0702u, 0777u}) {
    ASSERT_EQ(::chmod(open_dir.c_str(), mode), 0);
    auto p = prepare_state_dir(open_dir);
    ASSERT_FALSE(p) << std::oct << mode;
    EXPECT_EQ(p.error().code, ErrorCode::AccessDenied);
  }
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.state_dir = open_dir;
  auto a = Arena::open(cfg);
  ASSERT_FALSE(a);
  EXPECT_EQ(a.error().code, ErrorCode::AccessDenied);
  EXPECT_FALSE(std::filesystem::exists(open_dir + "/node-id"));  // nothing was written
  EXPECT_FALSE(std::filesystem::exists(open_dir + "/node-id.lock"));
  ASSERT_EQ(::chmod(open_dir.c_str(), 0700), 0);
  EXPECT_TRUE(prepare_state_dir(open_dir));
  // A directory owned by another user is refused (needs root to set up).
  if (::geteuid() == 0) {
    ASSERT_EQ(::chown(open_dir.c_str(), 4242, 4242), 0);
    auto p = prepare_state_dir(open_dir);
    ASSERT_FALSE(p);
    EXPECT_EQ(p.error().code, ErrorCode::AccessDenied);
    ASSERT_EQ(::chown(open_dir.c_str(), 0, 0), 0);
  }
}

// ---- review r9c U05/U06: a symlinked state_dir is refused; a FIFO or other odd file never hangs or passes ------------
TEST(NodeStateFile, SymlinkedStateDirIsRefused) {
  TempDir td;
  const std::string real = td.path() + "/real", link = td.path() + "/link";
  ASSERT_TRUE(prepare_state_dir(real));
  ASSERT_EQ(::symlink(real.c_str(), link.c_str()), 0);
  auto p = prepare_state_dir(link);
  ASSERT_FALSE(p);
  EXPECT_EQ(p.error().code, ErrorCode::AccessDenied);
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.state_dir = link;
  EXPECT_FALSE(Arena::open(cfg));
  EXPECT_FALSE(std::filesystem::exists(real + "/node-id"));  // nothing was written through the link
}

TEST(NodeStateFile, FifoAndNonRegularStateFilesAreRejectedWithoutHanging) {
  TempDir td;
  const std::string dir = td.path() + "/s";
  ASSERT_TRUE(prepare_state_dir(dir));
  ASSERT_EQ(::mkfifo((dir + "/node-id").c_str(), 0600), 0);  // would block an open without O_NONBLOCK
  auto r = read_node_id_file(dir);
  ASSERT_FALSE(r);
  EXPECT_EQ(r.error().code, ErrorCode::InvalidArgument);
  ASSERT_EQ(::mkfifo((dir + "/initialised").c_str(), 0600), 0);
  auto ini = state_dir_initialised(dir);
  ASSERT_FALSE(ini);
  EXPECT_EQ(ini.error().code, ErrorCode::InvalidArgument);
  ASSERT_EQ(::mkfifo((dir + "/node-id.lock").c_str(), 0600), 0);
  auto lk = StateDirLock::acquire(dir);
  ASSERT_FALSE(lk);
  EXPECT_EQ(lk.error().code, ErrorCode::InvalidArgument);
  // A directory in place of the marker is rejected the same way.
  ASSERT_EQ(::unlink((dir + "/initialised").c_str()), 0);
  ASSERT_EQ(::mkdir((dir + "/initialised").c_str(), 0700), 0);
  EXPECT_FALSE(state_dir_initialised(dir));
}

// ---- review r9c U03: the reformat crash window ------------------------------------------------------------------------
class RecordingBacking : public Backing {
 public:
  explicit RecordingBacking(std::unique_ptr<Backing> in) : in_(std::move(in)) {}
  Expected<std::span<std::byte>> map(std::uint32_t seg, std::size_t len) override { return in_->map(seg, len); }
  Status sync(std::uint32_t seg, std::size_t off, std::size_t len) override {
    order.push_back(seg);
    return in_->sync(seg, off, len);
  }
  BackingKind kind() const noexcept override { return in_->kind(); }
  std::vector<std::uint32_t> order;

 private:
  std::unique_ptr<Backing> in_;
};

TEST(Arena, FormatSyncsSegmentZeroLast) {
  auto cfg = small_cfg();
  auto rec = std::make_unique<RecordingBacking>(make_backing(cfg));
  auto* r = rec.get();
  auto a = Arena::open(cfg, std::move(rec));
  ASSERT_TRUE(a);
  ASSERT_GE(r->order.size(), 4u);
  EXPECT_EQ(r->order[0], 1u);
  EXPECT_EQ(r->order[1], 2u);
  EXPECT_EQ(r->order[2], 3u);
  EXPECT_EQ(r->order[3], 0u);  // the superblocks go last
}

TEST(ArenaStateFile, ValidSuperblockOverZeroedSegmentMetaIsABlankStoreNotAFailure) {
  TempDir td, st;
  auto cfg = small_cfg();
  cfg.node_id = 0;
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  cfg.state_dir = st.path() + "/s";
  std::uint32_t id = 0;
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    id = (*a)->superblock().node_id;
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  // The crash window of a reformat: segment 0 (with a valid superblock) reached the disk, segments 1..3 did not.
  for (unsigned s = 1; s < cfg.n_segments; ++s) {
    char name[32];
    std::snprintf(name, sizeof name, "/segment-%04u", s);
    std::FILE* f = std::fopen((td.path() + name).c_str(), "r+b");
    ASSERT_NE(f, nullptr);
    ASSERT_EQ(std::fseek(f, static_cast<long>(kSegmentMetaOff), SEEK_SET), 0);
    const std::string zeros(proto::kSegmentMetaSize, '\0');
    ASSERT_EQ(std::fwrite(zeros.data(), 1, zeros.size(), f), zeros.size());
    std::fclose(f);
  }
  auto a = Arena::open(cfg);
  ASSERT_TRUE(a) << (a ? "" : a.error().context);
  EXPECT_TRUE((*a)->fresh());
  EXPECT_EQ((*a)->superblock().node_id, id);  // the identity (state file) is kept
  ASSERT_TRUE((*a)->shutdown_clean());
  a->reset();  // release the state_dir lock
  a = Arena::open(cfg);  // and the next start is a normal warm one
  ASSERT_TRUE(a);
  EXPECT_FALSE((*a)->fresh());
}

TEST(Arena, CleanShutdownIsReportedAndKeepsGeometry) {
  TempDir td;
  auto cfg = small_cfg();
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    (void)(*a)->gens().next();
    ASSERT_TRUE((*a)->shutdown_clean());
  }
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    EXPECT_FALSE((*a)->fresh());
    EXPECT_TRUE((*a)->was_clean());
    EXPECT_GE((*a)->gens().next(), 1000u);  // continues above the persisted mark
  }
  auto bad = cfg;
  bad.node_id = 9;
  auto a = Arena::open(bad);
  ASSERT_FALSE(a);
  EXPECT_EQ(a.error().code, ErrorCode::InvalidArgument);
}

TEST(Arena, TornNewestSuperblockStillNeverReissues) {
  TempDir td;
  auto cfg = small_cfg();
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  std::uint64_t max_issued = 0;
  std::uint64_t newest_copy = 0;
  {
    auto a = Arena::open(cfg);
    ASSERT_TRUE(a);
    for (int i = 0; i < 2500; ++i) max_issued = (*a)->gens().next();
    newest_copy = (*a)->superblock().seq & 1;
  }
  {  // Tear the newest copy (flip a byte so its CRC fails).
    std::FILE* f = std::fopen((td.path() + "/segment-0000").c_str(), "r+b");
    ASSERT_NE(f, nullptr);
    ASSERT_EQ(std::fseek(f, static_cast<long>(newest_copy * proto::kSuperblockSize + 40), SEEK_SET), 0);
    std::fputc(0x5a, f);
    std::fclose(f);
  }
  auto a = Arena::open(cfg);
  ASSERT_TRUE(a);
  EXPECT_GT((*a)->gens().next(), max_issued);
}

TEST(Arena, SecondOpenOfSameDirIsBusy) {
  TempDir td;
  auto cfg = small_cfg();
  cfg.backing = BackingKind::File;
  cfg.dir = td.path();
  auto a = Arena::open(cfg);
  ASSERT_TRUE(a);
  auto b = Arena::open(cfg);
  ASSERT_FALSE(b);
  EXPECT_EQ(b.error().code, ErrorCode::Busy);
}

TEST(Arena, MissingDirFails) {
  auto cfg = small_cfg();
  cfg.backing = BackingKind::File;
  cfg.dir = "/nonexistent/mira-dir";
  EXPECT_FALSE(Arena::open(cfg));
}

TEST(Arena, HugetlbfsOnlyWhenProvided) {
  const char* dir = std::getenv("MIRACACHE_HUGETLBFS_DIR");
  if (!dir || !*dir) GTEST_SKIP() << "MIRACACHE_HUGETLBFS_DIR not set";
  auto cfg = small_cfg();
  cfg.backing = BackingKind::Hugetlbfs;
  cfg.dir = dir;
  cfg.segment_bytes = 64u << 20;
  cfg.run_bytes = 4u << 20;
  cfg.n_segments = 2;
  auto a = Arena::open(cfg);
  ASSERT_TRUE(a) << a.error().context;
  EXPECT_GE((*a)->gens().next(), 1u);
}

TEST(Arena, HugetlbfsRejectsPlainDirectory) {
#ifdef __linux__
  TempDir td;
  auto cfg = small_cfg();
  cfg.backing = BackingKind::Hugetlbfs;
  cfg.dir = td.path();
  auto a = Arena::open(cfg);
  ASSERT_FALSE(a);
  EXPECT_EQ(a.error().code, ErrorCode::InvalidArgument);
#else
  GTEST_SKIP() << "Linux only";
#endif
}

}  // namespace
}  // namespace miracache::store
