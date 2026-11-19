// SPDX-License-Identifier: Apache-2.0
#include "control/floor_state.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>

namespace miracache::control {

namespace {

constexpr char kMagic[] = "mira-bundle-floor-v1";

Error io(const char* ctx) { return Error{ErrorCode::Aborted, ctx}; }
Error corrupt(const char* ctx) { return Error{ErrorCode::Corrupt, ctx}; }

// RAII fd.
struct Fd {
  int fd = -1;
  Fd() = default;
  explicit Fd(int f) : fd(f) {}
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  ~Fd() {
    if (fd >= 0) ::close(fd);  // closing also drops the flock
  }
};

bool write_all(int fd, const std::string& s) {
  std::size_t off = 0;
  while (off < s.size()) {
    const ssize_t n = ::write(fd, s.data() + off, s.size() - off);
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    off += static_cast<std::size_t>(n);
  }
  return true;
}

// Whole file; `missing` is set (and an empty string returned) when it does not exist.
bool read_file(const std::string& path, std::string& out, bool& missing) {
  missing = false;
  Fd f(::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC));
  if (f.fd < 0) {
    if (errno == ENOENT) {
      missing = true;
      return true;
    }
    return false;
  }
  char buf[4096];
  for (;;) {
    const ssize_t n = ::read(f.fd, buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) continue;
      return false;
    }
    if (n == 0) break;
    out.append(buf, static_cast<std::size_t>(n));
    if (out.size() > (16u << 20)) return false;  // far beyond any real floor file
  }
  return true;
}

bool parse_u64(std::string_view s, std::uint64_t& out) {
  if (s.empty() || s.size() > 20) return false;
  if (s.size() > 1 && s[0] == '0') return false;
  std::uint64_t v = 0;
  for (const char c : s) {
    if (c < '0' || c > '9') return false;
    const std::uint64_t d = static_cast<std::uint64_t>(c - '0');
    if (v > (UINT64_MAX - d) / 10) return false;
    v = v * 10 + d;
  }
  out = v;
  return true;
}

bool parse_i64(std::string_view s, std::int64_t& out) {
  const bool neg = !s.empty() && s[0] == '-';
  std::uint64_t mag = 0;
  if (!parse_u64(neg ? s.substr(1) : s, mag)) return false;
  if (neg) {
    if (mag == 0 || mag > static_cast<std::uint64_t>(INT64_MAX) + 1) return false;
    out = static_cast<std::int64_t>(0 - mag);
  } else {
    if (mag > static_cast<std::uint64_t>(INT64_MAX)) return false;
    out = static_cast<std::int64_t>(mag);
  }
  return true;
}

bool take_line(std::string_view text, std::size_t& pos, std::string_view& line) {
  const std::size_t nl = text.find('\n', pos);
  if (nl == std::string_view::npos) return false;
  line = text.substr(pos, nl - pos);
  pos = nl + 1;
  return true;
}

bool take_field(std::string_view text, std::size_t& pos, std::string_view name, std::string_view& value) {
  std::string_view line;
  if (!take_line(text, pos, line)) return false;
  if (line.size() < name.size() + 2 || line.substr(0, name.size()) != name || line[name.size()] != ':' ||
      line[name.size() + 1] != ' ') {
    return false;
  }
  value = line.substr(name.size() + 2);
  return true;
}

bool fsync_dir(const std::string& dir) {
  Fd d(::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  return d.fd >= 0 && ::fsync(d.fd) == 0;
}

}  // namespace

// ---- acceptance -----------------------------------------------------------------------------

Expected<Verdict, BundleError> check_against_floor(const Floor& floor, const BundleView& b,
                                                   std::uint64_t pinned_min_sec_generation) {
  const std::uint64_t gen = b.body.generation;
  const bool have_floor = floor.generation > 0;
  if (have_floor) {
    if (gen < floor.generation) return BundleError{Reject::GenerationLower, "generation below the floor"};
    if (gen == floor.generation && b.body_hash != floor.body_hash) {
      return BundleError{Reject::EqualGeneration, "same generation, different body hash"};
    }
    // W07: a new sec needs a new generation (a poller with after=G would never fetch it).
    if (gen == floor.generation && b.sec.sec_generation > floor.sec_generation) {
      return BundleError{Reject::EqualGeneration, "same generation and body, higher sec_generation: bump the generation"};
    }
  }
  if (b.body.epoch < floor.epoch) return BundleError{Reject::EpochBackwards, "epoch below the applied epoch"};

  const std::uint64_t sec_floor = floor.effective_sec_floor(pinned_min_sec_generation);
  if (b.sec.sec_generation < sec_floor) {
    return BundleError{Reject::SecGenerationLower, "sec_generation below the security floor"};
  }
  if (floor.sec_generation > 0 && b.sec.sec_generation == floor.sec_generation && b.sec_hash != floor.sec_hash) {
    return BundleError{Reject::SecEqualGeneration, "same sec_generation, different sec hash"};
  }
  if (have_floor && gen == floor.generation && b.sec.sec_generation == floor.sec_generation) {
    return Verdict::Replace;
  }
  return Verdict::Apply;
}

// ---- text form ------------------------------------------------------------------------------

std::string serialize_floor(const Floor& f) {
  std::string s = kMagic;
  s += '\n';
  s += "generation: " + std::to_string(f.generation) + "\n";
  s += "body_hash: " + to_hex(f.body_hash) + "\n";
  s += "sec_generation: " + std::to_string(f.sec_generation) + "\n";
  s += "sec_hash: " + to_hex(f.sec_hash) + "\n";
  s += "epoch: " + std::to_string(f.epoch) + "\n";
  for (const auto& [name, t] : f.drop_before) {
    const std::vector<std::uint8_t> raw(name.begin(), name.end());
    s += "drop_before: " + to_hex(raw) + " " + std::to_string(t) + "\n";
  }
  return s;
}

Expected<Floor, Error> parse_floor(std::string_view text) {
  Floor f;
  std::size_t pos = 0;
  std::string_view line;
  if (!take_line(text, pos, line) || line != kMagic) return corrupt("floor: bad magic");
  std::string_view v;
  if (!take_field(text, pos, "generation", v) || !parse_u64(v, f.generation)) return corrupt("floor: generation");
  if (!take_field(text, pos, "body_hash", v) || !from_hex_lower(v, f.body_hash)) return corrupt("floor: body_hash");
  if (!take_field(text, pos, "sec_generation", v) || !parse_u64(v, f.sec_generation)) return corrupt("floor: sec_generation");
  if (!take_field(text, pos, "sec_hash", v) || !from_hex_lower(v, f.sec_hash)) return corrupt("floor: sec_hash");
  std::uint64_t epoch = 0;
  if (!take_field(text, pos, "epoch", v) || !parse_u64(v, epoch) || epoch > UINT32_MAX) return corrupt("floor: epoch");
  f.epoch = static_cast<std::uint32_t>(epoch);
  while (pos < text.size()) {
    if (!take_field(text, pos, "drop_before", v)) return corrupt("floor: trailing data");
    const std::size_t sp = v.find(' ');
    if (sp == std::string_view::npos || sp == 0 || sp % 2 != 0) return corrupt("floor: drop_before");
    std::vector<std::uint8_t> raw(sp / 2);
    std::int64_t t = 0;
    if (!from_hex_lower(v.substr(0, sp), raw) || !parse_i64(v.substr(sp + 1), t)) return corrupt("floor: drop_before");
    const std::string name(raw.begin(), raw.end());
    if (!f.drop_before.emplace(name, t).second) return corrupt("floor: duplicate drop_before");
  }
  return f;
}

// ---- the file -------------------------------------------------------------------------------

Expected<FloorState, Error> FloorState::open(std::string dir) {
  if (dir.empty()) return Error{ErrorCode::InvalidArgument, "floor: empty state_dir"};
  struct stat st {};
  if (::stat(dir.c_str(), &st) != 0) {
    if (errno != ENOENT || ::mkdir(dir.c_str(), 0700) != 0) return io("floor: cannot create state_dir");
  } else if (!S_ISDIR(st.st_mode)) {
    return Error{ErrorCode::InvalidArgument, "floor: state_dir is not a directory"};
  }
  return FloorState(std::move(dir));
}

Expected<Floor, Error> FloorState::load() const {
  Fd lock(::open((dir_ + "/bundle-floor.lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (lock.fd < 0) return io("floor: cannot open the lock file");
  while (::flock(lock.fd, LOCK_SH) != 0) {
    if (errno != EINTR) return io("floor: flock failed");
  }
  std::string text;
  bool missing = false;
  if (!read_file(dir_ + "/bundle-floor", text, missing)) return io("floor: cannot read bundle-floor");
  if (missing) return Floor{};
  return parse_floor(text);
}

// tmp + fsync + rename + directory fsync; the caller holds the exclusive lock.
static Status write_floor_file(const std::string& dir, const Floor& f) {
  const std::string tmp = dir + "/bundle-floor.tmp";
  // W08: a stale or planted tmp (file or symlink) is unlinked first and never followed.
  if (::unlink(tmp.c_str()) != 0 && errno != ENOENT) return io("floor: cannot remove a stale temp file");
  Fd out(::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (out.fd < 0) return io("floor: cannot create the temp file");
  if (!write_all(out.fd, serialize_floor(f)) || ::fsync(out.fd) != 0) {
    ::unlink(tmp.c_str());
    return io("floor: cannot write the temp file");
  }
  if (::rename(tmp.c_str(), (dir + "/bundle-floor").c_str()) != 0) {
    ::unlink(tmp.c_str());
    return io("floor: rename failed");
  }
  if (!fsync_dir(dir)) return io("floor: directory fsync failed");
  return {};
}

Expected<Verdict, CommitError> FloorState::commit(const BundleView& b, std::uint64_t pinned_min_sec_generation) const {
  Fd lock(::open((dir_ + "/bundle-floor.lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (lock.fd < 0) return CommitError(io("floor: cannot open the lock file"));
  while (::flock(lock.fd, LOCK_EX) != 0) {
    if (errno != EINTR) return CommitError(io("floor: flock failed"));
  }
  std::string text;
  bool missing = false;
  if (!read_file(dir_ + "/bundle-floor", text, missing)) return CommitError(io("floor: cannot read bundle-floor"));
  Floor f;
  if (!missing) {
    auto cur = parse_floor(text);
    if (!cur) return CommitError(cur.error());
    f = std::move(cur.value());
  }
  // W06: the check and the write are one step under the exclusive lock; the loser learns it lost.
  auto verdict = check_against_floor(f, b, pinned_min_sec_generation);
  if (!verdict) return CommitError(verdict.error());
  if (verdict.value() == Verdict::Replace) return Verdict::Replace;
  // Max-only: a number only rises, and its hash follows it.
  if (b.body.generation > f.generation) {
    f.generation = b.body.generation;
    f.body_hash = b.body_hash;
  }
  if (b.sec.sec_generation > f.sec_generation) {
    f.sec_generation = b.sec.sec_generation;
    f.sec_hash = b.sec_hash;
  }
  if (b.body.epoch > f.epoch) f.epoch = b.body.epoch;
  for (const PrincipalView& p : b.sec.principals) {
    if (!p.drop_before) continue;
    auto [it, inserted] = f.drop_before.emplace(p.name, *p.drop_before);
    if (!inserted && *p.drop_before > it->second) it->second = *p.drop_before;
  }

  if (auto st = write_floor_file(dir_, f); !st) return CommitError(st.error());
  return Verdict::Apply;
}

Status FloorState::raise_drop_before(const std::string& name, std::int64_t drop_before_unix_s) const {
  Fd lock(::open((dir_ + "/bundle-floor.lock").c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600));
  if (lock.fd < 0) return io("floor: cannot open the lock file");
  while (::flock(lock.fd, LOCK_EX) != 0) {
    if (errno != EINTR) return io("floor: flock failed");
  }
  std::string text;
  bool missing = false;
  if (!read_file(dir_ + "/bundle-floor", text, missing)) return io("floor: cannot read bundle-floor");
  Floor f;
  if (!missing) {
    auto cur = parse_floor(text);
    if (!cur) return cur.error();
    f = std::move(cur.value());
  }
  auto [it, inserted] = f.drop_before.emplace(name, drop_before_unix_s);
  if (!inserted) {
    if (drop_before_unix_s <= it->second) return {};  // max-only: already at or above, nothing to write
    it->second = drop_before_unix_s;
  }
  return write_floor_file(dir_, f);
}

}  // namespace miracache::control
