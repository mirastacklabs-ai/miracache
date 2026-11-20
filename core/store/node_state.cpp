// SPDX-License-Identifier: Apache-2.0
#include "store/node_state.h"

#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

#include "util/log.h"

namespace miracache::store {
namespace {

// An I/O failure gets an error code from errno and a log line with the path and strerror (the Error context is
// a static string by contract).
ErrorCode code_of(int e) {
  switch (e) {
    case EACCES:
    case EPERM:
    case EROFS:
    case ELOOP:  // a symlink where a state file should be (O_NOFOLLOW)
      return ErrorCode::AccessDenied;
    case ENOENT:
    case ENOTDIR:
      return ErrorCode::NotFound;
    case ENOSPC:
    case EDQUOT:
      return ErrorCode::ResourceExhausted;
    case EWOULDBLOCK:
      return ErrorCode::Busy;
    case EIO:
      return ErrorCode::Corrupt;
    default:
      return ErrorCode::InvalidArgument;
  }
}
Error fail(const char* what, const std::string& path, int e) {
  log::write(log::Level::Error, "store", what, {{"path", path}, {"errno", std::to_string(e)}, {"err", std::strerror(e)}});
  return Error{code_of(e), what};
}
Error refuse(ErrorCode c, const char* what, const std::string& path) {
  log::write(log::Level::Error, "store", what, {{"path", path}});
  return Error{c, what};
}

// Every call that can be interrupted is retried on EINTR.
template <typename F>
auto retry(F f) {
  for (;;) {
    auto r = f();
    if (!(r < 0 && errno == EINTR)) return r;
  }
}

Status mkdir_p(const std::string& dir) {
  std::string cur;
  for (std::size_t i = 0; i <= dir.size(); ++i) {
    if (i == dir.size() || dir[i] == '/') {
      if (!cur.empty() && ::mkdir(cur.c_str(), 0700) != 0 && errno != EEXIST)
        return fail("node state: cannot create state_dir", cur, errno);
    }
    if (i < dir.size()) cur += dir[i];
  }
  return {};
}

Status sync_dir(const std::string& dir) {
  const int dfd = retry([&] { return ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); });
  if (dfd < 0) return fail("node state: cannot open state_dir", dir, errno);
  const int r = retry([&] { return ::fsync(dfd); });
  const int e = errno;
  ::close(dfd);
  if (r != 0) return fail("node state: cannot sync state_dir", dir, e);
  return {};
}

// Tmp in the same dir, unlinked first and created O_EXCL|O_NOFOLLOW 0600 (a planted symlink or file is never
// written through), fsync, rename over `name`, dir fsync.
Status write_atomic(const std::string& dir, const char* name, const std::string& text) {
  const std::string path = dir + "/" + name, tmp = path + ".tmp";
  if (::unlink(tmp.c_str()) != 0 && errno != ENOENT) return fail("node state: cannot remove a stale tmp file", tmp, errno);
  const int fd = retry([&] { return ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600); });
  if (fd < 0) return fail("node state: cannot create tmp file", tmp, errno);
  int err = 0;
  if (::fchmod(fd, 0600) != 0) err = errno;
  std::size_t off = 0;
  while (err == 0 && off < text.size()) {
    const ssize_t w = retry([&] { return ::write(fd, text.data() + off, text.size() - off); });
    if (w < 0) err = errno;
    else if (w == 0) err = EIO;
    else off += static_cast<std::size_t>(w);
  }
  if (err == 0 && retry([&] { return ::fsync(fd); }) != 0) err = errno;
  ::close(fd);
  if (err == 0 && ::rename(tmp.c_str(), path.c_str()) != 0) err = errno;
  if (err != 0) {
    ::unlink(tmp.c_str());
    return fail("node state: cannot write state file", path, err);
  }
  return sync_dir(dir);
}

// Opens <dir>/<name> for reading without following a symlink. -1 + errno ENOENT: no such file.
int open_state_file(const std::string& path) {
  return retry([&] { return ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); });
}

}  // namespace

Status prepare_state_dir(const std::string& dir) {
  if (dir.empty()) return Error{ErrorCode::InvalidArgument, "node state: empty state_dir"};
  if (Status s = mkdir_p(dir); !s) return s;
  // The final component is not followed (a symlinked state_dir is refused); parents are the operator's.
  const int dfd = retry([&] { return ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); });
  if (dfd < 0) {
    struct stat ls {};
    if (errno == ENOTDIR && ::lstat(dir.c_str(), &ls) == 0 && S_ISLNK(ls.st_mode))
      return refuse(ErrorCode::AccessDenied, "node state: state_dir is a symlink; refusing to start", dir);
    if (errno == ENOTDIR) return refuse(ErrorCode::InvalidArgument, "node state: state_dir is not a directory", dir);
    return fail("node state: cannot open state_dir (a symlink is refused)", dir, errno);
  }
  struct stat st {};
  const int serr = ::fstat(dfd, &st) != 0 ? errno : 0;
  ::close(dfd);
  if (serr != 0) return fail("node state: cannot stat state_dir", dir, serr);
  if (!S_ISDIR(st.st_mode)) return refuse(ErrorCode::InvalidArgument, "node state: state_dir is not a directory", dir);
  if (st.st_uid != ::geteuid())
    return refuse(ErrorCode::AccessDenied, "node state: state_dir is owned by another user; refusing to start", dir);
  if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0)
    return refuse(ErrorCode::AccessDenied, "node state: state_dir is group- or world-writable; refusing to start", dir);
  return {};
}

Expected<StateDirLock> StateDirLock::acquire(const std::string& dir) {
  const std::string path = dir + "/" + kStateLockFile;
  const int fd = retry([&] { return ::open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600); });
  if (fd < 0) return fail("node state: cannot open the state_dir lock file", path, errno);
  struct stat st {};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    ::close(fd);
    return refuse(ErrorCode::InvalidArgument, "node state: the lock file is not a regular file", path);
  }
  if (retry([&] { return ::flock(fd, LOCK_EX | LOCK_NB); }) != 0) {
    const int e = errno;
    ::close(fd);
    if (e == EWOULDBLOCK)
      return refuse(ErrorCode::Busy,
                    "node state: state_dir is in use by another memory node (each memory node needs its own state_dir)",
                    dir);
    return fail("node state: cannot lock state_dir", path, e);
  }
  StateDirLock l;
  l.fd_ = fd;
  return l;
}

StateDirLock& StateDirLock::operator=(StateDirLock&& o) noexcept {
  if (this != &o) {
    if (fd_ >= 0) ::close(fd_);
    fd_ = o.fd_;
    o.fd_ = -1;
  }
  return *this;
}

StateDirLock::~StateDirLock() {
  if (fd_ >= 0) ::close(fd_);  // closing the last descriptor releases the flock
}

Expected<std::optional<std::uint32_t>> read_node_id_file(const std::string& dir, bool* invalid_out) {
  const std::string path = dir + "/" + kNodeIdFile;
  const int fd = open_state_file(path);
  if (fd < 0) {
    if (errno == ENOENT) return std::optional<std::uint32_t>{};
    return fail("node state: cannot open node-id", path, errno);
  }
  struct stat st {};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    ::close(fd);
    return refuse(ErrorCode::InvalidArgument, "node state: node-id is not a regular file", path);
  }
  char buf[64];
  const ssize_t n = retry([&] { return ::read(fd, buf, sizeof buf); });
  const int e = errno;
  ::close(fd);
  if (n < 0) return fail("node state: cannot read node-id", path, e);
  auto invalid = [&] {
    if (invalid_out) *invalid_out = true;
    log::write(log::Level::Warn, "store", "node-id does not hold a valid node ID; treated as missing", {{"path", path}});
    return std::optional<std::uint32_t>{};
  };
  std::uint64_t v = 0;
  std::size_t digits = 0;
  for (ssize_t i = 0; i < n; ++i) {
    if (buf[i] == '\n' && digits > 0 && i == n - 1) break;
    if (buf[i] < '0' || buf[i] > '9') return invalid();
    v = v * 10 + static_cast<std::uint64_t>(buf[i] - '0');
    if (++digits > 10) return invalid();
  }
  if (digits == 0 || v == 0 || v > 0xFFFFFFFFull) return invalid();
  return std::optional<std::uint32_t>{static_cast<std::uint32_t>(v)};
}

Status write_node_id_file(const std::string& dir, std::uint32_t id) {
  if (dir.empty() || id == 0) return Error{ErrorCode::InvalidArgument, "node state: bad state_dir or id"};
  return write_atomic(dir, kNodeIdFile, std::to_string(id) + "\n");
}

Expected<bool> state_dir_initialised(const std::string& dir) {
  const std::string path = dir + "/" + kInitialisedFile;
  const int fd = open_state_file(path);
  if (fd < 0) {
    if (errno == ENOENT) return false;
    return fail("node state: cannot open the initialised marker", path, errno);
  }
  struct stat st {};
  const bool reg = ::fstat(fd, &st) == 0 && S_ISREG(st.st_mode);
  ::close(fd);
  if (!reg) return refuse(ErrorCode::InvalidArgument, "node state: the initialised marker is not a regular file", path);
  return true;
}

Status mark_state_dir_initialised(const std::string& dir) {
  if (dir.empty()) return Error{ErrorCode::InvalidArgument, "node state: empty state_dir"};
  return write_atomic(dir, kInitialisedFile, "1\n");
}

}  // namespace miracache::store
