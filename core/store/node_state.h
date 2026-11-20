// SPDX-License-Identifier: Apache-2.0
// The memory node's state directory.
//
//   <state_dir>/node-id       the node ID (decimal, mode 0600). A wiped store (hugetlbfs after a reboot, a volatile
//                             anon store) keeps its identity because the ID lives here, not only in the store.
//   <state_dir>/initialised   marker (mode 0600), written once the directory holds an ID. With the marker present a
//                             missing node-id means "this node was replaced": a new ID is drawn and the store is
//                             reformatted. Without it the directory was never initialised (the upgrade path): a
//                             persistent store's superblock ID is adopted.
//   <state_dir>/node-id.lock  flock(LOCK_EX) held for the process lifetime: one memory node per state_dir.
//
// Both files are written atomically (unlink tmp, O_CREAT|O_EXCL|O_NOFOLLOW 0600, write, fsync, rename, dir fsync).
// The directory must belong to this user and must not be group- or world-writable (identity is security-relevant).
// Error contexts are static strings; the path and strerror are in a log line (comp=store) at each failure.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "util/expected.h"

namespace miracache::store {

inline constexpr const char* kNodeIdFile = "node-id";
inline constexpr const char* kInitialisedFile = "initialised";
inline constexpr const char* kStateLockFile = "node-id.lock";

// Creates `dir` (and missing parents) with mode 0700 if needed, then checks it: a directory (not a symlink to one;
// the parents are not checked and must not be writable by others) owned by the effective
// user, not group- or world-writable. Anything else is an error (the memory node refuses to start).
Status prepare_state_dir(const std::string& dir);

// flock(LOCK_EX|LOCK_NB) on <dir>/node-id.lock, held until destruction. A second holder (another process, or another
// open in this one) gets Busy, and the log line names the directory.
class StateDirLock {
 public:
  StateDirLock() = default;
  static Expected<StateDirLock> acquire(const std::string& dir);
  StateDirLock(StateDirLock&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
  StateDirLock& operator=(StateDirLock&& o) noexcept;
  StateDirLock(const StateDirLock&) = delete;
  StateDirLock& operator=(const StateDirLock&) = delete;
  ~StateDirLock();
  bool held() const noexcept { return fd_ >= 0; }

 private:
  int fd_ = -1;
};

// The ID in <dir>/node-id. nullopt: no such file, or its content is not a decimal ID in 1..2^32-1 (treated as
// missing, with a warning). A symlink, a non-regular file (a FIFO never blocks the start) or another I/O
// error is an error. The marker and the lock file must be regular files as well.
// `invalid` (optional) is set when the file exists but holds no valid ID (for the "node replaced" log line).
Expected<std::optional<std::uint32_t>> read_node_id_file(const std::string& dir, bool* invalid = nullptr);

// Writes <dir>/node-id atomically. `dir` must exist (prepare_state_dir).
Status write_node_id_file(const std::string& dir, std::uint32_t id);

// Whether <dir>/initialised exists (a symlink or another I/O error is an error).
Expected<bool> state_dir_initialised(const std::string& dir);

// Writes <dir>/initialised atomically.
Status mark_state_dir_initialised(const std::string& dir);

}  // namespace miracache::store
