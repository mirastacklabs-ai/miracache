// SPDX-License-Identifier: Apache-2.0
// The persisted bundle floor (membership plan decision 4): the highest generation and its body
// hash, the highest sec_generation and its sec hash, the highest epoch, and the per-principal
// drop_before maxima. One file, `<state_dir>/bundle-floor`, guarded by flock on
// `<state_dir>/bundle-floor.lock`, written atomically (tmp + fsync + rename), and updated
// max-only so several processes on one host can share it. A memory node uses it as its floor;
// a client process uses it only to reject older bundles.
#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "control/bundle.h"
#include "util/expected.h"

namespace miracache::control {

struct Floor {
  std::uint64_t generation = 0;  // 0 = blank
  Sha256Digest body_hash{};
  std::uint64_t sec_generation = 0;
  Sha256Digest sec_hash{};
  std::uint32_t epoch = 0;
  // principal name -> highest drop_before ever seen (unix seconds). Never decreases.
  std::map<std::string, std::int64_t> drop_before;

  // Security floor = max(persisted, pinned `min_sec_generation`).
  std::uint64_t effective_sec_floor(std::uint64_t pinned) const {
    return sec_generation > pinned ? sec_generation : pinned;
  }
};

enum class Verdict : std::uint8_t {
  Apply,    // newer generation: apply it
  Replace,  // equal generation, equal body hash, same sec: no apply; a new valid signature may
            // replace the stored envelope (key rotation re-sign / idempotent re-push)
};
// An equal generation and body hash with a higher sec_generation is rejected (equal_generation, W07):
// a new `sec` needs a new generation.

// The failure of FloorState::commit: either the floor's verdict (`rejected`, `reject` set: the
// bundle lost, e.g. another process committed a different body first) or an I/O / corrupt-file
// error (`io` set).
struct CommitError {
  bool rejected = false;
  BundleError reject{Reject::Schema, ""};
  Error io{ErrorCode::Aborted, ""};
  CommitError(BundleError r) : rejected(true), reject(r) {}  // NOLINT: implicit on purpose
  CommitError(Error e) : io(e) {}                            // NOLINT
};

// Pure acceptance check of an already verified and parsed bundle against `floor` (decision 4).
// Order: generation, epoch, then the security rules. `pinned_min_sec_generation` is the trust
// file's pin (0 = none), which applies even on a blank floor.
Expected<Verdict, BundleError> check_against_floor(const Floor& floor, const BundleView& bundle,
                                                   std::uint64_t pinned_min_sec_generation);

class FloorState {
 public:
  // `dir` is created (one level, mode 0700) if missing.
  static Expected<FloorState, Error> open(std::string dir);

  // Reads the file under a shared lock. A missing file is the blank floor; an unreadable or
  // malformed one is an error (a corrupt floor is never treated as blank).
  Expected<Floor, Error> load() const;

  // Under the exclusive lock: re-runs check_against_floor on the file as it is now (W06), so of
  // two processes that checked the same floor only the first commit wins; the loser gets the
  // reject (CommitError::rejected). Apply: merges the bundle into the file, max-only (every number
  // only rises, a hash follows its number, drop_before maxima are kept) and returns Apply.
  // Replace: nothing written, returns Replace. `pinned_min_sec_generation` is the trust file's
  // pin (0 = none), as for check_against_floor. Safe from several processes and threads.
  Expected<Verdict, CommitError> commit(const BundleView& bundle, std::uint64_t pinned_min_sec_generation = 0) const;

  // RB2 (POST /v1/drop_principal): raises the stored drop_before maximum of `name` to at least `drop_before_unix_s`
  // (max-only; a lower value writes nothing). Durable (tmp + fsync + rename + dir fsync) before it returns. Does not
  // touch the generation fields, so a blank floor stays blank for bundle acceptance.
  Status raise_drop_before(const std::string& name, std::int64_t drop_before_unix_s) const;

  const std::string& dir() const { return dir_; }

 private:
  explicit FloorState(std::string dir) : dir_(std::move(dir)) {}
  std::string dir_;
};

// Text form of the file (exposed for tests): strict, LF-only.
std::string serialize_floor(const Floor& floor);
Expected<Floor, Error> parse_floor(std::string_view text);

}  // namespace miracache::control
