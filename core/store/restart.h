// SPDX-License-Identifier: Apache-2.0
// A3.1 warm restart (spec 6.1 "Restart", steps 3-5): rebuilds the slab, the scope table, the block map, the chain
// index and the LRU of a re-opened persistent store from its media, before any session is admitted.
//
// What is on media and what it means (the invariants the store keeps at run time):
//  - A header slot holds a valid 128 B header only from the commit of its block (written after the digest check and
//    after the block entered the index) until the block is freed or turns ZOMBIE (cleared first). A WRITING block
//    (an in-flight put) never has one. So a valid header = a committed, digest-checked, live block.
//  - A scope record is OPEN while its implicit scope is live, DRAINING once it is doomed (expired, dropped, evicted
//    at a cap) until its last block is gone, and cleared when the scope is erased.
//  - The generation high-water mark in the superblock is above every generation ever issued (GenCounter).
// The state_gen array stays volatile (superblock sg_off = 0): its content is derived here from the headers.
//
// A block is adopted only if ALL hold: its header decodes (magic, version, hdr CRC) and validates; its generation is
// <= the persisted high-water mark (so every generation issued after the restart is new: generations are never
// reused); the run's inferred class places it inside the run; exactly one scope record (OPEN or DRAINING) names its
// scope_id and that record is OPEN; it is not a duplicate key of its scope (the higher generation wins); its chain
// reaches a root through blocks that are adopted too (the orphan sweep); and, on an UNCLEAN restart (the previous
// owner did not mark the superblock clean) or with `verify_extents`, the CRC32C of its extent equals the digest in
// its header. A clean restart trusts the fenced commit (spec 8.2: no write MR outlives the fence, committed blocks
// are immutable, the digest was checked before the header was written) and leaves extent re-checks to the
// scrubber; an unclean one re-verifies every extent, since the crash may have been a wild write. Everything else
// is discarded: its header slot is zeroed and its slot stays FREE.
//
// Scopes: OPEN records resume OPEN with their persisted opened_at and last_used (wall-clock ms, converted with
// Store::wall_offset_ns), so the idle TTL and max_ttl count the downtime and drop_before cutoffs (applied later by
// the owner from its floor) still compare opened_at; both are clamped to the restart's "now" (a wall clock that
// stepped back during the downtime cannot extend the idle TTL or max_ttl). DRAINING records are not resumed.
//
// Crash order: the scan changes no scope record until every header it will discard has been zeroed (records are
// released last: DRAINING, duplicate, shared-scope_id and torn ones). A crash at any point therefore leaves either the
// old state (records intact: the next scan decides the same) or the finished one (headers gone), never a header whose
// only remaining owner record is the wrong principal's. A record that fails its CRC (a torn in-place rewrite) still
// counts as an owner of its scope_id (its principal and scope_id bytes are rewritten with identical values, so they
// survive); if even those are unreadable no scope is resumed on that restart.
//
// Cost: proportional to the header-table slots (one 4 B magic read per empty slot) plus the adopted blocks; an
// unclean restart also reads every adopted extent once. Single-threaded (the store thread, before it serves).
#pragma once

#include <array>
#include <cstdint>
#include <functional>
#include <vector>

#include "store/arena.h"
#include "store/slab.h"
#include "store/store.h"
#include "util/expected.h"

namespace miracache::store {

// SharedScopeId: the block's scope_id is held by two or more principals (or by one whose record is torn); headers carry
// no principal, so the block cannot be attributed and is discarded (logged once per scope_id, see SharedScope).
// TornRecord (H05): a scope record failed its CRC and its principal or scope_id reads as zero, so no block on media can
// be attributed: every block that would otherwise be a resume candidate is discarded under this reason (the node comes
// back cold; RestartReport::blind_record_slots names the records, and the memory node logs one Warn line per slot).
enum class DiscardReason : std::uint8_t {
  Header,
  Generation,
  Geometry,
  Digest,
  Scope,
  Orphan,
  Duplicate,
  SharedScopeId,
  TornRecord
};
inline constexpr std::size_t kDiscardReasons = 9;
const char* discard_reason_name(DiscardReason r);

// One scope_id that several principals hold: what the scan discarded for it.
struct SharedScope {
  ScopeId scope{};
  std::vector<PrincipalId> principals;  // every principal with a readable record for the scope_id, ascending
  bool torn_record = false;             // a record for it failed its CRC (its principal may be among the above or unknown)
  std::uint64_t blocks = 0, bytes = 0;  // discarded (bytes: slab block bytes)
};

struct RestartReport {
  bool ran = false;       // false on a freshly formatted store (nothing to adopt)
  bool clean = false;     // the previous owner marked the superblock clean
  bool verified = false;  // every adopted extent's CRC32C was recomputed
  std::uint64_t slots_scanned = 0;
  std::uint64_t adopted_blocks = 0, adopted_bytes = 0;  // bytes: slab block bytes, as Store::bytes_used counts them
  std::array<std::uint64_t, kDiscardReasons> discarded{};
  std::uint64_t scopes_resumed = 0, scopes_draining = 0, scope_records_corrupt = 0;
  std::vector<SharedScope> shared_scopes;  // only those that had blocks on media
  // H05: scope-record slots whose record was torn with a zero principal or scope_id (scan order). Non-empty = the scan
  // ran blind: no scope was resumed and the blocks were discarded as TornRecord.
  std::vector<std::uint32_t> blind_record_slots;
  std::uint64_t discarded_total() const {
    std::uint64_t n = 0;
    for (auto d : discarded) n += d;
    return n;
  }
};

struct RestartOptions {
  bool verify_extents = false;  // re-check every extent's CRC also after a clean shutdown
  // Called after each segment's header table was scanned (progress logging).
  std::function<void(std::uint32_t seg, const RestartReport&)> progress;
  // Test hook (crash injection): called at each stage boundary; returning true abandons the scan there (restart_scan
  // returns Aborted) with the media exactly as a crash at that point would leave it.
  enum class Stage : std::uint8_t { RecordsLoaded, HeadersScanned };
  std::function<bool(Stage)> stop_after;
};

// On a fresh arena returns {ran = false} and does nothing. Otherwise the slab and the store must be new (nothing
// allocated, no scope) and the store's wall offset set.
Expected<RestartReport> restart_scan(Arena& arena, SlabAllocator& slab, Store& store, const RestartOptions& opt = {});

}  // namespace miracache::store
