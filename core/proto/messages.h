// SPDX-License-Identifier: Apache-2.0
// Message body codecs. Run A: RENEW, RENEW_ACK, RELEASE, INVALIDATE, INVALIDATE_ACK,
// PUT_COMMIT, PUT_DONE, PUT_CANCEL and the error reply. Run B: HELLO, HELLO_ACK,
// SEG_TABLE, PING, PONG, GOAWAY, STATS, STATS_ACK, LOOKUP, LOOKUP_ACK, PUT_BEGIN,
// PUT_BEGIN_ACK and the 20 B ticket (not framed). Layouts live in wire.h.
//
// encode_*: writes the body (no frame header; wrap with encode_frame) and returns its
// length; validates the same field rules as decode. decode_*: takes the parsed frame
// header (direction flags, D11) and the body; checks, in order: frame type/direction
// flags, fixed-part length, reserved-zero and ranges, then the TLV tail (frame.h).
// Decoded structs borrow the TLV tail from the input span.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "proto/frame.h"
#include "proto/wire.h"

namespace miracache::proto {

// Frame header skeleton for an op: type set, RESPONSE set for acks/PUT_DONE (D1/D15).
FrameHeader header_for(Op op, std::uint64_t request_id = 0);

struct Renew { std::uint64_t lease_id = 0; std::span<const std::byte> tlvs; };           // != 0
struct RenewAck {
  std::uint64_t lease_id = 0;
  std::uint32_t ttl_ms = 0;   // clamped to lease.max_ms by the server
  std::uint8_t status = 0;    // 0 OK, 1 EXPIRED (D3)
  std::span<const std::byte> tlvs;
};
struct Release { std::uint64_t lease_id = 0; std::span<const std::byte> tlvs; };
struct Invalidate {
  std::uint8_t scope_id[32] = {};
  std::uint8_t key_hash[32] = {};
  std::uint64_t gen = 1;  // 1..2^56-1 (D14)
  std::span<const std::byte> tlvs;
};
struct InvalidateAck { std::span<const std::byte> tlvs; };  // 0 B body (D4)

struct CommitEntry {
  std::uint16_t key_index = 0;  // strictly ascending across entries (D6)
  std::uint32_t crc32c = 0;
  std::uint64_t stored_len = 0;  // must equal the PUT_BEGIN value (D7; checked by the server)
};
struct PutCommit {
  std::uint64_t put_id = 0;
  std::uint16_t n = 0;  // 1..64
  std::array<CommitEntry, kMaxPutKeys> e{};
  std::span<const std::byte> tlvs;
};

enum class DoneStatus : std::uint8_t { Committed = 0, Aborted = 1 };
enum class DoneReason : std::uint8_t { None = 0, Digest = 1, Doomed = 2, Timeout = 3, Cancel = 4 };
struct DoneEntry {
  std::uint16_t key_index = 0;
  std::uint8_t status = 0;  // DoneStatus
  std::uint8_t reason = 0;  // DoneReason
};
// PUT_DONE: 16 B as PUT_COMMIT (put_id, n, z), then n x 4 B, padded to 8 B.
struct PutDone {
  std::uint64_t put_id = 0;
  std::uint16_t n = 0;  // 1..64
  std::array<DoneEntry, kMaxPutKeys> e{};
  std::span<const std::byte> tlvs;
};
struct PutCancel { std::uint64_t put_id = 0; std::span<const std::byte> tlvs; };

// ---- Run B ---------------------------------------------------------------------------
// HELLO / HELLO_ACK share one 48 B body (HELLO_ACK: features = intersection, chosen major
// in the frame header). cls 0 ctl / 1 fetch / 2 ingest; proto 1 RoCE / 2 iWARP.
struct Hello {
  std::uint8_t major_min = 0, major_max = 0, minor = 0;
  std::uint8_t cls = 0, ird = 0, ord = 0;
  std::uint8_t rail = 0;   // < 4
  std::uint8_t proto = 1;
  std::uint64_t features = 0;
  std::uint32_t node_id = 0;
  std::uint32_t mtu = 0;
  std::uint8_t conn_id[16] = {};
  std::uint32_t max_frame = static_cast<std::uint32_t>(kMaxFrameSize);  // must be 8192
  std::span<const std::byte> tlvs;
};
using HelloAck = Hello;
// H02: the boot-nonce TLV of a HELLO_ACK (kTlvTagBootNonce). encode writes kBootNonceTlvSize bytes at out[0..];
// find returns the nonce of a decoded tail (nullopt: the node sent none, or the entry is not 8 B).
WireResult<std::size_t> encode_boot_nonce_tlv(std::uint64_t nonce, std::span<std::byte> out);
std::optional<std::uint64_t> find_boot_nonce(std::span<const std::byte> tlvs);
// K03: the max-stored-block TLV of a HELLO_ACK (kTlvTagMaxStoredBlock), same shape as the boot nonce. find returns
// nullopt when the node sent none, the entry is not 8 B, or the value is 0 (all mean "unknown").
WireResult<std::size_t> encode_max_stored_block_tlv(std::uint64_t bytes, std::span<std::byte> out);
std::optional<std::uint64_t> find_max_stored_block(std::span<const std::byte> tlvs);
// F5: the hostname TLV of a HELLO_ACK (kTlvTagHostname). encode writes the TLV (4 B header + name, padded to 8 B; at most
// kMaxHostnameTlvSize bytes) at out[0..] and fails Malformed for an empty, too long or non-printable name; find returns
// the name of a decoded tail, nullopt when absent or invalid (all mean "unknown").
WireResult<std::size_t> encode_hostname_tlv(std::string_view name, std::span<std::byte> out);
std::optional<std::string> find_hostname(std::span<const std::byte> tlvs);

struct SegEntry {
  std::uint32_t seg_id = 0;
  std::uint32_t flags = 0;  // bit0 REMOVED
  std::uint64_t base = 0, len = 0;
  std::uint32_t rkey[kMaxRails] = {};
};
struct SegTable {
  std::uint16_t n = 0;  // <= 200
  std::uint8_t n_rails = 1;    // 1..4
  std::uint8_t local_rail = 0;  // < n_rails
  std::uint32_t table_gen = 0;
  std::uint64_t sg_base = 0, sg_slots = 0;
  std::uint32_t sg_rkey[kMaxRails] = {};
  std::array<SegEntry, kMaxSegEntries> e{};
  std::span<const std::byte> tlvs;
};

struct Ping { std::uint64_t timestamp_ns = 0; std::span<const std::byte> tlvs; };
using Pong = Ping;  // echoes the PING timestamp

enum class GoawayReason : std::uint32_t { Shutdown = 1, Upgrade = 2, Epoch = 3, Idle = 4 };
struct Goaway {
  std::uint32_t reason = 1;  // GoawayReason
  std::uint32_t drain_ms = 0;
  std::span<const std::byte> tlvs;
};

struct Stats { std::uint32_t selector = 0; std::span<const std::byte> tlvs; };
// STATS_ACK: the same 8 B, then counter TLVs in `tlvs`.
struct StatsAck { std::uint32_t selector = 0; std::span<const std::byte> tlvs; };

using KeyHash = std::array<std::uint8_t, kKeyHashSize>;
struct Lookup {
  std::uint8_t scope_id[32] = {};
  std::uint16_t flags = 0;  // bit0 LEASE; 0 = PROBE
  std::uint16_t n = 0;      // 1..128
  std::array<KeyHash, kMaxLookupKeys> key_hash{};
  std::span<const std::byte> tlvs;
};
struct LookupAckEntry {  // MISS entries are all-zero (D5)
  std::uint8_t status = 0;  // 0 MISS, 1 HIT
  std::uint32_t seg_id = 0;
  std::uint64_t offset = 0, stored_len = 0;
  std::uint64_t gen = 0;  // HIT: 1..2^56-1
  std::uint64_t gen_slot = 0;
};
struct LookupAck {
  std::uint64_t lease_id = 0;  // 0 = none (D2)
  std::uint32_t ttl_ms = 0;
  std::uint16_t n = 0;         // 1..128
  std::array<LookupAckEntry, kMaxLookupKeys> e{};
  std::span<const std::byte> tlvs;
};

struct PutBeginEntry {
  std::uint8_t key_hash[32] = {};
  std::uint8_t parent_hash[16] = {};
  std::uint64_t chain_pos = 0;
  std::uint64_t stored_len = 0;
};
struct PutBegin {
  std::uint8_t scope_id[32] = {};
  std::uint16_t n = 0;  // 1..64
  std::array<PutBeginEntry, kMaxPutKeys> e{};
  std::span<const std::byte> tlvs;
};
struct MrEntry { std::uint64_t addr = 0, len = 0; std::uint32_t rkey = 0; };
struct PutBeginAckEntry {
  std::uint8_t status = 0;    // 0 SKIP, 1 ACCEPT
  std::uint8_t mr_index = 0;  // ACCEPT: < n_mr; SKIP: 0
  std::uint64_t offset = 0;   // SKIP: 0
};
struct PutBeginAck {
  std::uint64_t put_id = 0;
  std::uint8_t status = 0;  // 0 OK, 1 REFUSED
  std::uint8_t n_mr = 0;    // <= 4; unused mr[] slots are zero
  std::uint16_t n = 0;      // <= 64 (0 allowed, e.g. REFUSED); the match with PUT_BEGIN is stateful
  std::uint32_t retry_after_ms = 0;
  std::array<MrEntry, kMaxRails> mr{};
  std::array<PutBeginAckEntry, kMaxPutKeys> e{};
  std::span<const std::byte> tlvs;
};

// Ticket (RDMA-CM private_data), exactly 20 B, no frame, no TLVs.
struct Ticket {
  std::uint8_t cls = 0;  // 0 ctl / 1 fetch / 2 ingest
  std::uint8_t id[16] = {};
};
WireResult<std::size_t> encode_ticket(const Ticket& t, std::span<std::byte> out);
WireResult<Ticket> decode_ticket(std::span<const std::byte> in);  // size must be exactly 20

struct ErrorReply {
  std::uint16_t status = 0;  // WireStatus 1..5
  std::uint32_t retry_after_ms = 0;
};

#define MIRACACHE_MSG_CODEC(T, name)                                                          \
  WireResult<std::size_t> encode_##name(const T& m, std::span<std::byte> body_out);          \
  WireResult<T> decode_##name(const FrameHeader& h, std::span<const std::byte> body)
MIRACACHE_MSG_CODEC(Renew, renew);
MIRACACHE_MSG_CODEC(RenewAck, renew_ack);
MIRACACHE_MSG_CODEC(Release, release);
MIRACACHE_MSG_CODEC(Invalidate, invalidate);
MIRACACHE_MSG_CODEC(InvalidateAck, invalidate_ack);
MIRACACHE_MSG_CODEC(PutCommit, put_commit);
MIRACACHE_MSG_CODEC(PutDone, put_done);
MIRACACHE_MSG_CODEC(PutCancel, put_cancel);
MIRACACHE_MSG_CODEC(Hello, hello);
MIRACACHE_MSG_CODEC(HelloAck, hello_ack);
MIRACACHE_MSG_CODEC(SegTable, seg_table);
MIRACACHE_MSG_CODEC(Ping, ping);
MIRACACHE_MSG_CODEC(Pong, pong);
MIRACACHE_MSG_CODEC(Goaway, goaway);
MIRACACHE_MSG_CODEC(Stats, stats);
MIRACACHE_MSG_CODEC(StatsAck, stats_ack);
MIRACACHE_MSG_CODEC(Lookup, lookup);
MIRACACHE_MSG_CODEC(LookupAck, lookup_ack);
MIRACACHE_MSG_CODEC(PutBegin, put_begin);
MIRACACHE_MSG_CODEC(PutBeginAck, put_begin_ack);
#undef MIRACACHE_MSG_CODEC

// Error reply: frame type = the request type, flags RESPONSE|ERROR, 8 B body.
// encode_error_reply_frame writes header + body; request_id/epoch come from `h`.
WireResult<std::size_t> encode_error_reply_frame(const FrameHeader& request_like,
                                                 const ErrorReply& m, std::span<std::byte> out);
WireResult<ErrorReply> decode_error_reply(const FrameHeader& h, std::span<const std::byte> body);

}  // namespace miracache::proto
