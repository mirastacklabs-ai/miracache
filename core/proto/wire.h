// SPDX-License-Identifier: Apache-2.0
// Wire v0 constants. Every
// fixed layout is pinned here with static_asserts so the byte offsets are frozen in one
// place. All integers are little-endian; "z" fields are reserved, must be zero on the
// wire and are rejected otherwise. Codecs for the Run A messages live in messages.h;
// the layouts of the remaining messages (Run B) are defined here already.
#pragma once

#include <cstddef>
#include <cstdint>

#include "util/expected.h"

namespace miracache::proto {

// ---- Frame header (32 B) -------------------------------------------------------------
inline constexpr std::uint8_t kFrameMagic[4] = {'M', 'A', 'R', 'M'};  // LE u32 0x4D52414D
inline constexpr std::uint32_t kFrameMagicLe = 0x4D52414D;
inline constexpr std::uint8_t kVerMajor = 0;
inline constexpr std::uint8_t kVerMinor = 0;
inline constexpr std::size_t kFrameHeaderSize = 32;
inline constexpr std::size_t kMaxFrameSize = 8192;  // D20; fabric's 64 KiB is untouched
inline constexpr std::size_t kMaxBodyLen = kMaxFrameSize - kFrameHeaderSize;  // 8160

namespace fh {  // frame header offsets
inline constexpr std::size_t magic = 0, ver_major = 4, ver_minor = 5, type = 6, flags = 8,
                             credits = 10, body_len = 12, request_id = 16, epoch = 24,
                             bundle_gen_lo = 28;
}
static_assert(fh::bundle_gen_lo + 4 == kFrameHeaderSize);
static_assert(kMaxBodyLen == 8160);

namespace flag {
inline constexpr std::uint16_t RESPONSE = 1, ERROR = 2, MORE = 4, CRITICAL_EXT = 8;
inline constexpr std::uint16_t kKnown = RESPONSE | ERROR | MORE | CRITICAL_EXT;
}  // namespace flag

enum class Op : std::uint16_t {
  HELLO = 0x01, HELLO_ACK = 0x02, SEG_TABLE = 0x03, PING = 0x04, PONG = 0x05,
  GOAWAY = 0x06, STATS = 0x07, STATS_ACK = 0x08,
  LOOKUP = 0x10, LOOKUP_ACK = 0x11, RENEW = 0x12, RENEW_ACK = 0x13, RELEASE = 0x14,
  INVALIDATE = 0x15, INVALIDATE_ACK = 0x16,
  PUT_BEGIN = 0x20, PUT_BEGIN_ACK = 0x21, PUT_COMMIT = 0x22, PUT_DONE = 0x23,
  PUT_CANCEL = 0x24,
};

constexpr bool is_known_op(std::uint16_t t) {
  return (t >= 0x01 && t <= 0x08) || (t >= 0x10 && t <= 0x16) || (t >= 0x20 && t <= 0x24);
}

// Error reply body (any request type): status u16, z u16, retry_after_ms u32.
enum class WireStatus : std::uint16_t {
  Ok = 0, Unsupported = 1, Malformed = 2, StaleEpoch = 3, Draining = 4, Busy = 5,
  Corrupt = 0x100,  // local only, never sent: bad magic/length, close the QP
};
inline constexpr std::size_t kErrorReplySize = 8;
namespace er { inline constexpr std::size_t status = 0, z = 2, retry_after_ms = 4; }
static_assert(er::retry_after_ms + 4 == kErrorReplySize);

struct WireError {
  WireStatus status = WireStatus::Ok;
  const char* context = "";
  bool close_qp = false;  // spec/plan section 3: corrupt framing and unsupported major close
};
template <typename T>
using WireResult = Expected<T, WireError>;
using WireStatusResult = Expected<void, WireError>;

// ---- TLV tail ------------------------------------------------------------------------
// tag u16, len u16, value, padded to 8 B (pad bytes zero). Tag bit 15 = critical.
inline constexpr std::size_t kTlvHeaderSize = 4;
inline constexpr std::uint16_t kTlvCriticalBit = 0x8000;
inline constexpr std::uint16_t kTlvTagRelease = 0x0001;  // non-critical
// H02: HELLO_ACK only, non-critical, value u64 LE: the memory node's boot nonce (drawn once per process). A peer that
// does not know the tag skips it; a HELLO_ACK without it means "no nonce" (a node from before the tag).
inline constexpr std::uint16_t kTlvTagBootNonce = 0x0002;
inline constexpr std::size_t kBootNonceTlvSize = 16;  // 4 B header + 8 B value, padded to 8 B
// Review s9 K03: HELLO_ACK only, non-critical, value u64 LE: the largest stored block (stored_len = 64 B header +
// payload + 16 B tag per segment) this node places, i.e. its store.run_bytes. A PUT_BEGIN key with a longer stored_len
// is refused. Absent (a node from before the tag), 0 or not 8 B long = unknown: the client then cannot check locally.
inline constexpr std::uint16_t kTlvTagMaxStoredBlock = 0x0003;
inline constexpr std::size_t kMaxStoredBlockTlvSize = 16;  // 4 B header + 8 B value, padded to 8 B
// Review s9 F5: HELLO_ACK only, non-critical, value = the memory node's hostname (the value its own logs carry), 1..255
// printable ASCII bytes (0x21..0x7e, no space), padded to 8 B. Absent (a node from before the tag), empty, longer than
// 255 B or with any other byte = unknown: static/lab mode has no admin ticket answer to name the node, so this is how the
// client learns it. The admin/bundle hostname keeps priority.
inline constexpr std::uint16_t kTlvTagHostname = 0x0004;
inline constexpr std::size_t kMaxHostnameLen = 255;
inline constexpr std::size_t kMaxHostnameTlvSize = 264;  // 4 B header + 255 B + 5 B padding to 8 B

// ---- Message layouts (offset namespaces; sizes are body bytes) ------------------------
inline constexpr std::size_t kHelloSize = 48;  // HELLO and HELLO_ACK
namespace hello {
inline constexpr std::size_t major_min = 0, major_max = 1, minor = 2, cls = 3, ird = 4,
                             ord = 5, rail = 6, proto = 7, features = 8, node_id = 16,
                             mtu = 20, conn_id = 24, max_frame = 40, z = 44;
}
static_assert(hello::z + 4 == kHelloSize && hello::conn_id + 16 == hello::max_frame);

inline constexpr std::size_t kSegTableFixed = 40, kSegEntrySize = 40, kMaxSegEntries = 200;
inline constexpr std::size_t kMaxRails = 4;  // D9
namespace segt {
inline constexpr std::size_t n = 0, n_rails = 2, local_rail = 3, table_gen = 4, sg_base = 8,
                             sg_slots = 16, sg_rkey = 24;
}
namespace sege {
inline constexpr std::size_t seg_id = 0, flags = 4, base = 8, len = 16, rkey = 24;
}
static_assert(segt::sg_rkey + 4 * kMaxRails == kSegTableFixed);
static_assert(sege::rkey + 4 * kMaxRails == kSegEntrySize);
static_assert(kFrameHeaderSize + kSegTableFixed + kMaxSegEntries * kSegEntrySize <= kMaxFrameSize);

inline constexpr std::size_t kPingSize = 8;    // PING / PONG: timestamp_ns u64
inline constexpr std::size_t kGoawaySize = 8;  // reason u32, drain_ms u32
inline constexpr std::size_t kStatsSize = 8;   // selector u32, z u32 (ack adds TLVs)

inline constexpr std::size_t kLookupFixed = 40, kKeyHashSize = 32, kScopeIdSize = 32;
inline constexpr std::size_t kMaxLookupKeys = 128;
namespace lk { inline constexpr std::size_t scope_id = 0, flags = 32, n = 34, z = 36; }
static_assert(lk::z + 4 == kLookupFixed);
static_assert(kFrameHeaderSize + 16 + kMaxLookupKeys * 40 <= kMaxFrameSize);  // LOOKUP_ACK
static_assert(kFrameHeaderSize + kLookupFixed + kMaxLookupKeys * kKeyHashSize <= kMaxFrameSize);

inline constexpr std::size_t kLookupAckFixed = 16, kLookupAckEntry = 40;
namespace lka { inline constexpr std::size_t lease_id = 0, ttl_ms = 8, n = 12, z = 14; }
namespace lkae {
inline constexpr std::size_t status = 0, z = 1, seg_id = 4, offset = 8, stored_len = 16,
                             gen = 24, gen_slot = 32;
}
static_assert(lka::z + 2 == kLookupAckFixed && lkae::gen_slot + 8 == kLookupAckEntry);

inline constexpr std::size_t kRenewSize = 8;       // lease_id u64 (!= 0)
inline constexpr std::size_t kRenewAckSize = 16;
namespace rna { inline constexpr std::size_t lease_id = 0, ttl_ms = 8, status = 12, z = 13; }
static_assert(rna::z + 3 == kRenewAckSize);
inline constexpr std::size_t kReleaseSize = 8;     // lease_id u64

inline constexpr std::size_t kInvalidateSize = 72;
namespace inv { inline constexpr std::size_t scope_id = 0, key_hash = 32, gen = 64; }
static_assert(inv::gen + 8 == kInvalidateSize);
inline constexpr std::size_t kInvalidateAckSize = 0;

inline constexpr std::size_t kPutBeginFixed = 40, kPutBeginEntry = 64, kMaxPutKeys = 64;
namespace pb { inline constexpr std::size_t scope_id = 0, n = 32, z = 34; }
namespace pbe {
inline constexpr std::size_t key_hash = 0, parent_hash = 32, chain_pos = 48, stored_len = 56;
}
static_assert(pb::z + 6 == kPutBeginFixed && pbe::stored_len + 8 == kPutBeginEntry);
static_assert(kFrameHeaderSize + kPutBeginFixed + kMaxPutKeys * kPutBeginEntry <= kMaxFrameSize);

inline constexpr std::size_t kPutBeginAckFixed = 112, kPutBeginAckEntry = 16, kMrEntry = 24;
namespace pba {
inline constexpr std::size_t put_id = 0, status = 8, n_mr = 9, n = 10, retry_after_ms = 12,
                             mr = 16;
}
namespace mre { inline constexpr std::size_t addr = 0, len = 8, rkey = 16, z = 20; }
namespace pbae { inline constexpr std::size_t status = 0, mr_index = 1, z = 2, offset = 8; }
static_assert(pba::mr + kMaxRails * kMrEntry == kPutBeginAckFixed && mre::z + 4 == kMrEntry);
static_assert(pbae::offset + 8 == kPutBeginAckEntry);
static_assert(kFrameHeaderSize + kPutBeginAckFixed + kMaxPutKeys * kPutBeginAckEntry <= kMaxFrameSize);

inline constexpr std::size_t kPutCommitFixed = 16, kPutCommitEntry = 16;  // PUT_DONE fixed too
namespace pc { inline constexpr std::size_t put_id = 0, n = 8, z = 10; }
namespace pce { inline constexpr std::size_t key_index = 0, z = 2, crc32c = 4, stored_len = 8; }
static_assert(pc::z + 6 == kPutCommitFixed && pce::stored_len + 8 == kPutCommitEntry);
inline constexpr std::size_t kPutDoneEntry = 4;
namespace pde { inline constexpr std::size_t key_index = 0, status = 2, reason = 3; }
static_assert(pde::reason + 1 == kPutDoneEntry);
static_assert(kFrameHeaderSize + kPutCommitFixed + kMaxPutKeys * kPutCommitEntry <= kMaxFrameSize);
static_assert(kFrameHeaderSize + kPutCommitFixed + kMaxPutKeys * kPutDoneEntry <= kMaxFrameSize);
inline constexpr std::size_t kPutCancelSize = 8;  // put_id u64

// Ticket (RDMA-CM private_data, 20 B): ver u8 = 0, class u8, z u16, id[16].
inline constexpr std::size_t kTicketSize = 20;
namespace tk { inline constexpr std::size_t ver = 0, cls = 1, z = 2, id = 4; }
static_assert(tk::id + 16 == kTicketSize);
static_assert(kTicketSize <= 48);  // == fabric::kMaxTicketBytes (core/fabric/types.h:86)

static_assert(kFrameHeaderSize % 8 == 0 && kHelloSize % 8 == 0 && kSegEntrySize % 8 == 0 &&
              kLookupFixed % 8 == 0 && kLookupAckEntry % 8 == 0 && kPutBeginEntry % 8 == 0 &&
              kPutBeginAckFixed % 8 == 0 && kPutCommitFixed % 8 == 0);  // 8 B array word

}  // namespace miracache::proto
