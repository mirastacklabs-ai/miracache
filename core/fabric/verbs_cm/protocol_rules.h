// SPDX-License-Identifier: Apache-2.0
// Every RoCEv2-vs-iWARP difference of the verbs_cm backend lives in this module (spec
// 3.1/3.2): protocol detection and the fabric.protocol override, READ-sink access flags,
// IRD/ORD for rdma_conn_param, active-side-sends-first, GID handling, and the protocol
// tag carried in connect private_data. Nothing else in verbs_cm branches on protocol.
#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "fabric/types.h"

struct ibv_context;

namespace miracache::fabric::protocol {

enum class Protocol : std::uint8_t { Unknown = 0, RoCE = 1, IWarp = 2, InfiniBand = 3 };
// `fabric.protocol = auto | roce | iwarp`. Auto trusts detection.
enum class Setting : std::uint8_t { Auto, RoCE, IWarp };

const char* to_string(Protocol p);
const char* to_string(Setting s);
Expected<Setting> parse_setting(std::string_view text);

// From verbs transport_type and port link layer, never from vendor identity.
Protocol detect(ibv_context* ctx);
// Applies the override: a setting that contradicts the device is a clear error.
Expected<Protocol> resolve(Setting setting, Protocol detected);

// Effective access of a region registered with `requested` (spec 3.2): on iWARP the
// sink of a READ (LocalWrite) also needs REMOTE_WRITE.
Access region_access(Protocol p, Access requested);
// iWARP (MPA): the active side must send first; the HELLO layer reads this.
bool active_sends_first(Protocol p);

// "transport/link" label for diagnostics ("iwarp/ethernet", "ib/ethernet" for RoCE, ...).
std::string node_type(ibv_context* ctx);

// rdma_conn_param retry knobs. RNR retry 7 means "retry forever" in verbs, which would hide
// a credit bug (spec 3.7 counts RNR as a bug metric), so the safety net is 6 and RNR then
// surfaces as RNR_RETRY_EXC_ERR.
inline constexpr std::uint8_t kRetryCount = kQpRetryCount;  // fabric/types.h: the client watchdog derives its grace from it
inline constexpr std::uint8_t kRnrRetryCount = 6;

// GID handling: rdma_cm resolves by IP on both; the table is only for diagnostics.
struct GidPolicy {
  bool resolve_via_cm;      // always true: we never pick GIDs ourselves
  bool single_entry_table;  // iWARP exposes one entry, RoCE one per address/type
};
GidPolicy gid_policy(Protocol p);

// rdma_conn_param.responder_resources (IRD) / initiator_depth (ORD).
struct Depth {
  std::uint8_t ird = 0;
  std::uint8_t ord = 0;
};
// Active side: the request (0 = device maximum) capped by the device.
Depth active_depth(Protocol p, std::uint8_t req_ird, std::uint8_t req_ord, std::uint32_t dev_ird,
                   std::uint32_t dev_ord);
// Passive side clamps to what the peer announced in the connect request.
Depth passive_depth(Protocol p, std::uint32_t peer_ord, std::uint32_t peer_ird, std::uint32_t dev_ird,
                    std::uint32_t dev_ord);
// What both ends agreed, from the peer's depths as it announced them in private_data (never
// from the CM event: RoCE reports the receiver's view, siw the sender's, cxgb4 like RoCE).
// ird = min(our IRD, peer ORD), ord = min(our ORD, peer IRD): one rule for both protocols.
ReadDepth effective_depth(Depth ours, Depth peer);

// ---- CM private_data ----
// REQ (active): [ver:1][len:1][protocol:1][ird:1][ord:1][ticket:len].
// REP (accept): [ver][0][protocol][ird][ord].
// RoCE's CM REQ delivers a fixed, zero-padded field with no length, so the length travels
// inside it. Total budget kMaxTicketBytes + kPrivHeader (53) stays under the ~56 B RoCE limit.
// The depths are the sender's rdma_conn_param values (responder_resources, initiator_depth).
// The version byte comes first and has the high bit set, so the unversioned layout (whose
// first byte is a ticket length <= 48) and any other version are refused, never misparsed.
inline constexpr std::uint8_t kPrivVersion = 0x81;
inline constexpr std::size_t kPrivHeader = 5;
std::size_t encode_private(Protocol p, Depth depth, std::span<const std::byte> ticket, std::byte* out);
struct Decoded {
  Protocol protocol = Protocol::Unknown;
  Depth depth;  // the sender's announced IRD/ORD
  std::span<const std::byte> ticket;
};
// Short or malformed private_data is Corrupt on every protocol; a version other than
// kPrivVersion is Unsupported.
Expected<Decoded> decode_private(std::span<const std::byte> raw);

// rdma_reject private_data (one byte) so the active side can say why it was refused.
// KRejectNone is also what the active side reads when no miracache node answered: a RoCE kernel
// REJ (no listener on the port) carries zeroed private_data, an iWARP ECONNREFUSED carries none. The
// host is up but the memory node is gone, so it reads as LinkDown (one ticket, then the backoff).
inline constexpr std::uint8_t kRejectNone = 0;
inline constexpr std::uint8_t kRejectProtocolMismatch = 1;
inline constexpr std::uint8_t kRejectAdmit = 2;
inline constexpr std::uint8_t kRejectBadPrivateData = 3;
inline constexpr std::uint8_t kRejectResources = 4;  // passive side out of CQ budget / accept slots
inline constexpr std::uint8_t kRejectVersion = 5;    // private_data version not understood
// The admit hook refused for now (the node is draining): retry later. The ticket was not
// redeemed, so the client must not burn its other tickets on this attempt (Busy, not AccessDenied).
inline constexpr std::uint8_t kRejectBusy = 6;

// The reject byte for an admit hook's error, and the error the active side reports for a reject
// byte. Header-only (no verbs) so the sim maps admit refusals through the same table and cannot
// drift from verbs: Busy -> kRejectBusy -> Busy; ResourceExhausted (connection cap) ->
// kRejectResources -> ResourceExhausted; any other refusal (unknown, used, expired or wrong-rail
// ticket) -> kRejectAdmit -> AccessDenied (the client tries its next ticket). Only kRejectAdmit is
// AccessDenied: kRejectNone and an unknown byte (a newer peer) are LinkDown.
inline std::uint8_t admit_reject_code(ErrorCode c) {
  switch (c) {
    case ErrorCode::Busy: return kRejectBusy;
    case ErrorCode::ResourceExhausted: return kRejectResources;
    default: return kRejectAdmit;
  }
}
inline Error reject_error(std::uint8_t code) {
  switch (code) {
    case kRejectProtocolMismatch:
      return {ErrorCode::Unsupported, "connect: peer refused: RoCE/iWARP protocol mismatch"};
    case kRejectAdmit: return {ErrorCode::AccessDenied, "connect: peer refused the ticket"};
    case kRejectBadPrivateData: return {ErrorCode::Corrupt, "connect: peer refused: bad private_data"};
    case kRejectResources: return {ErrorCode::ResourceExhausted, "connect: peer refused: out of resources"};
    case kRejectVersion: return {ErrorCode::Unsupported, "connect: peer refused: private_data version unsupported"};
    case kRejectBusy: return {ErrorCode::Busy, "connect: peer busy (draining): retry later"};
    default: return {ErrorCode::LinkDown, "connect: rejected by peer (no memory node listening?)"};
  }
}

}  // namespace miracache::fabric::protocol
