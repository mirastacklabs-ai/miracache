// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <array>
#include <cstdint>
#include <functional>
#include <span>
#include <string>
#include <utility>
#include <vector>

#include "util/clock.h"
#include "util/expected.h"

namespace miracache::fabric {

using NodeId = std::uint32_t;
using EndpointId = std::uint64_t;
using WrTag = std::uint64_t;  // caller-chosen work-request tag, echoed in the completion

// QP transport retry. verbs_cm sets retry_count = kQpRetryCount on every QP. On the active
// (client) side it also asks rdma_cm to pin the local ACK timeout exponent to kQpAckTimeoutExpMax
// (rdma_set_option RDMA_OPTION_ID_ACK_TIMEOUT, best effort). If the kernel refuses, rdma_cm's own
// value applies: packet_life_time + 1, which is 17 on current RoCE kernels (CMA_IBOE_PACKET_LIFETIME
// 16) and 19 on older ones, but on native IB comes from the SA path record and may be larger. Not a
// guarantee, then: an upper bound for the lab transports (rxe, RoCE). iWARP (siw, iw_cxgb4) has no
// ACK timeout at all (TCP retransmits underneath, for minutes); there the keepalive suspect timer
// (3 x keepalive_ms) is what detects a dead peer, and the watchdog grace only bounds a lost CQE.
inline constexpr std::uint8_t kQpRetryCount = 7;
inline constexpr std::uint8_t kQpAckTimeoutExpMax = 19;
// Worst-case time for a posted WR to fail with RETRY_EXC: 4.096 us * 2^exp per try, retry + 1 tries.
constexpr Nanos qp_retry_exhaustion(std::uint8_t ack_timeout_exp = kQpAckTimeoutExpMax,
                                    std::uint8_t retry_count = kQpRetryCount) {
  return Nanos{std::int64_t{4096} << ack_timeout_exp} * (retry_count + 1);
}

enum class Access : std::uint8_t {
  None = 0,
  LocalWrite = 1,   // the region may be the sink of a local READ
  RemoteRead = 2,
  RemoteWrite = 4,
};
constexpr Access operator|(Access a, Access b) {
  return static_cast<Access>(static_cast<std::uint8_t>(a) | static_cast<std::uint8_t>(b));
}
constexpr bool has(Access set, Access bit) {
  return (static_cast<std::uint8_t>(set) & static_cast<std::uint8_t>(bit)) != 0;
}

// A registered memory region. Remote peers address it by (rkey, virtual address).
struct MemRegion {
  std::byte* addr = nullptr;
  std::size_t len = 0;
  std::uint32_t lkey = 0;
  std::uint32_t rkey = 0;
  Access access = Access::None;
  // index of the device (fabric) this region was registered on. Set by MrManager, not by the fabric;
  // rkeys are per device, so a region is identified by (device, rkey).
  std::uint32_t device = 0;
};

// what a fabric reports about its device for rail health (port ACTIVE, the
// listener alive, no fatal async event in the last 10 s). Read on the loop thread.
struct FabricHealth {
  std::string port_state = "ACTIVE";  // "ACTIVE", "DOWN", "INIT", "ARMED", ... (ibv_query_port)
  bool fatal_recent = false;          // device fatal or CQ error ever, or a port error in the last 10 s
  // One entry per successful listen() call, in call order: false once that listener is gone (its address left the
  // device, or the CM reported the device removed). Empty = no listener information (treated as alive).
  std::vector<bool> listener_ok;
};

struct LocalRef {
  std::uint32_t lkey = 0;
  std::byte* addr = nullptr;
  std::uint32_t len = 0;
};

struct RemoteRef {
  std::uint32_t rkey = 0;
  std::uint64_t addr = 0;  // remote virtual address
  std::uint32_t len = 0;
};

// Upper bound on a two-sided frame; post_send refuses larger frames.
inline constexpr std::size_t kMaxFrameBytes = 64 * 1024;

// Protection domain handle (spec 3.3). A QP can only use regions registered in its own PD,
// so the PD an endpoint is created in must match the PD of every region it touches. The
// client allocates one PD per memory node (Fabric::alloc_pd); a default-constructed
// PdId is the fabric's default PD (created on first use, never freed).
struct PdId {
  std::uint32_t v = 0;
  constexpr bool operator==(const PdId&) const = default;
};
// Connection class (spec 3.3); selects buffer layout (spec 3.5), not the PD.
enum class EpClass : std::uint8_t { Control, Fetch, Ingest };

// A rail endpoint address (device-independent: the backend maps IP -> device).
struct RailAddr {
  std::string host;         // IPv4 literal; empty = wildcard on listen
  std::uint16_t port = 0;   // 0 = pick an ephemeral port on listen
};

// Where to connect. The sim backend routes by `node`; verbs_cm by `addr`.
struct Peer {
  Peer() = default;
  Peer(NodeId n, RailAddr a = {}) : node(n), addr(std::move(a)) {}
  NodeId node = 0;
  RailAddr addr;
};

// rdma_cm private_data budget kept for the connection ticket (spec 3.3: 20 B used,
// RoCE CM REQ leaves about 56). Opaque to the transport; validation is a later layer.
inline constexpr std::size_t kMaxTicketBytes = 48;

struct ConnParams {
  EpClass cls = EpClass::Control;
  PdId pd;  // protection domain of the new endpoint (default PD when unset)
  std::array<std::byte, kMaxTicketBytes> ticket{};
  std::uint8_t ticket_len = 0;
  // Requested read depths; 0 = the device maximum. The effective values are the
  // minimum of both sides (Endpoint::read_depth()).
  std::uint8_t ird = 0;  // responder_resources: inbound READs this side accepts
  std::uint8_t ord = 0;  // initiator_depth: outbound READs this side keeps in flight
  Nanos timeout = std::chrono::seconds(5);  // whole connect, relative to the call
};

// Negotiated READ depth of an established endpoint (spec 3.2).
struct ReadDepth {
  std::uint8_t ird = 0;  // min(our responder_resources, peer initiator_depth)
  std::uint8_t ord = 0;  // min(our initiator_depth, peer responder_resources)
};

enum class EpState : std::uint8_t { Ready, Error };

// Busy-poll budget for Fabric::poll: keep polling an empty CQ for this long.
struct PollBudget {
  Nanos busy{0};
};

struct DeviceCaps {
  const char* name = "";
  std::uint32_t max_inflight_reads = 0;
  bool supports_write = false;
};

// A two-sided message. Bytes are owned, so the sender's buffer is free on return.
struct Frame {
  std::vector<std::byte> bytes;
};

// CqError is a fabric-level event (endpoint 0, status = the error), not a work request.
enum class CompletionOp : std::uint8_t { Send, Recv, Read, Write, CqError };

struct Completion {
  EndpointId endpoint = 0;
  WrTag tag = 0;  // caller's tag; meaningless (zero) when is_recv or CqError
  bool is_recv = false;  // true for an inbound frame; tag 0 is a legal caller tag
  CompletionOp op = CompletionOp::Send;
  Status status;
  std::uint32_t bytes = 0;
  Frame frame;  // Recv only
};

}  // namespace miracache::fabric
