// SPDX-License-Identifier: Apache-2.0
#include "fabric/verbs_cm/protocol_rules.h"

#include <infiniband/verbs.h>

#include <algorithm>
#include <cstring>
#include <utility>

namespace miracache::fabric::protocol {

const char* to_string(Protocol p) {
  switch (p) {
    case Protocol::Unknown: return "unknown";
    case Protocol::RoCE: return "roce";
    case Protocol::IWarp: return "iwarp";
    case Protocol::InfiniBand: return "infiniband";
  }
  return "?";
}

const char* to_string(Setting s) {
  switch (s) {
    case Setting::Auto: return "auto";
    case Setting::RoCE: return "roce";
    case Setting::IWarp: return "iwarp";
  }
  return "?";
}

Expected<Setting> parse_setting(std::string_view t) {
  if (t == "auto") return Setting::Auto;
  if (t == "roce") return Setting::RoCE;
  if (t == "iwarp") return Setting::IWarp;
  return Error{ErrorCode::InvalidArgument, "fabric.protocol must be auto, roce or iwarp"};
}

Protocol detect(ibv_context* ctx) {
  switch (ctx->device->transport_type) {
    case IBV_TRANSPORT_IWARP:
      return Protocol::IWarp;
    case IBV_TRANSPORT_IB: {
      ibv_port_attr pa{};
      if (ibv_query_port(ctx, 1, &pa) != 0) return Protocol::Unknown;
      return pa.link_layer == IBV_LINK_LAYER_ETHERNET ? Protocol::RoCE : Protocol::InfiniBand;
    }
    default:
      return Protocol::Unknown;
  }
}

Expected<Protocol> resolve(Setting setting, Protocol detected) {
  switch (setting) {
    case Setting::Auto:
      if (detected == Protocol::Unknown || detected == Protocol::InfiniBand) {
        return Error{ErrorCode::Unsupported, "device is neither RoCE nor iWARP"};
      }
      return detected;
    case Setting::RoCE:
      if (detected != Protocol::RoCE) {
        return Error{ErrorCode::InvalidArgument, "fabric.protocol=roce but the device is not RoCE"};
      }
      return Protocol::RoCE;
    case Setting::IWarp:
      if (detected != Protocol::IWarp) {
        return Error{ErrorCode::InvalidArgument, "fabric.protocol=iwarp but the device is not iWARP"};
      }
      return Protocol::IWarp;
  }
  return Error{ErrorCode::InvalidArgument, "fabric.protocol"};
}

Access region_access(Protocol p, Access requested) {
  // Kernel core/rw.c: an iWARP READ sink must allow remote write.
  if (p == Protocol::IWarp && has(requested, Access::LocalWrite)) return requested | Access::RemoteWrite;
  return requested;
}

std::string node_type(ibv_context* ctx) {
  const ibv_transport_type tt = ctx->device->transport_type;
  ibv_port_attr pa{};
  const bool eth = ibv_query_port(ctx, 1, &pa) == 0 && pa.link_layer == IBV_LINK_LAYER_ETHERNET;
  return std::string(tt == IBV_TRANSPORT_IWARP ? "iwarp" : tt == IBV_TRANSPORT_IB ? "ib" : "other") +
         (eth ? "/ethernet" : "/ib");
}

bool active_sends_first(Protocol p) { return p == Protocol::IWarp; }

GidPolicy gid_policy(Protocol p) { return {true, p == Protocol::IWarp}; }

namespace {
std::uint8_t clamp8(std::uint32_t v) { return static_cast<std::uint8_t>(std::min<std::uint32_t>(v, 255)); }
}  // namespace

Depth active_depth(Protocol, std::uint8_t req_ird, std::uint8_t req_ord, std::uint32_t dev_ird,
                   std::uint32_t dev_ord) {
  return {clamp8(req_ird != 0 ? std::min<std::uint32_t>(req_ird, dev_ird) : dev_ird),
          clamp8(req_ord != 0 ? std::min<std::uint32_t>(req_ord, dev_ord) : dev_ord)};
}

Depth passive_depth(Protocol, std::uint32_t peer_ord, std::uint32_t peer_ird, std::uint32_t dev_ird,
                    std::uint32_t dev_ord) {
  return {clamp8(std::min(dev_ird, peer_ord)), clamp8(std::min(dev_ord, peer_ird))};
}

ReadDepth effective_depth(Depth ours, Depth peer) {
  return {clamp8(std::min<std::uint32_t>(ours.ird, peer.ord)), clamp8(std::min<std::uint32_t>(ours.ord, peer.ird))};
}

std::size_t encode_private(Protocol p, Depth depth, std::span<const std::byte> ticket, std::byte* out) {
  out[0] = static_cast<std::byte>(kPrivVersion);
  out[1] = static_cast<std::byte>(ticket.size());
  out[2] = static_cast<std::byte>(p);
  out[3] = static_cast<std::byte>(depth.ird);
  out[4] = static_cast<std::byte>(depth.ord);
  if (!ticket.empty()) std::memcpy(out + kPrivHeader, ticket.data(), ticket.size());
  return kPrivHeader + ticket.size();
}

Expected<Decoded> decode_private(std::span<const std::byte> raw) {
  if (raw.empty()) return Error{ErrorCode::Corrupt, "private_data too short"};
  if (std::to_integer<unsigned>(raw[0]) != kPrivVersion) {
    return Error{ErrorCode::Unsupported, "private_data version unsupported (old or newer peer)"};
  }
  if (raw.size() < kPrivHeader) return Error{ErrorCode::Corrupt, "private_data too short"};
  const auto n = static_cast<std::size_t>(std::to_integer<unsigned>(raw[1]));
  if (n > kMaxTicketBytes || n + kPrivHeader > raw.size()) {
    return Error{ErrorCode::Corrupt, "private_data length invalid"};
  }
  Decoded d;
  d.protocol = static_cast<Protocol>(std::to_integer<unsigned>(raw[2]));
  d.depth = {static_cast<std::uint8_t>(std::to_integer<unsigned>(raw[3])),
             static_cast<std::uint8_t>(std::to_integer<unsigned>(raw[4]))};
  d.ticket = raw.subspan(kPrivHeader, n);
  return d;
}

}  // namespace miracache::fabric::protocol
