// SPDX-License-Identifier: Apache-2.0
// Wildcard rule: pairing a memory node's rails with the client's local devices.
//
//   - A local device with a subnet pairs only with rails of that exact subnet (the first such device wins).
//   - A local device with a blank subnet (the legacy fabric.device, or a fabric.devices entry without `subnet`) is a
//     WILDCARD: it takes every rail that no subnet device claims, whatever the rail's subnet (and, with fabric.protocol =
//     auto, whatever its protocol). Only one wildcard is allowed (config parse); each subnet rail it takes is logged
//     once (its netdev may not reach that subnet).
//     So one device can serve rails in several subnets only through the wildcard.
//   - A rail with no subnet (a legacy node) pairs with the first wildcard device, else device 0.
//   - A pair must share a protocol: a rail that names one the client does not run (fabric.protocol not "auto") is
//     unpaired, whatever its subnet.
//   - An unpaired rail is unused, logged once (node ID, host, addr) and counted by the caller
//     (miracache_client_rail_unpaired{node}).
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "fabric/types.h"
#include "miracache/config.h"

namespace miracache {

// "host:port" -> RailAddr; false on a malformed address.
bool parse_rail(const std::string& s, fabric::RailAddr& out);

// The local devices: fabric.devices, else the legacy fabric.device as one wildcard device (subnet "").
std::vector<LocalDevice> local_devices(const ClientConfig& cfg);

// One node rail as the client sees it (bundle NodeView rail), and the local device it pairs with.
struct NodeRail {
  std::string addr, subnet, protocol;
};
struct PairedRail {
  std::uint8_t index = 0;
  fabric::RailAddr addr;
  std::size_t device = 0;  // index into local_devices(cfg)
};

// Pairs rails[0..3] per the rule above. `unpaired` = the number of rails left unused (each one logged once with
// node_id, host and addr: the rail's IP).
std::vector<PairedRail> pair_rails(const ClientConfig& cfg, const std::vector<NodeRail>& rails, std::uint32_t node_id,
                                   const std::string& host, std::uint32_t& unpaired);

}  // namespace miracache
