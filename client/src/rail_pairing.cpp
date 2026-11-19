// SPDX-License-Identifier: Apache-2.0
// RL2 decision 5: node rail <-> local device pairing (rail_pairing.h has the rule).
#include "src/rail_pairing.h"

#include <cstdlib>
#include <mutex>
#include <set>
#include <string>

#include "util/log.h"

namespace miracache {

namespace {
// H01: (node_id, rail, addr, subnet) of every subnet rail the wildcard device took and logged; pair_rails runs on each
// open and rebuild of a node, the line is written once per key per process.
bool first_wildcard_take(std::uint32_t node_id, std::size_t rail, const std::string& addr, const std::string& subnet) {
  static std::mutex mu;
  static std::set<std::string> seen;
  const std::string key = std::to_string(node_id) + '|' + std::to_string(rail) + '|' + addr + '|' + subnet;
  std::lock_guard<std::mutex> g(mu);
  return seen.insert(key).second;
}
}  // namespace

bool parse_rail(const std::string& s, fabric::RailAddr& out) {
  const auto colon = s.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= s.size()) return false;
  char* end = nullptr;
  const long port = std::strtol(s.c_str() + colon + 1, &end, 10);
  if (*end != '\0' || port <= 0 || port > 65535) return false;
  out.host = s.substr(0, colon);
  out.port = static_cast<std::uint16_t>(port);
  return true;
}

std::vector<LocalDevice> local_devices(const ClientConfig& cfg) {
  if (!cfg.devices.empty()) return cfg.devices;
  return {LocalDevice{cfg.device, ""}};
}

std::vector<PairedRail> pair_rails(const ClientConfig& cfg, const std::vector<NodeRail>& rails, std::uint32_t node_id,
                                   const std::string& host, std::uint32_t& unpaired) {
  const auto devs = local_devices(cfg);
  const std::size_t none = devs.size();
  std::size_t wildcard = none;  // the first device with a blank subnet
  for (std::size_t d = 0; d < devs.size() && wildcard == none; ++d)
    if (devs[d].subnet.empty()) wildcard = d;
  std::vector<PairedRail> out;
  unpaired = 0;
  for (std::size_t i = 0; i < rails.size() && i < 4; ++i) {
    PairedRail p;
    p.index = static_cast<std::uint8_t>(i);
    std::size_t dev = none;
    if (rails[i].subnet.empty()) {
      dev = wildcard != none ? wildcard : 0;  // a legacy node's rails: the wildcard, else device 0
    } else {
      for (std::size_t d = 0; d < devs.size() && dev == none; ++d)
        if (devs[d].subnet == rails[i].subnet) dev = d;  // exact subnet wins
      if (dev == none) dev = wildcard;                    // else the wildcard takes it (none if there is no wildcard)
    }
    const bool proto_ok = rails[i].protocol.empty() || cfg.protocol == FabricProtocol::Auto ||
                          rails[i].protocol == to_string(cfg.protocol);
    if (dev == none || !proto_ok || !parse_rail(rails[i].addr, p.addr)) {
      ++unpaired;
      log::write(log::Level::Warn, "client",
                 "memory-node rail is unpaired (no local device of its subnet and no wildcard device, or another protocol): unused",
                 {{"node_id", std::to_string(node_id)}, {"hostname", host}, {"addr", rails[i].addr}, {"rail", std::to_string(i)},
                  {"subnet", rails[i].subnet}, {"protocol", rails[i].protocol}});
      continue;
    }
    // H01: no local device names this rail's subnet, so the wildcard took it. With fabric.protocol = auto that is any
    // protocol and any subnet, which the wildcard's netdev may not reach: say so once.
    if (!rails[i].subnet.empty() && dev == wildcard &&
        first_wildcard_take(node_id, i, rails[i].addr, rails[i].subnet))
      log::write(log::Level::Warn, "client",
                 "memory-node rail paired with the wildcard device (no local device names its subnet); it is used only "
                 "if that device reaches the subnet",
                 {{"node_id", std::to_string(node_id)}, {"hostname", host}, {"addr", rails[i].addr}, {"rail", std::to_string(i)},
                  {"subnet", rails[i].subnet}, {"protocol", rails[i].protocol}, {"device", devs[dev].device}});
    p.device = dev;
    out.push_back(std::move(p));
  }
  return out;
}

}  // namespace miracache
