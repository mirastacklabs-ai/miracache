// SPDX-License-Identifier: Apache-2.0
// e2e helper (plan 2C): memory-node IDs are random and learned by the client, so a test that wants to
// know which node owns a scope reads the IDs back from the client's miracache_client_node_info series
// (value 1 = the ID currently in use) and builds the same placement list the client uses.
#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

#include "src/placement.h"

namespace miracache::e2e {

// ID the client currently holds for the node listening on `addr` ("ip:port"); 0 if it has none.
inline std::uint32_t learned_id(const std::string& client_metrics, const std::string& addr) {
  std::istringstream in(client_metrics);
  std::string line;
  const std::string want = "addr=\"" + addr + "\"";
  while (std::getline(in, line)) {
    if (line.rfind("miracache_client_node_info{", 0) != 0 || line.find(want) == std::string::npos) continue;
    if (line.size() < 2 || line.compare(line.size() - 2, 2, " 1") != 0) continue;  // a replaced ID reads 0
    const auto p = line.find("node_id=\"");
    if (p == std::string::npos) continue;
    return static_cast<std::uint32_t>(std::strtoul(line.c_str() + p + 9, nullptr, 10));
  }
  return 0;
}

// Placement list of nodes[i] = addrs[i] with weights[i], in config order (what the client hashes).
inline std::vector<PlaceNode> learned_places(const std::string& client_metrics, const std::vector<std::string>& addrs,
                                             const std::vector<std::uint32_t>& weights) {
  std::vector<PlaceNode> out;
  for (std::size_t i = 0; i < addrs.size(); ++i)
    out.push_back(PlaceNode{std::to_string(learned_id(client_metrics, addrs[i])), weights[i]});
  return out;
}

}  // namespace miracache::e2e
