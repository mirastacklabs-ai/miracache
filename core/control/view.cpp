// SPDX-License-Identifier: Apache-2.0
#include "control/view.h"

namespace miracache::control {

View view_from_bundle(const BodyView& body) {
  View v;
  v.epoch = body.epoch;
  for (const NodeView& n : body.nodes) {
    if (n.state != MemberState::Active) continue;
    v.nodes.emplace_back(std::to_string(n.node_id), n.weight, n.zone.value_or(std::string{}));
  }
  return v;
}

}  // namespace miracache::control
