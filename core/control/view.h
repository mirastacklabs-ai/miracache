// SPDX-License-Identifier: Apache-2.0
// The placement View of a verified bundle body (W13). Lives in control (which links placement), so
// placement never depends on the bundle parser.
#pragma once

#include "control/bundle.h"
#include "placement/placement.h"

namespace miracache::control {

// epoch = body.epoch; one PlaceNode per ACTIVE node (draining and readonly nodes are not owners),
// in bundle order: id = node_id as decimal text, weight, zone (empty when the node has none).
View view_from_bundle(const BodyView& body);

}  // namespace miracache::control
