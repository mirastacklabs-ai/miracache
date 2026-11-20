// SPDX-License-Identifier: Apache-2.0
// Static weighted-rendezvous placement (design spec 7.1). Pure: no I/O, no state beyond the node list.
//
//   owner(scope_id) = argmax over nodes of  -weight / ln(h)
//   x = first 8 bytes of SHA-256("mira-place-v1" || scope_id[32] || node_id as UTF-8 bytes), big-endian u64
//   h = (x + 0.5) / 2^64   (double, 0 < h <= 1)
//   ties: the lexicographically smaller node_id (byte order of the UTF-8 string)
//
// Edge: for x >= 2^64 - 1024, x + 0.5 rounds to 2^64 in double, so h == 1.0, ln(h) == +0 and
// the score is -inf. Not clamped: such a node loses to any finite score, and all -inf is a tie
// (smaller node_id). A Go reimplementation must do the same IEEE double arithmetic (spec 7.1).
//
// node_id is the decimal text of nodes[].id (e.g. "7"). A Go controller must reproduce this exactly.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace miracache {

struct PlaceNode {
  std::string id;            // node_id text
  std::uint32_t weight = 1;  // > 0
  // Zone (nodes[].zone). Empty = the node is its own zone. Either every node has one or none does.
  std::string zone;
  PlaceNode() = default;
  PlaceNode(std::string i, std::uint32_t w = 1, std::string z = {}) : id(std::move(i)), weight(w), zone(std::move(z)) {}
};

// x of the formula above (exposed for the golden vectors).
std::uint64_t place_hash(std::span<const std::uint8_t, 32> scope_id, const std::string& node_id);

// Test seam: the score of one node from its hash x (-weight / ln(h)), and the owner given the
// per-node hashes (hashes[i] belongs to nodes[i]; same size). place_owner is exactly this with
// hashes from place_hash, so tie-breaks can be tested with injected (equal-score) hashes.
double place_score(std::uint32_t weight, std::uint64_t x);
std::size_t place_owner_from_hashes(std::span<const PlaceNode> nodes, std::span<const std::uint64_t> hashes);

// Index into `nodes` of the owner; 0 if `nodes` has one entry. `nodes` must not be empty.
std::size_t place_owner(std::span<const PlaceNode> nodes, std::span<const std::uint8_t, 32> scope_id);

// Replicas: indices of the first min(r, nodes.size()) nodes of the placement order, best first:
// score descending, ties to the smaller node_id (the same rule as place_owner). [0] == place_owner.
// Not re-ranked when a node is down; the order depends only on the scope and the node list.
// Zones: when nodes have a zone, a node is taken only if no earlier pick has its zone; the owner ([0]) does not
// depend on zones. The result is shorter than r only if there are fewer than r distinct zones.
std::vector<std::size_t> place_order(std::span<const PlaceNode> nodes, std::span<const std::uint8_t, 32> scope_id,
                                     std::size_t r);
std::vector<std::size_t> place_order_from_hashes(std::span<const PlaceNode> nodes, std::span<const std::uint64_t> hashes,
                                                 std::size_t r);


// A membership view: the epoch and the node list placement runs over.
struct View {
  std::uint64_t epoch = 0;
  std::vector<PlaceNode> nodes;  // id, weight, zone
};

// The owner set of a scope in `view`: place_order over view.nodes. [0] is the owner. Shorter than r when the view
// has fewer than r nodes, or fewer than r distinct zones (zoned views); empty only for an empty view. Never an error.
// Returns indices into view.nodes.
std::vector<std::size_t> owner_set(const View& view, std::span<const std::uint8_t, 32> scope_id, std::size_t r);

}  // namespace miracache
