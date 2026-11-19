// SPDX-License-Identifier: Apache-2.0
#include "placement/placement.h"

#include <openssl/evp.h>

#include <algorithm>
#include <cmath>

#include "util/check.h"

namespace miracache {

namespace {
// One EVP_MD_CTX per thread, reused for every hash (MB2p); freed at thread exit.
struct ThreadCtx {
  EVP_MD_CTX* c = EVP_MD_CTX_new();
  ~ThreadCtx() { EVP_MD_CTX_free(c); }
};
}  // namespace

std::uint64_t place_hash(std::span<const std::uint8_t, 32> scope_id, const std::string& node_id) {
  static constexpr char kTag[] = "mira-place-v1";
  thread_local ThreadCtx tc;
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned len = 0;
  EVP_MD_CTX* c = tc.c;
  MIRACACHE_CHECK(c != nullptr);
  const bool ok = EVP_DigestInit_ex(c, EVP_sha256(), nullptr) == 1 &&
                  EVP_DigestUpdate(c, kTag, sizeof kTag - 1) == 1 && EVP_DigestUpdate(c, scope_id.data(), 32) == 1 &&
                  EVP_DigestUpdate(c, node_id.data(), node_id.size()) == 1 && EVP_DigestFinal_ex(c, md, &len) == 1;
  MIRACACHE_CHECK(ok);  // a silent 0 would make owners disagree for the thread's life (W13)
  std::uint64_t x = 0;
  for (int i = 0; i < 8; ++i) x = (x << 8) | md[i];
  return x;
}

double place_score(std::uint32_t weight, std::uint64_t x) {
  const double h = (static_cast<double>(x) + 0.5) / 18446744073709551616.0;
  return -static_cast<double>(weight) / std::log(h);
}

namespace {
// The argmax of the formula; hash_of(i) is node i's x. Shared by both entry points, so place_owner
// is exactly place_owner_from_hashes with place_hash, without building a hash vector per call (r6 B5).
template <class HashOf>
std::size_t argmax_owner(std::span<const PlaceNode> nodes, HashOf hash_of) {
  std::size_t best = 0;
  double best_score = 0;
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    const double score = place_score(nodes[i].weight, hash_of(i));
    if (i == 0 || score > best_score || (score == best_score && nodes[i].id < nodes[best].id)) {
      best = i;
      best_score = score;
    }
  }
  return best;
}
}  // namespace

std::size_t place_owner(std::span<const PlaceNode> nodes, std::span<const std::uint8_t, 32> scope_id) {
  return argmax_owner(nodes, [&](std::size_t i) { return place_hash(scope_id, nodes[i].id); });
}

std::size_t place_owner_from_hashes(std::span<const PlaceNode> nodes, std::span<const std::uint64_t> hashes) {
  MIRACACHE_CHECK(hashes.size() == nodes.size());
  return argmax_owner(nodes, [&](std::size_t i) { return hashes[i]; });
}

namespace {
template <class HashOf>
std::vector<std::size_t> order_by_score(std::span<const PlaceNode> nodes, std::size_t r, HashOf hash_of) {
  std::vector<std::pair<double, std::size_t>> sc(nodes.size());
  bool zoned = false;
  for (std::size_t i = 0; i < nodes.size(); ++i) {
    sc[i] = {place_score(nodes[i].weight, hash_of(i)), i};
    zoned = zoned || !nodes[i].zone.empty();
  }
  r = std::min(r, nodes.size());
  const auto better = [&](const auto& a, const auto& b) {
    return a.first > b.first || (a.first == b.first && nodes[a.second].id < nodes[b.second].id);
  };
  if (!zoned) {
    std::partial_sort(sc.begin(), sc.begin() + static_cast<std::ptrdiff_t>(r), sc.end(), better);
    std::vector<std::size_t> out(r);
    for (std::size_t i = 0; i < r; ++i) out[i] = sc[i].second;
    return out;
  }
  // A2.10 zones: walk the score order and take a node only if its zone is not used yet. Index 0 is always taken,
  // so the owner is the same with or without zones. Fewer than r come back if there are fewer than r zones.
  std::sort(sc.begin(), sc.end(), better);
  std::vector<std::size_t> out;
  for (const auto& e : sc) {
    if (out.size() >= r) break;
    bool used = false;
    for (std::size_t j : out) used = used || nodes[j].zone == nodes[e.second].zone;
    if (!used) out.push_back(e.second);
  }
  return out;
}
}  // namespace

std::vector<std::size_t> place_order(std::span<const PlaceNode> nodes, std::span<const std::uint8_t, 32> scope_id,
                                     std::size_t r) {
  return order_by_score(nodes, r, [&](std::size_t i) { return place_hash(scope_id, nodes[i].id); });
}

std::vector<std::size_t> place_order_from_hashes(std::span<const PlaceNode> nodes, std::span<const std::uint64_t> hashes,
                                                 std::size_t r) {
  MIRACACHE_CHECK(hashes.size() == nodes.size());
  return order_by_score(nodes, r, [&](std::size_t i) { return hashes[i]; });
}

}  // namespace miracache

namespace miracache {
std::vector<std::size_t> owner_set(const View& view, std::span<const std::uint8_t, 32> scope_id, std::size_t r) {
  return place_order(view.nodes, scope_id, r);
}
}  // namespace miracache
