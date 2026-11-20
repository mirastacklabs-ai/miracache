// SPDX-License-Identifier: Apache-2.0
// Static weighted-rendezvous placement (design spec 7.1): golden vectors (generated independently
// with openssl + awk, proto/golden/placement_v1.txt; a Go controller must match them), balance,
// weights and stability.
#include "src/placement.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <fstream>
#include <limits>
#include <random>
#include <sstream>
#include <string>

namespace miracache {
namespace {

using Scope = std::array<std::uint8_t, 32>;

Scope from_hex(const std::string& h) {
  Scope s{};
  for (std::size_t i = 0; i < 32; ++i) s[i] = static_cast<std::uint8_t>(std::stoi(h.substr(2 * i, 2), nullptr, 16));
  return s;
}

std::vector<PlaceNode> parse_nodes(const std::string& spec) {
  std::vector<PlaceNode> out;
  std::stringstream ss(spec);
  for (std::string it; std::getline(ss, it, ',');) {
    const auto c = it.find(':');
    out.push_back(PlaceNode{it.substr(0, c), static_cast<std::uint32_t>(std::stoul(it.substr(c + 1)))});
  }
  return out;
}

std::string owner_id(const std::vector<PlaceNode>& n, const Scope& s) { return n[place_owner(n, s)].id; }

Scope random_scope(std::mt19937_64& rng) {
  Scope s;
  for (auto& b : s) b = static_cast<std::uint8_t>(rng());
  return s;
}

TEST(Placement, GoldenVectors) {
  std::ifstream f(std::string(MIRACACHE_GOLDEN_DIR) + "/placement_v1.txt");
  ASSERT_TRUE(f.good());
  int hashes = 0, owners = 0;
  for (std::string line; std::getline(f, line);) {
    if (line.empty() || line[0] == '#') continue;
    std::stringstream ss(line);
    std::string kind, scope, a, b;
    ss >> kind >> scope >> a >> b;
    const Scope s = from_hex(scope);
    if (kind == "hash") {
      char want[17];
      std::snprintf(want, sizeof want, "%016llx", static_cast<unsigned long long>(place_hash(s, a)));
      EXPECT_EQ(b, want) << line;
      ++hashes;
    } else {
      ASSERT_EQ(kind, "owner");
      EXPECT_EQ(owner_id(parse_nodes(a), s), b) << line;
      ++owners;
    }
  }
  EXPECT_GE(hashes, 12);
  EXPECT_GE(owners, 60);
}

TEST(Placement, EqualWeightsSplitEvenly) {
  const auto nodes = parse_nodes("1:1,2:1,3:1");
  std::mt19937_64 rng(7);
  int cnt[3] = {0, 0, 0};
  constexpr int kN = 30000;
  for (int i = 0; i < kN; ++i) ++cnt[place_owner(nodes, random_scope(rng))];
  for (int c : cnt) EXPECT_NEAR(static_cast<double>(c) / kN, 1.0 / 3, 0.03) << c;
}

TEST(Placement, WeightsAreProportional) {
  const auto nodes = parse_nodes("1:1,2:1,3:2");
  std::mt19937_64 rng(8);
  int cnt[3] = {0, 0, 0};
  constexpr int kN = 30000;
  for (int i = 0; i < kN; ++i) ++cnt[place_owner(nodes, random_scope(rng))];
  EXPECT_NEAR(static_cast<double>(cnt[2]) / kN, 0.5, 0.03);
  EXPECT_NEAR(static_cast<double>(cnt[0]) / kN, 0.25, 0.03);
  EXPECT_NEAR(static_cast<double>(cnt[1]) / kN, 0.25, 0.03);
}

TEST(Placement, RemovingANodeMovesOnlyItsScopes) {
  const auto three = parse_nodes("1:1,2:1,3:1");
  const auto two = parse_nodes("1:1,3:1");  // node 2 removed
  std::mt19937_64 rng(9);
  int moved = 0, of2 = 0;
  constexpr int kN = 20000;
  for (int i = 0; i < kN; ++i) {
    const Scope s = random_scope(rng);
    const std::string before = owner_id(three, s), after = owner_id(two, s);
    if (before == "2") ++of2;
    else EXPECT_EQ(before, after);  // scopes of surviving nodes never move
    if (before != after) ++moved;
  }
  EXPECT_EQ(moved, of2);
  EXPECT_GT(of2, 0);
}

TEST(Placement, AddingANodeMovesScopesOnlyToIt) {
  const auto three = parse_nodes("1:1,2:1,3:1");
  const auto four = parse_nodes("1:1,2:1,3:1,4:1");
  std::mt19937_64 rng(10);
  int moved = 0;
  constexpr int kN = 20000;
  for (int i = 0; i < kN; ++i) {
    const Scope s = random_scope(rng);
    const std::string before = owner_id(three, s), after = owner_id(four, s);
    if (before != after) {
      EXPECT_EQ(after, "4");
      ++moved;
    }
  }
  EXPECT_NEAR(static_cast<double>(moved) / kN, 0.25, 0.03);
}

// ---- tie-break (injected hashes: equal doubles cannot be built from real SHA-256 outputs) ----

// First x2 in a window around the exact-real solution whose score for weight w2 equals `target`
// bit for bit. score = -w/ln(h) = target  =>  h = exp(-w/target).
bool find_equal_hash(std::uint32_t w2, double target, std::uint64_t* out) {
  const double h = std::exp(-static_cast<double>(w2) / target);
  const long double x0 = static_cast<long double>(h) * 18446744073709551616.0L;
  // Clamp before the cast (r6 B6): a long double outside [0, 2^64) cast to u64 is UB.
  const long double kMaxX = static_cast<long double>(std::numeric_limits<std::uint64_t>::max() - 4096);
  for (std::int64_t d = -(1 << 16); d <= (1 << 16); d += 256) {
    const long double xd = std::clamp(x0 + d, 0.0L, kMaxX);
    const auto x = static_cast<std::uint64_t>(xd);
    if (place_score(w2, x) == target) {
      *out = x;
      return true;
    }
  }
  return false;
}

std::size_t owner_of(const std::vector<PlaceNode>& n, const std::vector<std::uint64_t>& x) {
  return place_owner_from_hashes(n, x);
}

TEST(PlacementTie, SeamMatchesPlaceOwner) {
  std::mt19937_64 rng(5);
  const auto nodes = parse_nodes("1:1,2:3,3:2,10:5");
  for (int i = 0; i < 2000; ++i) {
    const Scope s = random_scope(rng);
    std::vector<std::uint64_t> xs;
    for (const auto& n : nodes) xs.push_back(place_hash(s, n.id));
    EXPECT_EQ(owner_of(nodes, xs), place_owner(nodes, s));
  }
}

TEST(PlacementTie, EqualWeightsEqualHashesGoToSmallerId) {
  // Byte order, not numeric order: "10" < "9".
  const std::uint64_t x = 0x1234567890abcdefull;
  for (std::uint32_t w : {1u, 7u}) {
    auto a = std::vector<PlaceNode>{{"10", w}, {"9", w}};
    EXPECT_EQ(a[owner_of(a, {x, x})].id, "10");
    a = {{"9", w}, {"10", w}};  // list order must not matter
    EXPECT_EQ(a[owner_of(a, {x, x})].id, "10");
    auto b = std::vector<PlaceNode>{{"b", w}, {"a", w}, {"c", w}};
    for (int rot = 0; rot < 3; ++rot) {
      EXPECT_EQ(b[owner_of(b, {x, x, x})].id, "a");
      std::rotate(b.begin(), b.begin() + 1, b.end());
    }
    // Three nodes where only two tie for the top: the third has a lower score.
    const auto c = std::vector<PlaceNode>{{"z", w}, {"m", w}, {"a", w}};
    EXPECT_EQ(c[owner_of(c, {x, x, 1ull})].id, "m");  // "a" has a tiny hash: score near zero
    EXPECT_EQ(c[owner_of(c, {x, 1ull, x})].id, "a");
    EXPECT_EQ(c[owner_of(c, {1ull, x, x})].id, "a");
  }
}

TEST(PlacementTie, DifferentWeightsEqualScoresGoToSmallerId) {
  std::mt19937_64 rng(77);
  int found2 = 0, found3 = 0;
  for (int t = 0; t < 4000 && (found2 < 20 || found3 < 20); ++t) {
    const std::uint64_t x1 = rng();
    const double s1 = place_score(1, x1);
    std::uint64_t x2 = 0, x3 = 0;
    if (!find_equal_hash(2, s1, &x2)) continue;
    ASSERT_EQ(place_score(2, x2), s1);
    ASSERT_NE(x1, x2);  // different hashes, same score
    // Two nodes: the smaller id wins wherever it sits in the list and whichever weight it has.
    for (bool small_first : {true, false}) {
      for (bool small_is_light : {true, false}) {
        std::vector<PlaceNode> n = {{"10", small_is_light ? 1u : 2u}, {"9", small_is_light ? 2u : 1u}};
        std::vector<std::uint64_t> x = {small_is_light ? x1 : x2, small_is_light ? x2 : x1};
        if (!small_first) {
          std::swap(n[0], n[1]);
          std::swap(x[0], x[1]);
        }
        EXPECT_EQ(n[owner_of(n, x)].id, "10");
      }
    }
    ++found2;
    if (!find_equal_hash(3, s1, &x3)) continue;
    ASSERT_EQ(place_score(3, x3), s1);
    // Three nodes, three different weights, one common score: "a" wins in every list order.
    std::vector<PlaceNode> n = {{"c", 1}, {"a", 2}, {"b", 3}};
    std::vector<std::uint64_t> x = {x1, x2, x3};
    for (int rot = 0; rot < 3; ++rot) {
      EXPECT_EQ(n[owner_of(n, x)].id, "a");
      std::rotate(n.begin(), n.begin() + 1, n.end());
      std::rotate(x.begin(), x.begin() + 1, x.end());
    }
    std::swap(n[0], n[2]);
    std::swap(x[0], x[2]);
    EXPECT_EQ(n[owner_of(n, x)].id, "a");
    ++found3;
  }
  EXPECT_GE(found2, 20) << "could not build equal scores for weights 1 and 2";
  EXPECT_GE(found3, 20) << "could not build equal scores for weights 1, 2 and 3";
}

TEST(PlacementTie, HigherScoreStillBeatsSmallerId) {
  const std::uint64_t lo = 0x4000000000000000ull, hi = 0xc000000000000000ull;  // hi has the larger score
  ASSERT_GT(place_score(1, hi), place_score(1, lo));
  const std::vector<PlaceNode> n = {{"a", 1}, {"b", 1}};
  EXPECT_EQ(n[owner_of(n, {lo, hi})].id, "b");
  EXPECT_EQ(n[owner_of(n, {hi, lo})].id, "a");
}

// r6 B7: x >= 2^64 - 1024 makes h exactly 1.0 and the score -inf (documented in placement.h and spec
// 7.1; a Go reimplementation must match). Such a node loses to any finite score; all -inf is a tie.
TEST(PlacementTie, TopHashesScoreMinusInfinity) {
  const std::uint64_t edge = std::numeric_limits<std::uint64_t>::max() - 1023;  // 2^64 - 1024
  EXPECT_TRUE(std::isinf(place_score(1, edge)) && place_score(1, edge) < 0);
  EXPECT_TRUE(std::isinf(place_score(5, std::numeric_limits<std::uint64_t>::max())));
  EXPECT_TRUE(std::isfinite(place_score(1, edge - 1)));
  const auto n = std::vector<PlaceNode>{{"a", 1}, {"b", 1}};
  EXPECT_EQ(n[owner_of(n, {edge, 1ull})].id, "b");  // a tiny finite score still beats -inf
  EXPECT_EQ(n[owner_of(n, {edge, edge + 7})].id, "a");  // both -inf: the smaller id
}


// ---- A2.10 replica order ----
TEST(PlacementOrder, GoldenVectors) {
  std::ifstream f(std::string(MIRACACHE_GOLDEN_DIR) + "/placement_order_v1.txt");
  ASSERT_TRUE(f.good());
  int n = 0;
  for (std::string line; std::getline(f, line);) {
    if (line.empty() || line[0] == '#') continue;
    std::stringstream ss(line);
    std::string kind, scope, nodes, want;
    ss >> kind >> scope >> nodes >> want;
    ASSERT_EQ(kind, "order");
    const auto pn = parse_nodes(nodes);
    std::string got;
    for (std::size_t i : place_order(pn, from_hex(scope), pn.size())) got += (got.empty() ? "" : ",") + pn[i].id;
    EXPECT_EQ(got, want) << line;
    ++n;
  }
  EXPECT_GE(n, 6);
}

TEST(PlacementOrder, FirstIsOwnerAndPrefixesAgree) {
  std::mt19937_64 rng(11);
  const auto nodes = parse_nodes("1:1,2:3,3:2,10:5,4:1");
  for (int i = 0; i < 2000; ++i) {
    const Scope s = random_scope(rng);
    const auto o1 = place_order(nodes, s, 1);
    ASSERT_EQ(o1.size(), 1u);
    EXPECT_EQ(o1[0], place_owner(nodes, s));
    const auto o3 = place_order(nodes, s, 3), o5 = place_order(nodes, s, 5);
    EXPECT_EQ(o3[0], o1[0]);
    EXPECT_TRUE(std::equal(o3.begin(), o3.end(), o5.begin()));
    EXPECT_EQ(place_order(nodes, s, 9).size(), 5u);  // capped at the node count
    auto sorted = o5;
    std::sort(sorted.begin(), sorted.end());
    for (std::size_t k = 0; k < 5; ++k) EXPECT_EQ(sorted[k], k);  // a permutation
  }
}

TEST(PlacementOrder, TiesGoToSmallerIdAtEveryRank) {
  const std::uint64_t x = 0x1234567890abcdefull;
  auto b = std::vector<PlaceNode>{{"b", 1}, {"10", 1}, {"a", 1}, {"9", 1}};
  for (int rot = 0; rot < 4; ++rot) {
    std::string got;
    for (std::size_t i : place_order_from_hashes(b, std::vector<std::uint64_t>{x, x, x, x}, 4)) got += b[i].id + ",";
    EXPECT_EQ(got, "10,9,a,b,");
    std::rotate(b.begin(), b.begin() + 1, b.end());
  }
  // A -inf node sorts last; two -inf nodes tie to the smaller id.
  const std::uint64_t edge = std::numeric_limits<std::uint64_t>::max() - 1023;
  const auto n = std::vector<PlaceNode>{{"a", 1}, {"b", 1}, {"c", 1}};
  const auto o = place_order_from_hashes(n, std::vector<std::uint64_t>{edge, 5ull, edge + 9}, 3);
  EXPECT_EQ((std::vector<std::size_t>{1, 0, 2}), o);
}

TEST(PlacementOrder, DownNodeDoesNotReRank) {
  // The order of the survivors is the same list minus the dead node: no third node is promoted into a rank
  // that is already taken (decision 2).
  std::mt19937_64 rng(3);
  const auto nodes = parse_nodes("1:1,2:1,3:1,4:1");
  for (int i = 0; i < 500; ++i) {
    const Scope s = random_scope(rng);
    const auto full = place_order(nodes, s, 4);
    EXPECT_EQ(place_order(nodes, s, 2), (std::vector<std::size_t>{full[0], full[1]}));
  }
}

// ---- A2.10 zones ----
std::vector<PlaceNode> parse_zoned(const std::string& spec) {  // "id:weight:zone,..."
  std::vector<PlaceNode> out;
  std::stringstream ss(spec);
  for (std::string it; std::getline(ss, it, ',');) {
    const auto c1 = it.find(':'), c2 = it.find(':', c1 + 1);
    out.push_back(PlaceNode{it.substr(0, c1), static_cast<std::uint32_t>(std::stoul(it.substr(c1 + 1, c2 - c1 - 1))), it.substr(c2 + 1)});
  }
  return out;
}

TEST(PlacementZones, GoldenVectors) {
  std::ifstream f(std::string(MIRACACHE_GOLDEN_DIR) + "/placement_zones_v1.txt");
  ASSERT_TRUE(f.good());
  int n = 0;
  for (std::string line; std::getline(f, line);) {
    if (line.empty() || line[0] == '#') continue;
    std::stringstream ss(line);
    std::string kind, scope, nodes, want;
    std::size_t r = 0;
    ss >> kind >> scope >> nodes >> r >> want;
    ASSERT_EQ(kind, "zorder");
    const auto pn = parse_zoned(nodes);
    std::string got;
    for (std::size_t i : place_order(pn, from_hex(scope), r)) got += (got.empty() ? "" : ",") + pn[i].id;
    EXPECT_EQ(got, want) << line;
    ++n;
  }
  EXPECT_GE(n, 9);
}

TEST(PlacementZones, OwnerNeverDependsOnZonesAndNoTwoPicksShareAZone) {
  std::mt19937_64 rng(21);
  const auto zoned = parse_zoned("1:1:a,2:3:a,3:2:b,10:5:b,4:1:c,5:2:c");
  auto plain = zoned;
  for (auto& p : plain) p.zone.clear();
  for (int i = 0; i < 3000; ++i) {
    const Scope s = random_scope(rng);
    const auto z = place_order(zoned, s, 3);
    ASSERT_EQ(z.size(), 3u);
    EXPECT_EQ(z[0], place_owner(plain, s));
    EXPECT_EQ(z[0], place_owner(zoned, s));
    EXPECT_EQ(z[0], place_order(plain, s, 1)[0]);
    EXPECT_NE(zoned[z[0]].zone, zoned[z[1]].zone);
    EXPECT_NE(zoned[z[0]].zone, zoned[z[2]].zone);
    EXPECT_NE(zoned[z[1]].zone, zoned[z[2]].zone);
    // A zone-less list is the plain order, with or without the zone field set to "".
    EXPECT_EQ(place_order(plain, s, 3), place_order(parse_nodes("1:1,2:3,3:2,10:5,4:1,5:2"), s, 3));
  }
}

TEST(PlacementZones, FewerZonesThanRGivesAShortSetNeverARepeatedZone) {
  std::mt19937_64 rng(5);
  const auto zoned = parse_zoned("1:1:a,2:1:a,3:1:b");
  for (int i = 0; i < 200; ++i) EXPECT_EQ(place_order(zoned, random_scope(rng), 3).size(), 2u);
}

TEST(PlacementZones, DownNodeDoesNotReRankWithZones) {
  // The set is a function of the scope and the node list only: asking for r=2 is the prefix of r=3.
  std::mt19937_64 rng(9);
  const auto zoned = parse_zoned("1:1:a,2:1:b,3:1:c,4:1:a");
  for (int i = 0; i < 500; ++i) {
    const Scope s = random_scope(rng);
    const auto full = place_order(zoned, s, 3);
    EXPECT_EQ(place_order(zoned, s, 2), (std::vector<std::size_t>{full[0], full[1]}));
  }
}
}  // namespace
}  // namespace miracache
