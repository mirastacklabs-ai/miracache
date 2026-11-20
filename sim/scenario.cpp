// SPDX-License-Identifier: Apache-2.0
#include "scenario.h"

#include <array>
#include <cstring>
#include <map>
#include <vector>

#include "fabric/sim/sim_fabric.h"

namespace miracache::sim {
namespace {

using namespace fabric;

constexpr std::size_t kSourceBytes = 64 * 1024;
constexpr std::uint32_t kSlot = 1024;
constexpr std::size_t kReadsPerNode = 32;

struct Node {
  SimFabric* fab = nullptr;
  std::vector<std::byte> source = std::vector<std::byte>(kSourceBytes);
  std::vector<std::byte> landing = std::vector<std::byte>(kReadsPerNode * kSlot);
  MemRegion src_mr, land_mr;
  Endpoint* ep = nullptr;
  std::vector<std::pair<std::uint32_t, std::uint32_t>> reads;  // (offset, len) per tag
  std::vector<WrTag> posted;                 // accepted posts, in post order
  std::map<WrTag, Status> rejected;          // posts refused because the endpoint was in ERR
};

struct Seen {
  std::map<WrTag, Status> status;
  std::vector<WrTag> order;  // first completion of each tag, in delivery order
  std::string failure;
};

void setup(Node& n, SimNetwork& net, NodeId id, Random& work) {
  n.fab = &net.add_node(id);
  for (auto& b : n.source) b = static_cast<std::byte>(work.next_u64());
  n.src_mr = n.fab->reg(n.source, Access::RemoteRead).value();
  n.land_mr = n.fab->reg(n.landing, Access::LocalWrite).value();
  for (std::size_t i = 0; i < kReadsPerNode; ++i) {
    const auto len = static_cast<std::uint32_t>(work.between(1, kSlot));
    const auto off = static_cast<std::uint32_t>(work.below(kSourceBytes - len + 1));
    n.reads.emplace_back(off, len);
  }
}

std::string check(Node& n, const Node& peer, Seen& seen, bool ordered) {
  for (const auto& [tag, st] : n.rejected) seen.status.try_emplace(tag, st);
  std::array<Completion, 16> batch;
  while (const auto got = n.fab->poll(batch)) {
    for (std::size_t i = 0; i < got; ++i) {
      const Completion& c = batch[i];
      auto [it, fresh] = seen.status.try_emplace(c.tag, c.status);
      if (fresh) seen.order.push_back(c.tag);
      if (!fresh && it->second.has_value() != c.status.has_value()) {
        return "duplicate completion disagrees with original";
      }
      if (c.status.has_value()) {
        const auto [off, len] = n.reads[c.tag];
        if (c.bytes != len || std::memcmp(n.landing.data() + c.tag * kSlot,
                                          peer.source.data() + off, len) != 0) {
          return "successful READ returned wrong bytes";
        }
      } else if (c.status.error().code != ErrorCode::Timeout &&
                 c.status.error().code != ErrorCode::LinkDown &&
                 c.status.error().code != ErrorCode::Aborted) {
        return std::string("unexpected error: ") + to_string(c.status.error().code);
      }
    }
  }
  if (seen.status.size() != kReadsPerNode) return "a READ never completed";
  // RC default: completions come back in post order (the opt-in unordered mode is exempt).
  if (ordered && seen.order != n.posted) return "completions not in post order";
  return n.ep->drained() ? "" : "endpoint not drained";
}

}  // namespace

ScenarioResult run_two_node_reads(std::uint64_t seed) {
  SimClock clock;
  SeededRandom net_rng(seed);
  SeededRandom work(seed ^ 0x9e3779b97f4a7c15ULL);
  FaultConfig faults;
  faults.drop = 0.05;
  // Even seeds run the RC-default ordered network; odd seeds opt in to reordering.
  faults.ordered = (seed % 2 == 0);
  faults.reorder = faults.ordered ? 0.0 : 0.25;
  faults.duplicate_completion = 0.10;
  SimNetwork net(clock, net_rng, faults);

  std::array<Node, 2> nodes;
  setup(nodes[0], net, 1, work);
  setup(nodes[1], net, 2, work);
  // Each node dials the other, so every direction uses its own dialled endpoint;
  // the accepted ends are unused and only need a listener to exist.
  ListenParams lp;
  lp.allow_unauthenticated_for_test = true;
  for (auto& n : nodes) static_cast<void>(n.fab->listen([](Endpoint*) {}, lp));
  auto dial = [&](Node& from, NodeId to) { from.ep = from.fab->connect(Peer{to}).value(); };
  Node& a = nodes[0];
  Node& b = nodes[1];
  dial(a, 2);
  dial(b, 1);

  ScenarioResult result;
  Node* all[2] = {&a, &b};
  Node* peers[2] = {&b, &a};
  for (int n = 0; n < 2; ++n) {
    Node& me = *all[n];
    const Node& peer = *peers[n];
    for (std::size_t tag = 0; tag < kReadsPerNode; ++tag) {
      const auto [off, len] = me.reads[tag];
      const Nanos when{static_cast<std::int64_t>(work.below(200'000))};
      net.schedule(when, [&, tag, off, len] {
        const RemoteRef remote{peer.src_mr.rkey,
                               reinterpret_cast<std::uint64_t>(peer.source.data()) + off, len};
        const LocalRef local{me.land_mr.lkey, me.landing.data() + tag * kSlot, len};
        if (auto s = me.ep->post_read(remote, local, tag); !s) {
          if (s.error().code == ErrorCode::Aborted) {  // endpoint already in ERR (RC)
            me.rejected.emplace(tag, s);
          } else {
            result.ok = false;
            result.failure = "post_read rejected";
          }
        } else {
          me.posted.push_back(tag);
        }
      });
    }
  }
  // One link flap somewhere in the first 200 us.
  const Nanos down{static_cast<std::int64_t>(work.below(150'000))};
  net.schedule(down, [&] { net.set_link(1, 2, false); });
  net.schedule(down + Nanos{static_cast<std::int64_t>(work.between(1, 60'000))},
               [&] { net.set_link(1, 2, true); });

  net.run_until_idle();

  Seen seen_a, seen_b;
  if (result.ok) result.failure = check(a, b, seen_a, faults.ordered);
  if (result.failure.empty()) result.failure = check(b, a, seen_b, faults.ordered);
  result.ok = result.ok && result.failure.empty();
  result.trace_hash = net.trace_hash();
  return result;
}

}  // namespace miracache::sim
