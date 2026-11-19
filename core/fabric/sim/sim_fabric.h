// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fabric/fabric.h"
#include "fabric/sim/sim_network.h"

namespace miracache::fabric {

class SimFabric;

// RL3 (multi-rail plan decisions 8, 9; P24): checks a client's fetch rules on every simulated device it is attached to
// (SimFabric::set_audit; one audit spans all of a client's devices, so a slice re-issued on another device is seen).
// Local buffers are host addresses, the same on every device. A READ or WRITE counts as outstanding from its post until
// its completion reaches the client: by default when SimFabric::poll delivers it; with `client_view`, only when the
// client's own logic takes it (on_seen, from the client's completion hook), since the rule is that the client acts
// only on a completion it has itself seen ("its own CQE has arrived"), not one still queued in a lower layer.
// Violations are recorded, not fatal, so a test (or a mutator run) can show them.
//   kSeqEarly          a block's state_gen READ posted while one of its payload READs is outstanding, or while a payload
//                      READ of it failed and was not yet read again successfully (seq before the last slice CQE, or
//                      before a pending re-issue: RL0 `seq-before-reissue`).
//   kReissueEarly      a READ posted into bytes an outstanding READ may still write (a re-issue before the original's
//                      CQE: RL0 `reissue-before-flush`; also a reuse of a span whose READ is still in flight).
//   kReleaseOutstanding a buffer given back (on_release, the client's hook) while a READ or WRITE on it is outstanding.
// `classify` (set by the test) names a READ's block and whether it is the state_gen READ; null = the buffer rules only.
class SimWrAudit {
 public:
  enum Rule { kSeqEarly = 0, kReissueEarly = 1, kReleaseOutstanding = 2 };
  struct TagInfo {
    std::uint64_t group = 0;
    bool seq = false;
  };
  std::function<std::optional<TagInfo>(WrTag)> classify;
  bool client_view = false;  // completions settle through on_seen (the client hook), not SimFabric::poll

  // `dev` + `ep` name the endpoint (endpoint ids repeat across devices).
  void on_post(const void* dev, EndpointId ep, CompletionOp op, WrTag tag, const LocalRef& l);
  void on_delivered(const void* dev, EndpointId ep, CompletionOp op, WrTag tag, bool ok);  // SimFabric::poll
  void on_seen(CompletionOp op, WrTag tag, bool ok);  // client_view: the client took it (tags unique per WR)
  void on_release(const std::byte* addr, std::size_t len);

  std::size_t count(Rule r) const { return counts_[r]; }
  std::size_t violations() const { return counts_[0] + counts_[1] + counts_[2]; }
  const std::vector<std::string>& messages() const { return msgs_; }
  std::size_t outstanding() const { return out_.size(); }

 private:
  struct Out {
    const void* dev;
    EndpointId ep;
    CompletionOp op;
    WrTag tag;
    std::uintptr_t addr;
    std::size_t len;
  };
  struct Group {
    unsigned data_out = 0;
    std::map<std::uintptr_t, unsigned> failed;  // payload READs (by landing address) failed and not yet read again
  };
  void flag(Rule r, std::string msg);
  void settle(std::vector<Out>::iterator it, CompletionOp op, WrTag tag, bool ok);
  std::vector<Out> out_;
  std::map<std::uint64_t, Group> groups_;
  std::size_t counts_[3] = {0, 0, 0};
  std::vector<std::string> msgs_;
};

// One end of a simulated reliable connection. Either end moving to ERR (abort(), a
// dropped request, CQ overflow) moves both: outstanding work on both ends flushes at
// once with Aborted, and new posts fail with Aborted.
class SimEndpoint final : public Endpoint {
 public:
  SimEndpoint(SimFabric& owner, EndpointId id, PdId pd = {}, EpClass cls = EpClass::Control)
      : owner_(owner), id_(id), pd_(pd), cls_(cls) {}

  EndpointId id() const override { return id_; }
  Status post_send(Frame frame, WrTag tag) override;
  Status post_read(RemoteRef remote, LocalRef local, WrTag tag) override;
  Status post_write(LocalRef local, RemoteRef remote, WrTag tag) override;
  // HR3b: an abort of an endpoint with work still outstanding is counted on its fabric (aborts_with_work).
  void abort() override;
  bool drained() const override { return pending_.empty(); }
  EpState state() const override { return aborted_ ? EpState::Error : EpState::Ready; }
  ReadDepth read_depth() const override { return {128, 128}; }
  std::span<const std::byte> peer_private_data() const override { return private_data_; }
  void set_private_data(std::span<const std::byte> d) { private_data_.assign(d.begin(), d.end()); }

  void connect_to(SimEndpoint* peer) { peer_ = peer; }
  // Passive side (RL1): the listener address this endpoint was accepted on.
  void set_rail(const RailAddr& a) {
    rail_ = a;
    has_rail_ = true;
  }
  bool on_rail(const RailAddr& a) const { return has_rail_ && rail_.host == a.host && rail_.port == a.port; }
  NodeId peer_node() const;
  SimFabric& owner() { return owner_; }
  bool aborted() const { return aborted_; }
  PdId pd() const { return pd_; }
  // Buffer-layout class: ConnParams::cls on the active side, Admission::cls (or
  // ListenParams::accept_class without an AdmitFn) on the passive side, as on verbs.
  EpClass cls() const { return cls_; }
  bool released() const { return released_; }
  // Scheduled network events that still hold a raw pointer to this endpoint.
  std::uint32_t pending_events() const { return pending_events_; }
  void mark_released() { released_ = true; }
  // Moves this end and its peer to ERR and flushes both ends' outstanding work.
  void enter_error();

 private:
  struct Pending {
    CompletionOp op;
    WrTag tag;
    bool pinned;
    std::uint32_t lkey;
  };

  // Refuses posts on an unconnected or errored endpoint.
  Status can_post() const;
  // Validates a local-buffer op (READ/WRITE) and pins its region.
  Status check_local(CompletionOp op, const LocalRef& local) const;
  // Registers the request and schedules `exec` at its delivery time. `exec` runs only
  // if the request is still outstanding, the endpoint is healthy, the link is up and
  // the request was not dropped, in that order (so flushed work is never "lost").
  void submit(CompletionOp op, WrTag tag, const LocalRef* pin, std::function<void(std::uint64_t)> exec);
  // Completes request `seq` (no-op if it was already flushed).
  void complete(std::uint64_t seq, Status status, std::uint32_t bytes);
  void retire(const Pending& p, Status status, std::uint32_t bytes);
  void flush_all();

  void run_read(std::uint64_t seq, RemoteRef remote, LocalRef local);
  void run_write(std::uint64_t seq, LocalRef local, RemoteRef remote);
  void place_slices(std::uint64_t seq, bool is_write, RemoteRef remote, std::byte* local,
                    std::vector<std::byte> snapshot, std::uint32_t len);

  SimFabric& owner_;
  EndpointId id_;
  PdId pd_;
  EpClass cls_;
  bool released_ = false;
  std::uint32_t pending_events_ = 0;
  SimEndpoint* peer_ = nullptr;
  RailAddr rail_;
  bool has_rail_ = false;
  bool aborted_ = false;
  std::vector<std::byte> private_data_;
  std::uint64_t next_seq_ = 0;
  std::map<std::uint64_t, Pending> pending_;  // outstanding requests in post order
  // RC ordering: a SEND is delivered only after every earlier WRITE on this endpoint has had all
  // its slices placed (an early iWARP write CQE does not change that). Deferred sends wait here.
  std::uint32_t writes_unplaced_ = 0;
  std::deque<std::function<void()>> deferred_sends_;
  void slice_placed();
  Nanos last_due_{0};                         // delivery times are monotonic when ordered
};

// One simulated NIC. Created via SimNetwork::add_node.
class SimFabric final : public Fabric {
 public:
  SimFabric(SimNetwork& net, NodeId id, std::size_t cq_capacity)
      : net_(net), id_(id), cq_capacity_(cq_capacity) {}

  Expected<DeviceCaps> probe() override;
  Expected<PdId> alloc_pd() override;
  Status free_pd(PdId pd) override;
  Expected<MemRegion> reg(std::span<std::byte> buf, Access access, PdId pd = {}) override;
  // Released endpoints are counted out at once and freed as soon as no scheduled delivery
  // still references them (swept on release/connect/poll). A released endpoint is in ERR,
  // so its peer never dereferences it again.
  Status release(Endpoint* ep) override;
  std::size_t endpoint_count() const;
  // Must name the registered region exactly (key, addr and len).
  Status dereg(const MemRegion& region) override;
  Expected<Endpoint*> connect(const Peer& peer, const ConnParams& params = {}) override;
  Status listen(AcceptFn on_accept, const ListenParams& params = {}) override;
  // Once the bounded CQ has overflowed, the completions already queued drain first,
  // then one CqError completion (ResourceExhausted) is returned and nothing else:
  // all of this node's endpoints are in ERR and later completions are discarded.
  std::size_t poll(std::span<Completion> out, PollBudget budget = {}) override;
  int wait_fd() override { return -1; }

  // RL1: several listeners per node, keyed by their RailAddr (a connect picks the listener with the same address;
  // an empty address picks the first, and a node with a single listener accepts any address, as before).
  // Fake port events for health tests: port state, fatal latch, and failing one listener (rail).
  FabricHealth health() override;
  void set_port_state_for_test(std::string s) { port_state_ = std::move(s); }
  void set_fatal_for_test(bool f) { fatal_ = f; }
  // Rkeys/lkeys of this device start here (before any registration), so two simulated devices hand out distinct keys,
  // as real devices do.
  void set_key_base_for_test(std::uint32_t base) { next_key_ = base; }
  // Test opt-in for the old behaviour: a node with ONE listener takes a connect to any address (a test that changes a
  // node's rail address under a sim that cannot listen on the new one). Off by default (verbs refuses a wrong address).
  void set_single_listener_takes_any_address_for_test(bool on) { any_addr_ = on; }
  // Flushes every endpoint accepted on the listener at `addr` (both ends move to ERR) and refuses connects to it
  // until restore_rail(); health() reports it as listener_ok = false. False if no such listener.
  bool fail_rail(const RailAddr& addr);
  bool restore_rail(const RailAddr& addr);
  // Moves every endpoint of this node that is connected to node `peer` to ERR (a whole-link failure).
  void abort_endpoints_to(NodeId peer);

  NodeId id() const { return id_; }
  SimNetwork& network() { return net_; }

  const MemRegion* find_region(std::uint32_t key) const;
  // Protection domain a region was registered in (default PdId{} if unknown).
  PdId region_pd(std::uint32_t key) const;
  void pin(std::uint32_t lkey) { ++pins_[lkey]; }
  void unpin(std::uint32_t lkey) { --pins_[lkey]; }
  void push_completion(Completion c);
  bool cq_overflowed() const { return overflowed_; }
  // HR3b (hot-reload plan): endpoints aborted while a WR was still outstanding on them (a session end, a drain, a
  // release that had to flush). A planned rebuild closes its old connection only when it is quiet: tests assert 0.
  std::uint64_t aborts_with_work() const { return aborts_with_work_.load(std::memory_order_relaxed); }
  void note_abort_with_work() { aborts_with_work_.fetch_add(1, std::memory_order_relaxed); }
  // RL3: READ/WRITE posts and completions of this device's endpoints are reported to `a` (null = off). Must outlive it.
  void set_audit(SimWrAudit* a) { audit_ = a; }
  SimWrAudit* audit() const { return audit_; }
  // Q6 fault hook: while `call` is set, connect() fails before any remote contact, as a local device at its resource
  // limit does (soft-iWARP's ibv_create_cq / rdma_create_qp with ENOMEM): ResourceExhausted, and the failure is
  // recorded in fabric::last_local_failure (`call`, `os_errno`, device "sim"). nullptr clears it. `call` must be static.
  void inject_local_failure(const char* call, int os_errno = 12 /* ENOMEM */) {
    local_errno_.store(os_errno, std::memory_order_relaxed);
    local_call_.store(call, std::memory_order_release);
  }
  std::uint64_t local_failures() const { return local_failures_.load(std::memory_order_relaxed); }
  // Run #233 test hook: every connect() of this device first lets `d` of virtual time pass, the network delivering
  // whatever is due meanwhile (a slow rdma_cm handshake: address/route resolution, a REP that takes long). 0 = instant.
  void set_connect_delay_for_test(Nanos d) { connect_delay_ = d; }

 private:
  SimEndpoint* make_endpoint(PdId pd, EpClass cls);
  bool known_pd(PdId pd) const;  // the default PD or one from alloc_pd()
  void sweep_released();

  SimNetwork& net_;
  NodeId id_;
  std::size_t cq_capacity_;
  bool overflowed_ = false;
  bool overflow_reported_ = false;
  std::uint32_t next_key_ = 1;
  std::map<std::uint32_t, MemRegion> regions_;
  std::map<std::uint32_t, std::uint32_t> pins_;
  std::vector<std::unique_ptr<SimEndpoint>> endpoints_;
  std::map<std::uint32_t, PdId> region_pd_;
  std::uint32_t next_pd_ = 1;
  std::vector<PdId> pds_;
  struct Listener {
    RailAddr addr;
    AcceptFn on_accept;
    AdmitFn admit;
    PdId accept_pd;
    EpClass accept_class = EpClass::Control;
    bool down = false;
  };
  Listener* find_listener(const RailAddr& a);
  bool any_addr_ = false;
  std::vector<Listener> listeners_;
  std::string port_state_ = "ACTIVE";
  bool fatal_ = false;
  std::deque<Completion> cq_;
  std::atomic<std::uint64_t> aborts_with_work_{0};
  SimWrAudit* audit_ = nullptr;
  std::atomic<const char*> local_call_{nullptr};  // Q6 fault hook (inject_local_failure)
  std::atomic<int> local_errno_{0};
  std::atomic<std::uint64_t> local_failures_{0};
  Nanos connect_delay_{0};  // set_connect_delay_for_test
};

}  // namespace miracache::fabric
