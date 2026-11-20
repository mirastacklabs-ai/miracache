// SPDX-License-Identifier: Apache-2.0
#include "fabric/sim/sim_fabric.h"
#include "fabric/verbs_cm/protocol_rules.h"  // reject table only (header-only, no verbs)

#include <algorithm>
#include <cstring>

namespace miracache::fabric {
namespace {

bool within(const MemRegion& r, std::uint64_t addr, std::uint64_t len) {
  const auto base = reinterpret_cast<std::uint64_t>(r.addr);
  return addr >= base && addr - base <= r.len && len <= r.len - (addr - base);
}

bool overlaps(std::uintptr_t a, std::size_t al, std::uintptr_t b, std::size_t bl) {
  return al != 0 && bl != 0 && a < b + bl && b < a + al;
}

}  // namespace

// ---- SimWrAudit ----

void SimWrAudit::flag(Rule r, std::string msg) {
  ++counts_[r];
  if (msgs_.size() < 64) msgs_.push_back(std::move(msg));
}

void SimWrAudit::on_post(const void* dev, EndpointId ep, CompletionOp op, WrTag tag, const LocalRef& l) {
  if (op != CompletionOp::Read && op != CompletionOp::Write) return;
  const auto a = reinterpret_cast<std::uintptr_t>(l.addr);
  if (op == CompletionOp::Read) {
    for (const auto& o : out_)
      if (o.op == CompletionOp::Read && overlaps(a, l.len, o.addr, o.len)) {
        flag(kReissueEarly, "READ posted into bytes an outstanding READ may still write (tag " + std::to_string(tag) +
                                " over " + std::to_string(o.tag) + ")");
        break;
      }
    if (classify) {
      if (auto ti = classify(tag)) {
        Group& g = groups_[ti->group];
        if (ti->seq) {
          if (g.data_out > 0) flag(kSeqEarly, "seq READ posted before the last payload CQE (group " + std::to_string(ti->group) + ")");
          else if (!g.failed.empty())
            flag(kSeqEarly, "seq READ posted while a failed payload slice was not read again (group " + std::to_string(ti->group) + ")");
        } else {
          ++g.data_out;
        }
      }
    }
  }
  out_.push_back(Out{dev, ep, op, tag, a, l.len});
}

void SimWrAudit::on_delivered(const void* dev, EndpointId ep, CompletionOp op, WrTag tag, bool ok) {
  if (client_view || (op != CompletionOp::Read && op != CompletionOp::Write)) return;
  settle(std::find_if(out_.begin(), out_.end(),
                      [&](const Out& o) { return o.dev == dev && o.ep == ep && o.op == op && o.tag == tag; }),
         op, tag, ok);
}

void SimWrAudit::on_seen(CompletionOp op, WrTag tag, bool ok) {
  if (!client_view || (op != CompletionOp::Read && op != CompletionOp::Write)) return;
  settle(std::find_if(out_.begin(), out_.end(), [&](const Out& o) { return o.op == op && o.tag == tag; }), op, tag, ok);
}

void SimWrAudit::settle(std::vector<Out>::iterator it, CompletionOp op, WrTag tag, bool ok) {
  if (it == out_.end()) return;  // a duplicate completion, or a WR posted before the audit was set
  const std::uintptr_t a = it->addr;
  out_.erase(it);
  if (op != CompletionOp::Read || !classify) return;
  auto ti = classify(tag);
  if (!ti) return;
  auto gi = groups_.find(ti->group);
  if (gi == groups_.end()) return;
  Group& g = gi->second;
  if (ti->seq) {
    groups_.erase(gi);  // the block's read is over
    return;
  }
  if (g.data_out > 0) --g.data_out;
  if (ok) {
    g.failed.erase(a);
  } else {
    ++g.failed[a];
  }
}

void SimWrAudit::on_release(const std::byte* addr, std::size_t len) {
  const auto a = reinterpret_cast<std::uintptr_t>(addr);
  for (const auto& o : out_)
    if (overlaps(a, len, o.addr, o.len)) {
      flag(kReleaseOutstanding, "buffer released while a WR on it is outstanding (tag " + std::to_string(o.tag) + ")");
      return;
    }
}

// ---- SimFabric ----

Expected<DeviceCaps> SimFabric::probe() {
  return DeviceCaps{"sim", 128, true};
}

Expected<PdId> SimFabric::alloc_pd() {
  const PdId id{next_pd_++};
  pds_.push_back(id);
  return id;
}

Status SimFabric::free_pd(PdId pd) {
  auto it = std::find(pds_.begin(), pds_.end(), pd);
  if (pd.v == 0 || it == pds_.end()) return Error{ErrorCode::InvalidArgument, "free_pd: unknown or default PD"};
  for (const auto& [k, p] : region_pd_) {
    if (p == pd) return Error{ErrorCode::Busy, "free_pd: PD has registered regions"};
  }
  for (const auto& e : endpoints_) {
    if (!e->released() && e->pd() == pd) return Error{ErrorCode::Busy, "free_pd: PD has endpoints"};
  }
  pds_.erase(it);
  return {};
}

Expected<MemRegion> SimFabric::reg(std::span<std::byte> buf, Access access, PdId pd) {
  if (buf.empty()) return Error{ErrorCode::InvalidArgument, "reg: empty buffer"};
  if (pd.v != 0 && std::find(pds_.begin(), pds_.end(), pd) == pds_.end()) {
    return Error{ErrorCode::InvalidArgument, "reg: unknown PdId"};
  }
  const std::uint32_t key = next_key_++;
  MemRegion r{buf.data(), buf.size(), key, key, access};
  regions_[key] = r;
  region_pd_[key] = pd;
  return r;
}

PdId SimFabric::region_pd(std::uint32_t key) const {
  auto it = region_pd_.find(key);
  return it == region_pd_.end() ? PdId{} : it->second;
}

Status SimFabric::release(Endpoint* ep) {
  for (auto& e : endpoints_) {
    if (static_cast<Endpoint*>(e.get()) != ep || e->released()) continue;
    if (!e->drained()) return Error{ErrorCode::Busy, "release: endpoint has outstanding work"};
    e->abort();  // the peer end goes to ERR too
    e->mark_released();
    sweep_released();
    return {};
  }
  return Error{ErrorCode::NotFound, "release: unknown endpoint"};
}

std::size_t SimFabric::endpoint_count() const {
  return static_cast<std::size_t>(
      std::count_if(endpoints_.begin(), endpoints_.end(), [](const auto& e) { return !e->released(); }));
}

Status SimFabric::dereg(const MemRegion& region) {
  auto it = regions_.find(region.lkey);
  if (it == regions_.end()) return Error{ErrorCode::NotFound, "dereg: unknown region"};
  if (it->second.addr != region.addr || it->second.len != region.len || it->second.rkey != region.rkey) {
    return Error{ErrorCode::InvalidArgument, "dereg: region does not match registration"};
  }
  if (pins_[region.lkey] > 0) return Error{ErrorCode::Busy, "dereg: region has posted work"};
  regions_.erase(it);
  region_pd_.erase(region.lkey);
  return {};
}

const MemRegion* SimFabric::find_region(std::uint32_t key) const {
  auto it = regions_.find(key);
  return it == regions_.end() ? nullptr : &it->second;
}

void SimFabric::sweep_released() {
  std::erase_if(endpoints_, [](const auto& e) { return e->released() && e->pending_events() == 0; });
}

SimEndpoint* SimFabric::make_endpoint(PdId pd, EpClass cls) {
  sweep_released();
  endpoints_.push_back(std::make_unique<SimEndpoint>(*this, net_.next_endpoint_id(), pd, cls));
  return endpoints_.back().get();
}

bool SimFabric::known_pd(PdId pd) const {
  return pd.v == 0 || std::find(pds_.begin(), pds_.end(), pd) != pds_.end();
}

// Mirrors the verbs rules that do not change the sim's behaviour for existing callers:
// max_pending_accepts must be > 0 and, without an AdmitFn, accept_pd must exist. (The sim's
// accept completes inside connect(), so at most zero endpoints are ever mid-handshake.)
Status SimFabric::listen(AcceptFn on_accept, const ListenParams& params) {
  if (params.max_pending_accepts == 0) return Error{ErrorCode::InvalidArgument, "listen: max_pending_accepts is 0"};
  if (!params.admit && !params.allow_unauthenticated_for_test) {
    return Error{ErrorCode::InvalidArgument, "listen: AdmitFn required (or allow_unauthenticated_for_test)"};
  }
  if (!params.admit && !known_pd(params.accept_pd)) {
    return Error{ErrorCode::InvalidArgument, "listen: unknown accept_pd"};
  }
  Listener* l = find_listener(params.addr);  // listening again on the same address replaces it, as before
  if (l == nullptr || !(l->addr.host == params.addr.host && l->addr.port == params.addr.port)) {
    listeners_.emplace_back();
    l = &listeners_.back();
  }
  l->addr = params.addr;
  l->on_accept = std::move(on_accept);
  l->admit = params.admit;
  l->accept_pd = params.accept_pd;
  l->accept_class = params.accept_class;
  l->down = false;
  return {};
}

// Exact address first; a caller that gives a host must match one exactly (as verbs: a connect to an address nobody
// listens on is refused). Without a host: the first listener (any port 0), or the only listener.
SimFabric::Listener* SimFabric::find_listener(const RailAddr& a) {
  for (auto& l : listeners_)
    if (l.addr.host == a.host && l.addr.port == a.port) return &l;
  if (listeners_.empty()) return nullptr;
  if (!a.host.empty()) return any_addr_ && listeners_.size() == 1 ? &listeners_.front() : nullptr;
  if (a.port == 0 || listeners_.size() == 1) return &listeners_.front();
  return nullptr;
}

FabricHealth SimFabric::health() {
  FabricHealth h;
  h.port_state = port_state_;
  h.fatal_recent = fatal_;
  for (const auto& l : listeners_) h.listener_ok.push_back(!l.down);
  return h;
}

bool SimFabric::fail_rail(const RailAddr& addr) {
  Listener* l = nullptr;
  for (auto& x : listeners_)
    if (x.addr.host == addr.host && x.addr.port == addr.port) l = &x;
  if (l == nullptr) return false;
  l->down = true;
  for (auto& ep : endpoints_)
    if (ep->on_rail(addr)) ep->enter_error();
  net_.trace(0x52414c46 /* RALF */, id_, addr.port, 0);
  return true;
}

bool SimFabric::restore_rail(const RailAddr& addr) {
  for (auto& x : listeners_)
    if (x.addr.host == addr.host && x.addr.port == addr.port) {
      x.down = false;
      return true;
    }
  return false;
}

void SimFabric::abort_endpoints_to(NodeId peer) {
  for (auto& ep : endpoints_)
    if (ep->peer_node() == peer) ep->enter_error();
}

NodeId SimEndpoint::peer_node() const { return peer_ != nullptr ? peer_->owner().id() : ~NodeId{0}; }

Expected<Endpoint*> SimFabric::connect(const Peer& peer, const ConnParams& params) {
  if (const char* call = local_call_.load(std::memory_order_acquire)) {  // Fault hook: the local device refuses
    local_failures_.fetch_add(1, std::memory_order_relaxed);
    last_local_failure() = LocalFailure{call, local_errno_.load(std::memory_order_relaxed), "sim", -1};
    return Error{ErrorCode::ResourceExhausted, call};
  }
  if (connect_delay_ > Nanos{0}) {  // test hook: a slow handshake; virtual time passes, the network runs meanwhile
    bool due = false;
    net_.schedule(connect_delay_, [&due] { due = true; });
    while (!due && net_.step()) {
    }
  }
  SimFabric* remote = net_.node(peer.node);
  Listener* lst = remote != nullptr ? remote->find_listener(peer.addr) : nullptr;
  if (lst == nullptr || !lst->on_accept || lst->down) {
    // As on verbs (the CM rejects a connect with no listener): a node that is not there is
    // LinkDown, not NotFound.
    return Error{ErrorCode::LinkDown, "connect: no listener"};
  }
  if (!net_.link_up(id_, peer.node)) return Error{ErrorCode::LinkDown, "connect: link down"};
  if (params.ticket_len > kMaxTicketBytes) return Error{ErrorCode::InvalidArgument, "connect: ticket too long"};
  const std::span<const std::byte> ticket(params.ticket.data(), params.ticket_len);
  Admission adm{lst->accept_class, lst->accept_pd};
  if (lst->admit) {
    auto r = lst->admit(ticket);
    // Through the verbs reject table, so a sim refusal reports what a CM reject would.
    if (!r) return protocol::reject_error(protocol::admit_reject_code(r.error().code));
    adm = *r;
    // As on verbs: an admission naming a PD the passive side does not have is a refusal.
    if (!remote->known_pd(adm.pd)) return protocol::reject_error(protocol::kRejectAdmit);
  }
  if (!known_pd(params.pd)) return Error{ErrorCode::InvalidArgument, "connect: unknown PdId"};
  SimEndpoint* local_ep = make_endpoint(params.pd, params.cls);
  SimEndpoint* remote_ep = remote->make_endpoint(adm.pd, adm.cls);
  local_ep->connect_to(remote_ep);
  remote_ep->connect_to(local_ep);
  remote_ep->set_private_data(ticket);
  net_.trace(0x434f4e4e /* CONN */, id_, peer.node, local_ep->id());
  remote_ep->set_rail(lst->addr);
  AcceptFn accept = lst->on_accept;  // the callback may listen again
  accept(remote_ep);
  return local_ep;
}

std::size_t SimFabric::poll(std::span<Completion> out, PollBudget) {
  sweep_released();
  std::size_t n = 0;
  while (n < out.size() && !cq_.empty()) {
    out[n] = std::move(cq_.front());
    if (audit_ && !out[n].is_recv) audit_->on_delivered(this, out[n].endpoint, out[n].op, out[n].tag, out[n].status.has_value());
    ++n;
    cq_.pop_front();
  }
  if (n < out.size() && cq_.empty() && overflowed_ && !overflow_reported_) {
    overflow_reported_ = true;
    Completion c;
    c.op = CompletionOp::CqError;
    c.status = Error{ErrorCode::ResourceExhausted, "completion queue overflow"};
    out[n++] = std::move(c);
  }
  return n;
}

void SimFabric::push_completion(Completion c) {
  if (overflowed_) return;  // already in the overflow error state; later completions are lost
  if (cq_.size() >= cq_capacity_) {
    overflowed_ = true;
    net_.trace(0x4f564552 /* OVER */, id_, cq_.size(), 0);
    for (auto& ep : endpoints_) ep->enter_error();
    return;
  }
  net_.trace(0x434f4d50 /* COMP */, c.endpoint, c.tag,
             (static_cast<std::uint64_t>(c.op) << 56) |
                 (static_cast<std::uint64_t>(c.status.has_value() ? 0 : 1 + static_cast<int>(c.status.error().code)) << 32) |
                 c.bytes);
  cq_.push_back(std::move(c));
}

// ---- SimEndpoint ----

Status SimEndpoint::can_post() const {
  if (peer_ == nullptr) return Error{ErrorCode::NotFound, "post: endpoint not connected"};
  if (aborted_) return Error{ErrorCode::Aborted, "post: endpoint in error state"};
  return {};
}

void SimEndpoint::retire(const Pending& p, Status status, std::uint32_t bytes) {
  if (p.pinned) owner_.unpin(p.lkey);
  Completion c;
  c.endpoint = id_;
  c.tag = p.tag;
  c.op = p.op;
  c.status = status;
  c.bytes = bytes;
  if (owner_.network().roll_duplicate()) owner_.push_completion(c);
  owner_.push_completion(std::move(c));
}

void SimEndpoint::complete(std::uint64_t seq, Status status, std::uint32_t bytes) {
  auto it = pending_.find(seq);
  if (it == pending_.end()) return;
  const Pending p = it->second;
  pending_.erase(it);
  retire(p, status, bytes);
}

void SimEndpoint::flush_all() {
  auto work = std::move(pending_);
  pending_.clear();
  for (const auto& [seq, p] : work) retire(p, Error{ErrorCode::Aborted, "endpoint flushed"}, 0);
}

void SimEndpoint::abort() {
  if (!aborted_ && !pending_.empty()) owner_.note_abort_with_work();
  enter_error();
}

void SimEndpoint::enter_error() {
  if (aborted_) return;
  aborted_ = true;
  if (peer_ != nullptr) peer_->aborted_ = true;
  owner_.network().trace(0x45525220 /* ERR */, id_, peer_ != nullptr ? peer_->id() : 0, 0);
  flush_all();
  if (peer_ != nullptr) peer_->flush_all();
}

void SimEndpoint::submit(CompletionOp op, WrTag tag, const LocalRef* pin,
                         std::function<void(std::uint64_t)> exec) {
  const std::uint64_t seq = next_seq_++;
  pending_.emplace(seq, Pending{op, tag, pin != nullptr, pin != nullptr ? pin->lkey : 0});
  if (pin != nullptr && owner_.audit()) owner_.audit()->on_post(&owner_, id_, op, tag, *pin);
  if (pin != nullptr) owner_.pin(pin->lkey);
  SimNetwork& net = owner_.network();
  const auto fate = net.roll_fate();
  Nanos due = net.now() + fate.delay;
  if (peer_ != nullptr && !fate.dropped) due += net.link_delay(owner_.id(), peer_->owner().id());  // a slow link
  if (net.faults().ordered) {  // RC: per-endpoint delivery never overtakes an earlier post
    due = std::max(due, last_due_);
    last_due_ = due;
  }
  ++pending_events_;
  net.schedule(due - net.now(), [this, seq, fate, exec = std::move(exec)] {
    struct Done {
      std::uint32_t& n;
      ~Done() { --n; }
    } done{pending_events_};
    if (pending_.find(seq) == pending_.end()) return;  // already flushed by an error
    // Order matters: error state and link state beat the drop fate, so work that was
    // in flight when the endpoint failed completes as Aborted, not as a lost request.
    if (aborted_) return complete(seq, Error{ErrorCode::Aborted, "endpoint flushed"}, 0);
    if (!owner_.network().link_up(owner_.id(), peer_->owner().id())) {
      return complete(seq, Error{ErrorCode::LinkDown, "link down"}, 0);
    }
    if (fate.dropped) {
      complete(seq, Error{ErrorCode::Timeout, "request lost"}, 0);
      enter_error();  // RC: a lost request breaks the connection
      return;
    }
    exec(seq);
  });
}

Status SimEndpoint::post_send(Frame frame, WrTag tag) {
  if (auto s = can_post(); !s) return s;
  if (frame.bytes.size() > kMaxFrameBytes) {
    return Error{ErrorCode::InvalidArgument, "post_send: frame exceeds kMaxFrameBytes"};
  }
  submit(CompletionOp::Send, tag, nullptr, [this, frame = std::move(frame)](std::uint64_t seq) mutable {
    auto deliver = [this, seq, frame = std::move(frame)]() mutable {
      if (pending_.find(seq) == pending_.end()) return;  // flushed while deferred
      const auto len = static_cast<std::uint32_t>(frame.bytes.size());
      Completion r;
      r.endpoint = peer_->id();
      r.is_recv = true;
      r.op = CompletionOp::Recv;
      r.bytes = len;
      r.frame = std::move(frame);
      peer_->owner().push_completion(std::move(r));
      complete(seq, {}, len);
    };
    // RC: the receiver sees a SEND only after the bytes of every earlier WRITE are placed.
    if (writes_unplaced_ > 0 || !deferred_sends_.empty()) deferred_sends_.push_back(std::move(deliver));
    else deliver();
  });
  return {};
}

void SimEndpoint::slice_placed() {
  if (--writes_unplaced_ != 0) return;
  auto work = std::move(deferred_sends_);
  deferred_sends_.clear();
  for (auto& d : work) d();
}

Status SimEndpoint::check_local(CompletionOp op, const LocalRef& local) const {
  const MemRegion* r = owner_.find_region(local.lkey);
  if (r == nullptr || !within(*r, reinterpret_cast<std::uint64_t>(local.addr), local.len)) {
    return Error{ErrorCode::InvalidArgument, "post: local ref outside region"};
  }
  if (!(owner_.region_pd(local.lkey) == pd_)) {
    return Error{ErrorCode::InvalidArgument, "post: local region belongs to a different protection domain"};
  }
  if (op == CompletionOp::Read && !has(r->access, Access::LocalWrite)) {
    return Error{ErrorCode::AccessDenied, "post_read: local region lacks LocalWrite"};
  }
  return {};
}

Status SimEndpoint::post_read(RemoteRef remote, LocalRef local, WrTag tag) {
  if (auto s = can_post(); !s) return s;
  if (auto s = check_local(CompletionOp::Read, local); !s) return s;
  submit(CompletionOp::Read, tag, &local, [this, remote, local](std::uint64_t seq) { run_read(seq, remote, local); });
  return {};
}

void SimEndpoint::run_read(std::uint64_t seq, RemoteRef remote, LocalRef local) {
  const MemRegion* r = peer_->owner().find_region(remote.rkey);
  if (r == nullptr || !(peer_->owner().region_pd(remote.rkey) == peer_->pd()) ||
      !has(r->access, Access::RemoteRead) || remote.len != local.len ||
      !within(*r, remote.addr, remote.len)) {
    return complete(seq, Error{ErrorCode::AccessDenied, "read: remote access error"}, 0);
  }
  if (remote.len <= owner_.network().options().slice_size) {
    std::memmove(local.addr, reinterpret_cast<const std::byte*>(remote.addr), remote.len);
    return complete(seq, {}, remote.len);
  }
  place_slices(seq, /*is_write=*/false, remote, local.addr, {}, remote.len);
}

// Sliced placement (SimOptions): each slice is its own event at a random delay, so slices
// land out of order and interleave with other ops on the same bytes. A READ completes
// when every slice has landed; a WRITE completes after the last slice (RoCE) or after a
// random number of slices (iWARP early CQE), the rest landing later. A WRITE's source is
// snapshotted when it starts, because an early CQE releases the caller's buffer.
void SimEndpoint::place_slices(std::uint64_t seq, bool is_write, RemoteRef remote, std::byte* local,
                               std::vector<std::byte> snapshot, std::uint32_t len) {
  SimNetwork& net = owner_.network();
  const SimOptions& opt = net.options();
  const std::uint32_t n = (len + opt.slice_size - 1) / opt.slice_size;
  struct Job {
    std::uint64_t seq;
    bool is_write;
    RemoteRef remote;
    std::byte* local;  // READ landing buffer
    std::vector<std::byte> src;  // WRITE source snapshot
    std::uint32_t len, slice, n, target, placed = 0;
    bool finished = false;
  };
  auto job = std::make_shared<Job>(Job{seq, is_write, remote, local, std::move(snapshot), len, opt.slice_size, n,
                                       n, 0, false});
  if (is_write && opt.iwarp_early_write_cqe) job->target = 1 + static_cast<std::uint32_t>(net.roll_below(n));
  if (is_write) writes_unplaced_ += n;
  for (std::uint32_t i = 0; i < n; ++i) {
    const Nanos delay{static_cast<std::int64_t>(net.roll_below(static_cast<std::uint64_t>(opt.slice_window.count()) + 1))};
    ++pending_events_;
    net.schedule(delay, [this, job, i] {
      struct Done {
        std::uint32_t& c;
        SimEndpoint* ep;
        bool write;
        ~Done() {
          --c;
          if (write) ep->slice_placed();  // may deliver SENDs that waited for this WRITE
        }
      } done{pending_events_, this, job->is_write};
      if (aborted_ || job->finished) return;  // flushed already, or the READ failed
      const std::uint64_t off = static_cast<std::uint64_t>(i) * job->slice;
      const std::uint32_t l = static_cast<std::uint32_t>(std::min<std::uint64_t>(job->slice, job->len - off));
      const MemRegion* r = peer_->owner().find_region(job->remote.rkey);
      const bool ok = r != nullptr && within(*r, job->remote.addr + off, l);
      if (job->is_write) {
        if (ok) std::memcpy(reinterpret_cast<std::byte*>(job->remote.addr + off), job->src.data() + off, l);
      } else if (ok) {
        std::memcpy(job->local + off, reinterpret_cast<const std::byte*>(job->remote.addr + off), l);
      } else {
        job->finished = true;  // region went away mid-READ
        return complete(job->seq, Error{ErrorCode::AccessDenied, "read: remote region gone"}, 0);
      }
      owner_.network().trace(0x534c4345 /* SLCE */, id_, job->seq, (off << 32) | l);
      if (++job->placed == job->target) complete(job->seq, {}, job->len);
    });
  }
}

Status SimEndpoint::post_write(LocalRef local, RemoteRef remote, WrTag tag) {
  if (auto s = can_post(); !s) return s;
  if (auto s = check_local(CompletionOp::Write, local); !s) return s;
  submit(CompletionOp::Write, tag, &local, [this, local, remote](std::uint64_t seq) { run_write(seq, local, remote); });
  return {};
}

void SimEndpoint::run_write(std::uint64_t seq, LocalRef local, RemoteRef remote) {
  const MemRegion* r = peer_->owner().find_region(remote.rkey);
  if (r == nullptr || !(peer_->owner().region_pd(remote.rkey) == peer_->pd()) ||
      !has(r->access, Access::RemoteWrite) || remote.len != local.len ||
      !within(*r, remote.addr, remote.len)) {
    return complete(seq, Error{ErrorCode::AccessDenied, "write: remote access error"}, 0);
  }
  if (local.len <= owner_.network().options().slice_size) {
    std::memmove(reinterpret_cast<std::byte*>(remote.addr), local.addr, local.len);
    return complete(seq, {}, local.len);
  }
  place_slices(seq, /*is_write=*/true, remote, nullptr, std::vector<std::byte>(local.addr, local.addr + local.len),
               local.len);
}

}  // namespace miracache::fabric
