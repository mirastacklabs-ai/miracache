// SPDX-License-Identifier: Apache-2.0
#include "src/loopback_port.h"

namespace miracache {

Expected<std::unique_ptr<LoopbackServer>> LoopbackServer::create(fabric::SimFabric& fab, const Clock& clock,
                                                                 Random& rng, const store::StoreConfig& cfg) {
  std::unique_ptr<LoopbackServer> s(new LoopbackServer(fab));
  auto a = store::Arena::open(cfg);
  if (!a) return a.error();
  s->arena_ = std::move(*a);
  s->slab_ = std::make_unique<store::SlabAllocator>(*s->arena_);
  s->store_ = std::make_unique<store::Store>(*s->arena_, *s->slab_, clock, rng);
  auto pd = fab.alloc_pd();
  if (!pd) return pd.error();
  s->ingest_pd_ = *pd;
  s->mrs_ = std::make_unique<store::MrManager>(fab, *s->arena_, fabric::PdId{}, s->ingest_pd_);
  LoopbackServer* raw = s.get();
  s->store_->set_readable([raw](std::uint32_t seg) { return raw->mrs_->readable(seg); });
  s->puts_ = std::make_unique<store::PutPath>(*s->store_, *s->slab_, *s->mrs_, *s->arena_, clock, s->exec_);
  for (;;) {
    auto step = s->mrs_->step_registration();
    if (!step) return step.error();
    if (!*step) break;
  }
  fabric::ListenParams lp;
  lp.admit = [raw](std::span<const std::byte> priv) -> Expected<fabric::Admission> {
    if (priv.size() == 1 && priv[0] == std::byte{1}) return fabric::Admission{fabric::EpClass::Fetch, fabric::PdId{}};
    if (priv.size() == 1 && priv[0] == std::byte{2})
      return fabric::Admission{fabric::EpClass::Ingest, raw->ingest_pd_};
    return Error{ErrorCode::AccessDenied, "loopback: bad connection class"};
  };
  if (auto st = fab.listen(
          [raw](fabric::Endpoint* e) {
            // The class is not visible on Endpoint; the PD tells fetch from ingest apart.
            auto* se = static_cast<fabric::SimEndpoint*>(e);
            raw->accepted_.emplace_back(se->cls(), e);
          },
          lp);
      !st)
    return st.error();
  return s;
}

Status LoopbackServer::check_invariants() const {
  if (auto s = store_->check_invariants(); !s) return s;
  if (auto s = slab_->check_invariants(); !s) return s;
  if (auto s = puts_->check_invariants(); !s) return s;
  return mrs_->check_invariants();
}

Expected<ServerInfo> LoopbackPort::hello() {
  ServerInfo i;
  i.node = srv_.fabric().id();
  for (std::uint32_t s = 0; s < srv_.mrs().registered_segments(); ++s) i.segs.push_back(srv_.mrs().segment_view(s));
  if (!srv_.mrs().array_mr()) return Error{ErrorCode::Unsupported, "loopback: MRs not registered"};
  i.array = *srv_.mrs().array_mr();
  return i;
}

void LoopbackPort::connected(fabric::EpClass cls, fabric::Endpoint*) {
  // The sim accepts inside connect(): the newest accepted endpoint of this class is ours.
  const auto& acc = srv_.accepted();
  for (auto it = acc.rbegin(); it != acc.rend(); ++it)
    if (it->first == cls) {
      if (cls == fabric::EpClass::Ingest) ingest_ep_ = it->second->id();
      return;
    }
}

store::LookupAck LoopbackPort::lookup(const store::LookupReq& q) {
  store::LookupReq r = q;
  r.principal = principal_;
  return srv_.store().lookup(session_, r);
}
Status LoopbackPort::renew(store::LeaseId lease) {
  auto r = srv_.store().renew(session_, lease);
  if (!r) return r.error();
  return {};
}
Status LoopbackPort::release(store::LeaseId lease) { return srv_.store().release(session_, lease); }

store::PutBeginAck LoopbackPort::put_begin(const store::PutBeginReq& q) {
  store::PutBeginReq r = q;
  r.principal = principal_;
  return srv_.puts().put_begin(ingest_ep_, r);
}
void LoopbackPort::put_commit(const store::PutCommitReq& q, store::PutDoneFn done) {
  if (settle_) settle_();
  srv_.puts().put_commit(ingest_ep_, q, std::move(done));
}
void LoopbackPort::put_cancel(store::PutId id, store::PutDoneFn done) {
  srv_.puts().put_cancel(ingest_ep_, id, std::move(done));
}

}  // namespace miracache
