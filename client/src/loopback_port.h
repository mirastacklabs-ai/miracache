// SPDX-License-Identifier: Apache-2.0
// In-process loopback: a real core/store stack on a server-side SimFabric node
// (LoopbackServer) and a ServerPort that calls it directly (LoopbackPort). Control calls are
// direct C++ calls; data moves over the fabric, so SimOptions slicing, torn reads and early
// iWARP CQEs apply. The wire adapter later replaces LoopbackPort with frames. Single-threaded: callers
// serialise (the facade does).
#pragma once

#include <functional>
#include <memory>
#include <vector>

#include "fabric/sim/sim_fabric.h"
#include "src/server_port.h"
#include "store/arena.h"
#include "store/mr_manager.h"
#include "store/put.h"
#include "store/slab.h"
#include "store/store.h"
#include "util/executor.h"
#include "util/random.h"

namespace miracache {

class LoopbackServer {
 public:
  // `fab` is the server's node (listens for Fetch/Ingest connections; the class is read
  // from ticket byte 0: 1 = fetch, 2 = ingest). MRs are fully registered before returning.
  static Expected<std::unique_ptr<LoopbackServer>> create(fabric::SimFabric& fab, const Clock& clock, Random& rng,
                                                          const store::StoreConfig& cfg);

  store::Store& store() { return *store_; }
  store::PutPath& puts() { return *puts_; }
  store::Arena& arena() { return *arena_; }
  store::SlabAllocator& slab() { return *slab_; }
  store::MrManager& mrs() { return *mrs_; }
  fabric::SimFabric& fabric() { return fab_; }
  void tick() {
    store_->tick();
    puts_->tick();
  }
  // Store-side invariants (store, slab, put path, MRs). Ok or Corrupt.
  Status check_invariants() const;
  const std::vector<std::pair<fabric::EpClass, fabric::Endpoint*>>& accepted() const { return accepted_; }

 private:
  explicit LoopbackServer(fabric::SimFabric& fab) : fab_(fab) {}
  fabric::SimFabric& fab_;
  std::unique_ptr<store::Arena> arena_;
  std::unique_ptr<store::SlabAllocator> slab_;
  std::unique_ptr<store::Store> store_;
  std::unique_ptr<store::MrManager> mrs_;
  InlineExecutor exec_;
  std::unique_ptr<store::PutPath> puts_;
  fabric::PdId ingest_pd_;
  std::vector<std::pair<fabric::EpClass, fabric::Endpoint*>> accepted_;
};

class LoopbackPort final : public ServerPort {
 public:
  // `settle` runs before every PUT_COMMIT. It stands in for the ordering a real QP gives (the
  // COMMIT SEND is delivered after the WRITE bytes are placed, whatever the WRITE CQE said);
  // tests pass `[&]{ net.run_until_idle(); }`. Empty = no barrier.
  LoopbackPort(LoopbackServer& server, store::PrincipalId principal, store::SessionId session,
               std::function<void()> settle = {})
      : srv_(server), principal_(principal), session_(session), settle_(std::move(settle)) {}

  Expected<ServerInfo> hello() override;
  void connected(fabric::EpClass cls, fabric::Endpoint* client_side) override;
  store::LookupAck lookup(const store::LookupReq& q) override;
  Status renew(store::LeaseId lease) override;
  Status release(store::LeaseId lease) override;
  store::PutBeginAck put_begin(const store::PutBeginReq& q) override;
  void put_commit(const store::PutCommitReq& q, store::PutDoneFn done) override;
  void put_cancel(store::PutId id, store::PutDoneFn done) override;

 private:
  LoopbackServer& srv_;
  store::PrincipalId principal_;
  store::SessionId session_;
  std::function<void()> settle_;
  fabric::EndpointId ingest_ep_ = 0;
};

}  // namespace miracache
