// SPDX-License-Identifier: Apache-2.0
// Backend-neutral fabric interface (spec 3.9). Subset implemented for M0:
// probe, reg/dereg, connect/listen, poll, and the endpoint verbs.
// Connect/accept carry a ticket in private_data; deadlines are a relative timeout.
#pragma once

#include <functional>
#include <span>
#include <string>

#include "fabric/types.h"

namespace miracache::fabric {

class Endpoint {
 public:
  virtual ~Endpoint() = default;
  virtual EndpointId id() const = 0;
  virtual Status post_send(Frame frame, WrTag tag) = 0;
  virtual Status post_read(RemoteRef remote, LocalRef local, WrTag tag) = 0;
  virtual Status post_write(LocalRef local, RemoteRef remote, WrTag tag) = 0;
  // Moves the endpoint to ERR: new posts fail, in-flight work flushes with Aborted.
  virtual void abort() = 0;
  // True when no posted work request is still outstanding; safe to release regions.
  virtual bool drained() const = 0;
  virtual EpState state() const = 0;
  // Negotiated IRD/ORD (spec 3.2); only meaningful once Ready.
  virtual ReadDepth read_depth() const = 0;
  // Connect private_data (the ticket) as presented by the active side; empty on the
  // active side and when none was sent.
  virtual std::span<const std::byte> peer_private_data() const = 0;
  // The remote side's "ip:port" for log lines (review s9 K10); empty when the backend cannot say (the default).
  virtual std::string peer_addr() const { return {}; }
};

using AcceptFn = std::function<void(Endpoint*)>;
// What the passive side decides for one connection: the buffer-layout class and the PD of
// the accepted endpoint, derived by the caller from the ticket.
struct Admission {
  EpClass cls = EpClass::Control;
  PdId pd;
};
// Called on the passive side before a connection is accepted, with the active side's
// private_data. Returning an error rejects the connection before any QP is created.
using AdmitFn = std::function<Expected<Admission>(std::span<const std::byte> private_data)>;

struct ListenParams {
  RailAddr addr;                        // verbs_cm only; the sim routes by NodeId
  AdmitFn admit;                        // required unless allow_unauthenticated_for_test
  // Without admit (tests only): every connection is accepted with this class and PD.
  bool allow_unauthenticated_for_test = false;
  EpClass accept_class = EpClass::Control;
  PdId accept_pd;
  std::uint32_t max_pending_accepts = 64;  // endpoints in the accept handshake at once
  Nanos accept_timeout = std::chrono::seconds(5);  // CONNECT_REQUEST to ESTABLISHED
};

class Fabric {
 public:
  virtual ~Fabric() = default;
  virtual Expected<DeviceCaps> probe() = 0;
  // Protection domains (spec 3.3). free_pd is refused with Busy while a region or an
  // endpoint still lives in it; the default PdId{} cannot be freed.
  virtual Expected<PdId> alloc_pd() = 0;
  virtual Status free_pd(PdId pd) = 0;
  // The region belongs to `pd`; only endpoints created in the same PD can use it.
  virtual Expected<MemRegion> reg(std::span<std::byte> buf, Access access, PdId pd = {}) = 0;
  // Refused with Busy while a work request references the region as a local buffer.
  virtual Status dereg(const MemRegion& region) = 0;
  // The fabric owns the returned endpoint; it lives until release() or the fabric dies.
  virtual Expected<Endpoint*> connect(const Peer& peer, const ConnParams& params = {}) = 0;
  // Frees an endpoint and everything it holds (QP, buffers, CM id). Busy unless the
  // endpoint is drained; a Ready endpoint is aborted first. The pointer is dead afterwards.
  // Endpoints that never reached the caller (failed connect or accept) are freed by the
  // fabric itself; every endpoint that was returned or passed to AcceptFn needs release().
  virtual Status release(Endpoint* ep) = 0;
  virtual Status listen(AcceptFn on_accept, const ListenParams& params = {}) = 0;
  // Drains up to out.size() completions; returns the count. Only spins on an empty CQ
  // for `budget.busy`; never sleeps. Also services connection events.
  virtual std::size_t poll(std::span<Completion> out, PollBudget budget = {}) = 0;
  // A pollable fd for blocking waits (-1 if the backend has none). Calling it arms
  // completion notification: poll() once more afterwards (closes the arm/poll race),
  // then wait for the fd to become readable, then poll() again.
  virtual int wait_fd() = 0;
  // RL1: port state, fatal events and listener liveness of the device behind this fabric (see FabricHealth).
  // Default: a healthy device with no listener information.
  virtual FabricHealth health() { return {}; }
};

// Q6: the last LOCAL device resource failure on this thread (a CQ, completion channel, PD, MR or QP the local device
// would not create: e.g. a soft-iWARP device at its CQ limit). The Error a fabric returns carries only a static
// context, so a caller that wants to report the verbs call, errno and device clears this before the call and reads it
// after a failure. `call` null = no local resource failure since the last clear. `rail` is set by the caller that knows
// which node rail the failing fabric serves (-1 = unknown). `provider_call` (review s10 Q07): false when the refusal is
// the fabric's own budget (cq_depth), not a verbs/provider call: there is no errno to report.
struct LocalFailure {
  const char* call = nullptr;
  int os_errno = 0;
  std::string device;
  int rail = -1;
  bool provider_call = true;
};
inline LocalFailure& last_local_failure() noexcept {
  thread_local LocalFailure f;
  return f;
}
inline void clear_local_failure() noexcept { last_local_failure() = LocalFailure{}; }

}  // namespace miracache::fabric
