// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <vector>

#include "fabric/fabric.h"
#include "store/put.h"
#include "store/store.h"
#include "util/clock.h"

// Typed in-process "server port" between ClientCore and a memory node (A1.6 L3). The control
// plane goes through these calls (the store's typed request structs); the DATA always moves
// over the fabric (RDMA READ/WRITE). The wire adapter (store S7) will implement this over
// frames; LoopbackPort implements it by calling core/store directly. The port owns the
// principal and session identity: whatever the request structs carry in those fields is
// overwritten by the port.
namespace miracache {

struct ClientMetrics;

struct ServerInfo {
  fabric::NodeId node = 0;
  std::vector<fabric::MemRegion> segs;  // fetch MRs, index = LookupEntry::seg_id
  fabric::MemRegion array;              // state_gen array MR (8 B per gen_slot)
};

class ServerPort {
 public:
  virtual ~ServerPort() = default;
  virtual Expected<ServerInfo> hello() = 0;
  // ClientCore calls this after connecting an endpoint of class `cls` (Fetch or Ingest).
  virtual void connected(fabric::EpClass cls, fabric::Endpoint* client_side) = 0;
  virtual store::LookupAck lookup(const store::LookupReq& q) = 0;
  virtual Status renew(store::LeaseId lease) = 0;
  // RL3: renewals the node confirmed (RENEW_ACK OK) since the last call, each with a time its lease surely outlives: the
  // RENEW's send time + the ttl the node granted (the node renewed after the send). Default: none reported.
  struct Renewed {
    store::LeaseId lease = 0;
    Nanos until{0};
  };
  virtual void take_renewed(std::vector<Renewed>& out) { out.clear(); }
  virtual Status release(store::LeaseId lease) = 0;
  virtual store::PutBeginAck put_begin(const store::PutBeginReq& q) = 0;
  // `done` may run inline or later; it runs on the caller's pump context.
  virtual void put_commit(const store::PutCommitReq& q, store::PutDoneFn done) = 0;
  virtual void put_cancel(store::PutId id, store::PutDoneFn done) = 0;
  // Wire port only. The segment table can grow after hello(); ClientCore calls this from
  // pump() and takes the new info when it returns true.
  virtual bool refresh_info(ServerInfo&) { return false; }
  // Wire port: absolute (Clock) deadline of the job whose calls follow; control RPCs wait at
  // most min(rpc_timeout, deadline - now) (spec 3, every op has a deadline). Nanos::max() =
  // none. ClientCore brackets lookup / put_begin / renew with this.
  virtual void set_op_deadline(Nanos) {}
  // Presence check: like lookup() but no lease is taken (so nothing to release).
  virtual store::LookupAck lookup_presence(const store::LookupReq& q) {
    store::LookupAck a = lookup(q);
    if (a.lease != 0) (void)release(a.lease);
    a.lease = 0;
    return a;
  }
  // ---- session lifecycle (wire port; the defaults describe an always-up in-process port) ----
  // False while the session is Down or Connecting: every op fails fast (no RPC is attempted).
  virtual bool session_up() const { return true; }
  // Grows by one on every Up -> Down transition. ClientCore compares it with the value it last
  // saw: a change means "fail every in-flight job now and drop leases / commit / endpoint state".
  virtual std::uint64_t session_down_count() const { return 0; }
  // Review w4 V08: the node left the membership (GOAWAY reason Epoch): stores the session loss cuts short are skips.
  virtual bool removed_from_membership() const { return false; }
  // The current client-side endpoint of class `cls` (Fetch / Ingest), valid while session_up();
  // ClientCore re-binds to these after a reconnect. nullptr = the port has no replacement.
  virtual fabric::Endpoint* endpoint(fabric::EpClass) { return nullptr; }
  // Largest key count of one LOOKUP; ClientCore splits larger batches into several.
  virtual std::size_t max_lookup_keys() const { return static_cast<std::size_t>(-1); }
  // Lets the port count its own events (reconnects, control-endpoint errors) in the client registry.
  // nullptr unbinds (N01: ClientCore unbinds in its destructor, so no holder keeps a dead pointer).
  virtual void bind_metrics(ClientMetrics*) {}
  // N02 (watchdog): the live endpoint of `cls` lost a completion. The port marks it dead, so the
  // session goes Down: every endpoint is aborted, drained and then reaped.
  virtual void endpoint_wedged(fabric::EpClass) {}
  // N02/Q01: true once the session end that made the down count `down` has happened and every endpoint
  // it aborted has been released by the fabric (drained, QP destroyed). Per session end: an endpoint that
  // never drains holds back only its own. Q04: false for an in-process port. It has no session and never
  // aborts the endpoint an abandoned op sits on (endpoint_wedged is a no-op), so that op may still DMA
  // into its span: the span stays quarantined (a leak in tests only, never a reuse under DMA).
  virtual bool session_reaped(std::uint64_t /*down*/) const { return false; }
  // RL3: ClientCore queued a fetch slice for re-issue after its own failed or flushed completion (telemetry only).
  virtual void slice_reissued() {}
  // R16: a READ or WRITE found its endpoint's send queue full (sq_depth) while it had work outstanding, so ClientCore
  // treats it as backpressure (it waits) instead of failing the key (telemetry only).
  virtual void send_queue_full(fabric::EpClass) {}
  // INVALIDATE(key, gen) (AEAD miss, spec 8.3). Best effort.
  virtual Status invalidate(const store::ScopeId&, const store::KeyHash&, std::uint64_t) {
    return Error{ErrorCode::Unsupported, "port: invalidate not supported"};
  }
};

}  // namespace miracache
