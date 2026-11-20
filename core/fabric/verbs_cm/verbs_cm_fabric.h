// SPDX-License-Identifier: Apache-2.0
// verbs/rdma_cm backend (spec 3). Built only with MIRACACHE_WITH_VERBS=ON.
// One VerbsCmFabric drives one RDMA device (one rail) from one thread; it is not
// thread-safe. Several fabrics may share a device: a process-wide dispatcher per
// ibv_context owns the async event fd and hands events to the owning fabric through a
// queue that the fabric's own poll() applies. A broken completion queue (ibv_poll_cq failure, CQ_ERR async event, failed
// notify arm) is fatal: all endpoints fail, poll() reports one CqError, and the fabric
// cannot recover; destroying it is the only cleanup. RC QPs only, SEND/RECV + RDMA READ/WRITE, connection setup through
// rdma_cm for both RoCE and iWARP. All libibverbs/librdmacm types stay in the .cpp.
#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "fabric/fabric.h"
#include "fabric/verbs_cm/protocol_rules.h"
#include "telemetry/metrics.h"

namespace miracache::fabric {

using NicProtocol = protocol::Protocol;
// ibv_reg_dmabuf_mr cannot be exercised without a real dma-buf fd, so the probe is
// tri-state: the provider has no entry point, has one (rejected our dummy fd for the
// expected reason), or registered a real dma-buf.
enum class DmabufProbe : std::uint8_t { Unsupported, EntryPointPresent, Works };

// Spec 4.2 capability probe result. Plain data so tests and logs can print it.
struct NicCaps {
  std::string device;
  std::string node_type;   // "ibv transport / link layer" as reported by verbs
  NicProtocol protocol = NicProtocol::Unknown;
  std::uint64_t max_mr_size = 0;
  std::uint32_t max_mr = 0;
  std::uint32_t max_qp = 0;
  std::uint32_t max_qp_wr = 0;
  std::uint32_t max_cqe = 0;
  std::uint32_t max_qp_rd_atom = 0;       // inbound READs per QP (IRD)
  std::uint32_t max_qp_init_rd_atom = 0;  // outbound READs per QP (ORD)
  std::uint32_t max_inline_data = 0;      // read back from a trial QP created asking for 256
  std::uint32_t active_mtu = 0;           // bytes, port 1
  std::uint32_t netdev_mtu = 0;           // 0 if unknown
  std::string firmware;
  bool read_sink_needs_remote_write = false;  // iWARP (spec 3.2)
  bool active_sends_first = false;            // iWARP/MPA: the HELLO layer must honour this
  // Memory windows: the flag in device_cap_flags lies on some drivers, so we really
  // call ibv_alloc_mw. Recorded only (v2); nothing depends on it.
  bool mw_flag_advertised = false;
  bool mw_alloc_ok = false;
  int mw_alloc_errno = 0;
  DmabufProbe dmabuf = DmabufProbe::Unsupported;
  int dmabuf_errno = 0;
  bool trial_reg_ok = false;  // a 1 MiB trial registration succeeded
};
std::string to_string(const NicCaps& caps);

struct VerbsOptions {
  std::string device;                    // e.g. "rxe0"; empty = first device
  protocol::Setting protocol = protocol::Setting::Auto;  // fabric.protocol
  // endpoint IDs of this fabric start here. A process with several fabrics (one per device) gives each its
  // own range (index << 48), so an EndpointId is unique across them.
  EndpointId ep_id_base = 0;
  // Test hook: advertise this protocol in connect private_data instead of the real one,
  // to exercise the peer-mismatch refusal. Unknown = advertise the truth.
  protocol::Protocol advertise_protocol_for_test = protocol::Protocol::Unknown;
  // Lifetime: the fabric keeps the pointers below (hold_established_for_test, clock) and reads
  // them from poll()/connect() until it is destroyed; the pointees must outlive the fabric.
  // Test hook: while this flag reads true, a passive endpoint's ESTABLISHED is held back
  // (QP live and receiving, AcceptFn not called) until poll() sees it false. A held endpoint
  // still counts as mid-handshake: ListenParams::accept_timeout applies to it.
  const std::atomic<bool>* hold_established_for_test = nullptr;
  // Test hook: put this protocol tag in the accept private_data instead of the real one, to
  // exercise the active side's ESTABLISHED tag check. Unknown = the truth.
  protocol::Protocol advertise_accept_protocol_for_test = protocol::Protocol::Unknown;
  // Test hook: flush completions of destroyed QPs are discarded without settling their CQE
  // reservation, to exercise the zombie_grace expiry (a provider that never flushes).
  bool drop_zombie_flushes_for_test = false;
  // NIC profile operating point (profiles/nic-profiles.toml; explicit config beats the profile). The
  // defaults are the pre-registry constants, so a caller that sets nothing behaves as before.
  std::uint8_t ack_timeout_exp = kQpAckTimeoutExpMax;  // active side: rdma_set_option ACK_TIMEOUT (RoCE)
  std::uint8_t retry_count = kQpRetryCount;            // rdma_conn_param.retry_count
  std::uint8_t rnr_retry_count = protocol::kRnrRetryCount;
  std::uint32_t inline_bytes = 0;                      // QP max_inline_data requested (0 = none; falls back on EINVAL)
  const Clock* clock = nullptr;          // null = RealClock
  // A destroyed QP's CQE reservation is held until its flush completions are drained, or,
  // for a provider that never delivers them, until this long after the destroy (on `clock`)
  // and at least one drain of the CQ.
  Nanos zombie_grace = std::chrono::milliseconds(100);
  // CQ budget: every QP reserves sq_depth + its receive slots; connect/accept fail with
  // ResourceExhausted once the reservations would exceed cq_depth.
  std::uint32_t cq_depth = 4096;
  std::uint32_t sq_depth = 128;          // send queue entries per QP (SEND + READ + WRITE)
  // Control/ingest endpoints; fetch endpoints use 2 slots of 8 KiB (spec 3.5, HELLO only).
  std::uint32_t send_slots = 16;         // bounce buffers for post_send, per endpoint
  std::uint32_t recv_slots = 16;         // pre-posted receives, per endpoint
};

// Kinds of ibv async events the fabric reacts to (the real events are routed by a
// per-device dispatcher; see inject_async_event_for_test).
enum class AsyncEventKind : std::uint8_t { QpFatal, CqErr, PortErr, DeviceFatal };

class VerbsCmFabric final : public Fabric {
 public:
  // Fails with NotFound when the device does not exist or no RDMA stack is present.
  static Expected<std::unique_ptr<VerbsCmFabric>> open(const VerbsOptions& options);
  ~VerbsCmFabric() override;
  VerbsCmFabric(const VerbsCmFabric&) = delete;
  VerbsCmFabric& operator=(const VerbsCmFabric&) = delete;

  const NicCaps& nic_caps() const;
  // The protocol endpoints created from now on use (detected, checked against the
  // fabric.protocol override).
  protocol::Protocol active_protocol() const;
  // Hook for a class-B make-before-break protocol switch (the hot reload comes later):
  // re-detects and applies `setting` to NEW endpoints only; existing ones keep running
  // on the protocol they were created with. Bumps protocol_epoch(); a controller drains
  // endpoints whose epoch is older (stale_endpoints()) and abort()s them when idle.
  Status set_protocol(protocol::Setting setting);
  std::uint32_t protocol_epoch() const;
  std::uint32_t endpoint_epoch(const Endpoint* ep) const;
  protocol::Protocol endpoint_protocol(const Endpoint* ep) const;
  std::vector<Endpoint*> stale_endpoints() const;
  // First IPv4 address on the netdev the device is bound to (for rdma_cm addressing).
  Expected<std::string> device_ipv4() const;
  // Port of the active listener (after listen with port 0), 0 if not listening.
  std::uint16_t listen_port() const;
  // Receive slots of an endpoint (2 for Fetch, recv_slots otherwise); diagnostics and tests.
  std::uint32_t endpoint_recv_slots(const Endpoint* ep) const;
  // Test hook: feeds an async event through the same per-device dispatcher and routing
  // table a real ibv async event uses. QpFatal targets `ep`'s QP, CqErr this fabric's CQ,
  // PortErr the given port (this fabric uses port 1), DeviceFatal every fabric on the device.
  Status inject_async_event_for_test(AsyncEventKind kind, Endpoint* ep = nullptr, int port = 1);
  // Test hook: the device's dispatcher thread exits as on POLLERR/POLLHUP of the async fd
  // (device removal): DeviceFatal reaches every fabric on the device once, and fabrics opened
  // on the device later get it at open. Process-wide for that device until all its fabrics close.
  void kill_async_dispatcher_for_test();
  // Where the QP attribute readback (once per rail, after RTS) publishes its gauges/counters (see
  // verbs_cm/qp_readback.h). `extra` labels every series and log line (the client passes node_id + hostname of
  // the memory node). Thread-safe; nullptr unbinds (call before the registry dies). Readbacks made while
  // unbound are published at the next bind.
  void set_qp_metrics(telemetry::Registry* reg, telemetry::Labels extra = {});
  // CQ entries currently reserved by live QPs and by destroyed QPs not yet settled (diagnostics).
  std::uint32_t cq_reserved() const;

  Expected<DeviceCaps> probe() override;
  // On iWARP, a region with LocalWrite (a possible READ sink) is also registered with
  // REMOTE_WRITE; MemRegion::access reports the effective rights.
  Expected<PdId> alloc_pd() override;
  Status free_pd(PdId pd) override;
  Expected<MemRegion> reg(std::span<std::byte> buf, Access access, PdId pd = {}) override;
  Status release(Endpoint* ep) override;
  // Endpoints currently owned by the fabric (diagnostics and leak tests).
  std::size_t endpoint_count() const;
  // Recv completions held back behind endpoints not announced yet (diagnostics and tests). Each one already gave
  // its receive slot back (re-posted at once), so on iWARP, which has no RNR retry, a peer may send that many more.
  // Fabric thread only (the thread that polls this fabric): it reads the endpoints' held lists without a lock.
  std::size_t held_recvs() const;
  Status dereg(const MemRegion& region) override;
  Expected<Endpoint*> connect(const Peer& peer, const ConnParams& params = {}) override;
  Status listen(AcceptFn on_accept, const ListenParams& params = {}) override;
  std::size_t poll(std::span<Completion> out, PollBudget budget = {}) override;
  int wait_fd() override;
  // ibv_query_port state of the fabric port, fatal-event latch, and one liveness flag per listen() call.
  FabricHealth health() override;

 private:
  struct Impl;
  explicit VerbsCmFabric(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

}  // namespace miracache::fabric
