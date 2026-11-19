// SPDX-License-Identifier: Apache-2.0
// WirePort (A1.6 L4+): the production ServerPort. Speaks wire v0 to the memory node (store S7)
// over a fabric::Fabric (verbs_cm or SimFabric).
//
//   * Three endpoints (control / fetch / ingest), one ticket each, one shared HELLO conn_id.
//     Control carries LOOKUP/RENEW/RELEASE/INVALIDATE/STATS; ingest carries PUT_BEGIN and
//     PUT_COMMIT/PUT_CANCEL on the SAME QP as the RDMA WRITEs (so the COMMIT is ordered after
//     the placed bytes); fetch carries only HELLO and the RDMA READs.
//   * ServerInfo is rebuilt from the latest SEG_TABLE (any endpoint; table_gen grows).
//   * The ServerPort calls are synchronous: they pump the fabric (through `inner`) until the
//     reply arrives. Completions that are not wire frames (READ/WRITE CQEs, CqError) are
//     stashed and handed to ClientCore by WirePort::fabric().poll(), which is the Fabric that
//     the ClientCore must be given. PUT_DONE callbacks also run from that poll().
//   * Session state machine: Up -> Down -> (Connecting -> Up). Down is entered on GOAWAY, on
//     any endpoint in Error state, or when control has been `suspect` for 3 keepalive periods.
//     Going Down aborts the three endpoints, fails pending commits, and makes every later call
//     a clean failure (miss / refused / aborted) with no RPC attempted; ClientCore sees
//     session_down_count() change and fails its in-flight jobs. keepalive() (the Client's
//     keepalive thread) then reconnects with exponential backoff (reconnect_min_ms ..
//     reconnect_max_ms, jittered through Random): three fresh tickets, HELLO x3, SEG_TABLE on
//     control, then Up again. A GOAWAY's drain_ms is a deadline, not a delay (r6 A1): backoff
//     starts at reconnect_min_ms as usual (a draining node refuses the connect), and no attempt is
//     scheduled later than the deadline, so a node restarted early is found within the backoff
//     bound. A GOAWAY seen while connecting fails that attempt (r6 A3): no Up/Down flap.
//   * RL2 rails (multi-rail plan decisions 1, 5, 6, 7, 9). With several rails (WireOptions::rails) or fetch_qps > 1 each
//     rail has its own endpoint set: 1 control, fetch_qps fetch, 1 ingest, its own tickets, all in ONE session (one
//     conn_id). ClientCore then gets two multiplexing endpoints (fetch, ingest) that route each work request to a rail:
//     a READ to the healthy rail's fetch QP with the fewest outstanding bytes (the remote rkey becomes that rail's
//     rkey[index] from SEG_TABLE, the local lkey that rail's device's registration of the landing sub-pool), a WRITE to
//     the ingest QP its put began on. Control (LOOKUP, RENEW, RELEASE, INVALIDATE, STATS) goes on the lowest-index
//     healthy rail; a put picks the healthy rail with the fewest outstanding put bytes and stays on its ingest QP.
//     A rail is Suspect after three missed PINGs (several rails) or a control RPC timeout: it takes no new work; a frame
//     clears it. A rail is given up when one of its QPs fails (a CQE error, ERR) or after three more keepalive periods
//     of suspicion: all its QPs go to ERR and their work flushes to the core; it reconnects on its own backoff with its
//     own tickets and takes work again only after HELLO and SEG_TABLE. The session (the node) is Up while one rail is
//     not given up; it goes Down only when the last one is.
//     RL2 follow-up B: that reconnect never waits inside keepalive() (which runs under the client lock): one tick
//     connects the rail's endpoints and sends their HELLOs, later ticks take the HELLO_ACKs and the SEG_TABLE as they
//     arrive, and the rail goes up (takes work) only when all are in, or is torn down at the background RPC cap (2 s).
//     Run #233: the fabric connects run OFF the lock too. keepalive() lends the rail's local device fabric to the
//     keepalive thread when the rail is the only rail of the port on that device and no endpoint (live or zombie) is
//     left on it; from then on nothing under the lock touches that fabric (service() skips it, no rail on it takes
//     work, the landing pool registers only at the core's build and frees only at close). build_rails() (no lock)
//     connects the rail's endpoint set on it, each connect bounded by reconnect_connect_ms, and sends each endpoint's
//     HELLO as it connects; the next keepalive() takes the fabric back and swaps the set in (its HELLO_ACKs and
//     SEG_TABLE are then filed and taken by the join above: the rail takes work only after all of them, with the
//     session's boot nonce) or, if the session ended or the build failed, releases it (zombies, reaped). The rail's PD
//     and landing registration are reused (none is made per rebuild). A rail sharing its device with another rail of
//     the port, or with a zombie of ours still on it, still connects inside the tick (as before).
//   * RL3 (decisions 8, 9): ClientCore cuts blocks into slice_bytes slices; the fetch mux puts each READ on the healthy
//     rail's fetch QP with the least outstanding bytes per unit of link speed (RailOpt::weight) whose window
//     (window_bytes) has room, else refuses it with Busy (the slice waits in the core). A slice is re-issued by the
//     core only after its own failed or flushed CQE, which reaches the core after the port has given its rail up.
//     Landing buffers stay the RL2 alias registrations (one per local device), not per-rail sub-pools: a re-issued
//     slice lands in the same bytes on another rail's device, so every device needs the span registered anyway.
// Single-threaded like ClientCore: callers serialise.
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <optional>
#include <memory>
#include <string>
#include <vector>

#include "fabric/fabric.h"
#include "proto/messages.h"
#include "src/dyn_config.h"
#include "src/server_port.h"
#include "util/clock.h"
#include "util/nonce_source.h"
#include "util/random.h"

namespace miracache {

// Supplies one unused connection ticket of `cls` per call. Errors: NotFound = none left.
using TicketFn = std::function<Expected<proto::Ticket>(fabric::EpClass cls)>;

// Lab ticket distribution: reads the file mira-memnode writes ([lab] ticket_file; lines
// "control|fetch|ingest <rail> <32 hex>"). Re-read on every call (the server refreshes it);
// ids already handed out by this source are skipped.
TicketFn lab_ticket_file_source(std::string path);
// RL2: one unused ticket of `cls` for node rail `rail` (the node admits a ticket only on its own rail).
using RailTicketFn = std::function<Expected<proto::Ticket>(fabric::EpClass cls, std::uint8_t rail)>;
// The same file, per rail: only the lines of the asked rail are used.
RailTicketFn lab_rail_ticket_file_source(std::string path);

struct WireOptions {
  // 0 (production): the node's ID is learned from HELLO_ACK (plan 2C). Nonzero (sim and tests): it routes the
  // sim and HELLO_ACK must carry exactly this ID, else the attempt fails (a config error, long backoff).
  fabric::NodeId node = 0;
  // Sim only: the peer the sim routes to when `node` is 0 (learn mode). verbs_cm ignores both and uses `rail`.
  fabric::NodeId route = 0;
  // Called (on the thread that runs the HELLO: the build or the reconnect) with the ID of every HELLO_ACK in the
  // learn mode. An error fails the HELLO as a config error (no retry storm); the Client uses it to refuse a
  // duplicate ID. Must not call back into the port.
  std::function<Status(std::uint32_t)> on_node_id;
  // F5: called (same thread as on_node_id, before it) when a HELLO_ACK carries a hostname (TLV 0x0004) that differs from the
  // last one. The Client keeps it as the fallback hostname of static/lab mode. Must not call back into the port.
  std::function<void(const std::string&)> on_node_hostname;
  fabric::RailAddr rail;       // verbs_cm: where the node listens (rail 0)
  TicketFn tickets;            // required
  std::function<void()> drive; // runs between polls while a call waits (tests: step the sim + server)
  // Q15 (B) (review s11, run #280): "wire: no reply" exactly rpc_timeout into a first build, while the fabric trace shows
  // the HELLO_ACKs and the SEG_TABLE arrive, means the awaited frame was not dispatched by the deadline: wait_until runs
  // service() (polls every CQ, files every frame) at least every 1 ms, and at the deadline it runs one more
  // non-blocking service() before it returns the timeout (run #293), so a frame that is in the CQ by the deadline is
  // taken, the last <= 1 ms poll slice and the sim's deadline tick included (no extra wait, same locks, each frame
  // filed once; the timeout, its suspect mark and its log lines are unchanged otherwise). A later reply is dropped by
  // design: rpc() erases its awaiting entry and a failed open() drops the endpoint (zombie: on_frame ignores it, a late
  // SEG_TABLE too). So the code confirms "the reply came after rpc_timeout" (siw0 under load), not a lost frame. 5 s
  // stays: a healthy node answers in ms, a longer first-build wait only delays the open behind a dead node, and a first
  // build that times out is retried inside the open (Env::open_settle, short caps) and then by the keepalive thread, the
  // same contract as a reconnect.
  Nanos rpc_timeout = std::chrono::seconds(5);
  Nanos commit_timeout = std::chrono::seconds(30);  // PUT_COMMIT with no PUT_DONE
  std::uint8_t wire_proto = 1;  // HELLO proto: 1 RoCE, 2 iWARP
  unsigned ticket_attempts = 4; // AccessDenied on connect (shared ticket file): try the next ticket
  // Client::open_wire keepalive period (spec 3: PING on control every 1 s; also drains
  // unsolicited SEG_TABLE/GOAWAY when no job runs). 0 = off. Read by the Client, not WirePort.
  unsigned keepalive_ms = 1000;
  std::uint32_t mtu = 4096;     // HELLO mtu (fabric.mtu, else the NIC profile)
  std::uint8_t read_depth = 16; // ORD asked on the fetch and ingest endpoints (fabric.read_depth, else the NIC profile)
  // Reconnect backoff (fabric.reconnect_min_ms / reconnect_max_ms). Reconnect only runs while
  // keepalive() is called, i.e. with keepalive_ms > 0 in the Client.
  unsigned reconnect_min_ms = 100;
  unsigned reconnect_max_ms = 5000;
  // fabric.reconnect_connect_ms: connect timeout of every endpoint (control, fetch, ingest) of a build or
  // reconnect that runs on the Client keepalive thread (R01/Q02); those attempts also cap HELLO and
  // SEG_TABLE at min(rpc_timeout, 2 s). The first Client::open build keeps the fabric default connect
  // timeout (5 s) and rpc_timeout. Not "one reconnect attempt" in general: a retried background build counts.
  unsigned reconnect_connect_ms = 1000;
  // HR2: the Client's live configuration. When set, reconnect_min_ms / reconnect_max_ms / reconnect_connect_ms and the
  // keepalive_ms of the suspect timer are read from it at each use (class A); the fields above are then only the
  // open-time values. The pointee must outlive the port.
  const DynSnap* dyn = nullptr;
  Random* random = nullptr;     // backoff jitter (deterministic in sim); null = no jitter
  std::function<void()> on_down;  // called (under the caller's lock) when the session goes Down
  // Ticket sources that need network I/O (admin mTLS): prepare runs on the keepalive thread WITHOUT
  // the core lock before every tick (refills the ticket cache); on_metrics hands over the registry.
  std::function<void()> prepare;
  // R14 (review s11): as prepare, but its network I/O ends within `budget` (the open's settle retries). Null: prepare.
  std::function<void(Nanos budget)> prepare_within;
  // R19 (review s11): the env-clock time before which a build cannot draw its tickets (the source backs off after a
  // failed fetch and its cache cannot serve a build), 0 = now. The open's settle waits for it. Null: always 0.
  std::function<Nanos()> tickets_ready_at;
  // G01: tells the ticket source how many fetch tickets per rail one build draws (the build's fetch_qps), before
  // prepare: a fetch_qps above ticket_batch then still finds enough tickets. Null: the source's default.
  std::function<void(std::uint32_t)> ticket_need;
  // G09 (review G07, Q6): a rail rejoin inside a live session failed on a LOCAL resource (fabric::last_local_failure()
  // is set; same thread). Args: the node rail index and its local device. The Client counts it in
  // miracache_client_endpoint_build_failures_total{cause="local_resource"} and logs it once per cause, as a build.
  std::function<void(unsigned rail, const std::string& device, const Error&)> on_local_failure;
  // Q03 (review s10): node rails whose endpoint sets connected on this port after the first build: `rejoin` false = the
  // session reconnected (Down -> Up; every rail that came up, called once, after the flip, on the reconnecting thread),
  // true = one rail rejoined a live session (under the caller's lock, from keepalive()). The Client closes the failure
  // entries of these rails (one recovery line), so their next failure is logged again. The first build is reported by
  // the Client's own build(), not here.
  std::function<void(const std::vector<unsigned>& rails, bool rejoin)> on_rails_up;
  std::function<void(ClientMetrics*)> on_metrics;
  // r7 R01: called (under the caller's lock, no I/O) when the session goes Down: the admin ticket source
  // resets its fetch backoff, so the reconnect after a restart is not stuck behind it.
  std::function<void()> on_down_tickets;
  // MB6b (bundle mode). `stamp`: every frame the port sends carries epoch = stamp >> 32 and bundle_gen_lo = low 32 bits
  // (the client's applied membership; 0 = unset). The pointee must outlive the port. `on_reply` is called for every
  // intact frame received, on the thread that pumps the port and under the caller's lock: it must be lock-free and do no
  // I/O. A zero epoch / bundle_gen_lo in a frame means "unstamped" (a node in lab mode, or a frame the node does not
  // stamp); the callee ignores zeros.
  const std::atomic<std::uint64_t>* stamp = nullptr;
  struct ReplyNote {
    std::uint32_t epoch = 0;
    std::uint32_t bundle_gen_lo = 0;
    bool stale_epoch = false;  // an ERROR reply with status StaleEpoch
  };
  std::function<void(const ReplyNote&)> on_reply;
  // ---- RL2: rails (multi-rail plan decisions 1, 5, 6, 7, 9) ----
  // One entry per PAIRED node rail (an unpaired rail is left out by the caller and counted in `unpaired_rails`).
  // Empty = one rail {`rail`, `route`, the port's `inner`, index 0}: the single-rail port, unchanged.
  struct RailOpt {
    std::uint8_t index = 0;          // the node's rail index: ticket, HELLO and SEG_TABLE rkey[index] (positional, STATIC)
    fabric::RailAddr addr;           // verbs_cm: where the node listens on this rail
    fabric::NodeId route = 0;        // sim only: the peer this rail routes to (0 = `route`, else `node`)
    fabric::Fabric* fab = nullptr;   // the local device this rail is paired with (null = the port's `inner`)
    std::string device;              // the local device name (log lines)
    // RL3 decision 8: the link speed of the local port (Mb/s, ibv_query_port active_speed x width); a READ goes to the
    // fetch QP with the least outstanding bytes per unit of weight. 0 = unknown (counts as 1, equal weights).
    std::uint32_t weight = 0;
  };
  std::vector<RailOpt> rails;
  // Fetch QPs per rail (the A3.3 operating point's fetch_qps, class B: a change applies at the next HR3b rebuild).
  std::uint32_t fetch_qps = 1;
  // RL3 decision 8: the outstanding READ bytes one fetch QP may carry (the A3.3 operating point's window_bytes, fixed
  // at open). A READ that fits no healthy QP's window is refused with Busy and waits in ClientCore; an idle QP always
  // takes one READ. 0 = no window. Applies to the multiplexing endpoints only (the single-rail path is unchanged).
  std::uint64_t window_bytes = 0;
  // Tickets per rail (the node admits a ticket only on its own rail). Unset = `tickets` (one rail only).
  RailTicketFn rail_tickets;
  // Goal 10: the Client's `node` label and the node's hostname, for the per-rail series and log lines.
  std::string label;
  std::function<std::string()> hostname;
  std::uint32_t unpaired_rails = 0;  // set as miracache_client_rail_unpaired{node} once metrics are bound
  // Run #233 (RL3 leftover): the caller runs WirePort::build_rails() WITHOUT its lock after every keepalive() (the
  // Client does). false: keepalive() runs the build itself, under the caller's lock (unit tests that drive keepalive()
  // alone; the behaviour before run #233).
  bool rail_build_off_lock = false;
  // R16: the send-queue entries of one QP (fabric::VerbsOptions::sq_depth; the provider refuses a post past it with
  // ResourceExhausted). A multiplexing endpoint keeps at most sq_depth - kSqReserve READs/WRITEs on one QP (the reserve
  // is for its frames) and answers Busy when every QP is at that cap, so the op waits in ClientCore. 0 = no cap.
  std::uint32_t sq_depth = 128;
  static constexpr std::uint32_t kSqReserve = 4;
};

struct ClientMetrics;
class WireFabric;

class WirePort final : public ServerPort {
 public:
  WirePort(fabric::Fabric& inner, const Clock& clock, NonceSource& nonce, WireOptions opts);
  ~WirePort() override;

  // The Fabric ClientCore must use with this port (forwards to `inner`, demuxes wire frames).
  fabric::Fabric& fabric();

  Expected<ServerInfo> hello() override;
  void connected(fabric::EpClass, fabric::Endpoint*) override {}
  bool refresh_info(ServerInfo& info) override;
  store::LookupAck lookup(const store::LookupReq& q) override;
  Status renew(store::LeaseId lease) override;
  void take_renewed(std::vector<Renewed>& out) override;  // RL3: RENEW_ACKs (OK) since the last call
  Status release(store::LeaseId lease) override;
  store::PutBeginAck put_begin(const store::PutBeginReq& q) override;
  void put_commit(const store::PutCommitReq& q, store::PutDoneFn done) override;
  void put_cancel(store::PutId id, store::PutDoneFn done) override;
  Status invalidate(const store::ScopeId& scope, const store::KeyHash& key, std::uint64_t gen) override;
  void set_op_deadline(Nanos d) override;
  store::LookupAck lookup_presence(const store::LookupReq& q) override;

  // One keepalive tick (caller holds the client lock): PING on control (fire-and-forget) and
  // drain every endpoint so unsolicited frames are consumed and receive slots reposted.
  // Any frame from the server (PONG included) clears the control-suspect state.
  void keepalive();
  // Run #233: connects the endpoint set of the rail keepalive() lent its device to (see the header comment), WITHOUT the
  // caller's lock, on the thread that calls keepalive() (never two at once). True if it built one (call keepalive()
  // again soon: it swaps the set in). No-op (false) when nothing is lent.
  bool build_rails();
  // J05 (review s8 wave15): gives a staged or built rail set back now (its endpoints aborted, released by reap() once
  // drained), for a port that will run no keepalive() again (a planned rebuild's old pair). Caller holds the client lock
  // and no build_rails() runs (the same thread calls both).
  void drop_rail_build();
  // Test hook: a rail's device is lent to build_rails() now (staged or built, not yet taken back by keepalive()).
  bool rail_build_pending() const;
  // Test hooks (thread-safe): build_rails() runs that connected a whole set; and (J01, process-wide) the times a path
  // under the client lock touched a device fabric while it was lent to build_rails() (logged; traps in debug builds).
  std::uint64_t off_lock_builds() const;
  static std::uint64_t lend_violations();
  // R01 off-lock reconnect (real time; the Client keepalive thread, session Down, NO client lock).
  // `quiesced` returns true once no job is inside the core (new jobs fail fast while the session
  // is not Up); `install` runs its argument under the client lock - only the flip to Up.
  // Without `quiesced` (keepalive(), the null-hooks form) the attempt reaps zombie endpoints without
  // checking that no job is inside the shared fabric: the caller must serialise it with all jobs
  // (hold the client lock, or be the only thread - sim and unit tests). Q08.
  struct ReconnectHooks {
    std::function<bool()> quiesced;
    std::function<void(const std::function<void()>&)> install;
    // One pause between two quiesced() checks (default: 1 ms). The Client gives its sim turn away around it (r9b T13).
    std::function<void()> wait;
  };
  void reconnect(const ReconnectHooks& hooks);
  std::uint64_t late_acks_released() const;  // R04 test hook
  std::uint64_t restarts_detected() const;   // F04 test hook: sessions a rejoining rail ended (a restarted memory node)
  // H02 test hook: the boot nonce the session's first HELLO_ACK carried (nullopt: none yet, or a node without the TLV).
  std::optional<std::uint64_t> boot_nonce() const;
  // K03: the largest stored block (stored_len) the node places, from the session's first HELLO_ACK; 0 = unknown (an older
  // node, or no HELLO_ACK yet). Lock-free: callable off the client lock.
  std::uint64_t max_stored_block() const;
  // K04 test hook: PUT_BEGINs refused locally (too large) or by an unhandled error reply (put_refused_total, all reasons).
  std::uint64_t put_refusals() const;
  // Runs WireOptions::prepare (network I/O for the ticket source). Call WITHOUT the client lock.
  void prepare_tickets();
  // Control RPCs fail fast while true: an RPC timed out and no frame has arrived since.
  bool control_suspect() const;
  std::uint64_t pings_sent() const;
  std::uint64_t pongs_received() const;
  // Pure SEG_TABLE -> ServerInfo (W04: seg ids are clamped to kMaxSegId, larger = malformed).
  static constexpr std::size_t kMaxSegId = 4096;
  static Expected<ServerInfo> info_from_seg_table(const proto::SegTable& t, fabric::NodeId node);

  // STATS round trip on control; returns the counter TLV bytes.
  Expected<std::vector<std::byte>> stats(std::uint32_t selector);

  // The node's ID: WireOptions::node, or the one HELLO_ACK carried (0 until the first HELLO). Thread-safe.
  std::uint32_t node_id() const;
  bool goaway_received() const;
  // Review w4 V08: the last GOAWAY had reason Epoch (removed from the membership); cleared when a session is Up again.
  // Thread-safe (the client's not-Up fast path reads it).
  bool removed_from_membership() const override;
  std::uint32_t table_gen() const;
  // Test hook: false once any wire endpoint died (until the next successful reconnect).
  bool healthy() const;

  // ---- session (see the header comment) ----
  enum class Session { Up, Down, Connecting };
  Session session() const;  // thread-safe
  bool session_up() const override { return session() == Session::Up; }
  std::uint64_t session_down_count() const override;
  fabric::Endpoint* endpoint(fabric::EpClass cls) override;
  std::size_t max_lookup_keys() const override { return proto::kMaxLookupKeys; }
  void bind_metrics(ClientMetrics* m) override;
  void endpoint_wedged(fabric::EpClass cls) override;
  bool session_reaped(std::uint64_t down) const override;
  // Milliseconds until the next reconnect attempt is due (0 = due now / not Down).
  unsigned reconnect_wait_ms() const;
  // Tells a Connecting attempt to give up now (Client shutdown); sticky.
  void abort_connect();
  // Q01/Q02: marks the calling thread's connect work (hello() and the fetch/ingest connects made by
  // ClientCore::init) as a background build: short connect on all endpoints, short HELLO/SEG_TABLE cap.
  // The Client sets it for builds on the keepalive thread only; reconnect() / keepalive() set it themselves.
  void set_background(bool on);
  // Q04: aborts and releases every endpoint (bounded wait for the fabric to drain). For a port that is
  // about to be destroyed after a failed build; its endpoints would otherwise stay in the fabric.
  // `real_until` (r7 R04): real-time deadline (RealClock) of the wait when no sim `drive` is set; 0 = 500 ms.
  void release_endpoints(Nanos real_until = Nanos{0});
  // r7 R04: aborts every endpoint without waiting (a Client aborts all nodes first, then waits once). J10: a staged or
  // built rail set (run #233) is given back and aborted too (the keepalive thread must be stopped).
  void abort_endpoints();
  // HR3b (planned rebuild; the caller holds the client lock). quiet: no endpoint has a WR outstanding (a retired port
  // whose jobs are done may close: no QP is destroyed while a WR is outstanding). drain_session: the §3.7 drain of a
  // retired port at its drain deadline: the session goes Down (endpoints to ERR, in-flight work flushes, the core fails
  // the jobs inside), not counted as a lost session.
  bool quiet() const;
  void drain_session();
  std::uint64_t connect_attempts() const;  // reconnect attempts started (test hook)

  // ---- RL2 rails (see the header comment). Test hooks and telemetry; same thread as the port's other calls. ----
  enum class RailState { Down = 0, Suspect = 1, Up = 2 };  // the miracache_client_rail_state value
  std::size_t rail_count() const;
  RailState rail_state(std::size_t pos) const;
  std::uint8_t rail_index(std::size_t pos) const;  // the node's rail index of position `pos`
  std::size_t control_rail() const;                 // position control RPCs use now; rail_count() = none healthy
  std::uint64_t rail_reads(std::size_t pos) const;  // READs posted on the rail's fetch QPs
  std::uint64_t rail_puts(std::size_t pos) const;   // PUT_BEGINs sent on the rail's ingest QP
  std::uint64_t rail_reconnects(std::size_t pos) const;  // the rail came back Up inside a live session
  // RL3: READ bytes outstanding on the rail's fetch QPs now (miracache_read_window) and landed on it so far.
  std::uint64_t rail_read_window(std::size_t pos) const;
  std::uint64_t rail_read_bytes(std::size_t pos) const;
  std::uint64_t slices_reissued() const;  // RL3: slices ClientCore re-issued on this port
  void slice_reissued() override;
  // R16: ClientCore found a single-rail endpoint's send queue full (counted on rail 0); the mux counts its own.
  void send_queue_full(fabric::EpClass cls) override;
  std::uint64_t rail_sq_full(std::size_t pos) const;  // R16: send-queue backpressure events on rail position pos

 private:
  store::LookupAck lookup_impl(const store::LookupReq& q, bool lease);
  friend class WireFabric;
  struct Impl;
  std::unique_ptr<Impl> p_;
  std::unique_ptr<WireFabric> wf_;
};

}  // namespace miracache
