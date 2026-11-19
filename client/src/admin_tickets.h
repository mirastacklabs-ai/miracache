// SPDX-License-Identifier: Apache-2.0
// Ticket source for a client on another host (A2.1): IssueTicket over HTTPS + mTLS
// (POST /v1/tickets on the memory node's admin port, batch form for the 3 classes).
//
//   * TLS 1.3 only; the server certificate chain is verified against [tls] ca and, if
//     nodes[].identity is set, its first spiffe:// URI SAN must equal it. No hostname check
//     (lab certs carry the SPIFFE id). The client key file must be mode 0600.
//   * Per-(rail, class) cache (RL2 follow-up: one request per rail in AdminTicketOptions::rails). draw() NEVER does network I/O: it pops one cached ticket (so it is safe
//     under the client core lock, from the reconnect path). A ticket is handed out once, never
//     reused, and dropped once older than ttl_s/2 (ttl_s comes from the response).
//   * prepare() does the network I/O (<= 2 s total, real time) and must be called WITHOUT the
//     core lock: before Client::open_wire, then from every keepalive tick. It refills when any
//     class holds < max(2, its need) live tickets (G01: fetch needs fetch_qps). A failed fetch leaves the cache as is (existing sessions
//     keep working; new connections fail cleanly until the node answers again).
//   * Never logs or exposes ticket ids or key material.
#pragma once

#include <atomic>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "src/wire_port.h"
#include "util/clock.h"
#include "util/random.h"


namespace miracache {

struct ClientMetrics;
class HttpsClient;

struct AdminTicketOptions {
  std::string admin;              // "host:port"
  std::string cert, key, ca;      // PEM paths
  std::string server_identity;    // expected spiffe:// id of the node; empty = chain check only
  unsigned batch = 4;             // tickets per class per call (1..64)
  unsigned io_timeout_ms = 2000;  // whole call: connect + handshake + request + response
  unsigned refill_below = 2;      // refill when any class has fewer live tickets than this
  // G01: fetch tickets one build draws per rail (WireOptions::fetch_qps, 1..64). A class refills below
  // max(refill_below, need) and asks for max(batch, need), so one build of any fetch_qps finds enough tickets.
  // Control and ingest need 1. Settable live (set_fetch_need) before each prepare().
  unsigned fetch_need = 1;
  // RL2 follow-up (multi-rail decision 4: the node admits a ticket only on its own rail): the node rail indices (0..3)
  // to keep tickets for, one cache and one request ("rail": r) per rail. Empty = rail 0 only (a single-rail node).
  std::vector<std::uint8_t> rails;
  // A03: after a failed fetch the next one waits backoff_min_ms * 2^n (capped at backoff_max_ms,
  // equal jitter through `random` when set). Success resets it.
  unsigned backoff_min_ms = 1000;
  unsigned backoff_max_ms = 30000;
  // r8b Q02: a tighter cap for "node away" failures only (LinkDown, Timeout, 503 draining), so the
  // first IssueTicket after a restart is at most this late; 0 = backoff_max_ms. A 403, a 429 or a
  // cert/TLS failure keeps backoff_max_ms: a misconfigured client is not retried at reconnect pace.
  unsigned away_backoff_max_ms = 0;
  Random* random = nullptr;
  // Test hook: called with the connected TCP fd before the TLS handshake starts.
  std::function<void(int)> test_after_connect;
};

class AdminTicketSource {
 public:
  // Loads cert/key/ca and checks the key file mode (0600). Errors: InvalidArgument, AccessDenied.
  static Expected<std::shared_ptr<AdminTicketSource>> create(AdminTicketOptions o, const Clock& clock);
  ~AdminTicketSource();

  TicketFn ticket_fn();           // draw() as a TicketFn (the source must outlive it)
  RailTicketFn rail_ticket_fn();  // draw(cls, rail) as a RailTicketFn (the source must outlive it)
  Expected<proto::Ticket> draw(fabric::EpClass cls);  // from the cache; NotFound when empty (no I/O); rail 0
  Expected<proto::Ticket> draw(fabric::EpClass cls, std::uint8_t rail);  // a ticket of node rail `rail`; NotFound: none
  Status prepare();               // refill if needed (network; not under the core lock)
  // R14 (review s11): as prepare(), with every admin call ending within `budget` (clock) from now; none starts once it
  // is spent (Timeout). Client::open's settle retries use it. Nanos::max() = prepare().
  Status prepare(Nanos budget);
  // R19: the clock time before which a build cannot draw its tickets (backing off after a failed fetch, and the cache
  // cannot serve one build: 1 control, fetch_need fetch, 1 ingest per rail); 0 = now. No I/O.
  Nanos ready_at() const;
  // r7 R01: forget the fetch backoff (no I/O; safe under the core lock). Called when the session goes
  // Down, so a restarted node is not hidden behind a backoff (up to 30 s) grown while it was away.
  void reset_backoff();
  void set_batch(unsigned n);  // HR2: fabric.ticket_batch, 1..64; the next refill uses it (thread-safe)
  void set_fetch_need(unsigned n);  // G01: fetch tickets per rail one build draws (1..64, clamped); thread-safe
  void bind_metrics(ClientMetrics* m);
  std::size_t cached(fabric::EpClass cls, std::uint8_t rail = 0) const;  // live tickets in the cache (test hook)
  std::uint64_t fetches() const { return fetches_.load(); }  // admin calls attempted (test hook)
  // The memory node's hostname / ID from the last good response ("" / 0 if its server sends none). Thread-safe.
  std::string hostname() const;
  std::uint32_t reported_node_id() const;

  // Strict response parser, exposed for tests. Fills `out` per class and ttl_s.
  struct Parsed {
    std::uint64_t ttl_s = 0;
    std::uint32_t node_id = 0;  // 0 = the response carried none (an older server)
    std::string hostname;       // empty = none
    std::deque<proto::Ticket> by_class[3];
  };
  // Every ticket must name `rail` (the rail the request asked for).
  static Expected<Parsed> parse_response(const std::string& body, unsigned max_per_class, std::uint8_t rail = 0);

 private:
  AdminTicketSource(AdminTicketOptions o, const Clock& clock, std::shared_ptr<HttpsClient> http);
  // Tickets of `rail` for the classes in the mask; timeout_ms 0 = io_timeout_ms (R14: else the call's own budget).
  Status fetch(std::uint8_t rail, unsigned class_mask, unsigned count, unsigned timeout_ms = 0);
  static constexpr std::size_t kRails = 4;
  void publish_gauges();
  struct Entry {
    proto::Ticket t;
    Nanos at;
  };
  const AdminTicketOptions o_;
  std::atomic<unsigned> batch_;
  std::atomic<unsigned> fetch_need_;
  // G01: the per-class refill mark, request size and cache cap for class `ci` (batch_ and fetch_need_ now).
  struct Want {
    std::size_t mark, count, cap;
  };
  Want want(int ci) const;
  const Clock& clock_;
  std::shared_ptr<HttpsClient> http_;
  mutable std::mutex mu_;  // guards cache_ and ttl_s_
  std::deque<Entry> cache_[kRails][3];  // [rail][class]
  std::uint64_t ttl_s_ = 300;
  std::string hostname_;       // mu_: last response
  std::uint32_t node_id_ = 0;  // mu_: last response
  unsigned fail_streak_ = 0;  // mu_: consecutive failed fetches
  Nanos next_try_{0};         // mu_: no fetch before this (backoff)
  Error last_err_{ErrorCode::NotFound, "admin: no fetch yet"};  // mu_
  bool last_failed_ = false;  // mu_: the latest fetch failed (Q15: draw() on an empty cache then returns last_err_)
  std::mutex fetch_mu_;  // one admin call at a time
  std::mutex mx_mu_;  // orders "bump total + counter" against bind_metrics' replay
  std::atomic<ClientMetrics*> mx_{nullptr};
  std::atomic<std::uint64_t> fetches_{0}, n_ok_{0}, n_err_{0};  // totals; replayed into the counters on bind
};

}  // namespace miracache
