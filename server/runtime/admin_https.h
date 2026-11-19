// SPDX-License-Identifier: Apache-2.0
// Admin API over HTTPS with mandatory client certificates (A2.1 slice; spec 3.3). Threads allowed
// here only (lint marker `// lint:server-runtime`).
//
//   POST /v1/tickets  {"class":"fetch","rail":0,"count":4}
//                     {"classes":["control","fetch","ingest"],"rail":0,"count":4}   (count 1..64 per class)
//   200 {"ttl_s":300,"tickets":[{"class":"fetch","rail":0,"id":"<32 hex>"},...],"node_id":N,"hostname":"h"}
//   400 malformed / unknown field, 403 identity not in the principal table (or no spiffe:// SAN),
//   404 other path, 405 other method, 408 read timeout, 413 over 8 KiB, 429 ticket cap, 503 node draining,
//   504 the store thread did not answer within 1 s.
//
// RB2: POST /v1/drain {"drain_ms":N}? (operator) and POST /v1/drop_principal {"name":"p","drop_before":
// "YYYY-MM-DDTHH:MM:SSZ"} (security-admin); roles, the route table and the audit wiring are in rbac.h. A denied
// call is 403 {"error":"role <r> required"}. With the audit log unavailable every route is 503.
//
// TLS 1.3 only; the client certificate is required and verified against `ca`. The identity is the
// single `spiffe://` URI SAN of the leaf (more than one is a 403). One accept thread plus at most
// `max_conns` (default 8) connection threads, at most 2 per source IP. A connection over either
// limit is closed at once, with no TLS work on the accept thread. Each connection has a 300 ms
// handshake budget and then a separate 2 s request budget, `Connection: close`. TicketTable is
// single-threaded: a connection thread posts an issue request to a mailbox and waits at most 1 s;
// the store thread answers inside pump(). stop() sets a flag the connection threads poll every
// 50 ms, so it returns within ~100 ms. Ticket ids, keys and certificates are never logged.
#pragma once

#include <pthread.h>

#include <array>
#include <atomic>
#include <condition_variable>  // lint:server-runtime
#include <cstdint>
#include <deque>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>  // lint:server-runtime
#include <utility>
#include <vector>

#include "server/runtime/rbac.h"
#include "server/server.h"
#include "telemetry/metrics.h"
#include "util/expected.h"

typedef struct ssl_ctx_st SSL_CTX;
typedef struct bio_st BIO;

namespace miracache::server {

// A socket BIO over `fd` (not closed with the BIO) whose writes use MSG_NOSIGNAL: a reset peer yields
// an error, never SIGPIPE, whatever the process's signal disposition is. Exposed for tests.
BIO* new_nosigpipe_socket_bio(int fd);

struct PushOutcome;  // bundle_store.h

struct AdminOptions {
  std::string listen;  // "host:port"; empty = off
  std::string cert, key, ca;
  std::uint64_t ttl_s = 300;  // echoed in the response
  std::uint32_t max_conns = 8;  // concurrent connection threads (1..1024)
  // Called (any connection thread) after a request is queued for pump(): wakes the store loop (r6 A7).
  // Taken at start(); reload_credentials does not change it. Must be thread-safe.
  std::function<void()> wakeup = {};
  // Tests only (r7 R03): TLS handshake budget in ms instead of kHandshakeMs (300); 0 = default.
  // Sanitizer builds can need more than 300 ms for one handshake on a loaded host.
  std::uint32_t handshake_ms_for_test = 0;
  // Tests only: the store-thread wait in ms instead of kStoreWaitMs; 0 = default.
  std::uint32_t store_wait_ms_for_test = 0;
  // Plan 2C: the memory node's own ID and hostname, added to the /v1/tickets response (clients learn the
  // hostname for their node_info series; old clients that skip unknown fields are unaffected). 0 / empty = omit.
  std::uint32_t node_id = 0;
  std::string hostname = {};
  // MB3a: bundle mode. Non-null enables POST/GET /v1/bundle and GET /v1/identity (mTLS identity only; the
  // signature is the gate). Owned by main, outlives the listener; taken at start() like `wakeup`.
  class BundleStore* bundle = nullptr;
  // RB2. Roles: bundle mode reads them from `bundle->rbac()` (the applied bundle's [[rbac]]); lab mode (bundle null)
  // from `lab_rbac` ([[admin.rbac]], SIGHUP). No bindings = only the routes that need no role work.
  std::vector<RbacBinding> lab_rbac = {};
  // Audit log (owned by main, outlives the listener, taken at start()). Null = no audit.
  AdminAudit* audit = nullptr;
  // The audit log was configured but could not be opened (audit.h policy): every route answers 503, the data plane
  // keeps serving. Taken at start().
  bool audit_failed = false;
  // [node] state_dir: POST /v1/drop_principal persists its drop_before raise in the floor file there. Empty = not persisted.
  std::string state_dir = {};
  // POST /v1/drain default GOAWAY window, [node] drain_ms.
  std::uint32_t drain_ms = 5000;
  // HR1/P39: the credential stat check (inode, mtime, size of cert, key and ca) runs this often (decision 1: 10 s); a
  // changed file is re-loaded, and one that does not parse or whose key does not match the certificate keeps the old
  // material (counted in miracache_cred_reload_total{kind="admin_tls",result="rejected"}, retried at the next check).
  std::uint32_t cred_stat_ms = 10000;
};

// A parsed POST /v1/tickets body. Strict: unknown or duplicate fields, string escapes and trailing
// bytes are errors. Exposed for tests.
struct TicketRequest {
  std::vector<fabric::EpClass> classes;
  std::uint8_t rail = 0;
  std::uint32_t count = 1;
};
Expected<TicketRequest> parse_ticket_request(const std::string& body);

class AdminHttps {
 public:
  static constexpr std::size_t kMaxRequestBytes = 8 * 1024;
  // Budgets (run #272). A client gives up after its own 2 s io_timeout_ms for the whole call, so a server budget past
  // ~1.5 s only keeps a thread for a caller that has left. 300 ms was too tight on a loaded host: the handshake thread
  // can wait that long for a CPU slice (siw0 VM, Q15), and a TLS 1.3 mTLS handshake costs a few ms of CPU on an older
  // DDR4 x86 with AES. Thread cost stays bounded: max_conns and kMaxPerIp cap the idle handshakes.
  static constexpr int kHandshakeMs = 1500;  // TLS handshake budget
  static constexpr int kTimeoutMs = 2000;    // request budget, counted from the end of the handshake
  static constexpr int kStoreWaitMs = 1500;  // wait for the store thread to pump a queued request (large puts hold it)
  static constexpr std::uint32_t kMaxPerIp = 2;  // concurrent connections from one source address
  static constexpr std::uint32_t kMaxCount = 64;

  // Empty `listen` returns nullptr. The key file must be 0600 (no group/other bits).
  static Expected<std::unique_ptr<AdminHttps>> start(const AdminOptions& o, telemetry::Registry& reg);
  ~AdminHttps();
  AdminHttps(const AdminHttps&) = delete;
  AdminHttps& operator=(const AdminHttps&) = delete;

  // Re-reads cert/key/ca (SIGHUP). On failure the old credentials stay in use.
  Status reload_credentials(const AdminOptions& o);
  // Store thread: answers the queued issue requests. Returns how many were handled.
  std::size_t pump(Server& srv);

  std::uint16_t port() const { return port_; }
  const AdminOptions& options() const { return opt_; }
  void stop();

 private:
  struct Pending {
    std::string identity;
    TicketRequest req;
    std::mutex m;
    std::condition_variable cv;  // lint:server-runtime
    bool done = false, abandoned = false;
    bool ok = false;
    Error err{ErrorCode::Aborted, ""};
    std::vector<std::pair<fabric::EpClass, proto::Ticket>> out;
  };
  // A closure for the store thread (bundle swap): pump() runs it between run_once turns.
  struct StoreTask {
    std::function<void(Server&)> fn;
    std::mutex m;
    std::condition_variable cv;  // lint:server-runtime
    bool done = false;
  };
  bool run_on_store(std::function<void(Server&)> task, const std::atomic<bool>& stop);
  struct Worker {
    pthread_t t{};  // started by net::spawn
    std::atomic<bool> done{false};
    std::uint32_t ip = 0;  // source address (network order), for the per-IP count
  };
  AdminHttps(int fd, std::uint16_t port, AdminOptions o, std::shared_ptr<SSL_CTX> ctx, telemetry::Registry& reg);
  void accept_loop();
  void serve(int fd, const std::string& peer);
  int store_wait_ms() const { return opt_.store_wait_ms_for_test > 0 ? static_cast<int>(opt_.store_wait_ms_for_test) : kStoreWaitMs; }
  // Names the cause of an expired budget: a counter, and one Warn per cause per second (log lines carry the node's
  // ID + hostname + IP from log::set_identity; `peer` is the client's address).
  void budget_expired(int cause, const std::string& peer, int budget_ms);
  void reap(bool all);
  std::shared_ptr<SSL_CTX> ctx() const;
  void count(const char* path, int code);
  // Audit helpers (RB2). audit_record writes now (false = the append failed: counted); without a log it is a no-op, or,
  // when the log is configured but unavailable (audit_failed), a stderr line + miracache_audit_unlogged_total.
  bool audit_record(const control::AuditEntry& e);
  void audit_denied(const control::AuditEntry& e);  // coalesced
  void write_apply_audit(const std::string& identity, const std::string& role, const PushOutcome& o);
  void reject(const char* reason);

  int lfd_;
  std::uint16_t port_;
  AdminOptions opt_;
  telemetry::Registry& reg_;
  telemetry::Counter* tls_fail_ = nullptr;
  std::atomic<std::int64_t> last_expiry_log_ms_[2] = {-100000, -100000};
  mutable std::mutex ctx_mu_;
  std::shared_ptr<SSL_CTX> ctx_;
  struct FileSig {
    std::int64_t mtime_ns = 0, size = -1, ino = 0;
    bool operator==(const FileSig&) const = default;
  };
  using CredSigs = std::array<FileSig, 3>;  // cert, key, ca
  static CredSigs cred_sigs(const AdminOptions& o);
  void maybe_reload_credentials();
  CredSigs cred_sig_{};        // the signatures the live ctx_ was built from; guarded by ctx_mu_
  std::int64_t next_cred_ns_ = 0;  // accept thread only
  std::mutex q_mu_;
  std::deque<std::shared_ptr<Pending>> q_;
  std::deque<std::shared_ptr<StoreTask>> tq_;  // guarded by q_mu_
  std::atomic<std::uint64_t> ttl_s_{300};
  std::atomic<std::uint32_t> max_conns_{8};
  std::atomic<std::uint32_t> drain_ms_{5000};
  RbacTable lab_rbac_;  // lab mode bindings; bundle mode reads opt_.bundle->rbac()
  std::atomic<bool> stop_{false};
  std::thread acceptor_;  // lint:server-runtime
  std::list<std::unique_ptr<Worker>> workers_;  // accept thread only (and stop())
  std::map<std::uint32_t, std::uint32_t> per_ip_;  // live workers per source address; same owner as workers_
};

}  // namespace miracache::server
