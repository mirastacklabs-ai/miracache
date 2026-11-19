// SPDX-License-Identifier: Apache-2.0
// Client-side metrics (A3.5 M2): one Registry per Client, every child registered up front so the
// data path only does relaxed atomic adds through the cached pointers (no lookup, no lock, no
// allocation). Labels are fixed enums; none carries a scope, session, key, salt or token value.
#pragma once

#include <cstdint>
#include <string>

#include "telemetry/metrics.h"
#include "util/clock.h"
#include "util/error.h"

namespace miracache {

struct ClientMetrics {
  enum FetchResult { kFHit, kFMiss, kFError };
  enum PutResult { kPCommitted, kPSkipped, kPRefused, kPAborted, kPError };
  enum FetchStage { kFTotal, kFLeaseWait, kFRead, kFDecrypt };
  enum PutStage { kPTotal, kPEncrypt, kPWrite, kPCommit };

  // `shared`: a registry owned by the Client (every memory node writes into it with its own `node`
  // label); null = a private registry and no node label (the single-node shape).
  explicit ClientMetrics(telemetry::Registry* shared = nullptr, const std::string& node_label = {})
      : reg(shared ? *shared : own_), shared_reg(shared != nullptr) {
    auto L = [&node_label](telemetry::Labels l) {
      if (!node_label.empty()) l.emplace_back("node", node_label);
      return l;
    };
    static constexpr const char* kFR[] = {"hit", "miss", "error"};
    static constexpr const char* kPR[] = {"committed", "skipped", "refused", "aborted", "error"};
    static constexpr const char* kFS[] = {"total", "lease_wait", "read", "decrypt"};
    static constexpr const char* kPS[] = {"total", "encrypt", "write", "commit"};
    static constexpr const char* kRd[] = {"retry_exc", "rnr", "flush", "access", "other"};
    auto& r = reg;
    for (int i = 0; i < 3; ++i) {
      lookup_keys[i] = &r.counter("miracache_client_lookup_keys_total", "Keys looked up, by result.", L({{"result", kFR[i]}}));
      fetch_ops[i] = &r.counter("miracache_client_fetch_ops_total", "Keys fetched, by result.", L({{"result", kFR[i]}}));
      fetch_bytes[i] = &r.counter("miracache_client_fetch_bytes_total", "Plaintext bytes of fetched keys, by result.", L({{"result", kFR[i]}}));
    }
    for (int i = 0; i < 4; ++i)
      fetch_s[i] = &r.histogram("miracache_client_fetch_seconds", "Fetch latency by stage.", L({{"stage", kFS[i]}}));
    for (int i = 0; i < 5; ++i) {
      put_ops[i] = &r.counter("miracache_client_put_ops_total", "Keys put, by result.", L({{"result", kPR[i]}}));
      put_bytes[i] = &r.counter("miracache_client_put_bytes_total", "Plaintext bytes of put keys, by result.", L({{"result", kPR[i]}}));
    }
    // Same series as the Client's (no node label): MB6b counts StaleEpoch / Draining refusals here, QT2 the keys an Ok
    // ack skipped under the put token buckets (retry_after_ms > 0).
    static constexpr const char* kSk[] = {"stale_epoch", "draining", "throttled"};
    for (int i = 0; i < 3; ++i)
      put_skipped[i] = &r.counter("miracache_client_put_skipped_total",
                                  "Root puts skipped by the client or refused as skippable, by reason.", {{"reason", kSk[i]}});
    for (int i = 0; i < 4; ++i)
      put_s[i] =&r.histogram("miracache_client_put_seconds", "Put latency by stage.", L({{"stage", kPS[i]}}));
    crypto_bytes[0] = &r.counter("miracache_client_crypto_bytes_total", "Plaintext bytes through AEAD.", L({{"dir", "encrypt"}}));
    crypto_bytes[1] = &r.counter("miracache_client_crypto_bytes_total", "Plaintext bytes through AEAD.", L({{"dir", "decrypt"}}));
    aead_fail = &r.counter("miracache_client_aead_fail_total", "Fetched blocks that failed AEAD verification.", L({}));
    validate_fail[0] = &r.counter("miracache_client_validate_fail_total", "Fetched blocks rejected by validation, by kind.", L({{"kind", "seq"}}));
    validate_fail[1] = &r.counter("miracache_client_validate_fail_total", "Fetched blocks rejected by validation, by kind.", L({{"kind", "hdr"}}));
    invalidate_sent = &r.counter("miracache_client_invalidate_sent_total", "INVALIDATE requests sent after an AEAD failure.", L({}));
    fetch_slices = &r.counter("miracache_client_fetch_slices_total", "Data READs posted for blocks cut into more than one slice (fabric.slice_bytes).", L({}));
    inflight[0] = &r.gauge("miracache_client_inflight", "Jobs in flight, by op.", L({{"op", "fetch"}}));
    inflight[1] = &r.gauge("miracache_client_inflight", "Jobs in flight, by op.", L({{"op", "put"}}));
    for (int i = 0; i < 5; ++i)
      rdma[i] = &r.counter("miracache_client_rdma_errors_total", "Failed work requests, by kind.", L({{"kind", kRd[i]}}));
    static constexpr const char* kRc[] = {"goaway", "ep_error", "suspect"};
    for (int i = 0; i < 3; ++i)
      reconnect[i] = &r.counter("miracache_client_reconnect_total", "Sessions lost (reconnect cycles started), by reason.", L({{"reason", kRc[i]}}));
    reconnect_fail = &r.counter("miracache_client_reconnect_fail_total", "Failed reconnect attempts.", L({}));
    session_up = &r.gauge("miracache_client_session_up", "1 while the wire session is up, 0 while down or connecting.", L({}));
    session_up->set(1);
    // r7 R05: endpoints torn down that the fabric has not drained yet (aborted, QP in ERR, held until it
    // drains). Normally 0 within milliseconds of a session end; a value that stays up is a lost flush.
    undrained_zombies = &r.gauge("miracache_client_undrained_zombies", "Aborted endpoints still waiting for the fabric to drain them.", L({}));
    static constexpr const char* kTr[] = {"ok", "error"};
    for (int i = 0; i < 2; ++i)
      ticket_fetch[i] = &r.counter("miracache_client_ticket_fetch_total", "Admin IssueTicket calls, by result.", L({{"result", kTr[i]}}));
    static constexpr const char* kTc[] = {"control", "fetch", "ingest"};
    for (int i = 0; i < 3; ++i)
      ticket_cache[i] = &r.gauge("miracache_client_ticket_cache", "Unused connection tickets cached, by class.", L({{"class", kTc[i]}}));
    watchdog_trips = &r.counter("miracache_client_watchdog_trips_total", "Stuck jobs force-failed by the watchdog (ops abandoned).", L({}));
    quarantined = &r.gauge("miracache_client_quarantined_bytes", "Landing pool bytes held back after a watchdog trip until their endpoints are reaped.", L({}));
  }

  static void observe(telemetry::Histogram* h, Nanos from, Nanos to) {
    h->observe_ns(to > from ? static_cast<std::uint64_t>((to - from).count()) : 0);
  }
  // Same mapping as the server: the fabric reports a code, not the verbs status.
  static int rdma_kind(ErrorCode c) {
    return c == ErrorCode::Timeout ? 0 : c == ErrorCode::Aborted ? 2 : c == ErrorCode::AccessDenied ? 3 : 4;
  }

  telemetry::Registry own_;
  telemetry::Registry& reg;
  const bool shared_reg;  // L02: reg is the Client's registry, shared by every core of every node (and by a successor core)
  telemetry::Counter *lookup_keys[3], *fetch_ops[3], *fetch_bytes[3];
  telemetry::Counter *put_ops[5], *put_bytes[5], *rdma[5], *put_skipped[3];
  telemetry::Histogram *fetch_s[4], *put_s[4];
  telemetry::Counter *crypto_bytes[2], *aead_fail, *validate_fail[2], *invalidate_sent, *fetch_slices;
  telemetry::Counter *reconnect[3], *reconnect_fail, *ticket_fetch[2], *watchdog_trips;
  telemetry::Gauge *inflight[2], *session_up, *ticket_cache[3], *quarantined, *undrained_zombies;
};

}  // namespace miracache
