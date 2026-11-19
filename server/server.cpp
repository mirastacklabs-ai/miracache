// SPDX-License-Identifier: Apache-2.0
#include "server/server.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cstring>
#include <cstdint>

#include "server/dyn_config.h"
#include "util/log.h"

namespace miracache::server {

using proto::FrameHeader;
using proto::Op;
using proto::WireStatus;

namespace {
bool is_zero16(const std::uint8_t (&p)[16]) {
  for (auto b : p)
    if (b) return false;
  return true;
}
std::uint32_t to_ms(Nanos d) {
  if (d <= Nanos{0}) return 0;
  const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(d).count();
  return static_cast<std::uint32_t>(std::min<std::int64_t>(ms, 0xffffffffLL));
}

constexpr const char* kEvictNames[store::kEvictReasons] = {"cap", "pressure", "invalidate", "drop", "ttl"};
constexpr const char* kPutResultNames[store::kPutResults] = {"committed", "skipped", "refused", "aborted"};
constexpr const char* kRefuseNames[store::kRefuseReasons] = {"quota", "full", "class_cap", "conn_cap", "lease_cap", "other"};
constexpr const char* kOpNames[] = {"lookup", "renew", "release", "invalidate", "put_begin",
                                    "put_commit", "put_cancel", "stats", "ping"};
constexpr std::size_t kNumOps = sizeof(kOpNames) / sizeof(kOpNames[0]);
constexpr const char* kRdmaNames[] = {"retry_exc", "rnr", "flush", "access", "other"};
constexpr const char* kRejectNames[] = {"unknown", "expired", "rail", "conn_cap", "other"};
constexpr const char* kIssueFailNames[] = {"unknown_identity", "invalid", "limit", "other"};
constexpr const char* kClassNames[] = {"control", "fetch", "ingest"};
constexpr std::size_t kMaxPrincipalGauges = 64;
constexpr Nanos kPublishEvery = std::chrono::milliseconds(250);
constexpr Nanos kRailPollEvery = std::chrono::milliseconds(500);  // RL1: rail health refresh

#ifndef MIRACACHE_VERSION_STR
#define MIRACACHE_VERSION_STR "unknown"
#endif
#ifndef MIRACACHE_GIT_SHA
#define MIRACACHE_GIT_SHA "unknown"
#endif

int op_index(std::uint16_t type) {
  switch (static_cast<Op>(type)) {
    case Op::LOOKUP: return 0;
    case Op::RENEW: return 1;
    case Op::RELEASE: return 2;
    case Op::INVALIDATE: return 3;
    case Op::PUT_BEGIN: return 4;
    case Op::PUT_COMMIT: return 5;
    case Op::PUT_CANCEL: return 6;
    case Op::STATS: return 7;
    case Op::PING: return 8;
    default: return -1;
  }
}
}  // namespace

// Every metric the memory node exports (A3.5 M1). Registered once, in exposition order; the
// hot path only bumps the pointers below. No label carries a scope, session, key or token.
struct Server::Mx {
  Mx(telemetry::Registry& r, const ServerConfig& cfg) : reg(r) {
    using telemetry::Labels;
    // Identity (plan 2B): node_id goes on every series as a const label; node_info carries the rest.
    r.set_const_labels({{"node_id", std::to_string(cfg.store.node_id)}});
    r.gauge("miracache_node_info", "Memory node identity; the value is always 1.",
            {{"hostname", log::hostname()}, {"addr", listen_addr_string(cfg)}})
        .set(1);
    lookup[0] = &r.counter("miracache_lookup_keys_total", "Keys looked up, by result.", {{"result", "hit"}});
    lookup[1] = &r.counter("miracache_lookup_keys_total", "Keys looked up, by result.", {{"result", "miss"}});
    for (std::size_t i = 0; i < store::kPutResults; ++i)
      sm.put_ops[i] = &r.counter("miracache_put_ops_total", "Put keys, by result.", {{"result", kPutResultNames[i]}});
    for (std::size_t i = 0; i < store::kPutResults; ++i)
      sm.put_bytes[i] = &r.counter("miracache_put_bytes_total", "Put stored bytes, by result.", {{"result", kPutResultNames[i]}});
    for (std::size_t i = 0; i < store::kRefuseReasons; ++i)
      sm.put_refused[i] = &r.counter("miracache_put_refused_total", "Put keys refused, by reason.", {{"reason", kRefuseNames[i]}});
    sm.put_digest_mismatch = &r.counter("miracache_put_digest_mismatch_total", "Puts whose server CRC32C differed from the client's.");
    sm.put_commit_seconds = &r.histogram("miracache_put_commit_seconds", "PUT_BEGIN to commit completion.");
    sm.invalidate_dropped = &r.counter("miracache_invalidate_total", "INVALIDATE requests, by result.", {{"result", "dropped"}});
    sm.invalidate_ignored = &r.counter("miracache_invalidate_total", "INVALIDATE requests, by result.", {{"result", "ignored"}});
    lease_active = &r.gauge("miracache_lease_active", "Leases currently held.");
    lease_granted = &r.counter("miracache_lease_granted_total", "Leases granted.");
    sm.lease_expired = &r.counter("miracache_lease_expired_total", "Leases that expired.");
    lease_renew = &r.counter("miracache_lease_renew_total", "Successful lease renewals.");
    for (const char* s : {"used", "free", "unregistered"})
      bytes[s[0] == 'u' && s[1] == 's' ? 0 : s[0] == 'f' ? 1 : 2] =
          &r.gauge("miracache_store_bytes", "Store bytes, by state.", {{"state", s}});
    blocks[0] = &r.gauge("miracache_store_blocks", "Store blocks, by state.", {{"state", "allocated"}});
    blocks[1] = &r.gauge("miracache_store_blocks", "Store blocks, by state.", {{"state", "free"}});
    for (std::size_t i = 0; i < store::kEvictReasons; ++i)
      sm.evict_bytes[i] = &r.counter("miracache_evict_bytes_total", "Bytes evicted, by reason.", {{"reason", kEvictNames[i]}});
    for (std::size_t i = 0; i < store::kEvictReasons; ++i)
      sm.evict_blocks[i] = &r.counter("miracache_evict_blocks_total", "Blocks evicted, by reason.", {{"reason", kEvictNames[i]}});
    scope_open = &r.gauge("miracache_scope_open", "Open scopes of configured principals.");
    // QT1 gauges (U2-15) and QT2 throttle counters. The registry has integer gauges only: occupancy is in ppm.
    sm.occupancy_ratio_ppm = &r.gauge("miracache_store_occupancy_ratio_ppm", "Committed + zombie + in-flight bytes over registered capacity, in parts per million.");
    sm.evict_backlog_blocks = &r.gauge("miracache_evict_backlog_blocks", "Blocks of expired or dropped scopes still waiting to be freed.");
    for (std::size_t i = 0; i < 2; ++i)
      sm.put_throttled[i] = &r.counter("miracache_put_throttled_total", "Put keys skipped by the put token buckets, by kind.", {{"kind", i == 0 ? "ops" : "bytes"}});
    sm.scrub_checked = &r.counter("miracache_scrub_checked_total", "Blocks re-checked by the scrubber.");
    sm.scrub_failed = &r.counter("miracache_scrub_failed_total", "Blocks the scrubber found corrupt and dropped.");
    sm.scrub_bytes = &r.counter("miracache_scrub_bytes_total", "Extent bytes re-checked by the scrubber.");
    sm.scrub_cycle_seconds = &r.gauge("miracache_scrub_cycle_seconds", "Duration of the last completed scrub cycle over the whole store.");
    sm.scope_opened = &r.counter("miracache_scope_opened_total", "Scopes opened by a root PUT_BEGIN.");
    sm.scope_denied = &r.counter("miracache_scope_denied_total", "Put attempts denied for lack of a scope.");
    for (std::size_t i = 0; i < 3; ++i)
      conn[i] = &r.gauge("miracache_conn_active", "Live connections, by class.", {{"class", kClassNames[i]}});
    tk_issued = &r.counter("miracache_ticket_issued_total", "Connection tickets issued.");
    for (std::size_t i = 0; i < 5; ++i)
      tk_reject[i] = &r.counter("miracache_ticket_reject_total", "Connection tickets refused, by reason.", {{"reason", kRejectNames[i]}});
    for (std::size_t i = 0; i < 4; ++i)
      tk_issue_fail[i] = &r.counter("miracache_ticket_issue_fail_total", "IssueTicket requests that failed, by reason.",
                                    {{"reason", kIssueFailNames[i]}});
    for (std::size_t i = 0; i < 5; ++i)
      rdma_err[i] = &r.counter("miracache_rdma_errors_total", "Failed work requests, by kind.", {{"kind", kRdmaNames[i]}});
    for (std::size_t o = 0; o < kNumOps; ++o)
      for (std::size_t s = 0; s < 2; ++s)
        req[o][s] = &r.counter("miracache_requests_total", "Requests handled, by op and status.",
                               {{"op", kOpNames[o]}, {"status", s == 0 ? "ok" : "error"}});
    r.gauge("miracache_build_info", "Build information; the value is always 1.",
            {{"version", MIRACACHE_VERSION_STR}, {"git_sha", MIRACACHE_GIT_SHA}})
        .set(1);
  }
  // Gauge for a configured principal; the numeric id is the label. Setup-time, not hot path.
  telemetry::Gauge* principal_gauge(store::PrincipalId p) {
    auto it = pbytes.find(p);
    if (it != pbytes.end()) return it->second;
    if (pbytes.size() >= kMaxPrincipalGauges) return nullptr;
    auto* g = &reg.gauge("miracache_principal_bytes", "Bytes held by a configured principal.", {{"principal", std::to_string(p)}});
    pbytes[p] = g;
    return g;
  }

  telemetry::Registry& reg;
  store::StoreMetrics sm;
  telemetry::Counter* lookup[2] = {};
  telemetry::Counter *lease_granted = nullptr, *lease_renew = nullptr, *tk_issued = nullptr;
  telemetry::Counter* tk_reject[5] = {};
  telemetry::Counter* tk_issue_fail[4] = {};
  telemetry::Counter* rdma_err[5] = {};
  telemetry::Counter* req[kNumOps][2] = {};
  telemetry::Gauge *lease_active = nullptr, *scope_open = nullptr;
  telemetry::Gauge* bytes[3] = {};
  telemetry::Gauge* blocks[2] = {};
  telemetry::Gauge* conn[3] = {};
  std::map<store::PrincipalId, telemetry::Gauge*> pbytes;
};

std::string listen_addr_string(const ServerConfig& cfg) {
  std::string out;
  for (const auto& r : cfg.rails) {
    if (!out.empty()) out += ',';
    out += (r.host.empty() ? "0.0.0.0" : r.host) + ':' + std::to_string(r.port);
  }
  return out;
}

Server::Server(const ServerConfig& cfg, std::vector<fabric::Fabric*> fabrics, const Clock& c, Random&, Executor&,
               Random& ticket_rng)
    : cfg_(cfg), fabrics_(std::move(fabrics)), clock_(c), mx_(new Mx(registry_, cfg)),
      tickets_(c, ticket_rng, cfg.ticket_ttl, 65536, cfg.ticket_max_per_identity) {
  dyn_base_ = std::make_shared<const DynConfig>(dyn_from_server_config(cfg_));
  dyn_.store(dyn_base_);
}

Expected<std::unique_ptr<Server>> Server::create(const ServerConfig& cfg, fabric::Fabric& fab, const Clock& clock,
                                                 Random& rng, Executor& exec, Random* ticket_rng) {
  return create(cfg, std::vector<fabric::Fabric*>{&fab}, clock, rng, exec, ticket_rng);
}

Expected<std::unique_ptr<Server>> Server::create(const ServerConfig& cfg, std::vector<fabric::Fabric*> fabrics,
                                                 const Clock& clock, Random& rng, Executor& exec, Random* ticket_rng) {
  ServerConfig resolved = cfg;
  // store.max_bytes not set (0): this node's n_segments x segment_bytes (K02; the same rule dyn_from_server_config uses).
  if (resolved.store.principal_default.max_bytes == 0) resolved.store.principal_default.max_bytes = backing_bytes(resolved.store);
  if (auto st = resolved.store.validate(); !st) return st.error();
  // One SEG_TABLE frame carries at most kMaxSegEntries segments; more could never be announced.
  if (cfg.store.n_segments > proto::kMaxSegEntries)
    return Error{ErrorCode::InvalidArgument, "server: n_segments exceeds the SEG_TABLE limit"};
  // RL1 (decisions 1 and 2): 1..4 rails (the wire carries 4), each on one of the fabrics.
  if (fabrics.empty() || std::find(fabrics.begin(), fabrics.end(), nullptr) != fabrics.end())
    return Error{ErrorCode::InvalidArgument, "server: no fabric"};
  if (cfg.rails.size() > proto::kMaxRails)
    return Error{ErrorCode::InvalidArgument, "server: more than 4 rails"};
  if (!cfg.rail_device.empty() && cfg.rail_device.size() != std::max<std::size_t>(cfg.rails.size(), 1))
    return Error{ErrorCode::InvalidArgument, "server: rail_device must name a device for every rail"};
  for (std::uint32_t d : cfg.rail_device)
    if (d >= fabrics.size()) return Error{ErrorCode::InvalidArgument, "server: rail_device names an unknown device"};
  // The arena first: the node ID lives in its superblock (drawn on a blank store, read back on a warm
  // one; plan 2C), and the metrics (const label node_id) are built from the resolved config.
  auto a = store::Arena::open(resolved.store);
  if (!a) return a.error();
  resolved.store.node_id = (*a)->superblock().node_id;
  if (resolved.max_conns_per_principal == 0)  // not set: computed from this node's rails and profile (G02)
    resolved.max_conns_per_principal = default_max_conns(resolved.rails.size(), resolved.fetch_qps);
  if (resolved.ticket_max_per_identity == 0)  // not set: computed from the same inputs (H07)
    resolved.ticket_max_per_identity = default_ticket_max(resolved.rails.size(), resolved.fetch_qps);
  const std::size_t nf = fabrics.size();
  std::unique_ptr<Server> s(new Server(resolved, std::move(fabrics), clock, rng, exec, ticket_rng ? *ticket_rng : rng));
  s->arena_ = std::move(*a);
  s->slab_ = std::make_unique<store::SlabAllocator>(*s->arena_);
  s->store_ = std::make_unique<store::Store>(*s->arena_, *s->slab_, clock, rng);
  // A3.1: scope records carry wall-clock ms; the store runs on Clock ns. Converted once (a later jump is not followed).
  s->store_->set_wall_offset_ns(s->wall_now_ns() - clock.now().count());
  if (auto st = s->restart(); !st) return st.error();
  std::vector<store::MrManager::DeviceSpec> devs;
  for (std::size_t d = 0; d < nf; ++d) {
    auto pd = s->fabrics_[d]->alloc_pd();
    if (!pd) return pd.error();
    s->fetch_pds_.push_back(fabric::PdId{});
    s->ingest_pds_.push_back(*pd);
    devs.push_back({s->fabrics_[d], s->fetch_pds_.back(), s->ingest_pds_.back()});
  }
  s->mrs_ = std::make_unique<store::MrManager>(std::move(devs), *s->arena_);
  if (auto st = s->probe_backing(); !st) return st.error();
  Server* raw = s.get();
  s->store_->set_readable([raw](std::uint32_t seg) { return raw->mrs_->readable(seg); });
  s->puts_ = std::make_unique<store::PutPath>(
      *s->store_, *s->slab_, *s->mrs_, *s->arena_, clock, exec, [raw](const store::PutDoneResult& r) {
        // The store ended this put on its own (timeout): tell the owning endpoint, request_id 0.
        raw->send_put_done(r.ep, 0, r);
      });
  s->store_->set_metrics(&s->mx_->sm);
  s->puts_->set_metrics(&s->mx_->sm);
  {  // SC1: the CRC runs on the executor; the log line carries the node identity (design rule: ID + hostname + addr).
    const std::string addr = listen_addr_string(resolved), id = std::to_string(resolved.store.node_id);
    s->scrub_ = std::make_unique<store::Scrubber>(
        *s->store_, *s->arena_, exec, clock, &s->mx_->sm, [addr, id](const store::Extent& e) {
          log::write(log::Level::Warn, "scrub", "corrupt block dropped",
                     {{"node_id", id}, {"host", log::hostname()}, {"addr", addr}, {"seg", std::to_string(e.seg)},
                      {"offset", std::to_string(e.off)}});
        });
    s->scrub_->set_rate(resolved.store.scrub_enabled ? resolved.store.scrub_bytes_per_s : 0);
  }
  if (!cfg.lab_identity.empty()) s->tickets_.principals().add(cfg.lab_identity, cfg.lab_principal);
  for (const auto& id : cfg.lab_identities) s->tickets_.principals().add(id, cfg.lab_principal);
  // H02: one boot nonce per process, through Random (seedable in the sim, real in production). Drawn last, so the draws
  // above keep their order. 0 is reserved.
  s->boot_nonce_ = rng.next_u64();
  if (s->boot_nonce_ == 0) s->boot_nonce_ = 1;
  return s;
}

Status Server::restart() {
  const std::string addr = listen_addr_string(cfg_), id = std::to_string(cfg_.store.node_id), host = log::hostname();
  const std::string n_seg = std::to_string(cfg_.store.n_segments);
  store::RestartOptions opt;
  opt.progress = [&](std::uint32_t seg, const store::RestartReport& r) {
    log::write(log::Level::Info, "store", "restart scan: segment scanned",
               {{"node_id", id}, {"host", host}, {"addr", addr}, {"segment", std::to_string(seg + 1) + "/" + n_seg},
                {"slots", std::to_string(r.slots_scanned)}, {"discarded_blocks", std::to_string(r.discarded_total())}});
  };
  const Nanos t0 = clock_.now();
  auto r = store::restart_scan(*arena_, *slab_, *store_, opt);
  if (!r) return r.error();
  restart_report_ = *r;
  if (!r->ran) return {};
  registry_.counter("miracache_restart_adopted_blocks_total", "Committed blocks kept by the warm-restart scan.").inc(r->adopted_blocks);
  registry_.counter("miracache_restart_adopted_bytes_total", "Block bytes kept by the warm-restart scan.").inc(r->adopted_bytes);
  for (std::size_t i = 0; i < store::kDiscardReasons; ++i)
    registry_
        .counter("miracache_restart_discarded_blocks_total", "Blocks the warm-restart scan discarded, by reason.",
                 {{"reason", store::discard_reason_name(static_cast<store::DiscardReason>(i))}})
        .inc(r->discarded[i]);
  for (const auto& sh : r->shared_scopes) {  // once per scope_id per scan: why this restart came back cold for it
    static constexpr char kHex[] = "0123456789abcdef";
    std::string scope_hex, principals;
    for (auto b : sh.scope) scope_hex += kHex[b >> 4], scope_hex += kHex[b & 15];
    for (auto p : sh.principals) principals += (principals.empty() ? "" : ",") + std::to_string(p);
    if (sh.torn_record) principals += principals.empty() ? "torn-record" : ",torn-record";
    log::write(log::Level::Warn, "store", "warm restart: scope_id held by several principals, its blocks were discarded",
               {{"node_id", id}, {"host", host}, {"addr", addr}, {"scope_id", scope_hex}, {"principals", principals},
                {"discarded_blocks", std::to_string(sh.blocks)}, {"discarded_bytes", std::to_string(sh.bytes)},
                {"reason", "shared_scope_id"}});
  }
  // H05: a torn scope record whose principal or scope_id reads as zero makes the whole scan blind (safe: cold). One
  // line per such slot, at most 8 (a crash tears few records); the blocks are counted under reason="torn_record".
  const auto& blind = r->blind_record_slots;
  for (std::size_t i = 0; i < blind.size() && i < 8; ++i)
    log::write(log::Level::Warn, "store",
               "warm restart: a torn scope record has no readable principal or scope_id; no scope was resumed (cold restart)",
               {{"node_id", id}, {"host", host}, {"addr", addr}, {"slot", std::to_string(blind[i])},
                {"torn_records", std::to_string(blind.size())},
                {"discarded_blocks", std::to_string(r->discarded[static_cast<std::size_t>(store::DiscardReason::TornRecord)])},
                {"reason", "torn_record"}});
  const auto ms = (clock_.now() - t0).count() / 1000000;
  log::write(log::Level::Info, "store", "warm restart: cache resumed",
             {{"node_id", id}, {"host", host}, {"addr", addr}, {"clean", r->clean ? "1" : "0"},
              {"verified", r->verified ? "1" : "0"}, {"adopted_blocks", std::to_string(r->adopted_blocks)},
              {"adopted_bytes", std::to_string(r->adopted_bytes)}, {"discarded_blocks", std::to_string(r->discarded_total())},
              {"scopes", std::to_string(r->scopes_resumed)}, {"scan_ms", std::to_string(ms)}});
  return {};
}

Status Server::probe_backing() {
  if (cfg_.store.backing == store::BackingKind::Anon) return {};
  // Run 0 of segment 0 is a data run (the scope region takes the tail); its first page is probed, nothing is written.
  auto page = arena_->block(0, arena_->layout().seg.run_data_off(0), store::kPage);
  for (std::uint32_t d = 0; d < fabrics_.size(); ++d) {  // every device: each has its own PD and registration path
    auto mr = mrs_->register_write(page, d);
    if (!mr) {
      log::write(log::Level::Error, "store", "store.dir pages cannot be registered for remote write; use tmpfs or hugetlbfs",
                 {{"node_id", std::to_string(cfg_.store.node_id)}, {"host", log::hostname()}, {"addr", listen_addr_string(cfg_)},
                  {"dir", cfg_.store.dir}, {"device", std::to_string(d)}, {"error", mr.error().context}});
      return Error{ErrorCode::Unsupported,
                   "server: store.dir is on a filesystem whose pages cannot be pinned for remote write (use tmpfs or hugetlbfs)"};
    }
    if (auto st = mrs_->fence(*mr); !st) return st;
  }
  return {};
}

Expected<std::vector<proto::Ticket>> Server::issue_ticket(const std::string& identity, fabric::EpClass cls,
                                                          std::uint8_t rail, std::uint32_t count) {
  auto r = tickets_.issue(identity, cls, rail, count);
  if (r) mx_->tk_issued->inc(r->size());
  else count_issue_fail(r.error().code);
  return r;
}

void Server::count_issue_fail(ErrorCode c) {
  mx_->tk_issue_fail[c == ErrorCode::AccessDenied ? 0 : c == ErrorCode::InvalidArgument ? 1 : c == ErrorCode::ResourceExhausted ? 2 : 3]->inc();
}

Status Server::check_issue_capacity(const std::string& identity, std::uint32_t total) {
  if (refusing_sessions()) {  // r7 R01: admit() refuses every new session now; do not hand out tickets for it
    count_issue_fail(ErrorCode::Busy);
    return Error{ErrorCode::Busy, "server: draining"};
  }
  auto st = tickets_.check_capacity(identity, total);
  if (!st) count_issue_fail(st.error().code);
  return st;
}

void Server::reload_identities(const std::string& lab_identity, const std::vector<std::string>& lab_identities,
                               store::PrincipalId lab_principal) {
  if (view_) return;  // bundle mode: the applied bundle owns every identity binding (lab keys are ignored)
  std::set<std::string> want(lab_identities.begin(), lab_identities.end());
  if (!lab_identity.empty()) want.insert(lab_identity);
  std::set<std::string> have(cfg_.lab_identities.begin(), cfg_.lab_identities.end());
  if (!cfg_.lab_identity.empty()) have.insert(cfg_.lab_identity);
  for (const auto& id : have)
    if (!want.count(id) || lab_principal != cfg_.lab_principal) remove_identity(id);  // revokes tickets and connections
  for (const auto& id : want) tickets_.principals().add(id, lab_principal);
  cfg_.lab_identity = lab_identity;
  cfg_.lab_identities = lab_identities;
  cfg_.lab_principal = lab_principal;
}

void Server::refresh_snapshot(bool counts) {
  static constexpr const char* kNames[] = {"active", "draining", "readonly", "removed"};
  std::uint64_t scopes = 0, bytes = 0;
  if (counts)
    for (store::PrincipalId p : tickets_.principals().principal_ids()) {
      scopes += store_->n_scopes(p);
      bytes += store_->bytes_used(p);
    }
  std::lock_guard<std::mutex> g(snap_mu_);
  snap_.member_state = kNames[static_cast<std::size_t>(applied_bundle_.member_state)];
  if (counts) {
    snap_.scopes = scopes;
    snap_.bytes_used = bytes;
  }
}

std::int64_t Server::wall_now_ns() const { return cfg_.wall_unix_ns ? cfg_.wall_unix_ns() : miracache::wall_unix_ns(); }

namespace {
constexpr std::int64_t kNsPerSec = 1'000'000'000;

// QT3 (v1 quota plan, decision 2). Stateless, from the bundle alone:
//   active node      floor(quota * w_self / sum(w_active))
//   non-active node  floor(quota * w_self / (sum(w_active) + w_self))   (P38: a draining/readonly/removed node)
// A node the bundle does not list counts as non-active with weight 1. The cap is at least 1 byte (the store
// requires a positive cap; 1 byte admits nothing).
std::uint64_t quota_cap(std::uint64_t quota, std::uint64_t w_self, std::uint64_t sum_active, bool self_active) {
  const std::uint64_t denom = self_active ? sum_active : sum_active + w_self;
  if (denom == 0) return std::max<std::uint64_t>(quota, 1);
  const unsigned __int128 c = static_cast<unsigned __int128>(quota) * w_self / denom;
  return std::max<std::uint64_t>(static_cast<std::uint64_t>(c), 1);
}
}  // namespace

std::uint64_t Server::principal_cap_bytes(store::PrincipalId id) const {
  auto it = caps_.find(id);
  return it == caps_.end() ? 0 : it->second;
}

void Server::load_drop_before_floor(const std::map<std::string, std::int64_t>& maxima) {
  for (const auto& [name, secs] : maxima) {
    auto [it, inserted] = drop_before_max_.emplace(name, secs);
    if (!inserted && secs > it->second) it->second = secs;
  }
  apply_drop_before();
}

// drop_before (P15/C19): monotonic per principal name, re-applied on EVERY apply and at load, so a node that
// missed the bundle which carried it still drops. The store compares it with each scope's opened_at and frees
// the blocks incrementally (Store::sweep_step, bounded per turn); lookups of such scopes miss at once.
void Server::apply_drop_before() {
  const std::int64_t wall = wall_now_ns();
  for (const auto& [name, secs] : drop_before_max_) {
    auto& c = drop_cutoff_ns_[name];
    if (c.first != secs || c.second == 0) {  // first sight or a rise: convert once to the Clock domain
      __int128 age = static_cast<__int128>(wall) - static_cast<__int128>(secs) * kNsPerSec;  // ns since drop_before
      const __int128 lim = static_cast<__int128>(1) << 61;
      age = std::clamp(age, -lim, lim);
      // Y18: converted ONCE per rise (a later wall-clock jump is not re-followed); a future drop_before is clamped to
      // now, so it drops what exists and never kills scopes opened after the apply.
      c = {secs, std::min(clock_.now().count(), clock_.now().count() - static_cast<std::int64_t>(age))};
      if (c.second == 0) c.second = -1;  // 0 marks "unset" above
    }
    store_->set_drop_cutoff(control::principal_id(name), c.second);
  }
}

// A bundle principal's policy: the default (idle TTL, put buckets: live through HR1) with the QT3 byte cap and the
// bundle's scope cap. Needs caps_ filled.
store::PrincipalPolicy Server::policy_of(const control::PrincipalView& p) const {
  store::PrincipalPolicy pol = cfg_.store.principal_default;
  auto c = caps_.find(p.id);
  if (c != caps_.end()) pol.max_bytes = c->second;
  pol.max_scopes = static_cast<std::uint32_t>(std::clamp<std::uint64_t>(p.max_scopes, 1, UINT32_MAX));
  return pol;
}

void Server::count_config_rejected(const char* why) {
  registry_.counter("miracache_config_reload_total", "Configuration reloads, by result.", {{"result", "rejected"}}).inc();
  log::write(log::Level::Warn, "config", "reload rejected; the old snapshot stays", {{"reason", why}});
}

void Server::apply_dyn(DynPtr d, const char* source) {
  const DynPtr old = dyn_.load();
  const std::vector<std::string> changed = dyn_changed_keys(*old, *d);
  dyn_into_server_config(*d, cfg_);
  tickets_.set_limits(d->ticket_ttl, d->ticket_max_per_identity);
  store::Store::Limits lim;
  lim.lease_ttl = d->lease_ttl;
  lim.lease_max = d->lease_max;
  lim.invalidate_per_s = d->invalidate_per_s;
  lim.def = cfg_.store.principal_default;
  store_->set_limits(lim);
  store_->set_retention(d->max_ttl);
  store_->set_evict(d->sweep_bytes_per_s, d->sweep_blocks_per_turn, d->high_pct, d->low_pct);
  slab_->set_max_exact_classes_per_owner(d->max_exact_classes_per_owner);
  puts_->set_timeouts(d->put_timeout);
  scrub_->set_rate(d->scrub_enabled ? d->scrub_bytes_per_s : 0);
  if (view_)  // bundle principals carry the default's idle TTL and put buckets: derive their policies again
    for (const auto& p : view_->sec.principals) store_->set_policy(p.id, policy_of(p));
  dyn_.store(d);
  registry_.counter("miracache_config_reload_total", "Configuration reloads, by result.", {{"result", "applied"}}).inc();
  registry_.gauge("miracache_config_generation", "Bundle generation of the applied memory-node configuration (0 = local file).")
      .set(static_cast<std::int64_t>(d->generation));
  registry_.gauge("miracache_config_pending_keys", "Node-local keys found in the bundle's config table (set them in the local file).")
      .set(static_cast<std::int64_t>(d->pending.size()));
  if (!changed.empty() || !d->pending.empty()) {
    std::string names;
    for (const auto& k : changed) names += (names.empty() ? "" : ",") + k;
    std::string pend;
    for (const auto& k : d->pending) pend += (pend.empty() ? "" : ",") + k;
    log::write(log::Level::Info, "config", "reload applied",
               {{"source", source}, {"generation", std::to_string(d->generation)}, {"changed", names}, {"pending", pend}});
  }
}

// Bundle mode: config.cluster.memnode (+ the node override keyed by this node's admin address) over the start-up
// snapshot. The admin thread already validated the same bytes (BundleStore::push), so a failure here means the base
// changed under it: the old snapshot stays, counted.
void Server::apply_bundle_config(const control::BundleView& v) {
  const std::string admin = bundle_node_admin(v.body, cfg_.store.node_id);  // same helper as BundleStore::push
  auto pr = parse_memnode_dyn(v.body.config_toml, *dyn_base_, admin, v.body.generation);
  if (!pr.dyn) {
    count_config_rejected(pr.error.c_str());
    return;
  }
  if (!pr.unknown.empty()) {
    registry_.counter("miracache_config_unknown_keys_total", "Unknown keys ignored in config.cluster.memnode (rolling upgrades).")
        .inc(pr.unknown.size());
    std::string names;
    for (const auto& k : pr.unknown) names += (names.empty() ? "" : ",") + k;
    log::write(log::Level::Warn, "config", "unknown memnode config keys ignored", {{"keys", names}});
  }
  DynConfig next = *pr.dyn;
  next.drain_ms = dyn_.load()->drain_ms;  // node-local: only the local file (SIGHUP) sets it
  apply_dyn(std::make_shared<const DynConfig>(std::move(next)), "bundle");
}

void Server::apply_principals(const control::BundleView& v) {
  // Identity -> principal bindings come from the bundle alone: lab bindings go, identities that vanish or change
  // principal are revoked (tickets and connections), the rest are (re)bound.
  std::map<std::string, store::PrincipalId> want;
  for (const auto& p : v.sec.principals)
    for (const auto& identity : p.identities) want[identity] = p.id;
  std::uint64_t revoked = 0;
  for (const auto& identity : tickets_.principals().identities()) {
    auto w = want.find(identity);
    auto old = tickets_.principals().find(identity);
    if (w == want.end() || !old || *old != w->second) {
      remove_identity(identity);
      ++revoked;
    }
  }
  for (const auto& [identity, pid] : want) tickets_.principals().add(identity, pid);
  bundle_identities_ = want;
  if (revoked > 0)
    registry_.counter("miracache_bundle_identities_revoked_total", "Identities unbound by an applied bundle.").inc(revoked);

  // Quota (QT3).
  std::uint64_t w_self = 1, sum_active = 0;
  bool self_active = false;
  for (const auto& n : v.body.nodes) {
    if (n.state == control::MemberState::Active) sum_active += n.weight;
    if (n.node_id == cfg_.store.node_id) {
      w_self = n.weight;
      self_active = n.state == control::MemberState::Active;
    }
  }
  caps_.clear();
  for (const auto& p : v.sec.principals) {
    const std::uint64_t cap = quota_cap(p.quota_bytes, w_self, sum_active, self_active);
    caps_[p.id] = cap;
    store_->set_policy(p.id, policy_of(p));
  }
  // Cap series: the principal NAME is the label, top-K 16 by name, the rest summed under "_other"; a principal that
  // left the table reads 0 (the registry keeps the series).
  for (const auto& [name, g] : cap_gauges_) g->set(0);
  std::uint64_t other = 0;
  std::size_t k = 0;
  std::vector<const control::PrincipalView*> sorted;
  for (const auto& p : v.sec.principals) sorted.push_back(&p);
  std::sort(sorted.begin(), sorted.end(), [](auto* a, auto* b) { return a->name < b->name; });
  for (const auto* p : sorted) {
    if (k++ >= 16) {
      other += caps_[p->id];
      continue;
    }
    auto& g = cap_gauges_[p->name];
    if (!g) g = &registry_.gauge("miracache_principal_cap_bytes", "Per-node byte cap of a principal (QT3).", {{"principal", p->name}});
    g->set(static_cast<std::int64_t>(std::min<std::uint64_t>(caps_[p->id], INT64_MAX)));
  }
  if (other > 0 || cap_gauges_.count("_other")) {
    auto& g = cap_gauges_["_other"];
    if (!g) g = &registry_.gauge("miracache_principal_cap_bytes", "Per-node byte cap of a principal (QT3).", {{"principal", "_other"}});
    g->set(static_cast<std::int64_t>(std::min<std::uint64_t>(other, INT64_MAX)));
  }
  registry_.gauge("miracache_bundle_principals", "Principals in the applied bundle.").set(static_cast<std::int64_t>(v.sec.principals.size()));
}

void Server::apply_bundle(const control::BundleView& v) {
  view_ = std::make_shared<const control::BundleView>(v);
  applied_bundle_.generation = v.body.generation;
  applied_bundle_.sec_generation = v.sec.sec_generation;
  applied_bundle_.epoch = v.body.epoch;
  applied_bundle_.previous_epoch = v.body.previous_epoch;
  applied_bundle_.replicas = v.body.replicas;
  applied_bundle_.body_hash = v.body_hash;
  applied_bundle_.sec_hash = v.sec_hash;
  // Member state: derived fresh from this bundle, never from the previous state or the SIGTERM latch (P08).
  const MemberState before = applied_bundle_.member_state;
  MemberState ms = MemberState::Removed;
  for (const auto& n : v.body.nodes)
    if (n.node_id == cfg_.store.node_id)
      ms = n.state == control::MemberState::Active     ? MemberState::Active
           : n.state == control::MemberState::Draining ? MemberState::Draining
                                                       : MemberState::Readonly;
  applied_bundle_.member_state = ms;
  // MB4: the current-view placement, computed once here with the same functions the client uses (C2).
  place_view_ = control::view_from_bundle(v.body);
  place_r_ = std::clamp<std::uint32_t>(v.body.replicas, 1, 3);
  self_id_text_ = std::to_string(cfg_.store.node_id);
  if (ms != before)
    log::write(log::Level::Info, "bundle", "member state changed",
               {{"from", std::to_string(static_cast<int>(before))}, {"to", std::to_string(static_cast<int>(ms))},
                {"generation", std::to_string(v.body.generation)}, {"node_id", self_id_text_}});
  if (ms == MemberState::Removed && before != MemberState::Removed) {  // decision 10 step 4: GOAWAY, no new sessions
    log::write(log::Level::Info, "bundle", "removed from the membership: GOAWAY",
               {{"generation", std::to_string(v.body.generation)}, {"epoch", std::to_string(v.body.epoch)},
                {"node_id", self_id_text_}});
    goaway(proto::GoawayReason::Epoch, cfg_.goaway_drain_ms);
  }
  apply_principals(v);
  refresh_snapshot(false);
  for (const auto& p : v.sec.principals) {
    if (!p.drop_before) continue;
    auto [it, inserted] = drop_before_max_.emplace(p.name, *p.drop_before);
    if (!inserted && *p.drop_before > it->second) it->second = *p.drop_before;
  }
  apply_drop_before();
  apply_bundle_config(v);
  registry_.gauge("miracache_bundle_generation", "Generation of the applied bundle.")
      .set(static_cast<std::int64_t>(v.body.generation));
  registry_.gauge("miracache_bundle_sec_generation", "Security generation of the applied bundle.")
      .set(static_cast<std::int64_t>(v.sec.sec_generation));
  registry_.gauge("miracache_membership_epoch", "Membership epoch of the applied bundle.").set(v.body.epoch);
  for (std::size_t i = 0; i < 4; ++i)
    registry_.gauge("miracache_member_state", "This node's member state in the applied bundle (1 = current).",
                    {{"state", i == 0 ? "active" : i == 1 ? "draining" : i == 2 ? "readonly" : "removed"}})
        .set(static_cast<std::size_t>(ms) == i ? 1 : 0);
  if (v.body.unknown_keys > 0)
    registry_.counter("miracache_bundle_unknown_keys_total", "Unknown keys ignored under config.* in applied bundles.")
        .inc(v.body.unknown_keys);
}

void Server::count_request(std::uint16_t type, bool ok) {
  const int o = op_index(type);
  if (o >= 0) mx_->req[o][ok ? 0 : 1]->inc();
}

// Refreshes the gauges that mirror store-thread state. Counters need no refresh.
void Server::publish_gauges() {
  last_publish_ = clock_.now();
  mx_->lease_active->set(static_cast<std::int64_t>(store_->n_leases()));
  std::uint64_t used = 0, alloc = 0, free_blocks = 0;
  for (const auto& cs : slab_->class_stats()) {
    used += cs.allocated * cs.len;
    alloc += cs.allocated;
    free_blocks += cs.free;
  }
  const std::uint64_t total = static_cast<std::uint64_t>(slab_->total_runs()) * arena_->config().run_bytes;
  const std::uint32_t reg = std::min(mrs_->registered_segments(), arena_->config().n_segments);
  const std::uint64_t unreg = static_cast<std::uint64_t>(arena_->config().n_segments - reg) * arena_->config().segment_bytes;
  mx_->bytes[0]->set(static_cast<std::int64_t>(used));
  mx_->bytes[1]->set(static_cast<std::int64_t>(total > used + unreg ? total - used - unreg : 0));
  mx_->bytes[2]->set(static_cast<std::int64_t>(unreg));
  mx_->blocks[0]->set(static_cast<std::int64_t>(alloc));
  mx_->blocks[1]->set(static_cast<std::int64_t>(free_blocks));
  std::int64_t scopes = 0;
  for (store::PrincipalId p : tickets_.principals().principal_ids()) {
    scopes += static_cast<std::int64_t>(store_->n_scopes(p));
    if (auto* g = mx_->principal_gauge(p)) g->set(static_cast<std::int64_t>(store_->bytes_used(p)));
  }
  mx_->scope_open->set(scopes);
  refresh_snapshot(true);
  std::int64_t n[3] = {0, 0, 0};
  for (const auto& [id, c] : conns_)
    if (!c.dead) ++n[static_cast<std::size_t>(c.grant.cls) % 3];
  for (std::size_t i = 0; i < 3; ++i) mx_->conn[i]->set(n[i]);
}

Server::~Server() {
  // Endpoints belong to the fabric, which may outlive us: abort and release what we can.
  for (auto& [id, c] : conns_) {
    puts_->on_endpoint_down(id);
    c.ep->abort();
    (void)release_ep(c.ep);
  }
  for (auto* ep : dying_) (void)release_ep(ep);
}

Status Server::release_ep(fabric::Endpoint* ep) {
  auto it = ep_dev_.find(ep->id());
  const std::uint32_t dev = it != ep_dev_.end() ? it->second : 0;
  Status st = fabrics_[dev]->release(ep);
  if (st && it != ep_dev_.end()) ep_dev_.erase(it);
  return st;
}

Status Server::start() {
  if (listening_) return {};
  std::vector<fabric::RailAddr> rails = cfg_.rails;
  if (rails.empty()) rails.emplace_back();
  for (std::size_t i = 0; i < rails.size(); ++i) {
    fabric::ListenParams lp;
    lp.addr = rails[i];
    // The listener index is the rail: a ticket for rail r is only good on listener r.
    lp.admit = [this, i](std::span<const std::byte> p) { return admit(p, i); };
    if (auto st = fabrics_[rail_dev(i)]->listen([this, i](fabric::Endpoint* e) { on_accept(e, i); }, lp); !st) return st;
  }
  listening_ = true;
  refresh_rail_health();  // identity is right from the first request
  return {};
}

// RL1: per-rail health (decision 11) and the rail gauges. A rail is up when its device port is ACTIVE, its listener
// is alive and the device has had no fatal async event in the last 10 s.
void Server::refresh_rail_health() {
  last_rail_poll_ = clock_.now();
  std::vector<fabric::FabricHealth> fh;
  fh.reserve(fabrics_.size());
  for (auto* f : fabrics_) fh.push_back(f->health());
  std::vector<std::size_t> seen(fabrics_.size(), 0);  // listen() calls so far per fabric = the listener's position
  std::vector<RailHealth> out;
  for (std::size_t r = 0; r < n_rails(); ++r) {
    const std::uint32_t d = rail_dev(r);
    const std::size_t pos = seen[d]++;
    RailHealth h;
    h.rail = static_cast<std::uint32_t>(r);
    const fabric::RailAddr ra = cfg_.rails.empty() ? fabric::RailAddr{} : cfg_.rails[r];
    h.addr = (ra.host.empty() ? "0.0.0.0" : ra.host) + ':' + std::to_string(ra.port);
    h.device = d < cfg_.device_names.size() ? cfg_.device_names[d] : "";
    h.port_state = fh[d].port_state;
    h.listener_ok = listening_ && (pos >= fh[d].listener_ok.size() || fh[d].listener_ok[pos]);
    h.up = h.port_state == "ACTIVE" && h.listener_ok && !fh[d].fatal_recent;
    registry_
        .gauge("miracache_rail_state", "Memory-node rail state: 1 = up (port ACTIVE, listener alive, no recent fatal event), 0 = down.",
               {{"hostname", log::hostname()}, {"rail", std::to_string(r)}, {"addr", h.addr}, {"device", h.device}})
        .set(h.up ? 1 : 0);
    out.push_back(std::move(h));
  }
  // Live endpoints per class and rail.
  std::vector<std::int64_t> n(3 * n_rails(), 0);
  for (const auto& [id, c] : conns_)
    if (!c.dead && c.grant.rail < n_rails()) ++n[static_cast<std::size_t>(c.grant.cls) % 3 * n_rails() + c.grant.rail];
  for (std::size_t cl = 0; cl < 3; ++cl)
    for (std::size_t r = 0; r < n_rails(); ++r)
      registry_.gauge("miracache_qp_active", "Live queue pairs, by class and rail.",
                      {{"class", kClassNames[cl]}, {"rail", std::to_string(r)}})
          .set(n[cl * n_rails() + r]);
  std::lock_guard<std::mutex> g(snap_mu_);
  for (const auto& h : out) {  // a transition is logged once (the process identity already carries node_id, host, addr)
    const bool was = snap_.rails.size() > h.rail ? snap_.rails[h.rail].up : true;
    if (was != h.up)
      log::write(h.up ? log::Level::Info : log::Level::Warn, "rail", h.up ? "rail up" : "rail down",
                 {{"rail", std::to_string(h.rail)}, {"addr", h.addr}, {"device", h.device},
                  {"port_state", h.port_state}, {"listener_ok", h.listener_ok ? "true" : "false"}});
  }
  snap_.rails = std::move(out);
}

std::size_t Server::principal_conns(store::PrincipalId p) const {
  std::size_t n = 0;
  for (const auto& [id, c] : conns_)
    if (!c.dead && c.grant.principal == p) ++n;
  for (const auto& [id, a] : admitted_)
    if (a.grant.principal == p) ++n;
  return n;
}

Expected<fabric::Admission> Server::admit(std::span<const std::byte> priv, std::size_t listener) {
  if (refusing_sessions()) {  // r6 A8: no new session during the drain (or once removed, MB4); refused before redeem, so no ticket is spent
    mx_->tk_reject[4]->inc();
    return Error{ErrorCode::Busy, "server: draining"};
  }
  auto g = tickets_.redeem(priv);  // consumed even when refused below
  if (!g) {
    mx_->tk_reject[g.error().code == ErrorCode::AccessDenied ? 0 : g.error().code == ErrorCode::Timeout ? 1 : 4]->inc();
    return g.error();
  }
  if (g->rail != listener) {
    mx_->tk_reject[2]->inc();
    return Error{ErrorCode::AccessDenied, "server: ticket rail does not match the listener"};
  }
  if (principal_conns(g->principal) >= cfg_.max_conns_per_principal) {
    mx_->tk_reject[3]->inc();
    return Error{ErrorCode::ResourceExhausted, "server: too many connections for this principal"};
  }
  admitted_[g->id] = Admitted{*g, clock_.now()};
  const std::uint32_t dev = rail_dev(listener);
  return fabric::Admission{g->cls, g->cls == fabric::EpClass::Ingest ? ingest_pds_[dev] : fetch_pds_[dev]};
}

void Server::on_accept(fabric::Endpoint* ep, std::size_t rail) {
  ep_dev_[ep->id()] = rail_dev(rail);
  auto t = proto::decode_ticket(ep->peer_private_data());
  TicketId id{};
  if (t) std::memcpy(id.data(), t->id, 16);
  auto it = t ? admitted_.find(id) : admitted_.end();
  if (it == admitted_.end()) {  // cannot happen with a correct fabric: admit() ran first
    ep->abort();
    dying_.push_back(ep);
    return;
  }
  Conn c;
  c.ep = ep;
  c.grant = it->second.grant;
  c.accepted_at = c.last_rx = clock_.now();
  admitted_.erase(it);
  conns_[ep->id()] = c;
}

void Server::kill(fabric::EndpointId id) {
  auto it = conns_.find(id);
  if (it == conns_.end() || it->second.dead) return;
  it->second.dead = true;
  it->second.ep->abort();  // stops further traffic; tick() reaps (drop_conn) outside any handler
}

void Server::remove_identity(const std::string& identity) {
  tickets_.remove_identity(identity);
  for (auto it = admitted_.begin(); it != admitted_.end();)
    it = it->second.grant.identity == identity ? admitted_.erase(it) : std::next(it);
  std::vector<fabric::EndpointId> ids;
  for (auto& [id, c] : conns_)
    if (c.grant.identity == identity) ids.push_back(id);
  for (auto id : ids) drop_conn(id);
}

void Server::add_lease(store::LeaseId id, const LeaseRec& rec) {
  if (auto old = leases_.find(id); old != leases_.end()) erase_lease(old);
  LeaseRec r = rec;
  r.by_expiry = lease_expiry_.emplace(r.expiry, id);
  ++lease_count_[r.principal];
  leases_[id] = r;
}

void Server::erase_lease(std::map<store::LeaseId, LeaseRec>::iterator it) {
  lease_expiry_.erase(it->second.by_expiry);
  if (auto c = lease_count_.find(it->second.principal); c != lease_count_.end() && --c->second == 0) lease_count_.erase(c);
  leases_.erase(it);
}

// Pops expired leases off the front of the expiry index: O(expired), O(1) when none is due.
void Server::purge_leases(Nanos now) {
  while (!lease_expiry_.empty() && now >= lease_expiry_.begin()->first) {
    auto it = leases_.find(lease_expiry_.begin()->second);
    if (it != leases_.end()) erase_lease(it);
    else lease_expiry_.erase(lease_expiry_.begin());
  }
}

std::size_t Server::live_leases(store::PrincipalId p) {
  purge_leases(clock_.now());
  auto it = lease_count_.find(p);
  return it == lease_count_.end() ? 0 : it->second;
}

void Server::drop_conn(fabric::EndpointId id) {
  auto it = conns_.find(id);
  if (it == conns_.end()) return;
  Conn c = it->second;
  conns_.erase(it);
  puts_->on_endpoint_down(id);
  if (c.hello) {
    auto sit = sessions_.find({c.grant.principal, c.conn_id});
    if (sit != sessions_.end() && --sit->second.refs == 0) {
      store_->on_session_end(sit->second.id);
      for (auto it2 = leases_.begin(); it2 != leases_.end();) {
        if (it2->second.session == sit->second.id) {
          auto del = it2++;
          erase_lease(del);
        } else {
          ++it2;
        }
      }
      sessions_.erase(sit);
    }
  }
  c.ep->abort();
  dying_.push_back(c.ep);
}

// ---- senders ---------------------------------------------------------------------------
void Server::send_body(fabric::EndpointId id, Op op, std::uint64_t rid, std::size_t body_len, std::uint16_t extra) {
  auto it = conns_.find(id);
  if (it == conns_.end() || it->second.dead) return;
  FrameHeader h = proto::header_for(op, rid);
  h.flags |= extra;
  if (view_) {  // MB4: every reply carries the node's epoch and bundle generation (bundle mode only)
    h.epoch = applied_bundle_.epoch;
    h.bundle_gen_lo = static_cast<std::uint32_t>(applied_bundle_.generation);
  }
  auto n = proto::encode_frame(h, std::span<const std::byte>(body_buf_.data(), body_len), frame_buf_);
  if (!n) return;  // an oversized or malformed reply is a server bug; the client times out
  fabric::Frame f;
  f.bytes.assign(frame_buf_.begin(), frame_buf_.begin() + static_cast<std::ptrdiff_t>(*n));
  if (!it->second.ep->post_send(std::move(f), 0)) kill(id);
}

void Server::send_error(fabric::EndpointId id, const FrameHeader& req, WireStatus st, std::uint32_t retry_ms) {
  ++err_replies_;
  count_request(req.type, false);
  auto it = conns_.find(id);
  if (it == conns_.end() || it->second.dead) return;
  FrameHeader stamped = req;
  if (view_) {  // MB4: a refusal tells the sender where this node is (StaleEpoch above all)
    stamped.epoch = applied_bundle_.epoch;
    stamped.bundle_gen_lo = static_cast<std::uint32_t>(applied_bundle_.generation);
  }
  auto n = proto::encode_error_reply_frame(stamped, proto::ErrorReply{static_cast<std::uint16_t>(st), retry_ms}, frame_buf_);
  if (!n) return;
  fabric::Frame f;
  f.bytes.assign(frame_buf_.begin(), frame_buf_.begin() + static_cast<std::ptrdiff_t>(*n));
  if (!it->second.ep->post_send(std::move(f), 0)) kill(id);
}

void Server::send_seg_table(Conn& c) {
  if (c.dead || c.grant.cls != fabric::EpClass::Control) return;
  auto m = std::make_unique<proto::SegTable>();
  const std::uint32_t nseg = std::min<std::uint32_t>(mrs_->registered_segments(), proto::kMaxSegEntries);
  m->n = static_cast<std::uint16_t>(nseg);
  const std::size_t nr = std::min<std::size_t>(n_rails(), proto::kMaxRails);
  m->n_rails = static_cast<std::uint8_t>(nr);
  m->local_rail = static_cast<std::uint8_t>(std::min<std::size_t>(c.grant.rail, nr - 1));
  m->table_gen = table_gen_;
  // Rkeys are per device: rail r carries the rkeys of the MRs registered on its device (rails on one device share).
  for (std::size_t r = 0; r < nr; ++r)
    if (const auto* a = mrs_->array_mr(rail_dev(r))) {
      m->sg_base = reinterpret_cast<std::uint64_t>(a->addr);
      m->sg_slots = a->len / 8;
      m->sg_rkey[r] = a->rkey;
    }
  for (std::uint32_t i = 0; i < nseg; ++i) {
    m->e[i].seg_id = i;
    // Q2: block offsets are relative to the segment base, so `base` stays the segment base; the registered MR is
    // only the data runs, so `len` ends where they end (the NIC refuses anything outside the MR, whatever a client
    // does with this table).
    const fabric::MemRegion v = mrs_->segment_view(i, rail_dev(0));
    m->e[i].base = reinterpret_cast<std::uint64_t>(v.addr);
    m->e[i].len = v.len;
    for (std::size_t r = 0; r < nr; ++r) m->e[i].rkey[r] = mrs_->segment_mr(i, rail_dev(r))->rkey;
  }
  auto n = proto::encode_seg_table(*m, body_buf_);
  if (n) send_body(c.ep->id(), Op::SEG_TABLE, 0, *n);
}

void Server::goaway(proto::GoawayReason why, std::uint32_t drain_ms) {
  std::vector<fabric::EndpointId> ids;
  for (auto& [id, c] : conns_)
    if (c.hello && c.grant.cls == fabric::EpClass::Control) ids.push_back(id);
  for (auto id : ids) {
    proto::Goaway g;
    g.reason = static_cast<std::uint32_t>(why);
    g.drain_ms = drain_ms;
    if (auto n = proto::encode_goaway(g, body_buf_)) send_body(id, Op::GOAWAY, 0, *n);
  }
}

void Server::begin_drain(proto::GoawayReason why, std::uint32_t drain_ms) {
  draining_ = true;
  scrub_->stop();  // SC1: a draining node starts no new scrub checks
  drain_deadline_ = clock_.now() + std::chrono::milliseconds(drain_ms);
  goaway(why, drain_ms);
}

bool Server::admin_drain(std::uint32_t drain_ms) {
  if (draining_) return false;
  begin_drain(proto::GoawayReason::Shutdown, drain_ms);
  return true;
}

Status Server::drop_principal_local(const std::string& name, std::int64_t drop_before_unix_s) {
  // U2-02: a cutoff ahead of the wall clock would be stored max-only but converted once (clamped to now): a later real
  // cutoff below it would silently do nothing. Same rule and skew as a bundle's drop_before.
  if (drop_before_unix_s > wall_now_ns() / kNsPerSec + control::kDropBeforeSkewSeconds)
    return Error{ErrorCode::InvalidArgument, "server: drop_before is later than now + 300 s"};
  if (view_) {
    bool known = false;
    for (const auto& p : view_->sec.principals) known = known || p.name == name;
    if (!known) return Error{ErrorCode::NotFound, "server: no such principal in the applied bundle"};
  }
  auto [it, inserted] = drop_before_max_.emplace(name, drop_before_unix_s);
  if (!inserted && drop_before_unix_s > it->second) it->second = drop_before_unix_s;
  apply_drop_before();
  return {};
}

Status Server::shutdown_clean() {
  // r8b Q04: with drain_ms == 0 begin_drain never ran; the fence loop below polls, so no new session
  // may be admitted while it runs.
  draining_ = true;
  scrub_->stop();  // SC1: no new checks (in-flight ones were finished by the caller draining the executor)
  admitted_.clear();
  std::vector<fabric::EndpointId> ids;
  for (auto& [id, c] : conns_) ids.push_back(id);
  for (auto id : ids) drop_conn(id);
  puts_->tick();  // retries fences that failed earlier (limbo)
  // r7 R08: one failed fence must not cost the warm restart. Retry a few times (bounded: a handful of
  // polls), letting the dropped QPs' flushes land in between.
  // r8 N05: each retry polls up to 10 ms (returns early on a completion), at most ~150 ms in all, so the
  // flushes have time to land instead of 8 retries back to back (µs).
  // r8b Q01: the 150 ms clock is the bound. A poll returns as soon as it has a completion, so flushes
  // trickling in one per poll may take many iterations; only idle ones (nothing polled) count against
  // the frozen-clock guard (the sim ignores the poll budget), plus a hard cap for a frozen clock with
  // completions that never stop.
  const Nanos fence_until = clock_.now() + std::chrono::milliseconds(150);
  constexpr int kIdleGuard = 32, kHardGuard = 4096;
  for (int idle = 0, i = 0; idle < kIdleGuard && i < kHardGuard && puts_->n_limbo() != 0; ++i) {
    if (run_once(fabric::PollBudget{std::chrono::milliseconds(10)}) == 0) ++idle;
    puts_->tick();
    if (clock_.now() >= fence_until) break;
  }
  if (puts_->n_puts() != 0) return Error{ErrorCode::Busy, "server: puts still in flight at exit"};
  if (puts_->n_limbo() != 0) return Error{ErrorCode::Busy, "server: write MRs not fenced at exit"};
  return arena_->shutdown_clean();
}

Nanos Server::next_wake_in() const {
  if (last_tick_ < Nanos{0}) return Nanos{0};
  const Nanos due = last_tick_ + std::max(cfg_.tick_interval, cfg_.idle_tick) - clock_.now();
  return std::max(Nanos{0}, due);
}

// ---- main loop -------------------------------------------------------------------------
std::size_t Server::run_once(fabric::PollBudget budget) {
  std::size_t work = 0;
  std::array<fabric::Completion, 32> out;
  // RL1: one fabric per device, polled round robin; the busy-spin budget is shared between them.
  const std::size_t nf = fabrics_.size();
  fabric::PollBudget share = budget;
  share.busy = budget.busy / static_cast<std::int64_t>(nf);
  for (std::size_t k = 0; k < nf; ++k) {
  const std::size_t n = fabrics_[(poll_rr_ + k) % nf]->poll(out, share);
  for (std::size_t i = 0; i < n; ++i) {
    auto& c = out[i];
    ++work;
    if (c.op == fabric::CompletionOp::CqError && c.endpoint == 0) {  // CQ-level event
      mx_->rdma_err[4]->inc();
      continue;
    }
    if (!c.status) {
      // The fabric reports a code, not the verbs status: Timeout = retry exceeded, AccessDenied
      // = remote access error, Aborted = flushed; RNR is not distinguishable (-> other).
      const auto code = c.status.error().code;
      mx_->rdma_err[code == ErrorCode::Timeout ? 0 : code == ErrorCode::Aborted ? 2 : code == ErrorCode::AccessDenied ? 3 : 4]
          ->inc();
      drop_conn(c.endpoint);  // flushed or failed work request: the QP is dead
      continue;
    }
    if (c.is_recv) on_frame(c.endpoint, c.frame.bytes);
  }
  }
  poll_rr_ = (poll_rr_ + 1) % nf;
  {
    auto step = mrs_->step_registration();
    if (!step) {
      ++reg_errors_;  // retried by the next call
    } else if (*step) {
      ++work;
      ++table_gen_;
      std::vector<fabric::EndpointId> ids;  // snapshot: re-find each conn, whatever happened to the others
      for (auto& [id, c] : conns_)
        if (c.hello && !c.dead && c.grant.cls == fabric::EpClass::Control) ids.push_back(id);
      for (auto id : ids)
        if (auto it = conns_.find(id); it != conns_.end()) send_seg_table(it->second);
    }
  }
  const Nanos now = clock_.now();
  if (last_tick_ < Nanos{0} || now - last_tick_ >= cfg_.tick_interval) {
    last_tick_ = now;
    tick();
    if (last_publish_ < Nanos{0} || now - last_publish_ >= kPublishEvery) publish_gauges();
    if (listening_ && (last_rail_poll_ < Nanos{0} || now - last_rail_poll_ >= kRailPollEvery)) refresh_rail_health();
  }
  return work;
}

void Server::tick() {
  store_->tick();  // QT1: reaping, drop_before, cap-cut convergence and pressure under one budget (<= 64 blocks per turn)
  scrub_->step();  // SC1: <= 16 blocks per turn at scrub.bytes_per_s; the CRC runs on the executor
  puts_->tick();
  const Nanos now = clock_.now();
  if (last_sweep_ < Nanos{0} || now - last_sweep_ >= cfg_.sweep_interval) {
    last_sweep_ = now;
    tickets_.sweep();
  }
  for (auto it = admitted_.begin(); it != admitted_.end();)  // connect never completed
    it = now - it->second.at >= cfg_.admit_timeout ? admitted_.erase(it) : std::next(it);
  purge_leases(now);
  std::vector<fabric::EndpointId> dead;
  for (auto& [id, c] : conns_) {
    bool idle;
    if (c.hello) {  // idle is per session: a frame on any endpoint keeps all of them alive
      auto s = sessions_.find({c.grant.principal, c.conn_id});
      idle = s != sessions_.end() && now - s->second.last_rx >= cfg_.idle_timeout;
    } else {
      idle = now - c.last_rx >= cfg_.idle_timeout;
    }
    if (c.dead || c.ep->state() == fabric::EpState::Error ||
        (!c.hello && now - c.accepted_at >= cfg_.hello_deadline) || idle)
      dead.push_back(id);
  }
  for (auto id : dead) drop_conn(id);
  for (auto it = dying_.begin(); it != dying_.end();) {
    if ((*it)->drained() && release_ep(*it)) it = dying_.erase(it);
    else ++it;
  }
}

Status Server::check_invariants() const {
  if (auto s = store_->check_invariants(); !s) return s;
  if (auto s = slab_->check_invariants(); !s) return s;
  if (auto s = puts_->check_invariants(); !s) return s;
  if (epoch_violations_ != 0)  // NoPutOnReadOnly, RootPutAtReplica (MB4)
    return Error{ErrorCode::Corrupt, "server: a PUT_BEGIN was accepted against the epoch / member state / owner set rules"};
  return mrs_->check_invariants();
}

// ---- dispatch --------------------------------------------------------------------------
void Server::on_frame(fabric::EndpointId id, std::span<const std::byte> bytes) {
  auto cit = conns_.find(id);
  if (cit == conns_.end() || cit->second.dead) return;
  cit->second.last_rx = clock_.now();
  if (cit->second.hello) {
    if (auto s = sessions_.find({cit->second.grant.principal, cit->second.conn_id}); s != sessions_.end())
      s->second.last_rx = cit->second.last_rx;
  }
  auto fr = proto::decode_frame(bytes);
  if (!fr) {
    if (fr.error().close_qp) drop_conn(id);
    return;  // a Malformed header has no request id to answer
  }
  const FrameHeader& h = fr->h;
  if (h.flags & (proto::flag::RESPONSE | proto::flag::ERROR)) return;  // PONG, acks to our GOAWAY...
  if (auto op = proto::check_opcode(h.type); !op) {
    send_error(id, h, WireStatus::Unsupported);
    return;
  }
  Conn& c = cit->second;
  const auto op = static_cast<Op>(h.type);
  if (op == Op::HELLO) return on_hello(c, h, fr->body);
  if (!c.hello) return send_error(id, h, WireStatus::Malformed);  // HELLO first on every endpoint
  const bool put_op = op == Op::PUT_BEGIN || op == Op::PUT_COMMIT || op == Op::PUT_CANCEL;
  auto counted = [this](const FrameHeader& hh, const auto& fn) {
    const auto before = err_replies_;
    fn();
    if (err_replies_ == before) count_request(hh.type, true);
  };
  if (op == Op::PING) {
    auto m = proto::decode_ping(h, fr->body);
    if (!m) return send_error(id, h, m.error().status);
    if (auto n = proto::encode_pong(*m, body_buf_)) send_body(id, Op::PONG, h.request_id, *n);
    count_request(h.type, true);
    return;
  }
  if (c.grant.cls == fabric::EpClass::Fetch) return send_error(id, h, WireStatus::Unsupported);
  if (put_op != (c.grant.cls == fabric::EpClass::Ingest)) return send_error(id, h, WireStatus::Unsupported);
  switch (op) {
    case Op::STATS: {
      auto m = proto::decode_stats(h, fr->body);
      if (!m) return send_error(id, h, m.error().status);
      proto::StatsAck a;
      a.selector = m->selector;  // counters: TODO (telemetry)
      if (auto n = proto::encode_stats_ack(a, body_buf_)) send_body(id, Op::STATS_ACK, h.request_id, *n);
      count_request(h.type, true);
      return;
    }
    // requests_total{status}: error = the handler answered with an error frame (send_error).
    // PUT_COMMIT / PUT_CANCEL answer later; on_put_done counts them.
    case Op::LOOKUP: return counted(h, [&] { on_lookup(c, h, fr->body); });
    case Op::RENEW: return counted(h, [&] { on_renew(c, h, fr->body); });
    case Op::RELEASE: return counted(h, [&] { on_release(c, h, fr->body); });
    case Op::INVALIDATE: return counted(h, [&] { on_invalidate(c, h, fr->body); });
    case Op::PUT_BEGIN: return counted(h, [&] { on_put_begin(c, h, fr->body); });
    case Op::PUT_COMMIT: return on_put_commit(c, h, fr->body);
    case Op::PUT_CANCEL: return on_put_cancel(c, h, fr->body);
    default: return send_error(id, h, WireStatus::Unsupported);
  }
}

void Server::on_hello(Conn& c, const FrameHeader& h, std::span<const std::byte> body) {
  const auto id = c.ep->id();
  auto m = proto::decode_hello(h, body);
  if (!m) return send_error(id, h, m.error().status);
  if (c.hello || m->cls != static_cast<std::uint8_t>(c.grant.cls) || m->major_min > proto::kVerMajor ||
      m->major_max < proto::kVerMajor)
    return send_error(id, h, c.hello || m->cls != static_cast<std::uint8_t>(c.grant.cls) ? WireStatus::Malformed
                                                                                          : WireStatus::Unsupported);
  decltype(c.conn_id) conn_id;
  std::memcpy(conn_id.data(), m->conn_id, 16);
  // r6 A8: during the drain a HELLO that would start a new session is refused (an endpoint admitted
  // just before begin_drain). Endpoints of a session that already exists still join it.
  // r7 R10: the refused connection keeps no conn_id (it never joined a session).
  if (refusing_sessions() && !sessions_.count({c.grant.principal, conn_id})) return send_error(id, h, WireStatus::Draining);
  c.conn_id = conn_id;
  auto& sref = sessions_[{c.grant.principal, c.conn_id}];
  if (sref.refs++ == 0) sref.id = next_session_++;
  sref.last_rx = clock_.now();
  c.session = sref.id;
  c.hello = true;
  proto::HelloAck a;
  a.major_min = a.major_max = proto::kVerMajor;
  a.minor = proto::kVerMinor;
  a.cls = m->cls;
  const auto rd = c.ep->read_depth();
  a.ird = rd.ird;
  a.ord = rd.ord;
  a.rail = c.grant.rail;
  a.proto = cfg_.wire_protocol;
  a.features = 0;  // intersection with the client's features; none defined in v0
  a.node_id = cfg_.store.node_id;
  a.mtu = cfg_.mtu;
  std::memcpy(a.conn_id, m->conn_id, 16);
  // H02: the boot nonce as a non-critical TLV (an older client skips it; CRITICAL_EXT stays clear). K03: then the largest
  // stored block this node places (store.run_bytes), non-critical too, so the client refuses an oversized put locally and
  // the engine adapters refuse at start-up.
  std::array<std::byte, proto::kBootNonceTlvSize + proto::kMaxStoredBlockTlvSize + proto::kMaxHostnameTlvSize> tl{};
  std::size_t tn = 0;
  if (auto t = proto::encode_boot_nonce_tlv(boot_nonce_, std::span<std::byte>(tl).first(proto::kBootNonceTlvSize)); t)
    tn += *t;
  if (auto t = proto::encode_max_stored_block_tlv(cfg_.store.run_bytes, std::span<std::byte>(tl).subspan(tn)); t)
    tn += *t;
  // F5: then the node's hostname (the value its own logs carry), so a static/lab-mode client can name it. Left out when it
  // cannot be encoded (empty, over 255 B, not printable): the client then says "unknown".
  if (auto t = proto::encode_hostname_tlv(log::hostname(), std::span<std::byte>(tl).subspan(tn)); t) tn += *t;
  a.tlvs = std::span<const std::byte>(tl.data(), tn);
  auto n = proto::encode_hello_ack(a, body_buf_);
  if (!n) return send_error(id, h, WireStatus::Malformed);
  send_body(id, Op::HELLO_ACK, h.request_id, *n);
  send_seg_table(c);  // Control only (see send_seg_table)
  if (draining_ && c.grant.cls == fabric::EpClass::Control) {  // joined during the drain: tell it at once
    proto::Goaway g;
    g.reason = static_cast<std::uint32_t>(proto::GoawayReason::Shutdown);
    const Nanos left = std::max(Nanos{0}, drain_deadline_ - clock_.now());
    g.drain_ms = static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(left).count());
    if (auto gn = proto::encode_goaway(g, body_buf_)) send_body(id, Op::GOAWAY, 0, *gn);
  } else if (refusing_sessions() && c.grant.cls == fabric::EpClass::Control) {  // removed (MB4): same, reason Epoch
    proto::Goaway g;
    g.reason = static_cast<std::uint32_t>(proto::GoawayReason::Epoch);
    g.drain_ms = cfg_.goaway_drain_ms;
    if (auto gn = proto::encode_goaway(g, body_buf_)) send_body(id, Op::GOAWAY, 0, *gn);
  }
}

void Server::on_lookup(Conn& c, const FrameHeader& h, std::span<const std::byte> body) {
  const auto id = c.ep->id();
  auto m = proto::decode_lookup(h, body);
  if (!m) return send_error(id, h, m.error().status);
  store::LookupReq q;
  q.principal = c.grant.principal;
  std::memcpy(q.scope.data(), m->scope_id, 32);
  q.keys.assign(m->key_hash.begin(), m->key_hash.begin() + m->n);
  const bool want_lease = (m->flags & 1) != 0;
  store::LookupAck ack;
  if (want_lease && live_leases(c.grant.principal) >= cfg_.max_leases_per_principal) {
    // Over the principal's lease cap: the same all-MISS, lease-0 ack the store gives over its
    // per-session cap (always valid on wire v0; the client recomputes).
    ack.entries.resize(q.keys.size());
  } else {
    ack = store_->lookup(c.session, q);
  }
  {  // every requested key is exactly one of hit / miss
    std::uint64_t hits = 0;
    for (std::size_t i = 0; i < q.keys.size(); ++i)
      if (i < ack.entries.size() && ack.entries[i].hit) ++hits;
    mx_->lookup[0]->inc(hits);
    mx_->lookup[1]->inc(q.keys.size() - hits);
  }
  if (want_lease && ack.lease != 0) {
    add_lease(ack.lease, LeaseRec{c.grant.principal, c.session, ack.lease_expiry, {}});
    mx_->lease_granted->inc();
  }
  if (!want_lease && ack.lease != 0) {  // PROBE: no lease may outlive the call
    (void)store_->release(c.session, ack.lease);
    ack.lease = 0;
  }
  auto w = std::make_unique<proto::LookupAck>();
  w->lease_id = ack.lease;
  w->ttl_ms = ack.lease ? to_ms(ack.lease_expiry - clock_.now()) : 0;
  w->n = m->n;
  for (std::size_t i = 0; i < m->n && i < ack.entries.size(); ++i) {
    const auto& e = ack.entries[i];
    if (!e.hit) continue;
    auto& o = w->e[i];
    o.status = 1;
    o.seg_id = e.seg_id;
    o.offset = e.offset;
    o.stored_len = e.stored_len;
    o.gen = e.gen;
    o.gen_slot = e.gen_slot;
  }
  auto n = proto::encode_lookup_ack(*w, body_buf_);
  if (!n) return send_error(id, h, WireStatus::Malformed);
  send_body(id, Op::LOOKUP_ACK, h.request_id, *n);
}

void Server::on_renew(Conn& c, const FrameHeader& h, std::span<const std::byte> body) {
  const auto id = c.ep->id();
  auto m = proto::decode_renew(h, body);
  if (!m) return send_error(id, h, m.error().status);
  proto::RenewAck a;
  a.lease_id = m->lease_id;
  auto r = store_->renew(c.session, m->lease_id);
  if (r) {
    a.status = 0;
    mx_->lease_renew->inc();
    a.ttl_ms = to_ms(*r - clock_.now());
    if (auto l = leases_.find(m->lease_id); l != leases_.end()) {
      LeaseRec rec = l->second;
      rec.expiry = *r;
      erase_lease(l);
      add_lease(m->lease_id, rec);
    }
  } else {
    a.status = 1;  // EXPIRED (D3)
  }
  auto n = proto::encode_renew_ack(a, body_buf_);
  if (n) send_body(id, Op::RENEW_ACK, h.request_id, *n);
}

void Server::on_release(Conn& c, const FrameHeader& h, std::span<const std::byte> body) {
  auto m = proto::decode_release(h, body);
  if (!m) return send_error(c.ep->id(), h, m.error().status);
  if (store_->release(c.session, m->lease_id)) {  // no reply (idempotent)
    if (auto l = leases_.find(m->lease_id); l != leases_.end()) erase_lease(l);
  }
}

void Server::on_invalidate(Conn& c, const FrameHeader& h, std::span<const std::byte> body) {
  const auto id = c.ep->id();
  auto m = proto::decode_invalidate(h, body);
  if (!m) return send_error(id, h, m.error().status);
  store::ScopeId s;
  store::KeyHash k;
  std::memcpy(s.data(), m->scope_id, 32);
  std::memcpy(k.data(), m->key_hash, 32);
  if (auto st = store_->invalidate(c.grant.principal, s, k, m->gen); !st)
    return send_error(id, h, WireStatus::Busy, 100);  // 10/s limit (spec 8.3)
  auto n = proto::encode_invalidate_ack(proto::InvalidateAck{}, body_buf_);
  if (n) send_body(id, Op::INVALIDATE_ACK, h.request_id, *n);
}

void Server::on_put_begin(Conn& c, const FrameHeader& h, std::span<const std::byte> body) {
  const auto id = c.ep->id();
  auto m = proto::decode_put_begin(h, body);
  if (!m) return send_error(id, h, m.error().status);
  bool any_root = false;
  for (std::size_t i = 0; i < m->n; ++i) any_root = any_root || is_zero16(m->e[i].parent_hash);
  store::ScopeId scope_id;
  std::memcpy(scope_id.data(), m->scope_id, 32);
  if (view_) {  // MB4, decision 8 (bundle mode only; lab mode is unchanged below)
    const std::uint32_t mine = applied_bundle_.epoch;
    if (h.epoch != mine) {  // lower: the sender is behind, retry 0; higher: this node lags, retry in 50 ms
      count_epoch_refusal("stale_epoch");
      return send_error(id, h, WireStatus::StaleEpoch, h.epoch > mine ? 50 : 0);
    }
    const MemberState ms = applied_bundle_.member_state;
    if (ms == MemberState::Readonly || ms == MemberState::Removed) {  // NoPutOnReadOnly: no PUT_BEGIN at all
      count_epoch_refusal(ms == MemberState::Readonly ? "readonly" : "removed");
      return send_error(id, h, WireStatus::Draining);
    }
    if (any_root) {
      if (!accepts_root_puts()) {  // draining member state or the SIGTERM latch
        count_epoch_refusal(draining_ ? "latch" : "draining");
        return send_error(id, h, WireStatus::Draining);
      }
      if (!in_owner_set(scope_id)) {  // RootPutAtReplica: SKIP every key, nothing is created
        count_epoch_refusal("not_owner");
        return send_skip_all(id, h, m->n);
      }
    }
  }
  if (draining_) {  // a root block starts a new chain: refuse it; children of chains already begun may finish
    for (std::size_t i = 0; i < m->n; ++i)
      if (is_zero16(m->e[i].parent_hash)) return send_error(id, h, WireStatus::Draining);
  }
  // A block longer than a slab run can never be placed (retrying cannot help): refuse it at once, loudly. Without this the
  // client only saw a bare Malformed error reply, turned it into status ABORTED and nothing was logged on the node.
  // stored_len = 64 B header + payload + 16 B tag per segment, so the largest payload is a little under run_bytes.
  for (std::size_t i = 0; i < m->n; ++i) {
    if (m->e[i].stored_len <= cfg_.store.run_bytes) continue;
    registry_.counter("miracache_put_too_large_total", "PUT_BEGINs refused because a block is larger than store.run_bytes.").inc();
    // K10: a mis-sized engine sends this on every put; log it once per (principal, size class) per minute, with the
    // count of refusals dropped since the last line. Size class = bit width of stored_len (a power-of-two bucket).
    const std::uint64_t len = m->e[i].stored_len;
    const std::string key = std::to_string(c.grant.principal) + "/" + std::to_string(std::bit_width(len));
    if (auto dropped = too_large_log_.admit(key, clock_.now())) {
      const std::string peer = c.ep->peer_addr();
      log::write(log::Level::Warn, "put", "PUT_BEGIN refused: block larger than store.run_bytes (raise run_bytes on this node)",
                 {{"stored_len", std::to_string(len)},
                  {"max_stored_block_bytes", std::to_string(cfg_.store.run_bytes)},
                  {"key_index", std::to_string(i)},
                  {"principal", std::to_string(c.grant.principal)},
                  {"identity", c.grant.identity},
                  {"peer", peer.empty() ? std::string("unknown") : peer},
                  {"suppressed", std::to_string(*dropped)}});
    }
    return send_error(id, h, WireStatus::Malformed);
  }
  store::PutBeginReq q;
  q.principal = c.grant.principal;
  std::memcpy(q.scope.data(), m->scope_id, 32);
  for (std::size_t i = 0; i < m->n; ++i) {
    const auto& e = m->e[i];
    store::PutKey k;
    std::memcpy(k.key.data(), e.key_hash, 32);
    if (!is_zero16(e.parent_hash)) {
      std::span<const std::uint8_t, 16> pre(e.parent_hash);
      if (auto full = store_->resolve_parent(q.principal, q.scope, pre)) k.parent = *full;
      else std::memcpy(k.parent.data(), e.parent_hash, 16);  // unknown parent: commit will refuse (NoOrphanTail)
    }
    k.chain_pos = e.chain_pos;
    k.stored_len = e.stored_len;
    q.keys.push_back(k);
  }
  q.device = rail_dev(c.grant.rail);  // RL1: the put's write MRs are registered on its ingest rail's device
  auto ack = puts_->put_begin(id, q);
  if (ack.status == store::BeginStatus::Malformed) return send_error(id, h, WireStatus::Malformed);
  if (view_ && ack.status == store::BeginStatus::Ok && ack.put_id != 0) {  // ghost: what was accepted must pass decision 8
    // Independent of the gate (review w4 V11): nothing here calls the gate's helpers or reads applied_bundle_; the
    // state, epoch and owner set are recomputed from the applied bundle itself and the frame fields.
    bool listed = false, active = false, draining = false;
    for (const auto& bn : view_->body.nodes)
      if (bn.node_id == cfg_.store.node_id) {
        listed = true;
        active = bn.state == control::MemberState::Active;
        draining = bn.state == control::MemberState::Draining;
      }
    // Not listed = removed; neither active nor draining = readonly: both refuse any PUT_BEGIN. A root batch also
    // needs active and no SIGTERM latch.
    const bool bad_state = !listed || !(active || draining) || (any_root && (!active || draining_));
    if (bad_state || h.epoch != view_->body.epoch ||
        (any_root && !Server::bundle_owns(*view_, cfg_.store.node_id, scope_id)))
      ++epoch_violations_;
  }
  auto w = std::make_unique<proto::PutBeginAck>();
  w->put_id = ack.put_id;
  w->status = ack.status == store::BeginStatus::Ok ? 0 : 1;
  w->retry_after_ms = ack.retry_after_ms;
  if (w->status == 0) {
    w->n_mr = static_cast<std::uint8_t>(std::min<std::size_t>(ack.mr.size(), proto::kMaxRails));
    for (std::size_t i = 0; i < w->n_mr; ++i) w->mr[i] = proto::MrEntry{ack.mr[i].addr, ack.mr[i].len, ack.mr[i].rkey};
    w->n = static_cast<std::uint16_t>(ack.entries.size());
    for (std::size_t i = 0; i < ack.entries.size() && i < proto::kMaxPutKeys; ++i) {
      if (!ack.entries[i].accept) continue;
      w->e[i] = proto::PutBeginAckEntry{1, ack.entries[i].mr_index, ack.entries[i].offset};
    }
  }
  auto n = proto::encode_put_begin_ack(*w, body_buf_);
  if (!n) return send_error(id, h, WireStatus::Malformed);
  send_body(id, Op::PUT_BEGIN_ACK, h.request_id, *n);
}

namespace {
bool owns_in(const View& v, const std::string& id_text, std::size_t r, const store::ScopeId& scope) {
  for (std::size_t i : owner_set(v, std::span<const std::uint8_t, 32>(scope), r))
    if (v.nodes[i].id == id_text) return true;
  return false;
}
}  // namespace

bool Server::in_owner_set(const store::ScopeId& scope) const {
  return view_ && owns_in(place_view_, self_id_text_, place_r_, scope);
}

bool Server::bundle_owns(const control::BundleView& v, std::uint32_t node_id, const store::ScopeId& scope) {
  return owns_in(control::view_from_bundle(v.body), std::to_string(node_id), std::clamp<std::uint32_t>(v.body.replicas, 1, 3), scope);
}

void Server::count_epoch_refusal(const char* reason) {
  registry_.counter("miracache_put_epoch_refused_total", "PUT_BEGINs refused or skipped by epoch, member state or owner set (MB4).",
                    {{"reason", reason}})
      .inc();
}

// SKIP for every key: PUT_BEGIN_ACK status OK, no entry accepted, no put created.
void Server::send_skip_all(fabric::EndpointId id, const FrameHeader& req, std::size_t n) {
  auto w = std::make_unique<proto::PutBeginAck>();
  w->n = static_cast<std::uint16_t>(n);
  auto len = proto::encode_put_begin_ack(*w, body_buf_);
  if (!len) return send_error(id, req, WireStatus::Malformed);
  send_body(id, Op::PUT_BEGIN_ACK, req.request_id, *len);
}

void Server::send_put_done(fabric::EndpointId ep, std::uint64_t rid, const store::PutDoneResult& r) {
  if (r.e.empty() || r.e.size() > proto::kMaxPutKeys) return;
  auto w = std::make_unique<proto::PutDone>();
  w->put_id = r.put_id;
  w->n = static_cast<std::uint16_t>(r.e.size());
  for (std::size_t i = 0; i < r.e.size(); ++i) w->e[i] = r.e[i];
  if (auto n = proto::encode_put_done(*w, body_buf_)) send_body(ep, Op::PUT_DONE, rid, *n);
}

void Server::on_put_done(fabric::EndpointId ep, std::uint64_t rid, const FrameHeader& req, const store::PutDoneResult& r) {
  if (r.status != store::CommitStatus::Ok) {
    // Malformed, UnknownPut (also a foreign put id): refused with an error reply; the put is untouched.
    return send_error(ep, req, WireStatus::Malformed);
  }
  count_request(req.type, true);
  send_put_done(ep, rid, r);
}

void Server::on_put_commit(Conn& c, const FrameHeader& h, std::span<const std::byte> body) {
  const auto id = c.ep->id();
  auto m = proto::decode_put_commit(h, body);
  if (!m) return send_error(id, h, m.error().status);
  store::PutCommitReq q;
  q.put_id = m->put_id;
  for (std::size_t i = 0; i < m->n; ++i)
    q.e.push_back(store::CommitEntry{m->e[i].key_index, m->e[i].crc32c, m->e[i].stored_len});
  // `done` runs on the store thread, possibly after the endpoint is gone (sends then no-op).
  const std::uint64_t rid = h.request_id;
  puts_->put_commit(id, q, [this, id, rid, h](const store::PutDoneResult& r) { on_put_done(id, rid, h, r); });
}

void Server::on_put_cancel(Conn& c, const FrameHeader& h, std::span<const std::byte> body) {
  const auto id = c.ep->id();
  auto m = proto::decode_put_cancel(h, body);
  if (!m) return send_error(id, h, m.error().status);
  const std::uint64_t rid = h.request_id;
  puts_->put_cancel(id, m->put_id, [this, id, rid, h](const store::PutDoneResult& r) { on_put_done(id, rid, h, r); });
}

}  // namespace miracache::server
