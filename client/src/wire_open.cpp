// SPDX-License-Identifier: Apache-2.0
// Client::open: the production wiring (real clock, thread pool, OS nonce source, verbs_cm
// fabric per node, WirePort per node). Lab mode, static membership: every [[nodes]] entry is a
// memory node (rail = its first address "host:port"); scopes are spread over them by weighted
// rendezvous placement (placement.h). Tickets come from the node's admin (IssueTicket over mTLS)
// if set, else lab.ticket_file (one node only). Bundle mode ([control]): the first verified bundle from the watcher
// decides the node table (open_bundle_mode); later bundles come through Client::apply_membership. A node's rails
// (1..4) pair with the local devices (fabric.devices: exact subnet, else a blank-subnet wildcard device; rail_pairing.h);
// each paired rail gets its own endpoint set.
#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "runtime/pause.h"
#include "runtime/thread_pool_executor.h"
#include "src/admin_http.h"
#include "src/admin_tickets.h"
#include "src/client.h"
#include "src/cred_watch.h"
#include "src/rail_pairing.h"
#include "util/log.h"
#include "util/nonce_source.h"

#ifdef MIRACACHE_WITH_VERBS
#include "fabric/profile/nic_profile.h"
#include "fabric/probe/nic_probe.h"
#include "fabric/verbs_cm/verbs_cm_fabric.h"
#endif

namespace miracache {

namespace {

#ifdef MIRACACHE_WITH_VERBS
// A rail's weight is its local port's link speed (ibv_query_port active_speed x active_width, Mb/s);
// 0 = unknown (equal weights). Probed once per device per process.
std::uint32_t link_weight(const std::string& device) {
  static std::mutex mu;
  static auto* cache = new std::map<std::string, std::uint32_t>;
  std::lock_guard lk(mu);
  auto it = cache->find(device);
  if (it != cache->end()) return it->second;
  std::uint32_t w = 0;
  if (auto f = fabric::probe::probe_device(device)) {
    for (const auto& p : f->ports)
      if (p.state == "active" && p.speed_mbps > 0) {
        w = p.speed_mbps;
        break;
      }
  }
  (*cache)[device] = w;
  return w;
}
#endif
}  // namespace

#ifdef MIRACACHE_WITH_VERBS
namespace {
struct ProdWorld {
  explicit ProdWorld(std::size_t workers) : ex(workers) {}
  RealClock clock;
  OsNonceSource salts;
  // One jitter source per node (reconnect backoff, build backoff, ticket refill): each node's
  // keepalive thread draws from its own, so no RNG is shared between threads. Lab mode: one per node, kept until the
  // Client dies. Bundle mode: only [0], the watcher's; each node's own lives in its slot (NodeSpec::owner).
  std::vector<std::unique_ptr<RealRandom>> jitter;
  ThreadPoolExecutor ex;
  // Lab mode only (bundle mode: per slot, NodeSpec::owner, freed at the slot's teardown).
  std::vector<std::unique_ptr<fabric::VerbsCmFabric>> fabs;  // one per node
  std::vector<std::shared_ptr<void>> hold;                   // ticket sources (also captured by the WireOptions closures)
};
}  // namespace
#endif

#ifdef MIRACACHE_WITH_VERBS
namespace {
// The watcher's callback reaches the Client through this (set once the Client exists). The Client stops the watcher
// before it dies, so the pointer is never used after that.
struct Forward {
  std::mutex mu;
  Client* client = nullptr;
};

// Bundle mode: the first verified bundle decides the first node table; after that
// the watcher feeds Client::apply_membership. Every bundle node gets its own verbs fabric, ticket source (admin from
// the bundle) and jitter source; its slot owns them (NodeSpec::owner) and frees them at its teardown, after its wire and
// core, having dropped the WireOptions closures that also hold the ticket source.
Expected<std::unique_ptr<Client>> open_bundle_mode(const ClientConfig& cfg) {
  const ControlConfig& cc = *cfg.control;
  auto w = std::make_shared<ProdWorld>(cfg.crypto_workers);
  auto fwd = std::make_shared<Forward>();
  w->jitter.push_back(std::make_unique<RealRandom>());  // [0]: the watcher's backoff jitter

  BundleWatcherOptions bo;
  bo.endpoints = cc.endpoints;
  bo.trust_keys = cc.trust_keys;
  bo.state_dir = cc.state_dir;
  bo.cert = cfg.tls_cert;
  bo.key = cfg.tls_key;
  bo.ca = cfg.tls_ca;
  bo.random = w->jitter[0].get();
  bo.on_bundle = [fwd](MembershipSnapPtr snap) {
    std::lock_guard lk(fwd->mu);
    if (fwd->client) fwd->client->apply_membership(std::move(snap));
  };
  bo.log = [](const std::string& line) { log::write(log::Level::Info, "client", line); };
  auto wat = BundleWatcher::create(std::move(bo), w->clock);
  if (!wat) return wat.error();
  std::shared_ptr<BundleWatcher> watcher = std::move(*wat);
  // The first bundle: poll every endpoint (the start-up sweep) until one verifies, for up to 30 s.
  {
    const Nanos until = w->clock.now() + std::chrono::seconds(30);
    while (!watcher->current() && w->clock.now() < until) {
      (void)watcher->poll_now();
      if (!watcher->current()) pause_for(std::chrono::milliseconds(500));
    }
    if (!watcher->current()) return Error{ErrorCode::Timeout, "client: no verified bundle from any [control] endpoint"};
  }

  fabric::profile::Overrides ov;
  ov.read_depth = cfg.read_depth;
  ov.inline_bytes = cfg.inline_bytes;
  ov.ack_timeout_exp = cfg.ack_timeout_exp;
  ov.retry_count = cfg.retry_count;
  ov.rnr_retry_count = cfg.rnr_retry_count;
  if (cfg.mtu_explicit) ov.mtu = cfg.mtu;
  auto sel = fabric::profile::select_for_device(cfg.device, cfg.profiles_file, ov);
  if (!sel) return sel.error();
  const auto op = sel->op;

  // Called on the open thread, then on the Client's membership thread (one call at a time).
  // The closure outlives this function (it runs on the membership thread for the Client's whole life) and the
  // caller's config may be a local (mira_client_open): it owns a copy.
  auto cfgp = std::make_shared<const ClientConfig>(cfg);
  auto make_spec = [cfgp, w, op](const control::NodeView& nv) -> Expected<Client::NodeSpec> {
    const ClientConfig& cfg = *cfgp;
    if (nv.rails.empty()) return Error{ErrorCode::InvalidArgument, "client: bundle node has no rails"};
    Client::NodeSpec sp;
    WireOptions& wo = sp.wopts;
    // Pair the bundle's rails; the first paired rail is the node's address (`rail`, labels).
    std::vector<NodeRail> nr;
    for (const auto& r : nv.rails) nr.push_back(NodeRail{r.addr, r.subnet, r.protocol});
    std::uint32_t unpaired = 0;
    const auto paired = pair_rails(cfg, nr, nv.node_id, nv.hostname, unpaired);
    if (paired.empty()) return Error{ErrorCode::InvalidArgument, "client: no bundle rail pairs with a local device"};
    wo.rail = paired[0].addr;
    wo.unpaired_rails = unpaired;
    wo.fetch_qps = op.fetch_qps;  // fetch_qps fetch QPs per rail (class B: planned rebuild)
    wo.window_bytes = op.window_bytes;  // The fetch QP window of the NIC profile operating point (fixed at open)
    wo.sq_depth = fabric::VerbsOptions{}.sq_depth;  // The QPs this opens use the fabric default send queue
    wo.keepalive_ms = cfg.keepalive_ms;
    wo.mtu = op.mtu;
    wo.read_depth = static_cast<std::uint8_t>(op.read_depth);
    wo.reconnect_min_ms = cfg.reconnect_min_ms;
    wo.reconnect_max_ms = cfg.reconnect_max_ms;
    wo.reconnect_connect_ms = cfg.reconnect_connect_ms;
    wo.wire_proto = cfg.protocol == FabricProtocol::Iwarp ? 2 : 1;
    // The slot owns these; they are freed when the slot is torn down (after its wire and core).
    struct Owned {
      RealRandom jitter;
      std::shared_ptr<AdminTicketSource> tickets;
      std::unique_ptr<fabric::VerbsCmFabric> fab;
      std::vector<std::unique_ptr<fabric::VerbsCmFabric>> more;  // The other paired local devices
    };
    auto owned = std::make_shared<Owned>();
    wo.random = &owned->jitter;
    AdminTicketOptions ao;
    ao.admin = nv.admin;
    ao.cert = cfg.tls_cert;
    ao.key = cfg.tls_key;
    ao.ca = cfg.tls_ca;
    ao.batch = cfg.ticket_batch;
    ao.fetch_need = std::max(1u, wo.fetch_qps);  // One build draws fetch_qps fetch tickets per rail
    ao.random = wo.random;
    ao.away_backoff_max_ms = std::max(ao.backoff_min_ms, cfg.reconnect_max_ms);
    for (const auto& p : paired) ao.rails.push_back(p.index);  // Tickets of every paired rail
    auto src = AdminTicketSource::create(std::move(ao), w->clock);
    if (!src) return src.error();
    std::shared_ptr<AdminTicketSource> s = *src;
    // The node admits a ticket only on its own rail (reject 2), so each paired rail draws its own.
    wo.rail_tickets = [s](fabric::EpClass cls, std::uint8_t rail) { return s->draw(cls, rail); };
    owned->tickets = s;  // no ticket I/O here: wo.prepare runs before the first build (the open; else the node's thread)
    wo.tickets = [s](fabric::EpClass cls) { return s->draw(cls); };
    wo.prepare = [s] { (void)s->prepare(); };
    wo.prepare_within = [s](Nanos budget) { (void)s->prepare(budget); };  // The settle retries
    wo.tickets_ready_at = [s] { return s->ready_at(); };
    wo.ticket_need = [s](std::uint32_t n) { s->set_fetch_need(n); };
    // The QP readback gauges of this node's fabrics go into the client registry (fabrics are created below; owned keeps them alive).
    const telemetry::Labels qp_lab{{"node_id", nv.node_id ? std::to_string(nv.node_id) : std::string("unknown")},
                                   {"hostname", nv.hostname.empty() ? std::string("unknown") : nv.hostname}};
    wo.on_metrics = [s, owned, qp_lab](ClientMetrics* m) {
      s->bind_metrics(m);
      if (owned->fab) owned->fab->set_qp_metrics(m ? &m->reg : nullptr, qp_lab);
      for (auto& f : owned->more) f->set_qp_metrics(m ? &m->reg : nullptr, qp_lab);
    };
    wo.on_down_tickets = [s] { s->reset_backoff(); };
    sp.hostname = [s] { return s->hostname(); };
    sp.reported_node_id = [s] { return s->reported_node_id(); };
    sp.on_dyn = [s](const ClientDyn& d) { s->set_batch(d.ticket_batch); };  // fabric.ticket_batch is class A
    fabric::VerbsOptions vo;
    vo.device = local_devices(cfg)[paired[0].device].device;
    vo.protocol = cfg.protocol == FabricProtocol::Roce    ? fabric::protocol::Setting::RoCE
                  : cfg.protocol == FabricProtocol::Iwarp ? fabric::protocol::Setting::IWarp
                                                          : fabric::protocol::Setting::Auto;
    vo.ack_timeout_exp = op.ack_timeout_exp;
    vo.retry_count = op.retry_count;
    vo.rnr_retry_count = op.rnr_retry_count;
    vo.inline_bytes = op.inline_bytes;
    auto fab = fabric::VerbsCmFabric::open(vo);
    if (!fab) {
      fabric::last_local_failure().rail = paired[0].index;  // The rail whose local device refused (its CQ)
      return fab.error();
    }
    owned->fab = std::move(*fab);
    owned->fab->set_qp_metrics(nullptr, qp_lab);  // The node's identity is on every readback log line from the first QP
    {  // One fabric (PD, CQ) per (node, local device); rails on the first paired device use the port's own
      const auto devs = local_devices(cfg);
      std::vector<std::pair<std::size_t, fabric::Fabric*>> by_dev{{paired[0].device, owned->fab.get()}};
      for (const auto& p : paired) {
        fabric::Fabric* f = nullptr;
        for (auto& [d, ff] : by_dev)
          if (d == p.device) f = ff;
        if (!f) {
          fabric::VerbsOptions v2 = vo;
          v2.device = devs[p.device].device;
          auto f2 = fabric::VerbsCmFabric::open(v2);
          if (!f2) {
            fabric::last_local_failure().rail = p.index;  // The rail whose local device refused (its CQ)
            return f2.error();
          }
          owned->more.push_back(std::move(*f2));
          owned->more.back()->set_qp_metrics(nullptr, qp_lab);
          f = owned->more.back().get();
          by_dev.emplace_back(p.device, f);
        }
        WireOptions::RailOpt ro;
        ro.index = p.index;
        ro.addr = p.addr;
        ro.fab = f == owned->fab.get() ? nullptr : f;
        ro.device = devs[p.device].device;
        ro.weight = link_weight(ro.device);
        wo.rails.push_back(std::move(ro));
      }
      if (wo.rails.size() == 1 && unpaired == 0) wo.rails.clear();  // one rail: the single-rail port
    }
    sp.fab = owned->fab.get();
    sp.owner = std::move(owned);
    return sp;
  };

  Client::Env env;
  env.clock = &w->clock;
  env.executor = &w->ex;
  env.salts = &w->salts;
  if (cfg.watchdog_grace_ms > 0) env.watchdog_grace = std::chrono::milliseconds(cfg.watchdog_grace_ms);
  env.nic_profile = sel->profile_id;
  env.nic_profile_verified = sel->verified;
  env.nic_unprofiled = sel->unprofiled;
  env.replicas = 1;  // R comes from the bundle (config.cluster.placement.replicas)
  env.replica_mode = cfg.replica_mode;
  env.replica_buffer_bytes = static_cast<std::size_t>(cfg.replica_buffer_bytes);
  env.slice_bytes = op.slice_bytes;  // config > profile > built-in (the profile's value is the base)
  env.set_crypto_workers = [w](unsigned n) { w->ex.set_workers(n); };  // class C (crypto.workers)
  env.open_settle = std::chrono::seconds(2);  // As open_wire_nodes (a failed first connect is retried inside the open)
  {  // The open-time live configuration; a key absent from the bundle's config.cluster.client takes these
    auto b = std::make_shared<ClientDyn>();
    b->keepalive_ms = cfg.keepalive_ms;
    b->reconnect_min_ms = cfg.reconnect_min_ms;
    b->reconnect_max_ms = cfg.reconnect_max_ms;
    b->reconnect_connect_ms = cfg.reconnect_connect_ms;
    b->watchdog_grace_ms = cfg.watchdog_grace_ms > 0
                               ? cfg.watchdog_grace_ms
                               : static_cast<std::uint32_t>(std::chrono::duration_cast<std::chrono::milliseconds>(env.watchdog_grace).count());
    b->ticket_batch = cfg.ticket_batch;
    b->slice_bytes = op.slice_bytes;
    b->replica_mode = cfg.replica_mode;
    b->replica_buffer_bytes = cfg.replica_buffer_bytes;
    b->crypto_workers = cfg.crypto_workers;
    b->subpool_bytes = cfg.subpool_bytes;
    b->mtu = op.mtu;
    b->protocol = cfg.protocol;
    b->fetch_qps = op.fetch_qps;
    env.dyn_base = std::move(b);
  }
  ClientCoreOptions copts;
  copts.pool_bytes = static_cast<std::size_t>(cfg.subpool_bytes);
  Client::BundleOpen bopen;
  bopen.initial = watcher->current();
  bopen.make_spec = std::move(make_spec);
  bopen.watcher = watcher;
  bopen.keepalive_ms = cfg.keepalive_ms;
  if (!cc.controller.empty()) {  // Client reports go to [control] controller with the same mTLS identity; none configured = none sent
    HttpsOptions ho;
    ho.cert = cfg.tls_cert;
    ho.key = cfg.tls_key;
    ho.ca = cfg.tls_ca;
    auto cancel = std::make_shared<std::atomic<bool>>(false);  // Shutdown cuts a report in flight short
    ho.cancel = cancel.get();
    auto http = HttpsClient::create(std::move(ho));
    if (!http) return http.error();
    bopen.cancel_reports = [cancel] { cancel->store(true, std::memory_order_release); };
    bopen.send_report = [http = *http, cancel, addr = cc.controller](const std::string& body) -> Status {
      auto r = http->request(addr, "POST", "/v1/reports", "application/json", body);
      if (!r) return r.error();
      if (r->code != 202) return Error{ErrorCode::AccessDenied, "client: the controller did not accept the report"};
      return {};
    };
  }
  // Room for nodes that join later; idle workers sleep on the runtime's condvar.
  const std::size_t n_bundle = std::max<std::size_t>(16, bopen.initial->view.body.nodes.size());
  auto cl = Client::open_bundle(env, std::move(bopen), w, copts, Client::runtime_for_nodes(n_bundle));
  if (!cl) return cl.error();
  {
    std::lock_guard lk(fwd->mu);
    fwd->client = cl->get();
    if (auto cur = watcher->current()) fwd->client->apply_membership(std::move(cur));  // a bundle that came in meanwhile
  }
  watcher->start();
  return cl;
}
}  // namespace
#endif

// Once the client is up, a CredWatch re-reads [tls] cert/key/ca and scope.secret_file when they change (the part of
// the part that is "start only"). It lives and dies with the Client; a plain ScopeProvider (not the reloadable one) just
// has no secret part. A failed start never fails the open: the client then simply keeps the material it loaded.
[[maybe_unused]] static Expected<std::unique_ptr<Client>> start_cred_watch(const ClientConfig& cfg, ScopeProvider& provider,
                                                          Expected<std::unique_ptr<Client>> c) {
  if (!c) return c;
  CredWatchOptions o;
  o.cert = cfg.tls_cert;
  o.key = cfg.tls_key;
  o.ca = cfg.tls_ca;
  auto* rp = dynamic_cast<ReloadableEngineNativeProvider*>(&provider);
  if (rp) o.secret_file = rp->source_path();  // the path the provider was loaded from (mira_provider_cfg may override the config)
  auto cw = CredWatch::create(std::move(o), rp);
  if (!cw) {
    log::write(log::Level::Warn, "client", "credential watch not started", {{"err", cw.error().context}});
    return c;
  }
  if (!*cw) return c;
  std::shared_ptr<CredWatch> w(std::move(*cw));
  w->start();
  (*c)->attach_service(w, [w](std::string& out) { w->write_metrics(out); });
  return c;
}

Expected<std::unique_ptr<Client>> Client::open(const ClientConfig& cfg, ScopeProvider& provider) {
  if (cfg.control) {  // bundle mode: membership comes from the signed bundle
#ifdef MIRACACHE_WITH_VERBS
    return start_cred_watch(cfg, provider, open_bundle_mode(cfg));
#else
    return Error{ErrorCode::Unsupported, "client: built without verbs support"};
#endif
  }
  if (cfg.nodes.empty()) return Error{ErrorCode::InvalidArgument, "client: no [[nodes]]"};
  std::size_t lab_ticket_nodes = 0;
  for (const auto& nc : cfg.nodes) {
    if (nc.admin.empty()) ++lab_ticket_nodes;
    if (nc.rails.empty()) return Error{ErrorCode::InvalidArgument, "client: nodes.rails entry must be host:port"};
  }
  if (lab_ticket_nodes > 0 && cfg.ticket_file.empty())
    return Error{ErrorCode::InvalidArgument, "client: lab.ticket_file or nodes.admin is required (no controller yet)"};
  if (lab_ticket_nodes > 1)
    return Error{ErrorCode::InvalidArgument, "client: lab.ticket_file serves one node; give every node nodes.admin"};
  const bool multi = cfg.nodes.size() > 1;
  std::vector<NodeSpec> specs(cfg.nodes.size());
  for (std::size_t i = 0; i < cfg.nodes.size(); ++i) {
    const NodeConfig& nc = cfg.nodes[i];
    WireOptions& wo = specs[i].wopts;
    wo.node = 0;  // learned from HELLO_ACK
    specs[i].label = nc.rails[0];
    specs[i].weight = nc.weight;
    specs[i].zone = nc.zone;
    if (!parse_rail(nc.rails[0], wo.rail))
      return Error{ErrorCode::InvalidArgument, "client: nodes.rails entry must be host:port"};
    if (nc.admin.empty()) wo.tickets = lab_ticket_file_source(cfg.ticket_file);
    // Lab rails carry no subnet, so every rail pairs with device 0. Several rails need per-rail
    // tickets: the lab ticket file has them, and the admin source draws them per rail (set below).
    if (nc.rails.size() > 1) {
      if (nc.admin.empty()) wo.rail_tickets = lab_rail_ticket_file_source(cfg.ticket_file);
      const std::string dev0 = local_devices(cfg)[0].device;
      for (std::size_t k = 0; k < nc.rails.size(); ++k) {
        WireOptions::RailOpt ro;
        ro.index = static_cast<std::uint8_t>(k);
        if (!parse_rail(nc.rails[k], ro.addr)) return Error{ErrorCode::InvalidArgument, "client: nodes.rails entry must be host:port"};
        ro.device = dev0;
        wo.rails.push_back(std::move(ro));
      }
    }
    wo.keepalive_ms = cfg.keepalive_ms;
    wo.mtu = cfg.mtu;
    wo.reconnect_min_ms = cfg.reconnect_min_ms;
    wo.reconnect_max_ms = cfg.reconnect_max_ms;
    wo.reconnect_connect_ms = cfg.reconnect_connect_ms;
    wo.wire_proto = cfg.protocol == FabricProtocol::Iwarp ? 2 : 1;
  }
#ifdef MIRACACHE_WITH_VERBS
  // Probe the local NIC, match a profile, log it. Precedence: config key > profile > built-in default.
  fabric::profile::Overrides ov;
  ov.read_depth = cfg.read_depth;
  ov.inline_bytes = cfg.inline_bytes;
  ov.ack_timeout_exp = cfg.ack_timeout_exp;
  ov.retry_count = cfg.retry_count;
  ov.rnr_retry_count = cfg.rnr_retry_count;
  if (cfg.mtu_explicit) ov.mtu = cfg.mtu;
  auto sel = fabric::profile::select_for_device(cfg.device, cfg.profiles_file, ov);
  if (!sel) return sel.error();
  for (auto& sp : specs) {
    sp.wopts.mtu = sel->op.mtu;
    sp.wopts.read_depth = static_cast<std::uint8_t>(sel->op.read_depth);
    sp.wopts.fetch_qps = sel->op.fetch_qps;  // Fetch QPs per rail from the NIC profile operating point
    sp.wopts.window_bytes = sel->op.window_bytes;  // The fetch QP window
    sp.wopts.sq_depth = fabric::VerbsOptions{}.sq_depth;  // The fabric default send queue
  }
  auto w = std::make_shared<ProdWorld>(cfg.crypto_workers);
  for (std::size_t i = 0; i < cfg.nodes.size(); ++i) {
    const NodeConfig& nc = cfg.nodes[i];
    WireOptions& wo = specs[i].wopts;
    w->jitter.push_back(std::make_unique<RealRandom>());
    wo.random = w->jitter.back().get();
    if (!nc.admin.empty()) {
      AdminTicketOptions ao;
      ao.admin = nc.admin;
      ao.server_identity = nc.identity;
      ao.cert = cfg.tls_cert;
      ao.key = cfg.tls_key;
      ao.ca = cfg.tls_ca;
      ao.batch = cfg.ticket_batch;
      ao.fetch_need = std::max(1u, wo.fetch_qps);  // One build draws fetch_qps fetch tickets per rail
      ao.random = wo.random;
      // The ticket fetch never waits longer than a reconnect does, so the first IssueTicket after
      // a long restart is at most reconnect_max_ms late. Only while the node is away (LinkDown,
      // Timeout, 503); a 403, 429 or cert failure keeps the 30 s cap.
      ao.away_backoff_max_ms = std::max(ao.backoff_min_ms, cfg.reconnect_max_ms);
      for (const auto& ro : wo.rails) ao.rails.push_back(ro.index);  // Tickets of every rail
      auto src = AdminTicketSource::create(std::move(ao), w->clock);
      if (!src) return src.error();
      std::shared_ptr<AdminTicketSource> s = *src;
      if (!wo.rails.empty()) wo.rail_tickets = [s](fabric::EpClass cls, std::uint8_t rail) { return s->draw(cls, rail); };
      // First batch now (nothing runs yet, so no lock to worry about); then the keepalive thread
      // keeps the cache warm outside the core lock. draw() never touches the network. With several
      // nodes an unreachable admin is not fatal: the node's keepalive thread retries (like a reconnect).
      if (Status f = s->prepare(); !f && !multi) return f.error();
      wo.tickets = [s](fabric::EpClass cls) { return s->draw(cls); };
      wo.prepare = [s] { (void)s->prepare(); };
      wo.prepare_within = [s](Nanos budget) { (void)s->prepare(budget); };  // The settle retries
      wo.tickets_ready_at = [s] { return s->ready_at(); };
      wo.ticket_need = [s](std::uint32_t n) { s->set_fetch_need(n); };
      wo.on_metrics = [s](ClientMetrics* m) { s->bind_metrics(m); };
      wo.on_down_tickets = [s] { s->reset_backoff(); };
      specs[i].hostname = [s] { return s->hostname(); };  // node_info: the memory node's own hostname
      specs[i].reported_node_id = [s] { return s->reported_node_id(); };
      w->hold.push_back(s);
    }
    fabric::VerbsOptions vo;
    vo.device = cfg.device;
    vo.protocol = cfg.protocol == FabricProtocol::Roce    ? fabric::protocol::Setting::RoCE
                  : cfg.protocol == FabricProtocol::Iwarp ? fabric::protocol::Setting::IWarp
                                                          : fabric::protocol::Setting::Auto;
    vo.ack_timeout_exp = sel->op.ack_timeout_exp;
    vo.retry_count = sel->op.retry_count;
    vo.rnr_retry_count = sel->op.rnr_retry_count;
    vo.inline_bytes = sel->op.inline_bytes;
    auto fab = fabric::VerbsCmFabric::open(vo);
    if (!fab) return fab.error();
    w->fabs.push_back(std::move(*fab));
    specs[i].fab = w->fabs.back().get();
    {  // Static config knows no node ID or hostname before the first ticket response: explicit "unknown" until
       // the metrics bind below (which then uses what the admin source has learned).
      fabric::VerbsCmFabric* qf = w->fabs.back().get();
      std::function<void(ClientMetrics*)> prev = std::move(wo.on_metrics);
      auto hostf = specs[i].hostname;
      auto idf = specs[i].reported_node_id;
      // The ID learned from HELLO_ACK (static/lab mode has no admin source to report it) reaches the series
      // through on_id_learned: the metrics are bound before the first HELLO, so they re-bind under the real ID.
      struct Learn {
        std::mutex mu;
        std::uint32_t id = 0;
        std::string host;  // The hostname HELLO_ACK brought (the admin source has priority)
        telemetry::Registry* reg = nullptr;
      };
      auto learn = std::make_shared<Learn>();
      auto labels = [hostf, idf, learn] {  // learn->mu held by the callers
        std::uint32_t id = idf ? idf() : 0;
        if (id == 0) id = learn->id;
        std::string h = hostf ? hostf() : std::string();
        if (h.empty()) h = learn->host;
        return telemetry::Labels{{"node_id", id ? std::to_string(id) : std::string("unknown")},
                                 {"hostname", h.empty() ? std::string("unknown") : h}};
      };
      {
        std::lock_guard lk(learn->mu);
        qf->set_qp_metrics(nullptr, labels());
      }
      wo.on_metrics = [prev, qf, labels, learn](ClientMetrics* m) {
        if (prev) prev(m);
        std::lock_guard lk(learn->mu);
        learn->reg = m ? &m->reg : nullptr;
        qf->set_qp_metrics(learn->reg, labels());
      };
      specs[i].on_id_learned = [qf, labels, learn](std::uint32_t id) {
        std::lock_guard lk(learn->mu);
        learn->id = id;
        qf->set_qp_metrics(learn->reg, labels());
      };
      specs[i].on_host_learned = [qf, labels, learn](const std::string& host) {  // Static/lab mode learns it from HELLO_ACK
        std::lock_guard lk(learn->mu);
        learn->host = host;
        qf->set_qp_metrics(learn->reg, labels());
      };
    }
  }
  Env env;
  env.clock = &w->clock;
  env.executor = &w->ex;
  env.salts = &w->salts;
  if (cfg.watchdog_grace_ms > 0) env.watchdog_grace = std::chrono::milliseconds(cfg.watchdog_grace_ms);  // Override
  env.nic_profile = sel->profile_id;
  env.nic_profile_verified = sel->verified;
  env.nic_unprofiled = sel->unprofiled;
  env.slice_bytes = sel->op.slice_bytes;  // config > profile > built-in
  env.replicas = cfg.replicas;
  env.replica_mode = cfg.replica_mode;
  env.replica_buffer_bytes = static_cast<std::size_t>(cfg.replica_buffer_bytes);
  // A node whose first connect fails is retried inside the open for up to 2 s (its ticket fetch backs off 0.5 to
  // 1 s after a failure) before the open returns with it pending.
  env.open_settle = std::chrono::seconds(2);
  ClientCoreOptions copts;
  copts.pool_bytes = static_cast<std::size_t>(cfg.subpool_bytes);
  const RuntimeOptions ro = Client::runtime_for_nodes(specs.size());  // Per-node lanes
  return start_cred_watch(cfg, provider, open_wire_nodes(env, std::move(specs), w, copts, ro));
#else
  (void)multi;
  return Error{ErrorCode::Unsupported, "client: built without verbs support"};
#endif
}

}  // namespace miracache
