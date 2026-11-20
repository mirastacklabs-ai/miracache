// SPDX-License-Identifier: Apache-2.0
// mira-memnode: the memory-node server over verbs_cm (RoCE or iWARP, auto-detected).
//   mira-memnode --config node.toml [--device rxe0] [--listen host:port]
// One store thread runs this loop; StoreExecutor workers run extent CRCs and marshal `done`
// back here (drain_done). Lab bring-up: with [lab] principal/ticket_file set, tickets for the
// lab identity are written to the file (one "class rail hex-id" per line) and refreshed at
// half the ticket TTL; clients read them from there (no controller needed).
#include <poll.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>

#include <atomic>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "control/floor_state.h"
#include "server/dyn_config.h"
#include "server/lab_tickets.h"
#include "server/node_config.h"
#include "server/runtime/admin_https.h"
#include "server/runtime/bundle_store.h"
#include "server/runtime/metrics_http.h"
#include "server/runtime/store_executor.h"
#include "server/runtime/wake_fd.h"
#include "util/buggify.h"
#include "util/check.h"
#include "util/clock.h"
#include "util/log.h"
#include "util/nonce_source.h"
#include "util/random.h"

#ifdef MIRACACHE_WITH_VERBS
#include "fabric/verbs_cm/verbs_cm_fabric.h"
#endif

namespace {
std::atomic<bool> g_stop{false};   // leave the loop now
std::atomic<bool> g_term{false};   // first SIGTERM/SIGINT: drain (GOAWAY), then leave
std::atomic<int> g_signals{0};
std::atomic<bool> g_reload{false};
// Set before the handlers are installed; cleared (handlers reset first) before `wake` is destroyed.
std::atomic<const miracache::server::WakeFd*> g_wake{nullptr};
void on_signal(int) {
  const int saved = errno;  // write(2) may set it; the interrupted code must not see that
  // First signal: graceful drain. Any further one: stop at once. (write(2) in signal() is async-signal-safe.)
  if (g_signals.fetch_add(1) >= 1) g_stop = true;
  else g_term = true;
  if (auto* w = g_wake.load()) w->signal();
  errno = saved;
}
void on_hup(int) {
  const int saved = errno;
  g_reload = true;
  if (auto* w = g_wake.load()) w->signal();
  errno = saved;
}
// On every way out of main after the handlers are installed, put the default dispositions
// back and only then forget the WakeFd, so no handler can touch a destroyed one.
//
// Main blocks SIGINT/SIGTERM/SIGHUP before it starts any thread (fabric dispatcher, executor
// workers, admin/metrics threads inherit the mask), and only the main thread unblocks them here. So a
// handler only ever runs on main, never on a worker racing ~SignalScope / ~WakeFd on an early return.
void term_signals(sigset_t* s) {
  sigemptyset(s);
  sigaddset(s, SIGINT);
  sigaddset(s, SIGTERM);
  sigaddset(s, SIGHUP);
}
// Threads started while it lives inherit the three signals blocked (main has them unblocked once the
// handlers are in, e.g. for the admin/metrics restarts on SIGHUP).
struct MaskTermSignals {
  MaskTermSignals() {
    sigset_t s;
    term_signals(&s);
    pthread_sigmask(SIG_BLOCK, &s, &old);
  }
  ~MaskTermSignals() { pthread_sigmask(SIG_SETMASK, &old, nullptr); }
  sigset_t old;
};
struct SignalScope {
  explicit SignalScope(const miracache::server::WakeFd& w) {
    g_wake = &w;
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGHUP, on_hup);
    sigset_t s;
    term_signals(&s);
    pthread_sigmask(SIG_UNBLOCK, &s, nullptr);  // main only; every other thread keeps them blocked
  }
  ~SignalScope() {
    std::signal(SIGINT, SIG_DFL);
    std::signal(SIGTERM, SIG_DFL);
    // SIGHUP is a reload request, never a stop: ignored from here on, so a HUP sent during the exit
    // path (exec.stop(), shutdown_clean()) cannot kill the node before the clean mark. SIGINT/SIGTERM keep
    // SIG_DFL (a further one stops at once, as documented).
    std::signal(SIGHUP, SIG_IGN);
    g_wake = nullptr;
  }
  SignalScope(const SignalScope&) = delete;
  SignalScope& operator=(const SignalScope&) = delete;
};

using namespace miracache;

void logm(log::Level l, std::string_view msg, std::initializer_list<log::Field> extra = {}) {
  log::write(l, "memnode", msg, extra);
}

// Ticket ids are secrets: draw them from the OS CSPRNG (NonceSource), not the xoshiro RealRandom.
class OsRandom final : public Random {
 public:
  std::uint64_t next_u64() override {
    auto s = src_.salt();
    MIRACACHE_CHECK(s.has_value());
    std::uint64_t v;
    std::memcpy(&v, s->b.data(), 8);
    return v;
  }

 private:
  OsNonceSource src_;
};

}  // namespace

// A MIRACACHE_TEETH tree has fault hooks compiled in (inactive unless a sim arms them). It is
// for the simulator only and must never become a production memnode.
static_assert(!miracache::buggify::kTeethBuilt, "mira-memnode must not be built with MIRACACHE_TEETH");

int main(int argc, char** argv) {
  // A peer that resets a socket must never kill the node: ignore SIGPIPE before any thread
  // starts. (The admin TLS path also sends with MSG_NOSIGNAL, so it does not rely on this.)
  std::signal(SIGPIPE, SIG_IGN);
  {  // before any thread starts; SignalScope unblocks them for main only
    sigset_t s;
    term_signals(&s);
    pthread_sigmask(SIG_BLOCK, &s, nullptr);
  }
  std::string config_path, device, listen;
  for (int i = 1; i < argc; ++i) {
    std::string a = argv[i];
    auto next = [&](std::string& dst) {
      if (i + 1 >= argc) return false;
      dst = argv[++i];
      return true;
    };
    if (a == "--config" && next(config_path)) continue;
    if (a == "--device" && next(device)) continue;
    if (a == "--listen" && next(listen)) continue;
    logm(log::Level::Error, "usage: mira-memnode --config FILE [--device DEV] [--listen HOST:PORT]");
    return 2;
  }
  if (config_path.empty()) {
    logm(log::Level::Error, "--config is required");
    return 2;
  }
  auto cfg = server::load_node_config(config_path);
  if (!cfg) {
    logm(log::Level::Error, "config load failed", {{"err", cfg.error().context}});
    return 1;
  }
  const server::NodeConfig boot_file = *cfg;  // as written in the file: the STATIC baseline a SIGHUP compares against
  if (!device.empty()) cfg->device = device;
  if (!listen.empty()) {
    auto colon = listen.rfind(':');
    if (colon == std::string::npos) {
      logm(log::Level::Error, "--listen wants HOST:PORT");
      return 2;
    }
    auto port = server::parse_port(listen.substr(colon + 1));
    if (!port) {
      logm(log::Level::Error, "--listen invalid", {{"err", port.error().context}});
      return 2;
    }
    cfg->server.rails = {fabric::RailAddr{listen.substr(0, colon), *port}};
  }
  // From here every log line carries node_id, host and addr (one identity for the process).
  log::set_identity({cfg->server.store.node_id, "", server::listen_addr_string(cfg->server)});
#ifndef MIRACACHE_WITH_VERBS
  logm(log::Level::Error, "built without verbs support");
  return 2;
#else
  RealClock clock;
  RealRandom rng;
  // one fabric per distinct device ([[node.rails]]; the legacy form is one device). Each device gets its own NIC
  // profile selection and an endpoint-ID range, so an EndpointId is unique across the fabrics.
  std::vector<std::string> devices = cfg->devices;
  if (devices.empty()) {
    devices.push_back(cfg->device);
    cfg->server.device_names = devices;
  }
  std::optional<fabric::profile::Selection> sel;  // the first device's (the info metrics describe it)
  std::vector<std::unique_ptr<fabric::VerbsCmFabric>> fabs;
  std::uint32_t mtu = 0;
  std::uint32_t max_fetch_qps = 1;
  for (std::size_t di = 0; di < devices.size(); ++di) {
    auto s = fabric::profile::select_for_device(devices[di], cfg->profiles_file, cfg->nic);
    if (!s) {
      logm(log::Level::Error, "nic profile selection failed", {{"device", devices[di]}, {"err", s.error().context}});
      return 1;
    }
    mtu = mtu == 0 ? s->op.mtu : std::min(mtu, s->op.mtu);
    max_fetch_qps = std::max(max_fetch_qps, s->op.fetch_qps);
    fabric::VerbsOptions vo;
    vo.device = devices[di];
    vo.protocol = cfg->protocol;
    vo.ack_timeout_exp = s->op.ack_timeout_exp;
    vo.retry_count = s->op.retry_count;
    vo.rnr_retry_count = s->op.rnr_retry_count;
    vo.inline_bytes = s->op.inline_bytes;
    vo.ep_id_base = static_cast<fabric::EndpointId>(di) << 48;
    auto f = fabric::VerbsCmFabric::open(vo);
    if (!f) {
      logm(log::Level::Error, "fabric open failed", {{"device", devices[di]}, {"err", f.error().context}});
      return 1;
    }
    fabs.push_back(std::move(*f));
    if (di == 0) sel = std::move(*s);
  }
  cfg->server.mtu = mtu;
  // Limits.max_conns_per_principal not set -> Server::create computes 16 sessions x rails x (2 + fetch_qps).
  cfg->server.fetch_qps = max_fetch_qps;
  const bool max_bytes_computed = cfg->server.store.principal_default.max_bytes == 0;  // resolved in Server::create
  const bool conns_computed =cfg->server.max_conns_per_principal == 0;
  const std::uint32_t conns_default = server::default_max_conns(cfg->server.rails.size(), max_fetch_qps);
  // Limits.ticket_max_per_identity not set -> max(1024, 16 sessions x rails x the per-rail ticket inventory).
  const bool tickets_computed = cfg->server.ticket_max_per_identity == 0;
  const std::uint32_t tickets_default = server::default_ticket_max(cfg->server.rails.size(), max_fetch_qps);
  std::vector<fabric::Fabric*> fabric_ptrs;
  for (auto& f : fabs) fabric_ptrs.push_back(f.get());
  server::StoreExecutor exec(cfg->workers);
  OsRandom ticket_rng;
  auto srv = server::Server::create(cfg->server, fabric_ptrs, clock, rng, exec, &ticket_rng);
  if (!srv) {
    logm(log::Level::Error, "server create failed", {{"err", srv.error().context}});
    return 1;
  }
  (*srv)->metrics()
      .gauge("miracache_nic_profile_info", "Matched NIC profile; the value is always 1.",
             {{"profile", sel->profile_id}, {"verified", fabric::profile::verified_label(sel->verified)}})
      .set(1);
  (*srv)->metrics().gauge("miracache_nic_unprofiled", "1 when only a generic fallback profile matched this NIC.", {})
      .set(sel->unprofiled ? 1 : 0);
  // QP attribute readback gauges land in the node registry (node_id is its const label); the fabrics are only
  // polled by the server, which dies first, so no readback can reach a dead registry.
  for (auto& f : fabs) f->set_qp_metrics(&(*srv)->metrics(), {{"hostname", log::hostname()}});
  // The node ID is known only now (read from the state file; drawn once if there is none).
  log::set_identity({(*srv)->node_id(), "", server::listen_addr_string(cfg->server)});
  // The boot nonce (16 hex digits, the format of the client's restart Warn) so an operator can match that line to
  // this start. The line also carries id + hostname + addr from set_identity above.
  char nonce_hex[24];
  std::snprintf(nonce_hex, sizeof nonce_hex, "%016llx", static_cast<unsigned long long>((*srv)->boot_nonce()));
  logm(log::Level::Info, "node id", {{"id", std::to_string((*srv)->node_id())},
                                     {"boot_nonce", nonce_hex},
                                     {"store", cfg->server.store.backing == store::BackingKind::Anon ? "volatile" : "persistent"},
                                     {"state_dir", cfg->server.store.state_dir}});
  // The largest block this node can place: one slab run (store.run_bytes). A client block (payload + 64 B header + 16 B tag
  // per 64 KiB segment) longer than this is refused at PUT_BEGIN; HELLO_ACK tells clients the value (TLV 0x0003) so they
  // refuse locally and the engine adapters refuse at start-up. Size it with the runbook table (memnode store sizing):
  // a power of two >= 4 x the largest stored block (1 MiB blocks: 8 MiB).
  logm(log::Level::Info, "store geometry",
       {{"max_stored_block_bytes", std::to_string(cfg->server.store.run_bytes)},
        {"run_bytes", std::to_string(cfg->server.store.run_bytes)},
        {"segment_bytes", std::to_string(cfg->server.store.segment_bytes)},
        {"min_block_bytes", std::to_string(cfg->server.store.min_block_bytes)},
        {"n_segments", std::to_string(cfg->server.store.n_segments)}});
  if (conns_computed)
    logm(log::Level::Info, "limits.max_conns_per_principal computed (16 sessions x rails x (2 + fetch_qps))",
         {{"value", std::to_string((*srv)->dyn()->max_conns_per_principal)},
          {"rails", std::to_string(std::max<std::size_t>(cfg->server.rails.size(), 1))},
          {"fetch_qps", std::to_string(max_fetch_qps)}});
  if (tickets_computed)
    logm(log::Level::Info, "limits.ticket_max_per_identity computed (max(1024, 16 sessions x rails x (32 + 4 x max(4, fetch_qps))))",
         {{"value", std::to_string((*srv)->dyn()->ticket_max_per_identity)},
          {"rails", std::to_string(std::max<std::size_t>(cfg->server.rails.size(), 1))},
          {"fetch_qps", std::to_string(max_fetch_qps)}});
  if (max_bytes_computed)
    logm(log::Level::Info, "store.max_bytes computed (n_segments x segment_bytes)",
         {{"value", std::to_string((*srv)->dyn()->max_bytes)},
          {"n_segments", std::to_string(cfg->server.store.n_segments)},
          {"segment_bytes", std::to_string(cfg->server.store.segment_bytes)}});
  if (auto st = (*srv)->start(); !st) {
    logm(log::Level::Error, "listen failed", {{"err", st.error().context}});
    return 1;
  }
  // Worker threads signal this after queuing a `done`; so do the signal handlers. See wake_fd.h.
  server::WakeFd wake;
  if (!wake.ok()) {
    logm(log::Level::Error, "eventfd failed", {{"err", std::strerror(errno)}});
    return 1;
  }
  exec.set_wakeup([&wake] { wake.signal(); });
  // Optional so the handlers go back to SIG_DFL right after the loop (a further signal during
  // the exit path then stops at once). Declared after `wake`: destroyed (handlers reset) before it.
  std::optional<SignalScope> signals;
  signals.emplace(wake);

  // /metrics endpoint: off the data path, its own threads. A bind failure is logged, not fatal.
  std::unique_ptr<server::MetricsHttp> http;
  std::string http_listen = cfg->telemetry_listen;
  auto start_http = [&] {
    MaskTermSignals mask;  // its threads start with the signals blocked
    http.reset();
    auto h = server::MetricsHttp::start(http_listen, (*srv)->metrics());
    if (!h) {
      logm(log::Level::Warn, "telemetry listen failed", {{"err", h.error().context}});
      return;
    }
    http = std::move(*h);
    if (http) logm(log::Level::Info, "metrics on", {{"listen", http_listen}, {"port", std::to_string(http->port())}});
  };
  start_http();

  // Admin API: IssueTicket over HTTPS + mTLS. Off unless [admin] listen is set. A bad
  // admin config at startup is fatal (a node that silently lacks its ticket door is worse).
  // The audit log (node-local [audit]; default <state_dir>/audit in bundle mode). Declared before `admin`: it outlives
  // the listener. If it cannot be opened the admin API is refused (every route 503) and the data plane keeps serving;
  // a SIGHUP retries. `audit_ptr` is what GET /v1/identity reads (audit_seq / audit_head).
  std::unique_ptr<server::AdminAudit> audit;
  std::atomic<server::AdminAudit*> audit_ptr{nullptr};
  bool audit_failed = false;
  const std::uint32_t my_id = (*srv)->node_id();
  std::string audit_dir = cfg->audit_dir;
  if (audit_dir.empty() && !cfg->trust_keys.empty() && !cfg->server.store.state_dir.empty())
    audit_dir = cfg->server.store.state_dir + "/audit";
  auto open_audit = [&]() -> bool {
    server::AdminAuditOptions ao;
    ao.dir = audit_dir;
    ao.max_bytes = cfg->audit_max_bytes;
    ao.max_total_bytes = cfg->audit_max_total_bytes;
    ao.node_id = my_id;
    ao.host = log::hostname();
    ao.addr = server::listen_addr_string(cfg->server);
    auto a = server::AdminAudit::open(std::move(ao));
    (*srv)->metrics().gauge("miracache_audit_open_failed", "1 when the audit log could not be opened (admin API refused).")
        .set(a ? 0 : 1);
    if (!a) {
      logm(log::Level::Error, "audit log cannot be opened: admin API refused, data plane keeps serving",
           {{"dir", audit_dir}, {"err", a.error().context}});
      return false;
    }
    audit = std::move(*a);
    audit_ptr.store(audit.get());
    return true;
  };
  if (!cfg->admin_listen.empty() && !audit_dir.empty()) audit_failed = !open_audit();
  std::unique_ptr<server::AdminHttps> admin;
  // Bundle mode: [control] trust_keys. Loads the trust file, the floor and bundle.current (re-verified; an
  // unverifiable one is logged, counted and the node serves without a bundle). A bad trust file or a corrupt floor
  // is fatal at start-up. STATIC: switching modes needs a restart.
  std::unique_ptr<server::BundleStore> bundle;
  if (!cfg->trust_keys.empty()) {
    server::BundleStoreOptions bo;
    bo.state_dir = cfg->server.store.state_dir;
    bo.trust_path = cfg->trust_keys;
    bo.node_id = my_id;
    bo.hostname = log::hostname();
    bo.addr = server::listen_addr_string(cfg->server);
    bo.admin = cfg->admin_listen;
    bo.dyn_base = (*srv)->dyn_base();  // a pushed bundle's config.cluster.memnode is validated against it
    bo.reg = &(*srv)->metrics();
    bo.snapshot = [s = srv->get()] { return s->node_snapshot(); };
    bo.clock = &clock;
    bo.audit_anchor = [&audit_ptr] {
      auto* a = audit_ptr.load();
      return a ? a->anchor() : std::make_pair(std::uint64_t{0}, std::string(64, '0'));  // last FSYNCED entry
    };
    {  // GET /v1/identity rails (refuse to start when a rail's subnet or the transport is unusable)
      const auto p = fabs.front()->active_protocol();
      const char* proto = p == fabric::protocol::Protocol::IWarp ? "iwarp"
                          : p == fabric::protocol::Protocol::InfiniBand ? "ib" : "roce";
      auto br = server::bundle_rails(cfg->server.rails, proto, cfg->rail_subnets);
      if (!br.error.empty()) {
        logm(log::Level::Error, "bundle mode cannot advertise this node's rails",
             {{"rail", br.bad_rail}, {"transport", proto}, {"err", br.error}});
        return 1;
      }
      bo.rails = std::move(br.rails);
    }
    auto b = server::BundleStore::open(std::move(bo));
    if (!b) {
      logm(log::Level::Error, "bundle store failed", {{"err", b.error().context}});
      return 1;
    }
    bundle = std::move(*b);
    bundle->set_rails_up(true);  // the RDMA listeners started above (a failed start exits)
  }
  // drop_before maxima live in the floor file (bundle deliveries, and POST /v1/drop_principal in both modes); honour
  // them even if the stored bundle no longer carries them. A floor that cannot be read is fatal, never silently skipped
  if (auto st = server::load_persisted_drop_before(**srv, cfg->server.store.state_dir); !st) {
    logm(log::Level::Error, "bundle-floor unreadable: refusing to start (persisted revocations would be lost)",
         {{"state_dir", cfg->server.store.state_dir}, {"err", st.error().context}});
    return 1;
  }
  if (bundle) {
    if (auto v = bundle->startup_view()) (*srv)->apply_bundle(*v);  // store thread, before the loop runs
  }
  auto admin_opts = [&wake, my_id, &bundle, &audit, &audit_failed](const server::NodeConfig& c, std::uint64_t ttl_s) {
    // A posted ticket request wakes the store loop (no idle-tick delay).
    server::AdminOptions o{c.admin_listen, c.admin_cert, c.admin_key, c.admin_ca, ttl_s, c.admin_max_conns,
                           [&wake] { wake.signal(); }};
    o.node_id = my_id;  // plan 2C: the response tells the client who answered
    o.hostname = log::hostname();
    o.bundle = bundle.get();
    o.audit = audit.get();
    o.audit_failed = audit_failed;
    o.drain_ms = c.drain_ms;
    o.state_dir = c.server.store.state_dir;
    for (const auto& [id, roles] : c.admin_rbac) o.lab_rbac.push_back({id, roles});
    return o;
  };
  const std::uint64_t ttl_s = static_cast<std::uint64_t>(
      std::chrono::duration_cast<std::chrono::seconds>(cfg->server.ticket_ttl).count());
  {
    MaskTermSignals mask;
    auto a = server::AdminHttps::start(admin_opts(*cfg, ttl_s), (*srv)->metrics());
    if (!a) {
      logm(log::Level::Error, "admin start failed", {{"err", a.error().context}});
      return 1;
    }
    admin = std::move(*a);
    if (admin) logm(log::Level::Info, "admin (mTLS) on", {{"listen", cfg->admin_listen}, {"port", std::to_string(admin->port())}});
  }
  logm(log::Level::Info, "listening");

  Nanos next_lab = Nanos{0};
  bool draining = false;
  Nanos drain_end{0};
  while (!g_stop) {
    wake.clear();  // BEFORE draining the executor: a signal() after this is seen by the poll below
    if (g_term && !draining) {
      if (cfg->drain_ms == 0) break;
      draining = true;
      drain_end = clock.now() + std::chrono::milliseconds(cfg->drain_ms);
      (*srv)->begin_drain(proto::GoawayReason::Shutdown, cfg->drain_ms);
      logm(log::Level::Info, "SIGTERM: GOAWAY sent", {{"drain_ms", std::to_string(cfg->drain_ms)}});
    }
    if (draining && ((*srv)->drain_idle() || clock.now() >= drain_end)) {
      logm(log::Level::Info, (*srv)->drain_idle() ? "drain complete" : "drain deadline reached");
      break;
    }
    if (g_reload.exchange(false)) {  // SIGHUP: re-read [telemetry] listen and rebind if it changed
      if (auto nc = server::load_node_config(config_path)) {
        // Lab identities: added ones are bound, removed ones are revoked (tickets and connections).
        (*srv)->reload_identities(nc->server.lab_identity, nc->server.lab_identities, nc->server.lab_principal);
        cfg->server.lab_identity = nc->server.lab_identity;  // the lab ticket writer follows the reload
        // lab mode takes every class A key from this file; bundle mode only node.drain_ms (the rest
        // comes from the bundle). A STATIC key that changed rejects the whole dynamic reload: the old snapshot stays.
        if (auto plan = server::plan_sighup(boot_file, *nc, *(*srv)->dyn(), bundle != nullptr, conns_default, tickets_default);
            plan.dyn) {
          (*srv)->apply_dyn(plan.dyn, "sighup");
          cfg->drain_ms = nc->drain_ms;
        } else {
          std::string names;
          for (const auto& k : plan.static_changed) names += (names.empty() ? "" : ",") + k;
          (*srv)->count_config_rejected("STATIC key changed (restart the node)");
          logm(log::Level::Warn, "reload: STATIC keys changed, dynamic keys not applied", {{"keys", names}});
          if (std::find(plan.static_changed.begin(), plan.static_changed.end(), "node.rails") != plan.static_changed.end())
            logm(log::Level::Warn, "rails change needs a restart (keeping the old rails)", {{"rails", server::listen_addr_string(cfg->server)}});
          if (std::find(plan.static_changed.begin(), plan.static_changed.end(), "admin.ca") != plan.static_changed.end())
            logm(log::Level::Warn, "admin.ca path change needs a restart (keeping the old path; the file's contents still reload)",
                 {{"admin_ca", cfg->admin_ca}});
        }
        nc->admin_ca = cfg->admin_ca;  // the path is STATIC; only the file's contents reload
        logm(log::Level::Info, "reload", {{"lab_identities", std::to_string(nc->server.lab_identities.size() + (nc->server.lab_identity.empty() ? 0 : 1))}});
        if (bundle) (void)bundle->reload_trust();  // keeps the old keys on failure (logged and counted inside)
        if (nc->telemetry_listen != http_listen) {
          http_listen = nc->telemetry_listen;
          start_http();
        }
        // Admin: same listen -> swap the credentials in place (keeps the old ones on failure);
        // new listen -> rebind (the old listener is closed first; a failure leaves it off).
        bool audit_recovered = false;  // the audit log opens now: the listener restarts to leave the refusing state
        if (audit_failed && !audit_dir.empty()) {
          admin.reset();  // stops its threads before `audit` changes
          audit_failed = !open_audit();
          audit_recovered = !audit_failed;
        }
        const auto o = admin_opts(*nc, static_cast<std::uint64_t>(
                                           std::chrono::duration_cast<std::chrono::seconds>((*srv)->dyn()->ticket_ttl).count()));
        if (admin && !audit_recovered && o.listen == admin->options().listen) {
          if (auto st = admin->reload_credentials(o); !st)
            logm(log::Level::Warn, "admin reload failed (keeping the old credentials)", {{"err", st.error().context}});
        } else {
          admin.reset();
          MaskTermSignals mask;
          auto a = server::AdminHttps::start(o, (*srv)->metrics());
          if (!a) logm(log::Level::Error, "admin start failed", {{"err", a.error().context}});
          else admin = std::move(*a);
        }
      } else {
        (*srv)->count_config_rejected("local file does not parse or has a bad value");
        logm(log::Level::Error, "reload failed", {{"err", nc.error().context}});
      }
    }
    // No refresh during the drain (the node admits no new session; clients must not burn them).
    if (!draining && !cfg->lab_ticket_file.empty() && clock.now() >= next_lab) {
      if (auto st = server::write_lab_tickets(**srv, cfg->server.lab_identity, cfg->lab_ticket_file, cfg->lab_tickets); !st)
        logm(log::Level::Warn, "lab tickets failed (keeping the old file)", {{"err", st.error().context}});
      next_lab = clock.now() + (*srv)->dyn()->ticket_ttl / 2;
    }
    std::size_t work = (*srv)->run_once();
    work += exec.drain_done();
    if (admin) work += admin->pump(**srv);
    if (work == 0) {
      // Idle. Order (see wake_fd.h): the top of the loop cleared `wake` and then drained the
      // executor; here wait_fd() arms the CQ notification and run_once() polls once more (closes the
      // CQ arm/poll race). Then sleep until a completion/connection event (fabric fd) or a worker's
      // queued `done` / a signal (eventfd, level-triggered, so a signal after the clear is never
      // missed), or the next timer: Server::tick() (idle_tick), the lab ticket refresh, the drain end.
      // With no fabric fd (cannot happen with verbs) the loop still sleeps on the eventfd alone.
      std::vector<int> fds;
      for (auto& fb : fabs) fds.push_back(fb->wait_fd());
      const bool have_fd = std::any_of(fds.begin(), fds.end(), [](int x) { return x >= 0; });
      if (!have_fd || (*srv)->run_once() == 0) {
        Nanos t = std::min<Nanos>((*srv)->next_wake_in(), std::chrono::milliseconds(100));  // sane cap
        if (!draining && !cfg->lab_ticket_file.empty()) t = std::min(t, std::max(Nanos{0}, next_lab - clock.now()));
        if (draining) t = std::min(t, std::max(Nanos{0}, drain_end - clock.now()));
        const auto ms = std::chrono::ceil<std::chrono::milliseconds>(t).count();
        if (ms > 0) (void)wake.wait(fds, static_cast<int>(ms));
      }
    }
  }
  // Exit order: no more admin posts; let the workers finish and run every queued `done`, so a
  // Digesting put commits (or is freed) now; then drop the connections and fence the write MRs; mark
  // the superblock clean last. (Before, the clean mark came first and a put could commit after it.)
  // SIG_DFL from here on: nothing reads the flags any more, so a further SIGTERM/SIGINT must stop
  // at once (as documented) instead of being swallowed during exec.stop().
  signals.reset();
  http.reset();
  admin.reset();
  exec.stop();
  exec.drain_done();
  // A refused clean mark (the next start is a cold one, the cache is lost) is exit status 3, so a
  // supervisor or rolling-restart script can tell it from a clean stop (0) without parsing stderr.
  if (auto st = (*srv)->shutdown_clean(); !st) {
    logm(log::Level::Error, "not marked clean", {{"err", st.error().context}});
    logm(log::Level::Error, "stopped (not clean, exit 3)");
    return 3;
  }
  logm(log::Level::Info, "stopped");
  return 0;
#endif
}
