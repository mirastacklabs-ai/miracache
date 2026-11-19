// SPDX-License-Identifier: Apache-2.0
// C ABI (A1.6 L4) over the L3 Client facade. Compiled WITH exceptions (unlike the rest of
// client/) only so every entry point can end in a catch-all: nothing throws across the ABI.
#include "miracache/miracache.h"

#include <sys/eventfd.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

#include "fabric/sim/sim_fabric.h"
#include "scope/engine_native.h"
#include "src/client.h"
#include "src/loopback_port.h"
#include "util/clock.h"
#include "util/nonce_source.h"
#include "util/random.h"

using namespace miracache;

namespace {

thread_local std::string g_last_error;

void set_err(const char* s) noexcept {
  try {
    g_last_error = s ? s : "";
  } catch (...) {
  }
}

int map_code(ErrorCode c) noexcept {
  switch (c) {
    case ErrorCode::InvalidArgument: return MIRA_E_CONFIG;
    case ErrorCode::NotFound: return MIRA_E_NOT_FOUND;
    case ErrorCode::AccessDenied: return MIRA_E_ACCESS;
    case ErrorCode::NotImplemented:
    case ErrorCode::Unsupported: return MIRA_E_UNSUPPORTED;
    case ErrorCode::ResourceExhausted: return MIRA_E_NOMEM;
    default: return MIRA_E_INTERNAL;
  }
}

int fail(const Error& e) noexcept {
  set_err(e.context);
  return map_code(e.code);
}

// Fixed built-in secret for loopback when the caller gives none (test/lab only).
constexpr std::uint8_t kLabSecret[32] = {0x6d, 0x69, 0x72, 0x61, 0x2d, 0x6c, 0x6f, 0x6f, 0x70, 0x62, 0x61,
                                         0x63, 0x6b, 0x2d, 0x6c, 0x61, 0x62, 0x2d, 0x73, 0x65, 0x63, 0x72,
                                         0x65, 0x74, 0x2d, 0x76, 0x31, 0x00, 0x00, 0x00, 0x00, 0x01};

store::StoreConfig lab_store_cfg() {
  using std::chrono::seconds;
  store::StoreConfig c;
  c.segment_bytes = 4u << 20;
  c.run_bytes = 256u << 10;
  c.min_block_bytes = 4096;
  c.n_segments = 8;
  c.gen_chunk = 1000;
  c.put_timeout = seconds(1000);
  c.lease_ttl = seconds(1000);
  c.lease_max = seconds(2000);
  c.principal_default.max_scopes = 8;
  c.principal_default.max_bytes = 16u << 20;
  c.principal_default.idle_ttl = seconds(100000);
  return c;
}

// In-process memory node + simulated fabric. Members are destroyed in reverse order, so the
// Client (held by mira_client, destroyed first) goes before everything here.
struct LoopWorld {
  SimClock clock;
  SeededRandom rng{1};
  fabric::SimNetwork net{clock, rng, {}, {}};
  fabric::SimFabric* srv = nullptr;
  fabric::SimFabric* cli = nullptr;
  std::unique_ptr<LoopbackServer> server;
  InlineExecutor ex;
  OsNonceSource salts;
  std::unique_ptr<LoopbackPort> port;
};

struct Region {
  std::uint8_t* base;
  std::size_t len;
};

}  // namespace

struct mira_scope {
  ScopeKeys sk;
  std::uint32_t group = 0;
};

struct mira_client {
  std::unique_ptr<LoopWorld> world;
  std::unique_ptr<ReloadableEngineNativeProvider> provider;  // HR4: the credential watch swaps its kver
  std::unique_ptr<Client> client;  // declared last: destroyed first
  std::mutex mu;
  bool closed = false;
  std::uint64_t next_region = 1;
  std::map<std::uint64_t, Region> regions;
  std::map<std::uint64_t, int> kinds;  // ticket -> MIRA_OP_*
  std::deque<Completion> pending;
};

namespace {

// Runs `f` with the catch-all; a thrown exception becomes MIRA_E_INTERNAL / MIRA_E_NOMEM.
template <class F>
int guarded(F&& f) noexcept {
  try {
    return f();
  } catch (const std::bad_alloc&) {
    set_err("out of memory");
    return MIRA_E_NOMEM;
  } catch (...) {
    set_err("internal error");
    return MIRA_E_INTERNAL;
  }
}

int submit(mira_client* c, const mira_scope* s, const mira_key* keys, std::size_t n, std::uint32_t timeout_ms,
           int kind, std::uint64_t* ticket_out) {
  if (!c || !s || !ticket_out || (n && !keys)) {
    set_err("null argument");
    return MIRA_E_INVALID;
  }
  std::lock_guard lk(c->mu);
  if (c->closed) {
    set_err("client closed");
    return MIRA_E_CLOSED;
  }
  std::vector<KeyRef> refs(n);
  std::vector<BufRef> bufs;
  for (std::size_t i = 0; i < n; ++i) {
    const mira_key& k = keys[i];
    if (!k.raw || k.raw_len == 0 || (k.parent_len && !k.parent)) {
      set_err("key: empty raw key or null parent");
      return MIRA_E_INVALID;
    }
    refs[i].raw = {reinterpret_cast<const std::byte*>(k.raw), k.raw_len};
    if (k.parent_len) refs[i].parent_raw = {reinterpret_cast<const std::byte*>(k.parent), k.parent_len};
    refs[i].chain_pos = k.chain_pos;
    if (kind != MIRA_OP_LOOKUP) {
      auto it = c->regions.find(k.region);
      if (it == c->regions.end()) {
        set_err("key: unknown region");
        return MIRA_E_INVALID;
      }
      const Region& r = it->second;
      if (k.len == 0 || k.offset > r.len || k.len > r.len - k.offset) {
        set_err("key: [offset, offset+len) outside the region");
        return MIRA_E_INVALID;
      }
      bufs.push_back(BufRef{std::span<std::byte>(reinterpret_cast<std::byte*>(r.base + k.offset), k.len)});
    }
  }
  const Nanos to = std::chrono::milliseconds(timeout_ms ? timeout_ms : 10000);
  Ticket t;
  if (kind == MIRA_OP_LOOKUP)
    t = c->client->lookup(s->sk, s->group, refs, to);
  else if (kind == MIRA_OP_FETCH)
    t = c->client->fetch(s->sk, s->group, refs, bufs, to);
  else
    t = c->client->store(s->sk, s->group, refs, bufs, to);
  c->kinds[t.id] = kind;
  *ticket_out = t.id;
  return MIRA_OK;
}

}  // namespace

extern "C" {

MIRA_API uint32_t mira_abi_version(void) { return MIRA_ABI_VERSION; }

MIRA_API const char* mira_strerror(int code) {
  switch (code) {
    case MIRA_OK: return "ok";
    case MIRA_E_INVALID: return "invalid argument";
    case MIRA_E_CONFIG: return "configuration rejected";
    case MIRA_E_UNSUPPORTED: return "unsupported in this build";
    case MIRA_E_NOT_FOUND: return "not found";
    case MIRA_E_ACCESS: return "access denied";
    case MIRA_E_CLOSED: return "client closed";
    case MIRA_E_NOMEM: return "out of memory";
    case MIRA_E_INTERNAL: return "internal error";
    case MIRA_E_BUFFER: return "buffer too small";
    default: return "unknown error";
  }
}

MIRA_API const char* mira_last_error(void) { return g_last_error.c_str(); }

MIRA_API int mira_client_open(const char* config_path_or_toml, const mira_provider_cfg* prov, mira_client** out) {
  return guarded([&]() -> int {
    if (!config_path_or_toml || !out) {
      set_err("null argument");
      return MIRA_E_INVALID;
    }
    *out = nullptr;
    if (prov && prov->struct_size < sizeof(mira_provider_cfg)) {
      set_err("mira_provider_cfg: struct_size too small");
      return MIRA_E_INVALID;
    }
    auto cfg = load_config(config_path_or_toml);
    if (!cfg) return fail(cfg.error());
    const std::string secret = (prov && prov->secret_file) ? std::string(prov->secret_file) : cfg->secret_file;
    auto p = ReloadableEngineNativeProvider::from_file(secret);
    if (!p) return fail(p.error());
    auto c = Client::open(*cfg, **p);
    if (!c) return fail(c.error());
    auto h = std::make_unique<mira_client>();
    h->provider = std::move(*p);
    h->client = std::move(*c);
    *out = h.release();
    return MIRA_OK;
  });
}

MIRA_API int mira_client_open_loopback(const mira_loopback_opts* opts, mira_client** out) {
  return guarded([&]() -> int {
    if (!out) {
      set_err("null argument");
      return MIRA_E_INVALID;
    }
    *out = nullptr;
    if (opts && opts->struct_size < sizeof(mira_loopback_opts)) {
      set_err("mira_loopback_opts: struct_size too small");
      return MIRA_E_INVALID;
    }
    auto h = std::make_unique<mira_client>();
    SecretSet set;
    {
      const std::uint8_t* sec = (opts && opts->secret32) ? opts->secret32 : kLabSecret;
      std::byte b[32];
      std::memcpy(b, sec, 32);
      set.secrets.emplace(1u, Secret<32>(std::span<const std::byte, 32>(b)));
      set.current = 1;
    }
    auto p = ReloadableEngineNativeProvider::create(set);
    if (!p) return fail(p.error());
    h->provider = std::move(*p);

    auto w = std::make_unique<LoopWorld>();
    w->srv = &w->net.add_node(1);
    w->cli = &w->net.add_node(2);
    auto srv = LoopbackServer::create(*w->srv, w->clock, w->rng, lab_store_cfg());
    if (!srv) return fail(srv.error());
    w->server = std::move(*srv);
    LoopWorld* wp = w.get();
    w->port = std::make_unique<LoopbackPort>(*w->server, 1, 100, [wp] { wp->net.run_until_idle(); });

    Client::Env env;
    env.fab = w->cli;
    env.port = w->port.get();
    env.clock = &w->clock;
    env.executor = &w->ex;
    env.salts = &w->salts;
    env.drive = [wp] {
      if (!wp->net.step()) wp->clock.advance_by(std::chrono::milliseconds(1));
    };
    RuntimeOptions ro;
    if (opts && opts->workers) ro.workers = opts->workers;
    auto cl = Client::open_loopback(env, {}, ro);
    if (!cl) return fail(cl.error());
    h->world = std::move(w);
    h->client = std::move(*cl);
    *out = h.release();
    return MIRA_OK;
  });
}

MIRA_API void mira_client_close(mira_client* c) {
  if (!c) return;
  try {
    {
      std::lock_guard lk(c->mu);
      c->closed = true;
    }
    if (c->client) c->client->shutdown();  // aborts + drains every in-flight op, joins workers
    delete c;
  } catch (...) {
  }
}

MIRA_API int mira_attach_region(mira_client* c, void* base, size_t len, uint64_t* region_out) {
  return guarded([&]() -> int {
    if (!c || !base || !len || !region_out) {
      set_err("null or empty region");
      return MIRA_E_INVALID;
    }
    std::lock_guard lk(c->mu);
    if (c->closed) return MIRA_E_CLOSED;
    const std::uint64_t id = c->next_region++;
    c->regions[id] = Region{static_cast<std::uint8_t*>(base), len};
    *region_out = id;
    return MIRA_OK;
  });
}

MIRA_API int mira_detach_region(mira_client* c, uint64_t region) {
  return guarded([&]() -> int {
    if (!c) return MIRA_E_INVALID;
    std::lock_guard lk(c->mu);
    if (c->regions.erase(region) == 0) {
      set_err("unknown region");
      return MIRA_E_INVALID;
    }
    return MIRA_OK;
  });
}

MIRA_API int mira_derive(mira_client* c, uint32_t engine, const uint8_t ns[32], const uint8_t* root,
                         size_t root_len, uint32_t group, mira_scope** out) {
  return guarded([&]() -> int {
    if (!c || !ns || !root || !root_len || !out || group > 1023 || (engine != 1 && engine != 2)) {
      set_err("bad argument");
      return MIRA_E_INVALID;
    }
    *out = nullptr;
    if (!c->provider) {
      set_err("no scope provider");
      return MIRA_E_UNSUPPORTED;
    }
    RequestMeta meta;
    meta.engine = static_cast<EngineKind>(engine);
    std::memcpy(meta.ns.data(), ns, 32);
    std::vector<std::byte> r(root_len);
    std::memcpy(r.data(), root, root_len);
    meta.roots.assign(static_cast<std::size_t>(group) + 1, r);  // groups < `group` share the root
    auto sk = c->provider->derive(meta);
    if (!sk) return fail(sk.error());
    auto s = std::make_unique<mira_scope>();
    s->sk = std::move(*sk);
    s->group = group;
    *out = s.release();
    return MIRA_OK;
  });
}

MIRA_API void mira_scope_free(mira_scope* s) {
  try {
    delete s;
  } catch (...) {
  }
}

MIRA_API int mira_lookup_nb(mira_client* c, const mira_scope* s, const mira_key* keys, size_t n,
                            uint32_t timeout_ms, uint64_t* ticket_out) {
  return guarded([&] { return submit(c, s, keys, n, timeout_ms, MIRA_OP_LOOKUP, ticket_out); });
}
MIRA_API int mira_fetch(mira_client* c, const mira_scope* s, const mira_key* keys, size_t n,
                        uint32_t timeout_ms, uint64_t* ticket_out) {
  return guarded([&] { return submit(c, s, keys, n, timeout_ms, MIRA_OP_FETCH, ticket_out); });
}
MIRA_API int mira_put(mira_client* c, const mira_scope* s, const mira_key* keys, size_t n,
                      uint32_t timeout_ms, uint64_t* ticket_out) {
  return guarded([&] { return submit(c, s, keys, n, timeout_ms, MIRA_OP_PUT, ticket_out); });
}

MIRA_API size_t mira_poll(mira_client* c, mira_completion* out, size_t max_out, uint8_t* status_buf,
                          size_t status_cap) {
  size_t count = 0;
  bool too_small = false;
  const int rc = guarded([&]() -> int {
    if (!c || (max_out && !out) || (status_cap && !status_buf)) return MIRA_E_INVALID;
    std::lock_guard lk(c->mu);
    Completion tmp[32];
    while (c->pending.size() < max_out) {
      const std::size_t got = c->client->poll(tmp);
      if (got == 0) break;
      for (std::size_t i = 0; i < got; ++i) c->pending.push_back(std::move(tmp[i]));
    }
    std::size_t off = 0;
    while (count < max_out && !c->pending.empty()) {
      Completion& cp = c->pending.front();
      if (cp.status.size() > status_cap - off) {
        if (count == 0) {
          set_err("mira_poll: status_buf too small for the next completion");
          too_small = true;
        }
        break;
      }
      mira_completion& o = out[count++];
      o = mira_completion{};
      o.ticket = cp.ticket.id;
      auto k = c->kinds.find(cp.ticket.id);
      o.kind = k == c->kinds.end() ? MIRA_OP_LOOKUP : static_cast<std::uint32_t>(k->second);
      if (k != c->kinds.end()) c->kinds.erase(k);
      o.n_keys = static_cast<std::uint32_t>(cp.status.size());
      o.status_off = static_cast<std::uint32_t>(off);
      for (KeyStatus st : cp.status) status_buf[off++] = static_cast<std::uint8_t>(st);
      c->pending.pop_front();
    }
    if (!c->pending.empty() && !too_small) {  // keep the eventfd readable for what is left
      const std::uint64_t one = 1;
      [[maybe_unused]] auto w = ::write(c->client->eventfd(), &one, sizeof one);
    }
    return MIRA_OK;
  });
  if (rc == MIRA_OK && too_small) return MIRA_POLL_ERROR;
  return rc == MIRA_OK ? count : 0;
}

MIRA_API int mira_event_fd(mira_client* c) {
  if (!c || !c->client) return -1;
  return c->client->eventfd();
}

MIRA_API int mira_client_metrics(mira_client* c, char* buf, size_t cap, size_t* needed) {
  return guarded([&]() -> int {
    if (!c || (cap && !buf)) {
      set_err("null argument");
      return MIRA_E_INVALID;
    }
    std::string text;
    {
      std::lock_guard lk(c->mu);
      if (c->closed || !c->client) {
        set_err("client closed");
        return MIRA_E_CLOSED;
      }
      text = c->client->metrics_text();
    }
    const std::size_t need = text.size() + 1;
    if (needed) *needed = need;
    if (cap < need) {
      set_err("mira_client_metrics: buffer too small");
      return MIRA_E_BUFFER;
    }
    std::memcpy(buf, text.c_str(), need);
    return MIRA_OK;
  });
}

MIRA_API int mira_check_block_size(mira_client* c, uint64_t block_bytes, size_t* checked) {
  return guarded([&]() -> int {
    if (checked) *checked = 0;
    if (!c) {
      set_err("null argument");
      return MIRA_E_INVALID;
    }
    std::string why;
    std::size_t n = 0;
    {
      std::lock_guard lk(c->mu);
      if (c->closed || !c->client) {
        set_err("client closed");
        return MIRA_E_CLOSED;
      }
      why = c->client->block_size_problem(block_bytes, &n);
    }
    if (checked) *checked = n;
    if (why.empty()) return MIRA_OK;
    g_last_error = std::move(why);
    return MIRA_E_CONFIG;
  });
}

}  // extern "C"
