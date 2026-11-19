// SPDX-License-Identifier: Apache-2.0
#include "fabric/verbs_cm/verbs_cm_fabric.h"
#include "fabric/verbs_cm/qp_readback.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <infiniband/verbs.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <rdma/rdma_cma.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <sstream>
#include <vector>

namespace miracache::fabric {
namespace {

constexpr std::size_t kPageAlign = 4096;
// Spec 3.5: receive buffers are 8 KiB; fetch QPs carry only HELLO and post two receives.
constexpr std::uint32_t kFetchSlotBytes = 8 * 1024;
constexpr std::uint32_t kFetchSlots = 2;
static_assert(kMaxTicketBytes + protocol::kPrivHeader <= 56, "ticket must fit the RoCE CM REQ budget");

Error from_errno(int e, const char* ctx) {
  switch (e) {
    case ENOMEM:
    case EAGAIN:
      return {ErrorCode::ResourceExhausted, ctx};
    case EINVAL:
    case EFAULT:
    case EBADF:
      return {ErrorCode::InvalidArgument, ctx};
    case EACCES:
    case EPERM:
      return {ErrorCode::AccessDenied, ctx};
    case ETIMEDOUT:
      return {ErrorCode::Timeout, ctx};
    case ENODEV:
    case ENOENT:
      return {ErrorCode::NotFound, ctx};
    case EOPNOTSUPP:
    case ENOSYS:
      return {ErrorCode::Unsupported, ctx};
    case ENETUNREACH:
    case EHOSTUNREACH:
    case ECONNREFUSED:
    case ENETDOWN:
      return {ErrorCode::LinkDown, ctx};
    default:
      return {ErrorCode::Aborted, ctx};
  }
}

// Q6: the local device would not create a resource (CQ, completion channel, PD, MR, QP): recorded for the caller
// (fabric::last_local_failure), which reports the call, errno and device and tells it from a remote/connect failure.
Error local_fail(int e, const char* call, const std::string& device) {
  last_local_failure() = LocalFailure{call, e, device, -1};
  return from_errno(e, call);
}

Error from_wc(ibv_wc_status st) {
  const char* ctx = ibv_wc_status_str(st);  // static storage
  switch (st) {
    case IBV_WC_WR_FLUSH_ERR:
      return {ErrorCode::Aborted, ctx};
    case IBV_WC_REM_ACCESS_ERR:
    case IBV_WC_LOC_PROT_ERR:
    case IBV_WC_MW_BIND_ERR:
      return {ErrorCode::AccessDenied, ctx};
    case IBV_WC_REM_INV_REQ_ERR:
    case IBV_WC_LOC_LEN_ERR:
    case IBV_WC_REM_OP_ERR:
    case IBV_WC_LOC_QP_OP_ERR:
      return {ErrorCode::InvalidArgument, ctx};
    case IBV_WC_RETRY_EXC_ERR:
    case IBV_WC_RNR_RETRY_EXC_ERR:
      return {ErrorCode::Timeout, ctx};
    default:
      return {ErrorCode::Aborted, ctx};
  }
}

int to_ibv_access(Access a) {
  int f = 0;
  if (has(a, Access::LocalWrite)) f |= IBV_ACCESS_LOCAL_WRITE;
  if (has(a, Access::RemoteRead)) f |= IBV_ACCESS_REMOTE_READ;
  if (has(a, Access::RemoteWrite)) f |= IBV_ACCESS_REMOTE_WRITE;
  return f;
}

std::uint32_t mtu_bytes(ibv_mtu m) {
  switch (m) {
    case IBV_MTU_256: return 256;
    case IBV_MTU_512: return 512;
    case IBV_MTU_1024: return 1024;
    case IBV_MTU_2048: return 2048;
    case IBV_MTU_4096: return 4096;
  }
  return 0;
}

bool read_file_line(const std::string& path, std::string& out) {
  std::ifstream f(path);
  return static_cast<bool>(std::getline(f, out));
}

void set_nonblock(int fd) {
  const int fl = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

bool make_sockaddr(const RailAddr& a, sockaddr_in& sa) {
  std::memset(&sa, 0, sizeof sa);
  sa.sin_family = AF_INET;
  sa.sin_port = htons(a.port);
  if (a.host.empty()) {
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    return true;
  }
  return inet_pton(AF_INET, a.host.c_str(), &sa.sin_addr) == 1;
}

}  // namespace

// ---------------------------------------------------------------------------------
// Per-device async event dispatcher. The async event fd belongs to librdmacm's shared
// ibv_context, so every fabric on a device would otherwise steal the others' events. One
// dispatcher per ibv_context (refcounted, process-wide) owns the fd, and routes QP events
// by the QP's owning fabric and CQ events by CQ; port and device errors go to every fabric
// on the context. Delivery is a push into the fabric's own queue: the dispatcher thread
// never touches fabric state, the fabric's poll() applies the effect.
// ---------------------------------------------------------------------------------
namespace detail {

struct AsyncNote {
  AsyncEventKind kind = AsyncEventKind::QpFatal;
  EndpointId ep = 0;  // QpFatal
  int port = 0;       // PortErr
};

class AsyncSink {
 public:
  virtual void push_async(const AsyncNote& n) = 0;  // thread-safe, non-blocking

 protected:
  ~AsyncSink() = default;
};

class AsyncDispatcher {
 public:
  // Null when the dispatcher cannot start (eventfd or thread creation failed); `why` says which.
  static AsyncDispatcher* acquire(ibv_context* ctx, const char** why) {
    std::lock_guard<std::mutex> g(registry_mu());
    auto& reg = registry();
    auto it = reg.find(key(ctx));
    if (it == reg.end()) {
      auto d = std::unique_ptr<AsyncDispatcher>(new AsyncDispatcher(ctx));
      if (const char* err = d->start(); err != nullptr) {
        *why = err;
        return nullptr;
      }
      it = reg.emplace(key(ctx), Slot{std::move(d), 0}).first;
    }
    ++it->second.refs;
    return it->second.disp.get();
  }
  static void release(AsyncDispatcher* d) {
    std::lock_guard<std::mutex> g(registry_mu());
    auto it = registry().find(key(d->ctx_));
    if (it == registry().end() || it->second.disp.get() != d) return;
    if (--it->second.refs == 0) registry().erase(it);  // ~AsyncDispatcher joins the thread
  }
  // A fabric of this process holds the context's dispatcher: it has (or is about to have) rings on the context.
  static bool live(const ibv_context* ctx) {
    std::lock_guard<std::mutex> g(registry_mu());
    return registry().count(key(ctx)) != 0;
  }

  void add_sink(AsyncSink* s) {
    std::lock_guard<std::mutex> g(mu_);
    sinks_.push_back(s);
    // The device died before this fabric joined: it must not wait for an event that already went.
    if (dead_) s->push_async({AsyncEventKind::DeviceFatal, 0, 0});
  }
  void remove_sink(AsyncSink* s) {  // also forgets everything the sink registered
    std::lock_guard<std::mutex> g(mu_);
    sinks_.erase(std::remove(sinks_.begin(), sinks_.end(), s), sinks_.end());
    std::erase_if(qps_, [s](const auto& kv) { return kv.second.sink == s; });
    std::erase_if(cqs_, [s](const auto& kv) { return kv.second == s; });
  }
  void add_qp(ibv_qp* qp, AsyncSink* s, EndpointId ep) {
    std::lock_guard<std::mutex> g(mu_);
    qps_[key(qp)] = QpOwner{s, ep};
  }
  void remove_qp(ibv_qp* qp) {
    std::lock_guard<std::mutex> g(mu_);
    qps_.erase(key(qp));
  }
  void add_cq(ibv_cq* cq, AsyncSink* s) {
    std::lock_guard<std::mutex> g(mu_);
    cqs_[key(cq)] = s;
  }

  // The routing table. Called by the dispatcher thread for real events and by the test hook.
  void route(AsyncEventKind kind, ibv_qp* qp, ibv_cq* cq, int port) {
    std::lock_guard<std::mutex> g(mu_);
    switch (kind) {
      case AsyncEventKind::QpFatal:
        if (auto it = qps_.find(key(qp)); it != qps_.end()) it->second.sink->push_async({kind, it->second.ep, 0});
        break;
      case AsyncEventKind::CqErr:
        if (auto it = cqs_.find(key(cq)); it != cqs_.end()) it->second->push_async({kind, 0, 0});
        break;
      case AsyncEventKind::PortErr:
      case AsyncEventKind::DeviceFatal:
        for (AsyncSink* s : sinks_) s->push_async({kind, 0, port});
        break;
    }
  }

  ~AsyncDispatcher() {
    if (started_) {
      stopping_.store(true);
      const std::uint64_t one = 1;
      static_cast<void>(::write(stop_fd_, &one, sizeof one));
      pthread_join(th_, nullptr);
    }
    // The async fd is librdmacm's (shared ibv_context): hand it back in the blocking mode
    // we found it in, now that no thread polls it.
    if (async_fl_ >= 0) fcntl(ctx_->async_fd, F_SETFL, async_fl_);
    if (stop_fd_ >= 0) ::close(stop_fd_);
  }

  // Test hook: makes the dispatcher thread take its fatal-exit path, as if the async fd had
  // reported POLLERR/POLLHUP (device removal).
  void kill_for_test() {
    kill_for_test_.store(true);
    const std::uint64_t one = 1;
    static_cast<void>(::write(stop_fd_, &one, sizeof one));
  }

 private:
  struct QpOwner {
    AsyncSink* sink = nullptr;
    EndpointId ep = 0;
  };
  struct Slot {
    std::unique_ptr<AsyncDispatcher> disp;
    int refs = 0;
  };
  static std::uintptr_t key(const void* p) { return reinterpret_cast<std::uintptr_t>(p); }
  // Both intentionally leaked: a fabric destroyed by another static's destructor at exit
  // must not find the registry or its mutex already gone.
  static std::mutex& registry_mu() {
    static auto* m = new std::mutex;
    return *m;
  }
  static std::map<std::uintptr_t, Slot>& registry() {
    static auto* reg = new std::map<std::uintptr_t, Slot>;
    return *reg;
  }

  explicit AsyncDispatcher(ibv_context* ctx) : ctx_(ctx) {}
  // Returns null on success, else what failed.
  const char* start() {
    stop_fd_ = ::eventfd(0, EFD_CLOEXEC);
    if (stop_fd_ < 0) return "async event dispatcher: eventfd failed";
    async_fl_ = fcntl(ctx_->async_fd, F_GETFL, 0);
    set_nonblock(ctx_->async_fd);
    // pthread_create, not std::thread: the build has no exceptions, so a std::thread that
    // cannot start would terminate the process instead of failing open().
    if (pthread_create(&th_, nullptr, &thread_entry, this) != 0) {  // lint:dispatcher-thread
      if (async_fl_ >= 0) fcntl(ctx_->async_fd, F_SETFL, async_fl_);
      async_fl_ = -1;
      return "async event dispatcher: thread creation failed";
    }
    started_ = true;
    return nullptr;
  }
  static void* thread_entry(void* self) {
    static_cast<AsyncDispatcher*>(self)->thread_main();
    return nullptr;
  }
  void thread_main() {
    const char* why = run();
    if (stopping_.load()) return;
    // Any other exit leaves the device without event delivery: nothing on it can be trusted
    // any more, so every fabric on the context fails all its endpoints, once.
    log::write(log::Level::Error, "verbs_cm", "async event dispatcher exiting: device fatal",
               {{"device", ibv_get_device_name(ctx_->device)}, {"why", why}});
    std::lock_guard<std::mutex> g(mu_);
    dead_ = true;
    for (AsyncSink* s : sinks_) s->push_async({AsyncEventKind::DeviceFatal, 0, 0});
  }
  // Returns why it stopped: the stop request, or a fatal condition of the async fd.
  const char* run() {
    for (;;) {
      pollfd p[2] = {{ctx_->async_fd, POLLIN, 0}, {stop_fd_, POLLIN, 0}};
      if (::poll(p, 2, -1) < 0) {
        if (errno == EINTR) continue;
        return "poll failed";
      }
      if (p[1].revents != 0) return kill_for_test_.load() ? "killed by test hook" : "stopped";
      if ((p[0].revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) return "async fd error/hangup (device removed?)";
      ibv_async_event ev;
      for (;;) {
        if (ibv_get_async_event(ctx_, &ev) != 0) {
          if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) break;
          return "ibv_get_async_event failed";
        }
        switch (ev.event_type) {
          case IBV_EVENT_QP_FATAL:
          case IBV_EVENT_QP_REQ_ERR:
          case IBV_EVENT_QP_ACCESS_ERR:
            route(AsyncEventKind::QpFatal, ev.element.qp, nullptr, 0);
            break;
          case IBV_EVENT_CQ_ERR:
            route(AsyncEventKind::CqErr, nullptr, ev.element.cq, 0);
            break;
          case IBV_EVENT_PORT_ERR:
            route(AsyncEventKind::PortErr, nullptr, nullptr, ev.element.port_num);
            break;
          case IBV_EVENT_DEVICE_FATAL:
            route(AsyncEventKind::DeviceFatal, nullptr, nullptr, 0);
            break;
          default:
            break;
        }
        ibv_ack_async_event(&ev);
      }
    }
  }

  ibv_context* ctx_;
  int stop_fd_ = -1;
  int async_fl_ = -1;  // the async fd's flags before we made it non-blocking
  std::atomic<bool> stopping_{false};
  std::atomic<bool> kill_for_test_{false};
  pthread_t th_{};
  bool started_ = false;  // th_ is a live (joinable) thread
  std::mutex mu_;
  bool dead_ = false;  // the thread exited on a fatal condition (guarded by mu_)
  // Keyed by address as an integer (identity only, never iterated in address order).
  std::vector<AsyncSink*> sinks_;
  std::map<std::uintptr_t, QpOwner> qps_;
  std::map<std::uintptr_t, AsyncSink*> cqs_;
};

// Soft-iWARP mmap-key sentinel. The siw kernel module hands out ring mmap keys
// first-fit from page 0 of the ucontext's mmap space, and libsiw treats key 0x90000 (page 144, SIW_INVAL_UOBJ_KEY) as
// "invalid": any CQ/QP ring whose mapping starts on page 144 is refused, with no errno. The ballast is one long-lived
// CQ of kEntries entries (32 B CQEs + 8 B control = 257 pages, pgoff 0-256) created as the first ring of each siw
// ibv_context, so page 144 is never free for a real ring. librdmacm shares one context per device per process, so there
// is one ballast per device, refcounted by the fabrics on it and destroyed with the last one (after its rings). It must
// be first: every fabric acquires it before it creates any CQ or QP. A failed creation is sticky while fabrics hold the
// slot, so they all keep the deep-ring floor instead.
// ASSUMPTION (s11c review P3-1): no foreign rings on this context. The verbs API cannot list a context's CQs/QPs, so the
// ballast's place is proven only against what this process knows: when the slot is created while a fabric of this process
// already holds the context's async dispatcher (it has rings there without a ballast), the ballast is not first, and every
// holder of that slot keeps the kSoftRingFloor fallback too. Rings created on librdmacm's shared context by code outside
// VerbsCmFabric (another library in the same process) are invisible; miracache creates none.
class SiwBallast {
 public:
  static constexpr int kEntries = 32768;
  struct Held {
    bool in_place = false;  // the ballast CQ exists on this context
    bool first = false;     // ... and no ring of this process predates it (else the floor still applies)
    bool created = false;   // this acquire created it
    int err = 0;            // errno of the failed creation (0 = none reported)
  };
  static Held acquire(ibv_context* ctx) {
    std::lock_guard<std::mutex> g(mu());
    auto& reg = registry();
    auto it = reg.find(key(ctx));
    Held h;
    if (it == reg.end()) {
      const bool first = !AsyncDispatcher::live(ctx);
      errno = 0;
      ibv_cq* cq = ibv_create_cq(ctx, kEntries, nullptr, nullptr, 0);
      it = reg.emplace(key(ctx), Slot{cq, 0, cq == nullptr ? errno : 0, first}).first;
      h.created = cq != nullptr;
    }
    ++it->second.refs;
    h.in_place = it->second.cq != nullptr;
    h.first = h.in_place && it->second.first;
    h.err = it->second.err;
    return h;
  }
  static void release(ibv_context* ctx) {
    std::lock_guard<std::mutex> g(mu());
    auto it = registry().find(key(ctx));
    if (it == registry().end() || --it->second.refs > 0) return;
    if (it->second.cq != nullptr) {
      if (const int rc = ibv_destroy_cq(it->second.cq); rc != 0) {
        log::write(log::Level::Warn, "verbs_cm", "soft-iWARP provider: destroying the ballast CQ failed",
                   {{"device", ibv_get_device_name(ctx->device)},
                    {"call", "ibv_destroy_cq"},
                    {"errno", std::string(std::strerror(rc))}});
      }
    }
    registry().erase(it);
  }

 private:
  struct Slot {
    ibv_cq* cq = nullptr;
    int refs = 0;
    int err = 0;
    bool first = false;  // no fabric of this process held the context when the ballast was created
  };
  static std::uintptr_t key(const void* p) { return reinterpret_cast<std::uintptr_t>(p); }
  // Leaked on purpose, as the dispatcher registry: a fabric destroyed at static teardown must still find them.
  static std::mutex& mu() {
    static auto* m = new std::mutex;
    return *m;
  }
  static std::map<std::uintptr_t, Slot>& registry() {
    static auto* reg = new std::map<std::uintptr_t, Slot>;
    return *reg;
  }
};

}  // namespace detail

std::string to_string(const NicCaps& c) {
  std::ostringstream o;
  o << "NicCaps{device=" << c.device << " protocol=" << to_string(c.protocol) << " (" << c.node_type << ")"
    << " fw=" << c.firmware << "\n"
    << "  max_mr_size=" << c.max_mr_size << " max_mr=" << c.max_mr << " max_qp=" << c.max_qp
    << " max_qp_wr=" << c.max_qp_wr << " max_cqe=" << c.max_cqe << "\n"
    << "  max_qp_rd_atom(IRD)=" << c.max_qp_rd_atom << " max_qp_init_rd_atom(ORD)=" << c.max_qp_init_rd_atom
    << " max_inline_data=" << c.max_inline_data << "\n"
    << "  active_mtu=" << c.active_mtu << " netdev_mtu=" << c.netdev_mtu
    << " read_sink_needs_remote_write=" << c.read_sink_needs_remote_write << "\n"
    << "  trial_reg_1MiB=" << c.trial_reg_ok << " mw_flag=" << c.mw_flag_advertised
    << " mw_alloc_ok=" << c.mw_alloc_ok << " (errno " << c.mw_alloc_errno << ")"
    << " dmabuf="
    << (c.dmabuf == DmabufProbe::Works ? "works"
        : c.dmabuf == DmabufProbe::EntryPointPresent ? "entry-point-present" : "unsupported")
    << " (errno " << c.dmabuf_errno << ")}";
  return o.str();
}

// ---------------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------------

struct VerbsCmFabric::Impl final : detail::AsyncSink {
  class Ep;

  enum class WrKind : std::uint8_t { Send, Read, Write, Recv };
  struct Wr {
    Ep* ep = nullptr;
    WrKind kind = WrKind::Send;
    WrTag tag = 0;
    std::uint32_t slot = 0;  // send/recv slot
    std::uint32_t lkey = 0;  // pinned region (Read/Write)
    std::uint32_t len = 0;   // bytes moved on success (byte_len is unreliable for READ/WRITE)
    std::uint64_t zid = 0;   // ep == nullptr: the QP is gone; settles zombies_[zid] when this WR flushes
  };
  // CQE reservation of a destroyed QP, held until its flush completions are drained (N08).
  struct Zombie {
    std::uint32_t reserve = 0;
    std::uint32_t left = 0;        // WRs still to flush
    Nanos died{0};                 // clock time the QP was destroyed
  };

  struct Region {
    MemRegion mr;
    ibv_mr* ibv = nullptr;
    PdId pd;
  };

  struct Lst;  // a listener (RL1), defined below
  // ---- Endpoint ----
  class Ep final : public Endpoint {
   public:
    Ep(Impl& f, EndpointId id, EpClass cls, PdId pd) : f_(f), id_(id), cls_(cls), pd_id_(pd) {}
    ~Ep() override { release(); }

    EndpointId id() const override { return id_; }
    Status post_send(Frame frame, WrTag tag) override;
    Status post_read(RemoteRef remote, LocalRef local, WrTag tag) override;
    Status post_write(LocalRef local, RemoteRef remote, WrTag tag) override;
    void abort() override;
    bool drained() const override { return outstanding_ == 0; }
    EpState state() const override { return phase_ == Phase::Ready ? EpState::Ready : EpState::Error; }
    ReadDepth read_depth() const override { return depth_; }
    std::span<const std::byte> peer_private_data() const override { return priv_; }
    std::string peer_addr() const override {
      if (cm_ == nullptr) return {};
      const sockaddr* sa = rdma_get_peer_addr(cm_);
      char ip[INET6_ADDRSTRLEN] = "";
      if (sa != nullptr && sa->sa_family == AF_INET)
        inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr, ip, sizeof ip);
      else if (sa != nullptr && sa->sa_family == AF_INET6)
        inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr, ip, sizeof ip);
      if (ip[0] == '\0') return {};
      return std::string(ip) + ":" + std::to_string(ntohs(rdma_get_dst_port(cm_)));
    }

    // ---- internals ----
    enum class Phase : std::uint8_t { Connecting, Accepting, Ready, Error };
    std::uint32_t frame_cap() const { return slot_bytes_; }
    Status check_posting() const;
    Status post_wr(ibv_send_wr& wr, WrKind kind, WrTag tag, std::uint32_t slot, std::uint32_t lkey,
                   std::uint32_t len);
    Status post_recv(std::uint32_t slot);
    void fail();  // QP -> ERR; outstanding work flushes through the CQ
    void release();
    std::byte* recv_buf(std::uint32_t i) { return buf_ + static_cast<std::size_t>(i) * slot_bytes_; }
    std::byte* send_buf(std::uint32_t i) { return buf_ + (static_cast<std::size_t>(recv_slots_) + i) * slot_bytes_; }

    Impl& f_;
    EndpointId id_;
    EpClass cls_;
    PdId pd_id_;
    std::uint32_t recv_slots_ = 0, send_slots_ = 0, slot_bytes_ = 0;  // per-class layout (spec 3.5)
    std::uint32_t cqe_reserve_ = 0;  // CQ entries reserved for this QP
    bool surfaced_ = false;          // handed to the caller (returned by connect / passed to AcceptFn)
    std::deque<Completion> early_;   // Recv completions that beat the announcement; delivered after it
    Nanos accept_deadline_{0};       // passive side: give up on ESTABLISHED at this time
    bool deferred_est_ = false;      // test hook: ESTABLISHED seen but not yet announced
    protocol::Protocol peer_proto_ = protocol::Protocol::Unknown;  // from the accept private_data
    bool peer_version_bad_ = false;  // the accept private_data had a version we do not speak
    protocol::Protocol proto_ = protocol::Protocol::Unknown;
    std::uint32_t epoch_ = 0;
    std::uint8_t reject_code_ = 0;
    Phase phase_ = Phase::Connecting;
    bool active_ = false;
    bool ack_opt_set_ = false;  // active side: rdma_set_option(ACK_TIMEOUT) was accepted (B11: only then is it compared)
    rdma_cm_id* cm_ = nullptr;
    bool has_qp_ = false;
    ibv_pd* pd_ = nullptr;
    std::byte* buf_ = nullptr;
    ibv_mr* buf_mr_ = nullptr;
    std::vector<std::uint32_t> free_send_;
    std::uint32_t outstanding_ = 0;
    std::uint8_t ird_cfg_ = 0, ord_cfg_ = 0;  // what we put in rdma_conn_param
    protocol::Depth peer_depth_;              // the peer's announced IRD/ORD (accept private_data)
    ReadDepth depth_;
    std::vector<std::byte> priv_;
    // Connect wait state (active side): last CM event seen for this id.
    rdma_cm_event_type last_ev_ = static_cast<rdma_cm_event_type>(-1);
    int last_status_ = 0;
    bool got_ev_ = false;
    rdma_conn_param established_{};
    Lst* lst_ = nullptr;  // passive side: the listener that accepted this endpoint
  };

  // ---- state ----
  VerbsOptions opt_;
  RealClock real_clock_;
  const Clock* clock_ = nullptr;
  NicCaps caps_;
  ibv_context** dev_list_ = nullptr;  // from rdma_get_devices; contexts are librdmacm's
  ibv_context* ctx_ = nullptr;
  std::map<std::uint32_t, ibv_pd*> pds_;  // PdId::v -> PD; 0 = default, created lazily
  std::uint32_t next_pd_ = 1;
  std::uint32_t cq_reserved_ = 0;         // CQEs promised to live QPs, against opt_.cq_depth
  ibv_comp_channel* comp_ = nullptr;
  ibv_cq* cq_ = nullptr;
  unsigned unacked_cq_events_ = 0;
  rdma_event_channel* cm_chan_ = nullptr;
  int epfd_ = -1;
  std::uint32_t max_frame_ = static_cast<std::uint32_t>(kMaxFrameBytes);
  protocol::Protocol detected_ = protocol::Protocol::Unknown;
  protocol::Protocol proto_ = protocol::Protocol::Unknown;  // what new endpoints use
  std::uint32_t proto_epoch_ = 1;

  std::vector<std::unique_ptr<Ep>> eps_;
  // RL1: several listeners per fabric (one per rail address on this device), each with its own accept and admit
  // callbacks. Connect requests are routed by the CM event's listen_id.
  struct Lst {
    rdma_cm_id* id = nullptr;
    AcceptFn on_accept;
    AdmitFn admit;
    EpClass accept_class = EpClass::Control;  // used only without an AdmitFn
    PdId accept_pd;
    std::string host;      // bound IPv4 literal; empty = wildcard
    bool cm_broken = false;  // the CM reported the address or device gone for this listener
  };
  std::deque<Lst> lsts_;  // stable addresses
  Lst* find_lst(const rdma_cm_id* id) {
    for (auto& l : lsts_)
      if (l.id == id) return &l;
    return nullptr;
  }
  std::uint16_t listen_port_ = 0;
  // Health inputs (RL1): applied by drain_async() on the polling thread.
  bool device_fatal_ = false;           // DeviceFatal seen (the device is gone for good)
  bool port_err_seen_ = false;
  Nanos port_err_at_{0};
  static constexpr Nanos kFatalWindow = std::chrono::seconds(10);
  std::uint32_t max_pending_ = 64;
  Nanos accept_timeout_ = std::chrono::seconds(5);

  // Async events (N01): the dispatcher thread pushes, poll() applies.
  detail::AsyncDispatcher* disp_ = nullptr;
  int async_efd_ = -1;
  std::mutex async_mu_;
  std::deque<detail::AsyncNote> async_q_;
  std::map<std::uint64_t, Zombie> zombies_;
  std::uint64_t next_zombie_ = 1;
  static constexpr int kPort = 1;  // the port this fabric uses (probe, device_ipv4)

  std::map<std::uint32_t, Region> regions_;  // by lkey
  std::map<std::uint32_t, std::uint32_t> pins_;
  std::map<std::uint64_t, Wr> wrs_;
  std::uint64_t next_wr_ = 1;
  EndpointId next_ep_ = 1;
  std::deque<Completion> ready_;  // completions produced while servicing events
  // A broken CQ (ibv_poll_cq failure or a CQ_ERR async event) is fatal: every endpoint is
  // failed, one CqError completion is reported, and nothing recovers it. The only cleanup
  // path is destroying the fabric (see VerbsCmFabric docs).
  bool cq_broken_ = false;
  bool cq_error_reported_ = false;

  ~Impl();
  void push_async(const detail::AsyncNote& n) override {
    {
      std::lock_guard<std::mutex> g(async_mu_);
      async_q_.push_back(n);
    }
    const std::uint64_t one = 1;
    static_cast<void>(::write(async_efd_, &one, sizeof one));
  }
  void drain_async();
  void retire_reserve(Ep* ep);
  void settle_zombie(std::uint64_t zid);
  void tick_zombies();
  void reclaim_cq();
  void surface(Ep* ep, bool announce);
  Status init();
  void probe_caps();
  ibv_pd* pd_ptr(PdId id);
  void reap_unsurfaced();
  void log(const char* msg) const { log::write(log::Level::Warn, "verbs_cm", msg, {{"device", caps_.device}}); }
  std::atomic<bool> ack_timeout_warned_{false};  // r7 R11: rdma_set_option(ACK_TIMEOUT) refusal, logged once
  QpReadback qp_readback_;  // B11
  void readback_qp(Ep* ep, rdma_cm_id* id);
  std::atomic<bool> inline_warned_{false};       // A3.3: the profile max_inline was refused, logged once
  // Soft-iWARP (libsiw + the siw kernel module) refuses any ring whose mmap starts on page 144 (detail::SiwBallast).
  // On that provider only (vendor ID, never a device name) the fabric holds the per-device ballast CQ that pins the
  // page. Only if the ballast cannot be created, or cannot be proven the context's first ring, do QP rings fall back to
  // at least kSoftRingFloor entries (run #266's floor, which dodged page 144 by layout luck); the fabric still posts and
  // budgets by sq_depth / recv_slots (R01).
  static constexpr std::uint32_t kSoftIwarpVendorId = 0x626d74;  // libsiw / siw kernel module
  static constexpr std::uint32_t kSoftRingFloor = 1024;
  bool soft_rings_ = false;     // the floor applies (siw without a ballast proven first)
  bool siw_ballast_ = false;    // this fabric holds a ref on its device's ballast (released last in ~Impl)
  void acquire_siw_ballast();
  std::uint32_t read_ird_max() const { return caps_.max_qp_rd_atom; }

  Ep* new_ep(EpClass cls, PdId pd) {
    eps_.push_back(std::make_unique<Ep>(*this, next_ep_++, cls, pd));
    eps_.back()->proto_ = proto_;
    eps_.back()->epoch_ = proto_epoch_;
    return eps_.back().get();
  }
  Status check_local_ref(bool is_read, const LocalRef& local, PdId ep_pd) const {
    auto it = regions_.find(local.lkey);
    if (it == regions_.end()) return Error{ErrorCode::InvalidArgument, "post: unknown local lkey"};
    if (!(it->second.pd == ep_pd)) {
      return Error{ErrorCode::InvalidArgument, "post: local region belongs to a different protection domain"};
    }
    const MemRegion& r = it->second.mr;
    const auto base = reinterpret_cast<std::uintptr_t>(r.addr);
    const auto a = reinterpret_cast<std::uintptr_t>(local.addr);
    if (a < base || a - base > r.len || local.len > r.len - (a - base)) {
      return Error{ErrorCode::InvalidArgument, "post: local ref outside region"};
    }
    if (is_read && !has(r.access, Access::LocalWrite)) {
      return Error{ErrorCode::AccessDenied, "post_read: local region lacks LocalWrite"};
    }
    return {};
  }
  Status setup_qp(Ep& ep);  // create QP in the class PD, allocate and post receive buffers
  // Frees an endpoint now (destroys QP, buffers, CM id). Caller guarantees nothing is outstanding.
  void reap(Ep* ep);
  Ep* find_ep(rdma_cm_id* id) {
    return id != nullptr ? static_cast<Ep*>(id->context) : nullptr;
  }

  void drain_comp_channel();
  std::size_t drain_cq(std::span<Completion> out);
  void handle_wc(const ibv_wc& wc, std::vector<Completion>& sink);
  // Pumps CM events without blocking; returns the number handled.
  int pump_cm();
  // Handles one event (acks it). Events of an in-progress active connect are only recorded.
  void dispatch(rdma_cm_event* ev);
  void on_connect_request(rdma_cm_event* ev);
  Status wait_ev(Ep& ep, rdma_cm_event_type want, Nanos deadline, const char* what);
  Nanos remaining(Nanos deadline) const { return deadline - clock_->now(); }
};

// ---- Impl: setup / teardown ----

Status VerbsCmFabric::Impl::init() {
  clock_ = opt_.clock != nullptr ? opt_.clock : &real_clock_;
  next_ep_ = opt_.ep_id_base + 1;
  int n = 0;
  dev_list_ = rdma_get_devices(&n);
  if (dev_list_ == nullptr || n == 0) return Error{ErrorCode::NotFound, "no RDMA devices (is rdma_ucm loaded?)"};
  for (int i = 0; i < n; ++i) {
    if (opt_.device.empty() || opt_.device == ibv_get_device_name(dev_list_[i]->device)) {
      ctx_ = dev_list_[i];
      break;
    }
  }
  if (ctx_ == nullptr) return Error{ErrorCode::NotFound, "RDMA device not found"};
  caps_.device = ibv_get_device_name(ctx_->device);
  probe_caps();
  if (caps_.max_cqe != 0 && opt_.cq_depth > caps_.max_cqe) {
    return Error{ErrorCode::InvalidArgument, "cq_depth exceeds the device max_cqe"};
  }

  cm_chan_ = rdma_create_event_channel();
  if (cm_chan_ == nullptr) return from_errno(errno, "rdma_create_event_channel (is /dev/infiniband/rdma_cm present?)");
  set_nonblock(cm_chan_->fd);
  errno = 0;  // L12: a provider that fails without setting errno must not show a stale one
  comp_ = ibv_create_comp_channel(ctx_);
  if (comp_ == nullptr) return local_fail(errno, "ibv_create_comp_channel", caps_.device);
  set_nonblock(comp_->fd);
  errno = 0;
  cq_ = ibv_create_cq(ctx_, static_cast<int>(opt_.cq_depth), nullptr, comp_, 0);
  if (cq_ == nullptr) return local_fail(errno, "ibv_create_cq", caps_.device);

  epfd_ = epoll_create1(EPOLL_CLOEXEC);
  if (epfd_ < 0) return from_errno(errno, "epoll_create1");
  async_efd_ = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
  if (async_efd_ < 0) return from_errno(errno, "eventfd");
  const char* why = "async event dispatcher";
  disp_ = detail::AsyncDispatcher::acquire(ctx_, &why);
  if (disp_ == nullptr) return Error{ErrorCode::ResourceExhausted, why};
  disp_->add_sink(this);
  disp_->add_cq(cq_, this);
  for (int fd : {comp_->fd, cm_chan_->fd, async_efd_}) {
    epoll_event e{};
    e.events = EPOLLIN;
    e.data.fd = fd;
    if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &e) != 0) return from_errno(errno, "epoll_ctl");
  }
  auto p = protocol::resolve(opt_.protocol, detected_);
  if (!p) return p.error();
  proto_ = *p;
  return {};
}

ibv_pd* VerbsCmFabric::Impl::pd_ptr(PdId id) {
  auto it = pds_.find(id.v);
  if (it != pds_.end()) return it->second;
  if (id.v != 0) return nullptr;  // unknown handle
  errno = 0;  // L12
  ibv_pd* pd = ibv_alloc_pd(ctx_);  // the default PD, created on first use
  if (pd != nullptr) pds_[0] = pd;
  return pd;
}

void VerbsCmFabric::Impl::reap(Ep* ep) {
  for (auto it = eps_.begin(); it != eps_.end(); ++it) {
    if (it->get() == ep) {
      eps_.erase(it);  // ~Ep releases everything
      return;
    }
  }
}

// Endpoints the caller never saw (failed connect/accept) have no owner: free them once
// they are in ERR and drained. Surfaced endpoints are only freed by Fabric::release().
void VerbsCmFabric::Impl::reap_unsurfaced() {
  for (auto it = eps_.begin(); it != eps_.end();) {
    Ep& e = **it;
    if (!e.surfaced_ && e.phase_ == Ep::Phase::Error && e.outstanding_ == 0) {
      it = eps_.erase(it);
    } else {
      ++it;
    }
  }
}

void VerbsCmFabric::Impl::drain_async() {
  std::uint64_t v;
  while (::read(async_efd_, &v, sizeof v) > 0) {
  }
  std::deque<detail::AsyncNote> q;
  {
    std::lock_guard<std::mutex> g(async_mu_);
    q.swap(async_q_);
  }
  for (const auto& n : q) {
    switch (n.kind) {
      case AsyncEventKind::QpFatal:
        for (auto& e : eps_) {
          if (e->id_ == n.ep) e->fail();
        }
        log("async event: QP error, endpoint failed");
        break;
      case AsyncEventKind::CqErr:
        cq_broken_ = true;
        log("async event: CQ_ERR, fabric is broken");
        break;
      case AsyncEventKind::PortErr:
        if (n.port != kPort) break;
        port_err_seen_ = true;
        port_err_at_ = clock_->now();
        for (auto& e : eps_) e->fail();
        log("async event: port error, all endpoints failed");
        break;
      case AsyncEventKind::DeviceFatal:
        device_fatal_ = true;
        for (auto& e : eps_) e->fail();
        log("async event: port/device error, all endpoints failed");
        break;
    }
  }
}

void VerbsCmFabric::Impl::probe_caps() {
  ibv_device_attr_ex attr{};
  if (ibv_query_device_ex(ctx_, nullptr, &attr) != 0) {
    ibv_device_attr a{};
    ibv_query_device(ctx_, &a);
    attr.orig_attr = a;
  }
  const ibv_device_attr& a = attr.orig_attr;
  caps_.firmware = a.fw_ver;
  caps_.max_mr_size = a.max_mr_size;
  caps_.max_mr = static_cast<std::uint32_t>(a.max_mr);
  caps_.max_qp = static_cast<std::uint32_t>(a.max_qp);
  caps_.max_qp_wr = static_cast<std::uint32_t>(a.max_qp_wr);
  caps_.max_cqe = static_cast<std::uint32_t>(a.max_cqe);
  caps_.max_qp_rd_atom = static_cast<std::uint32_t>(a.max_qp_rd_atom);
  caps_.max_qp_init_rd_atom = static_cast<std::uint32_t>(a.max_qp_init_rd_atom);
  caps_.mw_flag_advertised = (a.device_cap_flags & IBV_DEVICE_MEM_WINDOW) != 0;

  ibv_port_attr pa{};
  const bool have_port = ibv_query_port(ctx_, 1, &pa) == 0;
  if (have_port) caps_.active_mtu = mtu_bytes(pa.active_mtu);

  detected_ = protocol::detect(ctx_);
  caps_.protocol = detected_;
  // Before the trial CQ/QP below and every other ring of this fabric: the ballast must be the context's first ring.
  if (detected_ == protocol::Protocol::IWarp && a.vendor_id == kSoftIwarpVendorId) acquire_siw_ballast();
  {
    caps_.node_type = protocol::node_type(ctx_);
  }
  caps_.read_sink_needs_remote_write =
      has(protocol::region_access(detected_, Access::LocalWrite), Access::RemoteWrite);
  caps_.active_sends_first = protocol::active_sends_first(detected_);

  // Netdev MTU via sysfs: the device's first port -> netdev link.
  {
    std::string nd;
    const std::string base = std::string("/sys/class/infiniband/") + caps_.device + "/ports/1/gid_attrs/ndevs/0";
    std::string mtu;
    if (read_file_line(base, nd) && read_file_line("/sys/class/net/" + nd + "/mtu", mtu)) {
      caps_.netdev_mtu = static_cast<std::uint32_t>(std::strtoul(mtu.c_str(), nullptr, 10));
    }
  }

  // Trial probes run on a scratch PD so they never touch the live ones.
  ibv_pd* pd = ibv_alloc_pd(ctx_);
  if (pd == nullptr) return;
  // Trial registration of 1 MiB.
  {
    void* p = std::aligned_alloc(kPageAlign, 1 << 20);
    if (p != nullptr) {
      ibv_mr* mr = ibv_reg_mr(pd, p, 1 << 20, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
      caps_.trial_reg_ok = mr != nullptr;
      if (mr != nullptr) ibv_dereg_mr(mr);
      std::free(p);
    }
  }
  // Memory window: really allocate one (flags lie on bnxt_re/cxgb4). Recorded only.
  {
    errno = 0;
    ibv_mw* mw = ibv_alloc_mw(pd, IBV_MW_TYPE_1);
    caps_.mw_alloc_ok = mw != nullptr;
    caps_.mw_alloc_errno = mw != nullptr ? 0 : errno;
    if (mw != nullptr) ibv_dealloc_mw(mw);
  }
  // dma-buf: no portable way to mint a real fd here, so pass an invalid one and read
  // the failure: EOPNOTSUPP/ENOSYS = no provider support; anything else (EBADF, EINVAL)
  // means the entry point exists and rejected only our dummy fd.
  {
    errno = 0;
    ibv_mr* mr = ibv_reg_dmabuf_mr(pd, 0, 4096, 0, -1, IBV_ACCESS_LOCAL_WRITE);
    if (mr != nullptr) {
      caps_.dmabuf = DmabufProbe::Works;
      ibv_dereg_mr(mr);
    } else {
      caps_.dmabuf_errno = errno;
      caps_.dmabuf = (errno == EOPNOTSUPP || errno == ENOSYS) ? DmabufProbe::Unsupported
                                                               : DmabufProbe::EntryPointPresent;
    }
  }
  // Inline size: create a QP asking for 256 and read back what the device grants.
  {
    ibv_cq* cq = ibv_create_cq(ctx_, 16, nullptr, nullptr, 0);
    if (cq != nullptr) {
      ibv_qp_init_attr qa{};
      qa.send_cq = qa.recv_cq = cq;
      qa.qp_type = IBV_QPT_RC;
      qa.cap = {16, 16, 1, 1, 256};
      ibv_qp* qp = ibv_create_qp(pd, &qa);
      if (qp != nullptr) {
        caps_.max_inline_data = qa.cap.max_inline_data;
        ibv_destroy_qp(qp);
      }
      ibv_destroy_cq(cq);
    }
  }
  ibv_dealloc_pd(pd);
}

VerbsCmFabric::Impl::~Impl() {
  // Order: QPs and per-endpoint MRs, ids, user MRs, CQ (after acking events), PDs,
  // then the channels. Endpoints destroy their own QP/MR/id.
  eps_.clear();  // each endpoint unregisters its QP from the dispatcher
  if (disp_ != nullptr) {
    disp_->remove_sink(this);
    detail::AsyncDispatcher::release(disp_);
  }
  if (async_efd_ >= 0) ::close(async_efd_);
  for (auto& l : lsts_) rdma_destroy_id(l.id);
  for (auto& [k, r] : regions_) ibv_dereg_mr(r.ibv);
  if (cq_ != nullptr) {
    if (unacked_cq_events_ > 0) ibv_ack_cq_events(cq_, unacked_cq_events_);
    ibv_destroy_cq(cq_);
  }
  if (comp_ != nullptr) ibv_destroy_comp_channel(comp_);
  for (auto& [id, pd] : pds_) ibv_dealloc_pd(pd);
  if (cm_chan_ != nullptr) rdma_destroy_event_channel(cm_chan_);
  if (epfd_ >= 0) ::close(epfd_);
  // Last ring user: every CQ/QP of this fabric is gone, and the ballast goes with the device's last fabric.
  if (siw_ballast_) detail::SiwBallast::release(ctx_);
  if (dev_list_ != nullptr) rdma_free_devices(dev_list_);
}

void VerbsCmFabric::Impl::acquire_siw_ballast() {
  const detail::SiwBallast::Held h = detail::SiwBallast::acquire(ctx_);
  siw_ballast_ = true;  // the slot is refcounted whether or not the CQ exists
  soft_rings_ = !h.first;  // no ballast, or one that may not be the context's first ring (SiwBallast's assumption)
  if (h.created) {  // once per device (per ballast creation); log::write adds the process identity (node ID, host, addr)
    if (h.first) {
      log::write(log::Level::Info, "verbs_cm",
                 "soft-iWARP provider: a long-lived 32768-entry ballast CQ pins mmap pages 0-256 so no ring lands on "
                 "page 144 (libsiw's invalid-key value); QP rings keep their configured depth",
                 {{"device", caps_.device}});
    } else {
      log::write(log::Level::Warn, "verbs_cm",
                 "soft-iWARP provider: the ballast CQ was created after other rings on this device context, so it may "
                 "not cover page 144; QP rings fall back to at least 1024 entries",
                 {{"device", caps_.device}});
    }
  } else if (!h.in_place) {
    log::write(log::Level::Warn, "verbs_cm",
               "soft-iWARP provider: the ballast CQ could not be created; QP rings fall back to at least 1024 entries",
               {{"device", caps_.device},
                {"call", "ibv_create_cq"},
                {"errno", h.err != 0 ? std::string(std::strerror(h.err)) : std::string("none")}});
  }
}

// ---- Impl: QP setup ----

Status VerbsCmFabric::Impl::setup_qp(Ep& ep) {
  ep.pd_ = pd_ptr(ep.pd_id_);
  if (ep.pd_ == nullptr) {
    return ep.pd_id_.v == 0 ? local_fail(errno, "ibv_alloc_pd", caps_.device) : Error{ErrorCode::InvalidArgument, "unknown PdId"};
  }

  // Per-class layout (spec 3.5): fetch QPs only exchange HELLO (2 small receives); control
  // and ingest keep the full-frame buffers because their frames can reach kMaxFrameBytes.
  if (ep.cls_ == EpClass::Fetch) {
    ep.recv_slots_ = std::min(kFetchSlots, opt_.recv_slots);
    ep.send_slots_ = std::min(kFetchSlots, opt_.send_slots);
    ep.slot_bytes_ = std::min(kFetchSlotBytes, max_frame_);
  } else {
    ep.recv_slots_ = opt_.recv_slots;
    ep.send_slots_ = opt_.send_slots;
    ep.slot_bytes_ = max_frame_;
  }
  // Every WR can produce a CQE (all sends are signalled), so a QP can fill sq + rq entries.
  const std::uint32_t need = opt_.sq_depth + ep.recv_slots_;
  if (static_cast<std::uint64_t>(cq_reserved_) + need > opt_.cq_depth && !zombies_.empty()) reclaim_cq();
  if (static_cast<std::uint64_t>(cq_reserved_) + need > opt_.cq_depth) {
    // Q07: the fabric's own budget, no provider call: no errno is reported.
    last_local_failure() = LocalFailure{"completion queue budget exhausted (cq_depth)", 0, caps_.device, -1, /*provider_call=*/false};
    return Error{ErrorCode::ResourceExhausted, "completion queue budget exhausted (cq_depth)"};
  }

  const std::size_t total = static_cast<std::size_t>(ep.recv_slots_ + ep.send_slots_) * ep.slot_bytes_;
  ep.buf_ = static_cast<std::byte*>(std::aligned_alloc(kPageAlign, (total + kPageAlign - 1) & ~(kPageAlign - 1)));
  if (ep.buf_ == nullptr) return Error{ErrorCode::ResourceExhausted, "frame buffers"};
  std::memset(ep.buf_, 0, total);
  errno = 0;
  ep.buf_mr_ = ibv_reg_mr(ep.pd_, ep.buf_, total, IBV_ACCESS_LOCAL_WRITE);
  if (ep.buf_mr_ == nullptr) return local_fail(errno, "ibv_reg_mr(frame buffers)", caps_.device);

  ibv_qp_init_attr qa{};
  qa.qp_context = &ep;  // lets async QP events find the endpoint
  qa.send_cq = qa.recv_cq = cq_;
  qa.qp_type = IBV_QPT_RC;
  qa.cap.max_send_wr = opt_.sq_depth;
  qa.cap.max_recv_wr = ep.recv_slots_;
  qa.cap.max_send_sge = 1;
  qa.cap.max_recv_sge = 1;
  qa.cap.max_inline_data = opt_.inline_bytes;  // profile inline_bytes (A3.3); the device may round it up
  if (soft_rings_) {  // siw without a ballast proven first only (acquire_siw_ballast)
    static std::atomic<bool> logged{false};
    qa.cap.max_send_wr = std::max(qa.cap.max_send_wr, std::min(kSoftRingFloor, caps_.max_qp_wr));
    qa.cap.max_recv_wr = std::max(qa.cap.max_recv_wr, std::min(kSoftRingFloor, caps_.max_qp_wr));
    if (!logged.exchange(true)) {
      log::write(log::Level::Info, "verbs_cm",
                 "soft-iWARP provider without its ballast CQ: QP rings are created at least 1024 entries deep "
                 "(posting and CQ budget unchanged)",
                 {{"device", caps_.device}});
    }
  }
  errno = 0;
  int qp_rc = rdma_create_qp(ep.cm_, ep.pd_, &qa);
  if (qp_rc != 0 && opt_.inline_bytes != 0 && errno == EINVAL) {
    // An unverified profile may ask for more inline data than the device has: fall back to none.
    qa.cap.max_inline_data = 0;
    if (!inline_warned_.exchange(true)) log("rdma_create_qp refused the profile max_inline; created without inline data");
    errno = 0;
    qp_rc = rdma_create_qp(ep.cm_, ep.pd_, &qa);
  }
  if (qp_rc != 0) return local_fail(errno, "rdma_create_qp", caps_.device);
  ep.has_qp_ = true;
  disp_->add_qp(ep.cm_->qp, this, ep.id_);
  ep.cqe_reserve_ = need;
  cq_reserved_ += need;

  for (std::uint32_t i = 0; i < ep.send_slots_; ++i) ep.free_send_.push_back(i);
  for (std::uint32_t i = 0; i < ep.recv_slots_; ++i) {
    if (auto s = ep.post_recv(i); !s) return s;
  }
  return {};
}

// ---- Impl: completion handling ----

void VerbsCmFabric::Impl::drain_comp_channel() {
  ibv_cq* cq = nullptr;
  void* ctx = nullptr;
  while (ibv_get_cq_event(comp_, &cq, &ctx) == 0) ++unacked_cq_events_;
  if (unacked_cq_events_ >= 64) {  // ack in batches: each ack takes a lock
    ibv_ack_cq_events(cq_, unacked_cq_events_);
    unacked_cq_events_ = 0;
  }
}

void VerbsCmFabric::Impl::handle_wc(const ibv_wc& wc, std::vector<Completion>& sink) {
  auto it = wrs_.find(wc.wr_id);
  if (it == wrs_.end()) return;  // stale
  const Wr w = it->second;
  wrs_.erase(it);
  if (w.ep == nullptr) {  // flush of a destroyed QP
    if (!opt_.drop_zombie_flushes_for_test) settle_zombie(w.zid);
    return;
  }
  Ep& ep = *w.ep;
  const bool ok = wc.status == IBV_WC_SUCCESS;

  if (w.kind == WrKind::Recv) {
    if (!ok) {  // flushed or failed receive: never surfaced; the endpoint is in ERR
      ep.fail();
      return;
    }
    Completion c;
    c.endpoint = ep.id_;
    c.is_recv = true;
    c.op = CompletionOp::Recv;
    c.bytes = wc.byte_len;
    const std::byte* b = ep.recv_buf(w.slot);
    c.frame.bytes.assign(b, b + wc.byte_len);
    // A frame can beat the ESTABLISHED event that announces the endpoint: hold it back so
    // the caller never sees a Recv for an endpoint id it does not know yet.
    if (!ep.surfaced_) {
      ep.early_.push_back(std::move(c));
    } else {
      sink.push_back(std::move(c));
    }
    // Re-post in every phase but Error: a frame can be processed before the ESTABLISHED
    // event is, and that slot must not be lost.
    if (ep.phase_ != Ep::Phase::Error) static_cast<void>(ep.post_recv(w.slot));
    return;
  }

  --ep.outstanding_;
  if (w.kind == WrKind::Send) {
    ep.free_send_.push_back(w.slot);
  } else if (--pins_[w.lkey] == 0) {
    pins_.erase(w.lkey);
  }
  Completion c;
  c.endpoint = ep.id_;
  c.tag = w.tag;
  c.op = w.kind == WrKind::Send ? CompletionOp::Send : w.kind == WrKind::Read ? CompletionOp::Read : CompletionOp::Write;
  c.bytes = ok ? w.len : 0;
  if (!ok) {
    c.status = from_wc(wc.status);
    ep.fail();
  }
  sink.push_back(std::move(c));
}

std::size_t VerbsCmFabric::Impl::drain_cq(std::span<Completion> out) {
  std::size_t n = 0;
  // Surface completions queued by earlier calls first.
  while (n < out.size() && !ready_.empty()) {
    out[n++] = std::move(ready_.front());
    ready_.pop_front();
  }
  constexpr int kBatch = 16;
  ibv_wc wcs[kBatch];
  while (n < out.size() && !cq_broken_) {
    const int want = static_cast<int>(std::min<std::size_t>(kBatch, out.size() - n));
    const int got = ibv_poll_cq(cq_, want, wcs);
    if (got < 0) {
      cq_broken_ = true;
      break;
    }
    if (got == 0) {
      tick_zombies();
      break;
    }
    std::vector<Completion> sink;
    for (int i = 0; i < got; ++i) handle_wc(wcs[i], sink);
    for (auto& c : sink) {
      if (n < out.size()) {
        out[n++] = std::move(c);
      } else {
        ready_.push_back(std::move(c));
      }
    }
  }
  if (cq_broken_ && !cq_error_reported_ && n < out.size()) {
    cq_error_reported_ = true;
    for (auto& e : eps_) e->fail();
    Completion c;
    c.op = CompletionOp::CqError;
    c.status = Error{ErrorCode::ResourceExhausted, "completion queue error"};
    out[n++] = std::move(c);
  }
  return n;
}

// ---- Impl: connection events ----

int VerbsCmFabric::Impl::pump_cm() {
  int handled = 0;
  rdma_cm_event* ev = nullptr;
  while (rdma_get_cm_event(cm_chan_, &ev) == 0) {
    dispatch(ev);
    ++handled;
  }
  return handled;
}

void VerbsCmFabric::Impl::dispatch(rdma_cm_event* ev) {
  Ep* ep = find_ep(ev->id);
  const rdma_cm_event_type type = ev->event;
  if (type == RDMA_CM_EVENT_CONNECT_REQUEST) {
    on_connect_request(ev);  // acks internally
    return;
  }
  if (Lst* l = find_lst(ev->id); l != nullptr) {  // an event on a listening id: its address or device went away
    if (type == RDMA_CM_EVENT_ADDR_CHANGE || type == RDMA_CM_EVENT_DEVICE_REMOVAL) {
      l->cm_broken = true;
      log("rdma_cm: a listener lost its address or device");
    }
    rdma_ack_cm_event(ev);
    return;
  }
  if (ep != nullptr) {
    ep->last_ev_ = type;
    ep->last_status_ = ev->status;
    ep->got_ev_ = true;
    if (type == RDMA_CM_EVENT_REJECTED) {
      const auto* pd = static_cast<const std::uint8_t*>(ev->param.conn.private_data);
      ep->reject_code_ = pd != nullptr && ev->param.conn.private_data_len >= 1 ? pd[0] : protocol::kRejectNone;
    }
    if (type == RDMA_CM_EVENT_ESTABLISHED) {
      readback_qp(ep, ev->id);  // B11: QP is in RTS now (both sides)
      ep->established_ = ev->param.conn;
      const auto* raw = static_cast<const std::byte*>(ev->param.conn.private_data);
      auto dec = protocol::decode_private(
          {raw, raw != nullptr ? static_cast<std::size_t>(ev->param.conn.private_data_len) : 0});
      // The accept's protocol tag and the peer's announced depths; short or malformed
      // private_data leaves the tag Unknown, which connect() refuses on every protocol.
      ep->peer_proto_ = dec ? dec->protocol : protocol::Protocol::Unknown;
      ep->peer_version_bad_ = !dec && dec.error().code == ErrorCode::Unsupported;
      ep->peer_depth_ = dec ? dec->depth : protocol::Depth{};
      ep->established_.private_data = nullptr;
      if (ep->phase_ == Ep::Phase::Accepting) {
        if (opt_.hold_established_for_test != nullptr && opt_.hold_established_for_test->load()) {
          ep->deferred_est_ = true;  // announced later by poll(), once the hold is lifted
        } else {
          ep->phase_ = Ep::Phase::Ready;
          rdma_ack_cm_event(ev);
          surface(ep, true);
          return;
        }
      }
    } else if (type == RDMA_CM_EVENT_ADDR_CHANGE) {
      log("rdma_cm ADDR_CHANGE: the bound address moved, failing the endpoint");
      if (ep->phase_ != Ep::Phase::Connecting) ep->fail();
    } else if (type == RDMA_CM_EVENT_DISCONNECTED || type == RDMA_CM_EVENT_DEVICE_REMOVAL ||
               type == RDMA_CM_EVENT_CONNECT_ERROR || type == RDMA_CM_EVENT_REJECTED ||
               type == RDMA_CM_EVENT_UNREACHABLE) {
      if (ep->phase_ != Ep::Phase::Connecting) {  // Connecting: connect() sees last_ev_
        ep->fail();
        // Peer-initiated disconnect: answer it so the CM handshake completes (no TIMEWAIT hang).
        if (type == RDMA_CM_EVENT_DISCONNECTED && ep->cm_ != nullptr) rdma_disconnect(ep->cm_);
      }
    }
  }
  rdma_ack_cm_event(ev);
}

void VerbsCmFabric::Impl::on_connect_request(rdma_cm_event* ev) {
  rdma_cm_id* id = ev->id;
  auto reject = [&](std::uint8_t code) {
    const std::uint8_t why = code;
    rdma_reject(id, &why, 1);
    rdma_ack_cm_event(ev);
    rdma_destroy_id(id);
  };
  Lst* lst = find_lst(ev->listen_id);
  if (id->verbs != ctx_ || lst == nullptr || !lst->on_accept) {
    return reject(protocol::kRejectNone);  // wrong device / not listening
  }

  const auto* raw = static_cast<const std::byte*>(ev->param.conn.private_data);
  auto dec = protocol::decode_private({raw, raw != nullptr ? static_cast<std::size_t>(ev->param.conn.private_data_len) : 0});
  if (!dec) {
    return reject(dec.error().code == ErrorCode::Unsupported ? protocol::kRejectVersion
                                                             : protocol::kRejectBadPrivateData);
  }
  const protocol::Protocol ours =
      opt_.advertise_protocol_for_test != protocol::Protocol::Unknown ? opt_.advertise_protocol_for_test : proto_;
  if (dec->protocol != ours) return reject(protocol::kRejectProtocolMismatch);
  // Cap on endpoints in the accept handshake: a flood of requests must not pin unbounded QPs.
  const auto pending = static_cast<std::uint32_t>(std::count_if(
      eps_.begin(), eps_.end(), [](const auto& e) { return e->phase_ == Ep::Phase::Accepting; }));
  if (pending >= max_pending_) return reject(protocol::kRejectResources);
  std::vector<std::byte> priv(dec->ticket.begin(), dec->ticket.end());
  Admission adm{lst->accept_class, lst->accept_pd};
  if (lst->admit) {
    auto r = lst->admit(priv);
    if (!r) return reject(protocol::admit_reject_code(r.error().code));  // r7 R01: Busy (draining) is not AccessDenied
    adm = *r;
  }
  if (pd_ptr(adm.pd) == nullptr) return reject(protocol::kRejectAdmit);  // admit named an unknown PD
  // The active side's depths come from its private_data, not from the CM event (whose
  // ird/ord meaning differs between providers).
  const std::uint32_t peer_ord = dec->depth.ord;
  const std::uint32_t peer_ird = dec->depth.ird;

  Ep* ep = new_ep(adm.cls, adm.pd);
  ep->cm_ = id;
  ep->lst_ = lst;
  id->context = ep;
  ep->priv_ = std::move(priv);
  ep->phase_ = Ep::Phase::Accepting;
  ep->accept_deadline_ = clock_->now() + accept_timeout_;
  rdma_ack_cm_event(ev);  // id stays valid; only the event is released

  // A failed accept never reaches the caller, so free the endpoint right here.
  auto drop = [&](std::uint8_t code) {
    ep->fail();
    rdma_reject(id, &code, 1);
    reap(ep);
  };
  if (auto s = setup_qp(*ep); !s) {
    return drop(s.error().code == ErrorCode::ResourceExhausted ? protocol::kRejectResources : protocol::kRejectNone);
  }
  const protocol::Depth d = protocol::passive_depth(ep->proto_, peer_ord, peer_ird, caps_.max_qp_rd_atom,
                                                    caps_.max_qp_init_rd_atom);
  ep->ird_cfg_ = d.ird;
  ep->ord_cfg_ = d.ord;
  ep->depth_ = protocol::effective_depth(d, dec->depth);
  rdma_conn_param cp{};
  cp.responder_resources = d.ird;
  cp.initiator_depth = d.ord;
  cp.retry_count = opt_.retry_count;
  cp.rnr_retry_count = opt_.rnr_retry_count;
  // The accept carries our protocol tag (verified by the active side at ESTABLISHED) and
  // the depths we accepted, from which the active side derives the effective READ window.
  std::byte tag[protocol::kPrivHeader] = {};
  cp.private_data = tag;
  const protocol::Protocol accept_tag = opt_.advertise_accept_protocol_for_test != protocol::Protocol::Unknown
                                            ? opt_.advertise_accept_protocol_for_test
                                            : ep->proto_;
  cp.private_data_len = static_cast<std::uint8_t>(protocol::encode_private(accept_tag, d, {}, tag));
  if (rdma_accept(id, &cp) != 0) drop(protocol::kRejectNone);
}

// ---- Impl: CQE reservation of dead QPs (N08) and endpoint announcement (N05) ----

// The QP is destroyed, but its posted receives still flush into the shared CQ. Until those
// are drained the CQ can hold their entries, so the reservation stays against the budget.
void VerbsCmFabric::Impl::retire_reserve(Ep* ep) {
  if (ep->cqe_reserve_ == 0) return;
  const std::uint64_t zid = next_zombie_;
  std::uint32_t n = 0;
  for (auto& [id, w] : wrs_) {
    if (w.ep == ep) {
      w.ep = nullptr;
      w.zid = zid;
      ++n;
    }
  }
  if (n == 0) {
    cq_reserved_ -= ep->cqe_reserve_;
  } else {
    zombies_[next_zombie_++] = Zombie{ep->cqe_reserve_, n, clock_->now()};
  }
  ep->cqe_reserve_ = 0;
}

void VerbsCmFabric::Impl::settle_zombie(std::uint64_t zid) {
  auto it = zombies_.find(zid);
  if (it == zombies_.end()) return;
  if (--it->second.left == 0) {
    cq_reserved_ -= it->second.reserve;
    zombies_.erase(it);
  }
}

// Called only when a drain found the CQ empty. A provider that never generates flush
// entries for a destroyed QP would otherwise leak the budget, so a reservation is returned
// at an empty drain that happens at least opt_.zombie_grace (on the fabric's Clock) after
// the QP died: every flush that did arrive by then has been settled. Counting polls instead
// would expire every zombie within microseconds when the caller polls in a loop, before a
// slow provider has delivered its flushes.
void VerbsCmFabric::Impl::tick_zombies() {
  const Nanos now = clock_->now();
  for (auto it = zombies_.begin(); it != zombies_.end();) {
    if (now - it->second.died < opt_.zombie_grace) {
      ++it;
      continue;
    }
    const std::uint64_t zid = it->first;
    for (auto w = wrs_.begin(); w != wrs_.end();) {
      w = (w->second.ep == nullptr && w->second.zid == zid) ? wrs_.erase(w) : std::next(w);
    }
    cq_reserved_ -= it->second.reserve;
    it = zombies_.erase(it);
  }
}

// Drains the CQ completely once so finished flushes settle; reservations whose grace has
// passed expire by the normal rule (tick_zombies), never earlier. Completions found go to
// ready_ and reach the caller on the next poll().
void VerbsCmFabric::Impl::reclaim_cq() {
  ibv_wc wcs[16];
  for (;;) {
    const int got = ibv_poll_cq(cq_, 16, wcs);
    if (got < 0) {
      cq_broken_ = true;
      return;
    }
    if (got == 0) {
      tick_zombies();
      return;
    }
    std::vector<Completion> sink;
    for (int i = 0; i < got; ++i) handle_wc(wcs[i], sink);
    for (auto& c : sink) ready_.push_back(std::move(c));
  }
}

// Marks the endpoint as handed to the caller. Recv completions that arrived earlier are
// queued behind the announcement, in order.
void VerbsCmFabric::Impl::surface(Ep* ep, bool announce) {
  ep->surfaced_ = true;
  std::deque<Completion> early = std::move(ep->early_);
  ep->early_.clear();
  if (announce && ep->lst_ != nullptr && ep->lst_->on_accept) ep->lst_->on_accept(ep);
  for (auto& c : early) ready_.push_back(std::move(c));
}

// B11: the one place that reads QP attributes back. Both sides reach RTS inside rdma_cm (rdma_connect /
// rdma_accept) and both see CM ESTABLISHED right after, so this is called from the ESTABLISHED handler for
// every QP; only the first QP per (role, device, port, addr) is queried (QpReadback::claim). Never fails the
// connection: a failed query is logged (WARN once) and counted.
void VerbsCmFabric::Impl::readback_qp(Ep* ep, rdma_cm_id* id) {
  if (ep == nullptr || id == nullptr || id->qp == nullptr) return;
  const sockaddr* sa = ep->active_ ? rdma_get_peer_addr(id) : rdma_get_local_addr(id);
  char ip[INET6_ADDRSTRLEN] = "?";
  if (sa != nullptr && sa->sa_family == AF_INET)
    inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(sa)->sin_addr, ip, sizeof ip);
  else if (sa != nullptr && sa->sa_family == AF_INET6)
    inet_ntop(AF_INET6, &reinterpret_cast<const sockaddr_in6*>(sa)->sin6_addr, ip, sizeof ip);
  const QpSite site{ep->active_ ? "active" : "passive", caps_.device, std::to_string(id->port_num), ip};
  if (!qp_readback_.claim(site)) return;
  ibv_qp_attr attr{};
  ibv_qp_init_attr init{};
  const int mask = IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY | IBV_QP_MIN_RNR_TIMER | IBV_QP_PATH_MTU;
  const int rc = ibv_query_qp(id->qp, &attr, mask, &init);
  if (rc != 0) {
    qp_readback_.report(site, nullptr, rc > 0 ? rc : errno, {});
    return;
  }
  QpAttrs got;
  got.ack_timeout_exp = attr.timeout;
  got.retry_count = attr.retry_cnt;
  got.rnr_retry = attr.rnr_retry;
  got.min_rnr_timer = attr.min_rnr_timer;
  got.path_mtu_bytes = qp_mtu_bytes(attr.path_mtu);
  // What config asked for. iWARP has no ACK timeout / IB-style retry attributes: nothing to compare. The
  // ACK timeout is only asked for by the active side (rdma_set_option); the passive side takes it from the
  // path, and the min RNR timer and path MTU are not configurable here, so those are reported only.
  QpExpect want;
  if (ep->proto_ != protocol::Protocol::IWarp) {
    want.rnr_retry = opt_.rnr_retry_count;
    // F3 (K19): the passive QP's retry_cnt comes from the client's REQ, so only the active side can compare it.
    if (ep->active_) want.retry_count = opt_.retry_count;
    if (ep->active_ && ep->ack_opt_set_) want.ack_timeout_exp = opt_.ack_timeout_exp;
  }
  qp_readback_.report(site, &got, 0, want);
}

void VerbsCmFabric::set_qp_metrics(telemetry::Registry* reg, telemetry::Labels extra) {
  impl_->qp_readback_.set_metrics(reg, std::move(extra));
}

Status VerbsCmFabric::Impl::wait_ev(Ep& ep, rdma_cm_event_type want, Nanos deadline, const char* what) {
  for (;;) {
    pump_cm();
    if (ep.got_ev_) {
      ep.got_ev_ = false;
      if (ep.last_ev_ == want) return {};
      switch (ep.last_ev_) {
        case RDMA_CM_EVENT_REJECTED: return protocol::reject_error(ep.reject_code_);
        case RDMA_CM_EVENT_UNREACHABLE: return Error{ErrorCode::LinkDown, "connect: unreachable"};
        case RDMA_CM_EVENT_ADDR_ERROR:
        case RDMA_CM_EVENT_ROUTE_ERROR: return Error{ErrorCode::LinkDown, what};
        case RDMA_CM_EVENT_CONNECT_ERROR:
        case RDMA_CM_EVENT_DISCONNECTED:
        case RDMA_CM_EVENT_DEVICE_REMOVAL: return Error{ErrorCode::Aborted, "connect: failed"};
        default: continue;  // e.g. TIMEWAIT_EXIT of something else
      }
    }
    const Nanos left = remaining(deadline);
    if (left <= Nanos{0}) return Error{ErrorCode::Timeout, what};
    pollfd pfd{cm_chan_->fd, POLLIN, 0};
    const auto ms = static_cast<int>(std::max<std::int64_t>(1, std::chrono::duration_cast<std::chrono::milliseconds>(left).count()));
    ::poll(&pfd, 1, std::min(ms, 100));
  }
}

// ---- Endpoint ----

Status VerbsCmFabric::Impl::Ep::check_posting() const {
  if (phase_ == Phase::Error) return Error{ErrorCode::Aborted, "post: endpoint in error state"};
  if (phase_ != Phase::Ready) return Error{ErrorCode::NotFound, "post: endpoint not connected"};
  return {};
}

Status VerbsCmFabric::Impl::Ep::post_recv(std::uint32_t slot) {
  const std::uint64_t wr_id = f_.next_wr_++;
  ibv_sge sge{reinterpret_cast<std::uintptr_t>(recv_buf(slot)), slot_bytes_, buf_mr_->lkey};
  ibv_recv_wr wr{};
  wr.wr_id = wr_id;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  ibv_recv_wr* bad = nullptr;
  f_.wrs_[wr_id] = Wr{this, WrKind::Recv, 0, slot, 0, 0};
  if (const int rc = ibv_post_recv(cm_->qp, &wr, &bad); rc != 0) {
    f_.wrs_.erase(wr_id);
    return from_errno(rc, "ibv_post_recv");
  }
  return {};
}

Status VerbsCmFabric::Impl::Ep::post_wr(ibv_send_wr& wr, WrKind kind, WrTag tag, std::uint32_t slot,
                                        std::uint32_t lkey, std::uint32_t len) {
  // R01: the CQ budget reserves sq_depth CQEs per QP for sends, so the cap is enforced here, whatever ring the provider
  // gave (siw without its ballast rounds it up to 1024 WQEs). outstanding_ counts posted-and-not-yet-completed
  // send-queue WRs; every completion, flushed ones included, decrements it in handle_wc.
  if (outstanding_ >= f_.opt_.sq_depth) {
    return Error{ErrorCode::ResourceExhausted, "post_wr: send queue full (sq_depth)"};
  }
  const std::uint64_t wr_id = f_.next_wr_++;
  wr.wr_id = wr_id;
  wr.send_flags = IBV_SEND_SIGNALED;
  f_.wrs_[wr_id] = Wr{this, kind, tag, slot, lkey, len};
  ibv_send_wr* bad = nullptr;
  if (const int rc = ibv_post_send(cm_->qp, &wr, &bad); rc != 0) {
    f_.wrs_.erase(wr_id);
    return from_errno(rc, "ibv_post_send");
  }
  ++outstanding_;
  if (kind != WrKind::Send) ++f_.pins_[lkey];
  return {};
}

Status VerbsCmFabric::Impl::Ep::post_send(Frame frame, WrTag tag) {
  if (auto s = check_posting(); !s) return s;
  if (frame.bytes.size() > kMaxFrameBytes || frame.bytes.size() > slot_bytes_) {
    return Error{ErrorCode::InvalidArgument, "post_send: frame exceeds kMaxFrameBytes"};
  }
  if (free_send_.empty()) return Error{ErrorCode::ResourceExhausted, "post_send: no free send slot"};
  const std::uint32_t slot = free_send_.back();
  std::byte* dst = send_buf(slot);
  std::memcpy(dst, frame.bytes.data(), frame.bytes.size());
  ibv_sge sge{reinterpret_cast<std::uintptr_t>(dst), static_cast<std::uint32_t>(frame.bytes.size()), buf_mr_->lkey};
  ibv_send_wr wr{};
  wr.opcode = IBV_WR_SEND;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  if (auto s = post_wr(wr, WrKind::Send, tag, slot, 0, static_cast<std::uint32_t>(frame.bytes.size())); !s) return s;
  free_send_.pop_back();
  return {};
}


Status VerbsCmFabric::Impl::Ep::post_read(RemoteRef remote, LocalRef local, WrTag tag) {
  if (auto s = check_posting(); !s) return s;
  if (auto s = f_.check_local_ref(true, local, pd_id_); !s) return s;
  if (remote.len != local.len) return Error{ErrorCode::InvalidArgument, "post_read: length mismatch"};
  ibv_sge sge{reinterpret_cast<std::uintptr_t>(local.addr), local.len, local.lkey};
  ibv_send_wr wr{};
  wr.opcode = IBV_WR_RDMA_READ;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  wr.wr.rdma.remote_addr = remote.addr;
  wr.wr.rdma.rkey = remote.rkey;
  return post_wr(wr, WrKind::Read, tag, 0, local.lkey, local.len);
}

Status VerbsCmFabric::Impl::Ep::post_write(LocalRef local, RemoteRef remote, WrTag tag) {
  if (auto s = check_posting(); !s) return s;
  if (auto s = f_.check_local_ref(false, local, pd_id_); !s) return s;
  if (remote.len != local.len) return Error{ErrorCode::InvalidArgument, "post_write: length mismatch"};
  ibv_sge sge{reinterpret_cast<std::uintptr_t>(local.addr), local.len, local.lkey};
  ibv_send_wr wr{};
  wr.opcode = IBV_WR_RDMA_WRITE;
  wr.sg_list = &sge;
  wr.num_sge = 1;
  wr.wr.rdma.remote_addr = remote.addr;
  wr.wr.rdma.rkey = remote.rkey;
  return post_wr(wr, WrKind::Write, tag, 0, local.lkey, local.len);
}

void VerbsCmFabric::Impl::Ep::fail() {
  if (phase_ == Phase::Error) return;
  phase_ = Phase::Error;
  if (cm_ != nullptr && has_qp_) {
    ibv_qp_attr qa{};
    qa.qp_state = IBV_QPS_ERR;
    ibv_modify_qp(cm_->qp, &qa, IBV_QP_STATE);  // outstanding WRs now flush through the CQ
  }
}

void VerbsCmFabric::Impl::Ep::abort() {
  const bool was_ready = phase_ == Phase::Ready;
  fail();
  if (was_ready && cm_ != nullptr) rdma_disconnect(cm_);  // lets the peer see it too
}

void VerbsCmFabric::Impl::Ep::release() {
  if (cm_ != nullptr && has_qp_) {
    f_.disp_->remove_qp(cm_->qp);
    rdma_destroy_qp(cm_);
    has_qp_ = false;
  }
  f_.retire_reserve(this);  // CQE budget comes back once the QP's flush completions are drained
  if (buf_mr_ != nullptr) ibv_dereg_mr(buf_mr_);
  buf_mr_ = nullptr;
  std::free(buf_);
  buf_ = nullptr;
  if (cm_ != nullptr) {
    rdma_destroy_id(cm_);
    cm_ = nullptr;
  }
}

// ---------------------------------------------------------------------------------
// VerbsCmFabric
// ---------------------------------------------------------------------------------

VerbsCmFabric::VerbsCmFabric(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
VerbsCmFabric::~VerbsCmFabric() = default;

Expected<std::unique_ptr<VerbsCmFabric>> VerbsCmFabric::open(const VerbsOptions& options) {
  auto impl = std::make_unique<Impl>();
  impl->opt_ = options;
  if (auto s = impl->init(); !s) return s.error();
  return std::unique_ptr<VerbsCmFabric>(new VerbsCmFabric(std::move(impl)));
}

const NicCaps& VerbsCmFabric::nic_caps() const { return impl_->caps_; }
protocol::Protocol VerbsCmFabric::active_protocol() const { return impl_->proto_; }
std::uint32_t VerbsCmFabric::protocol_epoch() const { return impl_->proto_epoch_; }

Status VerbsCmFabric::set_protocol(protocol::Setting setting) {
  auto p = protocol::resolve(setting, protocol::detect(impl_->ctx_));
  if (!p) return p.error();
  impl_->detected_ = protocol::detect(impl_->ctx_);
  impl_->opt_.protocol = setting;
  if (*p != impl_->proto_) {
    impl_->proto_ = *p;
    ++impl_->proto_epoch_;
  }
  return {};
}

std::uint32_t VerbsCmFabric::endpoint_epoch(const Endpoint* ep) const {
  return static_cast<const Impl::Ep*>(ep)->epoch_;
}
protocol::Protocol VerbsCmFabric::endpoint_protocol(const Endpoint* ep) const {
  return static_cast<const Impl::Ep*>(ep)->proto_;
}
std::vector<Endpoint*> VerbsCmFabric::stale_endpoints() const {
  std::vector<Endpoint*> out;
  for (auto& e : impl_->eps_) {
    if (e->epoch_ != impl_->proto_epoch_ && e->phase_ != Impl::Ep::Phase::Error) out.push_back(e.get());
  }
  return out;
}
std::uint16_t VerbsCmFabric::listen_port() const { return impl_->listen_port_; }

namespace {
// True while some interface of this host still carries the IPv4 literal `host`.
bool host_has_ipv4(const std::string& host) {
  in_addr want{};
  if (inet_pton(AF_INET, host.c_str(), &want) != 1) return false;
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) return true;  // cannot tell: do not report a failure we did not see
  bool found = false;
  for (ifaddrs* a = list; a != nullptr && !found; a = a->ifa_next)
    found = a->ifa_addr != nullptr && a->ifa_addr->sa_family == AF_INET &&
            reinterpret_cast<const sockaddr_in*>(a->ifa_addr)->sin_addr.s_addr == want.s_addr;
  freeifaddrs(list);
  return found;
}
}  // namespace

FabricHealth VerbsCmFabric::health() {
  Impl& f = *impl_;
  FabricHealth h;
  ibv_port_attr pa{};
  if (ibv_query_port(f.ctx_, Impl::kPort, &pa) != 0) {
    h.port_state = "UNKNOWN";
  } else {
    switch (pa.state) {
      case IBV_PORT_ACTIVE: h.port_state = "ACTIVE"; break;
      case IBV_PORT_DOWN: h.port_state = "DOWN"; break;
      case IBV_PORT_INIT: h.port_state = "INIT"; break;
      case IBV_PORT_ARMED: h.port_state = "ARMED"; break;
      case IBV_PORT_ACTIVE_DEFER: h.port_state = "ACTIVE_DEFER"; break;
      default: h.port_state = "UNKNOWN"; break;
    }
  }
  f.drain_async();  // events pushed since the last poll()
  h.fatal_recent = f.device_fatal_ || f.cq_broken_ ||
                   (f.port_err_seen_ && f.clock_->now() - f.port_err_at_ < Impl::kFatalWindow);
  for (const auto& l : f.lsts_) h.listener_ok.push_back(!l.cm_broken && (l.host.empty() || host_has_ipv4(l.host)));
  return h;
}
std::uint32_t VerbsCmFabric::endpoint_recv_slots(const Endpoint* ep) const {
  return static_cast<const Impl::Ep*>(ep)->recv_slots_;
}

Status VerbsCmFabric::inject_async_event_for_test(AsyncEventKind kind, Endpoint* ep, int port) {
  ibv_qp* qp = nullptr;
  if (kind == AsyncEventKind::QpFatal) {
    auto* e = static_cast<Impl::Ep*>(ep);
    if (e == nullptr || e->cm_ == nullptr || !e->has_qp_) return Error{ErrorCode::InvalidArgument, "inject: no QP"};
    qp = e->cm_->qp;
  }
  impl_->disp_->route(kind, qp, impl_->cq_, port);
  return {};
}

void VerbsCmFabric::kill_async_dispatcher_for_test() { impl_->disp_->kill_for_test(); }
std::uint32_t VerbsCmFabric::cq_reserved() const { return impl_->cq_reserved_; }

Expected<std::string> VerbsCmFabric::device_ipv4() const {
  std::string nd;
  if (!read_file_line("/sys/class/infiniband/" + impl_->caps_.device + "/ports/1/gid_attrs/ndevs/0", nd)) {
    return Error{ErrorCode::NotFound, "device has no netdev in sysfs"};
  }
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) return from_errno(errno, "getifaddrs");
  std::string found;
  for (ifaddrs* a = list; a != nullptr; a = a->ifa_next) {
    if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_INET || nd != a->ifa_name) continue;
    char buf[INET_ADDRSTRLEN];
    const auto* sin = reinterpret_cast<const sockaddr_in*>(a->ifa_addr);
    if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof buf) != nullptr) {
      found = buf;
      break;
    }
  }
  freeifaddrs(list);
  if (found.empty()) return Error{ErrorCode::NotFound, "netdev has no IPv4 address"};
  return found;
}

Expected<DeviceCaps> VerbsCmFabric::probe() {
  // DeviceCaps::name must outlive the call: it points into the long-lived NicCaps.
  return DeviceCaps{impl_->caps_.device.c_str(),
                    std::min<std::uint32_t>(impl_->caps_.max_qp_init_rd_atom, 255), true};
}

Expected<PdId> VerbsCmFabric::alloc_pd() {
  errno = 0;
  ibv_pd* p = ibv_alloc_pd(impl_->ctx_);
  if (p == nullptr) return local_fail(errno, "ibv_alloc_pd", impl_->caps_.device);
  const PdId id{impl_->next_pd_++};
  impl_->pds_[id.v] = p;
  return id;
}

Status VerbsCmFabric::free_pd(PdId pd) {
  auto it = impl_->pds_.find(pd.v);
  if (pd.v == 0 || it == impl_->pds_.end()) return Error{ErrorCode::InvalidArgument, "free_pd: unknown or default PD"};
  for (auto& [k, r] : impl_->regions_) {
    if (r.pd == pd) return Error{ErrorCode::Busy, "free_pd: PD has registered regions"};
  }
  for (auto& e : impl_->eps_) {
    if (e->pd_id_ == pd) return Error{ErrorCode::Busy, "free_pd: PD has endpoints"};
  }
  if (ibv_dealloc_pd(it->second) != 0) return from_errno(errno, "ibv_dealloc_pd");
  impl_->pds_.erase(it);
  return {};
}

Status VerbsCmFabric::release(Endpoint* e) {
  Impl::Ep* ep = nullptr;
  for (auto& x : impl_->eps_) {
    if (static_cast<Endpoint*>(x.get()) == e) ep = x.get();
  }
  if (ep == nullptr) return Error{ErrorCode::NotFound, "release: unknown endpoint"};
  if (!ep->drained()) return Error{ErrorCode::Busy, "release: endpoint has outstanding work"};
  if (ep->phase_ == Impl::Ep::Phase::Ready) ep->abort();  // lets the peer see the close
  impl_->reap(ep);
  return {};
}

std::size_t VerbsCmFabric::endpoint_count() const { return impl_->eps_.size(); }

std::size_t VerbsCmFabric::held_recvs() const {
  std::size_t n = 0;
  for (const auto& e : impl_->eps_) n += e->early_.size();
  return n;
}

Expected<MemRegion> VerbsCmFabric::reg(std::span<std::byte> buf, Access access, PdId pd) {
  if (buf.empty()) return Error{ErrorCode::InvalidArgument, "reg: empty buffer"};
  Access eff = protocol::region_access(impl_->proto_, access);
  // Verbs rule on every transport: REMOTE_WRITE requires LOCAL_WRITE.
  if (has(eff, Access::RemoteWrite)) eff = eff | Access::LocalWrite;
  ibv_pd* p = impl_->pd_ptr(pd);
  if (p == nullptr) return pd.v == 0 ? local_fail(errno, "ibv_alloc_pd", impl_->caps_.device) : Error{ErrorCode::InvalidArgument, "reg: unknown PdId"};
  errno = 0;
  ibv_mr* mr = ibv_reg_mr(p, buf.data(), buf.size(), to_ibv_access(eff) | 0);
  if (mr == nullptr) return local_fail(errno, "ibv_reg_mr", impl_->caps_.device);
  MemRegion r{buf.data(), buf.size(), mr->lkey, mr->rkey, eff};
  impl_->regions_[r.lkey] = Impl::Region{r, mr, pd};
  return r;
}

Status VerbsCmFabric::dereg(const MemRegion& region) {
  auto it = impl_->regions_.find(region.lkey);
  if (it == impl_->regions_.end()) return Error{ErrorCode::NotFound, "dereg: unknown region"};
  const MemRegion& m = it->second.mr;
  if (m.addr != region.addr || m.len != region.len || m.rkey != region.rkey) {
    return Error{ErrorCode::InvalidArgument, "dereg: region does not match registration"};
  }
  if (auto p = impl_->pins_.find(region.lkey); p != impl_->pins_.end() && p->second > 0) {
    return Error{ErrorCode::Busy, "dereg: region has posted work"};
  }
  if (ibv_dereg_mr(it->second.ibv) != 0) return from_errno(errno, "ibv_dereg_mr");
  impl_->regions_.erase(it);
  return {};
}

Status VerbsCmFabric::listen(AcceptFn on_accept, const ListenParams& params) {
  if (!params.admit && !params.allow_unauthenticated_for_test) {
    return Error{ErrorCode::InvalidArgument, "listen: an AdmitFn is required (allow_unauthenticated_for_test is for tests)"};
  }
  if (params.max_pending_accepts == 0) return Error{ErrorCode::InvalidArgument, "listen: max_pending_accepts is 0"};
  sockaddr_in sa;
  if (!make_sockaddr(params.addr, sa)) return Error{ErrorCode::InvalidArgument, "listen: bad address"};
  if (!params.admit && impl_->pd_ptr(params.accept_pd) == nullptr) {
    return Error{ErrorCode::InvalidArgument, "listen: unknown accept_pd"};
  }
  rdma_cm_id* id = nullptr;
  if (rdma_create_id(impl_->cm_chan_, &id, nullptr, RDMA_PS_TCP) != 0) return from_errno(errno, "rdma_create_id");
  if (rdma_bind_addr(id, reinterpret_cast<sockaddr*>(&sa)) != 0) {
    const int e = errno;
    rdma_destroy_id(id);
    return from_errno(e, "rdma_bind_addr");
  }
  impl_->max_pending_ = params.max_pending_accepts;
  impl_->accept_timeout_ = params.accept_timeout;
  if (rdma_listen(id, 128) != 0) {
    const int e = errno;
    rdma_destroy_id(id);
    return from_errno(e, "rdma_listen");
  }
  if (impl_->lsts_.empty()) impl_->listen_port_ = ntohs(rdma_get_src_port(id));
  Impl::Lst l;
  l.id = id;
  l.on_accept = std::move(on_accept);
  l.admit = params.admit;
  l.accept_class = params.accept_class;
  l.accept_pd = params.accept_pd;
  l.host = params.addr.host;
  impl_->lsts_.push_back(std::move(l));
  return {};
}

Expected<Endpoint*> VerbsCmFabric::connect(const Peer& peer, const ConnParams& params) {
  Impl& f = *impl_;
  if (params.ticket_len > kMaxTicketBytes) return Error{ErrorCode::InvalidArgument, "connect: ticket too long"};
  sockaddr_in dst;
  if (!make_sockaddr(peer.addr, dst) || peer.addr.host.empty()) {
    return Error{ErrorCode::InvalidArgument, "connect: bad peer address"};
  }
  // Bind the source to this rail's IP so rdma_cm resolves to our device.
  auto src_ip = device_ipv4();
  sockaddr_in src{};
  if (src_ip) make_sockaddr(RailAddr{*src_ip, 0}, src);

  if (f.pd_ptr(params.pd) == nullptr) return Error{ErrorCode::InvalidArgument, "connect: unknown PdId"};
  const Nanos deadline = f.clock_->now() + params.timeout;
  Impl::Ep* ep = f.new_ep(params.cls, params.pd);
  ep->active_ = true;

  // A failed connect never reaches the caller: fail the endpoint, tear the CM side down
  // and free it now so retries do not accumulate QPs and pinned buffers.
  auto fail = [&](Error e) -> Expected<Endpoint*> {
    ep->fail();
    if (ep->cm_ != nullptr) rdma_disconnect(ep->cm_);
    f.reap(ep);
    return e;
  };
  rdma_cm_id* new_id = nullptr;
  if (rdma_create_id(f.cm_chan_, &new_id, ep, RDMA_PS_TCP) != 0) return fail(from_errno(errno, "rdma_create_id"));
  ep->cm_ = new_id;
  {  // Q05: pin the local ACK timeout the client watchdog grace is derived from (fabric/types.h). Best
     // effort: an older kernel refuses and rdma_cm's default (<= the pinned value on RoCE) applies.
     // iWARP accepts and ignores it (no ACK timeout there).
    std::uint8_t ack_to = f.opt_.ack_timeout_exp;  // profile (A3.3); default kQpAckTimeoutExpMax
    ep->ack_opt_set_ = rdma_set_option(ep->cm_, RDMA_OPTION_ID, RDMA_OPTION_ID_ACK_TIMEOUT, &ack_to, sizeof ack_to) == 0;
    if (!ep->ack_opt_set_ &&
        !f.ack_timeout_warned_.exchange(true))  // r7 R11: say so once (watchdog grace then rests on the default)
      f.log("rdma_set_option(ACK_TIMEOUT) refused; the rdma_cm default ACK timeout applies");
  }
  const int tmo_ms = static_cast<int>(std::max<std::int64_t>(
      1, std::chrono::duration_cast<std::chrono::milliseconds>(params.timeout).count()));
  if (rdma_resolve_addr(ep->cm_, src_ip ? reinterpret_cast<sockaddr*>(&src) : nullptr,
                        reinterpret_cast<sockaddr*>(&dst), tmo_ms) != 0) {
    return fail(from_errno(errno, "rdma_resolve_addr"));
  }
  if (auto s = f.wait_ev(*ep, RDMA_CM_EVENT_ADDR_RESOLVED, deadline, "connect: address resolution"); !s) {
    return fail(s.error());
  }
  if (ep->cm_->verbs != f.ctx_) {
    return fail(Error{ErrorCode::NotFound, "connect: rdma_cm resolved to a different device"});
  }
  if (rdma_resolve_route(ep->cm_, tmo_ms) != 0) return fail(from_errno(errno, "rdma_resolve_route"));
  if (auto s = f.wait_ev(*ep, RDMA_CM_EVENT_ROUTE_RESOLVED, deadline, "connect: route resolution"); !s) {
    return fail(s.error());
  }
  if (auto s = f.setup_qp(*ep); !s) return fail(s.error());

  const protocol::Depth want = protocol::active_depth(ep->proto_, params.ird, params.ord, f.caps_.max_qp_rd_atom,
                                                      f.caps_.max_qp_init_rd_atom);
  ep->ird_cfg_ = want.ird;
  ep->ord_cfg_ = want.ord;
  std::byte priv[protocol::kPrivHeader + kMaxTicketBytes] = {};
  const protocol::Protocol advertised = f.opt_.advertise_protocol_for_test != protocol::Protocol::Unknown
                                            ? f.opt_.advertise_protocol_for_test
                                            : ep->proto_;
  const std::size_t priv_len = protocol::encode_private(
      advertised, want, std::span<const std::byte>(params.ticket.data(), params.ticket_len), priv);
  rdma_conn_param cp{};
  cp.private_data = priv;
  cp.private_data_len = static_cast<std::uint8_t>(priv_len);
  cp.responder_resources = ep->ird_cfg_;
  cp.initiator_depth = ep->ord_cfg_;
  cp.retry_count = f.opt_.retry_count;
  cp.rnr_retry_count = f.opt_.rnr_retry_count;
  if (rdma_connect(ep->cm_, &cp) != 0) return fail(from_errno(errno, "rdma_connect"));
  if (auto s = f.wait_ev(*ep, RDMA_CM_EVENT_ESTABLISHED, deadline, "connect: establishing"); !s) {
    return fail(s.error());
  }
  if (ep->peer_version_bad_) {
    return fail(Error{ErrorCode::Unsupported, "connect: accept private_data version unsupported"});
  }
  if (ep->peer_proto_ != ep->proto_) {
    return fail(Error{ErrorCode::Unsupported, "connect: accept carried a different protocol tag"});
  }
  // The passive side's accept parameters are what was actually agreed.
  // From the depths the passive side announced in its accept private_data, never from the
  // CM event (RoCE reports the receiver's view, siw the sender's).
  ep->depth_ = protocol::effective_depth(want, ep->peer_depth_);
  ep->phase_ = Impl::Ep::Phase::Ready;
  f.surface(ep, false);
  return static_cast<Endpoint*>(ep);
}

std::size_t VerbsCmFabric::poll(std::span<Completion> out, PollBudget budget) {
  Impl& f = *impl_;
  const Nanos start = f.clock_->now();
  for (;;) {
    f.drain_comp_channel();
    f.drain_async();
    f.pump_cm();
    // Announce held-back ESTABLISHEDs (test hook). Collect first: AcceptFn may call back
    // into the fabric and change eps_.
    if (f.opt_.hold_established_for_test != nullptr && !f.opt_.hold_established_for_test->load()) {
      std::vector<Impl::Ep*> announce;
      for (auto& e : f.eps_) {
        if (!e->deferred_est_) continue;
        e->deferred_est_ = false;
        if (e->phase_ != Impl::Ep::Phase::Accepting) continue;  // died while held: reaped below
        e->phase_ = Impl::Ep::Phase::Ready;
        announce.push_back(e.get());
      }
      for (Impl::Ep* e : announce) f.surface(e, true);
    }
    // Accept deadline: a peer that never completes the handshake must not hold a QP forever.
    // A held ESTABLISHED (test hook) counts as not yet seen, so it times out like a real one.
    const Nanos now = f.clock_->now();
    for (auto& e : f.eps_) {
      if (e->phase_ == Impl::Ep::Phase::Accepting && now >= e->accept_deadline_) {
        f.log("accept timed out, endpoint dropped");
        e->fail();
      }
    }
    const std::size_t n = f.drain_cq(out);
    f.reap_unsurfaced();
    if (n > 0 || budget.busy <= Nanos{0} || f.clock_->now() - start >= budget.busy) return n;
  }
}

int VerbsCmFabric::wait_fd() {
  // Arm the CQ: the next completion makes the comp channel (and so epfd_) readable.
  // A failed arm would let a caller sleep forever: treat it as a broken CQ so the next
  // poll() reports it.
  if (impl_->cq_ != nullptr && ibv_req_notify_cq(impl_->cq_, 0) != 0) {
    impl_->cq_broken_ = true;
    impl_->log("ibv_req_notify_cq failed");
  }
  return impl_->epfd_;
}

}  // namespace miracache::fabric
