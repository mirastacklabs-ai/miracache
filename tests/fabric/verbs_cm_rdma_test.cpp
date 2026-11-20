// SPDX-License-Identifier: Apache-2.0
// Real-RDMA tests for the verbs_cm backend. Labelled `rdma` in ctest; every test skips
// cleanly when no RDMA device is usable. MIRACACHE_RDMA_DEVICE selects the device
// (rxe0 = RoCEv2, siw0 = iWARP); run the suite once per device.
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <functional>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <arpa/inet.h>
#include <fstream>
#include <ifaddrs.h>
#include <poll.h>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <infiniband/verbs.h>
#include <rdma/rdma_cma.h>

#include "fabric/verbs_cm/verbs_cm_fabric.h"

using namespace miracache;
using namespace miracache::fabric;

namespace {

using Clk = std::chrono::steady_clock;

// Deterministic, position-dependent fill so a misplaced or stale byte is detected.
void fill(std::span<std::byte> b, std::uint64_t seed) {
  std::uint64_t x = seed * 0x9E3779B97F4A7C15ULL + 1;
  for (auto& v : b) {
    x ^= x << 13; x ^= x >> 7; x ^= x << 17;
    v = static_cast<std::byte>(x >> 24);
  }
}

// Page-aligned buffer (registration of aligned memory is the fast path everywhere).
struct Buf {
  explicit Buf(std::size_t n) : p(static_cast<std::byte*>(std::aligned_alloc(4096, (n + 4095) & ~std::size_t{4095}))), n(n) {
    std::memset(p, 0, n);
  }
  ~Buf() { std::free(p); }
  Buf(const Buf&) = delete;
  Buf& operator=(const Buf&) = delete;
  std::span<std::byte> span() { return {p, n}; }
  std::byte* p;
  std::size_t n;
};

// A Clock tests can move. Frozen: only advance() moves it (callers must poll with a zero busy
// budget). Not frozen: real time plus whatever advance() added, so busy polls still end.
class FakeClock final : public Clock {
 public:
  explicit FakeClock(bool frozen = false) : frozen_(frozen) {}
  Nanos now() const override {
    const Nanos base = frozen_ ? Nanos{0} : std::chrono::duration_cast<Nanos>(Clk::now() - start_);
    return base + Nanos{offset_.load()};
  }
  void advance(Nanos d) { offset_ += d.count(); }

 private:
  bool frozen_;
  Clk::time_point start_ = Clk::now();
  std::atomic<std::int64_t> offset_{0};
};

// The "remote node": its own fabric, driven from its own thread (poll services both
// completions and rdma_cm, so connect() from the client can finish). Everything that
// touches the server fabric goes through call().
class Server {
 public:
  explicit Server(VerbsOptions o) {
    auto f = VerbsCmFabric::open(o);
    opened_ = f.has_value();
    if (opened_) fab = std::move(*f);
  }
  ~Server() { stop(); }
  bool opened() const { return opened_; }

  Status start(ListenParams lp = {}) {
    auto ip = fab->device_ipv4();
    if (!ip) return ip.error();
    ip_ = *ip;
    lp.addr = RailAddr{ip_, 0};
    if (!lp.admit) lp.allow_unauthenticated_for_test = true;
    // Test frames reach kMaxFrameBytes, so accept with the full-size control layout
    // unless the test picks a class.
    auto s = fab->listen(
        [this](Endpoint* e) {
          std::lock_guard<std::mutex> g(m_);
          accepted_[e->id()] = e;
          accepted_order_.push_back(e);
        },
        lp);
    if (!s) return s;
    th_ = std::thread([this] { loop(); });
    return {};
  }
  void stop() {
    if (th_.joinable()) {
      stop_ = true;
      th_.join();
    }
  }
  Peer peer() const { return Peer{0, RailAddr{ip_, fab->listen_port()}}; }

  // Runs fn on the server thread and waits for it.
  template <typename F>
  auto call(F fn) {
    using R = decltype(fn());
    auto task = std::make_shared<std::packaged_task<R()>>(std::move(fn));
    auto fut = task->get_future();
    {
      std::lock_guard<std::mutex> g(m_);
      tasks_.push_back([task] { (*task)(); });
    }
    return fut.get();
  }
  Endpoint* wait_accepted(std::size_t n = 1, std::chrono::milliseconds limit = std::chrono::seconds(5)) {
    const auto end = Clk::now() + limit;
    while (Clk::now() < end) {
      {
        std::lock_guard<std::mutex> g(m_);
        if (accepted_order_.size() >= n) return accepted_order_[n - 1];
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return nullptr;
  }
  std::atomic<bool> echo{false};
  std::atomic<std::uint64_t> recvs{0};  // inbound frames seen by the server loop
  std::atomic<std::uint64_t> early_recvs{0};  // ... whose endpoint AcceptFn had not announced yet (must stay 0)
  std::unique_ptr<VerbsCmFabric> fab;

 private:
  void loop() {
    std::vector<Completion> out(32);
    while (!stop_) {
      std::deque<std::function<void()>> tasks;
      {
        std::lock_guard<std::mutex> g(m_);
        tasks.swap(tasks_);
      }
      for (auto& t : tasks) t();
      const std::size_t n = fab->poll(out, PollBudget{std::chrono::microseconds(200)});
      // A frame can beat the ESTABLISHED event that announces its endpoint (the peer may
      // send as soon as it sees its own ESTABLISHED), so unknown endpoints retry later.
      for (std::size_t i = 0; i < n; ++i) {
        if (out[i].is_recv) {
          ++recvs;
          std::lock_guard<std::mutex> g(m_);
          if (accepted_.find(out[i].endpoint) == accepted_.end()) ++early_recvs;
        }
        if (out[i].is_recv && echo) backlog_.push_back(std::move(out[i]));
      }
      for (auto it = backlog_.begin(); it != backlog_.end();) {
        Endpoint* e = nullptr;
        {
          std::lock_guard<std::mutex> g(m_);
          auto f = accepted_.find(it->endpoint);
          if (f != accepted_.end()) e = f->second;
        }
        if (e == nullptr) {
          ++it;
          continue;
        }
        static_cast<void>(e->post_send(std::move(it->frame), 0));
        it = backlog_.erase(it);
      }
    }
  }

  std::vector<Completion> backlog_;
  bool opened_ = false;
  std::string ip_;
  std::atomic<bool> stop_{false};
  std::thread th_;
  std::mutex m_;
  std::deque<std::function<void()>> tasks_;
  std::map<EndpointId, Endpoint*> accepted_;
  std::vector<Endpoint*> accepted_order_;
};

// The whole suite is parametrised by device name, so the identical tests run on every
// device (rxe0 = RoCEv2, siw0 = iWARP). MIRACACHE_RDMA_DEVICES (comma list) overrides
// the default list; devices that do not exist skip cleanly.
std::vector<std::string> devices() {
  const char* env = std::getenv("MIRACACHE_RDMA_DEVICES");
  std::stringstream ss(env != nullptr ? env : "rxe0,siw0");
  std::vector<std::string> out;
  for (std::string d; std::getline(ss, d, ',');) {
    if (!d.empty()) out.push_back(d);
  }
  return out;
}

class RdmaTest : public ::testing::TestWithParam<std::string> {
 protected:
  void SetUp() override {
    device_ = GetParam();
    VerbsOptions o;
    o.device = device_;
    auto f = VerbsCmFabric::open(o);
    if (!f) {
      if (f.error().code == ErrorCode::NotFound) {
        GTEST_SKIP() << "no usable RDMA device " << device_ << " (" << f.error().context << ")";
      }
      FAIL() << "open(" << device_ << ") failed: " << f.error().context;
    }
    client = std::move(*f);
    server_options.device = device_;
  }
  void make_server() {
    server = std::make_unique<Server>(server_options);
    ASSERT_TRUE(server->opened());
  }
  void TearDown() override {
    if (server) server->stop();
  }

  bool iwarp() const { return client->nic_caps().protocol == NicProtocol::IWarp; }

  void start_server(ListenParams lp = {}) {
    if (!server) make_server();
    auto s = server->start(std::move(lp));
    ASSERT_TRUE(s) << s.error().context;
  }
  Endpoint* dial(ConnParams cp = {}) {
    auto e = client->connect(server->peer(), cp);
    EXPECT_TRUE(e) << (e ? "" : e.error().context);
    return e ? *e : nullptr;
  }
  // Polls the client until a completion for `tag` (non-recv) shows up.
  bool wait_tag(WrTag tag, Completion& out, std::chrono::seconds limit = std::chrono::seconds(20)) {
    for (auto it = stray.begin(); it != stray.end(); ++it) {
      if (!it->is_recv && it->tag == tag) {
        out = std::move(*it);
        stray.erase(it);
        return true;
      }
    }
    const auto end = Clk::now() + limit;
    std::vector<Completion> v(8);
    while (Clk::now() < end) {
      const std::size_t n = client->poll(v, PollBudget{std::chrono::microseconds(100)});
      bool found = false;
      for (std::size_t i = 0; i < n; ++i) {
        if (!found && !v[i].is_recv && v[i].tag == tag) {
          out = std::move(v[i]);
          found = true;
        } else {
          stray.push_back(std::move(v[i]));
        }
      }
      if (found) return true;
    }
    return false;
  }

  std::string dump_stray() {
    std::ostringstream o;
    for (auto& c : stray) {
      o << "[ep=" << c.endpoint << " tag=" << c.tag << " recv=" << c.is_recv << " op=" << int(c.op) << " st="
        << (c.status ? "ok" : c.status.error().context) << "] ";
    }
    return o.str();
  }
  void round_trip(std::size_t size);
  std::string device_;
  // Pointees of server_options (hold_established_for_test, clock) must outlive the server,
  // whose thread keeps polling until TearDown: they live here, declared before `server`,
  // never as locals of a test body (that was a stack-use-after-return).
  std::atomic<bool> hold{false};
  FakeClock server_clock;
  std::unique_ptr<VerbsCmFabric> client;
  VerbsOptions server_options;
  std::unique_ptr<Server> server;
  std::vector<Completion> stray;
};

}  // namespace

TEST_P(RdmaTest, ProbePrintsNicCaps) {
  const NicCaps& c = client->nic_caps();
  std::cout << to_string(c) << std::endl;
  RecordProperty("nic_caps", to_string(c));
  EXPECT_FALSE(c.device.empty());
  EXPECT_NE(c.protocol, NicProtocol::Unknown);
  if (c.device.rfind("siw", 0) == 0) EXPECT_EQ(c.protocol, NicProtocol::IWarp);
  if (c.device.rfind("rxe", 0) == 0) EXPECT_EQ(c.protocol, NicProtocol::RoCE);
  EXPECT_EQ(c.read_sink_needs_remote_write, c.protocol == NicProtocol::IWarp);
  EXPECT_GT(c.max_mr_size, 0u);
  EXPECT_GT(c.max_qp_rd_atom, 0u);
  EXPECT_GT(c.max_qp_init_rd_atom, 0u);
  EXPECT_TRUE(c.trial_reg_ok);
  auto caps = client->probe();
  ASSERT_TRUE(caps);
  EXPECT_STREQ(caps->name, c.device.c_str());
}

TEST_P(RdmaTest, ConnectAcceptLoopbackCarriesTicket) {
  start_server();
  ConnParams cp;
  cp.ticket_len = 20;
  for (std::size_t i = 0; i < cp.ticket_len; ++i) cp.ticket[i] = static_cast<std::byte>(0xA0 + i);
  Endpoint* c = dial(cp);
  ASSERT_NE(c, nullptr);
  EXPECT_EQ(c->state(), EpState::Ready);
  EXPECT_TRUE(c->drained());
  EXPECT_TRUE(c->peer_private_data().empty());  // active side
  EXPECT_GT(c->read_depth().ord, 0);
  EXPECT_GT(c->read_depth().ird, 0);

  Endpoint* s = server->wait_accepted();
  ASSERT_NE(s, nullptr);
  const auto got = server->call([s] {
    auto d = s->peer_private_data();
    return std::make_pair(std::vector<std::byte>(d.begin(), d.end()), s->state());
  });
  ASSERT_EQ(got.first.size(), 20u);
  for (std::size_t i = 0; i < 20; ++i) EXPECT_EQ(got.first[i], cp.ticket[i]);
  EXPECT_EQ(got.second, EpState::Ready);
}

TEST_P(RdmaTest, MaxTicketAndOversizeTicket) {
  start_server();
  ConnParams cp;
  cp.ticket_len = static_cast<std::uint8_t>(kMaxTicketBytes);
  fill(std::span<std::byte>(cp.ticket), 7);
  ASSERT_NE(dial(cp), nullptr);
  Endpoint* s = server->wait_accepted();
  ASSERT_NE(s, nullptr);
  const auto got = server->call([s] {
    auto d = s->peer_private_data();
    return std::vector<std::byte>(d.begin(), d.end());
  });
  ASSERT_EQ(got.size(), kMaxTicketBytes);
  EXPECT_EQ(std::memcmp(got.data(), cp.ticket.data(), kMaxTicketBytes), 0);

  cp.ticket_len = static_cast<std::uint8_t>(kMaxTicketBytes + 1);
  auto bad = client->connect(server->peer(), cp);
  ASSERT_FALSE(bad);
  EXPECT_EQ(bad.error().code, ErrorCode::InvalidArgument);
}

TEST_P(RdmaTest, AdmitHookRejectsBeforeAccept) {
  ListenParams lp;
  lp.admit = [](std::span<const std::byte> pd) -> Expected<Admission> {
    if (pd.size() == 4 && pd[0] == std::byte{1}) return Admission{};
    return Error{ErrorCode::AccessDenied, "bad ticket"};
  };
  start_server(lp);
  ConnParams good;
  good.ticket_len = 4;
  good.ticket[0] = std::byte{1};
  EXPECT_NE(dial(good), nullptr);
  ConnParams bad;
  bad.ticket_len = 4;
  bad.ticket[0] = std::byte{9};
  auto e = client->connect(server->peer(), bad);
  EXPECT_FALSE(e);
  EXPECT_EQ(server->call([&] { return 0; }), 0);
  Endpoint* only = server->wait_accepted(1);
  ASSERT_NE(only, nullptr);
  EXPECT_EQ(server->wait_accepted(2, std::chrono::milliseconds(300)), nullptr);  // the rejected connection never surfaced
}

TEST_P(RdmaTest, ReadDepthIsMinOfBothSides) {
  start_server();
  ConnParams cp;
  cp.ird = 2;
  cp.ord = 3;
  Endpoint* c = dial(cp);
  ASSERT_NE(c, nullptr);
  const NicCaps& caps = client->nic_caps();
  // The passive side clamps its device maximum to what the client announced: it absorbs
  // at most the client's ORD (3) READs and issues at most the client's IRD (2). The
  // client then takes the minimum of its own request and the server's answer.
  ASSERT_GE(caps.max_qp_rd_atom, 3u);
  ASSERT_GE(caps.max_qp_init_rd_atom, 3u);
  Endpoint* s = server->wait_accepted();
  ASSERT_NE(s, nullptr);
  const ReadDepth sd = server->call([s] { return s->read_depth(); });
  EXPECT_EQ(sd.ird, 3u);
  EXPECT_EQ(sd.ord, 2u);
  EXPECT_EQ(c->read_depth().ord, std::min<unsigned>(3, sd.ird));
  EXPECT_EQ(c->read_depth().ird, std::min<unsigned>(2, sd.ord));
}

TEST_P(RdmaTest, SendRecvPingPong) {
  start_server();
  server->echo = true;
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  std::vector<Completion> v(8);
  for (std::uint32_t i = 0; i < 200; ++i) {
    Frame f;
    f.bytes.resize(1 + (i * 331) % kMaxFrameBytes);
    fill(f.bytes, i);
    const Frame sent = f;
    ASSERT_TRUE(c->post_send(std::move(f), i));
    bool got_recv = false, got_send = false;
    const auto end = Clk::now() + std::chrono::seconds(10);
    while (!(got_recv && got_send) && Clk::now() < end) {
      const std::size_t n = client->poll(v, PollBudget{std::chrono::microseconds(100)});
      for (std::size_t k = 0; k < n; ++k) {
        ASSERT_TRUE(v[k].status) << v[k].status.error().context;
        if (v[k].is_recv) {
          got_recv = true;
          ASSERT_EQ(v[k].frame.bytes.size(), sent.bytes.size());
          EXPECT_EQ(v[k].frame.bytes, sent.bytes) << "iteration " << i;
          EXPECT_EQ(v[k].endpoint, c->id());
        } else {
          got_send = true;
          EXPECT_EQ(v[k].op, CompletionOp::Send);
          EXPECT_EQ(v[k].tag, i);
        }
      }
    }
    ASSERT_TRUE(got_recv && got_send) << "iteration " << i;
  }
  EXPECT_TRUE(c->drained());
  Frame big;
  big.bytes.resize(kMaxFrameBytes + 1);
  auto s = c->post_send(std::move(big), 0);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::InvalidArgument);
}

TEST_P(RdmaTest, WriteThenReadRoundTrip64KiBAnd8MiB) {
  start_server();
  for (const std::size_t size : {std::size_t{64} << 10, std::size_t{8} << 20}) {
    SCOPED_TRACE(size);
    round_trip(size);
    if (HasFatalFailure()) return;
  }
}

void RdmaTest::round_trip(std::size_t size) {
  Buf remote_buf(size);
  auto remote = server->call([&] { return server->fab->reg(remote_buf.span(), Access::RemoteRead | Access::RemoteWrite); });
  ASSERT_TRUE(remote) << remote.error().context;
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);

  Buf src(size), dst(size);
  fill(src.span(), size);
  auto src_mr = client->reg(src.span(), Access::None);
  auto dst_mr = client->reg(dst.span(), Access::LocalWrite);  // READ sink
  ASSERT_TRUE(src_mr);
  ASSERT_TRUE(dst_mr);

  RemoteRef rr{remote->rkey, reinterpret_cast<std::uint64_t>(remote->addr), static_cast<std::uint32_t>(size)};
  ASSERT_TRUE(c->post_write(LocalRef{src_mr->lkey, src.p, static_cast<std::uint32_t>(size)}, rr, 11));
  // Same QP: the READ is ordered behind the WRITE, so its data proves placement even on
  // iWARP, where the WRITE CQE only means "handed to TCP" (spec 3.2).
  ASSERT_TRUE(c->post_read(rr, LocalRef{dst_mr->lkey, dst.p, static_cast<std::uint32_t>(size)}, 12));
  Completion w, r;
  ASSERT_TRUE(wait_tag(11, w));
  ASSERT_TRUE(w.status) << w.status.error().context;
  EXPECT_EQ(w.op, CompletionOp::Write);
  EXPECT_EQ(w.bytes, size);
  ASSERT_TRUE(wait_tag(12, r));
  ASSERT_TRUE(r.status) << r.status.error().context;
  EXPECT_EQ(r.op, CompletionOp::Read);
  EXPECT_EQ(r.bytes, size);

  EXPECT_EQ(std::memcmp(dst.p, src.p, size), 0) << "READ-back differs from what was WRITTEN";
  EXPECT_EQ(std::memcmp(remote_buf.p, src.p, size), 0) << "server memory differs";
  EXPECT_TRUE(c->drained());
  EXPECT_TRUE(client->dereg(*src_mr));
  EXPECT_TRUE(client->dereg(*dst_mr));
  EXPECT_TRUE(server->call([&] { return server->fab->dereg(*remote); }));
}

INSTANTIATE_TEST_SUITE_P(Device, RdmaTest, ::testing::ValuesIn(devices()),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

TEST_P(RdmaTest, ReadSinkRegisteredPerTransportRules) {
  start_server();
  Buf remote_buf(4096), sink(4096), plain(4096);
  fill(remote_buf.span(), 99);
  auto remote = server->call([&] { return server->fab->reg(remote_buf.span(), Access::RemoteRead); });
  ASSERT_TRUE(remote);
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);

  // A sink asks only for LocalWrite; on iWARP the backend must add REMOTE_WRITE.
  auto sink_mr = client->reg(sink.span(), Access::LocalWrite);
  ASSERT_TRUE(sink_mr);
  EXPECT_EQ(has(sink_mr->access, Access::RemoteWrite), iwarp());
  EXPECT_TRUE(has(sink_mr->access, Access::LocalWrite));

  RemoteRef rr{remote->rkey, reinterpret_cast<std::uint64_t>(remote->addr), 4096};
  ASSERT_TRUE(c->post_read(rr, LocalRef{sink_mr->lkey, sink.p, 4096}, 1));
  Completion r;
  ASSERT_TRUE(wait_tag(1, r));
  ASSERT_TRUE(r.status) << r.status.error().context;
  EXPECT_EQ(std::memcmp(sink.p, remote_buf.p, 4096), 0);

  // A region without LocalWrite is not a legal sink on either transport.
  auto plain_mr = client->reg(plain.span(), Access::RemoteRead);
  ASSERT_TRUE(plain_mr);
  auto bad = c->post_read(rr, LocalRef{plain_mr->lkey, plain.p, 4096}, 2);
  ASSERT_FALSE(bad);
  EXPECT_EQ(bad.error().code, ErrorCode::AccessDenied);
  // Out-of-range local refs and unknown keys are refused before reaching the NIC.
  EXPECT_FALSE(c->post_read(rr, LocalRef{sink_mr->lkey, sink.p + 1, 4096}, 3));
  EXPECT_FALSE(c->post_read(rr, LocalRef{sink_mr->lkey + 12345, sink.p, 4096}, 4));
}

TEST_P(RdmaTest, DeregRefusedWhileBusy) {
  start_server();
  const std::size_t size = std::size_t{8} << 20;
  Buf remote_buf(size), sink(size);
  auto remote = server->call([&] { return server->fab->reg(remote_buf.span(), Access::RemoteRead); });
  ASSERT_TRUE(remote);
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  auto sink_mr = client->reg(sink.span(), Access::LocalWrite);
  ASSERT_TRUE(sink_mr);

  RemoteRef rr{remote->rkey, reinterpret_cast<std::uint64_t>(remote->addr), static_cast<std::uint32_t>(size)};
  ASSERT_TRUE(c->post_read(rr, LocalRef{sink_mr->lkey, sink.p, static_cast<std::uint32_t>(size)}, 5));
  EXPECT_FALSE(c->drained());
  auto busy = client->dereg(*sink_mr);  // nothing polled yet: the WR is outstanding
  ASSERT_FALSE(busy);
  EXPECT_EQ(busy.error().code, ErrorCode::Busy);

  Completion r;
  ASSERT_TRUE(wait_tag(5, r));
  ASSERT_TRUE(r.status);
  EXPECT_TRUE(c->drained());
  EXPECT_TRUE(client->dereg(*sink_mr));  // drained: now allowed
  EXPECT_FALSE(client->dereg(*sink_mr)); // already gone
  EXPECT_TRUE(server->call([&] { return server->fab->dereg(*remote); }));
}

TEST_P(RdmaTest, RemoteMrDeregisteredMidFlightErrorsTheEndpoint) {
  start_server();
  Buf good_buf(65536), doomed_buf(65536), sink(3 * 65536);
  auto good = server->call([&] { return server->fab->reg(good_buf.span(), Access::RemoteRead); });
  auto doomed = server->call([&] { return server->fab->reg(doomed_buf.span(), Access::RemoteRead); });
  ASSERT_TRUE(good);
  ASSERT_TRUE(doomed);
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  auto sink_mr = client->reg(sink.span(), Access::LocalWrite);
  ASSERT_TRUE(sink_mr);

  ASSERT_TRUE(server->call([&] { return server->fab->dereg(*doomed); }));  // rkey is now stale

  auto ref = [&](const MemRegion& m) {
    return RemoteRef{m.rkey, reinterpret_cast<std::uint64_t>(m.addr), 65536};
  };
  auto loc = [&](int i) { return LocalRef{sink_mr->lkey, sink.p + i * 65536, 65536}; };
  ASSERT_TRUE(c->post_read(ref(*good), loc(0), 1));
  ASSERT_TRUE(c->post_read(ref(*doomed), loc(1), 2));
  ASSERT_TRUE(c->post_read(ref(*good), loc(2), 3));

  Completion c1, c2, c3;
  ASSERT_TRUE(wait_tag(2, c2));
  ASSERT_TRUE(wait_tag(3, c3, std::chrono::seconds(3))) << dump_stray();
  ASSERT_TRUE(wait_tag(1, c1));
  EXPECT_FALSE(c2.status) << "the stale-rkey READ must fail";
  // rxe reports REM_ACCESS_ERR (AccessDenied); siw reports a generic error, so the
  // portable contract is only "an error completion".
  std::cout << "remote access error surfaced as: " << c2.status.error().context << std::endl;
  EXPECT_FALSE(c3.status) << "work behind the failure must be flushed";
  EXPECT_EQ(c1.op, CompletionOp::Read);

  EXPECT_EQ(c->state(), EpState::Error);
  EXPECT_TRUE(c->drained());
  auto again = c->post_read(ref(*good), loc(0), 4);
  ASSERT_FALSE(again);
  EXPECT_EQ(again.error().code, ErrorCode::Aborted);
  EXPECT_FALSE(c->post_write(loc(0), ref(*good), 5));
  Frame f;
  f.bytes.resize(8);
  EXPECT_FALSE(c->post_send(std::move(f), 6));
  // Drained: releasing the region is allowed again.
  EXPECT_TRUE(client->dereg(*sink_mr));
}

// Proves: after abort() the in-flight READ retires (flushed, or completed if it won the
// race), the endpoint is drained and refuses posts, and the peer sees the disconnect.
// Not covered: that the READ is specifically flushed with Aborted (the race is real).
TEST_P(RdmaTest, AbortRetiresWorkRefusesPostsAndNotifiesPeer) {
  start_server();
  const std::size_t size = std::size_t{8} << 20;
  Buf remote_buf(size), sink(size);
  auto remote = server->call([&] { return server->fab->reg(remote_buf.span(), Access::RemoteRead); });
  ASSERT_TRUE(remote);
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  auto sink_mr = client->reg(sink.span(), Access::LocalWrite);
  ASSERT_TRUE(sink_mr);
  RemoteRef rr{remote->rkey, reinterpret_cast<std::uint64_t>(remote->addr), static_cast<std::uint32_t>(size)};
  ASSERT_TRUE(c->post_read(rr, LocalRef{sink_mr->lkey, sink.p, static_cast<std::uint32_t>(size)}, 9));
  c->abort();
  EXPECT_EQ(c->state(), EpState::Error);
  Completion r;
  ASSERT_TRUE(wait_tag(9, r));  // flushed or (if it won the race) completed; either way it retires
  EXPECT_TRUE(c->drained());
  EXPECT_FALSE(c->post_read(rr, LocalRef{sink_mr->lkey, sink.p, 4096}, 10));
  EXPECT_TRUE(client->dereg(*sink_mr));
  // The peer learns of the disconnect.
  Endpoint* s = server->wait_accepted();
  ASSERT_NE(s, nullptr);
  const auto end = Clk::now() + std::chrono::seconds(5);
  EpState st = EpState::Ready;
  while (Clk::now() < end && st != EpState::Error) {
    st = server->call([s] { return s->state(); });
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  EXPECT_EQ(st, EpState::Error);
}

TEST_P(RdmaTest, EventFdWakesOnCompletion) {
  start_server();
  server->echo = true;
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  std::vector<Completion> v(8);
  ASSERT_TRUE(c->post_send(Frame{std::vector<std::byte>(16, std::byte{3})}, 1));
  bool got_recv = false;
  const auto end = Clk::now() + std::chrono::seconds(10);
  while (!got_recv && Clk::now() < end) {
    std::size_t n = client->poll(v);  // no busy budget: pure nonblocking
    if (n == 0) {
      const int fd = client->wait_fd();
      ASSERT_GE(fd, 0);
      n = client->poll(v);  // closes the arm/poll race
      if (n == 0) {
        pollfd p{fd, POLLIN, 0};
        ASSERT_GT(::poll(&p, 1, 2000), 0) << "wait_fd never became readable";
        EXPECT_TRUE(p.revents & POLLIN);
        n = client->poll(v);
      }
    }
    for (std::size_t i = 0; i < n; ++i) got_recv = got_recv || v[i].is_recv;
  }
  EXPECT_TRUE(got_recv);
}

namespace {
bool parse_ok(const char* t) { return protocol::parse_setting(t).has_value(); }
}  // namespace

TEST_P(RdmaTest, ProtocolOverrideMustMatchDevice) {
  const NicProtocol real = client->nic_caps().protocol;
  const auto wrong = real == NicProtocol::IWarp ? protocol::Setting::RoCE : protocol::Setting::IWarp;
  const auto right = real == NicProtocol::IWarp ? protocol::Setting::IWarp : protocol::Setting::RoCE;
  VerbsOptions o;
  o.device = device_;
  o.protocol = wrong;
  auto bad = VerbsCmFabric::open(o);
  ASSERT_FALSE(bad);
  EXPECT_EQ(bad.error().code, ErrorCode::InvalidArgument);
  std::cout << "mismatch error: " << bad.error().context << std::endl;
  o.protocol = right;
  auto ok = VerbsCmFabric::open(o);
  ASSERT_TRUE(ok);
  EXPECT_EQ((*ok)->active_protocol(), real);
  EXPECT_EQ(client->active_protocol(), real);  // auto detects the same
  EXPECT_FALSE(client->set_protocol(wrong));
  EXPECT_TRUE(parse_ok("auto") && parse_ok("roce") && parse_ok("iwarp") && !parse_ok("tcp"));
}

TEST_P(RdmaTest, PeerProtocolMismatchRefusesConnection) {
  // The server believes it is on the other protocol, so it must refuse the connection
  // with a clear, specific error rather than a generic reject.
  const NicProtocol real = client->nic_caps().protocol;
  server_options.advertise_protocol_for_test = real == NicProtocol::IWarp ? NicProtocol::RoCE : NicProtocol::IWarp;
  start_server();
  auto e = client->connect(server->peer());
  ASSERT_FALSE(e);
  EXPECT_EQ(e.error().code, ErrorCode::Unsupported);
  std::cout << "peer mismatch error: " << e.error().context << std::endl;
  EXPECT_EQ(server->wait_accepted(1, std::chrono::milliseconds(300)), nullptr);
}

// Proves: re-applying the matching setting keeps the epoch and leaves endpoints current.
// Not covered: a real protocol change (needs a device whose detected protocol differs),
// stale_endpoints() becoming non-empty, or draining stale endpoints.
TEST_P(RdmaTest, ReapplyingSameProtocolKeepsEpochAndEndpointsCurrent) {
  start_server();
  Endpoint* old_ep = dial();
  ASSERT_NE(old_ep, nullptr);
  const auto epoch0 = client->protocol_epoch();
  EXPECT_TRUE(client->stale_endpoints().empty());
  // Re-applying the matching setting does not change the protocol, so nothing goes stale.
  ASSERT_TRUE(client->set_protocol(protocol::Setting::Auto));
  EXPECT_EQ(client->protocol_epoch(), epoch0);
  EXPECT_EQ(client->endpoint_protocol(old_ep), client->active_protocol());
  EXPECT_EQ(client->endpoint_epoch(old_ep), epoch0);
}

// ---- endpoint lifecycle, PDs, CQ budget ----

// Q01: frames that arrive before the passive side has seen ESTABLISHED must not eat
// receive slots. The hook holds ESTABLISHED back while the client sends 3x the depth.
TEST_P(RdmaTest, FramesBeforeEstablishedDoNotLoseRecvSlots) {
  hold = true;
  server_options.hold_established_for_test = &hold;
  ListenParams lp;
  lp.accept_timeout = std::chrono::seconds(120);  // a held endpoint is still subject to it
  start_server(lp);
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  const std::uint64_t credits = server_options.recv_slots;  // receives the server posts per endpoint
  const std::uint64_t total = 3 * credits;
  auto held = [&] { return static_cast<std::uint64_t>(server->call([&] { return server->fab->held_recvs(); })); };
  std::vector<Completion> v(16);
  std::uint64_t sent = 0, send_done = 0, taken = 0;
  const auto end = Clk::now() + std::chrono::seconds(20);
  while ((sent < total || send_done < total) && Clk::now() < end) {
    // Throttle like the product's credits: at most `credits` frames the server has not taken in yet. A send
    // completion does not mean that: on iWARP (siw) it is local (the frame left on TCP), and iWARP has no RNR
    // retry, so a SEND that finds no posted receive kills the connection (the sender sees "local QP operation
    // error"). Each frame the server takes in while held re-posts its slot at once and counts in held_recvs().
    if (sent < total && sent - taken >= credits) taken = held();
    // A few sends in flight at most, so RoCE never relies on RNR retries either.
    while (sent < total && sent - send_done < 4 && sent - taken < credits) {
      auto ps = c->post_send(Frame{std::vector<std::byte>(64, std::byte{7})}, sent);
      ASSERT_TRUE(ps) << ps.error().context << " sent=" << sent;
      ++sent;
    }
    const std::size_t n = client->poll(v, PollBudget{std::chrono::microseconds(100)});
    for (std::size_t i = 0; i < n; ++i) {
      if (!v[i].is_recv) {
        ASSERT_TRUE(v[i].status) << v[i].status.error().context;
        ++send_done;
      }
    }
  }
  EXPECT_EQ(send_done, total);
  // 3x the slots taken in while held: every slot came back (Q01).
  while (taken < total && Clk::now() < end) {
    taken = held();
    if (taken < total) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  EXPECT_EQ(taken, total);
  EXPECT_EQ(server->recvs.load(), 0u) << "N05: no Recv may surface before the endpoint is announced";
  EXPECT_EQ(server->wait_accepted(1, std::chrono::milliseconds(100)), nullptr) << "hold should keep it unannounced";
  hold = false;
  EXPECT_NE(server->wait_accepted(), nullptr);
  while (server->recvs < total && Clk::now() < end) std::this_thread::sleep_for(std::chrono::milliseconds(1));
  EXPECT_EQ(server->recvs.load(), total);  // all held frames arrive, after the announcement, in order
  EXPECT_EQ(server->early_recvs.load(), 0u);
  EXPECT_EQ(server->call([&] { return server->fab->held_recvs(); }), 0u);  // handed over at the announcement
}

// Q02: failed connects and released endpoints must not accumulate.
TEST_P(RdmaTest, FailedConnectsAndReleasesDoNotLeakEndpoints) {
  auto ip = client->device_ipv4();
  ASSERT_TRUE(ip);
  ConnParams cp;
  cp.timeout = std::chrono::seconds(3);
  for (int i = 0; i < 20; ++i) {
    auto e = client->connect(Peer{0, RailAddr{*ip, 1}}, cp);  // nobody listens on port 1
    ASSERT_FALSE(e);
    EXPECT_EQ(client->endpoint_count(), 0u) << "iteration " << i;
  }
  start_server();
  for (int i = 0; i < 10; ++i) {
    Endpoint* c = dial();
    ASSERT_NE(c, nullptr);
    Endpoint* s = server->wait_accepted(static_cast<std::size_t>(i) + 1);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(client->endpoint_count(), 1u);
    ASSERT_TRUE(client->release(c));
    EXPECT_EQ(client->endpoint_count(), 0u);
    EXPECT_TRUE(server->call([&] { return server->fab->release(s); }));
  }
  EXPECT_EQ(server->call([&] { return server->fab->endpoint_count(); }), 0u);
  EXPECT_FALSE(client->release(nullptr));
}

TEST_P(RdmaTest, ReleaseRefusedWhileWorkOutstanding) {
  start_server();
  const std::size_t size = std::size_t{8} << 20;
  Buf remote_buf(size), sink(size);
  auto remote = server->call([&] { return server->fab->reg(remote_buf.span(), Access::RemoteRead); });
  ASSERT_TRUE(remote);
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  auto sink_mr = client->reg(sink.span(), Access::LocalWrite);
  ASSERT_TRUE(sink_mr);
  RemoteRef rr{remote->rkey, reinterpret_cast<std::uint64_t>(remote->addr), static_cast<std::uint32_t>(size)};
  ASSERT_TRUE(c->post_read(rr, LocalRef{sink_mr->lkey, sink.p, static_cast<std::uint32_t>(size)}, 1));
  auto busy = client->release(c);
  ASSERT_FALSE(busy);
  EXPECT_EQ(busy.error().code, ErrorCode::Busy);
  Completion r;
  ASSERT_TRUE(wait_tag(1, r));
  EXPECT_TRUE(client->release(c));
  EXPECT_TRUE(client->dereg(*sink_mr));
  EXPECT_TRUE(server->call([&] { return server->fab->dereg(*remote); }));
}

// Q03/Q07: a region in PD A is unusable through an endpoint in PD B, locally and remotely.
TEST_P(RdmaTest, RegionInOtherPdIsNotUsable) {
  make_server();
  auto sa = server->fab->alloc_pd();
  auto sb = server->fab->alloc_pd();
  ASSERT_TRUE(sa);
  ASSERT_TRUE(sb);
  ListenParams lp;
  lp.accept_pd = *sb;  // server endpoints live in PD B
  start_server(lp);
  Buf rb_a(4096), rb_b(4096), sink(4096);
  fill(rb_b.span(), 5);
  auto in_a = server->call([&] { return server->fab->reg(rb_a.span(), Access::RemoteRead, *sa); });
  auto in_b = server->call([&] { return server->fab->reg(rb_b.span(), Access::RemoteRead, *sb); });
  ASSERT_TRUE(in_a);
  ASSERT_TRUE(in_b);

  auto ca = client->alloc_pd();
  auto cb = client->alloc_pd();
  ASSERT_TRUE(ca);
  ASSERT_TRUE(cb);
  auto sink_a = client->reg(sink.span(), Access::LocalWrite, *ca);
  ASSERT_TRUE(sink_a);
  EXPECT_FALSE(client->free_pd(*ca)) << "PD with a region must be Busy";

  // Local side: endpoint in PD B must refuse a sink registered in PD A.
  ConnParams pb;
  pb.pd = *cb;
  Endpoint* eb = dial(pb);
  ASSERT_NE(eb, nullptr);
  RemoteRef good{in_b->rkey, reinterpret_cast<std::uint64_t>(in_b->addr), 4096};
  auto wrong_local = eb->post_read(good, LocalRef{sink_a->lkey, sink.p, 4096}, 1);
  ASSERT_FALSE(wrong_local);
  EXPECT_EQ(wrong_local.error().code, ErrorCode::InvalidArgument);

  // Positive control: same PD on both ends works.
  ConnParams pa;
  pa.pd = *ca;
  Endpoint* ea = dial(pa);
  ASSERT_NE(ea, nullptr);
  ASSERT_TRUE(ea->post_read(good, LocalRef{sink_a->lkey, sink.p, 4096}, 2));
  Completion ok;
  ASSERT_TRUE(wait_tag(2, ok));
  EXPECT_TRUE(ok.status) << (ok.status ? "" : ok.status.error().context);
  EXPECT_EQ(std::memcmp(sink.p, rb_b.p, 4096), 0);

  // Remote side: the server's endpoint is in PD B, so the rkey of its PD A region fails.
  Endpoint* ec = dial(pa);
  ASSERT_NE(ec, nullptr);
  RemoteRef bad{in_a->rkey, reinterpret_cast<std::uint64_t>(in_a->addr), 4096};
  ASSERT_TRUE(ec->post_read(bad, LocalRef{sink_a->lkey, sink.p, 4096}, 3));
  Completion denied;
  ASSERT_TRUE(wait_tag(3, denied));
  EXPECT_FALSE(denied.status) << "READ of a region in another PD must fail";

  ASSERT_TRUE(client->release(ea));
  ASSERT_TRUE(client->release(eb));
  ASSERT_TRUE(client->release(ec));
  EXPECT_TRUE(client->dereg(*sink_a));
  EXPECT_TRUE(client->free_pd(*ca));
  EXPECT_TRUE(client->free_pd(*cb));
  EXPECT_FALSE(client->free_pd(PdId{}));
}

// Q06: the CQ budget refuses endpoints that could overflow the shared CQ.
TEST_P(RdmaTest, CqBudgetRefusesTooManyEndpoints) {
  start_server();
  VerbsOptions o;
  o.device = device_;
  o.cq_depth = 200;
  o.sq_depth = 64;
  o.recv_slots = 16;  // 80 CQEs per QP: two fit in 200, the third does not
  auto f = VerbsCmFabric::open(o);
  ASSERT_TRUE(f);
  auto e1 = (*f)->connect(server->peer());
  auto e2 = (*f)->connect(server->peer());
  ASSERT_TRUE(e1);
  ASSERT_TRUE(e2);
  auto e3 = (*f)->connect(server->peer());
  ASSERT_FALSE(e3);
  EXPECT_EQ(e3.error().code, ErrorCode::ResourceExhausted);
  EXPECT_EQ((*f)->endpoint_count(), 2u);
  ASSERT_TRUE((*f)->release(*e1));
  EXPECT_TRUE((*f)->connect(server->peer()));  // budget returned
}

// Q15: fetch endpoints use the spec 3.5 layout (2 receives of 8 KiB, HELLO only).
TEST_P(RdmaTest, FetchClassUsesSmallFrameLayout) {
  ListenParams lp;
  lp.accept_class = EpClass::Fetch;
  start_server(lp);
  server->echo = true;
  ConnParams cp;
  cp.cls = EpClass::Fetch;
  Endpoint* c = dial(cp);
  ASSERT_NE(c, nullptr);
  auto too_big = c->post_send(Frame{std::vector<std::byte>(8 * 1024 + 1)}, 1);
  ASSERT_FALSE(too_big);
  EXPECT_EQ(too_big.error().code, ErrorCode::InvalidArgument);
  ASSERT_TRUE(c->post_send(Frame{std::vector<std::byte>(8 * 1024, std::byte{9})}, 2));
  Completion s;
  ASSERT_TRUE(wait_tag(2, s));
  EXPECT_TRUE(s.status);
}

// ---- round 2: dispatcher, admission, accept limits ----

template <typename F>
bool wait_until(F cond, std::chrono::seconds limit = std::chrono::seconds(5)) {
  const auto end = Clk::now() + limit;
  while (Clk::now() < end) {
    if (cond()) return true;
    std::this_thread::sleep_for(std::chrono::milliseconds(2));
  }
  return cond();
}

// R01: post_wr refuses the (sq_depth+1)-th outstanding send-queue WR with ResourceExhausted, for every provider (the CQ
// budget is enforced by code, not by the provider's ring size), and posting resumes once completions are polled.
TEST_P(RdmaTest, SendQueueDepthIsEnforcedAndRecovers) {
  start_server();
  VerbsOptions o;
  o.device = device_;
  o.sq_depth = 4;  // below send_slots (16), so the sq_depth check is the one that fires
  auto f = VerbsCmFabric::open(o);
  ASSERT_TRUE(f);
  auto er = (*f)->connect(server->peer());
  ASSERT_TRUE(er);
  Endpoint* e = *er;
  std::vector<Completion> v(16);
  auto frame = [] { return Frame{std::vector<std::byte>(16, std::byte{3})}; };
  auto wait_ready = [&] { return wait_until([&] { (*f)->poll(v); return e->state() == EpState::Ready; }); };
  ASSERT_TRUE(wait_ready());
  // No poll between the posts: nothing completes from the fabric's point of view, so outstanding_ climbs to sq_depth.
  for (WrTag t = 1; t <= 4; ++t) ASSERT_TRUE(e->post_send(frame(), t)) << "post " << t;
  auto over = e->post_send(frame(), 5);
  ASSERT_FALSE(over);
  EXPECT_EQ(over.error().code, ErrorCode::ResourceExhausted);
  // Drain the four completions; the counter returns to zero and the QP accepts work again.
  std::size_t done = 0;
  EXPECT_TRUE(wait_until([&] {
    const std::size_t n = (*f)->poll(v);
    for (std::size_t i = 0; i < n; ++i) done += (v[i].op == CompletionOp::Send && v[i].status) ? 1 : 0;
    return done >= 4;
  }));
  EXPECT_TRUE(e->drained());
  for (WrTag t = 6; t <= 9; ++t) ASSERT_TRUE(e->post_send(frame(), t)) << "post " << t;
  EXPECT_FALSE(e->post_send(frame(), 10));
  EXPECT_TRUE(wait_until([&] { (*f)->poll(v); return e->drained(); }));
  ASSERT_TRUE((*f)->release(e));
}

// N01: three fabrics (client, client2, server) sit on one ibv_context. An event for a QP or
// CQ of one fabric must only reach that fabric; port/device errors reach every fabric on
// the context. The events go into the real per-device dispatcher routing table (rxe/siw
// raise none on demand). On iWARP a failed QP also drops its TCP peer, so only endpoints
// that are not peers of a failed one are used as the "must stay Ready" witnesses.
TEST_P(RdmaTest, AsyncEventsRouteToTheOwningFabricOnly) {
  start_server();
  VerbsOptions o2;
  o2.device = device_;
  auto f2 = VerbsCmFabric::open(o2);
  ASSERT_TRUE(f2);
  VerbsCmFabric& client2 = **f2;
  Endpoint* c1 = dial();
  auto e2r = client2.connect(server->peer());
  ASSERT_TRUE(e2r);
  Endpoint* e2 = *e2r;
  ASSERT_NE(c1, nullptr);
  ASSERT_NE(server->wait_accepted(1), nullptr);
  Endpoint* s2 = server->wait_accepted(2);
  ASSERT_NE(s2, nullptr);
  auto server_state = [&](Endpoint* e) { return server->call([e] { return e->state(); }); };
  std::vector<Completion> v(8);
  auto saw_cq_error = [&](Fabric& f) {
    bool seen = false;
    for (int i = 0; i < 3; ++i) {
      const std::size_t n = f.poll(v);
      for (std::size_t k = 0; k < n; ++k) seen = seen || v[k].op == CompletionOp::CqError;
    }
    return seen;
  };

  // QP error on c1's QP: only client's endpoint fails.
  ASSERT_TRUE(client->inject_async_event_for_test(AsyncEventKind::QpFatal, c1));
  client->poll(v);
  EXPECT_EQ(c1->state(), EpState::Error);
  EXPECT_FALSE(saw_cq_error(client2));
  EXPECT_EQ(e2->state(), EpState::Ready) << "a QP event of another fabric must not fail this one";
  EXPECT_EQ(server_state(s2), EpState::Ready);

  // The same QP event fed in through a different fabric's inject (`client`, not e2's owner)
  // finds the QP's owner anyway (routing is by QP in the shared table).
  ASSERT_TRUE(client->inject_async_event_for_test(AsyncEventKind::QpFatal, e2));
  client->poll(v);
  client2.poll(v);
  EXPECT_EQ(e2->state(), EpState::Error);
  auto e3r = client2.connect(server->peer());  // fresh witness endpoint on client2
  ASSERT_TRUE(e3r);
  Endpoint* e3 = *e3r;
  Endpoint* s3 = server->wait_accepted(3);
  ASSERT_NE(s3, nullptr);

  // CQ error on `client`: only that fabric breaks and reports CqError.
  ASSERT_TRUE(client->inject_async_event_for_test(AsyncEventKind::CqErr));
  EXPECT_TRUE(saw_cq_error(*client));
  EXPECT_FALSE(saw_cq_error(client2));
  EXPECT_EQ(e3->state(), EpState::Ready) << "a CQ_ERR of another fabric must not fail this one";

  // Port error on another port: ignored by everyone.
  ASSERT_TRUE(client->inject_async_event_for_test(AsyncEventKind::PortErr, nullptr, 2));
  client2.poll(v);
  EXPECT_EQ(e3->state(), EpState::Ready);
  EXPECT_EQ(server_state(s3), EpState::Ready);

  // Port error on our port: broadcast to every fabric on the device, injected via `client`.
  ASSERT_TRUE(client->inject_async_event_for_test(AsyncEventKind::PortErr, nullptr, 1));
  client2.poll(v);
  EXPECT_EQ(e3->state(), EpState::Error) << "the port error reaches the other client fabric";
  EXPECT_TRUE(wait_until([&] { return server_state(s3) == EpState::Error; }))
      << "the port error reaches the server fabric through the shared dispatcher";
}

// N03: one listener places connections by ticket: different class and PD per connection.
TEST_P(RdmaTest, AdmitChoosesClassAndPdPerConnection) {
  make_server();
  auto pa = server->fab->alloc_pd();
  auto pb = server->fab->alloc_pd();
  ASSERT_TRUE(pa);
  ASSERT_TRUE(pb);
  ListenParams lp;
  lp.admit = [&](std::span<const std::byte> t) -> Expected<Admission> {
    if (t.size() == 1 && t[0] == std::byte{1}) return Admission{EpClass::Fetch, *pa};
    if (t.size() == 1 && t[0] == std::byte{2}) return Admission{EpClass::Control, *pb};
    return Error{ErrorCode::AccessDenied, "unknown ticket"};
  };
  start_server(lp);
  Buf in_a(4096), in_b(4096), sink(4096);
  fill(in_b.span(), 11);
  auto ra = server->call([&] { return server->fab->reg(in_a.span(), Access::RemoteRead, *pa); });
  auto rb = server->call([&] { return server->fab->reg(in_b.span(), Access::RemoteRead, *pb); });
  ASSERT_TRUE(ra);
  ASSERT_TRUE(rb);
  auto sk = client->reg(sink.span(), Access::LocalWrite);
  ASSERT_TRUE(sk);

  ConnParams fetch;
  fetch.cls = EpClass::Fetch;
  fetch.ticket_len = 1;
  fetch.ticket[0] = std::byte{1};
  ConnParams control;
  control.cls = EpClass::Control;
  control.ticket_len = 1;
  control.ticket[0] = std::byte{2};
  Endpoint* cf = dial(fetch);
  Endpoint* cc = dial(control);
  ASSERT_NE(cf, nullptr);
  ASSERT_NE(cc, nullptr);
  Endpoint* sf = server->wait_accepted(1);
  Endpoint* sc = server->wait_accepted(2);
  ASSERT_NE(sf, nullptr);
  ASSERT_NE(sc, nullptr);
  // Layouts match per connection: 2 receives for fetch, the full depth for control.
  EXPECT_EQ(server->call([&] { return server->fab->endpoint_recv_slots(sf); }), 2u);
  EXPECT_EQ(server->call([&] { return server->fab->endpoint_recv_slots(sc); }), server_options.recv_slots);
  EXPECT_EQ(client->endpoint_recv_slots(cf), 2u);  // N09: fetch posts exactly two receives
  EXPECT_EQ(client->endpoint_recv_slots(cc), server_options.recv_slots);
  // The fetch connection lives in PD A, the control connection in PD B.
  RemoteRef good{rb->rkey, reinterpret_cast<std::uint64_t>(rb->addr), 4096};
  ASSERT_TRUE(cc->post_read(good, LocalRef{sk->lkey, sink.p, 4096}, 1));
  Completion ok;
  ASSERT_TRUE(wait_tag(1, ok));
  EXPECT_TRUE(ok.status);
  EXPECT_EQ(std::memcmp(sink.p, in_b.p, 4096), 0);
  RemoteRef in_pd_a{ra->rkey, reinterpret_cast<std::uint64_t>(ra->addr), 4096};
  ASSERT_TRUE(cf->post_read(in_pd_a, LocalRef{sk->lkey, sink.p, 4096}, 2));
  Completion fetch_ok;
  ASSERT_TRUE(wait_tag(2, fetch_ok));
  EXPECT_TRUE(fetch_ok.status) << (fetch_ok.status ? "" : fetch_ok.status.error().context);
  ASSERT_TRUE(cc->post_read(in_pd_a, LocalRef{sk->lkey, sink.p, 4096}, 3));
  Completion denied;
  ASSERT_TRUE(wait_tag(3, denied));
  EXPECT_FALSE(denied.status) << "the control endpoint is in PD B and must not reach PD A memory";
}

// N04: no AdmitFn and no explicit opt-out means no listener.
TEST_P(RdmaTest, ListenRequiresAdmitUnlessOptedOut) {
  auto ip = client->device_ipv4();
  ASSERT_TRUE(ip);
  ListenParams lp;
  lp.addr = RailAddr{*ip, 0};
  auto s = client->listen([](Endpoint*) {}, lp);
  ASSERT_FALSE(s);
  EXPECT_EQ(s.error().code, ErrorCode::InvalidArgument);
  lp.allow_unauthenticated_for_test = true;
  EXPECT_TRUE(client->listen([](Endpoint*) {}, lp));
}

// N04: cq_depth beyond the device limit is refused at open.
TEST_P(RdmaTest, CqDepthAboveDeviceMaxIsRefused) {
  VerbsOptions o;
  o.device = device_;
  o.cq_depth = client->nic_caps().max_cqe + 1;
  auto f = VerbsCmFabric::open(o);
  ASSERT_FALSE(f);
  EXPECT_EQ(f.error().code, ErrorCode::InvalidArgument);
}

// N09/Q13: a forged protocol tag in the accept is refused by the active side at ESTABLISHED.
TEST_P(RdmaTest, ForgedAcceptTagIsRefusedByActiveSide) {
  server_options.advertise_accept_protocol_for_test =
      iwarp() ? NicProtocol::RoCE : NicProtocol::IWarp;
  start_server();
  auto e = client->connect(server->peer());
  ASSERT_FALSE(e);
  EXPECT_EQ(e.error().code, ErrorCode::Unsupported);
  EXPECT_EQ(client->endpoint_count(), 0u);
}

// N06/N09: the passive side's CQ budget refuses with a code the client maps to
// ResourceExhausted, and the half-built passive endpoint is reaped.
TEST_P(RdmaTest, PassiveBudgetRefusalIsResourceExhaustedAndReaped) {
  server_options.cq_depth = 200;  // one QP of sq 128 + 16 recvs fits, two do not
  start_server();
  Endpoint* first = dial();
  ASSERT_NE(first, nullptr);
  ASSERT_NE(server->wait_accepted(1), nullptr);
  auto second = client->connect(server->peer());
  ASSERT_FALSE(second);
  EXPECT_EQ(second.error().code, ErrorCode::ResourceExhausted);
  EXPECT_TRUE(wait_until([&] { return server->call([&] { return server->fab->endpoint_count(); }) == 1u; }))
      << "the failed passive endpoint must be reaped";
  EXPECT_EQ(first->state(), EpState::Ready);
}

// N04: the pending-accept cap refuses further requests while earlier ones are mid-handshake.
TEST_P(RdmaTest, PendingAcceptCapRefuses) {
  hold = true;
  server_options.hold_established_for_test = &hold;
  ListenParams lp;
  lp.max_pending_accepts = 1;
  lp.accept_timeout = std::chrono::seconds(120);
  start_server(lp);
  Endpoint* c1 = dial();
  ASSERT_NE(c1, nullptr);  // established on the client; the server holds it in Accepting
  auto c2 = client->connect(server->peer());
  ASSERT_FALSE(c2);
  EXPECT_EQ(c2.error().code, ErrorCode::ResourceExhausted);
  hold = false;
  EXPECT_NE(server->wait_accepted(1), nullptr);
}

// ---- round 3: dispatcher fatal paths, zombie grace, accept timeout, private_data ----

// DeviceFatal injected through one fabric reaches every fabric on the device.
TEST_P(RdmaTest, DeviceFatalBroadcastsToEveryFabric) {
  start_server();
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  Endpoint* s = server->wait_accepted();
  ASSERT_NE(s, nullptr);
  ASSERT_TRUE(client->inject_async_event_for_test(AsyncEventKind::DeviceFatal));
  std::vector<Completion> v(8);
  client->poll(v);
  EXPECT_EQ(c->state(), EpState::Error);
  EXPECT_TRUE(wait_until([&] { return server->call([s] { return s->state(); }) == EpState::Error; }))
      << "DeviceFatal reaches the server fabric through the shared dispatcher";
}

// R02/R07: the dispatcher thread exiting on a fatal async-fd condition (here the test hook,
// the same exit path as POLLERR/POLLHUP) broadcasts DeviceFatal to every fabric on the device.
TEST_P(RdmaTest, DispatcherFatalExitFailsEveryFabric) {
  start_server();
  Endpoint* c = dial();
  ASSERT_NE(c, nullptr);
  Endpoint* s = server->wait_accepted();
  ASSERT_NE(s, nullptr);
  client->kill_async_dispatcher_for_test();
  std::vector<Completion> v(8);
  EXPECT_TRUE(wait_until([&] {
    client->poll(v);
    return c->state() == EpState::Error;
  }));
  EXPECT_TRUE(wait_until([&] { return server->call([s] { return s->state(); }) == EpState::Error; }));
}

// R03: a second thread injects events while a fabric on the same device is destroyed. The
// dispatcher's routing table must never reach the dying fabric (clean under asan and tsan).
TEST_P(RdmaTest, DestroyWhileInjecting) {
  start_server();
  ASSERT_NE(dial(), nullptr);
  ASSERT_NE(server->wait_accepted(), nullptr);
  std::atomic<bool> started{false}, done{false};
  std::atomic<std::uint64_t> injected{0};
  std::thread injector([&] {
    while (!done) {
      static_cast<void>(client->inject_async_event_for_test(AsyncEventKind::PortErr, nullptr, 2));
      static_cast<void>(client->inject_async_event_for_test(AsyncEventKind::DeviceFatal));
      ++injected;
      started = true;
    }
  });
  while (!started) std::this_thread::yield();
  server.reset();  // stops the server thread, then destroys its fabric mid-injection
  const std::uint64_t at_reset = injected.load();
  while (injected.load() < at_reset + 100) std::this_thread::yield();
  done = true;
  injector.join();
  std::vector<Completion> v(8);
  client->poll(v);  // the client fabric still works and drains what was pushed to it
  EXPECT_EQ(client->endpoint_count(), 1u);
}

// R02: a destroyed QP's CQE reservation is returned on the Clock grace period, not after a
// number of polls, and reclaim_cq (inside connect) never expires it early.
TEST_P(RdmaTest, ZombieReservationExpiresOnClockGrace) {
  start_server();
  FakeClock clk(/*frozen=*/true);
  VerbsOptions o;
  o.device = device_;
  o.clock = &clk;
  o.cq_depth = 200;  // one QP (sq 128 + 16 recvs = 144) fits, two do not
  o.drop_zombie_flushes_for_test = true;  // behave like a provider that never flushes
  auto f = VerbsCmFabric::open(o);
  ASSERT_TRUE(f) << f.error().context;
  auto& fab = **f;
  auto e = fab.connect(server->peer());
  ASSERT_TRUE(e) << e.error().context;
  const std::uint32_t one_qp = fab.cq_reserved();
  ASSERT_GT(one_qp, 0u);
  ASSERT_TRUE(fab.release(*e));
  std::vector<Completion> v(16);
  for (int i = 0; i < 50; ++i) fab.poll(v);  // zero busy budget: returns at once
  EXPECT_EQ(fab.cq_reserved(), one_qp) << "50 empty polls must not expire the reservation";
  auto refused = fab.connect(server->peer());
  ASSERT_FALSE(refused);
  EXPECT_EQ(refused.error().code, ErrorCode::ResourceExhausted) << "reclaim_cq must not force-expire";
  clk.advance(o.zombie_grace - Nanos{1});
  fab.poll(v);
  EXPECT_EQ(fab.cq_reserved(), one_qp);
  clk.advance(Nanos{1});
  fab.poll(v);
  EXPECT_EQ(fab.cq_reserved(), 0u) << "grace passed and the CQ drained: reservation returned";
  auto again = fab.connect(server->peer());
  EXPECT_TRUE(again) << (again ? "" : again.error().context);
}

// Accept timeout on the server's Clock: a passive endpoint whose ESTABLISHED never arrives
// (held by the hook) is dropped once the clock passes accept_timeout, and never announced.
TEST_P(RdmaTest, AcceptTimeoutFollowsClock) {
  hold = true;
  server_options.hold_established_for_test = &hold;
  server_options.clock = &server_clock;
  ListenParams lp;
  lp.accept_timeout = std::chrono::seconds(60);  // real time never gets there in this test
  start_server(lp);
  ASSERT_NE(dial(), nullptr);
  auto count = [&] { return server->call([&] { return server->fab->endpoint_count(); }); };
  EXPECT_EQ(count(), 1u);
  server_clock.advance(std::chrono::seconds(61));
  EXPECT_TRUE(wait_until([&] { return count() == 0u; })) << "the held accept must time out";
  hold = false;
  EXPECT_EQ(server->wait_accepted(1, std::chrono::milliseconds(200)), nullptr) << "never announced";
}

// R06: private_data decoding refuses every malformed or foreign layout.
TEST_P(RdmaTest, DecodePrivateRejectsMalformed) {
  using namespace protocol;
  auto bytes = [](std::initializer_list<unsigned> l) {
    std::vector<std::byte> b;
    for (unsigned x : l) b.push_back(static_cast<std::byte>(x));
    return b;
  };
  // Round trip at the maximum ticket: 53 B, inside the 56 B RoCE budget.
  std::array<std::byte, kMaxTicketBytes> t{};
  fill(t, 3);
  std::byte buf[kPrivHeader + kMaxTicketBytes];
  const std::size_t n = encode_private(Protocol::RoCE, Depth{4, 5}, t, buf);
  ASSERT_EQ(n, kPrivHeader + kMaxTicketBytes);
  ASSERT_LE(n, 56u);
  auto ok = decode_private({buf, n});
  ASSERT_TRUE(ok);
  EXPECT_EQ(ok->protocol, Protocol::RoCE);
  EXPECT_EQ(ok->depth.ird, 4);
  EXPECT_EQ(ok->depth.ord, 5);
  EXPECT_EQ(std::memcmp(ok->ticket.data(), t.data(), t.size()), 0);
  // RoCE delivers a zero-padded field: trailing padding is fine.
  std::vector<std::byte> padded(buf, buf + kPrivHeader);
  padded[1] = std::byte{0};
  padded.resize(56);
  EXPECT_TRUE(decode_private(padded));

  auto code = [](const std::vector<std::byte>& b) { return decode_private(b).error().code; };
  EXPECT_EQ(code({}), ErrorCode::Corrupt);
  EXPECT_EQ(code(bytes({kPrivVersion, 0, 1})), ErrorCode::Corrupt);  // shorter than the header
  std::vector<std::byte> too_long = bytes({kPrivVersion, 49, 1, 0, 0});
  too_long.resize(kPrivHeader + 49);
  EXPECT_EQ(code(too_long), ErrorCode::Corrupt);  // ticket length > kMaxTicketBytes
  std::vector<std::byte> truncated = bytes({kPrivVersion, 10, 1, 0, 0});
  truncated.resize(kPrivHeader + 5);
  EXPECT_EQ(code(truncated), ErrorCode::Corrupt);  // n + header > size
  EXPECT_EQ(code(bytes({0x82, 0, 1, 0, 0})), ErrorCode::Unsupported);   // newer version
  EXPECT_EQ(code(bytes({20, 1, 4, 4, 0, 0})), ErrorCode::Unsupported);  // old unversioned layout
  EXPECT_EQ(reject_error(kRejectVersion).code, ErrorCode::Unsupported);
}

// ---- RL1: several listeners on one device (one per rail address) and fabric health --------------------------------

namespace {
// Every IPv4 address on the netdev the device is bound to (sysfs gid_attrs -> getifaddrs).
std::vector<std::string> device_ipv4s(const std::string& device) {
  std::vector<std::string> out;
  std::ifstream in("/sys/class/infiniband/" + device + "/ports/1/gid_attrs/ndevs/0");
  std::string nd;
  if (!std::getline(in, nd)) return out;
  ifaddrs* list = nullptr;
  if (getifaddrs(&list) != 0) return out;
  for (ifaddrs* a = list; a != nullptr; a = a->ifa_next) {
    if (a->ifa_addr == nullptr || a->ifa_addr->sa_family != AF_INET || nd != a->ifa_name) continue;
    char buf[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &reinterpret_cast<const sockaddr_in*>(a->ifa_addr)->sin_addr, buf, sizeof buf) != nullptr)
      out.push_back(buf);
  }
  freeifaddrs(list);
  return out;
}
}  // namespace

TEST_P(RdmaTest, TwoListenersOnOneDeviceRouteByAddress) {
  const auto ips = device_ipv4s(device_);
  if (ips.size() < 2) GTEST_SKIP() << device_ << " has one IPv4 address; the lab RDMA setup script adds the second";
  struct Seen {
    std::atomic<int> admit{0}, accept{0};
  };
  auto a = std::make_shared<Seen>(), b = std::make_shared<Seen>();
  make_server();
  // Listener 0 through the helper (ips[0], ephemeral port); listener 1 on the same port, other address.
  ListenParams la;
  la.admit = [a](std::span<const std::byte>) -> Expected<Admission> {
    ++a->admit;
    return Admission{EpClass::Control, PdId{}};
  };
  // The helper binds device_ipv4(); make sure that is ips[0]-or-whatever it found, and use the other one for B.
  auto first = server->fab->device_ipv4();
  ASSERT_TRUE(first);
  std::string second;
  for (const auto& ip : ips)
    if (ip != *first) second = ip;
  ASSERT_FALSE(second.empty());
  auto s0 = server->start(la);
  ASSERT_TRUE(s0) << s0.error().context;
  const std::uint16_t port = server->fab->listen_port();
  ASSERT_NE(port, 0);
  ListenParams lb;
  lb.addr = RailAddr{second, port};
  lb.admit = [b](std::span<const std::byte>) -> Expected<Admission> {
    ++b->admit;
    return Admission{EpClass::Control, PdId{}};
  };
  auto st = server->call([&] { return server->fab->listen([b](Endpoint*) { ++b->accept; }, lb); });
  ASSERT_TRUE(st) << st.error().context;

  ConnParams cp;
  cp.ticket_len = 20;
  auto ea = client->connect(Peer{0, RailAddr{*first, port}}, cp);
  ASSERT_TRUE(ea) << ea.error().context;
  EXPECT_EQ(a->admit.load(), 1);
  EXPECT_EQ(b->admit.load(), 0);
  auto eb = client->connect(Peer{0, RailAddr{second, port}}, cp);
  ASSERT_TRUE(eb) << eb.error().context;
  EXPECT_EQ(a->admit.load(), 1);  // each connect reached only its own listener's admit hook
  EXPECT_EQ(b->admit.load(), 1);
  for (int i = 0; i < 200 && b->accept.load() == 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
  EXPECT_EQ(b->accept.load(), 1);
  EXPECT_NE(server->wait_accepted(1), nullptr);  // listener 0's AcceptFn (the helper's) ran for the first connect

  // Health: port ACTIVE, both listeners alive, nothing fatal.
  auto h = server->call([&] { return server->fab->health(); });
  EXPECT_EQ(h.port_state, "ACTIVE");
  EXPECT_FALSE(h.fatal_recent);
  ASSERT_EQ(h.listener_ok.size(), 2u);
  EXPECT_TRUE(h.listener_ok[0]);
  EXPECT_TRUE(h.listener_ok[1]);
  // A port error event sets the fatal latch (10 s window) and fails the endpoints; the port itself still reads ACTIVE.
  ASSERT_TRUE(server->call([&] { return server->fab->inject_async_event_for_test(AsyncEventKind::PortErr, nullptr, 1); }));
  bool latched = false;
  for (int i = 0; i < 200 && !latched; ++i) {
    latched = server->call([&] { return server->fab->health(); }).fatal_recent;
    if (!latched) std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  EXPECT_TRUE(latched);
}

// Soft-iWARP mmap-key sentinel: siw hands out ring mmap keys first-fit from
// page 0 of the context, and libsiw refuses any ring whose key is 0x90000 (page 144). 400 one-page (16-entry) CQs on
// the fabric's own librdmacm context fill every hole up past page 144, so without the fabric's ballast CQ pinning pages
// 0-256 one of them starts on page 144 and is refused (measured: #144 on an empty context; with run #266's QP floor
// and no ballast, ~#112 after the fabric's 4096-entry CQ). Then the device's last fabric goes and comes back (the
// ballast is destroyed and re-created first), and a loopback connect with the configured (small, unfloored) rings works.
// Provider-independent: small rings next to an open fabric must always work.
namespace {
int small_cq_churn(const std::string& device, int count) {  // 0 = all created; else the 1-based index that failed
  int n = 0;
  ibv_context** list = rdma_get_devices(&n);
  if (list == nullptr) return -1;
  ibv_context* ctx = nullptr;
  for (int i = 0; i < n; ++i) {
    if (device == ibv_get_device_name(list[i]->device)) ctx = list[i];
  }
  int failed_at = ctx == nullptr ? -1 : 0;
  std::vector<ibv_cq*> cqs;
  for (int i = 0; ctx != nullptr && i < count && failed_at == 0; ++i) {
    ibv_cq* cq = ibv_create_cq(ctx, 16, nullptr, nullptr, 0);
    if (cq == nullptr) {
      failed_at = i + 1;
    } else {
      cqs.push_back(cq);
    }
  }
  for (ibv_cq* cq : cqs) ibv_destroy_cq(cq);
  rdma_free_devices(list);
  return failed_at;
}
}  // namespace

TEST_P(RdmaTest, SmallRingsNextToAFabricNeverHitTheSiwKeySentinel) {
  EXPECT_EQ(small_cq_churn(device_, 400), 0) << "a 16-entry CQ was refused next to an open fabric on " << device_;
  client.reset();  // the device's last fabric: its ballast (siw) goes with it
  VerbsOptions o;
  o.device = device_;
  auto f = VerbsCmFabric::open(o);
  ASSERT_TRUE(f) << f.error().context;
  client = std::move(*f);
  EXPECT_EQ(small_cq_churn(device_, 400), 0) << "after the fabric was re-opened, on " << device_;
  start_server();
  Endpoint* e = dial();
  ASSERT_NE(e, nullptr);
  EXPECT_EQ(small_cq_churn(device_, 400), 0) << "with a connected endpoint pair, on " << device_;
}
