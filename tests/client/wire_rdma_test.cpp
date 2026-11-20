// SPDX-License-Identifier: Apache-2.0
// Live RDMA (label `rdma`): an in-process mira-memnode equivalent (server::Server over a
// VerbsCmFabric on its own thread, lab ticket file) and the production Client::open (config
// TOML: nodes rails, lab.ticket_file, fabric.device) doing store -> fetch -> invalidate over
// real verbs/rdma_cm. Skips cleanly when the device is missing.
#include <gtest/gtest.h>
#include <unistd.h>

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "fabric/verbs_cm/verbs_cm_fabric.h"
#ifdef MIRA_WITH_SHARED
#include "miracache/miracache.h"
#endif
#include "server/server.h"
#include "src/client.h"
#include "src/wire_port.h"
#include "util/clock.h"
#include "util/log.h"
#include "util/nonce_source.h"
#include "util/random.h"

namespace miracache {
namespace {

using Bytes = std::vector<std::byte>;

std::vector<std::string> devices() {
  const char* env = std::getenv("MIRACACHE_RDMA_DEVICES");
  std::stringstream ss(env != nullptr ? env : "rxe0,siw0");
  std::vector<std::string> out;
  for (std::string d; std::getline(ss, d, ',');)
    if (!d.empty()) out.push_back(d);
  return out;
}

class TestKeys final : public KeySource {
 public:
  Expected<Dek> dek_for(std::span<const std::byte> raw) const override {
    std::array<std::byte, 32> k;
    mix(raw, 0x11, k.data());
    return Dek(std::span<const std::byte, 32>(k));
  }
  Expected<KeyHash> key_hash(std::span<const std::byte> raw) const override {
    KeyHash h;
    std::array<std::byte, 32> k;
    mix(raw, 0x22, k.data());
    std::memcpy(h.b, k.data(), 32);
    return h;
  }

 private:
  static void mix(std::span<const std::byte> raw, int tag, std::byte* out) {
    for (int i = 0; i < 32; ++i) {
      std::uint64_t x = 1469598103934665603ull ^ static_cast<std::uint64_t>(7 * 131 + tag + i);
      for (auto b : raw) x = (x ^ static_cast<std::uint64_t>(b)) * 1099511628211ull;
      x ^= x >> 29;
      x *= 0x9E3779B97F4A7C15ull;
      out[i] = static_cast<std::byte>(x >> 56);
    }
  }
};

class NoProvider final : public ScopeProvider {
 public:
  Expected<ScopeKeys> derive(const RequestMeta&) const override { return Error{ErrorCode::Unsupported, "n/a"}; }
};

// The memory node: Server on a VerbsCmFabric, one thread, lab tickets written to a file.
class Node {
 public:
  // `draining`: begin_drain before serving (r7 R02: every new connect is refused as Busy).
  Node(const std::string& device, const std::string& ticket_file, bool draining = false) : ticket_file_(ticket_file) {
    fabric::VerbsOptions vo;
    vo.device = device;
    auto f = fabric::VerbsCmFabric::open(vo);
    if (!f) {
      err = f.error();
      return;
    }
    fab_ = std::move(*f);
    auto ip = fab_->device_ipv4();
    if (!ip) {
      err = ip.error();
      return;
    }
    ip_ = *ip;
    server::ServerConfig sc;
    auto& c = sc.store;
    c.node_id = 1;  // HELLO_ACK node_id must match the client config nodes[].id (= 1)
    c.segment_bytes = 4u << 20;
    c.run_bytes = 256u << 10;
    c.min_block_bytes = 4096;
    c.n_segments = 4;
    c.gen_chunk = 1000;
    c.principal_default.max_scopes = 8;
    c.principal_default.max_bytes = 8u << 20;
    c.principal_default.idle_ttl = std::chrono::seconds(100000);
    sc.rails = {fabric::RailAddr{ip_, 0}};
    sc.lab_identity = "lab";
    sc.lab_principal = 5;
    sc.wire_protocol = fab_->nic_caps().protocol == fabric::NicProtocol::IWarp ? 2 : 1;
    auto s = server::Server::create(sc, *fab_, clock_, rng_, exec_);
    if (!s) {
      err = s.error();
      return;
    }
    srv_ = std::move(*s);
    if (auto st = srv_->start(); !st) {
      err = st.error();
      return;
    }
    write_tickets();
    if (draining) srv_->begin_drain(proto::GoawayReason::Shutdown, 60000);  // before the store thread starts
    th_ = std::thread([this] {
      while (!stop_) srv_->run_once(fabric::PollBudget{std::chrono::microseconds(200)});
    });
  }
  ~Node() {
    stop_ = true;
    if (th_.joinable()) th_.join();
  }
  std::string rail() const { return ip_ + ":" + std::to_string(fab_->listen_port()); }
  fabric::RailAddr rail_addr() const { return fabric::RailAddr{ip_, fab_->listen_port()}; }
  server::Server& server() { return *srv_; }
  std::optional<Error> err;

 private:
  void write_tickets() {
    std::ofstream f(ticket_file_);
    static const char* names[] = {"control", "fetch", "ingest"};
    for (std::uint8_t cls = 0; cls < 3; ++cls) {
      auto t = srv_->issue_ticket("lab", static_cast<fabric::EpClass>(cls), 0, 4);
      for (const auto& tk : *t) {
        f << names[cls] << " 0 ";
        char b[3];
        for (auto x : tk.id) {
          std::snprintf(b, sizeof b, "%02x", x);
          f << b;
        }
        f << '\n';
      }
    }
  }
  std::string ticket_file_, ip_;
  RealClock clock_;
  RealRandom rng_;
  InlineExecutor exec_;
  std::unique_ptr<fabric::VerbsCmFabric> fab_;
  std::unique_ptr<server::Server> srv_;
  std::atomic<bool> stop_{false};
  std::thread th_;
};

class WireRdma : public ::testing::TestWithParam<std::string> {};
INSTANTIATE_TEST_SUITE_P(Device, WireRdma, ::testing::ValuesIn(devices()),
                         [](const ::testing::TestParamInfo<std::string>& i) { return i.param; });

Completion wait_for(Client& c, Ticket t) {
  std::array<Completion, 4> comp;
  for (int i = 0; i < 20000; ++i) {
    std::size_t n = c.poll(comp);
    for (std::size_t k = 0; k < n; ++k)
      if (comp[k].ticket == t) return std::move(comp[k]);
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  ADD_FAILURE() << "no completion";
  return Completion{};
}

TEST_P(WireRdma, ClientOpenStoreFetchInvalidate) {
  char tmpl[] = "/tmp/mira-wire-ticketsXXXXXX";
  const int fd = ::mkstemp(tmpl);
  ASSERT_GE(fd, 0);
  ::close(fd);
  const std::string tickets = tmpl;
  Node node(GetParam(), tickets);
  if (node.err) {
    if (node.err->code == ErrorCode::NotFound) GTEST_SKIP() << "no usable RDMA device: " << node.err->context;
    FAIL() << node.err->context;
  }
  std::ostringstream toml;
  toml << "[scope]\nsecret_file = \"unused\"\n[[nodes]]\nrails = [\"" << node.rail() << "\"]\n"
       << "[fabric]\ndevice = \"" << GetParam() << "\"\n[lab]\nstatic_membership = true\nticket_file = \"" << tickets
       << "\"\n";
  auto cfg = load_config(toml.str());
  ASSERT_TRUE(cfg) << cfg.error().context;
  NoProvider prov;
  auto cl = Client::open(*cfg, prov);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;

  ScopeKeys sk;
  ScopeId s{};
  s.b[0] = 1;
  s.b[31] = 0x5c;
  sk.scopes = {s};
  sk.keys = std::make_shared<TestKeys>();
  sk.kver = 1;
  const char* names[] = {"k0", "k1", "k2"};
  std::vector<Bytes> raw, data, out;
  std::vector<KeyRef> refs;
  const std::size_t sizes[] = {1, 65536, 3 * 65536 + 777};
  for (int i = 0; i < 3; ++i) {
    raw.emplace_back(reinterpret_cast<const std::byte*>(names[i]), reinterpret_cast<const std::byte*>(names[i]) + 2);
    Bytes d(sizes[i]);
    for (std::size_t j = 0; j < d.size(); ++j) d[j] = static_cast<std::byte>((j * 31 + static_cast<std::size_t>(i) * 7 + 3) & 0xff);
    data.push_back(std::move(d));
    out.emplace_back(sizes[i], std::byte{0xAA});
  }
  for (int i = 0; i < 3; ++i) {
    KeyRef r;
    r.raw = raw[static_cast<std::size_t>(i)];
    if (i > 0) r.parent_raw = raw[static_cast<std::size_t>(i) - 1];
    r.chain_pos = static_cast<std::uint64_t>(i);
    refs.push_back(r);
  }
  std::vector<BufRef> pbufs, fbufs;
  for (auto& d : data) pbufs.push_back({std::span<std::byte>(d)});
  for (auto& o : out) fbufs.push_back({std::span<std::byte>(o)});

  auto sc = wait_for(c, c.store(sk, 0, refs, pbufs, std::chrono::seconds(10)));
  ASSERT_EQ(sc.status.size(), 3u);
  for (auto st : sc.status) EXPECT_EQ(st, KeyStatus::Committed);
  auto fc = wait_for(c, c.fetch(sk, 0, refs, fbufs, std::chrono::seconds(10)));
  ASSERT_EQ(fc.status.size(), 3u);
  for (std::size_t i = 0; i < 3; ++i) {
    EXPECT_EQ(fc.status[i], KeyStatus::Hit) << i;
    EXPECT_EQ(out[i], data[i]) << i;
  }
  // Re-put is idempotent; a miss on an unknown key zeroes the buffer.
  auto again = wait_for(c, c.store(sk, 0, refs, pbufs, std::chrono::seconds(10)));
  for (auto st : again.status) EXPECT_EQ(st, KeyStatus::Skipped);
  std::string nk = "nokey";
  Bytes nraw(reinterpret_cast<const std::byte*>(nk.data()), reinterpret_cast<const std::byte*>(nk.data()) + nk.size());
  KeyRef nr;
  nr.raw = nraw;
  Bytes nout(500, std::byte{0xAA});
  std::vector<BufRef> nb{{std::span<std::byte>(nout)}};
  auto mc = wait_for(c, c.fetch(sk, 0, std::span<const KeyRef>(&nr, 1), nb, std::chrono::seconds(10)));
  ASSERT_EQ(mc.status.size(), 1u);
  EXPECT_EQ(mc.status[0], KeyStatus::Miss);
  for (auto b : nout) EXPECT_EQ(b, std::byte{0});
  ASSERT_NE(c.wire_port(), nullptr);
  EXPECT_TRUE(c.wire_port()->healthy());
  EXPECT_TRUE(c.wire_port()->stats(0));
  c.shutdown();
  ::unlink(tmpl);
}

// r7 R01/R02: on verbs a draining node's admit refusal comes back as Busy (CM reject byte kRejectBusy),
// not AccessDenied, so one connect attempt draws ONE ticket, not ticket_attempts (4). Contrast: a forged
// ticket on a serving node is AccessDenied and the client does try ticket_attempts tickets.
TEST_P(WireRdma, DrainingRefusalIsBusyAndDrawsOneTicket) {
  char tmpl[] = "/tmp/mira-wire-ticketsXXXXXX";
  const int fd = ::mkstemp(tmpl);
  ASSERT_GE(fd, 0);
  ::close(fd);
  const std::string tickets = tmpl;
  for (const bool draining : {true, false}) {
    SCOPED_TRACE(draining ? "draining node, real tickets" : "serving node, forged tickets");
    Node node(GetParam(), tickets, draining);
    if (node.err) {
      ::unlink(tmpl);
      if (node.err->code == ErrorCode::NotFound) GTEST_SKIP() << "no usable RDMA device: " << node.err->context;
      FAIL() << node.err->context;
    }
    fabric::VerbsOptions vo;
    vo.device = GetParam();
    auto fab = fabric::VerbsCmFabric::open(vo);
    ASSERT_TRUE(fab) << fab.error().context;
    RealClock clock;
    OsNonceSource nonce;
    WireOptions wo;
    wo.node = 1;
    wo.rail = node.rail_addr();
    wo.wire_proto = (*fab)->nic_caps().protocol == fabric::NicProtocol::IWarp ? 2 : 1;
    ASSERT_EQ(wo.ticket_attempts, 4u);
    int drawn = 0;
    auto lab = lab_ticket_file_source(tickets);
    wo.tickets = [&](fabric::EpClass cls) -> Expected<proto::Ticket> {
      ++drawn;
      auto t = lab(cls);
      if (t && !draining) t->id[0] ^= 0xff;  // forged: unknown to the node
      return t;
    };
    {
      WirePort port(**fab, clock, nonce, wo);
      auto h = port.hello();
      ASSERT_FALSE(h);
      if (draining) {
        EXPECT_EQ(h.error().code, ErrorCode::Busy) << h.error().context;
        EXPECT_EQ(drawn, 1) << "a draining refusal must draw one ticket, not ticket_attempts";
      } else {
        EXPECT_EQ(h.error().code, ErrorCode::AccessDenied) << h.error().context;
        EXPECT_EQ(drawn, 4);
      }
      std::fprintf(stderr, "r7-R02 %s: code=%s tickets_drawn=%d\n", draining ? "draining" : "forged",
                   to_string(h.error().code), drawn);
    }
  }
  ::unlink(tmpl);
}

// r8 N01: the host is up but no memory node listens on the port (it was stopped): the kernel answers the
// connect with a REJ carrying zeroed private_data (RoCE) or ECONNREFUSED (iWARP), i.e. reject byte
// kRejectNone. That is LinkDown and draws ONE ticket, not ticket_attempts (4) as AccessDenied would.
TEST_P(WireRdma, NoListenerIsLinkDownAndDrawsOneTicket) {
  char tmpl[] = "/tmp/mira-wire-ticketsXXXXXX";
  const int fd = ::mkstemp(tmpl);
  ASSERT_GE(fd, 0);
  ::close(fd);
  const std::string tickets = tmpl;
  fabric::RailAddr gone;
  {
    Node node(GetParam(), tickets);
    if (node.err) {
      ::unlink(tmpl);
      if (node.err->code == ErrorCode::NotFound) GTEST_SKIP() << "no usable RDMA device: " << node.err->context;
      FAIL() << node.err->context;
    }
    gone = node.rail_addr();
  }  // the node (server, listener, fabric) is gone; the device and its address stay
  fabric::VerbsOptions vo;
  vo.device = GetParam();
  auto fab = fabric::VerbsCmFabric::open(vo);
  ASSERT_TRUE(fab) << fab.error().context;
  RealClock clock;
  OsNonceSource nonce;
  WireOptions wo;
  wo.node = 1;
  wo.rail = gone;
  wo.wire_proto = (*fab)->nic_caps().protocol == fabric::NicProtocol::IWarp ? 2 : 1;
  ASSERT_EQ(wo.ticket_attempts, 4u);
  int drawn = 0;
  auto lab = lab_ticket_file_source(tickets);
  wo.tickets = [&](fabric::EpClass cls) -> Expected<proto::Ticket> {
    ++drawn;
    return lab(cls);
  };
  {
    WirePort port(**fab, clock, nonce, wo);
    auto h = port.hello();
    ASSERT_FALSE(h);
    EXPECT_EQ(h.error().code, ErrorCode::LinkDown) << h.error().context;
    EXPECT_EQ(drawn, 1) << "no listener must draw one ticket, not ticket_attempts";
    std::fprintf(stderr, "r8-N01 no listener: code=%s tickets_drawn=%d\n", to_string(h.error().code), drawn);
  }
  ::unlink(tmpl);
}

// The log lines written while it lives (log::set_sink_fd to a temporary file).
struct LogCapture {
  LogCapture() : f(std::tmpfile()) {
    if (f) log::set_sink_fd(fileno(f));
  }
  ~LogCapture() {
    log::set_sink_fd(2);
    if (f) std::fclose(f);
  }
  std::string text() const {
    std::string s;
    if (!f) return s;
    char buf[4096];
    for (off_t off = 0;;) {
      const ssize_t k = pread(fileno(f), buf, sizeof buf, off);
      if (k <= 0) break;
      s.append(buf, static_cast<std::size_t>(k));
      off += k;
    }
    return s;
  }
  std::FILE* f;
};

// Review s9 K03/K04 over real verbs: HELLO_ACK carries the node's run_bytes (TLV 0x0003); the start-up check names the
// node; an oversized block is refused by the client before any PUT_BEGIN (the node counts nothing), with one WARN and
// miracache_client_put_refused_total{reason="too_large"}; a block that fits still commits.
TEST_P(WireRdma, HelloAckMaxBlockAndOversizedPutRefusedLocally) {
  char tmpl[] = "/tmp/mira-wire-maxblkXXXXXX";
  const int fd = ::mkstemp(tmpl);
  ASSERT_GE(fd, 0);
  ::close(fd);
  const std::string tickets = tmpl;
  Node node(GetParam(), tickets);
  if (node.err) {
    if (node.err->code == ErrorCode::NotFound) GTEST_SKIP() << "no usable RDMA device: " << node.err->context;
    FAIL() << node.err->context;
  }
  std::ostringstream toml;
  toml << "[scope]\nsecret_file = \"unused\"\n[[nodes]]\nrails = [\"" << node.rail() << "\"]\n"
       << "[fabric]\ndevice = \"" << GetParam() << "\"\n[lab]\nstatic_membership = true\nticket_file = \"" << tickets
       << "\"\n";
  auto cfg = load_config(toml.str());
  ASSERT_TRUE(cfg) << cfg.error().context;
  NoProvider prov;
  auto cl = Client::open(*cfg, prov);
  ASSERT_TRUE(cl) << cl.error().context;
  Client& c = **cl;
  ASSERT_NE(c.wire_port(), nullptr);
  EXPECT_EQ(c.wire_port()->max_stored_block(), 256u << 10) << "HELLO_ACK TLV 0x0003 = the node's run_bytes";
  std::size_t checked = 0;
  EXPECT_EQ(c.block_size_problem(64u << 10, &checked), "");
  EXPECT_EQ(checked, 1u);
  const std::string why = c.block_size_problem(256u << 10, &checked);
  std::printf("block_size_problem: %s\n", why.c_str());
  EXPECT_NE(why.find("memory node 1 "), std::string::npos) << why;
  EXPECT_NE(why.find(node.rail()), std::string::npos) << why;
  EXPECT_NE(why.find("(hostname " + log::hostname() + ", "), std::string::npos) << why;  // F5: from HELLO_ACK, no admin source
  EXPECT_EQ(why.find("hostname unknown"), std::string::npos) << why;
  EXPECT_NE(why.find("store.run_bytes = 2097152"), std::string::npos) << why;  // pow2 >= 4 x (256 KiB + 128)

  ScopeKeys sk;
  ScopeId s{};
  s.b[0] = 2;
  s.b[31] = 0x5c;
  sk.scopes = {s};
  sk.keys = std::make_shared<TestKeys>();
  sk.kver = 1;
  Bytes raw0{std::byte{'b'}, std::byte{'0'}}, raw1{std::byte{'f'}, std::byte{'1'}};
  KeyRef big;
  big.raw = raw0;
  Bytes data(256u << 10, std::byte{0x5a});
  std::vector<BufRef> bufs{{std::span<std::byte>(data)}};
  std::string text;
  {
    LogCapture cap;
    auto st = wait_for(c, c.store(sk, 0, std::span<const KeyRef>(&big, 1), bufs, std::chrono::seconds(10)));
    ASSERT_EQ(st.status.size(), 1u);
    EXPECT_EQ(st.status[0], KeyStatus::Aborted);
    text = cap.text();
  }
  std::printf("client log: %s", text.c_str());
  EXPECT_NE(text.find("PUT_BEGIN refused locally"), std::string::npos) << text;
  EXPECT_NE(text.find("node_id=1"), std::string::npos) << text;
  EXPECT_NE(text.find("max_stored_block_bytes=262144"), std::string::npos) << text;
  EXPECT_EQ(c.wire_port()->put_refusals(), 1u);
  const std::string m = c.metrics_text();
  // F5: static mode: no series of the node says hostname="unknown" or "", node_info carries the node's own hostname.
  EXPECT_EQ(m.find("hostname=\"unknown\""), std::string::npos) << m;
  EXPECT_EQ(m.find("hostname=\"\""), std::string::npos) << m;
  EXPECT_NE(m.find("miracache_client_node_info{"), std::string::npos) << m;
  EXPECT_NE(m.find("hostname=\"" + log::hostname() + "\""), std::string::npos) << m;
  EXPECT_NE(m.find("miracache_client_put_refused_total{"), std::string::npos) << m;
  EXPECT_NE(m.find("reason=\"too_large\"} 1"), std::string::npos) << m;
  std::string srv;
  node.server().metrics().write_prometheus(srv);
  EXPECT_EQ(srv.find("miracache_put_too_large_total"), std::string::npos) << "no PUT_BEGIN reached the node";
  KeyRef ok;
  ok.raw = raw1;
  Bytes small(128u << 10, std::byte{0x33});
  std::vector<BufRef> sb{{std::span<std::byte>(small)}};
  auto st2 = wait_for(c, c.store(sk, 0, std::span<const KeyRef>(&ok, 1), sb, std::chrono::seconds(10)));
  ASSERT_EQ(st2.status.size(), 1u);
  EXPECT_EQ(st2.status[0], KeyStatus::Committed);
  c.shutdown();
  ::unlink(tmpl);
}

#ifdef MIRA_WITH_SHARED
// The C ABI entry point against a live node: mira_client_open succeeds (no longer Unsupported).
TEST_P(WireRdma, CAbiOpenAgainstLabConfig) {
  char tmpl[] = "/tmp/mira-wire-abiXXXXXX";
  const int fd = ::mkstemp(tmpl);
  ASSERT_GE(fd, 0);
  ::close(fd);
  const std::string tickets = tmpl;
  char stmpl[] = "/tmp/mira-wire-secretXXXXXX";
  const int sfd = ::mkstemp(stmpl);  // mode 0600
  ASSERT_GE(sfd, 0);
  const std::string secret = "1 = " + std::string(64, 'a') + "\ncurrent = 1\n";
  ASSERT_EQ(::write(sfd, secret.data(), secret.size()), static_cast<ssize_t>(secret.size()));
  ::close(sfd);
  {
    Node node(GetParam(), tickets);
    if (node.err) {
      if (node.err->code == ErrorCode::NotFound) GTEST_SKIP() << "no usable RDMA device: " << node.err->context;
      FAIL() << node.err->context;
    }
    std::ostringstream toml;
    toml << "[scope]\nsecret_file = \"" << stmpl << "\"\n[[nodes]]\nrails = [\"" << node.rail() << "\"]\n"
         << "[fabric]\ndevice = \"" << GetParam() << "\"\n[lab]\nstatic_membership = true\nticket_file = \"" << tickets
         << "\"\n";
    mira_client* c = nullptr;
    const int rc = mira_client_open(toml.str().c_str(), nullptr, &c);
    EXPECT_EQ(rc, MIRA_OK) << mira_last_error();
    EXPECT_NE(c, nullptr);
    if (c != nullptr) {  // ABI 1.2 (review s9 K03): the start-up block size check against the live node
      std::size_t n = 0;
      EXPECT_EQ(mira_check_block_size(c, 64u << 10, &n), MIRA_OK) << mira_last_error();
      EXPECT_EQ(n, 1u);
      EXPECT_EQ(mira_check_block_size(c, 256u << 10, &n), MIRA_E_CONFIG);
      EXPECT_NE(std::string(mira_last_error()).find("store.run_bytes"), std::string::npos) << mira_last_error();
      // F5: static/lab mode has no admin hostname; the node named itself in HELLO_ACK, so the error names the real host.
      EXPECT_NE(std::string(mira_last_error()).find("(hostname " + log::hostname() + ","), std::string::npos) << mira_last_error();
      EXPECT_EQ(std::string(mira_last_error()).find("hostname unknown"), std::string::npos) << mira_last_error();
    }
    mira_client_close(c);
  }
  ::unlink(tmpl);
  ::unlink(stmpl);
}
#endif

}  // namespace
}  // namespace miracache
