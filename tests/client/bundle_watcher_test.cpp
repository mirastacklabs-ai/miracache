// SPDX-License-Identifier: Apache-2.0
// The client bundle watcher against fake HTTPS (TLS 1.3 + mTLS) memory-node admin endpoints.
// Certs come from deploy/examples/lab-certs.sh into a temp dir. Bundles are signed with the test signer.
#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "control/bundle_test_util.h"
#include "control/floor_state.h"
#include "miracache/config.h"
#include "src/bundle_watcher.h"
#include "util/clock.h"

namespace miracache {
namespace {

namespace tu = control::testutil;
using std::chrono::milliseconds;

struct Certs {
  std::string root, pki;
  Certs() {
    char t[] = "/tmp/mira-bw-XXXXXX";
    EXPECT_NE(::mkdtemp(t), nullptr);
    root = t;
    pki = root + "/pki";
    EXPECT_EQ(std::system((std::string("bash ") + MIRACACHE_LAB_CERTS_SH + " " + pki + " --nodes 1,2,3 --clients 1 >/dev/null").c_str()), 0);
  }
  ~Certs() { std::filesystem::remove_all(root); }
};
const Certs& certs() {
  static const Certs c;
  return c;
}

std::string temp_dir(const char* tag) {
  std::string t = std::string("/tmp/mira-bw-") + tag + "-XXXXXX";
  std::vector<char> b(t.begin(), t.end());
  b.push_back('\0');
  EXPECT_NE(::mkdtemp(b.data()), nullptr);
  return b.data();
}

// A fake memory-node admin listener: serves /v1/bundle over mTLS. One thread, one connection at a time.
class FakeNode {
 public:
  explicit FakeNode(int idx) {
    const auto& c = certs();
    ctx_ = SSL_CTX_new(TLS_server_method());
    SSL_CTX_set_min_proto_version(ctx_, TLS1_3_VERSION);
    EXPECT_EQ(SSL_CTX_use_certificate_chain_file(ctx_, (c.pki + "/node-" + std::to_string(idx) + ".pem").c_str()), 1);
    EXPECT_EQ(SSL_CTX_use_PrivateKey_file(ctx_, (c.pki + "/node-" + std::to_string(idx) + ".key").c_str(), SSL_FILETYPE_PEM), 1);
    EXPECT_EQ(SSL_CTX_load_verify_locations(ctx_, (c.pki + "/ca.pem").c_str(), nullptr), 1);
    SSL_CTX_set_verify(ctx_, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    lfd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    EXPECT_EQ(::bind(lfd_, reinterpret_cast<sockaddr*>(&a), sizeof a), 0);
    EXPECT_EQ(::listen(lfd_, 16), 0);
    socklen_t l = sizeof a;
    ::getsockname(lfd_, reinterpret_cast<sockaddr*>(&a), &l);
    port_ = ntohs(a.sin_port);
    th_ = std::thread([this] { loop(); });
  }
  ~FakeNode() {
    stop_ = true;
    th_.join();
    ::close(lfd_);
    SSL_CTX_free(ctx_);
  }
  std::string admin() const { return "127.0.0.1:" + std::to_string(port_); }

  // Serve this envelope (generation `gen` for the 304 rule).
  void serve(std::uint64_t gen, std::string envelope) {
    std::lock_guard lk(mu_);
    gen_ = gen;
    env_ = std::move(envelope);
  }
  void fail_posts(bool f) { fail_posts_ = f; }
  void conflict_posts(bool f) { conflict_posts_ = f; }  // POST answers 409 generation_lower
  void truncate(bool f) { truncate_ = f; }              // GET answers a short body and drops the connection
  int gets() const { return gets_; }
  int posts() const { return posts_; }
  std::vector<std::string> targets() {
    std::lock_guard lk(mu_);
    return targets_;
  }
  std::string last_post() {
    std::lock_guard lk(mu_);
    return last_post_;
  }

 private:
  void loop() {
    while (!stop_) {
      pollfd p{lfd_, POLLIN, 0};
      if (::poll(&p, 1, 20) <= 0) continue;
      int fd = ::accept(lfd_, nullptr, nullptr);
      if (fd < 0) continue;
      handle(fd);
      ::close(fd);
    }
  }
  void handle(int fd) {
    timeval tv{5, 0};  // a stuck peer cannot wedge the single-threaded fake
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    SSL* ssl = SSL_new(ctx_);
    SSL_set_fd(ssl, fd);
    if (SSL_accept(ssl) != 1) {
      ERR_clear_error();
      SSL_free(ssl);
      return;
    }
    std::string req;
    char buf[4096];
    std::size_t hdr_end = std::string::npos, want = 0;
    for (;;) {
      const int n = SSL_read(ssl, buf, sizeof buf);
      if (n <= 0) break;
      req.append(buf, static_cast<std::size_t>(n));
      if (hdr_end == std::string::npos) {
        hdr_end = req.find("\r\n\r\n");
        if (hdr_end != std::string::npos) {
          const auto cl = req.find("Content-Length: ");
          want = hdr_end + 4 + (cl == std::string::npos ? 0 : std::strtoul(req.c_str() + cl + 16, nullptr, 10));
        }
      }
      if (hdr_end != std::string::npos && req.size() >= want) break;
    }
    const auto sp1 = req.find(' '), sp2 = req.find(' ', sp1 + 1);
    const std::string method = req.substr(0, sp1), target = req.substr(sp1 + 1, sp2 - sp1 - 1);
    std::string status = "404 Not Found", body;
    {
      std::lock_guard lk(mu_);
      targets_.push_back(method + " " + target);
      if (method == "GET" && target.rfind("/v1/bundle", 0) == 0 && !env_.empty()) {
        const auto q = target.find("after=");
        const std::uint64_t after = q == std::string::npos ? 0 : std::strtoull(target.c_str() + q + 6, nullptr, 10);
        ++gets_;
        if (after != 0 && gen_ <= after) {
          status = "304 Not Modified";
        } else {
          status = "200 OK";
          body = env_;
        }
      } else if (method == "GET") {
        ++gets_;
      } else if (method == "POST" && target == "/v1/bundle") {
        ++posts_;
        last_post_ = req.substr(hdr_end + 4);
        status = conflict_posts_ ? "409 Conflict" : fail_posts_ ? "500 Internal Server Error" : "200 OK";
        if (conflict_posts_) body = "{\"reason\":\"generation_lower\"}";
      }
    }
    const bool trunc = truncate_ && !body.empty();
    const std::string resp = "HTTP/1.1 " + status + "\r\nContent-Length: " + std::to_string(body.size() + (trunc ? 100 : 0)) +
                             "\r\nConnection: close\r\n\r\n" + body;
    for (std::size_t off = 0; off < resp.size();) {
      const int n = SSL_write(ssl, resp.data() + off, static_cast<int>(resp.size() - off));
      if (n <= 0) break;
      off += static_cast<std::size_t>(n);
    }
    if (!trunc) SSL_shutdown(ssl);
    SSL_free(ssl);
  }

  SSL_CTX* ctx_ = nullptr;
  int lfd_ = -1;
  unsigned port_ = 0;
  std::thread th_;
  std::atomic<bool> stop_{false};
  std::mutex mu_;
  std::uint64_t gen_ = 0;
  std::string env_;
  std::vector<std::string> targets_;
  std::string last_post_;
  std::atomic<int> gets_{0}, posts_{0};
  std::atomic<bool> fail_posts_{false}, conflict_posts_{false}, truncate_{false};
};

// A bundle at `gen` whose two nodes' admin addresses are the fakes (so the bundle's own list works).
std::string bundle_for(std::uint64_t gen, const std::string& admin0, const std::string& admin1) {
  std::string body = tu::body_toml(gen, 7, 6);
  auto rep = [&](const std::string& from, const std::string& to) {
    for (auto p = body.find(from); p != std::string::npos; p = body.find(from, p + to.size())) body.replace(p, from.size(), to);
  };
  rep("10.0.0.10:9465", admin0);
  rep("10.0.0.11:9465", admin1);
  return tu::make_envelope(tu::sec_toml(5), body);
}

struct Env {
  std::string state, trust;
  Env() : state(temp_dir("state")), trust(temp_dir("trust") + "/trust.toml") {
    std::ofstream(trust) << tu::trust_toml();
  }
  ~Env() {
    std::filesystem::remove_all(state);
    std::filesystem::remove_all(std::filesystem::path(trust).parent_path());
  }
  BundleWatcherOptions opts(std::vector<std::string> eps, const std::string& state_dir = {}) const {
    const auto& c = certs();
    BundleWatcherOptions o;
    o.endpoints = std::move(eps);
    o.trust_keys = trust;
    o.state_dir = state_dir.empty() ? state : state_dir;
    o.cert = c.pki + "/client-1.pem";
    o.key = c.pki + "/client-1.key";
    o.ca = c.pki + "/ca.pem";
    o.io_timeout_ms = 3000;
    return o;
  }
};

template <class P>
bool wait_for(P p, int ms = 30000) {
  for (int i = 0; i < ms / 5; ++i) {
    if (p()) return true;
    std::this_thread::sleep_for(milliseconds(5));
  }
  return p();
}

// Waits until `count()` stays unchanged for 1.5 s (longer than any gap inside a chase), at most 30 s; returns it.
// Slow machines (tsan, 2 CPUs) stretch the chase but cannot make this return early.
template <class C>
int settle(C count) {
  int last = count();
  for (int waited = 0; waited < 30000;) {
    std::this_thread::sleep_for(milliseconds(1500));
    waited += 1500;
    const int now = count();
    if (now == last) return now;
    last = now;
  }
  return last;
}

std::unique_ptr<BundleWatcher> make(const BundleWatcherOptions& o, const RealClock& clk) {
  auto w = BundleWatcher::create(o, clk);
  EXPECT_TRUE(w) << (w ? "" : w.error().context);
  return w ? std::move(*w) : nullptr;
}

RealClock clk;

TEST(BundleWatcher, AppliesThenNotModified) {
  Env e;
  FakeNode n0(1);
  n0.serve(5, bundle_for(5, n0.admin(), "127.0.0.1:1"));
  std::atomic<int> called{0};
  auto o = e.opts({n0.admin()});
  o.on_bundle = [&](MembershipSnapPtr s) {
    EXPECT_EQ(s->generation(), 5u);
    ++called;
  };
  auto w = make(o, clk);
  ASSERT_TRUE(w->poll_now());
  EXPECT_EQ(w->applied_generation(), 5u);
  ASSERT_TRUE(w->current());
  EXPECT_EQ(w->current()->view.body.epoch, 7u);
  EXPECT_EQ(called, 1);
  EXPECT_EQ(n0.targets().front(), "GET /v1/bundle");  // start-up: no `after`
  ASSERT_TRUE(w->poll_now());                          // now GET ?after=5 -> 304
  EXPECT_EQ(n0.targets().back(), "GET /v1/bundle?after=5");
  EXPECT_EQ(w->stats().not_modified, 1u);
  EXPECT_EQ(called, 1);
  auto fl = control::FloorState::open(e.state);
  ASSERT_TRUE(fl);
  auto f = fl->load();
  ASSERT_TRUE(f);
  EXPECT_EQ(f->generation, 5u);
}

TEST(BundleWatcher, TamperedBundleIsRejected) {
  Env e;
  FakeNode n0(1);
  std::string env = bundle_for(5, n0.admin(), "127.0.0.1:1");
  env[env.size() - 3] ^= 1;  // a body byte: the publish signature no longer verifies
  n0.serve(5, env);
  std::atomic<int> called{0};
  auto o = e.opts({n0.admin()});
  o.on_bundle = [&](MembershipSnapPtr) { ++called; };
  auto w = make(o, clk);
  EXPECT_FALSE(w->poll_now());
  EXPECT_EQ(w->applied_generation(), 0u);
  EXPECT_EQ(called, 0);
  const auto st = w->stats();
  EXPECT_EQ(st.rejected, 1u);
  EXPECT_EQ(st.rejected_by_reason[static_cast<std::size_t>(control::Reject::BadSignature)], 1u);
}

TEST(BundleWatcher, ReplayOfAnOlderBundleIsRejected) {
  Env e;
  FakeNode n0(1);
  n0.serve(6, bundle_for(6, n0.admin(), "127.0.0.1:1"));
  auto w = make(e.opts({n0.admin()}), clk);
  ASSERT_TRUE(w->poll_now());
  ASSERT_EQ(w->applied_generation(), 6u);
  // A node (or a man in the middle) replays a validly signed older bundle; the floor refuses it.
  FakeNode n1(2);
  n0.serve(1000, bundle_for(5, n0.admin(), "127.0.0.1:1"));  // generation 5, but claims to be newer
  EXPECT_FALSE(w->poll_now());
  EXPECT_EQ(w->applied_generation(), 6u);
  EXPECT_EQ(w->stats().rejected_by_reason[static_cast<std::size_t>(control::Reject::GenerationLower)], 1u);
}

TEST(BundleWatcher, TwoProcessesOnOneStateDirBothApply) {
  Env e;
  FakeNode n0(1);
  n0.serve(7, bundle_for(7, n0.admin(), "127.0.0.1:1"));
  auto a = make(e.opts({n0.admin()}), clk);
  ASSERT_TRUE(a->poll_now());
  ASSERT_EQ(a->applied_generation(), 7u);
  // The floor is now 7. A second process (and a restarted one) accepts the current generation.
  auto b = make(e.opts({n0.admin()}), clk);
  ASSERT_TRUE(b->poll_now());
  EXPECT_EQ(b->applied_generation(), 7u);
  EXPECT_EQ(b->current()->generation(), a->current()->generation());
}

TEST(BundleWatcher, OneStaleEndpointAtStartupDoesNotWin) {
  for (int order = 0; order < 2; ++order) {
    Env e;
    FakeNode stale(1), fresh(2);
    stale.serve(5, bundle_for(5, stale.admin(), fresh.admin()));
    fresh.serve(9, bundle_for(9, stale.admin(), fresh.admin()));
    auto w = make(e.opts(order ? std::vector<std::string>{fresh.admin(), stale.admin()}
                               : std::vector<std::string>{stale.admin(), fresh.admin()}),
                  clk);
    ASSERT_TRUE(w->poll_now());
    EXPECT_EQ(w->applied_generation(), 9u) << order;
    EXPECT_EQ(stale.gets(), 1);  // every endpoint was polled
    EXPECT_EQ(fresh.gets(), 1);
  }
}

TEST(BundleWatcher, WakeStormIsBounded) {
  Env e;
  FakeNode n0(1), n1(2);
  const std::string b5 = bundle_for(5, n0.admin(), n1.admin());
  n0.serve(5, b5);
  n1.serve(5, b5);
  auto o = e.opts({n0.admin(), n1.admin()});
  o.poll_ms = 600000;
  auto w = make(o, clk);
  ASSERT_TRUE(w->poll_now());
  const int before = n0.gets() + n1.gets();
  w->start();
  // 4 threads x 500 replies, all carrying generation 6 (which no endpoint has): one wake.
  std::vector<std::thread> ts;
  for (int t = 0; t < 4; ++t)
    ts.emplace_back([&] {
      for (int i = 0; i < 500; ++i) w->on_reply_generation(6, n0.admin());
    });
  for (auto& t : ts) t.join();
  EXPECT_EQ(w->stats().wakes, 1u);
  // The chase is one hinted fetch plus one cycle of the endpoints, spaced >= 200 ms, then it stops.
  ASSERT_TRUE(wait_for([&] { return n0.gets() + n1.gets() - before >= 3; }));
  const int after = settle([&] { return n0.gets() + n1.gets() - before; });  // the chase ends by itself
  EXPECT_LE(after, 6);
  EXPECT_EQ(w->applied_generation(), 5u);
  // A new value wakes again.
  w->on_reply_generation(7, "");
  EXPECT_EQ(w->stats().wakes, 2u);
  w->stop();
}

TEST(BundleWatcher, LaggingClientFetchesFromTheReplyingNodeFirst) {
  Env e;
  FakeNode n0(1), n1(2);
  const std::string b5 = bundle_for(5, n0.admin(), n1.admin());
  n0.serve(5, b5);
  n1.serve(5, b5);
  auto o = e.opts({n0.admin(), n1.admin()});
  o.poll_ms = 600000;
  auto w = make(o, clk);
  ASSERT_TRUE(w->poll_now());
  n1.serve(6, bundle_for(6, n0.admin(), n1.admin()));  // only n1 has generation 6
  const int n0_before = n0.gets();
  w->start();
  w->on_reply_generation(6, n1.admin());  // n1 replied with bundle_gen_lo = 6
  ASSERT_TRUE(wait_for([&] { return w->applied_generation() == 6; }));
  EXPECT_EQ(n0.gets(), n0_before);  // n0 (first in the round-robin) was never asked
  EXPECT_EQ(n1.targets().back(), "GET /v1/bundle?after=5");
  w->stop();
}

TEST(BundleWatcher, A304WhileBehindRotatesToTheNextEndpoint) {
  Env e;
  FakeNode n0(1), n1(2);
  const std::string b5 = bundle_for(5, n0.admin(), n1.admin());
  n0.serve(5, b5);
  n1.serve(5, b5);
  auto o = e.opts({n0.admin(), n1.admin()});
  o.poll_ms = 600000;
  auto w = make(o, clk);
  ASSERT_TRUE(w->poll_now());
  n1.serve(6, bundle_for(6, n0.admin(), n1.admin()));
  w->start();
  w->on_reply_generation(6, "");  // no hint: n0 answers 304, then the watcher rotates to n1
  ASSERT_TRUE(wait_for([&] { return w->applied_generation() == 6; }));
  EXPECT_GE(w->stats().not_modified, 1u);
  w->stop();
}

TEST(BundleWatcher, PushEnvelopeOncePerSuccessAndBacksOffOnFailure) {
  Env e;
  FakeNode n0(1), target(2);
  const std::string b5 = bundle_for(5, n0.admin(), target.admin());
  n0.serve(5, b5);
  auto w = make(e.opts({n0.admin()}), clk);
  EXPECT_FALSE(w->push_envelope(target.admin()));  // nothing applied yet
  ASSERT_TRUE(w->poll_now());
  ASSERT_TRUE(w->push_envelope(target.admin()));
  EXPECT_EQ(target.posts(), 1);
  EXPECT_EQ(target.last_post(), b5);  // the exact verified bytes
  ASSERT_TRUE(w->push_envelope(target.admin()));
  EXPECT_EQ(target.posts(), 1);  // once per success per (node, generation)

  FakeNode bad(3);
  bad.fail_posts(true);
  EXPECT_FALSE(w->push_envelope(bad.admin()));
  EXPECT_EQ(bad.posts(), 1);
  auto again = w->push_envelope(bad.admin());
  EXPECT_FALSE(again);
  EXPECT_EQ(bad.posts(), 1);  // backing off: no second POST
  EXPECT_EQ(again.error().code, ErrorCode::Busy);
}

TEST(BundleWatcher, UnreachableEndpointsBackOffAndRetry) {
  Env e;
  FakeNode n0(1);  // serves nothing yet: 404
  auto o = e.opts({n0.admin()});
  o.backoff_min_ms = 50;
  o.backoff_max_ms = 200;
  std::atomic<int> called{0};
  o.on_bundle = [&](MembershipSnapPtr) { ++called; };
  auto w = make(o, clk);
  // The failing steps are driven by hand (poll_now ignores the backoff gate): no timing involved.
  EXPECT_FALSE(w->poll_now());
  EXPECT_FALSE(w->poll_now());
  EXPECT_GE(w->stats().failed, 2u);
  EXPECT_EQ(w->applied_generation(), 0u);
  EXPECT_EQ(called, 0);
  // The endpoint returns; the thread's own retry (backoff <= 200 ms, spacing >= 200 ms) picks it up.
  n0.serve(5, bundle_for(5, n0.admin(), "127.0.0.1:1"));
  w->start();
  ASSERT_TRUE(wait_for([&] { return w->applied_generation() == 5; }));
  EXPECT_EQ(called, 1);
  w->stop();
}

TEST(BundleWatcher, PushToANodeThatIsAheadIsDoneAndWakesAFetchFromIt) {
  Env e;
  FakeNode n0(1), ahead(2);
  n0.serve(5, bundle_for(5, n0.admin(), ahead.admin()));
  ahead.serve(6, bundle_for(6, n0.admin(), ahead.admin()));
  ahead.conflict_posts(true);  // 409 generation_lower
  auto o = e.opts({n0.admin()});
  o.poll_ms = 600000;
  auto w = make(o, clk);
  ASSERT_TRUE(w->poll_now());
  ASSERT_EQ(w->applied_generation(), 5u);
  w->start();
  auto r = w->push_envelope(ahead.admin());
  ASSERT_TRUE(r);
  EXPECT_EQ(*r, BundleWatcher::PushOutcome::NodeAhead);
  EXPECT_EQ(ahead.posts(), 1);
  auto r2 = w->push_envelope(ahead.admin());  // no re-POST of up to 1 MiB
  ASSERT_TRUE(r2);
  EXPECT_EQ(*r2, BundleWatcher::PushOutcome::NodeAhead);
  EXPECT_EQ(ahead.posts(), 1);
  ASSERT_TRUE(wait_for([&] { return w->applied_generation() == 6; }));  // fetched from the node that is ahead
  w->stop();
  // A node that is merely not ready is an error, not NodeAhead.
  FakeNode bad(3);
  bad.fail_posts(true);
  auto r3 = w->push_envelope(bad.admin());
  EXPECT_FALSE(r3);
}

TEST(BundleWatcher, TruncatedResponseIsATransportErrorNotABadSignature) {
  Env e;
  FakeNode n0(1);
  n0.serve(5, bundle_for(5, n0.admin(), "127.0.0.1:1"));
  n0.truncate(true);
  auto w = make(e.opts({n0.admin()}), clk);
  EXPECT_FALSE(w->poll_now());
  const auto st = w->stats();
  EXPECT_EQ(st.rejected, 0u);  // never reached verification
  EXPECT_GE(st.failed, 1u);
  EXPECT_EQ(w->applied_generation(), 0u);
  n0.truncate(false);
  EXPECT_TRUE(w->poll_now());
  EXPECT_EQ(w->applied_generation(), 5u);
}

TEST(BundleWatcher, TwoWatchersRacingOnOneStateDir) {
  for (int iter = 0; iter < 5; ++iter) {
    Env e;
    FakeNode a_node(1), b_node(2);
    a_node.serve(7, bundle_for(7, a_node.admin(), b_node.admin()));
    b_node.serve(8, bundle_for(8, a_node.admin(), b_node.admin()));
    // Same generation from the same node: both must apply it.
    {
      auto a = make(e.opts({b_node.admin()}), clk);
      auto b = make(e.opts({b_node.admin()}), clk);
      std::atomic<bool> go{false};
      Status sa, sb;
      std::thread ta([&] { while (!go) {} sa = a->poll_now(); });
      std::thread tb([&] { while (!go) {} sb = b->poll_now(); });
      go = true;
      ta.join();
      tb.join();
      EXPECT_TRUE(sa);
      EXPECT_TRUE(sb);
      EXPECT_EQ(a->applied_generation(), 8u);
      EXPECT_EQ(b->applied_generation(), 8u);
    }
    // Different generations racing: the floor ends at the highest; the loser of a lost commit does not publish.
    Env e2;
    auto lo = make(e2.opts({a_node.admin()}), clk);
    auto hi = make(e2.opts({b_node.admin()}), clk);
    std::atomic<bool> go{false};
    std::thread tl([&] { while (!go) {} (void)lo->poll_now(); });
    std::thread th([&] { while (!go) {} (void)hi->poll_now(); });
    go = true;
    tl.join();
    th.join();
    EXPECT_EQ(hi->applied_generation(), 8u);
    EXPECT_TRUE(lo->applied_generation() == 0u || lo->applied_generation() == 7u);
    auto fl = control::FloorState::open(e2.state);
    ASSERT_TRUE(fl);
    auto f = fl->load();
    ASSERT_TRUE(f);
    EXPECT_EQ(f->generation, 8u);
  }
}

TEST(BundleWatcher, WakeStormWithTwoAlternatingGenerationsStaysBounded) {
  Env e;
  FakeNode n0(1), n1(2);
  const std::string b42 = bundle_for(42, n0.admin(), n1.admin());
  n0.serve(42, b42);
  n1.serve(42, b42);
  auto o = e.opts({n0.admin(), n1.admin()});
  o.poll_ms = 600000;
  auto w = make(o, clk);
  ASSERT_TRUE(w->poll_now());
  const int before = n0.gets() + n1.gets();
  w->start();
  std::vector<std::thread> ts;
  for (int t = 0; t < 2; ++t)
    ts.emplace_back([&] {
      for (int i = 0; i < 1000; ++i) w->on_reply_generation((i & 1) ? 43 : 44, n0.admin());
    });
  for (auto& t : ts) t.join();
  EXPECT_LE(w->stats().wakes, 2u);  // 43 or 44 first, then at most the other one once; never again
  const int after = settle([&] { return n0.gets() + n1.gets() - before; });
  EXPECT_LE(after, 8);
  w->stop();
}

TEST(ControlConfig, ParsesAndRejects) {
  const std::string base = "[scope]\nsecret_file = \"s\"\n[tls]\ncert=\"c\"\nkey=\"k\"\nca=\"a\"\n";
  const std::string ctl = "[control]\nendpoints = [\"10.0.0.1:9465\", \"10.0.0.2:9465\"]\ncontroller = \"10.0.0.9:9470\"\ntrust_keys = \"t\"\nstate_dir = \"d\"\n";
  auto ok = load_config(base + ctl);
  ASSERT_TRUE(ok) << ok.error().context;
  ASSERT_TRUE(ok->control);
  EXPECT_EQ(ok->control->endpoints.size(), 2u);
  EXPECT_EQ(ok->control->controller, "10.0.0.9:9470");
  EXPECT_TRUE(ok->nodes.empty());
  auto bad = [&](const std::string& t) { return !load_config(t); };
  EXPECT_TRUE(bad(base + ctl + "[[nodes]]\nrails=[\"1.1.1.1:1\"]\n"));       // [[nodes]] with [control]
  EXPECT_TRUE(bad(base + ctl + "[lab]\nstatic_membership = true\n"));         // lab flag with [control]
  EXPECT_TRUE(bad(base + ctl + "[placement]\nreplicas = 2\n"));               // local R in bundle mode
  EXPECT_TRUE(bad("[scope]\nsecret_file = \"s\"\n" + ctl));                   // no [tls]
  EXPECT_TRUE(bad(base + "[control]\nendpoints = []\ntrust_keys=\"t\"\nstate_dir=\"d\"\n"));
  EXPECT_TRUE(bad(base + "[control]\nendpoints = [\"nohostport\"]\ntrust_keys=\"t\"\nstate_dir=\"d\"\n"));
  EXPECT_TRUE(bad(base + "[control]\nendpoints = [\"a:1\"]\nstate_dir=\"d\"\n"));  // trust_keys missing
  EXPECT_TRUE(bad(base + "[control]\nendpoints = [\"a:1\"]\ntrust_keys=\"t\"\nstate_dir=\"d\"\nbogus=1\n"));
  // Lab static mode is unchanged.
  EXPECT_TRUE(load_config("[scope]\nsecret_file = \"s\"\n[lab]\nstatic_membership = true\n[[nodes]]\nrails=[\"1.1.1.1:1\"]\n"));
}

}  // namespace
}  // namespace miracache
