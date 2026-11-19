// SPDX-License-Identifier: Apache-2.0
#include "server/runtime/metrics_http.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string_view>

#include "server/node_config.h"
#include "server/runtime/net_util.h"
#include "util/clock.h"

namespace miracache::server {
namespace {

// Sends under a 2 s total budget (M02): the socket is non-blocking and poll()s in 50 ms slices, so a
// scraper that never reads can neither pin a worker for long nor delay stop().
void send_all(int fd, const std::string& s, const std::atomic<bool>& stop) {
  RealClock clock;
  const Nanos deadline = clock.now() + std::chrono::milliseconds(MetricsHttp::kSendTimeoutMs);
  std::size_t off = 0;
  while (off < s.size()) {
    int flags = 0;
#ifdef MSG_NOSIGNAL
    flags = MSG_NOSIGNAL;
#endif
    ssize_t n = ::send(fd, s.data() + off, s.size() - off, flags);
    if (n > 0) {
      off += static_cast<std::size_t>(n);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) return;
    if (stop.load() || clock.now() >= deadline) return;
    pollfd p{fd, POLLOUT, 0};
    (void)net::poll_retry(&p, 1, 50);
  }
}

std::string response(int code, const char* reason, const std::string& body, const char* ctype = "text/plain; charset=utf-8") {
  std::string r = "HTTP/1.1 " + std::to_string(code) + ' ' + reason + "\r\nContent-Type: " + ctype +
                  "\r\nContent-Length: " + std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
  return r;
}

}  // namespace

Expected<std::unique_ptr<MetricsHttp>> MetricsHttp::start(const std::string& listen, telemetry::Registry& reg) {
  if (listen.empty()) return std::unique_ptr<MetricsHttp>();
  const auto colon = listen.rfind(':');
  if (colon == std::string::npos) return Error{ErrorCode::InvalidArgument, "telemetry: listen wants host:port"};
  const std::string host = listen.substr(0, colon);
  auto parsed = parse_port(std::string_view(listen).substr(colon + 1), /*allow_zero=*/true);  // M03: no atoi
  if (!parsed) return Error{ErrorCode::InvalidArgument, "telemetry: bad port"};
  const int port = *parsed;
  addrinfo hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  addrinfo* res = nullptr;
  if (::getaddrinfo(host.empty() ? nullptr : host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
    return Error{ErrorCode::InvalidArgument, "telemetry: cannot resolve listen address"};
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    ::freeaddrinfo(res);
    return Error{ErrorCode::ResourceExhausted, "telemetry: socket"};
  }
  int one = 1;
  (void)::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
  net::set_nonblock_cloexec(fd);
  const bool bound = ::bind(fd, res->ai_addr, res->ai_addrlen) == 0 && ::listen(fd, 16) == 0;
  ::freeaddrinfo(res);
  if (!bound) {
    ::close(fd);
    return Error{ErrorCode::Busy, "telemetry: cannot bind or listen"};
  }
  sockaddr_in sa{};
  socklen_t sl = sizeof sa;
  (void)::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &sl);
  std::unique_ptr<MetricsHttp> m(new MetricsHttp(fd, ntohs(sa.sin_port), reg));
  m->acceptor_ = std::thread([p = m.get()] { p->accept_loop(); });  // lint:server-runtime
  return m;
}

MetricsHttp::~MetricsHttp() { stop(); }

void MetricsHttp::stop() {
  if (stop_.exchange(true)) return;
  if (acceptor_.joinable()) acceptor_.join();
  reap(true);
  if (lfd_ >= 0) ::close(lfd_);
  lfd_ = -1;
}

void MetricsHttp::reap(bool all) {
  for (auto it = workers_.begin(); it != workers_.end();) {
    if (all || (*it)->done.load()) {
      ::pthread_join((*it)->t, nullptr);  // workers_ only holds started threads
      it = workers_.erase(it);
    } else {
      ++it;
    }
  }
}

void MetricsHttp::accept_loop() {
  net::block_all_signals();
  while (!stop_.load()) {
    reap(false);
    pollfd p{lfd_, POLLIN, 0};
    if (net::poll_retry(&p, 1, 50) <= 0) continue;
    int fd = ::accept(lfd_, nullptr, nullptr);
    if (fd < 0) continue;
    net::set_nonblock_cloexec(fd);
    net::set_send_timeout(fd, kSendTimeoutMs);
    if (workers_.size() >= kMaxConcurrent) {  // all slots busy
      send_all(fd, response(503, "Service Unavailable", "too many concurrent scrapes\n"), stop_);
      ::close(fd);
      continue;
    }
    auto w = std::make_unique<Worker>();
    Worker* raw = w.get();
    if (!net::spawn(raw->t, [this, raw, fd] {
          net::block_all_signals();
          serve(fd);
          ::close(fd);
          raw->done.store(true);
        })) {  // no thread available: drop the scrape, count it, keep accepting
      reg_.counter("miracache_metrics_conn_dropped_total", "Scrape connections dropped because no thread could be started.").inc();
      ::close(fd);
      continue;
    }
    workers_.push_back(std::move(w));
  }
}

void MetricsHttp::serve(int fd) {
  RealClock clock;
  const Nanos deadline = clock.now() + std::chrono::milliseconds(kReadTimeoutMs);
  std::string req;
  char buf[1024];
  while (req.find("\r\n\r\n") == std::string::npos) {
    if (req.size() >= kMaxRequestBytes) {
      send_all(fd, response(431, "Request Header Fields Too Large", "request too large\n"), stop_);
      return;
    }
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - clock.now()).count();
    if (stop_.load()) return;
    if (left <= 0) {
      send_all(fd, response(408, "Request Timeout", "read timeout\n"), stop_);
      return;
    }
    pollfd p{fd, POLLIN, 0};
    const int pr = net::poll_retry(&p, 1, static_cast<int>(std::min<long long>(left, 50)));  // sliced: stop() stays prompt
    if (pr < 0) return;
    if (pr == 0) continue;
    ssize_t n = ::recv(fd, buf, std::min(sizeof buf, kMaxRequestBytes - req.size()), 0);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
    if (n <= 0) return;
    req.append(buf, static_cast<std::size_t>(n));
  }
  const auto eol = req.find("\r\n");
  const std::string line = req.substr(0, eol);
  const auto sp1 = line.find(' ');
  const auto sp2 = sp1 == std::string::npos ? sp1 : line.find(' ', sp1 + 1);
  if (sp2 == std::string::npos) {
    send_all(fd, response(400, "Bad Request", "bad request line\n"), stop_);
    return;
  }
  const std::string method = line.substr(0, sp1);
  std::string path = line.substr(sp1 + 1, sp2 - sp1 - 1);
  if (const auto q = path.find('?'); q != std::string::npos) path.resize(q);
  if (path != "/metrics") {
    send_all(fd, response(404, "Not Found", "not found\n"), stop_);
    return;
  }
  if (method != "GET") {
    send_all(fd, response(405, "Method Not Allowed", "GET only\n"), stop_);
    return;
  }
  std::string body;
  body.reserve(16 * 1024);
  reg_.write_prometheus(body);
  send_all(fd, response(200, "OK", body, "text/plain; version=0.0.4; charset=utf-8"), stop_);
}

}  // namespace miracache::server
