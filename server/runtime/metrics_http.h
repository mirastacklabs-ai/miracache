// SPDX-License-Identifier: Apache-2.0
// /metrics HTTP endpoint. Threads allowed here only (lint marker `// lint:server-runtime`).
//
// GET /metrics only (404 for any other path, 405 for other methods), plain HTTP/1.1 with
// `Connection: close`. One accept thread plus at most 4 scrape threads; the data path never
// runs here. Request size cap 8 KiB (431), read timeout 2 s (408), a 5th concurrent scrape
// gets 503. The registry is read through Registry::write_prometheus (thread-safe).
#pragma once

#include <pthread.h>

#include <atomic>
#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <thread>  // lint:server-runtime

#include "telemetry/metrics.h"
#include "util/expected.h"

namespace miracache::server {

class MetricsHttp {
 public:
  static constexpr std::size_t kMaxRequestBytes = 8 * 1024;
  static constexpr int kReadTimeoutMs = 2000;
  static constexpr int kSendTimeoutMs = 2000;  // SO_SNDTIMEO and the send budget
  static constexpr std::size_t kMaxConcurrent = 4;

  // `listen` is "host:port" (IPv4; port 0 picks a free port). Empty = disabled: returns nullptr.
  static Expected<std::unique_ptr<MetricsHttp>> start(const std::string& listen, telemetry::Registry& reg);
  ~MetricsHttp();
  MetricsHttp(const MetricsHttp&) = delete;
  MetricsHttp& operator=(const MetricsHttp&) = delete;

  std::uint16_t port() const { return port_; }
  void stop();

 private:
  struct Worker {
    pthread_t t{};  // started by net::spawn
    std::atomic<bool> done{false};
  };
  MetricsHttp(int fd, std::uint16_t port, telemetry::Registry& reg) : lfd_(fd), port_(port), reg_(reg) {}
  void accept_loop();
  void serve(int fd);
  void reap(bool all);

  int lfd_;
  std::uint16_t port_;
  telemetry::Registry& reg_;
  std::atomic<bool> stop_{false};
  std::thread acceptor_;  // lint:server-runtime
  std::list<std::unique_ptr<Worker>> workers_;  // touched by the accept thread only (and stop())
};

}  // namespace miracache::server
