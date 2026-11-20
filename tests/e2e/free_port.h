// SPDX-License-Identifier: Apache-2.0
// Port choice for the e2e harnesses (memnode listen / admin / metrics ports).
//
// Flake (d), "admin: cannot bind or listen" at startup or at a restart on the same port. Root cause: the old
// free_port() bound port 0, read the number and closed the socket, so every port it returned
//   (1) came from the kernel's EPHEMERAL range (ip_local_port_range, 32768-60999), the same range the
//       kernel hands to the client side of every outgoing connection (the client's admin mTLS polls and
//       reconnect attempts, curl-style metrics scrapes, rxe CM traffic), and
//   (2) was not remembered: two calls can return the same number, and a number is free only until another
//       connect() autobinds it.
// During the SIGKILL dwell the client keeps connecting to the DEAD node's admin port on loopback. A port in
// the ephemeral range that nothing listens on is a legal source port for such a connect: the kernel can
// give a connect() to 127.0.0.1:P the source port P (TCP self-connect), or hand P to another outgoing
// connection. The restarted memnode then fails bind(P) with EADDRINUSE and the admin API reports
// "cannot bind or listen".
//
// Fix: pick ports BELOW the ephemeral range (never an autobind source port), remember every port handed out
// by this process so none repeats, and probe each candidate with a real bind. The harness decides the
// ports once, before any node starts, and reuses them for restarts.
#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <random>
#include <set>

namespace miracache {

// Lowest port of the kernel's ephemeral range (32768 if unreadable).
inline std::uint16_t ephemeral_low() {
  unsigned lo = 32768, hi = 60999;
  if (FILE* f = std::fopen("/proc/sys/net/ipv4/ip_local_port_range", "r")) {
    if (std::fscanf(f, "%u %u", &lo, &hi) != 2) lo = 32768;
    std::fclose(f);
  }
  return static_cast<std::uint16_t>(lo > 65535 ? 32768 : lo);
}

inline bool port_is_free(std::uint16_t port) {
  int fd = ::socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) return false;
  sockaddr_in sa{};
  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  sa.sin_port = htons(port);
  const bool ok = ::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa) == 0;
  ::close(fd);
  return ok;
}

// A port outside the ephemeral range, distinct from every earlier return value of this process, that was
// free on loopback when probed. Falls back to the ephemeral range only if the low range is exhausted.
inline std::uint16_t free_port() {
  static std::set<std::uint16_t> handed_out;
  static std::mt19937 rng{std::random_device{}()};
  const std::uint16_t eph = ephemeral_low();
  const std::uint16_t lo = 10000;
  if (eph > lo + 1000) {
    for (int tries = 0; tries < 2000; ++tries) {
      const auto p = static_cast<std::uint16_t>(lo + rng() % (eph - lo));
      if (handed_out.count(p) || !port_is_free(p)) continue;
      handed_out.insert(p);
      return p;
    }
  }
  for (int tries = 0; tries < 2000; ++tries) {  // no usable low range: the old way, but never a repeat
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    (void)::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof sa);
    socklen_t l = sizeof sa;
    (void)::getsockname(fd, reinterpret_cast<sockaddr*>(&sa), &l);
    ::close(fd);
    const std::uint16_t p = ntohs(sa.sin_port);
    if (handed_out.insert(p).second) return p;
  }
  return 0;
}

}  // namespace miracache
