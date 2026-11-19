// SPDX-License-Identifier: Apache-2.0
// Small socket/thread helpers shared by the admin and metrics listeners.
#pragma once

#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <functional>
#include <utility>

namespace miracache::server::net {

// Blocks every signal in the calling thread, so SIGHUP/SIGINT/SIGTERM are only ever delivered to
// the main thread and never interrupt a connection thread's poll() (A06). Call first in a thread body.
inline void block_all_signals() {
  sigset_t all;
  sigfillset(&all);
  (void)pthread_sigmask(SIG_BLOCK, &all, nullptr);
}

// Starts `f` on a new thread. The build uses -fno-exceptions, where a failing std::thread constructor
// aborts, so connection threads go through pthread_create and a failure is a return value (false).
inline void* spawn_trampoline(void* p) {
  auto* f = static_cast<std::function<void()>*>(p);
  (*f)();
  delete f;
  return nullptr;
}
inline bool spawn(pthread_t& t, std::function<void()> f) {
  auto* box = new std::function<void()>(std::move(f));
  if (::pthread_create(&t, nullptr, &spawn_trampoline, box) != 0) {  // std::thread cannot report failure here // lint:server-runtime
    delete box;
    return false;
  }
  return true;
}

inline void set_nonblock_cloexec(int fd) {
  const int fl = ::fcntl(fd, F_GETFL, 0);
  if (fl >= 0) (void)::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
  const int fdfl = ::fcntl(fd, F_GETFD, 0);
  if (fdfl >= 0) (void)::fcntl(fd, F_SETFD, fdfl | FD_CLOEXEC);
}

inline void set_send_timeout(int fd, int ms) {
  timeval tv{ms / 1000, (ms % 1000) * 1000};
  (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

// poll() that retries EINTR with the remaining time not tracked (callers pass short slices).
inline int poll_retry(pollfd* p, int n, int ms) {
  int r;
  do {
    r = ::poll(p, static_cast<nfds_t>(n), ms);
  } while (r < 0 && errno == EINTR);
  return r;
}

}  // namespace miracache::server::net
