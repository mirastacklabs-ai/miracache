// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <chrono>
#include <condition_variable>  // lint:client-runtime
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <thread>  // lint:client-runtime
#include <vector>

#include "miracache/types.h"

// Client runtime (A1.6 L2): tickets, one completion queue, an eventfd, and the worker threads.
// This directory is the only place in client/ allowed to own threads. The runtime is
// backend-agnostic: jobs run through the abstract Backend (the real ClientCore arrives in L3).
// Data-path calls (submit/poll/cancel/eventfd) never throw and never block on I/O.
namespace miracache {

enum class JobKind : std::uint8_t { Lookup, Fetch, Store };

// A job's lane: the memory node it will run on (a scheduling hint, s12). kNoLane is never capped.
inline constexpr std::uint32_t kNoLane = 0xFFFFFFFFu;

struct Job {
  JobKind kind = JobKind::Lookup;
  std::vector<std::uint64_t> keys;  // placeholder key ids; the real key type arrives in L3
  std::uint32_t lane = kNoLane;
};

struct Completion {
  Ticket ticket;
  std::vector<KeyStatus> status;  // one per key of the job, in key order
};

// Read-only view the backend polls while running a job.
class JobControl {
 public:
  virtual ~JobControl() = default;
  // True once cancel(ticket) was called or the runtime is shutting down. The backend should
  // wind the job down promptly and return; the completion is posted only after it returns.
  virtual bool cancelled() const noexcept = 0;
  // Sleeps up to `d`, returning early when cancelled() becomes true (cancel or shutdown).
  // Lets a backend wait without spinning. Returns cancelled().
  virtual bool wait_cancel_for(std::chrono::microseconds d) const noexcept = 0;
};

class Backend {
 public:
  virtual ~Backend() = default;
  // Runs one job to completion on a runtime worker thread (may block). Must fill
  // `status` with job.keys.size() entries. Must not throw.
  virtual void run(Ticket ticket, const Job& job, const JobControl& ctl,
                   std::vector<KeyStatus>& status) noexcept = 0;
  // Called instead of run() when the runtime completes a job as ABORTED without running it
  // (submit after shutdown, cancelled or shut down while queued). Release per-job state here.
  virtual void discarded(Ticket, const Job&) noexcept {}
};

// Lanes (s12, tpu-sync cross-check C1): a backend job holds its worker until its I/O has drained, so a memory node that
// stops answering keeps every job sent to it until that job's deadline. With lane_cap > 0 at most lane_cap jobs of one
// lane run at a time; a job whose lane is full stays queued WITHOUT taking a worker, and the workers run the next jobs
// of other lanes (FIFO among the runnable ones). Jobs whose lane is a stuck node then hold at most lane_cap workers.
// 0 = no lanes. The lane is a hint chosen at submit (the client uses the job's first-choice node), so a job that ends
// up waiting on ANOTHER node (sync replica legs, a read failing over, a previous-view read) still counts against its
// first-choice lane: lanes stop a stuck node from taking the workers of jobs aimed at other nodes, and the per-node
// circuit breaker bounds the rest (it fast-fails jobs to a node whose jobs keep running late).
struct RuntimeOptions {
  unsigned workers = 2;
  unsigned lane_cap = 0;
};

class Runtime {
 public:
  explicit Runtime(Backend& backend, RuntimeOptions opts = {});
  ~Runtime();  // shutdown()
  Runtime(const Runtime&) = delete;
  Runtime& operator=(const Runtime&) = delete;

  // Thread-safe, non-blocking. After shutdown the job completes immediately as ABORTED.
  Ticket submit(Job job) noexcept;
  // Thread-safe. Moves up to out.size() completions (FIFO) into `out`; returns the count.
  std::size_t poll(std::span<Completion> out) noexcept;
  // Readable (EPOLLIN) whenever completions are pending. Owned by the runtime; do not close.
  int eventfd() const noexcept { return efd_; }
  // Non-blocking request. The job's completion is posted only after the backend drained it.
  // No-op for unknown or already-completed tickets.
  void cancel(Ticket t) noexcept;
  // Stops accepting work, aborts queued jobs, asks running jobs to stop, joins workers.
  // Every unfinished job completes as ABORTED. Idempotent; completions stay pollable.
  void shutdown() noexcept;

 private:
  struct Slot;
  void worker_loop() noexcept;
  void push_completion_locked(Ticket t, std::vector<KeyStatus> st) noexcept;
  // Caller holds mu_. The first queued slot a worker may take now (cancelled ones always), or queue_.end().
  std::deque<std::shared_ptr<Slot>>::iterator runnable_locked() noexcept;

  Backend& backend_;
  const unsigned lane_cap_;
  std::map<std::uint32_t, unsigned> lane_running_;  // guarded by mu_; entries erased at 0
  int efd_ = -1;
  std::mutex mu_;
  std::condition_variable work_cv_;  // lint:client-runtime
  // Cancel / shutdown wake-ups for JobControl::wait_cancel_for.
  std::condition_variable ctl_cv_;  // lint:client-runtime
  std::deque<std::shared_ptr<Slot>> queue_;
  std::map<std::uint64_t, std::shared_ptr<Slot>> live_;  // queued or running
  std::deque<Completion> done_;
  std::uint64_t next_id_ = 1;
  bool stopping_ = false;
  std::vector<std::thread> workers_;  // lint:client-runtime
};

}  // namespace miracache
