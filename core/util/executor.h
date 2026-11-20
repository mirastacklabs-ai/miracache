// SPDX-License-Identifier: Apache-2.0
// Work offload seam shared by the store (extent CRC) and the client (segment
// decrypt). core/ never spawns threads: production pools live outside core/, and the
// simulator schedules on virtual time with a Random delay.
//
// Contract: `work` touches only the bytes it was given and may run on any thread. `done`
// happens-after `work`. Unless an executor documents a stronger guarantee, `done` may run
// on ANY thread (client/runtime ThreadPoolExecutor runs it on the worker; the decrypt
// pipeline locks for this). Owners that require `done` on their own thread (the
// single-threaded store) must be given an executor that marshals `done` back to that
// thread — tests use InlineExecutor or the sim executor; the production memory-node server
// must supply a marshalling executor. Callers must not hold locks across post():
// an inline executor may run both callbacks before returning.
#pragma once

#include <functional>
#include <utility>

namespace miracache {

class Executor {
 public:
  virtual ~Executor() = default;
  virtual void post(std::function<void()> work, std::function<void()> done) = 0;
};

// Runs work then done synchronously inside post(), on the caller's thread. For tests and
// single-threaded tools.
class InlineExecutor final : public Executor {
 public:
  void post(std::function<void()> work, std::function<void()> done) override {
    work();
    done();
  }
};

}  // namespace miracache
