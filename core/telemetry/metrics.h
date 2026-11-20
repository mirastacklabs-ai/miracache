// SPDX-License-Identifier: Apache-2.0
// Metrics library (spec 11.1). Hand-rolled Prometheus text exposition 0.0.4.
//
// Hot path: Counter::inc, Gauge::set/add and Histogram::observe_ns are single relaxed atomic
// operations: no locks, no allocation, no label lookup. Labels are fixed when a child is
// registered; registration is setup-time (it takes the registry mutex, as does the scrape).
// Rule: no label ever carries a scope, session, key, salt or token value.
//
// Output is deterministic: families in order of first registration, children in order of
// registration, histogram buckets ascending.
//
// Histograms: fixed log2 buckets 1 us * 2^k, k = 0..23 (1 us ... 8.388608 s), plus +Inf,
// _sum (seconds, kept as integer nanoseconds) and _count.
#pragma once

#include <array>
#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace miracache::telemetry {

using Labels = std::vector<std::pair<std::string, std::string>>;

class Counter {
 public:
  void inc(std::uint64_t n = 1) { v_.fetch_add(n, std::memory_order_relaxed); }
  std::uint64_t value() const { return v_.load(std::memory_order_relaxed); }

 private:
  std::atomic<std::uint64_t> v_{0};
};

class Gauge {
 public:
  void set(std::int64_t v) { v_.store(v, std::memory_order_relaxed); }
  void add(std::int64_t d) { v_.fetch_add(d, std::memory_order_relaxed); }
  std::int64_t value() const { return v_.load(std::memory_order_relaxed); }

 private:
  std::atomic<std::int64_t> v_{0};
};

class Histogram {
 public:
  static constexpr std::size_t kFinite = 24;           // le = 1e-6 * 2^k seconds, k = 0..23
  static constexpr std::size_t kBuckets = kFinite + 1;  // + the +Inf bucket
  // Upper bound of finite bucket k, in nanoseconds.
  static constexpr std::uint64_t edge_ns(std::size_t k) { return std::uint64_t{1000} << k; }
  // Index of the bucket a value falls in: the smallest k with ns <= edge_ns(k); kFinite = +Inf.
  static std::size_t bucket_of(std::uint64_t ns);

  void observe_ns(std::uint64_t ns) {
    b_[bucket_of(ns)].fetch_add(1, std::memory_order_relaxed);
    sum_ns_.fetch_add(ns, std::memory_order_relaxed);
    count_.fetch_add(1, std::memory_order_relaxed);
  }

  std::uint64_t count() const { return count_.load(std::memory_order_relaxed); }
  std::uint64_t sum_ns() const { return sum_ns_.load(std::memory_order_relaxed); }
  std::uint64_t bucket(std::size_t i) const { return b_[i].load(std::memory_order_relaxed); }  // non-cumulative

 private:
  std::array<std::atomic<std::uint64_t>, kBuckets> b_{};
  std::atomic<std::uint64_t> sum_ns_{0};
  std::atomic<std::uint64_t> count_{0};
};

class Registry {
 public:
  Registry() = default;
  Registry(const Registry&) = delete;
  Registry& operator=(const Registry&) = delete;

  // Each call adds one child (a fixed label set) to the family `name`, creating the family
  // on first use. Returned references stay valid for the registry's lifetime. A name may be
  // used for one type only (traps otherwise); a duplicate label set returns the existing child.
  Counter& counter(const std::string& name, const std::string& help, const Labels& labels = {});
  Gauge& gauge(const std::string& name, const std::string& help, const Labels& labels = {});
  Histogram& histogram(const std::string& name, const std::string& help, const Labels& labels = {});
  // A gauge read at scrape time. `fn` runs on the scraping thread: it must be thread-safe.
  void callback_gauge(const std::string& name, const std::string& help, const Labels& labels,
                      std::function<std::int64_t()> fn);

  // Labels written first on EVERY series (children registered before or after, histogram
  // buckets included), e.g. the memory node's {node_id="7"}. Set once at startup. Children must
  // not carry a label of the same name.
  void set_const_labels(Labels labels);

  // Takes one child out of the exposition (a series whose labels went stale, e.g. node_id "unknown" once the ID is
  // learned). The object stays valid (references are never invalidated) and keeps counting; registering the same label
  // set again brings it back. Unknown pointers are ignored.
  void hide(const Counter* c);
  void hide(const Gauge* g);

  // Appends the exposition text.
  void write_prometheus(std::string& out) const;
  std::size_t n_families() const;

 private:
  enum class Type : std::uint8_t { Counter, Gauge, Histogram };
  struct Child {
    Labels labels;
    std::unique_ptr<Counter> c;
    std::unique_ptr<Gauge> g;
    std::unique_ptr<Histogram> h;
    std::function<std::int64_t()> cb;
    bool hidden = false;  // not exported (hide)
  };
  struct Family {
    std::string name, help;
    Type type;
    std::deque<Child> children;
  };
  // Finds or creates the child; `make` runs under the registry mutex.
  Child& child(const std::string& name, const std::string& help, Type t, const Labels& labels);

  mutable std::mutex mu_;
  std::deque<Family> families_;
  Labels const_labels_;
};

}  // namespace miracache::telemetry
