// SPDX-License-Identifier: Apache-2.0
#include "telemetry/metrics.h"

#include <cstdio>

#include "util/check.h"

namespace miracache::telemetry {

std::size_t Histogram::bucket_of(std::uint64_t ns) {
  if (ns <= edge_ns(0)) return 0;
  const std::uint64_t v = (ns + 999) / 1000;  // microseconds, rounded up: ns <= 1000 * v
  const std::size_t k = static_cast<std::size_t>(64 - __builtin_clzll(v - 1));  // smallest k with 2^k >= v
  return k >= kFinite ? kFinite : k;
}

// Child objects are created inside the single locked section so a concurrent scrape never
// sees a half-built child.
Registry::Child& Registry::child(const std::string& name, const std::string& help, Type t, const Labels& labels) {
  std::lock_guard<std::mutex> lk(mu_);
  Family* f = nullptr;
  for (auto& x : families_)
    if (x.name == name) f = &x;
  if (!f) {
    families_.push_back(Family{name, help, t, {}});
    f = &families_.back();
  }
  MIRACACHE_CHECK(f->type == t);
  for (auto& c : f->children)
    if (c.labels == labels) {
      c.hidden = false;  // H08: registered again: exported again
      return c;
    }
  f->children.emplace_back();
  Child& c = f->children.back();
  c.labels = labels;
  switch (t) {
    case Type::Counter: c.c = std::make_unique<Counter>(); break;
    case Type::Gauge: c.g = std::make_unique<Gauge>(); break;
    case Type::Histogram: c.h = std::make_unique<Histogram>(); break;
  }
  return c;
}

Counter& Registry::counter(const std::string& name, const std::string& help, const Labels& labels) {
  return *child(name, help, Type::Counter, labels).c;
}
Gauge& Registry::gauge(const std::string& name, const std::string& help, const Labels& labels) {
  return *child(name, help, Type::Gauge, labels).g;
}
Histogram& Registry::histogram(const std::string& name, const std::string& help, const Labels& labels) {
  return *child(name, help, Type::Histogram, labels).h;
}
void Registry::callback_gauge(const std::string& name, const std::string& help, const Labels& labels,
                              std::function<std::int64_t()> fn) {
  Child& c = child(name, help, Type::Gauge, labels);
  std::lock_guard<std::mutex> lk(mu_);
  c.cb = std::move(fn);
}

void Registry::set_const_labels(Labels labels) {
  std::lock_guard<std::mutex> lk(mu_);
  const_labels_ = std::move(labels);
}

std::size_t Registry::n_families() const {
  std::lock_guard<std::mutex> lk(mu_);
  return families_.size();
}

namespace {
void esc(std::string& out, const std::string& s, bool label) {
  for (char ch : s) {
    if (ch == '\\') out += "\\\\";
    else if (ch == '\n') out += "\\n";
    else if (label && ch == '"') out += "\\\"";
    else out += ch;
  }
}
void put_labels(std::string& out, const Labels& cl, const Labels& l, const char* extra_k = nullptr, const char* extra_v = nullptr) {
  if (cl.empty() && l.empty() && !extra_k) return;
  out += '{';
  bool first = true;
  for (const Labels* set : {&cl, &l}) {
    for (const auto& [k, v] : *set) {
      if (!first) out += ',';
      first = false;
      out += k;
      out += "=\"";
      esc(out, v, true);
      out += '"';
    }
  }
  if (extra_k) {
    if (!first) out += ',';
    out += extra_k;
    out += "=\"";
    out += extra_v;
    out += '"';
  }
  out += '}';
}
std::string secs(std::uint64_t ns) {
  char buf[40];
  std::snprintf(buf, sizeof buf, "%.9g", static_cast<double>(ns) / 1e9);
  return buf;
}
}  // namespace

void Registry::hide(const Counter* p) {
  if (!p) return;
  std::lock_guard<std::mutex> lk(mu_);
  for (auto& f : families_)
    for (auto& c : f.children)
      if (c.c.get() == p) c.hidden = true;
}
void Registry::hide(const Gauge* p) {
  if (!p) return;
  std::lock_guard<std::mutex> lk(mu_);
  for (auto& f : families_)
    for (auto& c : f.children)
      if (c.g.get() == p) c.hidden = true;
}

void Registry::write_prometheus(std::string& out) const {
  std::lock_guard<std::mutex> lk(mu_);
  const Labels& cl = const_labels_;
  for (const auto& f : families_) {
    out += "# HELP " + f.name + ' ';
    esc(out, f.help, false);
    out += "\n# TYPE " + f.name + ' ';
    out += f.type == Type::Counter ? "counter" : f.type == Type::Gauge ? "gauge" : "histogram";
    out += '\n';
    for (const auto& c : f.children) {
      if (c.hidden) continue;
      if (f.type == Type::Histogram) {
        std::uint64_t cum = 0;
        for (std::size_t k = 0; k < Histogram::kBuckets; ++k) {
          cum += c.h->bucket(k);
          const std::string le = k < Histogram::kFinite ? secs(Histogram::edge_ns(k)) : "+Inf";
          out += f.name + "_bucket";
          put_labels(out, cl, c.labels, "le", le.c_str());
          out += ' ' + std::to_string(cum) + '\n';
        }
        out += f.name + "_sum";
        put_labels(out, cl, c.labels);
        out += ' ' + secs(c.h->sum_ns()) + '\n';
        out += f.name + "_count";
        put_labels(out, cl, c.labels);
        out += ' ' + std::to_string(c.h->count()) + '\n';
        continue;
      }
      out += f.name;
      put_labels(out, cl, c.labels);
      out += ' ';
      if (f.type == Type::Counter) out += std::to_string(c.c->value());
      else out += std::to_string(c.cb ? c.cb() : c.g->value());
      out += '\n';
    }
  }
}

}  // namespace miracache::telemetry
