// SPDX-License-Identifier: Apache-2.0
#include "fabric/verbs_cm/qp_readback.h"

#include <algorithm>
#include <cstring>

#include "util/log.h"

namespace miracache::fabric {

std::vector<QpMismatch> qp_compare(const QpAttrs& got, const QpExpect& want) {
  std::vector<QpMismatch> out;
  auto cmp = [&](const char* name, const std::optional<std::uint8_t>& w, unsigned g) {
    if (w && *w != g) out.push_back({name, *w, g});
  };
  cmp("ack_timeout_exp", want.ack_timeout_exp, got.ack_timeout_exp);
  cmp("retry_count", want.retry_count, got.retry_count);
  cmp("rnr_retry", want.rnr_retry, got.rnr_retry);
  return out;
}

std::uint32_t qp_mtu_bytes(int e) { return e >= 1 && e <= 5 ? 128u << e : 0u; }

static std::string timeout_text(std::uint8_t exp) {
  if (exp == 0) return "none";
  const double us = 4.096 * static_cast<double>(std::uint64_t{1} << (exp < 63 ? exp : 62));
  char b[32];
  if (us >= 1e6) std::snprintf(b, sizeof b, "%.2fs", us / 1e6);
  else if (us >= 1e3) std::snprintf(b, sizeof b, "%.2fms", us / 1e3);
  else std::snprintf(b, sizeof b, "%.1fus", us);
  return b;
}

std::string qp_format(const QpAttrs& a) {
  return "ack_timeout_exp=" + std::to_string(a.ack_timeout_exp) + " (" + timeout_text(a.ack_timeout_exp) +
         ") retry_count=" + std::to_string(a.retry_count) + " rnr_retry=" + std::to_string(a.rnr_retry) +
         " min_rnr_timer=" + std::to_string(a.min_rnr_timer) + " path_mtu=" + std::to_string(a.path_mtu_bytes);
}

static bool identity_unknown(const telemetry::Labels& extra) {
  for (const auto& x : extra)
    if (x.second == "unknown" || x.second.empty()) return true;
  return false;
}

void QpReadback::set_metrics(telemetry::Registry* reg, telemetry::Labels extra) {
  std::vector<std::pair<QpSite, Entry>> again;
  telemetry::Labels now;
  {
    std::lock_guard<std::mutex> g(mu_);
    reg_ = reg;
    extra_ = std::move(extra);
    now = extra_;
    const bool known = !identity_unknown(extra_);
    for (auto& [k, e] : entries_) {
      QpSite s{std::get<0>(k), std::get<1>(k), std::get<2>(k), std::get<3>(k)};
      if (reg_) publish_locked(s, e);
      // L06: the line written while the identity was "unknown" is written once more with the real node ID and hostname.
      if (known && e.log_unknown && (e.have_attrs || e.failed)) {
        e.log_unknown = false;
        again.emplace_back(std::move(s), e);
      }
    }
  }
  for (auto& [s, e] : again) log_entry(s, e, now, true);
}

bool QpReadback::claim(const QpSite& site) {
  std::lock_guard<std::mutex> g(mu_);
  return entries_.try_emplace(Key{site.role, site.device, site.port, site.addr}).second;
}

// F3 (K07, K08): publishes what the entry holds under the current registry and extra labels. An entry that was only
// claimed (no attrs, no failure) publishes nothing and stays unpublished, so a bind between claim() and report() cannot
// fix zeros. When the labels changed since the last publish into the same registry (node_id learned after HELLO), the
// old series are hidden and the new ones published. A registry change leaves the old registry alone (it may be gone).
void QpReadback::publish_locked(const QpSite& s, Entry& e) {
  if (!reg_ || (!e.have_attrs && !e.failed)) return;
  if (e.published_to == reg_ && e.published_labels == extra_) return;
  if (e.published_to == reg_) {
    for (auto* c : e.series_c) reg_->hide(c);
    for (auto* g : e.series_g) reg_->hide(g);
  }
  e.series_c.clear();
  e.series_g.clear();
  e.published_to = reg_;
  e.published_labels = extra_;
  telemetry::Labels l{{"role", s.role}, {"device", s.device}, {"port", s.port}, {"addr", s.addr}};
  for (const auto& x : extra_) l.push_back(x);
  if (e.failed) {
    auto& c = reg_->counter("miracache_qp_query_fail_total", "ibv_query_qp failed after the QP reached RTS (once per rail).", l);
    count_once(e, c, 1);
    e.series_c.push_back(&c);
    return;
  }
  const QpAttrs& a = e.attrs;
  auto gauge = [&](const char* name, const char* help, std::int64_t v) {
    auto& g = reg_->gauge(name, help, l);
    g.set(v);
    e.series_g.push_back(&g);
  };
  gauge("miracache_qp_ack_timeout_exp", "Read-back QP ACK timeout exponent (4.096 us * 2^v; 0 = none), first QP of the rail.", a.ack_timeout_exp);
  gauge("miracache_qp_retry_count", "Read-back QP transport retry count, first QP of the rail.", a.retry_count);
  gauge("miracache_qp_rnr_retry", "Read-back QP RNR retry count (7 = infinite), first QP of the rail.", a.rnr_retry);
  gauge("miracache_qp_min_rnr_timer", "Read-back QP min RNR timer code, first QP of the rail.", a.min_rnr_timer);
  gauge("miracache_qp_path_mtu_bytes", "Read-back QP path MTU in bytes, first QP of the rail.", a.path_mtu_bytes);
  static constexpr const char* kAttrs[] = {"ack_timeout_exp", "retry_count", "rnr_retry"};
  for (const char* name : kAttrs) {
    telemetry::Labels m = l;
    m.emplace_back("attr", name);
    auto& c = reg_->counter("miracache_qp_attr_mismatch_total", "QP attributes whose read-back value differs from config (once per rail).", m);
    e.series_c.push_back(&c);
    std::uint64_t by = 0;
    for (const auto& x : e.mism)
      if (std::strcmp(x.attr, name) == 0) ++by;
    count_once(e, c, by);
  }
}

void QpReadback::count_once(Entry& e, telemetry::Counter& c, std::uint64_t by) {
  if (by == 0) return;
  const bool seen = std::find(e.counted.begin(), e.counted.end(), &c) != e.counted.end();
  if (seen && c.value() >= by) return;  // L07: this series already holds this entry's count
  if (!seen) e.counted.push_back(&c);
  c.inc(by);
}

void QpReadback::log_entry(const QpSite& site, const Entry& e, const telemetry::Labels& extra, bool again) {
  std::vector<std::pair<std::string, std::string>> kv{
      {"role", site.role}, {"device", site.device}, {"port", site.port}, {"addr", site.addr}};
  for (auto& x : extra) kv.push_back(x);
  if (again) kv.emplace_back("identity", "learned");  // L06: the first line of this site said "unknown"
  auto emit = [&](log::Level lvl, const char* msg, std::vector<std::pair<std::string, std::string>> more) {
    std::vector<log::Field> f;
    for (auto& x : kv) f.emplace_back(x.first, x.second);
    for (auto& x : more) f.emplace_back(x.first, x.second);
    log::write(lvl, "qp_attrs", msg, std::span<const log::Field>(f));
  };
  if (!e.have_attrs) {
    emit(log::Level::Warn, "ibv_query_qp failed; QP attributes not read back, connection continues",
         {{"errno", std::to_string(e.err)}, {"err", std::strerror(e.err)}});
    return;
  }
  const QpAttrs* attrs = &e.attrs;
  emit(log::Level::Info, "QP attributes read back after RTS (first QP of this rail)",
       {{"ack_timeout_exp", std::to_string(attrs->ack_timeout_exp)},
        {"ack_timeout", timeout_text(attrs->ack_timeout_exp)},
        {"retry_count", std::to_string(attrs->retry_count)},
        {"rnr_retry", std::to_string(attrs->rnr_retry)},
        {"min_rnr_timer", std::to_string(attrs->min_rnr_timer)},
        {"path_mtu", std::to_string(attrs->path_mtu_bytes)}});
  for (const auto& m : e.mism)
    emit(log::Level::Warn, "QP attribute read back differs from config",
         {{"attr", m.attr}, {"expected", std::to_string(m.expected)}, {"actual", std::to_string(m.actual)}});
}

void QpReadback::report(const QpSite& site, const QpAttrs* attrs, int err, const QpExpect& want) {
  Entry snap;
  telemetry::Labels extra;
  {
    std::lock_guard<std::mutex> g(mu_);
    Entry& e = entries_[Key{site.role, site.device, site.port, site.addr}];
    if (attrs) {
      e.have_attrs = true;
      e.attrs = *attrs;
      e.mism = qp_compare(*attrs, want);
    } else {
      e.failed = true;
      e.err = err;
    }
    e.want = want;
    // L06: lines carry the identity known now; when it is still "unknown" they are written once more when it is learned.
    e.log_unknown = identity_unknown(extra_) && !extra_.empty();
    publish_locked(site, e);
    snap = e;
    extra = extra_;
  }
  log_entry(site, snap, extra, false);
}

}  // namespace miracache::fabric
