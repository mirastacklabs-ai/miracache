// SPDX-License-Identifier: Apache-2.0
#include "src/admin_tickets.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "src/admin_http.h"
#include "src/client_metrics.h"

namespace miracache {

namespace {

constexpr std::size_t kMaxResponse = 64 * 1024;  // one ticket response
const char* const kClassNames[3] = {"control", "fetch", "ingest"};

Error err(ErrorCode c, const char* ctx) { return Error{c, ctx}; }

// ---- strict JSON for the one response shape -------------------------------------------------
// {"ttl_s":N,"tickets":[{"class":"fetch","rail":0,"id":"<32 hex>"},...],"node_id":N,"hostname":"h"}
// (whitespace allowed; node_id and hostname are optional). Unknown fields, at the top level and per
// ticket, are skipped (forward compatibility). Duplicate known keys, escapes in known strings, non-integers and
// trailing bytes are errors.
struct Json {
  const std::string& s;
  std::size_t p = 0;
  bool ok = true;
  void ws() {
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\r' || s[p] == '\n')) ++p;
  }
  bool lit(char c) {
    ws();
    if (p < s.size() && s[p] == c) {
      ++p;
      return true;
    }
    return ok = false;
  }
  bool peek(char c) {
    ws();
    return p < s.size() && s[p] == c;
  }
  std::string str() {
    ws();
    std::string out;
    if (p >= s.size() || s[p] != '"') {
      ok = false;
      return out;
    }
    ++p;
    while (p < s.size() && s[p] != '"') {
      const unsigned char c = static_cast<unsigned char>(s[p]);
      if (c == '\\' || c < 0x20 || out.size() > 64) {
        ok = false;
        return out;
      }
      out.push_back(static_cast<char>(c));
      ++p;
    }
    if (p >= s.size()) ok = false;
    else ++p;
    return out;
  }
  // Forward compatibility: skips one JSON value of a field this client does not know (string with escapes,
  // number, true/false/null, nested object or array up to depth 8). Sets ok = false on malformed input.
  void skip_value(int depth = 0) {
    ws();
    if (!ok || depth > 8 || p >= s.size()) {
      ok = false;
      return;
    }
    const char c = s[p];
    if (c == '"') {
      ++p;
      while (p < s.size() && s[p] != '"') {
        if (static_cast<unsigned char>(s[p]) < 0x20) {
          ok = false;
          return;
        }
        if (s[p] == '\\') ++p;
        ++p;
      }
      if (p >= s.size()) {
        ok = false;
        return;
      }
      ++p;
    } else if (c == '{' || c == '[') {
      const char close = c == '{' ? '}' : ']';
      ++p;
      if (peek(close)) {
        ++p;
        return;
      }
      for (;;) {
        if (c == '{') {
          skip_value(depth + 1);  // the key (a string)
          if (!ok || !lit(':')) {
            ok = false;
            return;
          }
        }
        skip_value(depth + 1);
        if (!ok) return;
        if (peek(',')) {
          ++p;
          continue;
        }
        if (!lit(close)) ok = false;
        return;
      }
    } else if ((c >= '0' && c <= '9') || c == '-') {
      while (p < s.size() && ((s[p] >= '0' && s[p] <= '9') || s[p] == '-' || s[p] == '+' || s[p] == '.' || s[p] == 'e' || s[p] == 'E')) ++p;
    } else {
      for (const char* w : {"true", "false", "null"}) {
        const std::size_t n = std::strlen(w);
        if (s.compare(p, n, w) == 0) {
          p += n;
          return;
        }
      }
      ok = false;
    }
  }
  std::uint64_t num() {
    ws();
    const std::size_t b = p;
    std::uint64_t v = 0;
    while (p < s.size() && s[p] >= '0' && s[p] <= '9') {
      if (p - b > 9) {
        ok = false;
        return 0;
      }
      v = v * 10 + static_cast<std::uint64_t>(s[p] - '0');
      ++p;
    }
    if (p == b || (s[b] == '0' && p - b > 1)) ok = false;
    if (p < s.size() && (s[p] == '.' || s[p] == 'e' || s[p] == 'E' || s[p] == '-')) ok = false;
    return v;
  }
};

bool hex16(const std::string& h, std::uint8_t out[16]) {
  if (h.size() != 32) return false;
  auto nib = [](char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;  // the server emits lower case only
  };
  for (std::size_t i = 0; i < 16; ++i) {
    const int a = nib(h[2 * i]), b = nib(h[2 * i + 1]);
    if (a < 0 || b < 0) return false;
    out[i] = static_cast<std::uint8_t>(a * 16 + b);
  }
  return true;
}
}  // namespace

// ---- response parser ------------------------------------------------------------------------
Expected<AdminTicketSource::Parsed> AdminTicketSource::parse_response(const std::string& body, unsigned max_per_class,
                                                                     std::uint8_t want_rail) {
  Json j{body};
  Parsed out;
  bool have_ttl = false, have_tickets = false, have_nid = false, have_host = false;
  if (!j.lit('{')) return err(ErrorCode::Corrupt, "admin: bad response");
  if (!j.peek('}')) {
    for (;;) {
      const std::string k = j.str();
      if (!j.ok || !j.lit(':')) return err(ErrorCode::Corrupt, "admin: bad response");
      if ((k == "ttl_s" && have_ttl) || (k == "tickets" && have_tickets) || (k == "node_id" && have_nid) ||
          (k == "hostname" && have_host))
        return err(ErrorCode::Corrupt, "admin: duplicate response field");
      if (k == "ttl_s") {
        out.ttl_s = j.num();
        have_ttl = true;
        if (!j.ok || out.ttl_s < 2 || out.ttl_s > 7 * 86400) return err(ErrorCode::Corrupt, "admin: bad ttl_s");
      } else if (k == "node_id") {  // The memory node's own ID and hostname (additive fields)
        have_nid = true;
        const std::uint64_t v = j.num();
        if (!j.ok || v == 0 || v > 0xFFFFFFFFull) return err(ErrorCode::Corrupt, "admin: bad node_id");
        out.node_id = static_cast<std::uint32_t>(v);
      } else if (k == "hostname") {
        have_host = true;
        out.hostname = j.str();
        if (!j.ok) return err(ErrorCode::Corrupt, "admin: bad hostname");
        // The hostname lands in a metric label; anything but a plain DNS-ish name (1..64 of A-Za-z0-9._-) is unknown.
        bool plain = !out.hostname.empty() && out.hostname.size() <= 64;
        for (unsigned char ch : out.hostname)
          plain = plain && (std::isalnum(ch) || ch == '.' || ch == '_' || ch == '-');
        if (!plain) out.hostname.clear();
      } else if (k == "tickets") {
        have_tickets = true;
        if (!j.lit('[')) return err(ErrorCode::Corrupt, "admin: bad response");
        if (!j.peek(']')) {
          for (;;) {
            if (!j.lit('{')) return err(ErrorCode::Corrupt, "admin: bad ticket");
            std::string cls, id;
            std::uint64_t rail = 0;
            bool hc = false, hr = false, hi = false;
            for (;;) {
              const std::string tk = j.str();
              if (!j.ok || !j.lit(':')) return err(ErrorCode::Corrupt, "admin: bad ticket");
              if ((tk == "class" && hc) || (tk == "rail" && hr) || (tk == "id" && hi))
                return err(ErrorCode::Corrupt, "admin: duplicate ticket field");
              if (tk == "class") {
                hc = true;
                cls = j.str();
              } else if (tk == "rail") {
                hr = true;
                rail = j.num();
              } else if (tk == "id") {
                hi = true;
                id = j.str();
              } else {  // unknown per-ticket field: skipped (forward compatibility)
                j.skip_value();
              }
              if (!j.ok) return err(ErrorCode::Corrupt, "admin: bad ticket");
              if (j.peek(',')) {
                ++j.p;
                continue;
              }
              break;
            }
            if (!j.lit('}') || !hc || !hr || !hi) return err(ErrorCode::Corrupt, "admin: bad ticket");
            int ci = -1;
            for (int i = 0; i < 3; ++i)
              if (cls == kClassNames[i]) ci = i;
            proto::Ticket t;
            if (ci < 0 || rail != want_rail || !hex16(id, t.id)) return err(ErrorCode::Corrupt, "admin: bad ticket value");
            t.cls = static_cast<std::uint8_t>(ci);
            out.by_class[ci].push_back(t);
            if (out.by_class[ci].size() > max_per_class) return err(ErrorCode::Corrupt, "admin: too many tickets");
            if (j.peek(',')) {
              ++j.p;
              continue;
            }
            break;
          }
        }
        if (!j.lit(']')) return err(ErrorCode::Corrupt, "admin: bad response");
      } else {  // a field this client does not know: skipped (forward compatibility)
        j.skip_value();
        if (!j.ok) return err(ErrorCode::Corrupt, "admin: bad response");
      }
      if (j.peek(',')) {
        ++j.p;
        continue;
      }
      break;
    }
  }
  if (!j.lit('}')) return err(ErrorCode::Corrupt, "admin: bad response");
  j.ws();
  if (j.p != body.size() || !have_ttl || !have_tickets) return err(ErrorCode::Corrupt, "admin: bad response");
  return out;
}

// ---- source ---------------------------------------------------------------------------------
std::string AdminTicketSource::hostname() const {
  std::lock_guard lk(mu_);
  return hostname_;
}
std::uint32_t AdminTicketSource::reported_node_id() const {
  std::lock_guard lk(mu_);
  return node_id_;
}

Expected<std::shared_ptr<AdminTicketSource>> AdminTicketSource::create(AdminTicketOptions o, const Clock& clock) {
  if (o.admin.empty() || o.cert.empty() || o.key.empty() || o.ca.empty())
    return err(ErrorCode::InvalidArgument, "admin: nodes.admin needs tls.cert, tls.key and tls.ca");
  const auto colon = o.admin.rfind(':');
  if (colon == std::string::npos || colon == 0 || colon + 1 >= o.admin.size())
    return err(ErrorCode::InvalidArgument, "admin: nodes.admin must be host:port");
  if (o.batch < 1 || o.batch > 64) return err(ErrorCode::InvalidArgument, "admin: ticket_batch must be 1..64");
  HttpsOptions ho;
  ho.cert = o.cert;
  ho.key = o.key;
  ho.ca = o.ca;
  ho.io_timeout_ms = o.io_timeout_ms;
  ho.max_response = kMaxResponse;
  ho.test_after_connect = o.test_after_connect;
  auto http = HttpsClient::create(std::move(ho));
  if (!http) return http.error();
  return std::shared_ptr<AdminTicketSource>(new AdminTicketSource(std::move(o), clock, std::move(*http)));
}

AdminTicketSource::AdminTicketSource(AdminTicketOptions o, const Clock& clock, std::shared_ptr<HttpsClient> http)
    : o_(std::move(o)), batch_(o_.batch), fetch_need_(std::clamp(o_.fetch_need, 1u, 64u)), clock_(clock), http_(std::move(http)) {}
void AdminTicketSource::set_batch(unsigned n) {
  if (n >= 1 && n <= 64) batch_.store(n, std::memory_order_relaxed);  // Class A, new refills only
}
void AdminTicketSource::set_fetch_need(unsigned n) { fetch_need_.store(std::clamp(n, 1u, 64u), std::memory_order_relaxed); }
AdminTicketSource::~AdminTicketSource() = default;

void AdminTicketSource::bind_metrics(ClientMetrics* m) {
  {
    std::lock_guard ml(mx_mu_);
    mx_.store(m);
    if (m) {  // fetches made before the registry existed (the first batch at open)
      m->ticket_fetch[0]->inc(n_ok_.load());
      m->ticket_fetch[1]->inc(n_err_.load());
    }
  }
  publish_gauges();
}

void AdminTicketSource::publish_gauges() {
  ClientMetrics* m = mx_.load();
  if (!m) return;
  std::lock_guard lk(mu_);
  for (int i = 0; i < 3; ++i) {
    std::size_t n = 0;
    for (std::size_t r = 0; r < kRails; ++r) n += cache_[r][i].size();  // every rail's tickets of the class
    m->ticket_cache[i]->set(static_cast<double>(n));
  }
}

std::size_t AdminTicketSource::cached(fabric::EpClass cls, std::uint8_t rail) const {
  std::lock_guard lk(mu_);
  return rail < kRails ? cache_[rail][static_cast<int>(cls)].size() : 0;
}

TicketFn AdminTicketSource::ticket_fn() {
  return [this](fabric::EpClass cls) { return draw(cls); };
}
RailTicketFn AdminTicketSource::rail_ticket_fn() {
  return [this](fabric::EpClass cls, std::uint8_t rail) { return draw(cls, rail); };
}

Expected<proto::Ticket> AdminTicketSource::draw(fabric::EpClass cls) { return draw(cls, 0); }

Expected<proto::Ticket> AdminTicketSource::draw(fabric::EpClass cls, std::uint8_t rail) {
  const int ci = static_cast<int>(cls);
  if (rail >= kRails) return err(ErrorCode::InvalidArgument, "admin: rail out of range");
  Expected<proto::Ticket> out = err(ErrorCode::NotFound, "admin: no cached ticket (admin unreachable or not refilled yet)");
  {
    std::lock_guard lk(mu_);
    const Nanos now = clock_.now();
    const Nanos max_age = std::chrono::seconds(ttl_s_) / 2;
    auto& q = cache_[rail][ci];
    while (!q.empty() && now - q.front().at >= max_age) q.pop_front();
    if (!q.empty()) {
      out = q.front().t;  // single use: removed from the cache before it leaves
      q.pop_front();
    } else if (last_failed_) {
      // The cache is empty because the latest admin call failed: the build fails with that call's error (code and
      // text: "admin: connect failed", "admin: 429 ...", a TLS failure), not with a bare "no cached ticket".
      // The text only. The code is a fixed transport-class one (LinkDown): the build path keys behaviour on codes
      // (InvalidArgument = a node-ID conflict: max backoff, no build-fail count, the bundle mismatch line; Aborted = a
      // shutdown), and an admin failure is neither. last_err_ is the admin endpoint's latest failure, whatever rail or
      // class it was for: the refill backoff is shared by every rail, so it is also why this rail's cache is empty.
      out = Error{ErrorCode::LinkDown, last_err_.context};
    }
  }
  publish_gauges();
  return out;
}

void AdminTicketSource::reset_backoff() {
  std::lock_guard lk(mu_);
  fail_streak_ = 0;
  // A floor, not zero: the next fetch is at most backoff_min_ms away (never a tight retry loop
  // against an admin that is still failing). A fetch in flight that fails sets it from streak 0 (min).
  const Nanos floor = clock_.now() + std::chrono::milliseconds(std::max(1u, o_.backoff_min_ms));
  next_try_ = std::min(next_try_, floor);
}

// One request per rail and request size that needs a refill (the node's ticket route takes one rail and one count per
// call); rail 0 only when AdminTicketOptions::rails is empty. The backoff is the admin endpoint's, shared by every rail:
// the first failure stops.
// Each class has its own mark and size (want()): the fetch class wants fetch_need tickets for one build, so a node
// whose fetch_qps is above ticket_batch still connects. Classes that want the same count share one request.
Status AdminTicketSource::prepare() { return prepare(Nanos::max()); }

// The settle retries of Client::open give the refill what is left of the settle. Each admin call gets
// min(io_timeout_ms, the budget left), and none starts once it is spent (Timeout, no fetch, the backoff untouched).
Status AdminTicketSource::prepare(Nanos budget) {
  const Nanos end = budget == Nanos::max() ? Nanos::max() : clock_.now() + budget;
  std::vector<std::uint8_t> rails = o_.rails;
  if (rails.empty()) rails.push_back(0);
  for (const std::uint8_t rail : rails) {
    if (rail >= kRails) return err(ErrorCode::InvalidArgument, "admin: rail out of range");
    unsigned mask[3] = {0, 0, 0};
    std::size_t count[3] = {0, 0, 0};
    {
      std::lock_guard lk(mu_);
      const Nanos now = clock_.now();
      const Nanos max_age = std::chrono::seconds(ttl_s_) / 2;
      // Ask only for the classes below their refill mark, never past the class cap (2 x its request size): an
      // uneven drain would otherwise leave unredeemed tickets live on the node and hit its per-identity cap.
      for (int i = 0; i < 3; ++i) {
        auto& q = cache_[rail][i];
        while (!q.empty() && now - q.front().at >= max_age) q.pop_front();
        const Want w = want(i);
        if (q.size() >= w.mark) continue;
        const std::size_t c = std::max<std::size_t>(1, std::min(w.count, w.cap - q.size()));  // size < mark <= cap
        for (int g = 0; g < 3; ++g)
          if (mask[g] == 0 || count[g] == c) {
            mask[g] |= 1u << i;
            count[g] = c;
            break;
          }
      }
      if (mask[0] == 0) continue;
      if (now < next_try_) return last_err_;  // backing off after a failure: no network
    }
    for (int g = 0; g < 3 && mask[g] != 0; ++g) {
      unsigned call_ms = 0;  // 0 = the whole io_timeout_ms
      if (end != Nanos::max()) {
        const Nanos left = end - clock_.now();
        if (left <= Nanos{0}) {
          publish_gauges();
          return err(ErrorCode::Timeout, "admin: no time left for a ticket fetch (open settle)");
        }
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(left + std::chrono::microseconds(999)).count();
        call_ms = static_cast<unsigned>(std::clamp<std::int64_t>(ms, 1, 1 << 30));
      }
      Status s = fetch(rail, mask[g], static_cast<unsigned>(count[g]), call_ms);
      if (!s) {
        publish_gauges();
        return s;
      }
    }
  }
  publish_gauges();
  return {};
}

// The memory node sizes its default limits.ticket_max_per_identity from these caps (server/dyn_config.h
// default_ticket_max: 2 x the per-rail caps at ticket_batch 4, for 16 sessions); keep the two in step.
AdminTicketSource::Want AdminTicketSource::want(int ci) const {
  const std::size_t batch = std::clamp(batch_.load(std::memory_order_relaxed), 1u, 64u);
  const std::size_t need = ci == static_cast<int>(fabric::EpClass::Fetch)
                               ? std::clamp(fetch_need_.load(std::memory_order_relaxed), 1u, 64u)
                               : 1;
  Want w;
  w.count = std::max(batch, need);                  // <= 64: the node's per-call limit
  w.mark = std::max<std::size_t>(o_.refill_below, need);
  w.cap = std::max(2 * w.count, w.mark);
  return w;
}

// While the source backs off after a failed fetch, a build fails on the cached error unless the cache
// still holds what one build draws (per rail: 1 control, fetch_need fetch, 1 ingest). Then: next_try_; else 0.
Nanos AdminTicketSource::ready_at() const {
  std::vector<std::uint8_t> rails = o_.rails;
  if (rails.empty()) rails.push_back(0);
  const std::size_t need_fetch = std::clamp(fetch_need_.load(std::memory_order_relaxed), 1u, 64u);
  std::lock_guard lk(mu_);
  const Nanos now = clock_.now();  // one reading for the whole check
  if (!last_failed_ || now >= next_try_) return Nanos{0};
  const Nanos max_age = std::chrono::seconds(ttl_s_) / 2;
  for (const std::uint8_t rail : rails) {
    if (rail >= kRails) continue;
    for (int ci = 0; ci < 3; ++ci) {
      const std::size_t need = ci == static_cast<int>(fabric::EpClass::Fetch) ? need_fetch : 1;
      std::size_t live = 0;
      for (const Entry& e : cache_[rail][ci])
        if (now - e.at < max_age) ++live;
      if (live < need) return next_try_;
    }
  }
  return Nanos{0};
}

Status AdminTicketSource::fetch(std::uint8_t rail, unsigned class_mask, unsigned count, unsigned timeout_ms) {
  std::lock_guard fl(fetch_mu_);
  fetches_.fetch_add(1);
  bool hold_streak = false;  // Set for a 503 (draining): back off, but do not grow the streak
  auto done = [&](Status s) {
    {
      // The total and the counter move under the same lock bind_metrics replays under, so a fetch
      // finishing while the registry is being bound is counted exactly once.
      std::lock_guard ml(mx_mu_);
      (s ? n_ok_ : n_err_).fetch_add(1);
      if (ClientMetrics* m = mx_.load()) m->ticket_fetch[s ? 0 : 1]->inc();
    }
    std::lock_guard lk(mu_);
    if (s) {
      fail_streak_ = 0;
      next_try_ = Nanos{0};
      last_failed_ = false;
    } else {
      // Jittered exponential backoff (1 s -> 30 s): a 403/429/blackhole is not retried every tick.
      // The away cap applies to a node that is away (LinkDown, Timeout, 503), not to a refusal.
      const ErrorCode ec = s.error().code;
      const bool away = hold_streak || ec == ErrorCode::LinkDown || ec == ErrorCode::Timeout;
      unsigned cap = o_.backoff_max_ms;
      if (away && o_.away_backoff_max_ms != 0) cap = std::min(cap, o_.away_backoff_max_ms);
      const std::uint64_t lo = std::max(1u, o_.backoff_min_ms), hi = std::max<std::uint64_t>(lo, cap);
      std::uint64_t d = std::min<std::uint64_t>(hi, lo << std::min(fail_streak_, 20u));
      if (o_.random && d > 1) d = d / 2 + o_.random->below(d / 2 + 1);
      if (!hold_streak) ++fail_streak_;
      next_try_ = clock_.now() + std::chrono::milliseconds(d);
      last_err_ = s.error();
      last_failed_ = true;
    }
    return s;
  };
  std::string classes;
  for (int i = 0; i < 3; ++i)
    if (class_mask & (1u << i)) classes += std::string(classes.empty() ? "\"" : ",\"") + kClassNames[i] + "\"";
  const std::string body =
      "{\"classes\":[" + classes + "],\"rail\":" + std::to_string(rail) + ",\"count\":" + std::to_string(count) + "}";
  auto rsp = http_->request(o_.admin, "POST", "/v1/tickets", "application/json", body, o_.server_identity, timeout_ms);
  if (!rsp) return done(rsp.error());
  const int code = rsp->code;
  if (code == 403) return done(err(ErrorCode::AccessDenied, "admin: 403 identity not allowed"));
  if (code == 429) return done(err(ErrorCode::Busy, "admin: 429 ticket cap reached"));
  if (code == 503) {  // A drain is not a failing admin: the backoff does not grow
    hold_streak = true;
    return done(err(ErrorCode::Busy, "admin: 503 node draining"));
  }
  if (code != 200) return done(err(ErrorCode::LinkDown, "admin: unexpected HTTP status"));
  auto parsed = parse_response(rsp->body, count, rail);
  if (!parsed) return done(parsed.error());

  {
    std::lock_guard lk(mu_);
    const Nanos now = clock_.now();
    ttl_s_ = parsed->ttl_s;
    if (!parsed->hostname.empty()) hostname_ = parsed->hostname;
    if (parsed->node_id != 0) node_id_ = parsed->node_id;
    for (int i = 0; i < 3; ++i) {
      if (!(class_mask & (1u << i))) continue;  // not asked for: not kept
      const std::size_t cap = want(i).cap;  // The cache never holds more than 2 x the class's request size
      for (const auto& t : parsed->by_class[i])
        if (cache_[rail][i].size() < cap) cache_[rail][i].push_back(Entry{t, now});
    }
  }
  return done(Status{});
}

}  // namespace miracache
