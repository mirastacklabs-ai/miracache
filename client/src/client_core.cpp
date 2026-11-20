// SPDX-License-Identifier: Apache-2.0
#include "src/client_core.h"

#include <algorithm>
#include <array>
#include <cstring>

#include "proto/state_gen.h"
#include "util/crc32c.h"

namespace miracache {
namespace {

enum Kind : int { kFetch = 0, kStore = 1 };
enum Tag : std::uint64_t { kTagData = 0, kTagSeq = 1, kTagWrite = 2 };

// Store tags: job (32) | key (30) | tag (2).
constexpr std::uint64_t make_tag(std::uint64_t job, std::size_t key, Tag t) {
  return (job << 32) | (static_cast<std::uint64_t>(key) << 2) | t;
}
// Fetch tags: job (32) | key (18) | slice (10) | attempt (2) | tag (2). The attempt tells a re-issued slice's
// completion from a (duplicated) completion of the WR it replaced.
constexpr std::size_t kMaxFetchKeys = std::size_t{1} << 18;
constexpr std::uint32_t kMaxSlices = 1023;  // payload slice indices 0..1022; 1023 = the seq READ
constexpr std::uint32_t kSeqSlice = 1023;
constexpr std::uint32_t kMaxReissues = 3;  // per slice (the attempt field holds 0..3)
constexpr std::uint64_t make_ftag(std::uint64_t job, std::size_t key, std::uint32_t slice, std::uint32_t attempt, Tag t) {
  return (job << 32) | (static_cast<std::uint64_t>(key) << 14) | (static_cast<std::uint64_t>(slice) << 4) |
         (static_cast<std::uint64_t>(attempt & 3) << 2) | t;
}

store::ScopeId to_store(const ScopeId& s) {
  store::ScopeId o;
  std::memcpy(o.data(), s.b, 32);
  return o;
}
store::KeyHash to_store(const KeyHash& s) {
  store::KeyHash o;
  std::memcpy(o.data(), s.b, 32);
  return o;
}

// Bytes a span holds in the pool (LandingPool::bytes_in_use counts whole kPoolAlign units).
std::size_t pool_bytes(const PoolSpan& s) { return (s.len + kPoolAlign - 1) / kPoolAlign * kPoolAlign; }

void zero(std::span<std::byte> b) {
  if (!b.empty()) std::memset(b.data(), 0, b.size());
}

}  // namespace

struct ClientCore::FKey {
  bool final = false;
  KeyStatus st = KeyStatus::Miss;
  store::KeyHash hash{};
  std::optional<Dek> dek;
  BlockMeta meta{};
  store::LookupEntry le;
  PoolSpan span{}, seq{};
  bool has_span = false, has_seq = false;
  BlockId bid = 0;
  int wr = 0;                // WRs posted and not completed (payload slices + the seq READ)
  // The payload is cut into slices of slice_bytes; each is posted on the fetch QP the port picks
  // (weighted least outstanding bytes within the QP windows), waits in waitq_ while every window is full, and is
  // re-issued after its OWN failed or flushed CQE while the lease deadline allows. The seq READ is posted only once
  // every slice is done (landed, or given up), i.e. after the last slice's CQE, re-issues included.
  struct Slice {
    std::uint32_t off = 0, len = 0;
    enum class St : std::uint8_t { Queued, Posted, Done } st = St::Queued;
    std::uint8_t attempt = 0;  // re-issues so far
  };
  std::vector<Slice> sl;
  int data_left = 0;         // slices not done yet (queued or posted)
  bool data_failed = false;  // a slice failed for good or could not be posted
  bool seq_out = false;      // the seq READ is posted and not completed
  bool seq_queued = false;   // the seq READ waits for a fetch window
  bool pipe_pending = false;
  std::span<std::byte> out;
  Nanos t_read{0}, t_dec{0};  // metrics: READ posted / data landed (decrypt begins)
  bool has_read = false, has_dec = false;
};

struct ClientCore::PKey {
  bool final = false;
  bool cut = false;  // finalised by fail_all_jobs (session loss), not by a node answer
  KeyStatus st = KeyStatus::Aborted;
  store::PutKey pk;
  std::optional<Dek> dek;
  BlockMeta meta{};
  Layout lay;
  PoolSpan span{};
  bool has_span = false;
  bool accepted = false;
  std::uint32_t crc = 0;
  int wr = 0;
  bool write_wait = false;  // Sealed, its WRITE waits for room on the ingest QP's send queue
  std::span<std::byte> pt;
};

struct ClientCore::Job {
  std::uint64_t id = 0;
  Ticket ticket;
  int kind = kFetch;
  Nanos deadline{0};
  Notify cb;
  std::vector<KeyStatus> status;
  bool done_reported = false;

  bool stop = false;       // timed out or cancelled: wind down
  bool cancelled = false;  // done is deferred until drained
  // fetch
  std::vector<FKey> fk;
  std::vector<store::LeaseId> leases;  // one per LOOKUP part (batches over the port's key cap are split)
  Nanos last_renew{0};
  // lease_deadline = t_lease_granted + ttl - guard (guard = 2 x RTT, at least 1 ms), computed
  // conservatively from the LOOKUP: t_lease_granted is taken as the LOOKUP's send time. rtt = that LOOKUP's round trip.
  Nanos lease_deadline = Nanos::max();
  Nanos rtt{0};
  // Per lease (same order as `leases`) a time the node's lease surely outlives: tl + ttl from the LOOKUP,
  // moved to (RENEW send time + granted ttl) by each confirmed RENEW. lease_deadline = min of them - lease_guard.
  std::vector<Nanos> lease_until;
  Nanos lease_guard{0};
  // store
  std::vector<PKey> pk;
  store::ScopeId scope{};
  std::size_t next = 0;               // first key of the next / current batch
  std::vector<std::size_t> batch;     // key indices of the current batch
  enum class Phase { Idle, Writing, Committing, Backoff } phase = Phase::Idle;
  store::PutBeginAck ack;
  bool batch_failed = false;
  bool commit_ready = false;
  store::PutDoneResult commit_result;
  Nanos retry_at{0};
  bool dropped = false;
  std::uint64_t commit_gen = 0;  // identifies the live PUT_COMMIT callback
  std::uint64_t sess = 0;        // Session (down count) whose endpoints carry every op of this job
  Nanos t0{0}, t_write{0}, t_commit{0};  // metrics: job start, batch write start, commit start
};

ClientCore::ClientCore(fabric::Fabric& fab, ServerPort& port, const Clock& clock, Executor& ex,
                       NonceSource& salts, const ClientCoreOptions& opts)
    : fab_(fab), port_(port), clock_(clock), ex_(ex), salts_(salts), opts_(opts), mx_(opts.registry, opts.node_label) {}

// init() binds &mx_ into the port, which forwards it to the ticket source (WireOptions::on_metrics).
// Both outlive this core when a build fails (the port drains its endpoints after create() returned the
// error; the ticket source serves the next build) and would write into a dead ClientMetrics. Unbind both.
ClientCore::~ClientCore() { port_.bind_metrics(nullptr); }

Expected<std::unique_ptr<ClientCore>> ClientCore::create(fabric::Fabric& fab, ServerPort& port, const Clock& clock,
                                                         Executor& ex, NonceSource& salts,
                                                         const ClientCoreOptions& opts) {
  std::unique_ptr<ClientCore> c(new ClientCore(fab, port, clock, ex, salts, opts));
  if (auto s = c->init(); !s) return s.error();
  return c;
}

Status ClientCore::init() {
  port_.bind_metrics(&mx_);
  auto info = port_.hello();
  if (!info) return info.error();
  info_ = std::move(*info);
  auto g = GcmCtx::create();
  if (!g) return g.error();
  gcm_.emplace(std::move(*g));
  pool_ = std::make_unique<LandingPool>(fab_);
  sub_ = SubpoolKey{info_.node, 0};
  if (auto s = pool_->add_subpool(sub_, fabric::PdId{}, opts_.pool_bytes); !s) return s;
  pipe_ = std::make_unique<DecryptPipeline>(ex_, opts_.max_inflight_segments);
  for (auto cls : {fabric::EpClass::Fetch, fabric::EpClass::Ingest}) {
    fabric::ConnParams cp;
    cp.cls = cls;
    cp.ticket[0] = static_cast<std::byte>(cls == fabric::EpClass::Fetch ? 1 : 2);
    cp.ticket_len = 1;
    cp.ord = 16;
    auto ep = fab_.connect(fabric::Peer{info_.node}, cp);
    if (!ep) return ep.error();
    (cls == fabric::EpClass::Fetch ? fetch_ep_ : ingest_ep_) = *ep;
    port_.connected(cls, *ep);
  }
  seen_down_ = port_.session_down_count();
  mx_.session_up->set(port_.session_up() ? 1 : 0);
  if (opts_.pool_gauges) {  // last: a failed init must not leave a gauge callback reading a pool that is about to die
    const std::int64_t total = static_cast<std::int64_t>(pool_bytes_total());
    LandingPool* p = pool_.get();
    telemetry::Labels used{{"state", "used"}}, free_{{"state", "free"}};
    if (!opts_.node_label.empty()) used.emplace_back("node", opts_.node_label), free_.emplace_back("node", opts_.node_label);
    auto snap = std::make_shared<PoolSeriesSnap>();  // "used" first, "free" from the same read
    mx_.reg.callback_gauge("miracache_client_landing_pool_bytes", "Landing pool bytes, by state.", used,
                           [p, total, snap] { return snap->take(static_cast<std::int64_t>(p->bytes_in_use()), total); });
    mx_.reg.callback_gauge("miracache_client_landing_pool_bytes", "Landing pool bytes, by state.", free_,
                           [snap] { return snap->free_bytes(); });
  }
  return {};
}

// ---- session loss / reconnect -----------------------------------------------------------

// Fails every job at once (fetch/lookup -> MISS, put -> Refused) and forgets leases: the old
// session's server state is gone. Jobs are reported now and released after their RDMA ops
// drain (aborted endpoints flush them with Aborted), exactly like a timeout.
void ClientCore::fail_all_jobs() {
  std::vector<std::uint64_t> ids;
  for (auto& [id, _] : jobs_) ids.push_back(id);
  for (auto id : ids) {
    auto it = jobs_.find(id);
    if (it == jobs_.end()) continue;
    Job& j = *it->second;
    j.leases.clear();  // dropped locally, never RELEASEd on the dead session
    if (j.stop) continue;
    j.stop = true;
    if (j.kind == kFetch) {
      for (auto& k : j.fk)
        if (!k.final) k.final = true, k.st = KeyStatus::Miss;
    } else {
      for (auto& k : j.pk)
        if (!k.final) k.final = true, k.st = KeyStatus::Refused, k.cut = true;  // removed node: Skipped
      j.next = j.pk.size();
    }
    report_done(j);
  }
}

void ClientCore::sync_session() {
  const std::uint64_t dc = port_.session_down_count();
  if (dc != seen_down_) {
    seen_down_ = dc;
    fetch_ep_ = ingest_ep_ = nullptr;
    reads_out_ = writes_out_ = 0;  // The next session's endpoints start empty (late flushes saturate at 0)
    bound_ = false;
    mx_.session_up->set(0);
    fail_all_jobs();
  }
  if (!bound_ && port_.session_up()) {
    fabric::Endpoint* f = port_.endpoint(fabric::EpClass::Fetch);
    fabric::Endpoint* i = port_.endpoint(fabric::EpClass::Ingest);
    if (!f || !i) return;  // stay unbound: every op fails fast
    fetch_ep_ = f, ingest_ep_ = i;
    port_.connected(fabric::EpClass::Fetch, f);
    port_.connected(fabric::EpClass::Ingest, i);
    bound_ = true;
    mx_.session_up->set(1);
  }
}

// One LOOKUP per port_.max_lookup_keys() keys, all bounded by the job's deadline; entries line
// up with q.keys (an unanswered part stays all-MISS and is not counted in `answered`).
ClientCore::SplitAck ClientCore::lookup_split(const store::LookupReq& q, bool lease, Nanos deadline) {
  SplitAck out;
  const std::size_t n = q.keys.size(), cap = std::max<std::size_t>(1, port_.max_lookup_keys());
  out.entries.resize(n);
  port_.set_op_deadline(deadline);
  for (std::size_t off = 0; off < n; off += cap) {
    if (off > 0 && clock_.now() >= deadline) break;  // the remaining parts are unanswered
    const std::size_t len = std::min(cap, n - off);
    store::LookupAck a;
    if (len == n) {
      a = lease ? port_.lookup(q) : port_.lookup_presence(q);
    } else {
      store::LookupReq part;
      part.principal = q.principal;
      part.scope = q.scope;
      part.keys.assign(q.keys.begin() + static_cast<std::ptrdiff_t>(off), q.keys.begin() + static_cast<std::ptrdiff_t>(off + len));
      a = lease ? port_.lookup(part) : port_.lookup_presence(part);
    }
    if (a.lease != 0) {
      out.leases.push_back(a.lease);
      // An expiry the port did not give (0) means "unknown": no re-issue may count on that lease.
      out.lease_expiry = std::min(out.lease_expiry, a.lease_expiry);
    }
    if (a.entries.size() != len) continue;
    for (std::size_t i = 0; i < len; ++i) out.entries[off + i] = a.entries[i];
    out.answered += len;
  }
  port_.set_op_deadline(Nanos::max());
  return out;
}

ClientCore::Job& ClientCore::new_job(int kind, Nanos deadline, Notify cb, std::size_t n) {
  auto j = std::make_unique<Job>();
  j->id = next_job_++;
  j->ticket = Ticket{j->id};
  j->kind = kind;
  j->deadline = deadline;
  j->cb = std::move(cb);
  j->status.assign(n, KeyStatus::Miss);
  j->last_renew = clock_.now();
  j->t0 = j->last_renew;
  // submit_* ran sync_session() first. A job posts ops only while its session is bound: once that session
  // ends (seen_down_ moves) the job is stopped by fail_all_jobs and posts nothing more.
  j->sess = seen_down_;
  mx_.inflight[kind == kFetch ? 0 : 1]->add(1);
  Job& r = *j;
  jobs_.emplace(r.id, std::move(j));
  return r;
}

// ---- fetch ------------------------------------------------------------------------

Ticket ClientCore::submit_fetch(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys,
                                std::span<const BufRef> bufs, Nanos deadline, Notify cb) {
  const std::size_t n = keys.size();
  sync_session();
  Job& j = new_job(kFetch, deadline, std::move(cb), n);
  const Ticket tk = j.ticket;  // job_tick may erase the job
  j.fk.resize(n);
  for (auto& k : j.fk) k.final = true;  // until proven a candidate
  if (n != bufs.size() || group >= sk.scopes.size() || !sk.keys || n > kMaxFetchKeys) {
    for (std::size_t i = 0; i < n; ++i)
      if (i < bufs.size()) zero(bufs[i].buf);
    job_tick(j);
    return tk;
  }
  store::LookupReq q;
  q.scope = to_store(sk.scopes[group]);
  j.scope = q.scope;  // kept for INVALIDATE on an AEAD miss
  std::vector<std::size_t> idx;
  for (std::size_t i = 0; i < n; ++i) {
    FKey& k = j.fk[i];
    k.out = bufs[i].buf;
    zero(k.out);
    auto h = sk.keys->key_hash(keys[i].raw);
    auto d = sk.keys->dek_for(keys[i].raw);
    auto lay = layout(k.out.size(), opts_.segment_log2);
    if (!h || !d || !lay) continue;  // stays final MISS
    k.hash = to_store(*h);
    k.dek.emplace(std::move(*d));
    k.meta = BlockMeta{sk.kver, sk.scopes[group], *h, k.out.size(), opts_.segment_log2};
    q.keys.push_back(k.hash);
    idx.push_back(i);
  }
  if (!idx.empty()) {
    const Nanos tl = clock_.now();
    SplitAck ack = lookup_split(q, true, deadline);
    const Nanos tr = clock_.now();
    ClientMetrics::observe(mx_.fetch_s[ClientMetrics::kFLeaseWait], tl, tr);
    j.leases = std::move(ack.leases);
    // The port's expiry is (reply time + ttl); the grant happened after tl, so tl + ttl = expiry - rtt
    // is a deadline the lease surely outlives. guard = 2 x RTT, at least 1 ms.
    j.rtt = tr - tl;
    if (!j.leases.empty()) {
      const Nanos guard = std::max<Nanos>(2 * j.rtt, std::chrono::milliseconds(1));
      j.lease_deadline = ack.lease_expiry <= Nanos{0} ? Nanos{0} : ack.lease_expiry - j.rtt - guard;
      // An unknown expiry (0) stays unknown: a renewal moves only a deadline the LOOKUP gave.
      if (ack.lease_expiry > Nanos{0}) {
        j.lease_until.assign(j.leases.size(), ack.lease_expiry - j.rtt);
        j.lease_guard = guard;
      }
    }
    for (std::size_t m = 0; m < idx.size() && m < ack.entries.size(); ++m) {
      FKey& k = j.fk[idx[m]];
      k.le = ack.entries[m];
      if (!k.le.hit) continue;
      k.final = false;
    }
    for (std::size_t m = 0; m < idx.size(); ++m)
      if (!j.fk[idx[m]].final) fetch_start_key(j, idx[m]);
  }
  job_tick(j);
  return tk;
}

void ClientCore::fetch_start_key(Job& j, std::size_t i) {
  FKey& k = j.fk[i];
  auto fail = [&] { k.final = true, k.st = KeyStatus::Miss; };
  auto lay = layout(k.out.size(), opts_.segment_log2);
  // stored_len is server-supplied and goes into u32 READ lengths: refuse >= 4 GiB.
  auto bad_hdr = [&] {
    mx_.validate_fail[1]->inc();
    fail();
  };
  if (!fetch_ep_) return fail();  // session went down between the LOOKUP and now
  if (k.le.stored_len > UINT32_MAX) return bad_hdr();
  if (!lay || lay->stored_len != k.le.stored_len || k.le.seg_id >= info_.segs.size()) return bad_hdr();
  const fabric::MemRegion& seg = info_.segs[k.le.seg_id];
  // Server-supplied values: subtraction-form bounds checks so nothing can wrap.
  if (k.le.offset > seg.len || k.le.stored_len > seg.len - k.le.offset || k.le.gen_slot >= info_.array.len / 8)
    return bad_hdr();
  auto sp = pool_->acquire(sub_, k.le.stored_len);
  if (!sp) return fail();  // backpressure: a miss, never an error
  auto qs = pool_->acquire(sub_, 8);
  if (!qs) {
    free_span(*sp);
    return fail();
  }
  k.span = *sp, k.has_span = true;
  k.seq = *qs, k.has_seq = true;
  k.pipe_pending = true;
  const std::uint64_t jid = j.id;
  k.bid = pipe_->start(*k.dek, k.meta, k.span, k.out, [this, jid, i](FetchOutcome oc) {
    std::lock_guard lk(qmu_);
    fq_.emplace_back(jid, i, oc);
  });
  k.t_read = clock_.now(), k.has_read = true;
  // Class A (`fabric.slice_bytes`): the data is read in slices of at most the value the job started with
  // (opts_.slice_bytes is read once per key here); 0 or a block no larger than a slice = one READ, as before.
  // At most kMaxSlices slices per block (a larger block uses larger slices).
  std::uint64_t slice = opts_.slice_bytes ? opts_.slice_bytes() : 0;
  const std::uint32_t total = static_cast<std::uint32_t>(k.le.stored_len);
  if (slice != 0 && (total + slice - 1) / slice > kMaxSlices) slice = (total + kMaxSlices - 1) / kMaxSlices;
  const std::uint32_t nsl = slice == 0 || total <= slice ? 1u : static_cast<std::uint32_t>((total + slice - 1) / slice);
  k.sl.assign(nsl, FKey::Slice{});
  for (std::uint32_t s = 0; s < nsl; ++s) {
    k.sl[s].off = static_cast<std::uint32_t>(s * (nsl == 1 ? 0 : slice));
    k.sl[s].len = nsl == 1 ? total : std::min<std::uint32_t>(static_cast<std::uint32_t>(slice), total - k.sl[s].off);
  }
  k.data_left = static_cast<int>(nsl);
  k.data_failed = false;
  // Slices already waiting for a window go first (FIFO across keys); a slice that finds every window full waits too.
  bool wait = !waitq_.empty();
  int posted = 0;
  for (std::uint32_t s = 0; s < nsl && k.data_left > 0; ++s) {
    if (k.data_failed) {  // a slice could not be posted: the key is a miss, post nothing more of it
      k.sl[s].st = FKey::Slice::St::Done;
      slice_finished(j, i, false);
      continue;
    }
    if (!wait) {
      const Post p = post_slice(j, i, s);
      if (p == Post::Posted) {
        ++posted;
        continue;
      }
      if (p == Post::Failed) {
        k.sl[s].st = FKey::Slice::St::Done;
        slice_finished(j, i, false);
        continue;
      }
      wait = true;  // Busy
    }
    waitq_.push_back(WaitRef{j.id, i, s});
  }
  if (nsl > 1 && posted > 0) mx_.fetch_slices->inc(static_cast<std::uint64_t>(posted));
}

ClientCore::Post ClientCore::post_slice(Job& j, std::size_t i, std::uint32_t s) {
  FKey& k = j.fk[i];
  FKey::Slice& sl = k.sl[s];
  // A stopped job, or one whose session ended, posts nothing more (fetch_ep_ may be the NEXT session's endpoint).
  if (j.stop || seen_down_ != j.sess || !fetch_ep_ || !k.has_span || k.le.seg_id >= info_.segs.size()) return Post::Failed;
  const fabric::MemRegion& seg = info_.segs[k.le.seg_id];
  Status st = fetch_ep_->post_read({seg.rkey, reinterpret_cast<std::uint64_t>(seg.addr) + k.le.offset + sl.off, sl.len},
                                   {k.span.lkey, k.span.addr + sl.off, sl.len}, make_ftag(j.id, i, s, sl.attempt, kTagData));
  if (st) {
    sl.st = FKey::Slice::St::Posted;
    ++k.wr;
    ++reads_out_;
    return Post::Posted;
  }
  return read_refused(st);
}

// Busy (every fetch window or send queue full) waits; a full send queue (ResourceExhausted) with READs outstanding
// is backpressure too: a completion frees room and post_waiting() posts it. Anything else fails the slice.
ClientCore::Post ClientCore::read_refused(const Status& st) {
  if (st.error().code == ErrorCode::Busy) return Post::Busy;
  if (st.error().code == ErrorCode::ResourceExhausted && reads_out_ > 0) {
    port_.send_queue_full(fabric::EpClass::Fetch);
    return Post::Busy;
  }
  return Post::Failed;
}

ClientCore::Post ClientCore::post_seq(Job& j, std::size_t i) {
  FKey& k = j.fk[i];
  // The seq READ goes after the data READs completed (a block only mutates after its word does). info_.array may have
  // been replaced by a newer SEG_TABLE since fetch_start_key: re-check the slot against the CURRENT array.
  // A stopped job, or one whose session ended, posts nothing more: fetch_ep_ may already be the NEXT session's
  // endpoint (null-hooks reconnect), and the quarantine proof (force_fail) needs every op of the job on an endpoint of
  // session j.sess.
  if (j.stop || seen_down_ != j.sess || !k.has_seq || k.le.gen_slot >= info_.array.len / 8 || !fetch_ep_) return Post::Failed;
  Status ps = fetch_ep_->post_read({info_.array.rkey, reinterpret_cast<std::uint64_t>(info_.array.addr) + k.le.gen_slot * 8, 8},
                                   {k.seq.lkey, k.seq.addr, 8}, make_ftag(j.id, i, kSeqSlice, 0, kTagSeq));
  if (ps) {
    ++k.wr;
    ++reads_out_;
    k.seq_out = true;
    return Post::Posted;
  }
  return read_refused(ps);
}

// A payload slice is done for good. The last one opens the seq rule's gate (data_complete).
void ClientCore::slice_finished(Job& j, std::size_t i, bool ok) {
  FKey& k = j.fk[i];
  if (!ok) k.data_failed = true;
  if (k.data_left <= 0 || --k.data_left > 0) return;
  data_complete(j, i);
}

void ClientCore::data_complete(Job& j, std::size_t i) {
  FKey& k = j.fk[i];
  if (k.data_failed) {
    pipe_->on_landed(k.bid, 0, k.span.len);  // garbage in, tag check fails
    pipe_->on_seq(k.bid, false);
    return;
  }
  pipe_->on_landed(k.bid, 0, k.le.stored_len);
  k.t_dec = clock_.now(), k.has_dec = true;
  if (k.has_read) ClientMetrics::observe(mx_.fetch_s[ClientMetrics::kFRead], k.t_read, k.t_dec);
  const Post p = !waitq_.empty() ? Post::Busy : post_seq(j, i);
  if (p == Post::Failed) {
    pipe_->on_seq(k.bid, false);
  } else if (p == Post::Busy) {
    k.seq_queued = true;
    waitq_.push_back(WaitRef{j.id, i, kSeqSlice});
  }
}

// A slice whose own CQE reported an error or a flush may be sent again on another rail only while the
// re-sent slice is expected to finish (one RTT) before both the lease deadline and the job deadline; the port must
// still have a healthy rail (the failed rail is given up before its completions reach the core). A remote access
// error is not a rail fault: no re-issue.
bool ClientCore::may_reissue(const Job& j, const Status& st) const {
  if (j.stop || seen_down_ != j.sess || !fetch_ep_ || fetch_ep_->state() != fabric::EpState::Ready) return false;
  const ErrorCode c = st.error().code;
  if (c != ErrorCode::Aborted && c != ErrorCode::LinkDown && c != ErrorCode::Timeout) return false;
  const Nanos done_by = clock_.now() + j.rtt;
  return done_by < j.lease_deadline && done_by < j.deadline;
}

void ClientCore::fetch_on_cqe(Job& j, std::size_t i, std::uint32_t s, std::uint32_t attempt, bool is_seq, const Status& st) {
  FKey& k = j.fk[i];
  if (is_seq) {
    if (!k.seq_out) return;  // force_fail() abandoned it, or a duplicate completion
    k.seq_out = false;
    --k.wr;
    bool ok = false;
    if (st) {
      std::uint64_t w = 0;
      std::memcpy(&w, k.seq.addr, 8);
      ok = w == proto::pack_state_gen(proto::BlockState::Committed, k.le.gen);
    }
    pipe_->on_seq(k.bid, ok);
    return;
  }
  if (s >= k.sl.size()) return;
  FKey::Slice& sl = k.sl[s];
  // Not this slice's live WR: force_fail() abandoned it, or a duplicate completion of a WR it already replaced.
  if (sl.st != FKey::Slice::St::Posted || (sl.attempt & 3u) != attempt) return;
  --k.wr;
  if (st) {
    sl.st = FKey::Slice::St::Done;
    return slice_finished(j, i, true);
  }
  // Its own CQE is here (error or flush): nothing of this WR can land any more, so the slice may be sent again.
  if (sl.attempt < kMaxReissues && !k.data_failed && may_reissue(j, st)) {
    ++sl.attempt;
    sl.st = FKey::Slice::St::Queued;
    waitq_.push_back(WaitRef{j.id, i, s});
    ++reissued_;
    port_.slice_reissued();
    return;
  }
  sl.st = FKey::Slice::St::Done;
  slice_finished(j, i, false);
}

// Posts what waits for a fetch window, in order, until a window is full. Entries of stopped or finished jobs are
// settled here too (a slice that will never be posted is done; a seq READ that will never be posted is a miss).
void ClientCore::post_waiting() {
  bool busy = false;
  for (auto it = waitq_.begin(); it != waitq_.end();) {
    auto jt = jobs_.find(it->job);
    if (jt == jobs_.end() || it->key >= jt->second->fk.size()) {
      it = waitq_.erase(it);
      continue;
    }
    Job& j = *jt->second;
    FKey& k = j.fk[it->key];
    const bool dead = j.stop || seen_down_ != j.sess;
    if (it->slice == kSeqSlice) {
      if (!k.seq_queued) {
        it = waitq_.erase(it);
        continue;
      }
      const Post p = dead ? Post::Failed : busy ? Post::Busy : post_seq(j, it->key);
      if (p == Post::Busy) {
        busy = true;
        ++it;
        continue;
      }
      k.seq_queued = false;
      const std::size_t key = it->key;
      it = waitq_.erase(it);
      if (p == Post::Failed) pipe_->on_seq(k.bid, false);
      (void)key;
      continue;
    }
    if (it->slice >= k.sl.size() || k.sl[it->slice].st != FKey::Slice::St::Queued) {
      it = waitq_.erase(it);
      continue;
    }
    const std::uint32_t s = it->slice;
    const Post p = dead ? Post::Failed : busy ? Post::Busy : post_slice(j, it->key, s);
    if (p == Post::Busy) {
      busy = true;
      ++it;
      continue;
    }
    const std::size_t key = it->key;
    it = waitq_.erase(it);  // before slice_finished, which may queue the seq READ at the back
    if (p == Post::Failed) {
      k.sl[s].st = FKey::Slice::St::Done;
      slice_finished(j, key, false);
    } else if (k.sl.size() > 1) {
      mx_.fetch_slices->inc();
    }
  }
}

void ClientCore::free_span(const PoolSpan& s) {
  if (opts_.on_span_release) opts_.on_span_release(std::span<const std::byte>(s.addr, s.len));
  pool_->release(s);
}

void ClientCore::fetch_key_finished(Job& j, std::size_t i, FetchOutcome oc) {
  FKey& k = j.fk[i];
  k.pipe_pending = false;
  if (!k.final) {
    k.final = true;
    k.st = oc == FetchOutcome::Hit ? KeyStatus::Hit : KeyStatus::Miss;
    if (oc != FetchOutcome::Hit) zero(k.out);
    if (k.has_dec) ClientMetrics::observe(mx_.fetch_s[ClientMetrics::kFDecrypt], k.t_dec, clock_.now());
    if (oc == FetchOutcome::Hit) mx_.crypto_bytes[1]->inc(k.out.size());
    if (oc == FetchOutcome::MissSeq) mx_.validate_fail[0]->inc();
    if (oc == FetchOutcome::MissAead) mx_.aead_fail->inc();
    // Tampered block (AEAD miss): drop it server-side (spec 8.3). Best effort, no-op on loopback.
    if (oc == FetchOutcome::MissAead && port_.invalidate(j.scope, k.hash, k.le.gen)) mx_.invalidate_sent->inc();
  }
  if (k.wr == 0) {
    if (k.has_span) free_span(k.span), k.has_span = false;
    if (k.has_seq) free_span(k.seq), k.has_seq = false;
  }
}

// ---- store ------------------------------------------------------------------------

Ticket ClientCore::submit_store(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys,
                                std::span<const BufRef> bufs, Nanos deadline, Notify cb) {
  const std::size_t n = keys.size();
  sync_session();
  Job& j = new_job(kStore, deadline, std::move(cb), n);
  const Ticket tk = j.ticket;
  j.pk.resize(n);
  for (auto& s : j.status) s = KeyStatus::Aborted;
  const bool bad = n != bufs.size() || group >= sk.scopes.size() || !sk.keys;
  if (!bad) j.scope = to_store(sk.scopes[group]);
  for (std::size_t i = 0; i < n; ++i) {
    PKey& k = j.pk[i];
    if (bad) {
      k.final = true;
      continue;
    }
    k.pt = bufs[i].buf;
    auto h = sk.keys->key_hash(keys[i].raw);
    auto d = sk.keys->dek_for(keys[i].raw);
    auto lay = layout(k.pt.size(), opts_.segment_log2);
    if (!h || !d || !lay) {
      k.final = true;
      continue;
    }
    k.lay = *lay;
    k.dek.emplace(std::move(*d));
    k.meta = BlockMeta{sk.kver, sk.scopes[group], *h, k.pt.size(), opts_.segment_log2};
    k.pk.key = to_store(*h);
    if (!keys[i].parent_raw.empty()) {
      auto p = sk.keys->key_hash(keys[i].parent_raw);
      if (!p) {
        k.final = true;
        continue;
      }
      k.pk.parent = to_store(*p);
    }
    k.pk.chain_pos = keys[i].chain_pos;
    k.pk.stored_len = lay->stored_len;
  }
  job_tick(j);
  return tk;
}

void ClientCore::put_begin_batch(Job& j) {
  // Gather up to max_put_batch usable keys starting at j.next.
  j.batch.clear();
  while (j.next < j.pk.size() && j.batch.size() < opts_.max_put_batch) {
    if (!j.pk[j.next].final) j.batch.push_back(j.next);
    ++j.next;
  }
  if (j.batch.empty()) return;
  store::PutBeginReq q;
  q.scope = j.scope;
  for (auto bi : j.batch) q.keys.push_back(j.pk[bi].pk);
  port_.set_op_deadline(j.deadline);
  j.ack = port_.put_begin(q);
  port_.set_op_deadline(Nanos::max());
  if (j.ack.status == store::BeginStatus::Refused) {
    if (j.ack.skip != store::BeginSkip::None) {
      // StaleEpoch / Draining is a per-key SKIP, not a failure and not an in-job retry.
      std::size_t n = j.batch.size();
      for (std::size_t i = j.next; i < j.pk.size(); ++i) n += j.pk[i].final ? 0 : 1;
      for (auto bi : j.batch) j.pk[bi].final = true, j.pk[bi].st = KeyStatus::Skipped;
      put_drop_rest(j, KeyStatus::Skipped);
      j.batch.clear();
      mx_.put_skipped[j.ack.skip == store::BeginSkip::StaleEpoch ? 0 : 1]->inc(n);
      return;
    }
    if (j.ack.retry_after_ms == 0) {
      // Retry 0 = do not retry: drop the whole store (spec 8.2).
      for (auto bi : j.batch) j.pk[bi].final = true, j.pk[bi].st = KeyStatus::Refused;
      put_drop_rest(j, KeyStatus::Refused);
      j.batch.clear();
      return;
    }
    j.phase = Job::Phase::Backoff;
    j.retry_at = clock_.now() + std::chrono::milliseconds(j.ack.retry_after_ms);
    return;
  }
  if (j.ack.status != store::BeginStatus::Ok || j.ack.entries.size() != j.batch.size()) {
    for (auto bi : j.batch) j.pk[bi].final = true, j.pk[bi].st = KeyStatus::Aborted;
    j.batch.clear();
    return;
  }
  j.batch_failed = false;
  for (std::size_t b = 0; b < j.batch.size(); ++b) {
    PKey& k = j.pk[j.batch[b]];
    if (!j.ack.entries[b].accept) {
      k.final = true;
      k.st = KeyStatus::Skipped;  // already stored (idempotent put), or throttled (below)
    } else {
      k.accepted = true;
    }
  }
  if (j.ack.retry_after_ms > 0) {
    // An Ok ack that carries retry_after_ms was cut by the put token buckets: the node admits keys in order, so the
    // keys it skipped after the last admitted one are the throttled ones (a skip before it is an idempotent re-put).
    std::size_t last = 0;  // one past the last accepted entry
    for (std::size_t b = 0; b < j.batch.size(); ++b)
      if (j.ack.entries[b].accept) last = b + 1;
    const auto n = static_cast<std::uint64_t>(j.batch.size() - last);
    if (n) mx_.put_skipped[2]->inc(n);  // reason "throttled"
  }
  if (j.ack.put_id == 0) {
    j.batch.clear();
    return;
  }
  j.phase = Job::Phase::Writing;
  j.t_write = clock_.now();
  // Protocol check on server-supplied extents (index, offset, length) before any write.
  for (std::size_t b = 0; b < j.batch.size(); ++b) {
    const store::BeginEntry& e = j.ack.entries[b];
    if (!e.accept) continue;
    const std::uint64_t len = j.pk[j.batch[b]].lay.stored_len;
    if (e.mr_index >= j.ack.mr.size() || e.offset > j.ack.mr[e.mr_index].len ||
        len > j.ack.mr[e.mr_index].len - e.offset) {
      j.batch_failed = true;
      break;
    }
  }
  bool wait_write = false;
  for (std::size_t b = 0; b < j.batch.size(); ++b) {
    const std::size_t ki = j.batch[b];
    PKey& k = j.pk[ki];
    if (!k.accepted) continue;
    if (j.batch_failed) {
      k.accepted = false;
      continue;
    }
    auto sp = pool_->acquire(sub_, k.lay.stored_len);
    if (!sp) {
      j.batch_failed = true;
      k.accepted = false;
      continue;
    }
    k.span = *sp, k.has_span = true;
    std::span<std::byte> blk(k.span.addr, k.lay.stored_len);
    const Nanos te = clock_.now();
    auto sc = seal_begin(*k.dek, k.meta, salts_, blk.first(64));
    bool ok = static_cast<bool>(sc);
    for (std::uint32_t s = 0; ok && s < k.lay.segments; ++s) {
      std::uint32_t crc = 0;
      ok = static_cast<bool>(seal_segment(*gcm_, *sc, s, k.pt.subspan(std::uint64_t{s} << opts_.segment_log2, k.lay.pt_len(s)),
                                          blk, &crc));
    }
    if (!ok) {
      j.batch_failed = true;
      k.accepted = false;
      continue;
    }
    ClientMetrics::observe(mx_.put_s[ClientMetrics::kPEncrypt], te, clock_.now());
    mx_.crypto_bytes[0]->inc(k.pt.size());
    k.crc = crc32c(blk);
    // Once one WRITE waits for send-queue room, the rest of the batch waits behind it (in batch order).
    if (wait_write || put_post_write(j, b) == Post::Busy) k.write_wait = wait_write = true;
  }
}

ClientCore::Post ClientCore::put_post_write(Job& j, std::size_t b) {
  const std::size_t ki = j.batch[b];
  PKey& k = j.pk[ki];
  const store::BeginEntry& e = j.ack.entries[b];
  const store::MrRef& m = j.ack.mr[e.mr_index];
  Status st = ingest_ep_ ? ingest_ep_->post_write({k.span.lkey, k.span.addr, static_cast<std::uint32_t>(k.lay.stored_len)},
                                                  {m.rkey, m.addr + e.offset, static_cast<std::uint32_t>(k.lay.stored_len)},
                                                  make_tag(j.id, ki, kTagWrite))
                         : Status(Error{ErrorCode::Aborted, "client: session down"});
  if (st) {
    ++k.wr;
    ++writes_out_;
    return Post::Posted;
  }
  // Busy (the mux's send-queue cap) or a full send queue with WRITEs outstanding: wait for a completion.
  if (st.error().code == ErrorCode::Busy) return Post::Busy;
  if (st.error().code == ErrorCode::ResourceExhausted && writes_out_ > 0) {
    port_.send_queue_full(fabric::EpClass::Ingest);
    return Post::Busy;
  }
  j.batch_failed = true;
  k.accepted = false;
  return Post::Failed;
}

// Posts the batch's waiting WRITEs in order until one still finds the send queue full. A stopped job, a failed
// batch or a session that ended posts none of them (the key is not written; the batch is cancelled as before).
void ClientCore::put_post_waiting(Job& j) {
  for (std::size_t b = 0; b < j.batch.size(); ++b) {
    PKey& k = j.pk[j.batch[b]];
    if (!k.write_wait) continue;
    if (j.stop || j.batch_failed || j.sess != seen_down_) {
      k.write_wait = false;
      k.accepted = false;
      if (!j.stop) j.batch_failed = true;
      continue;
    }
    if (put_post_write(j, b) == Post::Busy) return;
    k.write_wait = false;
  }
}

void ClientCore::put_on_write(Job& j, std::size_t i, const Status& st) {
  if (j.pk[i].wr == 0) return;  // force_fail() abandoned this op: a late completion is ignored
  --j.pk[i].wr;
  if (!st) j.batch_failed = true;
}

void ClientCore::put_commit_batch(Job& j) {
  store::PutCommitReq q;
  q.put_id = j.ack.put_id;
  for (std::size_t b = 0; b < j.batch.size(); ++b) {
    const PKey& k = j.pk[j.batch[b]];
    if (j.ack.entries[b].accept) q.e.push_back({static_cast<std::uint16_t>(b), k.crc, k.lay.stored_len});
  }
  j.phase = Job::Phase::Committing;
  j.commit_ready = false;
  j.t_commit = clock_.now();
  ClientMetrics::observe(mx_.put_s[ClientMetrics::kPWrite], j.t_write, j.t_commit);
  // The callback holds ids, never a Job*: it is a no-op once the job is gone, the batch moved
  // on, or the commit was abandoned (commit_gen bumped).
  const std::uint64_t jid = j.id, gen = ++j.commit_gen;
  port_.put_commit(q, [this, jid, gen](const store::PutDoneResult& r) {
    auto it = jobs_.find(jid);
    if (it == jobs_.end()) return;
    Job& jj = *it->second;
    if (jj.commit_gen != gen || jj.phase != Job::Phase::Committing) return;
    jj.commit_result = r;
    jj.commit_ready = true;
  });
}

void ClientCore::put_free_spans(Job& j) {
  for (auto bi : j.batch) {
    PKey& k = j.pk[bi];
    if (k.has_span) free_span(k.span), k.has_span = false;
  }
}

void ClientCore::put_finish_batch(Job& j, const store::PutDoneResult& r) {
  ClientMetrics::observe(mx_.put_s[ClientMetrics::kPCommit], j.t_commit, clock_.now());
  for (std::size_t b = 0; b < j.batch.size(); ++b) {
    PKey& k = j.pk[j.batch[b]];
    if (!j.ack.entries[b].accept || k.final) continue;
    k.final = true;
    k.st = KeyStatus::Aborted;
    if (r.status == store::CommitStatus::Ok)
      for (const auto& de : r.e)
        if (de.key_index == b && de.status == static_cast<std::uint8_t>(proto::DoneStatus::Committed))
          k.st = KeyStatus::Committed;
  }
  put_free_spans(j);
  j.batch.clear();
  j.phase = Job::Phase::Idle;
}

void ClientCore::put_drop_rest(Job& j, KeyStatus st) {
  for (std::size_t i = j.next; i < j.pk.size(); ++i)
    if (!j.pk[i].final) j.pk[i].final = true, j.pk[i].st = st;
  j.next = j.pk.size();
  j.dropped = true;
}

// ---- probe / cancel ----------------------------------------------------------------

Ticket ClientCore::probe(const ScopeKeys& sk, std::uint32_t group, std::span<const KeyRef> keys, Nanos deadline,
                         ResultFn done) {
  sync_session();
  Ticket t{next_job_++};
  std::vector<KeyStatus> st(keys.size(), KeyStatus::Miss);
  std::size_t n_err = 0;
  if (group < sk.scopes.size() && sk.keys) {
    store::LookupReq q;
    q.scope = to_store(sk.scopes[group]);
    std::vector<std::size_t> idx;
    for (std::size_t i = 0; i < keys.size(); ++i) {
      auto h = sk.keys->key_hash(keys[i].raw);
      if (!h) continue;
      q.keys.push_back(to_store(*h));
      idx.push_back(i);
    }
    if (!idx.empty()) {
      SplitAck ack = lookup_split(q, false, deadline);  // presence only: no lease is taken
      for (std::size_t m = 0; m < idx.size() && m < ack.entries.size(); ++m)
        if (ack.entries[m].hit) st[idx[m]] = KeyStatus::Hit;
      // Keys the server did not answer (failed or short reply) count as errors.
      n_err = idx.size() - ack.answered;
    }
  }
  std::size_t n_hit = 0;
  for (auto s : st) n_hit += s == KeyStatus::Hit;
  mx_.lookup_keys[ClientMetrics::kFHit]->inc(n_hit);
  mx_.lookup_keys[ClientMetrics::kFError]->inc(n_err);
  mx_.lookup_keys[ClientMetrics::kFMiss]->inc(keys.size() - n_hit - n_err);
  if (done) done(t, st);
  return t;
}

void ClientCore::cancel(Ticket t) {
  auto it = jobs_.find(t.id);
  if (it == jobs_.end()) return;
  Job& j = *it->second;
  if (j.stop) return;
  j.stop = true;
  j.cancelled = true;
  if (j.kind == kFetch) {
    for (std::size_t i = 0; i < j.fk.size(); ++i)
      if (!j.fk[i].final) j.fk[i].final = true, j.fk[i].st = KeyStatus::Aborted;
  } else {
    for (auto& k : j.pk)
      if (!k.final) k.final = true, k.st = KeyStatus::Aborted;
    j.next = j.pk.size();
  }
  job_tick(j);
}

std::size_t ClientCore::pool_bytes_total() const { return (opts_.pool_bytes + kPoolAlign - 1) / kPoolAlign * kPoolAlign; }

std::size_t ClientCore::outstanding_ops(Ticket t) const {
  auto it = jobs_.find(t.id);
  if (it == jobs_.end()) return 0;
  const Job& j = *it->second;
  std::size_t n = 0;
  if (j.kind == kFetch) {
    for (const auto& k : j.fk) n += (k.wr != 0 || k.pipe_pending) ? 1 : 0;
  } else {
    for (const auto& k : j.pk) n += k.wr != 0 ? 1 : 0;
  }
  return n;
}

// Last resort: the job's RDMA completions never came (a lost CQE, a wedged QP). Fail the job's keys
// as Timeout, stop waiting for the ops and finish the job. Ops handed to the decrypt pipeline are told
// their READs failed and finish by themselves (the caller's buffer is zeroed when the job ends).
//
// Quarantine, and why no DMA can ever land in a reused span. An abandoned op is a WR still posted
// on endpoint E of session S (down count S while E was live; Job::sess). The WR's pool span goes to
// quarantine_ with reaped_at = S + 1 and is given back only when port_.session_reaped(S + 1):
//   1. force_fail marks E dead (endpoint_wedged) unless S already ended, so the session goes Down:
//      go_down lists S + 1 as unreaped, bumps the down count to S + 1 and, in the same call, aborts every
//      endpoint (E included; a QP in Error state flushes its WRs and starts no new DMA for them), tagging
//      each with S + 1. Every op of the job is on E (nothing is posted once the session ended).
//   2. reap() releases an aborted endpoint only once it is drained (every posted WR has completed or
//      been flushed: none can DMA any more) and the fabric gave it back (the QP is destroyed).
//   3. session_reaped(S + 1) becomes true only after a reap() found no endpoint tagged S + 1 left, so E
//      was released (2) after its abort (1).
//   4. release_quarantine() runs on this thread after that answer, so the span goes back to the pool,
//      and can be handed to a new op, strictly after E's last possible DMA. A lost flush keeps E undrained
//      and S + 1's spans quarantined: a leak (miracache_client_quarantined_bytes), never corruption.
//      only S + 1's; a later trip (another session end) gets its spans back as usual.
// Spans of completed WRITEs and of keys with nothing outstanding are released at once.
std::size_t ClientCore::force_fail(Ticket t) {
  auto it = jobs_.find(t.id);
  if (it == jobs_.end()) return 0;
  Job& j = *it->second;
  if (!j.stop) {
    j.stop = true;
    if (j.kind == kFetch) {
      for (auto& k : j.fk)
        if (!k.final) k.final = true, k.st = KeyStatus::Timeout;
    } else {
      for (auto& k : j.pk)
        if (!k.final) k.final = true, k.st = KeyStatus::Timeout;
      j.next = j.pk.size();
    }
  }
  report_done(j);
  const std::uint64_t reaped_at = j.sess + 1, jid = j.id;
  std::size_t n = 0;
  if (j.kind == kFetch) {
    for (auto& k : j.fk)
      if (k.wr != 0) {
        k.wr = 0;  // a late completion is ignored (fetch_on_cqe: no slice is Posted, seq_out is false)
        for (auto& s : k.sl) s.st = FKey::Slice::St::Done;  // Queued slices are dropped too
        k.data_left = 0;
        k.seq_out = k.seq_queued = false;
        if (k.has_span) quarantine(k.span, reaped_at, jid), k.has_span = false;
        if (k.has_seq) quarantine(k.seq, reaped_at, jid), k.has_seq = false;
        ++n;
        // The decrypt task waits for the READs: tell it they failed (a miss), like a failed post_read.
        // It ends through the usual queue on the next pump and the job is released then.
        if (k.pipe_pending) {
          pipe_->on_landed(k.bid, 0, k.span.len);
          pipe_->on_seq(k.bid, false);
        }
      }
  } else {
    for (auto& k : j.pk) {
      if (k.wr != 0) {
        k.wr = 0;  // a late completion only decrements wr: put_on_write is never reached (job gone or wr 0 guard)
        if (k.has_span) quarantine(k.span, reaped_at, jid), k.has_span = false;
        ++n;
      } else if (k.has_span) {
        free_span(k.span), k.has_span = false;  // This WRITE completed; nothing reads the span
      }
    }
    // The server still holds the put: cancel it, best effort. with an abandoned WRITE (n > 0)
    // the ingest endpoint is aborted right below, which usually flushes this SEND before it leaves, so
    // the put TTL is what frees the put then. Committing is not reached here in practice (job_tick
    // already cancels a stopped Committing job, and the pump runs before the watchdog force-fails).
    if ((j.phase == Job::Phase::Writing || j.phase == Job::Phase::Committing) && j.ack.put_id != 0)
      port_.put_cancel(j.ack.put_id, [](const store::PutDoneResult&) {});
    ++j.commit_gen;  // a PUT_DONE callback that arrives later is stale
    j.batch.clear();
    j.phase = Job::Phase::Idle;
  }
  if (n > 0) {
    mx_.watchdog_trips->inc();  // A trip counts only when something was abandoned
    // The endpoint lost a completion; while its session is still the live one, take it down.
    if (port_.session_down_count() == j.sess)
      port_.endpoint_wedged(j.kind == kFetch ? fabric::EpClass::Fetch : fabric::EpClass::Ingest);
  }
  finish_if_drained(j);  // may erase the job
  return n;
}

void ClientCore::quarantine(const PoolSpan& s, std::uint64_t reaped_at, std::uint64_t job) {
  quarantine_.push_back(Quarantined{s, reaped_at, job});
  quarantined_bytes_ += pool_bytes(s);
  mx_.quarantined->set(static_cast<std::int64_t>(quarantined_bytes_));
}

void ClientCore::release_quarantine() {
  bool changed = false;
  for (auto it = quarantine_.begin(); it != quarantine_.end();) {
    if (!jobs_.count(it->job) && port_.session_reaped(it->reaped_at)) {
      free_span(it->span);
      quarantined_bytes_ -= pool_bytes(it->span);
      it = quarantine_.erase(it);
      changed = true;
    } else {
      ++it;
    }
  }
  if (changed) mx_.quarantined->set(static_cast<std::int64_t>(quarantined_bytes_));
}

std::vector<std::span<std::byte>> ClientCore::quarantined_spans() const {
  std::vector<std::span<std::byte>> v;
  for (const auto& q : quarantine_) v.emplace_back(q.span.addr, q.span.len);
  return v;
}

// ---- progress ----------------------------------------------------------------------

void ClientCore::handle_cqe(const fabric::Completion& c) {
  if (!c.is_recv) {
    if (c.op == fabric::CompletionOp::CqError) mx_.rdma[4]->inc();
    else if (!c.status) mx_.rdma[ClientMetrics::rdma_kind(c.status.error().code)]->inc();
  }
  if (c.is_recv || c.op == fabric::CompletionOp::CqError) return;
  if (c.op == fabric::CompletionOp::Read && reads_out_ > 0) --reads_out_;  // Flushes too; stale ones saturate
  if (c.op == fabric::CompletionOp::Write && writes_out_ > 0) --writes_out_;
  if (opts_.on_cqe) opts_.on_cqe(c);  // Test hook (sim audit): the core has this completion now
  const std::uint64_t jid = c.tag >> 32;
  const Tag t = static_cast<Tag>(c.tag & 3);
  auto it = jobs_.find(jid);
  if (it == jobs_.end()) return;
  Job& j = *it->second;
  if (j.kind == kFetch && t != kTagWrite) {
    const std::size_t key = (c.tag >> 14) & (kMaxFetchKeys - 1);
    const auto slice = static_cast<std::uint32_t>((c.tag >> 4) & 0x3ff), attempt = static_cast<std::uint32_t>((c.tag >> 2) & 3);
    if (key < j.fk.size()) fetch_on_cqe(j, key, slice, attempt, t == kTagSeq, c.status);
  } else if (j.kind == kStore && t == kTagWrite) {
    const std::size_t key = (c.tag >> 2) & 0x3fffffff;
    if (key < j.pk.size()) put_on_write(j, key, c.status);
  }
}

std::optional<FetchTagInfo> ClientCore::fetch_tag(std::uint64_t tag) {
  const Tag t = static_cast<Tag>(tag & 3);
  if (t != kTagData && t != kTagSeq) return std::nullopt;
  return FetchTagInfo{tag >> 14, t == kTagSeq};  // job and key: one block of one job
}

bool ClientCore::all_final(const Job& j) const {
  if (j.kind == kFetch) {
    for (const auto& k : j.fk)
      if (!k.final) return false;
  } else {
    for (const auto& k : j.pk)
      if (!k.final) return false;
  }
  return true;
}

void ClientCore::report_done(Job& j) {
  if (j.done_reported) return;
  j.done_reported = true;
  const Nanos now = clock_.now();
  if (j.kind == kFetch) {
    for (std::size_t i = 0; i < j.fk.size(); ++i) {
      const KeyStatus s = j.status[i] = j.fk[i].st;
      const int r = s == KeyStatus::Hit ? ClientMetrics::kFHit
                    : s == KeyStatus::Miss ? ClientMetrics::kFMiss : ClientMetrics::kFError;
      mx_.fetch_ops[r]->inc();
      mx_.fetch_bytes[r]->inc(j.fk[i].out.size());
    }
    ClientMetrics::observe(mx_.fetch_s[ClientMetrics::kFTotal], j.t0, now);
  } else {
    // The node left the membership (GOAWAY Epoch) while the store was on it (a PUT_BEGIN, write or commit
    // the session loss cut short): nothing was stored, and that is a skip, not a failure. Only what
    // the session loss caused; a Refused the node ANSWERED (e.g. "parent unknown") stays Refused, so the client can
    // fall through to the previous set.
    if (port_.removed_from_membership()) {
      std::size_t n = 0;
      for (auto& k : j.pk)
        if ((k.st == KeyStatus::Refused && k.cut) || k.st == KeyStatus::Aborted) k.st = KeyStatus::Skipped, ++n;
      if (n) mx_.put_skipped[1]->inc(n);  // reason "draining"
    }
    for (std::size_t i = 0; i < j.pk.size(); ++i) {
      const KeyStatus s = j.status[i] = j.pk[i].st;
      const int r = s == KeyStatus::Committed ? ClientMetrics::kPCommitted
                    : s == KeyStatus::Skipped ? ClientMetrics::kPSkipped
                    : s == KeyStatus::Refused ? ClientMetrics::kPRefused
                    : s == KeyStatus::Aborted ? ClientMetrics::kPAborted : ClientMetrics::kPError;
      mx_.put_ops[r]->inc();
      mx_.put_bytes[r]->inc(j.pk[i].pt.size());
    }
    ClientMetrics::observe(mx_.put_s[ClientMetrics::kPTotal], j.t0, now);
  }
  if (j.cb.done) j.cb.done(j.ticket, j.status);
}

void ClientCore::finish_if_drained(Job& j) {
  // Drained = no RDMA op, pipeline task or put phase still touches the caller's buffers.
  if (j.kind == kFetch) {
    for (const auto& k : j.fk)
      if (k.wr != 0 || k.pipe_pending) return;
  } else {
    if (j.phase != Job::Phase::Idle) return;
    for (const auto& k : j.pk)
      if (k.wr != 0) return;
  }
  if (!j.stop && !all_final(j)) return;
  if (j.stop) {
    if (j.kind == kFetch)
      for (auto& k : j.fk) {
        if (k.st != KeyStatus::Hit) zero(k.out);
        if (k.has_span) free_span(k.span), k.has_span = false;
        if (k.has_seq) free_span(k.seq), k.has_seq = false;
      }
  }
  report_done(j);  // no-op unless this is the first report (cancel defers it to here)
  for (auto l : j.leases) (void)port_.release(l);
  j.leases.clear();
  if (j.cb.released) j.cb.released(j.ticket);
  mx_.inflight[j.kind == kFetch ? 0 : 1]->add(-1);
  jobs_.erase(j.id);
}

void ClientCore::job_tick(Job& j) {
  const Nanos now = clock_.now();
  if (!j.stop && now >= j.deadline && !all_final(j)) {
    j.stop = true;
    if (j.kind == kFetch) {
      for (auto& k : j.fk)
        if (!k.final) k.final = true, k.st = KeyStatus::Timeout;
    } else {
      for (auto& k : j.pk)
        if (!k.final) k.final = true, k.st = KeyStatus::Timeout;
      j.next = j.pk.size();
    }
    report_done(j);  // timeout: report now, release after the drain
  }
  if (j.kind == kFetch) {
    if (!j.stop && !j.leases.empty() && now - j.last_renew >= opts_.renew_every) {
      for (auto l : j.leases) (void)port_.renew(l);  // fire-and-forget on the wire; failure is harmless: the seq check rejects stale reads
      j.last_renew = now;
    }
  } else {
    for (int guard = 0; guard < 1000; ++guard) {
      using P = Job::Phase;
      if (j.phase == P::Writing) put_post_waiting(j);
      bool writes_out = false;
      for (const auto& k : j.pk) writes_out |= k.wr != 0 || k.write_wait;
      if (j.phase == P::Writing && !writes_out) {
        if (j.stop || j.batch_failed) {
          port_.put_cancel(j.ack.put_id, [](const store::PutDoneResult&) {});
          // Every non-final key of the batch (accepted or the one that failed locally).
          for (auto bi : j.batch) {
            PKey& k = j.pk[bi];
            if (!k.final) k.final = true, k.st = KeyStatus::Aborted;
          }
          put_free_spans(j);
          j.batch.clear();
          j.phase = P::Idle;
          if (j.batch_failed) put_drop_rest(j, KeyStatus::Aborted);
          j.batch_failed = false;
        } else {
          put_commit_batch(j);
        }
        continue;
      }
      if (j.phase == P::Committing && j.commit_ready) {
        put_finish_batch(j, j.commit_result);
        continue;
      }
      if (j.phase == P::Committing && j.stop) {
        // Deadline or cancel while PUT_DONE is outstanding (it may never come): abandon the
        // commit. The server frees the put (cancel during digest); our spans are no longer read.
        ++j.commit_gen;
        port_.put_cancel(j.ack.put_id, [](const store::PutDoneResult&) {});
        for (auto bi : j.batch) {
          PKey& k = j.pk[bi];
          if (!k.final) k.final = true, k.st = KeyStatus::Aborted;
        }
        put_free_spans(j);
        j.batch.clear();
        j.phase = P::Idle;
        continue;
      }
      if (j.phase == P::Backoff && j.stop) {
        j.phase = P::Idle;
        j.batch.clear();
        continue;
      }
      if (j.phase == P::Backoff && now >= j.retry_at) {
        j.phase = P::Idle;
        j.next = j.batch.empty() ? j.next : j.batch.front();  // retry the same batch
        j.batch.clear();
        continue;
      }
      if (j.phase == P::Idle && !j.stop && j.next < j.pk.size()) {
        std::size_t before = j.next;
        put_begin_batch(j);
        if (j.phase != P::Idle || j.next != before) continue;
      }
      break;
    }
  }
  if (!j.stop && all_final(j)) {
    bool quiet = true;
    if (j.kind == kStore) quiet = j.phase == Job::Phase::Idle;
    if (quiet) report_done(j);
  }
  finish_if_drained(j);
}

bool ClientCore::pump() {
  bool progress = false;
  sync_session();
  (void)port_.refresh_info(info_);  // wire port: the segment table can grow after hello()
  // A confirmed RENEW moves its job's re-issue deadline forward (never back).
  port_.take_renewed(renewed_);
  for (const auto& rn : renewed_) {
    for (auto& [id, jp] : jobs_) {
      Job& j = *jp;
      if (j.kind != kFetch || j.lease_until.size() != j.leases.size()) continue;
      auto at = std::find(j.leases.begin(), j.leases.end(), rn.lease);
      if (at == j.leases.end()) continue;
      Nanos& u = j.lease_until[static_cast<std::size_t>(at - j.leases.begin())];
      u = std::max(u, rn.until);
      j.lease_deadline = *std::min_element(j.lease_until.begin(), j.lease_until.end()) - j.lease_guard;
      break;
    }
  }
  std::array<fabric::Completion, 64> out;
  for (;;) {
    std::size_t n = fab_.poll(out);
    // The port notices a dead session inside poll(): fail the jobs BEFORE the flush completions
    // are interpreted, so they end as MISS / Refused, not as per-op errors.
    sync_session();
    if (n == 0) break;
    progress = true;
    for (std::size_t i = 0; i < n; ++i) handle_cqe(out[i]);
  }
  if (!waitq_.empty()) {  // Completions freed window room (or settled re-issues): post what waits
    const std::size_t before = waitq_.size();
    post_waiting();
    progress |= waitq_.size() != before;
  }
  std::deque<std::tuple<std::uint64_t, std::size_t, FetchOutcome>> q;
  {
    std::lock_guard lk(qmu_);
    q.swap(fq_);
  }
  progress |= !q.empty();
  for (auto& [jid, i, oc] : q) {
    auto it = jobs_.find(jid);
    if (it != jobs_.end()) fetch_key_finished(*it->second, i, oc);
  }
  std::vector<std::uint64_t> ids;
  for (auto& [id, _] : jobs_) ids.push_back(id);
  for (auto id : ids) {
    auto it = jobs_.find(id);
    if (it != jobs_.end()) job_tick(*it->second);
  }
  if (!quarantine_.empty()) release_quarantine();
  return progress;
}

Status ClientCore::check_invariants() const {
  if (fetch_ep_ && ingest_ep_) {
    if (fetch_ep_->state() != fabric::EpState::Ready || ingest_ep_->state() != fabric::EpState::Ready)
      return Error{ErrorCode::Corrupt, "client: endpoint in error"};
  }  // else: session down / not re-bound yet (see sync_session)
  // Quarantined spans are held on purpose until their endpoints are reaped.
  if (jobs_.empty() && pool_->bytes_in_use() != quarantined_bytes_) return Error{ErrorCode::Corrupt, "client: pool span leaked"};
  return {};
}

}  // namespace miracache
