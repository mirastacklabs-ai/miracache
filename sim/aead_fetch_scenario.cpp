// SPDX-License-Identifier: Apache-2.0
// A1.5 S3 scenario: client READs pre-sealed blocks from a server MR into the landing pool
// over a sliced SimFabric (so a READ really lands slice by slice, out of order) and runs
// the decrypt pipeline. Without a nemesis every block must validate (exit criterion: zero
// validation failures). With a rogue writer scribbling the pool between slices and during
// decrypt (via ChunkHook) every case must classify Hit-with-exact-bytes, MissAead or
// MissSeq; a Hit with wrong bytes, or a non-Hit whose engine buffer is not zeroed, fails.
#include <array>
#include <cstring>
#include <vector>

#include "client/decrypt_pipeline.h"
#include "client/landing_pool.h"
#include "crypto/block_codec.h"
#include "fabric/sim/sim_fabric.h"
#include "scenario.h"
#include "sim_executor.h"

namespace miracache::sim {
namespace {

using namespace fabric;

constexpr std::size_t kBlocks = 4;
constexpr std::uint8_t kSegLog2 = 16;
constexpr std::uint32_t kSliceSize = 1024;  // small, so every READ tears across many slices

// Sim-only salt source: distinct, nonzero, driven by the scenario's Random. Never used
// outside the simulator (production salts come from OsNonceSource).
class SimNonceSource final : public NonceSource {
 public:
  explicit SimNonceSource(Random& r) : rng_(r) {}

 protected:
  Status fill(std::span<std::byte> out) override {
    for (auto& b : out) b = static_cast<std::byte>(rng_.next_u64());
    out[0] = std::byte{0x5a};  // never all-zero
    return {};
  }

 private:
  Random& rng_;
};

struct Blk {
  std::unique_ptr<Dek> dek;
  BlockMeta meta{};
  std::vector<std::byte> plain;
  std::uint64_t stored_len = 0, server_off = 0;
  PoolSpan span;
  std::vector<std::byte> engine;
  BlockId id = 0;
  bool started = false, done = false;
  FetchOutcome outcome = FetchOutcome::Hit;
};

struct Nemesis {
  Random* rng = nullptr;
  std::array<Blk, kBlocks>* blocks = nullptr;
  bool enabled = false;
  std::uint64_t scribbles = 0;

  void scribble() {
    if (!enabled) return;
    Blk& b = (*blocks)[rng->below(kBlocks)];
    if (!b.started || b.span.addr == nullptr) return;
    const std::uint64_t off = rng->below(b.stored_len);
    const std::uint64_t len = rng->between(1, std::min<std::uint64_t>(64, b.stored_len - off));
    for (std::uint64_t i = 0; i < len; ++i) b.span.addr[off + i] = static_cast<std::byte>(rng->next_u64());
    ++scribbles;
  }
};

void hook(void* arg, std::size_t) {
  auto* n = static_cast<Nemesis*>(arg);
  if (n->rng->chance(0.5)) n->scribble();
}

}  // namespace

AeadFetchResult run_aead_fetch(std::uint64_t seed, bool nemesis_on) {
  AeadFetchResult res;
  SimClock clock;
  SeededRandom net_rng(seed);
  SeededRandom work(seed ^ 0x51ed270b3f2a9c4dULL);
  SeededRandom exec_rng(seed ^ 0xa0761d6478bd642fULL);
  SeededRandom evil(seed ^ 0xe7037ed1a0b428dbULL);
  SimOptions opts;
  opts.slice_size = kSliceSize;
  opts.slice_window = Nanos{4000};
  SimNetwork net(clock, net_rng, FaultConfig{}, opts);
  SimFabric& cli = net.add_node(1);
  SimFabric& srv = net.add_node(2);
  ListenParams lp;
  lp.allow_unauthenticated_for_test = true;
  static_cast<void>(srv.listen([](Endpoint*) {}, lp));

  // Server: pre-sealed blocks, each with its own DEK.
  std::array<Blk, kBlocks> blocks;
  SimNonceSource ns(work);
  auto gcm = GcmCtx::create();
  if (!gcm) { res.ok = false; res.failure = "GcmCtx::create"; return res; }
  std::vector<std::byte> store;
  for (auto& b : blocks) {
    std::array<std::byte, 32> k;
    for (auto& x : k) x = static_cast<std::byte>(work.next_u64());
    b.dek = std::make_unique<Dek>(std::span<const std::byte, 32>(k));
    b.meta.kver = static_cast<std::uint32_t>(work.between(1, 1000));
    for (auto& x : b.meta.scope_id.b) x = static_cast<std::uint8_t>(work.next_u64());
    for (auto& x : b.meta.key_hash.b) x = static_cast<std::uint8_t>(work.next_u64());
    b.meta.plaintext_len = work.between(1, 150'000);
    b.meta.segment_log2 = kSegLog2;
    b.plain.resize(b.meta.plaintext_len);
    for (auto& x : b.plain) x = static_cast<std::byte>(work.next_u64());
    auto lay = layout(b.meta.plaintext_len, kSegLog2);
    if (!lay) { res.ok = false; res.failure = "layout"; return res; }
    b.stored_len = lay->stored_len;
    b.server_off = (store.size() + 4095) / 4096 * 4096;
    store.resize(b.server_off + b.stored_len);
    std::span<std::byte> blk(store.data() + b.server_off, b.stored_len);
    auto sc = seal_begin(*b.dek, b.meta, ns, blk);
    if (!sc) { res.ok = false; res.failure = "seal_begin"; return res; }
    for (std::uint32_t i = 0; i < lay->segments; ++i) {
      const std::uint64_t seg = std::uint64_t{1} << kSegLog2;
      std::uint32_t crc = 0;
      if (!seal_segment(*gcm, *sc, i, std::span<const std::byte>(b.plain).subspan(i * seg, lay->pt_len(i)),
                        blk, &crc)) {
        res.ok = false; res.failure = "seal_segment"; return res;
      }
    }
  }
  const MemRegion srv_mr = srv.reg(store, Access::RemoteRead).value();
  Endpoint* ep = cli.connect(Peer{2}).value();

  LandingPool pool(cli);
  const SubpoolKey key{2, 0};
  if (!pool.add_subpool(key, PdId{}, std::size_t{1} << 20)) { res.ok = false; res.failure = "add_subpool"; return res; }

  SimExecutor exec(net, exec_rng);
  DecryptPipeline pipe(exec, 4);
  Nemesis nem{&evil, &blocks, nemesis_on, 0};
  pipe.set_chunk_hook(&hook, &nem);

  std::size_t completed = 0;
  for (std::size_t i = 0; i < kBlocks; ++i) {
    Blk& b = blocks[i];
    auto span = pool.acquire(key, b.stored_len);
    if (!span) { res.ok = false; res.failure = "acquire"; return res; }
    b.span = *span;
    b.engine.assign(b.meta.plaintext_len, std::byte{0xEE});  // poison: must never survive a miss
    b.started = true;
    b.id = pipe.start(*b.dek, b.meta, b.span, b.engine, [&, i](FetchOutcome oc) {
      blocks[i].outcome = oc;
      blocks[i].done = true;
      ++completed;
    });
    const Nanos when{static_cast<std::int64_t>(work.below(40'000))};
    net.schedule(when, [&, i] {
      Blk& bb = blocks[i];
      const RemoteRef rr{srv_mr.rkey, reinterpret_cast<std::uint64_t>(store.data()) + bb.server_off,
                         static_cast<std::uint32_t>(bb.stored_len)};
      const LocalRef lr{bb.span.lkey, bb.span.addr, static_cast<std::uint32_t>(bb.stored_len)};
      if (!ep->post_read(rr, lr, i)) { res.ok = false; res.failure = "post_read"; }
    });
  }
  // Rogue writer: scribbles on the pool between slices, i.e. while READs are in flight.
  if (nemesis_on) {
    const auto n = evil.between(2, 24);
    for (std::uint64_t k = 0; k < n; ++k) {
      net.schedule(Nanos{static_cast<std::int64_t>(evil.below(90'000))}, [&] { nem.scribble(); });
    }
  }

  bool seq_bad_any = false;
  auto drain = [&] {
    std::array<Completion, 16> batch;
    while (const auto got = cli.poll(batch)) {
      for (std::size_t j = 0; j < got; ++j) {
        const Completion& c = batch[j];
        if (c.op != CompletionOp::Read) continue;
        Blk& b = blocks[c.tag];
        if (!c.status) {
          res.ok = false; res.failure = "READ failed with no faults injected";
          continue;
        }
        pipe.on_landed(b.id, 0, c.bytes);
        // The seq/version check is modelled as a verdict from the server-side writer: with
        // the nemesis a concurrent update can invalidate it.
        const bool seq_ok = !(nemesis_on && evil.chance(0.125));
        seq_bad_any |= !seq_ok;
        pipe.on_seq(b.id, seq_ok);
      }
    }
  };
  while (net.step()) drain();
  drain();
  while (net.step()) drain();

  for (std::size_t i = 0; i < kBlocks && res.failure.empty(); ++i) {
    Blk& b = blocks[i];
    if (!b.done) { res.failure = "pipeline never reported"; break; }
    net.trace(0xAE, i, static_cast<std::uint64_t>(b.outcome), b.engine.size());
    switch (b.outcome) {
      case FetchOutcome::Hit:
        ++res.hits;
        if (b.engine != b.plain) res.failure = "Hit with wrong bytes";
        break;
      case FetchOutcome::MissSeq:
      case FetchOutcome::MissAead: {
        (b.outcome == FetchOutcome::MissSeq ? res.miss_seq : res.miss_aead)++;
        if (!nemesis_on) {
          res.failure = "validation failure with no nemesis";
        } else {
          for (auto x : b.engine)
            if (x != std::byte{0}) { res.failure = "miss left unverified bytes in engine buffer"; break; }
        }
        break;
      }
    }
  }
  (void)seq_bad_any;
  // Spans are released only after the QP drained.
  for (auto& b : blocks) pool.release(b.span);
  if (!ep->drained() && res.failure.empty()) res.failure = "endpoint not drained";
  res.ok = res.ok && res.failure.empty();
  res.trace_hash = net.trace_hash();
  res.scribbles = nem.scribbles;
  return res;
}

}  // namespace miracache::sim
