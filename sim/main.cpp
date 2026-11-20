// SPDX-License-Identifier: Apache-2.0
// sim_runner: runs the two-node READ scenario over many seeds and asserts that
// each seed is deterministic (two runs, identical trace hash).
//   sim_runner --seeds N [--first S]    run seeds S..S+N-1 (N >= 1, S >= 1; S defaults to 1)
//   sim_runner --seed X                 reproduce one seed (X >= 1), printing its trace hash
//   sim_runner --aead-seeds N [--aead-first S]
//                                       AEAD fetch scenario over seeds S..S+N-1 (S defaults to 1), each with and
//                                       without a nemesis, each run twice (identical trace hash);
//                                       runs instead of the READ scenario unless --seeds/--seed is given
//   sim_runner --store-seeds N [--store-first S] [--store-replay M] [--store-full-every K] [--store-golden FILE]
//                                       Store scenario over seeds S..S+N-1 (S defaults to 1; the seeds <= M,
//                                       default 0, run twice for determinism: M is an absolute seed number, so shards
//                                       with S > M replay nothing); K = CRC sweep cadence (default every step).
//                                       The coverage-vacuity checks apply to a run of N >= 50 seeds; --store-shard (a slice
//                                       of a sharded sweep) waives only the union-only "peak > 4 puts" check below N = 200;
//                                       --store-require-peak enforces it at any N.
//                                       --store-stats FILE: after a passing sweep, write its seed range and counters there.
//   sim_runner --store-union N --store-stats-in FILE [--store-stats-in FILE ...]
//                                       the vacuity checks over the union of a sharded sweep's --store-stats files, whose
//                                       ranges must tile 1..N; decides as one process of N seeds would, plus the peak
//                                       check at any N (sim/CMakeLists.txt: the <sweep>_union test)
//   sim_runner --store-seed X           one store seed, run twice, prints its trace hash
//   sim_runner --store-seeds N --teeth NAME --expect-fail
//                                       NAME in no_fence|skip_seq|commit_before_digest|reuse_generation (needs the
//                                       teeth build); exits 0 only if some seed FAILS
//   sim_runner --membership-seeds N     Membership scenario (3 nodes, R = 1 and 2) over seeds 1..N; --membership-seed X reproduces one
//   sim_runner --golden FILE           also check pinned trace hashes; FILE has lines
//                                       "<seed> <16 hex digits>" ('#' starts a comment)
// Argument errors exit with status 2.
#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "scenario.h"
#include "util/buggify.h"
#include "util/log.h"

namespace {

// Strict unsigned parse: digits only (no sign, space or prefix), whole string consumed,
// no overflow.
bool parse_u64(const char* s, int base, std::uint64_t& out) {
  if (s == nullptr || *s == '\0' || !(std::isalnum(static_cast<unsigned char>(*s)))) return false;
  errno = 0;
  char* end = nullptr;
  const unsigned long long v = std::strtoull(s, &end, base);
  if (errno != 0 || end == s || *end != '\0') return false;
  out = v;
  return true;
}

bool run_seed(std::uint64_t seed, std::set<std::uint64_t>& hashes, std::uint64_t* hash_out = nullptr) {
  const auto first = miracache::sim::run_two_node_reads(seed);
  const auto replay = miracache::sim::run_two_node_reads(seed);
  if (!first.ok) {
    std::fprintf(stderr, "seed %llu: invariant violated: %s\n", (unsigned long long)seed, first.failure.c_str());
    return false;
  }
  if (first.trace_hash != replay.trace_hash || first.ok != replay.ok) {
    std::fprintf(stderr, "seed %llu: NON-DETERMINISTIC (%016llx vs %016llx)\n", (unsigned long long)seed,
                 (unsigned long long)first.trace_hash, (unsigned long long)replay.trace_hash);
    return false;
  }
  hashes.insert(first.trace_hash);
  if (hash_out != nullptr) *hash_out = first.trace_hash;
  return true;
}

// Returns the number of pinned seeds checked, or -1 on any mismatch / unreadable file.
long check_golden(const char* path) {
  std::ifstream f(path);
  if (!f) {
    std::fprintf(stderr, "cannot open golden file %s\n", path);
    return -1;
  }
  std::string line;
  long checked = 0, lineno = 0;
  while (std::getline(f, line)) {
    ++lineno;
    if (const auto hash = line.find('#'); hash != std::string::npos) line.erase(hash);
    std::istringstream is(line);
    std::string seed_s, hash_s, extra;
    if (!(is >> seed_s)) continue;  // blank
    std::uint64_t seed = 0, want = 0;
    if (!(is >> hash_s) || (is >> extra) || !parse_u64(seed_s.c_str(), 10, seed) || seed < 1 ||
        !parse_u64(hash_s.c_str(), 16, want)) {
      std::fprintf(stderr, "%s:%ld: malformed golden line\n", path, lineno);
      return -1;
    }
    std::set<std::uint64_t> unused;
    std::uint64_t got = 0;
    if (!run_seed(seed, unused, &got)) return -1;
    if (got != want) {
      std::fprintf(stderr,
                   "seed %llu: trace hash %016llx != pinned %016llx (%s:%ld).\n"
                   "If the change is intentional, re-record with: sim_runner --seed %llu\n",
                   (unsigned long long)seed, (unsigned long long)got, (unsigned long long)want, path, lineno,
                   (unsigned long long)seed);
      return -1;
    }
    ++checked;
  }
  if (checked == 0) {
    std::fprintf(stderr, "%s: no pinned seeds\n", path);
    return -1;
  }
  return checked;
}

// No-fault runs must validate every block; nemesis runs must never Hit with
// wrong bytes. Both must replay with an identical trace hash.
int run_aead(std::uint64_t first, std::uint64_t n) {
  std::uint64_t hits = 0, seq = 0, aead = 0, scribbles = 0, fails = 0;
  for (std::uint64_t seed = first; seed - first < n; ++seed) {
    for (int nem = 0; nem < 2; ++nem) {
      const auto a = miracache::sim::run_aead_fetch(seed, nem != 0);
      const auto b = miracache::sim::run_aead_fetch(seed, nem != 0);
      if (!a.ok || a.ok != b.ok || a.trace_hash != b.trace_hash) {
        std::fprintf(stderr, "aead seed %llu nemesis=%d: %s\n", (unsigned long long)seed, nem,
                     !a.ok ? a.failure.c_str() : "NON-DETERMINISTIC");
        ++fails;
        continue;
      }
      if (nem != 0) {
        hits += a.hits; seq += a.miss_seq; aead += a.miss_aead; scribbles += a.scribbles;
      } else if (a.hits == 0 || a.miss_seq != 0 || a.miss_aead != 0) {
        std::fprintf(stderr, "aead seed %llu: no-fault run had misses\n", (unsigned long long)seed);
        ++fails;
      }
    }
  }
  std::printf("sim aead: %llu seeds, %llu validation failures; nemesis: %llu Hit(exact) %llu MissSeq %llu MissAead (%llu scribbles)\n",
              (unsigned long long)n, (unsigned long long)fails, (unsigned long long)hits,
              (unsigned long long)seq, (unsigned long long)aead, (unsigned long long)scribbles);
  if (fails != 0) return 1;
  if (aead == 0) {  // teeth: the nemesis must actually corrupt something
    std::fprintf(stderr, "nemesis never produced a MissAead\n");
    return 1;
  }
  return 0;
}

// Store scenario. `golden`: pinned "<seed> <hash>" lines, run in addition to 1..n.
struct StoreOpts {
  std::uint64_t n = 0, replay = 0, single = 0, first = 1;
  std::uint32_t full_every = 1;
  const char* golden = nullptr;
  const char* teeth = nullptr;
  bool expect_fail = false;
  bool shard = false;  // this run is one slice of a sharded sweep (--store-shard)
  bool require_peak = false;  // --store-require-peak: fail unless some seed reached > 4 puts on one endpoint (any N)
  const char* stats_out = nullptr;      // --store-stats FILE: on success, write this run's seed range and counters there
  std::uint64_t union_n = 0;            // --store-union N: aggregate mode over seeds 1..N (no seeds are run)
  std::vector<const char*> stats_in;    // --store-stats-in FILE (repeated): the shards' --store-stats files
};

// One counter of ScenarioStats in a --store-stats file. `is_max`: the union takes the max (max_ep_puts), not the sum.
struct StatField {
  const char* name;
  std::uint64_t miracache::sim::ScenarioStats::*field;
  bool is_max;
};
using SS = miracache::sim::ScenarioStats;
constexpr StatField kStatFields[] = {
    {"puts", &SS::puts, false}, {"refused", &SS::refused, false}, {"commits", &SS::commits, false},
    {"aborted", &SS::aborted, false}, {"timeouts", &SS::timeouts, false}, {"writes_landed", &SS::writes_landed, false},
    {"writes_rejected", &SS::writes_rejected, false}, {"hits", &SS::hits, false}, {"misses", &SS::misses, false},
    {"fetch_hits", &SS::fetch_hits, false}, {"miss_seq", &SS::miss_seq, false}, {"miss_aead", &SS::miss_aead, false},
    {"invalidates", &SS::invalidates, false}, {"drops", &SS::drops, false}, {"ep_cap_hits", &SS::ep_cap_hits, false},
    {"lease_cap_hits", &SS::lease_cap_hits, false}, {"unknown_probes", &SS::unknown_probes, false},
    {"below_cap_checks", &SS::below_cap_checks, false}, {"max_ep_puts", &SS::max_ep_puts, true},
    {"crash_checks", &SS::crash_checks, false}, {"crash_adopted", &SS::crash_adopted, false},
};
// Every counter of ScenarioStats is in the table (a new field without a row fails to compile).
static_assert(sizeof(SS) == sizeof(std::uint64_t) * std::size(kStatFields),
              "ScenarioStats gained or lost a counter: update kStatFields");
constexpr const char* kStatsMagic = "miracache-store-stats 2";

// The identity of this sim_runner binary (device, inode, size, mtime of /proc/self/exe, FNV-1a), so
// sim_store_vacuity rejects a stats file a different (older) build wrote: e.g. `ctest -FA -R sim_store_vacuity` after a
// rebuild, which skips the shards and their clean step. 0 if the OS cannot say (then any file of a 0-stamp build matches).
std::uint64_t build_stamp() {
  struct stat sb{};
  if (::stat("/proc/self/exe", &sb) != 0) return 0;
  const std::uint64_t parts[] = {static_cast<std::uint64_t>(sb.st_dev), static_cast<std::uint64_t>(sb.st_ino),
                                 static_cast<std::uint64_t>(sb.st_size), static_cast<std::uint64_t>(sb.st_mtim.tv_sec),
                                 static_cast<std::uint64_t>(sb.st_mtim.tv_nsec)};
  std::uint64_t h = 1469598103934665603ull;
  for (std::uint64_t p : parts)
    for (int i = 0; i < 8; ++i) {
      h ^= (p >> (8 * i)) & 0xff;
      h *= 1099511628211ull;
    }
  return h;
}

// The coverage-vacuity checks of a store run over `n` seeds with counters `st` ("the sweep actually exercised X at least once").
// `peak_required`: the "peak > 4 puts on one endpoint" check applies at n >= 50; `require_peak`: it applies at any n.
// Used by a sweep process on its own seeds and by --store-union on the union of the shards' counters.
int store_vacuity(const SS& st, std::uint64_t n, bool peak_required, bool require_peak) {
  if (n >= 50 && (st.crash_checks == 0 || st.crash_adopted == 0)) {
    std::fprintf(stderr, "store scenario never adopted a block from a crash snapshot\n");
    return 1;
  }
  // The roomy-cap seeds must reach more than 4 concurrent puts on one endpoint, and the
  // below-cap oracle must have run.
  if (n >= 50 && ((peak_required && st.max_ep_puts <= 4) || st.below_cap_checks == 0)) {
    std::fprintf(stderr, "store scenario never had > 4 puts on one endpoint or never checked below the cap\n");
    return 1;
  }
  if (require_peak && st.max_ep_puts <= 4) {
    std::fprintf(stderr, "store scenario never had > 4 puts on one endpoint (--store-require-peak / --store-union)\n");
    return 1;
  }
  // Teeth for the harness itself: a run that never commits, rejects a stray write or misses
  // on the seq check proves nothing.
  if (n >= 50 && (st.commits == 0 || st.writes_rejected == 0 || st.fetch_hits == 0 || st.miss_seq == 0)) {
    std::fprintf(stderr, "store scenario is vacuous (commits/rejected writes/fetch hits/seq misses)\n");
    return 1;
  }
  if (n >= 50 && (st.ep_cap_hits == 0 || st.lease_cap_hits == 0 || st.unknown_probes == 0)) {
    std::fprintf(stderr, "store scenario never reached a limit (endpoint cap/lease cap/UnknownPut)\n");
    return 1;
  }
  return 0;
}

// --store-stats: written only after the whole run passed (the file is removed first), via a temp file and rename, so a
// present file always means "this seed range ran and passed".
bool write_store_stats(const char* path, std::uint64_t first, std::uint64_t n, const SS& st) {
  const std::string tmp = std::string(path) + ".tmp";
  {
    std::ofstream f(tmp, std::ios::trunc);
    if (!f) return false;
    f << kStatsMagic << "\nbuild " << build_stamp() << "\nfirst " << first << "\nn " << n << "\n";
    for (const auto& k : kStatFields) f << k.name << ' ' << st.*k.field << "\n";
    f.flush();
    if (!f) return false;
  }
  return std::rename(tmp.c_str(), path) == 0;
}

bool read_store_stats(const char* path, std::uint64_t& first, std::uint64_t& n, SS& st) {
  std::ifstream f(path);
  std::string line;
  if (!f || !std::getline(f, line) || line != kStatsMagic) return false;
  std::map<std::string, std::uint64_t> kv;
  while (std::getline(f, line)) {
    std::istringstream is(line);
    std::string key, val;
    std::uint64_t v = 0;
    if (!(is >> key >> val) || !parse_u64(val.c_str(), 10, v) || !kv.emplace(key, v).second) return false;
  }
  if (kv.size() != 3 + std::size(kStatFields) || !kv.count("build") || !kv.count("first") || !kv.count("n")) return false;
  if (kv["build"] != build_stamp()) {
    std::fprintf(stderr, "store union: %s was written by another sim_runner build (stale; re-run the shards)\n", path);
    return false;
  }
  first = kv["first"];
  n = kv["n"];
  for (const auto& k : kStatFields) {
    const auto it = kv.find(k.name);
    if (it == kv.end()) return false;
    st.*k.field = it->second;
  }
  return true;
}

// --store-union N --store-stats-in F...: the vacuity checks over the union of a sharded sweep. Every file must be present
// and well formed, and their seed ranges must tile 1..N exactly (no gap, no overlap), so a shard that did not run or a stale
// file from another sweep shape fails here. The checks then decide as the unsharded process of N seeds would, plus the
// peak check at any N (it is a union property: it replaced the sim_store_peak tests).
int run_store_union(const StoreOpts& o) {
  if (o.stats_in.empty()) {
    std::fprintf(stderr, "sim_runner: --store-union needs at least one --store-stats-in FILE\n");
    return 2;
  }
  SS total;
  std::vector<std::pair<std::uint64_t, std::uint64_t>> ranges;  // (first, n)
  for (const char* path : o.stats_in) {
    std::uint64_t first = 0, n = 0;
    SS st;
    if (!read_store_stats(path, first, n, st)) {
      std::fprintf(stderr, "store union: %s is missing or malformed (did its shard run and pass?)\n", path);
      return 1;
    }
    for (const auto& k : kStatFields)
      total.*k.field = k.is_max ? std::max(total.*k.field, st.*k.field) : total.*k.field + st.*k.field;
    ranges.emplace_back(first, n);
  }
  std::sort(ranges.begin(), ranges.end());
  std::uint64_t next = 1;
  for (const auto& [first, n] : ranges) {
    if (first != next || n == 0) {
      std::fprintf(stderr, "store union: shard seed ranges do not tile 1..%llu (expected first seed %llu, got %llu+%llu)\n",
                   (unsigned long long)o.union_n, (unsigned long long)next, (unsigned long long)first, (unsigned long long)n);
      return 1;
    }
    next = first + n;
  }
  if (next != o.union_n + 1) {
    std::fprintf(stderr, "store union: shards cover seeds 1..%llu, expected 1..%llu\n", (unsigned long long)(next - 1),
                 (unsigned long long)o.union_n);
    return 1;
  }
  std::printf("sim store union: %zu shards, seeds 1..%llu; %llu commits, writes %llu rejected, fetch %llu exact %llu miss_seq; "
              "%llu endpoint-cap %llu below-cap %llu lease-cap %llu UnknownPut; peak %llu puts on one endpoint; "
              "%llu crash snapshots, %llu adopted\n",
              ranges.size(), (unsigned long long)o.union_n, (unsigned long long)total.commits,
              (unsigned long long)total.writes_rejected, (unsigned long long)total.fetch_hits, (unsigned long long)total.miss_seq,
              (unsigned long long)total.ep_cap_hits, (unsigned long long)total.below_cap_checks,
              (unsigned long long)total.lease_cap_hits, (unsigned long long)total.unknown_probes,
              (unsigned long long)total.max_ep_puts, (unsigned long long)total.crash_checks, (unsigned long long)total.crash_adopted);
  if (o.union_n < 50) std::printf("sim store union: N = %llu < 50, only the peak check applies (as for one process of N seeds)\n",
                                  (unsigned long long)o.union_n);
  return store_vacuity(total, o.union_n, true, true);
}

bool store_seed(std::uint64_t seed, const StoreOpts& o, bool replay, std::uint64_t* hash,
                miracache::sim::ScenarioStats* st = nullptr, std::string* why = nullptr) {
  const auto a = miracache::sim::run_store_scenario(seed, o.full_every);
  if (!a.ok) {
    std::fprintf(stderr, "store seed %llu: %s\n", (unsigned long long)seed, a.failure.c_str());
    if (why != nullptr) *why = a.failure;
    return false;
  }
  if (replay) {
    const auto b = miracache::sim::run_store_scenario(seed, o.full_every);
    if (!b.ok || b.trace_hash != a.trace_hash) {
      std::fprintf(stderr, "store seed %llu: NON-DETERMINISTIC (%016llx vs %016llx)\n", (unsigned long long)seed,
                   (unsigned long long)a.trace_hash, (unsigned long long)b.trace_hash);
      return false;
    }
  }
  if (hash != nullptr) *hash = a.trace_hash;
  if (st != nullptr) {
    st->puts += a.stats.puts; st->refused += a.stats.refused; st->commits += a.stats.commits;
    st->aborted += a.stats.aborted; st->timeouts += a.stats.timeouts;
    st->writes_landed += a.stats.writes_landed; st->writes_rejected += a.stats.writes_rejected;
    st->hits += a.stats.hits; st->misses += a.stats.misses; st->fetch_hits += a.stats.fetch_hits;
    st->miss_seq += a.stats.miss_seq; st->miss_aead += a.stats.miss_aead;
    st->invalidates += a.stats.invalidates; st->drops += a.stats.drops;
    st->ep_cap_hits += a.stats.ep_cap_hits; st->lease_cap_hits += a.stats.lease_cap_hits;
    st->unknown_probes += a.stats.unknown_probes;
    st->below_cap_checks += a.stats.below_cap_checks;
    st->max_ep_puts = std::max(st->max_ep_puts, a.stats.max_ep_puts);
    st->crash_checks += a.stats.crash_checks;
    st->crash_adopted += a.stats.crash_adopted;
  }
  return true;
}

int run_store_body(const StoreOpts& o, SS& st) {
  using miracache::buggify::Teeth;
  // Each injected bug must be caught by the oracle aimed at it, not by any failure: the run
  // must fail with this substring in its first failure message.
  struct Tooth {
    const char* name;
    Teeth t;
    const char* expect;
  };
  static constexpr Tooth kTeeth[] = {
      {"no_fence", Teeth::NoFence, "orphan write MR"},
      {"skip_seq", Teeth::SkipSeq, "zombie state word"},
      {"commit_before_digest", Teeth::CommitBeforeDigest, "fence/digest hole"},
      {"reuse_generation", Teeth::ReuseGeneration, "GenerationsUnique"},
      {"endpoint_cap_lax", Teeth::EndpointCapLax, "PUT_BEGIN accepted with the endpoint at its cap"},
      {"lease_cap_lax", Teeth::LeaseCapLax, "lease cap: LOOKUP"},
      {"unknown_put_ok", Teeth::UnknownPutOk, "was not answered UnknownPut"},
      {"foreign_put_id", Teeth::ForeignPutId, "foreign put id was not answered UnknownPut"},
  };
  const Tooth* tooth = nullptr;
  if (o.teeth != nullptr) {
    for (const auto& k : kTeeth)
      if (!std::strcmp(o.teeth, k.name)) tooth = &k;
    if (tooth == nullptr) {
      std::fprintf(stderr, "sim_runner: unknown teeth variant: %s\n", o.teeth);
      return 2;
    }
    const Teeth t = tooth->t;
    if (!miracache::buggify::kTeethBuilt) {
      std::fprintf(stderr, "sim_runner: built without MIRACACHE_TEETH\n");
      return 2;
    }
    miracache::buggify::set_teeth(t);
  }
  if (o.single != 0) {
    std::uint64_t h = 0;
    if (!store_seed(o.single, o, true, &h)) return 1;
    std::printf("store seed %llu trace %016llx\n", (unsigned long long)o.single, (unsigned long long)h);
    return 0;
  }
  std::uint64_t failed_seed = 0;
  std::string why;
  for (std::uint64_t s = o.first; s - o.first < o.n; ++s)
    if (!store_seed(s, o, s <= o.replay, nullptr, &st, &why)) {
      failed_seed = s;
      break;
    }
  if (o.expect_fail) {  // teeth: the sim must catch the injected bug
    if (failed_seed == 0) {
      std::fprintf(stderr, "teeth %s: NOT detected in %llu seeds\n", o.teeth ? o.teeth : "?", (unsigned long long)o.n);
      return 1;
    }
    if (tooth == nullptr || why.find(tooth->expect) == std::string::npos) {
      std::fprintf(stderr, "teeth %s: seed %llu failed for another reason: \"%s\" (want \"%s\")\n", o.teeth ? o.teeth : "?",
                   (unsigned long long)failed_seed, why.c_str(), tooth ? tooth->expect : "a --teeth variant");
      return 1;
    }
    std::printf("teeth %s: detected at seed %llu (%s)\n", o.teeth, (unsigned long long)failed_seed, why.c_str());
    return 0;
  }
  if (failed_seed != 0) {
    std::fprintf(stderr, "reproduce: sim_runner --store-seed %llu\n", (unsigned long long)failed_seed);
    return 1;
  }
  std::printf("sim store: %llu seeds ok; %llu puts (%llu refused), %llu commits, %llu aborted, %llu timeouts; writes %llu landed %llu rejected; "
              "lookup %llu hit %llu miss; fetch %llu exact %llu miss_seq %llu miss_aead; %llu invalidates, %llu drops\n",
              (unsigned long long)o.n, (unsigned long long)st.puts, (unsigned long long)st.refused,
              (unsigned long long)st.commits, (unsigned long long)st.aborted, (unsigned long long)st.timeouts,
              (unsigned long long)st.writes_landed, (unsigned long long)st.writes_rejected, (unsigned long long)st.hits,
              (unsigned long long)st.misses, (unsigned long long)st.fetch_hits, (unsigned long long)st.miss_seq,
              (unsigned long long)st.miss_aead, (unsigned long long)st.invalidates, (unsigned long long)st.drops);
  std::printf("sim store limits: %llu endpoint-cap checks, %llu below-cap checks, %llu lease-cap checks, %llu UnknownPut probes; "
              "peak %llu puts on one endpoint\n",
              (unsigned long long)st.ep_cap_hits, (unsigned long long)st.below_cap_checks, (unsigned long long)st.lease_cap_hits,
              (unsigned long long)st.unknown_probes, (unsigned long long)st.max_ep_puts);
  std::printf("sim store crash snapshots: %llu re-opened and scanned, %llu blocks adopted\n",
              (unsigned long long)st.crash_checks, (unsigned long long)st.crash_adopted);
  // Peak > 4 is a union property (only seeds divisible by 6 reach it, and rarely): a --store-shard run of fewer than 200
  // seeds is a slice of the sweep and does not require it; the unsharded sweep and 200+ seed shards do. --store-require-peak
  // enforces it at any N; the sweep's --store-union test enforces it over all shards.
  const bool peak_required = !o.shard || o.n >= 200;
  if (const int rc = store_vacuity(st, o.n, peak_required, o.require_peak)) return rc;
  if (o.golden != nullptr) {
    std::ifstream f(o.golden);
    if (!f) {
      std::fprintf(stderr, "cannot open golden file %s\n", o.golden);
      return 1;
    }
    std::string line;
    long checked = 0;
    while (std::getline(f, line)) {
      if (const auto hash = line.find('#'); hash != std::string::npos) line.erase(hash);
      std::istringstream is(line);
      std::string seed_s, hash_s;
      if (!(is >> seed_s)) continue;
      std::uint64_t seed = 0, want = 0, got = 0;
      if (!(is >> hash_s) || !parse_u64(seed_s.c_str(), 10, seed) || !parse_u64(hash_s.c_str(), 16, want)) {
        std::fprintf(stderr, "%s: malformed golden line\n", o.golden);
        return 1;
      }
      if (!store_seed(seed, o, true, &got)) return 1;
      if (got != want) {
        std::fprintf(stderr, "store seed %llu: trace hash %016llx != pinned %016llx; re-record with: sim_runner --store-seed %llu\n",
                     (unsigned long long)seed, (unsigned long long)got, (unsigned long long)want, (unsigned long long)seed);
        return 1;
      }
      ++checked;
    }
    if (checked == 0) return 1;
    std::printf("sim store: %ld pinned golden traces match\n", checked);
  }
  return 0;
}

int run_store(const StoreOpts& o) {
  if (o.union_n != 0) return run_store_union(o);
  const bool sweep = o.single == 0 && !o.expect_fail;
  if (o.stats_out != nullptr) {
    if (!sweep) {
      std::fprintf(stderr, "sim_runner: --store-stats needs a --store-seeds sweep (not --store-seed or --expect-fail)\n");
      return 2;
    }
    std::remove(o.stats_out);  // a failed run must not leave a stale "passed" file behind
  }
  SS st;
  const int rc = run_store_body(o, st);
  if (rc == 0 && o.stats_out != nullptr && !write_store_stats(o.stats_out, o.first, o.n, st)) {
    std::fprintf(stderr, "sim_runner: cannot write %s\n", o.stats_out);
    return 1;
  }
  return rc;
}

// Membership scenario (3 nodes, R = 1 and 2) over seeds 1..n; the first 100 seeds run twice (same trace hash).
int run_membership(std::uint64_t n) {
  miracache::sim::MembershipStats t;
  const int quiet_fd = ::open("/dev/null", O_WRONLY);  // the servers log every member-state change: not 2,000 seeds of it
  if (quiet_fd >= 0) miracache::log::set_sink_fd(quiet_fd);
  struct Restore {
    int fd;
    ~Restore() {
      if (fd >= 0) {
        miracache::log::set_sink_fd(2);
        ::close(fd);
      }
    }
  } restore{quiet_fd};
  for (std::uint64_t seed = 1; seed <= n; ++seed) {
    for (std::uint32_t r : {1u, 2u}) {
      const auto a = miracache::sim::run_membership_scenario(seed, r);
      if (!a.ok) {
        std::fprintf(stderr, "membership seed %llu R=%u: %s\nreproduce: sim_runner --membership-seed %llu\n", (unsigned long long)seed, r,
                     a.failure.c_str(), (unsigned long long)seed);
        return 1;
      }
      if (seed <= 100) {
        const auto b = miracache::sim::run_membership_scenario(seed, r);
        if (b.trace_hash != a.trace_hash || !b.ok) {
          std::fprintf(stderr, "membership seed %llu R=%u: NON-DETERMINISTIC (%016llx vs %016llx)\n", (unsigned long long)seed, r,
                       (unsigned long long)a.trace_hash, (unsigned long long)b.trace_hash);
          return 1;
        }
      }
      t.bundles += a.stats.bundles; t.pushes += a.stats.pushes; t.goaways += a.stats.goaways; t.commits += a.stats.commits;
      t.lookups += a.stats.lookups; t.root_accepted += a.stats.root_accepted; t.child_accepted += a.stats.child_accepted;
      t.skipped += a.stats.skipped; t.stale += a.stats.stale; t.draining += a.stats.draining;
      t.readded_accepts += a.stats.readded_accepts;
    }
  }
  std::printf("sim membership: %llu seeds x R=1,2 ok; %llu bundles (%llu pushes), %llu GOAWAYs; roots accepted %llu, children %llu, "
              "SKIP %llu, StaleEpoch %llu, Draining %llu; re-added accepts %llu; %llu lookups\n",
              (unsigned long long)n, (unsigned long long)t.bundles, (unsigned long long)t.pushes, (unsigned long long)t.goaways,
              (unsigned long long)t.root_accepted, (unsigned long long)t.child_accepted, (unsigned long long)t.skipped,
              (unsigned long long)t.stale, (unsigned long long)t.draining, (unsigned long long)t.readded_accepts,
              (unsigned long long)t.lookups);
  if (n >= 20 && (t.goaways == 0 || t.readded_accepts == 0 || t.skipped == 0 || t.stale == 0 || t.draining == 0 || t.child_accepted == 0)) {
    std::fprintf(stderr, "membership scenario is vacuous (a refusal reason, a GOAWAY or a re-added accept never happened)\n");
    return 1;
  }
  return 0;
}

int usage(const char* msg, const char* arg = nullptr) {
  if (arg != nullptr) std::fprintf(stderr, "sim_runner: %s: %s\n", msg, arg);
  else std::fprintf(stderr, "sim_runner: %s\n", msg);
  std::fprintf(stderr,
               "usage: sim_runner [--seeds N] [--first S] [--seed X] [--golden FILE]\n"
               "                  [--aead-seeds N] [--aead-first S]\n"
               "                  [--store-seeds N] [--store-first S] [--store-seed X] [--store-shard] [--store-require-peak] [--store-replay M]\n"
               "                  [--store-full-every K] [--store-golden FILE] [--store-stats FILE] [--teeth NAME --expect-fail]\n"
               "                  [--store-union N --store-stats-in FILE...]\n"
               "                  [--membership-seeds N] [--membership-seed X]\n");
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  std::uint64_t first = 1, count = 1;
  const char* golden = nullptr;
  bool single = false, seeds_given = false;
  std::uint64_t aead_n = 0, aead_first = 1, membership_n = 0, membership_one = 0;
  StoreOpts so;
  for (int i = 1; i < argc; i += 2) {
    const char* flag = argv[i];
    if (!std::strcmp(flag, "--expect-fail")) { so.expect_fail = true; --i; continue; }
    if (!std::strcmp(flag, "--store-shard")) { so.shard = true; --i; continue; }
    if (!std::strcmp(flag, "--store-require-peak")) { so.require_peak = true; --i; continue; }
    if (!std::strcmp(flag, "--store-trace")) { miracache::sim::g_store_trace = true; --i; continue; }
    if (i + 1 >= argc) return usage("missing value for", flag);
    const char* val = argv[i + 1];
    std::uint64_t v = 0;
    if (!std::strcmp(flag, "--golden")) { golden = val; continue; }
    if (!std::strcmp(flag, "--store-golden")) { so.golden = val; continue; }
    if (!std::strcmp(flag, "--teeth")) { so.teeth = val; continue; }
    if (!std::strcmp(flag, "--store-stats")) { so.stats_out = val; continue; }
    if (!std::strcmp(flag, "--store-stats-in")) { so.stats_in.push_back(val); continue; }
    if (!std::strcmp(flag, "--store-union")) {
      if (!parse_u64(val, 10, so.union_n) || so.union_n < 1) return usage("not a positive integer", val);
      continue;
    }
    if (!std::strcmp(flag, "--store-seeds") || !std::strcmp(flag, "--store-replay") || !std::strcmp(flag, "--store-seed") ||
        !std::strcmp(flag, "--store-full-every") || !std::strcmp(flag, "--store-first")) {
      if (!parse_u64(val, 10, v)) return usage("not an integer", val);
      if (!std::strcmp(flag, "--store-first")) {
        if (v < 1) return usage("value must be >= 1 for", flag);
        so.first = v;
      } else if (!std::strcmp(flag, "--store-seeds")) so.n = v;
      else if (!std::strcmp(flag, "--store-replay")) so.replay = v;
      else if (!std::strcmp(flag, "--store-seed")) so.single = v;
      else so.full_every = static_cast<std::uint32_t>(v);
      continue;
    }
    if (!std::strcmp(flag, "--membership-seeds") || !std::strcmp(flag, "--membership-seed")) {
      std::uint64_t mv = 0;
      if (!parse_u64(val, 10, mv) || mv < 1) return usage("not a positive integer", val);
      (!std::strcmp(flag, "--membership-seeds") ? membership_n : membership_one) = mv;
      continue;
    }
    if (!std::strcmp(flag, "--aead-seeds")) {
      if (!parse_u64(val, 10, aead_n) || aead_n < 1) return usage("not a positive integer", val);
      continue;
    }
    if (!std::strcmp(flag, "--aead-first")) {
      if (!parse_u64(val, 10, aead_first) || aead_first < 1) return usage("not a positive integer", val);
      continue;
    }
    if (!std::strcmp(flag, "--seeds") || !std::strcmp(flag, "--first") || !std::strcmp(flag, "--seed")) {
      seeds_given = true;
      if (!parse_u64(val, 10, v)) return usage("not a non-negative integer", val);
      if (v < 1) return usage("value must be >= 1 for", flag);
      if (!std::strcmp(flag, "--seeds")) count = v;
      else if (!std::strcmp(flag, "--first")) first = v;
      else { first = v; count = 1; single = true; }
    } else {
      return usage("unknown argument", flag);
    }
  }
  if (first > UINT64_MAX - (count - 1)) return usage("seed range wraps past 2^64-1");
  if (membership_one != 0) {
    for (std::uint32_t r : {1u, 2u}) {
      const auto m = miracache::sim::run_membership_scenario(membership_one, r);
      std::printf("membership seed %llu R=%u %s trace %016llx\n", (unsigned long long)membership_one, r, m.ok ? "ok" : m.failure.c_str(),
                  (unsigned long long)m.trace_hash);
      if (!m.ok) return 1;
    }
    return 0;
  }
  if (membership_n != 0) return run_membership(membership_n);
  if (so.n != 0 || so.single != 0 || so.union_n != 0) {
    if (so.n != 0 && so.first > UINT64_MAX - (so.n - 1)) return usage("store seed range wraps past 2^64-1");
    return run_store(so);
  }

  if (aead_n != 0) {
    if (aead_first > UINT64_MAX - (aead_n - 1)) return usage("aead seed range wraps past 2^64-1");
    if (const int rc = run_aead(aead_first, aead_n)) return rc;
    if (!seeds_given && golden == nullptr) return 0;
  }
  std::set<std::uint64_t> hashes;
  for (std::uint64_t i = 0; i < count; ++i) {
    const std::uint64_t s = first + i;
    std::uint64_t h = 0;
    if (!run_seed(s, hashes, &h)) {
      std::fprintf(stderr, "reproduce: sim_runner --seed %llu\n", (unsigned long long)s);
      return 1;
    }
    if (single) std::printf("seed %llu trace %016llx\n", (unsigned long long)s, (unsigned long long)h);
  }
  // Seeds must matter: a constant hash would mean the faults are not exercised.
  if (count > 1 && hashes.size() < count / 2) {
    std::fprintf(stderr, "only %zu distinct trace hashes over %llu seeds\n", hashes.size(), (unsigned long long)count);
    return 1;
  }
  std::printf("sim: %llu seeds ok, %zu distinct traces\n", (unsigned long long)count, hashes.size());
  if (golden != nullptr) {
    const long n = check_golden(golden);
    if (n < 0) return 1;
    std::printf("sim: %ld pinned golden traces match\n", n);
  }
  return 0;
}
