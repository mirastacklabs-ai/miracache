add_library(miracache_sim STATIC scenario.cpp aead_fetch_scenario.cpp store_scenario.cpp membership_scenario.cpp)
target_include_directories(miracache_sim PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(miracache_sim PUBLIC miracache_fabric miracache_core_client miracache_store miracache_server miracache_control)

add_executable(sim_runner main.cpp)
target_link_libraries(sim_runner PRIVATE miracache_sim)

# enable_testing() is called in the top-level CMakeLists before this directory is added.

# Seed sweeps are sharded: one sweep over seeds 1..N is registered as K ctest tests over disjoint seed ranges whose union
# is exactly 1..N, so a parallel ctest (ctest -j) runs them side by side instead of one process
# holding the whole run. Names: sim_store_1of6 ... sim_store_6of6 (plain sim_store when K collapses to 1). Every name
# starts with sim_ (briefs and scripts exclude '-E ^sim_').
#
# K = MIRACACHE_SIM_SHARDS (default 6: the gate runs ctest -j3, and 6 shards pack into two even waves of three (4 left a
# lone fourth shard running after the other three: measured, sim_reload 2000 seeds, 3 CPUs, 4 shards = 739 s + 387 s tail)
# and also split evenly for -j2 and -j6) capped at floor(N / min_per_shard), so a shard never gets too few seeds: the
# store sweep's coverage-vacuity checks (sim/main.cpp, "N >= 50") need >= 50 seeds in the run that applies them. Seeds
# are split as evenly as possible (the first N mod K shards get one extra seed).
#
# Determinism and collisions: a seed's trace depends on the seed only, never on the shard (single-seed reproduction
# `--seed X` / `--store-seed X` / `sim_reload --seed X` is unchanged). The sweeps use the in-process sim fabric (no
# sockets; the only files are a STATS_FLAG sweep's per-shard <test name>.stats, unique per test), so concurrent shards
# cannot collide. Position-dependent parts: `--store-replay 100` is an absolute seed bound, so seeds 1..100 run twice
# exactly once overall wherever the shard boundaries fall; the pinned goldens (--golden / --store-golden: extra fixed
# seeds) run in shard 1 only.
set(MIRACACHE_SIM_SHARDS 6 CACHE STRING "Shards per simulation seed sweep (disjoint seed ranges run as separate ctest tests)")

# miracache_sim_sweep(<name> <total seeds> <min seeds per shard> <exe> <seeds flag> <first flag>
#                     [ALL args...] [SHARDED args...] [FIRST_SHARD args...] [TIMEOUT s] [PROCESSORS n]
#                     [STATS_FLAG flag [UNION_MIN_PER m]])
# STATS_FLAG (union mode, s11 run #290): each shard also gets `<flag> <build dir>/<test name>.stats` (the shard writes its seed
# range and coverage counters there only when it passed), a `<name>_stats_clean` test removes those files first (fixture
# <name>_stats_clean), and the shards are the setup of fixture `<name>_shards`; the caller registers the aggregate test that
# requires it (reading ${<name>_STATS_FILES}). UNION_MIN_PER: when min_per would collapse the sweep to one process (N <
# 2 * min_per, the asan/tsan presets), shard it by UNION_MIN_PER instead; those shards are below the per-process vacuity
# threshold, so the aggregate test applies the checks to their union. Sweeps with N >= 2 * min_per shard exactly as before.
function(miracache_sim_sweep name total min_per exe seeds_flag first_flag)
  cmake_parse_arguments(P "" "TIMEOUT;PROCESSORS;STATS_FLAG;UNION_MIN_PER" "ALL;SHARDED;FIRST_SHARD" ${ARGN})
  math(EXPR cap "${total} / ${min_per}")
  if(cap LESS 2 AND P_STATS_FLAG AND P_UNION_MIN_PER)
    math(EXPR cap "${total} / ${P_UNION_MIN_PER}")
  endif()
  if(cap LESS 1)
    set(cap 1)
  endif()
  set(k ${MIRACACHE_SIM_SHARDS})
  if(k GREATER cap)
    set(k ${cap})
  endif()
  if(k LESS 1)
    set(k 1)
  endif()
  math(EXPR base "${total} / ${k}")
  math(EXPR rem "${total} % ${k}")
  set(stats_files)
  set(first 1)
  foreach(i RANGE 1 ${k})
    set(n ${base})
    if(i LESS_EQUAL rem)
      math(EXPR n "${n} + 1")
    endif()
    if(k EQUAL 1)
      set(tname ${name})
    else()
      set(tname ${name}_${i}of${k})
    endif()
    set(args ${seeds_flag} ${n} ${first_flag} ${first} ${P_ALL})
    if(k GREATER 1)
      list(APPEND args ${P_SHARDED})
    endif()
    if(i EQUAL 1)
      list(APPEND args ${P_FIRST_SHARD})
    endif()
    if(P_STATS_FLAG)
      set(stats ${CMAKE_CURRENT_BINARY_DIR}/${tname}.stats)
      list(APPEND stats_files ${stats})
      list(APPEND args ${P_STATS_FLAG} ${stats})
    endif()
    add_test(NAME ${tname} COMMAND ${exe} ${args})
    # PROCESSORS replaces RUN_SERIAL: default 1 (a shard is one process that mostly runs one thread, so ctest -jN packs N
    # of them without oversubscribing). sim_reload passes PROCESSORS 2: its client threads sleep, yield and wait in real
    # time, so a shard counts as two CPUs and cannot starve timing-sensitive unit tests running beside it. Its only
    # backstop is a count of idle polls (kSpinCap in reload_scenario.cpp), not wall time.
    set(procs 1)
    if(P_PROCESSORS)
      set(procs ${P_PROCESSORS})
    endif()
    set(props PROCESSORS ${procs})
    if(P_TIMEOUT)
      list(APPEND props TIMEOUT ${P_TIMEOUT})
    endif()
    if(P_STATS_FLAG)
      list(APPEND props FIXTURES_REQUIRED ${name}_stats_clean FIXTURES_SETUP ${name}_shards)
    endif()
    set_tests_properties(${tname} PROPERTIES ${props})
    math(EXPR first "${first} + ${n}")
  endforeach()
  if(P_STATS_FLAG)
    add_test(NAME ${name}_stats_clean COMMAND ${CMAKE_COMMAND} -E rm -f ${stats_files})
    set_tests_properties(${name}_stats_clean PROPERTIES FIXTURES_SETUP ${name}_stats_clean)
    set(${name}_STATS_FILES ${stats_files} PARENT_SCOPE)
  endif()
endfunction()

miracache_sim_sweep(sim_smoke ${MIRACACHE_SIM_SEEDS} 50 sim_runner --seeds --first
                    FIRST_SHARD --golden ${PROJECT_SOURCE_DIR}/tests/sim/golden_traces.txt)

# A1.5 exit criterion: 2,000 seeds, zero validation failures; nemesis seeds never Hit with wrong bytes.
miracache_sim_sweep(sim_aead ${MIRACACHE_AEAD_SEEDS} 100 sim_runner --aead-seeds --aead-first)

# A1.4 S6: store scenario, every invariant after every step (CRC sweep included), seeds
# 1..MIRACACHE_STORE_SEEDS (sim preset: 2000; the first 100 run twice for determinism), plus the pinned goldens.
#
# Coverage-vacuity checks ("the sweep exercised X at least once": commits, rejected writes, fetch hits, seq misses, limits,
# crash adoption, below-cap checks, peak > 4 puts on one endpoint; sim/main.cpp store_vacuity):
# - each shard of >= 50 seeds applies them to its own seeds (Q10: stricter than the union, every shard must be non-vacuous),
#   except the peak, a union property (only roomy-cap seeds, divisible by 6, reach it, and not all do; waived per shard below
#   200 seeds);
# - sim_store_vacuity applies them to the UNION of all shards (s11 run #290), exactly as one unsharded process of N seeds
#   would, plus the peak at any N. Each passing shard writes its seed range and counters to <build>/sim/<shard>.stats
#   (--store-stats); sim_store_stats_clean removes those files before the shards run; sim_store_vacuity
#   (FIXTURES_REQUIRED sim_store_shards, so ctest runs it after every shard and skips it if one failed) fails if a file is
#   missing, the ranges do not tile 1..N, a file was written by another sim_runner build (its stamp, so `ctest -FA -R
#   sim_store_vacuity` after a rebuild cannot pass on stale files), or a check is zero over the union.
#   Note (s11c review P3-6): the checks other than the peak apply only at N >= 50, as for one process. The tsan preset
#   (N = 30) therefore gets ONLY the union peak check; asan (60) and dev/release/sim (>= 100) get all of them. Lowering the
#   threshold for tsan would need its own measured floor per counter, so tsan stays a race-detection lane, not a coverage one.
# This lets the asan (60 seeds) and tsan (30 seeds) presets shard by UNION_MIN_PER 5 (6 shards of 10 / 5) instead of one
# 1431 s / 1339 s process: same seeds, same --store-replay 100, same goldens, the checks as one process would decide.
# dev/release/sim (N >= 100) shard by 50 exactly as before and gain the union peak check. The peak check over the union
# replaces Q02's sim_store_peak test (seeds 13..24) and run #286's single-seed sim_store_peak_18/_24: the sweep's union
# (1..N, N >= 30 in every preset) contains 13..24, so no test pins which seed reaches the peak.
if(MIRACACHE_STORE_SEEDS LESS 24)
  message(FATAL_ERROR "MIRACACHE_STORE_SEEDS=${MIRACACHE_STORE_SEEDS}: the store sweep needs >= 24 seeds (seeds 18 and 24 are the "
                      "known ones that reach the union-only peak check of sim_store_vacuity)")
endif()
miracache_sim_sweep(sim_store ${MIRACACHE_STORE_SEEDS} 50 sim_runner --store-seeds --store-first
                    ALL --store-replay 100 SHARDED --store-shard
                    FIRST_SHARD --store-golden ${PROJECT_SOURCE_DIR}/tests/sim/golden_store.txt
                    STATS_FLAG --store-stats UNION_MIN_PER 5)
set(union_args)
foreach(s ${sim_store_STATS_FILES})
  list(APPEND union_args --store-stats-in ${s})
endforeach()
add_test(NAME sim_store_vacuity COMMAND sim_runner --store-union ${MIRACACHE_STORE_SEEDS} ${union_args})
set_tests_properties(sim_store_vacuity PROPERTIES PROCESSORS 1 FIXTURES_REQUIRED sim_store_shards)

# Teeth: each injected store bug must make the simulator fail (MIRACACHE_TEETH builds only).
if(MIRACACHE_TEETH)
  foreach(variant no_fence skip_seq commit_before_digest reuse_generation
                  endpoint_cap_lax lease_cap_lax unknown_put_ok foreign_put_id)
    add_test(NAME sim_store_teeth_${variant}
             COMMAND sim_runner --store-seeds 200 --teeth ${variant} --expect-fail)
  endforeach()
endif()

# HR6: hot reload under load (sim): random valid reload sequences (class A and B, client and memory-node side) over three
# real memory nodes and a bundle-mode Client, 4-lane traffic, the strict oracle. sim preset: 2000 seeds. The client's own
# threads do the rebuilds, so a seed is not bit-reproducible; `sim_reload --seed X` replays its plan.
set(MIRACACHE_RELOAD_SEEDS 200 CACHE STRING "Seeds run by the sim_reload test")
add_executable(sim_reload reload_scenario.cpp)
target_include_directories(sim_reload PRIVATE ${PROJECT_SOURCE_DIR}/tests)
target_link_libraries(sim_reload PRIVATE miracache_sim miracache_client)
# Q05: PROCESSORS 2 (not 1): a seed runs a Client with its own threads and real-time waits, so it uses more than one CPU.
miracache_sim_sweep(sim_reload ${MIRACACHE_RELOAD_SEEDS} 10 sim_reload --seeds --first TIMEOUT 3000 PROCESSORS 2)
