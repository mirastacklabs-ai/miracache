#!/usr/bin/env bash
# Configure, build and ctest each preset. Run inside the dev container:
#   tools/dev/run.sh tools/ci/build_and_test.sh [preset...]
# Default presets: dev release asan sim fuzz, plus tsan when ThreadSanitizer works on this
# machine (the container needs `run.sh --tsan` for that). The fuzz preset also runs
# libFuzzer smokes: fuzz_block_headers for 30 s (override: MIRACACHE_FUZZ_SECONDS),
# fuzz_wire and fuzz_block_open for 20 s each.
# MIRA_CTEST_JOBS (default min(3, nproc); tsan: 1 unless set) sets ctest -j. The dev container has 2 CPUs by default (MIRA_DEV_CPUS, tools/dev/run.sh), so
# -j only helps once that is raised, e.g. `MIRA_DEV_CPUS=4 tools/dev/run.sh --tsan env MIRA_CTEST_JOBS=3 tools/ci/build_and_test.sh`
# (run.sh does not forward the environment into the container; `env` does).
# Optional x86_64 step (pre-hardware, slow under qemu emulation, NOT run by this script): the final gate also
# runs `tools/ci/x86_check.sh` from the host (release build + unit tests on linux/amd64); see the x86 check notes in the workstation setup guide.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Sanitizer findings must fail the run, never just print.
export UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
export ASAN_OPTIONS=detect_leaks=1:abort_on_error=1
export TSAN_OPTIONS=halt_on_error=1

fuzz_seconds=${MIRACACHE_FUZZ_SECONDS:-30}
# ctest parallelism (default 3, leaving CPU for other projects on the shared VM). Tests that cannot overlap are
# RUN_SERIAL in CMake (every rdma-labelled test, all e2e tests with fixed ports/devices). The long sim sweeps are sharded (sim_X_1of6.., MIRACACHE_SIM_SHARDS, PROCESSORS 1) and run in parallel; at tsan -j1 they stay sequential.
# J02: default min(3, nproc); the tsan preset defaults to 1 (timing-sensitive tests flake when they overlap on 2 CPUs). An
# explicit MIRA_CTEST_JOBS wins everywhere. RUN_SERIAL set (listed in tests/CMakeLists.txt): every
# rdma-labelled test, reload_walk_tests (ClientRebuild.ClassBChange*), bundle_watcher, cred_watch, the *Keepalive* tests
# in miracache_wire_tests.
cpus=$(nproc 2>/dev/null || echo 1)
default_jobs=$(( cpus < 3 ? cpus : 3 ))
jobs_for() { if [[ -n ${MIRA_CTEST_JOBS:-} ]]; then echo "$MIRA_CTEST_JOBS"; elif [[ $1 == tsan ]]; then echo 1; else echo "$default_jobs"; fi; }

tsan_works() {
  local dir rc=0; dir=$(mktemp -d)
  printf '#include <thread>\nint main(){int x=0;std::thread t([&]{x=1;});t.join();return x-1;}\n' >"$dir/t.cpp"
  { "${CXX:-clang++}" -fsanitize=thread "$dir/t.cpp" -o "$dir/t" 2>/dev/null && "$dir/t" 2>/dev/null; } || rc=$?
  rm -rf "$dir"; return $rc
}

# Lists extensionless ELF files under build/$1/{tests,server,core/fabric} that lack the user exec
# bit (object files, libraries and CMake scratch files have extensions or live in CMakeFiles).
lost_exec_bits() {
  local d f
  for d in "build/$1/tests" "build/$1/server" "build/$1/core/fabric"; do
    [[ -d $d ]] || continue
    while IFS= read -r -d '' f; do
      [[ $(head -c4 "$f" | od -An -tx1 | tr -d ' \n') == 7f454c46 ]] && echo "$f"
    done < <(find "$d" -type f ! -perm -u+x ! -name '*.*' ! -path '*/CMakeFiles/*' -print0)
  done
  return 0
}

fuzz_smoke() {
  local bin=build/fuzz/tests/fuzz_block_headers corpus g n=0
  [[ -x $bin ]] || { echo "fuzz smoke: $bin not built" >&2; return 1; }
  corpus=$(mktemp -d)
  # Seed with the golden headers: selector byte (0 = server, 1 = extent) + header bytes.
  for g in proto/golden/server_header_v0.hex proto/golden/extent_header_v0.hex; do
    { printf "\\x$((n % 2 == 0 ? 0 : 1))"
      for h in $(cat "$g"); do printf "\\x$h"; done; } >"$corpus/seed$n"
    n=$((n + 1))
  done
  # Golden order above is server then extent, matching selectors 0 and 1.
  echo "--- fuzz smoke: ${fuzz_seconds}s ---"
  "$bin" -max_total_time="$fuzz_seconds" -timeout=10 -rss_limit_mb=2048 "$corpus"
  rm -rf "$corpus"
}

# fuzz_run NAME SECONDS [SEED_DIR]: libFuzzer smoke of build/fuzz/tests/NAME. New units go to
# a temp dir so the committed corpus stays untouched; SEED_DIR is read-only extra seeds.
fuzz_run() {
  local name=$1 secs=$2 seeds=${3:-} bin corpus
  bin=build/fuzz/tests/$name
  [[ -x $bin ]] || { echo "fuzz smoke: $bin not built" >&2; return 1; }
  corpus=$(mktemp -d)
  echo "--- fuzz smoke: $name ${secs}s ---"
  "$bin" -max_total_time="$secs" -timeout=10 -rss_limit_mb=2048 "$corpus" ${seeds:+"$seeds"}
  rm -rf "$corpus"
}

presets=("$@")
if [[ ${#presets[@]} -eq 0 ]]; then
  presets=(dev release asan sim fuzz)
  if tsan_works; then presets+=(tsan); else echo "SKIP tsan: ThreadSanitizer does not run here (needs run.sh --tsan)"; fi
fi

tools/ci/lint_nondeterminism.sh

for p in "${presets[@]}"; do
  ctest_jobs=$(jobs_for "$p")
  echo "=== preset: $p ==="
  echo "ctest -j $ctest_jobs ($p)"
  # CI always builds with warnings as errors, whatever the cache says.
  cmake --preset "$p" -DMIRACACHE_WERROR=ON
  cmake --build --preset "$p"
  # Mac<->VM mount flake: a big sanitizer link sometimes lands without its exec bit, which later
  # shows up as "permission denied"/BAD_COMMAND in ctest. Delete such binaries and relink once.
  if lost=$(lost_exec_bits "$p") && [[ -n $lost ]]; then
    echo "WARNING: binaries without the exec bit (deleting, rebuilding once):" >&2
    printf '  %s\n' $lost >&2
    # shellcheck disable=SC2086
    rm -f $lost
    cmake --build --preset "$p"
    if lost=$(lost_exec_bits "$p") && [[ -n $lost ]]; then
      echo "FAIL: still no exec bit after a rebuild (build dir / mount problem, not the code):" >&2
      printf '  %s\n' $lost >&2
      exit 1
    fi
  fi
  # sim_smoke is registered only if enable_testing() precedes sim/; guard against regressions.
  listed=$(ctest --preset "$p" -N)
  if ! grep -q 'sim_smoke' <<<"$listed"; then
    echo "FAIL: sim_smoke is not registered in preset $p" >&2
    exit 1
  fi
  ctest --preset "$p" -j "$ctest_jobs"
  if [[ $p == fuzz ]]; then
    fuzz_smoke
    fuzz_run fuzz_wire 20 tests/fuzz/corpus/wire
    fuzz_run fuzz_block_open 20
    fuzz_run fuzz_bundle_envelope 20 tests/fuzz/corpus/bundle
    fuzz_run fuzz_audit_verify 20 tests/fuzz/corpus/audit
  fi
done
# R07: MIRA_SKIP_TAIL=1 skips the go / Python / engine-contract / binding + wheel tail (tools/ci/full_gate.sh runs it once, in the devrel lane).
if [[ ${MIRA_SKIP_TAIL:-0} == 1 ]]; then
  echo "=== tail (go, python, engine contracts, binding, wheel) skipped: MIRA_SKIP_TAIL=1 ==="
else
  echo "=== go: vet and test -race (pinned Go in build/go, tools/dev/go.sh) ==="
  tools/dev/go.sh -C controller vet ./...
  tools/dev/go.sh -C controller test -race ./...
  echo "=== python tests (pure Python, no vllm/torch) ==="
  PYTHONPATH=python python3 -m unittest discover -s tests/python -v
  echo "=== vLLM contract test (skips without vllm) ==="
  PYTHONPATH=python python3 -m unittest discover -s tests/engines/vllm -v
  echo "=== SGLang contract test (skips without sglang) ==="
  PYTHONPATH=python python3 -m unittest discover -s tests/engines/sglang -t tests/engines/sglang -v
  
  # Binding vs the built libmiracache.so (dev preset). Without it test_roundtrip skips cleanly above.
  dev_lib=build/dev/client/libmiracache.so
  if [[ " ${presets[*]} " == *" dev "* && -f $dev_lib ]]; then
    echo "=== python binding against $dev_lib ==="
    # The whole suite, not just test_roundtrip: test_agentbench_backend (loopback tests),
    # test_sglang_real_client and test_vllm_tier.TestRealClient all skip without MIRACACHE_LIB.
    MIRACACHE_LIB=$PWD/$dev_lib PYTHONPATH=python python3 -m unittest discover -s tests/python -v
    echo "=== wheel (stdlib builder) + test from the unpacked wheel ==="
    rm -rf build/wheel build/wheel-unpacked
    python3 tools/pkg/build_wheel.py --lib "$dev_lib" --out build/wheel
    python3 -m zipfile -e build/wheel/miracache-*.whl build/wheel-unpacked
    # No MIRACACHE_LIB: the library must be found inside the unpacked package.
    PYTHONPATH=build/wheel-unpacked python3 -m unittest discover -s tests/python -p 'test_roundtrip.py' -v
  fi
fi

echo "OK: ${presets[*]}"
