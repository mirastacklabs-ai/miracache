#!/usr/bin/env bash
# Runs the `rdma` ctest label (real verbs/rdma_cm tests) against each soft-RDMA device.
# Prepare the VM once, then run inside the dev container with the devices passed in:
#   tools/dev/rdma_setup.sh
#   tools/dev/run.sh --rdma tools/ci/rdma_test.sh [preset] [device...]
# Defaults: preset dev, devices "rxe0 siw0" (RoCEv2 and iWARP). Unlike a plain ctest run
# (which skips cleanly with no device), this script FAILS if a device is missing or any
# test skipped, so it can never pass vacuously. The final line is "OK: <dev> N/N[,...]", plus
# " (MultiRailE2e SKIPPED: no rail-fault helper)" when the multi-rail e2e could not run.
# Strict: any failed or skipped test on any device fails the script; nothing is excused. (siw0's small-ring mapping limit is
# handled in the fabric, see the workstation setup guide, "siw0 per-process queue-mapping limit".)
# MIRA_REQUIRE_MULTIRAIL=1 makes the MultiRailE2e skip a failure (exit 1, final line "FAIL: ... MultiRailE2e skipped"); bootstrap.sh
# --first-run-check sets it because it always starts the helper.
# Each device prints "R15 <dev>: late opens k/N, max wait X ms" (e2e opens that returned with a memory node still pending,
# tests/e2e/multi_node_rdma_test.cpp nodes_connected_within) and fails when all N >= 3 opens were late; the OK line carries the counts.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

preset=${1:-dev}
[[ $# -gt 0 ]] && shift
devices=("$@")
[[ ${#devices[@]} -eq 0 ]] && devices=(rxe0 siw0)

cmake --preset "$preset" -DMIRACACHE_WERROR=ON >/dev/null
cmake --build --preset "$preset" -j2 --target miracache_rdma_tests

present=$(ibv_devices | awk 'NR>2 {print $1}')
for d in "${devices[@]}"; do
  grep -qx "$d" <<<"$present" || { echo "FAIL: RDMA device $d not visible (run tools/dev/rdma_setup.sh, then run.sh --rdma)" >&2; exit 1; }
done

# Build the rest: the wire and e2e rdma-labelled test binaries (miracache_wire_rdma_tests, miracache_e2e_rdma_tests) and their
# helpers are not part of the miracache_rdma_tests target above. Test discovery does not need this step: it runs at ctest start
# (PRE_TEST, tests/CMakeLists.txt), so the per-device parameters are registered then.
cmake --build --preset "$preset" -j2 >/dev/null

# Multi-rail (tests/e2e/multirail_rdma_test.cpp, rxe0 only): the multi-rail end to end deletes a rail's address, which the unprivileged
# container cannot do. It needs the host-side agent (tools/dev/rail_fault_agent.sh <repo>/build/<preset>/rail-fault, started on
# the macOS host). Without a live agent that test is left out of the pass (it would skip), and the FINAL line says so
# (never a plain OK without it). The agent is alive when its heartbeat counter moves within 3 s: no clock is
# compared, so a host/VM clock skew cannot drop the test.
agent=build/$preset/rail-fault/agent
rail_e2e=0
if [[ -f $agent ]]; then
  beat0=$(cat "$agent" 2>/dev/null || true)
  for _ in 1 2 3 4 5 6; do
    sleep 0.5
    beat1=$(cat "$agent" 2>/dev/null || true)
    if [[ -n $beat1 && $beat1 != "$beat0" ]]; then rail_e2e=1; break; fi
  done
fi
[[ $rail_e2e -eq 1 ]] || echo "NOTE: no rail fault agent running; the RL4 multi-rail e2e (MultiRailE2e) is NOT run in this pass"
# With MIRA_REQUIRE_MULTIRAIL=1 a missing helper is known now; fail here, not after the whole pass (same final-line format).
if [[ $rail_e2e -eq 0 && ${MIRA_REQUIRE_MULTIRAIL:-0} == 1 ]] && printf "%s\n" "${devices[@]}" | grep -qx rxe0; then
  echo "FAIL: none (MultiRailE2e skipped: no rail-fault helper, MIRA_REQUIRE_MULTIRAIL=1)" >&2
  echo "FAIL: none MultiRailE2e skipped"
  exit 1
fi

summary=()
r15_sum=()
for d in "${devices[@]}"; do
  echo "=== rdma tests on $d ==="
  log=$(mktemp)
  excl=()
  [[ $rail_e2e -eq 1 ]] || excl=(-E MultiRailE2e)
  rc=0
  # The e2e opens append one line each to this file (tests/e2e/multi_node_rdma_test.cpp, nodes_connected_within).
  r15=$PWD/build/$preset/r15-$d.log
  rm -f "$r15"
  MIRA_R15_LOG=$r15 ctest --preset "$preset" -L rdma -R "/${d}" ${excl[@]+"${excl[@]}"} -j1 --output-on-failure --no-tests=error 2>&1 | tee "$log" || rc=$?
  if grep -Eq 'Skipped|Not Run' "$log"; then
    echo "FAIL: some rdma tests skipped on $d" >&2; rm -f "$log"; exit 1
  fi
  if [[ $rc -ne 0 ]]; then
    echo "FAIL: ctest failed on $d" >&2; rm -f "$log"; exit 1
  fi
  # "100% tests passed, 0 tests failed out of N": N/N for the final line.
  total=$(sed -nE 's/.*tests passed, 0 tests failed out of ([0-9]+).*/\1/p' "$log" | tail -1)
  rm -f "$log"
  [[ -n $total ]] || { echo "FAIL: no ctest summary for $d" >&2; exit 1; }
  summary+=("$d $total/$total")
  # The late-open waits are invisible in a passing ctest run. Print them per device ("R15 <dev>: ..."
  # lines; full_gate.sh repeats them in its summary) and fail when (a) any open waited >= 5000 ms for its nodes (half the
  # 10 s cap: far beyond one slow handshake), or (b) MORE THAN HALF of the opens were late (N >= 3): nodes routinely
  # connecting late is a regression, one or two late opens on a loaded tsan/siw lane are not (the
  # nightly baseline is 0 late, max 0 ms). No records at all means the accounting itself broke (the
  # MultiNodeE2e/ReplicaE2e opens run on every device), so that fails too.
  r15_n=0; r15_late=0; r15_max=0
  if [[ -f $r15 ]]; then
    r15_n=$(grep -c '^R15 ' "$r15" || true)
    r15_late=$(grep -c ' late=1 ' "$r15" || true)
    r15_max=$(sed -nE 's/.* wait_ms=([0-9]+) .*/\1/p' "$r15" | sort -n | tail -1)
    r15_max=${r15_max:-0}
  fi
  echo "R15 $d: late opens $r15_late/$r15_n, max wait $r15_max ms (log $r15)"
  grep ' late=1 ' "$r15" 2>/dev/null | sed 's/^/  /' || true
  if [[ $r15_n -eq 0 ]]; then
    echo "FAIL: no R15 open records on $d ($r15 missing or empty: the e2e open accounting broke)" >&2; exit 1
  fi
  if [[ $r15_max -ge 5000 ]]; then
    echo "FAIL: an e2e open on $d waited $r15_max ms (>= 5000) for its memory nodes (R15 regression)" >&2; exit 1
  fi
  if [[ $r15_n -ge 3 && $((r15_late * 2)) -gt $r15_n ]]; then
    echo "FAIL: more than half of the e2e opens on $d returned with a memory node still pending ($r15_late/$r15_n, R15 regression)" >&2; exit 1
  fi
  r15_sum+=("$d $r15_late/$r15_n late")
  # The hot-reload-under-load test (tests/e2e/reload_rdma_test.cpp) runs in the ctest pass above like every rdma test; this
  # keeps the pass from being vacuous if it ever stops being registered for the device.
  [[ $(ctest --preset "$preset" -L rdma -R "ReloadE2e.*/${d}" -N | grep -c 'ReloadE2e') -gt 0 ]] \
    || { echo "FAIL: the HR6 reload test (ReloadE2e) is not registered for $d" >&2; exit 1; }
  # The multi-rail test is parametrized on rxe0 only (the second address is on eth0); same registration check there.
  if [[ $d == rxe0 ]]; then
    [[ $(ctest --preset "$preset" -L rdma -R "MultiRailE2e.*/rxe0" -N | grep -c 'MultiRailE2e') -gt 0 ]] \
      || { echo "FAIL: the RL4 multi-rail test (MultiRailE2e) is not registered for rxe0" >&2; exit 1; }
  fi
done
skipped=""
if [[ $rail_e2e -eq 0 ]]; then
  for d in "${devices[@]}"; do [[ $d == rxe0 ]] && skipped=" (MultiRailE2e SKIPPED: no rail-fault helper)"; done
fi
if [[ -n $skipped && ${MIRA_REQUIRE_MULTIRAIL:-0} == 1 ]]; then
  (IFS=,; echo "FAIL: ${summary[*]} (MultiRailE2e skipped: no rail-fault helper, MIRA_REQUIRE_MULTIRAIL=1)" >&2)
  (IFS=,; echo "FAIL: ${summary[*]} MultiRailE2e skipped")
  exit 1
fi
(IFS=,; echo "OK: ${summary[*]}${skipped} (R15: ${r15_sum[*]})")
