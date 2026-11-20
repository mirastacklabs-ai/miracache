#!/usr/bin/env bash
# The full pre-push gate, in bounded parallel lanes. Host-side bash 3.2+; runs on the Mac (colima) or on a plain Linux host with Docker.
#   tools/ci/full_gate.sh [--dry-run]
#   if tools/ci/full_gate.sh > build/gate.log 2>&1; then git push; fi        # last line: "OK: ..." or "FAIL: ..."
#   waiter (ONE per run): until grep -qE "^OK: |^FAIL" build/gate.log || ! pgrep -f "[f]ull_gate.sh"; do sleep 30; done
# Lanes (logs in build/gate-<lane>.log):
#   asan | tsan | simfuzz | devrel -> rxe0 multirail (+ rail-fault helper) -> engine contract x2 -> docker e2e
#   then siw0 alone (its own run: the soft-iWARP e2e tests must not overlap other RDMA work),
#   then product alone (build/gate-product.log): systemd acceptance (Linux + root + systemd PID 1, else skipped) and the $0
#   agentbench rxe0 rehearsal (only with MIRA_GATE_AGENTBENCH=<agentbench checkout>); see "product step" below.
#   devrel's build_and_test.sh run is the ONLY one that runs the tail (go vet / go test -race / Python / vLLM+SGLang contract /
#   binding + wheel); the other lanes pass MIRA_SKIP_TAIL=1. x86 (tools/ci/x86_check.sh) joins only when the host is not x86_64.
# Resources: a lane gets CPUS/MEM derived from the Docker engine's CPU count and the memory it can use.
#   up to 8 CPUs (the Mac's colima VM): 2 CPU / 3 GB per lane; more than 8 CPUs: CPUS = ncpu/4 (min 2), MEM = 22 % of memory
#   (min 3 GiB). At most min(ncpu / CPUS, mem / MEM) lanes run at once (min 1); the rest queue in the order above.
#   Overrides: MIRA_GATE_LANE_CPUS, MIRA_GATE_LANE_MEM_GIB, MIRA_GATE_PARALLEL=0 (one lane at a time), MIRA_GATE_NCPU (pretend
#   ncpu), MIRA_GATE_CTEST_TSAN (ctest -j of the tsan lane; unset = J02's -j1 unless a lane has more than 2 CPUs, then
#   min(3, CPUS); when ncpu >= 24 AND CPUS >= 8, min(4, CPUS/2), i.e. 2 CPUs per tsan test, because the tsan lane's tail
#   runs alone once the other lanes finish). With the default CPUS = ncpu/4 that needs 32+ CPUs (a 24-31 CPU host gets lanes
#   of 6-7 CPUs and so min(3, CPUS)); MIRA_GATE_LANE_CPUS=8 enables it from 24 CPUs. CMAKE_BUILD_PARALLEL_LEVEL inside each
#   lane is set from CPUS (MIRA_BUILD_JOBS).
# Test order: ctest starts the longest tests first only when build/<preset>/Testing/Temporary/CTestCostData.txt exists. A
#   fresh build dir has none, so before a lane starts the gate seeds each of its presets' file from build/gate-costdata/
#   <preset>.txt (only when the build dir has none), and refreshes that copy after each green lane (MIRA_GATE_COSTDIR).
# Failure: fail-fast by default. The first failed lane stops new lanes, kills the running ones (process tree + docker kill of the
# containers labelled miracache-gate=<pid>), skips siw0 and product and prints "FAIL: ..." as the last, unindented line.
#   MIRA_GATE_KEEP_GOING=1 runs everything and reports all failures. INT/TERM clean up the same way.
# Test seam (no Docker, no build): MIRA_GATE_STUB=1 replaces each lane by `sleep $MIRA_GATE_STUB_SLEEP` (default 2) and fails the
#   lanes named in MIRA_GATE_STUB_FAIL (space list, e.g. "tsan" or "product"; product is stubbed too). MIRA_GATE_POLL = scheduler poll seconds (default 1).
# RDMA: RAIL_NETDEV (default eth0) is the netdev rxe0 sits on; rdma_setup.sh is run first (idempotent). Hold your
# machine's own RDMA lock around this script if other jobs share the devices.
# No RDMA (the GitLab dind runner, any container without devices): with MIRA_GATE_NO_RDMA=1, or on a Linux host (no colima)
#   whose /sys/class/infiniband is empty AND that is a container (/.dockerenv, /run/.containerenv) or has no rdma_rxe module,
#   the gate never loads modules or creates devices: devrel skips rdma-setup, rxe0 multirail (+ helper) and the rxe0 docker
#   e2e (it builds the deploy images and smoke-runs the controller image instead), siw0 and product are skipped, each with a
#   "skip rdma: <what>: <reason>" line, and the OK line ends "rdma(skipped)". A colima VM or a Linux host that can load
#   rdma_rxe (a DO VM, bare metal) runs everything as before. Stub mode honours MIRA_GATE_NO_RDMA=1 only.
# Do not pipe the gate through `tail`; check the exit status.
set -u
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd); cd "$ROOT"
dry=0
case ${1:-} in
  --dry-run) dry=1 ;;
  "") ;;
  *) echo "usage: $0 [--dry-run]" >&2; exit 2 ;;
esac
mkdir -p build
t0=$(date +%s)
export RAIL_NETDEV=${RAIL_NETDEV:-eth0}
STUB=${MIRA_GATE_STUB:-0}
KEEP=${MIRA_GATE_KEEP_GOING:-0}
POLL=${MIRA_GATE_POLL:-1}
# Heartbeat (s12): every MIRA_GATE_HEARTBEAT seconds (default 600, 0 = off) one indented "  ..   <lane> HH:MM:SS: <the
# lane's last progress line>" per running lane, so a CI job page shows the lanes are alive instead of ~90 silent minutes.
# Indented, so no "^OK: " / "^FAIL" waiter matches it.
HEARTBEAT=${MIRA_GATE_HEARTBEAT:-600}
[[ $HEARTBEAT =~ ^[0-9]+$ ]] || HEARTBEAT=600  # seconds only ("10m" would break the arithmetic on every poll)
# Every lane container carries this label (tools/dev/run.sh reads MIRA_DEV_LABEL), so a kill can find them.
export MIRA_DEV_LABEL="miracache-gate=$$"

# ---- resources ----
if [[ -n ${MIRA_GATE_NCPU:-} ]]; then ncpu=$MIRA_GATE_NCPU
elif (( STUB )); then ncpu=$(nproc 2>/dev/null || echo 2)
else ncpu=$(docker info --format '{{.NCPU}}' 2>/dev/null); ncpu=${ncpu:-$(nproc 2>/dev/null || echo 2)}; fi
if (( STUB )); then mem_b=${MIRA_GATE_STUB_MEM_B:-0}; else mem_b=$(docker info --format '{{.MemTotal}}' 2>/dev/null); mem_b=${mem_b:-0}; fi
if [[ -r /proc/meminfo ]] && (( ! STUB )); then   # a Linux host: never plan on more than what is available now
  avail_b=$(awk '/^MemAvailable:/ {print $2 * 1024}' /proc/meminfo)
  if [[ -n $avail_b && ( $mem_b -eq 0 || $avail_b -lt $mem_b ) ]]; then mem_b=$avail_b; fi
fi
mem_gib=$(( mem_b / 1073741824 ))
if (( ncpu <= 8 )); then
  def_cpus=2; def_mem=3
else
  def_cpus=$(( ncpu / 4 )); (( def_cpus < 2 )) && def_cpus=2
  def_mem=$(( mem_gib * 22 / 100 )); (( def_mem < 3 )) && def_mem=3
fi
CPUS=${MIRA_GATE_LANE_CPUS:-$def_cpus}
MEM_G=${MIRA_GATE_LANE_MEM_GIB:-$def_mem}
MEM=${MEM_G}g
# Bounded parallelism: as many lanes as fit the CPUs (and the memory, when known), at least one.
maxpar=$(( ncpu / CPUS ))
if (( mem_gib > 0 && MEM_G > 0 )); then mp_mem=$(( mem_gib / MEM_G )); (( mp_mem < maxpar )) && maxpar=$mp_mem; fi
(( maxpar < 1 )) && maxpar=1
[[ ${MIRA_GATE_PARALLEL:-1} == 0 ]] && maxpar=1
# R03: the tsan lane keeps J02's ctest -j1 unless asked for, or unless the lane has CPUs to spare.
if [[ -n ${MIRA_GATE_CTEST_TSAN:-} ]]; then CT_TSAN=$MIRA_GATE_CTEST_TSAN
elif (( ncpu >= 24 && CPUS >= 8 )); then CT_TSAN=$(( CPUS / 2 < 4 ? CPUS / 2 : 4 ))   # gate tail: 2 CPUs per tsan test
elif (( CPUS > 2 )); then CT_TSAN=$(( CPUS < 3 ? CPUS : 3 ))
else CT_TSAN=""; fi
x86=0; [[ $(uname -m) == x86_64 ]] || x86=1
# ---- RDMA available? (empty rdma_skip = yes; see "No RDMA" above) ----
rdma_skip=""
if [[ ${MIRA_GATE_NO_RDMA:-0} == 1 ]]; then rdma_skip="MIRA_GATE_NO_RDMA=1"
elif (( ! STUB )); then
  source "$ROOT/tools/dev/hostvm.sh"
  if [[ $HOSTVM_MODE == local ]] && [[ -z $(ls -A /sys/class/infiniband 2>/dev/null) ]]; then
    if [[ -f /.dockerenv || -f /run/.containerenv ]]; then
      rdma_skip="no RDMA device (/sys/class/infiniband empty) inside a container; the gate never loads modules from one"
    elif command -v modinfo >/dev/null 2>&1 && ! modinfo rdma_rxe >/dev/null 2>&1; then
      rdma_skip="no RDMA device (/sys/class/infiniband empty) and no rdma_rxe kernel module"
    fi
  fi
fi
echo "== gate shape: ncpu=$ncpu mem=${mem_gib}GiB -> lane ${CPUS} CPU / ${MEM}, at most $maxpar lanes at once, ctest tsan=${CT_TSAN:-1 (J02)}, fail-fast=$(( ! KEEP )), rail netdev=$RAIL_NETDEV, x86 lane=$x86$( ((STUB)) && echo ", stub=$STUB")${rdma_skip:+, rdma=skipped}"
if [[ -n $rdma_skip ]]; then echo "skip rdma: $rdma_skip"; fi
if (( dry )); then
  if [[ -n $rdma_skip ]]; then
    echo "lanes: asan tsan simfuzz devrel(+tail once, engine contract x2, docker images) (rdma skipped: rxe0, docker e2e, siw0, product)$( ((x86)) && echo ' x86')"
  else
    echo "lanes: asan tsan simfuzz devrel(+tail once, rxe0 multirail, engine contract x2, docker e2e) siw0 product(systemd, rehearsal)$( ((x86)) && echo ' x86')"
  fi
  exit 0
fi

# in-container runner: dev [run.sh flags...] -- <cmd...> with this gate's resources (CMAKE jobs = CPUS)
dev() { MIRA_DEV_CPUS=$CPUS MIRA_DEV_MEM=$MEM MIRA_BUILD_JOBS=$CPUS tools/dev/run.sh "$@"; }

lane_asan()    { dev --tsan env MIRA_SKIP_TAIL=1 MIRA_CTEST_JOBS=$CPUS tools/ci/build_and_test.sh asan; }
lane_tsan()    { dev --tsan env MIRA_SKIP_TAIL=1 ${CT_TSAN:+MIRA_CTEST_JOBS=$CT_TSAN} tools/ci/build_and_test.sh tsan; }
lane_simfuzz() { dev env MIRA_SKIP_TAIL=1 MIRA_CTEST_JOBS=$CPUS tools/ci/build_and_test.sh sim fuzz; }
lane_x86()     { tools/ci/x86_check.sh; }
lane_siw0()    { dev --rdma tools/ci/rdma_test.sh dev siw0; }
lane_devrel() {
  set -e
  local helper=""
  trap '[[ -n ${helper:-} ]] && { kill ${helper:-} 2>/dev/null || true; wait ${helper:-} 2>/dev/null || true; }; true' EXIT
  s() { echo "+ [$1] $(date '+%H:%M:%S')"; shift; "$@"; }
  if [[ -n $rdma_skip ]]; then
    echo "skip rdma: rdma-setup, rdma-rxe0 (multirail + rail-fault helper), docker-e2e on rxe0: $rdma_skip"
    s dev-release dev --tsan env MIRA_CTEST_JOBS=$CPUS tools/ci/build_and_test.sh dev release
    s engine-contract tools/ci/engine_contract.sh
    s engine-contract-bundle tools/ci/engine_contract.sh --bundle-mode
    s docker-images docker_images_smoke
    echo "OK: lane devrel (rdma skipped) $(date '+%H:%M:%S')"
    return 0
  fi
  s rdma-setup tools/dev/rdma_setup.sh "$RAIL_NETDEV" >/dev/null
  # build_and_test.sh dev release runs the tail (go, Python, binding + wheel) once, for the whole gate.
  s dev-release dev --tsan env MIRA_CTEST_JOBS=$CPUS tools/ci/build_and_test.sh dev release
  tools/dev/rail_fault_agent.sh "$ROOT/build/dev/rail-fault" 7200 > build/gate-railhelper.log 2>&1 &
  helper=$!
  s rdma-rxe0 dev --rdma env MIRA_REQUIRE_MULTIRAIL=1 tools/ci/rdma_test.sh dev rxe0
  kill $helper 2>/dev/null || true; wait $helper 2>/dev/null || true; helper=""
  s engine-contract tools/ci/engine_contract.sh
  s engine-contract-bundle tools/ci/engine_contract.sh --bundle-mode
  s docker-e2e tools/ci/docker_e2e.sh
  echo "OK: lane devrel $(date '+%H:%M:%S')"
}
# Without RDMA the rxe0 docker e2e cannot run; still build both deploy images and start the controller one (as docker_e2e.sh does).
docker_images_smoke() {
  local v; v=$(sed -n 's/^project(miracache VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
  deploy/docker/build.sh > build/docker-images-build.log 2>&1 || { tail -30 build/docker-images-build.log; echo "FAIL: docker images build"; return 1; }
  tail -1 build/docker-images-build.log
  docker image inspect "miracache-memnode:$v" >/dev/null || { echo "FAIL: no miracache-memnode:$v"; return 1; }
  docker run --rm --entrypoint mira-controller "miracache-controller:$v" --help 2>&1 | grep -q 'store-dir' \
    || { echo "FAIL: controller image does not start"; return 1; }
  echo "OK: docker images miracache-memnode:$v miracache-controller:$v (controller smoke ok; rxe0 e2e skipped)"
}
lane_stub() {  # $1 lane
  echo "stub lane $1 start"
  if [[ $1 == devrel ]]; then if [[ -n $rdma_skip ]]; then echo "stub devrel: rdma=skipped"; else echo "stub devrel: rdma=run"; fi; fi
  local p f
  for p in $(lane_presets "$1"); do   # stands in for ctest: report the cost data it found, then rewrite it
    f=$(costdata_file "$p"); mkdir -p "$(dirname "$f")"
    echo "stub costdata $p: $(if [[ -s $f ]]; then head -1 "$f"; else echo none; fi)"
    echo "stub-costdata lane=$1 preset=$p pid=$$" > "$f"
  done
  [[ $1 == product ]] && echo "stub product: systemd=${prod_sd:-run} rehearsal=${prod_rh:-run}"
  case " ${MIRA_GATE_STUB_FAIL:-} " in *" $1 "*) sleep 1; echo "stub lane $1 failing"; return 1 ;; esac  # fails early
  sleep "${MIRA_GATE_STUB_SLEEP:-2}"
  echo "OK: lane $1 (stub)"
}
run_lane() { if (( STUB )); then lane_stub "$1"; else "lane_$1"; fi; }

# ---- ctest cost data (gate tail): longest tests first, even in a fresh build dir ----
# Stub mode keeps its fake build dirs under build/gate-stub so a stub run never touches a real build dir.
if (( STUB )); then BROOT=${MIRA_GATE_STUB_BUILD:-build/gate-stub}; else BROOT=build; fi
COSTDIR=${MIRA_GATE_COSTDIR:-$BROOT/gate-costdata}
lane_presets() {  # $1 lane: the ctest presets its build_and_test.sh run uses (siw0's rdma-only pass refreshes none)
  case $1 in asan) echo asan ;; tsan) echo tsan ;; simfuzz) echo sim fuzz ;; devrel) echo dev release ;; esac
}
costdata_file() { echo "$BROOT/$1/Testing/Temporary/CTestCostData.txt"; }
seed_costdata() {  # $1 lane: copy the last green gate's cost data into a build dir that has none
  local p f src
  for p in $(lane_presets "$1"); do
    f=$(costdata_file "$p"); src=$COSTDIR/$p.txt
    if [[ -s $src && ! -s $f ]]; then
      mkdir -p "$(dirname "$f")" && cp "$src" "$f" && echo "  costdata $p: seeded from $src"
    fi
  done
  return 0
}
save_costdata() {  # $1 lane (green): keep its presets' cost data outside the build dirs for the next gate
  local p f
  for p in $(lane_presets "$1"); do
    f=$(costdata_file "$p")
    if [[ -s $f ]]; then
      mkdir -p "$COSTDIR" && cp "$f" "$COSTDIR/$p.txt.tmp" && mv -f "$COSTDIR/$p.txt.tmp" "$COSTDIR/$p.txt"
    fi
  done
  return 0
}

# ---- product step (after siw0, alone): the fully built product as it ships ----
# systemd: tools/ci/systemd_acceptance.sh on a Linux host as root with systemd as PID 1 (else a "skip" line); it reuses this
#   gate's release build (MIRA_ACCEPT_SKIP_BUILD=1) when every artifact it needs is newer than the gate's start, else builds.
#   MIRA_ACCEPT_APT=1 only when the operator sets MIRA_GATE_ACCEPT_APT=1. RAIL_NETDEV is passed through.
# rehearsal: the $0 agentbench rxe0 rehearsal (tools/bench/agentbench_rehearsal.sh) when MIRA_GATE_AGENTBENCH=<agentbench
#   checkout> is set; agentbench is mounted read-only, results go to build/gate-rehearsal/gate-<sha>-<utc>-miracache.
# A TERM to the gate reaches both: kill_tree TERMs the scripts, and the lane waits for systemd_acceptance's teardown.
if [[ $(uname -s) == Linux && $(id -u) == 0 && -d /run/systemd/system ]]; then prod_sd=""
elif [[ $(uname -s) != Linux ]]; then prod_sd="not a Linux host"
elif [[ $(id -u) != 0 ]]; then prod_sd="not root"
else prod_sd="systemd is not PID 1"; fi
prod_rh=""; [[ -n ${MIRA_GATE_AGENTBENCH:-} ]] || prod_rh="MIRA_GATE_AGENTBENCH not set"
if [[ -n $prod_sd && -n $prod_rh ]]; then prod_tag="product(skipped)"
elif [[ -n $prod_sd ]]; then prod_tag="product(systemd skipped)"
elif [[ -n $prod_rh ]]; then prod_tag="product(rehearsal skipped)"
else prod_tag="product"; fi
STAMP=$BROOT/gate-start.stamp; mkdir -p "$BROOT"; : > "$STAMP"   # artifacts newer than this were built by this gate
lane_product() {
  set +e  # each step checks its own status
  local child="" r sd_line="skipped" rh_line="skipped" f skip_build=1 ab run
  # A TERM (kill_tree) or INT: let the running script finish its own teardown before this lane exits.
  trap '[[ -n $child ]] && { kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null; }; exit 143' TERM
  trap '[[ -n $child ]] && { kill -TERM "$child" 2>/dev/null; wait "$child" 2>/dev/null; }; exit 130' INT
  fgw() { "$@" & child=$!; wait "$child"; r=$?; child=""; return $r; }
  if [[ -n $prod_sd ]]; then echo "skip product/systemd: $prod_sd"
  else
    for f in build/release/server/mira-memnode build/release/bin/mira-controller build/release/bin/mirctl \
             build/release/tests/miracache_e2e_rdma_tests; do
      [[ -x $f && $f -nt $STAMP ]] || skip_build=0
    done
    echo "+ [product/systemd] $(date '+%H:%M:%S') (MIRA_ACCEPT_SKIP_BUILD=$skip_build)"
    fgw env MIRA_ACCEPT_SKIP_BUILD=$skip_build RAIL_NETDEV="$RAIL_NETDEV" \
      ${MIRA_GATE_ACCEPT_APT:+MIRA_ACCEPT_APT=$MIRA_GATE_ACCEPT_APT} tools/ci/systemd_acceptance.sh > build/gate-product-systemd.log 2>&1
    r=$?; sed 's/^/  [systemd] /' build/gate-product-systemd.log
    sd_line=$(grep -E '^(OK|FAIL): ' build/gate-product-systemd.log | tail -1)
    (( r == 0 )) || { echo "FAIL: product/systemd: ${sd_line:-exit $r}"; return 1; }
  fi
  if [[ -n $prod_rh ]]; then echo "skip product/rehearsal: $prod_rh"
  else
    ab=$(cd "$MIRA_GATE_AGENTBENCH" 2>/dev/null && pwd) || { echo "FAIL: product/rehearsal: no directory $MIRA_GATE_AGENTBENCH"; return 1; }
    if [[ ! -x build/release/server/mira-memnode || ! -f build/release/client/libmiracache.so ]]; then
      echo "+ [product/rehearsal build] $(date '+%H:%M:%S')"
      fgw dev -- bash -c "cmake --preset release >/dev/null && cmake --build --preset release --target mira-memnode miracache_shared" \
        || { echo "FAIL: product/rehearsal: release build of mira-memnode + libmiracache.so"; return 1; }
    fi
    rsha=$(git rev-parse --short HEAD 2>/dev/null) || rsha=""
    [[ -z $rsha && -s build/TIP ]] && rsha=$(head -1 build/TIP | awk '{print $1}')
    rsha=${rsha:-unknown}
    run=gate-${rsha}-$(date -u '+%Y%m%dT%H%M%SZ')
    echo "+ [product/rehearsal] $(date '+%H:%M:%S') RUN_NAME=$run"
    fgw env MIRA_EXTRA_RO_MOUNT="$ab:/agentbench" MIRA_DEV_CPUS=$CPUS MIRA_DEV_MEM=$MEM tools/dev/run.sh --rdma -- env \
      AGENTBENCH_DIR=/agentbench RESULTS_DIR=/work/build/gate-rehearsal DEV=rxe0 CONFIG=configs/kvtier/rehearsal-rxe0.yaml \
      RUN_NAME="$run" MEMNODE=/work/build/release/server/mira-memnode LIB=/work/build/release/client/libmiracache.so \
      PYPATH=/work/python tools/bench/agentbench_rehearsal.sh > build/gate-product-rehearsal.log 2>&1
    r=$?; sed 's/^/  [rehearsal] /' build/gate-product-rehearsal.log
    rh_line=$(grep -E '^(OK|FAIL): ' build/gate-product-rehearsal.log | tail -1)
    (( r == 0 )) || { echo "FAIL: product/rehearsal: ${rh_line:-exit $r}"; return 1; }
  fi
  echo "OK: lane product: systemd: ${prod_sd:+skipped ($prod_sd)}${sd_line#skipped}; rehearsal: ${prod_rh:+skipped ($prod_rh)}${rh_line#skipped}"
}

# ---- scheduler: bash 3.2 (no wait -n, no associative arrays), so lanes are polled through bash's own job table ----
# (R23) Liveness is `jobs -r -p` membership, never a bare `kill -0 $pid`: bash drops a reaped child from its job table, so a
# reused pid can't look alive or get its process tree killed. A signal that arrives while a lane is being launched is
# deferred (launching=1, sigpend=NAME) and handled once pid + state are recorded, so no lane is left unkilled.
cur=()      # lane names of the current set
pids=()     # pid per lane (index = position in cur)
state=()    # 0 queued, 1 running, 2 done
failed=""   # names of failed lanes
rc=0
abort=0
ncur=0
launching=0
sigpend=""

is_running() {  # $1 pid: still a running child of this shell?
  case " $(jobs -r -p | tr '\n' ' ') " in *" $1 "*) return 0 ;; esac
  return 1
}
kill_tree() {  # $1 pid (a live child, checked by the caller): children first, then the pid itself
  local c
  for c in $(pgrep -P "$1" 2>/dev/null); do kill_tree "$c"; done
  kill "$1" 2>/dev/null || true
}
kill_running() {
  local i
  for ((i = 0; i < ncur; i++)); do
    if [[ ${state[$i]} == 1 ]] && is_running "${pids[$i]}"; then kill_tree "${pids[$i]}"; fi
  done
  if (( ! STUB )); then
    # lane containers and docker-e2e's mira-e2e-* nodes all carry the gate label; -a also finds stopped ones
    local ids; ids=$(docker ps -aq --filter "label=$MIRA_DEV_LABEL" 2>/dev/null)
    # shellcheck disable=SC2086
    [[ -n $ids ]] && docker rm -f $ids >/dev/null 2>&1
  fi
  for ((i = 0; i < ncur; i++)); do
    if [[ ${state[$i]} == 1 ]]; then wait "${pids[$i]}" 2>/dev/null; state[$i]=2; fi
  done
  return 0
}
on_signal() {  # $1 signal name
  if (( launching )); then sigpend=$1; return 0; fi   # handled right after the launch records pid + state
  trap '' INT TERM
  echo "FAIL: full gate interrupted by $1; killing lanes"
  kill_running
  if [[ $1 == INT ]]; then exit 130; else exit 143; fi
}
trap 'on_signal INT' INT
trap 'on_signal TERM' TERM

reap() {  # $1 index: a lane that exited
  local l=${cur[$1]} log=build/gate-${cur[$1]}.log
  if wait "${pids[$1]}"; then
    echo "  ok   $l $(date '+%H:%M:%S'): $(grep -E '^OK: ' "$log" | tail -1)"
    save_costdata "$l"
  else
    echo "  FAIL $l $(date '+%H:%M:%S'): $(tail -3 "$log" | tr '\n' ' ')"
    rc=1; failed="$failed $l"
    (( KEEP )) || abort=1
  fi
  # B-2: rdma_test.sh's per-device R15 late-open counts (rxe0 in devrel, siw0), shown even for a green lane
  grep -E '^R15 [^:]+: ' "$log" 2>/dev/null | sed 's/^/       /'
  state[$1]=2
}
heartbeat() {  # one line per running lane: its last ctest progress line or preset header (a stub lane has none)
  local i log last lines
  for ((i = 0; i < ncur; i++)); do
    [[ ${state[$i]} == 1 ]] || continue
    log=build/gate-${cur[$i]}.log
    last=$(grep -aE '^ *[0-9]+/[0-9]+ Test +#|^=== ' "$log" 2>/dev/null | tail -1 | sed 's/^ *//' | cut -c1-120)
    # The log's size too: the scheduler is alive either way, a lane whose count stops growing is the one to look at.
    lines=$(wc -l < "$log" 2>/dev/null | tr -d ' ')
    echo "  ..   ${cur[$i]} $(date '+%H:%M:%S'): ${last:-running} (log ${lines:-0} lines)"
  done
  return 0
}
run_set() {  # $1 max parallel, then lane names
  local mp=$1 i running next=0 n hb_at; shift
  hb_at=$(( $(date +%s) + HEARTBEAT ))
  cur=("$@"); n=$#; ncur=$n; pids=(); state=()
  for ((i = 0; i < n; i++)); do state[$i]=0; pids[$i]=0; done
  while :; do
    running=0
    for ((i = 0; i < n; i++)); do
      if [[ ${state[$i]} == 1 ]]; then
        if is_running "${pids[$i]}"; then running=$((running + 1)); else reap "$i"; fi
      fi
    done
    if (( abort )); then kill_running; return 0; fi
    while (( next < n && running < mp )); do
      echo "+ [lane ${cur[$next]}] $(date '+%H:%M:%S') -> build/gate-${cur[$next]}.log"
      seed_costdata "${cur[$next]}"
      launching=1
      ( run_lane "${cur[$next]}" ) > "build/gate-${cur[$next]}.log" 2>&1 &
      pids[$next]=$!; state[$next]=1
      launching=0
      if [[ -n $sigpend ]]; then on_signal "$sigpend"; fi
      next=$((next + 1)); running=$((running + 1))
    done
    (( running == 0 && next >= n )) && return 0
    if (( HEARTBEAT > 0 && $(date +%s) >= hb_at )); then
      heartbeat
      hb_at=$(( $(date +%s) + HEARTBEAT ))
    fi
    sleep "$POLL"
  done
}

lanes=(asan tsan simfuzz devrel); (( x86 )) && lanes+=(x86)
run_set "$maxpar" "${lanes[@]}"
if (( abort )); then
  skipped=" siw0 product skipped"
elif [[ -n $rdma_skip ]]; then
  skipped=""
  echo "skip rdma: siw0: $rdma_skip"
  echo "skip rdma: product (systemd acceptance + agentbench rxe0 rehearsal): $rdma_skip"
else
  skipped=""
  echo "+ [siw0 alone] $(date '+%H:%M:%S')"
  run_set 1 siw0
  if (( abort )); then
    skipped=" product skipped"
  else
    echo "+ [product alone] $(date '+%H:%M:%S'): ${prod_sd:+skip product/systemd: $prod_sd; }${prod_rh:+skip product/rehearsal: $prod_rh}"
    run_set 1 product
  fi
fi

min=$(( ($(date +%s) - t0) / 60 ))
# A host without .git (an rsynced VM copy) names the tip from build/TIP when present (first word), else "unknown".
sha=$(git rev-parse --short HEAD 2>/dev/null) || sha=""
[[ -z $sha && -s build/TIP ]] && sha=$(head -1 build/TIP | awk '{print $1}')
sha=${sha:-unknown}
if (( rc == 0 )) && [[ -n $rdma_skip ]]; then
  echo "OK: full gate $sha in $min min (asan tsan sim fuzz dev release pybind engines docker-images rdma(skipped)$( ((x86)) && echo ' x86'))"
elif (( rc == 0 )); then echo "OK: full gate $sha in $min min (asan tsan sim fuzz dev release pybind rxe0 engines docker siw0 $prod_tag$( ((x86)) && echo ' x86'))"
else echo "FAIL: full gate $sha after $min min: failed lane(s):${failed}.${skipped:+$skipped.} (see build/gate-*.log)"; fi
exit $rc
