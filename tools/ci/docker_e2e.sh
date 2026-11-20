#!/usr/bin/env bash
# Docker end to end on soft-RDMA (rxe0). Host-side bash, like engine_contract.sh; needs the
# open-source Docker engine/CLI and a host prepared with tools/dev/rdma_setup.sh (done here if rxe0 is missing).
# "The VM" is the colima VM on a Mac, or the Linux host itself when no colima is running (tools/dev/hostvm.sh).
# RAIL_NETDEV (default eth0) is the netdev rxe0 sits on.
#   tools/ci/docker_e2e.sh
# 1. builds miracache-memnode and miracache-controller (deploy/docker/build.sh);
# 2. starts 3 memory-node containers on rxe0 (deploy/docker/run-memnode.sh; own state volume and ports each,
#    lab certs from tools/dev/lab-certs.sh);
# 3. runs the multi-node client e2e (tests/e2e/multi_node_rdma_test.cpp, ExternalNodes) against them from
#    the dev container (tools/dev/run.sh --rdma): store, lookup, fetch, byte-for-byte oracle;
# 4. `docker stop` on node 2 (exit status 0 or 3 inside the stop timeout, drain logged), restarts it on the
#    SAME state volume and checks it keeps its node ID;
# 5. checks the logs and /metrics carry the HOST's hostname and IP, then removes every container and volume it made.
# Final line: "OK: docker e2e ..." or "FAIL: ...". The images stay (rebuilds are cached).
set -u  # no pipefail: "docker logs | grep -q" would fail on SIGPIPE
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT"
W=$ROOT/build/docker-e2e
VERSION=$(sed -n 's/^project(miracache VERSION \([0-9.]*\).*/\1/p' CMakeLists.txt)
N=3
RAIL0=17471 ADMIN0=19465 TEL0=19474  # admin 19466-68, telemetry 19475-77: keep the ranges apart
DRAIN_MS=3000
t_start=$(date +%s)
result=""

cleanup() {
  for i in $(seq 1 $N); do
    docker rm -f "mira-e2e-$i" >/dev/null 2>&1
    docker volume rm "mira-e2e-$i-state" >/dev/null 2>&1
  done
  rm -rf "$W"
}
fail() { result="FAIL: $*"; exit 1; }
finish() {
  cleanup
  if [[ -z $result ]]; then result="FAIL: aborted (see output above)"; fi
  echo "$result"
  [[ $result == OK:* ]]
}
trap finish EXIT

mkdir -p "$ROOT/build"
source "$ROOT/tools/dev/hostvm.sh"
command -v docker >/dev/null || fail "docker is required"
[[ $HOSTVM_MODE != none ]] || fail "need a running colima VM (macOS) or a Linux host"
netdev=${RAIL_NETDEV:-eth0}
free_gib=$(( $(df -Pk / | awk 'NR==2 {print $4}') / 1048576 ))  # POSIX df -k: portable (GNU df has no -g)
[[ $free_gib -ge 12 ]] || fail "only ${free_gib} GiB free on / (need 12)"

if ! vm sh -c 'rdma link show 2>/dev/null | grep -q "^link rxe0/"'; then tools/dev/rdma_setup.sh "$netdev" >/dev/null || fail "rdma_setup.sh"; fi
IP=$(vm ip -4 -o addr show "$netdev" | awk 'NR==1 {sub(/\/.*/, "", $4); print $4}')
VMHOST=$(vm hostname)
[[ -n $IP && -n $VMHOST ]] || fail "cannot read the VM address or hostname"
echo "== VM host=$VMHOST rxe0 ip=$IP"

echo "== build images"
deploy/docker/build.sh >"$ROOT/build/docker-e2e-build.log" 2>&1 || { tail -30 "$ROOT/build/docker-e2e-build.log"; fail "image build"; }
tail -1 "$ROOT/build/docker-e2e-build.log"
for img in memnode controller; do docker image ls --format '   {{.Repository}}:{{.Tag}} {{.Size}}' "miracache-$img:$VERSION"; done

echo "== build the e2e client test (dev container)"
tools/dev/run.sh -- bash -c 'cmake --preset dev -DMIRACACHE_WERROR=ON >/dev/null && cmake --build --preset dev --target miracache_e2e_rdma_tests' \
  >"$ROOT/build/docker-e2e-test-build.log" 2>&1 || { tail -30 "$ROOT/build/docker-e2e-test-build.log"; fail "e2e test build"; }

echo "== certs and configs"
mkdir -p "$W" && chmod 700 "$W"
bash tools/dev/lab-certs.sh "$W/pki" --nodes 1,2,3 --clients 1 >/dev/null || fail "lab-certs"
for i in $(seq 1 $N); do
  cat >"$W/node$i.toml" <<EOF
[node]
device = "rxe0"
listen = ["$IP:$((RAIL0 + i))"]
state_dir = "/var/lib/miracache"
drain_ms = $DRAIN_MS
[store]
backing = "anon"
segment_bytes = 4194304
run_bytes = 262144
min_block_bytes = 4096
n_segments = 4
max_scopes = 1000
max_bytes = 8388608
[lab]
principal = "lab"
identities = ["spiffe://lab/client-1"]
[admin]
listen = "127.0.0.1:$((ADMIN0 + i))"
cert = "/run/miracache/pki/node-$i.pem"
key = "/run/miracache/pki/node-$i.key"
ca = "/run/miracache/pki/ca.pem"
[telemetry]
listen = "127.0.0.1:$((TEL0 + i))"
EOF
done

export MIRA_RUN_USER="$(id -u):$(id -g)" MIRA_PKI_DIR="$W/pki"
start_node() {  # start_node <i>
  MIRA_NAME="mira-e2e-$1" MIRA_CONFIG="$W/node$1.toml" deploy/docker/run-memnode.sh ${MIRA_DEV_LABEL:+-- --label "$MIRA_DEV_LABEL"} >/dev/null
}
wait_listening() {  # wait_listening <i>
  for _ in $(seq 1 120); do
    docker logs "mira-e2e-$1" 2>&1 | grep -q 'msg="listening"' && return 0
    [[ $(docker inspect -f '{{.State.Running}}' "mira-e2e-$1" 2>/dev/null) == true ]] || { docker logs "mira-e2e-$1" 2>&1 | tail -15; return 1; }
    sleep 0.5
  done
  docker logs "mira-e2e-$1" 2>&1 | tail -15
  return 1
}
node_id() {  # node_id <i>: the id the node reports (also in its state volume)
  vm curl -s "http://127.0.0.1:$((TEL0 + $1))/metrics" | sed -n 's/^miracache_node_info{node_id="\([0-9]*\)".*/\1/p' | head -n1
}

echo "== start $N memory-node containers"
for i in $(seq 1 $N); do start_node "$i" || fail "start node $i"; done
for i in $(seq 1 $N); do wait_listening "$i" || fail "node $i did not reach 'listening'"; done
declare -a ID
for i in $(seq 1 $N); do ID[$i]=$(node_id "$i"); [[ -n ${ID[$i]} ]] || fail "node $i reports no node_id on /metrics"; done
echo "   node ids: ${ID[1]} ${ID[2]} ${ID[3]}"
[[ ${ID[1]} != "${ID[2]}" && ${ID[2]} != "${ID[3]}" && ${ID[1]} != "${ID[3]}" ]] || fail "duplicate node ids"

echo "== hostname / IP in logs and metrics (host network: must be the VM's, not a container's)"
for i in $(seq 1 $N); do
  line=$(docker logs "mira-e2e-$i" 2>&1 | grep 'msg="listening"' | head -n1)
  grep -q "host=$VMHOST " <<<"$line" || fail "node $i log host is not $VMHOST: $line"
  grep -q "node_id=${ID[$i]} " <<<"$line" || fail "node $i log lacks its node_id: $line"
  grep -q "addr=$IP:$((RAIL0 + i))" <<<"$line" || fail "node $i log addr is not $IP:$((RAIL0 + i)): $line"
  vm curl -s "http://127.0.0.1:$((TEL0 + i))/metrics" | grep "^miracache_node_info{" | grep -q "hostname=\"$VMHOST\"" \
    || fail "node $i miracache_node_info lacks hostname=$VMHOST"
done
echo "   $(docker logs mira-e2e-1 2>&1 | grep 'msg="listening"' | head -n1)"

echo "== client e2e from the dev container"
rails=$((RAIL0 + 1)),$((RAIL0 + 2)),$((RAIL0 + 3)); admins=$((ADMIN0 + 1)),$((ADMIN0 + 2)),$((ADMIN0 + 3))
tools/dev/run.sh --rdma -- bash -c "MIRA_EXT_DEVICE=rxe0 MIRA_EXT_IP=$IP MIRA_EXT_RAILS=$rails MIRA_EXT_ADMIN=$admins MIRA_EXT_PKI=/work/build/docker-e2e/pki \
  build/dev/tests/miracache_e2e_rdma_tests --gtest_filter='ExternalNodes.*'" >"$W/client.log" 2>&1
rc=$?
ext=$(grep '^\[EXT\]' "$W/client.log" | tail -n1)
if [[ $rc -ne 0 || $ext != *"oracle=ok"* ]]; then tail -30 "$W/client.log"; fail "client e2e (rc=$rc)"; fi
echo "   $ext"

echo "== docker stop node 2, then restart on the same state volume"
t0=$(date +%s.%N)
docker stop mira-e2e-2 >/dev/null || fail "docker stop"
t1=$(date +%s.%N)
code=$(docker inspect -f '{{.State.ExitCode}}' mira-e2e-2)
stop_s=$(awk -v a="$t0" -v b="$t1" 'BEGIN {printf "%.1f", b - a}')
[[ $code == 0 || $code == 3 ]] || { docker logs mira-e2e-2 2>&1 | tail -15; fail "stop exit code $code (want 0, or 3 = not marked clean)"; }
timeout_s=$(docker inspect -f '{{.Config.StopTimeout}}' mira-e2e-2)
awk -v s="$stop_s" -v t="$timeout_s" 'BEGIN {exit !(s < t)}' || fail "stop took ${stop_s}s (timeout ${timeout_s}s)"
drain=$(docker logs mira-e2e-2 2>&1 | grep -E 'GOAWAY sent|drain complete|drain deadline' | sed 's/.*msg=//' | tr '\n' ';')
[[ -n $drain ]] || fail "no drain log lines after SIGTERM"
echo "   exit=$code in ${stop_s}s (timeout ${timeout_s}s); drain: $drain"
docker rm mira-e2e-2 >/dev/null
start_node 2 || fail "restart node 2"
wait_listening 2 || fail "restarted node 2 did not reach 'listening'"
id2=$(node_id 2)
[[ $id2 == "${ID[2]}" ]] || fail "node 2 changed its id across the restart: ${ID[2]} -> $id2"
docker logs mira-e2e-2 2>&1 | grep -q 'node replaced' && fail "restarted node 2 logged 'node replaced'"
echo "   node 2 kept id $id2 on its state volume"

echo "== controller image smoke"
docker run --rm --entrypoint mira-controller "miracache-controller:$VERSION" --help 2>&1 | grep -q 'store-dir' || fail "controller image does not start"

dt=$(( $(date +%s) - t_start ))
result="OK: docker e2e ($ext; stop exit=$code ${stop_s}s; ids kept; host=$VMHOST ip=$IP; ${dt}s)"
