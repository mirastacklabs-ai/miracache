#!/usr/bin/env bash
# End-to-end pipeline smoke (not numbers): a real mira-memnode on a soft-RDMA device, plus the
# agentbench KV-tier stage driving miracache.bench.agentbench_backend.MiracacheBackend over the
# real libmiracache (wire mode, mTLS tickets). $0: local soft-RDMA only.
#   MIRA_EXTRA_RO_MOUNT=$HOME/repos/github/private/agentbench:/agentbench \
#     tools/dev/run.sh --rdma tools/ci/bench_smoke.sh [device]        (default device rxe0)
# agentbench source is found via AGENTBENCH_SRC (default /agentbench, the read-only mount).
# Steps: build memnode + libmiracache (dev preset) -> lab certs + secret -> memnode up with
# /metrics on :9464 -> small open-loop run -> check the report -> memnode down.
# Prints "OK: ..." on success, "FAIL: ..." otherwise (exit 1).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
ROOT=$PWD
dev=${1:-rxe0}
AB=${AGENTBENCH_SRC:-/agentbench}
[[ -d $AB/agentbench/kvtier ]] || { echo "FAIL: agentbench not at $AB (mount it with MIRA_EXTRA_RO_MOUNT)" >&2; exit 1; }

cmake --preset dev -DMIRACACHE_WERROR=ON >/dev/null
cmake --build --preset dev -j2 --target mira-memnode miracache_shared >/dev/null
MEMNODE=$ROOT/build/dev/server/mira-memnode
[[ -x $MEMNODE ]] || MEMNODE=$(find "$ROOT/build/dev" -name mira-memnode -type f -perm -u+x | head -1)
LIB=$ROOT/build/dev/client/libmiracache.so
[[ -x $MEMNODE && -f $LIB ]] || { echo "FAIL: memnode/libmiracache not built" >&2; exit 1; }

ibv_devices | awk 'NR>2 {print $1}' | grep -qx "$dev" || { echo "FAIL: RDMA device $dev not visible (tools/dev/rdma_setup.sh; run.sh --rdma)" >&2; exit 1; }
# IPv4 of the device's netdev (rdma_cm resolves through it).
netdev=$(rdma link show "$dev/1" 2>/dev/null | sed -n 's/.* netdev \([^ ]*\).*/\1/p' || true)
[[ -n $netdev ]] || netdev=eth0
ip=${MIRA_SMOKE_IP:-$(ip -4 -o addr show dev "$netdev" | awk '{print $4}' | cut -d/ -f1 | head -1)}
[[ -n $ip ]] || { echo "FAIL: no IPv4 on $netdev (set MIRA_SMOKE_IP)" >&2; exit 1; }

work=$(mktemp -d)
mem_pid=""
cleanup() { mkdir -p "${MIRA_SMOKE_OUT:-$ROOT/build/bench_smoke}" && cp "$work/memnode.log" "${MIRA_SMOKE_OUT:-$ROOT/build/bench_smoke}/memnode.log" 2>/dev/null; [[ -n $mem_pid ]] && kill "$mem_pid" 2>/dev/null && wait "$mem_pid" 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT

rdma_port=$((20000 + RANDOM % 20000)); admin_port=$((rdma_port + 1))
metrics_port=${MIRA_SMOKE_METRICS_PORT:-9464}
bash tools/dev/lab-certs.sh "$work/pki" --nodes 1 --clients 1 >/dev/null
# Secret file format (client/scope/engine_native.cpp): "current = <kver>" and "<kver> = <64 hex>".
printf 'current = 1\n1 = %s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$work/secret.json"
chmod 600 "$work/secret.json"

cat > "$work/node.toml" <<EOF
[node]
device = "$dev"
listen = ["$ip:$rdma_port"]
state_dir = "$work/state"
[store]
backing = "anon"
segment_bytes = ${MIRA_SMOKE_SEGMENT:-16777216}
run_bytes = ${MIRA_SMOKE_RUN_BYTES:-262144}
min_block_bytes = 4096
n_segments = 8
max_scopes = 8
max_bytes = ${MIRA_SMOKE_MAX_BYTES:-100663296}
[lab]
principal = "lab"
identities = ["spiffe://lab/client-1"]
[admin]
listen = "127.0.0.1:$admin_port"
cert = "$work/pki/node-1.pem"
key = "$work/pki/node-1.key"
ca = "$work/pki/ca.pem"
[telemetry]
listen = "127.0.0.1:$metrics_port"
EOF

cat > "$work/client.toml" <<EOF
[scope]
provider = "static"
secret_file = "$work/secret.json"
[[nodes]]
rails = ["$ip:$rdma_port"]
admin = "127.0.0.1:$admin_port"
identity = "spiffe://lab/node-1"
[tls]
cert = "$work/pki/client-1.pem"
key = "$work/pki/client-1.key"
ca = "$work/pki/ca.pem"
[fabric]
device = "$dev"
[lab]
static_membership = true
EOF

"$MEMNODE" --config "$work/node.toml" > "$work/memnode.log" 2>&1 &
mem_pid=$!
for _ in $(seq 1 200); do
  grep -q listening "$work/memnode.log" && break
  kill -0 "$mem_pid" 2>/dev/null || { echo "FAIL: mira-memnode exited early:" >&2; cat "$work/memnode.log" >&2; mem_pid=""; exit 1; }
  sleep 0.1
done
grep -q listening "$work/memnode.log" || { echo "FAIL: mira-memnode did not start" >&2; cat "$work/memnode.log" >&2; exit 1; }

# 16 blocks x 64 KiB = 1 MiB working set per op class; staging sized for the concurrency below.
cat > "$work/kvtier.yaml" <<EOF
backend:
  module: miracache.bench.agentbench_backend
  class: MiracacheBackend
  options:
    mode: wire
    config: $work/client.toml
    secret_file: $work/secret.json
    max_op_blocks: ${MIRA_SMOKE_MAX_OP:-64}
    max_inflight: ${MIRA_SMOKE_INFLIGHT:-8}
    timeout_s: 20
baseline:
  type: static
  gbps: 10
metrics:
  scrape: ["http://127.0.0.1:$metrics_port/metrics"]
  timeout_s: 2
workload:
  ops_per_s: 50
  duration_s: 4
  warmup_s: 1
  block_size: ${MIRA_SMOKE_BLOCK:-65536}
  batch_size: ${MIRA_SMOKE_BATCH:-4}
  read_ratio: 0.8
  keyspace: 200
  distribution: uniform
  prefill_fraction: 1.0
  concurrency: 8
  seed: 1
variants:
  - name: default
    options: {}
EOF

out=$work/run
mkdir -p "$out"
export PYTHONPATH=$ROOT/python:$AB MIRACACHE_LIB=$LIB
( cd "$out" && python3 - "$work/kvtier.yaml" <<'PY'
import sys
from agentbench.kvtier.stage import load_config, run_stage
run_stage(load_config(sys.argv[1]), "results/smoke")
PY
) || { echo "FAIL: kvtier stage failed; memnode log:" >&2; tail -20 "$work/memnode.log" >&2; exit 1; }

dest=${MIRA_SMOKE_OUT:-$ROOT/build/bench_smoke}
mkdir -p "$dest"; rm -rf "$dest/smoke"; cp -r "$out/results/smoke" "$dest/smoke"   # keep it even on FAIL
kv=$out/results/smoke/kvtier
[[ -f $out/results/smoke/report.md ]] || { echo "FAIL: report.md missing" >&2; exit 1; }
grep -q "^## Metrics" "$out/results/smoke/report.md" || { echo "FAIL: report.md has no '## Metrics' (Prometheus scrape) section" >&2; exit 1; }
[[ -f $kv/summary.json && -f $kv/metrics/default/deltas.json ]] || { echo "FAIL: report/scrape files missing under $kv" >&2; exit 1; }
res=$(python3 - "$kv/summary.json" "$kv/metrics/default/deltas.json" <<'PY'
import json, sys
s = json.load(open(sys.argv[1])); d = json.load(open(sys.argv[2]))
v = s["variants"][0]
ops = v.get("fetch_blocks_per_s", 0) + v.get("put_blocks_per_s", 0)
errs = v.get("errors", 0)
fams = [k for k in d if isinstance(d[k], dict) and k != "endpoint_urls"]
print(v["status"], ops, errs, len(fams))
bad = v["status"] != "ok" or ops <= 0 or errs != 0
print("variant:", {k: v.get(k) for k in ("fetch_blocks_per_s", "put_blocks_per_s", "hit_rate", "errors")}, file=sys.stderr)
sys.exit(1 if bad else 0)
PY
) || { echo "FAIL: report check (status ops errors): ${res:-?}" >&2; exit 1; }
echo "OK: bench smoke on $dev: (status ops errors scrape-families) = $res; report in $dest/smoke/report.md"
