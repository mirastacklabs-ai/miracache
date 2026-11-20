#!/usr/bin/env bash
# $0 rehearsal harness: runs an agentbench `kvtier` config (configs/kvtier/rehearsal-rxe0.yaml,
# saturation-rxe0.yaml, ...) against a real mira-memnode on a soft-RDMA device. It is
# miracache-specific (memnode TOML, lab PKI, mira-memnode start), so it lives here, not in
# agentbench; agentbench keeps only its generic stage and the named YAML configs.
# Runs INSIDE the miracache dev image (it has perftest, rdma-core, python3-venv) with the memory-node binary, the client
# library and a soft-RDMA device (rxe0). Python: /opt/venv if it exists (agentbench image); otherwise a venv cached at
# build/rehearsal-venv-<hash of agentbench pyproject.toml> with agentbench's declared dependencies (created on first run, needs
# network for pip). agentbench itself is used in place (PYTHONPATH), so a READ-ONLY mount of it works.
# Nothing here is billable; nothing is deleted.
#
# Env (required): MEMNODE (binary), LIB (libmiracache.so), PYPATH (client python dir),
#                 RUN_NAME (NEW results name prefix; an existing results dir is refused).
# Env (optional): RESULTS_DIR (default AGENTBENCH_DIR/results; set it, e.g. build/rehearsal-results, when agentbench is
#                 mounted read-only), AGENTBENCH_DIR (agentbench checkout; default: ../agentbench next to the miracache
#                 checkout), DEV (default rxe0), CONFIG (default configs/kvtier/rehearsal-rxe0.yaml,
#                 relative to AGENTBENCH_DIR), BW_SIZE (ib_read_bw message size, default 65536),
#                 NSEG (segments, default 16), RUN_BYTES / SEGMENT_BYTES (default: derived from the
#                 config's block_size, see below), PRE_TEST (pytest args run first; failure stops),
#                 SKIP_MOCK, CPU_LOG (set to capture top into cpu.log), CPU_SAMPLES (default 60),
#                 RUN_TIMEOUT (seconds, default 240), TELEMETRY_PORT (memnode /metrics port, default 9464).
# Sizing: run_bytes = power of two >= 4 x (block_size + header), header = 64 + 16 x ceil(block_size / 64 KiB) B and segment_bytes = max(16 MiB,
#   2 x run_bytes), unless RUN_BYTES / SEGMENT_BYTES are set. block_size is the largest `block_size:`
#   in the config (workload and variants). Fails at once if block_size + header > run_bytes.
# The last output line is always `OK: ...` or `FAIL: ...`; memnode.log is always copied to the results dir.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
DEV=${DEV:-rxe0}
TELEMETRY_PORT=${TELEMETRY_PORT:-9464}
if ! [[ $TELEMETRY_PORT =~ ^[0-9]+$ ]] || (( TELEMETRY_PORT < 1 || TELEMETRY_PORT > 65535 )); then
  echo "FAIL: TELEMETRY_PORT must be 1..65535, got '$TELEMETRY_PORT'" >&2; exit 1
fi
AB=${AGENTBENCH_DIR:-$ROOT/../agentbench}
: "${MEMNODE:?}" "${LIB:?}" "${PYPATH:?}" "${RUN_NAME:?}"
res="$RUN_NAME-miracache"
work=; pids=(); finished=0

say_fail() { echo "FAIL: $*" >&2; finished=1; exit 1; }
cleanup() {
  local rc=$?
  for p in "${pids[@]:-}"; do [[ -n $p ]] && kill "$p" 2>/dev/null || true; done
  if [[ -n $work && -n ${RESULTS_DIR:-} ]]; then
    # always keep the node log (and what rendered/sampled), success or failure
    mkdir -p "$RESULTS_DIR/$res" 2>/dev/null || true
    for f in memnode.log cpu.log; do [[ ! -f $work/$f ]] || cp "$work/$f" "$RESULTS_DIR/$res/$f" 2>/dev/null || true; done
    [[ ! -f $work/rehearsal.yaml ]] || cp "$work/rehearsal.yaml" "$RESULTS_DIR/$res/rendered-config.yaml" 2>/dev/null || true
  fi
  [[ -z $work ]] || rm -rf "$work"
  if [[ $rc -ne 0 && $finished -eq 0 ]]; then echo "FAIL: unexpected exit $rc" >&2; fi
}
trap cleanup EXIT

[[ -d $AB ]] || say_fail "agentbench checkout not found at $AB (set AGENTBENCH_DIR)"
AB=$(cd "$AB" && pwd)
cd "$AB"
CONFIG=${CONFIG:-configs/kvtier/rehearsal-rxe0.yaml}
[[ -f $CONFIG ]] || say_fail "config $CONFIG not found in $AB"

# --- results location: default AGENTBENCH_DIR/results; RESULTS_DIR lets agentbench be mounted read-only ---
RESULTS_DIR=${RESULTS_DIR:-$AB/results}
mkdir -p "$RESULTS_DIR" || say_fail "cannot create RESULTS_DIR $RESULTS_DIR"
RESULTS_DIR=$(cd "$RESULTS_DIR" && pwd)

# --- interpreter: /opt/venv if present (agentbench image), else a cached venv holding agentbench's declared
# dependencies (read from its pyproject.toml; agentbench itself is used in place via PYTHONPATH, so a read-only mount works) ---
if [[ -x /opt/venv/bin/python ]]; then
  PY=/opt/venv/bin/python
else
  [[ -f $AB/pyproject.toml ]] || say_fail "no /opt/venv and no $AB/pyproject.toml to build a venv from"
  BOOT_PY=python3
  vsum=$(sha256sum "$AB/pyproject.toml" | cut -c1-12)
  venv="$ROOT/build/rehearsal-venv-$vsum"
  if [[ ! -x $venv/bin/python ]]; then
    echo "creating rehearsal venv $venv from $AB/pyproject.toml dependencies (first run only)"
    rm -rf "$venv.tmp"
    mkdir -p "$ROOT/build"
    "$BOOT_PY" -m venv "$venv.tmp" || say_fail "venv creation failed (python3-venv missing from the image?)"
    "$BOOT_PY" -c 'import sys, tomllib
d = tomllib.load(open(sys.argv[1], "rb"))
print("\n".join(d["project"]["dependencies"] + ["pytest>=8.3.0", "pytest-asyncio>=0.24.0"]))' "$AB/pyproject.toml" \
      > "$venv.tmp/requirements.txt" || say_fail "cannot read dependencies from $AB/pyproject.toml"
    "$venv.tmp/bin/pip" install --quiet -r "$venv.tmp/requirements.txt" || say_fail "pip install of agentbench dependencies failed"
    mv "$venv.tmp" "$venv"
  fi
  PY=$venv/bin/python
fi
echo "python: $PY; results: $RESULTS_DIR"

# --- sizing from the config's block size (K05) ---
block=$(grep -oE '^[[:space:]]*(-[[:space:]]*)?block_size:[[:space:]]*[0-9]+|[{,][[:space:]]*block_size:[[:space:]]*[0-9]+' "$CONFIG" | grep -oE '[0-9]+$' | sort -n | tail -1 || true)
block=${block:-0}
# Stored size of a block = 64 B extent header + payload + 16 B GCM tag per segment (core/proto/extent_header.h,
# core/crypto/block_codec.h; segment >= 64 KiB, kMinLog2Segment = 16), so the overhead is at most
# 64 + 16 x ceil(P / 64 KiB). The 128 B server header lives in the header table, not in the run. Not a fixed 4096 B:
# it grows with the block (a block > 16 MiB needs more than 4096 B).
HEADER_BYTES=$(( 64 + 16 * ((block + 65535) / 65536) ))
if [[ -z ${RUN_BYTES:-} ]]; then
  need=$(( 4 * (block + HEADER_BYTES) )); RUN_BYTES=262144
  while (( RUN_BYTES < need )); do RUN_BYTES=$(( RUN_BYTES * 2 )); done
fi
if (( block > 0 && block + HEADER_BYTES > RUN_BYTES )); then
  say_fail "block_size $block + header $HEADER_BYTES > run_bytes $RUN_BYTES: every put would be refused (raise RUN_BYTES or unset it)"
fi
SEGMENT_BYTES=${SEGMENT_BYTES:-$(( 2 * RUN_BYTES > 16777216 ? 2 * RUN_BYTES : 16777216 ))}
NSEG=${NSEG:-16}
(( SEGMENT_BYTES >= 2 * RUN_BYTES )) || say_fail "segment_bytes $SEGMENT_BYTES < 2 x run_bytes $RUN_BYTES"
echo "sizing: block_size=$block run_bytes=$RUN_BYTES segment_bytes=$SEGMENT_BYTES n_segments=$NSEG"

# optional: offline tests first (PRE_TEST="tests/test_kvtier*.py"); a failure stops the run (K11)
if [[ -n ${PRE_TEST:-} ]]; then
  if ! "$PY" -m pytest -q -p no:cacheprovider $PRE_TEST 2>&1 | tail -n 3; then
    say_fail "pre-tests"
  fi
fi
for s in miracache $([[ -n ${SKIP_MOCK:-} ]] || echo mock); do
  [[ ! -e $RESULTS_DIR/$RUN_NAME-$s ]] || say_fail "$RESULTS_DIR/$RUN_NAME-$s exists; pick a new RUN_NAME"
done
netdev=$(rdma link show "$DEV/1" | sed -n 's/.* netdev \([^ ]*\).*/\1/p' || true)
ip=$(ip -4 -o addr show dev "${netdev:-eth0}" | awk '{print $4}' | cut -d/ -f1 | head -1 || true)
[[ -n ${ip:-} ]] || say_fail "no IPv4 for $DEV"
work=$(mktemp -d)

# memory node (lab PKI, secret, soft-RDMA listener, /metrics on 127.0.0.1:$TELEMETRY_PORT, default 9464)
rp=$((20000 + RANDOM % 20000)); ap=$((rp + 1))
bash "$HERE/../dev/lab-certs.sh" "$work/pki" --nodes 1 --clients 1 >/dev/null
printf 'current = 1\n1 = %s\n' "$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')" > "$work/secret.json"; chmod 600 "$work/secret.json"
cat > "$work/node.toml" <<EOT
[node]
device = "$DEV"
listen = ["$ip:$rp"]
state_dir = "$work/state"
[store]
backing = "anon"
segment_bytes = $SEGMENT_BYTES
run_bytes = $RUN_BYTES
min_block_bytes = 4096
n_segments = $NSEG
max_scopes = 64
max_bytes = $(( NSEG * SEGMENT_BYTES ))
[lab]
principal = "lab"
identities = ["spiffe://lab/client-1"]
[admin]
listen = "127.0.0.1:$ap"
cert = "$work/pki/node-1.pem"
key = "$work/pki/node-1.key"
ca = "$work/pki/ca.pem"
[telemetry]
listen = "127.0.0.1:$TELEMETRY_PORT"
EOT
cat > "$work/client.toml" <<EOT
[scope]
provider = "static"
secret_file = "$work/secret.json"
[[nodes]]
rails = ["$ip:$rp"]
admin = "127.0.0.1:$ap"
identity = "spiffe://lab/node-1"
[tls]
cert = "$work/pki/client-1.pem"
key = "$work/pki/client-1.key"
ca = "$work/pki/ca.pem"
[fabric]
device = "$DEV"
[lab]
static_membership = true
EOT
"$MEMNODE" --config "$work/node.toml" > "$work/memnode.log" 2>&1 & pids+=($!)
for _ in $(seq 1 200); do
  grep -q listening "$work/memnode.log" && break
  kill -0 "${pids[0]}" 2>/dev/null || { tail -20 "$work/memnode.log" >&2; say_fail "memnode exited"; }
  sleep 0.1
done
grep -q listening "$work/memnode.log" || { tail -20 "$work/memnode.log" >&2; say_fail "memnode did not start"; }

# perftest servers with the arguments the config's client side will use (one connection each)
ib_read_bw  -d "$DEV" -s "${BW_SIZE:-65536}" -n 2000 -F --report_gbits -q 2 -p 18515 > "$work/bw-server.log" 2>&1 & pids+=($!)
ib_read_lat -d "$DEV" -s 4096  -n 2000 -F -p 18516                      > "$work/lat-server.log" 2>&1 & pids+=($!)
sleep 1
for f in bw lat; do echo "== $f server log =="; head -n 6 "$work/$f-server.log"; done

sed -e "s#__SERVER__#$ip#; s#__RUN__#$work#g" "$CONFIG" > "$work/rehearsal.yaml"
if [[ -n ${CPU_LOG:-} ]]; then
  top -b -d 2 -n "${CPU_SAMPLES:-60}" -w 200 2>/dev/null | grep --line-buffered -E "^top -|^%Cpu|mira-memnode|python" > "$work/cpu.log" & pids+=($!)
fi
export PYTHONPATH=$PYPATH:$AB MIRACACHE_LIB=$LIB PYTHONDONTWRITEBYTECODE=1
# agentbench writes to ./results/<name>: with a custom RESULTS_DIR run from a scratch dir that mirrors the checkout
# (symlinks, so relative config paths still resolve) with results -> RESULTS_DIR.
if [[ $RESULTS_DIR != "$AB/results" ]]; then
  mkdir -p "$work/cwd"
  for e in "$AB"/* "$AB"/.[!.]*; do
    [[ -e $e && ${e##*/} != results ]] && ln -s "$e" "$work/cwd/${e##*/}"
  done
  ln -s "$RESULTS_DIR" "$work/cwd/results"
  cd "$work/cwd"
fi
if ! timeout "${RUN_TIMEOUT:-240}" "$PY" -m agentbench.cli kvtier run --config "$work/rehearsal.yaml" --output "$RUN_NAME-miracache" 2>&1 | while IFS= read -r l; do echo "$(date +%T) $l"; done; then
  tail -20 "$work/memnode.log" >&2
  for f in "$work"/*-server.log; do tail -n 5 "$f" >&2; done
  say_fail "miracache run"
fi
if [[ -z ${SKIP_MOCK:-} ]]; then
  if ! timeout 240 "$PY" -m agentbench.cli kvtier run --config configs/kvtier/rehearsal-rxe0-mock.yaml --output "$RUN_NAME-mock"; then
    say_fail "mock run"
  fi
fi
finished=1
echo "OK: done: $RESULTS_DIR/$res"
