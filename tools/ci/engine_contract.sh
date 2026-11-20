#!/usr/bin/env bash
# Engine contract run: builds (or reuses) the engines image and runs the contract tests and the
# real-engine construct smokes against the REAL pinned vLLM and SGLang (import-only; no engine
# start, no GPU). Too heavy for the main gate (tools/ci/build_and_test.sh); run it by hand or
# nightly. The fake-based unit suites (tests/python) stay in the gate and are NOT run here.
#   tools/ci/engine_contract.sh                 # exit 0 = all pass and nothing skipped
#   tools/ci/engine_contract.sh --bundle-mode   # the same pass with the engines handed a BUNDLE-MODE client.toml
#                                               # (MB11, P40). Run both for the M2 exit: `tools/ci/engine_contract.sh &&
#                                               # tools/ci/engine_contract.sh --bundle-mode`.
# The contract tests are import-only and use a fake client, so --bundle-mode changes only the client.toml the
# adapters are given (MIRACACHE_CLIENT_TOML, a [control] file written to a temp dir; no [[nodes]], no static
# membership). It proves the adapters accept a bundle-mode config path and never assume lab keys. The real
# bundle-mode Client open on live hardware is tests/e2e/membership_rdma_test.cpp (tools/ci/rdma_test.sh).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUNDLE_MODE=0
case "${1:-}" in
  "") ;;
  --bundle-mode) BUNDLE_MODE=1 ;;
  *) echo "usage: $0 [--bundle-mode]" >&2; exit 2 ;;
esac
VLLM=0.33.0
SGLANG=0.5.23
TAG=${MIRACACHE_ENGINES_IMAGE:-miracache-engines:$VLLM-$SGLANG}

"$ROOT/tools/dev/run.sh" -- true  # builds the dev image (the FROM of the engines image) if needed
if ! docker image inspect "$TAG" >/dev/null 2>&1; then
  docker build -t "$TAG" -f "$ROOT/tools/dev/Dockerfile.engines" \
    --build-arg VLLM_VERSION="$VLLM" --build-arg SGLANG_VERSION="$SGLANG" "$ROOT/tools/dev"
fi

export MIRACACHE_DEV_IMAGE=$TAG
"$ROOT/tools/dev/run.sh" -- bash -c '
  set -uo pipefail
  export PYTHONPATH=python:tests/python
  if [ "'"$BUNDLE_MODE"'" = 1 ]; then
    d=$(mktemp -d)
    printf "[scope]\nsecret_file = \"/etc/miracache/secret\"\n[control]\nendpoints = [\"127.0.0.1:9465\"]\ncontroller = \"127.0.0.1:9470\"\ntrust_keys = \"%s/trust.toml\"\nstate_dir = \"%s/state\"\n[tls]\ncert = \"/etc/miracache/client.pem\"\nkey = \"/etc/miracache/client.key\"\nca = \"/etc/miracache/ca.pem\"\n" "$d" "$d" > "$d/client.toml"
    export MIRACACHE_CLIENT_TOML=$d/client.toml
    echo "== bundle-mode pass: client.toml = $MIRACACHE_CLIENT_TOML"
    if grep -q "^\[\[nodes\]\]\|static_membership" "$d/client.toml"; then echo "FAIL: bundle-mode client.toml has lab keys"; exit 1; fi
  fi
  log=$(mktemp); rc=0
  for t in tests/engines/vllm/test_contract.py tests/engines/sglang/test_contract.py \
           tests/engines/vllm/test_real_construct.py tests/engines/sglang/test_real_construct.py \
           tests/engines/test_agentbench_configs.py; do
    echo "== $t"
    /opt/engines/bin/python -m unittest -v "$t" >>"$log" 2>&1 || rc=1
  done
  grep -E "^(Ran |OK|FAILED|ERROR|FAIL)|skipped" "$log"
  if grep -q "skipped" "$log"; then echo "FAIL: tests skipped (engine not importable)"; rc=1; fi
  [ $rc -eq 0 ] && echo OK || { echo FAIL; exit 1; }
'
