#!/usr/bin/env bash
# NM1: nightly model check (design spec 8.7). Runs on the macOS host (bash + cargo only).
# Builds model/ in release, then runs every variant (one process per variant, each under a
# time budget) at --bounds nightly: random simulation with a fixed seed and state budget.
# Extra runs: every variant at --bounds drain --set clients=1 --set ops=2, and at replica3.
# One summary line per run goes to stdout and the log; raw run output goes to the log only.
# Prints "OK: model nightly" (exit 0) or "FAIL: model nightly" (exit 1) on any MISMATCH,
# unexpected verdict, timeout, or build failure.
#
#   tools/ci/model_nightly.sh [log-file]
#
# Defaults (recorded here; the nightly uses these, the env overrides are for smoke tests only):
#   MODEL_NIGHTLY_BOUNDS=nightly   MODEL_NIGHTLY_SEED=20261109   MODEL_NIGHTLY_STATES=20000000
#   MODEL_NIGHTLY_THREADS=2        MODEL_NIGHTLY_TIMEOUT=1800 (seconds per run)
#   MODEL_NIGHTLY_EXTRA=1 (0 skips the drain and replica3 runs)
#   MODEL_NIGHTLY_LOG=model/out/nightly-<UTC stamp>.log (or the first argument)
#   CARGO_TARGET_DIR: honoured when locating the binary (the dev container builds into build/model-target).
# Smoke at ci bounds (plumbing check, not a verdict): 3 variants report MISMATCH there by design, because their
# counterexamples need more than one scope or principal and ci has scopes=1, principals=1: no-validation
# (NoForeignScopeRead), scope-keyed-by-id-only (NoCrossPrincipalRead), cap-evicts-any (CapEvictsOwnOnly). They hold at
# nightly/small bounds. A short MODEL_NIGHTLY_TIMEOUT can also time out commit-overtakes and forging-rogue (ci: 112 s+).
# Smoke example (seconds, not hours): MODEL_NIGHTLY_BOUNDS=ci MODEL_NIGHTLY_EXTRA=0 \
#   MODEL_NIGHTLY_TIMEOUT=120 tools/ci/model_nightly.sh /tmp/... (any log path)
set -e

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT"

BOUNDS="${MODEL_NIGHTLY_BOUNDS:-nightly}"
SEED="${MODEL_NIGHTLY_SEED:-20261109}"
STATES="${MODEL_NIGHTLY_STATES:-20000000}"
THREADS="${MODEL_NIGHTLY_THREADS:-2}"
TIMEOUT_S="${MODEL_NIGHTLY_TIMEOUT:-1800}"
EXTRA="${MODEL_NIGHTLY_EXTRA:-1}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG="${1:-${MODEL_NIGHTLY_LOG:-$ROOT/model/out/nightly-$STAMP.log}}"
mkdir -p "$(dirname "$LOG")"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/model-nightly.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

FAILURES=0
say() { echo "$*" | tee -a "$LOG"; }
header() { say "=== model nightly $STAMP bounds=$BOUNDS seed=$SEED sim_states=$STATES threads=$THREADS timeout=${TIMEOUT_S}s extra=$EXTRA"; }
fail_now() { say "FAIL: model nightly ($*)"; exit 1; }

# Runs "$@" with a time budget; stdout+stderr go to $1 (the run file). Sets RC.
# Uses timeout(1) when present, else a bash watchdog. RC=124 means the budget was exceeded.
run_budgeted() {
  local out="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    set +e; timeout "$TIMEOUT_S" "$@" > "$out" 2>&1; RC=$?; set -e
  else
    local marker="$out.timeout" pid watcher
    rm -f "$marker"
    set +e
    "$@" > "$out" 2>&1 & pid=$!
    ( sleep "$TIMEOUT_S" && touch "$marker" && kill -TERM "$pid" ) 2>/dev/null & watcher=$!
    wait "$pid"; RC=$?
    kill "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null
    set -e
    if [ -e "$marker" ]; then RC=124; fi
  fi
}

# One run: one variant at one bounds configuration. Extra args (e.g. --set) follow.
run_variant() {
  local variant="$1" bounds="$2"; shift 2
  local out="$WORK/run.out" start verdict states
  start=$SECONDS
  # seed and sim budget only matter in sim mode (the nightly bounds); bfs runs ignore them.
  run_budgeted "$out" "$BIN" check --variant "$variant" --bounds "$bounds" --threads "$THREADS" \
    --seed "$SEED" --sim-states "$STATES" "$@"
  local secs=$((SECONDS - start))
  states="$(sed -n 's/^states generated \([0-9]*\),.*/\1/p' "$out" | tail -n 1)"
  [ -n "$states" ] || states="-"
  if [ "$RC" -eq 124 ]; then
    verdict="TIMEOUT"
  elif [ "$RC" -ne 0 ]; then
    if grep -q "RESULT: MISMATCH" "$out"; then verdict="MISMATCH"; else verdict="ERROR"; fi
  elif grep -q "RESULT: every variant behaved as expected" "$out"; then
    verdict="OK"
  else
    verdict="ERROR"
  fi
  local label="variant=$variant bounds=$bounds${*:+ args=\"$*\"}"
  say "RUN $label verdict=$verdict states=$states seconds=$secs"
  { echo "----- run: $label verdict=$verdict exit=$RC"; cat "$out"; echo; } >> "$LOG"
  [ "$verdict" = "OK" ] || FAILURES=$((FAILURES + 1))
}

# Every variant name from `list` (first column), one run each.
run_all_variants() {
  local bounds="$1"; shift
  local names v
  names="$("$BIN" list | awk '{print $1}')"
  for v in $names; do
    run_variant "$v" "$bounds" "$@"
  done
}

header
say "--- build: cargo build --release (model/)"
if ! (cd "$ROOT/model" && cargo build --release >> "$LOG" 2>&1); then
  fail_now "build failed, see $LOG"
fi
BIN="${CARGO_TARGET_DIR:-$ROOT/model/target}/release/miracache-model"
[ -x "$BIN" ] || fail_now "binary missing: $BIN"

say "--- runs: every variant at --bounds $BOUNDS"
run_all_variants "$BOUNDS"

if [ "$EXTRA" != "0" ]; then
  say "--- extra runs: drain (clients=1 ops=2) and replica3, every variant"
  run_all_variants drain --set clients=1 --set ops=2
  run_all_variants replica3
fi

say "runs with a problem: $FAILURES"
if [ "$FAILURES" -eq 0 ]; then
  say "OK: model nightly"
else
  say "FAIL: model nightly ($FAILURES run(s) not as expected; log $LOG)"
  exit 1
fi
