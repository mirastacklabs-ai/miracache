#!/usr/bin/env bash
# Idempotent workstation setup: fixes what tools/dev/doctor.sh reports MISSING, then re-runs doctor.
#   tools/dev/bootstrap.sh [--yes] [--dry-run] [--first-run-check]
#   --yes              allow "brew install" of missing host tools (otherwise print it and exit 2)
#   --dry-run          print what would be done, change nothing
#   --first-run-check  afterwards run the first-run gate sequence (see the workstation setup guide, first-run section),
#                      logs in build/bootstrap-<step>.log, stop at the first failure
# Never upgrades brew packages, never restarts a running colima VM, never deletes anything,
# never touches containers it did not start. Bash 3.2 compatible.
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$ROOT" || exit 1
yes=0; dry=0; first=0
for a in "$@"; do
  case $a in
    --yes) yes=1 ;;
    --dry-run) dry=1 ;;
    --first-run-check) first=1 ;;
    *) echo "usage: $0 [--yes] [--dry-run] [--first-run-check]" >&2; exit 64 ;;
  esac
done

START_CMD="colima start --cpu 6 --memory 12 --disk 100 --vm-type vz --mount-type virtiofs --arch aarch64"
acted=0

# run CMD... (or just print it under --dry-run)
act() {
  acted=1
  if [[ $dry -eq 1 ]]; then echo "would run: $*"; return 0; fi
  echo "+ $*"
  "$@"
}

rep=$("$ROOT/tools/dev/doctor.sh" 2>&1) || true
has() { grep -q "^MISSING $1" <<<"$rep"; }

# 1. host tools (consent needed)
tools=""
for t in colima docker jq git; do has "tool $t" && tools="$tools $t"; done
if [[ -n $tools ]]; then
  acted=1
  if [[ $yes -eq 0 ]]; then
    echo "need: brew install$tools"
    [[ $dry -eq 1 ]] && echo "(dry run) host install needs consent; re-run with --yes" && exit 2
    echo "host install needs consent; re-run with --yes" >&2
    exit 2
  fi
  # shellcheck disable=SC2086
  act brew install $tools || { echo "brew install failed" >&2; exit 1; }
fi

# 2. colima VM (only start when not running; never restart a running one)
if has "colima VM"; then
  act $START_CMD || { echo "colima start failed" >&2; exit 1; }
fi
grep -q '^WARN VM shape' <<<"$rep" && echo "NOTE: VM is smaller than 6 CPU / 12 GB; leaving it running (other projects may use it). Resize manually when idle."

# 3. RDMA lab
if has "RDMA lab" || has "colima VM"; then
  act tools/dev/rdma_setup.sh || { echo "rdma_setup failed" >&2; exit 1; }
fi

# 4. dev image
if has "dev image" || has "docker daemon" || has "colima VM"; then
  echo "NOTE: first image build takes ~20-40 min"
  act tools/dev/run.sh -- true || { echo "dev image build failed" >&2; exit 1; }
fi

# 5. things only the user can fix
has "free disk" && echo "NOTE: free disk space on the Mac (gate needs >= 20 GiB); bootstrap never deletes anything."

if [[ $dry -eq 1 ]]; then
  [[ $acted -eq 0 ]] && echo "nothing to do"
  exit 0
fi
[[ $acted -eq 0 ]] && echo "nothing to do"

# 6. optional first-run gate sequence
if [[ $first -eq 1 ]]; then
  mkdir -p build
  step() { # name cmd...
    local n=$1; shift
    echo "+ [$n] $* > build/bootstrap-$n.log"
    if "$@" > "build/bootstrap-$n.log" 2>&1; then echo "OK $n"; else echo "FAIL $n (see build/bootstrap-$n.log)"; exit 1; fi
  }
  step gate tools/dev/run.sh --tsan tools/ci/build_and_test.sh
  rail=build/dev/rail-fault
  tools/dev/rail_fault_agent.sh "$ROOT/$rail" 7200 > build/bootstrap-railhelper.log 2>&1 &
  helper=$!
  if "$ROOT/tools/dev/run.sh" --rdma env MIRA_REQUIRE_MULTIRAIL=1 tools/ci/rdma_test.sh dev rxe0 > build/bootstrap-rdma.log 2>&1; then
    echo "OK rdma"; kill "$helper" 2>/dev/null
  else
    kill "$helper" 2>/dev/null; echo "FAIL rdma (see build/bootstrap-rdma.log)"; exit 1
  fi
  step engine-contract tools/ci/engine_contract.sh
  step engine-contract-bundle tools/ci/engine_contract.sh --bundle-mode
fi

echo "+ doctor"
"$ROOT/tools/dev/doctor.sh"
