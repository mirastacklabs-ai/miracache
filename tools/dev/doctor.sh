#!/usr/bin/env bash
# Read-only workstation readiness check (spec: the workstation setup guide). No network, < 15 s.
#   tools/dev/doctor.sh [--quiet]
# Prints one line per check: "OK <item>", "MISSING <item> — fix: <cmd>", "WARN <item> — <why>".
# --quiet prints only MISSING/WARN lines and the last line. Last line: "DOCTOR: READY" or
# "DOCTOR: NOT READY (<n> missing)". Exit 0 when ready, 1 when not. Bash 3.2 compatible.
set -uo pipefail

quiet=0
[[ ${1:-} == --quiet ]] && quiet=1

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
IMAGE=${MIRACACHE_DEV_IMAGE:-miracache-dev:24.04}
PROFILE=${COLIMA_PROFILE:-default}
missing=0

ok()   { [[ $quiet -eq 1 ]] || echo "OK $1"; }
miss() { echo "MISSING $1 — fix: $2"; missing=$((missing + 1)); }
warn() { echo "WARN $1 — $2"; }

# tmo SECS CMD...: run CMD with a wall-clock limit (macOS has no timeout). Output goes to stdout.
tmo() {
  local secs=$1 pid w rc
  shift
  "$@" 2>/dev/null &
  pid=$!
  ( sleep "$secs"; kill "$pid" 2>/dev/null ) >/dev/null 2>&1 &
  w=$!
  wait "$pid" 2>/dev/null
  rc=$?
  kill "$w" 2>/dev/null
  pkill -P "$w" 2>/dev/null
  wait "$w" 2>/dev/null
  return $rc
}

# 1. host tools
have_colima=0
have_docker=0
for t in colima docker jq git; do
  if command -v "$t" >/dev/null 2>&1; then
    ok "tool $t"
    [[ $t == colima ]] && have_colima=1
    [[ $t == docker ]] && have_docker=1
  else
    miss "tool $t" "tools/dev/bootstrap.sh --yes   (or: brew install $t)"
  fi
done

START_CMD="colima start --cpu 6 --memory 12 --disk 100 --vm-type vz --mount-type virtiofs --arch aarch64"
vm_up=0

# 2. colima VM + shape
if [[ $have_colima -eq 0 ]]; then
  miss "colima VM (colima not installed; VM checks skipped)" "brew install colima, then $START_CMD"
else
  if tmo 8 colima status -p "$PROFILE" >/dev/null 2>&1 \
     && tmo 8 colima list 2>/dev/null | awk -v p="$PROFILE" '$1==p && $2=="Running"{f=1} END{exit !f}'; then
    vm_up=1
    ok "colima VM running"
    shape=$(tmo 8 colima list 2>/dev/null | awk -v p="$PROFILE" '$1==p{print $4, $5}')
    cpus=${shape%% *}
    mem=${shape##* }
    mem=${mem%%[!0-9.]*}
    mem=${mem%%.*}
    if [[ -n $cpus && -n $mem && $cpus -ge 6 && $mem -ge 12 ]] 2>/dev/null; then
      ok "VM shape ${cpus} CPU / ${mem} GB"
    else
      warn "VM shape ${cpus:-?} CPU / ${mem:-?} GB" "below 6 CPU / 12 GB: works but slower; other projects may share the VM, do not restart it casually"
    fi
  else
    miss "colima VM running (VM checks skipped)" "$START_CMD"
  fi
fi

# 3. docker daemon
docker_up=0
if [[ $have_docker -eq 1 ]]; then
  if [[ -n $(tmo 8 docker version --format '{{.Server.Version}}') ]]; then
    docker_up=1
    ok "docker daemon reachable"
  else
    miss "docker daemon reachable" "start the colima VM ($START_CMD)"
  fi
fi

# 4. RDMA lab + rail address (one ssh call)
if [[ $vm_up -eq 1 ]]; then
  out=$(tmo 12 colima ssh -p "$PROFILE" -- sh -c 'test -e /dev/infiniband/rdma_cm && echo RDMA_CM; rdma link show 2>/dev/null; ip -4 addr show dev eth0 2>/dev/null; echo VM_DONE')
  if [[ $out != *VM_DONE* ]]; then
    miss "RDMA lab (VM did not answer in time)" "tools/dev/rdma_setup.sh"
  else
    if [[ $out == *RDMA_CM* && $out == *"link rxe0/"* && $out == *"link siw0/"* ]]; then
      ok "RDMA lab (rdma_cm, rxe0, siw0)"
    else
      miss "RDMA lab (need /dev/infiniband/rdma_cm, rxe0, siw0)" "tools/dev/rdma_setup.sh"
    fi
    if [[ $out == *"inet 10.98.0.1/"* ]]; then
      ok "rail address 10.98.0.1 on eth0"
    else
      warn "rail address 10.98.0.1 on eth0" "missing; multi-rail tests need it: tools/dev/rdma_setup.sh"
    fi
  fi
fi

# 5. dev image
if [[ $docker_up -eq 1 ]]; then
  if tmo 8 docker image inspect "$IMAGE" >/dev/null 2>&1 && docker image inspect "$IMAGE" >/dev/null 2>&1; then
    ok "dev image $IMAGE"
  else
    miss "dev image $IMAGE (first build ~20–40 min)" "tools/dev/run.sh -- true"
  fi
fi

# 6. disk
avail_kb=$(df -k "$ROOT" 2>/dev/null | awk 'NR==2{print $4}')
if [[ -n $avail_kb ]]; then
  gib=$((avail_kb / 1048576))
  if [[ $gib -lt 8 ]]; then
    miss "free disk ${gib} GiB (< 8)" "free space on the Mac; a full gate needs >= 20 GiB"
  elif [[ $gib -lt 20 ]]; then
    warn "free disk ${gib} GiB" "under 20 GiB; a full gate may run out of space"
  else
    ok "free disk ${gib} GiB"
  fi
fi

# 7. sibling repo, git remote
MAIN=$(cd "$ROOT" && cd "$(git rev-parse --git-common-dir 2>/dev/null)/.." 2>/dev/null && pwd) || MAIN=$ROOT
if [[ -d $ROOT/../agentbench || -d $MAIN/../agentbench ]]; then
  ok "sibling repo ../agentbench"
else
  warn "sibling repo ../agentbench" "only needed for end-to-end benchmarks; clone it next to miracache (see the workstation setup guide, section 3)"
fi
if command -v git >/dev/null 2>&1 && git -C "$ROOT" remote get-url origin >/dev/null 2>&1; then
  ok "git remote origin"
else
  warn "git remote origin" "not set: git remote add origin git@gitlab.com:mirastacklabs/miracache.git"
fi

if [[ $missing -eq 0 ]]; then
  echo "DOCTOR: READY"
  exit 0
fi
echo "DOCTOR: NOT READY ($missing missing)"
exit 1
