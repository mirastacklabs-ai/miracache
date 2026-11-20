#!/usr/bin/env bash
# RL4 host-side fault agent for the multi-rail rxe0 end-to-end test (tests/e2e/multirail_rdma_test.cpp).
# The dev container has no NET_ADMIN, so it cannot `ip addr del`; the test asks this agent (on the macOS host, which only
# runs `colima ssh`, or the Linux host itself) through a directory shared by the bind mount:
#   <dir>/req   "del" or "add" (written by the test, removed by the agent)
#   <dir>/ack   "<op> rc=<n>" (written by the agent, removed by the test)
#   <dir>/agent heartbeat: a counter rewritten every loop (0.2 s); the test and rdma_test.sh call the agent alive when it
#               moves within a few seconds (no clock is compared: host and VM clocks may disagree)
# Usage (host):  tools/dev/rail_fault_agent.sh <dir> [max_seconds]     (default 7200, longer than a full gate)
# Exits at max_seconds or when <dir>/stop appears. On start, on exit and on TERM/INT/HUP it makes sure the rail-2 address is back
# (a kill between "del" and "add" must never leave 10.98.0.1 deleted).
# Only the lab address added by tools/dev/rdma_setup.sh (10.98.0.1/24 on $RAIL_NETDEV, default eth0) is ever touched.
set -uo pipefail
dir=${1:?usage: rail_fault_agent.sh <dir> [max_seconds]}
max=${2:-7200}

addr=10.98.0.1/24
netdev=${RAIL_NETDEV:-eth0}
mkdir -p "$dir"
rm -f "$dir/req" "$dir/ack" "$dir/stop"
source "$(dirname "${BASH_SOURCE[0]}")/hostvm.sh"  # vm(): colima VM on a Mac, the Linux host itself otherwise
restore() { vm sudo ip addr show dev "$netdev" 2>/dev/null | grep -q "inet ${addr%/*}/" || vm sudo ip addr add "$addr" dev "$netdev"; }
trap 'restore; rm -f "$dir/agent" "$dir/agent.tmp"' EXIT
trap 'exit 0' TERM   # a TERM after the restore is a normal stop
trap 'exit 130' INT
trap 'exit 0' HUP   # the address is restored by the EXIT trap; a hang-up is a normal stop (was 130, which is INT's code)
restore
start=$SECONDS
beat=0
while (( SECONDS - start < max )) && [[ ! -e $dir/stop ]]; do
  beat=$((beat + 1))
  echo "$beat" > "$dir/agent.tmp" && mv "$dir/agent.tmp" "$dir/agent"
  if [[ -f $dir/req ]]; then
    op=$(cat "$dir/req"); rm -f "$dir/req"
    case $op in
      del) vm sudo ip addr del "$addr" dev "$netdev"; rc=$? ;;
      add) vm sudo ip addr add "$addr" dev "$netdev"; rc=$? ;;
      *) rc=99 ;;
    esac
    echo "$op rc=$rc" > "$dir/ack.tmp" && mv "$dir/ack.tmp" "$dir/ack"
  fi
  sleep 0.2
done
