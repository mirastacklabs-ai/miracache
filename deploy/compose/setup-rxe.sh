#!/usr/bin/env bash
# Idempotent: make sure a soft-RoCE (rxe) device exists on this Linux host or VM, then print it.
#   deploy/compose/setup-rxe.sh [netdev]       netdev defaults to $RAIL_NETDEV, else the default-route interface
# Loads rdma_rxe and rdma_ucm (rdma_cm needs /dev/infiniband/rdma_cm), adds rxe0 on the netdev when missing.
# Modules and links do not survive a reboot: run it again. Needs root (uses sudo when not root).
set -euo pipefail
sudo=""; [[ $(id -u) -eq 0 ]] || sudo=sudo
command -v rdma >/dev/null || { echo "setup-rxe: 'rdma' not found (Ubuntu: apt-get install iproute2 rdma-core)" >&2; exit 1; }
netdev=${1:-${RAIL_NETDEV:-$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')}}
[[ -n $netdev ]] || { echo "setup-rxe: no netdev given and no default route" >&2; exit 1; }
$sudo modprobe rdma_rxe
$sudo modprobe rdma_ucm
if ! rdma link show 2>/dev/null | grep -q "netdev $netdev\b"; then
  $sudo rdma link add rxe0 type rxe netdev "$netdev"
fi
for _ in $(seq 1 50); do
  [[ -c /dev/infiniband/rdma_cm && -c /dev/infiniband/uverbs0 ]] && break
  sleep 0.1
done
rdma link show
ls -l /dev/infiniband
