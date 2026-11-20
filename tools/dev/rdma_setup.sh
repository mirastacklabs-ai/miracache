#!/usr/bin/env bash
# Idempotent soft-RDMA setup inside the colima VM (run from the macOS host) or directly on a Linux host (no colima;
# runs locally, sudo unless root):
#   tools/dev/rdma_setup.sh [netdev]        (default netdev for rxe0: $RAIL_NETDEV or eth0)
# Loads rdma_rxe, siw and rdma_ucm (rdma_cm needs /dev/infiniband/rdma_cm, which
# only rdma_ucm creates) and creates rxe0 (RoCEv2) on the netdev and siw0 (iWARP) on a
# private dummy netdev (miraiw0, 10.99.0.1/24), when missing.
# Why siw0 is NOT on eth0: rdma_cm maps an IP to an RDMA device through the netdev, and
# when two devices share a netdev it always picks the first (rxe0), so no connection could
# ever reach siw0. One netdev per device keeps the mapping unambiguous.
# Modules and links do not survive a VM reboot; re-run after one.
# Does not touch the macOS host. Override the VM profile with COLIMA_PROFILE.
set -euo pipefail

netdev=${1:-${RAIL_NETDEV:-eth0}}


source "$(dirname "${BASH_SOURCE[0]}")/hostvm.sh"
[[ $HOSTVM_MODE != none ]] || { echo "rdma_setup.sh: no running colima VM and not a Linux host" >&2; exit 1; }
vm sudo bash -s -- "$netdev" <<'VM'
set -euo pipefail
netdev=$1
for m in rdma_rxe siw rdma_ucm; do modprobe "$m"; done
have() { rdma link show 2>/dev/null | grep -q "^link $1/"; }
iwdev=miraiw0
modprobe dummy numdummies=0 2>/dev/null || true
ip link show "$iwdev" >/dev/null 2>&1 || ip link add "$iwdev" type dummy
ip -4 addr show dev "$iwdev" | grep -q 'inet 10.99.0.1/' || ip addr add 10.99.0.1/24 dev "$iwdev"
ip link set "$iwdev" up
# RL1/RL4 (multi-rail plan decision 11): a second IPv4 address on each RDMA netdev, so one device can serve two rails
# (rdma_cm maps both addresses to the same device). Failing a rail in a lab = `ip addr del` of its address; the container cannot
# do that, so the RL4 test asks tools/dev/rail_fault_agent.sh on the host (10.98.0.1/24 is the only address it touches).
ip -4 addr show dev "$netdev" | grep -q 'inet 10.98.0.1/' || ip addr add 10.98.0.1/24 dev "$netdev"
ip -4 addr show dev "$iwdev" | grep -q 'inet 10.99.0.2/' || ip addr add 10.99.0.2/24 dev "$iwdev"
# Move siw0 off a shared netdev if an earlier setup put it there.
if have siw0 && ! rdma link show siw0/1 | grep -q "netdev $iwdev"; then rdma link delete siw0; fi
have rxe0 || rdma link add rxe0 type rxe netdev "$netdev"
have siw0 || rdma link add siw0 type siw netdev "$iwdev"
for i in $(seq 1 50); do
  [[ -c /dev/infiniband/rdma_cm && -c /dev/infiniband/uverbs0 && -c /dev/infiniband/uverbs1 ]] && break
  sleep 0.1
done
rdma link show
ls -l /dev/infiniband
VM
