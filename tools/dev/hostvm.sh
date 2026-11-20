# Sourced by host-side scripts. Decides where "the VM" is and defines vm():
#   HOSTVM_MODE=colima  a colima VM is present and running (macOS): vm() runs the command in it via `colima ssh`.
#   HOSTVM_MODE=local   a Linux host with no running colima: the host itself is the VM; vm() runs the command here.
#   HOSTVM_MODE=none    neither (macOS without colima): vm() fails with a clear message.
# In local mode a leading `sudo` is dropped when already root and kept otherwise. Override the colima profile with
# COLIMA_PROFILE. The soft-RDMA netdev for rxe0 is RAIL_NETDEV (default eth0).
HOSTVM_PROFILE=${COLIMA_PROFILE:-default}
if command -v colima >/dev/null 2>&1 \
   && colima list 2>/dev/null | awk -v p="$HOSTVM_PROFILE" '$1==p && $2=="Running"{f=1} END{exit !f}'; then
  HOSTVM_MODE=colima
elif [[ $(uname -s) == Linux ]]; then
  HOSTVM_MODE=local
else
  HOSTVM_MODE=none
fi
vm() {
  case $HOSTVM_MODE in
    colima) colima ssh -p "$HOSTVM_PROFILE" -- "$@" ;;
    local)
      if [[ ${1:-} == sudo && $(id -u) -eq 0 ]]; then shift; fi
      "$@" ;;
    *) echo "hostvm: no colima VM running and not a Linux host" >&2; return 127 ;;
  esac
}
