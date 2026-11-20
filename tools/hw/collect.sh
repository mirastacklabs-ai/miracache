#!/usr/bin/env bash
# tools/hw/collect.sh - strictly READ-ONLY host report for a Linux benchmark host.
#
#   tools/hw/collect.sh [-o FILE] [--no-pfc] [-h]
#
#   -o FILE    write the report to FILE instead of stdout (the only write this script does)
#   --no-pfc   do not WARN about PFC/ECN (back-to-back cables, iWARP, or a ZTR/RTTCC day)
#   -h         this help
#
# Every probe is optional: a missing tool prints "SKIP <probe>: <tool> not found" and the run
# continues. Never needs root; values that need root are marked "(root)" where they print
# nothing without it. Each probe is time-boxed (timeout 10). Never changes system state.
# Exit status is 0 even with WARN lines (it is a report); 2 on bad arguments.
# Runbook: the hardware runbook, section 3.1. Details: tools/hw/README.md.
set -u
export LC_ALL=C

out_file=""
want_pfc=1
while [ $# -gt 0 ]; do
  case $1 in
    -o) [ $# -ge 2 ] || { echo "collect.sh: -o needs a file" >&2; exit 2; }; out_file=$2; shift 2 ;;
    --no-pfc) want_pfc=0; shift ;;
    -h|--help) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "collect.sh: unknown argument: $1 (try -h)" >&2; exit 2 ;;
  esac
done
if [ -n "$out_file" ]; then
  exec >"$out_file" || exit 2
fi

WARNS=()
warn() { WARNS+=("$*"); }
have() { command -v "$1" >/dev/null 2>&1; }
hdr()  { printf '\n==== %s ====\n' "$*"; }
rd()   { cat "$1" 2>/dev/null; }          # read a file, empty on failure
# time-boxed run
tmo() { if have timeout; then timeout 10 "$@"; else "$@"; fi; }
# probe LABEL CMD ARGS...: prints output; sets PROBE_OUT / PROBE_RC; SKIP line if tool missing
PROBE_OUT=""; PROBE_RC=0
probe() {
  local label=$1; shift
  PROBE_OUT=""; PROBE_RC=127
  if ! have "$1"; then echo "SKIP $label: $1 not found"; return 1; fi
  PROBE_OUT=$(tmo "$@" 2>&1); PROBE_RC=$?
  [ -z "${QUIET:-}" ] && [ -n "$PROBE_OUT" ] && printf '%s\n' "$PROBE_OUT"
  if [ "$PROBE_RC" -ne 0 ]; then
    echo "NOTE $label: exit $PROBE_RC$([ "$PROBE_RC" = 124 ] && echo ' (timed out)') (may need root)"
    return 1
  fi
  return 0
}
is_soft() { case $1 in rxe*|siw*) return 0 ;; *) return 1 ;; esac; }

report() {
UID_NOW=$(id -u 2>/dev/null || echo '?')
HOST=$(hostname 2>/dev/null || rd /proc/sys/kernel/hostname)
echo "miracache host report (collect.sh, read-only)"
echo "date_utc:  $(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)"
echo "hostname:  $HOST"
echo "fqdn:      $(hostname -f 2>/dev/null || echo '-')"
echo "run_as:    uid=$UID_NOW$([ "$UID_NOW" = 0 ] || echo ' (not root: dmesg, some DCB/ethtool/lspci fields may be empty)')"
echo "ips:"
if have ip; then
  tmo ip -o addr show 2>&1 | awk '{print "  " $2 " " $3 " " $4}'
elif have hostname; then
  echo "  $(hostname -I 2>/dev/null)"
else
  echo "SKIP ips: ip not found"
fi

hdr "OS / KERNEL"
echo "uname: $(uname -srvm 2>/dev/null)"
if [ -r /etc/os-release ]; then grep -E '^(PRETTY_NAME|VERSION_ID)=' /etc/os-release; else echo "SKIP os-release: /etc/os-release not found"; fi
echo "cmdline: $(rd /proc/cmdline)"
if [ -r /sys/hypervisor/type ] || grep -q hypervisor /proc/cpuinfo 2>/dev/null; then echo "virtualized: yes (hypervisor flag)"; fi
if [ -f /.dockerenv ]; then echo "container: yes (/.dockerenv)"; fi

hdr "CPU / NUMA / GOVERNOR"
probe lscpu lscpu | grep -E '^(Architecture|Model name|CPU\(s\)|Socket|Thread|Core|NUMA node)' 
if have numactl; then probe numactl numactl -H; else echo "SKIP numactl: numactl not found"; ls -d /sys/devices/system/node/node* 2>/dev/null | sed 's/^/node dir: /'; fi
gov=$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort | uniq -c)
if [ -n "$gov" ]; then
  echo "scaling_governor (count value):"; printf '%s\n' "$gov" | sed 's/^/  /'
  if printf '%s\n' "$gov" | grep -qv performance; then warn "CPU governor is not 'performance' on all CPUs (runbook 3.3: cpupower frequency-set -g performance)"; fi
else
  echo "SKIP governor: no cpufreq in sysfs (VM or container)"
fi

hdr "MEMORY / HUGEPAGES"
grep -E 'MemTotal|HugePages_|Hugepagesize|Hugetlb' /proc/meminfo 2>/dev/null
for nd in /sys/devices/system/node/node*; do
  [ -d "$nd" ] || continue
  for sz in 1048576 2048; do
    f=$nd/hugepages/hugepages-${sz}kB/nr_hugepages
    [ -r "$f" ] && echo "$(basename "$nd") ${sz}kB nr_hugepages=$(rd "$f")"
  done
done
hp1g=$(rd /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages)
echo "1GiB pages total: ${hp1g:-n/a}"
if [ -z "$hp1g" ] || [ "$hp1g" = 0 ]; then warn "no 1 GiB hugepages reserved (needed on memory nodes only; runbook 3.2)"; fi
echo "hugetlbfs mounts:"; grep hugetlbfs /proc/mounts 2>/dev/null | sed 's/^/  /'
echo "THP: $(rd /sys/kernel/mm/transparent_hugepage/enabled)"

hdr "IOMMU"
cl=$(rd /proc/cmdline)
echo "cmdline iommu flags: $(printf '%s\n' "$cl" | tr ' ' '\n' | grep -E '^(iommu|intel_iommu|amd_iommu)' | tr '\n' ' ')"
echo "iommu groups: $(ls /sys/kernel/iommu_groups 2>/dev/null | wc -l)  devices in /sys/class/iommu: $(ls /sys/class/iommu 2>/dev/null | wc -l)"
if have dmesg; then
  d=$(tmo dmesg 2>&1 | grep -iE 'DMAR|AMD-Vi|iommu' | head -5)
  if [ -n "$d" ]; then printf '%s\n' "$d"; else echo "dmesg: nothing readable (root; kernel.dmesg_restrict)"; fi
else echo "SKIP dmesg: dmesg not found"; fi
if ! printf '%s\n' "$cl" | grep -qw 'iommu=pt'; then warn "iommu=pt not on the kernel command line (runbook 3.4)"; fi

hdr "MEMLOCK"
ml=$(ulimit -l 2>/dev/null)
echo "ulimit -l (this shell): ${ml:-n/a}"
grep -i 'locked memory' /proc/self/limits 2>/dev/null
if [ "$ml" != unlimited ]; then warn "memlock is '${ml:-n/a}', not unlimited (runbook 3.4: limits.d and LimitMEMLOCK=infinity in the unit)"; fi
if have systemctl; then
  for u in mira-memnode mira-client; do
    v=$(tmo systemctl show "$u" -p LoadState -p LimitMEMLOCK 2>/dev/null | tr '\n' ' ')
    case $v in *LoadState=loaded*) echo "unit $u: $v" ;; esac
  done
else echo "SKIP systemd-memlock: systemctl not found"; fi

hdr "KERNEL MODULES"
for m in ib_core ib_uverbs rdma_ucm rdma_cm mlx5_core mlx5_ib irdma ice rdma_rxe siw nvidia nvidia_peermem; do
  if [ -d "/sys/module/$m" ]; then echo "$m: loaded   $(rd /sys/module/$m/version)"; else echo "$m: absent"; fi
done
have lsmod || echo "SKIP lsmod: lsmod not found (state above is from /sys/module)"

hdr "RDMA TOOLS"
echo "-- rdma link show"; probe "rdma link" rdma link show; RDMA_LINK=$PROBE_OUT
echo "-- ibv_devices"; probe ibv_devices ibv_devices
for t in ib_write_bw ib_read_bw ib_send_bw; do
  if have "$t"; then echo "$t: $(command -v "$t") $(tmo "$t" --version 2>&1 | head -1)"; else echo "SKIP perftest: $t not found"; fi
done
have ib_write_bw || warn "perftest (ib_write_bw) not installed (runbook 3.1)"

hdr "RDMA DEVICES"
devs=$(ls /sys/class/infiniband 2>/dev/null)
if [ -z "$devs" ]; then
  echo "no RDMA devices in /sys/class/infiniband"
  warn "no RDMA device present"
fi
for d in $devs; do
  base=/sys/class/infiniband/$d
  echo; echo "--- device $d ---"
  echo "fw_ver:     $(rd $base/fw_ver)"
  echo "board_id:   $(rd $base/board_id)"
  echo "node_guid:  $(rd $base/node_guid)"
  echo "node_type:  $(rd $base/node_type)"
  pci=""; [ -e "$base/device" ] && pci=$(basename "$(readlink -f "$base/device" 2>/dev/null)")
  echo "pci:        ${pci:-none (virtual device)}"
  if [ -n "$pci" ]; then
    echo "numa_node:  $(rd $base/device/numa_node)"
    [ "$(rd $base/device/numa_node)" = -1 ] && ! is_soft "$d" && warn "$d: NIC numa_node is -1 (NUMA off or hidden; runbook 3.3)"
    if have lspci; then
      tmo lspci -s "$pci" 2>&1 | sed 's/^/  nic: /'
      tmo lspci -s "$pci" -vv 2>&1 | grep -E 'LnkCap:|LnkSta:' | sed 's/^/  /'
    else echo "SKIP lspci: lspci not found"; fi
  fi
  echo "-- ibv_devinfo $d"
  have ibv_devinfo || echo "SKIP ibv_devinfo($d): ibv_devinfo not found"
  QUIET=1 probe "ibv_devinfo($d)" ibv_devinfo -d "$d" -v; DEVINFO=$PROBE_OUT
  printf '%s\n' "$DEVINFO" | grep -E 'hca_id|transport|fw_ver|vendor_part_id|board_id|state|max_mtu|active_mtu|link_layer|phys_state'
  transport=$(printf '%s\n' "$DEVINFO" | awk '/transport:/{print $2; exit}')

  for pdir in $base/ports/*; do
    [ -d "$pdir" ] || continue
    p=$(basename "$pdir")
    echo "-- port $d/$p"
    st=$(rd $pdir/state); ph=$(rd $pdir/phys_state); ll=$(rd $pdir/link_layer)
    echo "state: $st | phys_state: $ph | link_layer: $ll | rate: $(rd $pdir/rate)"
    case $st in *ACTIVE*) ;; *) warn "$d/$p: port state is '$st' (not ACTIVE)" ;; esac
    nd=$(printf '%s\n' "$RDMA_LINK" | awk -v l="$d/$p" '$2==l{for(i=1;i<NF;i++)if($i=="netdev")print $(i+1)}' | head -1)
    [ -z "$nd" ] && nd=$(ls $base/device/net 2>/dev/null | head -1)
    [ -z "$nd" ] && nd=$(cat "$pdir"/gid_attrs/ndevs/* 2>/dev/null | grep -v "^$" | head -1)
    echo "netdev: ${nd:-none}"
    am=""; have ibv_devinfo && am=$(tmo ibv_devinfo -d "$d" -i "$p" 2>/dev/null | awk '/active_mtu:/{print $2; exit}')
    echo "RoCE/IB active_mtu: ${am:-n/a}"
    proto=other
    if [ "$ll" = Ethernet ]; then proto=roce; fi
    case $d in siw*) proto=iwarp ;; esac
    case $transport in *iWARP*) proto=iwarp ;; esac
    echo "protocol: $proto$(is_soft "$d" && echo ' (soft device)')"
    # GID table
    echo "GID table (idx gid type ndev):"
    v2=0; v1=0; ng=0
    for g in "$pdir"/gids/*; do
      [ -r "$g" ] || continue
      i=$(basename "$g"); gid=$(rd "$g")
      case $gid in 0000:0000:0000:0000:0000:0000:0000:0000|"") continue ;; esac
      ty=$(rd "$pdir/gid_attrs/types/$i"); gn=$(rd "$pdir/gid_attrs/ndevs/$i")
      echo "  $i $gid ${ty:-?} ${gn:-}"
      ng=$((ng+1))
      case $ty in *v2*) v2=$((v2+1)) ;; *v1*) v1=$((v1+1)) ;; esac
    done
    echo "GIDs: $ng  (RoCE v1: $v1, RoCE v2: $v2)"
    # link / MTU checks
    if [ -n "$nd" ] && [ -d "/sys/class/net/$nd" ]; then
      mtu=$(rd /sys/class/net/$nd/mtu); spd=$(rd /sys/class/net/$nd/speed 2>/dev/null)
      echo "netdev $nd: mtu=$mtu speed=${spd:-n/a}Mb/s operstate=$(rd /sys/class/net/$nd/operstate)"
      if have ethtool; then
        tmo ethtool -i "$nd" 2>&1 | sed 's/^/  ethtool -i: /'
        tmo ethtool "$nd" 2>&1 | grep -E 'Speed:|Duplex:|Link detected:' | sed 's/^/  /'
        tmo ethtool -a "$nd" 2>&1 | sed 's/^/  pause: /'
        tmo ethtool -S "$nd" 2>/dev/null | grep -iE 'pause|prio3|cnp|ecn' | head -20 | sed 's/^/  stat: /'
      else echo "SKIP ethtool($nd): ethtool not found"; fi
      if [ "$proto" = roce ] && ! is_soft "$d"; then
        [ "${mtu:-0}" -lt 4096 ] 2>/dev/null && warn "$d/$p: netdev $nd MTU $mtu < 4096 (runbook 3.5: 9000)"
        [ "${mtu:-0}" -ge 4096 ] 2>/dev/null && [ "$mtu" -lt 9000 ] && warn "$d/$p: netdev $nd MTU $mtu < 9000 (runbook 3.5 expects 9000)"
        [ -n "$am" ] && [ "$am" -lt 4096 ] 2>/dev/null && warn "$d/$p: RoCE active_mtu $am < 4096 (runbook 3.5)"
        [ "$v2" -eq 0 ] && warn "$d/$p: no RoCE v2 GID in the table"
      fi
      # PFC / ECN / DSCP trust
      pfc=unknown
      if [ "$proto" = roce ]; then
        echo "-- PFC / ECN / trust for $nd"
        if have dcb; then
          probe "dcb pfc($nd)" dcb pfc show dev "$nd"
          if [ "$PROBE_RC" = 0 ]; then
            if printf '%s\n' "$PROBE_OUT" | grep -qE '[0-7]:on'; then pfc=on; else pfc=off; fi
          fi
          probe "dcb app($nd)" dcb app show dev "$nd" >/dev/null; printf '%s\n' "$PROBE_OUT" | sed 's/^/  app: /'
        else echo "SKIP dcb($nd): dcb not found"; fi
        if have mlnx_qos; then
          probe "mlnx_qos($nd)" mlnx_qos -i "$nd"
          if [ "$pfc" = unknown ] && [ "$PROBE_RC" = 0 ]; then
            if printf '%s\n' "$PROBE_OUT" | awk '/PFC configuration/{f=1} f&&/enabled/{print; exit}' | grep -q 1; then pfc=on; else pfc=off; fi
          fi
          printf '%s\n' "$PROBE_OUT" | grep -i 'trust' | sed 's/^/  trust: /'
        else echo "SKIP mlnx_qos($nd): mlnx_qos not found"; fi
        ecn_ok=unknown
        if [ -d "/sys/class/net/$nd/ecn" ]; then
          for k in roce_np roce_rp; do
            for f in /sys/class/net/$nd/ecn/$k/enable/*; do
              [ -r "$f" ] && echo "  ecn $k/enable/$(basename "$f") = $(rd "$f")"
            done
          done
          a=$(rd /sys/class/net/$nd/ecn/roce_np/enable/3); b=$(rd /sys/class/net/$nd/ecn/roce_rp/enable/3)
          if [ "$a" = 1 ] && [ "$b" = 1 ]; then ecn_ok=on; else ecn_ok=off; fi
        else echo "SKIP ecn($nd): no /sys/class/net/$nd/ecn (mlx5 only)"; fi
        echo "PFC state: $pfc   ECN prio-3 (np+rp): $ecn_ok"
        if [ "$want_pfc" = 1 ] && ! is_soft "$d"; then
          [ "$pfc" = off ] && warn "$d/$p: PFC is off on $nd (RoCE needs PFC+ECN unless ZTR/RTTCC or back to back; use --no-pfc then)"
          [ "$pfc" = unknown ] && warn "$d/$p: PFC state unknown for $nd (no dcb/mlnx_qos output; may need root)"
          [ "$ecn_ok" = off ] && warn "$d/$p: ECN (roce_np/roce_rp) not enabled for prio 3 on $nd"
        fi
      fi
    else
      echo "netdev: no sysfs entry, MTU/ethtool/PFC probes skipped"
    fi
  done
done

hdr "RDMA STATISTICS (counters, read-only)"
if have rdma; then
  for d in $devs; do tmo rdma statistic show link "$d/1" 2>&1 | head -40; done
else echo "SKIP rdma-statistic: rdma not found"; fi

hdr "CLOCK SYNC"
synced=unknown
if have timedatectl; then
  v=$(tmo timedatectl show 2>/dev/null | grep -E '^(NTP|NTPSynchronized|Timezone|TimeUSec)=')
  [ -n "$v" ] && printf '%s\n' "$v" && { printf '%s\n' "$v" | grep -q '^NTPSynchronized=yes' && synced=yes || synced=no; }
else echo "SKIP timedatectl: timedatectl not found"; fi
if have chronyc; then
  probe "chronyc tracking" chronyc tracking
  if [ "$PROBE_RC" = 0 ]; then
    if printf '%s\n' "$PROBE_OUT" | grep -q 'Leap status *: Normal'; then synced=yes; else synced=no; fi
  fi
else echo "SKIP chronyc: chronyc not found"; fi
ls /dev/ptp* 2>/dev/null | sed 's/^/ptp device: /'
for dd in /sys/class/ptp/*; do [ -d "$dd" ] && echo "ptp clock: $(basename "$dd") $(rd "$dd/clock_name")"; done
if have pgrep; then for pr in ptp4l phc2sys chronyd; do pgrep -x "$pr" >/dev/null && echo "running: $pr"; done; else echo "SKIP pgrep: pgrep not found"; fi
echo "clock synced: $synced"
[ "$synced" = yes ] || warn "clock sync is '$synced' (needs chrony/timesyncd/PTP synchronized; runbook 3.1)"

hdr "GPU"
if have nvidia-smi; then
  probe nvidia-smi nvidia-smi --query-gpu=index,name,driver_version,memory.total,pci.bus_id --format=csv
  probe "nvidia-smi topo" nvidia-smi topo -m
else echo "SKIP nvidia-smi: nvidia-smi not found"; fi

hdr "SUMMARY"
devl=$(printf "%s " $devs); echo "host: $HOST   date_utc: $(date -u "+%Y-%m-%dT%H:%M:%SZ" 2>/dev/null)   rdma_devices: ${devl:-none}"
if [ ${#WARNS[@]} -eq 0 ]; then echo "no warnings"; else
  for w in "${WARNS[@]}"; do echo "WARN $w"; done
fi
echo "warnings: ${#WARNS[@]}"
}

report
exit 0
