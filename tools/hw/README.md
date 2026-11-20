# tools/hw

## collect.sh: read-only host report

```
tools/hw/collect.sh                          # report to stdout
tools/hw/collect.sh -o RUN/hosts/$(hostname)/collect-day0.txt
tools/hw/collect.sh --no-pfc -o FILE         # back to back, iWARP, or ZTR/RTTCC day: no PFC/ECN warnings
tools/hw/collect.sh -h
```

Bash only, no root, no writes except `-o FILE`, no state changes; each probe is time-boxed (`timeout 10`).
A missing tool prints `SKIP <probe>: <tool> not found` and the run goes on. Exit status is 0 even with
warnings (2 on bad arguments). Run it as a normal user first; values that need root (dmesg, some `dcb` /
`mlnx_qos` / `lspci` fields) print empty or a `NOTE ... may need root` line.

Sections: header (hostname, IPs, uid), OS/kernel, CPU/NUMA/governor, hugepages, IOMMU, memlock, kernel
modules, RDMA tools (`rdma link`, `ibv_devices`, perftest), per-device block (firmware, PCI, NIC NUMA node,
`ibv_devinfo`, link speed, netdev MTU, RoCE active MTU, GID table with RoCE version, `ethtool -i`, PFC / ECN /
DSCP trust), `rdma statistic`, clock sync, GPU, then `SUMMARY`.

`SUMMARY` lists one `WARN` line per problem the runbook cares about: memlock not unlimited, `iommu=pt`
missing, no 1 GiB hugepages (memory nodes only), governor not `performance`, no perftest, no RoCE v2 GID,
netdev MTU < 4096 (and < 9000), RoCE active MTU < 4096, port not ACTIVE, NIC NUMA node -1, PFC off or
unknown, ECN off on priority 3, clock not synced. Soft devices (`rxe*`, `siw*`) skip the MTU/PFC/ECN
warnings. Compare `collect-day0.txt` with `collect-final.txt` using `diff`.

Test inside the dev VM: `tools/dev/run.sh --rdma -- tools/hw/collect.sh`.
