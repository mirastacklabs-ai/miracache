---
name: Hardware report
about: Share results from running miracache on real servers, NICs or GPUs (works or fails)
title: "Hardware report: "
labels: hardware
---

<!-- Thank you: miracache is tested on software RDMA so far, so every hardware report helps. -->
<!-- Reports that something works are as useful as reports that it fails. Remove secrets, keys and certificates. -->

## Summary

<!-- One or two sentences: what you ran and whether it worked. -->

## Version

- miracache version (release tag or commit):
- Installed with: systemd / Docker:

## Memory node servers

- Server model, CPU, sockets:
- DRAM (type, size, channels populated):
- OS and kernel:
- Hugepages (size, count) and backing (`hugetlbfs` / `file`):
- Number of memory nodes:

## NICs and firmware

- NIC model (memory nodes / GPU hosts):
- Firmware version:
- Driver and rdma-core version:
- Protocol: RoCEv2 / iWARP
- Ports and speed, number of rails per host:
- RoCE only: PFC / ECN settings, or the NIC's congestion control:

## Switch

- Model and OS version:
- Relevant settings (lossless classes, ECN, MTU):

## GPU hosts (if any)

- GPU model and count per host:
- Engine and version: vLLM / SGLang:
- Model served, tensor-parallel size, block or page size:

## `mira-nicprobe --json` output

<!-- From one memory node and one GPU host. -->

```json
```

## `mira-preflight` output (GPU hosts)

```
```

## Results

<!-- What you ran (functional checks, workload), what worked, what failed, error messages, hit rate. -->
<!-- If you measured performance, describe the method and the conditions so others can reproduce it. -->

## Anything else
