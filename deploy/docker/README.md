# Run miracache in standalone Docker containers

Benchmarks use the systemd path on bare metal; Docker is for convenience (`deploy/systemd/`).
Open-source Docker engine and CLI only (colima on a Mac lab, `docker.io` packages on Linux); never Docker
Desktop. Kubernetes is out of scope for now.

## Images

BuildKit is required (the per-Dockerfile `Dockerfile.*.dockerignore` files are honoured only by it; the legacy
builder copies `build/` into the context and fails with a CMakeCache mismatch). Ubuntu's `docker.io` package does
not include it: `sudo apt-get install docker-buildx`. On a Mac: `brew install docker-buildx`. `build.sh` checks
`docker buildx version` first and stops with this hint.

```
deploy/docker/build.sh                      # miracache-memnode:<version>, miracache-controller:<version>
MIRA_IMAGE_NAMESPACE=<ns> deploy/docker/build.sh [--push]   # also tags docker.io/<ns>/..., pushes only with --push
```

Both are multi-stage: built on the Ubuntu 24.04 digest pinned in the dev image (Go: the version
pinned in `deploy/docker/go.sh`), run on the same digest with only the runtime libraries. They run as the
non-root user `mira` (uid 10001), `STOPSIGNAL SIGTERM`, labelled with version and git sha. The build
context is the repo root; the build runs through the host `docker` CLI, not the dev container.
The binary reports git sha `unknown` (no `.git` in the build context); the image label has the sha.

## Memory node

```
MIRA_CONFIG=/etc/miracache/memnode.toml MIRA_PKI_DIR=/etc/miracache/pki deploy/docker/run-memnode.sh
```

Variables are listed at the top of the script. The flags it passes and why:

| Flag | Why |
|---|---|
| `--network host` | RDMA CM resolves addresses through the host's netdevs; also puts the host's hostname and IP in every log line and metric |
| `--device /dev/infiniband/{rdma_cm,uverbs*}` | one `--device` per node, enumerated at start; no `--privileged` |
| `--ulimit memlock=-1:-1` (plus `--cap-drop ALL --cap-add IPC_LOCK`) | registering the store with the NIC pins memory. **The memlock limit is what makes this work.** With `--user 10001` the container process has no effective `IPC_LOCK` (Docker adds the cap to the bounding set, not to the effective/ambient sets of a non-root user, and the image sets no file caps), so the cap alone would not lift the limit. The `--cap-add` is harmless and kept for a root or ambient-cap run; do not rely on it |
| `-v $MIRA_STORE_DIR:$MIRA_STORE_DIR` | hugetlbfs (e.g. `/dev/hugepages`) or `file` backing dir bind-mounted at the same path: no copy layer |
| `-v <volume>:/var/lib/miracache` | `[node] state_dir`: holds `node-id`. Identity survives container restarts and image upgrades as long as the volume does. One volume per node; it is locked. Never copy it to another host. Replace a node: stop it, `rm node-id` inside the volume (spec 6.1) |
| `-v memnode.toml:/etc/miracache/memnode.toml:ro` | config |
| `-v $MIRA_PKI_DIR:/run/miracache/pki:ro` | certs and keys (mode 0600, readable by the run user); the toml names `/run/miracache/pki/...` |
| `--stop-timeout` | `drain_ms/1000 + 15` s, derived from the toml (`node.drain_ms`, default 5000): `SIGTERM` starts the drain, Docker's `SIGKILL` must come after it |
| `--restart on-failure:5` | see below |
| `--read-only`, `--security-opt no-new-privileges`, `--user 10001:10001` | the node writes only to `state_dir` and the store dir |
| default seccomp profile (kept) | the node only needs `mmap`, `mlock`, socket calls and `ioctl`/`write` on the verbs device nodes, all allowed by Docker's default profile |

**hugetlbfs under Docker is untested.** Our CI runs the nodes with anonymous backing (`backing = "anon"`).
The hugetlbfs bind mount (`uid=`/`gid=` of the run user, hugepage reservation, the 1 GiB page size) has never been exercised in a
container; for a hugetlbfs benchmark use the systemd path.

Files the user mounts must be readable by the run user (`MIRA_RUN_USER`, default `10001:10001`): for
example `chown 10001 /etc/miracache/pki/node-1.key`.

**No overhead on the data path.** No `--cpus`/`--memory` cgroup limits are set. For non-benchmark use add
them after `--` (`run-memnode.sh -- --cpus 4 --memory 8g`). NUMA pinning, the equivalent of the
`numactl --cpunodebind/--membind` line in the systemd unit: `MIRA_CPUSET_CPUS=0-15 MIRA_CPUSET_MEMS=0`
(passed as `--cpuset-cpus` / `--cpuset-mems`).

**Exit codes and restart policy.** `mira-memnode` exits 0 (stopped, marked clean), 3 (stopped, clean mark
refused, next start is cold), 1 (startup failed), 2 (usage). Exit 3 only follows a `SIGTERM`/`SIGINT`, i.e. a
stop someone asked for. Docker cannot express systemd's `SuccessExitStatus=3`, so the policy is chosen to make
that harmless: `on-failure:5` restarts after a crash (non-zero exit while nobody asked for a stop) and gives up
after 5 tries (a startup failure, exit 1, must not loop forever); a `docker stop` is never restarted, whatever
the exit code (exit 3 included). `unless-stopped` would also restart after exit 0 and loop on a bad config.
After a stop with exit 3, alert on the log line `msg="stopped (not clean, exit 3)"`, as with systemd.

Logs go to stdout/stderr as logfmt: `docker logs -f mira-memnode`. `docker kill -s HUP mira-memnode` reloads
certs and identities.

## Controller

```
MIRA_CONF_DIR=/etc/miracache deploy/docker/run-controller.sh [-- extra flags]
```

`MIRA_CONF_DIR` is mounted read-only at `/run/miracache` (`trust.toml`, `publish.seed`, `security.seed`,
`pki/controller.{pem,key}`, `pki/ca.pem`). The store and the audit log live in a named volume at
`/var/lib/miracache-controller` (back it up: the store plus the two signing seeds). Host network, no
capabilities, read-only root filesystem.

## Tested

Both images and a 3-node memory-node setup (start, stop with drain, restart on the same volume with the same node ID) are tested in CI.

## Building for another architecture

`deploy/docker/build.sh --platform linux/amd64 [memnode|controller|all]` builds under qemu emulation (slow);
tags get an `-amd64` suffix so they never replace the native image.
