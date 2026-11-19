#!/usr/bin/env bash
# Run one miracache memory node as a standalone Docker container (open-source Docker engine).
# Benchmarks use the systemd path on bare metal; Docker is for convenience (README.md in this directory).
#
#   MIRA_CONFIG=/etc/miracache/memnode.toml MIRA_PKI_DIR=/etc/miracache/pki deploy/docker/run-memnode.sh
#
# Environment (all optional except MIRA_CONFIG):
#   MIRA_IMAGE         image to run                       (default miracache-memnode:<CMake version>)
#   MIRA_NAME          container name                     (default mira-memnode)
#   MIRA_CONFIG        host path of memnode.toml, mounted read-only at /etc/miracache/memnode.toml   (required)
#   MIRA_PKI_DIR       host dir with ca.pem, node cert and key, mounted read-only at /run/miracache/pki;
#                      the toml must name the files there. Keys must be readable by MIRA_RUN_USER.
#   MIRA_STATE         named volume or absolute host dir for [node] state_dir (default <name>-state).
#                      Mounted at /var/lib/miracache (set state_dir to that in the toml). This is the node's
#                      identity: keep it across restarts and image upgrades. Never share it between nodes.
#   MIRA_STORE_DIR     absolute host dir bind-mounted rw at the SAME path, for [store] backing = hugetlbfs/file
#                      (e.g. /dev/hugepages); no copy layer, the node maps it directly.
#   MIRA_RUN_USER      uid:gid to run as                  (default 10001:10001, the image's "mira")
#   MIRA_DRAIN_MS      node.drain_ms the stop timeout is derived from (default: read from the toml, else 5000)
#   MIRA_RESTART       Docker restart policy              (default on-failure:5, see README.md)
#   MIRA_CPUSET_CPUS / MIRA_CPUSET_MEMS   NUMA pinning (--cpuset-cpus / --cpuset-mems), the equivalent of
#                      numactl --cpunodebind/--membind in the systemd unit. Unset = no pinning.
#   MIRA_FOREGROUND=1  run attached (default: detached; logs via `docker logs -f <name>`)
# Extra `docker run` flags can follow `--`. No CPU or memory cgroup limit is set (they would sit on the
# data path); add --cpus/--memory yourself after `--` for non-benchmark use only.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

extra=()
if [[ ${1:-} == -- ]]; then shift; extra=("$@"); elif [[ $# -gt 0 ]]; then echo "usage: $0 [-- docker-run-flags...]" >&2; exit 2; fi

version=$(sed -n 's/^project(miracache VERSION \([0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")
image=${MIRA_IMAGE:-miracache-memnode:$version}
name=${MIRA_NAME:-mira-memnode}
config=${MIRA_CONFIG:-}
[[ -n $config && -f $config ]] || { echo "run-memnode.sh: MIRA_CONFIG must name an existing memnode.toml" >&2; exit 2; }
config=$(cd "$(dirname "$config")" && pwd)/$(basename "$config")
state=${MIRA_STATE:-$name-state}
user=${MIRA_RUN_USER:-10001:10001}
restart=${MIRA_RESTART:-on-failure:5}

# Stop timeout: SIGTERM starts the drain (node.drain_ms); Docker must wait longer before SIGKILL.
drain_ms=${MIRA_DRAIN_MS:-$(sed -n 's/^[[:space:]]*drain_ms[[:space:]]*=[[:space:]]*\([0-9][0-9]*\).*/\1/p' "$config" | head -n1)}
drain_ms=${drain_ms:-5000}
stop_timeout=$(( (drain_ms + 999) / 1000 + 15 ))

# RDMA device nodes: every uverbs* plus rdma_cm (colima VM on macOS, the host itself on Linux).
if [[ $(uname -s) == Darwin ]]; then
  nodes=$(colima ssh -- sh -c 'ls /dev/infiniband | grep -E "^(rdma_cm|uverbs[0-9]+)$"' 2>/dev/null || true)
else
  nodes=$(ls /dev/infiniband 2>/dev/null | grep -E '^(rdma_cm|uverbs[0-9]+)$' || true)
fi
grep -q '^rdma_cm$' <<<"$nodes" || { echo "run-memnode.sh: no /dev/infiniband/rdma_cm (load rdma_ucm)" >&2; exit 1; }
devs=()
for n in $nodes; do devs+=(--device "/dev/infiniband/$n"); done

# State volume: make it owned by the run user (a fresh named volume is root-owned), mode 0700.
# A named volume must not be re-initialised from the image directory (Docker "copy-up" resets the owner of an
# empty volume to the image's user): mount it with nocopy.
nocopy=:nocopy; [[ $state == /* ]] && nocopy=
if [[ $state == /* ]]; then
  [[ -d $state ]] || { echo "run-memnode.sh: MIRA_STATE $state is not a directory" >&2; exit 2; }
else
  docker volume inspect "$state" >/dev/null 2>&1 || docker volume create "$state" >/dev/null
fi
docker run --rm --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER -v "$state:/var/lib/miracache$nocopy" \
  --entrypoint sh "$image" -c "chown $user /var/lib/miracache && chmod 0700 /var/lib/miracache"

mounts=(-v "$config:/etc/miracache/memnode.toml:ro" -v "$state:/var/lib/miracache$nocopy")
[[ -n ${MIRA_PKI_DIR:-} ]] && mounts+=(-v "$MIRA_PKI_DIR:/run/miracache/pki:ro")
[[ -n ${MIRA_STORE_DIR:-} ]] && mounts+=(-v "$MIRA_STORE_DIR:$MIRA_STORE_DIR")

pin=()
[[ -n ${MIRA_CPUSET_CPUS:-} ]] && pin+=(--cpuset-cpus "$MIRA_CPUSET_CPUS")
[[ -n ${MIRA_CPUSET_MEMS:-} ]] && pin+=(--cpuset-mems "$MIRA_CPUSET_MEMS")

mode=(-d)
[[ ${MIRA_FOREGROUND:-0} == 1 ]] && mode=()

# Data path stays native: host network, device nodes passed straight through, no cgroup limits, default
# seccomp profile (nothing the node uses is blocked by it: mmap/mlock/ioctl on the verbs devices/sockets).
exec docker run ${mode[@]+"${mode[@]}"} --name "$name" --restart "$restart" --stop-timeout "$stop_timeout" \
  --network host --user "$user" "${devs[@]}" \
  --cap-drop ALL --cap-add IPC_LOCK --ulimit memlock=-1:-1 \
  --security-opt no-new-privileges --read-only \
  "${mounts[@]}" ${pin[@]+"${pin[@]}"} ${extra[@]+"${extra[@]}"} \
  "$image" --config /etc/miracache/memnode.toml
