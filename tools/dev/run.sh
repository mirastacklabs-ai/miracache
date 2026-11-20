#!/usr/bin/env bash
# Build the dev image (cached) and run a command in it with the repo bind-mounted at /work.
#   tools/dev/run.sh [--arch amd64] [--rdma-setup] [--rdma] [--tsan] [--] [command...]     (default command: bash)
# Flags may appear in any position before "--"; everything after "--" is the command
# verbatim. Default: unprivileged, non-root (host uid:gid), default bridge network,
# all capabilities dropped except Docker's defaults, no-new-privileges.
#   --rdma-setup  run as root with only NET_ADMIN + SYS_MODULE (still no-new-privileges),
#                 for loading/configuring rxe or siw. Use only for that setup step.
#   --rdma        expose the VM's soft-RDMA devices (see tools/dev/rdma_setup.sh): passes
#                 /dev/infiniband/{rdma_cm,uverbs*} with --device, memlock unlimited, and
#                 the VM's network namespace (--network host). Still unprivileged, non-root,
#                 no added capabilities. Host networking is required because rdma_cm
#                 resolves addresses to RDMA devices through the netdev they are bound to
#                 (eth0 of the VM); a bridge-network veth is bound to no RDMA device.
#   --arch amd64  run the dev image for linux/amd64 under qemu emulation (own tag miracache-dev:24.04-amd64;
#                 the native image is never replaced). Slow; use build dirs separate from the native ones
#                 (tools/ci/x86_check.sh does). Incompatible with --rdma (the VM kernel RDMA devices are aarch64).
#   --tsan        add seccomp=unconfined so ThreadSanitizer can run (it needs syscalls
#                 the default profile blocks, e.g. personality()). NOT enabled by default.
# Optional extra read-only mount (off by default): MIRA_EXTRA_RO_MOUNT=host_path:container_path
#   e.g. MIRA_EXTRA_RO_MOUNT=$HOME/repos/github/private/agentbench:/agentbench  (used by
#   tools/ci/bench_smoke.sh via AGENTBENCH_SRC=/agentbench). Mounted ":ro"; one mount only.
# Resources: --cpus 2 --memory 3g by default (MIRA_DEV_CPUS / MIRA_DEV_MEM override).
# Inside, CMAKE_BUILD_PARALLEL_LEVEL defaults to 2 (MIRA_BUILD_JOBS overrides; tools/ci/full_gate.sh sets it per lane).
set -euo pipefail

IMAGE=${MIRACACHE_DEV_IMAGE:-miracache-dev:24.04}
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)

rdma_setup=0
tsan=0
rdma=0
arch=
cmd=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --rdma-setup) rdma_setup=1; shift ;;
    --rdma) rdma=1; shift ;;
    --tsan) tsan=1; shift ;;
    --arch) arch=${2:-}; [[ $arch == amd64 ]] || { echo "run.sh: --arch supports only amd64" >&2; exit 2; }; shift 2 ;;
    --) shift; cmd+=("$@"); break ;;
    *) cmd+=("$1"); shift ;;
  esac
done
[[ ${#cmd[@]} -eq 0 ]] && cmd=(bash)
if [[ -n $arch ]]; then
  [[ $rdma -eq 0 && $rdma_setup -eq 0 ]] || { echo "run.sh: --arch amd64 cannot be combined with --rdma/--rdma-setup" >&2; exit 2; }
  [[ -n ${MIRACACHE_DEV_IMAGE:-} ]] || IMAGE=$IMAGE-$arch
fi

secure=(--security-opt no-new-privileges)
user=(--user "$(id -u):$(id -g)")
if [[ $rdma_setup -eq 1 ]]; then
  user=(--user 0:0)
  secure+=(--cap-add NET_ADMIN --cap-add SYS_MODULE)
fi
if [[ $tsan -eq 1 ]]; then
  secure+=(--security-opt seccomp=unconfined)
fi

net=()
if [[ $rdma -eq 1 ]]; then
  # Enumerate the device nodes in the VM (colima) or on the Linux host itself (tools/dev/hostvm.sh).
  source "$ROOT/tools/dev/hostvm.sh"
  nodes=$(vm sh -c 'ls /dev/infiniband | grep -E "^(rdma_cm|uverbs[0-9]+)$"' 2>/dev/null || true)
  [[ -z $nodes ]] && nodes=$'rdma_cm\nuverbs0\nuverbs1'
  if ! grep -q '^rdma_cm$' <<<"$nodes"; then
    echo "run.sh --rdma: no /dev/infiniband/rdma_cm in the VM; run tools/dev/rdma_setup.sh" >&2
    exit 1
  fi
  for n in $nodes; do secure+=(--device "/dev/infiniband/$n"); done
  secure+=(--ulimit memlock=-1:-1)
  net=(--network host)
fi

# A custom image (e.g. miracache-engines, built by tools/ci/engine_contract.sh) is built by its
# owner; building the dev Dockerfile under its tag here would overwrite it.
if [[ -z ${MIRACACHE_DEV_IMAGE:-} ]]; then
  docker build -q ${arch:+--platform linux/$arch} -t "$IMAGE" "$ROOT/tools/dev" >/dev/null
fi

tty=()
[[ -t 0 && -t 1 ]] && tty=(-it)

# Resource caps (the VM is shared with other services); override per run.
limits=(--cpus "${MIRA_DEV_CPUS:-2}" --memory "${MIRA_DEV_MEM:-3g}")

extra=()
if [[ -n ${MIRA_EXTRA_RO_MOUNT:-} ]]; then
  [[ $MIRA_EXTRA_RO_MOUNT == /*:/* ]] || { echo "run.sh: MIRA_EXTRA_RO_MOUNT must be /abs/host:/abs/container" >&2; exit 2; }
  extra=(-v "${MIRA_EXTRA_RO_MOUNT}:ro")
fi

# MIRA_DEV_LABEL=key=value labels the container (tools/ci/full_gate.sh finds and kills its lane containers by label).
label=()
[[ -n ${MIRA_DEV_LABEL:-} ]] && label=(--label "$MIRA_DEV_LABEL")

exec docker run --rm ${arch:+--platform linux/$arch} ${limits[@]+"${limits[@]}"} ${tty[@]+"${tty[@]}"} "${secure[@]}" "${user[@]}" ${net[@]+"${net[@]}"} \
  ${extra[@]+"${extra[@]}"} ${label[@]+"${label[@]}"} \
  -e HOME=/tmp -e "CMAKE_BUILD_PARALLEL_LEVEL=${MIRA_BUILD_JOBS:-2}" \
  -v "$ROOT:/work" -w /work \
  "$IMAGE" "${cmd[@]}"
