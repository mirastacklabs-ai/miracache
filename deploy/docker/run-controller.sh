#!/usr/bin/env bash
# Run the miracache controller as a standalone Docker container (bundle mode, one per cluster).
# Benchmarks use the systemd path on bare metal; Docker is for convenience (README.md in this directory).
#
#   MIRA_CONF_DIR=/etc/miracache deploy/docker/run-controller.sh [-- extra mira-controller flags]
#
# MIRA_CONF_DIR (required) is mounted read-only at /run/miracache and must hold: trust.toml, publish.seed,
# security.seed (0600), pki/controller.pem, pki/controller.key (0600), pki/ca.pem, all readable by
# MIRA_RUN_USER. The defaults below point the controller at those files; flags after `--` are added to
# the command line (a repeated flag overrides the default).
# Optional: MIRA_IMAGE (default miracache-controller:<CMake version>), MIRA_NAME (mira-controller),
# MIRA_STATE (named volume or absolute host dir, default <name>-state; holds the store and the audit log),
# MIRA_RUN_USER (default 10001:10001), MIRA_API_LISTEN (default :9470), MIRA_RESTART (default on-failure:5),
# MIRA_FOREGROUND=1. The controller handles SIGTERM at once, so the stop timeout is a flat 15 s.
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
extra=()
if [[ ${1:-} == -- ]]; then shift; extra=("$@"); elif [[ $# -gt 0 ]]; then echo "usage: $0 [-- controller-flags...]" >&2; exit 2; fi

version=$(sed -n 's/^project(miracache VERSION \([0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")
image=${MIRA_IMAGE:-miracache-controller:$version}
name=${MIRA_NAME:-mira-controller}
conf=${MIRA_CONF_DIR:-}
[[ -n $conf && -d $conf ]] || { echo "run-controller.sh: MIRA_CONF_DIR must be an existing directory" >&2; exit 2; }
state=${MIRA_STATE:-$name-state}
user=${MIRA_RUN_USER:-10001:10001}

nocopy=:nocopy; [[ $state == /* ]] && nocopy=  # no copy-up: see run-memnode.sh
if [[ $state != /* ]]; then docker volume inspect "$state" >/dev/null 2>&1 || docker volume create "$state" >/dev/null; fi
docker run --rm --user 0:0 --cap-drop ALL --cap-add CHOWN --cap-add FOWNER -v "$state:/var/lib/miracache-controller$nocopy" \
  --entrypoint sh "$image" -c "chown $user /var/lib/miracache-controller && chmod 0700 /var/lib/miracache-controller"

mode=(-d)
[[ ${MIRA_FOREGROUND:-0} == 1 ]] && mode=()

exec docker run ${mode[@]+"${mode[@]}"} --name "$name" --restart "${MIRA_RESTART:-on-failure:5}" --stop-timeout 15 \
  --network host --user "$user" --cap-drop ALL --security-opt no-new-privileges --read-only \
  -v "$conf:/run/miracache:ro" -v "$state:/var/lib/miracache-controller$nocopy" \
  "$image" \
  --store-dir /var/lib/miracache-controller/store --audit-dir /var/lib/miracache-controller/audit \
  --trust-keys /run/miracache/trust.toml --publish-key /run/miracache/publish.seed \
  --security-key /run/miracache/security.seed \
  --cert /run/miracache/pki/controller.pem --key /run/miracache/pki/controller.key --ca /run/miracache/pki/ca.pem \
  --api-listen "${MIRA_API_LISTEN:-:9470}" ${extra[@]+"${extra[@]}"}
