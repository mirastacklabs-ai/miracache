#!/usr/bin/env bash
# Build the miracache runtime images with the host's Docker CLI (open-source engine; never Docker Desktop).
#   deploy/docker/build.sh [--platform linux/amd64|linux/arm64] [--push] [memnode|controller|all]
# --platform (or MIRA_IMAGE_PLATFORM) builds for another architecture (qemu emulation on the VM; slow).
# A non-native platform adds a -<arch> suffix to the tags so it never replaces the native image.
# Produces miracache-memnode:<version> and miracache-controller:<version> (version = CMake project
# version, MIRA_IMAGE_VERSION overrides). With MIRA_IMAGE_NAMESPACE set it also tags
# docker.io/<namespace>/miracache-{memnode,controller}:<version>. Nothing is pushed unless --push is given
# (then MIRA_IMAGE_NAMESPACE is required and you must be logged in to docker.io yourself).
set -euo pipefail
ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
push=0
platform=${MIRA_IMAGE_PLATFORM:-}
what=all
while [[ $# -gt 0 ]]; do
  a=$1; shift
  case $a in
    --push) push=1 ;;
    --platform) platform=${1:-}; [[ -n $platform ]] || { echo "build.sh: --platform needs a value" >&2; exit 2; }; shift ;;
    memnode|controller|all) what=$a ;;
    *) echo "usage: $0 [--platform P] [--push] [memnode|controller|all]" >&2; exit 2 ;;
  esac
done
version=${MIRA_IMAGE_VERSION:-$(sed -n 's/^project(miracache VERSION \([0-9.]*\).*/\1/p' "$ROOT/CMakeLists.txt")}
[[ -n $version ]] || { echo "build.sh: cannot read the version from CMakeLists.txt" >&2; exit 1; }
sha=$(git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
ns=${MIRA_IMAGE_NAMESPACE:-}
if [[ $push -eq 1 && -z $ns ]]; then echo "build.sh: --push needs MIRA_IMAGE_NAMESPACE" >&2; exit 2; fi

# The per-Dockerfile ignore files (Dockerfile.<name>.dockerignore) are honoured only by BuildKit; the legacy builder
# would copy build/ into the context and fail with a CMakeCache mismatch. Ubuntu's docker.io needs docker-buildx.
docker buildx version >/dev/null 2>&1 || {
  echo "build.sh: BuildKit is required but 'docker buildx' is not available." >&2
  echo "  Ubuntu: sudo apt-get install docker-buildx (next to docker.io); Mac: brew install docker-buildx." >&2
  exit 1
}

targets=()
case $what in all) targets=(memnode controller) ;; *) targets=("$what") ;; esac
suffix=
plat=()
if [[ -n $platform ]]; then
  plat=(--platform "$platform")
  case $(uname -m):$platform in aarch64:linux/arm64|arm64:linux/arm64|x86_64:linux/amd64) ;; *) suffix=-${platform#linux/} ;; esac
fi
for t in "${targets[@]}"; do
  tags=(-t "miracache-$t:$version$suffix")
  [[ -n $ns ]] && tags+=(-t "docker.io/$ns/miracache-$t:$version$suffix")
  docker build ${plat[@]+"${plat[@]}"} -f "$ROOT/deploy/docker/Dockerfile.$t" --build-arg "VERSION=$version" --build-arg "GIT_SHA=$sha" \
    "${tags[@]}" "$ROOT"
  if [[ $push -eq 1 ]]; then docker push "docker.io/$ns/miracache-$t:$version$suffix"; fi
done
echo "built: ${targets[*]} version=$version sha=$sha"
