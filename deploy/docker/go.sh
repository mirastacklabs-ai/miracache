#!/usr/bin/env bash
# Run the pinned Go toolchain inside the dev container:
#   deploy/docker/go.sh [-C dir] <go args...>   (e.g. -C controller build ./...)
# The toolchain is a pinned tool, not part of the image (membership plan decision 16, Q03): the
# release below is downloaded into build/go (gitignored) on first use, its SHA-256 is verified
# against the pins here (the values published at https://go.dev/dl/), and later runs reuse it.
# GOCACHE, GOMODCACHE and GOPATH live under build/. -C dir (relative to the repo root) is handled
# here. Never run Go on the macOS host.
set -euo pipefail

GO_VERSION=go1.27.4
SHA256_linux_amd64=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
SHA256_linux_arm64=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
BUILD=$ROOT/build
GOROOT_DIR=$BUILD/go

[[ $(uname -s) == Linux ]] || { echo "go.sh: Linux only; refusing on $(uname -s)" >&2; exit 1; }

case $(uname -m) in
  aarch64|arm64) arch=arm64; want=$SHA256_linux_arm64 ;;
  x86_64|amd64)  arch=amd64; want=$SHA256_linux_amd64 ;;
  *) echo "go.sh: unsupported machine $(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "$BUILD"

installed_version() {
  if [[ -x $GOROOT_DIR/bin/go && -f $GOROOT_DIR/VERSION ]]; then head -n1 "$GOROOT_DIR/VERSION"; fi
}

if [[ $(installed_version) != "$GO_VERSION" ]]; then
  # Serialize the install: two containers sharing build/ must not race on build/go.
  exec 9>"$BUILD/.go-install.lock"
  flock 9
fi
if [[ $(installed_version) != "$GO_VERSION" ]]; then
  tmp=$(mktemp -d "$BUILD/go-dl.XXXXXX")
  trap 'rm -rf "$tmp"' EXIT
  file=$GO_VERSION.linux-$arch.tar.gz
  echo "go.sh: downloading $file" >&2
  if command -v curl >/dev/null; then
    curl -fsSL --max-time 600 --retry 3 -o "$tmp/$file" "https://go.dev/dl/$file"
  else
    python3 -c 'import sys,urllib.request; open(sys.argv[2],"wb").write(urllib.request.urlopen(sys.argv[1], timeout=600).read())' \
      "https://go.dev/dl/$file" "$tmp/$file"
  fi
  got=$(sha256sum "$tmp/$file" | cut -d' ' -f1)
  if [[ $got != "$want" ]]; then
    echo "go.sh: SHA-256 mismatch for $file: got $got, want $want" >&2
    exit 1
  fi
  mkdir "$tmp/x"
  tar -xzmf "$tmp/$file" -C "$tmp/x"
  rm -rf "$GOROOT_DIR"
  mv "$tmp/x/go" "$GOROOT_DIR"
  rm -rf "$tmp"
  trap - EXIT
  echo "go.sh: installed $GO_VERSION in build/go" >&2
fi
exec 9>&-  # release the install lock before running go

export GOROOT=$GOROOT_DIR
export GOPATH=$BUILD/gopath GOMODCACHE=$BUILD/gopath/pkg/mod GOCACHE=$BUILD/go-cache
export GOTOOLCHAIN=local GOTELEMETRY=off GOFLAGS=${GOFLAGS:-}
export PATH=$GOROOT_DIR/bin:$PATH
mkdir -p "$GOPATH" "$GOCACHE"

if [[ ${1:-} == -C ]]; then
  [[ $# -ge 2 ]] || { echo "go.sh: -C needs a directory" >&2; exit 2; }
  cd "$ROOT/$2"
  shift 2
fi
exec go "$@"
