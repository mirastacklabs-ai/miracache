#!/usr/bin/env bash
# Build, test and package steps shared by the GitHub workflows (ci.yml, release.yml).
# Usage: .github/scripts/ci.sh <step> [arg]
#   deps                 apt packages for the C++ build (Ubuntu 24.04)
#   build <preset>       configure + build a CMake preset (release, asan, tsan), no simulator
#   test <preset>        ctest for the preset, without the tests that need a live RDMA device (label rdma)
#   go                   go vet + go test -race in controller/ (Go is set up by the workflow)
#   python               the Python unit tests (pure Python)
#   ruff                 ruff check python/
#   format <base-sha>    clang-format check of the C/C++ files changed since <base-sha>
#   dco <base> <head>    every commit in base..head carries Signed-off-by:
#   package <tag>        miracache-<tag>-linux-x86_64.tar.gz + SHA256SUMS from the release build
#   notes <tag>          release notes for <tag> from CHANGELOG.md (stdout)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

export CC=${CC:-clang-18} CXX=${CXX:-clang++-18}
sudo_() { if [[ $(id -u) -eq 0 ]]; then "$@"; else sudo "$@"; fi; }
step=${1:?step}
shift || true

case $step in
  deps)
    sudo_ apt-get update
    sudo_ env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates git clang-18 clang-tools-18 clang-format-18 libclang-rt-18-dev cmake ninja-build pkg-config \
      libibverbs-dev librdmacm-dev libssl-dev python3
    ;;
  build)
    p=${1:?preset}
    cmake --preset "$p" -DMIRACACHE_SIM=OFF -DMIRACACHE_WERROR=ON
    cmake --build --preset "$p"
    ;;
  test)
    p=${1:?preset}
    jobs=$(nproc)
    if [[ $p == tsan ]]; then
      jobs=1
      # ThreadSanitizer in LLVM 18 aborts on kernels with high-entropy ASLR ("unexpected memory mapping").
      sudo_ sysctl -w vm.mmap_rnd_bits=28 || true
    fi
    ctest --preset "$p" -LE rdma -j "$jobs"
    ;;
  go)
    cd controller
    go vet ./...
    go test -race ./...
    ;;
  python)
    PYTHONPATH=python python3 -m unittest discover -s ./tests/python -v
    ;;
  ruff)
    ruff check python/
    ;;
  format)
    base=${1:?base sha}
    files=$(git diff --name-only --diff-filter=ACMR "$base" HEAD -- '*.c' '*.cc' '*.cpp' '*.h' '*.hpp' || true)
    if [[ -z $files ]]; then echo "no C/C++ files changed"; exit 0; fi
    # shellcheck disable=SC2086
    clang-format-18 --dry-run -Werror $files
    ;;
  dco)
    base=${1:?base}
    head=${2:?head}
    bad=0
    for c in $(git rev-list --no-merges "$base..$head"); do
      if ! git log -1 --format=%B "$c" | grep -qiE '^Signed-off-by: .+ <.+>'; then
        echo "missing Signed-off-by: $(git log -1 --format='%h %s' "$c")"
        bad=1
      fi
    done
    if ((bad)); then
      echo "Add a sign-off to each commit: git commit -s (or git rebase --signoff <base>). See CONTRIBUTING.md."
      exit 1
    fi
    echo "all commits are signed off"
    ;;
  package)
    tag=${1:?tag}
    b=build/release
    cmake --build --preset release
    mkdir -p "$b/bin"
    (
      cd controller
      go build -trimpath -ldflags=-s -o "../$b/bin/mira-controller" ./cmd/mira-controller
      go build -trimpath -ldflags=-s -o "../$b/bin/mirctl" ./cmd/mirctl
    )
    name=miracache-$tag-linux-x86_64
    stage=build/dist/$name
    rm -rf build/dist
    mkdir -p "$stage/bin" "$stage/lib" "$stage/include/miracache"
    install -m 0755 "$b/server/mira-memnode" "$b/bin/mira-controller" "$b/bin/mirctl" "$stage/bin/"
    nicprobe=$(find "$b" -type f -name mira-nicprobe | head -n1)
    [[ -n $nicprobe ]] || { echo "mira-nicprobe not built" >&2; exit 1; }
    install -m 0755 "$nicprobe" "$stage/bin/"
    install -m 0755 "$b/client/libmiracache.so" "$stage/lib/"
    install -m 0644 client/include/miracache/*.h "$stage/include/miracache/"
    install -m 0644 LICENSE NOTICE "$stage/"
    strip --strip-unneeded "$stage"/bin/mira-memnode "$stage"/bin/mira-nicprobe "$stage/lib/libmiracache.so" || true
    tar -C build/dist --sort=name --owner=0 --group=0 --numeric-owner -czf "build/dist/$name.tar.gz" "$name"
    (cd build/dist && sha256sum "$name.tar.gz" > SHA256SUMS)
    ls -l build/dist
    tar -tzvf "build/dist/$name.tar.gz"
    cat build/dist/SHA256SUMS
    ;;
  notes)
    tag=${1:?tag}
    ver=${tag#*-}
    if [[ -f CHANGELOG.md ]]; then
      # The section whose "## " heading names the tag or its version; it ends at the next "## " heading.
      awk -v t="$tag" -v v="$ver" '
        /^## / { if (on) exit; on = (index($0, t) || index($0, "[" v "]") || index($0, " " v)); next }
        on { print }' CHANGELOG.md
    fi
    ;;
  *)
    echo "unknown step: $step" >&2
    exit 2
    ;;
esac
