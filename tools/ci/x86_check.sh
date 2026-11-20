#!/usr/bin/env bash
# x86_64 build + unit-test check from the aarch64 dev VM (pre-hardware gate item). Run from the Mac:
#   tools/ci/x86_check.sh            default: CROSS-compile natively, run the tests under qemu emulation (minutes)
#   tools/ci/x86_check.sh --emulate  compile too under qemu (build/x86-release; >8 h on a busy VM, last resort)
# Default path: native clang-18 + lld (native dev image, run.sh) cross-compile the release preset for
# x86_64-linux-gnu into build/x86-cross against a sysroot taken from the amd64 dev image (build/x86-sysroot,
# created here when missing; delete it to refresh), cmake/toolchains/x86_64-linux-gnu.cmake. Only the tests run
# emulated: ctest in the amd64 dev image (run.sh --arch amd64, tag miracache-dev:24.04-amd64) on the same tree.
# Lean on purpose: release preset, -j2, unit tests only. Excludes the RDMA tests (ctest label "rdma": rxe/siw in
# the VM kernel are aarch64, so RDMA on amd64-emulated userspace is out of scope; run those on the real x86_64
# hosts) and the seed sweeps (-E '^sim_'). Never touches the native build/release or the native dev image.
# Last line is "OK: x86_64 ..." or "FAIL ..."; exit status is non-zero on failure.
set -Eeuo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."

# Whatever fails (set -e, a bad variable, ^C), the last line is "FAIL: x86 check (...)" and the temporary
# sysroot container of make_sysroot goes. A step that already printed its own FAIL still gets this closing line.
cid=""          # the temporary sysroot container, while it exists
check_ok=0      # set at the very end of a successful run
fail_line=""
trap 'fail_line=$LINENO' ERR
trap 'exit 130' INT
trap 'exit 143' TERM
on_exit() {
  local rc=$?
  trap - ERR INT TERM EXIT
  [[ -n $cid ]] && docker rm -f "$cid" >/dev/null 2>&1 || true
  if (( rc != 0 && check_ok == 0 )); then
    echo "FAIL: x86 check (mode ${mode:-?}, exit $rc${fail_line:+, line $fail_line})" >&2
  fi
  exit "$rc"
}
trap on_exit EXIT

mode=cross
case ${1:-} in
  "") ;;
  --emulate) mode=emulate ;;
  --cross-build|--emulate-inner|--test) mode=${1#--} ;;
  *) echo "usage: $0 [--emulate]" >&2; exit 2 ;;
esac
ctest_args=(-j2 --output-on-failure -LE rdma -E '^sim_')
sysroot=build/x86-sysroot

make_sysroot() {
  [[ -f $sysroot/.complete ]] && return 0
  echo "=== creating $sysroot from miracache-dev:24.04-amd64 ==="
  docker image inspect miracache-dev:24.04-amd64 >/dev/null 2>&1 || tools/dev/run.sh --arch amd64 -- true
  rm -rf "$sysroot"; mkdir -p "$sysroot"
  local p
  cid=$(docker create --platform linux/amd64 miracache-dev:24.04-amd64)
  for p in usr/include usr/lib/x86_64-linux-gnu lib/x86_64-linux-gnu usr/lib/gcc/x86_64-linux-gnu usr/share/pkgconfig \
           usr/lib/llvm-18/lib/clang; do
    mkdir -p "$sysroot/$(dirname "$p")"
    docker cp "$cid:/$p" "$sysroot/$(dirname "$p")/" || { docker rm "$cid" >/dev/null; echo "FAIL: cannot copy $p" >&2; exit 1; }
  done
  docker rm "$cid" >/dev/null; cid=""
  # the dynamic loader path that libc.so (a linker script) names
  mkdir -p "$sysroot/lib64"
  ln -sf ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 "$sysroot/lib64/ld-linux-x86-64.so.2"
  touch "$sysroot/.complete"
}

case $mode in
  cross)
    start=$(date +%s)
    make_sysroot
    tools/dev/run.sh -- tools/ci/x86_check.sh --cross-build
    echo "cross build done in $(( $(date +%s) - start )) s; running tests under qemu-x86_64"
    tools/dev/run.sh --arch amd64 -- tools/ci/x86_check.sh --test
    echo "OK: x86_64 cross-built release + unit tests (emulated), $(( $(date +%s) - start )) s"
    ;;
  cross-build)   # inside the NATIVE dev container
    [[ $(uname -m) == aarch64 ]] || { echo "FAIL: --cross-build runs in the native (aarch64) container" >&2; exit 1; }
    [[ -x /usr/lib/llvm-18/bin/ld.lld ]] || { echo "FAIL: no ld.lld; rebuild the native dev image (tools/dev/Dockerfile)" >&2; exit 1; }
    cmake --preset release -B build/x86-cross -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/x86_64-linux-gnu.cmake \
      -DMIRACACHE_WERROR=ON
    cmake --build build/x86-cross -j2
    ;;
  test)          # inside the amd64 dev container (emulated)
    [[ $(uname -m) == x86_64 ]] || { echo "FAIL: --test runs in the amd64 container" >&2; exit 1; }
    ctest --test-dir build/x86-cross "${ctest_args[@]}"
    ;;
  emulate)
    tools/dev/run.sh --arch amd64 -- tools/ci/x86_check.sh --emulate-inner
    ;;
  emulate-inner) # inside the amd64 container: compile and test under qemu
    start=$(date +%s)
    cmake --preset release -B build/x86-release -DMIRACACHE_WERROR=ON
    cmake --build build/x86-release -j2
    ctest --test-dir build/x86-release "${ctest_args[@]}"
    echo "OK: x86_64 emulated release build + unit tests, $(( $(date +%s) - start )) s"
    ;;
esac
check_ok=1
