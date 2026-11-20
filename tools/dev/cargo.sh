#!/usr/bin/env bash
# Run cargo for model/ inside the dev container:  tools/dev/run.sh tools/dev/cargo.sh test --release
# The toolchain lives in build/rust (gitignored), installed from the pinned rustc, cargo and rust-std 1.82.0 archives from
# static.rust-lang.org (sha256-checked, extracted to build/rust-dist, each install.sh run
# with --prefix=/work/build/rust inside the container). Two build jobs, output under build/.
set -euo pipefail
[[ -x /work/build/rust/bin/cargo ]] || { echo "cargo.sh: no toolchain in build/rust (see the header of this file)" >&2; exit 1; }
export PATH=/work/build/rust/bin:$PATH
export CARGO_HOME=/work/build/cargo-home CARGO_TARGET_DIR=/work/build/model-target
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=clang-18 CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang-18
export CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2
cd /work/model
exec cargo "$@"
