# Dev/CI toolchain image for miracache. Ubuntu 24.04 (pinned by digest), clang-18,
# soft-RDMA userland. Bump the digest deliberately: docker pull ubuntu:24.04 &&
# docker inspect --format '{{index .RepoDigests 0}}' ubuntu:24.04
FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates clang-18 clang-format-18 clang-tidy-18 libclang-rt-18-dev \
      cmake ninja-build pkg-config \
      rdma-core libibverbs-dev librdmacm-dev ibverbs-utils iproute2 kmod \
      libssl-dev python3 python3-venv python3-pip perftest \
    && rm -rf /var/lib/apt/lists/*

# lld: the linker for the x86_64 cross build (tools/ci/x86_check.sh). Own layer so the cached layer above is kept.
RUN apt-get update && apt-get install -y --no-install-recommends lld-18 && rm -rf /var/lib/apt/lists/*

ENV CC=clang-18 CXX=clang++-18
WORKDIR /work
# The base image's unprivileged user (uid 1000). run.sh overrides with --user.
USER ubuntu
