# Changelog

All notable changes to miracache are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Releases are tagged `alpha-X.Y.Z` while the project is in
alpha; until a stable release, any version may change formats, configuration or APIs (always noted here).

## [Unreleased]

## [alpha-0.2.0] - 2026-11-19

Everything needed to build, test and check miracache yourself is now in this repository.

### Added
- The test suites: unit, integration, end-to-end (RDMA, skipped without an RDMA device), engine contract and
  golden-vector tests, plus the libFuzzer targets in `tests/fuzz/`.
- The deterministic fault-injection simulator (`sim/`, the `sim` preset) and the Rust/Stateright protocol model
  (`model/`). See `docs/simulator.md`.
- One-command quick start over soft-RoCE: `deploy/compose/run.sh` brings up three memory nodes and a test client
  and prints `PASS`.
- Store-and-fetch examples in C++, C and Python (`examples/`).
- Continuous integration with GitHub Actions (release, asan and tsan builds and tests; Go and Python tests; on pull
  requests also clang-format, DCO and secret checks).
- Signed release binaries: each release attaches a Linux x86-64 tarball, `SHA256SUMS` and a Sigstore bundle.
- Public documentation: architecture, wire protocol and storage formats, security model, operations guide, simulator.
- `SECURITY.md`, `CODE_OF_CONDUCT.md`, this changelog, and issue and pull request templates.
- Development and CI tooling in `tools/`.

### Changed
- Builds offline or behind a proxy: toml++ from a local source directory or a system install
  (`MIRACACHE_USE_SYSTEM_TOMLPLUSPLUS`). See `docs/operations.md`.
- The controller needs Go 1.22 or newer (was 1.27) and no longer forces a toolchain download.
- Example configs moved to `deploy/examples/` (memory node, client, cluster).

### Known issues
- The package versions inside the tree (CMake and Python `0.0.1`, the model crate `0.1.0`) are not yet tied to the
  release tag.

## [alpha-0.1.3] - 2026-11-18

### Changed
- README: the MIRASTACK LABS logo, in light and dark variants.
- GitHub repository description and topics ("About").

## alpha-0.1.2

Never published.

## [alpha-0.1.1] - 2026-11-18

### Changed
- README rewritten for first-time readers: what miracache is, how a fetch and a store work, status, requirements,
  quick start and security model.

### Added
- Example configurations for a memory node and a GPU-host client in `deploy/examples/`.

## [alpha-0.1.0] - 2026-11-18

First public release. Built and tested end to end on software RDMA (soft-RoCE and soft-iWARP); not yet validated on
hardware NICs or in GPU serving runs. No performance figures are published.

### Added
- `mira-memnode`, the memory node: encrypted KV blocks in pinned hugepage memory, leases, two-phase stores with a
  commit fence, eviction, scrubbing, an mTLS admin API and Prometheus metrics. The cache survives a process restart.
- `libmiracache`, the client library (C++ API, C ABI, Python binding): engine-native key derivation, AES-256-GCM,
  rendezvous placement, multi-rail RDMA over RoCEv2 and iWARP through `rdma_cm`, optional replicas.
- vLLM adapter (`MiraTier`, a secondary tier of the offloading connector) and SGLang adapter
  (`MiraHiCacheStorage`, a HiCache `dynamic` storage backend), contract-tested against the pinned engine versions
  (import only, no GPU).
- `mira-controller` and `mirctl` (Go): signed membership and configuration bundles, failure detection, audit log.
- `mira-preflight` and `node_prep` host checks, `mira-nicprobe`.
- systemd units, Docker images, Grafana dashboards and Prometheus alert rules.
- Wire format v0, crypto format v1 and storage layout v0, with golden vectors in `proto/golden/`.

[Unreleased]: https://github.com/mirastacklabs-ai/miracache/compare/alpha-0.2.0...HEAD
[alpha-0.2.0]: https://github.com/mirastacklabs-ai/miracache/releases/tag/alpha-0.2.0
[alpha-0.1.3]: https://github.com/mirastacklabs-ai/miracache/releases/tag/alpha-0.1.3
[alpha-0.1.1]: https://github.com/mirastacklabs-ai/miracache/releases/tag/alpha-0.1.1
[alpha-0.1.0]: https://github.com/mirastacklabs-ai/miracache/releases/tag/alpha-0.1.0
