# miracache

miracache by MIRASTACK LABS: a remote KV-cache tier for LLM inference engines. It pools the DRAM of commodity
x86 servers over RDMA (RoCE v2 or iWARP, any NIC through rdma-core) and plugs into vLLM and SGLang through their
public plugin interfaces. C++20 core, Go controller, Python engine adapters. Apache-2.0.

## Layout
| Path | What |
|---|---|
| `core/` | wire protocol, fabric (verbs / rdma_cm and a simulated fabric), store, placement, crypto, telemetry |
| `client/` | `libmiracache.so`, the client library the engine adapters load |
| `server/` | `mira-memnode`, the memory node |
| `controller/` | `mira-controller` and `mirctl` (Go): membership, configuration bundles, operator CLI |
| `python/` | the `miracache` package: vLLM and SGLang adapters, preflight checks |
| `proto/golden/` | golden vectors for every wire and storage format |
| `deploy/` | systemd units, Docker images, Grafana dashboards and alerts, engine setup |
| `profiles/` | NIC profiles |

## Build
Ubuntu 24.04 with clang-18, CMake 3.28+, Ninja, rdma-core (`libibverbs-dev`, `librdmacm-dev`) and OpenSSL
(`libssl-dev`):

```sh
cmake --preset release && cmake --build --preset release      # mira-memnode, mira-nicprobe, libmiracache.so
deploy/docker/go.sh -C controller build -o "$PWD/build/release/bin/" ./cmd/mira-controller ./cmd/mirctl
```

Or build the images: `deploy/docker/build.sh` (see [deploy/docker/README.md](deploy/docker/README.md)).

## Run
- On the host under systemd: [deploy/systemd/README.md](deploy/systemd/README.md)
- In Docker: [deploy/docker/README.md](deploy/docker/README.md)
- vLLM and SGLang: check the engine flags first with [deploy/preflight.md](deploy/preflight.md); SGLang example:
  [deploy/sglang/README.md](deploy/sglang/README.md)
- Monitoring: [deploy/observability/README.md](deploy/observability/README.md)

## License
Apache-2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE). Contributions need a DCO sign-off, see
[CONTRIBUTING.md](CONTRIBUTING.md).
