# Operating miracache

This page covers installing, configuring, watching, upgrading and troubleshooting a miracache cluster. Read
[architecture.md](architecture.md) first for the concepts (memory node, client, rail, principal, bundle).

> **Status: alpha.** These steps are tested on software RDMA (soft-RoCE and soft-iWARP) under systemd and in Docker.
> Hardware NICs and GPU serving runs have not been validated yet; please report what you find (there is an issue
> template for hardware reports).

## 1. What you deploy

| Role | Runs | Count |
|---|---|---|
| Memory node | `mira-memnode` | three or more, one per host |
| GPU host | the engine (vLLM or SGLang) with the miracache adapter and `libmiracache.so` | any |
| Controller (optional) | `mira-controller` | one per cluster, in bundle mode |

Two supported ways to run the services: **systemd units** on the host ([`deploy/systemd/`](../deploy/systemd/README.md))
and **standalone Docker containers** ([`deploy/docker/`](../deploy/docker/README.md)). Use systemd on bare metal when you
measure anything: Docker is a convenience path, and its run script is written to add no overhead (host network, RDMA
devices passed directly, no CPU or memory limits).

## 2. Build

Requirements: clang-18, CMake 3.28+, Ninja, rdma-core (`libibverbs-dev`, `librdmacm-dev`), OpenSSL (`libssl-dev`).

```sh
cmake --preset release && cmake --build --preset release      # mira-memnode, mira-nicprobe, libmiracache.so
deploy/docker/go.sh -C controller build -o "$PWD/build/release/bin/" ./cmd/mira-controller ./cmd/mirctl
deploy/docker/build.sh                                         # or: container images (needs docker buildx)
# or pull the published images: docker pull docker.io/mirastack/miracache-memnode:alpha (and miracache-controller)
```

`deploy/docker/go.sh` runs the pinned Go toolchain (see its `GO_VERSION`) on a Linux host or inside a build
container: it downloads the release once into `build/go`, verifies its SHA-256 and reuses it, so no Go install is
needed. The
controller's `go.mod` asks only for Go 1.22.0 as the language minimum, so your own Go 1.22 or newer builds it
(`go build ./...` inside `controller/`) with no toolchain download. Dependencies are not vendored: the only module is `github.com/BurntSushi/toml`, fetched through
`GOPROXY` (point it at your mirror if needed).

### Container images

Each release publishes `docker.io/mirastack/miracache-memnode` and `docker.io/mirastack/miracache-controller`
(linux/amd64), tagged `alpha-X.Y.Z` plus a moving `alpha` that follows the newest alpha release. Pin a release tag in
production. The images are signed with Sigstore by the release workflow; verify before you run one (cosign 3.x):

```sh
cosign verify docker.io/mirastack/miracache-memnode:alpha-X.Y.Z \
  --certificate-identity-regexp '^https://github.com/mirastacklabs-ai/miracache/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
MIRA_IMAGE=docker.io/mirastack/miracache-memnode:alpha-X.Y.Z \
  MIRA_CONFIG=/etc/miracache/memnode.toml MIRA_PKI_DIR=/etc/miracache/pki deploy/docker/run-memnode.sh
```

The run scripts and their flags are described in [`deploy/docker/`](../deploy/docker/README.md).

Examples that store and fetch one block through the C++ API, the C ABI and the Python package are in
[`examples/`](../examples/README.md); the C and C++ ones are built by the same CMake run (`-DMIRACACHE_EXAMPLES=OFF`
skips them).

### Building offline or behind a proxy

CMake downloads two dependencies with `FetchContent`: toml++ (every build) and GoogleTest (only the unit tests, which
need the `tests/` folder of a full checkout). The configure step then needs `github.com`. Either point CMake at a
local copy, or use a system package:

```sh
# 1. An unpacked source tree (fetch it on a machine with access, copy it over):
cmake --preset release -DFETCHCONTENT_SOURCE_DIR_TOMLPLUSPLUS=/opt/src/tomlplusplus-3.4.0
# 2. A system install of toml++ 3.4 (package `libtomlplusplus-dev`, or cmake --install of the source):
cmake --preset release -DMIRACACHE_USE_SYSTEM_TOMLPLUSPLUS=ON
```

| Dependency | Version | Used by | Offline route |
|---|---|---|---|
| toml++ | 3.4.0 | every build | `-DFETCHCONTENT_SOURCE_DIR_TOMLPLUSPLUS=<dir>` or `-DMIRACACHE_USE_SYSTEM_TOMLPLUSPLUS=ON` |
| GoogleTest | 1.15.2 | unit tests only | `-DFETCHCONTENT_SOURCE_DIR_GOOGLETEST=<dir>` |

`-DFETCHCONTENT_FULLY_DISCONNECTED=ON` makes CMake fail instead of trying the network when a source directory is
missing. OpenSSL and rdma-core come from your distribution. Behind an HTTP proxy, set `https_proxy` for CMake and
`GOPROXY` / `https_proxy` for the Go module download.

## 3. Prepare each memory node

1. **Check the RDMA device.** `build/release/core/fabric/mira-nicprobe --json` lists devices, their protocol (RoCE or
   iWARP), capabilities and the matched NIC profile. `ibv_devices` should show the device you will name in the config.
2. **Plan the host setup.** `node_prep` prints what it would change and changes nothing without `--apply --yes`:

   ```sh
   PYTHONPATH=python python -m miracache.node_prep --hugepage-gib 16                 # dry run
   PYTHONPATH=python python -m miracache.node_prep --hugepage-gib 16 --apply --yes   # as root
   ```

   It covers:
   - **Hugepages** sized to the cache (`--hugepage-gib`, matching `n_segments × segment_bytes`). 1 GiB pages are
     reserved on the kernel command line at boot (`node_prep` tells you; it never changes boot settings itself).
   - **A hugetlbfs mount** for the store, owned by the service user (`uid=`/`gid=` mount options, numeric).
   - **memlock**: the store is pinned for the NIC. Under systemd the unit sets `LimitMEMLOCK=infinity`; under Docker
     the run script passes `--ulimit memlock=-1:-1`.
3. **Create the service user** once: `sudo useradd --system --user-group --no-create-home --home-dir /var/lib/miracache --shell /usr/sbin/nologin mira`.
4. **Network.** Put the RDMA interfaces of one trust domain on their own VLAN or VRF. For RoCEv2, configure the fabric
   for RDMA as your NIC and switch vendor recommend (lossless with PFC and ECN, or the NIC's own congestion control).
   Open the admin port (default 9465) to GPU hosts and operators only, and the metrics port (default 9464) to your
   Prometheus only.
5. **NUMA.** Keep the memory node on the socket that owns its NIC and hugepages (`numactl` line in the systemd unit, or
   `MIRA_CPUSET_CPUS` / `MIRA_CPUSET_MEMS` for Docker).

## 4. Certificates

Every memory node, GPU host, controller and operator has a certificate from your own CA, with one `spiffe://` URI SAN
as its identity (for example `spiffe://lab/node-1`, `spiffe://lab/client-1`). Server certificates need `serverAuth`;
the controller's certificate is both a client and a server certificate, so it needs `serverAuth` and `clientAuth`. Key
files are owned by the service user, mode exactly `0600`. Certificates may be short-lived: they reload without a
restart.

## 5. Configure a memory node

Start from [`deploy/examples/memnode.toml`](../deploy/examples/memnode.toml) and install it as
`/etc/miracache/memnode.toml` (`root:mira 0640`). The main sections:

| Section | Keys you set | Notes |
|---|---|---|
| `[node]` | `device`, `protocol` (`auto`, `roce`, `iwarp`), `listen` (RDMA CM address), `state_dir` | `state_dir` holds the node's persisted ID: keep it across restarts, one per node, never copy it to another host. Up to 4 rails with `[[node.rails]]` |
| `[store]` | `backing` (`hugetlbfs` or `file`), `dir`, `segment_bytes`, `n_segments`, `run_bytes`, `max_bytes`, `max_scopes` | `run_bytes` is the largest block this node stores: a power of two at least 4× your engine's largest KV block, at most 256 MiB, with `segment_bytes ≥ 2 × run_bytes`. The adapters refuse to start if a block cannot fit |
| `[lab]` | `principal`, `identities` | static mode: which client identities form the principal |
| `[admin]` | `listen`, `cert`, `key`, `ca` | tickets and admin calls, mutual TLS |
| `[telemetry]` | `listen` | `GET /metrics`; bind the scrape interface, not `0.0.0.0` |
| `[control]` | `trust_keys` | turns on bundle mode (section 8) |

Live settings (no restart): `[lease]`, `[ticket]`, `[limits]`, `[retention]` (`idle_ttl_s`, default 1800),
`[evict]` (`high_pct` 92, `low_pct` 88), `[scrub]`, `[quota]`, and `store.max_scopes` / `max_bytes`. Unknown keys are
errors, so a typo fails loudly. **You never configure a node ID**: the node draws one on first start and keeps it in
`state_dir/node-id`.

Install and start (systemd):

```sh
sudo install -m 0755 build/release/server/mira-memnode /usr/local/bin/mira-memnode
sudo install -m 0644 deploy/systemd/mira-memnode.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now mira-memnode
journalctl -u mira-memnode -f      # ready at msg="admin (mTLS) on" and msg="listening"
```

Or Docker: `MIRA_CONFIG=/etc/miracache/memnode.toml MIRA_PKI_DIR=/etc/miracache/pki deploy/docker/run-memnode.sh`
(the script documents every flag it passes and why). hugetlbfs inside Docker has not been exercised yet; use systemd
for a hugetlbfs deployment until it is.

## 6. Configure the GPU hosts

1. **Client config.** Start from [`deploy/examples/client.toml`](../deploy/examples/client.toml) and install it as
   `/etc/miracache/client.toml`. One `[[nodes]]` entry per memory node in static mode: its `rails` (RDMA CM
   addresses), `admin` address and expected `identity`. Also `[tls]`, `[fabric]` (`protocol`, `device`), `[landing]`
   (the RDMA-visible buffer) and `[crypto]` (`workers`). Optional: `[placement] replicas = 2` with `zones` on the nodes.
2. **Deployment secret.** Create it once and copy the same file to every GPU host of the deployment (never to a memory
   node), owned by the engine user, mode `0600`, on persistent storage. Either `mirctl secret gen --out <file>` or:

   ```sh
   sudo install -d -m 0700 -o "$USER" /etc/miracache/keys
   umask 077; printf 'current = 1\n1 = %s\n' "$(openssl rand -hex 32)" > /etc/miracache/keys/secret
   ```

   Back it up: a lost secret makes the cache unreadable (everything misses and recomputes).
3. **Preflight.** `mira-preflight` hard-fails engine settings that would break caching or isolation
   ([`deploy/preflight.md`](../deploy/preflight.md)):

   ```sh
   PYTHONPATH=python python -m miracache.preflight --engine vllm --engine-args "<your vLLM flags>" \
       --secret-file /etc/miracache/keys/secret
   ```

   Then compare hosts: `preflight fingerprint` on each, `preflight compare a.json b.json ...`. Hosts that differ never
   share blocks; they miss silently, which is safe but wasteful.
4. **Engine flags.** vLLM: the offloading connector with `MiraTier` as a secondary tier (see the project README).
   SGLang: HiCache with the `dynamic` storage backend ([`deploy/sglang/`](../deploy/sglang/README.md)). In both, a
   failed load must mean "recompute": vLLM `kv_load_failure_policy = recompute`.
5. **Client metrics.** The adapter can serve `GET /metrics` on a port of its own: `metrics_port` on the vLLM tier
   entry, `miracache_metrics_port` in the SGLang extra config (port + rank).

## 7. Static mode (no controller)

Each `client.toml` lists the nodes, and each `memnode.toml` lists the client identities of its principal
(`[lab]`, with `static_membership = true` on the client). This is the simplest setup and enough for a fixed cluster.
Limits: there is no automatic removal of a dead node (each client's circuit breaker routes around it, and its share
misses), and a client configuration change needs an engine restart. A memory node reloads its live settings,
certificates and principal identities on `SIGHUP` (`systemctl reload mira-memnode`, or `docker kill -s HUP`).

## 8. Bundle mode (controller)

For larger or changing clusters, membership and live configuration come from a signed **bundle**.

1. **Signing keys.** `mirctl keys gen --out publish.seed --roles publish` and
   `mirctl keys gen --out security.seed --roles security`. Keep them offline-backed-up; files `mira:mira 0600`.
   The trust file (`trust.toml`) lists the public keys and their roles; every memory node and client gets a copy
   (`[control] trust_keys`).
2. **Intent file.** A `cluster.toml` lists only what you decide: `[[nodes]]` (admin address, weight, zone, state),
   `[[principals]]` (name, identities, `quota_bytes`, `max_scopes`), `[[rbac]]` (identity, roles) and `config.*` tables
   (for example `[config.cluster.placement] replicas = 2`). Node IDs, hostnames and rails are learned from the nodes.
3. **First publish** with `mirctl bundle publish --source cluster.toml --key publish.seed --sec-key security.seed
   --cert ... --tls-key ... --ca ...`. It talks to the memory nodes' admin APIs directly; no controller is needed.
4. **Optional controller.** Install `mira-controller` (unit in [`deploy/systemd/`](../deploy/systemd/README.md),
   default API port 9470) and import the cluster's current bundle once with `--recover-from <node admin address>`.
   From then on, use `mirctl node add|drain|remove|confirm-remove` against the controller. One writer per cluster:
   either the controller or `mirctl`.
5. **Clients** in bundle mode use `[control]` (`endpoints`, `trust_keys`, `state_dir`) instead of `[[nodes]]`.

Back up the controller's store directory and the two signing seeds. If the controller is down, the data path is not
affected; only joins, removals and configuration changes wait.

## 9. Observability

- **Metrics.** Each memory node serves Prometheus text on its `[telemetry] listen` address. Every series carries
  `node_id`, and `miracache_node_info{node_id,hostname,addr}` maps the ID to the host. Client series are keyed by
  `node="<first rail host:port>"`, with `miracache_client_node_info` mapping that to the learned ID and hostname.
  Memory nodes do not see fetch latency (clients read directly over RDMA): fetch latency comes from the client
  histogram `miracache_client_fetch_seconds`.
- **Dashboards and alerts** in [`deploy/observability/`](../deploy/observability/README.md): a cluster overview, a
  client dashboard, a fabric dashboard, and 13 alert rules (node down or not scraped, hit-rate collapse, fetch p99,
  replica buffer full, client watchdog, node ID conflict and mismatch, zombies, quarantined bytes, admin rejects, store
  checksum mismatch, client session down). The fetch p99 alert threshold is a starting value; tune it to your block
  size and network.
- **Logs.** logfmt, one line per event on stderr (the journal, or `docker logs`). Every line about a memory node carries
  its `node_id`, `host` and `addr`. Keys, tickets and payload are never logged.

Worth watching: hit rate, `miracache_client_aead_fail_total` (should stay at zero), `miracache_put_digest_mismatch_total`,
`miracache_ticket_reject_total`, `miracache_bundle_reject_total`, `miracache_store_bytes`, `miracache_rail_state`.

## 10. Day-2 operations

| Task | How | Effect on traffic |
|---|---|---|
| Change a live setting | bundle mode: publish a new bundle; static mode: edit `memnode.toml`, then `SIGHUP` | none; a bad value is rejected as a whole and the old settings stay |
| Rotate certificates | replace the files (the node: `SIGHUP`; the client watches its files) | none: new connections use the new credentials |
| Restart a memory node | `systemctl restart mira-memnode` | `SIGTERM` drains for `node.drain_ms` (5 s); clients see misses, not errors; the cache is kept on restart |
| Rolling upgrade | memory nodes one at a time, then clients | misses during each restart, no errors |
| Change a static setting (store size, rails, device) | rolling restart, one node at a time | as above |
| Drain a node for removal | `mirctl node drain` (bundle mode) | the node stops taking new chains, then leaves |
| Replace a node's hardware | on the new host, start with an empty `state_dir`; with `mirctl`, accept the new ID (`--accept-id-change`) | about 1/N of the cache is cold |
| Re-use a host as a new node | delete `state_dir/node-id` (keep the directory), restart | the node draws a new ID and starts empty |
| Rotate the deployment secret | `mirctl secret add-kver --file <secret>`, then copy the file to every GPU host (clients pick up the change without a restart) | a cold cache for that deployment: old blocks age out |
| Revoke a leaked secret | rotate, remove the old key version from every host, then drop the principal's old scopes (`POST /v1/drop_principal`, role `security-admin`) | as above; old ciphertext is unreadable |

Exit codes of `mira-memnode`: 0 stopped and marked clean; 3 stopped, but the clean mark was refused (the next start is
cold: alert on `msg="stopped (not clean, exit 3)"`); 1 start-up failed; 2 usage error. Keep the systemd
`TimeoutStopSec` (and Docker `--stop-timeout`) above the drain time.

## 11. Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| Memory node fails to start: memlock or registration error | memlock limit too low, or `CAP_IPC_LOCK` missing | unit has `LimitMEMLOCK=infinity`; Docker has `--ulimit memlock=-1:-1` |
| Fails to start: store or hugepage error | no hugepages reserved, mount not owned by `mira`, wrong page size | `grep Huge /proc/meminfo`; mount options `uid=`/`gid=`; `node_prep` dry run |
| Fails to start: key file refused | key mode not exactly `0600` or wrong owner | `ls -l` the key; `install -m 0600 -o mira -g mira` |
| Fails to start: `state_dir` locked | a second memory node uses the same `state_dir` | one `state_dir` per node |
| No RDMA device found | wrong `device`, modules not loaded, or Docker devices not passed | `mira-nicprobe --json`; `ibv_devices`; `/dev/infiniband/*` in the container |
| Clients connect but every fetch misses | hosts compute a different `ns`, the deployment secret differs between GPU hosts, or (SGLang) the prefix-keys flags are missing | compare `preflight fingerprint` across hosts; check the `ns fingerprint` start-up log line; run `check_sglang_config` |
| Connections refused, ticket errors (403) | the client identity is not in the node's principal table | `[lab] identities` or the bundle's `[[principals]]`; the client cert's `spiffe://` SAN |
| RoCE/iWARP mismatch | client and node use different protocols on a rail | set `protocol` explicitly on both sides |
| Adapter refuses to start: block too large | the engine block does not fit `run_bytes` | raise `store.run_bytes` (and `segment_bytes`) on every node |
| vLLM requests fail instead of recomputing | `kv_load_failure_policy` is not `recompute` | preflight fails this; set it at the top level and in the `MiraTier` entry |
| SGLang does not start | the adapter refused a setting (it names it) | fix the setting, or drop `--hicache-storage-backend` to run without L3 |
| Hit rate drops suddenly | a node is down, a rail is down, or the cache was rotated | the dashboards: node up, rails, `miracache_client_node_info`; the `MiracacheHitRateCollapse` alert |
| AEAD failure counter rises | corruption or tampering on a memory node or the network | treat as a security event; find the node from the counter's `node` label; the block was already invalidated |
| Node ID conflict alert | two nodes report the same ID (a copied `state_dir`) | never copy `state_dir`; delete `node-id` on the copy and restart it |
