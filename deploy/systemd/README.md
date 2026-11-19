# Run miracache under systemd

Benchmarks use the systemd path on bare metal; Docker is for convenience (see `deploy/docker/`).

| Unit | What |
|---|---|
| `mira-memnode.service` | memory node, one per host |
| `mira-controller.service` | controller (bundle mode), one per cluster |

## The `mira` user

Both units run as the system user and group `mira` (the same name and privileges as the Docker image,
`deploy/docker/`): not root. The memory node keeps only `CAP_IPC_LOCK` (ambient) and `LimitMEMLOCK=infinity`
(the Docker equivalent of `--cap-drop ALL --cap-add IPC_LOCK` and unlimited memlock); the controller keeps no capability.
Create it once per host:

```
sudo useradd --system --user-group --no-create-home --home-dir /var/lib/miracache --shell /usr/sbin/nologin mira
```

Files the service reads must be readable by `mira`: every TLS key (memory node and controller) and both signing seeds
are `mira:mira 0600` (`install -m 0600 -o mira -g mira`; the node insists on exactly 0600, the controller and `mirctl`
refuse any group/other bit), `memnode.toml` is `root:mira 0640`. Certificates
and `ca.pem` may be 0644. The `state_dir` (`/var/lib/miracache`) is created by systemd (`StateDirectory=`, 0700, owned by `mira`).
The hugetlbfs store mount must be owned by `mira` (`uid=`/`gid=` options, numeric).

## Install (memory node)

```
sudo install -m 0755 build/release/server/mira-memnode /usr/local/bin/mira-memnode
sudo install -d -m 0755 /etc/miracache
sudo install -d -m 0750 -o root -g mira /etc/miracache/pki
sudo install -m 0640 -o root -g mira your memnode.toml /etc/miracache/memnode.toml   # edit IPs, device, state_dir
sudo install -m 0644 /path/to/ca.pem /path/to/node-1.pem /etc/miracache/pki/                    # certificates: 0644 is fine
sudo install -m 0600 -o mira -g mira /path/to/node-1.key /etc/miracache/pki/node-1.key           # the key: exactly 0600, owned by mira
sudo install -m 0644 deploy/systemd/mira-memnode.service /etc/systemd/system/
# state_dir (/var/lib/miracache, 0700, mira): created by the unit's StateDirectory=
sudo systemctl daemon-reload && sudo systemctl enable --now mira-memnode
journalctl -u mira-memnode -f     # wait for msg="admin (mTLS) on" and msg="listening"
```

Certs: use your own certificates, then the `install -m 0600 -o mira -g mira` above for the node's key.

## Install (controller)

```
deploy/docker/go.sh -C controller build -o "$PWD/build/release/bin/" ./cmd/mirctl ./cmd/mira-controller   # the pinned Go, Linux
sudo install -m 0755 build/release/bin/mira-controller /usr/local/bin/
sudo install -m 0644 deploy/systemd/mira-controller.service /etc/systemd/system/
# /etc/miracache: trust.toml (root:mira 0640); pki/controller.pem and pki/ca.pem (0644)
# secrets, each mira:mira 0600: publish.seed, security.seed, pki/controller.key
sudo install -m 0600 -o mira -g mira /path/to/publish.seed /etc/miracache/publish.seed          # same for security.seed and controller.key
# The controller takes over a cluster that already has a bundle (first publish with mirctl):
# import it once with `mira-controller --recover-from <node admin addr> --store-dir /var/lib/miracache-controller/store ...`
# run as mira (the store dir must be mira's), e.g. under `systemd-run --wait -p User=mira -p StateDirectory=miracache-controller`.
sudo systemctl daemon-reload && sudo systemctl enable --now mira-controller
```

Adjust the flags in `ExecStart` to your setup (`mira-controller --help`). The controller's `--cert` is also its API server
certificate (unless `--api-cert`): it needs `serverAuth` as well as `clientAuth` (a `lab-certs.sh --nodes` cert has both),
and its URI SAN needs an `[[rbac]]` binding (`operator`) in the bundle.

## Behaviour to know

- `SuccessExitStatus=3`: exit 3 means "stopped, superblock not marked clean" (the next start is cold).
  It is a finished stop, not a crash, so `Restart=on-failure` does not loop on it. Alert on the log line
  `msg="stopped (not clean, exit 3)"`.
- `TimeoutStopSec=30` must stay above `node.drain_ms / 1000` (default 5 s) plus a margin: `SIGTERM`
  starts the drain, and systemd's `SIGKILL` would cut it.
- `LimitMEMLOCK=infinity` + `AmbientCapabilities=CAP_IPC_LOCK`: the store is registered with the NIC by a non-root process.
- Hardening is light on purpose: no `PrivateDevices`, `ProtectKernel*`, `RestrictAddressFamilies`; they would hide `/dev/infiniband`, sysfs or netlink from RDMA.
- `systemctl reload mira-memnode` sends `SIGHUP` (certs and identities reload).
- For fault-injection tests (C7) set `Restart=no` first, so a killed node stays down until the test restarts it.

## NUMA pinning

Pin to the socket that owns the NIC and the hugepages: replace `ExecStart` with the commented
`numactl --cpunodebind=<n> --membind=<n> ...` line in the unit. The Docker equivalent is
`MIRA_CPUSET_CPUS` / `MIRA_CPUSET_MEMS` in `deploy/docker/run-memnode.sh`.

## Tested

The setup above (three memory nodes, a first publish with `mirctl`, the controller hand-over and the controller unit) is installed and run under systemd in CI.
