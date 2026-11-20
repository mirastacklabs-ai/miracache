# Two-host run: memory node on host A, engine on host B

Host A runs `mira-memnode`. Host B runs the engine with libmiracache. RoCE or iWARP both work
(`protocol = "auto"` picks it from the NIC). No ticket file is shared: host B asks host A for
tickets over HTTPS with mutual TLS.

## 1. Make certs (once, on your own machine; needs bash and openssl)

```
tools/dev/lab-certs.sh ./pki --nodes 1 --clients 1
```

Never commit `./pki`. `ca.key` stays on your machine.

## 2. Copy files (keys must be mode 0600)

| File | Host A | Host B |
|---|---|---|
| `ca.pem` | yes | yes |
| `node-1.pem`, `node-1.key` | yes | no |
| `client-1.pem`, `client-1.key` | no | yes |
| `memnode.toml` (edit IPs, device) | yes | no |
| `client.toml` (edit IPs) and the scope secret file | no | yes |

Put the certs under `/etc/miracache/pki/`. Run `chmod 600 *.key`. The client refuses to start if
its key is not exactly 0600.

## 3. Open the ports (on host A, from host B only)

| Port | What |
|---|---|
| 7471 (`listen`) | RDMA CM. RoCEv2 also uses UDP 4791; iWARP uses TCP. |
| 9465 | Admin API, tickets over mTLS |
| 9464 | `/metrics` (Prometheus text) |

## 4. Start order

1. Host A: `systemctl start mira-memnode` (unit: `deploy/systemd/`; or the Docker container: `deploy/docker/`), i.e. `mira-memnode --config /etc/miracache/memnode.toml`. Wait for the log lines `msg="admin (mTLS) on"`
   and `msg="listening"` (logfmt, see below).
2. Host B: start the engine (or `Client::open`) with `client.toml`. If host A cannot be reached,
   open returns an error. Once connected, the session survives a dead admin port; reconnects use
   cached tickets and the cache refills when the admin API is back.

To stop the memnode, send `SIGTERM`. It sends GOAWAY to every client and keeps serving reads while
clients move away, then exits when no session or put is left, at most `node.drain_ms` (default 5000)
later. New root puts are refused during the drain. A second `SIGTERM` or `SIGINT` exits at once;
`drain_ms = 0` turns the drain off.

Exit status: `0` = stopped and the superblock marked clean (the next start is warm); `3` = stopped,
but the clean mark was refused (stderr: `msg="not marked clean"` and `msg="stopped (not clean, exit 3)"`;
the next start is cold, the cache is lost); `1` = startup failed; `2` = usage error. Exit 3 is a
finished stop, not a crash: the unit in `deploy/systemd/mira-memnode.service` sets `SuccessExitStatus=3` (so `Restart=on-failure` does
not treat it as a failure) and alert on the log line. A `SIGTERM`/`SIGINT` sent while the node is
still starting (fabric open, MR registration) is held until it is up and then handled as a normal
stop, so Ctrl-C can look ignored for that long. `SIGHUP` during the exit path is ignored.

After changing certs or `lab.identities` on host A, send the memnode `SIGHUP`. Certs are reloaded
(the old ones stay if the new ones fail to load). New identities are bound; an identity removed
from `lab.identities` is revoked at once: its unredeemed tickets are dropped and its open
connections are closed. There is no CRL: revoke a client by removing its identity and sending
`SIGHUP`. Always set `identity` in each `[[nodes]]` entry of `client.toml` (the node's SPIFFE id):
without it any server certificate under the lab CA is accepted as the admin server, and a future
client version will require it.

The admin port serves at most `admin.max_conns` connections at once (default 8) and 2 per source
address; a connection over a limit is closed without TLS and counted in
`miracache_admin_conn_rejected_total{reason}`. The TLS handshake must finish within 300 ms.

## More than one memory node

List every node in `client.toml` (see `client-3nodes.toml.example`). The client puts each scope on
one node by weighted rendezvous hashing of its `scope_id`, so a chain never splits. `weight`
(positive integer, default 1) sets a node's share. Every node needs its own `memnode.toml`, cert
and admin address; `lab.ticket_file` works for one node only. A node that is down at start does
not stop the client: its scopes miss (lookups) or are refused (stores) until it is reachable, and
the other nodes keep serving. Membership is the static list; adding or removing a node needs a new
`client.toml` and a client restart, and cached data on the old owner is not moved (it ages out).
Client metrics carry a `node="<host:port>"` label (the node's first rail) when there is more than one node.

**Node IDs are automatic.** There is no `id` in `memnode.toml` or `client.toml` (a config that has one
fails: "node id was removed; node IDs are assigned automatically"), and no setting takes an ID: `[node] state_dir`
(default `/var/lib/miracache`, created 0700) is a path. A memory node draws a random non-zero 32-bit ID once and
writes it to `<state_dir>/node-id` (mode 0600, written atomically). Every later start reads it back, so a
restart, a reboot that clears hugetlbfs and an `anon` (volatile) store all keep the ID: only the scopes of the
node itself are cold, never those of healthy nodes. The first start also writes the marker
`<state_dir>/initialised`. A node upgraded from a version without the file (no marker yet) adopts the ID in its
persistent store's superblock and writes both files. If the store carries another ID than the file, the store is
reformatted as blank (it is a cache) and the node starts; it never refuses to start over this.

**One `state_dir` per memory node.** The directory must belong to the user the memory node runs as and must not be
group- or world-writable (the node refuses to start otherwise). It is locked for the life of the process
(`<state_dir>/node-id.lock`): a second memory node on the same directory fails at start with
`msg="node state: state_dir is in use by another memory node ..." path=<state_dir>`. Two memory nodes on one host
need two `state_dir`s. A memory node that runs as non-root needs a `state_dir` it owns (the default
`/var/lib/miracache` must be creatable): `sudo install -d -m 0700 -o <user> /var/lib/miracache`, or set
`state_dir` to a directory of that user.

**Replacing a node** (a new identity for this machine, e.g. after cloning it or to retire its old ID):
1. Stop the memory node.
2. `rm <state_dir>/node-id`. Keep the directory and its `initialised` marker: they are what says "replaced".
3. Start it. It logs `msg="node replaced: new id"`, draws a new ID and reformats its store, even a persistent
   one that still holds data (that cache belongs to the old ID).
4. The client picks up the new ID at the reconnect. About 1/N of the scopes move to it, and by rendezvous about
   a further (N-1)/(N(N+1)) change owner among the healthy nodes (16.7 % at N=3), so replace deliberately.

A `node-id` that exists but holds garbage (not a decimal ID) counts as deleted: the node is replaced the same way, logged with `reason=invalid_file`. The `state_dir` must be a real directory, not a symlink, and its parents must not be writable by others.

**The bundle floor is same-user only.** The bundle floor (`<state_dir>/bundle-floor`, its `.lock` and the `.tmp` it is written through) is created mode 0600 in a 0700 directory, so every process that shares it (memory nodes and client processes on one host) must run as the same user. Another user cannot read or update it. Files are opened without following symlinks, and a stale `bundle-floor.tmp` is removed before each write. Do not point two users' processes at one `state_dir`; give each its own.

**Bundle mode needs concrete rail addresses.** With `[control] trust_keys` set, `mira-memnode` publishes each `[node] listen` rail (address, interface subnet in CIDR form, transport) through `GET /v1/identity`, and the controller builds the membership from it. Listen on the interface address of each rail (for example `10.0.0.10:7471`), never a wildcard or a hostname: if a rail's subnet cannot be determined, or the active transport is not RoCE or iWARP (InfiniBand is not a v1 transport), the node refuses to start with a logfmt error naming the rail (`msg="bundle mode cannot advertise this node's rails" rail=... err=...`). Lab mode (no `trust_keys`) is unchanged.

A plain restart (no `rm`) keeps the ID even when the store comes back empty. Never copy the state directory to a
second machine; a clone needs its own `state_dir` (or `rm node-id` on the clone as above).
The client learns each ID from the HELLO reply. A node the client has not reached yet owns no scopes, and the
client picks up its ID when it connects. If two nodes report the same ID, the one that answered second is
excluded and the client logs
`msg="duplicate node id N: A and B report the same ID; B is excluded from placement"` (both
addresses) and counts `miracache_client_node_id_conflicts_total{node}`; replace the cloned node (above: `rm node-id`)
to give it a fresh ID. A node whose session is down does not hold its ID against a node that answers (a
store moved to a new address is accepted at once). Two `[[nodes]]` with the same `rails` address are a config
error. The node's `/v1/tickets` answer carries `node_id` and `hostname`. The client series
`miracache_client_node_info{node,node_id,hostname,addr,zone} 1` shows what it learned. Client log
lines are logfmt like the memory node's, with `client_host` and the target's `node_id` and `addr`.

**Upgrade order.** Upgrade the memory nodes and the clients together (stop the engines, upgrade host A, then
host B, start A, then B). Mixed versions are not supported: a client of this version needs the ID in HELLO_ACK
that only this version's memory node sends.

## 5. Metrics for agentbench

- Memory node: `http://hostA:9464/metrics`.
- Client side: the vLLM / SGLang adapter serves `/metrics` on `metrics_port + rank`
  (adapter keys `metrics_port`, default 0 = off, and `metrics_host`, default 127.0.0.1; to scrape
  from another machine set `metrics_host` to that machine's scrape-interface address). It includes
  `miracache_client_ticket_fetch_total{result}` and `miracache_client_ticket_cache{class}`.
- Every `/metrics` endpoint is unauthenticated plain HTTP. Bind it to the scrape interface only
  (`telemetry.listen = "10.0.0.10:9464"`, never `0.0.0.0`) and firewall the port to the scraper.
- Give agentbench both: `hostA:9464` and `hostB:<metrics_port>`.
- Every memory-node series has a first label `node_id="N"`; `miracache_node_info{node_id,hostname,addr} 1`
  maps it to the hostname and RDMA address. Agentbench series keys therefore start with
  `{node_id="N",...}` for memory-node metrics.

## NIC profiles

Both the memory node and the client probe the local NIC at start and pick the operating point (read
depth, QP ACK timeout and retries, inline size, MTU) from the profile registry `profiles/nic-profiles.toml`
(compiled in; spec 4.3). Check what a host matches with `mira-nicprobe` (it prints the profile, whether its
values are `verified`, and the firmware check), or look for the `comp=nic_profile msg="profile matched"` line
at start. `miracache_nic_profile_info{profile,verified}` and `miracache_nic_unprofiled` are on `/metrics`.

- Precedence: explicit config key > profile > built-in default. Memory node `[nic]` keys: `profiles_file`,
  `mtu`, `inline_bytes`, `ack_timeout_exp`, `retry_count`, `rnr_retry_count`. Client `[fabric]` keys: the same
  names plus `read_depth` (`fabric.mtu` is the existing MTU key).
- `profiles_file` replaces the built-in registry (the file must load, or the process refuses to start).
- An unprofiled NIC runs on the conservative `generic-roce` / `generic-iwarp` point and logs a warning. Soft-RDMA
  (`rxe`, `siw`) has its own verified entries; real-NIC entries are `verified = false` until a lab capture.

## Memory-node log lines

logfmt on stderr (journald: `journalctl -u mira-memnode`), one event per line:

```
ts=2026-11-11T09:30:00.101Z level=info comp=memnode node_id=1 host=hostA addr=10.0.0.10:7471 msg="admin (mTLS) on" listen=10.0.0.10:9465 port=9465
ts=2026-11-11T09:30:00.123Z level=info comp=memnode node_id=1 host=hostA addr=10.0.0.10:7471 msg="listening"
```

Lines logged before the config is read carry `host` only.

## If it fails

- `admin: TLS handshake failed`: wrong `ca.pem`, or `identity` does not match the node cert.
- `admin: 403`: the client cert's SPIFFE id is not in `lab.identities` on host A.
- `tls.key must have mode 0600`: run `chmod 600` on it.
