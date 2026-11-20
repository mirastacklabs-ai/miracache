# Quick start: 3 memory nodes and a test client in Docker, over soft-RoCE

One command brings up three `mira-memnode` containers and a one-shot client that stores 4 blocks,
looks them up, fetches them back, compares the bytes, checks a miss, and prints `PASS` (exit 0) or
`FAIL: <reason>` (exit 1). No RDMA hardware needed: the host uses soft-RoCE (`rdma_rxe`).

Production runs under systemd on bare metal (`deploy/systemd/`). Docker here is a convenience path:
it uses the same binaries and the same data-path settings (host network, RDMA devices passed
through, memlock unlimited, no cpu/memory limits), but this setup is for trying miracache, not for
benchmarks.

## Prerequisites

- A Linux host or VM (kernel with `rdma_rxe`) with a NIC that has an IPv4 address. On a Mac, use a
  Linux VM that runs the Docker engine (for example colima).
- The open-source Docker engine, the `docker compose` plugin and BuildKit (Ubuntu:
  `apt-get install docker.io docker-compose-v2 docker-buildx`). Never Docker Desktop.
- About 6 GiB of free disk and 10 to 30 minutes for the first image build (compiles miracache).

## Run

```
deploy/compose/setup-rxe.sh          # once per boot: loads rdma_rxe, adds rxe0 on the default NIC
deploy/compose/run.sh                # build, start, check, tear down
```

`run.sh` is the same as:

```
cd deploy/compose
docker compose build node1          # one image at a time: each compile is heavy
docker compose build client
docker compose up -d node1 node2 node3
docker compose run --rm client      # prints PASS or FAIL: <reason>; its exit code is the result
docker compose down -v
```

Expected output (abridged):

```
client: connecting to the memory nodes (config /lab/client.toml)
store:  4 blocks of 65536 B, statuses=[2, 2, 2, 2]
lookup: ['HIT', 'HIT', 'HIT', 'HIT']
fetch:  statuses=[0, 0, 0, 0]
bytes:  262144 bytes read back identical
miss:   statuses=[1]
PASS
```

Options (environment): `MIRA_RDMA_DEVICE` (default: the first RDMA device), `MIRA_IP` (default: the
IPv4 address of that device's netdev), `RAIL_NETDEV` for `setup-rxe.sh`.

## What it does

- `prepare` (one-shot): finds the device and its IP and writes a throw-away lab CA, node and client
  certificates (mutual TLS for the admin API), the scope secret and the four configs into the
  volume `lab`. Everything is regenerated on every start and removed by `down -v`.
- `node1..3`: `mira-memnode` built from `deploy/docker/Dockerfile.memnode`, one state volume each (its
  persisted node identity), ports 7471-7473 (RDMA), 9465-9467 (admin, loopback), 9474-9476 (metrics,
  loopback). Memory is anonymous (`backing = "anon"`, 8 MiB per node) so no hugepages are needed;
  use hugetlbfs or a file for real work (`deploy/examples/memnode.toml`).
- `client`: `scripts/quickstart_check.py`, using the Python binding (`python/miracache`) over
  `libmiracache.so`, in static-membership mode (the node list is in the config, no controller).
  The client API has no invalidate call, so the check ends with a miss on a key never stored.

## Cleanup

`run.sh` runs `docker compose down -v` itself. After a manual `docker compose up`, run
`docker compose down -v` in this directory. The images stay (`miracache-quickstart-memnode`,
`miracache-quickstart-client`); remove them with `docker image rm`. `rdma link delete rxe0` removes the soft-RoCE device.

## Troubleshooting

- `FAIL: no RDMA device found`: run `setup-rxe.sh` (the containers read `/sys/class/infiniband`).
- `cannot open the client`: look at `docker compose logs node1`; the usual cause is an address the
  device cannot reach (set `MIRA_IP`) or a port already in use.
- Compose cannot see `/dev/infiniband`: the Docker daemon must run on the same Linux host or VM as the rxe device.
