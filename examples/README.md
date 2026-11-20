# Examples

Three small programs that do the same thing: connect to the memory nodes, store one 64 KiB block, look it up, fetch
it back and compare the bytes. Each prints `PASS` and exits 0, or says what failed and exits 1.

| Folder | API | Program |
|---|---|---|
| [`cpp/`](cpp/put_fetch.cpp) | the C++ client (`miracache_client`) | `example_cpp_put_fetch` |
| [`c/`](c/put_fetch.c) | the C ABI (`<miracache/miracache.h>`, `libmiracache.so`) | `example_c_put_fetch` |
| [`python/`](python/put_fetch.py) | the `miracache` Python package | `python/put_fetch.py` |

The engine adapters (vLLM, SGLang) use the same calls: derive a scope from the engine's namespace digest and chain
root, then store, look up and fetch blocks by their raw key. Submits never block: you get a ticket, and the completion
(one status per key) arrives through `poll`. Data-path failures are statuses, not errors.

## Build

The C and C++ examples are built with the rest of miracache (CMake option `MIRACACHE_EXAMPLES`, ON when miracache is
the top-level project, OFF when it is a subproject):

```sh
cmake --preset release && cmake --build --preset release --target example_cpp_put_fetch example_c_put_fetch
# programs: build/release/examples/cpp/example_cpp_put_fetch, build/release/examples/c/example_c_put_fetch
```

The Python example needs only `build/release/client/libmiracache.so` (target `miracache_shared`) and
`PYTHONPATH=python`.

## Run against the compose quick start

`deploy/compose/run.sh` builds and starts three memory nodes over soft-RoCE, runs its own check and tears everything
down. To run an example against the same nodes, start them by hand (see [`deploy/compose/README.md`](../deploy/compose/README.md)):

```sh
deploy/compose/setup-rxe.sh                      # once per boot
cd deploy/compose
docker compose build node1 client
docker compose up -d node1 node2 node3
docker compose run --rm -e MIRA_CLIENT_CONFIG=/lab/client.toml \
  -v "$PWD/../../examples/python/put_fetch.py:/put_fetch.py:ro" --entrypoint python3 client /put_fetch.py
docker compose down -v
```

The C and C++ programs are not in the quick-start client image; build them on the same Linux host and run them with
`/lab/client.toml` copied out of the `lab` volume (`docker compose cp` from a `prepare` container, or read the volume
from `/var/lib/docker/volumes/`), or use your own cluster as below.

## Run against a real cluster

Use the client configuration of your GPU hosts ([`deploy/examples/client.toml`](../deploy/examples/client.toml): the
memory node list or the controller, the TLS files and the deployment secret file) and run on a host with the same RDMA
fabric as the memory nodes:

```sh
build/release/examples/cpp/example_cpp_put_fetch /etc/miracache/client.toml
build/release/examples/c/example_c_put_fetch     /etc/miracache/client.toml
MIRA_CLIENT_CONFIG=/etc/miracache/client.toml PYTHONPATH=python python examples/python/put_fetch.py
```

The secret file must be readable by the user who runs the example (mode 0600). A stored block is encrypted under keys
derived from the secret and the scope, so another deployment secret, namespace or root key will not read it back.
