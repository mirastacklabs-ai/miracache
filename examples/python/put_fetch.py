"""Store one block in the memory nodes, look it up, fetch it back and compare, with the `miracache` package.

    PYTHONPATH=python MIRA_CLIENT_CONFIG=/path/to/client.toml python examples/python/put_fetch.py

The package loads libmiracache.so (build it first, see docs/operations.md). The client config names the memory
nodes and the deployment secret file (see deploy/examples/client.toml).
Submits are non-blocking: put/fetch return a ticket and the completion arrives later through poll().
"""
import os
import sys
import time

from miracache import _core as mc

CONFIG = os.environ.get("MIRA_CLIENT_CONFIG", "client.toml")
BLOCK = 65536


def wait_done(cl, ticket, timeout_s=30):
    """Waits for the completion of `ticket` and returns it."""
    end = time.monotonic() + timeout_s
    while time.monotonic() < end:
        cl.wait_event(200)  # returns when completions are pending (or after 200 ms)
        for c in cl.poll():
            if c.ticket == ticket:
                return c
    sys.exit("FAIL: timeout waiting for ticket %d" % ticket)


def main():
    try:
        cl = mc.Client.open(CONFIG)  # connects to the memory nodes named in the config
    except mc.MiraError as exc:
        sys.exit("FAIL: cannot open the client: %s" % exc)
    try:
        # Buffers are registered once and stay yours; keep them alive until the completion arrives.
        src = bytearray((i * 31 + 5) & 0xFF for i in range(BLOCK))
        dst = bytearray(BLOCK)
        r_src = cl.attach_region(src, BLOCK)
        r_dst = cl.attach_region(dst, BLOCK)

        # The scope says who may read the block: the engine, its 32-byte namespace digest, and the raw key of
        # the chain root of each KV-cache group (here only group 0).
        scope = cl.derive({"engine": "vllm", "ns": bytes(range(32)), "roots": {0: b"example-root"}}, 0)
        keys = [b"example-block-0"]  # the engine's block hash
        offsets = [0]

        c = wait_done(cl, cl.put(scope, keys, offsets=offsets, region=r_src))
        if not c.success:
            sys.exit("FAIL: store %s" % (c.statuses,))
        print("store:  %s" % (c.statuses,))

        # lookup_many answers HIT / MISS, or PENDING while the answer is still on its way.
        deadline = time.monotonic() + 30
        ans = cl.lookup_many(scope, keys)
        while "PENDING" in ans and time.monotonic() < deadline:
            cl.wait_event(100)
            ans = cl.lookup_many(scope, keys)
        print("lookup: %s" % (ans,))
        if ans != ["HIT"]:
            sys.exit("FAIL: lookup gave %s" % (ans,))

        c = wait_done(cl, cl.fetch(scope, keys, offsets=offsets, region=r_dst))
        if not c.success:
            sys.exit("FAIL: fetch %s" % (c.statuses,))
        if bytes(dst) != bytes(src):
            sys.exit("FAIL: fetched bytes differ")
        print("fetch:  %d bytes identical" % len(dst))
    except mc.MiraError as exc:
        sys.exit("FAIL: client error: %s" % exc)
    finally:
        cl.close()
    print("PASS")


main()
