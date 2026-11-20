"""Quick-start check: store (put) -> lookup -> fetch -> byte compare, plus a miss, against the 3 memory nodes.

Uses only the public `miracache` Python binding over libmiracache.so. Prints a final line `PASS` or
`FAIL: <reason>` and exits 0 or 1. (The client API has no invalidate call: entries leave by eviction or when
the nodes stop, so the check ends with a miss on a key that was never stored.)
"""
import os
import sys
import time

from miracache import _core as mc

CONFIG = os.environ.get("MIRA_CLIENT_CONFIG", "/lab/client.toml")
BLOCK = 65536
N = 4
TIMEOUT_S = 30


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def wait_done(cl, ticket):
    end = time.monotonic() + TIMEOUT_S
    while time.monotonic() < end:
        cl.wait_event(200)
        for c in cl.poll():
            if c.ticket == ticket:
                return c
    fail("timeout waiting for ticket %d" % ticket)


def open_client():
    last = None
    end = time.monotonic() + 60
    while time.monotonic() < end:  # the memory nodes may still be starting
        try:
            return mc.Client.open(CONFIG)
        except mc.MiraError as exc:
            last = exc
            time.sleep(1)
    fail("cannot open the client: %s" % last)


def main():
    print("client: connecting to the memory nodes (config %s)" % CONFIG)
    cl = open_client()
    try:
        src = bytearray(N * BLOCK)
        for i in range(len(src)):
            src[i] = (i * 31 + (i >> 8) * 7 + 5) & 0xFF
        dst = bytearray(N * BLOCK)
        r_src = cl.attach_region(src, BLOCK)
        r_dst = cl.attach_region(dst, BLOCK)
        scope = cl.derive({"engine": "vllm", "ns": bytes(range(32)), "roots": {0: b"quickstart-root"}}, 0)
        keys = [b"block-%d" % i for i in range(N)]
        offs = [i * BLOCK for i in range(N)]

        c = wait_done(cl, cl.put(scope, keys, offsets=offs, region=r_src))
        print("store:  %d blocks of %d B, statuses=%s" % (N, BLOCK, c.statuses))
        if not c.success:
            fail("store failed (statuses %s)" % c.statuses)

        end = time.monotonic() + TIMEOUT_S
        ans = []
        while time.monotonic() < end:
            ans = cl.lookup_many(scope, keys)
            if "PENDING" not in ans:
                break
            cl.wait_event(100)
        print("lookup: %s" % ans)
        if ans != ["HIT"] * N:
            fail("lookup after store gave %s" % ans)

        c = wait_done(cl, cl.fetch(scope, keys, offsets=offs, region=r_dst))
        print("fetch:  statuses=%s" % c.statuses)
        if not c.success:
            fail("fetch failed (statuses %s)" % c.statuses)
        if bytes(dst) != bytes(src):
            fail("fetched bytes differ from the stored bytes")
        print("bytes:  %d bytes read back identical" % len(dst))

        dst[:] = bytes(len(dst))
        c = wait_done(cl, cl.fetch(scope, [b"never-stored"], offsets=[0], region=r_dst))
        print("miss:   statuses=%s" % c.statuses)
        if c.success or c.statuses != [mc.MISS]:
            fail("a key that was never stored did not miss (statuses %s)" % c.statuses)
    except mc.MiraError as exc:
        fail("client error: %s" % exc)
    finally:
        cl.close()
    print("PASS")


main()
