"""Python binding vs libmiracache.so (loopback). Skips cleanly when the library is not built;
CI's dev preset points MIRACACHE_LIB at the built .so (ctest: python_roundtrip)."""
import gc
import threading
import time
import unittest

from miracache import _core
from miracache._core import Client, MiraError

LIB = _core.library_path()
BLK = 70000
NS = bytes(range(32))


def _wait(c, ticket, secs=10.0):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        for comp in c.poll():
            if comp.ticket == ticket:
                return comp
        c.wait_event(100)
    raise AssertionError("ticket %d did not complete" % ticket)


@unittest.skipIf(LIB is None, "libmiracache.so not built (set MIRACACHE_LIB)")
class RoundTrip(unittest.TestCase):
    def setUp(self):
        self.c = Client.open_loopback()
        self.addCleanup(self.c.close)
        self.scope = self.c.derive({"engine": "vllm", "ns": NS, "roots": {0: b"root"}}, 0)
        self.keys = [b"blk%d" % i for i in range(3)]
        self.parents = [None, self.keys[0], self.keys[1]]

    def test_put_then_fetch_bytes_equal(self):
        src = bytearray((i * 13 + 1) & 0xFF for i in range(3 * BLK))
        dst = bytearray(b"\xaa" * (3 * BLK))
        self.c.attach_region(src, BLK)
        rep = self.c.store(self.scope, self.keys, self.parents, [0, 1, 2], [0, BLK, 2 * BLK])
        self.assertEqual(rep.status, "OK")
        comp = _wait(self.c, rep.ticket)
        self.assertTrue(comp.success, comp.statuses)
        self.assertEqual(comp.statuses, [_core.COMMITTED] * 3)

        self.c.detach_region(1)
        rd = self.c.attach_region(dst, BLK)
        t = self.c.fetch(self.scope, self.keys, self.parents, [0, 1, 2], [0, BLK, 2 * BLK], region=rd)
        self.assertIsInstance(t, int)
        comp = _wait(self.c, t)
        self.assertTrue(comp.success)
        self.assertEqual(comp.successful_keys, self.keys)
        self.assertEqual(dst, src)

    def test_check_block_size_loopback_reports_no_limit(self):  # review s9 K03, ABI 1.2
        self.assertEqual(self.c.check_block_size(1 << 20), 0)  # the loopback node is not a wire node

    def test_miss_and_lookup(self):
        dst = bytearray(b"\xaa" * BLK)
        self.c.attach_region(dst, BLK)
        t = self.c.fetch(self.scope, [b"absent"], [None], [0], [0])
        comp = _wait(self.c, t)
        self.assertFalse(comp.success)
        self.assertEqual(comp.statuses, [_core.MISS])
        self.assertEqual(dst, bytearray(BLK))
        # lookup_nb: first call PENDING, then the answer.
        self.assertEqual(self.c.lookup_nb(self.scope, b"absent"), "PENDING")
        deadline = time.monotonic() + 10
        ans = "PENDING"
        while ans == "PENDING" and time.monotonic() < deadline:
            self.c.wait_event(50)
            ans = self.c.lookup_nb(self.scope, b"absent")
        self.assertEqual(ans, "MISS")

    def test_gil_released_during_blocking_wait(self):
        ticks = [0]
        stop = threading.Event()

        def spin():
            while not stop.is_set():
                ticks[0] += 1
                time.sleep(0.001)

        th = threading.Thread(target=spin)
        th.start()
        try:
            t0 = time.monotonic()
            self.assertFalse(self.c.wait_event(400))  # nothing pending: blocks the full 400 ms
            self.assertGreaterEqual(time.monotonic() - t0, 0.3)
        finally:
            stop.set()
            th.join()
        self.assertGreater(ticks[0], 50)  # ~400 ticks expected if the GIL was free

    def test_close_with_inflight_and_after(self):
        buf = bytearray(3 * BLK)
        self.c.attach_region(buf, BLK)
        for _ in range(10):
            self.c.fetch(self.scope, self.keys, self.parents, [0, 1, 2], [0, BLK, 2 * BLK])
        self.c.close()
        self.c.close()  # idempotent
        with self.assertRaises(MiraError) as cm:
            self.c.fetch(self.scope, self.keys)
        self.assertEqual(cm.exception.code, _core.E_CLOSED)

    def test_bad_arguments_raise(self):
        buf = bytearray(BLK)
        self.c.attach_region(buf, BLK)
        with self.assertRaises(MiraError) as cm:
            self.c.fetch(self.scope, [b"k"], offsets=[BLK], lengths=[BLK])  # outside the region
        self.assertEqual(cm.exception.code, _core.E_INVALID)


@unittest.skipIf(LIB is None, "libmiracache.so not built (set MIRACACHE_LIB)")
class BadConfig(unittest.TestCase):
    def test_bad_config_raises_mira_error(self):
        with self.assertRaises(MiraError) as cm:
            Client.open("[nodes\nbroken")
        self.assertEqual(cm.exception.code, _core.E_CONFIG)

    def test_missing_file_raises(self):
        with self.assertRaises(MiraError):
            Client.open("/nonexistent/client.toml")


@unittest.skipIf(LIB is None, "libmiracache.so not built (set MIRACACHE_LIB)")
class LookupScopeIdentity(unittest.TestCase):
    """_lookups must not be keyed by id(scope): ids are reused after GC, so a new scope would
    inherit a dead scope's answered lookup. Simulated by making every id() collide."""

    def test_new_scope_does_not_inherit_old_scopes_lookup(self):
        _core.id = lambda o: 1  # module-level shadow of the builtin: every scope "reuses" id 1
        self.addCleanup(delattr, _core, "id")
        c = Client.open_loopback()
        self.addCleanup(c.close)
        meta = {"engine": "vllm", "ns": NS, "roots": {0: b"root"}}
        old = c.derive(meta, 0)
        self.assertEqual(c.lookup_nb(old, b"absent"), "PENDING")
        end = time.monotonic() + 10
        while time.monotonic() < end and "MISS" not in c._lookups.values():
            c.wait_event(50)
            c._drain()
        self.assertIn("MISS", c._lookups.values())  # the old scope's answer is parked, unconsumed
        del old
        gc.collect()
        new = c.derive(meta, 0)
        # Must be a fresh lookup for the new scope, not the dead scope's parked MISS.
        self.assertEqual(c.lookup_nb(new, b"absent"), "PENDING")


if __name__ == "__main__":
    unittest.main()
