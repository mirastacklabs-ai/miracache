"""agentbench KV-tier backend: stub-client logic tests (always run), loopback round-trip
(skips without libmiracache.so), and a signature contract test against agentbench
(skips without agentbench; set AGENTBENCH_SRC to its checkout to enable)."""
import inspect
import os
import sys
import threading
import time
import unittest

from miracache import _core
from miracache._core import Completion, MiraError
_SRC = os.environ.get("AGENTBENCH_SRC")
if _SRC and _SRC not in sys.path:
    sys.path.insert(0, _SRC)
from miracache.bench import agentbench_backend as ab  # noqa: E402

LIB = _core.library_path()
BS = 4096


class StubClient:
    """In-memory stand-in for miracache.Client: no library, no network, no real store."""

    def __init__(self):
        self.store = {}
        self.regions = {}
        self.attach_calls = 0
        self.detach_calls = 0
        self.gate = None  # threading.Event: put/fetch block on it before returning when set
        self.done = []
        self.fail = None  # MiraError raised from fetch/put when set
        self._t = 0
        self._lk = {}

    def attach_region(self, buf, block_bytes=0):
        self.attach_calls += 1
        rid = self.attach_calls
        self.regions[rid] = buf
        return rid

    def detach_region(self, rid):
        self.detach_calls += 1
        del self.regions[rid]

    def derive(self, meta, group):
        return object()

    def _comp(self, kind, statuses):
        self._t += 1
        self.done.append(Completion(self._t, all(s in (_core.HIT, _core.COMMITTED) for s in statuses),
                                    [], False, False, kind, statuses))
        return self._t

    def put(self, scope, keys, parents=None, positions=None, offsets=None, deadline_ms=0,
            lengths=None, region=None):
        if self.fail:
            raise self.fail
        buf = self.regions[region]
        for k, o, n in zip(keys, offsets, lengths):
            self.store[bytes(k)] = bytes(buf[o:o + n])
        if self.gate is not None:
            self.gate.wait(10)
        return self._comp("put", [_core.COMMITTED] * len(keys))

    def fetch(self, scope, keys, parents=None, positions=None, offsets=None, deadline_ms=0,
              lengths=None, region=None):
        if self.fail:
            raise self.fail
        buf = self.regions[region]
        st = []
        for k, o, n in zip(keys, offsets, lengths):
            v = self.store.get(bytes(k))
            if v is None:
                st.append(_core.MISS)
            else:
                buf[o:o + n] = v
                st.append(_core.HIT)
        return self._comp("fetch", st)

    def lookup_nb(self, scope, key, parent=None):
        if key not in self._lk:
            self._lk[key] = True
            return "PENDING"
        del self._lk[key]
        return "HIT" if bytes(key) in self.store else "MISS"

    def poll(self):
        d, self.done = self.done, []
        return d

    def wait_event(self, timeout_ms=0):
        return False

    def close(self):
        pass


def stub_backend(slots=4, op_blocks=4, timeout=2.0):
    be = ab.MiracacheBackend()
    be._client, be._scope, be._block = StubClient(), object(), BS
    be._timeout = timeout
    setup = getattr(be, "_setup_staging", None)  # absent on the pre-pooling code
    if setup is not None:
        setup(slots * op_blocks * BS, op_blocks)
    return be


class PooledStaging(unittest.TestCase):
    def test_attach_once_per_backend_not_per_op(self):
        be = stub_backend()
        c = be._client
        for i in range(10):
            be.put([b"k%d" % i], [bytearray(BS)])
            be.fetch([b"k%d" % i], [bytearray(BS)])
        self.assertEqual(c.attach_calls, 1)
        be.close()
        self.assertEqual(c.detach_calls, 1)

    def test_duplicate_keys_in_batch(self):
        # The real library refuses a batch that repeats a key; the backend must fold duplicates.
        be = stub_backend()
        c = be._client
        for name in ("put", "fetch"):
            orig = getattr(c, name)

            def strict(scope, keys, _o=orig, _n=name, **kw):
                if len(set(map(bytes, keys))) != len(keys):
                    return c._comp(_n, [_core.REFUSED] * len(keys))
                return _o(scope, keys, **kw)
            setattr(c, name, strict)
        v1, v2 = bytearray(b"\x01" * BS), bytearray(b"\x02" * BS)
        be.put([b"a", b"b", b"a"], [v1, v2, bytearray(BS)])
        dst = [bytearray(BS) for _ in range(4)]
        self.assertEqual(be.fetch([b"a", b"b", b"a", b"zz"], dst), [ab.OK, ab.OK, ab.OK, ab.MISS])
        self.assertEqual(dst[0], v1)
        self.assertEqual(dst[1], v2)
        self.assertEqual(dst[2], v1)

    def test_oversize_op_clear_error(self):
        be = stub_backend(op_blocks=2)
        keys = [b"a", b"b", b"c"]
        with self.assertRaisesRegex(ValueError, "staging"):
            be.put(keys, [bytearray(BS)] * 3)
        with self.assertRaisesRegex(ValueError, "staging"):
            be.fetch(keys, [bytearray(BS)] * 3)

    def test_slot_exhaustion_times_out_without_corruption(self):
        be = stub_backend(slots=2, op_blocks=1, timeout=0.3)
        c = be._client
        c.gate = threading.Event()
        res = []

        def worker(i):
            try:
                be.put([b"k%d" % i], [bytearray([i + 1]) * BS])
                res.append("ok")
            except TimeoutError:
                res.append("timeout")

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in ts:
            t.start()
        time.sleep(0.15)
        c.gate.set()
        for t in ts:
            t.join(10)
        # Two held slots finish; the other two either got a freed slot or timed out cleanly.
        self.assertEqual(len(res), 4)
        self.assertGreaterEqual(res.count("ok"), 2)
        for i in range(4):
            if bytes([i + 1]) * BS in c.store.values():
                dst = [bytearray(BS)]
                self.assertEqual(be.fetch([b"k%d" % i], dst), [ab.OK])
                self.assertEqual(dst[0], bytearray([i + 1]) * BS)
        self.assertEqual(be._free_slots(), 2)  # every slot returned

    def test_concurrent_ops_do_not_overlap(self):
        be = stub_backend(slots=2, op_blocks=1, timeout=10)
        errs = []

        def worker(i):
            for r in range(30):
                k = b"w%d" % i
                v = bytearray([i + 1]) * BS
                be.put([k], [v])
                d = [bytearray(BS)]
                if be.fetch([k], d) != [ab.OK] or d[0] != v:
                    errs.append(i)

        ts = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
        for t in ts:
            t.start()
        for t in ts:
            t.join(30)
        self.assertEqual(errs, [])

    def test_close_while_in_flight(self):
        be = stub_backend(slots=2, op_blocks=1, timeout=5)
        c = be._client
        c.gate = threading.Event()
        res = []

        def inflight():
            try:
                be.put([b"x"], [bytearray(b"\x07" * BS)])
                res.append("ok")
            except Exception as e:  # noqa: BLE001
                res.append(type(e).__name__)

        t = threading.Thread(target=inflight)
        t.start()
        time.sleep(0.1)
        closer = threading.Thread(target=be.close)
        closer.start()
        time.sleep(0.2)
        # close must wait for the in-flight op: region still attached, not freed under it
        self.assertEqual(c.detach_calls, 0)
        with self.assertRaises(RuntimeError):  # new ops are refused once closing
            be.put([b"y"], [bytearray(BS)])
        c.gate.set()
        t.join(10)
        closer.join(10)
        self.assertEqual(res, ["ok"])
        self.assertEqual(c.detach_calls, 1)
        with self.assertRaises(RuntimeError):
            be.put([b"z"], [bytearray(BS)])

    def test_open_staging_config(self):
        be = ab.MiracacheBackend()
        be._client, be._block = StubClient(), BS
        with self.assertRaises(ValueError):  # smaller than one op
            be._setup_staging(BS, 4)
        with self.assertRaises(ValueError):
            ab.MiracacheBackend().open({"block_size": BS, "staging_bytes": BS, "max_op_blocks": 4})


class StubLogic(unittest.TestCase):
    def test_put_get_roundtrip(self):
        be = stub_backend()
        keys = [b"a", b"b"]
        src = [bytearray(bytes([i]) * BS) for i in (1, 2)]
        be.put(keys, src)
        dst = [bytearray(BS), bytearray(BS)]
        self.assertEqual(be.fetch(keys, dst), [ab.OK, ab.OK])
        self.assertEqual(dst, src)
        self.assertEqual(be.stats["put_bytes"], 2 * BS)
        self.assertEqual(be.stats["fetch_bytes"], 2 * BS)

    def test_lookup_hit_miss(self):
        be = stub_backend()
        be.put([b"a"], [bytearray(BS)])
        self.assertEqual(be.lookup([b"a", b"zz"]), [True, False])

    def test_fetch_miss_leaves_buffer(self):
        be = stub_backend()
        dst = [bytearray(b"\xaa" * BS)]
        self.assertEqual(be.fetch([b"nope"], dst), [ab.MISS])
        self.assertEqual(dst[0], bytearray(b"\xaa" * BS))

    def test_error_mapping(self):
        be = stub_backend()
        be._client.fail = MiraError(_core.E_CLOSED, "closed")
        self.assertEqual(be.fetch([b"a"], [bytearray(BS)]), [ab.ERROR])  # fetch: status, no raise
        with self.assertRaises(MiraError):  # put: raises
            be.put([b"a"], [bytearray(BS)])

    def test_put_bad_status_raises(self):
        be = stub_backend()
        be._client._comp = lambda kind, st: StubClient._comp(be._client, kind, [_core.REFUSED])
        with self.assertRaises(RuntimeError):
            be.put([b"a"], [bytearray(BS)])

    def test_wrong_buffer_size_and_unopened(self):
        be = stub_backend()
        with self.assertRaises(ValueError):
            be.put([b"a"], [bytearray(BS - 1)])
        with self.assertRaises(RuntimeError):
            ab.MiracacheBackend().lookup([b"a"])

    def test_open_option_validation(self):
        for cfg in ({"block_size": BS, "mode": "bogus"}, {"block_size": BS, "mode": "wire"},
                    {"block_size": BS, "cipher": False}, {"mode": "loopback"}):
            with self.assertRaises(ValueError):
                ab.MiracacheBackend().open(cfg)

    def test_no_null_cipher_capability(self):
        self.assertFalse(ab.MiracacheBackend.capabilities.get("supports_null_cipher"))


@unittest.skipIf(LIB is None, "libmiracache.so not built (set MIRACACHE_LIB)")
class Loopback(unittest.TestCase):
    def setUp(self):
        self.be = ab.MiracacheBackend()
        self.be.open({"mode": "loopback", "block_size": BS})
        self.addCleanup(self.be.close)

    def test_roundtrip_identical_bytes(self):
        keys = [b"blk%d" % i for i in range(3)]
        src = [bytearray((i * 7 + j) & 0xFF for j in range(BS)) for i in range(3)]
        self.be.put(keys, src)
        dst = [bytearray(BS) for _ in keys]
        self.assertEqual(self.be.fetch(keys, dst), [ab.OK] * 3)
        self.assertEqual(dst, src)

    def test_duplicate_keys_in_batch(self):
        v = bytearray(b"\x09" * BS)
        self.be.put([b"d", b"e", b"d"], [v, bytearray(BS), v])
        dst = [bytearray(BS) for _ in range(3)]
        self.assertEqual(self.be.fetch([b"d", b"e", b"d"], dst), [ab.OK] * 3)
        self.assertEqual(dst[0], v)
        self.assertEqual(dst[2], v)

    def test_miss_and_lookup(self):
        self.be.put([b"present"], [bytearray(b"\x05" * BS)])
        self.assertEqual(self.be.lookup([b"present", b"absent"]), [True, False])
        dst = [bytearray(BS)]
        self.assertEqual(self.be.fetch([b"absent"], dst), [ab.MISS])

    def test_fetch_after_close_is_error_or_raises(self):
        self.be.close()
        with self.assertRaises(RuntimeError):
            self.be.lookup([b"x"])


def _import_agentbench():
    try:
        from agentbench.kvtier import backend
        return backend
    except ImportError:
        return None


class Contract(unittest.TestCase):
    def test_signatures_match_agentbench(self):
        mod = _import_agentbench()
        if mod is None:
            self.skipTest("agentbench not importable (set AGENTBENCH_SRC)")
        ref = mod.KVTierBackend
        self.assertTrue(issubclass(ab.MiracacheBackend, ref))
        self.assertEqual((mod.OK, mod.MISS, mod.ERROR), (ab.OK, ab.MISS, ab.ERROR))
        for name in ref.__abstractmethods__:
            want = list(inspect.signature(getattr(ref, name)).parameters)
            got = list(inspect.signature(getattr(ab.MiracacheBackend, name)).parameters)
            self.assertEqual(got, want, name)
        self.assertFalse(getattr(ab.MiracacheBackend, "__abstractmethods__", None))

    def test_fallback_shape(self):
        # Method names the fallback must expose regardless of agentbench being installed.
        self.assertEqual(set(ab.KVTierBackend.__abstractmethods__) if not ab.HAVE_AGENTBENCH
                         else {"open", "put", "fetch", "lookup", "close"},
                         {"open", "put", "fetch", "lookup", "close"})


if __name__ == "__main__":
    unittest.main()
