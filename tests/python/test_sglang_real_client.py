"""MiraHiCacheStorage end to end against the REAL miracache._core.Client (loopback).
Skips unless libmiracache.so is found (MIRACACHE_LIB, or a dev build)."""
import os
import sys
import time
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)

from fake_sglang import (FakeMHAHostPool, FakeMLAKVSplitHostPool, HiCacheStorageConfig,  # noqa: E402
                         HiCacheStorageExtraInfo, build_dynamic_backend)
from miracache import _core  # noqa: E402
from miracache.sglang import MiraHiCacheStorage  # noqa: E402

LIB = _core.library_path()
PS = 64
KEYS = ["p%d" % i for i in range(6)]


def cfg(**extra):
    e = {"hicache_storage_pass_prefix_keys": True, "miracache_expect_prefix_keys": True,
         "interface_v1": 1}
    e.update(extra)
    return HiCacheStorageConfig(extra_config=e)


def fill(pool, pages):
    out = {}
    for p in pages:
        _, sizes = pool.get_page_buffer_meta(pool.tokens(p))
        blobs = [bytes(((p * 7 + j * 13 + i) % 251) + 1 for i in range(s)) for j, s in enumerate(sizes)]
        pool.write_page(p, blobs)
        out[p] = blobs
    return out


@unittest.skipIf(LIB is None, "libmiracache.so not built (set MIRACACHE_LIB)")
class RealClientEndToEnd(unittest.TestCase):
    def roundtrip(self, pool, stage_pages):
        client = _core.Client.open_loopback()
        s = build_dynamic_backend(lambda c, k: MiraHiCacheStorage(c, k, client=client),
                                  cfg(miracache_stage_pages=stage_pages), pool)
        self.addCleanup(s.close)
        src = fill(pool, range(6))
        root = HiCacheStorageExtraInfo(prefix_keys=None)
        self.assertEqual(s.batch_set_v1(KEYS[:3], pool.indices([0, 1, 2]), root), [True] * 3)
        cont = HiCacheStorageExtraInfo(prefix_keys=KEYS[:3])
        self.assertEqual(s.batch_set_v1(KEYS[3:], pool.indices([3, 4, 5]), cont), [True] * 3)
        end = time.monotonic() + 5
        n = 0
        while time.monotonic() < end:
            n = s.batch_exists(KEYS, root)
            if n == 6:
                break
            time.sleep(0.12)  # past the presence-cache TTL
        self.assertEqual(n, 6)
        dst = pool.indices([6, 7, 8, 9, 10, 11])
        self.assertEqual(s.batch_get_v1(KEYS, dst, root), [True] * 6)
        for sp, dp in zip(range(6), range(6, 12)):
            self.assertEqual(pool.read_page(dp), src[sp], sp)
        # an unknown key is a miss, not an error
        self.assertEqual(s.batch_get_v1(["nope"], pool.indices([11]), root), [False])
        self.assertFalse(any(k.startswith("internal_error") for k in s.counters), s.counters)
        self.assertNotIn("io_timeout", s.counters)

    def test_mha_page_first(self):
        self.roundtrip(FakeMHAHostPool(PS, 12, "page_first"), 16)

    def test_mha_layer_first_chunked(self):
        self.roundtrip(FakeMHAHostPool(PS, 12, "layer_first", layer_num=3), 2)

    def test_mla_kv_split(self):
        self.roundtrip(FakeMLAKVSplitHostPool(PS, 12), 4)


if __name__ == "__main__":
    unittest.main()
