"""Smoke: build MiraHiCacheStorage with the REAL SGLang HiCacheStorageConfig / base class, the
way the `dynamic` backend does (backend_class(storage_config, kwargs), then
register_mem_pool_host). No fake SGLang on sys.path. The host pool is a tiny stand-in with
the two members the adapter reads (page_size, get_page_buffer_meta); the client is FakeClient.
Skips when SGLang is not installed."""
import dataclasses
import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "python"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "python"))  # fake_client only

try:
    from sglang.srt.mem_cache import hicache_storage as hs  # type: ignore
except Exception:  # noqa: BLE001
    hs = None

PAGE = 64
ELEM = 1024


class Pool:
    page_size = PAGE

    def get_page_buffer_meta(self, indices):
        idx = indices.tolist()
        ptrs = [0x10000 + i * ELEM for i in idx[::PAGE]]
        return ptrs, [ELEM] * len(ptrs)


def real_config(**over):
    vals = dict(tp_rank=0, tp_size=1, pp_rank=0, pp_size=1, attn_cp_rank=0, attn_cp_size=1,
                is_mla_model=True, enable_storage_metrics=False, is_page_first_layout=True,
                model_name="m", extra_config={
                    "hicache_storage_pass_prefix_keys": True, "interface_v1": 1,
                    "miracache_expect_prefix_keys": True,
                    "miracache": {"config": "/etc/miracache/client.toml"}})
    vals.update(over)
    names = {f.name: f for f in dataclasses.fields(hs.HiCacheStorageConfig)}
    kw = {k: v for k, v in vals.items() if k in names}
    return hs.HiCacheStorageConfig(**kw)


@unittest.skipIf(hs is None, "sglang not installed")
class TestRealConstruct(unittest.TestCase):
    def test_constructs_like_dynamic_backend(self):
        from fake_client import FakeClient
        from miracache.sglang import MiraHiCacheStorage
        s = MiraHiCacheStorage(real_config(), {}, client=FakeClient())  # backend_factory.py:165
        self.assertIsInstance(s, hs.HiCacheStorage)
        s.register_mem_pool_host(Pool())  # cache_controller.py:667
        self.assertEqual(s.batch_exists(["a" * 8], None), 0)
        r = s.batch_exists_v2(["a"])
        self.assertIsInstance(r, hs.PoolTransferResult)


if __name__ == "__main__":
    unittest.main()
