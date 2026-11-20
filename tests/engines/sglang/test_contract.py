"""Contract test against the real SGLang classes (pin 18d862f).
Skips cleanly when SGLang is absent."""
import inspect
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "..", "python"))

try:
    from sglang.srt.mem_cache import hicache_storage as hs  # type: ignore
except Exception as exc:  # noqa: BLE001
    hs = None
    _why = repr(exc)

# upstream parameter names after self (hicache_storage.py line refs from research/19)
EXPECTED = {
    "register_mem_pool_host": ["mem_pool_host"],  # 7a/8f :381
    "batch_exists": ["keys", "extra_info"],  # 8c :543
    "batch_get_v1": ["keys", "host_indices", "extra_info"],  # 8a :454
    "batch_set_v1": ["keys", "host_indices", "extra_info"],  # 8b :466
    "batch_exists_v2": ["keys", "pool_transfers", "extra_info"],  # 8e :399
    "batch_get_v2": ["transfers", "extra_info"],  # 8e :432
    "batch_set_v2": ["transfers", "extra_info"],  # 8e :443
    "get": ["key", "target_location", "target_sizes"],  # 8d
    "batch_get": ["keys", "target_locations", "target_sizes"],
    "set": ["key", "value", "target_location", "target_sizes"],
    "batch_set": ["keys", "values", "target_locations", "target_sizes"],
    "exists": ["key"],
}


@unittest.skipIf(hs is None, "sglang not installed")
class TestContract(unittest.TestCase):
    def test_base_class(self):  # 7a
        from miracache.sglang import MiraHiCacheStorage
        self.assertTrue(issubclass(MiraHiCacheStorage, hs.HiCacheStorage))

    def test_method_signatures(self):  # 8a-8f
        from miracache.sglang import MiraHiCacheStorage
        for name, params in EXPECTED.items():
            theirs = list(inspect.signature(getattr(hs.HiCacheStorage, name)).parameters)[1:]
            ours = list(inspect.signature(getattr(MiraHiCacheStorage, name)).parameters)[1:]
            self.assertEqual(theirs, params, "upstream " + name)
            self.assertEqual(ours, theirs, name)

    def test_v2_return_types(self):  # 8e
        from miracache.sglang import MiraHiCacheStorage
        r = MiraHiCacheStorage.batch_exists_v2(object.__new__(MiraHiCacheStorage), ["a"])
        self.assertIsInstance(r, hs.PoolTransferResult)
        self.assertEqual((r.kv_hit_pages, r.extra_pool_hit_pages), (0, {}))
        out = MiraHiCacheStorage.batch_get_v2(object.__new__(MiraHiCacheStorage),
                                              [hs.PoolTransfer(name="kv", keys=["a", "b"])])
        self.assertEqual(out, {"kv": [False, False]})

    def test_config_fields(self):  # 9a/9b
        params = inspect.signature(hs.HiCacheStorageConfig).parameters
        for f in ("tp_rank", "tp_size", "pp_rank", "pp_size", "is_mla_model", "is_page_first_layout",
                  "model_name", "extra_config", "dcp_size", "logical_page_size"):
            self.assertIn(f, params)

    def test_extra_info_has_prefix_keys(self):  # 11
        self.assertIn("prefix_keys", inspect.signature(hs.HiCacheStorageExtraInfo).parameters)

    def test_constructor_called_as_dynamic_backend_does(self):  # 7b
        """backend_class(storage_config, kwargs) with kwargs == {}; no host pool at init."""
        from miracache.sglang import MiraHiCacheStorage
        params = list(inspect.signature(MiraHiCacheStorage.__init__).parameters)
        self.assertEqual(params[:3], ["self", "storage_config", "kwargs"])
        from sglang.srt.mem_cache.storage import backend_factory as bf  # type: ignore
        src = inspect.getsource(bf)
        self.assertIn("backend_class(storage_config, kwargs)", src)

    def test_dynamic_backend_hook(self):  # 7c
        from sglang.srt.mem_cache.storage import backend_factory as bf  # type: ignore
        src = inspect.getsource(bf)
        self.assertIn("dynamic", src)
        for k in ("backend_name", "module_path", "class_name"):
            self.assertIn(k, src)

    def test_config_flags_example(self):  # 7d, 11
        import json
        here = os.path.dirname(__file__)
        p = os.path.join(here, "..", "..", "..", "deploy", "sglang", "extra-config.example.json")
        d = json.load(open(p))
        for k in ("backend_name", "module_path", "class_name", "interface_v1",
                  "hicache_storage_pass_prefix_keys", "miracache_expect_prefix_keys"):
            self.assertIn(k, d)


if __name__ == "__main__":
    unittest.main()
