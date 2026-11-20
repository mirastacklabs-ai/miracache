"""Drift tripwire: the pinned vLLM must still offer what MiraTier relies on.

Mirrors the vLLM adapter signature table (row ids in the test
names / comments): every row that can be checked by import is checked here.

CPU-only import test; SKIPs when vLLM is not installed. Run in CI with the pinned vLLM and
nightly against main:  PYTHONPATH=python python3 -m unittest discover -s tests/engines/vllm
Nothing here starts an engine or touches a GPU.
"""
import dataclasses
import importlib
import inspect
import unittest

try:
    import vllm  # noqa: F401
    HAVE_VLLM = True
except Exception:  # noqa: BLE001 - any import failure means "not testable here"
    HAVE_VLLM = False

from miracache.vllm import compat  # noqa: E402


def fields(cls):
    if dataclasses.is_dataclass(cls):
        return [f.name for f in dataclasses.fields(cls)]
    return list(getattr(cls, "__annotations__", {}))


def params(fn):
    return list(inspect.signature(fn).parameters)


@unittest.skipUnless(HAVE_VLLM, "vllm not installed")
class TestVllmContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = importlib.import_module("vllm.v1.kv_offload.tiering.base")
        cls.kvbase = importlib.import_module("vllm.v1.kv_offload.base")
        cls.cfg = importlib.import_module("vllm.v1.kv_offload.config")
        cls.tier = cls.base.SecondaryTierManager

    # -- 6a / 6b: version gate and probes
    def test_version_in_tested_range(self):
        v = vllm.__version__
        if v != "dev":  # source tree without scm metadata: the probes below are the gate
            self.assertEqual(compat.check_version(v), [])

    def test_full_compat_check_passes(self):
        errs = compat.full_check(
            version=None, base_cls=self.tier, req_context_cls=self.kvbase.ReqContext,
            settings={"canonical_layout": True, "pipeline_parallel_size": 1,
                      "context_parallel_size": 1},
            transfer_job_cls=self.base.TransferJob, job_result_cls=self.base.JobResult)
        self.assertEqual(errs, [])

    # -- 1a / 1b / 1c / 1d
    def test_classes_exist(self):
        for name in ("SecondaryTierManager", "TransferJob", "JobResult"):
            self.assertTrue(hasattr(self.base, name), name)
        for name in ("ReqContext", "LookupResult", "RequestOffloadingContext", "OffloadingSpec"):
            self.assertTrue(hasattr(self.kvbase, name), name)

    def test_1b_init_signature_and_factory_call(self):
        self.assertEqual(params(self.tier.__init__)[:5],
                         ["self", "offloading_spec", "primary_kv_view", "tier_type",
                          "backpressure_detector"])
        self.assertEqual(compat.check_init_signature(self.tier), [])
        from miracache import vllm_tier
        # The factory calls by keyword with the rest of the tier dict splatted in.
        inspect.signature(vllm_tier.MiraTier.__init__).bind(
            None, offloading_spec=None, primary_kv_view=None, tier_type="MiraTier",
            backpressure_detector=None, config="/x/client.toml")

    def test_1c_factory_loads_out_of_tree_by_module_path(self):
        fac = importlib.import_module("vllm.v1.kv_offload.tiering.factory")
        f = fac.SecondaryTierFactory
        self.assertEqual(params(f.create_secondary_tier),
                         ["tier_config", "primary_kv_view", "offloading_spec"])
        self.assertTrue(callable(f.get_tier_class))

    def test_1d_tiering_spec_is_registered(self):
        fac = importlib.import_module("vllm.v1.kv_offload.factory")
        self.assertIn("TieringOffloadingSpec", fac.OffloadingSpecFactory._registry)
        self.assertIn("CPUOffloadingSpec", fac.OffloadingSpecFactory._registry)
        spec = importlib.import_module("vllm.v1.kv_offload.tiering.spec")
        self.assertTrue(hasattr(spec, "TieringOffloadingSpec"))

    # -- 2a / 2c / 2d
    def test_2a_transfer_job_fields(self):
        self.assertEqual(fields(self.base.TransferJob)[:5],
                         ["job_id", "keys", "chunk_ids", "is_promotion", "req_context"])

    def test_2c_job_result_fields(self):
        names = fields(self.base.JobResult)
        self.assertEqual(names[:5], ["job_id", "success", "successful_keys", "transfer_time",
                                     "transfer_bytes"])
        # 2d: deferred_release is main-only; absent in 0.32 / 0.33 (adapter feature-detects)
        self.assertEqual(compat.has_deferred_release(self.base.JobResult),
                         "deferred_release" in names)
        r = self.base.JobResult(job_id=1, success=False)  # keyword construction works
        self.assertEqual((r.job_id, r.success), (1, False))

    # -- 3a..3e
    def test_3_req_context(self):
        rc = self.kvbase.ReqContext
        self.assertIn("req_id", fields(rc))
        self.assertIn("kv_transfer_params", fields(rc))
        self.assertEqual(compat.check_req_context_class(rc), [])
        c = rc(req_id="x")
        self.assertIsNone(c.kv_transfer_params)  # 3b: default None, not {}
        self.assertEqual(params(rc.set_state), ["self", "val"])  # 3c
        self.assertEqual(params(rc.get_state), ["self", "cls"])
        self.assertIsNone(c.get_offload_key_position(b"missing"))  # 3e: None on a miss
        c.set_offload_key_position(b"k", 32)
        self.assertEqual(c.get_offload_key_position(b"k"), 32)
        self.assertIsInstance(c._offload_key_positions, dict)  # 3d

    # -- 4a..4f
    def test_4a_submit_signatures(self):
        for name in ("submit_load", "submit_store"):
            self.assertEqual(params(getattr(self.tier, name)), ["self", "job_metadata"], name)

    def test_tier_methods_and_arity(self):  # 4c, 4d, 4f
        self.assertEqual(compat.check_signatures(self.tier), [])
        self.assertEqual(params(self.tier.lookup), ["self", "key", "req_context"])
        for name in ("get_finished_jobs", "drain_jobs"):
            self.assertEqual(params(getattr(self.tier, name)), ["self"], name)
        self.assertEqual(params(self.tier.on_request_finished), ["self", "req_context"])
        self.assertTrue(hasattr(self.tier, "shutdown"))
        self.assertTrue(hasattr(self.tier, "has_pending_work"))

    def test_4b_lookup_result_members(self):
        names = {m.name for m in self.kvbase.LookupResult}
        for m in ("HIT", "MISS", "RETRY", "HIT_PENDING"):
            self.assertIn(m, names)

    def test_4e_on_new_request_returns_request_offloading_context(self):
        self.assertEqual(params(self.tier.on_new_request), ["self", "req_context"])
        ctx = self.kvbase.RequestOffloadingContext()
        self.assertIs(ctx.policy, self.kvbase.OffloadPolicy.CHUNK_LEVEL)

    # -- 5a..5i
    def test_5a_offloading_config_has_what_the_tier_reads(self):
        cfg = fields(self.cfg.OffloadingConfig)
        for f in ("canonical_layout", "parallel", "cache", "groups", "extra_config"):
            self.assertIn(f, cfg)
        for f in ("pp_size", "pcp_size", "dcp_size", "tp_size"):
            self.assertIn(f, fields(self.cfg.OffloadingParallelConfig))
        self.assertIn("blocks_per_chunk", fields(self.cfg.OffloadingCacheConfig))
        self.assertIn("tokens_per_block", fields(self.cfg.OffloadingGroupConfig))
        # ...and nothing of what check_vllm_config checks pre-launch (5a)
        self.assertNotIn("kv_load_failure_policy", cfg)
        self.assertEqual(params(self.kvbase.OffloadingSpec.__init__), ["self", "config"])

    def test_5b_to_5e_vllm_config_fields_for_the_preflight(self):
        kvt = importlib.import_module("vllm.config.kv_transfer").KVTransferConfig
        self.assertIn("kv_load_failure_policy", fields(kvt))
        cache = importlib.import_module("vllm.config.cache").CacheConfig
        self.assertIn("prefix_caching_hash_algo", fields(cache))
        self.assertIn("block_size", fields(cache))
        par = importlib.import_module("vllm.config.parallel").ParallelConfig
        for f in ("pipeline_parallel_size", "prefill_context_parallel_size",
                  "decode_context_parallel_size"):
            self.assertIn(f, fields(par))

    def test_5j_ns_inputs_model_path_and_cache_dtype(self):
        # ns relies on OffloadingConfig.model: name = the weights path (not --served-model-name) and
        # dtype = the model dtype when --kv-cache-dtype is auto, else the exact cache dtype string
        # (so fp8_e4m3 vs fp8_e5m2 differ). The compute dtype (--dtype) under an explicit cache dtype
        # is not there: preflight's mirror rule covers it. If this drifts, revisit compat.namespace_fields.
        mod = importlib.import_module("vllm.distributed.kv_transfer.kv_connector.v1.offloading.config")
        src = inspect.getsource(mod.build_offloading_config)
        for s in ("name=vllm_config.model_config.model", "vllm_config.model_config.dtype",
                  'vllm_config.cache_config.cache_dtype == "auto"', 'removeprefix("torch.")'):
            self.assertIn(s, src)

    def test_5g_hash_algos_offered(self):
        utils = importlib.import_module("vllm.utils.hashing")
        self.assertTrue(hasattr(utils, "sha256_cbor"))

    def test_5h_tokens_per_chunk_source(self):
        src = inspect.getsource(self.kvbase.OffloadingSpec.__init__)
        self.assertIn("tokens_per_block", src)
        self.assertIn("blocks_per_chunk", src)
        spec = type("S", (), {"tokens_per_block": (16, 32), "blocks_per_chunk": 2})()
        self.assertEqual(compat.tokens_per_chunk_by_group(spec), (32, 64))

    def test_5i_block_size_bytes_property(self):
        self.assertIsInstance(inspect.getattr_static(self.tier, "block_size_bytes"), property)


if __name__ == "__main__":
    unittest.main()
