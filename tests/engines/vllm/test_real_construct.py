"""Smoke: build MiraTier against the REAL vLLM base classes and dataclasses (no fake on
sys.path). The miracache client is the in-memory FakeClient (not an engine class).
Skips when vLLM is not installed. Nothing starts an engine or touches a GPU."""
import os
import sys
import unittest

HERE = os.path.dirname(__file__)
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "python"))
sys.path.insert(0, os.path.join(HERE, "..", "..", "python"))  # fake_client only

try:
    import vllm  # noqa: F401
    from vllm.v1.kv_offload import base as kvbase
    from vllm.v1.kv_offload import config as kvcfg
    from vllm.v1.kv_offload.tiering import base as tbase
    HAVE = True
except Exception:  # noqa: BLE001
    HAVE = False

SLOT = 4096


def real_spec(tokens_per_block=(16,), bpc=1):
    """A real OffloadingSpec instance (abstract hooks stubbed) over a real OffloadingConfig."""
    import dataclasses
    groups = tuple(kvcfg.OffloadingGroupConfig(t, ("l%d" % i,), i)
                   for i, t in enumerate(tokens_per_block))
    vals = dict(
        groups=groups, worker_kv_bytes_per_block=SLOT, enable_kv_cache_events=False,
        extra_config={}, engine_id="e0", model=kvcfg.OffloadingModelConfig("m", "fp8"),
        cache=kvcfg.OffloadingCacheConfig(tokens_per_hash=16, blocks_per_chunk=bpc),
        parallel=kvcfg.OffloadingParallelConfig(0, 1, 1, 1, 1, 1, 0, 1, None, True),
        canonical_layout=True)
    names = {f.name for f in dataclasses.fields(kvcfg.OffloadingConfig)}
    cfg = kvcfg.OffloadingConfig(**{k: v for k, v in vals.items() if k in names})
    stubs = {n: (lambda self, *a, **k: None) for n in getattr(kvbase.OffloadingSpec,
                                                              "__abstractmethods__", ())}
    return type("RealSpecStub", (kvbase.OffloadingSpec,), stubs)(cfg)


@unittest.skipUnless(HAVE, "vllm not installed")
class TestRealConstruct(unittest.TestCase):
    def make(self):
        from fake_client import FakeClient
        from miracache import vllm_tier
        self.client = FakeClient()
        view = memoryview(bytearray(16 * SLOT)).cast("B", shape=[16, SLOT])
        cls = type("T", (vllm_tier.MiraTier,), {"client_factory": staticmethod(lambda p: self.client)})
        # tiering/factory.py: keywords, rest of the tier dict splatted
        return cls(offloading_spec=real_spec(), primary_kv_view=view, tier_type="MiraTier",
                   backpressure_detector=None, config="/x/client.toml", drain_timeout_s=1.0,
                   kv_load_failure_policy="recompute")

    def test_is_real_subclass_and_constructs(self):
        t = self.make()
        self.assertIsInstance(t, tbase.SecondaryTierManager)
        self.assertEqual(t.block_size_bytes, SLOT)
        self.assertEqual(t.tier_type, "MiraTier")
        t.shutdown()

    def test_new_request_and_lookup_use_real_types(self):
        t = self.make()
        ctx = kvbase.ReqContext(req_id="r1")
        out = t.on_new_request(ctx)
        self.assertIsInstance(out, kvbase.RequestOffloadingContext)
        self.assertIn(t.lookup(b"k" * 12, ctx), set(kvbase.LookupResult))
        self.assertEqual(list(t.get_finished_jobs()), [])
        t.on_request_finished(ctx)
        t.shutdown()


if __name__ == "__main__":
    unittest.main()
