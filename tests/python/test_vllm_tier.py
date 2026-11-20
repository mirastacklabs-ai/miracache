import logging
import os
import sys
import unittest
from types import SimpleNamespace as NS
from unittest import mock

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "fake_vllm"))  # stand-in for vllm (tests only)

from fake_client import FakeClient  # noqa: E402
from miracache.vllm import compat  # noqa: E402
from miracache.vllm.core import StoreReply  # noqa: E402
from miracache import vllm_tier  # noqa: E402
import vllm  # noqa: E402
import vllm.v1.kv_offload.tiering.base as tbase  # noqa: E402
from vllm.v1.kv_offload.base import (LookupResult, OffloadingSpec, OffloadPolicy,  # noqa: E402
                                     ReqContext, RequestOffloadingContext)
from vllm.v1.kv_offload.config import (OffloadingCacheConfig, OffloadingConfig,  # noqa: E402
                                       OffloadingGroupConfig, OffloadingModelConfig,
                                       OffloadingParallelConfig)
from vllm.v1.kv_offload.tiering.base import TransferJob  # noqa: E402

TPC = 16
SLOT = 4096
NSLOTS = 16


def key(name, group=0):
    return name.encode().ljust(8, b"_") + group.to_bytes(4, "little")


def chain(prefix, n, group=0, start=1, tpc=TPC):
    return {key(f"{prefix}{i}", group): i * tpc for i in range(start, n + 1)}


def make_spec(canonical=True, pp=1, pcp=1, dcp=1, tokens_per_block=(16,), bpc=1):
    groups = tuple(OffloadingGroupConfig(t, ("l%d" % i,), i) for i, t in enumerate(tokens_per_block))
    cfg = OffloadingConfig(
        groups=groups, worker_kv_bytes_per_block=SLOT, enable_kv_cache_events=False,
        extra_config={}, engine_id="e0", model=OffloadingModelConfig("m", "fp8"),
        cache=OffloadingCacheConfig(tokens_per_hash=16, blocks_per_chunk=bpc),
        parallel=OffloadingParallelConfig(0, 1, 1, pp, pcp, dcp, 0, 1, None, True),
        canonical_layout=canonical)
    return OffloadingSpec(cfg)


def make_view(slots=NSLOTS, slot=SLOT):
    return memoryview(bytearray(slots * slot)).cast("B", shape=[slots, slot])


class Base(unittest.TestCase):
    def make(self, spec=None, client=None, cls=None, **tier_kw):
        """Build exactly as tiering/factory.py:91-97 does: keywords, rest of the dict splatted."""
        self.client = client or FakeClient()
        self.view = make_view()
        base = cls or vllm_tier.MiraTier
        sub = type("T", (base,), {"client_factory": staticmethod(lambda path: self.client)})
        kw = {"config": "/x/client.toml", "drain_timeout_s": 1.0, "kv_load_failure_policy": "recompute"}
        kw.update(tier_kw)
        return sub(offloading_spec=spec or make_spec(), primary_kv_view=self.view,
                   tier_type="MiraTier", backpressure_detector=None, **kw)

    def setUp(self):
        self.t = self.make()
        self.ctx = ReqContext("r1")
        self.ctx._offload_key_positions.update(chain("a", 3))
        self.t.on_new_request(self.ctx)

    def seed(self, ctx):
        pos = ctx._offload_key_positions
        root = min(pos, key=pos.get)
        for k in pos:
            self.client.objects.add((("scope", root), k))

    def job(self, jid, keys, chunk_ids=None, promo=True, ctx=None):
        return TransferJob(jid, keys, list(range(len(keys))) if chunk_ids is None else chunk_ids,
                           promo, ctx or self.ctx)


class TestImport(unittest.TestCase):
    def test_module_imports_without_vllm(self):
        self.assertIn("MiraTier", vllm_tier.__all__)


class TestConstructor(Base):  # research/19 1b, 5a, 5h, 5i
    def test_factory_call_shape_and_super_init(self):
        t = self.make()
        self.assertEqual(t.tier_type, "MiraTier")
        self.assertEqual(t.block_size_bytes, SLOT)  # primary_kv_view.strides[0]
        self.assertIsNone(t.bp_detector)

    def test_metrics_port_serves_until_shutdown_and_is_off_by_default(self):
        import http.client
        import socket
        self.assertIsNone(self.t._metrics_srv)  # metrics_port absent = off
        with socket.socket() as sk:
            sk.bind(("127.0.0.1", 0))
            base = sk.getsockname()[1] - 1
        client = FakeClient()
        client.metrics = lambda: "miracache_client_fake_total 3\n"
        t = self.make(client=client, metrics_port=base, metrics_rank=1)  # port = base + rank
        conn = http.client.HTTPConnection("127.0.0.1", base + 1, timeout=5)
        conn.request("GET", "/metrics")
        r = conn.getresponse()
        body = r.read().decode()
        conn.close()
        self.assertEqual(r.status, 200)
        self.assertIn("miracache_client_fake_total 3\n", body)
        self.assertIn("miracache_adapter_lookup_tokens_total 0\n", body)
        t.shutdown()
        self.assertIsNone(t._metrics_srv)
        with self.assertRaises(OSError):
            http.client.HTTPConnection("127.0.0.1", base + 1, timeout=2).request("GET", "/metrics")

    def test_unknown_keys_one_warning(self):
        with self.assertLogs("miracache.vllm_tier", level="WARNING") as cm:
            self.make(foo=1, bar=2)
        self.assertEqual(len(cm.output), 1)
        self.assertIn("bar", cm.output[0])
        self.assertIn("foo", cm.output[0])

    def test_known_extra_key_locality_no_warning(self):
        with self.assertNoLogs("miracache.vllm_tier", level="WARNING"):
            self.make(locality=None)

    def test_missing_or_bad_config_refuses(self):
        for bad in (None, "", {"x": 1}, 5):
            with self.assertRaises(compat.CompatError, msg=repr(bad)):
                self.make(config=bad)

    def test_no_vllm_config_needed(self):
        # The tier sees only the OffloadingSpec: kv_load_failure_policy / hash algo are
        # check_vllm_config's job (5a); nothing of the sort is reachable here.
        self.make()

    def test_registers_primary_view_once(self):
        self.assertEqual(len(self.client.attached), 1)
        buf, blk = self.client.attached[0]
        self.assertIs(buf, self.view)
        self.assertEqual(blk, SLOT)

    def test_attach_failure_refuses(self):
        c = FakeClient()
        c.raise_on = {"attach_region"}
        with self.assertRaises(compat.CompatError):
            self.make(client=c)
        self.assertTrue(c.closed)  # V03: the opened client is not leaked

    def test_failure_after_attach_also_closes_client(self):
        c = FakeClient()
        with self.assertRaises(ValueError):
            self.make(client=c, fetch_deadline_ms="not-a-number")
        self.assertTrue(c.closed)

    def test_deadlines_default_and_configured(self):  # V01
        t = self.make()
        t.on_new_request(self.ctx)
        self.seed(self.ctx)
        t.lookup(key("a2"), self.ctx)
        t.submit_load(self.job(1, [key("a2")], [1]))
        t.submit_store(self.job(2, [key("a1")], [2], promo=False))
        self.assertEqual(self.client.lookup_deadlines, [50])
        self.assertEqual(self.client.fetch_deadlines, [300])
        self.assertEqual(self.client.store_deadlines, [2000])
        t = self.make(fetch_deadline_ms=120, lookup_deadline_ms=7, store_deadline_ms=900)
        t.on_new_request(self.ctx)
        self.seed(self.ctx)
        t.lookup(key("a2"), self.ctx)
        t.submit_load(self.job(3, [key("a2")], [1]))
        t.submit_store(self.job(4, [key("a1")], [2], promo=False))
        self.assertEqual(self.client.lookup_deadlines, [7])
        self.assertEqual(self.client.fetch_deadlines, [120])
        self.assertEqual(self.client.store_deadlines, [900])

    def test_job_carries_configured_deadline(self):  # V01
        t = self.make(fetch_deadline_ms=111, store_deadline_ms=2222)
        self.assertEqual(t._job(self.job(5, [key("a2")], [1])).deadline_ms, 111)
        self.assertEqual(t._job(self.job(6, [key("a2")], [1], promo=False)).deadline_ms, 2222)

    def test_tokens_per_chunk_per_group(self):
        spec = make_spec(tokens_per_block=(16, 32), bpc=2)
        self.assertEqual(compat.tokens_per_chunk_by_group(spec), (32, 64))
        t = self.make(spec=spec)
        ctx = ReqContext("rg")
        # group 0 chunk 0 ends at 32 tokens, group 1 chunk 0 ends at 64
        ctx._offload_key_positions.update({**chain("a", 2, 0, tpc=32), **chain("c", 2, 1, tpc=64)})
        self.client.objects.add((("scope", key("a1", 0)), key("a2", 0)))
        self.client.objects.add((("scope", key("c1", 1)), key("c2", 1)))
        self.assertIs(t.lookup(key("a2", 0), ctx), LookupResult.HIT)
        self.assertIs(t.lookup(key("c2", 1), ctx), LookupResult.HIT)
        n = len(self.client.derive_calls)
        # a position that is chunk 0 for 16-token blocks only must not count as root for group 1
        ctx2 = ReqContext("rg2")
        ctx2._offload_key_positions.update(chain("d", 3, 1, tpc=32))
        self.assertIs(t.lookup(key("d2", 1), ctx2), LookupResult.MISS)
        self.assertEqual(len(self.client.derive_calls), n)  # no scope derived: skip L3

    def test_tokens_per_chunk_bad_spec(self):
        with self.assertRaises(compat.CompatError):
            compat.tokens_per_chunk_by_group(NS(tokens_per_block=(), blocks_per_chunk=1))
        with self.assertRaises(compat.CompatError):
            compat.tokens_per_chunk_by_group(NS(tokens_per_block=(16,), blocks_per_chunk=0))


class TestRequestContext(Base):  # 4e
    def test_on_new_request_returns_context(self):
        r = self.t.on_new_request(ReqContext("r9"))
        self.assertIsInstance(r, RequestOffloadingContext)
        self.assertIs(r.policy, OffloadPolicy.CHUNK_LEVEL)

    def test_on_new_request_error_still_returns_context(self):
        self.assertIsInstance(self.t.on_new_request(object()), RequestOffloadingContext)

    def test_on_request_finished_returns_none(self):
        self.assertIsNone(self.t.on_request_finished(self.ctx))


class TestLookup(Base):
    def test_retry_then_hit(self):
        self.seed(self.ctx)
        self.client.pending_lookups[key("a2")] = 1
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.RETRY)
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.HIT)

    def test_miss(self):
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.MISS)

    def test_root_is_min_position_per_group_and_rederived_after_recompute(self):
        self.seed(self.ctx)
        self.t.lookup(key("a2"), self.ctx)
        self.ctx._offload_key_positions.clear()
        self.ctx._offload_key_positions.update(chain("b", 3))  # preemption recompute
        self.seed(self.ctx)
        self.assertIs(self.t.lookup(key("b2"), self.ctx), LookupResult.HIT)
        roots = [m["roots"][g] for m, g in self.client.derive_calls]
        self.assertEqual(roots, [key("a1"), key("b1")])

    def test_two_groups(self):
        ctx = ReqContext("r2")
        ctx._offload_key_positions.update({**chain("a", 2, 0), **chain("c", 2, 1)})
        self.seed(ctx)
        self.t.lookup(key("a2", 0), ctx)
        self.t.lookup(key("c2", 1), ctx)
        self.assertEqual({g: m["roots"][g] for m, g in self.client.derive_calls},
                         {0: key("a1", 0), 1: key("c1", 1)})

    def test_min_position_not_chunk0_skips_l3(self):
        ctx = ReqContext("r3")
        ctx._offload_key_positions.update(chain("a", 5, start=3))
        self.assertIs(self.t.lookup(key("a4"), ctx), LookupResult.MISS)
        self.assertEqual(self.client.derive_calls, [])

    def test_empty_dict_skips_l3(self):
        self.assertIs(self.t.lookup(key("a1"), ReqContext("r4")), LookupResult.MISS)
        self.assertEqual(self.client.derive_calls, [])

    def test_miracache_skip(self):
        self.seed(self.ctx)
        self.ctx.kv_transfer_params = {"miracache": {"skip": True}}
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.MISS)

    def test_none_kv_transfer_params_is_fine(self):  # 3b: default is None upstream
        self.assertIsNone(self.ctx.kv_transfer_params)
        self.seed(self.ctx)
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.HIT)


class TestAddressing(Base):  # 2a, 2b
    def test_load_offsets_come_from_chunk_ids_not_chain_position(self):
        self.seed(self.ctx)
        self.assertIsNone(self.t.submit_load(self.job(1, [key("a2"), key("a3")], [9, 4])))
        _, keys, parents, pos, offs = self.client.fetch_calls[0]
        self.assertEqual(offs, [9 * SLOT, 4 * SLOT])  # chain position would give 1*SLOT, 2*SLOT
        self.assertEqual(pos, [2 * TPC, 3 * TPC])
        self.assertEqual(parents, [key("a1"), key("a2")])
        self.assertEqual(self.client.regions_used, [1])  # the attach_region id

    def test_store_offsets_and_is_promotion(self):
        self.assertIsNone(self.t.submit_store(self.job(2, [key("a1"), key("a2")], [7, 3], promo=False)))
        _, _, _, _, offs = self.client.store_calls[0]
        self.assertEqual(offs, [7 * SLOT, 3 * SLOT])
        self.assertEqual(self.client.regions_used, [1])

    def test_chunk_ids_numpy_like_ints(self):
        class I:  # np.int64-like
            def __init__(self, v):
                self.v = v

            def __int__(self):
                return self.v

        self.seed(self.ctx)
        self.t.submit_load(self.job(3, [key("a1")], [I(5)]))
        self.assertEqual(self.client.fetch_calls[0][4], [5 * SLOT])

    def test_chunk_ids_length_mismatch_fails_job(self):
        self.seed(self.ctx)
        self.t.submit_load(self.job(4, [key("a1"), key("a2")], [1]))
        (r,) = self.t.get_finished_jobs()
        self.assertFalse(r.success)
        self.assertEqual(self.client.fetch_calls, [])


class TestJobs(Base):
    def test_load_ok_result_by_keyword(self):  # 2c
        self.seed(self.ctx)
        self.assertIsNone(self.t.submit_load(self.job(1, [key("a2"), key("a3")])))
        (r,) = self.t.get_finished_jobs()
        self.assertIsInstance(r, tbase.JobResult)
        self.assertEqual((r.job_id, r.success), (1, True))
        self.assertEqual(r.successful_keys, [key("a2"), key("a3")])
        self.assertIsNone(r.transfer_time)  # an Event once landed here (positional bug)
        self.assertIsNone(r.transfer_bytes)
        self.assertIsNone(r.deferred_release)

    def test_store_result_has_no_successful_keys(self):
        self.t.submit_store(self.job(1, [key("a1"), key("a2")], promo=False))
        (r,) = self.t.get_finished_jobs()
        self.assertTrue(r.success)
        self.assertIsNone(r.successful_keys)
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.HIT)

    def test_store_skip_is_success(self):
        self.client.future_client = True
        self.client.store_reply = StoreReply("SKIP")
        self.t.submit_store(self.job(1, [key("a1")], promo=False))
        (r,) = self.t.get_finished_jobs()
        self.assertTrue(r.success)

    def test_store_refused_drops_job(self):
        self.client.future_client = True
        self.client.store_reply = StoreReply("REFUSED", retry_after_ms=0)
        self.t.submit_store(self.job(1, [key("a1")], promo=False))
        (r,) = self.t.get_finished_jobs()
        self.assertFalse(r.success)

    def test_miracache_skip_fails_job(self):
        self.ctx.kv_transfer_params = {"miracache": {"skip": True}}
        self.t.submit_load(self.job(5, [key("a1")]))
        (r,) = self.t.get_finished_jobs()
        self.assertEqual((r.job_id, r.success), (5, False))

    def test_drain_reopens_intake(self):
        # vLLM calls drain_jobs() from reset_cache() and keeps going: the tier must keep serving.
        self.seed(self.ctx)
        self.t.submit_load(self.job(8, [key("a1")]))
        self.t.drain_jobs()
        self.assertEqual([(r.job_id, r.success) for r in self.t.get_finished_jobs()], [(8, True)])
        self.assertFalse(self.t.has_pending_work())  # drain guarantee: nothing survives it
        self.assertIs(self.t.lookup(key("a1"), self.ctx), LookupResult.HIT)
        self.t.submit_load(self.job(9, [key("a1")]))
        (r,) = self.t.get_finished_jobs()
        self.assertEqual((r.job_id, r.success), (9, True))

    def test_drain_timeout_keeps_tier_closed(self):
        t = self.t = self.make(client=TestDeferredRelease.never_releasing(), drain_timeout_s=0.05)
        t.on_new_request(self.ctx)
        t.submit_load(self.job(1, [key("a1")]))
        t.drain_jobs()
        t.get_finished_jobs()
        t.submit_load(self.job(2, [key("a1")]))
        (r,) = t.get_finished_jobs()
        self.assertEqual((r.job_id, r.success), (2, False))  # client was closed by the timeout

    def test_submit_returns_none_and_internal_error_gives_failed_result(self):  # 4a
        self.ctx._offload_key_positions = ["not", "a", "dict"]  # tier-level error in _job()
        for jid, fn, promo in ((3, self.t.submit_load, True), (4, self.t.submit_store, False)):
            self.assertIsNone(fn(self.job(jid, [key("a2")], promo=promo)))
        res = {r.job_id: r for r in self.t.get_finished_jobs()}
        self.assertEqual(set(res), {3, 4})  # never a silently open job
        self.assertFalse(res[3].success or res[4].success)

    def test_keyword_call_param_name(self):  # 4a: param is job_metadata
        self.seed(self.ctx)
        self.t.submit_load(job_metadata=self.job(6, [key("a1")]))
        (r,) = self.t.get_finished_jobs()
        self.assertEqual((r.job_id, r.success), (6, True))

    def test_core_errors_give_failed_results(self):
        self.client.raise_on = {"fetch", "store"}
        self.seed(self.ctx)
        self.t.submit_load(self.job(1, [key("a2")]))
        self.t.submit_store(self.job(2, [key("a2")], promo=False))
        res = {r.job_id: r.success for r in self.t.get_finished_jobs()}
        self.assertEqual(res, {1: False, 2: False})

    def test_never_raises(self):
        self.client.raise_on = {"derive", "lookup_nb", "fetch", "store", "poll"}
        self.seed(self.ctx)
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.MISS)
        self.t.submit_load(self.job(1, [key("a2")]))
        self.t.submit_store(self.job(2, [key("a2")], promo=False))
        self.t.get_finished_jobs()
        self.t.drain_jobs()
        self.t.shutdown()
        self.t.on_request_finished(self.ctx)
        self.assertIs(self.t.lookup(key("a2"), object()), LookupResult.MISS)

    def test_non_dict_private_field_is_a_miss_not_a_raise(self):
        self.ctx._offload_key_positions = ["not", "a", "dict"]
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.MISS)


class TestDeferredRelease(Base):  # 2d
    @staticmethod
    def never_releasing():
        c = FakeClient()
        c.release_after = 10 ** 9  # the client never releases
        c.future_client = True
        return c

    def failing_load(self, jid=7, keys=("a1", "a2", "a3"), fail="a3"):
        self.seed(self.ctx)
        self.client.fail_keys.add(key(fail))
        self.client.future_client = True
        self.client.defer_release = True
        self.t.submit_load(self.job(jid, [key(k) for k in keys]))
        (r,) = self.t.get_finished_jobs()
        return r

    def test_failed_promotion_gets_event_set_on_release(self):
        r = self.failing_load()
        self.assertFalse(r.success)
        self.assertEqual(r.successful_keys, [key("a1"), key("a2")])
        self.assertIsInstance(r.deferred_release, tbase.threading.Event)
        self.assertFalse(r.deferred_release.is_set())
        self.assertTrue(self.t.has_pending_work())
        for _ in range(5):
            self.t.get_finished_jobs()
        self.assertTrue(r.deferred_release.is_set())
        self.assertFalse(self.t.has_pending_work())

    def test_drain_sets_pending_events(self):
        r = self.failing_load(keys=("a2", "a3"))
        self.t.drain_jobs()
        self.assertTrue(r.deferred_release.is_set())

    def test_drain_timeout_still_sets_events(self):
        t = self.t = self.make(client=self.never_releasing(), drain_timeout_s=0.05)
        r = self.failing_load()
        t.drain_jobs()
        self.assertTrue(r.deferred_release.is_set())
        self.assertGreaterEqual(t._core.counters.get("drain_timeout", 0), 1)

    def test_shutdown_after_drain_timeout_sets_events_and_closes(self):
        t = self.t = self.make(client=self.never_releasing(), drain_timeout_s=0.05)
        r = self.failing_load()
        t.shutdown()
        self.assertTrue(r.deferred_release.is_set())
        self.assertTrue(self.client.closed)  # close() also drops the region (real client)

    def test_clean_shutdown_detaches_then_closes(self):
        self.t.shutdown()
        self.assertEqual(self.client.detached, [1])
        self.assertTrue(self.client.closed)

    def test_drain_timeout_closes_client_before_setting_events(self):  # R09
        t = self.t = self.make(client=self.never_releasing(), drain_timeout_s=0.05)
        r = self.failing_load()
        self.client.delay_polls = 10 ** 9  # a second load that never completes
        t.submit_load(self.job(8, [key("a1")]))
        seen = []
        self.client.on_close = lambda: seen.append(r.deferred_release.is_set())
        t.drain_jobs()
        self.assertEqual(seen, [False])  # event still unset while the client's I/O was live
        self.assertTrue(r.deferred_release.is_set())
        res = {x.job_id: x.success for x in t.get_finished_jobs()}
        self.assertEqual(res, {8: False})  # the open job got a JobResult
        self.assertFalse(t.has_pending_work())

    def test_event_created_after_drain_is_already_set(self):
        t = self.t = self.make(client=self.never_releasing(), drain_timeout_s=0.05)
        self.seed(self.ctx)
        self.client.fail_keys.add(key("a2"))
        self.client.future_client = True
        self.client.defer_release = True
        t.submit_load(self.job(1, [key("a1"), key("a2")]))
        t.drain_jobs()  # result not fetched yet
        (r,) = t.get_finished_jobs()
        self.assertTrue(r.deferred_release.is_set())

    def test_no_event_for_store_or_successful_promotion(self):
        self.seed(self.ctx)
        self.client.future_client = True
        self.client.defer_release = True
        self.t.submit_store(self.job(1, [key("a1")], promo=False))
        self.t.submit_load(self.job(2, [key("a2")]))
        self.assertEqual(self.t.get_finished_jobs(), [])  # held until the client released
        out = []
        for _ in range(6):
            out += self.t.get_finished_jobs()
        self.assertEqual({r.job_id: r.success for r in out}, {1: True, 2: True})
        for r in out:
            self.assertIsNone(r.deferred_release)  # manager.py:573-574, 627-629 assert None

    def test_held_results_flushed_by_drain(self):
        t = self.t = self.make(client=self.never_releasing(), drain_timeout_s=0.05)
        self.seed(self.ctx)
        self.client.future_client = True
        self.client.defer_release = True
        t.submit_store(self.job(1, [key("a1")], promo=False))
        self.assertEqual(t.get_finished_jobs(), [])
        t.drain_jobs()
        (r,) = t.get_finished_jobs()
        self.assertEqual((r.job_id, r.success), (1, True))

    def test_no_path_leaves_event_unset(self):
        # Mixed bag, then drain: every event handed out is set.
        evs = []
        self.seed(self.ctx)
        self.client.future_client = True
        self.client.defer_release = True
        self.client.fail_keys.update({key("a2"), key("a3")})
        for i, k in enumerate(("a2", "a3"), start=1):
            self.t.submit_load(self.job(i, [key("a1"), key(k)]))
        evs += [r.deferred_release for r in self.t.get_finished_jobs()]
        self.t.drain_jobs()
        evs += [r.deferred_release for r in self.t.get_finished_jobs()]
        self.assertTrue(evs and all(e is not None and e.is_set() for e in evs))

    def test_field_absent_in_0_32_0_33_never_used(self):
        orig = tbase.JobResult
        tbase.JobResult = tbase.JobResultV033
        try:
            self.assertFalse(compat.has_deferred_release(tbase.JobResult))
            cls = vllm_tier._build()
            t = self.make(cls=cls)
            self.t = t
            r_all = []
            self.seed(self.ctx)
            self.client.fail_keys.add(key("a3"))
            self.client.future_client = True
            self.client.defer_release = True
            t.submit_load(self.job(7, [key("a1"), key("a3")]))
            self.assertEqual(t.get_finished_jobs(), [])  # held, no Event can be expressed
            for _ in range(6):
                r_all += t.get_finished_jobs()
            (r,) = r_all
            self.assertFalse(r.success)
            self.assertFalse(hasattr(r, "deferred_release"))
        finally:
            tbase.JobResult = orig


class TestNamespace(Base):  # R02
    def test_ns_is_32_bytes_and_reaches_derive(self):
        self.seed(self.ctx)
        self.assertIs(self.t.lookup(key("a2"), self.ctx), LookupResult.HIT)
        ns = self.client.derive_calls[0][0]["ns"]
        self.assertIsInstance(ns, bytes)
        self.assertEqual(len(ns), 32)
        self.assertEqual(ns, self.t._core._layout.ns)

    def test_ns_deterministic_and_sensitive(self):
        base = compat.namespace_digest(make_spec(), SLOT, (TPC,), "0.34.0")
        self.assertEqual(base, compat.namespace_digest(make_spec(), SLOT, (TPC,), "0.34.0"))

        def spec_with(**over):
            s = make_spec()
            cfg = s.config
            model = OffloadingModelConfig(over.get("model", "m"), over.get("dtype", "fp8"))
            par = OffloadingParallelConfig(over.get("rank", 0), over.get("world", 1),
                                           over.get("tp", 1), 1, 1, 1, 0, 1, None, True)
            return OffloadingSpec(OffloadingConfig(
                groups=cfg.groups, worker_kv_bytes_per_block=SLOT, enable_kv_cache_events=False,
                extra_config={}, engine_id="other-engine", model=model, cache=cfg.cache,
                parallel=par, canonical_layout=True))

        self.assertEqual(base, compat.namespace_digest(spec_with(), SLOT, (TPC,), "0.34.0"))
        for d in (compat.namespace_digest(spec_with(model="m2"), SLOT, (TPC,), "0.34.0"),
                  compat.namespace_digest(spec_with(dtype="bf16"), SLOT, (TPC,), "0.34.0"),
                  compat.namespace_digest(spec_with(rank=1, world=2, tp=2), SLOT, (TPC,), "0.34.0"),
                  compat.namespace_digest(spec_with(tp=2, world=2), SLOT, (TPC,), "0.34.0"),
                  compat.namespace_digest(make_spec(), 2 * SLOT, (TPC,), "0.34.0"),
                  compat.namespace_digest(make_spec(), SLOT, (2 * TPC,), "0.34.0"),
                  compat.namespace_digest(make_spec(), SLOT, (TPC,), "0.34.1"),
                  compat.namespace_digest(make_spec(), SLOT, (TPC,), "0.34.0", "rev2")):
            self.assertNotEqual(d, base)

    def test_ns_golden_vectors(self):
        # Pinned before the encoding moved to miracache/ns.py: vLLM's ns bytes (and so every
        # vLLM scope ID and key) must not change. A new value here is a deliberate cold cache.
        old = os.environ.get("PYTHONHASHSEED")
        try:
            os.environ["PYTHONHASHSEED"] = "0"
            self.assertEqual(compat.namespace_digest(make_spec(), SLOT, (TPC,), "0.34.0").hex(),
                             "9fd6394eb66d300430d925b6793ebe6873673101255922b1501e6baa4e890b02")
            os.environ.pop("PYTHONHASHSEED")
            self.assertEqual(compat.namespace_digest(make_spec(), SLOT, (TPC,), "0.34.0", "rev1").hex(),
                             "6dfb3debd6d8b059b8a23efa41fd5830e699a3544edcb58240cc504c5fa56c9f")
        finally:
            if old is None:
                os.environ.pop("PYTHONHASHSEED", None)
            else:
                os.environ["PYTHONHASHSEED"] = old

    def test_ns_fields_tier_key(self):
        base = self.make()._core._layout.ns
        self.assertEqual(self.make(ns_fields={})._core._layout.ns, base)  # empty = not in ns
        q = self.make(ns_fields={"quantization": "fp8"})._core._layout.ns
        self.assertNotEqual(q, base)
        self.assertEqual(self.make(ns_fields={"quantization": "fp8"})._core._layout.ns, q)
        self.assertNotEqual(self.make(ns_fields={"quantization": "awq"})._core._layout.ns, q)

    def test_bad_ns_fields_refuse_before_the_client_opens(self):
        opened = []
        base = vllm_tier.MiraTier
        sub = type("T", (base,), {"client_factory": staticmethod(lambda p: opened.append(p) or FakeClient())})
        for bad in (["x"], {"x": float("nan")}, {1: "x"}):
            with self.assertRaises(compat.CompatError):
                sub(offloading_spec=make_spec(), primary_kv_view=make_view(), tier_type="MiraTier",
                    backpressure_detector=None, config="/x/client.toml", ns_fields=bad,
                    kv_load_failure_policy="recompute")
        self.assertEqual(opened, [])

    def test_refuses_without_the_recompute_promise(self):  # s12 C3
        opened = []
        sub = type("T", (vllm_tier.MiraTier,), {"client_factory": staticmethod(lambda p: opened.append(p) or FakeClient())})
        for kw in ({}, {"kv_load_failure_policy": "fail"}):
            with self.assertRaises(compat.CompatError) as cm:
                sub(offloading_spec=make_spec(), primary_kv_view=make_view(), tier_type="MiraTier",
                    backpressure_detector=None, config="/x/client.toml", **kw)
            self.assertIn("kv_load_failure_policy", str(cm.exception))
        self.assertEqual(opened, [])

    def test_real_engine_policy_is_checked_when_visible(self):  # s12 C3
        with mock.patch.object(vllm_tier, "_engine_failure_policy", return_value="fail"):
            with self.assertRaises(compat.CompatError):
                self.make()
        with mock.patch.object(vllm_tier, "_engine_failure_policy", return_value="recompute"):
            self.assertIsNotNone(self.make()._core)

    def test_model_revision_tier_key(self):
        a = self.make(model_revision="abc")._core._layout.ns
        b = self.make(model_revision="def")._core._layout.ns
        self.assertNotEqual(a, b)

    def test_missing_model_refuses(self):
        s = make_spec()
        cfg = s.config
        bad = OffloadingSpec(OffloadingConfig(
            groups=cfg.groups, worker_kv_bytes_per_block=SLOT, enable_kv_cache_events=False,
            extra_config={}, engine_id="e0", model=OffloadingModelConfig("", "fp8"),
            cache=cfg.cache, parallel=cfg.parallel, canonical_layout=True))
        with self.assertRaises(compat.CompatError):
            self.make(spec=bad)


class TestJobBounds(Base):  # R19
    def test_chunk_id_beyond_primary_view_fails_job(self):
        self.seed(self.ctx)
        self.t.submit_load(self.job(1, [key("a1")], [NSLOTS]))
        self.t.submit_store(self.job(2, [key("a1")], [-1], promo=False))
        self.t.submit_load(self.job(3, [key("a1")], [NSLOTS - 1]))
        res = {r.job_id: r.success for r in self.t.get_finished_jobs()}
        self.assertEqual(res, {1: False, 2: False, 3: True})
        self.assertEqual(len(self.client.fetch_calls), 1)
        self.assertEqual(self.client.store_calls, [])

    def test_multi_group_job_fails(self):
        ctx = ReqContext("rg")
        ctx._offload_key_positions.update({**chain("a", 2, 0), **chain("c", 2, 1)})
        self.seed(ctx)
        self.t.submit_load(self.job(1, [key("a1", 0), key("c1", 1)], ctx=ctx))
        (r,) = self.t.get_finished_jobs()
        self.assertFalse(r.success)
        self.assertEqual(self.client.fetch_calls, [])


def _real_lib():
    p = os.environ.get("MIRACACHE_LIB")
    return p if p and os.path.isfile(p) else None


@unittest.skipIf(_real_lib() is None, "set MIRACACHE_LIB to the built libmiracache.so")
class TestRealClient(unittest.TestCase):
    """MiraTier against the real ctypes client (miracache._core.Client.open_loopback): the
    lookup -> store -> lookup -> load path with real derive (32-byte ns), real PENDING lookups
    and real bytes in the primary view. The fake hid R02; this test does not."""

    def setUp(self):
        from miracache._core import Client
        self.client = Client.open_loopback()
        self.buf = bytearray(NSLOTS * SLOT)
        self.view = memoryview(self.buf).cast("B", shape=[NSLOTS, SLOT])
        sub = type("T", (vllm_tier.MiraTier,), {"client_factory": staticmethod(lambda p: self.client)})
        self.t = sub(offloading_spec=make_spec(), primary_kv_view=self.view, tier_type="MiraTier",
                     backpressure_detector=None, config="/x/client.toml", drain_timeout_s=5.0,
                     kv_load_failure_policy="recompute")
        self.ctx = ReqContext("real1")
        self.ctx._offload_key_positions.update(chain("a", 3))
        self.t.on_new_request(self.ctx)

    def tearDown(self):
        self.t.shutdown()

    def lookup(self, k):
        import time
        end = time.monotonic() + 5
        while True:
            r = self.t.lookup(k, self.ctx)
            if r is not LookupResult.RETRY or time.monotonic() > end:
                return r
            self.client.wait_event(10)

    def finish(self, n):
        import time
        out, end = [], time.monotonic() + 5
        while len(out) < n and time.monotonic() < end:
            out += self.t.get_finished_jobs()
            if len(out) < n:
                self.client.wait_event(10)
        return out

    def test_lookup_store_lookup_load(self):
        keys = [key("a1"), key("a2"), key("a3")]
        self.assertIs(self.t.lookup(keys[1], self.ctx), LookupResult.RETRY)  # real: PENDING first
        self.assertIs(self.lookup(keys[1]), LookupResult.MISS)
        for i in range(3):  # recognisable bytes in primary slots 2, 3, 4
            self.buf[(i + 2) * SLOT:(i + 3) * SLOT] = bytes([i + 1]) * SLOT
        self.t.submit_store(self.job(1, keys, [2, 3, 4], promo=False))
        (r,) = self.finish(1)
        self.assertEqual((r.job_id, r.success), (1, True))
        self.assertEqual(self.t._core.counters, {})
        for k in keys:
            self.assertIs(self.lookup(k), LookupResult.HIT, k)
        self.t.submit_load(self.job(2, keys[1:], [10, 11]))
        (r,) = self.finish(1)
        self.assertEqual((r.job_id, r.success), (2, True))
        self.assertEqual(r.successful_keys, keys[1:])
        self.assertEqual(bytes(self.buf[10 * SLOT:11 * SLOT]), bytes([2]) * SLOT)
        self.assertEqual(bytes(self.buf[11 * SLOT:12 * SLOT]), bytes([3]) * SLOT)

    def job(self, jid, keys, chunk_ids, promo=True):
        return TransferJob(jid, keys, chunk_ids, promo, self.ctx)

    def test_unknown_root_misses(self):
        other = ReqContext("real2")
        other._offload_key_positions.update(chain("z", 2))
        self.t.on_new_request(other)
        r = self.t.lookup(key("z2"), other)
        self.assertIn(r, (LookupResult.RETRY, LookupResult.MISS))
        self.assertEqual(self.t._core.counters, {})  # no derive / lookup error


class TestRefusal(Base):
    def refuses(self, **over):
        with self.assertRaises(compat.CompatError):
            self.make(make_spec(**over))

    def test_bad_offloading_config(self):  # 5a: only what OffloadingConfig holds
        self.refuses(canonical=False)
        self.refuses(pp=2)
        self.refuses(pcp=2)
        self.refuses(dcp=2)

    def test_version_range(self):  # 6b
        old = vllm.__version__
        try:
            for v, ok in (("0.31.9", False), ("0.32.0", True), ("0.34.0", True),
                          ("0.34.1.dev5+g65711a1", True), ("0.35.0", False), ("dev", True)):
                vllm.__version__ = v
                if ok:
                    self.make()
                else:
                    with self.assertRaises(compat.CompatError, msg=v):
                        self.make()
        finally:
            vllm.__version__ = old

    def test_private_field_missing(self):
        import vllm.v1.kv_offload.base as b

        class Bare:  # a ReqContext without the private field
            req_id = ""

        errs = compat.check_req_context_class(Bare)
        self.assertTrue(errs and compat.PRIVATE_FIELD in errs[0])
        self.assertEqual(compat.check_req_context_class(b.ReqContext), [])
        orig = b.ReqContext
        b.ReqContext = Bare
        try:
            with self.assertRaises(compat.CompatError):
                self.make()
        finally:
            b.ReqContext = orig

    def test_private_field_not_dict(self):
        with self.assertRaises(compat.CompatError):
            compat.positions_of(NS(_offload_key_positions=[1]))
        with self.assertRaises(compat.CompatError):
            compat.positions_of(NS())

    def test_signature_drift(self):
        class Base2:
            def lookup(self, key):  # one parameter short
                pass

        errs = compat.check_signatures(Base2)
        self.assertTrue(any("lookup" in e for e in errs))
        self.assertTrue(any("submit_load is missing" in e for e in errs))

    def test_init_signature_probe(self):  # 1b
        class Old:
            def __init__(self, vllm_config, tier_config):
                pass

        self.assertTrue(compat.check_init_signature(Old))
        self.assertEqual(compat.check_init_signature(tbase.SecondaryTierManager), [])

    def test_job_type_probe(self):  # 2a, 2c
        class OldJob:
            job_id: int
            keys: list
            req_context: object

        errs = compat.check_job_types(OldJob, tbase.JobResult)
        self.assertTrue(errs and "chunk_ids" in errs[0] and "is_promotion" in errs[0])
        self.assertEqual(compat.check_job_types(TransferJob, tbase.JobResult), [])


class TestFakeMirrorsUpstream(unittest.TestCase):  # 3b, 3c, 3e, 4b
    def test_req_context_helpers(self):
        c = ReqContext("x")
        self.assertIsNone(c.kv_transfer_params)
        self.assertIsNone(c.get_offload_key_position(b"k"))
        c.set_offload_key_position(b"k", 32)
        self.assertEqual(c.get_offload_key_position(b"k"), 32)
        c.set_state(NS)
        self.assertIs(c.get_state(type(NS)), NS)
        self.assertIsNone(c.get_state(int))

    def test_lookup_result_members(self):
        self.assertEqual([m.name for m in LookupResult], ["MISS", "HIT", "HIT_PENDING", "RETRY"])


class TestCompat(unittest.TestCase):
    def test_versions(self):
        self.assertEqual(compat.check_version("0.32.0"), [])
        self.assertEqual(compat.check_version("0.33.1.dev12+gabc"), [])
        self.assertEqual(compat.check_version("0.34.2"), [])
        self.assertTrue(compat.check_version("0.35.0"))
        self.assertTrue(compat.check_version("garbage"))


class TestBlockSizeCheck(Base):  # review s9 K03
    def setUp(self):
        pass

    def test_refuses_when_a_node_cannot_hold_one_slot(self):
        c = FakeClient()
        c.max_block = SLOT - 1
        with self.assertRaises(compat.CompatError) as cm:
            self.make(client=c)
        msg = str(cm.exception)
        for part in ("MiraTier refuses to start", "vLLM chunk slot", str(SLOT), "memory node 7", "mn-a",
                     "10.0.0.10:7471", "store.run_bytes"):
            self.assertIn(part, msg)
        self.assertEqual(c.block_checks, [SLOT])
        self.assertEqual(c.attached, [])  # refused before the primary view is registered
        self.assertTrue(c.closed)  # V03: the open client is closed on a refused start

    def test_fits_or_unknown_limit_starts(self):
        for limit in (None, SLOT):
            c = FakeClient()
            c.max_block = limit
            t = self.make(client=c)
            self.assertEqual(c.block_checks, [SLOT])
            t.shutdown()

    def test_helper_tolerates_old_libraries_and_other_errors(self):
        from miracache._core import E_INTERNAL, MiraError, block_size_refusal
        lg = logging.getLogger("miracache.test_block")
        self.assertIsNone(block_size_refusal(object(), 1, "x", lg))  # no check at all (old fake)
        with self.assertLogs(lg, level="WARNING"):
            self.assertIsNone(block_size_refusal(NS(check_block_size=lambda b: -1), 1, "x", lg))  # ABI < 1.2

        def boom(_):
            raise MiraError(E_INTERNAL, "boom")
        with self.assertLogs(lg, level="WARNING"):
            self.assertIsNone(block_size_refusal(NS(check_block_size=boom), 1, "x", lg))


if __name__ == "__main__":
    logging.basicConfig()
    unittest.main()
