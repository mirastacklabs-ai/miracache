import inspect
import json
import os
import sys
import threading
import types
import unittest
from unittest import mock

HERE = os.path.dirname(__file__)
sys.path.insert(0, HERE)

from fake_client import FakeClient  # noqa: E402
from fake_sglang import (REAL_SIGNATURES, FakeMHAHostPool, FakeMLAKVSplitHostPool,  # noqa: E402
                         HiCacheStorageConfig, HiCacheStorageExtraInfo, PoolTransfer,
                         PoolTransferResult, all_layouts, build_dynamic_backend)
from miracache.sglang import MiraHiCacheStorage, MiraRefusal  # noqa: E402
from miracache.sglang import storage as st  # noqa: E402
from miracache import ns as ns_mod  # noqa: E402
from miracache.vllm.core import Completion, StoreReply  # noqa: E402

PS = 64
EXAMPLE = os.path.join(HERE, "..", "..", "deploy", "sglang", "extra-config.example.json")


class RegionClient(FakeClient):
    """Fake client with the real region API: bytes move between the attached region and a store.

    Like the real client, an op reads/writes the memory it was given until it completes, even
    after detach_region. ``late_next = n`` makes the next n fetch/put ops "late": they do not
    complete on their own; ``finish_late()`` (or ``finish_on_poll``) runs them later, touching
    the region buffer they were submitted with. ``tick`` advances ``clock[0]`` on every poll."""

    def __init__(self, clock=None, tick=0.0):
        super().__init__()
        self.regions = {}
        self.data = {}  # (scope, key) -> bytes
        self.region_calls = []
        self.deadlines = []
        self.late_next = 0
        self.late = {}  # ticket -> (kind, scope, keys, offsets, lengths, buf)
        self.finish_on_poll = False
        self.clock, self.tick = clock, tick
        self._rid = 0

    def attach_region(self, buf, block_bytes=0):
        self._maybe_raise("attach_region")
        self._rid += 1
        self.regions[self._rid] = (buf, block_bytes)
        self.attached.append((buf, block_bytes))
        return self._rid

    def detach_region(self, region):
        self.detached.append(region)
        self.regions.pop(region, None)

    def derive(self, meta, group):
        self._maybe_raise("derive")
        assert len(meta["ns"]) == 32
        self.derive_calls.append((dict(meta), group))
        return ("scope", meta["ns"], meta["roots"][group])

    def lookup_nb(self, scope, key, parent=None, deadline_ms=0):
        self._maybe_raise("lookup_nb")
        if self.clock is not None:
            self.clock[0] += self.lookup_tick
        return self._answer(scope, key)

    def _answer(self, scope, key):
        left = self.pending_lookups.get(key, 0)
        if left > 0:
            self.pending_lookups[key] = left - 1
            return "PENDING"
        return "HIT" if (scope, key) in self.data else "MISS"

    lookup_submissions = 0
    lookup_tick = 0.0  # clock cost of one lookup submission (an RTT)

    def lookup_many(self, scope, keys, parents=None, deadline_ms=0):
        """One submission for n keys, like the real client: one RTT, per-key answers."""
        self.lookup_submissions += 1
        self.lookup_deadlines.append(deadline_ms)
        if self.clock is not None:
            self.clock[0] += self.lookup_tick
        self._maybe_raise("lookup_nb")
        return [self._answer(scope, k) for k in keys]

    def _run(self, kind, scope, keys, offsets, lengths, buf):
        ok = []
        for k, o, n in zip(keys, offsets, lengths):
            if kind == "fetch":
                if k not in self.fail_keys and (scope, k) in self.data:
                    buf[o:o + n] = self.data[(scope, k)]
                    ok.append(k)
            else:
                self.data[(scope, k)] = bytes(buf[o:o + n])
                ok.append(k)
        return ok

    def _op(self, kind, scope, keys, offsets, lengths, region):
        buf = self.regions[region][0]
        t = self._ticket()
        if self.late_next > 0:
            self.late_next -= 1
            self.late[t] = (kind, scope, list(keys), list(offsets), list(lengths), buf)
            return t
        ok = self._run(kind, scope, keys, offsets, lengths, buf)
        self._queue.append([self.delay_polls, Completion(
            t, success=len(ok) == len(keys), successful_keys=ok, deferred_release=self.defer_release)])
        if self.defer_release:
            self._release_queue.append([self.delay_polls + self.release_after,
                                        Completion(t, released=True)])
        return t

    def finish_late(self, only=None):
        for t, (kind, scope, keys, offs, lens, buf) in list(self.late.items()):
            if only is not None and t != only:
                continue
            ok = self._run(kind, scope, keys, offs, lens, buf)
            self._queue.append([0, Completion(t, success=len(ok) == len(keys), successful_keys=ok)])
            del self.late[t]

    def fetch(self, scope, keys, parents=None, positions=None, offsets=None, deadline_ms=0,
              lengths=None, region=None):
        self._maybe_raise("fetch")
        self.fetch_calls.append((scope, list(keys), list(parents), list(positions), list(offsets)))
        self.region_calls.append(("fetch", region, list(lengths)))
        self.deadlines.append(deadline_ms)
        return self._op("fetch", scope, keys, offsets, lengths, region)

    def put(self, scope, keys, parents=None, positions=None, offsets=None, deadline_ms=0,
            lengths=None, region=None):
        self._maybe_raise("put")
        self.store_calls.append((scope, list(keys), list(parents), list(positions), list(offsets)))
        self.region_calls.append(("put", region, list(lengths)))
        self.deadlines.append(deadline_ms)
        return self._op("put", scope, keys, offsets, lengths, region)

    def store(self, scope, keys, parents=None, positions=None, offsets=None, lengths=None, region=None):
        """Legacy path (older adapters used it); the real client's store has no deadline."""
        self._maybe_raise("store")
        return StoreReply("OK", self.put(scope, keys, parents, positions, offsets, 0, lengths, region))

    def poll(self):
        self._maybe_raise("poll")
        if self.clock is not None:
            self.clock[0] += self.tick
        if self.finish_on_poll:
            self.finish_on_poll = False
            self.finish_late()
        return super().poll()


class CancelClient(RegionClient):
    """Supports cancel(ticket): the op stops promptly and completes (no bytes moved)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.cancelled = []

    def cancel(self, ticket):
        self.cancelled.append(ticket)
        if ticket in self.late:
            del self.late[ticket]
            self._queue.append([0, Completion(ticket, success=False, successful_keys=[])])


def cfg(tp_rank=0, tp_size=1, flag=True, **over):
    e = {"hicache_storage_pass_prefix_keys": True, "interface_v1": 1}
    if flag:
        e["miracache_expect_prefix_keys"] = True
    e.update(over.pop("extra", {}))
    return HiCacheStorageConfig(tp_rank=tp_rank, tp_size=tp_size, extra_config=e, **over)


def make(client=None, pool=None, clock=None, **kw):
    client = client or RegionClient()
    pool = pool or FakeMHAHostPool(PS)
    ckw = {"clock": clock} if clock is not None else {}
    s = build_dynamic_backend(lambda c, k: MiraHiCacheStorage(c, k, client=client, **ckw), cfg(**kw), pool)
    return s, client, pool


def make_timed(cls=RegionClient, pool=None, **kw):
    """Adapter + client sharing a fake clock that jumps 1 s per poll (timeouts in a few polls)."""
    t = [0.0]
    c = cls(clock=t, tick=1.0)
    s, c, pool = make(c, pool, clock=lambda: t[0], **kw)
    return s, c, pool


def info(prefix):
    return HiCacheStorageExtraInfo(prefix_keys=prefix)


KEYS = ["k%d" % i for i in range(4)]


def fill(pool, pages, seed=1):
    """Distinct bytes in every buffer of every page; returns {page: blobs}."""
    out = {}
    for p in pages:
        _, sizes = pool.get_page_buffer_meta(pool.tokens(p))
        blobs = [bytes(((seed * 31 + p * 7 + j * 13 + i) % 251) + 1 for i in range(s))
                 for j, s in enumerate(sizes)]
        pool.write_page(p, blobs)
        out[p] = blobs
    return out


def zero(pool, page):
    return all(set(b) == {0} for b in pool.read_page(page))


class TestRoundTrip(unittest.TestCase):
    def test_every_layout_roundtrips_all_buffers(self):
        """K and V (and every layer / kv-split buffer) survive."""
        for name, mk, bpp in all_layouts(PS, 8):
            with self.subTest(name):
                s, c, pool = make(pool=mk())
                self.assertEqual(s.buffers_per_page, bpp)
                _, sizes = pool.get_page_buffer_meta(pool.tokens(0))
                self.assertEqual(s.block_bytes, sum(sizes))
                src = fill(pool, [0, 1, 2, 3])
                self.assertEqual(s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([])), [True] * 4)
                for p in (4, 5, 6, 7):  # destination pages start zeroed
                    self.assertTrue(zero(pool, p))
                self.assertEqual(s.batch_get_v1(KEYS, pool.indices([4, 5, 6, 7]), info([])), [True] * 4)
                for sp, dp in zip([0, 1, 2, 3], [4, 5, 6, 7]):
                    self.assertEqual(pool.read_page(dp), src[sp])
                    self.assertEqual(len(pool.read_page(dp)), bpp)
                self.assertEqual(c.region_calls[0][2], [s.block_bytes] * 4)

    def test_kv_split_buffers_have_different_sizes(self):
        """page_first_kv_split returns k, v, index_k, scale per page with distinct sizes."""
        pool = FakeMLAKVSplitHostPool(PS, 8)
        _, sizes = pool.get_page_buffer_meta(pool.tokens(0))
        self.assertEqual(len(set(sizes)), 4)
        s, c, _ = make(pool=pool)
        self.assertEqual(s.buffers_per_page, 4)

    def test_mha_k_and_v_are_distinct_and_both_stored(self):
        s, c, pool = make(pool=FakeMHAHostPool(PS, 8, "page_first"))
        src = fill(pool, [0])
        k, v = src[0]
        self.assertNotEqual(k, v)
        s.batch_set_v1(KEYS[:1], pool.indices([0]), info([]))
        stored = next(iter(c.data.values()))
        self.assertEqual(stored, k + v)  # documented order: buffers concatenated as returned

    def test_put_get_addressing(self):
        s, c, pool = make()
        fill(pool, [0, 1, 2, 3])
        self.assertEqual(s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([])), [True] * 4)
        scope, keys, parents, pos, offs = c.store_calls[0]
        self.assertEqual(keys, [k.encode() for k in KEYS])
        self.assertEqual(parents, [None, b"k0", b"k1", b"k2"])
        self.assertEqual(pos, [PS, 2 * PS, 3 * PS, 4 * PS])
        self.assertEqual(offs, [i * s.block_bytes for i in range(4)])  # staging offsets, not addresses
        self.assertEqual(scope[2], b"k0")

    def test_batch_larger_than_staging_is_chunked(self):
        s, c, pool = make(extra={"miracache_stage_pages": 2})
        src = fill(pool, [0, 1, 2, 3])
        self.assertEqual(s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([])), [True] * 4)
        self.assertEqual(len(c.store_calls), 2)
        self.assertEqual(s.batch_get_v1(KEYS, pool.indices([4, 5, 6, 7]), info([])), [True] * 4)
        self.assertEqual([pool.read_page(d) for d in (4, 5, 6, 7)], [src[i] for i in range(4)])

    def test_root_from_prefix_and_parent(self):
        s, c, pool = make()
        fill(pool, [0, 1])
        self.assertEqual(s.batch_set_v1(["k2", "k3"], pool.indices([0, 1]), info(["k0", "k1"])), [True] * 2)
        scope, _, parents, pos, _ = c.store_calls[0]
        self.assertEqual(scope[2], b"k0")
        self.assertEqual(parents[0], b"k1")
        self.assertEqual(pos, [3 * PS, 4 * PS])
        self.assertEqual(s.batch_exists(["k2", "k3"], info(["k0", "k1"])), 2)

    def test_exists_partial_and_get_partial(self):
        s, c, pool = make()
        fill(pool, [0, 1])
        s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), info([]))
        self.assertEqual(s.batch_exists(KEYS, info([])), 2)
        self.assertEqual(s.batch_get_v1(KEYS, pool.indices([2, 3, 4, 5]), info([])),
                         [True, True, False, False])

    def test_pending_lookup_retries(self):
        s, c, pool = make()
        s.batch_set_v1(KEYS[:1], pool.indices([0]), info([]))
        c.pending_lookups[b"k0"] = 2
        self.assertEqual(s.batch_exists(KEYS[:1], info([])), 1)

    def test_presence_cache(self):
        t = [0.0]
        c = RegionClient()
        pool = FakeMHAHostPool(PS)
        s = build_dynamic_backend(lambda cf, k: MiraHiCacheStorage(cf, k, client=c, clock=lambda: t[0]),
                                  cfg(), pool)
        s.batch_set_v1(KEYS[:1], pool.indices([0]), info([]))
        self.assertEqual(s.batch_exists(KEYS[:1], info([])), 1)
        c.data.clear()
        self.assertEqual(s.batch_exists(KEYS[:1], info([])), 1)  # cached
        t[0] = 0.2
        self.assertEqual(s.batch_exists(KEYS[:1], info([])), 0)

    def test_deferred_release(self):
        s, c, pool = make_timed()
        s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), info([]))
        c.defer_release = True
        self.assertEqual(s.batch_get_v1(KEYS[:2], pool.indices([2, 3]), info([])), [True, True])
        self.assertNotIn("release_timeout", s.counters)


class TestStagingSafety(unittest.TestCase):
    """A region an op may still touch is never reused."""

    def test_every_op_has_a_deadline_shorter_than_the_wait(self):
        s, c, pool = make()
        fill(pool, [0, 1])
        s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), info([]))
        s.batch_get_v1(KEYS[:2], pool.indices([2, 3]), info([]))
        self.assertEqual(len(c.deadlines), 2)
        for d in c.deadlines:
            self.assertGreater(d, 0)
            self.assertLess(d, st.IO_TIMEOUT_S * 1000)

    def test_late_put_never_commits_another_pages_bytes(self):
        s, c, pool = make_timed()
        src = fill(pool, [0, 1, 2, 3])
        c.late_next = 1
        self.assertEqual(s.batch_set_v1(["a0", "a1"], pool.indices([0, 1]), info([])), [False, False])
        self.assertEqual(s.counters.get("io_timeout"), 1)
        self.assertEqual(s.batch_set_v1(["b0", "b1"], pool.indices([2, 3]), info([])), [True, True])
        c.finish_late()  # the old op finally reads its region and commits a0, a1
        want = {b"a0": src[0], b"a1": src[1], b"b0": src[2], b"b1": src[3]}
        for (_scope, k), v in c.data.items():
            self.assertEqual(v, b"".join(want[k]), k)
        self.assertEqual(len(c.data), 4)

    def test_late_fetch_never_scatters_stale_bytes(self):
        s, c, pool = make_timed()
        src = fill(pool, [0, 1, 2, 3])
        self.assertEqual(s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([])), [True] * 4)
        c.late_next = 1
        self.assertEqual(s.batch_get_v1(KEYS[:2], pool.indices([4, 5]), info([])), [False, False])
        self.assertTrue(zero(pool, 4) and zero(pool, 5))
        c.finish_on_poll = True  # the old fetch writes its region while the next one is in flight
        self.assertEqual(s.batch_get_v1(KEYS[2:], pool.indices([6, 7]), info(KEYS[:2])), [True, True])
        self.assertEqual(pool.read_page(6), src[2])
        self.assertEqual(pool.read_page(7), src[3])
        self.assertTrue(zero(pool, 4) and zero(pool, 5))
        # the late op completed, so its quarantined region was retired (detached)
        self.assertEqual(s.counters.get("quarantine_retired"), 1)
        self.assertEqual(c.detached, [1])
        self.assertEqual(s._quarantine, {})

    def test_late_op_region_not_detached_while_live(self):
        s, c, pool = make_timed()
        fill(pool, [0, 1])
        c.late_next = 1
        s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), info([]))
        self.assertEqual(c.detached, [])
        self.assertEqual(len(s._quarantine), 1)
        self.assertEqual(len(c.attached), 2)  # a fresh staging region
        self.assertNotEqual(c.region_calls[-1][1], s._region)

    def test_cancel_when_supported_reuses_region(self):
        s, c, pool = make_timed(CancelClient)
        fill(pool, [0, 1])
        region = s._region
        c.late_next = 1
        self.assertEqual(s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), info([])), [False, False])
        self.assertEqual(len(c.cancelled), 1)
        self.assertEqual(s.counters.get("cancelled"), 1)
        self.assertEqual(s._region, region)
        self.assertEqual(s._quarantine, {})
        self.assertEqual(c.data, {})
        self.assertEqual(s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), info([])), [True, True])

    def test_too_many_live_ops_disable_l3(self):
        s, c, pool = make_timed()
        c.late_next = 100
        for i in range(st.MAX_QUARANTINE + 1):
            s.batch_set_v1(["x%d" % i], pool.indices([0]), info([]))
        self.assertFalse(s.ready)
        n = len(c.store_calls)
        self.assertEqual(s.batch_set_v1(["y"], pool.indices([0]), info([])), [False])
        self.assertEqual(len(c.store_calls), n)

    def test_release_never_arrives_is_a_timeout(self):
        s, c, pool = make_timed()
        fill(pool, [0, 1])
        s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), info([]))
        c.defer_release, c.release_after = True, 10 ** 6
        self.assertEqual(s.batch_get_v1(KEYS[:2], pool.indices([2, 3]), info([])), [False, False])
        self.assertTrue(zero(pool, 2) and zero(pool, 3))
        self.assertEqual(s.counters.get("release_timeout"), 1)
        self.assertEqual(len(s._quarantine), 1)


class TestCompletions(unittest.TestCase):
    """Completions: a same-poll released event is not dropped."""

    def test_same_poll_released_event_is_not_dropped(self):
        s, c, pool = make_timed()
        fill(pool, [0, 1])
        s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), info([]))
        c.defer_release, c.release_after = True, 0  # completion + released in one poll
        self.assertEqual(s.batch_get_v1(KEYS[:2], pool.indices([2, 3]), info([])), [True, True])
        self.assertNotIn("release_timeout", s.counters)
        self.assertEqual(s._quarantine, {})

    def test_first_timeout_aborts_rest_of_batch(self):
        s, c, pool = make_timed(extra={"miracache_stage_pages": 2})
        fill(pool, [0, 1, 2, 3])
        c.late_next = 1
        self.assertEqual(s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([])), [False] * 4)
        self.assertEqual(len(c.store_calls), 1)

    def test_batch_exists_takes_the_lock(self):
        s, c, pool = make()
        held = []

        class Spy:
            def __enter__(self_):
                held.append(True)
                return self_

            def __exit__(self_, *a):
                return False

        s._lock = Spy()
        s.batch_exists(KEYS, info([]))
        self.assertTrue(held)


class TestPrefixKeys(unittest.TestCase):
    def test_none_or_empty_prefix_is_root_batch(self):
        """None (hybrid controller, empty prefix) is a root batch, not a miss."""
        s, c, pool = make()
        fill(pool, [0, 1])
        for ex in (HiCacheStorageExtraInfo(), None, info([])):
            c.data.clear()
            self.assertEqual(s.batch_set_v1(KEYS[:2], pool.indices([0, 1]), ex), [True, True])
            self.assertEqual(c.store_calls[-1][2], [None, b"k0"])
            self.assertEqual(c.store_calls[-1][0][2], b"k0")
            self.assertEqual(s.batch_exists(KEYS[:2], ex), 2)
            self.assertEqual(s.batch_get_v1(KEYS[:2], pool.indices([2, 3]), ex), [True, True])

    def test_root_batches_counted_and_all_root_warns_once(self):
        """A 100% root-batch rate (SGLang flag off) is visible at runtime."""
        s, c, pool = make()
        s.batch_set_v1(["c1"], pool.indices([0]), info(["c0"]))
        self.assertEqual((s.counters["batches"], s.counters.get("root_batches", 0)), (1, 0))
        s2, c2, pool2 = make()
        with self.assertLogs("miracache.sglang", "WARNING") as cm:
            for i in range(st.ROOT_WARN_AFTER + 5):
                s2.batch_set_v1(["r%d" % i], pool2.indices([0]), None)
        self.assertEqual(s2.counters["root_batches"], st.ROOT_WARN_AFTER + 5)
        self.assertEqual(s2.get_stats()["batches"], st.ROOT_WARN_AFTER + 5)
        warns = [m for m in cm.output if "root batches" in m]
        self.assertEqual(len(warns), 1)
        self.assertIn("hicache_storage_pass_prefix_keys", warns[0])


class TestNamespace(unittest.TestCase):
    def test_miss_on_other_tp_size_and_rank(self):
        c = RegionClient()
        pool = FakeMHAHostPool(PS)
        a, _, _ = make(c, pool, tp_rank=0, tp_size=2)
        b, _, _ = make(c, pool, tp_rank=0, tp_size=4)
        r, _, _ = make(c, pool, tp_rank=1, tp_size=2)
        a.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([]))
        self.assertEqual(b.batch_exists(KEYS, info([])), 0)
        self.assertEqual(b.batch_get_v1(KEYS, pool.indices([4, 5, 6, 7]), info([])), [False] * 4)
        self.assertEqual(r.batch_exists(KEYS, info([])), 0)
        a2, _, _ = make(c, pool, tp_rank=0, tp_size=2)
        self.assertEqual(a2.batch_exists(KEYS, info([])), 4)

    def test_other_layout_other_ns(self):
        c = RegionClient()
        a, _, _ = make(c, FakeMHAHostPool(PS, 8, "page_first"))
        b, _, _ = make(c, FakeMHAHostPool(PS, 8, "layer_first"))
        self.assertNotEqual(a.ns, b.ns)


def dtype_pool(dtype="torch.bfloat16", **kw):
    p = FakeMHAHostPool(PS, **kw)
    p.dtype = dtype  # S/mem_cache/pool_host/base.py: self.dtype (the stored dtype)
    return p


class TestNamespaceGolden(unittest.TestCase):
    """The SGLang ns: which fields and the exact bytes. A change here is a deliberate cold
    cache for every SGLang deployment (all scope IDs and keys change)."""

    def make_v(self, version="0.5.23", pool=None, **kw):
        with mock.patch.object(st, "engine_version", return_value=version):
            s, _, _ = make(RegionClient(), pool or dtype_pool(), **kw)
        return s

    def test_fields(self):
        s = self.make_v(tp_rank=1, tp_size=4, extra={"ns_fields": {"model_revision": "abc"}})
        f = st.namespace_fields(s._cfg, s.mem_pool_host, page_size=s.page_size,
                                block_bytes=s.block_bytes, buffers_per_page=s.buffers_per_page,
                                extra=s._extra, version="0.5.23")
        self.assertEqual(f, {
            "engine": "sglang", "engine_version": "0.5.23", "model": "m",
            "kv_dtype": "torch.bfloat16", "tp_rank": 1, "tp_size": 4,
            "attn_cp_rank": 0, "attn_cp_size": 1, "dcp_rank": 0, "dcp_size": 1,
            "tp_lcm_size": None, "should_split_heads": False, "rank_replicated": None,
            "is_mla": False, "page_first": True, "page_size": PS, "block_bytes": s.block_bytes,
            "buffers_per_page": s.buffers_per_page, "key_scheme": "rank-suffix",
            "extra_ns": {"model_revision": "abc"}})
        self.assertEqual(s.ns, ns_mod.digest(f))

    def test_rank_split_fields_change_ns(self):
        base = self.make_v().ns
        for over in ({"attn_cp_rank": 1, "attn_cp_size": 2}, {"dcp_rank": 1, "dcp_size": 2},
                     {"tp_lcm_size": 8}, {"should_split_heads": True}, {"rank_replicated": True},
                     {"is_mla_model": True}, {"model_name": "m2"}):
            self.assertNotEqual(self.make_v(**over).ns, base, over)

    def test_ns_fields_null_is_empty(self):
        self.assertEqual(self.make_v(extra={"ns_fields": None}).ns, self.make_v().ns)

    def test_refusals(self):
        for kw, text in (({"model_name": None}, "no model name"), ({"model_name": ""}, "no model name"),
                         ({"extra": {"ns_fields": ["x"]}}, "JSON object"),
                         ({"extra": {"ns_fields": {"x": float("inf")}}}, "cannot build ns")):
            with self.assertRaises(MiraRefusal) as cm:
                self.make_v(**kw)
            self.assertIn(text, str(cm.exception))

    def test_golden_vector(self):
        s = self.make_v(tp_rank=1, tp_size=4, extra={"ns_fields": {"model_revision": "abc"}})
        self.assertEqual((s.page_size, s.block_bytes, s.buffers_per_page), (PS, 4096, 2))
        self.assertEqual(s.ns.hex(), SGLANG_NS_GOLDEN)

    def test_version_dtype_and_ns_fields_change_ns(self):
        base = self.make_v().ns
        for other in (self.make_v(version="0.5.24").ns,
                      self.make_v(pool=dtype_pool("torch.uint8")).ns,
                      self.make_v(pool=dtype_pool("torch.float16")).ns,
                      self.make_v(extra={"ns_fields": {"kv_cache_dtype": "fp8_e5m2"}}).ns,
                      self.make_v(extra={"ns_fields": {"model_revision": "r2"}}).ns):
            self.assertNotEqual(other, base)
        self.assertEqual(self.make_v().ns, base)

    def test_no_sglang_no_dtype_still_starts(self):
        s = self.make_v(version="", pool=FakeMHAHostPool(PS))  # unit tests: no SGLang, no dtype
        self.assertEqual(len(s.ns), 32)
        self.assertEqual(st.pool_dtype(FakeMHAHostPool(PS)), "")

    def test_non_json_ns_fields_refused_before_any_state_change(self):
        c = RegionClient()
        with mock.patch.object(st, "engine_version", return_value="0.5.23"):
            with self.assertRaises(MiraRefusal) as cm:
                make(c, dtype_pool(), extra={"ns_fields": {"x": float("nan")}})
        self.assertIn("cannot build ns", str(cm.exception))
        self.assertEqual(c.regions, {})  # refused before the staging region was attached

    def test_engine_version_without_sglang(self):
        with mock.patch.dict(sys.modules, {"sglang": None, "sglang.version": None}):
            with mock.patch("importlib.metadata.version", side_effect=Exception("none")):
                self.assertEqual(st.engine_version(), "")
        fake = types.ModuleType("sglang.version")
        fake.__version__ = "9.9.9"
        with mock.patch.dict(sys.modules, {"sglang": types.ModuleType("sglang"), "sglang.version": fake}):
            self.assertEqual(st.engine_version(), "9.9.9")


SGLANG_NS_GOLDEN = "afd20c11708cf332c70a1195f968840d47f258469f3ab10f87aaeb6796b52776"


class LayerMajorPool(FakeMHAHostPool):
    """A pool whose multi-page meta is buffer-major (all pages' K, then all V): not upstream."""

    def get_page_buffer_meta(self, indices):
        ptrs, sizes = super().get_page_buffer_meta(indices)
        n = len(indices) // self.page_size
        bpp = len(ptrs) // n
        order = [p * bpp + j for j in range(bpp) for p in range(n)]
        return [ptrs[i] for i in order], [sizes[i] for i in order]


class TestLayoutProbe(unittest.TestCase):
    """Layout probe: a non-page-major pool is refused."""

    def test_non_page_major_pool_refused(self):
        s = MiraHiCacheStorage(cfg(), {}, client=RegionClient())
        with self.assertRaisesRegex(MiraRefusal, "page-major"):
            s.register_mem_pool_host(LayerMajorPool(PS, 8, "layer_first"))
        self.assertFalse(s.ready)

    def test_probe_uses_torch_arange_when_torch_imports(self):
        seen = []

        class T(list):
            def tolist(self):
                return list(self)

        fake_torch = types.ModuleType("torch")
        fake_torch.int64 = "int64"
        fake_torch.arange = lambda a, b, dtype=None: (seen.append(dtype), T(range(a, b)))[1]
        pool = FakeMHAHostPool(PS)
        orig = pool.get_page_buffer_meta
        kinds = []
        pool.get_page_buffer_meta = lambda idx: (kinds.append(type(idx)), orig(idx))[1]
        with mock.patch.dict(sys.modules, {"torch": fake_torch}):
            s = MiraHiCacheStorage(cfg(), {}, client=RegionClient())
            s.register_mem_pool_host(pool)
        self.assertTrue(seen and all(d == "int64" for d in seen))
        self.assertTrue(kinds and all(k is T for k in kinds))

    def test_probe_falls_back_without_torch(self):
        with mock.patch.dict(sys.modules, {"torch": None}):
            idx = st._probe_indices(0, PS)
        self.assertEqual(idx.tolist(), list(range(PS)))

    def test_buffer_size_pattern_change_after_registration_is_a_miss(self):
        s, c, pool = make(pool=FakeMLAKVSplitHostPool(PS, 8))
        pool.k_width, pool.rope = pool.rope, pool.k_width  # same sum, different split
        self.assertEqual(s.batch_set_v1(KEYS[:1], pool.indices([0]), info([])), [False])


class FakeOpenClient:
    """Stands in for miracache.Client: records Client.open(config, secret_file=None)."""
    calls = []

    @classmethod
    def open(cls, config, secret_file=None):
        cls.calls.append((config, secret_file))
        return RegionClient()


class TestClientConfig(unittest.TestCase):
    """Client configuration: miracache.config is required, unknown keys are refused, config and secret_file reach Client.open."""

    def setUp(self):
        FakeOpenClient.calls = []
        p = mock.patch("miracache.Client", FakeOpenClient)
        p.start()
        self.addCleanup(p.stop)

    def test_missing_config_key_refused_with_named_key(self):
        for mc in (None, {}, {"secret_file": "/s"}, {"config": ""}, "x"):
            extra = {} if mc is None else {"miracache": mc}
            with self.assertRaises(MiraRefusal) as cm:
                MiraHiCacheStorage(cfg(extra=extra), {})
            self.assertIn('"miracache.config"', str(cm.exception))
            self.assertIn("/etc/miracache/client.toml", str(cm.exception))
        self.assertEqual(FakeOpenClient.calls, [])

    def test_unknown_key_refused(self):
        with self.assertRaisesRegex(MiraRefusal, "unknown"):
            MiraHiCacheStorage(cfg(extra={"miracache": {"config": "/c", "workers": 2}}), {})

    def test_config_and_secret_file_passed_to_open(self):
        MiraHiCacheStorage(cfg(extra={"miracache": {"config": "/c.toml"}}), {})
        MiraHiCacheStorage(cfg(extra={"miracache": {"config": "/c.toml", "secret_file": "/s"}}), {})
        self.assertEqual(FakeOpenClient.calls, [("/c.toml", None), ("/c.toml", "/s")])

    def test_shipped_example_opens_the_client(self):
        with open(EXAMPLE) as f:
            extra = json.load(f)
        self.assertEqual(extra["miracache"], {"config": "/etc/miracache/client.toml"})
        MiraHiCacheStorage(HiCacheStorageConfig(extra_config=extra), {})
        self.assertEqual(FakeOpenClient.calls, [("/etc/miracache/client.toml", None)])


class TestRefusals(unittest.TestCase):
    def test_constructor_is_the_real_shape_without_host_pool(self):
        """(storage_config, kwargs={}) works with no pool and no page_size."""
        s = MiraHiCacheStorage(cfg(), {}, client=RegionClient())
        self.assertFalse(s.ready)
        self.assertEqual(s.batch_exists(KEYS, info([])), 0)  # before registration: a miss, no raise
        self.assertEqual(s.batch_get_v1(KEYS, [], info([])), [False] * 4)
        s.register_mem_pool_host(FakeMHAHostPool(PS))
        self.assertTrue(s.ready)
        self.assertEqual(s.page_size, PS)

    def test_pp(self):
        with self.assertRaisesRegex(MiraRefusal, "PP"):
            MiraHiCacheStorage(cfg(pp_size=2), {}, client=RegionClient())

    def test_no_miracache_pp_size_fallback(self):
        """pp_size is always on the real config; the old extra key is ignored."""
        MiraHiCacheStorage(cfg(extra={"miracache_pp_size": 4}), {}, client=RegionClient())

    def test_expect_prefix_keys_flag_required(self):
        """Our own flag; message names BOTH flags."""
        with self.assertRaises(MiraRefusal) as cm:
            MiraHiCacheStorage(cfg(flag=False), {}, client=RegionClient())
        self.assertIn("miracache_expect_prefix_keys", str(cm.exception))
        self.assertIn("hicache_storage_pass_prefix_keys", str(cm.exception))
        with self.assertRaises(MiraRefusal):
            MiraHiCacheStorage(cfg(flag=False, extra={"miracache_expect_prefix_keys": False}), {},
                               client=RegionClient())

    def test_small_page_refused_at_registration_not_init(self):
        """The page-size refusal moved to register_mem_pool_host."""
        s = MiraHiCacheStorage(cfg(), {}, client=RegionClient())
        with self.assertRaisesRegex(MiraRefusal, "page-size"):
            s.register_mem_pool_host(FakeMHAHostPool(8))
        self.assertFalse(s.ready)
        s.register_mem_pool_host(FakeMHAHostPool(16))
        self.assertTrue(s.ready)

    def test_unsupported_layout_refused_at_registration(self):
        s = MiraHiCacheStorage(cfg(), {}, client=RegionClient())
        with self.assertRaises(MiraRefusal):
            s.register_mem_pool_host(FakeMHAHostPool(PS, 8, "bogus"))

    def test_pool_without_page_size(self):
        s = MiraHiCacheStorage(cfg(), {}, client=RegionClient())
        with self.assertRaises(MiraRefusal):
            s.register_mem_pool_host(object())


class TestNeverRaise(unittest.TestCase):
    def check(self, method):
        s, c, pool = make()
        fill(pool, [0, 1, 2, 3])
        s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([]))
        c.raise_on = {method}
        s2, _, _ = make(c, pool)
        return s2, c, pool

    def test_client_errors(self):
        for m, call, want in [
            ("derive", lambda s, p: s.batch_exists(KEYS, info([])), 0),
            ("lookup_nb", lambda s, p: s.batch_exists(KEYS, info([])), 0),
            ("fetch", lambda s, p: s.batch_get_v1(KEYS, p.indices([4, 5, 6, 7]), info([])), [False] * 4),
            ("put", lambda s, p: s.batch_set_v1(KEYS, p.indices([0, 1, 2, 3]), info([])), [False] * 4),
            ("poll", lambda s, p: s.batch_get_v1(KEYS, p.indices([4, 5, 6, 7]), info([])), [False] * 4),
        ]:
            s, c, pool = self.check(m)
            self.assertEqual(call(s, pool), want, m)
            self.assertGreaterEqual(sum(v for k, v in s.counters.items()
                                        if k.startswith("internal_error")), 1, m)

    def test_bad_inputs(self):
        s, _, pool = make()
        self.assertEqual(s.batch_get_v1(KEYS, None, info([])), [False] * 4)
        self.assertEqual(s.batch_set_v1(KEYS, pool.indices([0]), info([])), [False] * 4)  # short indices
        self.assertEqual(s.batch_get_v1([], [], info([])), [])

    def test_pool_returns_wrong_buffer_count(self):
        s, _, pool = make()
        pool.layout = "layer_first"  # buffers/page changes after registration
        self.assertEqual(s.batch_get_v1(KEYS, pool.indices([0, 1, 2, 3]), info([])), [False] * 4)

    def test_uses_put_not_store(self):
        """The real client's store() has no deadline (10 s default in c_abi.cpp:169)."""
        s, c, pool = make()
        c.raise_on = {"store"}
        self.assertEqual(s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([])), [True] * 4)

    def test_failed_keys_partial_and_not_scattered(self):
        s, c, pool = make()
        src = fill(pool, [0, 1, 2, 3])
        s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([]))
        c.fail_keys = {b"k1"}
        self.assertEqual(s.batch_get_v1(KEYS, pool.indices([4, 5, 6, 7]), info([])), [True, False, True, True])
        self.assertEqual(pool.read_page(4), src[0])
        self.assertTrue(zero(pool, 5))  # failed page left untouched
        self.assertEqual(pool.read_page(6), src[2])

    def test_concurrent_calls(self):
        s, c, pool = make(extra={"miracache_stage_pages": 1})
        fill(pool, [0, 1, 2, 3])
        errs = []

        def work(i):
            try:
                for _ in range(20):
                    s.batch_set_v1(["t%d" % i], pool.indices([i]), info([]))
                    s.batch_exists(["t%d" % i], info([]))
            except Exception as e:  # noqa: BLE001
                errs.append(e)

        ts = [threading.Thread(target=work, args=(i,)) for i in range(4)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertEqual(errs, [])
        self.assertFalse(any(k.startswith("internal_error") for k in s.counters), s.counters)


class TestSignatures(unittest.TestCase):
    """Every adapter method name/param/return type against the upstream names."""

    def test_param_names_match_upstream(self):
        for name, (params, _ret) in REAL_SIGNATURES.items():
            ours = list(inspect.signature(getattr(MiraHiCacheStorage, name)).parameters)[1:]
            self.assertEqual(ours, params, name)

    def test_v2_names_and_types(self):
        """Method names, parameters and return types match upstream."""
        s, _, _ = make()
        r = s.batch_exists_v2(["a", "b"], [PoolTransfer("mamba", keys=["x"])], info([]))
        self.assertEqual(type(r).__name__, PoolTransferResult.__name__)
        self.assertEqual((r.kv_hit_pages, r.extra_pool_hit_pages), (0, {}))
        self.assertIsNone(r.restorable_prefix_pages)
        ts = [PoolTransfer("kv", keys=["a", "b"]), PoolTransfer("mamba", keys=["c"])]
        self.assertEqual(s.batch_get_v2(ts, info([])), {"kv": [False, False], "mamba": [False]})
        self.assertEqual(s.batch_set_v2(ts, info([])), {"kv": [False, False], "mamba": [False]})
        self.assertEqual(s.batch_get_v2([], None), {})
        self.assertEqual(s.batch_get_v2(None), {})

    def test_legacy_are_misses(self):
        s, _, _ = make()
        self.assertFalse(s.exists("k"))
        self.assertEqual(s.batch_get(["a", "b"]), [None, None])
        self.assertFalse(s.set("k"))
        self.assertFalse(s.batch_set(["a"]))
        self.assertIsNone(s.get("k"))

    def test_fake_config_has_all_upstream_fields(self):
        """The fake config has every upstream field."""
        want = ["tp_rank", "tp_size", "pp_rank", "pp_size", "attn_cp_rank", "attn_cp_size",
                "is_mla_model", "enable_storage_metrics", "is_page_first_layout", "model_name",
                "tp_lcm_size", "should_split_heads", "dp_rank", "extra_config", "unified_suffixes",
                "dcp_size", "dcp_rank", "logical_page_size", "unified_chunk_spans", "rank_replicated"]
        self.assertEqual(list(inspect.signature(HiCacheStorageConfig).parameters), want)


class TestFakeClientHonest(unittest.TestCase):
    def test_defaults_match_real_client(self):
        c = FakeClient()
        c.check_ns = True
        self.assertFalse(c.defer_release)
        self.assertIsNone(c.store_reply)
        with self.assertRaises(Exception):
            c.derive({"engine": "sglang", "ns": b"short", "roots": {0: b"r"}}, 0)
        t = c.put(("s",), [b"a"], [None], [0], [0], 100, [8], 1)
        self.assertIsInstance(t, int)
        comps = c.poll()
        self.assertEqual([(x.ticket, x.deferred_release, x.released) for x in comps], [(t, False, False)])


class PollOnceRaises(RegionClient):
    """poll() raises once (an unexpected error while an op is in flight)."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.boom = False

    def poll(self):
        if self.boom:
            self.boom = False
            raise RuntimeError("injected poll")
        return super().poll()


class TestStrayCompletions(unittest.TestCase):
    """Past STRAY_CAP buffered completions only the ones nobody waits for are dropped;
    the op in flight and the quarantined ops keep theirs (else the op times out / the region never retires)."""

    def test_overflow_keeps_awaited_and_quarantined(self):
        s, _, _ = make()
        n = st.STRAY_CAP + 10
        s._done = {t: types.SimpleNamespace(ticket=t) for t in range(n)}
        s._released = {n + 1, n + 2}
        s._awaiting = {5}
        s._quarantine = {7: (None, None), n + 1: (None, None)}
        s._pump()
        self.assertIn(5, s._done)
        self.assertIn(7, s._done)
        self.assertIn(n + 1, s._released)
        self.assertNotIn(n + 2, s._released)
        self.assertEqual(set(s._done), {5, 7})
        self.assertEqual(s.counters.get("stray_completions"), n - 2 + 1)

    def test_the_op_in_flight_is_awaited_and_cleared_after(self):
        c = RegionClient()
        s, _, pool = make(c)
        seen = []
        real_poll = c.poll

        def poll():  # the adapter pumps while it waits: record what it protects at that moment
            seen.append(set(s._awaiting))
            return real_poll()

        c.poll = poll
        s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([]))
        self.assertTrue(any(len(x) == 1 for x in seen), seen)  # the put's ticket, while it was waited for
        self.assertEqual(s._awaiting, set())


class TestReviewR3(unittest.TestCase):
    def test_g01_long_prefix_is_one_batched_lookup(self):
        """200 present pages: one submission, all reported present (was: 50 ms from batch start)."""
        t = [0.0]
        c = RegionClient(clock=t, tick=0.0)
        c.lookup_tick = 0.002  # one RTT per submission
        s, c, pool = make(c, clock=lambda: t[0])
        keys = ["p%d" % i for i in range(200)]
        scope = s._chain(keys, info([]))[1]
        for k in keys:
            c.data[(scope, k.encode())] = b"x"
            c.pending_lookups[k.encode()] = 1  # first ask is PENDING, like the real client
        self.assertEqual(s.batch_exists(keys, info([])), 200)
        self.assertEqual(c.lookup_submissions, 2)  # initial + one re-ask of the PENDING keys
        self.assertEqual(c.lookup_deadlines[0], st.LOOKUP_DEADLINE_MS)

    def test_g01_deadline_is_configurable_and_late_answers_are_discarded(self):
        t = [0.0]
        c = RegionClient(clock=t, tick=0.0)
        c.lookup_tick = 0.01
        s, c, pool = make(c, clock=lambda: t[0], extra={"miracache_lookup_deadline_ms": 20})
        scope = s._chain(["a"], info([]))[1]
        c.data[(scope, b"a")] = b"x"
        c.pending_lookups[b"a"] = 100  # never answers within the deadline
        self.assertEqual(s.batch_exists(["a"], info([])), 0)
        self.assertEqual(c.lookup_deadlines[0], 20)
        self.assertEqual(s.counters.get("lookup_deadline"), 1)
        c.pending_lookups[b"a"] = 0  # the old lookup answers now: consumed, not left behind
        t[0] += 1.0
        s.batch_exists(["zz"], info([]))
        self.assertEqual(s._orphans, {})

    def test_g02_unexpected_error_while_op_in_flight_quarantines_the_region(self):
        c = PollOnceRaises()
        s, c, pool = make(c, extra={"miracache_stage_pages": 2})
        fill(pool, [0, 1, 2, 3])
        first = s._region
        c.boom = True
        out = s.batch_set_v1(KEYS, pool.indices([0, 1, 2, 3]), info([]))
        self.assertEqual(out, [False] * 4)  # rest of the batch failed
        self.assertEqual(len(c.store_calls), 1)  # chunk 2 never ran on the old region
        self.assertEqual(len(s._quarantine), 1)
        self.assertNotEqual(s._region, first)
        self.assertNotIn(first, c.detached)  # live op's region is not detached

    def test_g03_l3_comes_back_when_quarantine_drains(self):
        s, c, pool = make_timed()
        c.late_next = 100
        for i in range(st.MAX_QUARANTINE + 1):
            s.batch_set_v1(["x%d" % i], pool.indices([0]), info([]))
        self.assertFalse(s.ready)
        c.late_next = 0
        c.finish_late()  # every abandoned op completes
        self.assertEqual(s.batch_set_v1(["y"], pool.indices([0]), info([])), [True])
        self.assertTrue(s.ready)
        self.assertEqual(s.counters.get("l3_reenabled"), 1)
        self.assertEqual(len(s._quarantine), 0)

    def test_g03_stays_off_while_ops_are_still_live(self):
        s, c, pool = make_timed()
        c.late_next = 100
        for i in range(st.MAX_QUARANTINE + 1):
            s.batch_set_v1(["x%d" % i], pool.indices([0]), info([]))
        n = len(c.store_calls)
        self.assertEqual(s.batch_set_v1(["y"], pool.indices([0]), info([])), [False])
        self.assertEqual(s.batch_exists(["y"], info([])), 0)
        self.assertEqual(len(c.store_calls), n)
        self.assertFalse(s.ready)

    def test_v02_close_takes_the_lock(self):
        s, c, pool = make()
        s._lock.acquire()
        th = threading.Thread(target=s.close)
        th.start()
        th.join(0.2)
        self.assertTrue(th.is_alive())  # blocked behind the in-flight call
        self.assertFalse(c.closed)
        s._lock.release()
        th.join(2)
        self.assertTrue(c.closed)


class TestBlockSizeCheck(unittest.TestCase):
    def test_page_too_large_for_a_node_refuses_at_registration(self):
        s, c, _ = make()
        block = s.block_bytes
        self.assertGreater(block, 0)
        self.assertEqual(c.block_checks, [block])  # one page = one stored block, checked at registration
        c2 = RegionClient()
        c2.max_block = block - 1
        with self.assertRaises(MiraRefusal) as cm:
            make(client=c2)
        msg = str(cm.exception)
        for part in ("SGLang page", str(block), "memory node 7", "mn-a", "10.0.0.10:7471", "store.run_bytes"):
            self.assertIn(part, msg)
        self.assertEqual(c2.attached, [])  # refused before the staging region is attached

    def test_page_that_fits_or_unknown_limit_registers(self):
        for limit in (None, 1 << 30):
            c = RegionClient()
            c.max_block = limit
            s, _, _ = make(client=c)
            self.assertTrue(s.ready, limit)


if __name__ == "__main__":
    unittest.main()
