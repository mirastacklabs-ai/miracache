import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fake_client import FakeClient  # noqa: E402
from miracache.vllm.core import Job, Layout, Lookup, StoreReply, TierCore  # noqa: E402

TPC = 16
NS32 = bytes(range(32))
LAYOUT = Layout(tokens_per_chunk=TPC, block_size_bytes=4096, ns=NS32)


def J(jid, rid, keys, pos, chunk_ids=None, **kw):
    """Job with primary slots 0..n-1 unless chunk_ids is given (TransferJob.chunk_ids)."""
    return Job(jid, rid, keys, pos, chunk_ids=list(range(len(keys))) if chunk_ids is None else chunk_ids, **kw)


def key(name: str, group: int = 0) -> bytes:
    return name.encode().ljust(8, b"_") + group.to_bytes(4, "little")


def chain(prefix: str, n: int, group: int = 0, start: int = 1):
    """positions {key: end_token} for chunks start..n (chunk i ends at i*TPC)."""
    return {key(f"{prefix}{i}", group): i * TPC for i in range(start, n + 1)}


class Base(unittest.TestCase):
    def setUp(self):
        self.c = FakeClient()
        self.core = TierCore(self.c, LAYOUT)
        self.core.on_new_request("r1")

    def put(self, positions, root_name=None):
        root = min(positions, key=positions.get)
        for k in positions:
            self.c.objects.add((("scope", root), k))


class TestLookup(Base):
    def test_retry_then_hit(self):
        pos = chain("a", 3)
        self.put(pos)
        k = key("a2")
        self.c.pending_lookups[k] = 1
        self.assertEqual(self.core.lookup("r1", k, pos), Lookup.RETRY)
        self.assertEqual(self.core.lookup("r1", k, pos), Lookup.HIT)
        self.assertEqual(len(self.c.derive_calls), 1)  # derived once, cached

    def test_miss_for_absent_key(self):
        pos = chain("a", 3)
        self.assertEqual(self.core.lookup("r1", key("a2"), pos), Lookup.MISS)

    def test_miss_when_root_invalid_or_empty(self):
        mid = chain("a", 4, start=3)  # min position is chunk 3, not chunk 0
        self.assertEqual(self.core.lookup("r1", key("a3"), mid), Lookup.MISS)
        self.assertEqual(self.core.lookup("r1", key("a3"), {}), Lookup.MISS)
        self.assertEqual(self.c.derive_calls, [])
        self.assertGreaterEqual(self.core.counters["scope_missing.no_root"], 1)

    def test_rederive_after_preemption_key_change(self):
        old = chain("a", 3)
        self.put(old)
        self.assertEqual(self.core.lookup("r1", key("a2"), old), Lookup.HIT)
        new = chain("b", 3)  # keys recomputed after preemption
        self.put(new)
        self.assertEqual(self.core.lookup("r1", key("b2"), new), Lookup.HIT)
        self.assertEqual(len(self.c.derive_calls), 2)
        self.assertEqual(self.c.derive_calls[1][0]["roots"][0], key("b1"))

    def test_rederive_when_root_becomes_valid(self):
        self.assertEqual(self.core.lookup("r1", key("a3"), chain("a", 4, start=3)), Lookup.MISS)
        pos = chain("a", 4)
        self.put(pos)
        self.assertEqual(self.core.lookup("r1", key("a3"), pos), Lookup.HIT)

    def test_per_group_roots(self):
        p0, p1 = chain("a", 2, group=0), chain("c", 2, group=1)
        pos = {**p0, **p1}
        self.put(p0)
        self.put(p1)
        self.assertEqual(self.core.lookup("r1", key("a2", 0), pos), Lookup.HIT)
        self.assertEqual(self.core.lookup("r1", key("c2", 1), pos), Lookup.HIT)
        roots = {g: m["roots"][g] for m, g in self.c.derive_calls}
        self.assertEqual(roots, {0: key("a1", 0), 1: key("c1", 1)})


class TestLoad(Base):
    def test_load_ok_with_chain_args(self):
        pos = chain("a", 3)
        self.put(pos)
        job = J(1, "r1", [key("a2"), key("a3")], pos, chunk_ids=[5, 2])
        self.assertEqual(len(self.core.load(job)), 1)
        _, keys, parents, p, offs = self.c.fetch_calls[0]
        self.assertEqual(parents, [key("a1"), key("a2")])
        self.assertEqual(p, [2 * TPC, 3 * TPC])
        self.assertEqual(offs, [5 * 4096, 2 * 4096])  # chunk_id * stride, not chain position
        (r,) = self.core.finished()
        self.assertTrue(r.success)
        self.assertEqual(r.successful_keys, keys)

    def test_partial_failure_with_deferred_release(self):
        pos = chain("a", 3)
        self.put(pos)
        self.c.fail_keys.add(key("a3"))
        self.c.future_client = True
        self.c.defer_release = True
        self.core.load(J(7, "r1", [key("a1"), key("a2"), key("a3")], pos))
        (r,) = self.core.finished()
        self.assertFalse(r.success)
        self.assertEqual(r.successful_keys, [key("a1"), key("a2")])
        self.assertTrue(r.deferred_release)
        self.assertEqual(len(self.core._inflight), 1)  # buffers still held
        self.core.drain()
        self.assertEqual(self.core._inflight, {})

    def test_load_without_root_fails_job(self):
        pos = chain("a", 4, start=3)
        self.core.load(J(2, "r1", [key("a3")], pos))
        (r,) = self.core.finished()
        self.assertFalse(r.success)
        self.assertEqual(self.c.fetch_calls, [])


class TestAddressing(Base):
    def test_region_passed_to_fetch_and_store(self):
        core = TierCore(self.c, Layout(TPC, 4096, NS32, region=7))
        pos = chain("a", 2)
        self.put(pos)
        core.load(J(1, "r", [key("a1")], pos))
        core.store(J(2, "r", [key("a2")], pos))
        self.assertEqual(self.c.regions_used, [7, 7])

    def test_chunk_ids_length_mismatch_fails_job(self):
        pos = chain("a", 2)
        self.put(pos)
        self.core.load(J(1, "r1", [key("a1"), key("a2")], pos, chunk_ids=[3]))
        (r,) = self.core.finished()
        self.assertFalse(r.success)
        self.assertEqual(self.c.fetch_calls, [])

    def test_is_promotion_carried_to_results(self):
        pos = chain("a", 2)
        self.put(pos)
        self.core.load(J(1, "r1", [key("a1")], pos, is_promotion=True))
        self.core.store(J(2, "r1", [key("a2")], pos, is_promotion=False))
        self.core.load(J(3, "r1", [], pos, is_promotion=True))  # fails at submit
        got = {r.job_id: r.is_promotion for r in self.core.finished()}
        self.assertEqual(got, {1: True, 2: False, 3: True})

    def test_layout_tokens_per_chunk_by_group(self):
        lay = Layout(16, 4096, NS32, tokens_per_chunk_by_group=(16, 48))
        self.assertEqual((lay.tpc(0), lay.tpc(1), lay.tpc(5)), (16, 48, 16))
        core = TierCore(self.c, lay)
        pos = {**chain("a", 2, 0), **{key("c1", 1): 48, key("c2", 1): 96}}
        self.assertEqual(core.lookup("r", key("c2", 1), pos), Lookup.MISS)
        self.assertEqual(len(self.c.derive_calls), 1)  # group 1 root (pos 48) accepted


class TestStore(Base):
    def test_store_ok(self):
        pos = chain("a", 2)
        self.core.store(J(1, "r1", [key("a1"), key("a2")], pos))
        (r,) = self.core.finished()
        self.assertTrue(r.success)
        self.assertEqual(self.core.lookup("r1", key("a2"), pos), Lookup.HIT)

    def test_store_mid_chain_no_root_is_noop(self):
        pos = chain("a", 5, start=3)
        self.assertEqual(self.core.store(J(1, "r1", [key("a4")], pos)), [])
        self.assertEqual(self.c.store_calls, [])
        (r,) = self.core.finished()
        self.assertFalse(r.success)

    def test_store_skip(self):
        self.c.future_client = True
        self.c.store_reply = StoreReply("SKIP")
        pos = chain("a", 1)
        self.core.store(J(1, "r1", [key("a1")], pos))
        (r,) = self.core.finished()
        self.assertTrue(r.success)
        self.assertEqual(self.core.counters["store_skipped"], 1)

    def test_store_refused_zero_retry_drops(self):
        self.c.future_client = True
        self.c.store_reply = StoreReply("REFUSED", retry_after_ms=0)
        pos = chain("a", 1)
        self.core.store(J(1, "r1", [key("a1")], pos))
        (r,) = self.core.finished()
        self.assertFalse(r.success)
        self.core.finished()
        self.assertEqual(len(self.c.store_calls), 1)  # never retried
        self.assertEqual(self.core.counters["store_dropped"], 1)

    def test_store_refused_with_delay_retries(self):
        now = [0.0]
        core = TierCore(self.c, LAYOUT, clock=lambda: now[0])
        self.c.future_client = True
        self.c.store_reply = StoreReply("REFUSED", retry_after_ms=100)
        pos = chain("a", 1)
        core.store(J(1, "r1", [key("a1")], pos))
        self.assertEqual(core.finished(), [])
        self.c.store_reply = None
        now[0] = 0.2
        (r,) = core.finished()
        self.assertTrue(r.success)
        self.assertEqual(len(self.c.store_calls), 2)


class TestLifecycle(Base):
    def test_drain_waits_for_inflight(self):
        pos = chain("a", 2)
        self.put(pos)
        self.c.delay_polls = 3
        self.core.load(J(1, "r1", [key("a1")], pos))
        self.assertEqual(len(self.core._inflight), 1)
        self.core.drain()
        self.assertEqual(self.core._inflight, {})
        self.assertEqual(len(self.core.finished()), 1)
        self.assertEqual(self.core.lookup("r1", key("a1"), pos), Lookup.MISS)  # intake stopped

    def test_injected_exceptions_never_escape(self):
        pos = chain("a", 2)
        self.put(pos)
        for name in ("derive", "lookup_nb", "fetch", "store", "poll"):
            self.c.raise_on = {name}
            core = TierCore(self.c, LAYOUT)
            res = core.lookup("r", key("a1"), pos)
            if name in ("derive", "lookup_nb"):
                self.assertEqual(res, Lookup.MISS)
            self.assertIsInstance(core.load(J(1, "r", [key("a1")], pos)), list)
            self.assertIsInstance(core.store(J(2, "r", [key("a1")], pos)), list)
            self.assertIsInstance(core.finished(), list)
            core.drain()
            core.on_request_finished("r")
            if name in ("derive", "lookup_nb"):
                self.assertGreaterEqual(core.counters["internal_error.lookup"], 1)
        # failed jobs are reported, not lost
        self.c.raise_on = {"fetch"}
        core = TierCore(self.c, LAYOUT)
        core.load(J(9, "r", [key("a1")], pos))
        (r,) = core.finished()
        self.assertEqual((r.job_id, r.success), (9, False))

    def test_error_logged_once(self):
        self.c.raise_on = {"lookup_nb"}
        pos = chain("a", 1)
        with self.assertLogs("miracache.vllm", level="ERROR") as cm:
            for _ in range(3):
                self.core.lookup("r1", key("a1"), pos)
        self.assertEqual(len(cm.output), 1)
        self.assertEqual(self.core.counters["internal_error.lookup"], 3)

    def test_on_request_finished_frees_state(self):
        pos = chain("a", 1)
        self.core.lookup("r1", key("a1"), pos)
        self.assertIn("r1", self.core._reqs)
        self.core.on_request_finished("r1")
        self.assertNotIn("r1", self.core._reqs)


class _S:
    """Weak-referenceable scope handle (the real Scope frees its C handle on GC)."""

    def __init__(self, root):
        self.root = root


class ObjClient(FakeClient):
    def derive(self, meta, group):
        super().derive(meta, group)
        return _S(meta["roots"][group])

    def lookup_nb(self, scope, key, parent=None):
        left = self.pending_lookups.get(key, 0)
        if left > 0:
            self.pending_lookups[key] = left - 1
            return "PENDING"
        return "MISS"


class TestNamespace(Base):
    def test_fake_rejects_short_ns_like_the_real_client(self):
        core = TierCore(self.c, Layout(TPC, 4096, b"ns"))
        self.assertEqual(core.lookup("r", key("a1"), chain("a", 1)), Lookup.MISS)
        self.assertEqual(self.c.derive_calls, [])

    def test_ns_reaches_derive(self):
        self.core.lookup("r1", key("a1"), chain("a", 1))
        self.assertEqual(self.c.derive_calls[0][0]["ns"], NS32)


class TestDrainTimeout(Base):
    def test_inflight_job_gets_failed_result_and_client_closed(self):
        pos = chain("a", 2)
        self.put(pos)
        self.c.delay_polls = 10 ** 9  # never completes
        self.core.load(J(1, "r1", [key("a1")], pos))
        self.core.store(J(2, "r1", [key("a2")], pos))
        self.core.drain(timeout_s=0.02)
        res = {r.job_id: r.success for r in self.core.finished()}
        self.assertEqual(res, {1: False, 2: False})
        self.assertTrue(self.c.closed)
        self.assertEqual(self.core._inflight, {})
        self.assertFalse(self.core.pending())

    def test_release_reported_only_after_client_closed(self):
        pos = chain("a", 2)
        self.put(pos)
        self.c.future_client = True
        self.c.defer_release = True
        self.c.release_after = 10 ** 9  # the client never releases
        self.c.fail_keys.add(key("a2"))
        self.core.load(J(7, "r1", [key("a1"), key("a2")], pos))
        (r,) = self.core.finished()
        self.assertTrue(r.deferred_release)
        seen = []
        self.c.on_close = lambda: seen.append(list(self.core.released))
        self.core.drain(timeout_s=0.02)
        self.assertEqual(seen, [[]])  # nothing released while I/O could still run
        self.assertEqual(self.core.released, [7])
        self.assertEqual(self.core.finished(), [])  # no second result for job 7

    def test_drain_in_time_does_not_close(self):
        pos = chain("a", 2)
        self.put(pos)
        self.core.load(J(1, "r1", [key("a1")], pos))
        self.core.drain()
        self.assertFalse(self.c.closed)


class TestRetryPath(Base):
    def refusing(self):
        now = [0.0]
        core = TierCore(self.c, LAYOUT, clock=lambda: now[0])
        self.c.future_client = True
        self.c.store_reply = StoreReply("REFUSED", retry_after_ms=100)
        return core, now

    def test_exception_in_retry_fails_that_job_and_continues(self):
        core, now = self.refusing()
        pos = chain("a", 2)
        core.store(J(1, "r1", [key("a1")], pos))
        core.store(J(2, "r1", [key("a2")], pos))
        self.c.store_reply = None
        real = self.c.store

        def store(scope, keys, *a, **k):
            if key("a1") in keys:
                raise RuntimeError("boom")
            return real(scope, keys, *a, **k)

        self.c.store = store
        now[0] = 1.0
        res = {r.job_id: r.success for r in core.finished()}
        res.update({r.job_id: r.success for r in core.finished()})
        self.assertEqual(res, {1: False, 2: True})
        self.assertFalse(core.pending())

    def test_retries_are_capped(self):
        from miracache.vllm.core import MAX_STORE_RETRIES
        core, now = self.refusing()
        core.store(J(1, "r1", [key("a1")], chain("a", 1)))
        out = []
        for i in range(1, 20):
            now[0] = float(i)
            out += core.finished()
        self.assertEqual(len(self.c.store_calls), 1 + MAX_STORE_RETRIES)
        self.assertEqual([(r.job_id, r.success) for r in out], [(1, False)])
        self.assertFalse(core.pending())

    def test_late_store_does_not_recreate_request_state(self):
        pos = chain("a", 2)
        self.core.on_request_finished("r1")
        self.core.store(J(1, "r1", [key("a1")], pos))
        self.assertNotIn("r1", self.core._reqs)
        (r,) = self.core.finished()
        self.assertTrue(r.success)  # still stored, just not cached
        self.core.lookup("r1", key("a1"), pos)
        self.assertNotIn("r1", self.core._reqs)
        self.core.on_new_request("r1")  # a new request with that id is tracked again
        self.core.lookup("r1", key("a1"), pos)
        self.assertIn("r1", self.core._reqs)


class TestScopeLifetime(unittest.TestCase):
    def setUp(self):
        self.c = ObjClient()
        self.core = TierCore(self.c, LAYOUT)

    def test_inflight_holds_scope_until_completion(self):
        import gc
        import weakref
        pos = chain("a", 2)
        self.c.delay_polls = 1
        self.core.load(J(1, "r1", [key("a1")], pos))
        ref = weakref.ref(self.c.fetch_calls[0][0])
        del self.c.fetch_calls[:]  # the fake must not keep it alive either
        self.core.on_request_finished("r1")
        gc.collect()
        self.assertIsNotNone(ref())  # op still in flight: scope must stay alive
        self.assertEqual(len(self.core.finished()), 0)
        self.assertEqual(len(self.core.finished()), 1)
        gc.collect()
        self.assertIsNone(ref())

    def test_pending_lookup_pins_scope_keyed_by_serial(self):
        import gc
        import weakref
        pos = chain("a", 2)
        self.c.pending_lookups[key("a2")] = 2
        self.assertEqual(self.core.lookup("r1", key("a2"), pos), Lookup.RETRY)
        self.assertEqual(len(self.core._lookups), 1)
        (ck,) = self.core._lookups
        self.assertIsInstance(ck[0], int)  # a serial, never id(scope)
        self.assertEqual(ck[1], key("a2"))
        ref = weakref.ref(self.core._lookups[ck][1].scope)
        self.core.on_request_finished("r1")
        gc.collect()
        self.assertIsNotNone(ref())  # the client still holds a PENDING entry for it
        self.core.finished()  # orphan re-asked: still PENDING
        gc.collect()
        self.assertIsNotNone(ref())
        self.core.finished()  # answer consumed: pin dropped
        gc.collect()
        self.assertIsNone(ref())
        self.assertEqual(self.core._lookups, {})

    def test_answer_unpins(self):
        pos = chain("a", 2)
        self.c.pending_lookups[key("a2")] = 1
        self.core.lookup("r1", key("a2"), pos)
        self.assertEqual(self.core.lookup("r1", key("a2"), pos), Lookup.MISS)
        self.assertEqual(self.core._lookups, {})


class TestJobValidation(Base):
    def test_chunk_id_out_of_range_fails_job(self):
        core = TierCore(self.c, Layout(TPC, 4096, NS32, num_slots=4))
        pos = chain("a", 2)
        self.put(pos)
        for jid, cids in ((1, [4]), (2, [-1]), (3, [0, 9])):
            core.load(J(jid, "r", [key("a1"), key("a2")][:len(cids)], pos, chunk_ids=cids))
        core.store(J(4, "r", [key("a1")], pos, chunk_ids=[4]))
        core.load(J(5, "r", [key("a1")], pos, chunk_ids=[3]))  # last slot: fine
        res = {r.job_id: r.success for r in core.finished()}
        self.assertEqual(res, {1: False, 2: False, 3: False, 4: False, 5: True})
        self.assertEqual(len(self.c.fetch_calls), 1)
        self.assertEqual(self.c.store_calls, [])
        self.assertEqual(core.counters["job_rejected.chunk_id"], 4)

    def test_multi_group_job_fails(self):
        pos = {**chain("a", 2, 0), **chain("c", 2, 1)}
        self.put(chain("a", 2, 0))
        self.core.load(J(1, "r1", [key("a1", 0), key("c1", 1)], pos))
        (r,) = self.core.finished()
        self.assertFalse(r.success)
        self.assertEqual(self.c.fetch_calls, [])
        self.assertEqual(self.core.counters["job_rejected.multi_group"], 1)


if __name__ == "__main__":
    unittest.main()
