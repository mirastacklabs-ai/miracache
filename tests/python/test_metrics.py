"""A3.5 M2: Client.metrics()/metrics_dict(), mira_poll POLL_ERROR handling, adapter counters and
the adapter /metrics endpoint. The fake-lib and fake-client tests need no native library; the
real-lib test skips without MIRACACHE_LIB."""
import ctypes
import gc
import http.client
import os
import socket
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from fake_client import FakeClient  # noqa: E402
from miracache import _core  # noqa: E402
from miracache.adapter_metrics import (AdapterMetrics, MetricsServer, combined_text,  # noqa: E402
                                       start_metrics_server)
from miracache.vllm.core import Job, Layout, Lookup, TierCore  # noqa: E402

SAMPLE = (
    "# HELP miracache_client_fetch_ops_total Keys fetched, by result.\n"
    "# TYPE miracache_client_fetch_ops_total counter\n"
    'miracache_client_fetch_ops_total{result="hit"} 3\n'
    'miracache_client_fetch_ops_total{result="miss"} 0\n'
    "# TYPE miracache_client_fetch_seconds histogram\n"
    'miracache_client_fetch_seconds_bucket{stage="total",le="1e-06"} 0\n'
    'miracache_client_fetch_seconds_bucket{stage="total",le="+Inf"} 2\n'
    'miracache_client_fetch_seconds_sum{stage="total"} 0.0025\n'
    'miracache_client_fetch_seconds_count{stage="total"} 2\n'
    "miracache_client_aead_fail_total 0\n"
)


class FakeLib:
    """Just the calls these tests make. mira_client_metrics follows the real contract: *needed =
    size incl. NUL, E_BUFFER when cap is too small. mira_poll can answer POLL_ERROR."""

    def __init__(self, text=SAMPLE, status_need=0):
        self.text = text
        self.metrics_calls = []  # cap of each call
        self.status_need = status_need  # first completion needs this many status bytes
        self.poll_caps = []
        self.grow_text = False

    def mira_event_fd(self, h):
        return -1

    def mira_scope_free(self, h):
        pass

    def mira_client_close(self, h):
        pass

    def mira_client_metrics(self, h, buf, cap, needed):
        self.metrics_calls.append(cap)
        data = self.text.encode() + b"\0"
        needed._obj.value = len(data)
        if cap < len(data):
            return _core.E_BUFFER
        ctypes.memmove(buf, data, len(data))
        return _core.OK

    def mira_poll(self, h, comps, cap, sbuf, sz):
        self.poll_caps.append(sz)
        if self.status_need == 0:
            return 0
        if sz < self.status_need:
            return _core.POLL_ERROR
        comps[0].ticket, comps[0].kind, comps[0].n_keys, comps[0].status_off = 1, 1, self.status_need, 0
        ctypes.memmove(sbuf, bytes([_core.HIT]) * self.status_need, self.status_need)
        self.status_need = 0
        return 1

    def mira_strerror(self, rc):
        return b"err"

    def mira_last_error(self):
        return b""


class FakeLibCase(unittest.TestCase):
    def install(self, lib):
        saved = _core._lib
        _core._lib = lib
        c = _core.Client(1)
        self.addCleanup(self._restore, saved, c)
        return c

    @staticmethod
    def _restore(saved, c):
        c.close()
        gc.collect()
        _core._lib = saved


class TestParse(unittest.TestCase):
    def test_parse_metrics(self):
        d = _core.parse_metrics(SAMPLE)
        self.assertEqual(d['miracache_client_fetch_ops_total{result="hit"}'], 3.0)
        self.assertEqual(d["miracache_client_aead_fail_total"], 0.0)
        self.assertEqual(d['miracache_client_fetch_seconds_bucket{stage="total",le="+Inf"}'], 2.0)
        self.assertEqual(d['miracache_client_fetch_seconds_sum{stage="total"}'], 0.0025)
        self.assertEqual(d['miracache_client_fetch_seconds_count{stage="total"}'], 2.0)
        self.assertEqual(len(d), 7)  # comments skipped, every series kept

    def test_parse_ignores_garbage_lines(self):
        self.assertEqual(_core.parse_metrics("\nnot_a_number abc\nok 1\n# x\n"), {"ok": 1.0})


class TestClientMetrics(FakeLibCase):
    def test_metrics_text_and_dict(self):
        lib = FakeLib()
        c = self.install(lib)
        self.assertEqual(c.metrics(), SAMPLE)
        self.assertEqual(c.metrics_dict()['miracache_client_fetch_ops_total{result="hit"}'], 3.0)

    def test_buffer_grows_to_the_needed_size(self):
        big = SAMPLE + "".join("m%d 1\n" % i for i in range(5000))
        lib = FakeLib(big)
        c = self.install(lib)
        self.assertEqual(c.metrics(), big)
        self.assertGreater(len(lib.metrics_calls), 1)  # first call was too small
        self.assertEqual(len(c.metrics_dict()), 7 + 5000)

    def test_old_library_without_metrics_raises_unsupported(self):
        c = self.install(FakeLib())
        c._lib = type("Old", (), {"mira_event_fd": lambda s, h: -1, "mira_client_close": lambda s, h: None})()
        with self.assertRaises(_core.MiraError) as cm:
            c.metrics()
        self.assertEqual(cm.exception.code, _core.E_UNSUPPORTED)

    def test_closed_client_raises_closed(self):
        c = self.install(FakeLib())
        c.close()
        with self.assertRaises(_core.MiraError) as cm:
            c.metrics()
        self.assertEqual(cm.exception.code, _core.E_CLOSED)


class TestScrapeIsOffTheDataPath(FakeLibCase):
    def test_metrics_does_not_wait_for_the_data_path_lock(self):
        # M01: a scrape used to take Client._mu, so a slow data-path call stalled the exporter
        # (and the exporter stalled the engine's calls).
        c = self.install(FakeLib())
        out = []
        with c._mu:  # the data path is busy
            th = threading.Thread(target=lambda: out.append(c.metrics()))
            th.start()
            th.join(2.0)
            self.assertFalse(th.is_alive(), "metrics() blocked on the data-path lock")
        self.assertEqual(out, [SAMPLE])

    def test_close_still_waits_for_a_scrape_in_flight(self):
        c = self.install(FakeLib())
        with c._metrics_mu:
            th = threading.Thread(target=c.close)
            th.start()
            th.join(0.3)
            self.assertTrue(th.is_alive(), "close() must not free the handle under a running scrape")
        th.join(2.0)
        self.assertFalse(th.is_alive())


class TestParkedLookupAnswers(FakeLibCase):
    def test_unconsumed_answers_are_dropped_after_a_few_seconds(self):
        # P01: an engine that gave up on a request never re-asks; its parked answer must not stay.
        lib = FakeLib(status_need=2)
        c = self.install(lib)
        t = [100.0]
        c._clock = lambda: t[0]
        ck_a, ck_b = (1, b"a"), (1, b"b")
        c._lookups[ck_a] = c._lookups[ck_b] = "PENDING"
        c._inflight[1] = ("lookup", [], [ck_a, ck_b])
        c._drain()
        self.assertEqual(c._lookups, {ck_a: "HIT", ck_b: "HIT"})
        t[0] += 2.0
        c._drain()
        self.assertEqual(len(c._lookups), 2, "answers younger than the TTL stay")
        t[0] += 4.0  # 6 s after parking
        c._drain()
        self.assertEqual(c._lookups, {})
        self.assertEqual(c._answered_at, {})

    def test_consumed_answers_leave_no_timestamp_and_pending_is_never_swept(self):
        lib = FakeLib(status_need=1)
        c = self.install(lib)
        t = [10.0]
        c._clock = lambda: t[0]
        ck = (1, b"k")
        c._lookups[ck] = "PENDING"
        c._inflight[1] = ("lookup", [], [ck])
        c._drain()
        scope = type("S", (), {"serial": 1})()
        c._submit = lambda *a, **k: None
        self.assertEqual(c.lookup_many(scope, [b"k"]), ["HIT"])
        self.assertEqual((c._lookups, c._answered_at), ({}, {}))
        c._lookups[(1, b"p")] = "PENDING"  # still waiting for the node
        t[0] += 60.0
        c._drain()
        self.assertEqual(c._lookups, {(1, b"p"): "PENDING"})


class TestPollError(FakeLibCase):
    def test_poll_error_grows_the_status_buffer_and_retries(self):
        need = (1 << 16) + 5000  # more than the starting buffer
        lib = FakeLib(status_need=need)
        c = self.install(lib)
        c._inflight[1] = ("fetch", [b"k"] * need, None)
        done = c.poll()
        self.assertEqual(len(done), 1)
        self.assertEqual(done[0].statuses, [_core.HIT] * need)
        self.assertGreater(lib.poll_caps[-1] if lib.poll_caps else 0, 0)
        self.assertEqual(lib.poll_caps[0], 1 << 16)
        self.assertGreaterEqual(max(lib.poll_caps), need)
        self.assertLess(len(lib.poll_caps), 10)  # grew geometrically, never spun

    def test_poll_error_never_iterates_the_sentinel(self):
        lib = FakeLib(status_need=1 << 40)  # can never fit: must give up, not loop or range(SIZE_MAX)
        c = self.install(lib)
        t0 = time.monotonic()
        with self.assertRaises(_core.MiraError):
            c.poll()
        self.assertLess(time.monotonic() - t0, 5)


@unittest.skipIf(_core.library_path() is None, "libmiracache.so not built (set MIRACACHE_LIB)")
class TestRealLib(unittest.TestCase):
    def test_loopback_counters(self):
        blk = 70000
        c = _core.Client.open_loopback()
        self.addCleanup(c.close)
        sc = c.derive({"engine": "vllm", "ns": bytes(range(32)), "roots": {0: b"root"}}, 0)
        keys = [b"mk%d" % i for i in range(2)]
        src = bytearray(2 * blk)
        c.attach_region(src, blk)
        rep = c.store(sc, keys, [None, keys[0]], [0, 1], [0, blk])
        self._wait(c, rep.ticket)
        d = c.metrics_dict()
        self.assertEqual(d['miracache_client_put_ops_total{result="committed"}'], 2.0)
        self.assertEqual(d['miracache_client_put_bytes_total{result="committed"}'], 2.0 * blk)
        self.assertEqual(d['miracache_client_crypto_bytes_total{dir="encrypt"}'], 2.0 * blk)
        self.assertEqual(d['miracache_client_inflight{op="put"}'], 0.0)
        self.assertEqual(d['miracache_client_put_seconds_count{stage="total"}'], 1.0)
        self.assertIn('miracache_client_fetch_seconds_bucket{stage="total",le="+Inf"}', d)
        self.assertIn("# TYPE miracache_client_put_seconds histogram", c.metrics())

    @staticmethod
    def _wait(c, ticket):
        end = time.monotonic() + 10
        while time.monotonic() < end:
            for comp in c.poll():
                if comp.ticket == ticket:
                    return comp
            c.wait_event(100)
        raise AssertionError("no completion")


TPC = 16
LAYOUT = Layout(tokens_per_chunk=TPC, block_size_bytes=4096, ns=bytes(range(32)))


def key(name):
    return name.encode().ljust(8, b"_") + (0).to_bytes(4, "little")


class TestVllmAdapterCounters(unittest.TestCase):
    def setUp(self):
        self.c = FakeClient()
        self.core = TierCore(self.c, LAYOUT)
        self.core.on_new_request("r1")
        self.pos = {key("a%d" % i): i * TPC for i in range(1, 5)}
        root = min(self.pos, key=self.pos.get)
        for k in self.pos:
            self.c.objects.add((("scope", root), k))

    def test_lookup_tokens(self):
        self.assertEqual(self.core.lookup("r1", key("a2"), self.pos), Lookup.HIT)
        self.assertEqual(self.core.lookup("r1", key("zz"), self.pos), Lookup.MISS)
        v = self.core.adapter.values()
        self.assertEqual(v["miracache_adapter_lookup_tokens_total"], 2 * TPC)
        self.assertEqual(v["miracache_adapter_hit_tokens_total"], TPC)

    def test_retry_is_not_counted_until_answered(self):
        k = key("a2")
        self.c.pending_lookups[k] = 1
        self.assertEqual(self.core.lookup("r1", k, self.pos), Lookup.RETRY)
        self.assertEqual(self.core.adapter.values()["miracache_adapter_lookup_tokens_total"], 0)
        self.assertEqual(self.core.lookup("r1", k, self.pos), Lookup.HIT)
        self.assertEqual(self.core.adapter.values()["miracache_adapter_lookup_tokens_total"], TPC)

    def test_load_success_and_failure(self):
        ks = [key("a1"), key("a2"), key("a3")]
        self.c.fail_keys.add(key("a3"))
        self.core.load(Job(1, "r1", ks, self.pos, chunk_ids=[0, 1, 2], is_promotion=True))
        (r,) = self.core.finished()
        self.assertFalse(r.success)
        v = self.core.adapter.values()
        self.assertEqual(v["miracache_recompute_avoided_tokens_total"], 2 * TPC)
        self.assertEqual(v["miracache_adapter_load_fail_total"], 1)

    def test_rejected_load_counts_every_block_as_failed(self):
        self.core.load(Job(2, "r1", [key("a1"), key("a2")], self.pos, chunk_ids=[0], is_promotion=True))
        self.core.finished()
        self.assertEqual(self.core.adapter.values()["miracache_adapter_load_fail_total"], 2)

    def test_render_has_all_four_series_label_free(self):
        text = self.core.adapter.render()
        for n in ("miracache_adapter_hit_tokens_total", "miracache_adapter_lookup_tokens_total",
                  "miracache_adapter_load_fail_total", "miracache_recompute_avoided_tokens_total"):
            self.assertIn("# TYPE %s counter\n%s 0\n" % (n, n), text)
        self.assertNotIn("{", text)


class TestSglangAdapterCounters(unittest.TestCase):
    def test_lookup_and_load_counters(self):
        import test_sglang_storage as ts
        s, c, pool = ts.make()
        self.addCleanup(s.close)
        ts.fill(pool, [0, 1, 2, 3])
        self.assertEqual(s.batch_set_v1(ts.KEYS, pool.indices([0, 1, 2, 3]), ts.info([])), [True] * 4)
        self.assertEqual(s.batch_exists(ts.KEYS + ["nope"], ts.info([])), 4)
        v = s.adapter.values()
        self.assertEqual(v["miracache_adapter_lookup_tokens_total"], 5 * ts.PS)
        self.assertEqual(v["miracache_adapter_hit_tokens_total"], 4 * ts.PS)
        self.assertEqual(s.batch_get_v1(ts.KEYS, pool.indices([4, 5, 6, 7]), ts.info([])), [True] * 4)
        self.assertEqual(s.adapter.values()["miracache_recompute_avoided_tokens_total"], 4 * ts.PS)
        self.assertEqual(s.batch_get_v1(["gone"], pool.indices([4]), ts.info([])), [False])
        self.assertEqual(s.adapter.values()["miracache_adapter_load_fail_total"], 1)

    def test_metrics_port_serves_client_and_adapter_text(self):
        import test_sglang_storage as ts
        base = _free_port()
        s, c, pool = ts.make(extra={"miracache_metrics_port": base})
        self.addCleanup(s.close)
        c.metrics = lambda: "miracache_client_fake_total 7\n"
        status, body = _get(base, "/metrics")  # rank 0 -> base + 0
        self.assertEqual(status, 200)
        self.assertIn("miracache_client_fake_total 7\n", body)
        self.assertIn("miracache_adapter_hit_tokens_total 0\n", body)
        s.close()
        with self.assertRaises(OSError):
            _get(base, "/metrics")

    def test_metrics_port_zero_is_off(self):
        import test_sglang_storage as ts
        s, c, pool = ts.make()
        self.addCleanup(s.close)
        self.assertIsNone(s._metrics_srv)


def _free_port():
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))
        return sk.getsockname()[1]


def _get(port, path, method="GET"):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        conn.request(method, path)
        r = conn.getresponse()
        return r.status, r.read().decode()
    finally:
        conn.close()


class TestHttpEndpoint(unittest.TestCase):
    def test_serves_text_and_404s_everything_else(self):
        m = AdapterMetrics()
        m.inc("miracache_adapter_hit_tokens_total", 5)

        class C:
            def metrics(self):
                return "miracache_client_x_total 1"  # no trailing newline: the join adds one

        srv = MetricsServer("127.0.0.1", 0, lambda: combined_text(C(), m))
        self.addCleanup(srv.stop)
        status, body = _get(srv.port, "/metrics")
        self.assertEqual(status, 200)
        self.assertIn("miracache_client_x_total 1\n# HELP miracache_adapter_hit_tokens_total", body)
        self.assertIn("miracache_adapter_hit_tokens_total 5\n", body)
        self.assertEqual(_get(srv.port, "/metrics?x=1")[0], 200)
        for path in ("/", "/metric", "/metrics/", "/healthz"):
            self.assertEqual(_get(srv.port, path)[0], 404, path)
        self.assertEqual(_get(srv.port, "/metrics", "POST")[0], 405)
        # content type
        conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
        conn.request("GET", "/metrics")
        self.assertTrue(conn.getresponse().getheader("Content-Type").startswith("text/plain; version=0.0.4"))
        conn.close()

    def test_port_is_base_plus_rank_and_zero_is_off(self):
        self.assertIsNone(start_metrics_server({"metrics_port": 0}, 3, lambda: ""))
        self.assertIsNone(start_metrics_server({}, 0, lambda: ""))
        base = _free_port()
        srv = start_metrics_server({"metrics_port": base - 2}, 2, lambda: "a 1\n")
        self.assertIsNotNone(srv)
        self.addCleanup(srv.stop)
        self.assertEqual(srv.port, base)
        self.assertEqual(_get(base, "/metrics"), (200, "a 1\n"))

    def test_bind_failure_never_raises(self):
        with socket.socket() as sk:
            sk.bind(("127.0.0.1", 0))
            sk.listen(1)
            port = sk.getsockname()[1]
            self.assertIsNone(start_metrics_server({"metrics_port": port}, 0, lambda: ""))

    def test_idle_connections_are_capped_and_never_block_a_scrape(self):
        # M01: 10 peers connect and say nothing. Handler threads stay <= the cap (extra
        # connections get 503 and are closed), idle ones time out after 5 s, and a scrape
        # succeeds within 6 s.
        srv = MetricsServer("127.0.0.1", 0, lambda: "a 1\n")
        self.addCleanup(srv.stop)
        base_threads = threading.active_count()
        idle = [socket.create_connection(("127.0.0.1", srv.port), timeout=5) for _ in range(10)]
        self.addCleanup(lambda: [s.close() for s in idle])
        time.sleep(0.3)
        self.assertLessEqual(threading.active_count() - base_threads, 4, "handler threads must stay at the cap")
        t0 = time.monotonic()
        saw_503, ok = False, False
        peak = 0
        while time.monotonic() - t0 < 6.0:
            status, _ = _get(srv.port, "/metrics")
            peak = max(peak, threading.active_count() - base_threads)
            if status == 503:
                saw_503 = True
            elif status == 200:
                ok = True
                break
            time.sleep(0.2)
        self.assertTrue(ok, "a scrape must get through within 6 s (idle handlers time out at 5 s)")
        self.assertTrue(saw_503, "connections over the cap must be refused with 503")
        self.assertLessEqual(peak, 4)

    def test_handler_timeout_is_five_seconds(self):
        from miracache import adapter_metrics as am
        self.assertEqual(am.HANDLER_TIMEOUT_S, 5.0)
        self.assertEqual(am.MAX_CONNECTIONS, 4)
        srv = MetricsServer("127.0.0.1", 0, lambda: "a 1\n", timeout=0.3, max_connections=1)
        self.addCleanup(srv.stop)
        s = socket.create_connection(("127.0.0.1", srv.port), timeout=5)
        self.addCleanup(s.close)
        time.sleep(0.1)
        self.assertEqual(_get(srv.port, "/metrics")[0], 503)  # the one slot is held by the silent peer
        s.settimeout(3)
        self.assertEqual(s.recv(100), b"")  # the server closed the silent connection after ~0.3 s
        end = time.monotonic() + 2.0  # the handler thread releases its slot just after closing
        status = _get(srv.port, "/metrics")[0]
        while status != 200 and time.monotonic() < end:
            time.sleep(0.05)
            status = _get(srv.port, "/metrics")[0]
        self.assertEqual(status, 200)  # slot free again

    def test_client_without_metrics_still_serves_adapter(self):
        self.assertIn("miracache_adapter_load_fail_total 0", combined_text(object(), AdapterMetrics()))


if __name__ == "__main__":
    unittest.main()
