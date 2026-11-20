"""miracache._core without the real library: a fake C ABI records every call.

Cases: no call into C after (or during) mira_client_close; n keys -> one mira_lookup_nb.
"""
import ctypes
import gc
import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(__file__))

from miracache import _core  # noqa: E402


class FakeLib:
    """Just enough of the C ABI. ``poll_gate``: the first mira_poll blocks until set."""

    def __init__(self):
        self.calls = []  # (name, n)
        self.violations = []  # C calls made while/after the handle was being closed
        self.closing = self.closed = False
        self.poll_entered = threading.Event()
        self.poll_gate = None
        self.close_hold = 0.0  # mira_client_close lingers (a slow close)
        self.statuses = []  # per-key statuses of the next lookup completion
        self._next = 1
        self._ready = []  # (ticket, n_keys)

    def _enter(self, name):
        if self.closing or self.closed:
            self.violations.append(name)

    def mira_event_fd(self, h):
        return -1

    def mira_scope_free(self, h):
        pass

    def mira_lookup_nb(self, h, s, keys, n, timeout_ms, tref):
        self._enter("lookup")
        self.calls.append(("lookup", n, timeout_ms))
        tref._obj.value = self._next
        self._ready.append((self._next, n))
        self._next += 1
        return 0

    def mira_poll(self, h, comps, cap, sbuf, sz):
        self._enter("poll")
        self.calls.append(("poll", 0, 0))
        gate, self.poll_gate = self.poll_gate, None
        if gate is not None:
            self.poll_entered.set()
            gate.wait(5)
        if not self._ready:
            return 0
        t, n = self._ready.pop(0)
        comps[0].ticket, comps[0].kind, comps[0].n_keys, comps[0].status_off = t, 0, n, 0
        st = bytes(self.statuses or [_core.HIT] * n)
        ctypes.memmove(sbuf, st, len(st))
        return 1

    def mira_client_close(self, h):
        self._enter("close")
        self.calls.append(("close", 0, 0))
        self.closing = True
        time.sleep(self.close_hold)
        self.closing, self.closed = False, True


class CoreCase(unittest.TestCase):
    def setUp(self):
        self.lib = FakeLib()
        self._saved = _core._lib
        _core._lib = self.lib
        self.c = _core.Client(1)
        self.scope = _core.Scope(1, 0)

    def tearDown(self):
        # Scope.__del__ calls load_library(): free the fake handles while the fake is installed,
        # never let a handle "1" reach the real library.
        self.c.close()
        self.scope = self.c = None
        gc.collect()
        _core._lib = self._saved


class TestBatchedLookup(CoreCase):
    def test_n_keys_one_submission_per_key_results(self):
        self.lib.statuses = [_core.HIT, _core.MISS, _core.HIT]
        keys = [b"a", b"b", b"c"]
        self.assertEqual(self.c.lookup_many(self.scope, keys, None, 40), ["PENDING"] * 3)
        self.assertEqual([x for x in self.lib.calls if x[0] == "lookup"], [("lookup", 3, 40)])
        self.assertEqual(self.c.lookup_many(self.scope, keys), ["HIT", "MISS", "HIT"])
        self.assertEqual(len([x for x in self.lib.calls if x[0] == "lookup"]), 1)  # consumed, no resubmit

    def test_pending_keys_are_not_resubmitted_and_new_ones_join(self):
        self.c.lookup_many(self.scope, [b"a"])
        self.assertEqual(self.c.lookup_many(self.scope, [b"a", b"b", b"c"]), ["HIT", "PENDING", "PENDING"])
        self.assertEqual([x[1] for x in self.lib.calls if x[0] == "lookup"], [1, 2])

    def test_lookup_nb_is_the_one_key_case(self):
        self.assertEqual(self.c.lookup_nb(self.scope, b"a"), "PENDING")
        self.assertEqual(self.c.lookup_nb(self.scope, b"a"), "HIT")


class TestCloseRace(CoreCase):
    def test_no_c_call_after_close_starts(self):
        self.lib.close_hold = 0.3
        self.lib.poll_gate = threading.Event()
        gate = self.lib.poll_gate
        threads = [threading.Thread(target=self.c.poll)]  # A: blocked inside mira_poll
        threads[0].start()
        self.assertTrue(self.lib.poll_entered.wait(2))
        threads.append(threading.Thread(target=self.c.close))  # B: waits for _mu
        threads[1].start()
        time.sleep(0.05)
        for _ in range(4):  # C: passed the unlocked checks, waits for _mu
            th = threading.Thread(target=lambda: (self.c.poll(), self._try_submit()))
            th.start()
            threads.append(th)
            time.sleep(0.02)
        gate.set()
        for th in threads:
            th.join(5)
        self.assertEqual(self.lib.violations, [])
        self.assertTrue(self.lib.closed)
        names = [x[0] for x in self.lib.calls]
        self.assertEqual(names[names.index("close"):], ["close"])  # nothing after close

    def _try_submit(self):
        try:
            self.c.lookup_nb(self.scope, b"x")
        except _core.MiraError as exc:
            self.assertEqual(exc.code, _core.E_CLOSED)

    def test_submit_after_close_raises_closed(self):
        self.c.close()
        with self.assertRaises(_core.MiraError) as cm:
            self.c.lookup_many(self.scope, [b"x"])
        self.assertEqual(cm.exception.code, _core.E_CLOSED)
        self.assertEqual(self.lib.violations, [])


if __name__ == "__main__":
    unittest.main()
