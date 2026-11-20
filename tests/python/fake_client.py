"""In-memory ClientProtocol implementation with injectable errors and delays.

Mirrors ``miracache._core.Client`` where the adapters depend on it: ``derive`` rejects an
``ns`` that is not 32 bytes (``_core.py:231-233``), calls after ``close()`` raise E_CLOSED,
and ``poll`` after ``close()`` returns nothing. Two behaviours the real client NEVER produces
today (its ``Completion.deferred_release`` / ``released`` are always False and ``store``
always answers "OK") exist only for tests that model a future client, behind
``future_client = True``:
  - ``defer_release``: completions with ``deferred_release=True`` plus a later
    ``released=True`` follow-up;
  - ``store_reply``: a forced StoreReply such as SKIP or REFUSED.
Setting either without ``future_client`` raises AssertionError at the call.
Known gap (kept on purpose): ``lookup_nb`` answers at once; the real client always says
PENDING first. The real-client test in test_vllm_tier.py covers that path.
"""
from __future__ import annotations

from miracache._core import E_CLOSED, E_CONFIG, E_INVALID, MiraError
from miracache.vllm.core import Completion, StoreReply


class FakeClient:
    def __init__(self) -> None:
        self.objects: set = set()  # (scope, key)
        self.pending_lookups: dict = {}  # key -> PENDING answers left
        self.derive_calls: list = []
        self.fetch_calls: list = []
        self.store_calls: list = []
        self.put_deadlines: list = []  # deadline_ms of each put(), in call order
        self.fetch_deadlines: list = []  # deadline_ms of each fetch(), in call order
        self.store_deadlines: list = []  # deadline_ms of each store(), in call order
        self.lookup_deadlines: list = []  # deadline_ms of each lookup_nb(), in call order
        self.fail_keys: set = set()  # fetch of these keys fails
        self.future_client = False  # opt-in for defer_release / store_reply (see module doc)
        self.defer_release = False  # future client: completions carry deferred_release=True
        self.delay_polls = 0  # completions appear after N polls
        self.release_after = 2  # release follow-up appears this many polls after the completion
        self.store_reply = None  # future client: force a StoreReply
        self.raise_on: set = set()  # method names that raise
        self._next = 1
        self._queue: list = []  # [polls_left, Completion]
        self._release_queue: list = []
        self.attached: list = []  # (buf, block_bytes) per attach_region
        self.detached: list = []
        self.regions_used: list = []  # region= kwarg of each fetch/store, in call order
        self.closed = False
        self.on_close = None  # callable run at close(), before in-flight ops are dropped
        self.max_block = None  # The nodes' largest block (None = unknown); see check_block_size
        self.block_checks: list = []  # block_bytes of each check_block_size call

    def _maybe_raise(self, name: str) -> None:
        if name in self.raise_on:
            raise RuntimeError("injected " + name)
        if self.closed:
            raise MiraError(E_CLOSED, "client closed")

    def _future_only(self) -> None:
        if (self.defer_release or self.store_reply is not None) and not self.future_client:
            raise AssertionError("defer_release / store_reply model a future client: "
                                 "set future_client = True")

    def check_block_size(self, block_bytes):
        """As the real client; ``max_block`` (None = no node reports a limit) stands for
        the nodes' HELLO_ACK limit, compared with the plaintext size for simplicity."""
        self._maybe_raise("check_block_size")
        self.block_checks.append(block_bytes)
        if self.max_block is None:
            return 0
        if block_bytes > self.max_block:
            raise MiraError(E_CONFIG, "block of %d B is larger than memory node 7 (hostname mn-a, "
                            "10.0.0.10:7471) places: %d B (its store.run_bytes)"
                            % (block_bytes, self.max_block))
        return 1

    def attach_region(self, buf, block_bytes=0):
        self._maybe_raise("attach_region")
        self.attached.append((buf, block_bytes))
        return len(self.attached)

    def detach_region(self, region):
        self._maybe_raise("detach_region")
        self.detached.append(region)

    def derive(self, meta, group):
        self._maybe_raise("derive")
        if len(bytes(meta["ns"])) != 32:
            raise MiraError(E_INVALID, "meta['ns'] must be 32 bytes")
        self.derive_calls.append((dict(meta), group))
        return ("scope", meta["roots"][group])

    def lookup_nb(self, scope, key, parent=None, deadline_ms=0):
        self._maybe_raise("lookup_nb")
        self.lookup_deadlines.append(deadline_ms)
        left = self.pending_lookups.get(key, 0)
        if left > 0:
            self.pending_lookups[key] = left - 1
            return "PENDING"
        return "HIT" if (scope, key) in self.objects else "MISS"

    def _ticket(self) -> int:
        t = self._next
        self._next += 1
        return t

    def fetch(self, scope, keys, parents, positions, offsets, deadline_ms, lengths=None,
              region=None):
        self._maybe_raise("fetch")
        self._future_only()
        self.regions_used.append(region)
        self.fetch_deadlines.append(deadline_ms)
        self.fetch_calls.append((scope, list(keys), list(parents), list(positions), list(offsets)))
        t = self._ticket()
        ok = [k for k in keys if k not in self.fail_keys and (scope, k) in self.objects]
        c = Completion(t, success=len(ok) == len(keys), successful_keys=ok,
                       deferred_release=self.defer_release)
        self._queue.append([self.delay_polls, c])
        if self.defer_release:
            self._release_queue.append([self.delay_polls + self.release_after,
                                        Completion(t, released=True)])
        return t

    def store(self, scope, keys, parents, positions, offsets, lengths=None, region=None,
              deadline_ms=0):
        self._maybe_raise("store")
        self._future_only()
        self.store_deadlines.append(deadline_ms)
        self.regions_used.append(region)
        self.store_calls.append((scope, list(keys), list(parents), list(positions), list(offsets)))
        if self.store_reply is not None:
            return self.store_reply
        t = self._ticket()
        for k in keys:
            self.objects.add((scope, k))
        self._queue.append([self.delay_polls, Completion(t, True, list(keys),
                                                         deferred_release=self.defer_release)])
        if self.defer_release:
            self._release_queue.append([self.delay_polls + self.release_after,
                                        Completion(t, released=True)])
        return StoreReply("OK", t)

    def put(self, scope, keys, parents=None, positions=None, offsets=None, deadline_ms=0,
            lengths=None, region=None):
        """Real-client shape: submit, return the int ticket; outcome arrives through poll()."""
        self._maybe_raise("put")
        self._future_only()
        self.put_deadlines.append(deadline_ms)
        self.regions_used.append(region)
        self.store_calls.append((scope, list(keys), list(parents or []), list(positions or []),
                                 list(offsets or [])))
        t = self._ticket()
        for k in keys:
            self.objects.add((scope, k))
        self._queue.append([self.delay_polls, Completion(t, True, list(keys),
                                                         deferred_release=self.defer_release)])
        if self.defer_release:
            self._release_queue.append([self.delay_polls + self.release_after,
                                        Completion(t, released=True)])
        return t

    def poll(self):
        if "poll" in self.raise_on:
            raise RuntimeError("injected poll")
        if self.closed:
            return []
        out = []
        for q in (self._queue, self._release_queue):
            for item in list(q):
                if item[0] <= 0:
                    out.append(item[1])
                    q.remove(item)
                else:
                    item[0] -= 1
        return out

    def close(self):
        """Like the real close(): aborts and drains in-flight ops; idempotent."""
        if self.closed:
            return
        if self.on_close is not None:
            self.on_close()
        self.closed = True
        self._queue.clear()
        self._release_queue.clear()
