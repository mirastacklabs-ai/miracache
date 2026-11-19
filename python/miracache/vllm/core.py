"""vLLM-independent tier core: root derivation, lookup/load/store bookkeeping.

The L8 adapter feeds this class vLLM's private ``_offload_key_positions`` dict
(``{OffloadKey(bytes): end_token_position}``) on each call. The last 4 bytes of a
key are its KV-cache group index. Nothing here imports vllm or torch.

Scope lifetime: a client scope (``miracache._core.Scope`` frees its C handle on GC) is held
by ``_ScopeRef`` and stays alive while any op uses it: ``_Inflight`` keeps it until the op's
completion, and ``_lookups`` pins it while the client holds a PENDING lookup for it, so no
new scope can reuse its address under a client-side ``id(scope)`` key.
"""
from __future__ import annotations

import enum
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Optional, Protocol, Sequence

from ..adapter_metrics import (HIT_TOKENS, LOAD_FAIL, LOOKUP_TOKENS, RECOMPUTE_AVOIDED,
                               AdapterMetrics)
from .never_raise import never_raise

log = logging.getLogger("miracache.vllm")

GROUP_BYTES = 4
NS_BYTES = 32
MAX_STORE_RETRIES = 3  # REFUSED-with-delay resubmits per store job, then it is dropped
_FINISHED_CAP = 65536  # finished request ids remembered (late ops must not recreate state)
_ORPHAN_STEP = 64  # orphaned PENDING lookups re-asked per finished() call


class Lookup(enum.Enum):
    HIT = "HIT"
    MISS = "MISS"
    RETRY = "RETRY"


@dataclass(frozen=True)
class Layout:
    tokens_per_chunk: int  # default, used for groups not in tokens_per_chunk_by_group
    block_size_bytes: int  # slot stride in the registered primary view (primary_kv_view.strides[0])
    ns: bytes = b""  # 32-byte namespace digest (compat.namespace_digest); derive rejects others
    tokens_per_chunk_by_group: tuple = ()  # tokens_per_block[g] * blocks_per_chunk
    region: Optional[int] = None  # attach_region id of the primary view (None = client default)
    num_slots: int = 0  # primary_kv_view.shape[0]; chunk_ids must be in [0, num_slots) (0 = unchecked)

    def tpc(self, group: int) -> int:
        t = self.tokens_per_chunk_by_group
        return int(t[group]) if 0 <= group < len(t) else self.tokens_per_chunk


@dataclass
class Job:
    job_id: int
    req_id: str
    keys: Sequence[bytes]  # one KV group per job
    positions: Mapping[bytes, int]  # the request's offload-key positions
    deadline_ms: int = 0
    chunk_ids: Sequence[int] = ()  # TransferJob.chunk_ids: primary slot of keys[i]
    is_promotion: bool = False  # TransferJob.is_promotion (load into primary)


@dataclass
class JobResult:
    job_id: int
    success: bool
    successful_keys: list = field(default_factory=list)
    deferred_release: bool = False  # buffers still owned by the client
    is_promotion: bool = False


@dataclass
class Completion:  # what ClientProtocol.poll() returns
    ticket: int
    success: bool = True
    successful_keys: list = field(default_factory=list)
    deferred_release: bool = False  # done, buffers not yet released (future client; real: False)
    released: bool = False  # follow-up event: buffers now released (future client; real: False)


@dataclass
class StoreReply:
    status: str  # "OK" | "SKIP" | "REFUSED" (today's real client always answers "OK")
    ticket: Optional[int] = None
    retry_after_ms: int = 0


class ClientProtocol(Protocol):
    def derive(self, meta: Mapping[str, Any], group: int) -> Any: ...
    # HIT | MISS | PENDING. The real client also takes ``parent`` and ``deadline_ms`` (0 = its
    # default); both optional, so a client without them still satisfies the protocol.
    def lookup_nb(self, scope: Any, key: bytes, parent: Optional[bytes] = None,
                  deadline_ms: int = 0) -> str: ...
    def fetch(self, scope: Any, keys: Sequence[bytes], parents: Sequence[Optional[bytes]],
              positions: Sequence[int], offsets: Sequence[int], deadline_ms: int,
              region: Optional[int] = None) -> int: ...  # offsets = chunk_id * stride
    def store(self, scope: Any, keys: Sequence[bytes], parents: Sequence[Optional[bytes]],
              positions: Sequence[int], offsets: Sequence[int],
              region: Optional[int] = None, deadline_ms: int = 0) -> StoreReply: ...  # deadline_ms optional
    def poll(self) -> Sequence[Completion]: ...
    # optional: close() -- aborts and drains every in-flight op (used on drain timeout)


def group_of(key: bytes) -> int:
    return int.from_bytes(key[-GROUP_BYTES:], "little")


class _ScopeRef:
    """A derived client scope plus a per-core serial (never ``id(scope)``)."""
    __slots__ = ("serial", "scope")

    def __init__(self, serial: int, scope: Any) -> None:
        self.serial = serial
        self.scope = scope


@dataclass
class _Inflight:
    job: Job
    kind: str
    group: int
    scope: Any  # _ScopeRef: strong reference until the op completes (R18)
    reported: bool = False  # a JobResult with deferred_release=True was already emitted


class TierCore:
    def __init__(self, client: ClientProtocol, layout: Layout,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._client = client
        self._layout = layout
        self._clock = clock
        self.counters: dict = {}
        self.adapter = AdapterMetrics()  # miracache_adapter_* / miracache_recompute_* (A3.5 M2)
        self._logged: set = set()
        self._reqs: dict = {}  # req_id -> {group: (root_key|None, _ScopeRef|None)}
        self._finished: dict = {}  # req_id -> None, insertion-ordered, capped
        self._inflight: dict = {}  # ticket -> _Inflight
        self._lookups: dict = {}  # (scope serial, key) -> (req_id, _ScopeRef) while PENDING
        self._results: list = []
        self._retries: list = []  # (not_before, Job, attempt)
        self._serial = 0
        self._closed = False
        self.lookup_deadline_ms = 0  # >0: passed to lookup_nb as deadline_ms (0 = client default)
        self.client_closed = False  # a drain timed out and closed the client
        self.released: list = []  # job_ids whose buffers were released (follow-up event)

    # -- helpers -------------------------------------------------------
    def _lk(self) -> dict:
        return {"deadline_ms": self.lookup_deadline_ms} if self.lookup_deadline_ms > 0 else {}

    def _bump(self, name: str, n: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + n

    def _error(self, name: str, exc: BaseException) -> None:
        key = "internal_error." + name
        self._bump(key)
        if key not in self._logged:
            self._logged.add(key)
            log.error("miracache %s failed: %r (further errors counted only)", name, exc)

    def _derive(self, group: int, root: bytes) -> _ScopeRef:
        meta = {"engine": "vllm", "ns": self._layout.ns, "roots": {group: root}}
        scope = self._client.derive(meta, group)
        self._serial += 1
        return _ScopeRef(self._serial, scope)

    def _scope(self, req_id: str, group: int, positions: Mapping[bytes, int]) -> Optional[_ScopeRef]:
        """Scope for (request, group), derived lazily; None means skip L3."""
        root = None
        best = None
        for k, p in positions.items():
            if group_of(k) == group and (best is None or p < best):
                best, root = p, k
        if root is not None and best != self._layout.tpc(group):
            root = None  # not chunk 0: the chain root is unknown
        if req_id in self._finished:  # late op of a finished request: never recreate state (R17)
            if root is None:
                self._bump("scope_missing.no_root")
                return None
            return self._derive(group, root)
        groups = self._reqs.setdefault(req_id, {})
        cached = groups.get(group)
        if cached is not None and cached[0] == root:
            return cached[1]  # unchanged (a None root caches the miss too)
        ref = None
        if root is None:
            self._bump("scope_missing.no_root")
        else:
            ref = self._derive(group, root)
        groups[group] = (root, ref)
        return ref

    def _reject(self, job: Job) -> Optional[str]:
        """Why the job cannot be addressed safely, or None (R19)."""
        if len(job.chunk_ids) != len(job.keys):
            return "chunk_ids_len"
        group = group_of(job.keys[0])
        if any(group_of(k) != group for k in job.keys):
            return "multi_group"
        n = self._layout.num_slots
        for c in job.chunk_ids:
            c = int(c)
            if c < 0 or (n > 0 and c >= n):
                return "chunk_id"
        return None

    def _chain(self, job: Job, group: int):
        pos = [job.positions[k] for k in job.keys]
        by_pos = {p: k for k, p in job.positions.items() if group_of(k) == group}
        tpc = self._layout.tpc(group)
        parents = [by_pos.get(p - tpc) for p in pos]
        # Address by the primary slot vLLM names (TransferJob.chunk_ids), never by chain position.
        offsets = [int(c) * self._layout.block_size_bytes for c in job.chunk_ids]
        return parents, pos, offsets

    def _fail(self, job: Job) -> None:
        if job.is_promotion:  # a load that never ran or was dropped: every block failed
            self.adapter.inc(LOAD_FAIL, len(job.keys))
        self._results.append(JobResult(job.job_id, False, [], False, job.is_promotion))

    # -- public API ----------------------------------------------------
    @never_raise(lambda self, exc, req_id: None)
    def on_new_request(self, req_id: str) -> None:
        self._finished.pop(req_id, None)
        self._reqs.setdefault(req_id, {})

    @never_raise(lambda self, exc, *a, **k: Lookup.MISS)
    def lookup(self, req_id: str, key: bytes, positions: Mapping[bytes, int]) -> Lookup:
        if self._closed:
            return Lookup.MISS
        ref = self._scope(req_id, group_of(key), positions)
        if ref is None:
            return Lookup.MISS
        ck = (ref.serial, bytes(key))
        r = self._client.lookup_nb(ref.scope, key, **self._lk())
        if r == "PENDING":
            self._lookups[ck] = (req_id, ref)  # pin: the client holds an entry for this scope
            return Lookup.RETRY
        self._lookups.pop(ck, None)
        tok = self._layout.tpc(group_of(key))
        self.adapter.inc(LOOKUP_TOKENS, tok)  # answered lookups only: RETRY is asked again
        if r == "HIT":
            self.adapter.inc(HIT_TOKENS, tok)
        return Lookup.HIT if r == "HIT" else Lookup.MISS

    def _submit(self, job: Job, kind: str, attempt: int = 0) -> list:
        if self._closed or not job.keys:
            self._fail(job)
            return []
        why = self._reject(job)
        if why is not None:
            self._bump("job_rejected." + why)
            self._fail(job)
            return []
        group = group_of(job.keys[0])
        ref = self._scope(job.req_id, group, job.positions)
        if ref is None:
            self._fail(job)  # no valid root: skip L3
            return []
        parents, pos, offsets = self._chain(job, group)
        if kind == "load":
            t = self._client.fetch(ref.scope, list(job.keys), parents, pos, offsets, job.deadline_ms,
                                   region=self._layout.region)
            self._inflight[t] = _Inflight(job, kind, group, ref)
            return [t]
        kw = {"deadline_ms": job.deadline_ms} if job.deadline_ms > 0 else {}
        rep = self._client.store(ref.scope, list(job.keys), parents, pos, offsets,
                                 region=self._layout.region, **kw)
        if rep.status == "OK" and rep.ticket is not None:
            self._inflight[rep.ticket] = _Inflight(job, kind, group, ref)
            return [rep.ticket]
        if rep.status == "SKIP":
            self._bump("store_skipped")
            self._results.append(JobResult(job.job_id, True, list(job.keys), False, job.is_promotion))
        elif rep.status == "REFUSED" and rep.retry_after_ms > 0 and attempt < MAX_STORE_RETRIES:
            self._retries.append((self._clock() + rep.retry_after_ms / 1000.0, job, attempt + 1))
        else:  # REFUSED with no delay, retries used up, or unknown: drop
            if rep.status == "REFUSED" and rep.retry_after_ms > 0:
                self._bump("store_retry_exhausted")
            self._bump("store_dropped")
            self._fail(job)
        return []

    @never_raise(lambda self, exc, job: (self._fail(job), [])[1])
    def load(self, job: Job) -> list:
        return self._submit(job, "load")

    @never_raise(lambda self, exc, job: (self._fail(job), [])[1])
    def store(self, job: Job) -> list:
        return self._submit(job, "store")

    def _pump(self) -> None:
        for c in self._client.poll():
            f = self._inflight.get(c.ticket)
            if f is None:
                continue
            if c.released:
                self.released.append(f.job.job_id)
                del self._inflight[c.ticket]
                continue
            if f.kind == "load":
                ok = len(c.successful_keys)
                self.adapter.inc(RECOMPUTE_AVOIDED, ok * self._layout.tpc(f.group))
                self.adapter.inc(LOAD_FAIL, max(0, len(f.job.keys) - ok))
            self._results.append(JobResult(f.job.job_id, c.success,
                                           list(c.successful_keys), c.deferred_release,
                                           f.job.is_promotion))
            if c.deferred_release:
                f.reported = True
            else:
                del self._inflight[c.ticket]

    def _reap_orphans(self) -> None:
        """Re-ask PENDING lookups of finished requests so their pins (and the client's entries)
        are consumed instead of leaking."""
        n = 0
        for ck, (req_id, ref) in list(self._lookups.items()):
            if n >= _ORPHAN_STEP:
                break
            if req_id not in self._finished:
                continue
            n += 1
            try:
                r = self._client.lookup_nb(ref.scope, ck[1], **self._lk())
            except Exception as exc:  # noqa: BLE001
                self._error("reap_lookup", exc)
                r = "MISS"
            if r != "PENDING":
                del self._lookups[ck]

    @never_raise(lambda self, exc: [])
    def finished(self) -> list:
        now = self._clock()
        due = [(j, n) for t, j, n in self._retries if t <= now]
        self._retries = [e for e in self._retries if e[0] > now]
        for j, n in due:
            try:
                self._submit(j, "store", n)
            except Exception as exc:  # noqa: BLE001 - fail this job, keep going (R17)
                self._error("retry", exc)
                self._fail(j)
        self._pump()
        self._reap_orphans()
        out, self._results = self._results, []
        return out

    def _abort_inflight(self) -> None:
        """Drain timed out: stop the client's I/O first (close() aborts and drains every op; the
        buffers are untouched once it returns), then fail the jobs still open and report the
        deferred releases. Nothing is reported released while an op could touch the buffers."""
        pending = list(self._inflight.values())
        close = getattr(self._client, "close", None)
        if close is not None:
            try:
                close()
                self.client_closed = True
            except Exception as exc:  # noqa: BLE001
                self._error("close", exc)
        else:
            self._bump("drain_no_close")
        self._inflight.clear()
        for f in pending:
            if f.reported:
                self.released.append(f.job.job_id)  # its JobResult was already emitted
            else:
                self._fail(f.job)

    @never_raise(lambda self, exc, timeout_s=10.0: None)
    def drain(self, timeout_s: float = 10.0) -> None:
        """Stop intake; wait until every ticket is complete and released. On timeout every open
        job still gets a (failed) JobResult and the client is closed first (R09)."""
        self._closed = True
        for _, j, _ in self._retries:
            self._fail(j)
        self._retries = []
        end = self._clock() + timeout_s
        try:
            while self._inflight and self._clock() < end:
                self._pump()
                if self._inflight:
                    time.sleep(0.001)
        finally:
            if self._inflight:
                self._bump("drain_timeout")
                self._abort_inflight()

    def reopen(self) -> None:
        """Accept submissions again after a completed drain. vLLM calls drain_jobs() from
        reset_cache() and keeps using the tier, so a drain is a barrier, not a shutdown. Stays
        closed if the drain timed out and closed the client (nothing left to submit to)."""
        if not self.client_closed:
            self._closed = False

    def pending(self) -> bool:
        """Work the engine must keep stepping for (has_pending_work)."""
        return bool(self._inflight or self._retries or self._results)

    @never_raise(lambda self, exc, req_id: None)
    def on_request_finished(self, req_id: str) -> None:
        self._reqs.pop(req_id, None)
        self._finished[req_id] = None
        while len(self._finished) > _FINISHED_CAP:
            del self._finished[next(iter(self._finished))]
