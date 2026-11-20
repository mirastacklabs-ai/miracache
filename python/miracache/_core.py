"""ctypes binding over the miracache C ABI (client/include/miracache/miracache.h).

Pure Python: loads ``libmiracache.so``. ctypes drops the GIL for the duration of every
foreign call and ``wait_event`` blocks in ``select.poll``, so other Python threads run while
the client works. The class satisfies the ``ClientProtocol`` used by ``miracache.vllm.core``
(derive / lookup_nb / fetch / store / poll), so a fake client can be swapped for it.

Library lookup order: ``$MIRACACHE_LIB``, next to this package, ``build/dev/client/`` in a
source checkout. ``load_library()`` raises ``MiraError(UNSUPPORTED)`` when none is found.
"""
from __future__ import annotations

import ctypes
import itertools
import os
import select
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

ABI_MAJOR = 1
ABI_MINOR_METRICS = 1  # mira_client_metrics arrived in ABI 1.1; an older 1.x library lacks it
ABI_MINOR_BLOCK_CHECK = 2  # mira_check_block_size arrived in ABI 1.2

# Return codes (miracache.h).
OK, E_INVALID, E_CONFIG, E_UNSUPPORTED, E_NOT_FOUND, E_ACCESS, E_CLOSED, E_NOMEM, E_INTERNAL, E_BUFFER = range(10)
POLL_ERROR = ctypes.c_size_t(-1).value  # MIRA_POLL_ERROR: mira_poll could not fit the next completion
_STATUS_BUF_START = 1 << 16
_STATUS_BUF_MAX = 1 << 26  # growing past this means a broken library, not a big completion
# Per-key statuses.
HIT, MISS, COMMITTED, SKIPPED, REFUSED, ABORTED, TIMEOUT = range(7)
_OP_LOOKUP, _OP_FETCH, _OP_PUT = 0, 1, 2
_ENGINES = {"vllm": 1, "sglang": 2}
_GOOD = {_OP_FETCH: (HIT,), _OP_PUT: (COMMITTED, SKIPPED), _OP_LOOKUP: (HIT,)}


class MiraError(Exception):
    """Failure of a control-plane call. ``code`` is one of the E_* constants."""

    def __init__(self, code: int, message: str = "") -> None:
        super().__init__("%s (code %d)" % (message, code) if message else "miracache error %d" % code)
        self.code = code
        self.message = message


class _Key(ctypes.Structure):
    _fields_ = [("raw", ctypes.c_void_p), ("raw_len", ctypes.c_size_t),
                ("parent", ctypes.c_void_p), ("parent_len", ctypes.c_size_t),
                ("chain_pos", ctypes.c_uint64), ("region", ctypes.c_uint64),
                ("offset", ctypes.c_uint64), ("len", ctypes.c_uint64)]


class _Completion(ctypes.Structure):
    _fields_ = [("ticket", ctypes.c_uint64), ("kind", ctypes.c_uint32), ("n_keys", ctypes.c_uint32),
                ("status_off", ctypes.c_uint32), ("reserved", ctypes.c_uint32)]


class _ProviderCfg(ctypes.Structure):
    _fields_ = [("struct_size", ctypes.c_uint32), ("secret_file", ctypes.c_char_p)]


class _LoopOpts(ctypes.Structure):
    _fields_ = [("struct_size", ctypes.c_uint32), ("workers", ctypes.c_uint32),
                ("secret32", ctypes.c_void_p)]


def _candidates() -> List[str]:
    out = []
    env = os.environ.get("MIRACACHE_LIB")
    if env:
        out.append(env)
    here = os.path.dirname(os.path.abspath(__file__))
    out.append(os.path.join(here, "libmiracache.so"))
    out.append(os.path.join(here, "..", "..", "build", "dev", "client", "libmiracache.so"))
    return out


_lib: Optional[ctypes.CDLL] = None
_lib_lock = threading.Lock()


def library_path() -> Optional[str]:
    """Path of the first library candidate that exists, or None."""
    for p in _candidates():
        if os.path.isfile(p):
            return os.path.abspath(p)
    return None


def load_library() -> ctypes.CDLL:
    global _lib
    with _lib_lock:
        if _lib is not None:
            return _lib
        path = library_path()
        if path is None:
            raise MiraError(E_UNSUPPORTED, "libmiracache.so not found (set MIRACACHE_LIB)")
        lib = ctypes.CDLL(path)
        vp, sz, u32, u64, i32 = ctypes.c_void_p, ctypes.c_size_t, ctypes.c_uint32, ctypes.c_uint64, ctypes.c_int
        pu64 = ctypes.POINTER(u64)

        def sig(name: str, res: Any, *args: Any) -> None:
            fn = getattr(lib, name)
            fn.restype = res
            fn.argtypes = list(args)

        sig("mira_abi_version", u32)
        sig("mira_strerror", ctypes.c_char_p, i32)
        sig("mira_last_error", ctypes.c_char_p)
        sig("mira_client_open", i32, ctypes.c_char_p, ctypes.POINTER(_ProviderCfg), ctypes.POINTER(vp))
        sig("mira_client_open_loopback", i32, ctypes.POINTER(_LoopOpts), ctypes.POINTER(vp))
        sig("mira_client_close", None, vp)
        sig("mira_attach_region", i32, vp, vp, sz, pu64)
        sig("mira_detach_region", i32, vp, u64)
        sig("mira_derive", i32, vp, u32, ctypes.c_char_p, ctypes.c_char_p, sz, u32, ctypes.POINTER(vp))
        sig("mira_scope_free", None, vp)
        for n in ("mira_lookup_nb", "mira_fetch", "mira_put"):
            sig(n, i32, vp, vp, ctypes.POINTER(_Key), sz, u32, pu64)
        sig("mira_poll", sz, vp, ctypes.POINTER(_Completion), sz, ctypes.c_char_p, sz)
        sig("mira_event_fd", i32, vp)
        ver = lib.mira_abi_version()
        if (ver >> 16) != ABI_MAJOR:
            raise MiraError(E_UNSUPPORTED, "libmiracache ABI major %d, expected %d"
                            % (ver >> 16, ABI_MAJOR))
        if (ver & 0xFFFF) >= ABI_MINOR_METRICS:  # older 1.0 libraries load fine, without metrics
            sig("mira_client_metrics", i32, vp, ctypes.c_char_p, sz, ctypes.POINTER(sz))
        if (ver & 0xFFFF) >= ABI_MINOR_BLOCK_CHECK:
            sig("mira_check_block_size", i32, vp, u64, ctypes.POINTER(sz))
        _lib = lib
        return lib


def _check(rc: int) -> None:
    if rc != OK:
        lib = load_library()
        detail = (lib.mira_last_error() or b"").decode("utf-8", "replace")
        what = (lib.mira_strerror(rc) or b"").decode()
        raise MiraError(rc, "%s: %s" % (what, detail) if detail else what)


def block_size_refusal(client: Any, block_bytes: int, what: str, log: Any) -> Optional[str]:
    """Shared by the engine adapters at start-up: the refusal text when a
    connected memory node cannot store one ``block_bytes`` block (``what`` names the engine's
    block), else None. A client without the check (a test fake, a library older than ABI 1.2)
    or with no node reporting a limit is logged and passes: the node still refuses oversized
    puts itself, and the client then logs a WARN and counts miracache_client_put_refused_total."""
    fn = getattr(client, "check_block_size", None)
    if fn is None:
        return None
    try:
        n = fn(int(block_bytes))
    except MiraError as exc:
        if exc.code != E_CONFIG:
            log.warning("miracache: block size check failed (%s); not checked", exc)
            return None
        return "miracache: %s of %d B cannot be stored: %s" % (what, block_bytes, exc.message or exc)
    if n == -1:
        log.warning("miracache: libmiracache predates ABI 1.2; %s size (%d B) not checked against the "
                    "memory nodes' store.run_bytes", what, block_bytes)
    elif n == 0:
        log.info("miracache: no connected memory node reports its block limit; %s size (%d B) not "
                 "checked now (the client checks each node when it connects and logs an ERROR for "
                 "one that cannot store it)", what, block_bytes)
    else:
        # The client logs "checked N of M" itself; nodes still connecting (or added
        # later) are checked by the client when their session comes up.
        log.info("miracache: %s size %d B fits the %d connected memory node(s) that report a limit "
                 "(nodes that connect later are checked by the client then)", what, block_bytes, n)
    return None


def parse_metrics(text: str) -> Dict[str, float]:
    """Prometheus text exposition -> ``{series: value}``. Comment lines are skipped; the series key
    is the line up to its last space (``name`` or ``name{k="v",...}``), so label sets stay intact."""
    out: Dict[str, float] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] == "#":
            continue
        series, _, val = line.rpartition(" ")
        if not series:
            continue
        try:
            out[series] = float(val)  # accepts +Inf / NaN
        except ValueError:
            continue
    return out


_scope_serials = itertools.count(1)  # monotonic, never reused (unlike id())


class Scope:
    """Opaque derived scope for one KV-cache group (freed on garbage collection)."""

    def __init__(self, handle: int, group: int) -> None:
        self._h = ctypes.c_void_p(handle)
        self.group = group
        self.serial = next(_scope_serials)  # lookup-table key; id() is reused after GC

    def __del__(self) -> None:
        try:
            if self._h:
                load_library().mira_scope_free(self._h)
                self._h = ctypes.c_void_p(None)
        except Exception:
            pass


@dataclass
class Completion:
    """Same shape as ``miracache.vllm.core.Completion`` plus the raw statuses."""
    ticket: int
    success: bool = True
    successful_keys: list = field(default_factory=list)
    deferred_release: bool = False  # always False: a completion means buffers are released
    released: bool = False
    kind: str = ""
    statuses: List[int] = field(default_factory=list)


@dataclass
class StoreReply:
    status: str  # "OK" | "SKIP" | "REFUSED"
    ticket: Optional[int] = None
    retry_after_ms: int = 0


class Client:
    def __init__(self, handle: int) -> None:
        self._lib = load_library()
        self._h = ctypes.c_void_p(handle)
        self._mu = threading.Lock()
        # Guards only the handle against close() for metrics(): a scrape must never wait for the
        # data-path lock _mu. close() takes _mu, then this one; metrics() takes just this one.
        self._metrics_mu = threading.Lock()
        self._regions: Dict[int, Tuple[Any, int, int]] = {}  # id -> (ctypes view, len, block_bytes)
        self._default_region: Optional[int] = None
        self._inflight: Dict[int, Tuple[str, list, Any]] = {}  # ticket -> (kind, keys, extra)
        self._lookups: Dict[Any, Any] = {}  # (scope.serial, key) -> "PENDING" | "HIT" | "MISS"
        # When each HIT/MISS answer was parked; answers nobody re-asks for are dropped after
        # ``answer_ttl`` seconds (an engine that gave up on a request never consumes them).
        self._answered_at: Dict[Any, float] = {}
        self._clock = time.monotonic  # tests replace it with a fake clock
        self.answer_ttl = 5.0
        self._next_sweep = 0.0
        self._done: List[Completion] = []
        self._closed = False
        self._efd = self._lib.mira_event_fd(self._h)

    # -- construction -------------------------------------------------------
    @classmethod
    def open(cls, config: str, secret_file: Optional[str] = None) -> "Client":
        """Open from a config path or TOML text. Raises MiraError (E_CONFIG, E_ACCESS, ...).
        Connects over the wire to the nodes named in the config (mira_client_open); a config that
        parses but whose nodes cannot be reached or authenticated raises the matching MiraError."""
        lib = load_library()
        h = ctypes.c_void_p()
        prov = None
        if secret_file is not None:
            prov = ctypes.byref(_ProviderCfg(ctypes.sizeof(_ProviderCfg), os.fsencode(secret_file)))
        _check(lib.mira_client_open(os.fsencode(config), prov, ctypes.byref(h)))
        return cls(h.value)

    @classmethod
    def open_loopback(cls, workers: int = 0, secret: Optional[bytes] = None) -> "Client":
        """Test/lab client against an in-process memory node over a simulated fabric."""
        lib = load_library()
        if secret is not None and len(secret) != 32:
            raise MiraError(E_INVALID, "secret must be 32 bytes")
        sbuf = ctypes.create_string_buffer(secret, 32) if secret is not None else None
        opts = _LoopOpts(ctypes.sizeof(_LoopOpts), workers, ctypes.addressof(sbuf) if sbuf else None)
        h = ctypes.c_void_p()
        _check(lib.mira_client_open_loopback(ctypes.byref(opts), ctypes.byref(h)))
        return cls(h.value)

    # -- regions ------------------------------------------------------------
    def attach_region(self, buf: Any, block_bytes: int = 0) -> int:
        """Register a writable buffer (bytearray, memoryview, numpy array ...). ``block_bytes``
        is the default per-key length for fetch/store when ``lengths`` is not given. The
        first attached region is the default for fetch/store. Keep ``buf`` alive and unresized."""
        self._need_open()
        view = (ctypes.c_char * len(memoryview(buf).cast("B"))).from_buffer(buf)
        rid = ctypes.c_uint64()
        with self._mu:  # close() frees the handle under _mu: never call C after it
            self._need_open()
            _check(self._lib.mira_attach_region(self._h, ctypes.addressof(view), ctypes.sizeof(view),
                                                ctypes.byref(rid)))
            self._regions[rid.value] = (view, ctypes.sizeof(view), block_bytes)
            if self._default_region is None:
                self._default_region = rid.value
        return rid.value

    def detach_region(self, region: int) -> None:
        self._need_open()
        with self._mu:
            self._need_open()
            _check(self._lib.mira_detach_region(self._h, region))
            self._regions.pop(region, None)
            if self._default_region == region:
                self._default_region = next(iter(self._regions), None)

    # -- scopes -------------------------------------------------------------
    def derive(self, meta: Mapping[str, Any], group: int) -> Scope:
        """meta = {"engine": "vllm"|"sglang"|int, "ns": 32 bytes, "roots": {group: bytes}|[bytes]}."""
        self._need_open()
        engine = meta.get("engine", "vllm")
        engine = _ENGINES[engine] if isinstance(engine, str) else int(engine)
        ns = bytes(meta["ns"])
        if len(ns) != 32:
            raise MiraError(E_INVALID, "meta['ns'] must be 32 bytes")
        roots = meta["roots"]
        root = bytes(roots[group])
        h = ctypes.c_void_p()
        with self._mu:
            self._need_open()
            _check(self._lib.mira_derive(self._h, engine, ns, root, len(root), group, ctypes.byref(h)))
        return Scope(h.value, group)

    # -- data path ----------------------------------------------------------
    def _keys(self, keys: Sequence[bytes], parents: Optional[Sequence[Optional[bytes]]],
              positions: Optional[Sequence[int]], offsets: Optional[Sequence[int]],
              lengths: Optional[Sequence[int]], region: Optional[int]):
        n = len(keys)
        arr = (_Key * max(n, 1))()
        keep = []
        rid = region if region is not None else (self._default_region or 0)
        blk = self._regions[rid][2] if rid in self._regions else 0
        for i, k in enumerate(keys):
            kb = ctypes.create_string_buffer(bytes(k), len(k))
            keep.append(kb)
            arr[i].raw, arr[i].raw_len = ctypes.addressof(kb), len(k)
            p = parents[i] if parents is not None else None
            if p:
                pb = ctypes.create_string_buffer(bytes(p), len(p))
                keep.append(pb)
                arr[i].parent, arr[i].parent_len = ctypes.addressof(pb), len(p)
            arr[i].chain_pos = positions[i] if positions is not None else i
            arr[i].region = rid
            arr[i].offset = offsets[i] if offsets is not None else 0
            arr[i].len = lengths[i] if lengths is not None else blk
        return arr, keep

    def _submit(self, fn: Any, kind: str, scope: Scope, keys: Sequence[bytes], parents, positions, offsets,
                lengths, region, timeout_ms: int, extra: Any = None) -> int:
        self._need_open()
        arr, keep = self._keys(keys, parents, positions, offsets, lengths, region)
        t = ctypes.c_uint64()
        with self._mu:  # poll() must not see the completion before _inflight is filled
            self._need_open()  # re-check under _mu: close() may have won the race
            _check(fn(self._h, scope._h, arr, len(keys), max(int(timeout_ms), 0), ctypes.byref(t)))
            self._inflight[t.value] = (kind, list(keys), extra)
        return t.value

    def fetch(self, scope: Scope, keys: Sequence[bytes], parents: Optional[Sequence[Optional[bytes]]] = None,
              positions: Optional[Sequence[int]] = None, offsets: Optional[Sequence[int]] = None,
              deadline_ms: int = 0, lengths: Optional[Sequence[int]] = None,
              region: Optional[int] = None) -> int:
        """Submit a fetch into the attached region; returns the int ticket."""
        return self._submit(self._lib.mira_fetch, "fetch", scope, keys, parents, positions, offsets, lengths,
                            region, deadline_ms)

    def put(self, scope: Scope, keys: Sequence[bytes], parents=None, positions=None, offsets=None,
            deadline_ms: int = 0, lengths=None, region: Optional[int] = None) -> int:
        return self._submit(self._lib.mira_put, "put", scope, keys, parents, positions, offsets, lengths,
                            region, deadline_ms)

    def store(self, scope: Scope, keys: Sequence[bytes], parents=None, positions=None, offsets=None,
              lengths=None, region: Optional[int] = None, deadline_ms: int = 0) -> StoreReply:
        """ClientProtocol.store: submit a put; the outcome arrives through poll()."""
        t = self.put(scope, keys, parents, positions, offsets, deadline_ms, lengths, region)
        return StoreReply("OK", t)

    def lookup_nb(self, scope: Scope, key: bytes, parent: Optional[bytes] = None,
                  deadline_ms: int = 0) -> str:
        """Non-blocking presence check: "HIT" | "MISS" | "PENDING". The first call submits the
        lookup and returns PENDING; call again later (the answer is consumed once)."""
        return self.lookup_many(scope, [key], [parent], deadline_ms)[0]

    def lookup_many(self, scope: Scope, keys: Sequence[bytes],
                    parents: Optional[Sequence[Optional[bytes]]] = None,
                    deadline_ms: int = 0) -> List[str]:
        """``lookup_nb`` for n keys: one answer per key ("HIT" | "MISS" | "PENDING"). All keys
        not yet asked go out in ONE submission (one LOOKUP RPC, mira_lookup_nb takes n keys)."""
        self._drain()
        out: List[str] = []
        new: List[Tuple[int, Any]] = []  # (index, ck) of keys this call submits
        with self._mu:
            for i, key in enumerate(keys):
                ck = (scope.serial, bytes(key))
                cur = self._lookups.get(ck)
                if cur in ("HIT", "MISS"):
                    del self._lookups[ck]
                    self._answered_at.pop(ck, None)
                    out.append(cur)
                elif cur == "PENDING" or any(ck == c for _, c in new):
                    out.append("PENDING")
                else:
                    self._lookups[ck] = "PENDING"
                    new.append((i, ck))
                    out.append("PENDING")
        if new:
            try:
                self._submit(self._lib.mira_lookup_nb, "lookup", scope, [keys[i] for i, _ in new],
                             [parents[i] if parents is not None else None for i, _ in new],
                             None, None, None, None, deadline_ms, extra=[c for _, c in new])
            except BaseException:
                with self._mu:
                    for _, ck in new:
                        self._lookups.pop(ck, None)
                raise
        return out

    # -- completions --------------------------------------------------------
    def _sweep_answers(self) -> None:
        """Drops HIT/MISS answers parked longer than ``answer_ttl`` (at most once a second)."""
        now = self._clock()
        with self._mu:
            if now < self._next_sweep:
                return
            self._next_sweep = now + 1.0
            for ck, at in list(self._answered_at.items()):
                if now - at > self.answer_ttl:
                    del self._answered_at[ck]
                    if self._lookups.get(ck) in ("HIT", "MISS"):
                        del self._lookups[ck]

    def _drain(self) -> None:
        if self._closed:
            return
        self._sweep_answers()
        cap = 64
        comps = (_Completion * cap)()
        sbuf = ctypes.create_string_buffer(_STATUS_BUF_START)
        while True:
            with self._mu:
                if self._closed:  # close() won the race: the handle is gone
                    return
                n = self._lib.mira_poll(self._h, comps, cap, sbuf, len(sbuf))
                if n == POLL_ERROR:
                    # The next completion's statuses do not fit: nothing was consumed. Grow the
                    # buffer and retry; never treat the sentinel as a count.
                    if len(sbuf) >= _STATUS_BUF_MAX:
                        raise MiraError(E_INTERNAL, "mira_poll: status buffer cannot be grown further")
                    sbuf = ctypes.create_string_buffer(len(sbuf) * 4)
                    continue
                if n == 0:
                    return
                if n > cap:
                    raise MiraError(E_INTERNAL, "mira_poll returned %d completions for capacity %d" % (n, cap))
                for i in range(n):
                    c = comps[i]
                    st = list(sbuf.raw[c.status_off:c.status_off + c.n_keys])
                    kind, keys, extra = self._inflight.pop(c.ticket, ("fetch", [], None))
                    if kind == "lookup":
                        now = self._clock()
                        for j, ck in enumerate(extra):
                            self._lookups[ck] = "HIT" if j < len(st) and st[j] == HIT else "MISS"
                            self._answered_at[ck] = now
                        continue
                    good = _GOOD[_OP_FETCH if kind == "fetch" else _OP_PUT]
                    ok = [k for k, s in zip(keys, st) if s in good]
                    self._done.append(Completion(c.ticket, success=len(ok) == len(keys) and len(keys) > 0,
                                                 successful_keys=ok, kind=kind, statuses=st))

    def poll(self) -> List[Completion]:
        """Non-blocking: completions (fetch/put) that finished since the last call."""
        self._drain()
        with self._mu:
            out, self._done = self._done, []
        return out

    def event_fd(self) -> int:
        return self._efd

    def wait_event(self, timeout_ms: int = -1) -> bool:
        """Block (GIL released) until completions are pending or the timeout elapses."""
        if self._closed:
            return False
        p = select.poll()
        p.register(self._efd, select.POLLIN)
        return bool(p.poll(None if timeout_ms < 0 else timeout_ms))

    # -- start-up block size check ---------------------------
    def check_block_size(self, block_bytes: int) -> int:
        """Can every connected memory node store one block of ``block_bytes`` (one vLLM chunk
        slot / one SGLang page)? Returns how many nodes reported their limit (0: none did, e.g.
        older nodes, which still refuse oversized puts themselves). Raises MiraError(E_CONFIG)
        naming the node (ID, hostname, address), the stored size, its limit and the
        store.run_bytes to set. A library older than ABI 1.2 cannot check: returns -1."""
        self._need_open()
        fn = getattr(self._lib, "mira_check_block_size", None)
        if fn is None:
            return -1
        n = ctypes.c_size_t(0)
        with self._mu:
            self._need_open()
            _check(fn(self._h, ctypes.c_uint64(int(block_bytes)), ctypes.byref(n)))
        return int(n.value)

    # -- metrics --------------------------------------------------
    def metrics(self) -> str:
        """This client's metrics as Prometheus text (exposition 0.0.4). Raises MiraError
        (E_UNSUPPORTED) when the loaded library predates ABI 1.1."""
        self._need_open()
        fn = getattr(self._lib, "mira_client_metrics", None)
        if fn is None:
            raise MiraError(E_UNSUPPORTED, "libmiracache has no mira_client_metrics (ABI < 1.1)")
        cap = 1 << 14
        for _ in range(8):  # the text can grow between the size probe and the copy
            buf = ctypes.create_string_buffer(cap)
            need = ctypes.c_size_t(0)
            with self._metrics_mu:  # not _mu: a scrape must not queue behind the data path
                self._need_open()
                rc = fn(self._h, buf, cap, ctypes.byref(need))
            if rc == OK:
                return buf.value.decode("utf-8", "replace")
            if rc != E_BUFFER:
                _check(rc)
            cap = max(need.value, cap) + 1024
        raise MiraError(E_INTERNAL, "mira_client_metrics: size kept growing")

    def metrics_dict(self) -> Dict[str, float]:
        """``metrics()`` parsed: ``{'name{k="v"}': value}``; histogram ``_bucket``/``_sum``/``_count``
        series are separate keys (``name_bucket{stage="total",le="0.001"}``)."""
        return parse_metrics(self.metrics())

    # -- lifecycle ----------------------------------------------------------
    def _need_open(self) -> None:
        if self._closed:
            raise MiraError(E_CLOSED, "client closed")

    def close(self) -> None:
        """Aborts and drains in-flight ops, then frees the client. Idempotent. Buffers passed to
        fetch/put are untouched once this returns."""
        with self._mu, self._metrics_mu:  # held across the C close: no thread may be inside the handle after it
            if self._closed:
                return
            self._closed = True
            self._lib.mira_client_close(self._h)
            self._h = ctypes.c_void_p(None)
            self._regions.clear()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass
