"""MiraHiCacheStorage: SGLang HiCacheStorage (interface_v1) backed by miracache.

Importable without SGLang or torch: the real base class is imported lazily and
falls back to ``object``. Signatures verified against SGLang main 18d862f
(``S/`` = ``python/sglang/srt/``).

Lifecycle (S/managers/cache_controller.py:664-667): the ``dynamic`` backend calls
``MiraHiCacheStorage(storage_config, kwargs)`` with ``kwargs == {}``
(S/mem_cache/storage/backend_factory.py:165), then ``register_mem_pool_host(pool)``,
then the batch calls. Page size, buffer layout and the client region come from the
pool, so the page-size refusal lives in ``register_mem_pool_host`` (startup).

Page layout (v1): one miracache block per SGLang page = all of that page's host
buffers, as returned by ``pool.get_page_buffer_meta(indices)`` (absolute
``(ptr, size)`` pairs). Upstream returns them PAGE-MAJOR for every layout
("page-layout verification"): page 0's buffers, then page 1's, ... The adapter
checks that at registration (2-page probe) and refuses a pool that is not.
Store = gather into a staging region, load = fetch into the staging region then
scatter back. Staging always (absolute addresses give no attachable base buffer).

Staging safety: every fetch/put carries a client deadline shorter than
the adapter's wait. If the wait still times out, the op may be live and may still
read/write its staging region, so that region is never reused: the op is cancelled
when the client supports it (and reused only if the cancel completes promptly);
otherwise the region is quarantined until the op's completion arrives and a fresh
region is attached. The rest of the batch is failed. Any other exception while an op is in
flight is treated the same way. If more than MAX_QUARANTINE regions are quarantined L3 is
switched off, but each later call keeps pumping and re-enables L3 once the quarantine drains.

Metrics: the adapter counts ``miracache_adapter_hit_tokens_total``,
``miracache_adapter_lookup_tokens_total``, ``miracache_adapter_load_fail_total`` (pages) and
``miracache_recompute_avoided_tokens_total``. Extra-config ``miracache_metrics_port`` (alias
``metrics_port``; 0 = off, default) serves ``GET /metrics`` (client + adapter series) on
``port + tp_rank`` from a daemon thread; ``miracache_metrics_host`` (127.0.0.1) is the bind address.

batch_exists sends all pages in ONE lookup with a per-call client deadline (extra-config
``miracache_lookup_deadline_ms``, default 50) plus a small grace wait.

Rules: refuse at construction / registration (MiraRefusal) when PP>1, the operator
did not set ``miracache_expect_prefix_keys``, ``miracache.config`` is missing or
page size < 16; after that no data-path call raises (a failure is a miss / False
per page). At the pin a refusal at startup stops SGLang (see deploy/sglang/README.md).
The chain root is ``(prefix_keys + keys)[0]``; ``extra_info.prefix_keys`` None or
empty is a root batch (S/mem_cache/hybrid_cache/hybrid_cache_controller.py:1611
sends None for an empty prefix). Root batches are counted; if every batch is a root
batch the adapter warns once (SGLang's ``hicache_storage_pass_prefix_keys`` is
probably off).
"""
from __future__ import annotations

import ctypes
import logging
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .. import ns as _ns
from .._core import block_size_refusal
from ..adapter_metrics import (HIT_TOKENS, LOAD_FAIL, LOOKUP_TOKENS, RECOMPUTE_AVOIDED,
                               AdapterMetrics, combined_text, start_metrics_server)

log =logging.getLogger("miracache.sglang")

MIN_PAGE_SIZE = 16
PRESENCE_TTL_S = 0.1  # spec 2.3: batch_exists fills a 100 ms presence cache
IO_TIMEOUT_S = 5.0  # adapter wait per op
OP_DEADLINE_MS = 3000  # client deadline per fetch/put: always < IO_TIMEOUT_S
LOOKUP_DEADLINE_MS = 50  # default client deadline of one batched lookup (extra-config
#                          "miracache_lookup_deadline_ms"); the adapter waits this + LOOKUP_GRACE_S
LOOKUP_GRACE_S = 0.05
CANCEL_GRACE_S = 0.5 # after cancel(), wait this long for the op to finish before quarantining
MAX_QUARANTINE = 4  # live abandoned staging regions; beyond this L3 is disabled
DEFAULT_STAGE_PAGES = 16  # staging region = this many pages; larger batches are chunked
ROOT_WARN_AFTER = 64  # batches; warn once if all of them were root batches
STRAY_CAP = 4096  # buffered completions beyond this: the ones nobody waits for are dropped (counted)
CLIENT_CONFIG_HINT = '"miracache": {"config": "/etc/miracache/client.toml"}'

try:  # real SGLang types (hicache_storage.py:374, :244)
    from sglang.srt.mem_cache.hicache_storage import HiCacheStorage as _Base  # type: ignore
    from sglang.srt.mem_cache.hicache_storage import PoolTransferResult  # type: ignore
except Exception:  # noqa: BLE001 - sglang/torch absent
    from dataclasses import dataclass, field

    _Base = object  # type: ignore

    @dataclass
    class PoolTransferResult:  # type: ignore[no-redef]
        """Mirror of hicache_storage.py:244-262."""
        kv_hit_pages: int
        extra_pool_hit_pages: Dict[str, int] = field(default_factory=dict)
        restorable_prefix_pages: Optional[List[int]] = None

        @classmethod
        def empty(cls) -> "PoolTransferResult":
            return cls(0, {})


class MiraRefusal(RuntimeError):
    """Raised at init/registration only: the adapter refuses to start. At the pin SGLang
    re-raises it from attach_storage_backend (cache_controller.py:723-747), so startup fails."""


class _Abandoned(Exception):
    """A chunk's op did not finish in time; the rest of the batch is failed."""


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _truthy(v: Any) -> bool:
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes")
    return bool(v)


def engine_version() -> str:
    """The running SGLang's version ("" when SGLang is not importable, e.g. in unit tests).
    Part of ``ns``: a SGLang upgrade starts a fresh cache, as in the engine's own caches."""
    try:
        from sglang.version import __version__ as v  # type: ignore
        return str(v)
    except Exception:  # noqa: BLE001
        pass
    try:
        from importlib.metadata import version as dist_version
        return str(dist_version("sglang"))
    except Exception:  # noqa: BLE001
        return ""


def pool_dtype(mem_pool_host: Any) -> str:
    """KV dtype as the host pool stores it (S/mem_cache/pool_host/base.py: ``self.dtype``).
    SGLang stores every fp8 variant as uint8, so this separates bf16 / fp16 / fp8 but not
    fp8_e4m3 from fp8_e5m2: put ``kv_cache_dtype`` in ``ns_fields`` for that (preflight fails
    without it)."""
    d = _get(mem_pool_host, "dtype", None)
    return "" if d is None else str(d)


def _opt_int(v: Any) -> Optional[int]:
    return None if v is None else int(v)


def _opt_bool(v: Any) -> Optional[bool]:
    return None if v is None else bool(v)


def namespace_fields(storage_config: Any, mem_pool_host: Any, *, page_size: int, block_bytes: int,
                     buffers_per_page: int, extra: Dict[str, Any], version: str) -> Dict[str, Any]:
    """What ``ns`` covers for SGLang: engine and version, model, KV dtype
    and layout, page geometry, key scheme, every rank/split field of HiCacheStorageConfig that
    changes which KV bytes a rank holds (TP, attention CP, DCP, head split, replication), plus the
    operator's ``ns_fields`` (values SGLang does not pass to a storage backend: weights path when
    a served-model-name alias is used, revision, quantization, exact fp8 variant; preflight fails
    when they are missing). ``model_name`` is SGLang's served model name, not the weights path.
    The encoding is ``miracache.ns.digest``; the bytes are pinned by TestNamespaceGolden."""
    c = storage_config
    return {
        "engine": "sglang", "engine_version": version,
        "model": _get(c, "model_name", None),
        "kv_dtype": pool_dtype(mem_pool_host),
        "tp_rank": int(_get(c, "tp_rank", 0) or 0),
        "tp_size": int(_get(c, "tp_size", 1) or 1),
        "attn_cp_rank": int(_get(c, "attn_cp_rank", 0) or 0),
        "attn_cp_size": int(_get(c, "attn_cp_size", 1) or 1),
        "dcp_rank": int(_get(c, "dcp_rank", 0) or 0),
        "dcp_size": int(_get(c, "dcp_size", 1) or 1),
        "tp_lcm_size": _opt_int(_get(c, "tp_lcm_size", None)),
        "should_split_heads": bool(_get(c, "should_split_heads", False)),
        "rank_replicated": _opt_bool(_get(c, "rank_replicated", None)),
        "is_mla": bool(_get(c, "is_mla_model", False)),
        "page_first": bool(_get(c, "is_page_first_layout", False)),
        "page_size": int(page_size), "block_bytes": int(block_bytes),
        "buffers_per_page": int(buffers_per_page),
        "key_scheme": "rank-suffix", "extra_ns": extra.get("ns_fields") or {},
    }


def _b(k: Any) -> bytes:
    return k.encode() if isinstance(k, str) else bytes(k)


class _Indices(list):
    """Fallback index 'tensor' when torch is absent: upstream get_page_buffer_meta uses only
    len() and .tolist() (mha.py:863-866, mla.py:1278-1281)."""

    def tolist(self) -> list:
        return list(self)


def _probe_indices(start: int, stop: int) -> Any:
    """Token indices for the registration probe: a torch int64 tensor when torch imports
    (what SGLang passes as host_indices), else the list stand-in."""
    try:
        import torch  # type: ignore
        return torch.arange(start, stop, dtype=torch.int64)
    except Exception:  # noqa: BLE001
        return _Indices(range(start, stop))


def client_kwargs(extra: Dict[str, Any]) -> Dict[str, str]:
    """``extra["miracache"]`` -> kwargs for ``Client.open(config, secret_file=None)``.
    Raises ValueError naming the missing/bad key."""
    mc = extra.get("miracache")
    if not isinstance(mc, dict) or not isinstance(mc.get("config"), str) or not mc["config"]:
        raise ValueError("extra-config key \"miracache.config\" is missing: set %s "
                         "(plus \"secret_file\" when client.toml does not name one)"
                         % CLIENT_CONFIG_HINT)
    bad = sorted(set(mc) - {"config", "secret_file"})
    if bad:
        raise ValueError("unknown key(s) in extra-config \"miracache\": %s (allowed: config, "
                         "secret_file)" % ", ".join(bad))
    out = {"config": mc["config"]}
    if mc.get("secret_file") is not None:
        if not isinstance(mc["secret_file"], str) or not mc["secret_file"]:
            raise ValueError("extra-config \"miracache.secret_file\" must be a path string")
        out["secret_file"] = mc["secret_file"]
    return out


class MiraHiCacheStorage(_Base):  # type: ignore[misc,valid-type]
    def __init__(self, storage_config: Any, kwargs: Optional[dict] = None, *,
                 client: Any = None, clock: Callable[[], float] = time.monotonic) -> None:
        # kwargs: always {} from the dynamic backend (backend_factory.py:165); ignored.
        extra = dict(_get(storage_config, "extra_config", None) or {})
        self._extra = extra
        self.counters: Dict[str, int] = {}
        self._clock = clock
        self._logged: set = set()
        self.tp_rank = int(_get(storage_config, "tp_rank", 0) or 0)
        self.tp_size = int(_get(storage_config, "tp_size", 1) or 1)
        self._cfg = storage_config
        self.mem_pool_host: Any = None
        self.ready = False  # True after a successful register_mem_pool_host

        # pp_size is always set on the real config (hicache_storage.py:31)
        if int(_get(storage_config, "pp_size", 1) or 1) > 1:
            raise MiraRefusal("miracache: SGLang pipeline parallelism (PP>1) is unsupported in v1; L3 disabled")
        # SGLang pops hicache_storage_pass_prefix_keys before we are built
        # (hybrid_cache_controller.py:553-560), so we cannot see it. Our own flag
        # is the operator's promise that SGLang's flag is on too.
        if not _truthy(extra.get("miracache_expect_prefix_keys", False)):
            raise MiraRefusal(
                "miracache: set BOTH \"miracache_expect_prefix_keys\": true in "
                "--hicache-storage-backend-extra-config AND SGLang's "
                "\"hicache_storage_pass_prefix_keys\": true; without them prefix_keys is "
                "never passed and the chain root is unknown")
        self._client = client if client is not None else self._make_client(extra)
        self._stage_pages = max(1, int(extra.get("miracache_stage_pages", DEFAULT_STAGE_PAGES)))
        self._lookup_deadline_ms = max(1, int(extra.get("miracache_lookup_deadline_ms",
                                                         LOOKUP_DEADLINE_MS)))
        self._orphans: Dict[int, Tuple[Any, List[bytes]]] = {}  # lookups given up on
        self._degraded = False  # L3 off because of quarantine/attach failure; revivable
        self._lock = threading.Lock()  # one staging region: serialize all client use
        self._scopes: Dict[bytes, Any] = {}  # root key -> scope
        self._presence: Dict[Any, float] = {}  # (root, key) -> expiry
        self.page_size = 0
        self.block_bytes = 0
        self.buffers_per_page = 0
        self._sizes: List[int] = []  # per-page buffer sizes, in order (probe)
        self.ns = b""
        self._stage: Any = None
        self._stage_addr = 0
        self._region: Optional[int] = None
        # Completions buffered across polls: ticket -> completion; tickets released.
        self._done: Dict[int, Any] = {}
        self._released: set = set()
        self._awaiting: set = set()  # tickets an op is waiting on right now (never dropped as stray)
        # Abandoned ops: ticket -> (staging buffer, region id) kept alive, never reused.
        self._quarantine: Dict[int, Tuple[Any, Optional[int]]] = {}
        self._batches = 0
        self._root_batches = 0
        self.adapter = AdapterMetrics()
        self._metrics_srv = start_metrics_server(
            {"metrics_port": extra.get("miracache_metrics_port", extra.get("metrics_port", 0)),
             "metrics_host": extra.get("miracache_metrics_host", extra.get("metrics_host", "127.0.0.1"))},
            self.tp_rank, lambda: combined_text(self._client, self.adapter))

    # ---- helpers -----------------------------------------------------
    @staticmethod
    def _make_client(extra: Dict[str, Any]) -> Any:
        try:
            kw = client_kwargs(extra)
        except ValueError as exc:
            raise MiraRefusal("miracache: %s" % exc) from None
        try:
            from miracache import Client  # type: ignore  # ctypes client
            return Client.open(**kw)
        except Exception as exc:  # noqa: BLE001
            raise MiraRefusal("miracache: cannot open client from %r: %r" % (kw["config"], exc)) from exc

    def _bump(self, name: str, n: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + n

    def _err(self, where: str, exc: BaseException) -> None:
        self._bump("internal_error." + where)
        if where not in self._logged:
            self._logged.add(where)
            log.error("miracache %s failed: %r (further errors counted only)", where, exc)

    def _chain(self, keys: Sequence[str], extra_info: Any):
        """-> (root bytes, scope, prefix list), or None to skip L3 for this call.
        prefix_keys None/empty = the batch starts at the chain root."""
        prefix = list(_get(extra_info, "prefix_keys", None) or [])
        full = prefix + list(keys)
        if not full:
            return None
        root = _b(full[0])
        scope = self._scopes.get(root)
        if scope is None:
            scope = self._client.derive({"engine": "sglang", "ns": self.ns, "roots": {0: root}}, 0)
            if len(self._scopes) > 4096:
                self._scopes.clear()
            self._scopes[root] = scope
        return root, scope, prefix

    def _count_batch(self, prefix: List[Any]) -> None:
        """A 100% root-batch rate means SGLang is not passing prefix_keys."""
        self._batches += 1
        self._bump("batches")
        if not prefix:
            self._root_batches += 1
            self._bump("root_batches")
        if (self._batches == ROOT_WARN_AFTER and self._root_batches == self._batches
                and "root_rate" not in self._logged):
            self._logged.add("root_rate")
            log.warning("miracache: all %d batches so far were root batches (prefix_keys None/"
                        "empty); SGLang's hicache_storage_pass_prefix_keys is probably off, so "
                        "continuation pages are stored under the wrong root. Run "
                        "`python -m miracache.check_sglang_config`", self._batches)

    def _page_buffers(self, host_indices: Any, n: int) -> List[List[Any]]:
        """Per page, its (ptr, size) buffers. get_page_buffer_meta is page-major for every
        upstream layout, verified at registration."""
        if host_indices is None or len(host_indices) != n * self.page_size:
            raise ValueError("host_indices length %r != %d pages * page_size %d"
                             % (None if host_indices is None else len(host_indices), n, self.page_size))
        ptrs, sizes = self.mem_pool_host.get_page_buffer_meta(host_indices)
        bpp = self.buffers_per_page
        if len(ptrs) != n * bpp or len(sizes) != len(ptrs):
            raise ValueError("host pool returned %d buffers for %d pages (expected %d each)"
                             % (len(ptrs), n, bpp))
        pages = []
        for i in range(n):
            sz = [int(s) for s in sizes[i * bpp:(i + 1) * bpp]]
            if sz != self._sizes:
                raise ValueError("page %d buffer sizes %r != registered %r" % (i, sz, self._sizes))
            pages.append([(int(ptrs[i * bpp + j]), sz[j]) for j in range(bpp)])
        return pages

    def _gather(self, pages: List[List[Any]]) -> None:
        """Host buffers -> staging, one block per page (buffer order preserved)."""
        for slot, bufs in enumerate(pages):
            off = self._stage_addr + slot * self.block_bytes
            for ptr, size in bufs:
                ctypes.memmove(off, ptr, size)
                off += size

    def _scatter(self, pages: List[List[Any]], ok: List[bool]) -> None:
        """Staging -> host buffers for the pages whose fetch succeeded."""
        for slot, bufs in enumerate(pages):
            if not ok[slot]:
                continue
            off = self._stage_addr + slot * self.block_bytes
            for ptr, size in bufs:
                ctypes.memmove(ptr, off, size)
                off += size

    # ---- completions + staging lifetime ---------------------
    def _pump(self) -> None:
        """Poll once; buffer every completion and release event (none is dropped)."""
        for c in self._client.poll():
            t = c.ticket
            if getattr(c, "released", False):
                self._released.add(t)
            else:
                self._done[t] = c
            if t in self._quarantine and self._is_free(t):
                self._retire(t)
        if len(self._done) + len(self._released) > STRAY_CAP:  # completions nobody waits for
            # Drop only those. The op in flight and every quarantined op are still
            # waited for: dropping their completion would time the op out, and a quarantined region whose release
            # event was dropped would never retire.
            keep = self._awaiting | set(self._quarantine)
            stray_done = [t for t in self._done if t not in keep]
            stray_rel = [t for t in self._released if t not in keep]
            self._bump("stray_completions", len(stray_done) + len(stray_rel))
            for t in stray_done:
                del self._done[t]
            self._released.difference_update(stray_rel)

    def _is_free(self, t: int) -> bool:
        """The op is over and no longer touches its region."""
        if t in self._released:
            return True
        c = self._done.get(t)
        return c is not None and not getattr(c, "deferred_release", False)

    def _forget(self, t: int) -> None:
        self._done.pop(t, None)
        self._released.discard(t)

    def _retire(self, t: int) -> None:
        _buf, region = self._quarantine.pop(t)
        self._forget(t)
        self._bump("quarantine_retired")
        if region is not None:
            try:
                self._client.detach_region(region)
            except Exception as exc:  # noqa: BLE001
                self._err("detach_region", exc)

    def _sleep(self) -> None:
        w = getattr(self._client, "wait_event", None)
        if w is not None:
            w(1)  # GIL released while blocked (real client)
        else:
            time.sleep(0.0005)

    def _wait_until(self, cond: Callable[[], bool], end: float) -> bool:
        while True:
            if cond():
                return True
            if self._clock() >= end:
                return False
            self._pump()
            if cond():
                return True
            self._sleep()

    def _abandon(self, t: int, why: str) -> None:
        """The op on the current staging region did not finish: never reuse that region."""
        self._bump(why)
        cancel = getattr(self._client, "cancel", None)
        if cancel is not None:
            try:
                cancel(t)
                if self._wait_until(lambda: self._is_free(t), self._clock() + CANCEL_GRACE_S):
                    self._forget(t)
                    self._bump("cancelled")
                    return
            except Exception as exc:  # noqa: BLE001
                self._err("cancel", exc)
        self._quarantine[t] = (self._stage, self._region)
        self._stage, self._stage_addr, self._region = None, 0, None
        self._bump("quarantined")
        if len(self._quarantine) > MAX_QUARANTINE:
            self.ready, self._degraded = False, True
            log.error("miracache: %d ops still live after timeouts; L3 disabled until they drain",
                      len(self._quarantine))
            return
        try:
            self._new_stage()
        except Exception as exc:  # noqa: BLE001
            self.ready, self._degraded = False, True
            self._err("attach_region", exc)

    def _revive(self) -> None:
        """L3 was disabled by _abandon. Keep pumping; once the quarantine has drained,
        attach a fresh stage and turn L3 back on. Called with the lock held."""
        if self.ready or not self._degraded or self.mem_pool_host is None:
            return
        self._pump()
        if len(self._quarantine) > MAX_QUARANTINE // 2:
            return
        try:
            if self._stage is None:
                self._new_stage()
        except Exception as exc:  # noqa: BLE001
            self._err("attach_region", exc)
            return
        self.ready, self._degraded = True, False
        self._bump("l3_reenabled")
        log.warning("miracache: quarantine drained; L3 re-enabled")

    def _new_stage(self) -> None:
        buf = bytearray(self.block_bytes * self._stage_pages)
        addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
        region = self._client.attach_region(buf, self.block_bytes)
        self._stage, self._stage_addr, self._region = buf, addr, region

    # ---- registration (startup) -------------------------------------
    def register_mem_pool_host(self, mem_pool_host: Any) -> None:
        """hicache_storage.py:381-382. Page size, layout and the client region come from here."""
        self.ready = False
        ps = _get(mem_pool_host, "logical_page_size", None) or _get(mem_pool_host, "page_size", None)
        if not ps:
            raise MiraRefusal("miracache: cannot determine page size from the host pool; "
                              "use --page-size >= 16")
        ps = int(ps)
        if ps < MIN_PAGE_SIZE:
            raise MiraRefusal("miracache: --page-size %d < %d (objects too small for RDMA); "
                              "use >= 16 (64 recommended)" % (ps, MIN_PAGE_SIZE))
        try:  # probe pages 0 and 0-1: buffers per page, sizes, and page-major order
            p1, s1 = mem_pool_host.get_page_buffer_meta(_probe_indices(0, ps))
            p2, s2 = mem_pool_host.get_page_buffer_meta(_probe_indices(0, 2 * ps))
            p1, s1 = [int(p) for p in p1], [int(s) for s in s1]
            p2, s2 = [int(p) for p in p2], [int(s) for s in s2]
        except Exception as exc:  # noqa: BLE001
            raise MiraRefusal("miracache: unsupported host pool layout: %r" % (exc,)) from exc
        bpp, block = len(p1), sum(s1)
        if bpp < 1 or block <= 0 or len(s1) != bpp:
            raise MiraRefusal("miracache: host pool returned no page buffers")
        if len(p2) != 2 * bpp or p2[:bpp] != p1 or s2 != s1 + s1:
            raise MiraRefusal("miracache: host pool get_page_buffer_meta is not page-major "
                              "(page 0's buffers first); unsupported layout")
        # One page (page_size tokens x every layer of this TP rank) is one stored block; refuse when a memory
        # node's store.run_bytes cannot hold it (every put would be refused). Runbook: memnode store sizing.
        why = block_size_refusal(self._client, block, "SGLang page (%d tokens, %d buffers, this TP rank)"
                                 % (ps, bpp), log)
        if why:
            raise MiraRefusal(why)
        version = engine_version()
        # Before any state changes: a refusal here leaves the adapter as it was.
        if not _get(self._cfg, "model_name", None):
            raise MiraRefusal("miracache: SGLang passed no model name to the storage backend; ns "
                              "would not separate models")
        nsf = self._extra.get("ns_fields")
        if nsf is not None and not isinstance(nsf, dict):
            raise MiraRefusal("miracache: extra-config \"ns_fields\" must be a JSON object")
        try:
            ns = _ns.digest(namespace_fields(self._cfg, mem_pool_host, page_size=ps, block_bytes=block,
                                             buffers_per_page=bpp, extra=self._extra, version=version))
        except (TypeError, ValueError) as exc:
            raise MiraRefusal("miracache: cannot build ns (check extra-config \"ns_fields\": JSON "
                              "values only, string keys): %s" % (exc,)) from None
        with self._lock:
            if self._region is not None:
                try:
                    self._client.detach_region(self._region)
                except Exception as exc:  # noqa: BLE001
                    self._err("detach_region", exc)
                self._region = None
            self.mem_pool_host = mem_pool_host
            self.page_size, self.block_bytes, self.buffers_per_page = ps, block, bpp
            self._sizes = s1
            try:
                self._new_stage()
            except Exception as exc:  # noqa: BLE001
                raise MiraRefusal("miracache: cannot attach staging region: %r" % (exc,)) from exc
            self.ns = ns
            log.info("miracache sglang ns fingerprint %s (sglang %s, kv dtype %s, tp %d/%d, "
                     "%d buffers/page, %d B/page)", _ns.fingerprint(ns), version or "?",
                     pool_dtype(mem_pool_host) or "?", self.tp_rank, self.tp_size, bpp, block)
            self._scopes.clear()
            self._presence.clear()
            self._orphans.clear()
            self._degraded = False
            self.ready = True

    # ---- interface_v1 -----------------------------------------------
    def batch_exists(self, keys: List[str], extra_info: Any = None) -> int:
        """Number of consecutive leading keys present (hicache_storage.py:543)."""
        try:
            with self._lock:
                return self._exists(keys, extra_info)
        except Exception as exc:  # noqa: BLE001
            self._err("batch_exists", exc)
            return 0

    def _lookup(self, scope: Any, bkeys: List[bytes]) -> List[str]:
        """One batched submission for all keys; per-key fallback for clients without it."""
        dl = self._lookup_deadline_ms
        many = getattr(self._client, "lookup_many", None)
        if many is not None:
            return list(many(scope, bkeys, None, dl))
        return [self._client.lookup_nb(scope, k) for k in bkeys]

    def _reap_orphans(self) -> None:
        """Keys a previous call gave up waiting for: their answers are consumed and discarded so
        no stale HIT/MISS is read by a later call."""
        for sid, (scope, bks) in list(self._orphans.items()):
            try:
                r = self._lookup(scope, bks)
            except Exception as exc:  # noqa: BLE001
                self._err("reap_lookup", exc)
                r = []
            left = [k for k, a in zip(bks, r) if a == "PENDING"]
            if left:
                self._orphans[sid] = (scope, left)
            else:
                del self._orphans[sid]

    def _exists(self, keys: List[str], extra_info: Any) -> int:
        self._revive()
        if not self.ready:
            return 0
        ch = self._chain(keys, extra_info)
        if ch is None:
            return 0
        root, scope, _ = ch
        self._reap_orphans()
        now = self._clock()
        bk = [_b(k) for k in keys]
        res: List[Optional[str]] = [None] * len(keys)
        pend: List[int] = []
        for i, k in enumerate(keys):
            if self._presence.get((root, k), 0.0) > now:
                res[i] = "HIT"
            else:
                pend.append(i)
        if pend:  # one batched lookup, one deadline for the whole call
            end = self._clock() + self._lookup_deadline_ms / 1000.0 + LOOKUP_GRACE_S
            while True:
                ans = self._lookup(scope, [bk[i] for i in pend])
                nxt = []
                for i, a in zip(pend, ans):
                    if a == "PENDING":
                        nxt.append(i)
                    else:
                        res[i] = a
                pend = nxt
                if not pend or self._clock() >= end:
                    break
                time.sleep(0.0005)
            if pend:  # gave up: consume the late answers on a later call, never use them
                if sum(len(v[1]) for v in self._orphans.values()) < 4096:
                    self._orphans.setdefault(id(scope), (scope, []))[1].extend(bk[i] for i in pend)
                self._bump("lookup_deadline")
        n = 0
        for i, k in enumerate(keys):
            if res[i] != "HIT":
                break
            self._presence[(root, k)] = now + PRESENCE_TTL_S
            n += 1
        if len(self._presence) > 65536:
            self._presence = {p: e for p, e in self._presence.items() if e > now}
        self.adapter.inc(LOOKUP_TOKENS, len(keys) * self.page_size)
        self.adapter.inc(HIT_TOKENS, n * self.page_size)
        return n

    def _io(self, kind: str, keys: List[str], host_indices: Any, extra_info: Any) -> List[bool]:
        out = self._io_inner(kind, keys, host_indices, extra_info)
        if kind == "get":
            ok = sum(1 for x in out if x)
            self.adapter.inc(RECOMPUTE_AVOIDED, ok * self.page_size)
            self.adapter.inc(LOAD_FAIL, len(keys) - ok)
        return out

    def _io_inner(self, kind: str, keys: List[str], host_indices: Any, extra_info: Any) -> List[bool]:
        n = len(keys)
        out = [False] * n
        where = "batch_get_v1" if kind == "get" else "batch_set_v1"
        try:
            if n == 0:
                return []
            with self._lock:
                self._revive()
                if not self.ready:
                    return out
                ch = self._chain(keys, extra_info)
                if ch is None:
                    return out
                _root, scope, prefix = ch
                self._count_batch(prefix)
                pages = self._page_buffers(host_indices, n)
                bkeys = [_b(k) for k in keys]
                parents: List[Optional[bytes]] = [_b(prefix[-1]) if prefix else None] + bkeys[:-1]
                pos = [(len(prefix) + i + 1) * self.page_size for i in range(n)]
                for lo in range(0, n, self._stage_pages):
                    if not self.ready:
                        break
                    hi = min(n, lo + self._stage_pages)
                    try:
                        out[lo:hi] = self._chunk(kind, scope, bkeys[lo:hi], parents[lo:hi],
                                                 pos[lo:hi], pages[lo:hi])
                    except _Abandoned:
                        break  # the first timeout fails the rest of the batch
                    except Exception as exc:  # noqa: BLE001
                        self._err(where, exc)
            return out
        except Exception as exc:  # noqa: BLE001
            self._err(where, exc)
            return [False] * n

    def _chunk(self, kind: str, scope: Any, bkeys: List[bytes], parents: List[Any],
               pos: List[int], pages: List[List[Any]]) -> List[bool]:
        m = len(bkeys)
        offs = [i * self.block_bytes for i in range(m)]
        lens = [self.block_bytes] * m
        if kind == "get":
            t = self._client.fetch(scope, bkeys, parents, pos, offs, OP_DEADLINE_MS, lens, self._region)
        else:
            self._gather(pages)
            t = self._client.put(scope, bkeys, parents, pos, offs, OP_DEADLINE_MS, lens, self._region)
        free = False  # True once the op no longer touches the staging region
        self._awaiting.add(t)
        try:
            end = self._clock() + IO_TIMEOUT_S
            if not self._wait_until(lambda: t in self._done, end):
                self._abandon(t, "io_timeout")
                raise _Abandoned()
            if not self._wait_until(lambda: self._is_free(t), end):
                self._abandon(t, "release_timeout")  # still holds the region: same as a timeout
                raise _Abandoned()
            free = True
            c = self._done.get(t)
            self._forget(t)
            ok_keys = set(c.successful_keys)
            ok = [b in ok_keys for b in bkeys]
            if kind == "get":
                self._scatter(pages, ok)
            return ok
        except _Abandoned:
            raise
        except BaseException as exc:  # the op may be live: never reuse its staging region
            if free:
                raise
            self._err("chunk_wait", exc)
            self._abandon(t, "io_error")
            raise _Abandoned() from exc
        finally:
            self._awaiting.discard(t)  # a quarantined op stays protected through self._quarantine

    def batch_get_v1(self, keys: List[str], host_indices: Any, extra_info: Any = None) -> List[bool]:
        return self._io("get", keys, host_indices, extra_info)

    def batch_set_v1(self, keys: List[str], host_indices: Any, extra_info: Any = None) -> List[bool]:
        return self._io("set", keys, host_indices, extra_info)

    # ---- legacy v0 single-key methods: unsupported, always a miss ----------
    def get(self, key: str, target_location: Any = None, target_sizes: Any = None) -> Any:
        return None

    def batch_get(self, keys: List[str], target_locations: Any = None, target_sizes: Any = None) -> Any:
        return [None] * len(keys)

    def set(self, key: str, value: Any = None, target_location: Any = None, target_sizes: Any = None) -> bool:
        return False

    def batch_set(self, keys: List[str], values: Any = None, target_locations: Any = None,
                  target_sizes: Any = None) -> bool:
        return False

    def exists(self, key: str) -> bool:
        return False

    # v2 (hybrid sidecar pools, hicache_storage.py:399-447): not supported in v1.
    # Correctly typed all-miss results (the callers index into them).
    def batch_exists_v2(self, keys: List[str], pool_transfers: Any = None,
                        extra_info: Any = None) -> "PoolTransferResult":
        return PoolTransferResult.empty()

    def batch_get_v2(self, transfers: List[Any], extra_info: Any = None) -> Dict[str, List[bool]]:
        return self._v2_miss(transfers)

    def batch_set_v2(self, transfers: List[Any], extra_info: Any = None) -> Dict[str, List[bool]]:
        return self._v2_miss(transfers)

    @staticmethod
    def _v2_miss(transfers: Any) -> Dict[str, List[bool]]:
        out: Dict[str, List[bool]] = {}
        try:
            for t in transfers or []:
                out[str(_get(t, "name"))] = [False] * len(_get(t, "keys", None) or [])
        except Exception:  # noqa: BLE001
            pass
        return out

    def get_stats(self) -> Dict[str, int]:
        return dict(self.counters)

    def close(self) -> None:
        """The real client's close aborts and drains every in-flight op before returning, so
        quarantined staging buffers can be dropped after it."""
        srv, self._metrics_srv = getattr(self, "_metrics_srv", None), None
        if srv is not None:
            srv.stop()
        with self._lock:  # no data-path call may be inside the client while it closes
            try:
                c = getattr(self._client, "close", None)
                if c:
                    c()
            except Exception as exc:  # noqa: BLE001
                self._err("close", exc)
            self.ready, self._degraded = False, False
            self._quarantine.clear()
