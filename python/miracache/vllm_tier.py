"""vLLM secondary tier: ``MiraTier(SecondaryTierManager)``.

Loaded by vLLM (tiering/factory.py at the pin) from ``kv_connector_extra_config``::

    {"spec_name": "TieringOffloadingSpec", "cpu_bytes_to_use": N, "canonical_layout": true,
     "secondary_tiers": [{"type": "MiraTier", "module_path": "miracache.vllm_tier",
                          "config": "/etc/miracache/client.toml",
                          "kv_load_failure_policy": "recompute"}]}

The factory calls ``MiraTier(offloading_spec=, primary_kv_view=, tier_type=,
backpressure_detector=, **rest_of_tier_dict)``, so ``config`` (a path string) arrives as a
keyword. The module imports without vLLM; the class is built on first attribute access
(PEP 562) so the base class is the real one at run time and a stand-in in tests.

Rules: refuse to start only on a real incompatibility (``CompatError`` from ``__init__``),
but never raise from a data-path method: failure is a miss or a failed ``JobResult``.
No vLLM patches; the only private read is ``ReqContext._offload_key_positions``
(guarded by ``miracache.vllm.compat``). The tier sees only ``OffloadingConfig``: it checks
canonical_layout and PP/CP; the hash algo is checked by ``miracache.check_vllm_config`` before launch.
``kv_load_failure_policy`` is not visible either, so the tier entry must repeat it
(``"kv_load_failure_policy": "recompute"``, the operator's promise; the tier refuses to start
without it, and check_vllm_config / preflight fail when it differs from the top-level value).

Addressing: the primary KV view is registered once (``attach_region``); key ``i`` of a job
lives at ``job.chunk_ids[i] * primary_kv_view.strides[0]``. ``JobResult.deferred_release`` is
used only for failed promotion jobs and only where the field exists (absent in 0.32/0.33);
every event is set on release, on ``drain_jobs`` or on ``shutdown``. A drain that times out
fails every open job and closes the client (aborting its I/O) before any event is set. A drain
that completes re-opens intake (vLLM calls it from ``reset_cache`` and keeps running); only
``shutdown`` and a timed-out drain leave the tier closed.

Namespace: ``ns`` (32 bytes, ``compat.namespace_digest``) is computed here from the
OffloadingConfig, the slot stride and the vLLM version; optional tier key ``model_revision``
adds the weights revision and ``ns_fields`` (a JSON object, e.g. ``{"quantization": "fp8"}``)
anything else vLLM does not pass to a tier; preflight fails when ``--revision`` or
``--quantization`` is not mirrored. Hosts whose ``ns_fingerprint`` log lines differ never share
blocks.

Tier keys (all optional besides ``config``): ``drain_timeout_s`` (10), ``locality``,
``model_revision``, ``ns_fields``, and the per-op client deadlines in milliseconds (spec 3: every op has a
deadline, expiry = miss; without them the C default of 10 s applies): ``fetch_deadline_ms``
(300, load jobs), ``lookup_deadline_ms`` (50, lookups), ``store_deadline_ms`` (2000, store jobs).

Metrics keys: ``metrics_port`` (0 = off, default) serves ``GET /metrics`` (Prometheus text: the
client's ``miracache_client_*`` series plus ``miracache_adapter_*`` / ``miracache_recompute_*``)
on ``metrics_port + rank`` from a daemon thread; ``metrics_host`` (127.0.0.1) is the bind
address; ``metrics_rank`` overrides the rank taken from MIRACACHE_RANK / LOCAL_RANK / RANK (0).
"""
from __future__ import annotations

import logging
import sys
import threading
from typing import Any, Callable, Optional

from ._core import block_size_refusal
from .adapter_metrics import combined_text, rank_from_env, start_metrics_server
from .vllm import compat
from .vllm.core import Job, Layout, Lookup, TierCore
from .vllm.never_raise import never_raise

log = logging.getLogger("miracache.vllm_tier")

__all__ = ["MiraTier"]
_cls: Optional[type] = None


def _engine_failure_policy() -> Optional[str]:
    """vLLM's own kv_load_failure_policy when the current config is reachable here, else None. At the pin the
    scheduler builds connectors outside a set_current_vllm_config() context, so this is usually None (then the tier
    entry's promise is the check)."""
    try:
        from vllm.config import get_current_vllm_config_or_none  # type: ignore
        cfg = get_current_vllm_config_or_none()
        kvt = getattr(cfg, "kv_transfer_config", None) if cfg is not None else None
        v = getattr(kvt, "kv_load_failure_policy", None)
        return None if v is None else str(v)
    except Exception:  # noqa: BLE001 - not available in this vLLM / no config: nothing to check
        return None


def _default_client_factory(config_path: str) -> Any:
    from miracache import Client  # type: ignore[attr-defined]
    return Client.open(config_path)


def _build() -> type:
    from vllm.v1.kv_offload.base import LookupResult, RequestOffloadingContext
    from vllm.v1.kv_offload.tiering.base import (JobResult, SecondaryTierManager,
                                                 TransferJob)

    lookup_map = {Lookup.HIT: LookupResult.HIT, Lookup.MISS: LookupResult.MISS,
                  Lookup.RETRY: LookupResult.RETRY}
    has_dr = compat.has_deferred_release(JobResult)

    class MiraTier(SecondaryTierManager):  # type: ignore[misc, valid-type]
        client_factory: Optional[Callable[[str], Any]] = None
        KNOWN_KEYS = ("config", "drain_timeout_s", "locality", "model_revision", "ns_fields", "kv_load_failure_policy",
                      "fetch_deadline_ms", "lookup_deadline_ms", "store_deadline_ms",
                      "metrics_port", "metrics_host", "metrics_rank")

        def __init__(self, offloading_spec: Any, primary_kv_view: memoryview, tier_type: str,
                     backpressure_detector: Any = None, **tier_kwargs: Any) -> None:
            # Real call: tiering/factory.py:91-97 (tier dict minus type/module_path/backpressure
            # splatted as keywords; "config" arrives as a path string).
            self.counters: dict = {}
            self._logged: set = set()
            self._core: Optional[TierCore] = None
            self._events: dict = {}  # job_id -> Event handed to vLLM (failed promotions only)
            self._released_early: set = set()
            self._held: dict = {}  # job_id -> result waiting for the client's release
            self._ready: list = []  # results to emit on the next get_finished_jobs
            self._closed = False
            self._region: Optional[int] = None
            self._metrics_srv: Any = None
            cfg_path = tier_kwargs.get("config")
            self._startup_checks(offloading_spec, cfg_path, tier_kwargs)
            unknown = sorted(set(tier_kwargs) - set(self.KNOWN_KEYS))
            if unknown:
                log.warning("MiraTier: ignoring unknown tier keys %s", unknown)
            super().__init__(offloading_spec, primary_kv_view, tier_type, backpressure_detector)
            bsb = int(self.block_size_bytes)
            tpcs = compat.tokens_per_chunk_by_group(offloading_spec)
            if bsb <= 0:
                raise compat.CompatError("primary_kv_view.strides[0] must be positive")
            # ns: the 32-byte namespace digest of everything that makes KV bytes comparable
            # (design spec 2.6). Computed here, never taken from the client, and before the
            # client opens so a bad field refuses without leaking a client.
            try:
                ns = compat.namespace_digest(offloading_spec, bsb, tpcs, self._vllm_version(),
                                             tier_kwargs.get("model_revision"),
                                             tier_kwargs.get("ns_fields"))
            except (TypeError, ValueError) as exc:
                raise compat.CompatError(f"cannot build ns (check the MiraTier \"ns_fields\" and the "
                                         f"OffloadingConfig): {exc}") from None
            factory = type(self).client_factory or _default_client_factory
            client = factory(str(cfg_path))
            num_slots = int(primary_kv_view.shape[0]) if primary_kv_view.shape else 0
            try:
                # K03: one chunk slot (all layers, all TP ranks' shards) is one stored block; refuse to start when a
                # memory node's store.run_bytes cannot hold it (every store would be refused).
                why = block_size_refusal(client, bsb, "vLLM chunk slot (primary_kv_view.strides[0])", log)
                if why:
                    raise compat.CompatError("MiraTier refuses to start: " + why)
                try:  # register the primary KV view once; keys are addressed by chunk_id * stride
                    self._region = client.attach_region(primary_kv_view, bsb)
                except Exception as exc:  # noqa: BLE001
                    raise compat.CompatError(f"attach_region(primary_kv_view) failed: {exc!r}") from exc
                self._client = client
                self._core = TierCore(client, Layout(tpcs[0], bsb, ns, tpcs, self._region, num_slots))
                self._drain_timeout = float(tier_kwargs.get("drain_timeout_s", 10.0))
                self._fetch_deadline_ms = int(tier_kwargs.get("fetch_deadline_ms", 300))
                self._store_deadline_ms = int(tier_kwargs.get("store_deadline_ms", 2000))
                self._core.lookup_deadline_ms = int(tier_kwargs.get("lookup_deadline_ms", 50))
                core = self._core
                rank = tier_kwargs.get("metrics_rank")
                self._metrics_srv = start_metrics_server(
                    tier_kwargs, rank_from_env() if rank is None else int(rank),
                    lambda: combined_text(client, core.adapter))
            except BaseException:  # V03: never leak the open client when start-up fails
                self._core = None
                try:
                    client.close()
                except Exception:  # noqa: BLE001
                    pass
                raise
            log.info("MiraTier up: tokens_per_chunk=%s slot_bytes=%d slots=%d ns_fingerprint=%s",
                     list(tpcs), bsb, num_slots, ns.hex()[:8])

        @staticmethod
        def _vllm_version() -> str:
            return str(getattr(sys.modules.get("vllm"), "__version__", None) or "unknown")

        # -- start-up refusal (real incompatibilities only) ------------------
        def _startup_checks(self, spec: Any, cfg_path: Any, tier_kwargs: Optional[dict] = None) -> None:
            import vllm.v1.kv_offload.base as kvbase  # fresh lookup, not the build-time one
            import vllm.v1.kv_offload.tiering.base as tbase
            errs = []
            if not isinstance(cfg_path, str) or not cfg_path:
                errs.append("tier entry needs 'config': path to client.toml (string)")
            # s12 (tpu-sync cross-check C3): a lookup HIT takes no lease, so a block can be evicted before its load: the
            # load then fails and only kv_load_failure_policy="recompute" turns that into a recompute (vLLM's default
            # "fail" fails the user's request). vLLM does not pass that setting to a tier, so the operator repeats it in
            # the MiraTier entry (the same promise pattern as SGLang's miracache_expect_prefix_keys); preflight checks
            # that the two agree. Where vLLM does expose its config, the real value is checked too.
            pol = (tier_kwargs or {}).get("kv_load_failure_policy")
            if pol != "recompute":
                errs.append('tier entry needs "kv_load_failure_policy": "recompute" (and the same at the top level of '
                            "--kv-transfer-config): the tier cannot see vLLM's setting, and its default \"fail\" turns "
                            f"a cache miss into a request error; got {pol!r}")
            real = _engine_failure_policy()
            if real is not None and real != "recompute":
                errs.append(f'vLLM kv_transfer_config.kv_load_failure_policy is {real!r}; it must be "recompute"')
            version = getattr(sys.modules.get("vllm"), "__version__", None) or "unknown"
            # A source tree without scm metadata reports "dev": the probes are the gate then.
            errs += compat.full_check(
                version=None if version == "dev" else version,
                base_cls=SecondaryTierManager, req_context_cls=kvbase.ReqContext,
                settings=compat.settings_from_offloading_config(getattr(spec, "config", None)),
                transfer_job_cls=getattr(tbase, "TransferJob", TransferJob),
                job_result_cls=getattr(tbase, "JobResult", JobResult))
            if errs:
                raise compat.CompatError("MiraTier refuses to start: " + "; ".join(errs))

        # -- helpers ---------------------------------------------------------
        def _skip(self, ctx: Any) -> bool:
            p = getattr(ctx, "kv_transfer_params", None) or {}
            m = p.get("miracache") if isinstance(p, dict) else None
            return bool(isinstance(m, dict) and m.get("skip"))

        def _job(self, job: Any) -> Job:
            ctx = job.req_context
            return Job(job.job_id, str(ctx.req_id), list(job.keys),
                       dict(compat.positions_of(ctx)),
                       deadline_ms=(self._fetch_deadline_ms if job.is_promotion
                                    else self._store_deadline_ms),
                       chunk_ids=[int(c) for c in job.chunk_ids],
                       is_promotion=bool(job.is_promotion))

        def _fail_job(self, job: Any) -> None:
            """Internal error: the job still ends with a failed JobResult (never left open)."""
            jid = getattr(job, "job_id", None)
            if jid is not None and self._core is not None:
                self._core._fail(Job(jid, "", [], {},
                                     is_promotion=bool(getattr(job, "is_promotion", False))))

        def _make(self, r: Any, ev: Optional[threading.Event] = None) -> Any:
            kw: dict = dict(job_id=r.job_id, success=r.success,
                            successful_keys=list(r.successful_keys) if r.is_promotion else None)
            if ev is not None:
                kw["deferred_release"] = ev
            return JobResult(**kw)

        def _sync_events(self) -> None:
            core = self._core
            assert core is not None
            ids, core.released = core.released, []
            for jid in ids:
                ev = self._events.pop(jid, None)
                held = self._held.pop(jid, None)
                if ev is not None:
                    ev.set()
                elif held is not None:
                    self._ready.append(self._make(held))
                else:
                    self._released_early.add(jid)

        def _release_all(self) -> None:
            """Drain / shutdown: no outstanding event may stay unset (tiering/base.py:388-390)."""
            self._closed = True
            for ev in list(self._events.values()):
                ev.set()
            self._events.clear()
            for r in list(self._held.values()):
                self._ready.append(self._make(r))
            self._held.clear()

        # -- SecondaryTierManager API ---------------------------------------
        @never_raise(lambda self, exc, *a, **k: RequestOffloadingContext())
        def on_new_request(self, req_context: Any) -> Any:
            self._core.on_new_request(str(req_context.req_id))
            return RequestOffloadingContext()

        @never_raise(lambda self, exc, *a, **k: LookupResult.MISS)
        def lookup(self, key: bytes, req_context: Any) -> Any:
            if self._skip(req_context):
                return LookupResult.MISS
            pos = compat.positions_of(req_context)
            return lookup_map[self._core.lookup(str(req_context.req_id), key, pos)]

        @never_raise(lambda self, exc, *a, **k: self._fail_job(
            a[0] if a else k.get("job_metadata")))
        def submit_load(self, job_metadata: Any) -> None:
            if self._skip(job_metadata.req_context):
                self._fail_job(job_metadata)
            else:
                self._core.load(self._job(job_metadata))

        @never_raise(lambda self, exc, *a, **k: self._fail_job(
            a[0] if a else k.get("job_metadata")))
        def submit_store(self, job_metadata: Any) -> None:
            if self._skip(job_metadata.req_context):
                self._fail_job(job_metadata)
            else:
                self._core.store(self._job(job_metadata))

        @never_raise(lambda self, exc: [])
        def get_finished_jobs(self) -> list:
            out, self._ready = self._ready, []
            for r in self._core.finished():
                if not r.deferred_release:
                    out.append(self._make(r))
                    continue
                released = r.job_id in self._released_early or self._closed
                self._released_early.discard(r.job_id)
                if has_dr and r.is_promotion and not r.success:
                    # The only case vLLM accepts an event for (manager.py:573-574, 627-629).
                    ev = threading.Event()
                    if released:
                        ev.set()
                    else:
                        self._events[r.job_id] = ev
                    out.append(self._make(r, ev))
                elif released:
                    out.append(self._make(r))
                else:  # cannot express a deferred release: report once the client released
                    self._held[r.job_id] = r
            self._sync_events()
            out += self._ready
            self._ready = []
            return out

        @never_raise(lambda self, exc: None)
        def drain_jobs(self) -> None:
            try:
                self._core.drain(self._drain_timeout)
                self._sync_events()
            finally:
                self._release_all()
                self._core.reopen()  # reset_cache() drains, then the engine keeps using the tier

        @never_raise(lambda self, exc: False)
        def has_pending_work(self) -> bool:
            return bool(self._core.pending() or self._events or self._held or self._ready)

        @never_raise(lambda self, exc, *a, **k: None)
        def on_request_finished(self, req_context: Any) -> None:
            self._core.on_request_finished(str(req_context.req_id))

        @never_raise(lambda self, exc: None)
        def shutdown(self) -> None:
            try:
                self._core.drain(self._drain_timeout)
                self._sync_events()
            finally:
                srv, self._metrics_srv = self._metrics_srv, None
                if srv is not None:
                    srv.stop()
                self._release_all()
                region, self._region = self._region, None
                if not self._core.client_closed:  # a timed-out drain already closed it
                    try:
                        if region is not None:
                            self._client.detach_region(region)
                    finally:
                        close = getattr(self._client, "close", None)
                        if close is not None:
                            close()

    return MiraTier


def __getattr__(name: str) -> Any:
    global _cls
    if name == "MiraTier":
        if _cls is None:
            _cls = _build()
        return _cls
    raise AttributeError(name)
