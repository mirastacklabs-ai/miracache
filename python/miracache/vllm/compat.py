"""vLLM compatibility gate: version pin, signature probes, private-field check.

Pure Python; imports nothing from vllm at module load. Everything here either returns
a list of human-readable problems or raises ``CompatError`` (start-up only: the data
path never raises, see ``MiraTier``).
"""
from __future__ import annotations

import dataclasses
import inspect
import os
import re
from typing import Any, Mapping, Optional

from .. import ns as _ns

# Tested range. 0.32.0 = first tag with kv_offload/tiering (research/16); main 65711a1
# (reports 0.34.x) was the verification pin. Upper bound is exclusive: widen only after
# L9 passes there. The signature probes below are the real gate; this range is a guard.
MIN_VERSION = (0, 32, 0)
MAX_VERSION_EXCLUSIVE = (0, 35, 0)

PRIVATE_FIELD = "_offload_key_positions"

# method -> number of positional parameters after self (research/16, design spec 2.3).
EXPECTED_METHODS: Mapping[str, int] = {
    "lookup": 2,  # (key, req_context)
    "submit_load": 1,  # (job)
    "submit_store": 1,  # (job)
    "get_finished_jobs": 0,
    "drain_jobs": 0,
    "on_new_request": 1,  # (req_context)
    "on_request_finished": 1,
}


# Fields the adapter reads / builds (tiering/base.py:74-106 at the pin).
TRANSFER_JOB_FIELDS = ("job_id", "keys", "chunk_ids", "is_promotion", "req_context")
JOB_RESULT_FIELDS = ("job_id", "success", "successful_keys")
INIT_PARAMS = ("offloading_spec", "primary_kv_view", "tier_type", "backpressure_detector")


class CompatError(RuntimeError):
    """vLLM does not match what MiraTier was tested against; refuse to start."""


def parse_version(v: str) -> tuple:
    m = re.match(r"^\s*v?(\d+)\.(\d+)(?:\.(\d+))?", str(v))
    if not m:
        raise CompatError(f"unparseable vLLM version {v!r}")
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def check_version(v: str) -> list:
    try:
        t = parse_version(v)
    except CompatError as e:
        return [str(e)]
    if t < MIN_VERSION or t >= MAX_VERSION_EXCLUSIVE:
        lo = ".".join(map(str, MIN_VERSION))
        hi = ".".join(map(str, MAX_VERSION_EXCLUSIVE))
        return [f"vLLM {v} is outside the tested range [{lo}, {hi})"]
    return []


def check_signatures(base_cls: type) -> list:
    errs = []
    for name, nparams in EXPECTED_METHODS.items():
        fn = getattr(base_cls, name, None)
        if fn is None or not callable(fn):
            errs.append(f"{base_cls.__name__}.{name} is missing")
            continue
        try:
            sig = inspect.signature(fn)
        except (TypeError, ValueError):
            errs.append(f"{base_cls.__name__}.{name} has no inspectable signature")
            continue
        params = [p for p in sig.parameters.values()
                  if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)]
        has_var = any(p.kind == p.VAR_POSITIONAL for p in sig.parameters.values())
        if len(params) - 1 < nparams and not has_var:  # minus self
            errs.append(f"{base_cls.__name__}.{name} takes {len(params) - 1} positional "
                        f"parameters, expected {nparams}")
    return errs


def _field_names(cls: type) -> set:
    if dataclasses.is_dataclass(cls):
        return {f.name for f in dataclasses.fields(cls)}
    return set(getattr(cls, "__annotations__", {}))


def has_deferred_release(job_result_cls: type) -> bool:
    """JobResult.deferred_release exists on main only (absent in 0.32/0.33): feature-detect."""
    return "deferred_release" in _field_names(job_result_cls)


def check_init_signature(base_cls: type) -> list:
    """SecondaryTierManager.__init__ must accept the four args the factory passes by keyword
    (tiering/factory.py:91-97)."""
    try:
        params = inspect.signature(base_cls.__init__).parameters
    except (TypeError, ValueError):
        return [f"{base_cls.__name__}.__init__ has no inspectable signature"]
    missing = [p for p in INIT_PARAMS if p not in params]
    if missing:
        return [f"{base_cls.__name__}.__init__ lacks parameters {missing}"]
    return []


def check_job_types(transfer_job_cls: type, job_result_cls: type) -> list:
    errs = []
    miss = [f for f in TRANSFER_JOB_FIELDS if f not in _field_names(transfer_job_cls)]
    if miss:
        errs.append(f"TransferJob lacks fields {miss}")
    miss = [f for f in JOB_RESULT_FIELDS if f not in _field_names(job_result_cls)]
    if miss:
        errs.append(f"JobResult lacks fields {miss}")
    return errs


def check_req_context_class(cls: type) -> list:
    """Class-level check of the private field (no instance exists at start-up)."""
    found = False
    if dataclasses.is_dataclass(cls):
        found = any(f.name == PRIVATE_FIELD for f in dataclasses.fields(cls))
    found = (found or PRIVATE_FIELD in getattr(cls, "__annotations__", {})
             or hasattr(cls, PRIVATE_FIELD) or PRIVATE_FIELD in getattr(cls, "__slots__", ()))
    if not found:
        try:  # plain class assigning self.<field> in __init__
            found = PRIVATE_FIELD in inspect.getsource(cls)
        except (OSError, TypeError):
            found = False
    if not found:
        return [f"{cls.__name__}.{PRIVATE_FIELD} not found: vLLM no longer exposes the "
                "chain-root source; refusing to start"]
    return []


def positions_of(req_context: Any) -> dict:
    """Runtime read of the private field. Raises CompatError unless it is a dict."""
    d = getattr(req_context, PRIVATE_FIELD, None)
    if not isinstance(d, dict):
        raise CompatError(f"ReqContext.{PRIVATE_FIELD} is {type(d).__name__}, expected dict")
    return d


# -- configuration the spec requires of vLLM ---------------------------------------
def validate_tier_settings(s: Mapping[str, Any]) -> list:
    """What the tier itself can see in OffloadingConfig: canonical_layout, PP, CP.
    ``s`` keys: canonical_layout, pipeline_parallel_size, context_parallel_size."""
    errs = []
    if s.get("canonical_layout") is not True:
        errs.append("kv_connector_extra_config.canonical_layout must be true")
    for k, label in (("pipeline_parallel_size", "pipeline parallelism"),
                     ("context_parallel_size", "context parallelism")):
        v = s.get(k, 1)
        if v not in (None, 1):
            errs.append(f"{label} must be 1 (canonical layout); got {v!r}")
    return errs


def validate_settings(s: Mapping[str, Any]) -> list:
    """Operator-side preflight (check_vllm_config only; the tier never sees these).
    ``s`` keys: canonical_layout, kv_load_failure_policy, prefix_caching_hash_algo,
    block_size, pipeline_parallel_size, context_parallel_size, enable_log_requests."""
    errs = validate_tier_settings(s)
    if s.get("kv_load_failure_policy") != "recompute":
        errs.append("kv_load_failure_policy must be 'recompute' (default 'fail' turns a "
                    f"cache miss into a request error); got {s.get('kv_load_failure_policy')!r}")
    if s.get("prefix_caching_hash_algo") != "sha256_cbor":
        errs.append("--prefix-caching-hash-algo must be sha256_cbor; got "
                    f"{s.get('prefix_caching_hash_algo')!r}")
    bs = s.get("block_size")
    if bs is not None and (not isinstance(bs, int) or isinstance(bs, bool) or bs <= 0):
        errs.append(f"block_size must be a positive integer; got {bs!r}")
    if s.get("enable_log_requests"):
        errs.append("request logging must be off (it logs kv_transfer_params / cache_salt)")
    return errs


def _dig(obj: Any, *path: str, default: Any = None) -> Any:
    for p in path:
        obj = obj.get(p) if isinstance(obj, dict) else getattr(obj, p, None)
        if obj is None:
            return default
    return obj


def settings_from_offloading_config(cfg: Any) -> dict:
    """Extract what the tier can check from ``OffloadingConfig`` (v1/kv_offload/config.py:70-95;
    parallel.pp_size / pcp_size / dcp_size at :43-61). No VllmConfig reaches the tier."""
    par = getattr(cfg, "parallel", None)
    pcp = getattr(par, "pcp_size", 1) or 1
    dcp = getattr(par, "dcp_size", 1) or 1
    return {
        "canonical_layout": getattr(cfg, "canonical_layout", None),
        "pipeline_parallel_size": getattr(par, "pp_size", 1) or 1,
        "context_parallel_size": pcp * dcp,
    }


def tokens_per_chunk_by_group(offloading_spec: Any) -> tuple:
    """tokens_per_block[g] * blocks_per_chunk (kv_offload/base.py:794-796; scheduler.py:153)."""
    tpb = tuple(getattr(offloading_spec, "tokens_per_block", ()) or ())
    bpc = int(getattr(offloading_spec, "blocks_per_chunk", 0) or 0)
    out = tuple(int(t) * bpc for t in tpb)
    if not out or any(v <= 0 for v in out):
        raise CompatError(f"cannot derive tokens_per_chunk from tokens_per_block={tpb!r} "
                          f"blocks_per_chunk={bpc!r}")
    return out


NS_DOMAIN = _ns.NS_DOMAIN  # kept for importers; the encoding lives in miracache/ns.py
NS_HASH_ALGO = "sha256_cbor"  # the only algo check_vllm_config accepts (spec 2.5)


def namespace_fields(offloading_spec: Any, slot_bytes: int, tokens_per_chunk: tuple,
                     engine_version: Optional[str], model_revision: Optional[str] = None,
                     ns_fields: Optional[Mapping[str, Any]] = None) -> dict:
    """What ``ns`` covers (design spec 2.6, design/03 R19): engine and version, model id (the
    weights path, ``model_config.model``) and revision, KV dtype (the cache dtype) and layout,
    slot stride and chunking per group, prefix-hash algo and seed, TP rank/size, plus the
    optional tier key ``ns_fields`` (e.g. ``{"quantization": "fp8"}``: values vLLM does not pass
    to a tier; preflight fails when --quantization is not mirrored). ``extra_ns`` is added only
    when ``ns_fields`` is non-empty, so the ns of a tier without it is unchanged. Lookahead
    tokens are not visible to the tier. Raises CompatError when the model id or KV dtype is
    missing (ns would then not separate models)."""
    cfg = getattr(offloading_spec, "config", None)
    model = _dig(cfg, "model", "name")
    dtype = _dig(cfg, "model", "dtype")
    if not model or not dtype:
        raise CompatError("OffloadingConfig.model.name / .dtype missing: cannot build ns")
    groups = [[int(getattr(g, "group_id", i)), int(getattr(g, "tokens_per_block", 0)),
               [str(n) for n in (getattr(g, "layer_names", ()) or ())]]
              for i, g in enumerate(getattr(cfg, "groups", ()) or ())]
    if ns_fields is not None and not isinstance(ns_fields, Mapping):
        raise CompatError("MiraTier \"ns_fields\" must be a JSON object")
    extra = {"extra_ns": dict(ns_fields)} if ns_fields else {}
    return {
        **extra,
        "engine": "vllm",
        "engine_version": str(engine_version or ""),
        "model": str(model),
        "model_revision": str(model_revision or ""),
        "kv_dtype": str(dtype),
        "kv_cache_layout": _dig(cfg, "kv_cache_layout"),
        "canonical_layout": bool(_dig(cfg, "canonical_layout", default=False)),
        "replicated_layout": bool(_dig(cfg, "replicated_layout", default=False)),
        "worker_kv_bytes_per_block": int(_dig(cfg, "worker_kv_bytes_per_block", default=0)),
        "slot_stride": int(slot_bytes),
        "tokens_per_hash": int(_dig(cfg, "cache", "tokens_per_hash", default=0)),
        "blocks_per_chunk": int(_dig(cfg, "cache", "blocks_per_chunk", default=0)),
        "tokens_per_chunk": [int(t) for t in tokens_per_chunk],
        "groups": groups,
        "hash_algo": NS_HASH_ALGO,
        "hash_seed": os.environ.get("PYTHONHASHSEED"),
        "tp_rank": int(_dig(cfg, "parallel", "rank", default=0)),
        "tp_size": int(_dig(cfg, "parallel", "tp_size", default=1)),
        "world_size": int(_dig(cfg, "parallel", "world_size", default=1)),
    }


def namespace_digest(*args: Any, **kwargs: Any) -> bytes:
    """32-byte ``ns`` of ``namespace_fields`` through the one encoding (``miracache.ns.digest``).
    Same arguments give the same bytes on every host; pinned by TestNamespace (golden vector)."""
    return _ns.digest(namespace_fields(*args, **kwargs))


def full_check(*, version: Optional[str], base_cls: type, req_context_cls: Optional[type],
               settings: Mapping[str, Any], transfer_job_cls: Optional[type] = None,
               job_result_cls: Optional[type] = None) -> list:
    errs = []
    if version is not None:
        errs += check_version(version)
    errs += check_signatures(base_cls)
    errs += check_init_signature(base_cls)
    if transfer_job_cls is not None and job_result_cls is not None:
        errs += check_job_types(transfer_job_cls, job_result_cls)
    if req_context_cls is not None:
        errs += check_req_context_class(req_context_cls)
    errs += validate_tier_settings(settings)
    return errs
