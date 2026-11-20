"""Preflight checks. vLLM rules come from ``check_vllm_config``/``vllm.compat`` (reused, not
duplicated); SGLang rules mirror the adapter's refusals (``sglang.storage``). Results are
(level, id, message)."""
from __future__ import annotations

import os
from typing import Any, Dict, List, Mapping, Optional, Tuple

from .. import check_sglang_config as csc
from .. import check_vllm_config as cvc
from ..node_prep.facts import UNLIMITED
from ..sglang import storage as sgl
from ..vllm import compat
from . import engine_args as ea
from .fingerprint import make as make_fingerprint
from .secret import check_secret_file

Result = Tuple[str, str, str]  # (level "fail"|"warn", id, message)

_VLLM_IDS = (("canonical_layout", "vllm.canonical_layout"),
             ("kv_load_failure_policy", "vllm.kv_load_failure_policy"),
             ("hash-algo", "vllm.hash_algo"),
             ("block_size", "vllm.block_size"),
             ("parallelism", "vllm.parallelism"))
_OFF = ("", "0", "false", "off", "none", "no")


def _vllm_id(msg: str) -> str:
    for kw, i in _VLLM_IDS:
        if kw in msg:
            return i
    return "vllm.config"


def vllm_checks(tokens: List[str], env: Mapping[str, str], provider: str,
                version: Optional[str]) -> Tuple[List[Result], Dict[str, Any]]:
    res: List[Result] = []
    kvc = ea.flag(tokens, "--kv-transfer-config")
    s, mira, problems = cvc.settings_from_args(kvc, tokens)
    for p in problems:
        res.append(("fail", "vllm.kv_transfer_config", p))
    if not mira and not problems:
        res.append(("warn", "vllm.no_mira_tier", "no MiraTier in --kv-transfer-config "
                    "(kv_connector_extra_config.secondary_tiers); miracache is not wired in"))
    logging_on = bool(s.pop("enable_log_requests", False))
    env_log = str(env.get("VLLM_REQUEST_BODY_LOG_LEVEL", "")).strip().lower() not in _OFF
    for p in compat.validate_settings(s):
        res.append(("fail", _vllm_id(p), p))
    if version:
        for p in compat.check_version(version):
            res.append(("fail", "vllm.version", p))
    if logging_on or env_log:
        res.append(_logging_result("vllm", provider))
    if mira:
        res += _vllm_ns_results(tokens, _mira_tiers(kvc))
    fields = {"block_size": s.get("block_size"),
              "lookahead_slots": ea.to_int(ea.flag(tokens, "--num-lookahead-slots"), 0),
              "lora_paths": sorted(_lora_paths(tokens)),
              "kv_cache_dtype": ea.flag(tokens, "--kv-cache-dtype"),
              "canonical_layout": s.get("canonical_layout"),
              "hash_algo": s.get("prefix_caching_hash_algo")}
    return res, fields


def _mira_tiers(kv_transfer_config: Optional[str]) -> List[Dict[str, Any]]:
    """MiraTier entries of --kv-transfer-config ([] when absent or not valid JSON: that is
    already reported by settings_from_args)."""
    import json
    try:
        kv = json.loads(kv_transfer_config) if kv_transfer_config else {}
        tiers = (kv.get("kv_connector_extra_config") or {}).get("secondary_tiers") or []
    except (ValueError, AttributeError):
        return []
    return [t for t in tiers if isinstance(t, dict) and t.get("type") == "MiraTier"]


# Engine flags that change the KV bytes but never reach the miracache adapter. Each must be
# mirrored into ns (operator config) or two hosts that differ in it would share KV: a wrong hit,
# which the ns rules forbid, so these are fails. (flag, ns_fields key, why)
_WRONG_HIT = "hosts that differ in it (or an upgrade that changes it) would reuse KV computed differently"


def _mirror_result(engine: str, rid: str, flag: str, val: str, have: Any, where: str) -> Result:
    return ("fail", f"{engine}.{rid}",
            f"{flag} {val} is not mirrored into ns: set {where} to {val!r} (now {have!r}). "
            f"{engine} does not pass it to the miracache adapter, so {_WRONG_HIT}")


# (flags, ns_fields key, result id). A value of "auto" (dtypes) or "main" (revision: a moving ref,
# nothing to pin; the deployment guide says to pin a commit) needs no mirror. Flag names checked
# against the pinned engines' argument parsers (vLLM 0.33.0, SGLang 0.5.23).
_VLLM_MIRROR = ((("--quantization", "-q"), "quantization", "ns_quantization"),
                (("--dtype",), "dtype", "ns_dtype"),  # the cache dtype is in ns; the compute dtype is not
                (("--hf-overrides",), "hf_overrides", "ns_hf_overrides"))
_SGLANG_MIRROR = ((("--revision",), "model_revision", "ns_revision"),
                  (("--quantization",), "quantization", "ns_quantization"),
                  (("--quantization-param-path",), "quantization_param_path", "ns_quantization_params"),
                  (("--dtype",), "dtype", "ns_dtype"),
                  # the host pool's dtype separates bf16/fp16/fp8 but stores every fp8 variant as uint8
                  (("--kv-cache-dtype",), "kv_cache_dtype", "ns_kv_dtype"),
                  (("--json-model-override-args",), "model_override_args", "ns_model_override_args"))
_NO_MIRROR = ("", "auto", "main")


def _ns_fields_of(engine: str, where: str, v: Any) -> Tuple[Dict[str, Any], List[Result]]:
    if v is None:
        return {}, []
    if not isinstance(v, dict):
        return {}, [("fail", f"{engine}.ns_fields", f"{where} \"ns_fields\" must be a JSON object; got "
                     f"{type(v).__name__} (the adapter refuses to start)")]
    return v, []


def _mirror_all(engine: str, tokens: List[str], table: tuple, nsf: Mapping[str, Any],
                where: str) -> List[Result]:
    res: List[Result] = []
    for flags, key, rid in table:
        val = ea.flag(tokens, *flags)
        if val is not None and val not in _NO_MIRROR and str(nsf.get(key, "")) != val:
            res.append(_mirror_result(engine, rid, flags[0], val, nsf.get(key),
                                      "%s \"ns_fields\": {\"%s\": ...}" % (where, key)))
    return res


def _vllm_ns_results(tokens: List[str], tiers: List[Dict[str, Any]]) -> List[Result]:
    res: List[Result] = []
    rev = ea.flag(tokens, "--revision")
    for t in tiers:
        if rev not in (None,) + _NO_MIRROR and str(t.get("model_revision") or "") != rev:
            res.append(_mirror_result("vllm", "ns_revision", "--revision", rev,
                                      t.get("model_revision"), "the MiraTier key \"model_revision\""))
        nsf, bad = _ns_fields_of("vllm", "MiraTier", t.get("ns_fields"))
        res += bad + _mirror_all("vllm", tokens, _VLLM_MIRROR, nsf, "MiraTier")
    return res


def _sglang_ns_results(tokens: List[str], extra: Mapping[str, Any]) -> List[Result]:
    """Values that change the KV but never reach a SGLang storage backend: the adapter can only
    put them into ``ns`` when the operator copies them into extra-config ``ns_fields``."""
    nsf, res = _ns_fields_of("sglang", "extra-config", extra.get("ns_fields"))
    res += _mirror_all("sglang", tokens, _SGLANG_MIRROR, nsf, "extra-config")
    # SGLang gives the storage backend its served model name: an alias does not name the weights.
    served = ea.flag(tokens, "--served-model-name")
    path = ea.flag(tokens, "--model-path", "--model")
    if served and served != path:
        want = path or "<weights path>"
        if str(nsf.get("model_path", "")) != want:
            res.append(_mirror_result("sglang", "ns_model_path", "--model-path", want, nsf.get("model_path"),
                                      "extra-config \"ns_fields\": {\"model_path\": ...}"))
    return res


def _lora_paths(tokens: List[str]) -> List[str]:
    import json
    out = []
    for v in ea.multi(tokens, "--lora-modules"):
        if v.startswith("{"):
            try:
                out.append(str(json.loads(v).get("path")))
                continue
            except ValueError:
                pass
        out.append(v.split("=", 1)[1] if "=" in v else v)
    return out


def _logging_result(engine: str, provider: str) -> Result:
    if provider == "et-gateway":
        return ("fail", f"{engine}.request_logging",
                "request logging is on; it must be off with et-gateway (defence in depth)")
    return ("warn", f"{engine}.request_logging",
            "request logging is on; with engine-native a logged salt yields no key without the "
            "deployment secret, but turn it off anyway")


def sglang_checks(tokens: List[str], env: Mapping[str, str], provider: str,
                  version: Optional[str]) -> Tuple[List[Result], Dict[str, Any]]:
    res: List[Result] = []
    # Same rules as `python -m miracache.check_sglang_config` (reused, not duplicated).
    extra, ps, pp, pre = csc.from_tokens(tokens)
    for i, m in pre + csc.problems(extra, ps, pp):
        res.append(("fail", i, m))
    if isinstance(ps, int) and not isinstance(ps, bool) and sgl.MIN_PAGE_SIZE <= ps < 64:
        res.append(("warn", "sglang.page_size_small",
                    f"--page-size {ps} works but 64 is recommended"))
    scheme = ea.flag(tokens, "--hicache-storage-key-scheme")
    if scheme not in (None, "", "rank-suffix"):
        res.append(("fail", "sglang.key_scheme",
                    f"--hicache-storage-key-scheme must be the default rank-suffix; got {scheme!r}"))
    lr = ea.flag(tokens, "--log-requests")
    if lr is not None and str(lr).lower() not in ("false", "0"):
        res.append(_logging_result("sglang", provider))
    if isinstance(extra, dict):
        res += _sglang_ns_results(tokens, extra)
    fields = {"page_size": ps, "key_scheme": scheme or "rank-suffix",
              "ns_fields": extra.get("ns_fields", {}),
              "interface_v1": extra.get("interface_v1")}
    return res, fields


def _truthy(v: Any) -> bool:
    return sgl._truthy(v) if v is not None else False


def node_checks(facts: Mapping[str, Any], min_memlock_mib: int) -> List[Result]:
    res: List[Result] = []
    hp = facts.get("hugepages", {})
    if not any((v.get("total") or 0) > 0 for v in hp.values()):
        res.append(("warn", "node.hugepages", "no hugepages reserved (landing pool/store need "
                    "them); run `python -m miracache.node_prep` for a plan"))
    soft = (facts.get("memlock") or {}).get("soft")
    if soft is None:
        res.append(("warn", "node.memlock", "memlock limit unknown"))
    elif soft != UNLIMITED and soft < min_memlock_mib * 1024 * 1024:
        res.append(("warn", "node.memlock", f"memlock soft limit {soft // (1024 * 1024)} MiB "
                    f"< {min_memlock_mib} MiB; RDMA memory registration may fail"))
    return res


def load_nic_report(path: str) -> Dict[str, Any]:
    """Loads `mira-nicprobe --json`. The report is attached verbatim; its "profiles" array
    is turned into results by nic_profile_checks()."""
    import json
    with open(path) as f:
        return json.load(f)


def nic_profile_checks(nic: Mapping[str, Any]) -> List[Tuple[str, str, str]]:
    """Turn the "profiles" array of `mira-nicprobe --json` into results. The matched profile
    is always reported (info-level "ok"); a firmware below the profile minimum fails; an unprofiled
    NIC (generic fallback) and unverified profile values warn; a device with no profile fails."""
    out: List[Tuple[str, str, str]] = []
    for ent in nic.get("profiles") or []:
        dev = ent.get("device", "?")
        if "profile" not in ent:
            out.append(("fail", "nic.profile", f"{dev}: no NIC profile applies ({ent.get('error', 'unknown error')})"))
            continue
        p = ent["profile"]
        pid, op = p.get("id", "?"), p.get("operating_point", {})
        out.append(("ok", "nic.profile", f"{dev}: profile {pid} (verified={str(p.get('verified', False)).lower()}, "
                    f"fetch_qps={op.get('fetch_qps')}, slice_bytes={op.get('slice_bytes')}, "
                    f"read_depth={op.get('read_depth')}, registry {p.get('registry_version', '?')})"))
        fw = p.get("firmware", {})
        if fw.get("status") == "below_min":
            out.append(("fail", "nic.firmware", f"{dev}: firmware {fw.get('version') or '?'} is below the minimum "
                        f"{fw.get('min')} of profile {pid}"))
        elif fw.get("status") == "unknown":
            out.append(("warn", "nic.firmware", f"{dev}: firmware version '{fw.get('version', '')}' cannot be compared "
                        f"with the minimum {fw.get('min')} of profile {pid}"))
        if p.get("unprofiled"):
            out.append(("warn", "nic.unprofiled", f"{dev}: unprofiled NIC, using conservative {pid}"))
        elif not p.get("verified"):
            out.append(("warn", "nic.unverified", f"{dev}: profile {pid} values are not verified on hardware"))
    return out


def run(*, engine: str, tokens: List[str], model: Optional[str], tp: Any,
        env: Mapping[str, str], provider: str = "engine-native", secret_file: Optional[str] = None,
        engine_version: Optional[str] = None, facts: Optional[Mapping[str, Any]] = None,
        min_memlock_mib: int = 1024, nic_report: Optional[str] = None) -> Dict[str, Any]:
    fn = vllm_checks if engine == "vllm" else sglang_checks
    results, efields = fn(tokens, env, provider, engine_version)
    if provider == "engine-native":
        if not secret_file:
            results.append(("fail", "secret.missing", "engine-native needs --secret-file"))
        else:
            results += [("fail", i, m) for i, m in check_secret_file(secret_file)]
    if facts is not None:
        results += node_checks(facts, min_memlock_mib)
    fields = {"engine": engine, "engine_version": engine_version, "model_id": model,
              "tp_size": tp, "provider": provider,
              "pythonhashseed": env.get("PYTHONHASHSEED", "unset"), **efields}
    report: Dict[str, Any] = {
        "results": [{"level": lv, "id": i, "message": m} for lv, i, m in results],
        "fingerprint": make_fingerprint(fields),
    }
    if nic_report:
        try:
            report["nic"] = load_nic_report(nic_report)
            report["results"] += [{"level": lv, "id": i, "message": m}
                                  for lv, i, m in nic_profile_checks(report["nic"])]
        except (OSError, ValueError) as e:
            report["results"].append({"level": "fail", "id": "nic.report",
                                      "message": f"cannot read NIC report {nic_report}: {e}"})
    report["fails"] = sum(r["level"] == "fail" for r in report["results"])
    report["warnings"] = sum(r["level"] == "warn" for r in report["results"])
    return report
