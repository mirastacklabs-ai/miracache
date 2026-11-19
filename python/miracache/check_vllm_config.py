"""Validate the vLLM-side flags MiraTier requires, before launching vLLM.

    python -m miracache.check_vllm_config --answers answers.json
    python -m miracache.check_vllm_config --kv-transfer-config '{...}' \
        --prefix-caching-hash-algo sha256_cbor --block-size 16

Exit 0 = ok (or no MiraTier configured), 1 = problems (one per line on stderr), 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from typing import Any, Optional, Sequence

from .vllm import compat

MODULE_PATH = "miracache.vllm_tier"
SPEC_NAME = "TieringOffloadingSpec"


def _flag(tokens: Sequence[str], name: str) -> Optional[str]:
    for i, t in enumerate(tokens):
        if t == name and i + 1 < len(tokens):
            return tokens[i + 1]
        if t.startswith(name + "="):
            return t.split("=", 1)[1]
    return None


def _has(tokens: Sequence[str], name: str) -> bool:
    return any(t == name or t.startswith(name + "=") for t in tokens)


def settings_from_args(kv_transfer_config: Optional[str], tokens: Sequence[str]) -> tuple:
    """Return (settings, mira_configured, problems)."""
    problems = []
    kv: Any = {}
    if kv_transfer_config:
        try:
            kv = json.loads(kv_transfer_config)
        except ValueError as e:
            return {}, True, [f"--kv-transfer-config is not valid JSON: {e}"]
    extra = kv.get("kv_connector_extra_config") or {}
    tiers = extra.get("secondary_tiers") or []
    mira = [t for t in tiers if isinstance(t, dict) and t.get("type") == "MiraTier"]
    if mira and any(t.get("module_path") != MODULE_PATH for t in mira):
        problems.append(f"MiraTier module_path must be {MODULE_PATH!r}")
    if mira and not all(t.get("config") for t in mira):
        problems.append("MiraTier entry needs 'config': path to client.toml")
    if mira and kv.get("kv_connector") != "OffloadingConnector":
        problems.append("kv_connector must be 'OffloadingConnector'")
    if mira:
        # vllm/v1/kv_offload/factory.py:31 defaults spec_name to CPUOffloadingSpec, which
        # ignores secondary_tiers (read only by TieringOffloadingSpec, tiering/spec.py:337):
        # MiraTier would silently never load. cpu_bytes_to_use is required (cpu/spec.py:99-102).
        if extra.get("spec_name") != SPEC_NAME:
            problems.append(f"kv_connector_extra_config.spec_name must be {SPEC_NAME!r} "
                            f"(got {extra.get('spec_name')!r}); otherwise secondary_tiers is "
                            "ignored and MiraTier never loads")
        cbu = extra.get("cpu_bytes_to_use")
        if isinstance(cbu, bool) or not isinstance(cbu, int) or cbu <= 0:
            problems.append("kv_connector_extra_config.cpu_bytes_to_use must be a positive "
                            f"integer (bytes of the CPU primary tier); got {cbu!r}")
        if not all(isinstance(t.get("config"), str) for t in mira):
            problems.append("MiraTier 'config' must be a path string (it is passed to the "
                            "constructor as a keyword)")
        # s12 (C3): the tier cannot see the top-level policy, so the entry repeats it; the tier refuses without it.
        if any(t.get("kv_load_failure_policy") != "recompute" for t in mira):
            problems.append('MiraTier entry needs "kv_load_failure_policy": "recompute" (the tier cannot see the '
                            "top-level setting and refuses to start without this promise)")
    bs = _flag(tokens, "--block-size")
    pp = _flag(tokens, "--pipeline-parallel-size")
    s = {
        "canonical_layout": extra.get("canonical_layout"),
        "kv_load_failure_policy": kv.get("kv_load_failure_policy"),
        "prefix_caching_hash_algo": _flag(tokens, "--prefix-caching-hash-algo"),
        "block_size": int(bs) if bs and bs.isdigit() else (None if bs is None else bs),
        "pipeline_parallel_size": int(pp) if pp and pp.isdigit() else (1 if pp is None else pp),
        "context_parallel_size": 1,
        "enable_log_requests": _has(tokens, "--enable-log-requests"),
    }
    for flag in ("--prefill-context-parallel-size", "--decode-context-parallel-size"):
        v = _flag(tokens, flag)
        if v is not None and v != "1":
            s["context_parallel_size"] = v
    return s, bool(mira), problems


def check(kv_transfer_config: Optional[str], tokens: Sequence[str], env: dict) -> tuple:
    s, mira, problems = settings_from_args(kv_transfer_config, tokens)
    if not mira:
        return False, problems
    problems += compat.validate_settings(s)
    if env.get("PYTHONHASHSEED") not in (None, ""):
        print("note: PYTHONHASHSEED is set; it must be identical on all hosts", file=sys.stderr)
    return True, problems


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m miracache.check_vllm_config")
    ap.add_argument("--answers", help="agentbench answers JSON (reads extra_args)")
    ap.add_argument("--kv-transfer-config", help="the JSON given to --kv-transfer-config")
    ap.add_argument("--prefix-caching-hash-algo")
    ap.add_argument("--block-size")
    ap.add_argument("--pipeline-parallel-size")
    a = ap.parse_args(argv)
    tokens: list = []
    kvc = a.kv_transfer_config
    if a.answers:
        try:
            with open(a.answers) as f:
                ans = json.load(f)
            tokens = shlex.split(str(ans.get("extra_args", "")))
        except (OSError, ValueError) as e:
            print(f"cannot read {a.answers}: {e}", file=sys.stderr)
            return 2
        kvc = kvc or _flag(tokens, "--kv-transfer-config")
    for flag, val in (("--prefix-caching-hash-algo", a.prefix_caching_hash_algo),
                      ("--block-size", a.block_size),
                      ("--pipeline-parallel-size", a.pipeline_parallel_size)):
        if val is not None:
            tokens += [flag, val]
    if not kvc:
        print("no --kv-transfer-config given: MiraTier not configured, nothing to check")
        return 0
    configured, problems = check(kvc, tokens, dict(os.environ))
    if not configured and not problems:
        print("MiraTier not configured: nothing to check")
        return 0
    if problems:
        for p in problems:
            print("FAIL: " + p, file=sys.stderr)
        return 1
    print("ok: vLLM flags satisfy MiraTier requirements")
    return 0


if __name__ == "__main__":
    sys.exit(main())
