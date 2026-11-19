"""Validate the SGLang flags MiraHiCacheStorage requires, before launching SGLang.

    python -m miracache.check_sglang_config --extra-config deploy/sglang/extra-config.example.json \
        --page-size 64 [--pp-size 1]
    python -m miracache.check_sglang_config --engine-args '--model-path M --page-size 64 \
        --hicache-storage-backend dynamic --hicache-storage-backend-extra-config {...}'

``--extra-config`` takes the JSON text or a path to a JSON file. SGLang pops its own
``hicache_storage_pass_prefix_keys`` before the backend is built
(S/mem_cache/hybrid_cache/hybrid_cache_controller.py:553-560), so the adapter cannot
see it: this pre-launch check is where its absence is caught.

Exit 0 = ok, 1 = problems (one per line on stderr), 2 = usage.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .sglang.storage import MIN_PAGE_SIZE, _truthy, client_kwargs

MODULE_PATH = "miracache.sglang"
CLASS_NAME = "MiraHiCacheStorage"
EXTRA_FLAG = "--hicache-storage-backend-extra-config"

Problem = Tuple[str, str]  # (id, message); ids match the preflight result ids


def _flag(tokens: Sequence[str], *names: str) -> Optional[str]:
    for i, t in enumerate(tokens):
        for n in names:
            if t == n:
                return tokens[i + 1] if i + 1 < len(tokens) and not tokens[i + 1].startswith("--") else ""
            if t.startswith(n + "="):
                return t.split("=", 1)[1]
    return None


def _int(v: Any) -> Any:
    if v is None or v == "":
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return v


def load_extra(text_or_path: Optional[str]) -> Dict[str, Any]:
    """JSON text or a path to a JSON file -> dict. Raises ValueError."""
    if not text_or_path:
        return {}
    text = text_or_path
    if not text.lstrip().startswith("{") and os.path.isfile(text):
        with open(text) as f:
            text = f.read()
    try:
        d = json.loads(text)
    except ValueError as e:
        raise ValueError(f"{EXTRA_FLAG} is not valid JSON: {e}")
    if not isinstance(d, dict):
        raise ValueError(f"{EXTRA_FLAG} must be a JSON object")
    return d


def problems(extra: Dict[str, Any], page_size: Any, pp_size: Any) -> List[Problem]:
    """Every rule the adapter enforces at start-up, plus SGLang's own prefix-keys flag."""
    out: List[Problem] = []
    for key in ("hicache_storage_pass_prefix_keys", "miracache_expect_prefix_keys"):
        if not _truthy(extra.get(key, False)):
            out.append(("sglang.pass_prefix_keys",
                        f"{key} must be true in {EXTRA_FLAG} (set BOTH "
                        "hicache_storage_pass_prefix_keys and miracache_expect_prefix_keys)"))
    if not _truthy(extra.get("interface_v1", 0)):
        out.append(("sglang.interface_v1", f"interface_v1 must be 1 in {EXTRA_FLAG} "
                    "(zero-copy page functions)"))
    if extra.get("module_path") != MODULE_PATH or extra.get("class_name") != CLASS_NAME:
        out.append(("sglang.backend_class", f"module_path must be {MODULE_PATH!r} and class_name "
                    f"{CLASS_NAME!r}; got {extra.get('module_path')!r}, {extra.get('class_name')!r}"))
    if not extra.get("backend_name"):
        out.append(("sglang.backend_class", "backend_name is required by the dynamic backend "
                    "(backend_factory.py:142)"))
    try:
        client_kwargs(extra)
    except ValueError as e:
        out.append(("sglang.client_config", str(e)))
    if isinstance(pp_size, bool) or not isinstance(pp_size, int):
        out.append(("sglang.args", f"--pp-size must be an integer; got {pp_size!r}"))
    elif pp_size > 1:
        out.append(("sglang.pp", "SGLang pipeline parallelism (PP>1) is unsupported in v1 "
                    "(design/03 R29)"))
    if page_size is None:
        out.append(("sglang.page_size", f"--page-size is not set (SGLang default 1); use "
                    f"--page-size >= {MIN_PAGE_SIZE} (64 recommended)"))
    elif isinstance(page_size, bool) or not isinstance(page_size, int):
        out.append(("sglang.args", f"--page-size must be an integer; got {page_size!r}"))
    elif page_size < MIN_PAGE_SIZE:
        out.append(("sglang.page_size", f"--page-size {page_size} < {MIN_PAGE_SIZE} (objects too "
                    "small for RDMA); use >= 16 (64 recommended)"))
    return out


def from_tokens(tokens: Sequence[str]) -> Tuple[Dict[str, Any], Any, Any, List[Problem]]:
    """Engine CLI tokens -> (extra, page_size, pp_size, problems)."""
    pre: List[Problem] = []
    try:
        extra = load_extra(_flag(tokens, EXTRA_FLAG))
    except (OSError, ValueError) as e:
        extra = {}
        pre.append(("sglang.extra_config", str(e)))
    ps = _int(_flag(tokens, "--page-size"))
    pp = _int(_flag(tokens, "--pp-size", "--pipeline-parallel-size"))
    return extra, ps, 1 if pp is None else pp, pre


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m miracache.check_sglang_config")
    ap.add_argument("--engine-args", help="the SGLang launch_server argument string")
    ap.add_argument("--extra-config", help=f"the {EXTRA_FLAG} value (JSON text or file path)")
    ap.add_argument("--page-size")
    ap.add_argument("--pp-size")
    a = ap.parse_args(argv)
    tokens = shlex.split(a.engine_args) if a.engine_args else []
    extra, ps, pp, probs = from_tokens(tokens)
    if a.engine_args and _flag(tokens, "--hicache-storage-backend") != "dynamic":
        probs.append(("sglang.backend", "--hicache-storage-backend must be 'dynamic'"))
    if a.extra_config is not None:
        try:
            extra = load_extra(a.extra_config)
        except (OSError, ValueError) as e:
            print("FAIL: " + str(e), file=sys.stderr)
            return 1
    if not extra and not probs:
        print(f"FAIL: no {EXTRA_FLAG} given (use --extra-config or --engine-args)", file=sys.stderr)
        return 2
    if a.page_size is not None:
        ps = _int(a.page_size)
    if a.pp_size is not None:
        pp = _int(a.pp_size)
    probs += problems(extra, ps, pp)
    if probs:
        for _id, msg in probs:
            print("FAIL: " + msg, file=sys.stderr)
        return 1
    print("ok: SGLang flags satisfy MiraHiCacheStorage requirements")
    return 0


if __name__ == "__main__":
    sys.exit(main())
