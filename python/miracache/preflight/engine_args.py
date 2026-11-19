"""Parse engine CLI strings / agentbench answers JSON into plain dicts. No engine import."""
from __future__ import annotations

import json
import shlex
from typing import Any, Dict, List, Optional, Sequence


def flag(tokens: Sequence[str], *names: str) -> Optional[str]:
    """Value of the LAST matching ``--name v`` / ``--name=v`` ('' for a bare flag), as argparse
    resolves a repeated option: an --engine-args value overrides the same flag from an answers
    file (load_inputs puts the answers first), exactly as the engine would see it."""
    found: Optional[str] = None
    for i, t in enumerate(tokens):
        for n in names:
            if t == n:
                found = tokens[i + 1] if i + 1 < len(tokens) and not tokens[i + 1].startswith("--") else ""
            elif t.startswith(n + "="):
                found = t.split("=", 1)[1]
    return found


def has(tokens: Sequence[str], name: str) -> bool:
    return any(t == name or t.startswith(name + "=") for t in tokens)


def multi(tokens: Sequence[str], name: str) -> List[str]:
    """All values following ``name`` up to the next ``--flag`` (vLLM ``--lora-modules a=p b=q``)."""
    out: List[str] = []
    for i, t in enumerate(tokens):
        if t.startswith(name + "="):
            out.append(t.split("=", 1)[1])
        elif t == name:
            for v in tokens[i + 1:]:
                if v.startswith("--"):
                    break
                out.append(v)
    return out


def to_int(v: Optional[str], default: Optional[int] = None) -> Any:
    if v is None or v == "":
        return default
    try:
        return int(v)
    except ValueError:
        return v  # leave bad values visible to the checks


def load_inputs(engine: str, engine_args: Optional[str], answers: Optional[str]) -> Dict[str, Any]:
    """-> {"tokens": [...], "model": str|None, "tp": int|None}. Raises ValueError on bad input."""
    tokens: List[str] = []
    model = tp = None
    if answers:
        try:
            with open(answers) as f:
                ans = json.load(f)
        except (OSError, ValueError) as e:
            raise ValueError(f"cannot read answers file {answers}: {e}")
        # agentbench turns these answer keys into engine flags, so the
        # checks that read those flags (ns mirroring, fingerprint) must see them too. This is the
        # bare-metal launch; agentbench's container launch serves a local snapshot path with no
        # --revision instead, which is safe while served_name is the HF id and the revision is
        # mirrored into ns (the example answers files do both).
        if engine == "sglang" and ans.get("model"):
            tokens += ["--model-path", str(ans["model"])]
        if ans.get("revision") not in (None, "", "main"):
            tokens += ["--revision", str(ans["revision"])]
        if ans.get("served_name"):
            tokens += ["--served-model-name", str(ans["served_name"])]
        if ans.get("kv_cache_dtype") not in (None, "", "auto"):
            tokens += ["--kv-cache-dtype", str(ans["kv_cache_dtype"])]
        tokens += shlex.split(str(ans.get("extra_args", "")))
        tokens += shlex.split(str(ans.get("advanced_args", "")))
        model = ans.get("model")
        tp = to_int(str(ans["tp"])) if ans.get("tp") not in (None, "") else None
    if engine_args:
        tokens += shlex.split(engine_args)
    m = flag(tokens, "--model", "--model-path")
    if m is None and "serve" in tokens:  # `vllm serve MODEL ...`
        i = tokens.index("serve")
        if i + 1 < len(tokens) and not tokens[i + 1].startswith("--"):
            m = tokens[i + 1]
    t = flag(tokens, "--tensor-parallel-size", "--tp-size", "--tp")
    return {"tokens": tokens, "model": m or model, "tp": to_int(t, tp)}


def json_flag(tokens: Sequence[str], name: str) -> Dict[str, Any]:
    v = flag(tokens, name)
    if not v:
        return {}
    try:
        d = json.loads(v)
    except ValueError as e:
        raise ValueError(f"{name} is not valid JSON: {e}")
    return d if isinstance(d, dict) else {}
