"""Cross-host parity fingerprint (spec 2.5): hosts whose fields differ never share keys."""
from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List, Mapping, Sequence

VERSION = 1


def canonical(fields: Mapping[str, Any]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), default=str).encode()


def make(fields: Mapping[str, Any]) -> Dict[str, Any]:
    f = json.loads(canonical(fields))  # normalise through JSON
    return {"version": VERSION, "hash": hashlib.sha256(canonical(f)).hexdigest(), "fields": f}


def diff(docs: Sequence[Mapping[str, Any]], names: Sequence[str]) -> List[str]:
    """One message per mismatching field, naming the field and each host's value."""
    msgs: List[str] = []
    keys = sorted({k for d in docs for k in d["fields"]})
    for k in keys:
        vals = [d["fields"].get(k, "<absent>") for d in docs]
        if any(json.dumps(v, sort_keys=True) != json.dumps(vals[0], sort_keys=True) for v in vals):
            detail = ", ".join(f"{n}={json.dumps(v, sort_keys=True)}" for n, v in zip(names, vals))
            msgs.append(f"mismatch in field {k!r}: {detail}")
    return msgs


def load(path: str) -> Dict[str, Any]:
    """Accept `preflight fingerprint` output or `preflight --json` output (has "fingerprint")."""
    with open(path) as f:
        d = json.load(f)
    if isinstance(d, dict) and "fingerprint" in d:
        d = d["fingerprint"]
    if not isinstance(d, dict) or not isinstance(d.get("fields"), dict):
        raise ValueError(f"{path}: not a fingerprint document")
    if make(d["fields"])["hash"] != d.get("hash"):
        raise ValueError(f"{path}: hash does not match its fields (edited or corrupt)")
    return d
