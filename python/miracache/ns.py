"""The one ``ns`` definition (spec rev 5.1 §2.6).

``ns`` is the 32-byte namespace digest that goes into every scope ID, key hash and DEK
(engine-native provider). Two adapter hosts share cache only when their ``ns`` is equal, so
this function must give the same bytes for the same fields on every host and in every
miracache release. Each adapter decides WHICH fields it can see (``vllm.compat.namespace_fields``,
``sglang.storage.namespace_fields``); this module decides HOW they are encoded.

Encoding v1: SHA-256 over ``"mira-ns-v1\\0"`` followed by the canonical JSON of the fields
(sorted keys, no whitespace, ASCII only, no NaN/Infinity). Values must be JSON-native
(str, int, bool, None, lists, dicts of those): anything else raises ``TypeError`` rather than
being turned into a host-dependent string.

Never change this encoding or an adapter's field list without meaning to: every host then
computes a new ``ns`` and the whole cache misses (silently) until it refills. The golden-vector
tests (TestNamespace.test_ns_golden_vectors in test_vllm_tier.py,
TestNamespaceGolden in test_sglang_storage.py) fail on any such change, so it is always a
deliberate decision.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any, Mapping

NS_DOMAIN = b"mira-ns-v1\x00"


def _check_keys(v: Any) -> None:
    """json.dumps turns int/float/bool/None dict keys into strings ({1: x} == {"1": x}); refuse
    them so two different inputs can never encode alike."""
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise TypeError(f"ns: dict keys must be strings, got {k!r}")
            _check_keys(x)
    elif isinstance(v, (list, tuple)):
        for x in v:
            _check_keys(x)


def canonical(fields: Mapping[str, Any]) -> bytes:
    """Canonical JSON bytes of ``fields`` (encoding v1)."""
    _check_keys(dict(fields))
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def digest(fields: Mapping[str, Any]) -> bytes:
    """32-byte ``ns`` = SHA-256(NS_DOMAIN || canonical(fields))."""
    return hashlib.sha256(NS_DOMAIN + canonical(fields)).digest()


def fingerprint(ns: bytes) -> str:
    """First 8 hex digits of ``ns``, for the start-up log line (cross-host comparison)."""
    return bytes(ns).hex()[:8]
