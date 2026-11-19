"""Deployment secret file checks (engine-native; security.md, spec 2.5). Never prints key bytes.

Mirrors ``load_secret_file`` (client/scope/engine_native.cpp) and ``check_secret_file``
(client/src/config.cpp) rule for rule; keep them in sync. Format (text, one entry per line):

    # comment                (a line whose first non-blank char is '#'; no inline comments)
    current = <kver>         (decimal u32, non-zero, exactly once)
    <kver> = <64 hex chars>  (decimal u32, non-zero, unique; hex is case-insensitive)

Blank/space/tab/CR around lines, keys and values is ignored. No limit on the number of kvers.
The file must be a regular file with mode exactly 0600 (0400 is rejected, as in the client).
"""
from __future__ import annotations

import os
import re
import stat
from typing import Dict, List, Optional, Tuple

_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_U32 = re.compile(r"^[0-9]{1,10}$")  # ASCII digits only, like the C++ parse_u32
_WS = " \t\r"


def _u32(s: str) -> Optional[int]:
    """C++ parse_u32 + non-zero check; None when invalid."""
    if not _U32.match(s):
        return None
    v = int(s)
    return v if 0 < v <= 0xFFFFFFFF else None


def check_secret_file(path: str) -> List[Tuple[str, str]]:
    """-> list of (check_id, message); empty = ok."""
    try:
        st = os.stat(path)
    except OSError as e:
        return [("secret.missing", f"secret file {path} not readable: {e.strerror}")]
    if not stat.S_ISREG(st.st_mode):
        return [("secret.not_regular", f"secret file {path} is not a regular file")]
    out: List[Tuple[str, str]] = []
    if stat.S_IMODE(st.st_mode) != 0o600:
        out.append(("secret.permissions",
                    f"secret file {path} has mode {stat.S_IMODE(st.st_mode):04o}; "
                    "it must be exactly 0600"))
    try:
        with open(path, "rb") as f:
            text = f.read().decode("latin-1")  # byte-for-byte, like the C++ loader
    except OSError:
        out.append(("secret.malformed", f"secret file {path} could not be read"))
        return out

    secrets: Dict[int, str] = {}
    current: Optional[int] = None
    for n, raw in enumerate(text.split("\n"), 1):
        line = raw.strip(_WS)
        if not line or line[0] == "#":
            continue
        k, eq, v = line.partition("=")
        if not eq:
            out.append(("secret.malformed", f"line {n}: expected '<key> = <value>'"))
            return out
        k, v = k.strip(_WS), v.strip(_WS)
        if k == "current":
            if current is not None:
                out.append(("secret.malformed", f"line {n}: duplicate \"current\""))
                return out
            current = _u32(v)
            if current is None:
                out.append(("secret.malformed", f"line {n}: current must be a non-zero decimal kver"))
                return out
            continue
        kver = _u32(k)
        if kver is None:
            out.append(("secret.malformed", f"line {n}: kver {k!r} must be a non-zero decimal number"))
            return out
        if not _HEX64.match(v):
            out.append(("secret.malformed",
                        f"line {n}: secret for kver {k!r} must be 32 bytes as 64 hex characters"))
            return out
        if kver in secrets:
            out.append(("secret.malformed", f"line {n}: duplicate kver {kver}"))
            return out
        secrets[kver] = v
    if current is None:
        out.append(("secret.kver_missing", 'secret file needs a "current = <kver>" line'))
    elif current not in secrets:
        out.append(("secret.kver_missing", f"current kver {current} has no secret entry"))
    return out
