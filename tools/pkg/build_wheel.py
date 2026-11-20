#!/usr/bin/env python3
"""Offline wheel builder (stdlib only: no setuptools/pip/wheel needed).

  tools/dev/run.sh python3 tools/pkg/build_wheel.py --lib build/dev/client/libmiracache.so --out build/wheel

Bundles python/miracache/**/*.py (+ _core.pyi) and libmiracache.so into
miracache-<ver>-py3-none-<platform>.whl following PEP 427 (RECORD with sha256 hashes).
"""
import argparse
import base64
import hashlib
import os
import platform
import re
import sys
import zipfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def _version():
    text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    return re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)


def _plat():
    sysname = platform.system().lower()
    return "%s_%s" % (sysname, platform.machine().replace("-", "_"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True, help="path to libmiracache.so")
    ap.add_argument("--out", default=os.path.join(ROOT, "build", "wheel"))
    a = ap.parse_args()
    if not os.path.isfile(a.lib):
        sys.exit("library not found: %s" % a.lib)
    ver = _version()
    dist = "miracache-%s" % ver
    di = dist + ".dist-info"
    files = []  # (arcname, bytes)
    src = os.path.join(ROOT, "python")
    for d, _, names in os.walk(os.path.join(src, "miracache")):
        if "__pycache__" in d:
            continue
        for n in sorted(names):
            if n.endswith((".py", ".pyi")):
                p = os.path.join(d, n)
                files.append((os.path.relpath(p, src).replace(os.sep, "/"), open(p, "rb").read()))
    files.append(("miracache/libmiracache.so", open(a.lib, "rb").read()))
    files.append((di + "/METADATA", ("Metadata-Version: 2.1\nName: miracache\nVersion: %s\n"
                                     "Summary: Remote KV-cache tier over RDMA (ctypes binding)\n"
                                     "License: Apache-2.0\nRequires-Python: >=3.10\n" % ver).encode()))
    files.append((di + "/WHEEL", ("Wheel-Version: 1.0\nGenerator: miracache-build_wheel\n"
                                  "Root-Is-Purelib: false\nTag: py3-none-%s\n" % _plat()).encode()))
    rec = []
    for name, data in files:
        h = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
        rec.append("%s,sha256=%s,%d" % (name, h, len(data)))
    rec.append(di + "/RECORD,,")
    files.append((di + "/RECORD", ("\n".join(rec) + "\n").encode()))
    os.makedirs(a.out, exist_ok=True)
    out = os.path.join(a.out, "%s-py3-none-%s.whl" % (dist, _plat()))
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            zi = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))  # reproducible
            zi.external_attr = (0o755 if name.endswith(".so") else 0o644) << 16
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
    print(out)


if __name__ == "__main__":
    main()
