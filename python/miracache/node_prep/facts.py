"""Read node facts (hugepages, memlock, RDMA modules, IOMMU) from /proc and /sys under a root.

``root`` defaults to ``/``; tests pass a fake tree. Read-only: nothing here writes.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional

SOFT_RDMA_MODULES = ("rdma_rxe", "siw")  # software RDMA: listed only, never loaded
UNLIMITED = -1


def _read(root: str, path: str) -> Optional[str]:
    try:
        with open(os.path.join(root, path.lstrip("/"))) as f:
            return f.read()
    except OSError:
        return None


def _int(s: Optional[str]) -> Optional[int]:
    try:
        return int(s.strip()) if s is not None else None
    except ValueError:
        return None


def parse_memlock(limits_text: Optional[str]) -> Dict[str, Optional[int]]:
    """Parse the 'Max locked memory' row of /proc/<pid>/limits (bytes; -1 = unlimited)."""
    out: Dict[str, Optional[int]] = {"soft": None, "hard": None}
    for line in (limits_text or "").splitlines():
        if line.startswith("Max locked memory"):
            parts = line[len("Max locked memory"):].split()
            vals = [UNLIMITED if p == "unlimited" else _int(p) for p in parts[:2]]
            if len(vals) == 2:
                out["soft"], out["hard"] = vals
    return out


def read_facts(root: str = "/") -> Dict[str, Any]:
    meminfo = _read(root, "/proc/meminfo") or ""
    m = re.search(r"^Hugepagesize:\s+(\d+) kB", meminfo, re.M)
    default_kb = int(m.group(1)) if m else None
    hp: Dict[str, Dict[str, Optional[int]]] = {}
    for kb in (2048, 1048576):
        base = f"/sys/kernel/mm/hugepages/hugepages-{kb}kB/"
        hp[str(kb)] = {"total": _int(_read(root, base + "nr_hugepages")),
                       "free": _int(_read(root, base + "free_hugepages"))}
    modules_txt = _read(root, "/proc/modules") or ""
    loaded = {ln.split()[0] for ln in modules_txt.splitlines() if ln.strip()}
    mods = {}
    for name in SOFT_RDMA_MODULES + ("rdma_cm", "ib_core"):
        mods[name] = name in loaded or os.path.isdir(os.path.join(root, "sys/module", name))
    cmdline = (_read(root, "/proc/cmdline") or "").split()
    iommu_pt = any(t in ("iommu=pt", "intel_iommu=pt", "amd_iommu=pt") for t in cmdline)
    try:
        iommu_active = bool(os.listdir(os.path.join(root, "sys/kernel/iommu_groups")))
    except OSError:
        iommu_active = False
    mounts: List[Dict[str, str]] = []
    for ln in (_read(root, "/proc/mounts") or "").splitlines():
        f = ln.split()
        if len(f) >= 4 and f[2] == "hugetlbfs":
            mounts.append({"path": f[1], "options": f[3]})
    return {
        "hugepagesize_kb": default_kb,
        "hugepages": hp,
        "nr_hugepages_sysctl": _int(_read(root, "/proc/sys/vm/nr_hugepages")),
        "memlock": parse_memlock(_read(root, "/proc/self/limits")),
        "modules": mods,
        "iommu_passthrough": iommu_pt,
        "iommu_active": iommu_active,
        "cmdline": cmdline,
        "hugetlbfs_mounts": mounts,
    }
