"""``python -m miracache.node_prep`` (spec 2.4). DRY-RUN BY DEFAULT.

Plans: hugepages (2 MiB via vm.nr_hugepages, 1 GiB via kernel cmdline), hugetlbfs mount,
memlock ulimit, RDMA kernel modules (rdma_rxe/siw are only listed, never loaded), IOMMU
passthrough hint. ``--apply`` additionally needs ``--yes`` and root; it is the only path
that writes anything. Exit: 0 = plan printed / applied, 2 = refused or usage.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Sequence

from .facts import SOFT_RDMA_MODULES, UNLIMITED, read_facts

SYSCTL_FILE = "/etc/sysctl.d/90-miracache.conf"
LIMITS_FILE = "/etc/security/limits.d/90-miracache.conf"
SIZE_KB = {"2M": 2048, "1G": 1048576}


def _action(kind: str, desc: str, *, current: Any = None, target: Any = None,
            commands: Optional[List[List[str]]] = None, files: Optional[Dict[str, str]] = None,
            reboot: bool = False, applicable: bool = True) -> Dict[str, Any]:
    return {"kind": kind, "desc": desc, "current": current, "target": target,
            "commands": commands or [], "files": files or {}, "reboot_required": reboot,
            "applicable": applicable}


def plan(facts: Dict[str, Any], *, hugepage_size: str = "1G", hugepage_gib: int = 8,
         memlock_user: str = "*", mount_dir: Optional[str] = None) -> List[Dict[str, Any]]:
    """Pure function: facts -> actions still needed. Idempotent (satisfied items are omitted)."""
    acts: List[Dict[str, Any]] = []
    kb = SIZE_KB[hugepage_size]
    pages = hugepage_gib * 1024 * 1024 // kb
    cur = (facts["hugepages"].get(str(kb)) or {}).get("total")
    if (cur or 0) < pages:
        if hugepage_size == "2M":
            acts.append(_action(
                "hugepages", f"reserve {pages} x 2 MiB hugepages (vm.nr_hugepages)",
                current=facts.get("nr_hugepages_sysctl"), target=pages,
                commands=[["sysctl", "-w", f"vm.nr_hugepages={pages}"]],
                files={SYSCTL_FILE: f"vm.nr_hugepages = {pages}\n"}))
        else:
            acts.append(_action(
                "hugepages", f"reserve {pages} x 1 GiB hugepages; reliable only at boot: add "
                f"'default_hugepagesz=1G hugepagesz=1G hugepages={pages}' to the kernel cmdline",
                current=cur, target=pages, reboot=True, applicable=False))
    mdir = mount_dir or ("/dev/hugepages-1G" if hugepage_size == "1G" else "/dev/hugepages")
    opt = "pagesize=" + hugepage_size
    if not any(m["path"] == mdir for m in facts.get("hugetlbfs_mounts", [])):
        acts.append(_action("hugetlbfs", f"mount hugetlbfs at {mdir} ({opt})", target=mdir,
                            commands=[["mkdir", "-p", mdir],
                                      ["mount", "-t", "hugetlbfs", "-o", opt, "none", mdir]]))
    need_bytes = hugepage_gib * 1024 ** 3
    soft = facts["memlock"].get("soft")
    if soft is None or (soft != UNLIMITED and soft < need_bytes):
        acts.append(_action(
            "memlock", f"raise memlock ulimit for {memlock_user!r} to unlimited "
            "(or grant CAP_IPC_LOCK to the service)", current=soft, target="unlimited",
            files={LIMITS_FILE: f"{memlock_user} soft memlock unlimited\n"
                                f"{memlock_user} hard memlock unlimited\n"}))
    for name in SOFT_RDMA_MODULES:
        state = "loaded" if facts["modules"].get(name) else "not loaded"
        acts.append(_action("module", f"{name} ({state}): software RDMA, listed only; "
                            "node-prep never loads it", current=state, applicable=False))
    for name in ("ib_core", "rdma_cm"):
        if not facts["modules"].get(name):
            acts.append(_action("module", f"{name} not loaded: install the NIC/RDMA stack "
                                "(node-prep does not modprobe)", current="not loaded",
                                applicable=False))
    if not facts.get("iommu_passthrough"):
        acts.append(_action("iommu", "hint: add 'iommu=pt' to the kernel cmdline for lower "
                            "DMA overhead (not required)", current="off", target="iommu=pt",
                            reboot=True, applicable=False))
    return acts


def render(acts: List[Dict[str, Any]], applying: bool) -> str:
    lines = ["node-prep " + ("APPLY" if applying else "DRY RUN (no changes made)")]
    for a in acts:
        lines.append(f"- [{a['kind']}] {a['desc']}" + ("  (reboot required)" if a["reboot_required"] else ""))
        if a["current"] is not None or a["target"] is not None:
            lines.append(f"    current={a['current']} target={a['target']}")
        for c in a["commands"]:
            lines.append("    $ " + " ".join(c))
        for p, body in a["files"].items():
            lines.append(f"    write {p}: {body.strip()!r}")
    if not acts:
        lines.append("nothing to do")
    return "\n".join(lines)


def apply_plan(acts: List[Dict[str, Any]], run: Callable[[List[str]], None],
               write: Callable[[str, str], None]) -> None:
    for a in acts:
        if not a["applicable"]:
            continue
        for p, body in a["files"].items():
            write(p, body)
        for c in a["commands"]:
            run(c)


def _real_write(path: str, body: str) -> None:
    with open(path, "w") as f:
        f.write(body)


def main(argv: Optional[Sequence[str]] = None, *, geteuid: Callable[[], int] = os.geteuid,
         runner: Optional[Callable[[List[str]], None]] = None,
         writer: Optional[Callable[[str, str], None]] = None, out=None) -> int:
    out = out or sys.stdout
    ap = argparse.ArgumentParser(prog="python -m miracache.node_prep")
    ap.add_argument("--root", default="/", help="filesystem root to read facts from")
    ap.add_argument("--hugepage-size", choices=sorted(SIZE_KB), default="1G")
    ap.add_argument("--hugepage-gib", type=int, default=8)
    ap.add_argument("--memlock-user", default="*")
    ap.add_argument("--mount-dir")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--apply", action="store_true", help="apply the plan (needs --yes and root)")
    ap.add_argument("--yes", action="store_true")
    a = ap.parse_args(argv)
    if a.apply and not a.yes:
        print("refused: --apply requires --yes (dry run is the default)", file=sys.stderr)
        return 2
    if a.apply and geteuid() != 0:
        print("refused: --apply requires root", file=sys.stderr)
        return 2
    acts = plan(read_facts(a.root), hugepage_size=a.hugepage_size, hugepage_gib=a.hugepage_gib,
                memlock_user=a.memlock_user, mount_dir=a.mount_dir)
    if a.json:
        print(json.dumps({"dry_run": not a.apply, "actions": acts}, indent=2), file=out)
    else:
        print(render(acts, a.apply), file=out)
    if a.apply:
        apply_plan(acts, runner or (lambda c: subprocess.run(c, check=True)),
                   writer or _real_write)
        print("applied (reboot-required items are listed above and were not applied)", file=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
