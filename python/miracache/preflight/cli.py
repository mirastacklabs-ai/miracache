"""``python -m miracache.preflight [check|fingerprint|compare]`` (spec 2.5).

check (default): exit 0 ok, 1 hard fail, 2 warnings only with --strict-warnings (also usage).
fingerprint:     print the parity fingerprint (hash + fields) for this host.
compare A B ...: hard-fail (exit 1) on any field mismatch across hosts, naming the field.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any, Dict, List, Optional, Sequence

from ..node_prep.facts import read_facts
from . import checks, engine_args as ea, fingerprint as fp


def _common(ap: argparse.ArgumentParser) -> None:
    ap.add_argument("--engine", choices=("vllm", "sglang"), required=True)
    ap.add_argument("--engine-args", help="the engine CLI string, e.g. 'serve M --block-size 16'")
    ap.add_argument("--answers", help="agentbench answers JSON (extra_args, model, tp)")
    ap.add_argument("--engine-version")
    ap.add_argument("--provider", choices=("engine-native", "et-gateway"), default="engine-native")
    ap.add_argument("--secret-file")
    ap.add_argument("--env", action="append", default=[], metavar="K=V",
                    help="engine environment (default: this process's environment)")
    ap.add_argument("--root", default="/", help="filesystem root for node facts")
    ap.add_argument("--no-node-facts", action="store_true")
    ap.add_argument("--min-memlock-mib", type=int, default=1024)
    ap.add_argument("--nic-report", help="mira-nicprobe --json output")
    ap.add_argument("--json", action="store_true")


def _env(pairs: List[str]) -> Dict[str, str]:
    if not pairs:
        return dict(os.environ)
    return dict(p.split("=", 1) for p in pairs if "=" in p)


def _report(a: argparse.Namespace) -> Dict[str, Any]:
    inp = ea.load_inputs(a.engine, a.engine_args, a.answers)
    facts = None if a.no_node_facts else read_facts(a.root)
    return checks.run(engine=a.engine, tokens=inp["tokens"], model=inp["model"], tp=inp["tp"],
                      env=_env(a.env), provider=a.provider, secret_file=a.secret_file,
                      engine_version=a.engine_version, facts=facts,
                      min_memlock_mib=a.min_memlock_mib, nic_report=a.nic_report)


def _check(argv: Sequence[str], out) -> int:
    ap = argparse.ArgumentParser(prog="python -m miracache.preflight")
    _common(ap)
    ap.add_argument("--strict-warnings", action="store_true")
    a = ap.parse_args(argv)
    try:
        rep = _report(a)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if a.json:
        print(json.dumps(rep, indent=2, sort_keys=True), file=out)
    else:
        for r in rep["results"]:
            print(f"{r['level'].upper():4} {r['id']}: {r['message']}", file=out)
        print(f"fingerprint {rep['fingerprint']['hash'][:16]}  "
              f"fails={rep['fails']} warnings={rep['warnings']}", file=out)
    if rep["fails"]:
        return 1
    if rep["warnings"] and a.strict_warnings:
        return 2
    return 0


def _fingerprint(argv: Sequence[str], out) -> int:
    ap = argparse.ArgumentParser(prog="python -m miracache.preflight fingerprint")
    _common(ap)
    a = ap.parse_args(argv)
    try:
        doc = _report(a)["fingerprint"]
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    print(json.dumps(doc, indent=2, sort_keys=True), file=out)
    return 0


def _compare(argv: Sequence[str], out) -> int:
    ap = argparse.ArgumentParser(prog="python -m miracache.preflight compare")
    ap.add_argument("files", nargs="+")
    a = ap.parse_args(argv)
    try:
        docs = [fp.load(p) for p in a.files]
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    msgs = fp.diff(docs, a.files)
    for m in msgs:
        print("FAIL " + m, file=out)
    if msgs:
        return 1
    print(f"ok: {len(docs)} hosts agree (fingerprint {docs[0]['hash'][:16]})", file=out)
    return 0


def main(argv: Optional[Sequence[str]] = None, out=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    out = out or sys.stdout
    if argv and argv[0] == "fingerprint":
        return _fingerprint(argv[1:], out)
    if argv and argv[0] == "compare":
        return _compare(argv[1:], out)
    if argv and argv[0] == "check":
        argv = argv[1:]
    return _check(argv, out)


if __name__ == "__main__":
    sys.exit(main())
