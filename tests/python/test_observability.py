"""Guards deploy/observability/ against drifting from the code.

Every `miracache_*` metric name used in a dashboard or alert expression must be a metric the C++
code registers. Run: python3 -m unittest discover -s tests/python.
"""
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OBS = ROOT / "deploy" / "observability"
SRC_DIRS = ("core", "server", "client")
NAME_RE = re.compile(r"miracache_[a-z0-9_]+")
REG_RE = re.compile(r'"(miracache_[a-z0-9_]+)"')
HIST_SUFFIXES = ("_bucket", "_sum", "_count")


def registered_metrics():
    names, hist = set(), set()
    for d in SRC_DIRS:
        for p in (ROOT / d).rglob("*"):
            if p.suffix not in (".cpp", ".h", ".cc", ".hpp") or not p.is_file():
                continue
            text = p.read_text(errors="replace")
            names.update(REG_RE.findall(text))
            hist.update(re.findall(r'histogram\(\s*"(miracache_[a-z0-9_]+)"', text))
    return names, hist


def walk_strings(o, key=None):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from walk_strings(v, k)
    elif isinstance(o, list):
        for v in o:
            yield from walk_strings(v, key)
    elif isinstance(o, str):
        yield key, o


def dashboard_exprs():
    out = []
    for f in sorted((OBS / "dashboards").glob("*.json")):
        doc = json.loads(f.read_text())
        for k, s in walk_strings(doc):
            if k in ("expr", "query", "definition"):
                out.append((f.name, s))
    return out


def alert_rules():
    """Minimal parser for our alerts.yml layout: list of {alert, expr, annotations} (no YAML lib needed)."""
    rules, cur, lines = [], None, (OBS / "alerts.yml").read_text().splitlines()
    i = 0
    while i < len(lines):
        ln = lines[i]
        m = re.match(r"\s*- alert: (\S+)", ln)
        if m:
            cur = {"alert": m.group(1), "expr": "", "annotations": {}}
            rules.append(cur)
        elif cur is not None:
            m = re.match(r"(\s*)expr:\s*(.*)$", ln)
            if m:
                if m.group(2) in ("|", ">", "|-", ">-"):
                    ind = len(m.group(1))
                    buf = []
                    while i + 1 < len(lines) and (not lines[i + 1].strip() or len(lines[i + 1]) - len(lines[i + 1].lstrip()) > ind):
                        i += 1
                        buf.append(lines[i])
                    cur["expr"] = "\n".join(buf)
                else:
                    cur["expr"] = m.group(2)
            m = re.match(r"\s+(summary|description):\s*(.*)$", ln)
            if m:
                cur["annotations"][m.group(1)] = m.group(2)
        i += 1
    return rules


def check_names(test, where, expr, reg, hist):
    for n in NAME_RE.findall(expr):
        base = n
        for suf in HIST_SUFFIXES:
            if n.endswith(suf) and n[: -len(suf)] in hist:
                base = n[: -len(suf)]
        test.assertIn(base, reg, f"{where}: metric {n!r} is not registered by the code")
        if base != n:
            test.assertIn(base, hist)
        elif base in hist:
            test.fail(f"{where}: histogram {n!r} used without _bucket/_sum/_count")


class ObservabilityTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reg, cls.hist = registered_metrics()

    def test_registry_scan_finds_metrics(self):
        self.assertGreater(len(self.reg), 40)
        self.assertIn("miracache_node_info", self.reg)
        self.assertIn("miracache_client_fetch_seconds", self.hist)

    def test_dashboards_use_registered_metrics(self):
        exprs = dashboard_exprs()
        self.assertGreater(len(exprs), 30)
        used = set()
        for where, e in exprs:
            check_names(self, where, e, self.reg, self.hist)
            used.update(NAME_RE.findall(e))
        self.assertIn("miracache_node_info", used)

    def test_dashboards_are_importable_shape(self):
        for f in sorted((OBS / "dashboards").glob("*.json")):
            doc = json.loads(f.read_text())
            self.assertEqual([i["name"] for i in doc["__inputs"]], ["DS_PROMETHEUS"], f.name)
            self.assertGreaterEqual(doc["schemaVersion"], 36, f.name)
            self.assertTrue(doc["uid"] and doc["title"], f.name)
            ids = [p["id"] for p in doc["panels"]]
            self.assertEqual(len(ids), len(set(ids)), f.name)
            for p in doc["panels"]:
                for t in p.get("targets", []):
                    self.assertTrue(t["expr"].strip(), f"{f.name} panel {p['id']}")
            self.assertNotIn("tenant", f.read_text().lower())

    def test_dashboard_variables(self):
        names = {}
        for f in (OBS / "dashboards").glob("*.json"):
            names[f.name] = {v["name"] for v in json.loads(f.read_text())["templating"]["list"]}
        self.assertIn("client_host", names["miracache-client.json"])
        for n in names.values():
            self.assertTrue({"node_id", "hostname"} <= n or {"client_host"} <= n)

    def test_alerts_use_registered_metrics(self):
        rules = alert_rules()
        self.assertGreaterEqual(len(rules), 8)
        for r in rules:
            self.assertTrue(r["expr"].strip(), r["alert"])
            check_names(self, "alerts.yml " + r["alert"], r["expr"], self.reg, self.hist)
            self.assertIn("summary", r["annotations"], r["alert"])
            self.assertIn("description", r["annotations"], r["alert"])
            self.assertNotIn("tenant", (r["annotations"]["summary"] + r["annotations"]["description"]).lower())
        # alerts about a memory node must show its hostname
        for r in rules:
            if "group_left" in r["expr"] and "hostname" in r["expr"]:
                self.assertIn("$labels.hostname", r["annotations"]["summary"], r["alert"])

    def test_drift_is_detected(self):
        with self.assertRaises(AssertionError):
            check_names(self, "synthetic", "rate(miracache_not_a_metric_total[5m])", self.reg, self.hist)


if __name__ == "__main__":
    unittest.main()
