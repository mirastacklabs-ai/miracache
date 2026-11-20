import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from miracache.node_prep import cli, facts  # noqa: E402


def build_root(base, *, hp2m=0, hp1g=0, mounts="", modules="", cmdline="ro quiet",
               memlock="8388608"):
    def w(rel, body):
        p = os.path.join(base, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(body)
    w("proc/meminfo", "MemTotal: 1 kB\nHugepagesize:       2048 kB\n")
    w("sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages", f"{hp2m}\n")
    w("sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages", f"{hp1g}\n")
    w("proc/sys/vm/nr_hugepages", f"{hp2m}\n")
    w("proc/mounts", mounts)
    w("proc/modules", modules)
    w("proc/cmdline", cmdline + "\n")
    w("proc/self/limits", "Limit Soft Hard Units\n"
      f"Max locked memory         {memlock}                {memlock}                bytes\n")
    return base


class TestNodePrep(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def snapshot(self):
        out = {}
        for d, _, fs in os.walk(self.tmp.name):
            for f in fs:
                p = os.path.join(d, f)
                with open(p) as fh:
                    out[p] = fh.read()
        return out

    def run_main(self, *args, euid=1000):
        out, err = io.StringIO(), io.StringIO()
        calls = []
        with contextlib.redirect_stderr(err):
            rc = cli.main(list(args), geteuid=lambda: euid, runner=calls.append,
                          writer=lambda p, b: calls.append(("write", p)), out=out)
        return rc, out.getvalue(), err.getvalue(), calls

    def test_facts_parse(self):
        r = build_root(self.tmp.name, hp2m=512, modules="rdma_rxe 1 0 - Live 0x0\nib_core 1 0 - Live\n",
                       mounts="none /dev/hugepages hugetlbfs rw,pagesize=2M 0 0\n",
                       cmdline="ro iommu=pt", memlock="unlimited")
        f = facts.read_facts(r)
        self.assertEqual(f["hugepages"]["2048"]["total"], 512)
        self.assertEqual(f["memlock"], {"soft": -1, "hard": -1})
        self.assertTrue(f["modules"]["rdma_rxe"] and f["modules"]["ib_core"])
        self.assertFalse(f["modules"]["siw"])
        self.assertTrue(f["iommu_passthrough"])
        self.assertEqual(f["hugetlbfs_mounts"], [{"path": "/dev/hugepages", "options": "rw,pagesize=2M"}])

    def test_plan_1g_on_bare_node(self):
        r = build_root(self.tmp.name)
        rc, text, _, calls = self.run_main("--root", r, "--hugepage-gib", "4")
        self.assertEqual((rc, calls), (0, []))
        self.assertIn("DRY RUN", text)
        self.assertIn("reserve 4 x 1 GiB hugepages", text)
        self.assertIn("hugepages=4", text)
        self.assertIn("mount -t hugetlbfs -o pagesize=1G none /dev/hugepages-1G", text)
        self.assertIn("memlock", text)
        self.assertIn("rdma_rxe (not loaded): software RDMA, listed only", text)
        self.assertIn("siw (not loaded)", text)
        self.assertIn("iommu=pt", text)
        self.assertIn("reboot required", text)

    def test_plan_2m_json(self):
        r = build_root(self.tmp.name)
        rc, text, _, _ = self.run_main("--root", r, "--hugepage-size", "2M", "--hugepage-gib", "2", "--json")
        doc = json.loads(text)
        self.assertTrue(doc["dry_run"])
        hp = [a for a in doc["actions"] if a["kind"] == "hugepages"][0]
        self.assertEqual(hp["target"], 1024)
        self.assertEqual(hp["commands"], [["sysctl", "-w", "vm.nr_hugepages=1024"]])
        mods = [a for a in doc["actions"] if a["kind"] == "module"]
        self.assertTrue(all(not a["applicable"] and not a["commands"] for a in mods))

    def test_plan_idempotent_when_satisfied(self):
        r = build_root(self.tmp.name, hp1g=8, memlock="unlimited", cmdline="ro iommu=pt",
                       modules="ib_core 1 0 - Live\nrdma_cm 1 0 - Live\n",
                       mounts="none /dev/hugepages-1G hugetlbfs rw,pagesize=1G 0 0\n")
        f = facts.read_facts(r)
        acts = cli.plan(f, hugepage_size="1G", hugepage_gib=8)
        self.assertEqual([a["kind"] for a in acts], ["module", "module"])  # only the soft-RDMA listing
        self.assertTrue(all(not a["applicable"] for a in acts))

    def test_dry_run_writes_nothing(self):
        r = build_root(self.tmp.name)
        before = self.snapshot()
        self.run_main("--root", r)
        self.assertEqual(before, self.snapshot())

    def test_apply_refused_without_yes(self):
        r = build_root(self.tmp.name)
        rc, text, err, calls = self.run_main("--root", r, "--apply", euid=0)
        self.assertEqual(rc, 2)
        self.assertIn("--yes", err)
        self.assertEqual((text, calls), ("", []))

    def test_apply_refused_without_root(self):
        r = build_root(self.tmp.name)
        rc, text, err, calls = self.run_main("--root", r, "--apply", "--yes", euid=1000)
        self.assertEqual(rc, 2)
        self.assertIn("root", err)
        self.assertEqual(calls, [])

    def test_apply_uses_injected_runner_only(self):
        # Injected runner/writer: nothing real is executed or written.
        r = build_root(self.tmp.name)
        rc, text, _, calls = self.run_main("--root", r, "--hugepage-size", "2M", "--hugepage-gib", "2",
                                           "--apply", "--yes", euid=0)
        self.assertEqual(rc, 0)
        self.assertIn(["sysctl", "-w", "vm.nr_hugepages=1024"], calls)
        self.assertIn(("write", cli.SYSCTL_FILE), calls)
        self.assertFalse(any(isinstance(c, list) and c[0] == "modprobe" for c in calls))


if __name__ == "__main__":
    unittest.main()
