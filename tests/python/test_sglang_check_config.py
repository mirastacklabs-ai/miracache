"""python -m miracache.check_sglang_config (pre-launch check, reused by preflight)."""
import contextlib
import io
import json
import os
import shlex
import unittest

from miracache import check_sglang_config as csc

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "sglang",
                       "extra-config.example.json")


def example():
    with open(EXAMPLE) as f:
        return json.load(f)


def run(*argv):
    err, out = io.StringIO(), io.StringIO()
    with contextlib.redirect_stderr(err), contextlib.redirect_stdout(out):
        rc = csc.main(list(argv))
    return rc, err.getvalue()


class TestCheckSglangConfig(unittest.TestCase):
    def test_shipped_example_passes(self):
        self.assertEqual(run("--extra-config", EXAMPLE, "--page-size", "64")[0], 0)
        self.assertEqual(run("--extra-config", json.dumps(example()), "--page-size", "16",
                             "--pp-size", "1")[0], 0)

    def test_both_prefix_flags_required(self):
        for key in ("hicache_storage_pass_prefix_keys", "miracache_expect_prefix_keys"):
            for e in ({**example(), key: False}, {k: v for k, v in example().items() if k != key}):
                rc, err = run("--extra-config", json.dumps(e), "--page-size", "64")
                self.assertEqual(rc, 1, key)
                self.assertIn(key, err)

    def test_pp_and_page_size(self):
        e = json.dumps(example())
        self.assertEqual(run("--extra-config", e, "--page-size", "64", "--pp-size", "2")[0], 1)
        self.assertEqual(run("--extra-config", e, "--page-size", "15")[0], 1)
        rc, err = run("--extra-config", e)  # SGLang default page size is 1
        self.assertEqual(rc, 1)
        self.assertIn("--page-size", err)

    def test_client_config_required(self):
        e = {**example(), "miracache": {}}
        rc, err = run("--extra-config", json.dumps(e), "--page-size", "64")
        self.assertEqual(rc, 1)
        self.assertIn("miracache.config", err)

    def test_engine_args(self):
        args = ("--model-path m --page-size 64 --hicache-storage-backend dynamic "
                "--hicache-storage-backend-extra-config '%s'" % json.dumps(example()))
        self.assertEqual(run("--engine-args", args)[0], 0)
        self.assertEqual(run("--engine-args", args + " --pp-size 2")[0], 1)
        rc, err = run("--engine-args", args.replace("dynamic", "file"))
        self.assertEqual(rc, 1)
        self.assertIn("dynamic", err)

    def test_bad_json_and_nothing_given(self):
        self.assertEqual(run("--extra-config", "{nope", "--page-size", "64")[0], 1)
        self.assertEqual(run("--page-size", "64")[0], 2)

    def test_problems_api(self):
        self.assertEqual(csc.problems(example(), 64, 1), [])
        ids = {i for i, _ in csc.problems({}, None, 2)}
        self.assertTrue({"sglang.pass_prefix_keys", "sglang.interface_v1", "sglang.pp",
                         "sglang.page_size", "sglang.client_config"} <= ids)


AB = os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "agentbench")


def answers(name):
    with open(os.path.join(AB, name + ".json")) as f:
        return json.load(f)


@unittest.skipUnless(os.path.isdir(AB), "benchmark answer files are not in this source tree")
class TestShippedAgentbenchPair(unittest.TestCase):
    """The shipped benchmark on/off answer files must not rot."""

    def test_on_passes_our_checks(self):
        on = answers("sglang-on")
        self.assertEqual(run("--engine-args", on["extra_args"])[0], 0)
        self.assertEqual(on["tp"], "1")
        toks = shlex.split(on["extra_args"])
        extra = json.loads(toks[toks.index(csc.EXTRA_FLAG) + 1])
        self.assertEqual(extra["miracache"]["config"], "/etc/miracache/client.toml")
        self.assertIn("--enable-hierarchical-cache", toks)

    def test_on_passes_preflight(self):
        from miracache.preflight import checks
        from miracache.preflight import engine_args as ea
        inp = ea.load_inputs("sglang", None, os.path.join(AB, "sglang-on.json"))
        res, _ = checks.sglang_checks(inp["tokens"], {}, "engine-native", None)
        self.assertEqual([r for r in res if r[0] == "fail"], [])

    def test_off_has_no_miracache_tier(self):
        off = answers("sglang-off")
        self.assertNotIn("miracache", off["extra_args"])
        self.assertNotIn("--hicache-storage-backend", off["extra_args"])
        rc, err = run("--engine-args", off["extra_args"])
        self.assertEqual(rc, 1)
        self.assertIn("dynamic", err)

    def test_on_off_differ_only_in_storage_backend(self):
        on, off = answers("sglang-on"), answers("sglang-off")
        self.assertEqual({k for k in on if on[k] != off.get(k)},
                         {"name", "extra_args", "pip_extras"})
        cut = lambda s: s[:s.index(" --hicache-storage-backend ")]  # noqa: E731
        self.assertEqual(cut(on["extra_args"]), off["extra_args"])
        self.assertIn("--hicache-size", off["extra_args"])  # same local host tier on both


if __name__ == "__main__":
    unittest.main()
