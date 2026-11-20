import json
import os
import shlex
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from miracache import check_vllm_config as c  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
TIER = {"type": "MiraTier", "module_path": "miracache.vllm_tier", "config": "/x",
        "kv_load_failure_policy": "recompute"}


def kv_json(**over):
    extra = {"spec_name": "TieringOffloadingSpec", "cpu_bytes_to_use": 1 << 30,
             "canonical_layout": True, "secondary_tiers": [TIER]}
    extra.update(over)
    extra = {k: v for k, v in extra.items() if v is not None}
    return json.dumps({"kv_connector": "OffloadingConnector", "kv_load_failure_policy": "recompute",
                       "kv_connector_extra_config": extra})


KV = kv_json()
GOOD = ("--prefix-caching-hash-algo", "sha256_cbor", "--block-size", "16")


NEED_ANSWERS = unittest.skipUnless(os.path.isdir(os.path.join(ROOT, "deploy", "agentbench")),
                                "benchmark answer files are not in this source tree")


def answers_args(name):
    with open(os.path.join(ROOT, "deploy", "agentbench", name + ".json")) as f:
        return shlex.split(json.load(f)["extra_args"])


def answers_kv(name):
    return json.loads(c._flag(answers_args(name), "--kv-transfer-config"))


class TestCheck(unittest.TestCase):
    def run_main(self, *a):
        return c.main(list(a))

    def test_ok(self):
        self.assertEqual(self.run_main("--kv-transfer-config", KV, *GOOD), 0)

    def test_bad_hash_algo(self):
        self.assertEqual(self.run_main("--kv-transfer-config", KV,
                                       "--prefix-caching-hash-algo", "sha256"), 1)

    def test_bad_policy_and_pp(self):
        kv = KV.replace("recompute", "fail")
        self.assertEqual(self.run_main("--kv-transfer-config", kv,
                                       "--prefix-caching-hash-algo", "sha256_cbor",
                                       "--pipeline-parallel-size", "2"), 1)

    def test_bad_json(self):
        self.assertEqual(self.run_main("--kv-transfer-config", "{"), 1)

    def test_no_mira_tier_is_ok(self):
        self.assertEqual(self.run_main("--kv-transfer-config", '{"kv_connector":"X"}'), 0)

    def test_secondary_tier_would_be_ignored_fails(self):
        for kv in (kv_json(spec_name=None),  # default CPUOffloadingSpec ignores secondary_tiers
                   kv_json(spec_name="CPUOffloadingSpec"),
                   kv_json(cpu_bytes_to_use=None),
                   kv_json(cpu_bytes_to_use=0),
                   kv_json(cpu_bytes_to_use="10GB")):
            self.assertEqual(self.run_main("--kv-transfer-config", kv, *GOOD), 1, kv)

    def test_config_must_be_a_path_string(self):
        kv = kv_json(secondary_tiers=[{**TIER, "config": {"path": "/x"}}])
        self.assertEqual(self.run_main("--kv-transfer-config", kv, *GOOD), 1)

    def test_tier_must_repeat_the_recompute_policy(self):
        missing = {k: v for k, v in TIER.items() if k != "kv_load_failure_policy"}
        for tier in (missing, {**TIER, "kv_load_failure_policy": "fail"}):
            kv = kv_json(secondary_tiers=[tier])
            self.assertEqual(self.run_main("--kv-transfer-config", kv, *GOOD), 1, tier)

    @NEED_ANSWERS
    def test_shipped_agentbench_answers(self):
        for name in ("on", "off"):
            p = os.path.join(ROOT, "deploy", "agentbench", name + ".json")
            self.assertEqual(self.run_main("--answers", p), 0, name)

    @NEED_ANSWERS
    def test_on_json_actually_loads_the_tier(self):
        extra = answers_kv("on")["kv_connector_extra_config"]
        self.assertEqual(extra["spec_name"], "TieringOffloadingSpec")
        self.assertGreater(extra["cpu_bytes_to_use"], 0)
        (tier,) = extra["secondary_tiers"]
        self.assertEqual((tier["type"], tier["module_path"]), ("MiraTier", "miracache.vllm_tier"))
        self.assertIsInstance(tier["config"], str)

    @NEED_ANSWERS
    def test_on_off_differ_only_in_tier(self):
        d = os.path.join(ROOT, "deploy", "agentbench")
        with open(os.path.join(d, "on.json")) as f1, open(os.path.join(d, "off.json")) as f2:
            on, off = json.load(f1), json.load(f2)
        diff = {k for k in on if on[k] != off.get(k)}
        self.assertEqual(diff, {"name", "extra_args", "pip_extras"})
        # inside extra_args: same CPU tier and flags, only secondary_tiers differs (fair on/off)
        on_kv, off_kv = answers_kv("on"), answers_kv("off")
        on_extra = on_kv.pop("kv_connector_extra_config")
        off_extra = off_kv.pop("kv_connector_extra_config")
        self.assertNotIn("secondary_tiers", off_extra)
        self.assertEqual({k: v for k, v in on_extra.items() if k != "secondary_tiers"}, off_extra)
        self.assertEqual(on_kv, off_kv)
        flags = lambda a: a[:a.index("--kv-transfer-config")]  # noqa: E731
        self.assertEqual(flags(answers_args("on")), flags(answers_args("off")))


if __name__ == "__main__":
    unittest.main()
