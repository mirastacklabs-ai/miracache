import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from miracache.preflight import cli  # noqa: E402

KV = ('{"kv_connector":"OffloadingConnector","kv_load_failure_policy":"recompute",'
      '"kv_connector_extra_config":{"canonical_layout":true,"spec_name":"TieringOffloadingSpec",'
      '"cpu_bytes_to_use":1073741824,"secondary_tiers":'
      '[{"type":"MiraTier","module_path":"miracache.vllm_tier","config":"/x",'
      '"kv_load_failure_policy":"recompute"}]}}')
GOOD_VLLM = ("serve org/model --block-size 16 --prefix-caching-hash-algo sha256_cbor "
             "--tensor-parallel-size 2 --kv-transfer-config '%s'" % KV)
SG_EXTRA = {"backend_name": "miracache", "module_path": "miracache.sglang",
            "class_name": "MiraHiCacheStorage", "interface_v1": 1,
            "hicache_storage_pass_prefix_keys": True, "miracache_expect_prefix_keys": True,
            "miracache": {"config": "/etc/miracache/client.toml"}}
GOOD_SGLANG = ("--model-path org/model --tp 2 --page-size 64 --hicache-storage-backend-extra-config "
               "'%s'" % json.dumps(SG_EXTRA))
NEED_ANSWERS = unittest.skipUnless(os.path.isdir(os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "agentbench")),
                                "benchmark answer files are not in this source tree")
HEX = "ab" * 32


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.secret = self.write_secret()

    def write_secret(self, text=None, mode=0o600, name="secret.conf"):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w", newline="") as f:
            f.write(text if text is not None else "current = 1\n1 = %s\n" % HEX)
        os.chmod(p, mode)
        return p

    def run_cli(self, *args, env=("PYTHONHASHSEED=0",)):
        out = io.StringIO()
        a = list(args)
        for e in (env if a[0] != "compare" else ()):
            a += ["--env", e]
        with contextlib.redirect_stderr(io.StringIO()):
            rc = cli.main(a, out=out)
        return rc, out.getvalue()

    def check(self, engine, args, *extra, secret=None, env=("PYTHONHASHSEED=0",)):
        rc, text = self.run_cli(engine and "--engine", engine, "--engine-args", args,
                                "--secret-file", secret or self.secret, "--no-node-facts",
                                "--json", *extra, env=env)
        return rc, json.loads(text)

    @staticmethod
    def ids(rep, level):
        return {r["id"] for r in rep["results"] if r["level"] == level}


class TestVllm(Base):
    def test_ok(self):
        rc, rep = self.check("vllm", GOOD_VLLM)
        self.assertEqual((rc, rep["fails"]), (0, 0), rep["results"])

    def test_spec_name_cpu_bytes_config_checked(self):
        for bad in (GOOD_VLLM.replace("TieringOffloadingSpec", "CPUOffloadingSpec"),
                    GOOD_VLLM.replace('"cpu_bytes_to_use":1073741824,', ""),
                    GOOD_VLLM.replace("1073741824", "0"),
                    GOOD_VLLM.replace('"config":"/x"', '"config":5')):
            rc, rep = self.check("vllm", bad)
            self.assertEqual(rc, 1, bad)
            self.assertIn("vllm.kv_transfer_config", self.ids(rep, "fail"))

    def test_policy_fail(self):
        rc, rep = self.check("vllm", GOOD_VLLM.replace("recompute", "fail"))
        self.assertEqual(rc, 1)
        self.assertIn("vllm.kv_load_failure_policy", self.ids(rep, "fail"))

    def test_hash_algo_fail_including_sha256(self):
        for algo in ("sha256", "builtin"):
            rc, rep = self.check("vllm", GOOD_VLLM.replace("sha256_cbor", algo))
            self.assertEqual(rc, 1)
            self.assertIn("vllm.hash_algo", self.ids(rep, "fail"))

    def test_hash_algo_missing_fails(self):
        rc, rep = self.check("vllm", GOOD_VLLM.replace("--prefix-caching-hash-algo sha256_cbor", ""))
        self.assertIn("vllm.hash_algo", self.ids(rep, "fail"))

    def test_pp_fail(self):
        rc, rep = self.check("vllm", GOOD_VLLM + " --pipeline-parallel-size 2")
        self.assertIn("vllm.parallelism", self.ids(rep, "fail"))

    def test_logging_warns_engine_native_fails_gateway(self):
        rc, rep = self.check("vllm", GOOD_VLLM + " --enable-log-requests")
        self.assertEqual(rc, 0)
        self.assertIn("vllm.request_logging", self.ids(rep, "warn"))
        rc, rep = self.check("vllm", GOOD_VLLM + " --enable-log-requests", "--provider", "et-gateway")
        self.assertEqual(rc, 1)
        self.assertIn("vllm.request_logging", self.ids(rep, "fail"))

    def test_logging_env_warns(self):
        rc, rep = self.check("vllm", GOOD_VLLM, env=("PYTHONHASHSEED=0", "VLLM_REQUEST_BODY_LOG_LEVEL=DEBUG"))
        self.assertIn("vllm.request_logging", self.ids(rep, "warn"))

    def test_strict_warnings_exit_2(self):
        rc, _ = self.run_cli("--engine", "vllm", "--engine-args", GOOD_VLLM + " --enable-log-requests",
                             "--secret-file", self.secret, "--no-node-facts", "--strict-warnings")
        self.assertEqual(rc, 2)

    def test_answers_json(self):
        p = os.path.join(self.tmp.name, "a.json")
        with open(p, "w") as f:
            json.dump({"model": "m", "tp": "1", "extra_args": GOOD_VLLM.split(" ", 2)[2]}, f)
        rc, text = self.run_cli("--engine", "vllm", "--answers", p, "--secret-file", self.secret,
                                "--no-node-facts", "--json")
        rep = json.loads(text)
        self.assertEqual(rc, 0, rep["results"])
        self.assertEqual(rep["fingerprint"]["fields"]["model_id"], "m")

    def test_revision_must_be_mirrored_in_tier(self):
        rc, rep = self.check("vllm", GOOD_VLLM + " --revision abc123")
        self.assertEqual(rc, 1)
        self.assertIn("vllm.ns_revision", self.ids(rep, "fail"))
        good = GOOD_VLLM.replace('"config":"/x"', '"config":"/x","model_revision":"abc123"')
        rc, rep = self.check("vllm", good + " --revision abc123")
        self.assertNotIn("vllm.ns_revision", self.ids(rep, "fail"))
        self.assertEqual(rc, 0, rep["results"])
        rc, rep = self.check("vllm", GOOD_VLLM)
        self.assertNotIn("vllm.ns_revision", self.ids(rep, "fail"))

    def test_quantization_must_be_mirrored_in_tier(self):
        rc, rep = self.check("vllm", GOOD_VLLM + " --quantization fp8")
        self.assertEqual(rc, 1)
        self.assertIn("vllm.ns_quantization", self.ids(rep, "fail"))
        good = GOOD_VLLM.replace('"config":"/x"', '"config":"/x","ns_fields":{"quantization":"fp8"}')
        rc, rep = self.check("vllm", good + " --quantization fp8")
        self.assertEqual(rc, 0, rep["results"])

    def test_dtype_and_hf_overrides_must_be_mirrored_in_tier(self):
        for flags, key, val, rid in (("--dtype float16", "dtype", "float16", "vllm.ns_dtype"),
                                     ("--hf-overrides '{\"a\":1}'", "hf_overrides", '{"a":1}',
                                      "vllm.ns_hf_overrides"),
                                     ("-q awq", "quantization", "awq", "vllm.ns_quantization")):
            rc, rep = self.check("vllm", GOOD_VLLM + " " + flags)
            self.assertIn(rid, self.ids(rep, "fail"), flags)
            good = GOOD_VLLM.replace('"config":"/x"', '"config":"/x","ns_fields":%s' % json.dumps({key: val}))
            rc, rep = self.check("vllm", good + " " + flags)
            self.assertEqual(rc, 0, (flags, rep["results"]))
        rc, rep = self.check("vllm", GOOD_VLLM + " --dtype auto --revision main")
        self.assertFalse({i for i in self.ids(rep, "fail") if ".ns_" in i})

    def test_tier_ns_fields_not_an_object_fails(self):
        bad = GOOD_VLLM.replace('"config":"/x"', '"config":"/x","ns_fields":"fp8"')
        rc, rep = self.check("vllm", bad)
        self.assertIn("vllm.ns_fields", self.ids(rep, "fail"))

    def test_no_tier_no_ns_check(self):
        no_tier = GOOD_VLLM.replace(',"secondary_tiers":[{"type":"MiraTier","module_path":'
                                    '"miracache.vllm_tier","config":"/x","kv_load_failure_policy":"recompute"}]', "")
        self.assertNotIn("MiraTier", no_tier)
        rc, rep = self.check("vllm", no_tier + " --revision abc123")
        self.assertNotIn("vllm.ns_revision", self.ids(rep, "fail"))

    @NEED_ANSWERS
    def test_shipped_agentbench_on_has_ns_mirrored(self):
        p = os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "agentbench", "on.json")
        rc, text = self.run_cli("--engine", "vllm", "--answers", p, "--secret-file", self.secret,
                                "--no-node-facts", "--json")
        rep = json.loads(text)
        self.assertFalse({i for i in self.ids(rep, "fail") if ".ns_" in i}, rep["results"])

    def test_unknown_version_fails(self):
        rc, rep = self.check("vllm", GOOD_VLLM, "--engine-version", "0.1.0")
        self.assertIn("vllm.version", self.ids(rep, "fail"))


class TestSglang(Base):
    def test_ok(self):
        rc, rep = self.check("sglang", GOOD_SGLANG)
        self.assertEqual((rc, rep["fails"]), (0, 0), rep["results"])

    def test_page_size_small_fails(self):
        rc, rep = self.check("sglang", GOOD_SGLANG.replace("--page-size 64", "--page-size 8"))
        self.assertEqual(rc, 1)
        self.assertIn("sglang.page_size", self.ids(rep, "fail"))

    def test_page_size_default_missing_fails(self):
        rc, rep = self.check("sglang", GOOD_SGLANG.replace("--page-size 64", ""))
        self.assertIn("sglang.page_size", self.ids(rep, "fail"))

    def test_page_size_16_warns(self):
        rc, rep = self.check("sglang", GOOD_SGLANG.replace("--page-size 64", "--page-size 16"))
        self.assertEqual(rc, 0)
        self.assertIn("sglang.page_size_small", self.ids(rep, "warn"))

    def test_prefix_keys_false_or_missing_fails(self):
        for extra in ({**SG_EXTRA, "hicache_storage_pass_prefix_keys": False},
                      {k: v for k, v in SG_EXTRA.items() if k != "hicache_storage_pass_prefix_keys"}):
            args = "--page-size 64 --hicache-storage-backend-extra-config '%s'" % json.dumps(extra)
            rc, rep = self.check("sglang", args)
            self.assertEqual(rc, 1)
            self.assertIn("sglang.pass_prefix_keys", self.ids(rep, "fail"))

    def test_expect_prefix_keys_false_or_missing_fails(self):
        for extra in ({**SG_EXTRA, "miracache_expect_prefix_keys": False},
                      {k: v for k, v in SG_EXTRA.items() if k != "miracache_expect_prefix_keys"}):
            args = "--page-size 64 --hicache-storage-backend-extra-config '%s'" % json.dumps(extra)
            rc, rep = self.check("sglang", args)
            self.assertEqual(rc, 1)
            self.assertIn("sglang.pass_prefix_keys", self.ids(rep, "fail"))

    def test_page_size_15_fails_16_ok(self):
        rc, rep = self.check("sglang", GOOD_SGLANG.replace("--page-size 64", "--page-size 15"))
        self.assertIn("sglang.page_size", self.ids(rep, "fail"))
        rc, rep = self.check("sglang", GOOD_SGLANG.replace("--page-size 64", "--page-size 16"))
        self.assertNotIn("sglang.page_size", self.ids(rep, "fail"))

    def test_pp_fails(self):
        rc, rep = self.check("sglang", GOOD_SGLANG + " --pp-size 2")
        self.assertIn("sglang.pp", self.ids(rep, "fail"))

    def test_key_scheme_and_interface(self):
        rc, rep = self.check("sglang", GOOD_SGLANG + " --hicache-storage-key-scheme unified")
        self.assertIn("sglang.key_scheme", self.ids(rep, "fail"))
        extra = {k: v for k, v in SG_EXTRA.items() if k != "interface_v1"}
        rc, rep = self.check("sglang", "--page-size 64 --hicache-storage-backend-extra-config '%s'"
                             % json.dumps(extra))
        self.assertIn("sglang.interface_v1", self.ids(rep, "fail"))

    def test_client_config_missing_fails(self):
        """Preflight reuses check_sglang_config, which needs miracache.config."""
        for mc in ({}, {"secret_file": "/s"}, None):
            extra = dict(SG_EXTRA, miracache=mc) if mc is not None else {
                k: v for k, v in SG_EXTRA.items() if k != "miracache"}
            rc, rep = self.check("sglang", "--page-size 64 --hicache-storage-backend-extra-config '%s'"
                                 % json.dumps(extra))
            self.assertEqual(rc, 1)
            self.assertIn("sglang.client_config", self.ids(rep, "fail"))

    def test_log_requests_warns(self):
        rc, rep = self.check("sglang", GOOD_SGLANG + " --log-requests")
        self.assertEqual(rc, 0)
        self.assertIn("sglang.request_logging", self.ids(rep, "warn"))

    @staticmethod
    def with_ns_fields(nsf, more=""):
        return ("--model-path org/model --tp 2 --page-size 64 %s --hicache-storage-backend-extra-config "
                "'%s'" % (more, json.dumps(dict(SG_EXTRA, ns_fields=nsf))))

    def assert_mirror(self, rid, flags, key, val):
        """flags not mirrored -> fail; mirrored with another value -> fail; same value -> ok."""
        rc, rep = self.check("sglang", GOOD_SGLANG + " " + flags)
        self.assertEqual(rc, 1)
        self.assertIn(rid, self.ids(rep, "fail"))
        rc, rep = self.check("sglang", self.with_ns_fields({key: "other"}, flags))
        self.assertIn(rid, self.ids(rep, "fail"))
        rc, rep = self.check("sglang", self.with_ns_fields({key: val}, flags))
        self.assertNotIn(rid, self.ids(rep, "fail"))
        self.assertEqual(rc, 0, rep["results"])

    def test_revision_must_be_in_ns_fields(self):
        self.assert_mirror("sglang.ns_revision", "--revision abc123", "model_revision", "abc123")

    def test_quantization_must_be_in_ns_fields(self):
        self.assert_mirror("sglang.ns_quantization", "--quantization fp8", "quantization", "fp8")

    def test_kv_dtype_must_be_in_ns_fields(self):
        self.assert_mirror("sglang.ns_kv_dtype", "--kv-cache-dtype fp8_e5m2", "kv_cache_dtype", "fp8_e5m2")
        self.assert_mirror("sglang.ns_kv_dtype", "--kv-cache-dtype=bf16", "kv_cache_dtype", "bf16")
        rc, rep = self.check("sglang", GOOD_SGLANG + " --kv-cache-dtype auto")
        self.assertNotIn("sglang.ns_kv_dtype", self.ids(rep, "fail"))

    def test_other_kv_changing_flags_must_be_in_ns_fields(self):
        self.assert_mirror("sglang.ns_dtype", "--dtype float16", "dtype", "float16")
        self.assert_mirror("sglang.ns_quantization_params", "--quantization-param-path /s.json",
                           "quantization_param_path", "/s.json")
        self.assert_mirror("sglang.ns_model_override_args", "--json-model-override-args '{\"a\":1}'",
                           "model_override_args", '{"a":1}')
        rc, rep = self.check("sglang", GOOD_SGLANG + " --dtype auto")
        self.assertNotIn("sglang.ns_dtype", self.ids(rep, "fail"))

    def test_revision_main_needs_no_mirror(self):
        rc, rep = self.check("sglang", GOOD_SGLANG + " --revision main")
        self.assertNotIn("sglang.ns_revision", self.ids(rep, "fail"))

    def test_ns_fields_not_an_object_fails(self):
        rc, rep = self.check("sglang", self.with_ns_fields(["x"]))
        self.assertEqual(rc, 1)
        self.assertIn("sglang.ns_fields", self.ids(rep, "fail"))

    def test_engine_args_override_answers_last_wins(self):
        p = os.path.join(self.tmp.name, "a.json")
        with open(p, "w") as f:
            json.dump({"model": "org/model", "tp": "2", "revision": "abc123",
                       "extra_args": self.with_ns_fields({"model_revision": "def456"}).split(" ", 6)[6]}, f)
        rc, text = self.run_cli("--engine", "sglang", "--answers", p, "--engine-args", "--revision def456",
                                "--secret-file", self.secret, "--no-node-facts", "--json")
        self.assertNotIn("sglang.ns_revision", self.ids(json.loads(text), "fail"))

    def test_served_name_alias_needs_model_path(self):
        # SGLang hands the storage backend its served model name: an alias does not name the weights.
        self.assert_mirror("sglang.ns_model_path", "--served-model-name prod", "model_path", "org/model")
        rc, rep = self.check("sglang", GOOD_SGLANG + " --served-model-name org/model")  # same as path
        self.assertNotIn("sglang.ns_model_path", self.ids(rep, "fail"))

    def test_no_ns_fails_by_default(self):
        rc, rep = self.check("sglang", GOOD_SGLANG)
        self.assertFalse({i for i in self.ids(rep, "fail") if ".ns_" in i})

    def test_answers_file_flags_are_seen(self):
        """agentbench turns revision / served_name / kv_cache_dtype answers into flags."""
        p = os.path.join(self.tmp.name, "a.json")
        with open(p, "w") as f:
            json.dump({"model": "org/model", "tp": "2", "revision": "abc123", "served_name": "prod",
                       "kv_cache_dtype": "fp8_e4m3", "extra_args": GOOD_SGLANG.split(" ", 4)[4]}, f)
        rc, text = self.run_cli("--engine", "sglang", "--answers", p, "--secret-file", self.secret,
                                "--no-node-facts", "--json")
        fails = self.ids(json.loads(text), "fail")
        self.assertTrue({"sglang.ns_revision", "sglang.ns_kv_dtype", "sglang.ns_model_path"} <= fails, fails)

    @NEED_ANSWERS
    def test_shipped_agentbench_on_has_ns_mirrored(self):
        p = os.path.join(os.path.dirname(__file__), "..", "..", "deploy", "agentbench", "sglang-on.json")
        rc, text = self.run_cli("--engine", "sglang", "--answers", p, "--secret-file", self.secret,
                                "--no-node-facts", "--json")
        rep = json.loads(text)
        self.assertFalse({i for i in self.ids(rep, "fail") if ".ns_" in i}, rep["results"])


class TestSecret(Base):
    def run_secret(self, path):
        rc, rep = self.check("vllm", GOOD_VLLM, secret=path)
        return rc, self.ids(rep, "fail")

    def test_missing(self):
        rc, f = self.run_secret(os.path.join(self.tmp.name, "nope"))
        self.assertEqual(rc, 1)
        self.assertIn("secret.missing", f)

    def test_no_secret_flag(self):
        rc, text = self.run_cli("--engine", "vllm", "--engine-args", GOOD_VLLM, "--no-node-facts", "--json")
        self.assertEqual(rc, 1)

    def test_permissions(self):
        for mode in (0o640, 0o604, 0o644, 0o660, 0o400, 0o700):  # exactly 0600, as the C++ client
            rc, f = self.run_secret(self.write_secret(mode=mode, name="s%o" % mode))
            self.assertEqual(rc, 1, oct(mode))
            self.assertIn("secret.permissions", f)

    def test_golden_fixture_shared_with_cpp(self):
        # Same file tests/client/engine_native_test.cpp loads (SharedGoldenFixture).
        with open(os.path.join(os.path.dirname(__file__), "..", "..", "proto", "golden", "secret_golden.txt")) as f:
            body = f.read()
        self.assertEqual(self.run_secret(self.write_secret(body, name="golden")), (0, set()))

    def test_accepts(self):
        h = HEX
        for text in ("current = 1\n1 = %s\n" % h,
                     "current = 1\n1 = %s" % h,                       # no trailing newline
                     "# c\n\n  current\t=  2 \r\n 1=%s\r\n2 = %s\r\n" % (h, h.upper()),
                     "1 = %s\ncurrent = 1\n" % h,                     # order is free
                     "current = 01\n1 = %s\n" % h,                    # leading zeros parse
                     "current = 4294967295\n4294967295 = %s\n" % h,
                     "current = 1\n" + "".join("%d = %s\n" % (i, h) for i in range(1, 40))):  # no kver cap
            self.assertEqual(self.run_secret(self.write_secret(text, name="ok")), (0, set()), text[:40])

    def test_malformed(self):
        h = HEX
        for text in ("not a secret", '{"current": 1, "secrets": {"1": "%s"}}' % h,
                     "current = 1\nhello\n",                          # line without '='
                     "current = 1\n1 =\n", "current = 1\n1 = %s\n" % h[2:],
                     "current = 1\n1 = %s00\n" % h, "current = 1\n1 = %s\n" % ("zz" * 32),
                     "current = 1\n1 = 0x%s\n" % h[2:],
                     "current = 1\n1 = %s # note\n" % h,              # no inline comments
                     "current = 1\ncurrent = 1\n1 = %s\n" % h,        # duplicate current
                     "current = 1\n1 = %s\n1 = %s\n" % (h, h),        # duplicate kver
                     "current = 1\n1 = %s\n01 = %s\n" % (h, h),       # duplicate after parse
                     "current = 0\n0 = %s\n" % h, "current = x\n1 = %s\n" % h,
                     "current = -1\n1 = %s\n" % h, "current = 4294967296\n1 = %s\n" % h,
                     "current = 1\nx = %s\n" % h, "current = 1\n1 = %s\n 0 = %s\n" % (h, h)):
            self.assertIn("secret.malformed", self.run_secret(self.write_secret(text, name="m"))[1], text)

    def test_kver_missing(self):
        h = HEX
        for text in ("", "1 = %s\n" % h, "# only\n", "current = 2\n1 = %s\n" % h, "current = 1\n"):
            self.assertIn("secret.kver_missing", self.run_secret(self.write_secret(text, name="k"))[1], text)

    def test_gateway_provider_skips_secret(self):
        rc, rep = self.check("vllm", GOOD_VLLM, "--provider", "et-gateway",
                             secret=os.path.join(self.tmp.name, "nope"))
        self.assertEqual(rc, 0)

    def test_secret_bytes_never_printed(self):
        rc, text = self.run_cli("--engine", "vllm", "--engine-args", GOOD_VLLM, "--secret-file",
                                self.secret, "--no-node-facts", "--json")
        self.assertNotIn(HEX, text)


class TestNodeFacts(Base):
    def fake_root(self, hp=0, memlock="unlimited"):
        r = self.tmp.name + "/root"
        for d, name, body in (
                ("sys/kernel/mm/hugepages/hugepages-2048kB", "nr_hugepages", str(hp)),
                ("proc", "meminfo", "Hugepagesize:       2048 kB\n"),
                ("proc", "self/limits" if False else "limits_unused", "")):
            os.makedirs(os.path.join(r, d), exist_ok=True)
            with open(os.path.join(r, d, name), "w") as f:
                f.write(body)
        os.makedirs(os.path.join(r, "proc/self"), exist_ok=True)
        with open(os.path.join(r, "proc/self/limits"), "w") as f:
            f.write("Limit  Soft Limit  Hard Limit  Units\n"
                    "Max locked memory         %s   %s   bytes\n" % (memlock, memlock))
        return r

    def facts_run(self, root):
        rc, text = self.run_cli("--engine", "vllm", "--engine-args", GOOD_VLLM, "--secret-file",
                                self.secret, "--root", root, "--json")
        return rc, json.loads(text)

    def test_warnings(self):
        rc, rep = self.facts_run(self.fake_root(hp=0, memlock="65536"))
        self.assertEqual(rc, 0)
        self.assertEqual(self.ids(rep, "warn"), {"node.hugepages", "node.memlock"})

    def test_clean(self):
        rc, rep = self.facts_run(self.fake_root(hp=1024, memlock="unlimited"))
        self.assertEqual(self.ids(rep, "warn"), set())


class TestFingerprint(Base):
    def fp(self, args=GOOD_VLLM, engine="vllm", env=("PYTHONHASHSEED=0",), *extra):
        rc, text = self.run_cli("fingerprint", "--engine", engine, "--engine-args", args,
                                "--no-node-facts", *extra, env=env)
        self.assertEqual(rc, 0)
        return json.loads(text)

    def save(self, doc, name):
        p = os.path.join(self.tmp.name, name)
        with open(p, "w") as f:
            json.dump(doc, f)
        return p

    def test_stable_and_order_independent(self):
        a = self.fp()
        b = self.fp()
        self.assertEqual(a, b)
        self.assertEqual(len(a["hash"]), 64)
        for k in ("pythonhashseed", "block_size", "lookahead_slots", "lora_paths", "model_id",
                  "engine_version", "tp_size"):
            self.assertIn(k, a["fields"])

    def test_lora_order_irrelevant(self):
        a = self.fp(GOOD_VLLM + " --lora-modules a=/p/1 b=/p/2")
        b = self.fp(GOOD_VLLM + " --lora-modules b=/p/2 a=/p/1")
        self.assertEqual(a["hash"], b["hash"])

    def compare(self, a, b):
        rc, text = self.run_cli("compare", self.save(a, "a.json"), self.save(b, "b.json"))
        return rc, text

    def test_compare_ok(self):
        self.assertEqual(self.compare(self.fp(), self.fp())[0], 0)

    def test_compare_names_each_field(self):
        base = self.fp(GOOD_VLLM + " --num-lookahead-slots 0 --lora-modules a=/p/1",
                       "vllm", ("PYTHONHASHSEED=0",), "--engine-version", "0.32.0")
        variants = {
            "pythonhashseed": self.fp(GOOD_VLLM + " --num-lookahead-slots 0 --lora-modules a=/p/1",
                                      "vllm", ("PYTHONHASHSEED=1",), "--engine-version", "0.32.0"),
            "block_size": self.fp((GOOD_VLLM + " --num-lookahead-slots 0 --lora-modules a=/p/1")
                                  .replace("--block-size 16", "--block-size 32"),
                                  "vllm", ("PYTHONHASHSEED=0",), "--engine-version", "0.32.0"),
            "lookahead_slots": self.fp(GOOD_VLLM + " --num-lookahead-slots 4 --lora-modules a=/p/1",
                                       "vllm", ("PYTHONHASHSEED=0",), "--engine-version", "0.32.0"),
            "lora_paths": self.fp(GOOD_VLLM + " --num-lookahead-slots 0 --lora-modules a=/p/2",
                                  "vllm", ("PYTHONHASHSEED=0",), "--engine-version", "0.32.0"),
            "model_id": self.fp(GOOD_VLLM.replace("org/model", "org/other") + " --num-lookahead-slots 0 "
                                "--lora-modules a=/p/1", "vllm", ("PYTHONHASHSEED=0",),
                                "--engine-version", "0.32.0"),
            "engine_version": self.fp(GOOD_VLLM + " --num-lookahead-slots 0 --lora-modules a=/p/1",
                                      "vllm", ("PYTHONHASHSEED=0",), "--engine-version", "0.33.0"),
            "tp_size": self.fp(GOOD_VLLM.replace("size 2", "size 4") + " --num-lookahead-slots 0 "
                               "--lora-modules a=/p/1", "vllm", ("PYTHONHASHSEED=0",),
                               "--engine-version", "0.32.0"),
        }
        for field, other in variants.items():
            rc, text = self.compare(base, other)
            self.assertEqual(rc, 1, field)
            self.assertIn("field '%s'" % field, text)
            self.assertEqual(text.count("mismatch in field"), 1, text)

    def test_sglang_ns_inputs_mismatch(self):
        a = self.fp(GOOD_SGLANG, "sglang")
        b = self.fp(GOOD_SGLANG.replace("--page-size 64", "--page-size 32"), "sglang")
        rc, text = self.compare(a, b)
        self.assertEqual(rc, 1)
        self.assertIn("field 'page_size'", text)
        extra = dict(SG_EXTRA, ns_fields={"k": "v"})
        c = self.fp("--model-path org/model --tp 2 --page-size 64 --hicache-storage-backend-extra-config "
                    "'%s'" % json.dumps(extra), "sglang")
        self.assertIn("field 'ns_fields'", self.compare(a, c)[1])

    def test_compare_three_and_tamper(self):
        a = self.fp()
        rc, _ = self.run_cli("compare", self.save(a, "1"), self.save(a, "2"), self.save(a, "3"))
        self.assertEqual(rc, 0)
        bad = json.loads(json.dumps(a))
        bad["fields"]["block_size"] = 99
        rc, _ = self.run_cli("compare", self.save(a, "1"), self.save(bad, "2"))
        self.assertEqual(rc, 2)

    def test_compare_accepts_check_json(self):
        rc, text = self.run_cli("--engine", "vllm", "--engine-args", GOOD_VLLM, "--secret-file",
                                self.secret, "--no-node-facts", "--json")
        p = os.path.join(self.tmp.name, "full.json")
        with open(p, "w") as f:
            f.write(text)
        rc, _ = self.run_cli("compare", p, self.save(self.fp(), "x"))
        self.assertEqual(rc, 0)


class TestNicHook(Base):
    def test_report_attached(self):
        p = os.path.join(self.tmp.name, "nic.json")
        with open(p, "w") as f:
            json.dump({"devices": []}, f)
        rc, rep = self.check("vllm", GOOD_VLLM, "--nic-report", p)
        self.assertEqual(rep["nic"], {"devices": []})
        rc, rep = self.check("vllm", GOOD_VLLM, "--nic-report", p + ".missing")
        self.assertIn("nic.report", self.ids(rep, "fail"))

    def nic(self, profile=None, error=None):
        ent = {"device": "mlx5_0"}
        if profile is not None:
            ent["profile"] = profile
        else:
            ent["error"] = error
        p = os.path.join(self.tmp.name, "nicp.json")
        with open(p, "w") as f:
            json.dump({"devices": [], "profiles": [ent]}, f)
        return self.check("vllm", GOOD_VLLM, "--nic-report", p)[1]

    @staticmethod
    def prof(**kw):
        d = {"id": "mlx5-cx6dx-roce", "verified": True, "unprofiled": False, "registry_version": "t",
             "firmware": {"version": "22.35.1012", "min": "22.31.0", "status": "ok"},
             "operating_point": {"fetch_qps": 4, "slice_bytes": 1048576, "read_depth": 16}}
        d.update(kw)
        return d

    def test_profile_reported_ok(self):
        rep = self.nic(self.prof())
        self.assertIn("nic.profile", self.ids(rep, "ok"))
        self.assertEqual(rep["fails"], 0)

    def test_firmware_below_profile_minimum_fails(self):
        rep = self.nic(self.prof(firmware={"version": "20.1.1", "min": "22.31.0", "status": "below_min"}))
        self.assertIn("nic.firmware", self.ids(rep, "fail"))

    def test_unprofiled_and_unverified_warn(self):
        self.assertIn("nic.unprofiled", self.ids(self.nic(self.prof(id="generic-roce", unprofiled=True)), "warn"))
        self.assertIn("nic.unverified", self.ids(self.nic(self.prof(verified=False)), "warn"))

    def test_no_profile_fails(self):
        self.assertIn("nic.profile", self.ids(self.nic(error="no profile matches"), "fail"))


if __name__ == "__main__":
    unittest.main()
