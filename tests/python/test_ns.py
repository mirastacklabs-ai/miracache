"""miracache.ns: the one ns encoding (design/03 R19). A change to these vectors means every
host computes a new ns and the whole cache misses once: change them only on purpose."""
import hashlib
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from miracache import ns  # noqa: E402

FIELDS = {"engine": "sglang", "model": "org/model", "tp_rank": 1, "tp_size": 4, "is_mla": False,
          "extra_ns": {"model_revision": "abc"}, "groups": [[0, 16, ["l0", "l1"]]], "seed": None}
# Written by hand from the documented encoding (sorted keys, no whitespace), not by ns.canonical.
CANON = ('{"engine":"sglang","extra_ns":{"model_revision":"abc"},"groups":[[0,16,["l0","l1"]]],'
         '"is_mla":false,"model":"org/model","seed":null,"tp_rank":1,"tp_size":4}')
FIELDS_GOLDEN = "33a17372b5267947720048252e19bd8c2eff2cd87814e9920b4ced8b97f0c27f"


class TestNsEncoding(unittest.TestCase):
    def test_canonical_bytes(self):
        self.assertEqual(ns.canonical(FIELDS), CANON.encode("ascii"))

    def test_digest_is_domain_separated_sha256(self):
        want = hashlib.sha256(b"mira-ns-v1\x00" + CANON.encode("ascii")).digest()
        self.assertEqual(ns.digest(FIELDS), want)
        self.assertEqual(len(want), 32)

    def test_golden_vector(self):
        self.assertEqual(ns.digest(FIELDS).hex(), FIELDS_GOLDEN)
        self.assertEqual(ns.digest({}).hex(),
                         "53387dab3b771940e81c45801f4bc0a8699d983b022529a79a959080ff993df8")

    def test_key_order_does_not_matter(self):
        self.assertEqual(ns.digest(dict(reversed(list(FIELDS.items())))), ns.digest(FIELDS))

    def test_every_value_matters(self):
        seen = {ns.digest(FIELDS)}
        for k, v in (("model", "org/model2"), ("tp_rank", 2), ("is_mla", True),
                     ("extra_ns", {"model_revision": "abd"}), ("seed", "0"), ("seed", 0)):
            seen.add(ns.digest(dict(FIELDS, **{k: v})))
        self.assertEqual(len(seen), 7)

    def test_non_ascii_is_escaped(self):
        self.assertEqual(ns.canonical({"m": "é"}), b'{"m":"\\u00e9"}')

    def test_non_json_values_refused(self):
        for bad in ({"x": object()}, {"x": float("nan")}, {"x": b"raw"}, {"x": {1, 2}},
                    {1: "x"}, {"x": {None: 1}}, {"x": [{True: 1}]}):
            with self.assertRaises((TypeError, ValueError)):
                ns.digest(bad)

    def test_fingerprint(self):
        d = ns.digest(FIELDS)
        self.assertEqual(ns.fingerprint(d), d.hex()[:8])


if __name__ == "__main__":
    unittest.main()
