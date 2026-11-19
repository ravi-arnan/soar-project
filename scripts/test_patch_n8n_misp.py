#!/usr/bin/env python3
"""Unit test patch MISP n8n (offline). Jalankan: python3 -m unittest scripts/test_patch_n8n_misp.py"""
import importlib.util
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _load():
    spec = importlib.util.spec_from_file_location("pnm", os.path.join(HERE, "patch-n8n-misp.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


P = _load()

JS_V2 = (
    "const mb = $input.first().json;\n"
    "const cacheNode = $('Cek Cache VT').first().json;\n"
    "const cache_hit = !!cacheNode.cache_hit;\n"
    "const mb_known = false;\n"
    "const mb_malicious = false;\n"
    "const mb_threat = mb_known && mb_malicious;\n"
    "const out = {};\n"
    "if (malicious >= 20 || ruleLevel >= 12 || (mb_threat && malicious >= 5)) {\n"
    "  sev = 'CRITICAL';\n"
    "} else if (!is_system_file && (otx_threat || mb_threat || malicious >= 5 || ruleLevel >= 7)) {\n"
    "  sev = 'HIGH';\n"
    "}\n"
    "const fields = {\n"
    "    source: 'vt',\n"
    "    mb_query_status,\n"
    "    mb_threat\n"
    "};\n"
    "// patch:cache-mb:v2"
)


class TestPatchN8nMisp(unittest.TestCase):
    def test_patch_v2_to_v3_and_idempotency(self):
        js3, ch = P.patch_misp_js(JS_V2)
        self.assertTrue(ch)
        self.assertIn("const misp = $input.first().json;", js3)
        self.assertIn("const mb = $('MalwareBazaar Lookup').first().json;", js3)
        self.assertIn("const misp_threat = misp_hit;", js3)
        self.assertIn("const misp_to_ids =", js3)
        self.assertIn("otx_threat || mb_threat || misp_threat || malicious >= 5", js3)
        self.assertIn("misp_hit,", js3)
        self.assertIn("misp_sources", js3)
        self.assertIn("// patch:misp:v1", js3)
        self.assertIn("// patch:cache-mb:v2", js3)

        js3b, ch2 = P.patch_misp_js(js3)
        self.assertFalse(ch2)
        self.assertEqual(js3b, js3)

    def test_fails_when_v2_marker_missing(self):
        with self.assertRaises(SystemExit):
            P.patch_misp_js("const x = 1; // tanpa marker")

    def test_misp_node_definition(self):
        self.assertEqual(P.MISP_NODE["type"], "n8n-nodes-base.httpRequest")
        self.assertEqual(P.MISP_NODE.get("onError"), "continueRegularOutput")
        self.assertIn(
            "Ekstrak Alert",
            P.MISP_NODE["parameters"]["queryParameters"]["parameters"][0]["value"],
        )


if __name__ == "__main__":
    unittest.main()
