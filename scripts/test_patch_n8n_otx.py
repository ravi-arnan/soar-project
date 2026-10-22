#!/usr/bin/env python3
"""Unit test untuk patch-n8n-otx.py (Milestone M5 - Credential Hardening).

Menguji:
  1. Struktur node OTX Lookup menggunakan httpHeaderAuth (tanpa secret inline).
  2. Sanitasi node OTX lama yang membocorkan headerParameters plaintext.
  3. Logika patching JS 'Rangkum Hasil' dan idempotensinya.
  4. Penyusunan ulang koneksi (rewire) pada workflow standar dan modern (cache/MB).
  5. Idempotensi eksekusi penuh patch_workflow_otx.
  6. Resolver ensure_otx_credential (reuse, alias matching, dry-run, exception handling).

Jalankan:
  nice -n 19 python3 -m unittest scripts/test_patch_n8n_otx.py
"""

import importlib.util
import json
import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

MODULE_PATH = Path(__file__).with_name("patch-n8n-otx.py")
SPEC = importlib.util.spec_from_file_location("patch_otx", MODULE_PATH)
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)


class TestPatchN8nOtx(unittest.TestCase):
    def test_otx_node_structure_uses_managed_credential(self):
        node = P.otx_node("cred-test-id", "OTX API Key")
        self.assertEqual(node["name"], "OTX Lookup")
        self.assertEqual(node["type"], "n8n-nodes-base.httpRequest")
        self.assertEqual(node["onError"], "continueRegularOutput")

        params = node["parameters"]
        self.assertEqual(params["authentication"], "genericCredentialType")
        self.assertEqual(params["genericAuthType"], "httpHeaderAuth")
        self.assertNotIn("headerParameters", params)
        self.assertNotIn("sendHeaders", params)

        creds = node["credentials"]
        self.assertIn("httpHeaderAuth", creds)
        self.assertEqual(creds["httpHeaderAuth"]["id"], "cred-test-id")
        self.assertEqual(creds["httpHeaderAuth"]["name"], "OTX API Key")

    def test_sanitize_otx_node_removes_inline_secrets(self):
        leaky_node = {
            "name": "OTX Lookup",
            "type": "n8n-nodes-base.httpRequest",
            "parameters": {
                "method": "GET",
                "url": "=https://otx.alienvault.com/api/v1/indicators/file/{{ hash }}",
                "sendHeaders": True,
                "headerParameters": {
                    "parameters": [{"name": "X-OTX-API-KEY", "value": "plain-text-leaked-key-12345"}]
                },
                "options": {},
            },
        }

        changed = P.sanitize_otx_node(leaky_node, "cred-secure-99", "OTX API Key")
        self.assertTrue(changed)

        params = leaky_node["parameters"]
        self.assertNotIn("headerParameters", params)
        self.assertNotIn("sendHeaders", params)
        self.assertEqual(params.get("authentication"), "genericCredentialType")
        self.assertEqual(params.get("genericAuthType"), "httpHeaderAuth")

        creds = leaky_node.get("credentials", {})
        self.assertEqual(
            creds.get("httpHeaderAuth"),
            {"id": "cred-secure-99", "name": "OTX API Key"},
        )

        # Idempotensi sanitasi pada node yang sudah bersih
        changed_second = P.sanitize_otx_node(leaky_node, "cred-secure-99", "OTX API Key")
        self.assertFalse(changed_second)

    def test_patch_summary_js_logic_and_idempotency(self):
        js_old = """const data = $input.first().json;
const stats = data.data?.attributes?.last_analysis_stats || {};
const malicious = stats.malicious || 0;
const suspicious = stats.suspicious || 0;
const undetected = stats.undetected || 0;
const total = malicious + suspicious + undetected;
    detection_ratio: `${malicious}/${total}`,
if (malicious >= 20 || ruleLevel >= 12) {
  sev = 'CRITICAL';
} else if (malicious >= 5 || ruleLevel >= 7) {
  sev = 'HIGH';
}
return [{
  json: {
    silent,
    should_active_response
  }
}];"""

        js_new, changed = P.patch_summary(js_old)
        self.assertTrue(changed)
        self.assertIn("const is_otx = !!data.pulse_info;", js_new)
        self.assertIn("const otx_threat = is_otx && otx_pulses > 0;", js_new)
        self.assertIn("otx_threat || malicious >= 5 || ruleLevel >= 7", js_new)
        self.assertIn("source: is_otx ? 'otx' : 'vt'", js_new)

        # Idempoten
        js_again, changed_again = P.patch_summary(js_new)
        self.assertFalse(changed_again)
        self.assertEqual(js_again, js_new)

    def test_patch_workflow_otx_fresh(self):
        wf = {
            "name": "Deteksi Malware Test",
            "nodes": [
                {
                    "name": "Scan VirusTotal",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {},
                },
                {
                    "name": "Rangkum Hasil",
                    "type": "n8n-nodes-base.code",
                    "parameters": {
                        "jsCode": (
                            "const data = $input.first().json;\n"
                            "const stats = data.data?.attributes?.last_analysis_stats || {};\n"
                            "const total = malicious + suspicious + undetected;\n"
                            "    detection_ratio: `${malicious}/${total}`,\n"
                            "} else if (malicious >= 5 || ruleLevel >= 7) {\n"
                            "    silent,\n    should_active_response"
                        )
                    },
                },
            ],
            "connections": {
                "Scan VirusTotal": {
                    "main": [[{"node": "Rangkum Hasil", "type": "main", "index": 0}]]
                }
            },
        }

        res_wf, changed, changes = P.patch_workflow_otx(wf, "cred-abc", "OTX API Key")
        self.assertTrue(changed)
        self.assertTrue(any("VT OK?" in c for c in changes))
        self.assertTrue(any("OTX Lookup" in c for c in changes))

        # Verifikasi node VT OK? dan OTX Lookup ada
        vt_ok = P.get_node(res_wf["nodes"], "VT OK?")
        otx = P.get_node(res_wf["nodes"], "OTX Lookup")
        self.assertIsNotNone(vt_ok)
        self.assertIsNotNone(otx)
        self.assertEqual(otx["credentials"]["httpHeaderAuth"]["id"], "cred-abc")

        # Verifikasi rewire
        conns = res_wf["connections"]
        self.assertEqual(
            conns["Scan VirusTotal"]["main"][0][0]["node"],
            "VT OK?",
        )
        self.assertEqual(conns["VT OK?"]["main"][0][0]["node"], "Rangkum Hasil")
        self.assertEqual(conns["VT OK?"]["main"][1][0]["node"], "OTX Lookup")
        self.assertEqual(conns["OTX Lookup"]["main"][0][0]["node"], "Rangkum Hasil")

    def test_patch_workflow_otx_with_cache_and_malwarebazaar(self):
        wf = {
            "name": "Deteksi Malware Modern",
            "nodes": [
                {"name": "Scan VirusTotal", "type": "n8n-nodes-base.httpRequest"},
                {"name": "Simpan Cache VT", "type": "n8n-nodes-base.httpRequest"},
                {"name": "MalwareBazaar Lookup", "type": "n8n-nodes-base.httpRequest"},
                {
                    "name": "Rangkum Hasil",
                    "type": "n8n-nodes-base.code",
                    "parameters": {"jsCode": "const is_otx = true;"},
                },
            ],
            "connections": {
                "Simpan Cache VT": {
                    "main": [[{"node": "MalwareBazaar Lookup", "type": "main", "index": 0}]]
                }
            },
        }

        res_wf, changed, changes = P.patch_workflow_otx(wf, "cred-mod-1", "OTX API Key")
        self.assertTrue(changed)

        conns = res_wf["connections"]
        # Simpan Cache VT diarahkan ke VT OK?
        self.assertEqual(conns["Simpan Cache VT"]["main"][0][0]["node"], "VT OK?")
        # VT OK? true -> MalwareBazaar Lookup, false -> OTX Lookup
        self.assertEqual(conns["VT OK?"]["main"][0][0]["node"], "MalwareBazaar Lookup")
        self.assertEqual(conns["VT OK?"]["main"][1][0]["node"], "OTX Lookup")
        # OTX Lookup -> MalwareBazaar Lookup
        self.assertEqual(conns["OTX Lookup"]["main"][0][0]["node"], "MalwareBazaar Lookup")

    def test_patch_workflow_otx_sanitizes_existing_leaky_node(self):
        wf = {
            "name": "Deteksi Malware Leaky",
            "nodes": [
                {"name": "VT OK?", "type": "n8n-nodes-base.if"},
                {
                    "name": "OTX Lookup",
                    "type": "n8n-nodes-base.httpRequest",
                    "parameters": {
                        "sendHeaders": True,
                        "headerParameters": {
                            "parameters": [{"name": "X-OTX-API-KEY", "value": "leaked-secret"}]
                        },
                    },
                },
                {
                    "name": "Rangkum Hasil",
                    "type": "n8n-nodes-base.code",
                    "parameters": {"jsCode": "const is_otx = true;"},
                },
            ],
            "connections": {
                "Scan VirusTotal": {"main": [[{"node": "VT OK?", "type": "main", "index": 0}]]},
                "VT OK?": {
                    "main": [
                        [{"node": "Rangkum Hasil", "type": "main", "index": 0}],
                        [{"node": "OTX Lookup", "type": "main", "index": 0}],
                    ]
                },
                "OTX Lookup": {"main": [[{"node": "Rangkum Hasil", "type": "main", "index": 0}]]},
            },
        }

        res_wf, changed, changes = P.patch_workflow_otx(wf, "cred-sanitized", "OTX API Key")
        self.assertTrue(changed)
        self.assertTrue(any("dimigrasi ke credential" in c for c in changes))

        otx_node = P.get_node(res_wf["nodes"], "OTX Lookup")
        self.assertNotIn("headerParameters", otx_node["parameters"])
        self.assertEqual(
            otx_node["credentials"]["httpHeaderAuth"],
            {"id": "cred-sanitized", "name": "OTX API Key"},
        )

        # Pass kedua harus 100% idempoten tanpa perubahan
        res_wf2, changed2, changes2 = P.patch_workflow_otx(res_wf, "cred-sanitized", "OTX API Key")
        self.assertFalse(changed2)
        self.assertEqual(len(changes2), 0)

    def test_ensure_otx_credential_reuse_alias_and_dryrun(self):
        # 1. Bila cred_id eksplisit diberikan
        cid, cname = P.ensure_otx_credential("http://fake", "k", cred_id="direct-id", cred_name="Custom Name")
        self.assertEqual(cid, "direct-id")
        self.assertEqual(cname, "Custom Name")

        # 2. Bila n8n sudah memiliki credential alias 'OTX Header Auth'
        mock_creds_resp = {
            "data": [
                {"id": "existing-alias-id", "name": "OTX Header Auth", "type": "httpHeaderAuth"}
            ]
        }
        with patch.object(P, "api_get", return_value=mock_creds_resp):
            cid2, cname2 = P.ensure_otx_credential("http://fake", "k")
            self.assertEqual(cid2, "existing-alias-id")
            self.assertEqual(cname2, "OTX Header Auth")

        # 3. Dry run saat credential belum ada
        with patch.object(P, "api_get", return_value={"data": []}):
            cid3, cname3 = P.ensure_otx_credential("http://fake", "k", otx_key="dummy-key", dry_run=True)
            self.assertEqual(cid3, "dry-run-otx-id")
            self.assertEqual(cname3, "OTX API Key")

        # 4. Gagal bila credential belum ada dan otx_key tidak diisi
        with patch.object(P, "api_get", return_value={"data": []}):
            with self.assertRaises(ValueError):
                P.ensure_otx_credential("http://fake", "k", otx_key=None, dry_run=False)


if __name__ == "__main__":
    unittest.main()
