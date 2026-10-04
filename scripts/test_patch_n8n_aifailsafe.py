#!/usr/bin/env python3
"""Test untuk patch-n8n-ai-failsafe.py.

Dua lapis:
  1. Transformasi: node diganti, idempoten (marker), node hilang -> SystemExit.
  2. Perilaku (JS dieksekusi via `node` dengan stub n8n):
     - 'AI Generate' sukses -> spread field Build Payload + ai_response bersih.
     - 'AI Generate' gagal (httpRequest throw) -> TIDAK melempar, field utuh,
       ai_response = fallback, llm_error terisi.
     - 'AI Generate' tanpa ATRIA_API_KEY -> fallback, tidak memanggil HTTP.
     - Template Telegram: dievaluasi sebagai ekspresi JS; tidak boleh ada
       'undefined' walau $json rusak ({}), karena field diambil dari 'Build
       Payload'.

Jalankan: python3 scripts/test_patch_n8n_aifailsafe.py
"""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("patch-n8n-ai-failsafe.py")
SPEC = importlib.util.spec_from_file_location("patch_aifailsafe", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


JS_HARNESS = r"""
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
const CODE = __CODE__;
function callNode(code, $json, nodes, helpers, env) {
  const $ = (name) => {
    if (!(name in nodes)) throw new Error('node tidak disediakan: ' + name);
    return { first: () => ({ json: nodes[name] }), item: { json: nodes[name] } };
  };
  const $input = { first: () => ({ json: $json }) };
  const fn = new AsyncFunction('$json', '$', '$input', '$env', 'helpers', code);
  return fn.call({ helpers: helpers || {} }, $json, $, $input, env || {}, helpers || {});
}
__RUN__
"""


def run_js(body_js, code=None):
    codes = {"ai": MODULE.AI_JSCODE} if code is None else code
    program = JS_HARNESS.replace("__CODE__", json.dumps(codes)).replace(
        "__RUN__", body_js
    )
    proc = subprocess.run(
        ["node", "-e", program], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise AssertionError("node gagal:\n" + proc.stderr[:2000])
    return json.loads(proc.stdout.strip())


def tg_expression():
    """Ambil ekspresi JS murni dari TG_TEXT (buang pembungkus `={{ ... }}`)."""
    s = MODULE.TG_TEXT
    assert s.startswith("={{") and s.endswith("}}"), "bentuk TG_TEXT tak terduga"
    return s[3:-2]


def run_template(json_obj, build_payload):
    body = r"""
(() => {
  const $ = (name) => {
    if (name !== 'Build Payload') throw new Error('node tak terduga: ' + name);
    return { first: () => ({ json: __BP__ }) };
  };
  const expr = __EXPR__;
  const out = (new Function('$json', '$', 'return (' + expr + ')')(__JSON__, $));
  console.log(JSON.stringify({ out }));
})();
""".replace("__BP__", json.dumps(build_payload)).replace(
        "__EXPR__", json.dumps(tg_expression())
    ).replace("__JSON__", json.dumps(json_obj))
    proc = subprocess.run(
        ["node", "-e", body], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise AssertionError("node gagal:\n" + proc.stderr[:2000])
    return json.loads(proc.stdout.strip())["out"]


BP_FIXTURE = {
    "severityIcon": "🚨",
    "severityLabel": "TINGGI",
    "alert_title": "RANTAI PROSES MENCURIGAKAN",
    "target_label": "Proses",
    "filename": "rundll32.exe",
    "filepath": "C:\\Windows\\SysWOW64\\rundll32.exe",
    "chain_cmd": 'rundll32.exe "E_UPWJ01.dll",EPGetVersionEx',
    "hash_display": "Tidak tersedia",
    "severity": "HIGH",
    "rule_level": 10,
    "detection_text": "Scan dilewati hash tidak ada",
    "agent_name": "bali-handmade",
    "timestamp": "2026-09-30T03:17:59.883+0000",
    "vt_footer": "⚠️ VirusTotal: Hash tidak tersedia untuk discan",
}


class TransformasiTest(unittest.TestCase):
    def make_nodes(self):
        return [
            {"name": MODULE.AI_NAME, "parameters": {"jsCode": "const old = 1;"}},
            {"name": MODULE.TG_NAME, "parameters": {"text": "={{ $json.x }}"}},
        ]

    def test_patch_node_dan_idempoten(self):
        nodes = self.make_nodes()
        self.assertTrue(
            MODULE.patch_node(nodes, MODULE.AI_NAME, MODULE.AI_JSCODE, MODULE.MARKER)
        )
        self.assertIn(MODULE.MARKER, nodes[0]["parameters"]["jsCode"])
        self.assertFalse(
            MODULE.patch_node(nodes, MODULE.AI_NAME, MODULE.AI_JSCODE, MODULE.MARKER)
        )

    def test_patch_telegram_dan_idempoten(self):
        nodes = self.make_nodes()
        self.assertTrue(
            MODULE.patch_telegram(nodes, MODULE.TG_NAME, MODULE.TG_TEXT, MODULE.TG_MARKER)
        )
        self.assertIn(MODULE.TG_MARKER, nodes[1]["parameters"]["text"])
        self.assertFalse(
            MODULE.patch_telegram(nodes, MODULE.TG_NAME, MODULE.TG_TEXT, MODULE.TG_MARKER)
        )

    def test_node_hilang_system_exit(self):
        with self.assertRaises(SystemExit):
            MODULE.patch_node([], MODULE.AI_NAME, MODULE.AI_JSCODE, MODULE.MARKER)
        with self.assertRaises(SystemExit):
            MODULE.patch_telegram([], MODULE.TG_NAME, MODULE.TG_TEXT, MODULE.TG_MARKER)


class AiNodeTest(unittest.TestCase):
    BASE = {
        "prompt": "analisa file ini",
        "filename": "eicar.com",
        "severity": "CRITICAL",
        "agent_name": "rocky-server",
    }

    def test_sukses_spread_field_dan_bersihkan(self):
        out = run_js(
            r"""
(async () => {
  const helpers = { httpRequest: async () => ({ choices: [{ message: { content: 'Bahaya **tinggi** [isolasi]' } }] }) };
  const r = (await callNode(CODE.ai, __BASE__, {}, helpers, { ATRIA_API_KEY: 'k' }))[0].json;
  console.log(JSON.stringify(r));
})();
""".replace("__BASE__", json.dumps(self.BASE))
        )
        self.assertEqual(out["filename"], "eicar.com")
        self.assertEqual(out["severity"], "CRITICAL")
        self.assertEqual(out["ai_response"], "Bahaya tinggi isolasi")
        self.assertIsNone(out["llm_error"])

    def test_gagal_tidak_melempar_dan_field_utuh(self):
        out = run_js(
            r"""
(async () => {
  const helpers = { httpRequest: async () => { throw new Error('ETIMEDOUT 60s'); } };
  const r = (await callNode(CODE.ai, __BASE__, {}, helpers, { ATRIA_API_KEY: 'k' }))[0].json;
  console.log(JSON.stringify(r));
})();
""".replace("__BASE__", json.dumps(self.BASE))
        )
        self.assertEqual(out["filename"], "eicar.com")
        self.assertEqual(out["severity"], "CRITICAL")
        self.assertEqual(out["ai_response"], "Analisis AI tidak tersedia saat ini karena layanan AI gagal atau tidak dikonfigurasi.")
        self.assertIn("ETIMEDOUT", out["llm_error"])

    def test_tanpa_key_fallback_tanpa_http(self):
        out = run_js(
            r"""
(async () => {
  let called = 0;
  const helpers = { httpRequest: async () => { called++; return {}; } };
  const r = (await callNode(CODE.ai, __BASE__, {}, helpers, {}))[0].json;
  console.log(JSON.stringify({ r, called }));
})();
""".replace("__BASE__", json.dumps(self.BASE))
        )
        self.assertEqual(out["called"], 0)
        self.assertIn("ATRIA_API_KEY", out["r"]["llm_error"])
        self.assertEqual(out["r"]["filename"], "eicar.com")


class TemplateTest(unittest.TestCase):
    def test_normal_lengkap(self):
        out = run_template(
            {**BP_FIXTURE, "ai_response": "EPSON lolbin kemungkinan benign"},
            BP_FIXTURE,
        )
        self.assertNotIn("undefined", out)
        self.assertIn("TINGGI", out)
        self.assertIn("RANTAI PROSES MENCURIGAKAN", out)
        self.assertIn("rundll32", out)
        self.assertIn("level 10", out)
        self.assertIn("bali", out)
        self.assertIn("EPSON lolbin kemungkinan benign", out)
        self.assertIn("VirusTotal", out)

    def test_json_rusak_tetap_utuh(self):
        # Simulasi residual: $json bukan output Build Payload (mis. item error).
        out = run_template({}, BP_FIXTURE)
        self.assertNotIn("undefined", out)
        self.assertIn("TINGGI", out)
        self.assertIn("rundll32", out)
        self.assertIn("bali", out)
        self.assertIn("Analisis AI tidak tersedia", out)
        self.assertIn("VirusTotal", out)


if __name__ == "__main__":
    unittest.main()
