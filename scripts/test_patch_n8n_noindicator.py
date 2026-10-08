#!/usr/bin/env python3
"""Test untuk patch-n8n-noindicator.py.

Dua lapis:
  1. Transformasi: pola OLD->NEW kena semua node, idempoten, gagal keras
     (SystemExit) kalau pola live tak cocok.
  2. Perilaku: JS hasil patch dijalankan via `node` dengan stub n8n
     ($json/$()/this.helpers) memakai urutan patch nyata:
         systemfile -> noindicator
     supaya precondition (is_system_file) benar-benar ada.

Jalankan: python3 scripts/test_patch_n8n_noindicator.py
"""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# test_patch_n8n_systemfile menyediakan cuplikan PERSIS kode node LIVE pra-patch
# (EKSTRAK_LIVE/RANGKUM_LIVE/BUILD_LIVE) + harness stub n8n.
SF_TEST = _load("sf_test", "test_patch_n8n_systemfile.py")
MODULE = _load("patch_noindicator", "patch-n8n-noindicator.py")


def make_nodes():
    """Node pasca patch systemfile (precondition patch noindicator)."""
    nodes = SF_TEST.make_nodes()
    SF_TEST.MODULE.apply_patches(nodes)
    return nodes


def js_for(nodes, name):
    return next(n["parameters"]["jsCode"] for n in nodes if n["name"] == name)


# Harness JS: jalankan kode tiap node (async) dengan stub n8n.
JS_HARNESS = r"""
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
const CODE = __CODE__;
function callNode(code, $json, nodes, helpers) {
  const $ = (name) => {
    if (!(name in nodes)) throw new Error('node tidak disediakan: ' + name);
    return { first: () => ({ json: nodes[name] }), item: { json: nodes[name] } };
  };
  const $input = { first: () => ({ json: $json }) };
  const fn = new AsyncFunction('$json', '$', '$input', '$env', 'helpers', code);
  return fn.call({ helpers: helpers || {} }, $json, $, $input, {}, helpers || {});
}
__RUN__
"""


def run_js(body_js, patched_nodes):
    codes = {
        "ekstrak": js_for(patched_nodes, MODULE.EKSTRAK),
        "rangkum": js_for(patched_nodes, MODULE.RANGKUM),
        "build": js_for(patched_nodes, MODULE.BUILD),
    }
    program = JS_HARNESS.replace("__CODE__", json.dumps(codes)).replace("__RUN__", body_js)
    proc = subprocess.run(
        ["node", "-e", program], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise AssertionError("node gagal:\n" + proc.stderr[:2000])
    return json.loads(proc.stdout.strip())


RUN_JS = r"""
(async () => {
  const mbNone = { query_status: 'no_results' };
  const vt404 = { error: { code: 'NotFoundError' }, data: null };
  const vtErr429 = { error: { code: 'QuotaExceeded' }, data: null };

  const ex = async (alert) => (await callNode(CODE.ekstrak, alert, {}, {}))[0].json;

  const rangkum = async (exJson, vtjson) => (await callNode(CODE.rangkum, mbNone, {
    'Ekstrak Alert': exJson,
    'Cek Cache VT': { cache_hit: false, cached_stats: null },
    'Scan VirusTotal': vtjson,
  }, {}))[0].json;

  const build = async (rk, exd) => (await callNode(CODE.build, {},
    { 'Rangkum Hasil': rk, 'Ekstrak Alert': exd }, {}))[0].json;

  const pipeline = async (alert, vtjson) => {
    const e = await ex(alert);
    const r = await rangkum(e, vtjson);
    const b = await build(r, e);
    return { e, r, b };
  };

  const fim = (path, level, ruleId, perm) => ({ body: {
    rule: { id: ruleId || '554', level: level, description: 'FIM' },
    syscheck: Object.assign({ path: path, sha256_after: 'a'.repeat(64), event: 'added' },
                            perm ? { perm_after: perm } : {}),
    agent: { id: '009', name: 'nixbox' }, timestamp: '2026-10-06T16:35:13Z'
  }});

  const dl = '/home/ravi/Downloads/Telegram Desktop/';

  const cases = {};
  cases.mp4_unknown   = await pipeline(fim(dl + 'VID-20260120-WA0029.mp4', 5), vt404);
  cases.mp4_modified  = await pipeline(fim(dl + 'VID-20260120-WA0029.mp4', 7, '550'), vt404);
  cases.exe_unknown   = await pipeline(fim(dl + 'setup-baru.exe', 5), vt404);
  cases.sh_exec_unknown = await pipeline(fim(dl + 'install.sh', 5, '554', 'rwxr-xr-x'), vt404);
  cases.exe_known_clean = await pipeline(fim(dl + 'tool-bersih.exe', 5), {
    data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 70 } } }
  });
  cases.bak_unknown   = await pipeline(fim(dl + 'catatan.bak', 5), vt404);
  cases.eicar         = await pipeline(fim(dl + 'eicar.com', 5), {
    data: { attributes: { last_analysis_stats: { malicious: 65, suspicious: 0, undetected: 2 } } }
  });
  cases.mp4_weak      = await pipeline(fim(dl + 'klip.mp4', 5), {
    data: { attributes: { last_analysis_stats: { malicious: 3, suspicious: 0, undetected: 60 } } }
  });
  cases.hosts         = await pipeline(fim('c:\\windows\\system32\\drivers\\etc\\hosts', 7, '550'), vt404);
  cases.mp4_vt_error  = await pipeline(fim(dl + 'film.mp4', 5), vtErr429);

  const pick = (c) => ({ r: c.r, b: c.b });
  console.log(JSON.stringify({
    mp4_unknown: pick(cases.mp4_unknown),
    mp4_modified: pick(cases.mp4_modified),
    exe_unknown: pick(cases.exe_unknown),
    exe_known_clean: pick(cases.exe_known_clean),
    sh_exec_unknown: pick(cases.sh_exec_unknown),
    txt_unknown: pick(cases.bak_unknown),
    eicar: pick(cases.eicar),
    mp4_weak: pick(cases.mp4_weak),
    hosts: pick(cases.hosts),
    mp4_vt_error: pick(cases.mp4_vt_error),
  }));
})().catch((e) => { console.error('ERR', (e && e.stack) || e); process.exit(1); });
"""


class TransformTests(unittest.TestCase):
    def test_applies_all_nodes(self):
        nodes = make_nodes()
        changed = MODULE.apply_patches(nodes)
        self.assertEqual(set(changed), {MODULE.EKSTRAK, MODULE.RANGKUM, MODULE.BUILD})
        for name in changed:
            self.assertIn(MODULE.MARKER, js_for(nodes, name))

    def test_idempotent(self):
        nodes = make_nodes()
        MODULE.apply_patches(nodes)
        self.assertEqual(MODULE.apply_patches(nodes), [])

    def test_fails_loud_on_unexpected_pattern(self):
        nodes = make_nodes()
        for n in nodes:
            if n["name"] == MODULE.RANGKUM:
                n["parameters"]["jsCode"] = "const x = 1;"
        with self.assertRaises(SystemExit):
            MODULE.apply_patches(nodes)

    def test_wiring_inserts_gate(self):
        nodes = make_nodes() + [
            {"name": "AI Generate", "type": "n8n-nodes-base.code", "parameters": {}},
            {"name": "Log ke Fleet", "type": "n8n-nodes-base.code", "parameters": {}},
        ]
        conns = {
            MODULE.BUILD: {
                "main": [[
                    {"node": "AI Generate", "type": "main", "index": 0},
                    {"node": "Log ke Fleet", "type": "main", "index": 0},
                ]]
            }
        }
        self.assertTrue(MODULE.apply_wiring(nodes, conns))
        self.assertIsNotNone(MODULE.get_node(nodes, MODULE.NOTIFY_IF))
        build_targets = [t["node"] for t in conns[MODULE.BUILD]["main"][0]]
        self.assertIn(MODULE.NOTIFY_IF, build_targets)
        # Log ke Fleet TIDAK digate (tetap langsung dari Build Payload).
        self.assertIn("Log ke Fleet", build_targets)
        if_targets = [t["node"] for t in conns[MODULE.NOTIFY_IF]["main"][0]]
        self.assertEqual(if_targets, ["AI Generate"])
        # idempoten
        self.assertFalse(MODULE.apply_wiring(nodes, conns))


class BehaviourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nodes = make_nodes()
        MODULE.apply_patches(nodes)
        cls.out = run_js(RUN_JS, nodes)

    def test_mp4_tanpa_indikator_diamkan(self):
        c = self.out["mp4_unknown"]
        self.assertEqual(c["r"]["severity"], "INFO")
        self.assertEqual(c["r"]["decision"], "no-indicator")
        self.assertTrue(c["r"]["is_benign_ext"])
        self.assertFalse(c["r"]["notify"])
        self.assertFalse(c["r"]["should_active_response"])
        self.assertEqual(c["b"]["alert_title"], "TANPA INDIKASI MALWARE")
        self.assertFalse(c["b"]["notify"])

    def test_mp4_modified_rule7_tetap_info(self):
        c = self.out["mp4_modified"]
        self.assertEqual(c["r"]["severity"], "INFO")
        self.assertFalse(c["r"]["notify"])

    def test_exe_unknown_perlu_review(self):
        c = self.out["exe_unknown"]
        self.assertEqual(c["r"]["severity"], "MEDIUM")
        self.assertEqual(c["r"]["decision"], "unknown-executable")
        self.assertTrue(c["r"]["unknown_exec_review"])
        self.assertTrue(c["r"]["notify"])
        self.assertFalse(c["r"]["should_active_response"])
        self.assertEqual(c["b"]["alert_title"], "FILE PERLU REVIEW")

    def test_exe_vt_kenal_bersih_jadi_info(self):
        c = self.out["exe_known_clean"]
        self.assertEqual(c["r"]["severity"], "INFO")
        self.assertFalse(c["r"]["unknown_exec_review"])
        self.assertTrue(c["r"]["notify"])

    def test_sh_exec_bit_unknown_perlu_review(self):
        c = self.out["sh_exec_unknown"]
        self.assertTrue(c["r"]["is_exec"])
        self.assertEqual(c["r"]["decision"], "unknown-executable")

    def test_non_media_unknown_info_tapi_diberitakan(self):
        c = self.out["txt_unknown"]
        self.assertEqual(c["r"]["severity"], "INFO")
        self.assertFalse(c["r"]["is_benign_ext"])
        self.assertTrue(c["r"]["notify"])
        self.assertEqual(c["b"]["alert_title"], "TANPA INDIKASI MALWARE")

    def test_eicar_tetap_critical_dengan_ar(self):
        c = self.out["eicar"]
        self.assertEqual(c["r"]["severity"], "CRITICAL")
        self.assertTrue(c["r"]["should_active_response"])
        self.assertTrue(c["r"]["notify"])
        self.assertEqual(c["b"]["alert_title"], "MALWARE TERDETEKSI")

    def test_weak_indicator_tetap_medium_dengan_label_malware(self):
        c = self.out["mp4_weak"]
        self.assertEqual(c["r"]["severity"], "MEDIUM")
        self.assertEqual(c["r"]["decision"], "weak-indicator")
        self.assertTrue(c["r"]["notify"])
        self.assertEqual(c["b"]["alert_title"], "MALWARE TERDETEKSI")

    def test_hosts_system_file_tak_berubah(self):
        c = self.out["hosts"]
        self.assertTrue(c["r"]["is_system_file"])
        self.assertEqual(c["r"]["severity"], "MEDIUM")
        self.assertFalse(c["r"]["silent"])  # tetap diberitakan
        self.assertTrue(c["r"]["notify"])
        self.assertEqual(c["b"]["alert_title"], "PERUBAHAN FILE KONFIGURASI SISTEM")

    def test_vt_error_bukan_disenyapkan(self):
        c = self.out["mp4_vt_error"]
        self.assertEqual(c["r"]["severity"], "MEDIUM")
        self.assertEqual(c["r"]["decision"], "unverified")
        self.assertTrue(c["r"]["notify"])


if __name__ == "__main__":
    unittest.main()
