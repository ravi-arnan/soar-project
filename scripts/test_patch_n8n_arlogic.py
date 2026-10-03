#!/usr/bin/env python3
"""Test untuk patch-n8n-arlogic.py.

Dua lapis:
  1. Transformasi: node diganti, idempoten (marker), node hilang -> SystemExit.
  2. Perilaku: JS hasil patch dieksekusi via `node` dengan stub n8n ->
     Trigger AR mengirim `!quarantine-file`, status 'isolated' terdeteksi untuk
     respons sukses Wazuh (kedua bentuk), 'failed' untuk error, dan Fleet
     Quarantine hanya memanggil HTTP saat AR gagal (bukan saat 'isolated').

Jalankan: python3 scripts/test_patch_n8n_arlogic.py
"""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("patch-n8n-arlogic.py")
SPEC = importlib.util.spec_from_file_location("patch_arlogic", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def js_ar():
    return MODULE.AR_JSCODE


def js_fq():
    return MODULE.FQ_JSCODE


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


def run_js(body_js, node_jsons):
    codes = {"ar": js_ar(), "fq": js_fq()}
    program = JS_HARNESS.replace("__CODE__", json.dumps(codes)).replace(
        "__RUN__", body_js
    )
    proc = subprocess.run(
        ["node", "-e", program], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise AssertionError("node gagal:\n" + proc.stderr[:2000])
    return json.loads(proc.stdout.strip())


class TransformasiTest(unittest.TestCase):
    def make_nodes(self):
        return [
            {"name": MODULE.AR_NAME, "parameters": {"jsCode": "const old = 1;"}},
            {"name": MODULE.FQ_NAME, "parameters": {"jsCode": "const old = 2;"}},
        ]

    def test_replace_dan_idempoten(self):
        nodes = self.make_nodes()
        self.assertTrue(
            MODULE.patch_node(nodes, MODULE.AR_NAME, MODULE.AR_JSCODE, MODULE.MARKER)
        )
        self.assertTrue(
            MODULE.patch_node(nodes, MODULE.FQ_NAME, MODULE.FQ_JSCODE, MODULE.MARKER)
        )
        self.assertIn(MODULE.MARKER, nodes[0]["parameters"]["jsCode"])
        self.assertIn(MODULE.MARKER, nodes[1]["parameters"]["jsCode"])
        self.assertFalse(
            MODULE.patch_node(nodes, MODULE.AR_NAME, MODULE.AR_JSCODE, MODULE.MARKER)
        )
        self.assertFalse(
            MODULE.patch_node(nodes, MODULE.FQ_NAME, MODULE.FQ_JSCODE, MODULE.MARKER)
        )

    def test_node_hilang_system_exit(self):
        with self.assertRaises(SystemExit):
            MODULE.patch_node([], MODULE.AR_NAME, MODULE.AR_JSCODE, MODULE.MARKER)


class PerilakuTest(unittest.TestCase):
    def test_ar_kirim_quarantine_file_dan_status_isolated(self):
        out = run_js(
            r"""
(async () => {
  const calls = [];
  const helpers = { httpRequest: async (opts) => {
    calls.push({url: opts.url, body: JSON.parse(opts.body)});
    return { error: 0 };
  }};
  const res = (await callNode(CODE.ar, {}, {
    'Get Wazuh Token': { data: { token: 't' } },
    'Ekstrak Alert': { agent_id: '010', filepath: '/tmp/eicar.com' },
  }, helpers, {}))[0].json;
  console.log(JSON.stringify({calls, status: res.status}));
})();
""",
            {},
        )
        self.assertEqual(out["status"], "isolated")
        self.assertEqual(out["calls"][0]["body"]["command"], "!quarantine-file")
        self.assertEqual(out["calls"][0]["body"]["arguments"], ["/tmp/eicar.com"])

    def test_ar_status_isolated_bentuk_sukses_baru(self):
        out = run_js(
            r"""
(async () => {
  const helpers = { httpRequest: async () => ({
    total_affected_items: 1, total_failed_items: 0, failed_items: [], affected_items: [{}] })};
  const res = (await callNode(CODE.ar, {}, {
    'Get Wazuh Token': { data: { token: 't' } },
    'Ekstrak Alert': { agent_id: '010', filepath: '/tmp/x' },
  }, helpers, {}))[0].json;
  console.log(JSON.stringify({status: res.status}));
})();
""",
            {},
        )
        self.assertEqual(out["status"], "isolated")

    def test_ar_status_failed_saat_error(self):
        out = run_js(
            r"""
(async () => {
  const helpers = { httpRequest: async () => { throw new Error('1701 Agent does not exist'); } };
  const res = (await callNode(CODE.ar, {}, {
    'Get Wazuh Token': { data: { token: 't' } },
    'Ekstrak Alert': { agent_id: '002', filepath: '/tmp/x' },
  }, helpers, {}))[0].json;
  console.log(JSON.stringify({status: res.status}));
})();
""",
            {},
        )
        self.assertEqual(out["status"], "failed")

    def test_fq_skip_saat_isolated_dan_systemfile(self):
        out = run_js(
            r"""
(async () => {
  let called = 0;
  const helpers = { httpRequest: async () => { called++; return {}; } };
  const base = { 'Trigger Active Response': { status: 'isolated' }, 'Ekstrak Alert': { agent_id: '001', filepath: '/a', is_system_file: false } };
  const r1 = (await callNode(CODE.fq, {}, base, helpers, {}))[0].json;
  const r2 = (await callNode(CODE.fq, {}, { 'Trigger Active Response': { status: 'failed' }, 'Ekstrak Alert': { agent_id: '001', filepath: '/etc/hosts', is_system_file: true } }, helpers, {}))[0].json;
  console.log(JSON.stringify({r1: r1.fleet_quarantine, r2: r2.fleet_quarantine, called}));
})();
""",
            {},
        )
        self.assertEqual(out["called"], 0)
        self.assertEqual(out["r1"]["result"], "skipped-wazuh-ok")
        self.assertEqual(out["r2"]["result"], "skipped-system-file")

    def test_fq_queue_saat_ar_failed_dan_bukan_systemfile(self):
        out = run_js(
            r"""
(async () => {
  let called = 0;
  const helpers = { httpRequest: async () => { called++; return {ok: true}; } };
  const r = (await callNode(CODE.fq, {}, { 'Trigger Active Response': { status: 'failed' }, 'Ekstrak Alert': { agent_id: '002', filepath: '/home/u/eicar', is_system_file: false } }, helpers, {}))[0].json;
  console.log(JSON.stringify({called, result: r.fleet_quarantine.result}));
})();
""",
            {},
        )
        self.assertEqual(out["called"], 1)
        self.assertEqual(out["result"], "queued")


if __name__ == "__main__":
    unittest.main()
