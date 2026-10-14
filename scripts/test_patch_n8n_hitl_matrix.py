#!/usr/bin/env python3
"""Test untuk patch-n8n-hitl-matrix.py (milestone M3).

Tiga lapis:
  1. Struktur: node baru dibuat, koneksi diarahkan ulang (kebijakan lewat
     `Tentukan Otonomi`), tombol HITL terpasang, jalur callback jadi linear,
     workflow SLA terbentuk.
  2. Idempoten: patch kedua tidak mengubah apa pun.
  3. Perilaku: JS hasil patch dieksekusi via `node` dengan stub n8n
     ($json/$()/this.helpers) -> matriks confidence->otonomi, pendaftaran
     keputusan, parsing aksi tombol, dan pemilihan Active Response.

Jalankan: python3 scripts/test_patch_n8n_hitl_matrix.py
"""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("patch-n8n-hitl-matrix.py")
SPEC = importlib.util.spec_from_file_location("patch_hitl", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


# --- fixture: bentuk node/koneksi live yang relevan (pra-patch 2026-10-14) ---
def _node(name, typ, pos, params=None, **extra):
    n = {"name": name, "type": typ, "typeVersion": 2, "position": list(pos),
         "parameters": params or {}}
    n.update(extra)
    return n


def _main(*names):
    return [[{"node": n, "type": "main", "index": 0} for n in names]]


def malware_wf():
    return {
        "name": "Deteksi Malware",
        "id": "wf-malware",
        "active": True,
        "settings": {"executionOrder": "v1"},
        "nodes": [
            _node("Rangkum Hasil", "n8n-nodes-base.code", [1000, 100],
                  {"mode": "runOnceForAllItems", "jsCode": "return [];"}),
            _node("Rangkum Chain", "n8n-nodes-base.code", [1000, 300],
                  {"mode": "runOnceForAllItems", "jsCode": "return [];"}),
            _node("Cek Ancaman", "n8n-nodes-base.if", [1300, 100], {}),
            _node("Log ke Fleet", "n8n-nodes-base.httpRequest", [1300, 300], {}),
            _node("Build Payload", "n8n-nodes-base.code", [1600, 100], {}),
            _node("Perlu Notifikasi?", "n8n-nodes-base.if", [1900, 100], {}),
            _node("AI Generate", "n8n-nodes-base.code", [2200, 100], {}),
            _node("Send Telegram Alert", "n8n-nodes-base.telegram", [2500, 100],
                  {"resource": "message", "operation": "sendMessage",
                   "chatId": "1295213498", "text": "={{ $json.x }}"}),
            _node("Log Telegram Alert", "n8n-nodes-base.code", [2700, 100],
                  {"mode": "runOnceForAllItems", "jsCode": MODULE.TGLOG_OLD_LIVE}),
        ],
        "connections": {
            "Rangkum Hasil": {"main": _main("Cek Ancaman", "Log ke Fleet")},
            "Rangkum Chain": {"main": _main("Build Payload", "Log ke Fleet")},
            "Cek Ancaman": {"main": _main("Get Wazuh Token") + _main("Build Payload")},
            "Perlu Notifikasi?": {"main": _main("AI Generate") + [[]]},
            "AI Generate": {"main": _main("Send Telegram Alert")},
        },
    }


def callback_wf():
    return {
        "name": "Telegram Callback Handler",
        "id": "wf-callback",
        "active": True,
        "settings": {"executionOrder": "v1"},
        "nodes": [
            _node("Webhook", "n8n-nodes-base.webhook", [0, 0], {}),
            _node("Parse Keputusan", "n8n-nodes-base.code", [200, 0],
                  {"mode": "runOnceForAllItems", "jsCode": "return [];"}),
            _node("Answer Callback", "n8n-nodes-base.telegram", [450, 0], {}),
            _node("Perlu Tindakan?", "n8n-nodes-base.if", [650, 0], {}),
            _node("Get Wazuh Token", "n8n-nodes-base.httpRequest", [850, 0], {}),
            _node("Jalankan AR", "n8n-nodes-base.code", [1050, 0],
                  {"mode": "runOnceForAllItems", "jsCode": "return [];"}),
            _node("Edit Pesan Isolasi", "n8n-nodes-base.telegram", [1250, -100], {}),
            _node("Edit Pesan Abaikan", "n8n-nodes-base.telegram", [1250, 100], {}),
        ],
        "connections": {
            "Webhook": {"main": _main("Parse Keputusan")},
            "Parse Keputusan": {"main": _main("Answer Callback")},
            "Answer Callback": {"main": _main("Perlu Tindakan?")},
            "Perlu Tindakan?": {"main": _main("Get Wazuh Token") + _main("Edit Pesan Abaikan")},
            "Get Wazuh Token": {"main": _main("Jalankan AR")},
            "Jalankan AR": {"main": _main("Edit Pesan Isolasi")},
        },
    }


def js_for(wf, name):
    return next(n["parameters"]["jsCode"] for n in wf["nodes"] if n["name"] == name)


# JS 'Log Telegram Alert' live pra-patch (dipakai fixture + uji gagal-keras)
MODULE.TGLOG_OLD_LIVE = (
    "const inp = $input.first().json;\n"
    "const rec = { ts: new Date().toISOString() };\n"
    "try {\n  const r = inp.result || inp;\n  rec.message_id = r.message_id || null;\n} catch (e) {}\n"
    + MODULE.TGLOG_OLD
)


def node_named(wf, name):
    return next((n for n in wf["nodes"] if n["name"] == name), None)


# --- harness JS: jalankan kode node (async) dengan stub n8n ---
JS_HARNESS = r"""
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
const CODE = __CODE__;
function callNode(code, $json, nodes, helpers) {
  const $ = (name) => {
    if (!(name in nodes)) throw new Error('node tidak disediakan: ' + name);
    return { first: () => ({ json: nodes[name] }) };
  };
  const $input = { first: () => ({ json: $json }) };
  const fn = new AsyncFunction('$json', '$', '$input', '$env', 'helpers', code);
  return fn.call({ helpers: helpers || {} }, $json, $, $input, {}, helpers || {});
}
__RUN__
"""


def run_js(body_js, mwf, cwf):
    codes = {
        "policy": js_for(mwf, "Tentukan Otonomi"),
        "register": js_for(mwf, "Catat Keputusan Tertunda"),
        "parse": js_for(cwf, "Parse Keputusan"),
        "claim": js_for(cwf, "Catat Keputusan"),
        "ar": js_for(cwf, "Jalankan AR"),
        "sla": MODULE.SLA_BUILD_JS,
    }
    program = JS_HARNESS.replace("__CODE__", json.dumps(codes)).replace("__RUN__", body_js)
    proc = subprocess.run(["node", "-e", program], capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise AssertionError("node gagal:\n" + proc.stderr[:2000])
    return json.loads(proc.stdout.strip())


RUN_JS = r"""
(async () => {
  const policy = async (json) => (await callNode(CODE.policy, json, {}, {}))[0].json;

  const fileBase = {
    filename: 'setup-installer.exe', filepath: '/home/ravi/Downloads/setup-installer.exe',
    hash: 'a'.repeat(64), agent_id: '010', agent_name: 'ravi-debian',
    severity: 'CRITICAL', rule_id: '554', malicious: 30, total: 70,
  };
  const critical = await policy(fileBase);
  const high = await policy({ ...fileBase, severity: 'HIGH', malicious: 6 });
  const medWeak = await policy({ ...fileBase, severity: 'MEDIUM', malicious: 2, has_indicator: true });
  const medUnknown = await policy({ ...fileBase, severity: 'MEDIUM', malicious: 0,
    unknown_exec_review: true, total: 0 });
  const info = await policy({ ...fileBase, severity: 'INFO', total: 0, filename: 'foto.jpg' });
  const sysfile = await policy({ ...fileBase, severity: 'MEDIUM', is_system_file: true,
    filename: 'hosts', filepath: 'C:\\Windows\\System32\\drivers\\etc\\hosts' });
  const chain = await policy({ severity: 'HIGH', chain: { image: 'C:\\Windows\\System32\\cmd.exe',
    commandLine: 'cmd /c powershell -w hidden' }, agent_id: '005', rule_id: '110012',
    filename: 'cmd.exe', filepath: '', hash: null });

  // pendaftaran keputusan: stub helpers.httpRequest menangkap body
  const seen = [];
  const helpers = { httpRequest: async (opts) => { seen.push({ url: opts.url, body: opts.body }); return { ok: true }; } };
  const reg = (await callNode(CODE.register, { alert_title: 'FILE PERLU REVIEW' },
    { 'Tentukan Otonomi': medUnknown }, helpers))[0].json;
  const regNoPath = (await callNode(CODE.register, { alert_title: 'X' },
    { 'Tentukan Otonomi': { ...medUnknown, filepath: '' } }, helpers))[0].json;

  // parse tombol baru + legacy
  const parse = async (data, text) => (await callNode(CODE.parse, { body: { callback_query: {
      data: data, id: 'cb1', from: { first_name: 'Ravi' },
      message: { text: text || '', chat: { id: 1 }, message_id: 9 } } } }, {}, {}))[0].json;
  const pQ = await parse('q:010:' + 'a'.repeat(16));
  const pA = await parse('a:005:chain:110012:0');
  const pF = await parse('f:010:' + 'a'.repeat(16));
  const pLegacy = await parse('iso:003', 'Isolasi File\nPath: /home/ravi/Downloads/eicar\\.com\nHash: `' + 'b'.repeat(64) + '`');
  const pPhish = await parse('pblk:007', 'URL: `http://jahat.example/login`');

  // klaim keputusan (registry mengembalikan path + agent)
  const claimed = [];
  const helpersClaim = { httpRequest: async (opts) => {
    claimed.push({ url: opts.url, body: opts.body });
    return opts.url.includes('/decision/resolve')
      ? { ok: true, found: true, filepath: '/home/ravi/Downloads/setup-installer.exe',
          agent_id: '010', hash: 'a'.repeat(64), severity: 'MEDIUM' }
      : { ok: true };
  } };
  const cl = (await callNode(CODE.claim, {}, { 'Parse Keputusan': pQ }, helpersClaim))[0].json;

  // Active Response: karantina pakai path registry / tanpa AR untuk f: / blokir domain
  const arCalls = [];
  const helpersAR = { httpRequest: async (opts) => { arCalls.push(opts); return { error: 0 }; } };
  const arQ = (await callNode(CODE.ar, {}, {
    'Catat Keputusan': cl, 'Get Wazuh Token': { data: { token: 'tok' } } }, helpersAR))[0].json;
  const arF = (await callNode(CODE.ar, {}, {
    'Catat Keputusan': { ...cl, decision_action: 'false_positive', action: 'f' },
    'Get Wazuh Token': { data: { token: 'tok' } } }, helpersAR))[0].json;
  const arPblk = (await callNode(CODE.ar, {}, {
    'Catat Keputusan': { ...cl, action: 'pblk', isPhishing: true, url: 'http://jahat.example/login' },
    'Get Wazuh Token': { data: { token: 'tok' } } }, helpersAR))[0].json;

  // sweeper SLA: kosong -> [], ada item -> eskalasi + tandai di registry
  const slaEmpty = await callNode(CODE.sla, { items: [] }, {}, helpersAR);
  const slaCalls = [];
  const helpersSLA = { httpRequest: async (opts) => { slaCalls.push(opts); return { ok: true }; } };
  const slaFull = (await callNode(CODE.sla, { items: [
    { did: 'a'.repeat(16), severity: 'MEDIUM', title: 'FILE PERLU REVIEW',
      filename: 'setup-installer.exe', agent_id: '010', age_secs: 1200, hitl: true },
    { did: 'c'.repeat(16), severity: 'HIGH', title: 'RANTAI PROSES MENCURIGAKAN',
      filepath: 'C:\\Windows\\System32\\cmd.exe', agent_id: '005', age_secs: 1000, hitl: true },
  ] }, {}, helpersSLA))[0].json;

  console.log(JSON.stringify({ critical, high, medWeak, medUnknown, info, sysfile, chain,
    reg, regNoPath, seen, pQ, pA, pF, pLegacy, pPhish, cl, claimed,
    arQ, arF, arPblk, arCalls, slaEmpty, slaFull, slaCalls }));
})().catch((e) => { console.error('ERR', (e && e.stack) || e); process.exit(1); });
"""


class StructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mwf = malware_wf()
        cls.cwf = callback_wf()
        cls.malware_changes, cls.malware_payload = MODULE.patch_malware(cls.mwf, False)
        cls.callback_changes, cls.callback_payload = MODULE.patch_callback(cls.cwf, False)

    def test_policy_node_added_with_marker(self):
        js = js_for(self.mwf, "Tentukan Otonomi")
        self.assertIn(MODULE.MARKER, js)
        self.assertIn("hitl-review", js)
        self.assertIn("should_active_response: autonomy === 'auto'", js)

    def test_registry_node_added(self):
        self.assertIn(MODULE.MARKER, js_for(self.mwf, "Catat Keputusan Tertunda"))
        self.assertIn("/decision/pending", js_for(self.mwf, "Catat Keputusan Tertunda"))

    def test_policy_is_single_source_for_connections(self):
        conns = self.mwf["connections"]
        self.assertEqual(conns["Rangkum Hasil"]["main"],
                         [[{"node": "Tentukan Otonomi", "type": "main", "index": 0}]])
        self.assertEqual(conns["Rangkum Chain"]["main"],
                         [[{"node": "Tentukan Otonomi", "type": "main", "index": 0}]])
        targets = [c["node"] for c in conns["Tentukan Otonomi"]["main"][0]]
        self.assertEqual(targets, ["Cek Ancaman", "Log ke Fleet"])

    def test_telegram_log_gets_audit_fields_from_policy(self):
        js = js_for(self.mwf, "Log Telegram Alert")
        self.assertIn(MODULE.MARKER, js)
        self.assertIn("$('Tentukan Otonomi').first().json", js)
        self.assertIn("rec.hash = src.hash", js)
        self.assertIn("rec.tier = src.policy_tier", js)
        self.assertNotIn("for (const nm of", js)

    def test_fails_loud_if_telegram_log_pattern_changes(self):
        mwf = malware_wf()
        node_named(mwf, "Log Telegram Alert")["parameters"]["jsCode"] = "const x = 1;"
        with self.assertRaises(SystemExit):
            MODULE.patch_malware(mwf, False)

    def test_registry_gate_before_ai(self):
        conns = self.mwf["connections"]
        self.assertEqual(conns["Perlu Notifikasi?"]["main"][0][0]["node"], "Catat Keputusan Tertunda")
        self.assertEqual(conns["Perlu Notifikasi?"]["main"][1], [])
        self.assertEqual(conns["Catat Keputusan Tertunda"]["main"][0][0]["node"], "AI Generate")

    def test_buttons_are_dynamic_per_autonomy(self):
        btn = node_named(self.mwf, "Send Telegram Alert")["parameters"]
        self.assertEqual(btn["replyMarkup"], "inlineKeyboard")
        rows = btn["inlineKeyboard"]["rows"][0]["row"]["buttons"]
        self.assertIn("action_kind === 'quarantine'", rows[0]["text"])
        self.assertIn("'q:'", rows[0]["additionalFields"]["callback_data"])
        self.assertIn("'a:'", rows[0]["additionalFields"]["callback_data"])
        self.assertIn("'f:'", rows[1]["additionalFields"]["callback_data"])
        self.assertLess(len("q:010:0123456789abcdef"), 64)

    def test_callback_path_linear_without_false_branch(self):
        conns = self.cwf["connections"]
        self.assertEqual(conns["Parse Keputusan"]["main"][0][0]["node"], "Catat Keputusan")
        self.assertEqual(conns["Catat Keputusan"]["main"][0][0]["node"], "Answer Callback")
        self.assertEqual(conns["Answer Callback"]["main"][0][0]["node"], "Get Wazuh Token")
        self.assertEqual(conns["Get Wazuh Token"]["main"][0][0]["node"], "Jalankan AR")
        self.assertEqual(conns["Jalankan AR"]["main"][0][0]["node"], "Edit Pesan Hasil")
        for dead in ("Perlu Tindakan?", "Edit Pesan Isolasi", "Edit Pesan Abaikan"):
            self.assertIsNone(node_named(self.cwf, dead))
        self.assertIsNotNone(node_named(self.cwf, "Edit Pesan Hasil"))

    def test_callback_tolerates_stale_callbacks(self):
        self.assertEqual(node_named(self.cwf, "Answer Callback")["onError"], "continueRegularOutput")
        self.assertEqual(node_named(self.cwf, "Edit Pesan Hasil")["onError"], "continueRegularOutput")

    def test_claim_and_ar_use_registry(self):
        self.assertIn("/decision/resolve", js_for(self.cwf, "Catat Keputusan"))
        self.assertIn("(reg && reg.filepath) || p.filePath", js_for(self.cwf, "Catat Keputusan"))
        self.assertIn("/webhook-log", js_for(self.cwf, "Catat Keputusan"))
        self.assertIn("'tanpa-ar'", js_for(self.cwf, "Jalankan AR"))

    def test_idempotent_second_pass(self):
        changes_m, payload_m = MODULE.patch_malware(malware_wf(), False)
        self.assertTrue(changes_m)
        self.assertIsNotNone(payload_m)
        # jalankan kedua kali di workflow yang sudah dipatch
        again_m = MODULE.patch_malware(self.mwf, False)
        self.assertEqual(again_m, ([], None))
        again_c = MODULE.patch_callback(self.cwf, False)
        self.assertEqual(again_c, ([], None))

    def test_new_telegram_node_inherits_credentials(self):
        # n8n menolak publish node Telegram tanpa credential telegramApi
        cwf = callback_wf()
        for n in cwf["nodes"]:
            if n["type"] == "n8n-nodes-base.telegram":
                n["credentials"] = {"telegramApi": {"id": "cred-1", "name": "Telegram account"}}
        MODULE.patch_callback(cwf, False)
        edit = node_named(cwf, "Edit Pesan Hasil")
        self.assertEqual(edit["credentials"]["telegramApi"]["id"], "cred-1")
        sla = MODULE.build_sla_workflow("1", {"telegramApi": {"id": "cred-1"}})
        self.assertEqual(sla["nodes"][3]["credentials"]["telegramApi"]["id"], "cred-1")

    def test_sla_workflow_shape(self):
        wf = MODULE.build_sla_workflow("1295213498")
        names = [n["name"] for n in wf["nodes"]]
        self.assertEqual(names, [MODULE.SLA_TRIGGER, MODULE.SLA_FETCH, MODULE.SLA_BUILD,
                                 MODULE.SLA_SEND, MODULE.SLA_LOG])
        self.assertIn("overdue=1", wf["nodes"][1]["parameters"]["url"])
        self.assertIn(MODULE.MARKER, js_for(wf, MODULE.SLA_BUILD))
        self.assertEqual(wf["connections"][MODULE.SLA_TRIGGER]["main"][0][0]["node"], MODULE.SLA_FETCH)
        self.assertEqual(wf["nodes"][0]["parameters"]["rule"]["interval"][0]["minutesInterval"], 1)
        self.assertEqual(wf["name"], MODULE.SLA_NAME)


class BehaviourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        mwf, cwf = malware_wf(), callback_wf()
        MODULE.patch_malware(mwf, False)
        MODULE.patch_callback(cwf, False)
        cls.out = run_js(RUN_JS, mwf, cwf)

    def test_critical_is_autonomous(self):
        r = self.out["critical"]
        self.assertEqual(r["policy_tier"], "auto-critical")
        self.assertEqual(r["confidence"], "high")
        self.assertEqual(r["autonomy"], "auto")
        self.assertFalse(r["needs_decision"])
        self.assertTrue(r["should_active_response"])
        self.assertEqual(r["action_kind"], "fp_only")
        self.assertEqual(len(r["did"]), 16)

    def test_high_is_autonomous(self):
        self.assertEqual(self.out["high"]["policy_tier"], "auto-high")
        self.assertTrue(self.out["high"]["should_active_response"])

    def test_medium_weak_indicator_is_hitl(self):
        r = self.out["medWeak"]
        self.assertEqual(r["policy_tier"], "hitl-review")
        self.assertEqual(r["autonomy"], "hitl")
        self.assertTrue(r["needs_decision"])
        self.assertFalse(r["should_active_response"])
        self.assertEqual(r["action_kind"], "quarantine")
        self.assertEqual(r["hitl_deadline_secs"], 900)

    def test_unknown_executable_is_hitl(self):
        r = self.out["medUnknown"]
        self.assertEqual(r["policy_tier"], "hitl-review")
        self.assertTrue(r["needs_decision"])
        self.assertFalse(r["should_active_response"])

    def test_info_is_observe_only(self):
        r = self.out["info"]
        self.assertEqual(r["policy_tier"], "observe")
        self.assertEqual(r["autonomy"], "observe")
        self.assertFalse(r["needs_decision"])
        self.assertFalse(r["should_active_response"])

    def test_system_file_never_auto(self):
        r = self.out["sysfile"]
        self.assertEqual(r["policy_tier"], "manual-config")
        self.assertEqual(r["autonomy"], "notify-hold")
        self.assertFalse(r["should_active_response"])

    def test_chain_is_hitl_with_synthetic_key(self):
        r = self.out["chain"]
        self.assertEqual(r["policy_tier"], "hitl-chain")
        self.assertEqual(r["action_kind"], "acknowledge")
        self.assertTrue(r["needs_decision"])
        self.assertFalse(r["should_active_response"])
        self.assertEqual(r["decision_key"], "chain:110012:005")
        self.assertEqual(r["filepath"], "C:\\Windows\\System32\\cmd.exe")

    def test_registry_registration_payload(self):
        body = self.out["seen"][0]["body"]
        self.assertIn("/decision/pending", self.out["seen"][0]["url"])
        self.assertTrue(body["hitl"])
        self.assertEqual(body["deadline_secs"], 900)
        self.assertEqual(body["tier"], "hitl-review")
        self.assertEqual(body["filepath"], "/home/ravi/Downloads/setup-installer.exe")
        self.assertEqual(body["title"], "FILE PERLU REVIEW")
        self.assertEqual(body["agent_id"], "010")
        self.assertEqual(self.out["reg"]["decision_registry"]["attempted"], True)
        self.assertEqual(self.out["regNoPath"]["decision_registry"]["attempted"], False)
        self.assertEqual(len(self.out["seen"]), 1)  # tanpa path -> tidak memanggil HTTP

    def test_parse_new_actions(self):
        self.assertEqual(self.out["pQ"]["registryAction"], "quarantine")
        self.assertTrue(self.out["pQ"]["doBlock"])
        self.assertEqual(self.out["pQ"]["did"], "a" * 16)
        self.assertEqual(self.out["pQ"]["agentId"], "010")
        self.assertEqual(self.out["pF"]["registryAction"], "false_positive")
        self.assertFalse(self.out["pF"]["doBlock"])
        self.assertEqual(self.out["pF"]["logStatus"], "analyst-fp")
        self.assertEqual(self.out["pA"]["registryAction"], "acknowledged")
        self.assertEqual(self.out["pA"]["logStatus"], "analyst-ack")

    def test_parse_legacy_buttons(self):
        lg = self.out["pLegacy"]
        self.assertEqual(lg["registryAction"], "quarantine")
        self.assertEqual(lg["agentId"], "003")
        self.assertEqual(lg["filePath"], "/home/ravi/Downloads/eicar.com")  # escape dilepas
        self.assertEqual(lg["hash"], "b" * 64)
        self.assertEqual(lg["did"], "")
        ph = self.out["pPhish"]
        self.assertTrue(ph["isPhishing"])
        self.assertEqual(ph["url"], "http://jahat.example/login")

    def test_claim_uses_registry_and_logs_audit(self):
        cl = self.out["cl"]
        self.assertEqual(cl["filePath"], "/home/ravi/Downloads/setup-installer.exe")
        self.assertEqual(cl["agentId"], "010")
        self.assertTrue(cl["fleet_logged"])
        urls = [c["url"] for c in self.out["claimed"]]
        self.assertTrue(any("/decision/resolve" in u for u in urls))
        self.assertTrue(any("/webhook-log" in u for u in urls))
        resolve_body = next(c["body"] for c in self.out["claimed"] if c["url"].endswith("/decision/resolve"))
        self.assertEqual(resolve_body["hash"], "a" * 16)  # did pendek -> prefix lookup
        self.assertEqual(resolve_body["action"], "quarantine")
        self.assertEqual(resolve_body["by"], "Ravi")

    def test_ar_only_for_quarantine_and_block(self):
        self.assertEqual(self.out["arQ"]["status"], "terkirim")
        self.assertIn("!quarantine-file", json.dumps(self.out["arCalls"][0]["body"]))
        self.assertIn("/home/ravi/Downloads/setup-installer.exe",
                      json.dumps(self.out["arCalls"][0]["body"]))
        self.assertEqual(self.out["arF"]["status"], "tanpa-ar")
        self.assertEqual(self.out["arPblk"]["status"], "terkirim")
        self.assertIn("!block-domain", json.dumps(self.out["arCalls"][1]["body"]))
        self.assertEqual(len(self.out["arCalls"]), 2)  # f:/a: tidak memanggil AR

    def test_sla_sweeper(self):
        self.assertEqual(self.out["slaEmpty"], [])
        full = self.out["slaFull"]
        self.assertEqual(full["count"], 2)
        self.assertIn("BELUM DITANGANI", full["text"])
        self.assertIn("setup-installer.exe", full["text"])
        self.assertIn("agent 005", full["text"])
        escalated = [c["body"]["hash"] for c in self.out["slaCalls"] if c["url"].endswith("/decision/escalate")]
        self.assertEqual(escalated, ["a" * 16, "c" * 16])


if __name__ == "__main__":
    unittest.main(verbosity=2)
