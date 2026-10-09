#!/usr/bin/env python3
"""Test untuk patch-n8n-systemfile.py.

Dua lapis:
  1. Transformasi: pola OLD->NEW kena semua node, idempoten, dan gagal keras
     (SystemExit) kalau pola live tak cocok (supaya workflow live tidak dirusak).
  2. Perilaku: JS hasil patch benar-benar dieksekusi via `node` dengan stub
     n8n ($json/$()/this.helpers) -> cek is_system_file, severity MEDIUM,
     AR mati, judul/VT/prompt, dan Fleet Quarantine tidak memanggil HTTP.

Jalankan: python3 scripts/test_patch_n8n_systemfile.py
"""

import importlib.util
import json
import subprocess
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("patch-n8n-systemfile.py")
SPEC = importlib.util.spec_from_file_location("patch_systemfile", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


# --- cuplikan PERSIS kode node di workflow LIVE (pra-patch, 2026-09-28) ---
EKSTRAK_LIVE = r"""const body = $json.body ?? $json;

const hash = body?.syscheck?.sha256_after
          || body?.syscheck?.sha256_before
          || body?.data?.sha256_after
          || body?.data?.hash
          || body?.sha256
          || body?.md5
          || null;

const filename = body?.syscheck?.path?.split('/').pop()
              || body?.data?.path?.split('/').pop()
              || body?.filename
              || 'unknown';

const filepath = body?.syscheck?.path
              || body?.data?.path
              || body?.filepath
              || '/unknown';

const srcip = body?.data?.srcip
           || body?.data?.src_ip
           || body?.decoder?.srcip
           || body?.agent?.ip
           || body?.srcip
           || '0.0.0.0';

return [{
  json: {
    rule_id:          body?.rule?.id || body?.rule_id || 'unknown',
    rule_level:       body?.rule?.level || body?.rule_level || 0,
    rule_description: body?.rule?.description || body?.rule_description || 'No description',
    hash:             hash,
    hash_available:   hash !== null && hash !== undefined && hash !== '',
    filename:         filename,
    filepath:         filepath,
    srcip:            srcip,
    agent_id:         (body?.agent?.id || body?.agent_id || '000').toString().padStart(3, '0'),
    agent_name:       body?.agent?.name || body?.agent_name || 'unknown',
    model:            body?.model || 'Atria-Dawn-Preview',
    timestamp:        body?.timestamp || new Date().toISOString()
  }
}];"""

RANGKUM_LIVE = r"""const mb = $input.first().json;

const cacheNode = $('Cek Cache VT').first().json;
const cache_hit = !!cacheNode.cache_hit;

let data = null;
let otx_data = null;
if (cache_hit) {
  data = { data: { attributes: { last_analysis_stats: cacheNode.cached_stats || {} } } };
} else {
  try { data = $('Scan VirusTotal').first().json; } catch (e) { data = null; }
  try { otx_data = $('OTX Lookup').first().json; } catch (e) { otx_data = null; }
}

const is_otx = !!otx_data?.pulse_info;
const stats = is_otx ? {} : (data?.data?.attributes?.last_analysis_stats || {});
const otx_pulses = is_otx ? (otx_data.pulse_info?.count || 0) : 0;
const otx_threat = is_otx && otx_pulses > 0;

// MISP (sumber intel ke-4) -- di fixture ini dimatikan.
const misp_threat = false;

let mb_known = false;
let mb_malicious = false;
let mb_signature = '';
let mb_tags = [];
let mb_file_type = '';
let mb_query_status = 'not_checked';
if (mb && typeof mb.query_status === 'string') {
  mb_query_status = mb.query_status;
  if (mb_query_status === 'ok' && mb.data) {
    const d = Array.isArray(mb.data) ? mb.data[0] : mb.data;
    mb_known = true;
    mb_signature = d?.signature || '';
    mb_tags = d?.tags || [];
    mb_file_type = d?.file_type || '';
    const MALICIOUS_TAGS = ['ransomware', 'trojan', 'backdoor', 'banker',
      'infostealer', 'rat', 'keylogger', 'botnet', 'apt', 'dropper', 'loader'];
    mb_malicious = (!!mb_signature && mb_signature !== 'n/a')
      || mb_tags.some((t) => MALICIOUS_TAGS.includes(String(t).toLowerCase()));
  }
}
const mb_threat = mb_known && mb_malicious;

const malicious = stats.malicious || 0;
const suspicious = stats.suspicious || 0;
const undetected = stats.undetected || 0;
const total = malicious + suspicious + undetected;
const detection_ratio = is_otx ? (otx_pulses + ' pulse OTX') : (malicious + '/' + total);

const alertData = $('Ekstrak Alert').first().json;
const ruleLevel = alertData.rule_level || 0;

let severity, severityIcon, severityLabel, silent;
if (malicious >= 20 || ruleLevel >= 12 || (mb_threat && malicious >= 5)) {
  severity = 'CRITICAL'; severityIcon = '🆘'; severityLabel = 'KRITIS'; silent = false;
} else if (otx_threat || mb_threat || misp_threat || malicious >= 5 || ruleLevel >= 7) {
  severity = 'HIGH'; severityIcon = '🚨'; severityLabel = 'TINGGI'; silent = false;
} else {
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG'; silent = true;
}

const should_active_response = severity !== 'MEDIUM';

return [{
  json: {
    filename: alertData.filename,
    filepath: alertData.filepath,
    hash: alertData.hash,
    agent_id: alertData.agent_id,
    agent_name: alertData.agent_name,
    srcip: alertData.srcip,
    malicious,
    suspicious,
    undetected,
    total,
    detection_ratio,
    timestamp: alertData.timestamp,
    rule_level: ruleLevel,
    severity,
    severityIcon,
    severityLabel,
    silent,
    should_active_response,
    source: cache_hit ? 'vt-cache' : (is_otx ? 'otx' : 'vt'),
    otx_threat,
    otx_pulses,
    cache_hit,
    mb_known,
    mb_malicious,
    mb_signature,
    mb_tags,
    mb_file_type,
    mb_query_status,
    mb_threat
  }
}];

// patch:cache-mb:v2"""

BUILD_LIVE = r"""let vtData, alertData;
try {
  vtData = $('Rangkum Hasil').first().json;
  alertData = $('Ekstrak Alert').first().json;
} catch (e) {
  vtData = $('Rangkum Chain').first().json;
  alertData = $('Ekstrak Chain').first().json;
}

const filename = vtData.filename || 'unknown';
const hash = vtData.hash || null;
const hashExists = !!hash;
const malicious = vtData.malicious || 0;
const total = vtData.total || 0;
const hasVT = total > 0;
const ruleLevel = vtData.rule_level || 0;
const severity = vtData.severity;
const severityIcon = vtData.severityIcon;
const severityLabel = vtData.severityLabel;
const silent = vtData.silent;
const isChain = !!alertData.chain;

let severityGuidance;
if (severity === 'CRITICAL') {
  severityGuidance = 'Konteks: ancaman KRITIS. Berikan rekomendasi immediate response, isolasi sistem, dan eradikasi.';
} else if (severity === 'HIGH') {
  severityGuidance = 'Konteks: ancaman TINGGI. Berikan rekomendasi tindakan dalam 24 jam, verifikasi dan kontainmen.';
} else {
  severityGuidance = 'Konteks: ancaman SEDANG informational. Berikan rekomendasi monitoring rutin.';
}

let detectionText, vtFooter, vtPromptLine;
if (hasVT) {
  detectionText = malicious + '/' + total;
  vtFooter = 'Lihat di VirusTotal';
  vtPromptLine = 'VirusTotal: ' + malicious + ' dari ' + total + ' antivirus mendeteksi file ini sebagai malware.';
} else if (hashExists) {
  detectionText = 'Belum dikenali VirusTotal';
  vtFooter = 'Hash belum pernah disubmit ke VirusTotal';
  vtPromptLine = 'VirusTotal: hash file belum pernah dikenali NotFound, tidak ada data deteksi.';
} else {
  detectionText = 'Scan dilewati hash tidak ada';
  vtFooter = 'VirusTotal: Hash tidak tersedia untuk discan';
  vtPromptLine = 'Catatan: Hash tidak tersedia, scan VirusTotal tidak dilakukan.';
}

const hashDisplay = hashExists ? hash : 'Tidak tersedia';

let prompt, alertTitle, targetLabel, chainCmd;
if (isChain) {
  const c = alertData.chain;
  alertTitle = 'RANTAI PROSES MENCURIGAKAN';
  targetLabel = 'Proses';
  chainCmd = (c.commandLine || '') + (c.parentCommandLine ? ' (parent: ' + c.parentCommandLine + ')' : '');
  prompt = 'CHAIN PROMPT ' + severityGuidance;
} else {
  alertTitle = 'MALWARE TERDETEKSI';
  targetLabel = 'File';
  chainCmd = '';
  prompt =
    'Severity: ' + severity + ' Wazuh level ' + ruleLevel + ', malicious ' + malicious + ' dari ' + total + '\n' +
    'File: ' + filename + '\n' +
    'Hash: ' + hashDisplay + '\n' +
    vtPromptLine + '\n\n' +
    severityGuidance + '\n' +
    'Jelaskan tingkat bahaya file ini dan berikan rekomendasi tindakan yang harus diambil.';
}

return [{
  json: {
    model: 'Atria-Dawn-Preview',
    prompt: prompt,
    stream: false,
    has_vt_data: hasVT,
    hash_exists: hashExists,
    hash_display: hashDisplay,
    detection_text: detectionText,
    vt_footer: vtFooter,
    malicious: malicious,
    total: total,
    severity: severity,
    severityIcon: severityIcon,
    severityLabel: severityLabel,
    silent: silent,
    rule_level: ruleLevel,
    alert_title: alertTitle,
    target_label: targetLabel,
    chain_cmd: chainCmd,
    filename: filename,
    filepath: vtData.filepath,
    agent_name: alertData.agent_name,
    timestamp: vtData.timestamp
  }
}];"""

FLEETQ_LIVE = r"""const ar = $('Trigger Active Response').first().json;
const alert = $('Ekstrak Alert').first().json;
let fleet = { attempted: false, result: 'skipped-wazuh-ok' };
if (ar.status !== 'isolated') {
  try {
    const resp = await this.helpers.httpRequest({
      method: 'POST',
      url: 'http://host.docker.internal:8080/api/commands',
      body: JSON.stringify({
        agent_id: alert.agent_id,
        action: 'quarantine',
        target: alert.filepath,
        by: 'n8n-auto-ar',
      }),
      timeout: 15000,
    });
    fleet = { attempted: true, result: 'queued', detail: resp };
  } catch (e) {
    fleet = { attempted: true, result: 'failed',
      error: String((e && e.message) || e).slice(0, 200) };
  }
}
return [{ json: { ...ar, fleet_quarantine: fleet } }];"""


def make_nodes():
    return [
        {"name": MODULE.EKSTRAK, "type": "n8n-nodes-base.code", "parameters": {"jsCode": EKSTRAK_LIVE}},
        {"name": MODULE.RANGKUM, "type": "n8n-nodes-base.code", "parameters": {"jsCode": RANGKUM_LIVE}},
        {"name": MODULE.BUILD, "type": "n8n-nodes-base.code", "parameters": {"jsCode": BUILD_LIVE}},
        {"name": MODULE.FLEET_Q, "type": "n8n-nodes-base.code", "parameters": {"jsCode": FLEETQ_LIVE}},
    ]


def js_for(nodes, name):
    return next(n["parameters"]["jsCode"] for n in nodes if n["name"] == name)


# --- harness JS: menjalankan kode node (async) dengan stub n8n ---
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
        "fleetq": js_for(patched_nodes, MODULE.FLEET_Q),
    }
    program = JS_HARNESS.replace("__CODE__", json.dumps(codes)).replace(
        "__RUN__", body_js
    )
    proc = subprocess.run(
        ["node", "-e", program], capture_output=True, text=True, timeout=60
    )
    if proc.returncode != 0:
        raise AssertionError("node gagal:\n" + proc.stderr[:2000])
    return json.loads(proc.stdout.strip())


RUN_JS = r"""
(async () => {
  const hostsAlert = { body: {
    rule: { id: '550', level: 7, description: 'Integrity checksum changed.' },
    syscheck: { path: 'c:\\windows\\system32\\drivers\\etc\\hosts',
                sha256_after: 'f4615', event: 'modified' },
    agent: { id: '002', name: 'bali-handmade' }, timestamp: '2026-09-28T15:14:14Z'
  }};
  const normalAlert = { body: {
    rule: { id: '554', level: 5, description: 'File added to the system.' },
    syscheck: { path: '/home/ravi/Downloads/eicar.com', sha256_after: 'abc123', event: 'added' },
    agent: { id: '009', name: 'nixbox' }, timestamp: '2026-09-28T15:00:00Z'
  }};

  const ex = async (body) => (await callNode(CODE.ekstrak, body, {}, {}))[0].json;
  const exHosts = await ex(hostsAlert);
  const exNormal = await ex(normalAlert);

  const rangkum = async (exJson) => (await callNode(CODE.rangkum,
    { query_status: 'not_checked' },
    { 'Ekstrak Alert': exJson, 'Cek Cache VT': { cache_hit: false },
      'Scan VirusTotal': { data: { attributes: { last_analysis_stats: { malicious: 0, suspicious: 0, undetected: 0 } } } } },
    {}))[0].json;

  const rkHosts = await rangkum(exHosts);
  const rkNormal = await rangkum({ ...exNormal, rule_level: 7 });

  const build = async (rk, exd) => (await callNode(CODE.build, {},
    { 'Rangkum Hasil': rk, 'Ekstrak Alert': exd }, {}))[0].json;

  const bpHosts = await build(rkHosts, exHosts);
  const bpNormal = await build(rkNormal, { ...exNormal, rule_level: 7 });

  const boom = { httpRequest: () => { throw new Error('HTTP DIPANGGIL (seharusnya tidak)'); } };
  const fqHosts = (await callNode(CODE.fleetq, {}, {
    'Trigger Active Response': { status: 'blocked' }, 'Ekstrak Alert': exHosts }, boom))[0].json;

  console.log(JSON.stringify({
    exHosts, exNormal, rkHosts, rkNormal, bpHosts, bpNormal, fqHosts
  }));
})().catch((e) => { console.error('ERR', (e && e.stack) || e); process.exit(1); });
"""


class TransformTests(unittest.TestCase):
    def test_applies_to_all_nodes(self):
        nodes = make_nodes()
        changed = MODULE.apply_patches(nodes)
        self.assertEqual(set(changed), {MODULE.EKSTRAK, MODULE.RANGKUM, MODULE.BUILD, MODULE.FLEET_Q})
        for name in changed:
            self.assertIn(MODULE.MARKER, js_for(nodes, name))

    def test_idempotent(self):
        nodes = make_nodes()
        MODULE.apply_patches(nodes)
        changed_again = MODULE.apply_patches(nodes)
        self.assertEqual(changed_again, [])

    def test_fails_loud_on_unexpected_pattern(self):
        nodes = make_nodes()
        js_for_node = next(n for n in nodes if n["name"] == MODULE.EKSTRAK)
        js_for_node["parameters"]["jsCode"] = "const x = 1;"
        with self.assertRaises(SystemExit):
            MODULE.apply_patches(nodes)


class BehaviourTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        nodes = make_nodes()
        MODULE.apply_patches(nodes)
        cls.out = run_js(RUN_JS, nodes)

    def test_ekstrak_detects_system_file(self):
        self.assertTrue(self.out["exHosts"]["is_system_file"])
        self.assertFalse(self.out["exNormal"]["is_system_file"])

    def test_hosts_severity_capped_and_no_ar(self):
        rk = self.out["rkHosts"]
        self.assertTrue(rk["is_system_file"])
        self.assertEqual(rk["severity"], "MEDIUM")
        self.assertFalse(rk["should_active_response"])
        self.assertFalse(rk["silent"])  # tetap diberitakan, bukan silent-failure

    def test_normal_high_still_high(self):
        rk = self.out["rkNormal"]
        self.assertEqual(rk["severity"], "HIGH")
        self.assertTrue(rk["should_active_response"])

    def test_build_payload_titles_and_vt(self):
        bp = self.out["bpHosts"]
        self.assertEqual(bp["alert_title"], "PERUBAHAN FILE KONFIGURASI SISTEM")
        self.assertIn("N/A", bp["detection_text"])
        self.assertIn("soar-sinkhole", bp["prompt"])
        self.assertNotIn("MALWARE TERDETEKSI", bp["alert_title"])
        self.assertEqual(self.out["bpNormal"]["alert_title"], "MALWARE TERDETEKSI")

    def test_fleet_quarantine_skips_system_file(self):
        fq = self.out["fqHosts"]["fleet_quarantine"]
        self.assertFalse(fq["attempted"])
        self.assertEqual(fq["result"], "skipped-system-file")


if __name__ == "__main__":
    unittest.main()
