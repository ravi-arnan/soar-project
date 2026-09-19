#!/usr/bin/env python3
"""Cabang process-chain (rule 110001-110011) di workflow live 'Deteksi Malware'.

Latar: webhook wazuh-alert menerima dua jenis alert. FIM (ada hash) lewat
jalur Filter -> Scan VT. Alert Sysmon process-chain TIDAK punya hash sehingga
mati di Filter (cond-has-hash) — dan kalaupun lolos, Scan VT / karantina file
tidak masuk akal untuk LOLBin (binary sah seperti powershell.exe!).

Cabang baru (jalur FIM TIDAK DIUBAH sama sekali):
  Webhook -+-> Filter Alert Malware (jalur lama, utuh)
             +-> Cabang Chain? -true-> Ekstrak Chain -> Rangkum Chain
                                 -false-> (tak terkoneksi, berhenti)
Rangkum Chain -> Build Payload + Log ke Fleet (dipakai bersama).

Palang: output FALSE IF yang dibuat via API tidak mengeksekusi downstream
di n8n 2.40 (terbukti reproduksi terisolasi 19 Sep). Jadi desain ini HANYA
pakai output TRUE + fan-out Webhook, pola yang terbukti jalan.

Rangkum Chain: severity dari rule_level, should_active_response=false
(TIDAK ada AR otomatis untuk chain — LOLBin = binary sah, karantina
powershell.exe = bunuh sistem). Build Payload + Telegram dipakai bersama
dengan fallback try/catch + prompt chain-aware.

Cara pakai: python3 scripts/patch-n8n-chain.py [--dry-run]
Idempoten + backup otomatis.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "..", "backups")
WORKFLOW_ID_DEFAULT = "1MVcpL7ZKfBhR2tc"

CABANG_NAME = "Cabang Chain?"
EKSTRAK_CHAIN = "Ekstrak Chain"
RANGKUM_CHAIN = "Rangkum Chain"
HASH_Q = "Ada Hash?"  # nama node desain lama (dihapus bila ketemu)

CABANG_PARAMS = {
    "conditions": {
        "options": {
            "caseSensitive": True,
            "leftValue": "",
            "typeValidation": "strict",
            "version": 2,
        },
        "conditions": [
            {
                "id": "cond-is-chain",
                "leftValue": "={{ (() => { const id = Number((($json.body ?? $json).rule?.id) || ($json.body ?? $json).rule_id || 0); return id >= 110001 && id <= 110011; })() }}",
                "rightValue": True,
                "operator": {"type": "boolean", "operation": "equals"},
            }
        ],
        "combinator": "and",
    },
    "options": {},
}

HASH_Q_PARAMS = {
    "conditions": {
        "options": {
            "caseSensitive": True,
            "leftValue": "",
            "typeValidation": "strict",
            "version": 2,
        },
        "conditions": [
            {
                "id": "cond-has-hash",
                "leftValue": "={{ !!($json.hash_available) }}",
                "rightValue": True,
                "operator": {"type": "boolean", "operation": "equals"},
            }
        ],
        "combinator": "and",
    },
    "options": {},
}

EKSTRAK_CHAIN_JS = """// Ekstrak alert process-chain manager (rule 110001-110011) ke format yang
// sama dengan Ekstrak Alert + info rantai proses. Defensive: baca varian
// nested (data.sysmon.*), flat (sysmon.*), dan JSON modern (win.eventdata).
// Dedup INLINE di sini (tidak share node Dedup): key agent+rule+image+cmd.
const body = $json.body ?? $json;
const rule = body?.rule || {};
const data = body?.data || {};
const sys = data.sysmon || data?.win?.eventdata || body.sysmon || {};
const flat = (k) => sys[k] ?? data['sysmon.' + k] ?? body['sysmon.' + k] ?? null;

const image = flat('image') || flat('Image') || 'unknown';
const commandLine = flat('commandLine') || flat('CommandLine') || '';
const parentImage = flat('parentImage') || flat('ParentImage') || '';
const parentCmd = flat('parentCommandLine') || flat('ParentCommandLine') || '';
const user = data.srcuser || body.srcuser || flat('User') || '';
const agent = body?.agent || {};
const agentId = (agent.id || body.agent_id || '000').toString().padStart(3, '0');
const ruleId = rule.id || body.rule_id || 'unknown';
const srcip = agent.ip || body?.srcip || '0.0.0.0';

try {
  const resp = await this.helpers.httpRequest({
    method: 'POST',
    url: 'http://host.docker.internal:8080/api/seen',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      key: [agentId, ruleId, image, commandLine].join('|'),
      window_secs: 300,
    }),
    timeout: 10000,
  });
  if (resp && resp.duplicate) return [];
} catch (e) { /* fail-open, teruskan */ }
const filename = String(image).split(/[/\\\\]/).pop() || 'unknown';

return [{
  json: {
    rule_id:          ruleId,
    rule_level:       rule.level || body.rule_level || 0,
    rule_description: rule.description || body.rule_description || 'Process chain mencurigakan',
    hash:             null,
    hash_available:   false,
    filename:         filename,
    filepath:         image,
    srcip:            srcip,
    agent_id:         agentId,
    agent_name:       agent.name || body.agent_name || 'unknown',
    model:            body?.model || 'llama3.2:3b',
    timestamp:        body?.timestamp || new Date().toISOString(),
    chain: {
      image: image,
      commandLine: String(commandLine),
      parentImage: parentImage,
      parentCommandLine: String(parentCmd),
      user: String(user),
    },
  }
}];"""

RANGKUM_CHAIN_JS = """// Severity chain dari rule_level (tanpa VT: tidak ada hash).
// should_active_response=false SELALU: LOLBin = binary sah, AR otomatis
// (karantina powershell.exe dsb) = bunuh sistem. Respons = analis via Telegram.
const a = $('Ekstrak Chain').first().json;
const ruleLevel = a.rule_level || 0;

let severity, severityIcon, severityLabel, silent;
if (ruleLevel >= 12) {
  severity = 'CRITICAL'; severityIcon = '🆘'; severityLabel = 'KRITIS'; silent = false;
} else if (ruleLevel >= 7) {
  severity = 'HIGH'; severityIcon = '🚨'; severityLabel = 'TINGGI'; silent = false;
} else {
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG'; silent = true;
}

return [{
  json: {
    filename: a.filename,
    filepath: a.filepath,
    hash: null,
    agent_id: a.agent_id,
    agent_name: a.agent_name,
    srcip: a.srcip,
    malicious: 0,
    suspicious: 0,
    undetected: 0,
    total: 0,
    detection_ratio: 'chain rule ' + a.rule_id,
    timestamp: a.timestamp,
    rule_id: a.rule_id,
    rule_level: ruleLevel,
    rule_description: a.rule_description,
    severity: severity,
    severityIcon: severityIcon,
    severityLabel: severityLabel,
    silent: silent,
    should_active_response: false,
    source: 'chain',
    chain: a.chain,
  }
}];"""

# Build Payload baru: fallback Rangkum/Ekstrak Chain + prompt LOLBin + field
# untuk Telegram ($json.* supaya Telegram tak referensi nama node).
BUILD_JS = """let vtData, alertData;
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

// Severity-specific AI guidance
let severityGuidance;
if (severity === 'CRITICAL') {
  severityGuidance = 'Konteks: ancaman KRITIS. Berikan rekomendasi immediate response, isolasi sistem, dan eradikasi.';
} else if (severity === 'HIGH') {
  severityGuidance = 'Konteks: ancaman TINGGI. Berikan rekomendasi tindakan dalam 24 jam, verifikasi dan kontainmen.';
} else {
  severityGuidance = 'Konteks: ancaman SEDANG informational. Berikan rekomendasi monitoring rutin.';
}

// 3-state VT message
let detectionText, vtFooter, vtPromptLine;
if (hasVT) {
  detectionText = malicious + '/' + total;
  vtFooter = '🔗 [Lihat di VirusTotal](https://www.virustotal.com/gui/file/' + hash + ')';
  vtPromptLine = 'VirusTotal: ' + malicious + ' dari ' + total + ' antivirus mendeteksi file ini sebagai malware.';
} else if (hashExists) {
  detectionText = 'Belum dikenali VirusTotal';
  vtFooter = 'ℹ️ Hash belum pernah disubmit ke VirusTotal';
  vtPromptLine = 'VirusTotal: hash file belum pernah dikenali NotFound, tidak ada data deteksi.';
} else {
  detectionText = 'Scan dilewati hash tidak ada';
  vtFooter = '⚠️ VirusTotal: Hash tidak tersedia untuk discan';
  vtPromptLine = 'Catatan: Hash tidak tersedia, scan VirusTotal tidak dilakukan.';
}

const hashDisplay = hashExists ? hash : 'Tidak tersedia';

let prompt, alertTitle, targetLabel, chainCmd;
if (isChain) {
  const c = alertData.chain;
  alertTitle = 'RANTAI PROSES MENCURIGAKAN';
  targetLabel = 'Proses';
  chainCmd = (c.commandLine || '') + (c.parentCommandLine ? ' (parent: ' + c.parentCommandLine + ')' : '');
  prompt =
    'You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter markdown seperti asterisk underscore backtick atau bracket.\\n\\n' +
    'Severity: ' + severity + ' Wazuh rule ' + vtData.rule_id + ' level ' + ruleLevel + ': ' + (vtData.rule_description || '') + '\\n' +
    'Proses: ' + c.image + '\\n' +
    'Command line: ' + (c.commandLine || '-') + '\\n' +
    'Parent: ' + (c.parentImage || '-') + ' ' + (c.parentCommandLine || '') + '\\n' +
    'Agent: ' + alertData.agent_name + '\\n\\n' +
    severityGuidance + '\\n' +
    'Nilai apakah rantai proses ini indikasi LOLBin atau malware (JANGAN sarankan menghapus binary sistem Windows), dan rekomendasi verifikasi berikutnya.';
} else {
  alertTitle = 'MALWARE TERDETEKSI';
  targetLabel = 'File';
  chainCmd = '';
  prompt =
    'You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter markdown seperti asterisk underscore backtick atau bracket.\\n\\n' +
    'Severity: ' + severity + ' Wazuh level ' + ruleLevel + ', malicious ' + malicious + ' dari ' + total + '\\n' +
    'File: ' + filename + '\\n' +
    'Hash: ' + hashDisplay + '\\n' +
    vtPromptLine + '\\n\\n' +
    severityGuidance + '\\n' +
    'Jelaskan tingkat bahaya file ini dan berikan rekomendasi tindakan yang harus diambil.';
}

return [{
  json: {
    model: 'llama3.2:3b',
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

# Telegram: judul/label dinamis + semua field dari $json (tidak referensi
# nama node, jadi aman untuk dua jalur). Baris Command hanya bila ada.
TELEGRAM_TEXT = """={{ $json.severityIcon + " *" + $json.severityLabel + " - " + $json.alert_title + "*\\n\\n📁 " + $json.target_label + ": " + (($json.filename ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1') + "\\n📂 Path: " + (($json.filepath ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1') + ($json.chain_cmd ? ("\\n💻 Command: " + (($json.chain_cmd ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1')) : "") + "\\n🔍 Hash: `" + $json.hash_display + "`\\n🛡️ Severity: " + $json.severity + " level " + $json.rule_level + "\\n📊 Deteksi: " + $json.detection_text + "\\n🖥️ Agent: " + (($json.agent_name ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1') + "\\n🕐 Waktu: " + ($json.timestamp ?? '') + "\\n\\n🤖 *Analisis AI:*\\n" + (($json.ai_response ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1') + "\\n\\n" + $json.vt_footer }}"""


def api_get(url, api_key):
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": api_key})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def api_put(url, api_key, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="PUT",
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def get_node(nodes, name):
    for n in nodes:
        if n.get("name") == name:
            return n
    return None


def ensure_node(nodes, spec):
    n = get_node(nodes, spec["name"])
    if n is None:
        nodes.append(spec)
        print("  Node '%s' ditambahkan." % spec["name"])
        return True, spec
    changed = False
    for k in ("parameters", "type", "typeVersion"):
        if n.get(k) != spec[k]:
            n[k] = spec[k]
            changed = True
    if changed:
        print("  Node '%s' diperbarui." % spec["name"])
    else:
        print("  Node '%s' sudah sesuai." % spec["name"])
    return changed, n


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://192.168.1.47:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--workflow-id", default=WORKFLOW_ID_DEFAULT)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    with open(args.api_key_file) as f:
        api_key = f.read().strip()
    base = args.n8n_url.rstrip("/")
    wf_url = base + "/api/v1/workflows/" + args.workflow_id

    print("Mengambil workflow ...")
    wf = api_get(wf_url, api_key)
    nodes = wf.get("nodes", [])
    conns = wf.get("connections", {})

    os.makedirs(BACKUP_DIR, exist_ok=True)
    bp = os.path.join(
        BACKUP_DIR, "deteksi-malware-chain-" + time.strftime("%Y%m%d-%H%M%S") + ".json"
    )
    with open(bp, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + bp)

    changed = False

    c, _ = ensure_node(
        nodes,
        {
            "name": CABANG_NAME,
            "type": "n8n-nodes-base.if",
            "typeVersion": 2,
            "position": [-660, 448],
            "parameters": CABANG_PARAMS,
        },
    )
    changed |= c
    c, _ = ensure_node(
        nodes,
        {
            "name": EKSTRAK_CHAIN,
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "position": [-660, 680],
            "parameters": {"mode": "runOnceForAllItems", "jsCode": EKSTRAK_CHAIN_JS},
            "onError": "continueRegularOutput",
        },
    )
    changed |= c
    # Node "Ada Hash?" (desain lama) dihapus: output FALSE IF via API tidak
    # mengeksekusi downstream di n8n 2.40. Diganti fan-out + true-only.
    hq = get_node(nodes, HASH_Q)
    if hq is not None:
        nodes.remove(hq)
        conns.pop(HASH_Q, None)
        print("  Node 'Ada Hash?' dihapus.")
        changed = True
    c, _ = ensure_node(
        nodes,
        {
            "name": RANGKUM_CHAIN,
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "position": [360, 560],
            "parameters": {"mode": "runOnceForAllItems", "jsCode": RANGKUM_CHAIN_JS},
            "onError": "continueRegularOutput",
        },
    )
    changed |= c

    # Build Payload + Telegram dipakai bersama dua jalur.
    build = get_node(nodes, "Build Payload")
    if build["parameters"].get("jsCode") != BUILD_JS:
        build["parameters"]["jsCode"] = BUILD_JS
        print("  Node 'Build Payload' diperbarui (fallback chain + prompt LOLBin).")
        changed = True
    else:
        print("  Node 'Build Payload' sudah sesuai.")
    tg = get_node(nodes, "Send Telegram Alert")
    if tg["parameters"].get("text") != TELEGRAM_TEXT:
        tg["parameters"]["text"] = TELEGRAM_TEXT
        print("  Node 'Send Telegram Alert' diperbarui ($json semua).")
        changed = True
    else:
        print("  Node 'Send Telegram Alert' sudah sesuai.")

    def wire(frm, to_true, to_false=None):
        nonlocal_changed = False
        want = {"main": [[{"node": to_true, "type": "main", "index": 0}]]}
        if to_false:
            want["main"].append([{"node": to_false, "type": "main", "index": 1}])
        if conns.get(frm) != want:
            conns[frm] = want
            print(
                "  Rewire: %s -> %s%s"
                % (frm, to_true, (" + " + to_false) if to_false else "")
            )
            nonlocal_changed = True
        return nonlocal_changed

    # Hanya output TRUE yang dipakai (false-branch IF via API mati di 2.40).
    # Webhook fan-out ke Filter (FIM, tak berubah) + Cabang (chain).
    want_webhook = {
        "main": [
            [
                {"node": "Filter Alert Malware", "type": "main", "index": 0},
                {"node": CABANG_NAME, "type": "main", "index": 0},
            ]
        ]
    }
    if conns.get("Webhook") != want_webhook:
        conns["Webhook"] = want_webhook
        print("  Rewire: Webhook -> Filter + Cabang Chain? (fan-out)")
        changed = True
    # Cabang true(0)=chain; false tak terkoneksi:
    want_cabang = {"main": [[{"node": EKSTRAK_CHAIN, "type": "main", "index": 0}]]}
    if conns.get(CABANG_NAME) != want_cabang:
        conns[CABANG_NAME] = want_cabang
        print("  Rewire: Cabang Chain? true->Ekstrak Chain")
        changed = True
    changed |= wire(EKSTRAK_CHAIN, RANGKUM_CHAIN)
    # Kembalikan Dedup -> Scan VT langsung (jalur FIM utuh):
    changed |= wire("Dedup Alert", "Scan VirusTotal")
    # Rangkum Chain paralel ke Build Payload + Log ke Fleet (seperti Rangkum Hasil):
    want_rc = {
        "main": [
            [{"node": "Build Payload", "type": "main", "index": 0}],
            [{"node": "Log ke Fleet", "type": "main", "index": 0}],
        ]
    }
    if conns.get(RANGKUM_CHAIN) != want_rc:
        conns[RANGKUM_CHAIN] = want_rc
        print("  Rewire: Rangkum Chain -> Build Payload + Log ke Fleet")
        changed = True

    if args.dry_run:
        print("[DRY-RUN] Perubahan: " + str(changed))
        return
    if not changed:
        print("Tidak ada perubahan.")
        return
    payload = {
        "name": wf.get("name"),
        "nodes": nodes,
        "connections": conns,
        "settings": wf.get("settings", {}),
        "staticData": wf.get("staticData"),
    }
    print("Menulis ke n8n ...")
    try:
        result = api_put(wf_url, api_key, payload)
        print("Selesai. Aktif: " + str(result.get("active")))
    except urllib.error.HTTPError as e:
        print("GAGAL PUT: " + str(e.code) + " " + e.read().decode()[:300])
        sys.exit(1)


if __name__ == "__main__":
    main()
