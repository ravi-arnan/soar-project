#!/usr/bin/env python3
"""Perlakuan khusus file konfigurasi sistem (mis. hosts) di workflow live
'Deteksi Malware' (n8n public API).

Latar (temuan 2026-09-28): alert FIM rule 550 "Integrity checksum changed"
(level 7) pada `c:\\windows\\system32\\drivers\\etc\\hosts` naik jadi
"TINGGI - MALWARE TERDETEKSI" -- padahal perubahan file konfigurasi BUKAN
vonis malware, hash `hosts` spesifik-mesin sehingga VirusTotal tak relevan,
dan SOAR ini SENDIRI menulis ke hosts untuk sinkhole phishing
(`# soar-sinkhole`). Lebih jauh, severity HIGH membuat `should_active_response`
true sehingga `Fleet Quarantine` mencoba mengarantina file OS.

Patch ini menyentuh 4 node (jalur FIM saja, selain itu tidak diubah):

  1. Ekstrak Alert  -> tandai `is_system_file` (hosts / drivers\\etc\\ / resolv.conf)
  2. Rangkum Hasil  -> file sistem: severity maksimum MEDIUM (tetap diberitakan,
                       tidak silent), `should_active_response=false`
  3. Build Payload  -> judul "PERUBAHAN FILE KONFIGURASI SISTEM", VirusTotal
                       ditandai N/A, prompt AI diberi konteks sinkhole sendiri
  4. Fleet Quarantine -> pengaman: JANGAN pernah karantina file sistem

Cara pakai (jalankan DI ravi-debian, API key: /tmp/n8n_api_key.txt):
  python3 scripts/patch-n8n-systemfile.py [--dry-run]

Idempoten (marker `patch:systemfile:v1`), backup otomatis ke backups/.
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
MARKER = "patch:systemfile:v1"

EKSTRAK = "Ekstrak Alert"
RANGKUM = "Rangkum Hasil"
BUILD = "Build Payload"
FLEET_Q = "Fleet Quarantine"


def read_file(p):
    with open(p) as f:
        return f.read().strip()


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


# --------------------------------------------------------------------------
# 1. Ekstrak Alert -- deteksi file konfigurasi sistem
# --------------------------------------------------------------------------
EKSTRAK_OLD = """const filepath = body?.syscheck?.path
              || body?.data?.path
              || body?.filepath
              || '/unknown';"""

EKSTRAK_NEW = """const filepath = body?.syscheck?.path
              || body?.data?.path
              || body?.filepath
              || '/unknown';

// File konfigurasi sistem: dikelola OS dan/atau AR kita sendiri (sinkhole
// menulis ke hosts). Perubahannya BUKAN vonis malware -> perlakukan khusus
// (severity dibatasi, Active Response otomatis dilarang).
const lowerPath = String(filepath).toLowerCase();
const is_system_file = /[\\\\/]etc[\\\\/]hosts$/.test(lowerPath)
                    || /[\\\\/]system32[\\\\/]drivers[\\\\/]etc[\\\\/]/.test(lowerPath)
                    || /[\\\\/]etc[\\\\/]resolv\\.conf$/.test(lowerPath);
// patch:systemfile:v1"""

EKSTRAK_OLD_OUT = """    agent_name:       body?.agent?.name || body?.agent_name || 'unknown',
    model:            body?.model || 'Atria-Dawn-Preview',"""

EKSTRAK_NEW_OUT = """    agent_name:       body?.agent?.name || body?.agent_name || 'unknown',
    is_system_file:   is_system_file,
    model:            body?.model || 'Atria-Dawn-Preview',"""


def patch_ekstrak(js):
    if MARKER in js:
        return js, False
    for old in (EKSTRAK_OLD, EKSTRAK_OLD_OUT):
        if old not in js:
            raise SystemExit(
                "Pola 'Ekstrak Alert' tidak cocok, patch dibatalkan. Pola hilang:\n"
                + old
            )
    js = js.replace(EKSTRAK_OLD, EKSTRAK_NEW).replace(EKSTRAK_OLD_OUT, EKSTRAK_NEW_OUT)
    return js, True


# --------------------------------------------------------------------------
# 2. Rangkum Hasil -- batasi severity + matikan AR untuk file sistem
# --------------------------------------------------------------------------
RANGKUM_OLD_HEAD = """const alertData = $('Ekstrak Alert').first().json;
const ruleLevel = alertData.rule_level || 0;"""

RANGKUM_NEW_HEAD = """const alertData = $('Ekstrak Alert').first().json;
const ruleLevel = alertData.rule_level || 0;
// File konfigurasi sistem (mis. hosts): perubahan FIM bukan vonis malware dan
// Active Response otomatis dimatikan (JANGAN pernah karantina file OS).
const is_system_file = !!alertData.is_system_file;"""

RANGKUM_OLD_SEV = """let severity, severityIcon, severityLabel, silent;
if (malicious >= 20 || ruleLevel >= 12 || (mb_threat && malicious >= 5)) {
  severity = 'CRITICAL'; severityIcon = '🆘'; severityLabel = 'KRITIS'; silent = false;
} else if (otx_threat || mb_threat || misp_threat || malicious >= 5 || ruleLevel >= 7) {
  severity = 'HIGH'; severityIcon = '🚨'; severityLabel = 'TINGGI'; silent = false;
} else {
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG'; silent = true;
}

const should_active_response = severity !== 'MEDIUM';"""

RANGKUM_NEW_SEV = """let severity, severityIcon, severityLabel, silent;
if (!is_system_file && (malicious >= 20 || ruleLevel >= 12 || (mb_threat && malicious >= 5))) {
  severity = 'CRITICAL'; severityIcon = '🆘'; severityLabel = 'KRITIS'; silent = false;
} else if (!is_system_file && (otx_threat || mb_threat || misp_threat || malicious >= 5 || ruleLevel >= 7)) {
  severity = 'HIGH'; severityIcon = '🚨'; severityLabel = 'TINGGI'; silent = false;
} else {
  // File sistem: tetap diberitakan (bukan silent-failure) tapi tidak "TINGGI".
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG';
  silent = is_system_file ? false : true;
}

const should_active_response = !is_system_file && severity !== 'MEDIUM';
// patch:systemfile:v1"""

RANGKUM_OLD_OUT = """    silent,
    should_active_response,
    source: cache_hit ? 'vt-cache' : (is_otx ? 'otx' : 'vt'),"""

RANGKUM_NEW_OUT = """    silent,
    should_active_response,
    is_system_file,
    source: cache_hit ? 'vt-cache' : (is_otx ? 'otx' : 'vt'),"""


def patch_rangkum(js):
    if MARKER in js:
        return js, False
    for old in (RANGKUM_OLD_HEAD, RANGKUM_OLD_SEV, RANGKUM_OLD_OUT):
        if old not in js:
            raise SystemExit(
                "Pola 'Rangkum Hasil' tidak cocok, patch dibatalkan. Pola hilang:\n"
                + old
            )
    js = (
        js.replace(RANGKUM_OLD_HEAD, RANGKUM_NEW_HEAD)
        .replace(RANGKUM_OLD_SEV, RANGKUM_NEW_SEV)
        .replace(RANGKUM_OLD_OUT, RANGKUM_NEW_OUT)
    )
    return js, True


# --------------------------------------------------------------------------
# 3. Build Payload -- judul + VT N/A + konteks sinkhole di prompt
# --------------------------------------------------------------------------
BUILD_OLD_VT = "const hashDisplay = hashExists ? hash : 'Tidak tersedia';"

BUILD_NEW_VT = """const hashDisplay = hashExists ? hash : 'Tidak tersedia';

// File konfigurasi sistem: hash spesifik-mesin -> VirusTotal tidak relevan.
if (alertData.is_system_file) {
  detectionText = 'N/A (file konfigurasi sistem)';
  vtFooter = 'ℹ️ VirusTotal tidak relevan untuk file konfigurasi spesifik-mesin';
}"""

BUILD_OLD_BRANCH = """} else {
  alertTitle = 'MALWARE TERDETEKSI';
  targetLabel = 'File';
  chainCmd = '';
  prompt ="""

BUILD_NEW_BRANCH = """} else if (alertData.is_system_file) {
  // Perubahan file konfigurasi sistem (mis. hosts): bukan vonis malware,
  // VirusTotal tidak relevan, dan bisa berasal dari sinkhole SOAR ini sendiri.
  alertTitle = 'PERUBAHAN FILE KONFIGURASI SISTEM';
  targetLabel = 'File';
  chainCmd = '';
  prompt =
    'You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter markdown seperti asterisk underscore backtick atau bracket.\\n\\n' +
    'Jenis: perubahan file konfigurasi sistem. Wazuh rule ' + vtData.rule_id + ' level ' + ruleLevel + ': ' + (vtData.rule_description || '') + '\\n' +
    'File: ' + filename + '\\n' +
    'Hash: ' + hashDisplay + '\\n\\n' +
    'Konteks penting: sistem SOAR ini SENDIRI menulis ke file hosts untuk memblokir domain phishing (entri ditandai komentar soar-sinkhole); sistem operasi atau perkakas lain juga bisa mengubahnya. VirusTotal tidak relevan untuk file konfigurasi spesifik-mesin.\\n' +
    'Jelaskan bahwa ini perubahan file konfigurasi yang perlu DIPERIKSA MANUAL, bukan kepastian malware; sebutkan entri soar-sinkhole sebagai kemungkinan sah; rekomendasikan memeriksa isi file. JANGAN menyarankan isolasi/karantina host hanya berdasar perubahan file ini.';
} else {
  alertTitle = 'MALWARE TERDETEKSI';
  targetLabel = 'File';
  chainCmd = '';
  prompt ="""


def patch_build(js):
    if MARKER in js:
        return js, False
    for old in (BUILD_OLD_VT, BUILD_OLD_BRANCH):
        if old not in js:
            raise SystemExit(
                "Pola 'Build Payload' tidak cocok, patch dibatalkan. Pola hilang:\n"
                + old
            )
    js = js.replace(BUILD_OLD_VT, BUILD_NEW_VT).replace(BUILD_OLD_BRANCH, BUILD_NEW_BRANCH)
    return js + "\n// patch:systemfile:v1", True


# --------------------------------------------------------------------------
# 4. Fleet Quarantine -- pengaman: jangan karantina file sistem
# --------------------------------------------------------------------------
FQ_OLD = """let fleet = { attempted: false, result: 'skipped-wazuh-ok' };
if (ar.status !== 'isolated') {"""

FQ_NEW = """const sysFile = !!alert.is_system_file;
// Pengaman: file konfigurasi sistem (mis. hosts) TIDAK PERNAH dikarantina.
let fleet = { attempted: false, result: sysFile ? 'skipped-system-file' : 'skipped-wazuh-ok' };
if (!sysFile && ar.status !== 'isolated') {"""


def patch_fleet_quarantine(js):
    if MARKER in js:
        return js, False
    if FQ_OLD not in js:
        raise SystemExit(
            "Pola 'Fleet Quarantine' tidak cocok, patch dibatalkan. Pola hilang:\n" + FQ_OLD
        )
    return js.replace(FQ_OLD, FQ_NEW) + "\n// patch:systemfile:v1", True


PATCHERS = [
    (EKSTRAK, patch_ekstrak),
    (RANGKUM, patch_rangkum),
    (BUILD, patch_build),
    (FLEET_Q, patch_fleet_quarantine),
]


def apply_patches(nodes):
    """Terapkan semua patcher ke list nodes. Kembalikan (jenis, nama) yang berubah."""
    changed = []
    for name, fn in PATCHERS:
        node = get_node(nodes, name)
        if node is None:
            raise SystemExit("Node '" + name + "' tidak ditemukan di workflow live.")
        js = node.get("parameters", {}).get("jsCode", "")
        new_js, did = fn(js)
        if did:
            node["parameters"]["jsCode"] = new_js
            changed.append(name)
    return changed


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--workflow-id", default=WORKFLOW_ID_DEFAULT)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.api_key_file):
        sys.exit("API key file tidak ada: " + args.api_key_file)
    api_key = read_file(args.api_key_file)
    base = args.n8n_url.rstrip("/")
    wf_url = base + "/api/v1/workflows/" + args.workflow_id

    print("Mengambil workflow " + args.workflow_id + " ...")
    wf = api_get(wf_url, api_key)
    nodes = wf.get("nodes", [])
    print("  Node saat ini: " + str(len(nodes)))

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(
        BACKUP_DIR,
        "deteksi-malware-live-systemfile-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = apply_patches(nodes)
    for name in changed:
        print("  Diubah: " + name)
    if not changed:
        print("  Semua node sudah ter-patch (idempoten).")

    if args.dry_run:
        print("[DRY-RUN] Node yang akan berubah: " + (", ".join(changed) or "(tidak ada)"))
        return
    if not changed:
        return

    payload = {
        "name": wf.get("name"),
        "nodes": nodes,
        "connections": wf.get("connections", {}),
        "settings": wf.get("settings", {}),
        "staticData": wf.get("staticData"),
    }
    print("Menulis ke n8n ...")
    try:
        result = api_put(wf_url, api_key, payload)
        print("Selesai. Aktif: " + str(result.get("active")) + " | node: " + str(len(result.get("nodes", []))))
    except urllib.error.HTTPError as e:
        sys.exit("Gagal PUT: " + str(e.code) + " " + e.read().decode()[:300])


if __name__ == "__main__":
    main()
