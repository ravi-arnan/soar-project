#!/usr/bin/env python3
"""Rombak kebijakan severity jalur file di workflow LIVE 'Deteksi Malware'.

Latar (FP 2026-10-06): `VID-20260120-WA0029.mp4` di
`/home/ravi/Downloads/Telegram Desktop/` naik jadi notifikasi
"⚠️ SEDANG - MALWARE TERDETEKSI" padahal VirusTotal 404 (hash belum pernah
dikenal), MalwareBazaar/OTX kosong, dan satu-satunya pemicu cuma rule FIM 554
"File added to the system" level 5. Di node `Rangkum Hasil`, MEDIUM adalah
cabang `else` -- jadi file apa pun tanpa indikator otomatis divonis MALWARE.

Kebijakan baru (disetujui Ravi 2026-10-06):

  1. Tidak ada indikator sama sekali (VT 0 deteksi + MB/OTX kosong + tanpa
     indikator rule) -> severity INFO, BUKAN "MALWARE TERDETEKSI".
       - Media/dokumen jinak (mp4, mp3, jpg, png, pdf, docx, ...) -> TIDAK
         dikirim notifikasi sama sekali (diamkan).
       - Tipe lain tanpa indikator -> INFO informasional (tetap diberitakan,
         silent, tanpa tombol/AR).
  2. Hash belum dikenal VT TAPI eksekutabel (ekstensi berisiko / bit exec) ->
     MEDIUM "PERLU REVIEW" (indikator lemah; tanpa tombol/AR).
  3. rule_level FIM (550/554, level 5-7) TIDAK lagi menaikkan severity file.
     Severity jalur file murni dari threat intel (VT/MB/OTX) + status
     eksekutabel; rule_level tetap ditampilkan di pesan.
  4. VT error non-404 (429/5xx/timeout) = tidak terverifikasi -> MEDIUM
     (jangan sampai error transien disenyapkan sebagai INFO).
  5. AR otomatis (should_active_response) HANYA untuk CRITICAL/HIGH nyata
     (VT/MB/OTX), bukan dari rule FIM.

Node yang disentuh (jalur FIM saja; cabang chain & file sistem tak diubah):
  1. Ekstrak Alert   -> tambah `is_exec` (bit eksekusi dari perm_after unix).
  2. Rangkum Hasil   -> model severity baru + flag decision/notify.
  3. Build Payload   -> judul & prompt AI untuk INFO / PERLU REVIEW + `notify`.
  4. Perlu Notifikasi? (baru, IF) -> gate kirim Telegram, media jinak dilewati.

Idempoten (marker `patch:noindicator:v1`), fail-loud kalau pola live tak
cocok, backup otomatis ke backups/.

Cara pakai (jalankan DI ravi-debian, n8n terjangkau):
  python3 scripts/patch-n8n-noindicator.py --dry-run
  python3 scripts/patch-n8n-noindicator.py
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
MARKER = "patch:noindicator:v1"

EKSTRAK = "Ekstrak Alert"
RANGKUM = "Rangkum Hasil"
BUILD = "Build Payload"
NOTIFY_IF = "Perlu Notifikasi?"

# Ekstensi eksekutabel / berisiko: hash tak dikenal + tipe ini = perlu review.
# Mirror scripts/apply-g2-exec-bit.py:70-72.
RISKY_EXT_JS = (
    "['exe','dll','scr','com','bat','cmd','ps1','psm1','vbs','vbe','js','jse',"
    "'jar','msi','msp','apk','sh','bash','bin','run','elf','deb','rpm','py',"
    "'pyc','pl','php','wsf','wsh','lnk','iso','img','dmg','app','desktop',"
    "'hta','cpl','sys','drv','ocx','reg','pif','msc','job','scf','inf','ins',"
    "'asp','aspx','jsp','vba']"
)

# Media/dokumen jinak: tanpa indikator = tidak perlu dinotifikasi sama sekali.
BENIGN_EXT_JS = (
    "['mp4','mkv','avi','mov','webm','flv','wmv','m4v','mpg','mpeg','3gp',"
    "'mp3','wav','flac','aac','ogg','m4a','opus','wma','mid','midi',"
    "'jpg','jpeg','png','gif','bmp','webp','heic','heif','svg','ico','tif',"
    "'tiff','raw','cr2','nef','psd',"
    "'pdf','txt','md','markdown','csv','tsv','rtf','doc','docx','xls','xlsx',"
    "'ppt','pptx','odt','ods','odp','epub','mobi',"
    "'json','xml','yaml','yml','toml','ini','conf','properties',"
    "'ttf','otf','woff','woff2','eot','srt','vtt','ass','sub']"
)


def read_file(p):
    with open(p) as f:
        return f.read().strip()


def api_get(url, api_key):
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": api_key})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def api_put(url, api_key, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="PUT",
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def get_node(nodes, name):
    for n in nodes:
        if n.get("name") == name:
            return n
    return None


# --------------------------------------------------------------------------
# 1. Ekstrak Alert -- tambah is_exec (bit eksekusi)
# --------------------------------------------------------------------------
EKSTRAK_SEV_OLD = """                    || /[\\\\/]etc[\\\\/]resolv\\.conf$/.test(lowerPath);
// patch:systemfile:v1"""

EKSTRAK_SEV_NEW = """                    || /[\\\\/]etc[\\\\/]resolv\\.conf$/.test(lowerPath);

// Bit eksekusi (khusus perm unix-style seperti rwxr-xr-x). Windows melaporkan
// perm normalisasi (rw-r--r--) sehingga .exe tertangkap lewat daftar ekstensi.
const permRaw = body?.syscheck?.perm_after
             ?? body?.syscheck?.perm_before
             ?? body?.data?.perm_after
             ?? '';
const permStr = Array.isArray(permRaw) ? permRaw.join('') : String(permRaw || '');
const is_exec = /^[-r][-w][-x][-r][-w][-x]/.test(permStr) && permStr.charAt(2) === 'x';
// patch:systemfile:v1"""

EKSTRAK_OUT_OLD = """    is_system_file:   is_system_file,
    model:            body?.model || 'Atria-Dawn-Preview',"""

EKSTRAK_OUT_NEW = """    is_system_file:   is_system_file,
    is_exec:          is_exec,
    model:            body?.model || 'Atria-Dawn-Preview',"""


def patch_ekstrak(js):
    if MARKER in js:
        return js, False
    for old in (EKSTRAK_SEV_OLD, EKSTRAK_OUT_OLD):
        if old not in js:
            raise SystemExit(
                "Pola 'Ekstrak Alert' tidak cocok, patch dibatalkan. Pola hilang:\n"
                + old
            )
    js = js.replace(EKSTRAK_SEV_OLD, EKSTRAK_SEV_NEW).replace(
        EKSTRAK_OUT_OLD, EKSTRAK_OUT_NEW
    )
    return js + "\n// patch:noindicator:v1", True


# --------------------------------------------------------------------------
# 2. Rangkum Hasil -- model severity baru (INFO + review + intel-only)
# --------------------------------------------------------------------------
RANGKUM_SEV_OLD = """let severity, severityIcon, severityLabel, silent;
if (!is_system_file && (malicious >= 20 || ruleLevel >= 12 || (mb_threat && malicious >= 5))) {
  severity = 'CRITICAL'; severityIcon = '🆘'; severityLabel = 'KRITIS'; silent = false;
} else if (!is_system_file && (otx_threat || mb_threat || misp_threat || malicious >= 5 || ruleLevel >= 7)) {
  severity = 'HIGH'; severityIcon = '🚨'; severityLabel = 'TINGGI'; silent = false;
} else {
  // File sistem: tetap diberitakan (bukan silent-failure) tapi tidak "TINGGI".
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG';
  silent = is_system_file ? false : true;
}

const should_active_response = !is_system_file && severity !== 'MEDIUM';"""

RANGKUM_SEV_NEW = """// Kebijakan severity baru (patch:noindicator:v1). Prinsip: label MALWARE hanya
// bila ada indikator nyata dari threat intel. rule_level FIM (550/554) TIDAK
// lagi menaikkan severity jalur file.
const _ext = String(alertData.filename || '').includes('.')
  ? String(alertData.filename).split('.').pop().toLowerCase()
  : '';
const is_exec = !!alertData.is_exec;
const vt_known = total > 0;
let _vtErrCode = '';
try { _vtErrCode = $('Scan VirusTotal').first().json?.error?.code || ''; } catch (e) {}
// 404 NotFoundError = hash memang belum dikenal. Error lain (429/5xx/timeout)
// = gagal verifikasi, jangan disenyapkan jadi INFO.
const vt_unverified = !cache_hit && !is_otx && !vt_known && !!_vtErrCode
  && _vtErrCode !== 'NotFoundError';

const RISKY_EXT = RISKY_EXT_PLACEHOLDER;
const BENIGN_EXT = BENIGN_EXT_PLACEHOLDER;
const is_risky_ext = RISKY_EXT.includes(_ext);
const is_benign_ext = BENIGN_EXT.includes(_ext);

const has_indicator = malicious >= 1 || suspicious >= 1 || mb_threat || otx_threat || misp_threat;
const unknown_exec_review = !is_system_file && !has_indicator && !vt_known
  && !vt_unverified && (is_risky_ext || is_exec);

let severity, severityIcon, severityLabel, silent, notify, decision;
if (is_system_file) {
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG';
  silent = false; decision = 'system-file';
} else if (malicious >= 20 || (mb_threat && malicious >= 5)) {
  severity = 'CRITICAL'; severityIcon = '🆘'; severityLabel = 'KRITIS';
  silent = false; decision = 'threat-critical';
} else if (mb_threat || otx_threat || misp_threat || malicious >= 5) {
  severity = 'HIGH'; severityIcon = '🚨'; severityLabel = 'TINGGI';
  silent = false; decision = 'threat-high';
} else if (has_indicator) {
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG';
  silent = true; decision = 'weak-indicator';
} else if (vt_unverified) {
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG';
  silent = true; decision = 'unverified';
} else if (unknown_exec_review) {
  severity = 'MEDIUM'; severityIcon = '⚠️'; severityLabel = 'SEDANG';
  silent = true; decision = 'unknown-executable';
} else {
  severity = 'INFO'; severityIcon = 'ℹ️'; severityLabel = 'INFO';
  silent = true; decision = 'no-indicator';
}
// Media/dokumen jinak tanpa indikator: jangan kirim notifikasi sama sekali.
notify = !(decision === 'no-indicator' && is_benign_ext);

const should_active_response = !is_system_file
  && (severity === 'CRITICAL' || severity === 'HIGH');"""

RANGKUM_OUT_OLD = """    silent,
    should_active_response,
    is_system_file,
    source: cache_hit ? 'vt-cache' : (is_otx ? 'otx' : 'vt'),"""

RANGKUM_OUT_NEW = """    silent,
    should_active_response,
    is_system_file,
    is_exec,
    ext: _ext,
    has_indicator,
    unknown_exec_review,
    is_benign_ext,
    vt_unverified,
    decision,
    notify,
    source: cache_hit ? 'vt-cache' : (is_otx ? 'otx' : 'vt'),"""


def patch_rangkum(js):
    if MARKER in js:
        return js, False
    for old in (RANGKUM_SEV_OLD, RANGKUM_OUT_OLD):
        if old not in js:
            raise SystemExit(
                "Pola 'Rangkum Hasil' tidak cocok, patch dibatalkan. Pola hilang:\n"
                + old
            )
    new_sev = RANGKUM_SEV_NEW.replace("RISKY_EXT_PLACEHOLDER", RISKY_EXT_JS).replace(
        "BENIGN_EXT_PLACEHOLDER", BENIGN_EXT_JS
    )
    js = js.replace(RANGKUM_SEV_OLD, new_sev).replace(RANGKUM_OUT_OLD, RANGKUM_OUT_NEW)
    return js + "\n// patch:noindicator:v1", True


# --------------------------------------------------------------------------
# 3. Build Payload -- judul + prompt INFO / PERLU REVIEW + flag notify
# --------------------------------------------------------------------------
BUILD_GUIDE_OLD = """} else {
  severityGuidance = 'Konteks: ancaman SEDANG informational. Berikan rekomendasi monitoring rutin.';
}"""

BUILD_GUIDE_NEW = """} else if (vtData.unknown_exec_review) {
  severityGuidance = 'Konteks: file eksekutabel dengan hash belum dikenal threat intel. Minta analis memverifikasi asal file sebelum dijalankan.';
} else if (severity === 'INFO') {
  severityGuidance = 'Konteks: tidak ada indikasi malware dari threat intel. Nyatakan file tidak menunjukkan indikasi berbahaya dan sarankan verifikasi manual hanya bila perlu.';
} else {
  severityGuidance = 'Konteks: ancaman SEDANG informational. Berikan rekomendasi monitoring rutin.';
}"""

BUILD_TITLE_OLD = """} else {
  alertTitle = 'MALWARE TERDETEKSI';
  targetLabel = 'File';
  chainCmd = '';
  prompt ="""

BUILD_TITLE_NEW = """} else if (vtData.severity === 'INFO') {
  // Tanpa indikator apa pun: bukan vonis malware, murni informasional.
  alertTitle = 'TANPA INDIKASI MALWARE';
  targetLabel = 'File';
  chainCmd = '';
  prompt =
    'You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter markdown seperti asterisk underscore backtick atau bracket.\\n\\n' +
    'File: ' + filename + '\\n' +
    'Hash: ' + hashDisplay + '\\n' +
    vtPromptLine + '\\n\\n' +
    'Tidak ada satu pun indikator malware dari threat intel (VirusTotal/MalwareBazaar/OTX) maupun rule deteksi. Nyatakan bahwa file ini TIDAK menunjukkan indikasi berbahaya, JANGAN sebut malware, dan sarankan verifikasi manual hanya bila pengguna ragu. JANGAN menyarankan isolasi atau karantina.';
} else if (vtData.unknown_exec_review) {
  // Hash belum dikenal VT tapi eksekutabel/berisiko: perlu review manual.
  alertTitle = 'FILE PERLU REVIEW';
  targetLabel = 'File';
  chainCmd = '';
  prompt =
    'You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter markdown seperti asterisk underscore backtick atau bracket.\\n\\n' +
    'File: ' + filename + '\\n' +
    'Hash: ' + hashDisplay + '\\n' +
    vtPromptLine + '\\n\\n' +
    'File ini berekstensi/ber-flag eksekutabel tetapi hash-nya belum dikenal threat intel sehingga belum bisa dipastikan. Nyatakan bahwa file PERLU REVIEW manual (cek asal, tanda tangan, izin eksekusi), BUKAN vonis malware. JANGAN menyarankan isolasi host otomatis.';
} else {
  alertTitle = 'MALWARE TERDETEKSI';
  targetLabel = 'File';
  chainCmd = '';
  prompt ="""

BUILD_OUT_OLD = """    target_label: targetLabel,
    chain_cmd: chainCmd,"""

BUILD_OUT_NEW = """    target_label: targetLabel,
    chain_cmd: chainCmd,
    decision: isChain ? 'chain' : (vtData.decision || ''),
    notify: isChain ? true : (vtData.notify !== false),"""


def patch_build(js):
    if MARKER in js:
        return js, False
    for old in (BUILD_GUIDE_OLD, BUILD_TITLE_OLD, BUILD_OUT_OLD):
        if old not in js:
            raise SystemExit(
                "Pola 'Build Payload' tidak cocok, patch dibatalkan. Pola hilang:\n"
                + old
            )
    js = (
        js.replace(BUILD_GUIDE_OLD, BUILD_GUIDE_NEW)
        .replace(BUILD_TITLE_OLD, BUILD_TITLE_NEW)
        .replace(BUILD_OUT_OLD, BUILD_OUT_NEW)
    )
    return js + "\n// patch:noindicator:v1", True


PATCHERS = [
    (EKSTRAK, patch_ekstrak),
    (RANGKUM, patch_rangkum),
    (BUILD, patch_build),
]

NOTIFY_IF_NODE = {
    "name": NOTIFY_IF,
    "type": "n8n-nodes-base.if",
    "typeVersion": 2.3,
    "position": [-1400, 336],
    "parameters": {
        "conditions": {
            "options": {"caseSensitive": True, "typeValidation": "loose", "version": 2},
            "conditions": [
                {
                    "id": "cond-notify",
                    "leftValue": "={{ $json.notify }}",
                    "rightValue": True,
                    "operator": {"type": "boolean", "operation": "equals"},
                }
            ],
            "combinator": "and",
        },
        "options": {},
    },
}


def apply_patches(nodes):
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


def apply_wiring(nodes, conns):
    """Sisipkan gate 'Perlu Notifikasi?' antara Build Payload dan downstream."""
    already_gated = get_node(nodes, NOTIFY_IF) is not None and any(
        t.get("node") == NOTIFY_IF
        for b in conns.get(BUILD, {}).get("main", [])
        for t in b
    )
    if already_gated:
        if conns.get(NOTIFY_IF) is None:
            raise SystemExit(
                "Node '" + NOTIFY_IF + "' ada & terhubung dari Build Payload "
                "tetapi koneksi keluarnya hilang; periksa manual, patch dibatalkan."
            )
        return False

    build_targets = [t for b in conns.get(BUILD, {}).get("main", []) for t in b]
    if not build_targets:
        raise SystemExit(
            "Build Payload tidak punya target downstream; tidak bisa menyisipkan "
            "gate notifikasi. Patch dibatalkan."
        )
    log_targets = [t for t in build_targets if t.get("node") == "Log ke Fleet"]
    notify_targets = [t for t in build_targets if t.get("node") != "Log ke Fleet"]
    if not notify_targets:
        raise SystemExit(
            "Build Payload hanya mengarah ke Log ke Fleet; tidak ada jalur "
            "notifikasi untuk digate. Patch dibatalkan."
        )

    want_build = {
        "main": [
            [{"node": NOTIFY_IF, "type": "main", "index": 0}] + log_targets
        ]
    }
    want_if = {"main": [notify_targets]}

    changed = False
    if get_node(nodes, NOTIFY_IF) is None:
        nodes.append(json.loads(json.dumps(NOTIFY_IF_NODE)))
        print("  Node '" + NOTIFY_IF + "' ditambahkan.")
        changed = True
    if conns.get(BUILD) != want_build:
        conns[BUILD] = want_build
        print("  Rewire: " + BUILD + " -> " + NOTIFY_IF)
        changed = True
    if conns.get(NOTIFY_IF) != want_if:
        conns[NOTIFY_IF] = want_if
        print(
            "  Rewire: "
            + NOTIFY_IF
            + " true -> "
            + ", ".join(t["node"] for t in notify_targets)
        )
        changed = True
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
    conns = wf.get("connections", {})
    print("  Node saat ini: " + str(len(nodes)))

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(
        BACKUP_DIR,
        "deteksi-malware-live-noindicator-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = apply_patches(nodes)
    for name in changed:
        print("  Diubah: " + name)
    wiring_changed = apply_wiring(nodes, conns)

    if get_node(nodes, "Send Telegram Info") is not None:
        print(
            "  CATATAN: node 'Send Telegram Info' masih ada di workflow -- periksa "
            "apakah jalur MEDIUM memakai node ini (template-nya perlu ikut di-update)."
        )

    if not changed and not wiring_changed:
        print("  Semua node sudah ter-patch (idempoten).")

    if args.dry_run:
        print("[DRY-RUN] Node diubah: " + (", ".join(changed) or "(tidak ada)"))
        return
    if not changed and not wiring_changed:
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
        print(
            "Selesai. Aktif: "
            + str(result.get("active"))
            + " | node: "
            + str(len(result.get("nodes", [])))
        )
    except urllib.error.HTTPError as e:
        sys.exit("Gagal PUT: " + str(e.code) + " " + e.read().decode()[:300])


if __name__ == "__main__":
    main()
