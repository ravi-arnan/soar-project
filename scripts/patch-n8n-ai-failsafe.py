#!/usr/bin/env python3
"""Bikin node AI (dan notifikasi Telegram) gagal-aman di workflow live
'Deteksi Malware' (n8n).

Latar (temuan 2026-10-04): kadang notifikasi Telegram keluar dengan semua
field `undefined`:

    undefined undefined - undefined
    📁 undefined:
    📂 Path:
    🔍 Hash: undefined
    ...

Penyebab: rantai live `Build Payload -> AI Generate -> Send Telegram Alert`.
Node 'AI Generate' (Code, panggil Atria API) memakai
`onError: continueRegularOutput`. Saat panggilan AI gagal (timeout 60s,
5xx/429, `ATRIA_API_KEY` kosong, atau respons tanpa
`choices[0].message.content`), n8n TIDAK meneruskan `$json` dari Build
Payload -- outputnya jadi item error. 'Send Telegram Alert' membaca SEMUA
field dari `$json` -> semuanya undefined. Itu sebabnya muncul 'kadang' saja
(hanya saat AI gagal).

Patch ini dua lapis:

  1. 'AI Generate' -> bungkus panggilan HTTP dengan try/catch; SELALU
     `return [{ json: { ...$json, ai_response, llm_error } }]`. Gagal AI hanya
     membuat bagian analisis jadi teks fallback, field lain tetap utuh.
  2. 'Send Telegram Alert' -> field terstruktur (file/path/severity/hash/agent/
     waktu/dll) diambil dari node sumber `$('Build Payload')`, bukan `$json`,
     plus fallback `?? ''`. Jadi walau `$json` rusak, pesan tetap utuh.

Cara pakai (jalankan di ravi-debian, n8n terjangkau):
  python3 scripts/patch-n8n-ai-failsafe.py \
    --n8n-url http://127.0.0.1:5678 \
    --api-key-file /tmp/n8n_api_key.txt [--dry-run]

Idempoten (marker `patch:aifailsafe:v1` di kode AI + deteksi path
`$('Build Payload')` di template Telegram). Backup otomatis ke backups/.
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
MARKER = "patch:aifailsafe:v1"

AI_NAME = "AI Generate"
TG_NAME = "Send Telegram Alert"

# Marker struktural di template Telegram (bukti lapis 2 sudah diterapkan).
TG_MARKER = "$('Build Payload').first().json"

# Lapis 1: node AI Generate gagal-aman. Sama seperti versi live (Atria API,
# model Atria-Dawn-Preview) tetapi dibungkus try/catch + fallback.
AI_JSCODE = """const apiKey = $env.ATRIA_API_KEY;
const FALLBACK = 'Analisis AI tidak tersedia saat ini karena layanan AI gagal atau tidak dikonfigurasi.';

let clean = '';
let errMsg = null;

if (!apiKey) {
  errMsg = 'ATRIA_API_KEY belum di-set di n8n env';
} else {
  const body = {
    model: 'Atria-Dawn-Preview',
    max_tokens: 1500,
    temperature: 0.3,
    messages: [{ role: 'user', content: $json.prompt }],
  };
  try {
    const resp = await this.helpers.httpRequest({
      method: 'POST',
      url: 'https://api.atria-asi.ai/v1/chat/completions',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + apiKey,
      },
      body: JSON.stringify(body),
      timeout: 60000,
    });
    const text = resp?.choices?.[0]?.message?.content || '';
    clean = text
      .replace(/<think>[\\s\\S]*?<\\/think>/g, '')
      .replace(/[*_`\\[\\]()]/g, '')
      .replace(/\\n\\n+/g, '\\n')
      .trim();
  } catch (e) {
    errMsg = String((e && e.message) || e).slice(0, 200);
  }
}

return [{ json: { ...$json, ai_response: clean || FALLBACK, llm_error: errMsg, llm_model: 'Atria-Dawn-Preview' } }];
// patch:aifailsafe:v1"""

# Lapis 2: template Telegram ambil field terstruktur dari 'Build Payload'
# (bukan $json), plus fallback `?? ''`. Field AI tetap dari $json output
# 'AI Generate'. Escaping Markdown dipertahankan seperti versi live.
TG_TEXT = """={{ $('Build Payload').first().json.severityIcon + " *" + $('Build Payload').first().json.severityLabel + " - " + $('Build Payload').first().json.alert_title + "*\\n\\n📁 " + $('Build Payload').first().json.target_label + ": " + ((($('Build Payload').first().json.filename ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1')) + "\\n📂 Path: " + ((($('Build Payload').first().json.filepath ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1')) + ($('Build Payload').first().json.chain_cmd ? ("\\n💻 Command: " + ((($('Build Payload').first().json.chain_cmd ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1'))) : "") + "\\n🔍 Hash: `" + ($('Build Payload').first().json.hash_display ?? 'Tidak tersedia') + "`" + "\\n🛡️ Severity: " + ($('Build Payload').first().json.severity ?? '') + " level " + ($('Build Payload').first().json.rule_level ?? '') + "\\n📊 Deteksi: " + ($('Build Payload').first().json.detection_text ?? '') + "\\n🖥️ Agent: " + ((($('Build Payload').first().json.agent_name ?? '') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1')) + "\\n🕐 Waktu: " + ($('Build Payload').first().json.timestamp ?? '') + "\\n\\n🤖 *Analisis AI:*\\n" + (($json.ai_response ?? 'Analisis AI tidak tersedia.') + '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1') + "\\n\\n" + ($('Build Payload').first().json.vt_footer ?? '') }}"""


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


def patch_node(nodes, name, js, marker):
    n = get_node(nodes, name)
    if n is None:
        raise SystemExit("Node '" + name + "' tidak ditemukan.")
    cur = n.get("parameters", {}).get("jsCode", "")
    if marker in cur:
        return False
    n["parameters"]["jsCode"] = js
    return True


def patch_telegram(nodes, name, text, marker):
    n = get_node(nodes, name)
    if n is None:
        raise SystemExit("Node '" + name + "' tidak ditemukan.")
    cur = n.get("parameters", {}).get("text", "")
    if marker in cur:
        return False
    n["parameters"]["text"] = text
    return True


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
        "deteksi-malware-live-ai-failsafe-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = []
    if patch_node(nodes, AI_NAME, AI_JSCODE, MARKER):
        changed.append(AI_NAME)
    if patch_telegram(nodes, TG_NAME, TG_TEXT, TG_MARKER):
        changed.append(TG_NAME)

    if args.dry_run:
        print("[DRY-RUN] Node akan dipatch: " + str(changed))
        return

    if not changed:
        print("Tidak ada perubahan.")
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
        print("Selesai. Aktif: " + str(result.get("active")))
    except urllib.error.HTTPError as e:
        print("GAGAL PUT: " + str(e.code) + " " + e.read().decode()[:300])
        sys.exit(1)


if __name__ == "__main__":
    main()
