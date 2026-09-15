#!/usr/bin/env python3
"""Patch AI Generate (Experiential/deepseek-v4-flash) ke workflow live
'Deteksi Malware' di n8n (via public API).

Latar: node Preload Model + Ollama Generate dalam keadaan disabled dan service
Ollama mati sehingga "Analisis AI" di Telegram selalu kosong. Patch ini
menyisipkan jalur LLM eksternal (Anthropic-compatible):

  Build Payload -> AI Generate -> Send Telegram Alert

AI Generate memanggil Experiential API (model deepseek-v4-flash, gratis),
membaca key dari $env.EXPERIENTIAL_API_KEY (env container n8n). Output field
`ai_response`; template Telegram diperbarui dari `ollama_response`.

Cara pakai (jalankan DI ravi-debian):
  python3 scripts/patch-n8n-ai-generate.py \
    --n8n-url http://127.0.0.1:5678 \
    --api-key-file /tmp/n8n_api_key.txt [--dry-run]

Idempoten: aman dijalankan berulang. Backup otomatis ke
backups/deteksi-malware-live-ai-*.json
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
AI_NAME = "AI Generate"
TG_NAME = "Send Telegram Alert"

AI_JSCODE = """const apiKey = $env.EXPERIENTIAL_API_KEY;
if (!apiKey) throw new Error('EXPERIENTIAL_API_KEY belum di-set di n8n env');

const body = {
  model: 'deepseek-v4-flash',
  max_tokens: 300,
  messages: [{ role: 'user', content: $json.prompt }],
};

const resp = await this.helpers.httpRequest({
  method: 'POST',
  url: 'https://api.experientiallabs.ai/v1/messages',
  headers: {
    'Content-Type': 'application/json',
    'x-api-key': apiKey,
    'anthropic-version': '2023-06-01',
  },
  body: JSON.stringify(body),
  timeout: 60000,
});

let text = '';
const parts = resp?.content || [];
for (const p of parts) {
  if (p && p.type === 'text' && p.text) text += p.text;
}
if (!text) text = JSON.stringify(resp).slice(0, 500);
const clean = text
  .replace(/<think>[\\s\\S]*?<\\/think>/g, '')
  .replace(/[*_`\\[\\]()]/g, '')
  .replace(/\\n\\n+/g, '\\n')
  .trim();

return [{ json: { ...$json, ai_response: clean, llm_model: 'deepseek-v4-flash' } }];"""

AI_NODE = {
    "name": AI_NAME,
    "type": "n8n-nodes-base.code",
    "typeVersion": 2,
    "position": [1770, 448],
    "parameters": {"mode": "runOnceForAllItems", "jsCode": AI_JSCODE},
    "onError": "continueRegularOutput",
}


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
        "deteksi-malware-live-ai-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = False

    ai = get_node(nodes, AI_NAME)
    if ai is None:
        nodes.append(dict(AI_NODE))
        print("  Node 'AI Generate' ditambahkan.")
        changed = True
    elif ai.get("parameters", {}).get("jsCode") != AI_JSCODE:
        ai["parameters"]["jsCode"] = AI_JSCODE
        print("  Node 'AI Generate' diperbarui.")
        changed = True
    else:
        print("  Node 'AI Generate' sudah sesuai.")

    bp = conns.get("Build Payload", {}).get("main", [[]])
    if not (bp and bp[0] and bp[0][0].get("node") == AI_NAME):
        conns["Build Payload"] = {
            "main": [[{"node": AI_NAME, "type": "main", "index": 0}]]
        }
        print("  Rewire: Build Payload -> AI Generate")
        changed = True

    ac = conns.get(AI_NAME, {}).get("main", [])
    want = [[{"node": TG_NAME, "type": "main", "index": 0}]]
    if ac != want:
        conns[AI_NAME] = {"main": want}
        print("  Rewire: AI Generate -> Send Telegram Alert")
        changed = True

    tg = get_node(nodes, TG_NAME)
    if tg is None:
        raise SystemExit("Node 'Send Telegram Alert' tidak ditemukan.")
    text = tg.get("parameters", {}).get("text", "")
    if "$json.ollama_response" in text:
        tg["parameters"]["text"] = text.replace(
            "$json.ollama_response", "$json.ai_response"
        )
        print("  Telegram template: ollama_response -> ai_response")
        changed = True
    else:
        print("  Telegram template: sudah pakai ai_response.")

    if args.dry_run:
        print("[DRY-RUN] Perubahan terdeteksi: " + str(changed))
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
