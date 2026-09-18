#!/usr/bin/env python3
"""Patch Fleet Quarantine ke workflow live 'Deteksi Malware' di n8n.

Latar: alert FIM datang dari agen Rust (id 002/003) yang POST langsung ke
webhook n8n dengan format mirip Wazuh. Node 'Trigger Active Response' lalu
memanggil Wazuh API !quarantine-file untuk agent itu, tapi manager Wazuh
tidak mengenal id Rust -> 1701 "Agent does not exist" -> file tidak
dikarantina.

Patch ini menyisipkan node Code 'Fleet Quarantine' setelah Trigger AR:

  Trigger Active Response -> Fleet Quarantine -> Build Payload

Kalau status Wazuh AR != 'isolated', node antrekan perintah quarantine ke
fleet-monitor (POST /api/commands, di-poll agen Rust tiap heartbeat dan
dieksekusi lokal via do_quarantine). Selalu pass-through agar Telegram tetap
terkirim; onError continue.

Cara pakai (jalankan di nixbox, n8n live terjangkau via LAN):
  python3 scripts/patch-n8n-fleet-quarantine.py \
    --n8n-url http://192.168.1.47:5678 \
    --api-key-file /tmp/n8n_api_key.txt [--dry-run]

Idempoten: aman dijalankan berulang. Backup otomatis ke
backups/deteksi-malware-live-fleet-*.json
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
FQ_NAME = "Fleet Quarantine"
AR_NAME = "Trigger Active Response"
NEXT_NAME = "Build Payload"

FQ_JSCODE = """// Fallback karantina via fleet (agen Rust 002/003 bukan agent Wazuh,
// Wazuh API balas 1701 untuk id itu). Hanya jalan kalau Wazuh AR gagal.
const ar = $('Trigger Active Response').first().json;
const alert = $('Ekstrak Alert').first().json;
let fleet = { attempted: false, result: 'skipped-wazuh-ok' };
if (ar.status !== 'isolated') {
  try {
    const resp = await this.helpers.httpRequest({
      method: 'POST',
      url: 'http://host.docker.internal:8080/api/commands',
      headers: { 'Content-Type': 'application/json' },
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
    ap.add_argument("--n8n-url", default="http://192.168.1.47:5678")
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
        "deteksi-malware-live-fleet-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = False

    ar = get_node(nodes, AR_NAME)
    if ar is None:
        raise SystemExit("Node 'Trigger Active Response' tidak ditemukan.")

    fq = get_node(nodes, FQ_NAME)
    if fq is None:
        pos = ar.get("position", [1500, 400])
        node = {
            "name": FQ_NAME,
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "position": [pos[0] + 220, pos[1]],
            "parameters": {"mode": "runOnceForAllItems", "jsCode": FQ_JSCODE},
            "onError": "continueRegularOutput",
        }
        nodes.append(node)
        print("  Node 'Fleet Quarantine' ditambahkan.")
        changed = True
    elif fq.get("parameters", {}).get("jsCode") != FQ_JSCODE:
        fq["parameters"]["jsCode"] = FQ_JSCODE
        print("  Node 'Fleet Quarantine' diperbarui.")
        changed = True
    else:
        print("  Node 'Fleet Quarantine' sudah sesuai.")

    want_ar = {"main": [[{"node": FQ_NAME, "type": "main", "index": 0}]]}
    if conns.get(AR_NAME) != want_ar:
        conns[AR_NAME] = want_ar
        print("  Rewire: Trigger Active Response -> Fleet Quarantine")
        changed = True

    want_fq = {"main": [[{"node": NEXT_NAME, "type": "main", "index": 0}]]}
    if conns.get(FQ_NAME) != want_fq:
        conns[FQ_NAME] = want_fq
        print("  Rewire: Fleet Quarantine -> Build Payload")
        changed = True

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
