#!/usr/bin/env python3
"""Patch Dedup lapis-2 ke workflow live 'Deteksi Malware' di n8n.

Latar (janji board #18): agent sudah debounce 60 dtk per path, tapi kalau
alert yang sama masuk 2x cepat (retry jaringan, double-POST webhook, dua
event FIM berurutan untuk file+hash yang sama), n8n tetap scan VT 2x dan
kirim Telegram 2x. Dedup lapis-1 di agent tidak menutup jalur ini.

Patch ini menyisipkan node Code 'Dedup Alert' di titik:

  Ekstrak Alert -> Dedup Alert -> Scan VirusTotal

Node mengingat kunci `agent_id|hash|filepath` di workflow staticData
(antar-eksekusi). Item yang kuncinya terlihat dalam WINDOW_SECS terakhir
di-drop (return kosong = cabang berhenti). Selain itu fail-open: kalau
jsCode error, item diteruskan agar deteksi tidak mati karena bug dedup.

Cara pakai (jalankan di nixbox, n8n live terjangkau via LAN):
  python3 scripts/patch-n8n-dedup.py \
    --n8n-url http://192.168.1.47:5678 \
    --api-key-file /tmp/n8n_api_key.txt [--dry-run]

Idempoten: aman dijalankan berulang. Backup otomatis ke
backups/deteksi-malware-live-dedup-*.json
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
DEDUP_NAME = "Dedup Alert"
PREV_NAME = "Ekstrak Alert"
NEXT_NAME = "Scan VirusTotal"
WINDOW_SECS = 300  # ponytail: cukup untuk retry/double-POST; kalau butuh
# lebih lama (misal agent kirim ulang >5 mnt), naikkan konstanta ini saja.

DEDUP_JSCODE = (
    """// Dedup lapis-2 via claim-check atomik di fleet-monitor (POST /api/seen).
// state disimpan di server karena workflow staticData n8n tidak persist
// antar-eksekusi di versi ini (terbukti uji 19 Sep: 3 POST identik lolos
// semua). Fail-open: error apa pun -> teruskan item (deteksi tidak boleh
// mati karena bug dedup / fleet down).
const alert = $('Ekstrak Alert').first().json;
try {
  const resp = await this.helpers.httpRequest({
    method: 'POST',
    url: 'http://host.docker.internal:8080/api/seen',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      key: [alert.agent_id, alert.rule_id, alert.hash, alert.filepath].join('|'),
      window_secs: %d,
    }),
    timeout: 10000,
  });
  if (resp && resp.duplicate) return [];  // duplikat: hentikan cabang ini
} catch (e) { /* fail-open, teruskan */ }
return [{ json: alert }];"""
    % WINDOW_SECS
)


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
        "deteksi-malware-live-dedup-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = False

    prev = get_node(nodes, PREV_NAME)
    if prev is None:
        raise SystemExit("Node 'Ekstrak Alert' tidak ditemukan.")

    dedup = get_node(nodes, DEDUP_NAME)
    if dedup is None:
        pos = prev.get("position", [1000, 400])
        node = {
            "name": DEDUP_NAME,
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "position": [pos[0] + 220, pos[1]],
            "parameters": {"mode": "runOnceForAllItems", "jsCode": DEDUP_JSCODE},
            "onError": "continueRegularOutput",
        }
        nodes.append(node)
        print("  Node 'Dedup Alert' ditambahkan.")
        changed = True
    elif dedup.get("parameters", {}).get("jsCode") != DEDUP_JSCODE:
        dedup["parameters"]["jsCode"] = DEDUP_JSCODE
        print("  Node 'Dedup Alert' diperbarui.")
        changed = True
    else:
        print("  Node 'Dedup Alert' sudah sesuai.")

    want_prev = {"main": [[{"node": DEDUP_NAME, "type": "main", "index": 0}]]}
    if conns.get(PREV_NAME) != want_prev:
        conns[PREV_NAME] = want_prev
        print("  Rewire: Ekstrak Alert -> Dedup Alert")
        changed = True

    want_dedup = {"main": [[{"node": NEXT_NAME, "type": "main", "index": 0}]]}
    if conns.get(DEDUP_NAME) != want_dedup:
        conns[DEDUP_NAME] = want_dedup
        print("  Rewire: Dedup Alert -> Scan VirusTotal")
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
