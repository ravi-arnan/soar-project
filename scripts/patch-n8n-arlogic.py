#!/usr/bin/env python3
"""Rapikan logika Active Response di workflow live 'Deteksi Malware' (n8n).

Latar (temuan 2026-09-28): node 'Trigger Active Response' masih mengirim
`!firewall-drop` dengan `srcip` (default 0.0.0.0) -- konsepnya tidak nyambung
untuk alert FILE (FIM). Selain itu `status` selalu 'blocked'/'failed' sehingga
guard `ar.status !== 'isolated'` di 'Fleet Quarantine' selalu true -> karantina
fleet selalu dicoba, dan deteksi sukses AR tidak pernah tercapai.

Patch ini mengganti dua node:

  1. 'Trigger Active Response' -> `!quarantine-file` dengan filepath, dan
     status yang benar: sukses bila Wazuh mengembalikan `{error: 0}` ATAU
     bentuk AR sukses tanpa `error` dan `failed_items` kosong. Sukses =>
     'isolated'; HTTP throw / error non-zero => 'failed'.
  2. 'Fleet Quarantine' -> guard `ar.status !== 'isolated'` kini bermakna;
     file sistem tetap dilindungi; header Authorization ditambah bila env
     FLEET_COMMAND_TOKEN ada (harmless untuk fleet-monitor versi lama).

Cara pakai (jalankan di nixbox, n8n terjangkau via Tailscale 100.73.91.17):
  python3 scripts/patch-n8n-arlogic.py \
    --n8n-url http://100.73.91.17:5678 \
    --api-key-file /tmp/n8n_api_key.txt [--dry-run]

Idempoten (marker `patch:arlogic:v1`), backup otomatis ke backups/.
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
MARKER = "patch:arlogic:v1"

AR_NAME = "Trigger Active Response"
FQ_NAME = "Fleet Quarantine"

AR_JSCODE = """const token = $('Get Wazuh Token').item.json.data.token;
const agentId = $('Ekstrak Alert').item.json.agent_id || '001';
const filepath = $('Ekstrak Alert').item.json.filepath;

let response;
try {
  response = await this.helpers.httpRequest({
    method: 'PUT',
    url: 'https://172.17.0.1:55000/active-response?agents_list=' + agentId + '&wait_for_complete=true',
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: '!quarantine-file', arguments: [filepath] }),
    rejectUnauthorized: false, timeout: 30000
  });
} catch (e) {
  response = { error: 'exception', detail: String((e && e.message) || e).slice(0, 200) };
}

// Wazuh 4.x: sukses = {error: 0} ATAU bentuk AR sukses (tanpa field `error`
// dan failed_items kosong). Sukses => status 'isolated'; sisanya 'failed'.
const wazuhOk = response && (
  response.error === 0 ||
  (response.error === undefined &&
    (!response.failed_items || response.failed_items.length === 0) &&
    (response.total_failed_items === undefined || response.total_failed_items === 0))
);

return [{ json: { active_response: response, quarantined: filepath, agent_id: agentId, status: wazuhOk ? 'isolated' : 'failed' } }];
// patch:arlogic:v1"""

FQ_JSCODE = """// Fallback karantina via fleet (agen Rust bukan agent Wazuh, Wazuh API balas
// 1701 untuk id itu). Hanya jalan kalau Wazuh AR gagal.
const ar = $('Trigger Active Response').first().json;
const alert = $('Ekstrak Alert').first().json;
const sysFile = !!alert.is_system_file;
const commandToken = $env.FLEET_COMMAND_TOKEN;
let fleet = { attempted: false, result: sysFile ? 'skipped-system-file' : 'skipped-wazuh-ok' };
if (!sysFile && ar.status !== 'isolated') {
  try {
    const headers = { 'Content-Type': 'application/json' };
    if (commandToken) headers['Authorization'] = 'Bearer ' + commandToken;
    const resp = await this.helpers.httpRequest({
      method: 'POST',
      url: 'http://host.docker.internal:8080/api/commands',
      headers: headers,
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
return [{ json: { ...ar, fleet_quarantine: fleet } }];
// patch:systemfile:v1
// patch:arlogic:v1"""


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://100.73.91.17:5678")
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
        "deteksi-malware-live-arlogic-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = []
    if patch_node(nodes, AR_NAME, AR_JSCODE, MARKER):
        changed.append(AR_NAME)
    if patch_node(nodes, FQ_NAME, FQ_JSCODE, MARKER):
        changed.append(FQ_NAME)

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
