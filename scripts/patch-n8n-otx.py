#!/usr/bin/env python3
"""Patch OTX fallback ke workflow live 'Deteksi Malware' di n8n (via public API).

Struktur live (dengan cache VT / MB / fail-open fallback):
  Ekstrak Alert -> Cek Cache VT -> Cache Hit?
      hit  -> MalwareBazaar Lookup -> Rangkum Hasil
      miss -> Scan VirusTotal -> Simpan Cache VT -> VT OK?
                 true  -> MalwareBazaar Lookup -> Rangkum Hasil
                 false -> OTX Lookup -> MalwareBazaar Lookup -> Rangkum Hasil

Keamanan Kredensial (Milestone M5):
  OTX API Key dikelola aman via credential tipe 'httpHeaderAuth' ('OTX API Key'),
  BUKAN ditulis mentah (inline) pada parameter node headerParameters.
  Jika node OTX lama ditemukan memiliki API key plaintext, script akan
  membersihkannya (sanitasi) dan menyambungkan credential resmi.

Cara pakai (jalankan DI ravi-debian):
  python3 scripts/patch-n8n-otx.py \\
    --n8n-url http://127.0.0.1:5678 \\
    --api-key-file /tmp/n8n_api_key.txt \\
    [--otx-key <OTX_API_KEY> | --otx-cred-id <CRED_ID>] [--dry-run]

Idempoten: aman dijalankan berulang. Backup workflow live disimpan otomatis
ke backups/deteksi-malware-live-otx-*.json
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
VT_OK_NAME = "VT OK?"
OTX_NAME = "OTX Lookup"
SUMMARY_NAME = "Rangkum Hasil"
OTX_CRED_NAME_DEFAULT = "OTX API Key"
OTX_CRED_ALIASES = ("OTX API Key", "OTX Header Auth")


def read_file(p):
    with open(p) as f:
        return f.read().strip()


def api_get(url, api_key):
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": api_key})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def api_send(url, api_key, payload, method="POST"):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def api_put(url, api_key, payload):
    return api_send(url, api_key, payload, method="PUT")


def get_node(nodes, name):
    for n in nodes:
        if n.get("name") == name:
            return n
    return None


VT_OK_NODE = {
    "name": VT_OK_NAME,
    "type": "n8n-nodes-base.if",
    "typeVersion": 2.3,
    "position": [250, 300],
    "parameters": {
        "conditions": {
            "options": {"caseSensitive": True, "typeValidation": "loose", "version": 2},
            "conditions": [
                {
                    "id": "cond-vt-ok",
                    "leftValue": "={{ $json.data ? true : false }}",
                    "rightValue": True,
                    "operator": {"type": "boolean", "operation": "equals"},
                }
            ],
            "combinator": "and",
        },
        "options": {},
    },
}


def otx_node(cred_id, cred_name=OTX_CRED_NAME_DEFAULT):
    """Buat definisi node OTX Lookup yang memakai credential terkelola httpHeaderAuth."""
    return {
        "name": OTX_NAME,
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.4,
        "position": [250, 480],
        "parameters": {
            "method": "GET",
            "url": "=https://otx.alienvault.com/api/v1/indicators/file/{{ $('Ekstrak Alert').first().json.hash }}",
            "authentication": "genericCredentialType",
            "genericAuthType": "httpHeaderAuth",
            "options": {
                "response": {"response": {"fullResponse": False, "neverError": True}},
                "timeout": 15000,
            },
        },
        "credentials": {
            "httpHeaderAuth": {
                "id": str(cred_id),
                "name": cred_name,
            }
        },
        "onError": "continueRegularOutput",
    }


def sanitize_otx_node(node, cred_id, cred_name=OTX_CRED_NAME_DEFAULT):
    """Bersihkan API key inline dari parameter node OTX dan sambungkan credential terkelola."""
    changed = False
    params = node.setdefault("parameters", {})
    if params.get("authentication") != "genericCredentialType":
        params["authentication"] = "genericCredentialType"
        changed = True
    if params.get("genericAuthType") != "httpHeaderAuth":
        params["genericAuthType"] = "httpHeaderAuth"
        changed = True
    if "headerParameters" in params:
        del params["headerParameters"]
        changed = True
    if "sendHeaders" in params:
        del params["sendHeaders"]
        changed = True
    creds = node.setdefault("credentials", {})
    otx_cred = creds.get("httpHeaderAuth", {})
    if otx_cred.get("id") != str(cred_id) or otx_cred.get("name") != cred_name:
        creds["httpHeaderAuth"] = {"id": str(cred_id), "name": cred_name}
        changed = True
    return changed


def ensure_otx_credential(base, api_key, otx_key=None, cred_id=None, cred_name=OTX_CRED_NAME_DEFAULT, dry_run=False):
    """Reuse credential 'OTX API Key' / 'OTX Header Auth' bila ada; buat bila belum."""
    if cred_id:
        return str(cred_id), cred_name

    creds = api_get(base.rstrip("/") + "/api/v1/credentials?limit=250", api_key).get("data", [])
    for c in creds:
        if c.get("name") in (cred_name, *OTX_CRED_ALIASES) and c.get("type") == "httpHeaderAuth":
            print("  Credential '{}' sudah ada (id {}).".format(c.get("name"), c["id"]))
            return str(c["id"]), c.get("name")

    if not otx_key:
        raise ValueError(
            f"Credential '{cred_name}' belum ada di n8n, dan --otx-key tidak diberikan untuk membuatnya."
        )

    if dry_run:
        print(f"  [DRY-RUN] akan membuat credential '{cred_name}'.")
        return "dry-run-otx-id", cred_name

    created = api_send(
        base.rstrip("/") + "/api/v1/credentials",
        api_key,
        {
            "name": cred_name,
            "type": "httpHeaderAuth",
            "data": {"name": "X-OTX-API-KEY", "value": otx_key},
        },
        "POST",
    )
    print("  Credential '{}' dibuat (id {}).".format(cred_name, created["id"]))
    return str(created["id"]), cred_name


OLD_HEAD = """const data = $input.first().json;
const stats = data.data?.attributes?.last_analysis_stats || {};"""

NEW_HEAD = """const data = $input.first().json;
// OTX fallback: input dari OTX Lookup berbentuk {pulse_info:{count,...}}, bukan VT
const is_otx = !!data.pulse_info;
const stats = is_otx ? {} : (data.data?.attributes?.last_analysis_stats || {});
const otx_pulses = is_otx ? (data.pulse_info?.count || 0) : 0;
const otx_threat = is_otx && otx_pulses > 0;"""

OLD_TOTAL = "const total = malicious + suspicious + undetected;"
NEW_TOTAL = """const total = malicious + suspicious + undetected;
const detection_ratio = is_otx ? (otx_pulses + ' pulse OTX') : (malicious + '/' + total);"""

OLD_RATIO = "    detection_ratio: `${malicious}/${total}`,"
NEW_RATIO = "    detection_ratio,"

OLD_HIGH = "} else if (malicious >= 5 || ruleLevel >= 7) {"
NEW_HIGH = "} else if (otx_threat || malicious >= 5 || ruleLevel >= 7) {"

OLD_OUT = """    silent,
    should_active_response"""
NEW_OUT = """    silent,
    should_active_response,
    source: is_otx ? 'otx' : 'vt',
    otx_threat,
    otx_pulses"""


def patch_summary(js):
    """Kembalikan (js_baru, berubah). Idempoten via marker is_otx."""
    if "is_otx" in js:
        return js, False
    pairs = [
        (OLD_HEAD, NEW_HEAD),
        (OLD_TOTAL, NEW_TOTAL),
        (OLD_RATIO, NEW_RATIO),
        (OLD_HIGH, NEW_HIGH),
        (OLD_OUT, NEW_OUT),
    ]
    for old, new in pairs:
        if old not in js:
            raise SystemExit(
                "Pola Rangkum Hasil tidak cocok, patch dibatalkan agar tidak merusak "
                "workflow live. Pola hilang:\n" + old[:120]
            )
    for old, new in pairs:
        js = js.replace(old, new)
    return js, True


def patch_workflow_otx(wf, cred_id, cred_name=OTX_CRED_NAME_DEFAULT):
    """Patch struktur workflow untuk menyisipkan/memperbarui OTX Lookup dan VT OK?.

    Mengembalikan (wf, changed, list_perubahan).
    """
    nodes = wf.setdefault("nodes", [])
    conns = wf.setdefault("connections", {})
    changes = []
    changed = False

    # 1. Pastikan node VT OK?
    if get_node(nodes, VT_OK_NAME) is None:
        nodes.append(dict(VT_OK_NODE))
        changes.append(f"Node '{VT_OK_NAME}' ditambahkan.")
        changed = True

    # 2. Pastikan node OTX Lookup dan sanitasi bila sudah ada
    existing_otx = get_node(nodes, OTX_NAME)
    if existing_otx is None:
        nodes.append(otx_node(cred_id, cred_name))
        changes.append(f"Node '{OTX_NAME}' ditambahkan dengan credential '{cred_name}'.")
        changed = True
    else:
        if sanitize_otx_node(existing_otx, cred_id, cred_name):
            changes.append(
                f"Node '{OTX_NAME}' dimigrasi ke credential terkelola '{cred_name}' (secret inline dibersihkan)."
            )
            changed = True

    # 3. Tentukan target dan sumber berdasarkan konteks workflow
    has_mb = get_node(nodes, "MalwareBazaar Lookup") is not None
    has_store = get_node(nodes, "Simpan Cache VT") is not None
    next_node = "MalwareBazaar Lookup" if has_mb else SUMMARY_NAME
    source_node = "Simpan Cache VT" if has_store else "Scan VirusTotal"

    # Rewire: source -> VT OK?
    src_conn = conns.get(source_node, {}).get("main", [[]])
    if not (src_conn and src_conn[0] and src_conn[0][0].get("node") == VT_OK_NAME):
        conns[source_node] = {
            "main": [[{"node": VT_OK_NAME, "type": "main", "index": 0}]]
        }
        changes.append(f"Rewire: {source_node} -> {VT_OK_NAME}")
        changed = True

    # Rewire: VT OK? true -> next_node, false -> OTX Lookup
    vt_ok_conn = conns.get(VT_OK_NAME, {}).get("main", [])
    want_vt_ok = [
        [{"node": next_node, "type": "main", "index": 0}],
        [{"node": OTX_NAME, "type": "main", "index": 0}],
    ]
    if vt_ok_conn != want_vt_ok:
        conns[VT_OK_NAME] = {"main": want_vt_ok}
        changes.append(f"Rewire: {VT_OK_NAME} true -> {next_node}, false -> {OTX_NAME}")
        changed = True

    # Rewire: OTX Lookup -> next_node
    otx_conn = conns.get(OTX_NAME, {}).get("main", [])
    want_otx = [[{"node": next_node, "type": "main", "index": 0}]]
    if otx_conn != want_otx:
        conns[OTX_NAME] = {"main": want_otx}
        changes.append(f"Rewire: {OTX_NAME} -> {next_node}")
        changed = True

    # 4. Patch Rangkum Hasil jika ada dan belum sadar OTX
    rk = get_node(nodes, SUMMARY_NAME)
    if rk is not None:
        js = rk.get("parameters", {}).get("jsCode", "")
        new_js, js_changed = patch_summary(js)
        if js_changed:
            rk["parameters"]["jsCode"] = new_js
            changes.append("Rangkum Hasil: logika OTX fallback ditambahkan.")
            changed = True

    return wf, changed, changes


def main():
    ap = argparse.ArgumentParser(description="Patch OTX fallback ke workflow n8n")
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--workflow-id", default=WORKFLOW_ID_DEFAULT)
    ap.add_argument("--otx-key", default=None, help="AlienVault OTX API key (untuk membuat credential jika belum ada)")
    ap.add_argument("--otx-cred-id", default=None, help="Gunakan ID credential yang sudah ada langsung")
    ap.add_argument("--otx-cred-name", default=OTX_CRED_NAME_DEFAULT, help="Nama credential n8n (default: 'OTX API Key')")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.api_key_file):
        sys.exit("API key file tidak ada: " + args.api_key_file)
    api_key = read_file(args.api_key_file)
    base = args.n8n_url.rstrip("/")
    wf_url = base + "/api/v1/workflows/" + args.workflow_id

    print("Memeriksa/menyiapkan credential OTX...")
    cred_id, cred_name = ensure_otx_credential(
        base,
        api_key,
        otx_key=args.otx_key,
        cred_id=args.otx_cred_id,
        cred_name=args.otx_cred_name,
        dry_run=args.dry_run,
    )

    print("Mengambil workflow " + args.workflow_id + " ...")
    wf = api_get(wf_url, api_key)
    nodes = wf.get("nodes", [])
    print("  Node saat ini: " + str(len(nodes)))

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(
        BACKUP_DIR,
        "deteksi-malware-live-otx-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    wf, changed, changes = patch_workflow_otx(wf, cred_id, cred_name)
    for c in changes:
        print("  " + c)

    if args.dry_run:
        print("[DRY-RUN] Perubahan terdeteksi: " + str(changed))
        return

    if not changed:
        print("Tidak ada perubahan.")
        return

    payload = {
        "name": wf.get("name"),
        "nodes": wf.get("nodes"),
        "connections": wf.get("connections"),
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
