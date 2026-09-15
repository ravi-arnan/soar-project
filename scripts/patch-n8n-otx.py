#!/usr/bin/env python3
"""Patch OTX fallback ke workflow live 'Deteksi Malware' di n8n (via public API).

Struktur live (13 node, tanpa cache/429-handling):
  Ekstrak Alert -> Scan VirusTotal -> Rangkum Hasil -> Cek Ancaman ...

Patch ini menyisipkan gerbang + fallback (OTX hanya dipanggil saat VT gagal,
bukan ensemble dobel):
  Scan VirusTotal -> VT OK? -> Rangkum Hasil
                         +-> OTX Lookup -> Rangkum Hasil

Rangkum Hasil diperbarui agar sadar dua bentuk input (VT vs OTX):
  - input OTX positif (pulse>0) -> HIGH, tidak silent (jalur alert + active response)
  - input OTX negatif/tak dikenal -> MEDIUM silent (sama seperti VT unknown)

Cara pakai (jalankan DI ravi-debian):
  python3 scripts/patch-n8n-otx.py \
    --n8n-url http://127.0.0.1:5678 \
    --api-key-file /tmp/n8n_api_key.txt \
    --otx-key <OTX_API_KEY> [--dry-run]

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


def otx_node(otx_key):
    return {
        "name": OTX_NAME,
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.4,
        "position": [250, 480],
        "parameters": {
            "method": "GET",
            "url": "=https://otx.alienvault.com/api/v1/indicators/file/{{ $('Ekstrak Alert').first().json.hash }}",
            "sendHeaders": True,
            "headerParameters": {
                "parameters": [{"name": "X-OTX-API-KEY", "value": otx_key}]
            },
            "options": {
                "response": {"response": {"fullResponse": False, "neverError": True}},
                "timeout": 15000,
            },
        },
        "onError": "continueRegularOutput",
    }


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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--workflow-id", default=WORKFLOW_ID_DEFAULT)
    ap.add_argument("--otx-key", required=True)
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
        "deteksi-malware-live-otx-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = False

    if get_node(nodes, VT_OK_NAME) is None:
        nodes.append(dict(VT_OK_NODE))
        print("  Node 'VT OK?' ditambahkan.")
        changed = True
    else:
        print("  Node 'VT OK?' sudah ada.")

    if get_node(nodes, OTX_NAME) is None:
        nodes.append(otx_node(args.otx_key))
        print("  Node 'OTX Lookup' ditambahkan.")
        changed = True
    else:
        print("  Node 'OTX Lookup' sudah ada.")

    # Rewire: Scan VirusTotal -> VT OK? ; VT OK? true -> Rangkum ; false -> OTX -> Rangkum
    svt = conns.get("Scan VirusTotal", {}).get("main", [[]])
    if not (svt and svt[0] and svt[0][0].get("node") == VT_OK_NAME):
        conns["Scan VirusTotal"] = {
            "main": [[{"node": VT_OK_NAME, "type": "main", "index": 0}]]
        }
        print("  Rewire: Scan VirusTotal -> VT OK?")
        changed = True

    vt_ok = conns.get(VT_OK_NAME, {}).get("main", [])
    want_vt_ok = [
        [{"node": SUMMARY_NAME, "type": "main", "index": 0}],
        [{"node": OTX_NAME, "type": "main", "index": 0}],
    ]
    if vt_ok != want_vt_ok:
        conns[VT_OK_NAME] = {"main": want_vt_ok}
        print("  Rewire: VT OK? true -> Rangkum Hasil, false -> OTX Lookup")
        changed = True

    otx_con = conns.get(OTX_NAME, {}).get("main", [])
    want_otx = [[{"node": SUMMARY_NAME, "type": "main", "index": 0}]]
    if otx_con != want_otx:
        conns[OTX_NAME] = {"main": want_otx}
        print("  Rewire: OTX Lookup -> Rangkum Hasil")
        changed = True

    rk = get_node(nodes, SUMMARY_NAME)
    if rk is None:
        raise SystemExit("Node 'Rangkum Hasil' tidak ditemukan di workflow live.")
    js = rk.get("parameters", {}).get("jsCode", "")
    new_js, js_changed = patch_summary(js)
    if js_changed:
        rk["parameters"]["jsCode"] = new_js
        print("  Rangkum Hasil: logika OTX fallback ditambahkan.")
        changed = True
    else:
        print("  Rangkum Hasil: sudah sadar OTX.")

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
