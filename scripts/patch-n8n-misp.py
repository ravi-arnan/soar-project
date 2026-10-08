#!/usr/bin/env python3
"""MISP (feed OSINT) sebagai sumber threat-intel ke-4 untuk workflow LIVE.

Menambah node `MISP Lookup` antara `MalwareBazaar Lookup` dan `Rangkum Hasil`,
lalu meng-upgrade jsCode `Rangkum Hasil` agar sadar MISP (misp_threat menaikkan
severity). Idempoten (marker `// patch:misp:v1`), backup otomatis, ada --dry-run.

Prasyarat: workflow live sudah dipatch `scripts/patch-n8n-vt-cache-mb.py`
(marker `// patch:cache-mb:v2`) — patch ini membangun di atasnya (v2 -> v3).

Alur setelah patch:
  ... -> MalwareBazaar Lookup -> MISP Lookup -> Rangkum Hasil
`MISP Lookup` (di KEDUA jalur) memanggil service MISP feed (default
http://host.docker.internal:8090/lookup?value=<hash>); fail-open (service mati ->
misp_hit false, jalur tetap jalan).

Jalankan DI ravi-debian:
  python3 scripts/patch-n8n-misp.py --api-key-file /tmp/n8n_api_key.txt [--dry-run]
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
MISP_NODE_NAME = "MISP Lookup"
MB_NODE_NAME = "MalwareBazaar Lookup"
SUMMARY_NAME = "Rangkum Hasil"
MISP_BASE = "http://host.docker.internal:8090"

V2_MARKER = "// patch:cache-mb:v2"
V3_MARKER = "// patch:misp:v1"


def read_file(p):
    with open(p) as f:
        return f.read().strip()


def api_get(url, api_key):
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": api_key})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def api_send(url, api_key, payload, method):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        method=method,
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def get_node(nodes, name):
    for n in nodes:
        if n.get("name") == name:
            return n
    return None


MISP_NODE = {
    "name": MISP_NODE_NAME,
    "type": "n8n-nodes-base.httpRequest",
    "typeVersion": 4.4,
    "position": [360, 390],
    "parameters": {
        "method": "GET",
        "url": MISP_BASE + "/lookup",
        "sendQuery": True,
        "queryParameters": {
            "parameters": [
                {"name": "value", "value": "={{ $('Ekstrak Alert').first().json.hash }}"}
            ]
        },
        "options": {
            "response": {"response": {"neverError": True}},
            "timeout": 8000,
        },
    },
    "onError": "continueRegularOutput",
}

# Ganti head v2 (input = MB) menjadi v3 (input = MISP, MB via referensi node).
OLD_HEAD = "const mb = $input.first().json;"
NEW_HEAD = (
    "const misp = $input.first().json;\n"
    "const mb = $('" + MB_NODE_NAME + "').first().json;"
)

OLD_MB_THREAT = "const mb_threat = mb_known && mb_malicious;"
NEW_MB_THREAT = OLD_MB_THREAT + """

// MISP feed OSINT (sumber intel komunitas). misp_hit = hash ada di event MISP.
const misp_matches = Array.isArray(misp && misp.matches) ? misp.matches : [];
const misp_hit = !!(misp && misp.found && misp_matches.length > 0);
const misp_to_ids = misp_matches.some((m) => m && m.to_ids);
const misp_threat = misp_hit;
const misp_event = (misp_matches[0] && misp_matches[0].event_info) || '';
const misp_tags = (misp_matches[0] && misp_matches[0].tags) || [];
const misp_sources = [...new Set(misp_matches.map((m) => m && m.event_uuid).filter(Boolean))];"""

OLD_HIGH = (
    "} else if (!is_system_file && (otx_threat || mb_threat || malicious >= 5 "
    "|| ruleLevel >= 7)) {"
)
NEW_HIGH = (
    "} else if (!is_system_file && (otx_threat || mb_threat || misp_threat "
    "|| malicious >= 5 || ruleLevel >= 7)) {"
)

OLD_OUT = "    mb_query_status,\n    mb_threat"
NEW_OUT = """    mb_query_status,
    mb_threat,
    misp_hit,
    misp_to_ids,
    misp_threat,
    misp_event,
    misp_tags,
    misp_sources"""


def patch_misp_js(js):
    """Upgrade jsCode Rangkum Hasil v2 -> v3 (MISP-aware). Return (js, changed)."""
    if V3_MARKER in js:
        return js, False
    if V2_MARKER not in js:
        raise SystemExit(
            "Rangkum Hasil belum dipatch vt-cache-mb (marker v2 tak ada). "
            "Jalankan patch-n8n-vt-cache-mb.py dulu."
        )
    for old, new in (
        (OLD_HEAD, NEW_HEAD),
        (OLD_MB_THREAT, NEW_MB_THREAT),
        (OLD_HIGH, NEW_HIGH),
        (OLD_OUT, NEW_OUT),
    ):
        if new in js:
            continue
        if old not in js:
            raise SystemExit(
                "Pola Rangkum Hasil tidak cocok, patch dibatalkan. Hilang:\n" + old[:120]
            )
        js = js.replace(old, new, 1)
    return js + "\n\n" + V3_MARKER, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--workflow-id", default=WORKFLOW_ID_DEFAULT)
    ap.add_argument("--misp-base", default=MISP_BASE)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    global MISP_NODE
    if not os.path.exists(args.api_key_file):
        sys.exit("API key file tidak ada: " + args.api_key_file)
    api_key = read_file(args.api_key_file)
    base = args.n8n_url.rstrip("/")
    wf_url = base + "/api/v1/workflows/" + args.workflow_id
    MISP_NODE = json.loads(json.dumps(MISP_NODE).replace(MISP_BASE, args.misp_base.rstrip("/")))

    print("Mengambil workflow " + args.workflow_id + " ...")
    wf = api_get(wf_url, api_key)
    nodes = wf.get("nodes", [])
    conns = wf.get("connections", {})
    print("  Node saat ini: " + str(len(nodes)))

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(
        BACKUP_DIR, "deteksi-malware-live-misp-" + time.strftime("%Y%m%d-%H%M%S") + ".json"
    )
    if not args.dry_run:
        with open(backup_path, "w") as f:
            json.dump(wf, f, indent=2)
        print("  Backup: " + backup_path)

    changed = False

    if get_node(nodes, MISP_NODE_NAME) is None:
        nodes.append(json.loads(json.dumps(MISP_NODE)))
        print(f"  Node '{MISP_NODE_NAME}' ditambahkan.")
        changed = True
    else:
        print(f"  Node '{MISP_NODE_NAME}' sudah ada.")

    def set_conn(src, outs):
        want = {"main": [[{"node": t, "type": "main", "index": 0}] for t in outs]}
        if conns.get(src) != want:
            conns[src] = want
            print("  Rewire: {} -> {}".format(src, ", ".join(outs) or "(kosong)"))
            return True
        return False

    changed |= set_conn(MB_NODE_NAME, [MISP_NODE_NAME])
    changed |= set_conn(MISP_NODE_NAME, [SUMMARY_NAME])

    rk = get_node(nodes, SUMMARY_NAME)
    if rk is None:
        raise SystemExit(f"Node '{SUMMARY_NAME}' tidak ditemukan.")
    new_js, js_changed = patch_misp_js(rk.get("parameters", {}).get("jsCode", ""))
    if js_changed:
        rk["parameters"]["jsCode"] = new_js
        print("  Rangkum Hasil: sadar MISP (misp_threat).")
        changed = True
    else:
        print("  Rangkum Hasil: sudah sadar MISP.")

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
        result = api_send(wf_url, api_key, payload, "PUT")
        print(f"Selesai. Aktif: {result.get('active')}, node: {len(result.get('nodes', []))}")
    except urllib.error.HTTPError as e:
        print(f"GAGAL PUT: {e.code} {e.read().decode()[:300]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
