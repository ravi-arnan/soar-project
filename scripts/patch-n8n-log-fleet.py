#!/usr/bin/env python3
"""Sisipkan node "Log ke Fleet" (HTTP Request) ke workflow n8n "Deteksi Malware".

Alasan: fleet-monitor.py menyediakan POST /webhook-log supaya Threat Events di
dashboard terisi. Node ini mengirim ringkasan verdict (severity + hash + path)
dari node `Rangkum Hasil` ke sana, sebagai cabang paralel supaya alur AR/Telegram
tidak berubah.

Pemakaian:
    # dari JSON workflow yang sudah ada
    python3 patch-n8n-log-fleet.py --in live.json --out patched.json

    # atau sekalian PUT ke n8n lewat API
    python3 patch-n8n-log-fleet.py --in live.json \
        --n8n-url http://127.0.0.1:5678 --api-key-file /tmp/n8n_api_key.txt --apply

Idempoten: kalau node "Log ke Fleet" sudah ada, hanya parameternya yang
diselaraskan (tidak menambah duplikat).
"""

import argparse
import json
import sys
import urllib.request

NODE_NAME = "Log ke Fleet"
NODE_ID = "5f3c1a90-6d2b-4c5e-9a71-0b8e4d2c7f13"
SOURCE_NODE = "Rangkum Hasil"
TARGET_NODE = "Cek Ancaman"  # tetangga yang sudah ada, biar cabang baru sejajar

# Alamat fleet-monitor DILIHAT DARI DALAM container n8n.
# 127.0.0.1 di dalam container = container itu sendiri, bukan host — sudah
# dites: host.docker.internal:8080 -> 200, 127.0.0.1:8080 -> fetch failed.
FLEET_URL = "http://host.docker.internal:8080/webhook-log"


def build_node() -> dict:
    return {
        "parameters": {
            "method": "POST",
            "url": FLEET_URL,
            "sendBody": True,
            "specifyBody": "json",
            "jsonBody": (
                "={{ JSON.stringify({"
                "agent: $json.agent_name,"
                "agent_id: $json.agent_id,"
                "path: $json.filepath,"
                "hash: $json.hash || '',"
                "severity: $json.severity,"
                "status: 'detected',"
                "ai: ''"
                "}) }}"
            ),
            "options": {
                "timeout": 5000,
            },
        },
        "id": NODE_ID,
        "name": NODE_NAME,
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.4,
        "position": [580, 460],
        # Jangan biarkan dashboard mati mematikan pipeline deteksi.
        "onError": "continueRegularOutput",
        "notes": "Kirim verdict ke fleet-monitor /webhook-log (Threat Events dashboard)",
    }


def patch(workflow: dict) -> dict:
    nodes = workflow["nodes"]
    conns = workflow.setdefault("connections", {})

    node = build_node()
    existing = next((n for n in nodes if n.get("name") == NODE_NAME), None)
    if existing:
        nodes[nodes.index(existing)] = node
        print(f"[=] node '{NODE_NAME}' sudah ada, parameter diselaraskan")
    else:
        nodes.append(node)
        print(f"[+] node '{NODE_NAME}' ditambahkan")

    if SOURCE_NODE not in conns:
        sys.exit(f"ERROR: node sumber '{SOURCE_NODE}' tidak ditemukan di connections")

    main = conns[SOURCE_NODE].setdefault("main", [[]])
    targets = main[0]
    if not any(t.get("node") == NODE_NAME for t in targets):
        # Sisipkan SETELAH TARGET_NODE: cabang yang sudah ada tetap jalan dulu,
        # pencatatan ke fleet tidak menambah latensi alur AR/Telegram.
        idx = next(
            (i for i, t in enumerate(targets) if t.get("node") == TARGET_NODE),
            len(targets) - 1,
        )
        targets.insert(idx + 1, {"node": NODE_NAME, "type": "main", "index": 0})
        print(f"[+] edge {SOURCE_NODE} -> {NODE_NAME} (cabang paralel)")
    else:
        print(f"[=] edge {SOURCE_NODE} -> {NODE_NAME} sudah ada")

    return workflow


def put_workflow(base_url: str, api_key: str, workflow_id: str, wf: dict) -> dict:
    payload = {
        "name": wf["name"],
        "nodes": wf["nodes"],
        "connections": wf["connections"],
        "settings": wf.get("settings", {"executionOrder": "v1"}),
    }
    req = urllib.request.Request(
        f"{base_url}/api/v1/workflows/{workflow_id}",
        data=json.dumps(payload).encode(),
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--out", dest="outfile")
    ap.add_argument("--n8n-url", default="")
    ap.add_argument("--api-key-file", default="")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    wf = json.load(open(a.infile))
    wf = patch(wf)

    if a.outfile:
        json.dump(wf, open(a.outfile, "w"), indent=2, ensure_ascii=False)
        print(f"[i] hasil ditulis ke {a.outfile}")

    if a.apply:
        if not (a.n8n_url and a.api_key_file):
            sys.exit("ERROR: --apply butuh --n8n-url dan --api-key-file")
        key = open(a.api_key_file).read().strip()
        res = put_workflow(a.n8n_url, key, wf["id"], wf)
        print(f"[i] PUT ok: id={res.get('id')} nodes={len(res.get('nodes', []))}")


if __name__ == "__main__":
    main()
