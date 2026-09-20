#!/usr/bin/env python3
"""Bersihkan node mati jalur AI lokal (Ollama) dari workflow live 'Deteksi Malware'.

Latar: node `Preload Model` + `Ollama Generate` sudah tidak terpakai — tidak ada
layanan Ollama di server dan `Preload Model` tidak punya koneksi masuk (orphan),
sehingga cabang itu tidak pernah dieksekusi. Sekaligus menormalkan field `model`
yang tersisa (dulu nama model lokal) menjadi model yang benar-benar dipakai.

Yang dilakukan:
  1. Hapus node `Preload Model` dan `Ollama Generate`.
  2. Hapus semua edge yang menyentuh node tersebut (sumber maupun tujuan).
  3. Update `model: 'llama3.2:3b'` -> `'Atria-Dawn-Preview'` di jsCode node
     Ekstrak Alert / Ekstrak Chain (field inert, hanya penanda informasi).

Jalankan DI ravi-debian:
  python3 scripts/patch-n8n-drop-ollama.py --api-key-file /tmp/n8n_api_key.txt [--dry-run]

Idempoten (node tidak ada = no-op). Backup otomatis ke
backups/deteksi-malware-live-drop-ollama-*.json
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
DROP_NODES = ("Preload Model", "Ollama Generate")
OLD_MODEL = "llama3.2:3b"
NEW_MODEL = "Atria-Dawn-Preview"


def read_file(p):
    with open(p) as f:
        return f.read().strip()


def api(url, api_key, payload=None, method="GET"):
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode() if payload is not None else None,
        method=method,
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


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
    wf = api(wf_url, api_key)
    nodes = wf.get("nodes", [])
    conns = wf.get("connections", {})
    print("  Node saat ini: " + str(len(nodes)))

    os.makedirs(BACKUP_DIR, exist_ok=True)
    if not args.dry_run:
        backup = os.path.join(
            BACKUP_DIR,
            "deteksi-malware-live-drop-ollama-"
            + time.strftime("%Y%m%d-%H%M%S")
            + ".json",
        )
        with open(backup, "w") as f:
            json.dump(wf, f, indent=2)
        print("  Backup: " + backup)

    changed = False

    # 1. hapus node
    kept = [n for n in nodes if n.get("name") not in DROP_NODES]
    for name in DROP_NODES:
        if any(n.get("name") == name for n in nodes):
            print(f"  Node '{name}' dihapus.")
            changed = True
        else:
            print(f"  Node '{name}' sudah tidak ada.")

    # 2. hapus edge yang menyentuh node tersebut
    new_conns = {}
    for src, c in conns.items():
        if src in DROP_NODES:
            changed = True
            continue
        mains = []
        for arr in c.get("main", []):
            targets = [t for t in (arr or []) if t.get("node") not in DROP_NODES]
            if len(targets) != len(arr or []):
                changed = True
            mains.append(targets)
        new_conns[src] = {**c, "main": mains}
    print("  Edge ke/dari node mati dibersihkan.")

    # 3. normalkan field model di jsCode
    for n in kept:
        js = (n.get("parameters") or {}).get("jsCode")
        if isinstance(js, str) and OLD_MODEL in js:
            n["parameters"]["jsCode"] = js.replace(OLD_MODEL, NEW_MODEL)
            print("  {}: model '{}' -> '{}'.".format(n["name"], OLD_MODEL, NEW_MODEL))
            changed = True

    if args.dry_run:
        print(
            f"[DRY-RUN] node: {len(nodes)} -> {len(kept)}, perubahan: {changed}"
        )
        return

    if not changed:
        print("Tidak ada perubahan.")
        return

    payload = {
        "name": wf.get("name"),
        "nodes": kept,
        "connections": new_conns,
        "settings": wf.get("settings", {}),
        "staticData": wf.get("staticData"),
    }
    print("Menulis ke n8n ...")
    try:
        result = api(wf_url, api_key, payload, "PUT")
        print(
            f"Selesai. Aktif: {result.get('active')}, "
            f"node: {len(result.get('nodes', []))}"
        )
    except urllib.error.HTTPError as e:
        print(f"GAGAL PUT: {e.code} {e.read().decode()[:300]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
