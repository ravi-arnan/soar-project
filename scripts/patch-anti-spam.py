#!/usr/bin/env python3
"""Patch n8n workflows untuk mencegah spam notifikasi Telegram.

1. Deteksi Malware (1MVcpL7ZKfBhR2tc):
   - Tambahkan 'html','htm' ke BENIGN_EXT di node 'Rangkum Hasil'.
   - Perbaiki evaluasi vt_unverified: jika VT rate-limited/error, hanya file
     dengan ekstensi berisiko (is_risky_ext) atau executable bit (is_exec)
     yang divonis MEDIUM (unverified) untuk HITL review. File media/dokumen
     jinak tetap diperlakukan sebagai INFO tanpa memicu alert karantina ke Telegram.

2. Deteksi Phishing (ELhIxkr2uJ43IACs):
   - Putus koneksi 'Build Payload Aman' -> 'Send Telegram Info'.
   - URL yang aman (SAFE) tidak perlu mengirim pesan notifikasi ke Telegram,
     cukup selesai secara silent dan dicatat di database.
"""

import argparse
import datetime
import json
import os
import sys
import urllib.request

API_KEY_DEFAULT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiI0YmI1NTMxZi0yYmFjLTQ3NWEtOTBjMS04MzEwMDcxNDE2OWMiLCJpc3MiOiJuOG4iLCJhdWQiOiJwdWJsaWMtYXBpIiwianRpIjoiZWIwNGZmNDYtZmYyMi00NWI1LWE1ZjktOGZlZGJhNzAzMGM5IiwiaWF0IjoxNzkzMjA4NTM5fQ."
    "du0al6ShsHYc6le8ACttmxWSsOl0fOdyQ1QgovIwgvM"
)

MALWARE_WF_ID = "1MVcpL7ZKfBhR2tc"
PHISHING_WF_ID = "ELhIxkr2uJ43IACs"
BACKUP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "backups")


def get_wf(base_url: str, wid: str, api_key: str) -> dict:
    req = urllib.request.Request(
        f"{base_url}/api/v1/workflows/{wid}",
        headers={"X-N8N-API-KEY": api_key},
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def put_wf(base_url: str, wid: str, wf_data: dict, api_key: str) -> dict:
    payload = {
        "name": wf_data["name"],
        "nodes": wf_data["nodes"],
        "connections": wf_data["connections"],
        "settings": wf_data.get("settings", {}),
    }
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        f"{base_url}/api/v1/workflows/{wid}",
        data=data,
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.load(r)


def patch_malware_wf(wf: dict) -> bool:
    changed = False
    for n in wf.get("nodes", []):
        if n.get("name") == "Rangkum Hasil":
            code = n.get("parameters", {}).get("jsCode", "")
            # 1. Tambahkan 'html','htm' ke BENIGN_EXT jika belum ada
            if "'html','htm'" not in code and "'epub','mobi'" in code:
                code = code.replace(
                    "'epub','mobi'",
                    "'epub','mobi','html','htm'",
                )
                changed = True
                print("  [Malware] Ditambahkan 'html','htm' ke BENIGN_EXT.")

            # 2. Perbaiki vt_unverified agar hanya menaikkan file berisiko
            target_old = "} else if (vt_unverified) {"
            target_new = "} else if (vt_unverified && (is_risky_ext || is_exec)) {"
            if target_old in code:
                code = code.replace(target_old, target_new)
                changed = True
                print("  [Malware] Perbaikan logika vt_unverified: hanya file berisiko/eksekutabel.")

            if changed:
                n["parameters"]["jsCode"] = code
    return changed


def patch_phishing_wf(wf: dict) -> bool:
    conns = wf.setdefault("connections", {})
    bpa = conns.get("Build Payload Aman")
    if bpa and bpa.get("main") and len(bpa["main"]) > 0 and len(bpa["main"][0]) > 0:
        conns["Build Payload Aman"] = {"main": [[]]}
        print("  [Phishing] Pemutusan koneksi 'Build Payload Aman' -> 'Send Telegram Info'.")
        return True
    return False


def main():
    ap = argparse.ArgumentParser(description="Patch anti-spam untuk n8n SOAR")
    ap.add_argument("--n8n-url", default="http://100.73.91.17:5678")
    ap.add_argument("--api-key", default=API_KEY_DEFAULT)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    print(f"Mengambil workflow dari n8n ({args.n8n_url}) ...")
    mw = get_wf(args.n8n_url, MALWARE_WF_ID, args.api_key)
    ph = get_wf(args.n8n_url, PHISHING_WF_ID, args.api_key)

    mw_backup = os.path.join(BACKUP_DIR, f"deteksi-malware-before-anti-spam-{ts}.json")
    ph_backup = os.path.join(BACKUP_DIR, f"deteksi-phishing-before-anti-spam-{ts}.json")
    with open(mw_backup, "w") as f:
        json.dump(mw, f, indent=2)
    with open(ph_backup, "w") as f:
        json.dump(ph, f, indent=2)
    print(f"Backup disimpan ke:\n  {mw_backup}\n  {ph_backup}")

    mw_changed = patch_malware_wf(mw)
    ph_changed = patch_phishing_wf(ph)

    if not mw_changed and not ph_changed:
        print("Tidak ada perubahan yang diperlukan (semua patch sudah terpasang).")
        return

    if args.dry_run:
        print("Dry run aktif: perubahan TIDAK dikirim ke server live.")
        return

    if mw_changed:
        print(f"Mengirim update Deteksi Malware ({MALWARE_WF_ID}) ...")
        put_wf(args.n8n_url, MALWARE_WF_ID, mw, args.api_key)
        print("  Deteksi Malware OK.")

    if ph_changed:
        print(f"Mengirim update Deteksi Phishing ({PHISHING_WF_ID}) ...")
        put_wf(args.n8n_url, PHISHING_WF_ID, ph, args.api_key)
        print("  Deteksi Phishing OK.")

    print("\nPatch anti-spam berhasil diterapkan ke server live.")


if __name__ == "__main__":
    main()
