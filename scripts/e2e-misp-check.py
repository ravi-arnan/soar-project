#!/usr/bin/env python3
"""E2E check integrasi MISP: hash yang HANYA dikenal MISP -> severity naik HIGH.

Kontrol: hash sintetis disisipkan ke index MISP (dan sengaja TIDAK dikenal
VirusTotal/MalwareBazaar). Rule level dibuat 5 (di bawah ambang HIGH=7), jadi
kalau severity naik ke HIGH, penyebabnya PASTI kontribusi MISP (misp_threat).

Jalankan DI ravi-debian:
  python3 scripts/e2e-misp-check.py --api-key-file /tmp/n8n_api_key.txt

Keluar 0 = hijau. Membersihkan baris sintetis di akhir.
"""
import argparse
import json
import os
import sqlite3
import sys
import time
import urllib.request

WORKFLOW_ID = "1MVcpL7ZKfBhR2tc"
MISP_DB_DEFAULT = os.path.join(os.path.dirname(__file__), "..", "state", "misp.db")


def http_get(url, key):
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": key})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read())


def http_post(url, payload):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--misp-db", default=MISP_DB_DEFAULT)
    ap.add_argument("--timeout", type=int, default=120)
    args = ap.parse_args()
    key = open(args.api_key_file).read().strip()
    base = args.n8n_url.rstrip("/")

    stamp = time.strftime("%H%M%S")
    # 1. hash sintetis (216-bit acak -> praktis tak dikenal VT/MB)
    import hashlib
    sha = hashlib.sha256(("misp-e2e-" + stamp).encode()).hexdigest()
    con = sqlite3.connect(args.misp_db, timeout=180)
    con.execute("PRAGMA busy_timeout=180000")  # service bisa sedang sync (penulis lain)
    for attempt in range(20):
        try:
            con.execute(
                "INSERT OR IGNORE INTO attributes(value,type,event_uuid,event_info,event_date,category,to_ids,tags)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (sha, "sha256", "e2e-misp-" + stamp, "SOAR E2E MISP test (synthetic)",
                 "2026-10-08", "Payload delivery", 1, "e2e,test"),
            )
            con.commit()
            break
        except sqlite3.OperationalError:
            time.sleep(2)
    con.close()
    print(f"hash sintetis di MISP: {sha}")

    # 2. injeksi alert FIM level 5 (< ambang HIGH) dengan hash tsb
    payload = {
        "rule": {"id": "553", "level": 5, "description": "e2e misp check"},
        "syscheck": {"path": f"/home/e2e/Downloads/e2e-misp-{stamp}.bin",
                     "sha256_after": sha, "event": "added", "perm_after": "rw-r--r--"},
        "agent": {"id": "003", "name": "e2e-misp", "ip": "192.168.1.50"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    t0 = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    print("POST webhook ...", flush=True)
    http_post(base + "/webhook/wazuh-alert", payload)

    # 3. tunggu eksekusi & periksa runData
    ok = False
    deadline = time.time() + args.timeout
    while time.time() < deadline and not ok:
        time.sleep(10)
        ex = http_get(base + f"/api/v1/executions?workflowId={WORKFLOW_ID}&limit=5", key)
        for e in ex.get("data", []):
            if (e.get("startedAt") or "") < t0:
                continue
            det = http_get(base + f"/api/v1/executions/{e['id']}?includeData=true", key)
            rd = (det.get("data") or {}).get("resultData", {}).get("runData", {})
            misp_node = rd.get("MISP Lookup", [{}])[0].get("data", {}).get("main", [[{}]])[0][0].get("json", {})
            rk = rd.get("Rangkum Hasil", [{}])[0].get("data", {}).get("main", [[{}]])[0][0].get("json", {})
            if "Rangkum Hasil" not in rd:
                continue
            print(f"exec {e['id']}: MISP found={misp_node.get('found')} count={misp_node.get('count')} | "
                  f"misp_hit={rk.get('misp_hit')} misp_threat={rk.get('misp_threat')} "
                  f"severity={rk.get('severity')} source={rk.get('source')}")
            if rk.get("misp_hit") and rk.get("misp_threat") and rk.get("severity") == "HIGH":
                ok = True
            break

    # 4. bersihkan
    con = sqlite3.connect(args.misp_db, timeout=180)
    con.execute("PRAGMA busy_timeout=180000")
    for _ in range(20):
        try:
            con.execute("DELETE FROM attributes WHERE event_uuid=?", ("e2e-misp-" + stamp,))
            con.commit()
            break
        except sqlite3.OperationalError:
            time.sleep(2)
    con.close()
    print("baris sintetis dibersihkan.")

    print("HIJAU: MISP menaikkan severity ke HIGH" if ok else "GAGAL: MISP tidak menaikkan severity")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
