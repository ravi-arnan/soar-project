#!/usr/bin/env python3
"""E2E check pipeline SOAR (TODO board #41).

Mengirim 1 alert FIM sintetis (EICAR) + 1 alert process-chain sintetis ke
webhook n8n, lalu memverifikasi kedua eksekusi menempuh jalur yang benar
tanpa error:
  FIM:   Webhook -> Filter -> Ekstrak -> Dedup -> Scan VT -> ... -> AI
  Chain: Webhook -> Cabang -> Ekstrak Chain -> Rangkum Chain -> Build -> AI

CATATAN: tiap run mengirim 2 pesan Telegram asli (node Telegram live).
Jalankan manual sesekali saja (regresi), bukan cron.

Pakai: python3 scripts/e2e-soar-check.py [--n8n-url ...] [--timeout 300]
Keluar 0 = semua hijau, 1 = ada yang gagal.
"""

import argparse
import json
import sys
import time
import urllib.request

WORKFLOW_ID = "1MVcpL7ZKfBhR2tc"
EICAR = "275a021bbfb6489e5a62c837bd1997d1c35b5bd83db497d624139cf10d4cc1399"

FIM_NODES = [
    "Filter Alert Malware",
    "Ekstrak Alert",
    "Dedup Alert",
    "Scan VirusTotal",
    "Rangkum Hasil",
    "Build Payload",
    "AI Generate",
]
CHAIN_NODES = [
    "Cabang Chain?",
    "Ekstrak Chain",
    "Rangkum Chain",
    "Build Payload",
    "AI Generate",
]


def post(url, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    urllib.request.urlopen(req, timeout=15).read()


def api(url, key):
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": key})
    return json.loads(urllib.request.urlopen(req, timeout=15).read())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://192.168.1.47:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--timeout", type=int, default=300)
    args = ap.parse_args()
    key = open(args.api_key_file).read().strip()
    base = args.n8n_url.rstrip("/")
    hook = base + "/webhook/wazuh-alert"
    stamp = time.strftime("%H%M%S")

    fim = {
        "agent": {"id": "003", "name": "e2e-check"},
        "syscheck": {"path": "/tmp/e2e-%s.bin" % stamp, "sha256_after": EICAR},
        "rule": {"id": "1002", "level": 7, "description": "e2e fim check"},
    }
    chain = {
        "rule": {
            "id": "110002",
            "level": 10,
            "description": "e2e chain check (cmd->powershell hidden)",
        },
        "agent": {"id": "007", "name": "e2e-check", "ip": "192.168.1.50"},
        "data": {
            "sysmon": {
                "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                # stamp agar unik per run (dedup 5 mnt tidak menelan run ulang)
                "commandLine": "powershell.exe -WindowStyle Hidden -File e2e-%s.ps1"
                % stamp,
                "parentImage": "C:\\Windows\\System32\\cmd.exe",
                "parentCommandLine": "cmd.exe /c e2e-%s.bat" % stamp,
            }
        },
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    print("POST FIM ...", flush=True)
    t0 = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    post(hook, fim)
    time.sleep(5)
    print("POST chain ...", flush=True)
    post(hook, chain)

    deadline = time.time() + args.timeout
    fim_ok = chain_ok = False
    while time.time() < deadline and not (fim_ok and chain_ok):
        time.sleep(15)
        ex = api(
            base + "/api/v1/executions?workflowId=" + WORKFLOW_ID + "&limit=4", key
        )
        for e in ex.get("data", []):
            if (e.get("startedAt") or "") < t0:
                continue  # eksekusi lama, bukan dari run ini
            det = api(base + "/api/v1/executions/%s?includeData=true" % e["id"], key)
            rd = (det.get("data") or {}).get("resultData", {}).get("runData", {})
            nodes = set(rd.keys())
            errs = [n for n in nodes if (rd[n][0].get("error"))]
            if errs:
                print("GAGAL exec %s error di %s" % (e["id"], errs))
                return 1
            if set(FIM_NODES) <= nodes and not fim_ok:
                fim_ok = True
                print(
                    "HIJAU FIM (exec %s): %d node, tanpa error" % (e["id"], len(nodes))
                )
            if set(CHAIN_NODES) <= nodes and not chain_ok:
                chain_ok = True
                print(
                    "HIJAU chain (exec %s): %d node, tanpa error"
                    % (e["id"], len(nodes))
                )
    if not fim_ok:
        print("GAGAL: jalur FIM tak lengkap dalam %ds" % args.timeout)
    if not chain_ok:
        print("GAGAL: jalur chain tak lengkap dalam %ds" % args.timeout)
    return 0 if (fim_ok and chain_ok) else 1


if __name__ == "__main__":
    sys.exit(main())
