#!/usr/bin/env python3
"""Patch OTX fallback ke workflow 'Deteksi Malware' di n8n (live, via public API).

Tujuan: tambah AlienVault OTX sebagai sumber intel KEDUA (fallback) saat
VirusTotal rate-limit / error. Alur jadi:

  Scan VirusTotal -> VT 429? -> Wait VT Retry 60s -> OTX Lookup -> Rangkum Hasil
                 -> VT 429? (success) -> [MalwareBazaar / Rangkum Hasil]

OTX dipanggil HANYA saat VT gagal (fallback), bukan ensemble dobel.

Cara pakai (jalankan DI ravi-debian):
  python3 patch-n8n-otx.py \
    --n8n-url http://127.0.0.1:5678 \
    --api-key-file /tmp/n8n_api_key.txt \
    --workflow-id 1MVcpL7ZKfBhR2tc \
    --otx-key <your-otx-api-key>

  --dry-run : tampilkan perubahan tanpa menulis ke n8n (default: apply)

Idempoten: aman dijalankan berulang (node sudah ada -> skip).
Backup workflow live disimpan otomatis ke backups/deteksi-malware-live-otx-*.json
"""

import argparse
import json
import os
import sys
import time
import urllib.request
import urllib.error

API_KEY_FILE_DEFAULT = "/tmp/n8n_api_key.txt"
BACKUP_DIR = os.path.join(os.path.dirname(__file__), "..", "backups")

OTX_NODE_NAME = "OTX Lookup"


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


def get_position(nodes):
    """Hitung posisi OTX: di kanan bawah Wait VT Retry 60s / node yang tunggu."""
    # Cari node bernama mirip 'Wait VT'
    anchor = None
    for n in nodes:
        if "wait" in n.get("name", "").lower() and "vt" in n.get("name", "").lower():
            anchor = n
            break
    if anchor:
        px, py = anchor.get("position", [0, 0])
        return [px + 160, py + 60]
    # fallback: tambah di (520, 620)
    return [520, 620]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default=API_KEY_FILE_DEFAULT)
    ap.add_argument("--workflow-id", default="1MVcpL7ZKfBhR2tc")
    ap.add_argument("--otx-key", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.api_key_file):
        sys.exit(
            f"API key file tidak ada: {args.api_key_file}\n"
            "Ambil dari n8n: Settings > API > Create key, simpan ke file tsb."
        )
    api_key = read_file(args.api_key_file)
    base = args.n8n_url.rstrip("/")

    # 1. Tarik workflow live
    wf_url = f"{base}/api/v1/workflows/{args.workflow_id}"
    print(f"Mengambil workflow {args.workflow_id} dari {base} ...")
    try:
        wf = api_get(wf_url, api_key)
    except Exception as e:
        sys.exit(f"Gagal ambil workflow: {e}")

    nodes = wf.get("nodes", [])
    conns = wf.get("connections", {})

    # Backward compatible: workflow bisa disimpan langsung atau dgn 'nodes' key
    print(f"  Node saat ini: {len(nodes)}")

    # Backup
    os.makedirs(BACKUP_DIR, exist_ok=True)
    ts = time.strftime("%Y%m%d-%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"deteksi-malware-live-otx-{ts}.json")
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print(f"  Backup: {backup_path}")

    changed = False

    # 2. Cek apakah OTX sudah ada
    if get_node(nodes, OTX_NODE_NAME):
        print(f"  Node '{OTX_NODE_NAME}' sudah ada, skip penambahan.")
    else:
        otx_node = {
            "parameters": {
                "method": "GET",
                "url": "=https://otx.alienvault.com/api/v1/indicators/file/{{ $('Ekstrak Alert').item.json.hash }}",
                "authentication": "genericCredentialType",
                "genericAuthType": "httpHeaderAuth",
                "sendHeaders": True,
                "headerParameters": {
                    "parameters": [{"name": "X-OTX-API-KEY", "value": args.otx_key}]
                },
                "options": {
                    "response": {
                        "response": {"fullResponse": True, "neverError": True}
                    },
                    "timeout": 15000,
                },
            },
            "id": "otx-lookup-" + args.otx_key[:6],
            "name": OTX_NODE_NAME,
            "type": "n8n-nodes-base.httpRequest",
            "typeVersion": 4.4,
            "position": get_position(nodes),
            "onError": "continueRegularOutput",
        }
        nodes.append(otx_node)
        print(f"  Node '{OTX_NODE_NAME}' ditambahkan.")

        # 3. Rewire: semua node yang masuk Rangkum Hasil dari jalur VT-fail dialihkan ke OTX
        #    Strategi aman: arahkan 'Wait VT Retry 60s' -> OTX Lookup -> Rangkum Hasil
        #    (karena 429 berarti VT gagal -> OTX sebagai fallback)
        rewire_targets = []
        for name in ["Wait VT Retry 60s", "Wait VT Retry", "Wait 60s"]:
            if name in conns:
                rewire_targets.append(name)

        rerouted = False
        for name in rewire_targets:
            if name in conns:
                conns[name] = {
                    "main": [[{"node": OTX_NODE_NAME, "type": "main", "index": 0}]]
                }
                print(f"  Rewire: {name} -> {OTX_NODE_NAME}")
                rerouted = True

        if not rerouted:
            print(
                "  INFO: tidak ada node Wait VT Retry yang ditemukan. OTX ditambahkan"
                " tapi belum di-rewire — periksa manual."
            )

        # 4. OTX Lookup -> Rangkum Hasil
        conns[OTX_NODE_NAME] = {
            "main": [[{"node": "Rangkum Hasil", "type": "main", "index": 0}]]
        }
        print(f"  Rewire: {OTX_NODE_NAME} -> Rangkum Hasil")

        changed = True

    # 5. Update Rangkum Hasil: baca OTX sebagai fallback
    rk = get_node(nodes, "Rangkum Hasil")
    if rk and "jsCode" in rk.get("parameters", {}):
        js = rk["parameters"]["jsCode"]
        if "OTX fallback" not in js:
            preamble = """// ===== OTX fallback (sumber intel kedua, saat VT gagal) =====
let otx_known = false;
let otx_malicious = false;
let otx_pulses = 0;
let otx_families = [];
let otx_query_status = 'not_checked';
try {
  const otxRaw = $input.first().json;
  const otxFp = otxRaw.active_status !== undefined ? otxRaw : (otxRaw.body || otxRaw);
  if (otxFp && otxFp.pulse_info) {
    otx_pulses = (otxFp.pulse_info.count || 0);
    const fams = otxFp.pulse_info.pulses || [];
    otx_families = fams.flatMap(p => (p.malware_families || []).map(m => m.display_name))
                       .filter(Boolean).slice(0,5);
    otx_known = true;
    otx_malicious = otx_pulses > 0;
    otx_query_status = 'ok';
  } else if (otxFp && otxFp.detail && (otxFp.detail.includes('not found') || otxFp.detail.includes('does not exist'))) {
    otx_query_status = 'not_found';
  } else {
    otx_query_status = otxFp?.detail ? 'error' : 'ok';
  }
} catch (e) { otx_query_status = 'error'; }
"""
            marker = "const inp = $input.first().json;"
            if marker in js:
                js = js.replace(marker, preamble + marker)
                print("  Rangkum Hasil: OTX preamble ditambahkan.")
                changed = True
            else:
                print(
                    "  WARNING: marker 'const inp' tak ditemukan, OTX preamble disisipkan di awal."
                )
                js = preamble + js
                changed = True

        # Integrasi fallback: kalau VT unverified dan OTX malicious -> jadi review/threat
        if "const otx_threat = otx_known && otx_malicious" not in js:
            # Jadikan OTX sebagai koreksi terhadap vt_unverified (fallback verdict)
            # Tambah di awal blok decidion: override vt_unverified kalau OTX bilang bersih/known
            old = "const THREAT  ="
            if old in js:
                inject = (
                    "// OTX fallback: bila VT unconfirmed tapi OTX jelas, pakai OTX\n"
                    "const otx_threat = otx_known && otx_malicious;\n"
                    "const use_otx_verdict = (vt_unverified || vt_status === 'error') && otx_known;\n"
                )
                js = js.replace(old, inject + old)
                print("  Rangkum Hasil: otx_threat/use_otx_verdict di-definisikan.")
                changed = True
            else:
                print(
                    "  WARNING: 'const THREAT' tak ditemukan. Skip integrasi verdict."
                )

        rk["parameters"]["jsCode"] = js

    if args.dry_run:
        print(f"\n[DRY-RUN] Tidak menulis ke n8n. Perubahan terdeteksi: {changed}")
        sys.exit(0)

    if not changed:
        print("\nTidak ada perubahan. Workflow sudah punya OTX.")
        sys.exit(0)

    # 6. Tulis kembali
    payload = {
        "name": wf.get("name"),
        "nodes": nodes,
        "connections": conns,
        "settings": wf.get("settings", {}),
        "staticData": wf.get("staticData"),
    }
    print("\nMenulis ke n8n ...")
    try:
        result = api_put(wf_url, api_key, payload)
        print("Selesai. Workflow diperbarui.")
        print(f"  Aktif: {result.get('active')}")
    except urllib.error.HTTPError as e:
        print(f"GAGAL PUT: {e.code} {e.read().decode()[:300]}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
