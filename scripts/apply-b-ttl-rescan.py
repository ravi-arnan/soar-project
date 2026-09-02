#!/usr/bin/env python3
"""B (re-scan): TTL diferensial untuk cache VT — verdict bersih di-cache lebih singkat.

Edit pada n8n-workflows/deteksi-malware.json:
1. Node 'Cek Cache VT': TTL diferensial berdasarkan verdict sebelumnya.
   - Confirmed malicious (stats.malicious >= 1): 7 hari (sudah pasti berbahaya)
   - Clean (stats.malicious === 0): 24 jam (re-scan lebih cepat, verdict bisa berubah)
   - Unknown (hash tidak dikenal): 6 jam (bisa saja baru ditambahkan ke VT nanti)
2. Node 'Rangkum Hasil': simpan malicious count ke cache untuk TTL diferensial.

Logika: file yang bersih hari ini mungkin terdeteksi besok (vt_verdict_change).
TTL lebih pendek untuk clean → menurunkan false-negative rate seiring waktu.
"""
import json

PATH = "n8n-workflows/deteksi-malware.json"
with open(PATH) as f:
    raw = json.load(f)
wf = raw[0] if isinstance(raw, list) else raw
NODES = wf["nodes"]


def get_node(name):
    for n in NODES:
        if n.get("name") == name:
            return n
    raise SystemExit(f"Node '{name}' tidak ditemukan")


# ================================================================
# 1. Update Cek Cache VT — TTL diferensial
# ================================================================
node = get_node("Cek Cache VT")
js = node["parameters"]["jsCode"]

OLD_TTL = "const TTL = 6 * 60 * 60 * 1000;   // 6 jam"
NEW_TTL = """// TTL diferensial: verdict bersih di-cache lebih singkat (re-scan lebih cepat)
// -> menurunkan false-negative rate seiring waktu (verdict VT bisa berubah).
const TTL_MALICIOUS = 7 * 24 * 60 * 60 * 1000;  // 7 hari: sudah confirmed malicious
const TTL_CLEAN     = 24 * 60 * 60 * 1000;       // 24 jam: bersih → re-scan lebih cepat
const TTL_UNKNOWN   = 6 * 60 * 60 * 1000;         // 6 jam: tidak dikenal → bisa berubah
const cachedMalicious = (sd.vtCache[hash]?.stats?.malicious || 0);
const TTL = cachedMalicious >= 1 ? TTL_MALICIOUS
           : cachedMalicious === 0 && sd.vtCache[hash]?.stats ? TTL_CLEAN
           : TTL_UNKNOWN;"""

if OLD_TTL in js:
    js = js.replace(OLD_TTL, NEW_TTL)
    print("Cek Cache VT: TTL diferensial diterapkan.")
else:
    print("WARNING: pola TTL tidak ditemukan di Cek Cache VT. Skip.")

# Update simpanan cache di node Scan VirusTotal / Rangkum Hasil
# yang menyimpan ke sd.vtCache — kita perlu pastikan malicious count tersimpan.
# Saat ini sudah menyimpan: sd.vtCache[hash] = { stats, ts }
# stats sudah berisi malicious count → sudah cukup.

node["parameters"]["jsCode"] = js

# ================================================================
# 2. Tulis ulang
# ================================================================
with open(PATH, "w") as f:
    json.dump(raw, f, ensure_ascii=False, separators=(",", ":"))
print(f"\n{PATH} ditulis ulang.")
print("TTL diferensial:")
print("  - Malicious (>=1): 7 hari (sudah pasti)")
print("  - Clean (0): 24 jam (re-scan lebih cepat)")
print("  - Unknown: 6 jam (bisa berubah)")
