#!/usr/bin/env python3
"""B: cache verdict VT (lapis-1) + MalwareBazaar sebagai sumber intel kedua.

Kenapa lewat public API, bukan `n8n-workflows/deteksi-malware.json`: workflow
LIVE 'Deteksi Malware' sudah menyimpang dari file repo (Gemini->Atria, dedup,
cabang chain, OTX) — import file repo akan menimpa yang sedang jalan. Patch ini
mengubah workflow LIVE, idempoten, dan menyimpan backup sebelum menulis.

Jalankan DI ravi-debian (n8n 127.0.0.1:5678):
  python3 scripts/patch-n8n-vt-cache-mb.py \
    --api-key-file /tmp/n8n_api_key.txt --mb-key-file /tmp/mb_api_key.txt [--dry-run]

Alur setelah patch:
  Dedup Alert -> Cek Cache VT -> Cache Hit?
      hit  -> MalwareBazaar Lookup -> Rangkum Hasil   (VT dilewati, hemat kuota)
      miss -> Scan VirusTotal -> Simpan Cache VT -> VT OK?
                 true  -> MalwareBazaar Lookup -> Rangkum Hasil
                 false -> OTX Lookup -> MalwareBazaar Lookup -> Rangkum Hasil

MB sengaja dijalankan di KEDUA jalur (bukan hanya cache miss): verdict dari
cache yang "bersih" tetap harus diadu dengan MB, kalau tidak hash yang dikenal
MB tapi belum dikenal VT akan lolos senyap selama TTL cache berlaku.

Kenapa cache ada di fleet-monitor: staticData n8n tidak persist di versi ini
(terbukti saat dedup 19 Sep), jadi verdict disimpan server-side, key = HASH
(bukan per-agent) supaya burst 100 PC dengan hash sama = 1 panggilan VT.
TTL diferensial: malicious 7 hari, bersih 24 jam, tak dikenal 6 jam.

Kenapa MB: "signature" MB = hash sudah terdaftar malware walau VT masih 0/N
(celah false-negative). MB = sumber kedua; ensemble VT atau MB mendeteksi ->
THREAT. Credential: 'MalwareBazaar Auth' (HTTP Header Auth, Auth-Key).

Idempoten + bisa di-upgrade: kalau workflow sudah pernah dipatch versi sebelumnya
(MB hanya di jalur cache miss), script menaikkannya ke desain terbaru.
Marker versi di jsCode: patch:cache-mb:v2. Backup otomatis ke
backups/deteksi-malware-live-vt-cache-mb-*.json
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

CACHE_NODE_NAME = "Cek Cache VT"
CACHE_IF_NAME = "Cache Hit?"
STORE_NODE_NAME = "Simpan Cache VT"
MB_NODE_NAME = "MalwareBazaar Lookup"
SUMMARY_NAME = "Rangkum Hasil"
FLEET_BASE = "http://host.docker.internal:8080"
MB_CRED_NAME = "MalwareBazaar Auth"


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


def ensure_mb_credential(base, api_key, mb_key, dry_run):
    """Reuse credential 'MalwareBazaar Auth' kalau ada; buat kalau belum."""
    creds = api_get(base + "/api/v1/credentials?limit=250", api_key).get("data", [])
    for c in creds:
        if c.get("name") == MB_CRED_NAME and c.get("type") == "httpHeaderAuth":
            print("  Credential '{}' sudah ada (id {}).".format(MB_CRED_NAME, c["id"]))
            return c["id"]
    if dry_run:
        print(f"  [DRY-RUN] akan membuat credential '{MB_CRED_NAME}'.")
        return "dry-run-cred-id"
    created = api_send(
        base + "/api/v1/credentials",
        api_key,
        {
            "name": MB_CRED_NAME,
            "type": "httpHeaderAuth",
            "data": {"name": "Auth-Key", "value": mb_key},
        },
        "POST",
    )
    print("  Credential '{}' dibuat (id {}).".format(MB_CRED_NAME, created["id"]))
    return created["id"]


CACHE_NODE_JS = """// Lapis-1: cache verdict VT di fleet-monitor (POST /api/vt-cache/lookup).
// Kuota VT free 4 req/menit, dan dedup /api/seen ber-key per-agent -> burst
// 100 PC dengan hash SAMA tetap 100 panggilan VT. Cache ini ber-key HASH.
// Fail-open: cache mati/error/timeout -> lanjut panggil VT seperti biasa.
const alert = $input.first().json;
const out = { ...alert, cache_hit: false, cached_stats: null, cache_age_secs: null };
if (alert.hash && /^[0-9a-f]{32,64}$/i.test(alert.hash)) {
  try {
    const resp = await this.helpers.httpRequest({
      method: 'POST',
      url: 'FLEET_BASE/api/vt-cache/lookup',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hash: alert.hash }),
      timeout: 8000,
    });
    if (resp && resp.hit) {
      out.cache_hit = true;
      out.cached_stats = resp.stats || null;
      out.cache_age_secs = resp.age_secs;
    }
  } catch (e) { /* fail-open */ }
}
return [{ json: out }];""".replace("FLEET_BASE", FLEET_BASE)

STORE_NODE_JS = """// Simpan verdict VT ke cache fleet (POST /api/vt-cache/store) supaya hash yang
// sama dari banyak PC tidak memanggil VT berulang. Fail-open: error apa pun ->
// item diteruskan apa adanya (VT OK? tetap membaca $json.data).
// Hanya verdict sah yang disimpan: data VT, atau 404 NotFoundError (hash belum
// dikenal VT -> kelas TTL 'unknown'). 429/5xx/timeout TIDAK disimpan supaya
// error transien tidak membekukan verdict jadi "tidak dikenal" selama 6 jam.
const body = $input.first().json;
const alert = $('Ekstrak Alert').first().json;
const stats = body?.data?.attributes?.last_analysis_stats;
const errCode = body?.error?.code;
let stored = 'skipped';
try {
  let payload = null;
  if (stats) {
    payload = { hash: alert.hash, stats: {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      undetected: stats.undetected || 0,
      harmless: stats.harmless || 0,
      timeout: stats.timeout || 0,
    } };
  } else if (errCode === 'NotFoundError') {
    payload = { hash: alert.hash, not_found: true };
  }
  if (payload) {
    const resp = await this.helpers.httpRequest({
      method: 'POST',
      url: 'FLEET_BASE/api/vt-cache/store',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      timeout: 8000,
    });
    stored = (resp && resp.status) || 'ok';
  }
} catch (e) { stored = 'error'; }
return [{ json: { ...body, cache_stored: stored } }];""".replace("FLEET_BASE", FLEET_BASE)

CACHE_NODE = {
    "name": CACHE_NODE_NAME,
    "type": "n8n-nodes-base.code",
    "typeVersion": 2,
    "position": [0, 448],
    "parameters": {"mode": "runOnceForAllItems", "jsCode": CACHE_NODE_JS},
}

CACHE_IF_NODE = {
    "name": CACHE_IF_NAME,
    "type": "n8n-nodes-base.if",
    "typeVersion": 2.3,
    "position": [140, 448],
    "parameters": {
        "conditions": {
            "options": {"caseSensitive": True, "typeValidation": "loose", "version": 2},
            "conditions": [
                {
                    "id": "cond-cache-hit",
                    "leftValue": "={{ $json.cache_hit }}",
                    "rightValue": True,
                    "operator": {"type": "boolean", "operation": "equals"},
                }
            ],
            "combinator": "and",
        },
        "options": {},
    },
}

STORE_NODE = {
    "name": STORE_NODE_NAME,
    "type": "n8n-nodes-base.code",
    "typeVersion": 2,
    "position": [200, 300],
    "parameters": {"mode": "runOnceForAllItems", "jsCode": STORE_NODE_JS},
}


def mb_node(cred_id):
    return {
        "name": MB_NODE_NAME,
        "type": "n8n-nodes-base.httpRequest",
        "typeVersion": 4.4,
        "position": [300, 390],
        "parameters": {
            "method": "POST",
            "url": "https://mb-api.abuse.ch/api/v1/",
            "authentication": "genericCredentialType",
            "genericAuthType": "httpHeaderAuth",
            "sendBody": True,
            "contentType": "multipart-form-data",
            "bodyParameters": {
                "parameters": [
                    {"name": "query", "value": "get_info"},
                    {
                        "name": "hash",
                        "value": "={{ $('Ekstrak Alert').first().json.hash }}",
                    },
                ]
            },
            "options": {
                "response": {"response": {"neverError": True}},
                "timeout": 15000,
            },
        },
        "credentials": {"httpHeaderAuth": {"id": cred_id, "name": MB_CRED_NAME}},
        "onError": "continueRegularOutput",
    }


# Head jsCode 'Rangkum Hasil' persis versi LIVE sebelum patch ini (jalur upgrade).
HEAD_LIVE_ORIGINAL = """const data = $input.first().json;
// OTX fallback: input dari OTX Lookup berbentuk {pulse_info:{count,...}}, bukan VT
const is_otx = !!data.pulse_info;
const stats = is_otx ? {} : (data.data?.attributes?.last_analysis_stats || {});
const otx_pulses = is_otx ? (data.pulse_info?.count || 0) : 0;
const otx_threat = is_otx && otx_pulses > 0;"""

# Versi 1 (MB hanya di jalur cache miss) — supaya workflow yang sudah dipatch
# sebagian bisa dinaikkan ke versi 2 tanpa dianggap pola asing.
HEAD_V1 = """const inp = $input.first().json;

// Lapis-1 cache VT (node 'Cek Cache VT'): hit -> Scan VirusTotal dilewati.
// Cache miss -> input = respons 'MalwareBazaar Lookup' (sumber intel kedua),
// data VT/OTX diambil lewat referensi node (hanya salah satu yang jalan).
const cache_hit = !!inp.cache_hit;

let data = null;
let otx_data = null;
if (cache_hit) {
  data = { data: { attributes: { last_analysis_stats: inp.cached_stats || {} } } };
} else {
  try { data = $('Scan VirusTotal').first().json; } catch (e) { data = null; }
  try { otx_data = $('OTX Lookup').first().json; } catch (e) { otx_data = null; }
}

// OTX fallback: input dari OTX Lookup berbentuk {pulse_info:{count,...}}, bukan VT
const is_otx = !!otx_data?.pulse_info;
const stats = is_otx ? {} : (data?.data?.attributes?.last_analysis_stats || {});
const otx_pulses = is_otx ? (otx_data.pulse_info?.count || 0) : 0;
const otx_threat = is_otx && otx_pulses > 0;

// MalwareBazaar (ensemble, sumber intel kedua). Signature MB = hash sudah
// terdaftar sebagai malware walau VT masih 0/N -> tanpa ini kasus itu
// disenyapkan sebagai MEDIUM (false-negative).
let mb_known = false;
let mb_malicious = false;
let mb_signature = '';
let mb_tags = [];
let mb_file_type = '';
let mb_query_status = 'not_checked';
const mb = cache_hit ? null : inp;
if (mb && typeof mb.query_status === 'string') {
  mb_query_status = mb.query_status;
  if (mb_query_status === 'ok' && mb.data) {
    const d = Array.isArray(mb.data) ? mb.data[0] : mb.data;
    mb_known = true;
    mb_signature = d?.signature || '';
    mb_tags = d?.tags || [];
    mb_file_type = d?.file_type || '';
    const MALICIOUS_TAGS = ['ransomware', 'trojan', 'backdoor', 'banker',
      'infostealer', 'rat', 'keylogger', 'botnet', 'apt', 'dropper', 'loader'];
    mb_malicious = (!!mb_signature && mb_signature !== 'n/a')
      || mb_tags.some((t) => MALICIOUS_TAGS.includes(String(t).toLowerCase()));
  }
}
const mb_threat = mb_known && mb_malicious;"""

VERSION_MARKER = "// patch:cache-mb:v2"

# Target (versi 2): input Rangkum Hasil SELALU respons 'MalwareBazaar Lookup'
# (node MB dijalankan di kedua jalur), status cache dibaca dari node
# 'Cek Cache VT' yang selalu dieksekusi.
HEAD_V2 = """const mb = $input.first().json;

// Lapis-1 cache VT (node 'Cek Cache VT'): hit -> Scan VirusTotal dilewati.
// Input node ini SELALU respons 'MalwareBazaar Lookup' (jalan di kedua jalur),
// jadi status cache dibaca dari node 'Cek Cache VT' (selalu dieksekusi).
const cacheNode = $('Cek Cache VT').first().json;
const cache_hit = !!cacheNode.cache_hit;

let data = null;
let otx_data = null;
if (cache_hit) {
  data = { data: { attributes: { last_analysis_stats: cacheNode.cached_stats || {} } } };
} else {
  try { data = $('Scan VirusTotal').first().json; } catch (e) { data = null; }
  try { otx_data = $('OTX Lookup').first().json; } catch (e) { otx_data = null; }
}

// OTX fallback: input dari OTX Lookup berbentuk {pulse_info:{count,...}}, bukan VT
const is_otx = !!otx_data?.pulse_info;
const stats = is_otx ? {} : (data?.data?.attributes?.last_analysis_stats || {});
const otx_pulses = is_otx ? (otx_data.pulse_info?.count || 0) : 0;
const otx_threat = is_otx && otx_pulses > 0;

// MalwareBazaar (ensemble, sumber intel kedua). Signature MB = hash sudah
// terdaftar sebagai malware walau VT masih 0/N -> tanpa ini kasus itu
// disenyapkan sebagai MEDIUM (false-negative).
let mb_known = false;
let mb_malicious = false;
let mb_signature = '';
let mb_tags = [];
let mb_file_type = '';
let mb_query_status = 'not_checked';
if (mb && typeof mb.query_status === 'string') {
  mb_query_status = mb.query_status;
  if (mb_query_status === 'ok' && mb.data) {
    const d = Array.isArray(mb.data) ? mb.data[0] : mb.data;
    mb_known = true;
    mb_signature = d?.signature || '';
    mb_tags = d?.tags || [];
    mb_file_type = d?.file_type || '';
    const MALICIOUS_TAGS = ['ransomware', 'trojan', 'backdoor', 'banker',
      'infostealer', 'rat', 'keylogger', 'botnet', 'apt', 'dropper', 'loader'];
    mb_malicious = (!!mb_signature && mb_signature !== 'n/a')
      || mb_tags.some((t) => MALICIOUS_TAGS.includes(String(t).toLowerCase()));
  }
}
const mb_threat = mb_known && mb_malicious;"""

OLD_SEV = "if (malicious >= 20 || ruleLevel >= 12) {"
NEW_SEV = "if (malicious >= 20 || ruleLevel >= 12 || (mb_threat && malicious >= 5)) {"

OLD_HIGH = "} else if (otx_threat || malicious >= 5 || ruleLevel >= 7) {"
NEW_HIGH = "} else if (otx_threat || mb_threat || malicious >= 5 || ruleLevel >= 7) {"

OLD_OUT = """    source: is_otx ? 'otx' : 'vt',
    otx_threat,
    otx_pulses"""
NEW_OUT = """    source: cache_hit ? 'vt-cache' : (is_otx ? 'otx' : 'vt'),
    otx_threat,
    otx_pulses,
    cache_hit,
    mb_known,
    mb_malicious,
    mb_signature,
    mb_tags,
    mb_file_type,
    mb_query_status,
    mb_threat"""


def patch_summary(js):
    """Naikkan jsCode 'Rangkum Hasil' ke versi cache + MB terbaru.

    Idempoten via VERSION_MARKER. Bisa dijalankan pada workflow yang belum
    pernah dipatch (HEAD_LIVE_ORIGINAL) maupun yang sudah versi 1 (HEAD_V1).
    """
    if VERSION_MARKER in js:
        return js, False
    for old_head in (HEAD_LIVE_ORIGINAL, HEAD_V1):
        if old_head in js:
            js = js.replace(old_head, HEAD_V2)
            break
    else:
        raise SystemExit(
            "Head Rangkum Hasil tidak dikenali (bukan versi live asli maupun "
            "versi 1) — patch dibatalkan agar tidak merusak workflow live."
        )
    for old, new in ((OLD_SEV, NEW_SEV), (OLD_HIGH, NEW_HIGH), (OLD_OUT, NEW_OUT)):
        if new in js:
            continue  # sudah versi baru
        if old not in js:
            raise SystemExit(
                "Pola Rangkum Hasil tidak cocok, patch dibatalkan agar tidak "
                "merusak workflow live. Pola hilang:\n" + old[:140]
            )
        js = js.replace(old, new)
    return js + "\n\n" + VERSION_MARKER, True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--workflow-id", default=WORKFLOW_ID_DEFAULT)
    ap.add_argument("--mb-key-file", default="/tmp/mb_api_key.txt")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.api_key_file):
        sys.exit("API key file tidak ada: " + args.api_key_file)
    api_key = read_file(args.api_key_file)
    mb_key = read_file(args.mb_key_file) if os.path.exists(args.mb_key_file) else ""
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
        "deteksi-malware-live-vt-cache-mb-"
        + time.strftime("%Y%m%d-%H%M%S")
        + ".json",
    )
    if not args.dry_run:
        with open(backup_path, "w") as f:
            json.dump(wf, f, indent=2)
        print("  Backup: " + backup_path)

    changed = False

    # 1. Credential MalwareBazaar (dipakai node MB)
    mb_cred_id = ensure_mb_credential(base, api_key, mb_key, args.dry_run)

    # 2. Node baru
    for node_def in (CACHE_NODE, CACHE_IF_NODE, STORE_NODE):
        if get_node(nodes, node_def["name"]) is None:
            nodes.append(json.loads(json.dumps(node_def)))
            print("  Node '{}' ditambahkan.".format(node_def["name"]))
            changed = True
        else:
            print("  Node '{}' sudah ada.".format(node_def["name"]))

    existing_mb = get_node(nodes, MB_NODE_NAME)
    if existing_mb is None:
        nodes.append(mb_node(mb_cred_id))
        print(f"  Node '{MB_NODE_NAME}' ditambahkan.")
        changed = True
    else:
        existing_mb.setdefault("credentials", {})["httpHeaderAuth"] = {
            "id": mb_cred_id,
            "name": MB_CRED_NAME,
        }
        print(f"  Node '{MB_NODE_NAME}' sudah ada (credential dirapikan).")

    # 3. Rewire
    def set_conn(src, outs):
        want = {"main": [[{"node": t, "type": "main", "index": 0}] for t in outs]}
        if conns.get(src) != want:
            conns[src] = want
            print("  Rewire: {} -> {}".format(src, ", ".join(outs) or "(kosong)"))
            return True
        return False

    changed |= set_conn("Dedup Alert", [CACHE_NODE_NAME])
    changed |= set_conn(CACHE_NODE_NAME, [CACHE_IF_NAME])
    changed |= set_conn(CACHE_IF_NAME, [MB_NODE_NAME, "Scan VirusTotal"])
    changed |= set_conn("Scan VirusTotal", [STORE_NODE_NAME])
    changed |= set_conn(STORE_NODE_NAME, ["VT OK?"])
    changed |= set_conn("VT OK?", [MB_NODE_NAME, "OTX Lookup"])
    changed |= set_conn("OTX Lookup", [MB_NODE_NAME])
    changed |= set_conn(MB_NODE_NAME, [SUMMARY_NAME])

    # 4. Rangkum Hasil
    rk = get_node(nodes, SUMMARY_NAME)
    if rk is None:
        raise SystemExit(f"Node '{SUMMARY_NAME}' tidak ditemukan di workflow live.")
    new_js, js_changed = patch_summary(rk.get("parameters", {}).get("jsCode", ""))
    if js_changed:
        rk["parameters"]["jsCode"] = new_js
        print("  Rangkum Hasil: sadar cache-hit + ensemble MalwareBazaar.")
        changed = True
    else:
        print("  Rangkum Hasil: sudah sadar cache + MB.")

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
        print(
            f"Selesai. Aktif: {result.get('active')}, "
            f"node: {len(result.get('nodes', []))}"
        )
    except urllib.error.HTTPError as e:
        print(f"GAGAL PUT: {e.code} {e.read().decode()[:300]}")
        sys.exit(1)


if __name__ == "__main__":
    main()
