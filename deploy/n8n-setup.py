#!/usr/bin/env python3
"""n8n-setup.py — sinkronisasi credentials + import workflow n8n via REST API.

Menutup satu-satunya langkah manual yang tersisa dari setup-server.sh: buat
credentials n8n dari .env (Telegram, Wazuh, GSB, urlscan, MalwareBazaar) +
VirusTotal key (ditanya sekali, TIDAK disimpan ke .env), lalu import 4 workflow
dengan **remap credential ID by name** — hal yang tidak dilakukan import-from-file
UI (file bawa ID credential dari mesin lama, node jadi merah).

API: pakai n8n public REST API v1 dengan owner API key (N8N_OWNER_API_KEY di
.env atau flag --api-key). Public API v1 punya endpoint credentials penuh
(create/list), jadi tidak perlu cache encryption key.

Pemakaian:
  N8N_OWNER_API_KEY=xxx python3 deploy/n8n-setup.py --push-credentials
  N8N_OWNER_API_KEY=xxx python3 deploy/n8n-setup.py --import-workflows
  N8N_OWNER_API_KEY=xxx python3 deploy/n8n-setup.py --all
  python3 deploy/n8n-setup.py --dry-run          # tanpa API key: cetak rencana saja

ponytail: idempoten — credential dengan nama sama di-reuse (update data kalau
berubah), workflow dengan nama sama di-update (bukan duplikat).
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(REPO, ".env")

WORKFLOWS = [
    "deteksi-malware",
    "deteksi-phishing",
    "telegram-callback-handler",
    "proaktif-phishing",
]

# Kredensial yang dibuat dari .env. name harus SAMA dengan yang direferensikan
# node di n8n-workflows/*.json (kolom "credentials" -> "<type>.name").
CREDENTIALS = [
    {
        "name": "Telegram account",
        "type": "telegramApi",
        "schema": {"telegramApi": {"accessToken": None}},  # dari TELEGRAM_BOT_TOKEN
        "env": {"TELEGRAM_BOT_TOKEN": "accessToken"},
        "keys_env": ["TELEGRAM_BOT_TOKEN"],
    },
    {
        "name": "Wazuh Creds",
        "type": "httpBasicAuth",
        "env": {"WAZUH_API_USER": "user", "WAZUH_API_PASS": "password"},
        "keys_env": ["WAZUH_API_USER", "WAZUH_API_PASS"],
    },
    {
        "name": "GSB Query Auth",
        "type": "httpQueryAuth",
        "env": {"GSB_API_KEY": "key", "_GSB_PARAM": "name"},
        "keys_env": ["GSB_API_KEY"],
        "extra": {"name": "key"},  # query param name = 'key' (GSB v4)
    },
    {
        "name": "urlscan API",
        "type": "httpHeaderAuth",
        "env": {"URLSCAN_API_KEY": "value", "_URLSCAN_HEADER": "name"},
        "keys_env": ["URLSCAN_API_KEY"],
        "extra": {"name": "X-API-Key"},  # header name urlscan.io
    },
    {
        # MalwareBazaar: node "MalwareBazaar Lookup" pakai httpHeaderAuth Auth-Key.
        # Sumber intel kedua (ensemble VT+MB) — key dari .env MALWAREBAZAAR_API_KEY.
        "name": "MalwareBazaar Auth",
        "type": "httpHeaderAuth",
        "env": {"MALWAREBAZAAR_API_KEY": "value", "_MB_HEADER": "name"},
        "keys_env": ["MALWAREBAZAAR_API_KEY"],
        "extra": {"name": "Auth-Key"},  # header name mb-api.abuse.ch
    },
    {
        # VirusTotal: node "Scan VirusTotal" pakai httpHeaderAuth x-apikey.
        # Key TIDAK di .env — ditanya interaktif / flag --vt-key / env VT_API_KEY.
        "name": "VirusTotal API Key",
        "type": "httpHeaderAuth",
        "env": {"VT_API_KEY_EFFECTIVE": "value", "_VT_HEADER": "name"},
        "keys_env": ["VT_API_KEY_EFFECTIVE"],
        "extra": {"name": "x-apikey"},
        "secret_source": "VT_API_KEY",  # dari flag/env/prompt, bukan .env
    },
]


def load_env():
    env = {}
    if os.path.exists(ENV_FILE):
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip().strip('"').strip("'")
    return env


def ask_vt_key(env):
    """VirusTotal key: flag --vt-key > env VT_API_KEY > prompt. Tidak ke .env."""
    if args.vt_key:
        return args.vt_key
    if os.environ.get("VT_API_KEY"):
        return os.environ["VT_API_KEY"]
    if not sys.stdin.isatty():
        return None
    print(
        "? VirusTotal API key (https://www.virustotal.com/gui/my-apikey): ",
        end="",
        flush=True,
    )
    key = input().strip()
    return key or None


def build_data(cred, env, vt_key):
    """Susun field data sesuai schema tipe credential n8n."""
    t = cred["type"]
    data = {}
    if t == "telegramApi":
        data = {"accessToken": env.get("TELEGRAM_BOT_TOKEN", "")}
    elif t == "httpBasicAuth":
        data = {
            "user": env.get("WAZUH_API_USER", ""),
            "password": env.get("WAZUH_API_PASS", ""),
        }
    elif t == "httpQueryAuth":
        data = {"name": "key"}
    elif t == "httpHeaderAuth":
        header = cred.get("extra", {}).get("name", "X-API-Key")
        if cred["name"].startswith("VirusTotal"):
            value = vt_key or ""
        else:
            value = env.get(cred["keys_env"][0], "")
        data = {"name": header, "value": value}
    return data


def missing_keys(cred, env, vt_key):
    """Kembalikan daftar env var yang masih kosong untuk credential ini."""
    out = []
    if cred["name"].startswith("VirusTotal"):
        if not vt_key:
            out.append("VT_API_KEY (--vt-key / prompt)")
    else:
        for k in cred["keys_env"]:
            if not env.get(k):
                out.append(k)
    return out


# ----------------------------------------------------------------- HTTP helper


def api(base, key, method, path, body=None):
    req = urllib.request.Request(
        base.rstrip("/") + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"X-N8N-API-Key": key, "Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:300]
        raise SystemExit(f"[x] {method} {path} -> HTTP {e.code}: {detail}")


# ------------------------------------------------------------------- workflow


def remap_credentials(nodes, name_to_id):
    """Ganti credential id di nodes dengan id credential yang BARU dibuat
    (match by name + type). Inilah yang bikin node tidak merah pasca-import."""
    remapped = 0
    for node in nodes:
        creds = node.get("credentials") or {}
        for ctype, ref in list(creds.items()):
            cname = ref.get("name")
            if (
                cname
                and cname in name_to_id
                and name_to_id[cname][0] == ctype
                and ref.get("id") != name_to_id[cname][1]
            ):
                ref["id"] = name_to_id[cname][1]
                remapped += 1
    return remapped


def import_workflows(base, key, name_to_id, dry=False):
    results = []
    for wf in WORKFLOWS:
        path = os.path.join(REPO, "n8n-workflows", wf + ".json")
        with open(path) as f:
            raw = json.load(f)

        # File repo kadang dibungkus list (export UI) — ambil objeknya.
        if isinstance(raw, list):
            raw = raw[0]

        nodes = raw.get("nodes", [])
        remapped = remap_credentials(nodes, name_to_id)

        body = {
            "name": raw.get("name", wf),
            "nodes": nodes,
            "connections": raw.get("connections", {}),
            "settings": raw.get("settings", {"executionOrder": "v1"}),
        }
        want_active = bool(raw.get("active"))

        # Idempoten: kalau workflow dengan nama sama sudah ada -> update.
        # (dry-run: lewati lookup API, cukup rencana)
        match = None
        if not dry:
            existing = api(base, key, "GET", "/api/v1/workflows?limit=250")
            match = next(
                (w for w in existing.get("data", []) if w.get("name") == body["name"]),
                None,
            )
        if match:
            wid = match["id"]
            api(base, key, "PUT", f"/api/v1/workflows/{wid}", body)
            results.append((wf, "updated", remapped, wid))
        else:
            if dry:
                results.append((wf, "create", remapped, None))
            else:
                created = api(base, key, "POST", "/api/v1/workflows", body)
                wid = created.get("id")
                results.append((wf, "created", remapped, wid))

        # Aktifkan (trigger webhook/schedule butuh active)
        if not dry and want_active and wid:
            try:
                cur = api(base, key, "GET", f"/api/v1/workflows/{wid}")
                if not cur.get("active"):
                    # PUT active butuh full object versi terbaru (versionId dsb.)
                    cur.update(body)
                    cur["active"] = True
                    cur.pop("shared", None)
                    cur.pop("versionId", None)
                    api(base, key, "PUT", f"/api/v1/workflows/{wid}", cur)
            except SystemExit:
                results.append((wf, "aktif-gagal(coba UI)", remapped, wid))

    return results


def push_credentials(base, key, env, vt_key, dry=False):
    """Buat/update 5 credentials; kembalikan map name -> (type, id)."""
    # Ambil daftar credential yang sudah ada (idempoten)
    have = {}
    if not dry:
        listing = api(base, key, "GET", "/api/v1/credentials?limit=250")
        for c in listing.get("data", []):
            have[c["name"]] = c

    name_to_id = {}
    for cred in CREDENTIALS:
        missing = missing_keys(cred, env, vt_key)
        if missing:
            print(f"  [skip] {cred['name']}: {', '.join(missing)} kosong")
            continue
        data = build_data(cred, env, vt_key)
        if dry:
            print(f"  [dry] {cred['name']} ({cred['type']})")
            name_to_id[cred["name"]] = (cred["type"], "DRY")
            continue
        if cred["name"] in have:
            cid = have[cred["name"]]["id"]
            api(
                base,
                key,
                "PATCH",
                f"/api/v1/credentials/{cid}",
                {"name": cred["name"], "type": cred["type"], "data": data},
            )
            print(f"  [update] {cred['name']} (id={cid})")
        else:
            created = api(
                base,
                key,
                "POST",
                "/api/v1/credentials",
                {"name": cred["name"], "type": cred["type"], "data": data},
            )
            cid = created.get("id") or (created.get("data") or {}).get("id")
            print(f"  [create] {cred['name']} (id={cid})")
        name_to_id[cred["name"]] = (cred["type"], cid)
    return name_to_id


def main():
    global args
    ap = argparse.ArgumentParser(description="n8n credentials + workflow sync")
    ap.add_argument("--url", default=os.environ.get("N8N_URL", "http://127.0.0.1:5678"))
    ap.add_argument("--api-key", default=os.environ.get("N8N_OWNER_API_KEY", ""))
    ap.add_argument(
        "--vt-key", default="", help="VirusTotal API key (tidak disimpan ke .env)"
    )
    ap.add_argument("--push-credentials", action="store_true")
    ap.add_argument("--import-workflows", action="store_true")
    ap.add_argument("--all", action="store_true", help="credentials lalu workflows")
    ap.add_argument(
        "--dry-run", action="store_true", help="tanpa N8N_OWNER_API_KEY: cetak rencana"
    )
    args = ap.parse_args()

    env = load_env()
    vt_key = ask_vt_key(env)

    dry = args.dry_run or not args.api_key
    base, key = args.url, args.api_key

    do_creds = args.all or args.push_credentials or dry
    do_wfs = args.all or args.import_workflows or dry

    print(f"n8n: {base}  mode: {'DRY-RUN' if dry else 'LIVE'}")
    name_to_id = {}
    if do_creds:
        print("== credentials ==")
        name_to_id = push_credentials(base, key, env, vt_key, dry=dry)
    if do_wfs:
        print("== workflows ==")
        if not name_to_id and not dry:
            # ambil credential existing biar remap tetap jalan
            listing = api(base, key, "GET", "/api/v1/credentials?limit=250")
            for c in listing.get("data", []):
                name_to_id[c["name"]] = (c.get("type", ""), c["id"])
        results = import_workflows(base, key, name_to_id, dry=dry)
        for wf, action, remapped, wid in results:
            print(f"  [{action}] {wf}  (remap {remapped} credential ref)")
        if dry:
            print("\n(dry-run — jalankan dengan N8N_OWNER_API_KEY untuk eksekusi)")

    return 0


if __name__ == "__main__":
    sys.exit(main())
