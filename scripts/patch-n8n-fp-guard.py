#!/usr/bin/env python3
"""patch-n8n-fp-guard.py — perisai lapis-2 anti false-positive + fix Telegram crash.

Latar (14 Sep): agent lama mengirim noise (mirror Wine dosdevices, git objects,
db-wal, cache) -> Filter Alert Malware lolos semua (cuma cek "ada hash") ->
Telegram spam + kuota VT habis. Exec 702: Telegram gagal total karena
parse_mode Markdown pecah oleh karakter di path file.

Dua perubahan (dry-run default, --apply untuk PUT via API):
  1. Filter Alert Malware: tambah kondisi boolean "path BUKAN noise"
     (pola regex sama dengan should_ignore() di agent-rs/src/main.rs).
  2. Send Telegram Alert: escape karakter Markdown pada 3 interpolasi teks
     bebas (filename, filepath, ollama_response). vt_footer dibiarkan mentah
     (link VT disengaja).

Pola CLI sama dengan patch-n8n-log-fleet.py:
  python3 scripts/patch-n8n-fp-guard.py --in /tmp/wf-live.json --out /tmp/wf-patched.json
  python3 scripts/patch-n8n-fp-guard.py --in /tmp/wf-live.json --apply \\
      --n8n-url http://127.0.0.1:5678 --api-key-file /tmp/n8n_api_key.txt
"""

import argparse
import copy
import datetime
import json
import os
import sys
import urllib.request

WORKFLOW_ID = "1MVcpL7ZKfBhR2tc"  # Deteksi Malware (live)

# ponytail: kanan = regex literal "/pola/flags" (didukung parseRegexLiteral,
# diverifikasi dari source n8n-workflow filter-parameter.js di container).
# Kiri HANYA pakai konstruk yang terbukti (??, ||, ?.) — ekspresi kompleks
# (regex literal & .test di kiri) bikin IF error "convert to boolean"
# (exec 719/720). Daftar pola mirror should_ignore() agent-rs.
NOISE_PATTERN = (
    r"/\/(dosdevices|\.git|node_modules|__pycache__|\.cache|cache)\/"
    r"|\.db-(wal|shm|journal)$"
    r"|\.(tmp|log|swp|iso|dmg)$"
    r"|~$|\.ds_store$|thumbs\.db$/i"
)
PATH_EXPR = (
    "($json.body ?? $json).syscheck?.path "
    "|| ($json.body ?? $json).data?.path "
    "|| ($json.body ?? $json).filepath || ''"
)

# Escape Markdown legacy untuk interpolasi teks bebas di pesan Telegram.
# vt_footer TIDAK di-escape (link disengaja). Lihat exec 702.
MD_ESCAPE_JS = r".replace(/([_*\[\]()~`>#+\-=|{}.!\\])/g, '\\$1')"


def md_wrap(expr: str) -> str:
    return f"(({expr} ?? '') + ''){MD_ESCAPE_JS}"


def find_node(wf: dict, name: str) -> dict:
    for n in wf["nodes"]:
        if n["name"] == name:
            return n
    sys.exit(f"ERROR: node {name!r} tidak ketemu")


def patch_filter(node: dict) -> None:
    conds = node["parameters"]["conditions"]["conditions"]
    if len([c for c in conds if c.get("id") == "cond-has-hash"]) != 1:
        sys.exit("ERROR: kondisi Filter berubah dari yang dikenal, batal (cek manual)")
    # ponytail: prefix "=" WAJIB — tanpa itu n8n anggap literal string
    # (bukan ekspresi). Pernah kejadian 14 Sep: "{{ ... }}" lolos semua
    # (notRegex vs teks literal = true) dan versi boolean-nya error
    # "convert to boolean" (exec 719/720/721/723).
    left = "={{ " + PATH_EXPR + " }}"
    for c in conds:
        if c.get("id") == "cond-not-noise":
            # ponytail: v1/v2 (regex literal & .test/.includes di kiri) bikin
            # IF error "convert to boolean" (exec 719/720). Bentuk final:
            # op string NATIVE notRegex + pola di kanan. Timpa kalau beda.
            want = {
                "id": "cond-not-noise",
                "leftValue": left,
                "rightValue": NOISE_PATTERN,
                "operator": {"type": "string", "operation": "notRegex"},
            }
            if c == want:
                print("[=] Filter: cond-not-noise sudah final, skip")
            else:
                c.clear()
                c.update(want)
                print("[+] Filter: cond-not-noise diganti notRegex native")
            return
    conds.append(
        {
            "id": "cond-not-noise",
            "leftValue": left,
            "rightValue": NOISE_PATTERN,
            "operator": {"type": "string", "operation": "notRegex"},
        }
    )
    print("[+] Filter: cond-not-noise ditambahkan (AND dengan cond-has-hash)")


def patch_telegram(node: dict) -> None:
    text = node["parameters"]["text"]
    # ponytail: idempoten — apply 2x tanpa guard bikin escape ganda
    # (backslash literal di pesan). Pernah kejadian 14 Sep, jangan diulang.
    if text.count(".replace(/([") >= 3:
        print("[=] Telegram: sudah di-escape, skip")
        return
    targets = {
        '$("Ekstrak Alert").first().json.filename': "filename",
        '$("Ekstrak Alert").first().json.filepath': "filepath",
        "$json.ollama_response": "ollama_response",
    }
    for raw, label in targets.items():
        if text.count(raw) != 1:
            sys.exit(
                f"ERROR: interpolasi {label} muncul {text.count(raw)}x "
                "(ekspektasi 1x), batal biar tidak salah ganti"
            )
        text = text.replace(raw, md_wrap(raw))
        print(f"[+] Telegram: {label} di-escape Markdown")
    node["parameters"]["text"] = text


def patch(wf: dict) -> dict:
    wf = copy.deepcopy(wf)
    if wf.get("id", WORKFLOW_ID) != WORKFLOW_ID:
        sys.exit(f"ERROR: workflow id {wf.get('id')} != {WORKFLOW_ID}, batal")
    patch_filter(find_node(wf, "Filter Alert Malware"))
    patch_telegram(find_node(wf, "Send Telegram Alert"))
    return wf


def put_workflow(base_url: str, api_key: str, wf: dict) -> dict:
    payload = {
        "name": wf["name"],
        "nodes": wf["nodes"],
        "connections": wf["connections"],
        "settings": wf.get("settings", {"executionOrder": "v1"}),
    }
    req = urllib.request.Request(
        f"{base_url}/api/v1/workflows/{WORKFLOW_ID}",
        data=json.dumps(payload).encode(),
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
        method="PUT",
    )
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--out", dest="outfile", default="")
    ap.add_argument("--n8n-url", default="")
    ap.add_argument("--api-key-file", default="")
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args()

    wf = json.load(open(a.infile))
    patched = patch(wf)

    # Backup otomatis sebelum apply (pola repo: backups/)
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    backup_dir = os.path.join(repo, "backups")
    if a.apply:
        os.makedirs(backup_dir, exist_ok=True)
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        backup = os.path.join(backup_dir, f"deteksi-malware-pre-fp-guard-{ts}.json")
        json.dump(wf, open(backup, "w"), indent=2, ensure_ascii=False)
        print(f"[i] backup workflow asli: {backup}")

    if a.outfile:
        json.dump(patched, open(a.outfile, "w"), indent=2, ensure_ascii=False)
        print(f"[i] hasil ditulis ke {a.outfile}")

    if a.apply:
        if not (a.n8n_url and a.api_key_file):
            sys.exit("ERROR: --apply butuh --n8n-url dan --api-key-file")
        key = open(a.api_key_file).read().strip()
        res = put_workflow(a.n8n_url, key, patched)
        print(f"[i] PUT ok: id={res.get('id')} nodes={len(res.get('nodes', []))}")


if __name__ == "__main__":
    main()
