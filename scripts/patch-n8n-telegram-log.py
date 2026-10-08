#!/usr/bin/env python3
"""Observability Telegram: catat setiap alert Telegram yang terkirim.

Menambah node `Log Telegram Alert` di SETIAP workflow yang mengirim Telegram
(`Deteksi Malware`, `Deteksi Phishing`), di-rewire setelah node kirim, dan
fail-open (pengiriman alert tidak tergantung service log).

Bot API Telegram tidak menyediakan histori pesan keluar; node ini menutup celah
itu dengan mengirim ringkasan ke service `alert-log` (default :8091).

Idempoten (node ada + edge benar = tidak berubah), backup otomatis, --dry-run.

Jalankan DI ravi-debian:
  python3 scripts/patch-n8n-telegram-log.py --api-key-file /tmp/n8n_api_key.txt [--dry-run]
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "..", "backups")
LOG_NODE_NAME = "Log Telegram Alert"
LOG_BASE = "http://host.docker.internal:8091"
MARKER = "// patch:tglog:v1"
WORKFLOWS = {
    "1MVcpL7ZKfBhR2tc": "Deteksi Malware",
    "ELhIxkr2uJ43IACs": "Deteksi Phishing",
}
SEND_OPS = {"sendMessage", "sendPhoto", "sendDocument", "sendLocation"}


def read_file(p):
    with open(p) as f:
        return f.read().strip()


def api_get(url, key):
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": key})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def api_send(url, key, payload, method):
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method=method,
        headers={"X-N8N-API-KEY": key, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def log_node_js(workflow_name, node_name, log_base=LOG_BASE):
    js = """// patch:tglog:v1 — catat alert Telegram yang benar-benar terkirim.
// Bot API tak punya histori keluar; kirim ringkasan ke service alert-log.
const inp = $input.first().json;
const rec = { ts: new Date().toISOString(), workflow: 'WF', node: 'NODE' };
try {
  const r = inp.result || inp;
  rec.telegram_ok = (inp.ok === true) || !!r.message_id;
  rec.message_id = r.message_id || null;
  rec.chat_id = (r.chat && r.chat.id) || null;
} catch (e) {}
for (const nm of ['Build Payload', 'Rangkum Hasil', 'Rangkum Chain']) {
  try {
    const p = $(nm).first().json;
    rec.severity = rec.severity || p.severity || p.severityLabel;
    rec.agent = rec.agent || p.agent || p.agentName;
    rec.hash = rec.hash || p.hash;
    rec.path = rec.path || p.filePath || p.path;
    rec.title = rec.title || p.title || p.subject;
    break;
  } catch (e) {}
}
try {
  await this.helpers.httpRequest({
    method: 'POST', url: 'BASE/log', headers: { 'Content-Type': 'application/json' },
    body: rec, timeout: 5000,
  });
} catch (e) { /* fail-open: alert tetap terkirim walau log mati */ }
return [{ json: inp }];"""
    return js.replace("WF", workflow_name).replace("NODE", node_name).replace("BASE", log_base.rstrip("/"))


def log_node(workflow_name, node_name, pos, log_base=LOG_BASE):
    return {
        "name": LOG_NODE_NAME,
        "type": "n8n-nodes-base.code",
        "typeVersion": 2,
        "position": pos,
        "parameters": {"mode": "runOnceForAllItems",
                       "jsCode": log_node_js(workflow_name, node_name, log_base)},
        "onError": "continueRegularOutput",
    }


def is_send_node(n):
    if n.get("type") != "n8n-nodes-base.telegram":
        return False
    p = n.get("parameters", {})
    return p.get("resource") == "message" and p.get("operation") in SEND_OPS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--log-base", default=LOG_BASE)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    log_base = args.log_base.rstrip("/")
    if not os.path.exists(args.api_key_file):
        sys.exit("API key file tidak ada: " + args.api_key_file)
    key = read_file(args.api_key_file)
    base = args.n8n_url.rstrip("/")
    os.makedirs(BACKUP_DIR, exist_ok=True)

    total_changed = 0
    for wid, wname in WORKFLOWS.items():
        wf_url = f"{base}/api/v1/workflows/{wid}"
        print(f"== workflow {wid} ({wname}) ==")
        try:
            wf = api_get(wf_url, key)
        except urllib.error.HTTPError as e:
            print(f"  lewati: {e.code}")
            continue
        nodes = wf.get("nodes", [])
        conns = wf.get("connections", {})
        send_nodes = [n for n in nodes if is_send_node(n)]
        if not send_nodes:
            print("  tak ada node Telegram kirim; lewati.")
            continue

        if not args.dry_run:
            bp = os.path.join(BACKUP_DIR, f"{wid}-tglog-{time.strftime('%Y%m%d-%H%M%S')}.json")
            with open(bp, "w") as f:
                json.dump(wf, f, indent=2)
            print("  backup: " + bp)

        changed = False
        have = any(n.get("name") == LOG_NODE_NAME for n in nodes)
        if not have:
            # posisi: di bawah node kirim pertama
            pos = [send_nodes[0].get("position", [0, 0])[0], send_nodes[0].get("position", [0, 0])[1] + 140]
            nodes.append(log_node(wname, send_nodes[0]["name"], pos, log_base))
            print(f"  node '{LOG_NODE_NAME}' ditambahkan.")
            changed = True

        for sn in send_nodes:
            want = {"main": [[{"node": LOG_NODE_NAME, "type": "main", "index": 0}]]}
            if conns.get(sn["name"]) != want:
                conns[sn["name"]] = want
                print(f"  rewire: {sn['name']} -> {LOG_NODE_NAME}")
                changed = True

        if args.dry_run:
            print("  [DRY-RUN] perubahan:", changed)
            total_changed += changed
            continue
        if not changed:
            print("  tidak ada perubahan.")
            continue
        payload = {"name": wf.get("name"), "nodes": nodes, "connections": conns,
                   "settings": wf.get("settings", {}), "staticData": wf.get("staticData")}
        try:
            res = api_send(wf_url, key, payload, "PUT")
            print(f"  tersimpan. active={res.get('active')} node={len(res.get('nodes', []))}")
            total_changed += 1
        except urllib.error.HTTPError as e:
            print(f"  GAGAL PUT: {e.code} {e.read().decode()[:200]}")
    print("Selesai. workflow berubah:", total_changed)


if __name__ == "__main__":
    main()
