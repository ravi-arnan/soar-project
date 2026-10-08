#!/usr/bin/env python3
"""Pencatat alert Telegram keluar (observability) untuk SOAR.

n8n mem-POST setiap alert Telegram yang benar-benar terkirim ke sini; service
menyimpannya sebagai JSONL (durable) di `state/telegram-alerts.jsonl` dan
menyediakan GET untuk melihat riwayat. Ini menutup celah: Bot API Telegram
TIDAK menyediakan histori pesan keluar, jadi kita catat sendiri di titik kirim.

Env:
  ALERT_LOG_FILE  default /state/telegram-alerts.jsonl (atau state/telegram-alerts.jsonl)
  ALERT_LOG_PORT  default 8091

Endpoint:
  POST /log   {..} atau [{..}]  -> {"ok":true,"stored":N}
  GET  /log?limit=50            -> {"count":N,"items":[...]}
  GET  /stats                   -> total, by_severity, by_workflow, last_ts
  GET  /healthz
"""
import json
import os
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOG_FILE = os.getenv("ALERT_LOG_FILE", "state/telegram-alerts.jsonl")
PORT = int(os.getenv("ALERT_LOG_PORT", "8091"))
_lock = threading.Lock()


def _ensure_dir():
    d = os.path.dirname(os.path.abspath(LOG_FILE))
    if d:
        os.makedirs(d, exist_ok=True)


def append_records(records):
    _ensure_dir()
    with _lock:
        with open(LOG_FILE, "a") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(records)


def read_records(limit=50):
    if not os.path.exists(LOG_FILE):
        return []
    with _lock:
        with open(LOG_FILE) as f:
            lines = f.readlines()
    out = []
    for ln in lines[-max(1, limit):]:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def stats():
    items = read_records(limit=100000)
    last_ts = next((i.get("ts") for i in reversed(items) if i.get("ts")), None)
    return {
        "total": len(items),
        "by_severity": dict(Counter(i.get("severity") for i in items if i.get("severity"))),
        "by_workflow": dict(Counter(i.get("workflow") for i in items if i.get("workflow"))),
        "last_ts": last_ts,
        "file": LOG_FILE,
    }


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/healthz", "/"):
            return self._json({"status": "ok", "file": LOG_FILE})
        if u.path == "/log":
            lim = int((q.get("limit") or ["50"])[0])
            items = read_records(limit=lim)
            return self._json({"count": len(items), "items": items})
        if u.path == "/stats":
            return self._json(stats())
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        if u.path != "/log":
            return self._json({"error": "not found"}, 404)
        try:
            n = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(n).decode() or "{}")
        except (ValueError, UnicodeDecodeError):
            return self._json({"error": "bad json"}, 400)
        recs = body if isinstance(body, list) else [body]
        stored = append_records(recs)
        self._json({"ok": True, "stored": stored})


def serve(port=PORT):
    _ensure_dir()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[serve] alert-log di :{port}, file={LOG_FILE}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--log", type=int, default=0, metavar="N")
    a = ap.parse_args()
    if a.stats:
        print(json.dumps(stats(), indent=2, ensure_ascii=False))
    elif a.log:
        print(json.dumps(read_records(a.log), indent=2, ensure_ascii=False))
    else:
        serve(a.port)
