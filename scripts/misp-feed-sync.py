#!/usr/bin/env python3
"""Konsumen feed MISP (OSINT) untuk SOAR — sumber threat-intel ke-4.

Menarik feed MISP format publik (default: CIRCL OSINT) TANPA API key, mengekstrak
atribut IOC (hash/domain/ip/url) dari event, lalu menyimpan index ke SQLite untuk
lookup cepat. Bisa juga dijalankan sebagai service HTTP (`--serve`) supaya n8n
dapat bertanya `GET /lookup?value=<hash>`.

Kenapa feed, bukan instance MISP penuh: feed MISP = data MISP asli & ter-update,
tanpa perlu menjalankan stack MISP (MySQL+Redis+PHP) yang berat. Cocok untuk
server terbatas; tidak ada RAM/disk MISP platform — hanya index (beberapa MB).

Env:
  MISP_FEED_URL   default https://www.circl.lu/doc/misp/feed-osint
  MISP_DB         default state/misp.db
  MISP_PORT       default 8090 (untuk --serve)
  MISP_SYNC_HOURS default 12 (interval sync di mode serve)
  MISP_MAX_EVENTS default 0 (0 = semua)

Pakai:
  python3 misp-feed-sync.py --sync                 # bangun/perbarui index
  python3 misp-feed-sync.py --sync --limit 50      # uji cepat
  python3 misp-feed-sync.py --lookup <hash|domain|ip|url>
  python3 misp-feed-sync.py --stats
  python3 misp-feed-sync.py --serve                # HTTP + sync berkala
"""

import argparse
import concurrent.futures
import json
import os
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

FEED_URL = os.getenv("MISP_FEED_URL", "https://www.circl.lu/doc/misp/feed-osint").rstrip("/")
DB_PATH = os.getenv("MISP_DB", "state/misp.db")
PORT = int(os.getenv("MISP_PORT", "8090"))
SYNC_HOURS = float(os.getenv("MISP_SYNC_HOURS", "12"))
MAX_EVENTS = int(os.getenv("MISP_MAX_EVENTS", "0"))
WORKERS = int(os.getenv("MISP_WORKERS", "8"))
TIMEOUT = int(os.getenv("MISP_TIMEOUT", "30"))

# Tipe atribut yang diindeks untuk lookup cepat.
HASH_TYPES = {"md5", "sha1", "sha256", "sha512", "ssdeep", "imphash",
              "authentihash", "sha3-256", "sha3-512"}
OTHER_TYPES = {"domain", "hostname", "url", "uri", "ip-src", "ip-dst", "ip",
               "domain|ip", "email", "filename"}


# ─── DB ─────────────────────────────────────────────────────────────────
def db_connect(path=DB_PATH):
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    con = sqlite3.connect(path, timeout=30)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def db_init(con):
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS events(
            uuid TEXT PRIMARY KEY,
            timestamp INTEGER,
            info TEXT,
            date TEXT,
            orgc TEXT
        );
        CREATE TABLE IF NOT EXISTS attributes(
            value TEXT,
            type TEXT,
            event_uuid TEXT,
            event_info TEXT,
            event_date TEXT,
            category TEXT,
            to_ids INTEGER,
            tags TEXT,
            PRIMARY KEY(value, type, event_uuid)
        );
        CREATE INDEX IF NOT EXISTS idx_attr_value ON attributes(value);
        """
    )
    con.commit()


# ─── Fetch ──────────────────────────────────────────────────────────────
def fetch_json(url, timeout=TIMEOUT):
    req = Request(url, headers={"User-Agent": "soar-misp-feed/1.0"})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def _norm_type(t):
    t = (t or "").lower().strip()
    if "|" in t:  # e.g. "filename|sha256" -> hash-nya sha256
        parts = [p for p in t.split("|") if p in HASH_TYPES]
        if parts:
            return parts[-1]
        return t
    return t


def extract_attributes(event):
    """Ambil atribut relevan dari Event MISP (top-level + dalam Object)."""
    ev = event.get("Event", event)
    attrs = []
    for a in ev.get("Attribute", []) or []:
        attrs.append(a)
    for obj in ev.get("Object", []) or []:
        for a in obj.get("Attribute", []) or []:
            attrs.append(a)
    return ev, attrs


def index_event(con, event):
    ev, attrs = extract_attributes(event)
    uuid = ev.get("uuid")
    if not uuid:
        return 0
    tags = ",".join(t.get("name", "") for t in (ev.get("Tag") or []) if t.get("name"))
    orgc = (ev.get("Orgc") or {}).get("name", "")
    con.execute(
        "INSERT OR REPLACE INTO events(uuid,timestamp,info,date,orgc) VALUES(?,?,?,?,?)",
        (uuid, int(ev.get("timestamp", 0) or 0), ev.get("info", ""), ev.get("date", ""), orgc),
    )
    n = 0
    for a in attrs:
        raw = a.get("type") or ""
        v = str(a.get("value", "")).strip()
        if not v:
            continue
        t = _norm_type(raw)
        if t not in HASH_TYPES and t not in OTHER_TYPES:
            continue
        if t in HASH_TYPES:
            if "|" in raw:  # komposit, mis. "evil.exe|d41d8cd98f..."
                v = v.split("|")[-1]
            v = v.lower()
            if len(v) < 32:  # buang yang bukan hash valid
                continue
        con.execute(
            "INSERT OR IGNORE INTO attributes(value,type,event_uuid,event_info,event_date,category,to_ids,tags) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (v, t, uuid, ev.get("info", ""), ev.get("date", ""),
             a.get("category", ""), 1 if a.get("to_ids") else 0, tags),
        )
        n += 1
    return n


def sync(db=DB_PATH, limit=MAX_EVENTS, workers=WORKERS, feed_url=FEED_URL, log=print):
    """Tarik manifest + event baru → index. Return dict statistik."""
    feed_url = feed_url.rstrip("/")
    log(f"[sync] feed={feed_url}")
    manifest = fetch_json(f"{feed_url}/manifest.json")
    if not isinstance(manifest, dict):
        raise RuntimeError("manifest bukan objek JSON")
    con = db_connect(db)
    db_init(con)

    known = {r[0]: r[1] for r in con.execute("SELECT uuid,timestamp FROM events")}
    todo = []
    for uuid, meta in manifest.items():
        ts = int((meta or {}).get("timestamp", 0) or 0)
        if known.get(uuid) == ts and ts:
            continue
        todo.append((uuid, ts))
    if limit:
        todo = todo[:limit]
    log(f"[sync] manifest {len(manifest)} event; perlu diambil: {len(todo)}")

    got = attrs = failed = 0
    lock = threading.Lock()

    def one(item):
        uuid, ts = item
        try:
            ev = fetch_json(f"{feed_url}/{uuid}.json")
            return uuid, ev
        except (HTTPError, URLError, ValueError) as e:
            return uuid, {"__error": str(e)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        for uuid, ev in pool.map(one, todo):
            if "__error" in ev:
                failed += 1
                continue
            with lock:
                attrs += index_event(con, ev)
                got += 1
                if got % 100 == 0:
                    con.commit()
                    log(f"[sync]   {got}/{len(todo)} event, {attrs} atribut")
    con.commit()

    tot_ev = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    tot_at = con.execute("SELECT COUNT(*) FROM attributes").fetchone()[0]
    con.close()
    stats = {"feed": feed_url, "manifest": len(manifest), "fetched": got,
             "failed": failed, "attrs_added": attrs, "events_total": tot_ev,
             "attrs_total": tot_at, "timestamp": int(time.time())}
    log(f"[sync] selesai: +{got} event, +{attrs} atribut | total {tot_ev} event / {tot_at} atribut")
    return stats


# ─── Lookup ─────────────────────────────────────────────────────────────
def lookup(value, db=DB_PATH):
    if not value:
        return {"found": False, "value": value, "matches": []}
    v = value.strip()
    con = db_connect(db)
    db_init(con)
    rows = con.execute(
        "SELECT value,type,event_uuid,event_info,event_date,category,to_ids,tags "
        "FROM attributes WHERE value=? OR value=? LIMIT 25",
        (v, v.lower()),
    ).fetchall()
    con.close()
    matches = [
        {"value": r[0], "type": r[1], "event_uuid": r[2], "event_info": r[3],
         "event_date": r[4], "category": r[5], "to_ids": bool(r[6]),
         "tags": [t for t in (r[7] or "").split(",") if t]}
        for r in rows
    ]
    return {"found": bool(matches), "value": value, "count": len(matches),
            "matches": matches, "source": "misp-feed"}


def stats(db=DB_PATH):
    con = db_connect(db)
    db_init(con)
    ev = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    at = con.execute("SELECT COUNT(*) FROM attributes").fetchone()[0]
    by_type = dict(con.execute(
        "SELECT type, COUNT(*) FROM attributes GROUP BY type ORDER BY 2 DESC LIMIT 15"))
    last = con.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
    con.close()
    return {"events": ev, "attributes": at, "by_type": by_type,
            "last_event_ts": last, "db": db, "feed": FEED_URL}


# ─── HTTP service ───────────────────────────────────────────────────────
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
            return self._json({"status": "ok", "feed": FEED_URL})
        if u.path == "/lookup":
            return self._json(lookup((q.get("value") or q.get("hash") or [""])[0], DB_PATH))
        if u.path == "/stats":
            return self._json(stats(DB_PATH))
        self._json({"error": "not found"}, 404)


def serve(db=DB_PATH, port=PORT, sync_hours=SYNC_HOURS, feed_url=FEED_URL):
    def loop():
        while True:
            try:
                sync(db, feed_url=feed_url)
            except Exception as e:  # noqa: BLE001
                print(f"[sync] error: {e}", file=sys.stderr, flush=True)
            time.sleep(max(1, sync_hours) * 3600)

    threading.Thread(target=loop, daemon=True).start()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[serve] MISP feed service di :{port}, feed={feed_url}, db={db}", flush=True)
    srv.serve_forever()


def main():
    ap = argparse.ArgumentParser(description="Konsumen feed MISP (OSINT) untuk SOAR")
    ap.add_argument("--sync", action="store_true", help="bangun/perbarui index")
    ap.add_argument("--lookup", metavar="VALUE", help="cari IOC (hash/domain/ip/url)")
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--serve", action="store_true", help="jalankan HTTP + sync berkala")
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--feed-url", default=FEED_URL)
    ap.add_argument("--limit", type=int, default=MAX_EVENTS)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()

    if args.lookup is not None:
        print(json.dumps(lookup(args.lookup, args.db), indent=2, ensure_ascii=False))
    elif args.stats:
        print(json.dumps(stats(args.db), indent=2, ensure_ascii=False))
    elif args.serve:
        serve(args.db, args.port, feed_url=args.feed_url)
    elif args.sync:
        print(json.dumps(sync(args.db, args.limit, feed_url=args.feed_url),
                         indent=2, ensure_ascii=False))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
