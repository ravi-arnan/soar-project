#!/usr/bin/env python3
"""Konsumen feed MISP (OSINT) untuk SOAR - sumber threat-intel ke-4.

Env:
  MISP_FEED_URL   default https://www.circl.lu/doc/misp/feed-osint
  MISP_DB         default state/misp.db
  MISP_BIND       default 127.0.0.1
  MISP_PORT       default 8090
  MISP_SYNC_HOURS default 12
  MISP_MAX_EVENTS default 0 (0 = semua)
  MISP_API_TOKEN  opsional; jika diisi, /lookup dan /stats wajib Bearer token
"""

import argparse
import concurrent.futures
import hmac
import json
import os
import re
import sqlite3
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, urlparse
from urllib.request import Request, urlopen

FEED_URL = os.getenv("MISP_FEED_URL", "https://www.circl.lu/doc/misp/feed-osint").rstrip("/")
DB_PATH = os.getenv("MISP_DB", "state/misp.db")
BIND = os.getenv("MISP_BIND", "127.0.0.1")
PORT = int(os.getenv("MISP_PORT", "8090"))
SYNC_HOURS = float(os.getenv("MISP_SYNC_HOURS", "12"))
MAX_EVENTS = int(os.getenv("MISP_MAX_EVENTS", "0"))
WORKERS = int(os.getenv("MISP_WORKERS", "8"))
TIMEOUT = int(os.getenv("MISP_TIMEOUT", "30"))
API_TOKEN = os.getenv("MISP_API_TOKEN", "").strip()
MAX_RESPONSE_BYTES = 32 * 1024 * 1024
UUID_RE = re.compile(r"^[0-9a-fA-F-]{8,64}$")

HASH_TYPES = {
    "md5", "sha1", "sha256", "sha512", "ssdeep", "imphash",
    "authentihash", "sha3-256", "sha3-512",
}
OTHER_TYPES = {
    "domain", "hostname", "url", "uri", "ip-src", "ip-dst", "ip",
    "domain|ip", "email", "filename",
}


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


def fetch_json(url, timeout=TIMEOUT):
    req = Request(url, headers={"User-Agent": "soar-misp-feed/1.0"})
    with urlopen(req, timeout=timeout) as r:
        data = r.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise ValueError("respons MISP melebihi batas ukuran")
        return json.loads(data.decode("utf-8", "replace"))


def _norm_type(t):
    t = (t or "").lower().strip()
    if "|" in t:
        parts = [p for p in t.split("|") if p in HASH_TYPES]
        if parts:
            return parts[-1]
        return t
    return t


def extract_attributes(event):
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
    con.execute("DELETE FROM attributes WHERE event_uuid=?", (uuid,))
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
            if "|" in raw:
                v = v.split("|")[-1]
            v = v.lower()
            if len(v) < 32:
                continue
        con.execute(
            "INSERT OR IGNORE INTO attributes(value,type,event_uuid,event_info,event_date,category,to_ids,tags) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (
                v, t, uuid, ev.get("info", ""), ev.get("date", ""),
                a.get("category", ""), 1 if a.get("to_ids") else 0, tags,
            ),
        )
        n += 1
    return n


def sync(db=DB_PATH, limit=MAX_EVENTS, workers=WORKERS, feed_url=FEED_URL, log=print):
    feed_url = feed_url.rstrip("/")
    log(f"[sync] feed={feed_url}")
    manifest = fetch_json(f"{feed_url}/manifest.json")
    if not isinstance(manifest, dict):
        raise RuntimeError("manifest bukan objek JSON")
    con = db_connect(db)
    try:
        db_init(con)
        known = {r[0]: r[1] for r in con.execute("SELECT uuid,timestamp FROM events")}
        todo = []
        for uuid, meta in manifest.items():
            if not isinstance(uuid, str) or not UUID_RE.fullmatch(uuid):
                continue
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
            uuid, _ts = item
            try:
                ev = fetch_json(f"{feed_url}/{uuid}.json")
                return uuid, ev
            except (HTTPError, URLError, ValueError) as e:
                return uuid, {"__error": str(e)}

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            for _uuid, ev in pool.map(one, todo):
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
    finally:
        con.close()

    res = {
        "feed": feed_url, "manifest": len(manifest), "fetched": got,
        "failed": failed, "attrs_added": attrs, "events_total": tot_ev,
        "attrs_total": tot_at, "timestamp": int(time.time()),
    }
    log(f"[sync] selesai: +{got} event, +{attrs} atribut | total {tot_ev} event / {tot_at} atribut")
    return res


def lookup(value, db=DB_PATH):
    if not value:
        return {"found": False, "value": value, "matches": []}
    v = value.strip()
    con = db_connect(db)
    try:
        try:
            rows = con.execute(
                "SELECT value,type,event_uuid,event_info,event_date,category,to_ids,tags "
                "FROM attributes WHERE value=? OR value=? LIMIT 25",
                (v, v.lower()),
            ).fetchall()
        except sqlite3.OperationalError:
            db_init(con)
            rows = []
    finally:
        con.close()
    matches = [
        {
            "value": r[0], "type": r[1], "event_uuid": r[2], "event_info": r[3],
            "event_date": r[4], "category": r[5], "to_ids": bool(r[6]),
            "tags": [t for t in (r[7] or "").split(",") if t],
        }
        for r in rows
    ]
    return {
        "found": bool(matches), "value": value, "count": len(matches),
        "matches": matches, "source": "misp-feed",
    }


def stats(db=DB_PATH, feed_url=FEED_URL):
    con = db_connect(db)
    try:
        try:
            ev = con.execute("SELECT COUNT(*) FROM events").fetchone()[0]
            at = con.execute("SELECT COUNT(*) FROM attributes").fetchone()[0]
            by_type = dict(
                con.execute(
                    "SELECT type, COUNT(*) FROM attributes GROUP BY type ORDER BY 2 DESC LIMIT 15"
                )
            )
            last = con.execute("SELECT MAX(timestamp) FROM events").fetchone()[0]
        except sqlite3.OperationalError:
            db_init(con)
            ev, at, by_type, last = 0, 0, {}, None
    finally:
        con.close()
    return {
        "events": ev, "attributes": at, "by_type": by_type,
        "last_event_ts": last, "db": db, "feed": feed_url,
    }


def _authorized(headers):
    if not API_TOKEN:
        return True
    value = headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return False
    try:
        return hmac.compare_digest(value[7:].strip(), API_TOKEN)
    except (TypeError, UnicodeEncodeError):
        return False


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        try:
            self.request.settimeout(15)
        except OSError:
            pass

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        db_path = getattr(self.server, "db_path", DB_PATH)
        feed_url = getattr(self.server, "feed_url", FEED_URL)
        try:
            if u.path in ("/healthz", "/"):
                return self._json({"status": "ok"})
            if not _authorized(self.headers):
                return self._json({"error": "unauthorized"}, 401, {"WWW-Authenticate": "Bearer"})
            if u.path == "/lookup":
                return self._json(lookup((q.get("value") or q.get("hash") or [""])[0], db_path))
            if u.path == "/stats":
                return self._json(stats(db_path, feed_url=feed_url))
            return self._json({"error": "not found"}, 404)
        except Exception as e:  # noqa: BLE001
            return self._json({"error": f"internal error: {type(e).__name__}"}, 500)


def serve(db=DB_PATH, port=PORT, sync_hours=SYNC_HOURS, feed_url=FEED_URL, bind=BIND):
    con = db_connect(db)
    try:
        db_init(con)
    finally:
        con.close()

    def loop():
        while True:
            try:
                sync(db, feed_url=feed_url)
            except Exception as e:  # noqa: BLE001
                print(f"[sync] error: {e}", file=sys.stderr, flush=True)
            time.sleep(max(1, sync_hours) * 3600)

    threading.Thread(target=loop, daemon=True).start()
    srv = ThreadingHTTPServer((bind, port), Handler)
    srv.db_path = db
    srv.feed_url = feed_url
    print(f"[serve] MISP feed service di {bind}:{port}, feed={feed_url}, db={db}", flush=True)
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
    ap.add_argument("--bind", default=BIND)
    ap.add_argument("--port", type=int, default=PORT)
    args = ap.parse_args()

    if args.lookup is not None:
        print(json.dumps(lookup(args.lookup, args.db), indent=2, ensure_ascii=False))
    elif args.stats:
        print(json.dumps(stats(args.db, feed_url=args.feed_url), indent=2, ensure_ascii=False))
    elif args.serve:
        serve(args.db, args.port, feed_url=args.feed_url, bind=args.bind)
    elif args.sync:
        print(json.dumps(sync(args.db, args.limit, feed_url=args.feed_url), indent=2, ensure_ascii=False))
    else:
        ap.print_help()


if __name__ == "__main__":
    main()
