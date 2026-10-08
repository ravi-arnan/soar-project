#!/usr/bin/env python3
"""Unit test MISP feed consumer (offline, tanpa jaringan).

Jalankan: python3 scripts/test_misp_feed.py
Keluar 0 = semua lulus.
"""
import importlib.util
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))


def load_mod():
    spec = importlib.util.spec_from_file_location(
        "misp_feed", os.path.join(HERE, "misp-feed-sync.py")
    )
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


M = load_mod()
passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


SHA = "a" * 64
EVENT = {
    "Event": {
        "uuid": "evt-1",
        "info": "OSINT Test Event",
        "date": "2026-01-01",
        "timestamp": "1767225600",
        "Orgc": {"name": "CIRCL"},
        "Tag": [{"name": "type:OSINT"}, {"name": "tlp:white"}],
        "Attribute": [
            {"type": "sha256", "value": SHA, "category": "Payload delivery", "to_ids": True},
            {"type": "md5", "value": "b" * 32, "category": "Payload delivery", "to_ids": False},
            {"type": "domain", "value": "evil.example.com", "category": "Network activity"},
            {"type": "sha256", "value": "short", "category": "Payload delivery"},  # invalid
            {"type": "comment", "value": "abaikan", "category": "Other"},  # tipe tak relevan
        ],
        "Object": [
            {"Attribute": [{"type": "filename|sha256", "value": "x.exe|" + "c" * 64,
                            "category": "Payload delivery", "to_ids": True}]}
        ],
    }
}


def main():
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "misp.db")

    # 1. normalisasi tipe
    check("norm filename|sha256 -> sha256", M._norm_type("filename|sha256") == "sha256")
    check("norm md5 -> md5", M._norm_type("md5") == "md5")
    check("norm unknown passthrough", M._norm_type("comment") == "comment")

    # 2. index + lookup
    con = M.db_connect(db)
    M.db_init(con)
    n = M.index_event(con, EVENT)
    con.commit()
    con.close()
    # 4 relevan: sha256, md5, domain, filename|sha256 (short & comment dibuang)
    check("index_event memasukkan 4 atribut relevan", n == 4)

    r = M.lookup(SHA, db)
    check("lookup sha256 found", r["found"] and r["count"] == 1)
    check("lookup membawa konteks event", r["matches"][0]["event_info"] == "OSINT Test Event")
    check("lookup membawa tag", "tlp:white" in r["matches"][0]["tags"])
    check("lookup mendeteksi filename|sha256 sebagai sha256",
          M.lookup("c" * 64, db)["found"])

    check("lookup case-insensitive (hash kapital)", M.lookup(SHA.upper(), db)["found"])
    check("lookup yang tak ada -> found False", M.lookup("f" * 64, db)["found"] is False)
    check("short hash tidak terindeks", M.lookup("short", db)["found"] is False)

    # 3. idempotensi
    con = M.db_connect(db)
    M.db_init(con)
    M.index_event(con, EVENT)
    con.commit()
    cnt = con.execute("SELECT COUNT(*) FROM attributes").fetchone()[0]
    con.close()
    check("index ulang tidak menduplikasi (idempoten)", cnt == 4)

    # 4. stats
    s = M.stats(db)
    check("stats events=1", s["events"] == 1)
    check("stats attributes=4", s["attributes"] == 4)
    check("stats punya by_type", "sha256" in s["by_type"])

    # 5. HTTP service
    M.DB_PATH = db
    srv = ThreadingHTTPServer(("127.0.0.1", 0), M.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r2:
            h = json.load(r2)
        check("HTTP /healthz ok", h.get("status") == "ok")
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/lookup?value={SHA}", timeout=5) as r2:
            lk = json.load(r2)
        check("HTTP /lookup mengembalikan found", lk.get("found") is True)
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/stats", timeout=5) as r2:
            st = json.load(r2)
        check("HTTP /stats events=1", st.get("events") == 1)
    finally:
        srv.shutdown()

    print(f"\n{passed}/{passed + failed} lulus")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
