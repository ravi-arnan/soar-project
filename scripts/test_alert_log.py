#!/usr/bin/env python3
"""Unit test alert-log service (offline). Jalankan: python3 scripts/test_alert_log.py"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


def load():
    spec = importlib.util.spec_from_file_location("alog", os.path.join(HERE, "alert-log.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def get(url):
    with urllib.request.urlopen(url, timeout=5) as r:
        return json.load(r)


def post(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def main():
    M = load()
    tmp = tempfile.mkdtemp()
    M.LOG_FILE = os.path.join(tmp, "tg.jsonl")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), M.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    base = f"http://127.0.0.1:{port}"
    try:
        check("healthz ok", get(base + "/healthz").get("status") == "ok")
        r = post(base + "/log", {"ts": "2026-10-08T22:00:00Z", "workflow": "Deteksi Malware",
                                 "node": "Send Telegram Alert", "severity": "HIGH",
                                 "telegram_ok": True, "message_id": 111})
        check("POST /log stored=1", r.get("stored") == 1)
        post(base + "/log", [{"workflow": "Deteksi Phishing", "severity": "CRITICAL"},
                             {"workflow": "Deteksi Malware", "severity": "CRITICAL"}])
        lg = get(base + "/log?limit=10")
        check("GET /log mengembalikan 3 item", lg.get("count") == 3)
        check("urutan terbaru di akhir", lg["items"][-1].get("severity") == "CRITICAL")
        st = get(base + "/stats")
        check("stats total=3", st.get("total") == 3)
        check("stats by_severity", st["by_severity"].get("CRITICAL") == 2)
        check("stats by_workflow", st["by_workflow"].get("Deteksi Malware") == 2)
        check("stats last_ts ada", bool(st.get("last_ts")))
        # limit
        check("GET /log?limit=1 -> 1 item", get(base + "/log?limit=1").get("count") == 1)
    finally:
        srv.shutdown()

    print(f"\n{passed}/{passed + failed} lulus")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
