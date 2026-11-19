#!/usr/bin/env python3
"""Unit tests untuk scripts/misp-feed-sync.py (unittest.TestCase, offline)."""
import importlib.util
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))


def load_mod():
    spec = importlib.util.spec_from_file_location("misp_feed", os.path.join(HERE, "misp-feed-sync.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


SHA = "a" * 64
EVENT = {
    "Event": {
        "uuid": "11111111-1111-1111-1111-111111111111",
        "info": "OSINT Test Event",
        "date": "2026-01-01",
        "timestamp": "1767225600",
        "Orgc": {"name": "CIRCL"},
        "Tag": [{"name": "type:OSINT"}, {"name": "tlp:white"}],
        "Attribute": [
            {"type": "sha256", "value": SHA, "category": "Payload delivery", "to_ids": True},
            {"type": "md5", "value": "b" * 32, "category": "Payload delivery", "to_ids": False},
            {"type": "domain", "value": "evil.example.com", "category": "Network activity"},
            {"type": "sha256", "value": "short", "category": "Payload delivery"},
            {"type": "comment", "value": "abaikan", "category": "Other"},
        ],
        "Object": [
            {
                "Attribute": [
                    {
                        "type": "filename|sha256",
                        "value": "x.exe|" + "c" * 64,
                        "category": "Payload delivery",
                        "to_ids": True,
                    }
                ]
            }
        ],
    }
}


class TestMispFeedSync(unittest.TestCase):
    def setUp(self):
        self.M = load_mod()
        self.tmp = tempfile.mkdtemp()
        self.db = os.path.join(self.tmp, "custom-misp.db")
        con = self.M.db_connect(self.db)
        try:
            self.M.db_init(con)
            self.added = self.M.index_event(con, EVENT)
            con.commit()
        finally:
            con.close()

    def test_normalization_and_indexing(self):
        self.assertEqual(self.M._norm_type("filename|sha256"), "sha256")
        self.assertEqual(self.M._norm_type("md5"), "md5")
        self.assertEqual(self.M._norm_type("comment"), "comment")
        self.assertEqual(self.added, 4)

        r = self.M.lookup(SHA, self.db)
        self.assertTrue(r["found"])
        self.assertEqual(r["count"], 1)
        self.assertEqual(r["matches"][0]["event_info"], "OSINT Test Event")
        self.assertIn("tlp:white", r["matches"][0]["tags"])
        self.assertTrue(self.M.lookup("c" * 64, self.db)["found"])
        self.assertTrue(self.M.lookup(SHA.upper(), self.db)["found"])
        self.assertFalse(self.M.lookup("f" * 64, self.db)["found"])
        self.assertFalse(self.M.lookup("short", self.db)["found"])

    def test_idempotency_and_stats(self):
        con = self.M.db_connect(self.db)
        try:
            self.M.index_event(con, EVENT)
            con.commit()
            cnt = con.execute("SELECT COUNT(*) FROM attributes").fetchone()[0]
        finally:
            con.close()
        self.assertEqual(cnt, 4)

        st = self.M.stats(self.db)
        self.assertEqual(st["events"], 1)
        self.assertEqual(st["attributes"], 4)
        self.assertIn("sha256", st["by_type"])

    def test_http_handler_honors_server_db_path_and_optional_token(self):
        # Set global DB_PATH ke path lain untuk memastikan Handler memakai srv.db_path
        self.M.DB_PATH = os.path.join(self.tmp, "other-empty.db")
        self.M.API_TOKEN = "misp-secret-token"
        srv = ThreadingHTTPServer(("127.0.0.1", 0), self.M.Handler)
        srv.db_path = self.db
        srv.feed_url = "https://feed.example.test"
        port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.1)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=5) as r:
                self.assertEqual(json.load(r)["status"], "ok")
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(f"http://127.0.0.1:{port}/lookup?value={SHA}", timeout=5)
            self.assertEqual(ctx.exception.code, 401)

            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/lookup?value={SHA}",
                headers={"Authorization": "Bearer misp-secret-token"},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.load(r)
            self.assertTrue(data["found"])
            self.assertEqual(data["count"], 1)
        finally:
            srv.shutdown()
            srv.server_close()


if __name__ == "__main__":
    unittest.main()
