#!/usr/bin/env python3
"""Unit tests untuk scripts/alert-log.py (unittest.TestCase, offline)."""
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
    spec = importlib.util.spec_from_file_location("alog", os.path.join(HERE, "alert-log.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def _post(url, obj, headers=None):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(obj).encode("utf-8"), headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def _expect_error(method, url, obj=None, headers=None):
    try:
        if method == "GET":
            _get(url, headers)
        else:
            _post(url, obj, headers)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)
    return None, None


class TestAlertLog(unittest.TestCase):
    def setUp(self):
        self.M = load_mod()
        self.tmp = tempfile.mkdtemp()
        self.M.LOG_FILE = os.path.join(self.tmp, "tg.jsonl")
        self.M.DECISION_FILE = os.path.join(self.tmp, "decisions.json")
        self.M.DECISION_AUDIT_FILE = os.path.join(self.tmp, "decisions-audit.jsonl")
        self.M.LOG_TOKEN = "secret-alert-log-token-32-chars-ok"
        self.M.DEV_INSECURE = False
        self.M.DECISIONS.clear()
        self.auth = {"Authorization": f"Bearer {self.M.LOG_TOKEN}"}
        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), self.M.Handler)
        self.port = self.srv.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()
        time.sleep(0.1)

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def test_auth_fail_closed_and_healthz_open(self):
        self.assertEqual(_get(self.base + "/healthz").get("status"), "ok")
        code, _ = _expect_error("GET", self.base + "/log")
        self.assertEqual(code, 401)
        code, _ = _expect_error("POST", self.base + "/log", {"workflow": "x"})
        self.assertEqual(code, 401)
        code, _ = _expect_error("GET", self.base + "/stats")
        self.assertEqual(code, 401)
        # Fail-closed bila LOG_TOKEN kosong dan DEV_INSECURE=False
        self.M.LOG_TOKEN = ""
        code, _ = _expect_error("POST", self.base + "/log", {"workflow": "x"})
        self.assertEqual(code, 401)

    def test_log_and_stats(self):
        r = _post(
            self.base + "/log",
            {"ts": "2026-10-08T22:00:00Z", "workflow": "Deteksi Malware", "severity": "HIGH"},
            self.auth,
        )
        self.assertEqual(r.get("stored"), 1)
        _post(
            self.base + "/log",
            [
                {"workflow": "Deteksi Phishing", "severity": "CRITICAL"},
                {"workflow": "Deteksi Malware", "severity": "CRITICAL"},
            ],
            self.auth,
        )
        lg = _get(self.base + "/log?limit=10", self.auth)
        self.assertEqual(lg.get("count"), 3)
        self.assertEqual(lg["items"][-1].get("severity"), "CRITICAL")
        st = _get(self.base + "/stats", self.auth)
        self.assertEqual(st.get("total"), 3)
        self.assertEqual(st["by_severity"].get("CRITICAL"), 2)
        self.assertEqual(st["by_workflow"].get("Deteksi Malware"), 2)

    def test_hitl_decision_lifecycle_and_multi_agent_isolation(self):
        h = "a" * 64
        r1 = _post(
            self.base + "/decision/pending",
            {
                "hash": h, "agent_id": "010", "filepath": "/home/u1/Downloads/evil.exe",
                "severity": "HIGH", "tier": "hitl-review", "hitl": True, "deadline_secs": 900,
            },
            self.auth,
        )
        r2 = _post(
            self.base + "/decision/pending",
            {
                "hash": h, "agent_id": "011", "filepath": "/home/u2/Downloads/evil.exe",
                "severity": "HIGH", "tier": "hitl-review", "hitl": True, "deadline_secs": 900,
            },
            self.auth,
        )
        self.assertTrue(r1["ok"] and r2["ok"])
        self.assertNotEqual(r1["did"], r2["did"])
        pend = _get(self.base + "/decision/pending", self.auth)
        self.assertEqual(pend["count"], 2)

        # Prefix 1 karakter harus ditolak (anti-short-prefix resolve)
        res_short = _post(
            self.base + "/decision/resolve",
            {"hash": "a", "action": "quarantine", "by": "analyst"},
            self.auth,
        )
        self.assertFalse(res_short.get("found"))

        # Resolve spesifik agent 010 memakai did
        res1 = _post(
            self.base + "/decision/resolve",
            {"hash": r1["did"], "action": "quarantine", "by": "analyst"},
            self.auth,
        )
        self.assertTrue(res1["ok"] and res1["found"])
        self.assertEqual(res1["agent_id"], "010")
        self.assertEqual(res1["filepath"], "/home/u1/Downloads/evil.exe")

        # Agent 011 masih pending dan tidak tertimpa
        pend2 = _get(self.base + "/decision/pending", self.auth)
        self.assertEqual(pend2["count"], 1)
        self.assertEqual(pend2["items"][0]["agent_id"], "011")

    def test_expiry_persisted_and_cannot_resolve(self):
        h = "f" * 64
        key = f"010:{h}"
        self.M.DECISIONS[key] = {
            "key": key, "hash": h, "did": self.M._decision_did("010", h), "hitl": True,
            "agent_id": "010", "filepath": "/tmp/old.bin",
            "created_ts": time.time() - self.M.DECISION_TTL_SECS - 10,
            "deadline_ts": time.time() - 1000, "status": "pending",
        }
        items = _get(self.base + "/decision/pending?all=1", self.auth)["items"]
        self.assertTrue(any(i.get("hash") == h and i.get("status") == "expired" for i in items))
        # Status expired terpersist di memory/state dan tidak bisa di-resolve
        self.assertEqual(self.M.DECISIONS[key]["status"], "expired")
        code, body = _expect_error(
            "POST",
            self.base + "/decision/resolve",
            {"hash": h, "action": "quarantine", "by": "analyst"},
            self.auth,
        )
        self.assertEqual(code, 400)
        self.assertIn("kedaluwarsa", body.get("error", ""))


if __name__ == "__main__":
    unittest.main()
