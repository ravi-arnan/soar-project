#!/usr/bin/env python3
"""Unit tests for Workstream 6 (SOC Operational Completeness v1.1):
- Persistent Command Queue & Execution History (ACK)
- Centralized Tamper-Evident Audit Trail (SHA-256 hash chain)
- Agent Lifecycle Management (Revoke & Poll Token Rotation)
- Alert Triage Lifecycle & Event Enrichment
- Dashboard HITL Approval Queue Integration
"""
import importlib.util
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

TEST_COMMAND_TOKEN = "cmd-" + "c" * 48
TEST_POLL_TOKEN_009 = "poll-009-" + "p" * 44
TEST_ALERT_LOG_TOKEN = "al-" + "a" * 50

os.environ.setdefault("FLEET_COMMAND_TOKEN", TEST_COMMAND_TOKEN)
os.environ.setdefault(
    "FLEET_AGENT_POLL_TOKENS_JSON",
    json.dumps({"009": TEST_POLL_TOKEN_009}),
)
os.environ.setdefault("ALERT_LOG_TOKEN", TEST_ALERT_LOG_TOKEN)

SCRIPT_PATH = Path(__file__).resolve().with_name("fleet-monitor.py")
SPEC = importlib.util.spec_from_file_location("fleet_monitor_soc_test", SCRIPT_PATH)
fleet_monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fleet_monitor)


class SocOpsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.db_path = os.path.join(cls._tmpdir.name, "test-soc-events.db")
        cls.state_path = os.path.join(cls._tmpdir.name, "test-soc-state.json")
        fleet_monitor.EVENTS_DB = cls.db_path
        fleet_monitor.STATE_FILE = cls.state_path
        fleet_monitor.FLEET_COMMAND_TOKEN = TEST_COMMAND_TOKEN
        fleet_monitor.FLEET_AGENT_POLL_TOKENS = {"009": TEST_POLL_TOKEN_009}
        fleet_monitor._event_store_init()

        cls.server = HTTPServer(("127.0.0.1", 0), fleet_monitor.Handler)
        cls.port = cls.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)
        cls._tmpdir.cleanup()

    def setUp(self):
        fleet_monitor.FLEET_COMMAND_TOKEN = TEST_COMMAND_TOKEN
        fleet_monitor.FLEET_AGENT_POLL_TOKENS = {"009": TEST_POLL_TOKEN_009}
        fleet_monitor.COMMANDS.clear()
        fleet_monitor.EVENTS.clear()
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM commands")
            conn.execute("DELETE FROM audit_logs")
            conn.execute("DELETE FROM alert_triage")
            conn.execute("DELETE FROM enrolled_agents")
            conn.commit()

    def request(self, method, path, body=None, token=None):
        headers = {}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = Request(f"{self.base_url}{path}", data=data, headers=headers, method=method)
        try:
            with urlopen(req, timeout=3) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except HTTPError as err:
            raw = err.read().decode("utf-8")
            err.close()
            return err.code, json.loads(raw)

    def test_persistent_command_lifecycle_and_restart_reload(self):
        # 1. Queue command
        code, body = self.request(
            "POST",
            "/api/commands",
            {
                "agent_id": "009",
                "action": "quarantine",
                "target": "/home/ravi/Downloads/malware.bin",
                "by": "analyst@soar.local",
            },
            token=TEST_COMMAND_TOKEN,
        )
        self.assertEqual(code, 200)
        self.assertEqual(body["status"], "queued")

        # 2. Simulate fleet-monitor restart: clear in-memory dict, reload from SQLite
        fleet_monitor.COMMANDS.clear()
        fleet_monitor._command_store_load_queued()
        self.assertEqual(len(fleet_monitor.COMMANDS.get("009", [])), 1)
        cmd_id = fleet_monitor.COMMANDS["009"][0]["id"]
        self.assertTrue(cmd_id.startswith("cmd_"))

        # 3. Verify command history shows status='queued'
        code, hist = self.request(
            "GET", "/api/commands/history?agent_id=009", token=TEST_COMMAND_TOKEN
        )
        self.assertEqual(code, 200)
        self.assertEqual(hist["counts"]["queued"], 1)
        self.assertEqual(hist["commands"][0]["id"], cmd_id)
        self.assertEqual(hist["commands"][0]["status"], "queued")

        # 4. Agent polls GET /api/commands -> transitions to 'delivered'
        code, poll_body = self.request(
            "GET", "/api/commands?agent_id=009", token=TEST_POLL_TOKEN_009
        )
        self.assertEqual(code, 200)
        self.assertEqual(len(poll_body["commands"]), 1)
        self.assertEqual(poll_body["commands"][0]["id"], cmd_id)

        code, hist2 = self.request(
            "GET", "/api/commands/history?agent_id=009", token=TEST_COMMAND_TOKEN
        )
        self.assertEqual(hist2["counts"]["delivered"], 1)
        self.assertEqual(hist2["commands"][0]["status"], "delivered")

        # 5. Agent posts ACK -> transitions to 'succeeded'
        code, ack_body = self.request(
            "POST",
            "/api/commands/ack",
            {
                "id": cmd_id,
                "agent_id": "009",
                "status": "succeeded",
                "output": "quarantined to /var/lib/soar-agent/quarantine/123_malware.bin",
            },
            token=TEST_POLL_TOKEN_009,
        )
        self.assertEqual(code, 200)
        self.assertTrue(ack_body["ok"])
        self.assertEqual(ack_body["command"]["status"], "succeeded")
        self.assertIn("quarantined", ack_body["command"]["output"])

        code, hist3 = self.request(
            "GET", "/api/commands/history?agent_id=009", token=TEST_COMMAND_TOKEN
        )
        self.assertEqual(hist3["counts"]["succeeded"], 1)

    def test_audit_trail_hash_chain_verification_and_tamper_detection(self):
        # Generate several audited actions
        self.request(
            "POST",
            "/api/commands",
            {"agent_id": "009", "action": "scan", "target": "/home/ravi/Downloads"},
            token=TEST_COMMAND_TOKEN,
        )
        self.request(
            "POST",
            "/api/triage",
            {"event_key": "evt_101", "status": "investigating", "note": "Checking sample"},
            token=TEST_COMMAND_TOKEN,
        )

        code, audit = self.request("GET", "/api/audit?verify=1", token=TEST_COMMAND_TOKEN)
        self.assertEqual(code, 200)
        self.assertTrue(audit["chain_valid"])
        self.assertGreaterEqual(audit["verified_count"], 2)
        self.assertIsNone(audit["broken_at_id"])

        # Tamper with an audit log entry in SQLite and verify chain_valid becomes False
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("UPDATE audit_logs SET actor = 'attacker' WHERE id = (SELECT MIN(id) FROM audit_logs)")
            conn.commit()

        code, tampered = self.request("GET", "/api/audit?verify=1", token=TEST_COMMAND_TOKEN)
        self.assertEqual(code, 200)
        self.assertFalse(tampered["chain_valid"])
        self.assertIsNotNone(tampered["broken_at_id"])

    def test_agent_rotate_and_revoke_lifecycle(self):
        # 1. Rotate token for agent 009
        code, rot = self.request(
            "POST",
            "/api/enroll/rotate",
            {"agent_id": "009", "rotated_by": "admin@soar.local"},
            token=TEST_COMMAND_TOKEN,
        )
        self.assertEqual(code, 200)
        self.assertTrue(rot["success"])
        new_token = rot["result"]["poll_token"]
        self.assertGreaterEqual(len(new_token), 32)
        self.assertNotEqual(new_token, TEST_POLL_TOKEN_009)

        # Old token must be rejected (401), new token must succeed (200)
        code_old, _ = self.request("GET", "/api/commands?agent_id=009", token=TEST_POLL_TOKEN_009)
        self.assertEqual(code_old, 401)
        code_new, _ = self.request("GET", "/api/commands?agent_id=009", token=new_token)
        self.assertEqual(code_new, 200)

        # 2. Queue a command then revoke agent 009
        self.request(
            "POST",
            "/api/commands",
            {"agent_id": "009", "action": "scan", "target": "/home/ravi/Downloads"},
            token=TEST_COMMAND_TOKEN,
        )
        code_rev, rev = self.request(
            "POST",
            "/api/enroll/revoke",
            {"agent_id": "009", "reason": "Host decommissioned", "revoked_by": "admin@soar.local"},
            token=TEST_COMMAND_TOKEN,
        )
        self.assertEqual(code_rev, 200)
        self.assertTrue(rev["success"])
        self.assertEqual(rev["result"]["status"], "revoked")

        # Polling with rotated token must now return 403 (agent not registered)
        code_after, _ = self.request("GET", "/api/commands?agent_id=009", token=new_token)
        self.assertEqual(code_after, 403)

    def test_alert_triage_and_event_enrichment(self):
        # Insert an event via /webhook-log
        ev_hash = "e" * 64
        self.request(
            "POST",
            "/webhook-log",
            {
                "agent": "ravi-debian",
                "agent_id": "009",
                "path": "/home/ravi/Downloads/dropper.elf",
                "hash": ev_hash,
                "severity": "HIGH",
            },
            token=TEST_COMMAND_TOKEN,
        )

        code, ev_resp = self.request("GET", "/api/events", token=TEST_COMMAND_TOKEN)
        self.assertEqual(code, 200)
        ev_id = ev_resp["events"][0]["id"]
        self.assertEqual(ev_resp["events"][0]["triage_status"], "new")

        # Update triage status
        code, tr_resp = self.request(
            "POST",
            "/api/triage",
            {
                "event_key": ev_id,
                "status": "contained",
                "assignee": "ravi@soar.local",
                "note": "Quarantined via Rust agent",
            },
            token=TEST_COMMAND_TOKEN,
        )
        self.assertEqual(code, 200)
        self.assertEqual(tr_resp["updated"], 1)

        # Verify /api/events now includes enriched triage fields
        code, ev_after = self.request("GET", "/api/events", token=TEST_COMMAND_TOKEN)
        self.assertEqual(code, 200)
        self.assertEqual(ev_after["events"][0]["triage_status"], "contained")
        self.assertEqual(ev_after["events"][0]["triage_assignee"], "ravi@soar.local")
        self.assertEqual(ev_after["events"][0]["triage_note"], "Quarantined via Rust agent")

    def test_dashboard_hitl_resolve_dispatches_rust_command_and_updates_triage(self):
        # Start a lightweight mock alert-log server
        class _MockAlertLogHandler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(length).decode("utf-8"))
                resp = {
                    "ok": True,
                    "found": True,
                    "duplicate": False,
                    "did": body.get("did") or "did1234567890",
                    "hash": body.get("hash") or ("f" * 64),
                    "agent_id": "009",
                    "filepath": "/home/ravi/Downloads/ransom.bin",
                    "severity": "HIGH",
                    "action": body.get("action", "quarantine"),
                    "by": body.get("by", "analyst"),
                    "response_secs": 12,
                }
                raw = json.dumps(resp).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        mock_srv = HTTPServer(("127.0.0.1", 0), _MockAlertLogHandler)
        mock_thread = threading.Thread(target=mock_srv.serve_forever, daemon=True)
        mock_thread.start()
        old_url = os.environ.get("ALERT_LOG_URL")
        os.environ["ALERT_LOG_URL"] = f"http://127.0.0.1:{mock_srv.server_port}"
        try:
            code, res = self.request(
                "POST",
                "/api/hitl/resolve",
                {
                    "did": "did1234567890",
                    "hash": "f" * 64,
                    "agent_id": "009",
                    "action": "quarantine",
                    "by": "ravi@soar.local",
                    "note": "Approved from dashboard",
                },
                token=TEST_COMMAND_TOKEN,
            )
            self.assertEqual(code, 200)
            self.assertTrue(res["ok"])
            self.assertIsNotNone(res["ar_dispatched"])
            self.assertEqual(res["ar_dispatched"]["action"], "quarantine")
            self.assertEqual(res["ar_dispatched"]["target"], "/home/ravi/Downloads/ransom.bin")

            # Verify command is queued for agent 009
            self.assertEqual(len(fleet_monitor.COMMANDS.get("009", [])), 1)
            self.assertEqual(fleet_monitor.COMMANDS["009"][0]["action"], "quarantine")
        finally:
            if old_url is None:
                os.environ.pop("ALERT_LOG_URL", None)
            else:
                os.environ["ALERT_LOG_URL"] = old_url
            mock_srv.shutdown()
            mock_srv.server_close()


if __name__ == "__main__":
    unittest.main()
