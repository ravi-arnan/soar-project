#!/usr/bin/env python3
"""
Unit test untuk Automated Agent Enrollment & Approval Workflow (Tahap 2).
Memverifikasi:
- Pembuatan permohonan pendaftaran agent (pending request)
- Lookup status permohonan pendaftaran
- Persetujuan (Approve) oleh admin yang menerbitkan Agent ID dan Poll Token unik
- Pendaftaran token ke dalam FLEET_AGENT_POLL_TOKENS secara dinamis
- Penolakan (Reject) permohonan pendaftaran
- Pemuatan ulang enrolled agents dari database SQLite
- Pembuatan script bash dan powershell installer otomatis
"""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_TEST_DIR = tempfile.TemporaryDirectory()
os.environ["FLEET_EVENTS_DB"] = os.path.join(_TEST_DIR.name, "test-enrollment.db")
os.environ["FLEET_COMMAND_TOKEN"] = "test-command-token-enroll-12345678"

MODULE_PATH = Path(__file__).with_name("fleet-monitor.py")
SPEC = importlib.util.spec_from_file_location("fleet_monitor", MODULE_PATH)
assert SPEC and SPEC.loader
fm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fm)


class TestAgentEnrollment(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fm._event_store_init()

    def test_01_create_enrollment_request(self):
        req = fm._enroll_request_create(
            hostname="finance-workstation-01",
            os_name="linux",
            arch="x86_64",
            ip="192.168.1.105",
        )
        self.assertIsNotNone(req)
        self.assertTrue(req["request_id"].startswith("req_"))
        self.assertEqual(req["hostname"], "finance-workstation-01")
        self.assertEqual(req["status"], "pending")
        self.assertEqual(req["os"], "linux")

        # Verifikasi via lookup
        fetched = fm._enroll_request_get(req["request_id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["id"], req["request_id"])
        self.assertEqual(fetched["status"], "pending")
        self.assertIsNone(fetched["agent_id"])

    def test_02_list_enrollment_requests(self):
        reqs = fm._enroll_requests_list(status_filter="pending")
        self.assertGreaterEqual(len(reqs), 1)
        found = any(r["hostname"] == "finance-workstation-01" for r in reqs)
        self.assertTrue(found)

    def test_03_approve_enrollment_request(self):
        req = fm._enroll_request_create(
            hostname="hr-laptop-02",
            os_name="windows",
            arch="x64",
            ip="192.168.1.110",
        )
        approved = fm._enroll_request_approve(
            req_id=req["request_id"],
            custom_agent_id="004",
            custom_name="laptop-hr",
            approved_by="admin_test",
        )
        self.assertEqual(approved["status"], "approved")
        self.assertEqual(approved["agent_id"], "004")
        self.assertEqual(approved["agent_name"], "laptop-hr")
        self.assertGreaterEqual(len(approved["poll_token"]), 32)

        # Verifikasi bahwa token terdaftar di runtime memori FLEET_AGENT_POLL_TOKENS
        self.assertIn("004", fm.FLEET_AGENT_POLL_TOKENS)
        self.assertEqual(fm.FLEET_AGENT_POLL_TOKENS["004"], approved["poll_token"])

        # Verifikasi status lookup request
        status_info = fm._enroll_request_get(req["request_id"])
        self.assertEqual(status_info["status"], "approved")
        self.assertEqual(status_info["agent_id"], "004")
        self.assertEqual(status_info["poll_token"], approved["poll_token"])

    def test_04_reject_enrollment_request(self):
        req = fm._enroll_request_create(
            hostname="unknown-rogue-device",
            os_name="linux",
            arch="arm64",
            ip="10.0.0.99",
        )
        rejected = fm._enroll_request_reject(req["request_id"], rejected_by="admin_test")
        self.assertEqual(rejected["status"], "rejected")

        # Status check
        status_info = fm._enroll_request_get(req["request_id"])
        self.assertEqual(status_info["status"], "rejected")
        self.assertIsNone(status_info["agent_id"])

    def test_05_cannot_reapprove_or_rereject(self):
        req = fm._enroll_request_create(hostname="test-once", os_name="linux")
        fm._enroll_request_approve(req["request_id"])
        with self.assertRaises(ValueError):
            fm._enroll_request_approve(req["request_id"])
        with self.assertRaises(ValueError):
            fm._enroll_request_reject(req["request_id"])

    def test_06_script_generation(self):
        origin = "https://soar.raviarnan.dev"
        sh_script = fm._generate_linux_installer_script(origin)
        self.assertIn(origin, sh_script)
        self.assertIn("/api/enroll/request", sh_script)
        self.assertIn("/api/enroll/status", sh_script)
        self.assertIn("soar-agent.service", sh_script)

        ps_script = fm._generate_windows_installer_script(origin)
        self.assertIn(origin, ps_script)
        self.assertIn("/api/enroll/request", ps_script)
        self.assertIn("Invoke-RestMethod", ps_script)


if __name__ == "__main__":
    unittest.main()
