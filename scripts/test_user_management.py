#!/usr/bin/env python3
"""Unit test untuk User Management, PBKDF2-600k, RBAC & Cloudflare Access Sync di fleet-monitor.py."""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_TEST_DIR = tempfile.TemporaryDirectory()
os.environ["FLEET_EVENTS_DB"] = os.path.join(_TEST_DIR.name, "test-users.db")
os.environ["FLEET_COMMAND_TOKEN"] = "test-command-token-rbac-1234567890"
os.environ["FLEET_BOOTSTRAP_ADMIN_EMAIL"] = "admin@example.com"
os.environ["FLEET_BOOTSTRAP_ADMIN_PASSWORD"] = "BootstrapAdmin2026!"

MODULE_PATH = Path(__file__).with_name("fleet-monitor.py")
SPEC = importlib.util.spec_from_file_location("fleet_monitor", MODULE_PATH)
assert SPEC and SPEC.loader
fm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fm)


class TestUserManagement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fm._event_store_init()
        fm._user_create(
            username="analyst",
            password="AnalystUser2026!",
            role="analyst",
            email="analyst@soar.local",
            name="SOC Analyst",
        )
        fm._user_create(
            username="auditor",
            password="AuditorUser2026!",
            role="viewer",
            email="auditor@example.com",
            name="External Auditor",
        )

    def test_01_bootstrap_admin_and_roles(self):
        users = fm._user_list()
        usernames = {u["username"]: u for u in users}
        self.assertIn("admin", usernames)
        self.assertEqual(usernames["admin"]["role"], "admin")
        self.assertEqual(usernames["admin"]["email"], "admin@example.com")
        self.assertIn("analyst", usernames)
        self.assertEqual(usernames["analyst"]["role"], "analyst")
        self.assertIn("auditor", usernames)
        self.assertEqual(usernames["auditor"]["role"], "viewer")

    def test_02_authenticate_users_and_pbkdf2_600k(self):
        admin = fm._user_authenticate("admin", "BootstrapAdmin2026!")
        self.assertIsNotNone(admin)
        self.assertEqual(admin["role"], "admin")

        analyst = fm._user_authenticate("analyst", "AnalystUser2026!")
        self.assertIsNotNone(analyst)
        self.assertEqual(analyst["role"], "analyst")

        self.assertIsNone(fm._user_authenticate("admin", "wrong-password"))
        self.assertIsNone(fm._user_authenticate("ghost_user", "any-password"))

        # Verifikasi format hash baru PBKDF2 600k
        h = fm._hash_password("Secret12345!")
        self.assertTrue(h.startswith("pbkdf2_sha256$600000$"))
        self.assertTrue(fm._verify_password("Secret12345!", h))

    def test_03_create_user(self):
        new_user = fm._user_create(
            username="investigator1",
            password="InvestigatorPass123!",
            role="analyst",
            email="inv1@example.com",
            name="Forensics Analyst",
        )
        self.assertEqual(new_user["username"], "investigator1")
        self.assertEqual(new_user["role"], "analyst")
        self.assertTrue(new_user["id"].startswith("usr_"))
        self.assertIsNotNone(fm._user_authenticate("investigator1", "InvestigatorPass123!"))

    def test_04_create_user_validation(self):
        with self.assertRaises(ValueError):
            fm._user_create("ab", "ValidPass123!")
        with self.assertRaises(ValueError):
            fm._user_create("valid_user", "short")
        with self.assertRaises(ValueError):
            fm._user_create("admin", "AnotherPass123!")

    def test_05_update_user(self):
        created = fm._user_create(
            username="junior_dev",
            password="JuniorDevPass123!",
            role="viewer",
            email="dev@soar.local",
            name="Junior Developer",
        )
        updated = fm._user_update(created["id"], {"role": "analyst", "name": "Mid Developer"})
        self.assertEqual(updated["role"], "analyst")
        self.assertEqual(updated["name"], "Mid Developer")

    def test_06_guard_last_admin(self):
        with self.assertRaises(ValueError):
            fm._user_update("usr_admin", {"active": False})
        with self.assertRaises(ValueError):
            fm._user_update("usr_admin", {"role": "viewer"})
        with self.assertRaises(ValueError):
            fm._user_delete("usr_admin")

    def test_07_delete_user(self):
        temp_user = fm._user_create(
            username="temp_contractor",
            password="TempContractor123!",
            role="viewer",
        )
        self.assertTrue(fm._user_delete(temp_user["id"]))
        self.assertIsNone(fm._user_authenticate("temp_contractor", "TempContractor123!"))

    def test_08_lookup_by_email(self):
        user = fm._user_by_email("auditor@example.com")
        self.assertIsNotNone(user)
        self.assertEqual(user["role"], "viewer")

        admin = fm._user_by_email("admin@example.com")
        self.assertIsNotNone(admin)
        self.assertEqual(admin["role"], "admin")

        self.assertIsNone(fm._user_by_email("unknown@notfound.com"))

    def test_09_cloudflare_sync_unconfigured(self):
        with mock.patch.dict(os.environ, {
            "CLOUDFLARE_API_TOKEN": "",
            "CLOUDFLARE_ACCOUNT_ID": "",
            "CLOUDFLARE_ACCESS_POLICY_ID": "",
        }, clear=False):
            res = fm._sync_cloudflare_access_policy()
            self.assertFalse(res["configured"])
            self.assertFalse(res["synced"])
            self.assertEqual(res["status"], "unconfigured")

    def test_10_cloudflare_sync_preserves_rules_and_excludes_local_emails(self):
        captured = {}

        def fake_cf_req(url, token, method="GET", payload=None, timeout=12):
            captured.setdefault("calls", []).append((method, url, payload))
            if method == "GET":
                return {
                    "success": True,
                    "result": {
                        "id": "pol-123",
                        "name": "Admin only",
                        "decision": "allow",
                        "precedence": 1,
                        "custom_cf_field": True,
                        "include": [
                            {"email": {"email": "stale@old.com"}},
                            {"ip": {"ip": "10.0.0.0/8"}},
                        ],
                        "require": [],
                        "exclude": [],
                    },
                }
            return {"success": True, "result": {"id": "pol-123", "name": "Admin only"}}

        with mock.patch.dict(os.environ, {
            "CLOUDFLARE_API_TOKEN": "cf-test-token-secret",
            "CLOUDFLARE_ACCOUNT_ID": "acc-123",
            "CLOUDFLARE_ACCESS_APP_ID": "app-456",
            "CLOUDFLARE_ACCESS_POLICY_ID": "pol-123",
        }, clear=False), mock.patch.object(fm, "_cf_api_request", side_effect=fake_cf_req):
            res = fm._sync_cloudflare_access_policy()
            self.assertTrue(res["configured"])
            self.assertTrue(res["synced"])
            self.assertIn("admin@example.com", res["emails"])
            self.assertIn("auditor@example.com", res["emails"])
            # Email .local tidak boleh ikut dikirim ke Cloudflare Access
            self.assertNotIn("analyst@soar.local", res["emails"])
            put_call = [c for c in captured["calls"] if c[0] == "PUT"][0]
            self.assertTrue(put_call[2].get("custom_cf_field"))
            include_rules = put_call[2]["include"]
            self.assertIn({"ip": {"ip": "10.0.0.0/8"}}, include_rules)
            self.assertNotIn({"email": {"email": "stale@old.com"}}, include_rules)


if __name__ == "__main__":
    unittest.main()
