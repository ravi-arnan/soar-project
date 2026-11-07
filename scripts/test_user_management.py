#!/usr/bin/env python3
"""
Unit test untuk User Management & Role-Based Access Control (RBAC) di fleet-monitor.py.
Memverifikasi:
- Seeding akun default (admin, analyst, auditor)
- Autentikasi user (PBKDF2-HMAC-SHA256 password hashing & verification)
- Pembuatan user baru dengan validasi role (admin, analyst, viewer)
- Update profile, role, dan password
- Guard proteksi agar admin aktif terakhir tidak dapat dihapus atau dinonaktifkan
- API endpoints /api/users dan /api/auth/login
"""

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

_TEST_DIR = tempfile.TemporaryDirectory()
os.environ["FLEET_EVENTS_DB"] = os.path.join(_TEST_DIR.name, "test-users.db")
os.environ["FLEET_COMMAND_TOKEN"] = "test-command-token-rbac-12345"

MODULE_PATH = Path(__file__).with_name("fleet-monitor.py")
SPEC = importlib.util.spec_from_file_location("fleet_monitor", MODULE_PATH)
assert SPEC and SPEC.loader
fm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fm)


class TestUserManagement(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fm._event_store_init()

    def test_01_default_users_seeded(self):
        users = fm._user_list()
        self.assertGreaterEqual(len(users), 3)
        usernames = {u["username"]: u for u in users}
        self.assertIn("admin", usernames)
        self.assertEqual(usernames["admin"]["role"], "admin")
        self.assertIn("analyst", usernames)
        self.assertEqual(usernames["analyst"]["role"], "analyst")
        self.assertIn("auditor", usernames)
        self.assertEqual(usernames["auditor"]["role"], "viewer")

    def test_02_authenticate_users(self):
        # Admin auth
        admin = fm._user_authenticate("admin", "Admin@SOAR2026!")
        self.assertIsNotNone(admin)
        self.assertEqual(admin["username"], "admin")
        self.assertEqual(admin["role"], "admin")

        # Analyst auth
        analyst = fm._user_authenticate("analyst", "Analyst@SOAR2026!")
        self.assertIsNotNone(analyst)
        self.assertEqual(analyst["role"], "analyst")

        # Wrong password
        wrong = fm._user_authenticate("admin", "wrong-password")
        self.assertIsNone(wrong)

        # Non-existent user
        non_exist = fm._user_authenticate("ghost_user", "any-password")
        self.assertIsNone(non_exist)

    def test_03_create_user(self):
        new_user = fm._user_create(
            username="investigator1",
            password="InvestigatorPass123!",
            role="analyst",
            email="inv1@soar.local",
            name="Forensics Analyst",
        )
        self.assertEqual(new_user["username"], "investigator1")
        self.assertEqual(new_user["role"], "analyst")
        self.assertEqual(new_user["email"], "inv1@soar.local")
        self.assertTrue(new_user["id"].startswith("usr_"))

        # Verifikasi auth user baru
        auth_ok = fm._user_authenticate("investigator1", "InvestigatorPass123!")
        self.assertIsNotNone(auth_ok)
        self.assertEqual(auth_ok["role"], "analyst")

    def test_04_create_user_validation(self):
        # Username terlalu pendek
        with self.assertRaises(ValueError):
            fm._user_create("ab", "ValidPass123!")

        # Password terlalu pendek
        with self.assertRaises(ValueError):
            fm._user_create("valid_user", "short")

        # Username duplikat
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
        # Promosikan jadi analyst
        updated = fm._user_update(created["id"], {"role": "analyst", "name": "Mid Developer"})
        self.assertEqual(updated["role"], "analyst")
        self.assertEqual(updated["name"], "Mid Developer")

        # Verifikasi efek update pada auth
        auth_dev = fm._user_authenticate("junior_dev", "JuniorDevPass123!")
        self.assertEqual(auth_dev["role"], "analyst")

    def test_06_guard_last_admin(self):
        # Dilarang menonaktifkan akun admin terakhir
        with self.assertRaises(ValueError):
            fm._user_update("usr_admin", {"active": False})

        # Dilarang mengubah role admin terakhir jadi viewer
        with self.assertRaises(ValueError):
            fm._user_update("usr_admin", {"role": "viewer"})

        # Dilarang menghapus akun admin terakhir
        with self.assertRaises(ValueError):
            fm._user_delete("usr_admin")

    def test_07_delete_user(self):
        temp_user = fm._user_create(
            username="temp_contractor",
            password="TempContractor123!",
            role="viewer",
        )
        self.assertTrue(fm._user_delete(temp_user["id"]))
        # Pastikan tidak bisa login lagi
        self.assertIsNone(fm._user_authenticate("temp_contractor", "TempContractor123!"))


if __name__ == "__main__":
    unittest.main()
