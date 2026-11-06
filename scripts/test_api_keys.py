#!/usr/bin/env python3
"""
Unit test untuk manajemen API Keys & Agent Access di fleet-monitor.py.
Memverifikasi:
- Pembuatan token (hashing SHA-256, prefix, format soar_live_)
- Hak akses scope (read:fleet, read:intel, write:actions)
- Pencabutan token (revocation)
- Autentikasi via header Authorization Bearer dan X-API-Key
"""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Setup database sementara untuk testing
_TEST_DIR = tempfile.TemporaryDirectory()
os.environ["FLEET_EVENTS_DB"] = os.path.join(_TEST_DIR.name, "test-api-keys.db")
os.environ["FLEET_COMMAND_TOKEN"] = "test-command-token-12345"

MODULE_PATH = Path(__file__).with_name("fleet-monitor.py")
SPEC = importlib.util.spec_from_file_location("fleet_monitor", MODULE_PATH)
assert SPEC and SPEC.loader
fm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fm)


class TestApiKeys(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fm._event_store_init()

    def test_01_create_api_key(self):
        created = fm._api_key_create("Agentic SOC Bot", ["read:intel", "write:actions"])
        self.assertTrue(created["token"].startswith("soar_live_"))
        self.assertEqual(created["name"], "Agentic SOC Bot")
        self.assertIn("read:intel", created["scopes"])
        self.assertIn("write:actions", created["scopes"])
        self.assertTrue(created["prefix"].startswith("soar_live_"))
        self.assertTrue(created["id"].startswith("key_"))

    def test_02_list_api_keys(self):
        keys = fm._api_key_list()
        self.assertGreater(len(keys), 0)
        # Pastikan secret token mentah / key_hash tidak bocor ke output list
        for k in keys:
            self.assertNotIn("token", k)
            self.assertNotIn("key_hash", k)
            self.assertIn("prefix", k)
            self.assertIn("scopes", k)
            self.assertIn("revoked", k)

    def test_03_verify_api_key_valid(self):
        created = fm._api_key_create("Incident Responder", ["read:fleet", "write:actions"])
        token = created["token"]

        # Verifikasi via Authorization: Bearer
        headers_bearer = {"Authorization": f"Bearer {token}"}
        valid, info = fm._verify_api_key(headers_bearer, "write:actions")
        self.assertTrue(valid)
        self.assertIsNotNone(info)
        self.assertEqual(info["name"], "Incident Responder")

        # Verifikasi via X-API-Key
        headers_x = {"X-API-Key": token}
        valid_x, info_x = fm._verify_api_key(headers_x, "read:fleet")
        self.assertTrue(valid_x)
        self.assertIsNotNone(info_x)

    def test_04_verify_api_key_scope_denied(self):
        created = fm._api_key_create("Read Only Monitor", ["read:fleet"])
        token = created["token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Minta scope write:actions pada key yang hanya punya read:fleet
        valid, info = fm._verify_api_key(headers, "write:actions")
        self.assertFalse(valid)
        self.assertIsNone(info)

    def test_05_revoke_api_key(self):
        created = fm._api_key_create("Temporary Agent", ["read:fleet"])
        token = created["token"]
        key_id = created["id"]
        headers = {"Authorization": f"Bearer {token}"}

        # Sebelum dicabut: valid
        valid_before, _ = fm._verify_api_key(headers, "read:fleet")
        self.assertTrue(valid_before)

        # Cabut
        ok = fm._api_key_revoke(key_id)
        self.assertTrue(ok)

        # Setelah dicabut: tidak valid
        valid_after, _ = fm._verify_api_key(headers, "read:fleet")
        self.assertFalse(valid_after)

    def test_06_verify_wildcard_scope(self):
        created = fm._api_key_create("Super Admin Agent", ["*"])
        token = created["token"]
        headers = {"Authorization": f"Bearer {token}"}

        v1, _ = fm._verify_api_key(headers, "read:fleet")
        v2, _ = fm._verify_api_key(headers, "read:intel")
        v3, _ = fm._verify_api_key(headers, "write:actions")
        self.assertTrue(v1)
        self.assertTrue(v2)
        self.assertTrue(v3)


if __name__ == "__main__":
    unittest.main()
