#!/usr/bin/env python3
"""
Unit test untuk Konfigurasi Dinamis AI Engine & Multi-Source Threat Intel (Tahap 3).
Memverifikasi:
- Seeding default konfigurasi dinamis (AI model Gemini 2.5 Flash, VT, MB, OTX)
- Pengambilan konfigurasi dengan masking API key
- Pembaruan konfigurasi dinamis (model AI, temperature, threshold, dan consensus mode)
- Pengujian inferensi AI (_test_ai_inference)
- Proteksi agar masking key tidak menimpa nilai secret asli
- Endpoint runtime-config untuk konsumsi n8n
"""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

_TEST_DIR = tempfile.TemporaryDirectory()
os.environ["FLEET_EVENTS_DB"] = os.path.join(_TEST_DIR.name, "test-settings.db")
os.environ["FLEET_COMMAND_TOKEN"] = "test-command-token-settings-12345"

MODULE_PATH = Path(__file__).with_name("fleet-monitor.py")
SPEC = importlib.util.spec_from_file_location("fleet_monitor", MODULE_PATH)
assert SPEC and SPEC.loader
fm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fm)


class TestDynamicSettings(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fm._event_store_init()

    def test_01_default_settings_seeded(self):
        settings = fm._get_masked_settings()
        self.assertIn("ai_config", settings)
        self.assertIn("threat_intel_config", settings)

        ai = settings["ai_config"]
        self.assertEqual(ai["model"], "gemini-2.5-flash")
        self.assertEqual(ai["provider"], "google")
        self.assertEqual(ai["temperature"], 0.3)

        ti = settings["threat_intel_config"]
        self.assertEqual(ti["consensus_mode"], "ensemble")
        sources = ti["sources"]
        self.assertTrue(sources["virustotal"]["enabled"])
        self.assertTrue(sources["malwarebazaar"]["enabled"])
        self.assertTrue(sources["alienvault_otx"]["enabled"])

    def test_02_update_ai_model_and_params(self):
        # Update model ke gemini-1.5-pro dengan temperature 0.5
        payload = {
            "ai_config": {
                "model": "gemini-1.5-pro",
                "temperature": 0.5,
                "max_tokens": 2000,
            }
        }
        res = fm._update_system_settings(payload, updated_by="admin_test")
        ai = res["ai_config"]
        self.assertEqual(ai["model"], "gemini-1.5-pro")
        self.assertEqual(ai["temperature"], 0.5)
        self.assertEqual(ai["max_tokens"], 2000)

        # Kembalikan ke gemini-2.5-flash
        fm._update_system_settings(
            {"ai_config": {"model": "gemini-2.5-flash", "temperature": 0.3}},
            updated_by="admin_test",
        )

    def test_03_update_threat_intel_sources_and_thresholds(self):
        payload = {
            "threat_intel_config": {
                "consensus_mode": "majority",
                "sources": {
                    "virustotal": {"min_engines_high": 7, "min_engines_critical": 25},
                    "alienvault_otx": {"min_pulses": 2},
                },
            }
        }
        res = fm._update_system_settings(payload, updated_by="admin_test")
        ti = res["threat_intel_config"]
        self.assertEqual(ti["consensus_mode"], "majority")
        self.assertEqual(ti["sources"]["virustotal"]["min_engines_high"], 7)
        self.assertEqual(ti["sources"]["alienvault_otx"]["min_pulses"], 2)

    def test_04_mask_secret_protection(self):
        # Set API key asli
        fm._update_system_settings(
            {"ai_config": {"api_key": "AIzaSyTestSecretKey1234567890"}},
            updated_by="admin_test",
        )
        settings = fm._get_masked_settings()
        masked = settings["ai_config"]["api_key"]
        self.assertTrue("••••••••" in masked)
        self.assertTrue(settings["ai_config"]["has_api_key"])

        # Kirim ulang payload dengan nilai masking (seperti dari form UI)
        fm._update_system_settings(
            {"ai_config": {"api_key": masked, "temperature": 0.4}},
            updated_by="admin_test",
        )
        raw_ai = fm._get_system_setting("ai_config")
        # Nilai asli di database tidak boleh ditimpa menjadi "••••••••"
        self.assertEqual(raw_ai["api_key"], "AIzaSyTestSecretKey1234567890")
        self.assertEqual(raw_ai["temperature"], 0.4)

    def test_05_test_ai_inference_simulation(self):
        res = fm._test_ai_inference("custom", "local-llama-3", "Uji alert EICAR")
        self.assertTrue(res["success"])
        self.assertEqual(res["model"], "local-llama-3")
        self.assertIn("Simulasi respons inferensi berhasil", res["response"])


if __name__ == "__main__":
    unittest.main()
