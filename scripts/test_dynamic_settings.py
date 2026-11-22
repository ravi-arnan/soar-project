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

    def test_06_fallback_config_and_mask_protection(self):
        fm._update_system_settings(
            {
                "ai_config": {
                    "provider": "openai",
                    "model": "gpt-4o-mini",
                    "api_key": "sk-primary-test-key-123456",
                    "fallback_enabled": True,
                    "fallback_provider": "anthropic",
                    "fallback_model": "claude-3-5-sonnet-latest",
                    "fallback_api_key": "sk-ant-fallback-secret-987654",
                    "fallback_base_url": "",
                }
            },
            updated_by="admin_test",
        )
        masked = fm._get_masked_settings()["ai_config"]
        self.assertEqual(masked["provider"], "openai")
        self.assertEqual(masked["fallback_provider"], "anthropic")
        self.assertTrue(masked["fallback_enabled"])
        self.assertTrue(masked["has_fallback_api_key"])
        self.assertIn("••••••••", masked["fallback_api_key"])

        # Simpan ulang dengan nilai masked seperti dari form UI
        fm._update_system_settings(
            {
                "ai_config": {
                    "api_key": masked["api_key"],
                    "fallback_api_key": masked["fallback_api_key"],
                    "fallback_model": "claude-3-5-haiku-latest",
                }
            },
            updated_by="admin_test",
        )
        raw_ai = fm._get_system_setting("ai_config")
        self.assertEqual(raw_ai["api_key"], "sk-primary-test-key-123456")
        self.assertEqual(raw_ai["fallback_api_key"], "sk-ant-fallback-secret-987654")
        self.assertEqual(raw_ai["fallback_model"], "claude-3-5-haiku-latest")

    def test_07_auto_fallback_on_primary_failure(self):
        # Primary openai tanpa key yang valid -> fallback ke custom simulasi
        res = fm._test_ai_inference(
            "openai",
            "gpt-4o-mini",
            "Tes auto fallback",
            api_key="",
            fallback_config={
                "enabled": True,
                "provider": "custom",
                "model": "fallback-local-llm",
                "api_key": "",
                "base_url": "",
            },
            target="auto",
        )
        self.assertTrue(res["success"])
        self.assertTrue(res.get("used_fallback"))
        self.assertEqual(res["provider"], "custom")
        self.assertEqual(res["model"], "fallback-local-llm")
        self.assertIn("Simulasi respons inferensi berhasil", res["response"])

    def test_08_openai_and_anthropic_real_http_dispatch(self):
        import io
        import json as _json
        from unittest.mock import patch

        class _FakeResp:
            def __init__(self, payload):
                self._data = _json.dumps(payload).encode("utf-8")

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        captured = []

        def fake_urlopen(req, timeout=20):
            captured.append((req.full_url, dict(req.header_items()), _json.loads(req.data.decode("utf-8"))))
            if "anthropic" in req.full_url:
                return _FakeResp({"content": [{"type": "text", "text": "Analisis Claude aman."}]})
            return _FakeResp({"choices": [{"message": {"content": "Analisis GPT aman."}}]})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res_oai = fm._invoke_ai_provider(
                "openai",
                "gpt-4o",
                "Cek hash",
                api_key="sk-test-openai",
                system_instruction="Instruksi SOC",
            )
            res_ant = fm._invoke_ai_provider(
                "anthropic",
                "claude-3-5-sonnet-latest",
                "Cek hash",
                api_key="sk-ant-test",
                system_instruction="Instruksi SOC",
            )

        self.assertTrue(res_oai["success"])
        self.assertEqual(res_oai["response"], "Analisis GPT aman.")
        self.assertEqual(captured[0][0], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(captured[0][2]["messages"][0]["role"], "system")

        self.assertTrue(res_ant["success"])
        self.assertEqual(res_ant["response"], "Analisis Claude aman.")
        self.assertEqual(captured[1][0], "https://api.anthropic.com/v1/messages")
        self.assertEqual(captured[1][2]["system"], "Instruksi SOC")

    def test_09_user_touch_login_updates_last_login_at(self):
        # Pastikan user baru memiliki last_login_at None lalu terisi via _user_touch_login
        created = fm._user_create(
            username="sso_auditor",
            password="StrongPassword!123",
            role="viewer",
            email="sso-auditor@example.com",
            name="SSO Auditor",
        )
        self.assertIsNone(created["last_login_at"])

        ok_email = fm._user_touch_login(email="SSO-AUDITOR@EXAMPLE.COM")
        self.assertTrue(ok_email)
        users = {u["username"]: u for u in fm._user_list()}
        self.assertIsNotNone(users["sso_auditor"]["last_login_at"])

        # Fallback match via username bila email tidak cocok/kosong
        ok_admin = fm._user_touch_login(username="admin")
        self.assertTrue(ok_admin)
        users_after = {u["username"]: u for u in fm._user_list()}
        self.assertIsNotNone(users_after["admin"]["last_login_at"])

        # User tidak dikenal mengembalikan False
        self.assertFalse(fm._user_touch_login(username="nobody_xyz", email="none@invalid.local"))

    def test_10_saved_api_keys_masking_and_switch(self):
        saved_res = fm._update_system_settings(
            {
                "ai_config": {
                    "provider": "experiential",
                    "model": "gpt-6-luna:free",
                    "primary_saved_key_id": "key_xpl_1",
                    "saved_api_keys": [
                        {
                            "id": "key_xpl_1",
                            "name": "Experiential Free",
                            "provider": "experiential",
                            "model": "gpt-6-luna:free",
                            "base_url": "",
                            "api_key": "xpl_secret_test_key_998877",
                            "models": [
                                {"id": "gpt-6-luna:free", "label": "gpt-6-luna:free [FREE]", "free": True, "chat_supported": True},
                            ],
                        }
                    ],
                }
            },
            updated_by="admin_test",
        )
        ai_safe = saved_res["ai_config"]
        self.assertEqual(ai_safe["primary_saved_key_id"], "key_xpl_1")
        self.assertEqual(len(ai_safe["saved_api_keys"]), 1)
        self.assertIn("••••••••", ai_safe["saved_api_keys"][0]["api_key"])
        self.assertTrue(ai_safe["saved_api_keys"][0]["has_api_key"])

        # Re-save dengan nilai masked (seperti dari UI) tidak boleh menimpa secret asli
        fm._update_system_settings(
            {"ai_config": {"saved_api_keys": ai_safe["saved_api_keys"], "primary_saved_key_id": "key_xpl_1"}},
            updated_by="admin_test",
        )
        raw_ai = fm._get_system_setting("ai_config")
        self.assertEqual(raw_ai["saved_api_keys"][0]["api_key"], "xpl_secret_test_key_998877")
        self.assertEqual(raw_ai["api_key"], "xpl_secret_test_key_998877")

    def test_11_experiential_fetch_models_and_invoke(self):
        import json as _json
        from unittest.mock import patch

        class _FakeResp:
            def __init__(self, payload):
                self._data = _json.dumps(payload).encode("utf-8")

            def read(self):
                return self._data

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        captured = []

        def fake_urlopen(req, timeout=20):
            captured.append((req.full_url, dict(req.header_items())))
            if req.full_url.endswith("/models"):
                return _FakeResp(
                    {
                        "data": [
                            {"id": "aion-2.0", "pricing": {"input_nano_usd_per_million_tokens": 800, "output_nano_usd_per_million_tokens": 1600}},
                            {"id": "clef:free", "pricing": {"input_nano_usd_per_million_tokens": 0, "output_nano_usd_per_million_tokens": 0}},
                            {"id": "gpt-6-luna:free", "context_window_tokens": 1050000, "pricing": {"input_nano_usd_per_million_tokens": 0, "output_nano_usd_per_million_tokens": 0}},
                        ]
                    }
                )
            return _FakeResp({"choices": [{"message": {"content": "Isolasi workstation segera."}}]})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res_models = fm._fetch_provider_models("experiential", saved_key_id="key_xpl_1")
            res_test = fm._test_ai_inference("experiential", "gpt-6-luna:free", "Cek alert", saved_key_id="key_xpl_1")

        self.assertTrue(res_models["success"])
        self.assertEqual(res_models["free_count"], 2)
        # Chat :free harus diurutkan paling atas sebelum non-chat :free dan berbayar
        self.assertEqual(res_models["models"][0]["id"], "gpt-6-luna:free")
        self.assertTrue(res_models["models"][0]["chat_supported"])
        self.assertEqual(res_models["models"][1]["id"], "clef:free")
        self.assertFalse(res_models["models"][1]["chat_supported"])
        self.assertEqual(res_models["models"][2]["id"], "aion-2.0")
        self.assertFalse(res_models["models"][2]["free"])

        self.assertTrue(res_test["success"])
        self.assertEqual(res_test["response"], "Isolasi workstation segera.")
        self.assertEqual(captured[0][0], "https://api.experientiallabs.ai/v1/models")
        self.assertEqual(captured[1][0], "https://api.experientiallabs.ai/v1/chat/completions")

    def test_10_custom_saved_key_models_and_test_allowed(self):
        from unittest.mock import patch

        fm._update_system_settings(
            {
                "ai_config": {
                    "saved_api_keys": [
                        {
                            "id": "key_custom_or",
                            "name": "OpenRouter Custom",
                            "provider": "custom",
                            "model": "google/gemini-3.8-flash",
                            "base_url": "https://openrouter.ai/api/v1",
                            "api_key": "sk-or-v1-secret-1234567890",
                        }
                    ]
                }
            },
            updated_by="admin_test",
        )

        class _FakeResp:
            def __init__(self, payload):
                self._raw = fm.json.dumps(payload).encode("utf-8")

            def read(self):
                return self._raw

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        def fake_urlopen(req, timeout=20):
            if req.full_url.endswith("/models"):
                return _FakeResp({"data": [{"id": "google/gemini-3.8-flash"}]})
            return _FakeResp({"choices": [{"message": {"content": "OK"}}]})

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            res_models = fm._fetch_provider_models(
                "custom",
                base_url="https://openrouter.ai/api/v1",
                saved_key_id="key_custom_or",
            )
            res_test = fm._test_ai_inference(
                "custom",
                "google/gemini-3.8-flash",
                "Balas hanya dengan satu kata: OK",
                base_url="https://openrouter.ai/api/v1",
                saved_key_id="key_custom_or",
            )
        self.assertTrue(res_models["success"])
        self.assertEqual(res_models["models"][0]["id"], "google/gemini-3.8-flash")
        self.assertTrue(res_test["success"])
        self.assertEqual(res_test["response"], "OK")

        # Foreign base_url tidak boleh menerima stored key milik saved key custom
        res_bad = fm._fetch_provider_models(
            "custom",
            base_url="https://evil.example/v1",
            saved_key_id="key_custom_or",
        )
        self.assertFalse(res_bad["success"])
        self.assertIn("Ditolak", res_bad["error"])


if __name__ == "__main__":
    unittest.main()
