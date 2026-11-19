#!/usr/bin/env python3
"""Unit tests untuk scripts/health-monitor.py."""

import importlib.util
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

MOD_PATH = Path(__file__).resolve().parent / "health-monitor.py"
SPEC = importlib.util.spec_from_file_location("health_monitor_mod", MOD_PATH)
hm = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hm)


class TestHealthMonitor(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.state_file = os.path.join(self.tmp.name, "health.json")
        self.cfg = {
            "token": "123:SECRET_TOKEN",
            "chat_id": "999",
            "wazuh_url": "https://127.0.0.1:55000",
            "wazuh_user": "u",
            "wazuh_pass": "p",
            "n8n_url": "http://127.0.0.1:5678/healthz",
            "fleet_url": "http://127.0.0.1:8080",
            "fleet_token": "tok",
            "dashboard_url": "http://127.0.0.1:3000",
            "misp_url": "http://127.0.0.1:8090",
            "alert_log_url": "http://127.0.0.1:8091",
            "gemini_key": "gk",
            "fail_threshold": 2,
            "state_file": self.state_file,
            "ping_url": "https://hc-ping.example/uuid",
        }

    def tearDown(self):
        self.tmp.cleanup()

    def test_hysteresis_requires_two_consecutive_failures(self):
        prev = {"n8n": True, "fleet_monitor": True}
        eff1, s1 = hm.apply_hysteresis(prev, {"n8n": False, "fleet_monitor": True}, {}, fail_threshold=2)
        self.assertTrue(eff1["n8n"])
        self.assertEqual(s1["n8n"], 1)
        self.assertEqual(hm.compute_transitions(prev, eff1), [])

        eff2, s2 = hm.apply_hysteresis(eff1, {"n8n": False, "fleet_monitor": True}, s1, fail_threshold=2)
        self.assertFalse(eff2["n8n"])
        self.assertEqual(s2["n8n"], 2)
        self.assertEqual(hm.compute_transitions(eff1, eff2), [("n8n", "down", False)])

        # Recovery is immediate
        eff3, s3 = hm.apply_hysteresis(eff2, {"n8n": True, "fleet_monitor": True}, s2, fail_threshold=2)
        self.assertTrue(eff3["n8n"])
        self.assertEqual(s3["n8n"], 0)
        self.assertEqual(hm.compute_transitions(eff2, eff3), [("n8n", "up", True)])

    def test_failed_telegram_does_not_overwrite_prev_state(self):
        prev = {"n8n": True}
        with mock.patch.object(hm, "collect", return_value={"n8n": False}), \
             mock.patch.object(hm, "send_telegram", return_value=False) as m_tg:
            next_prev, next_streaks, ok = hm.run_tick(self.cfg, prev, {"n8n": 1})
        self.assertFalse(ok)
        self.assertEqual(next_prev, prev)
        self.assertEqual(next_streaks["n8n"], 2)
        m_tg.assert_called_once()

    def test_atomic_state_save_and_deadman_ping_on_all_healthy(self):
        with mock.patch.object(hm, "collect", return_value={"n8n": True, "fleet_monitor": True}), \
             mock.patch.object(hm, "ping_deadman") as m_ping:
            curr, streaks, ok = hm.run_tick(self.cfg, {"n8n": True, "fleet_monitor": True}, {})
        self.assertTrue(ok)
        self.assertEqual(curr, {"n8n": True, "fleet_monitor": True})
        m_ping.assert_called_once()
        loaded_status, loaded_streaks = hm._load_state(self.state_file)
        self.assertEqual(loaded_status, curr)
        self.assertEqual(loaded_streaks, streaks)


if __name__ == "__main__":
    unittest.main()
