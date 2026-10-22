#!/usr/bin/env python3
"""Unit test untuk scripts/fleet-tui.py (Fleet Monitor TUI).

Menguji:
  1. Formatting dan pemotongan teks path (left_trunc).
  2. Pemetaan warna dan status severity.
  3. Filter query dan logika pencarian agent (filter_agents).
  4. Filter siklus severity event (filter_events).

Jalankan:
  nice -n 19 python3 -m unittest scripts/test_fleet_tui.py
"""

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("fleet-tui.py")
SPEC = importlib.util.spec_from_file_location("fleet_tui", MODULE_PATH)
T = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(T)


class TestFleetTui(unittest.TestCase):
    def test_left_trunc(self):
        # Path pendek tidak dipotong
        self.assertEqual(T.left_trunc("/tmp/a.txt", 20), "/tmp/a.txt")
        # Teks sama panjang
        self.assertEqual(T.left_trunc("12345", 5), "12345")
        # Path panjang dipotong dari kiri dengan prefix elipsis
        truncated = T.left_trunc("/home/user/Downloads/malware.exe", 15)
        self.assertEqual(len(truncated), 15)
        self.assertTrue(truncated.startswith("…"))
        self.assertTrue(truncated.endswith("malware.exe"))
        # Edge case width kecil
        self.assertEqual(T.left_trunc("test", 1), "t")

    def test_severity_mappings(self):
        self.assertIn("CRITICAL", T.SEV_ORDER)
        self.assertIn("HIGH", T.SEV_ORDER)
        self.assertIn("MEDIUM", T.SEV_ORDER)
        self.assertIn("UNVERIFIED", T.SEV_ORDER)
        self.assertIn("INFO", T.SEV_ORDER)
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "UNVERIFIED", "INFO"]:
            self.assertIn(sev, T.SEV_COLOR)

    def test_ui_agent_filter(self):
        ui = T.Ui(stdscr=None, base="http://127.0.0.1:8080", interval=5)
        agents = [
            {"id": "001", "name": "ideapc", "ip": "100.124.118.45", "status": "active"},
            {"id": "009", "name": "nixbox", "ip": "100.75.103.60", "status": "active"},
            {"id": "010", "name": "ravi-debian", "ip": "100.73.91.17", "status": "active"},
        ]

        # Tanpa filter -> semua tampil
        self.assertEqual(len(ui.filter_agents(agents)), 3)

        # Filter nama
        ui.filter = "nix"
        res = ui.filter_agents(agents)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["id"], "009")

        # Filter IP
        ui.filter = "100.73"
        res = ui.filter_agents(agents)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["name"], "ravi-debian")

        # Filter ID
        ui.filter = "001"
        res = ui.filter_agents(agents)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["name"], "ideapc")

        # Filter tidak cocok
        ui.filter = "nonexistent"
        self.assertEqual(len(ui.filter_agents(agents)), 0)

    def test_ui_event_severity_cycle(self):
        ui = T.Ui(stdscr=None, base="http://127.0.0.1:8080", interval=5)
        events = [
            {"id": "1", "severity": "CRITICAL", "agent": "nixbox"},
            {"id": "2", "severity": "HIGH", "agent": "ideapc"},
            {"id": "3", "severity": "INFO", "agent": "ravi-debian"},
        ]

        # Filter default (0: semua)
        self.assertEqual(len(ui.filter_events(events)), 3)

        # Filter CRITICAL (indeks 1)
        ui.ev_sev = 1
        res = ui.filter_events(events)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["severity"], "CRITICAL")

        # Filter HIGH (indeks 2)
        ui.ev_sev = 2
        res = ui.filter_events(events)
        self.assertEqual(len(res), 1)
        self.assertEqual(res[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
