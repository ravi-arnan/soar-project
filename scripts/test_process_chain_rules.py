#!/usr/bin/env python3
"""Unit tests untuk validasi scripts/process-chain-rules.xml dan regex rule MITRE ATT&CK."""

import os
import re
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(HERE, "process-chain-rules.xml")


class TestProcessChainRules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = ET.parse(RULES_PATH)
        cls.root = cls.tree.getroot()
        cls.rules_by_id = {}
        for rule in cls.root.findall("rule"):
            rid = rule.get("id")
            cls.rules_by_id[rid] = rule

    def test_xml_structure_and_unique_ids(self):
        """Memastikan root XML adalah group dan seluruh rule id unik."""
        self.assertEqual(self.root.tag, "group")
        rule_elements = self.root.findall("rule")
        self.assertGreater(len(rule_elements), 30)
        ids = [r.get("id") for r in rule_elements]
        self.assertEqual(len(ids), len(set(ids)), "Ada rule id yang duplikat di XML")

    def test_rules_presence_and_metadata(self):
        """Memverifikasi keberadaan rule baru T1490, T1547.001, dan T1053.005 beserta metadata levelnya."""
        expected_rules = {
            "110039": {"level": "12", "attack": "attack_T1490"},
            "110040": {"level": "12", "attack": "attack_T1490"},
            "110041": {"level": "9", "attack": "attack_T1547.001"},
            "110042": {"level": "9", "attack": "attack_T1547.001"},
            "110043": {"level": "9", "attack": "attack_T1053.005"},
            "110044": {"level": "9", "attack": "attack_T1053.005"},
        }
        for rid, meta in expected_rules.items():
            self.assertIn(rid, self.rules_by_id, f"Rule id {rid} harus ada di XML")
            rule_el = self.rules_by_id[rid]
            self.assertEqual(rule_el.get("level"), meta["level"])
            group_el = rule_el.find("group")
            self.assertIsNotNone(group_el, f"Rule {rid} harus punya tag group")
            self.assertIn(meta["attack"], group_el.text)

    def test_t1490_inhibit_system_recovery_regex(self):
        """Uji deteksi mitigasi ransomware T1490 (vssadmin, wmic, bcdedit, wbadmin)."""
        rule_json = self.rules_by_id["110039"]
        img_field = rule_json.find("./field[@name='win.eventdata.image']")
        cmd_field = rule_json.find("./field[@name='win.eventdata.commandLine']")

        img_re = img_field.text
        cmd_re = cmd_field.text

        # Kasus positif ancaman
        positive_imgs = [
            r"C:\Windows\System32\vssadmin.exe",
            r"C:\Windows\System32\wmic.exe",
            r"C:\Windows\System32\bcdedit.exe",
            r"C:\Windows\System32\wbadmin.exe",
        ]
        positive_cmds = [
            "vssadmin.exe delete shadows /all /quiet",
            "vssadmin delete shadows",
            "vssadmin resize shadowstorage /for=c: /on=c: /maxsize=401MB",
            "wmic shadowcopy delete",
            "bcdedit.exe /set {default} recoveryenabled no",
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            "wbadmin delete catalog -quiet",
            "wbadmin delete systemstatebackup",
        ]

        for img in positive_imgs:
            self.assertTrue(re.search(img_re, img), f"Gagal mencocokkan image: {img}")
        for cmd in positive_cmds:
            self.assertTrue(re.search(cmd_re, cmd), f"Gagal mencocokkan commandLine: {cmd}")

        # Kasus negatif (operasi normal / benign)
        negative_cmds = [
            "vssadmin list shadows",
            "vssadmin list shadowstorage",
            "bcdedit /enum {current}",
            "wmic process get name,processid",
        ]
        for cmd in negative_cmds:
            self.assertFalse(re.search(cmd_re, cmd), f"False positive pada benign cmd: {cmd}")

    def test_t1547_001_registry_run_keys_regex(self):
        """Uji deteksi persistence T1547.001 (reg.exe Run/RunOnce ke folder user)."""
        rule_json = self.rules_by_id["110041"]
        img_re = rule_json.find("./field[@name='win.eventdata.image']").text
        cmd_re = rule_json.find("./field[@name='win.eventdata.commandLine']").text

        self.assertTrue(re.search(img_re, r"C:\Windows\System32\reg.exe"))

        positive_cmds = [
            r"reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Dropper /t REG_SZ /d C:\Users\Admin\AppData\Local\Temp\evil.exe /f",
            r"reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce /d C:\Users\Public\payload.exe",
            r"REG ADD HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /d C:\Users\Kasir\Downloads\invoice.bat",
        ]
        for cmd in positive_cmds:
            self.assertTrue(re.search(cmd_re, cmd), f"Gagal deteksi persistence: {cmd}")

        negative_cmds = [
            r"reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
            r"reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Official /d C:\Windows\System32\cmd.exe",
        ]
        for cmd in negative_cmds:
            self.assertFalse(re.search(cmd_re, cmd), f"False positive pada registry benign: {cmd}")

    def test_t1053_005_scheduled_task_regex(self):
        """Uji deteksi persistence T1053.005 (schtasks.exe /create ke folder user)."""
        rule_json = self.rules_by_id["110043"]
        img_re = rule_json.find("./field[@name='win.eventdata.image']").text
        cmd_re = rule_json.find("./field[@name='win.eventdata.commandLine']").text

        self.assertTrue(re.search(img_re, r"C:\Windows\System32\schtasks.exe"))

        positive_cmds = [
            r"schtasks.exe /create /tn EvilUpdate /tr C:\Users\Victim\AppData\Roaming\miner.exe /sc onlogon",
            r'schtasks /create /tn SystemSync /tr "C:\Temp\updater.bat" /sc daily',
            r"schtasks /create /tn MalTask /tr C:\Users\Public\backdoor.exe /sc minute",
        ]
        for cmd in positive_cmds:
            self.assertTrue(re.search(cmd_re, cmd), f"Gagal deteksi scheduled task: {cmd}")

        negative_cmds = [
            r"schtasks /query /fo LIST /v",
            r"schtasks.exe /delete /tn OldTask /f",
            r"schtasks /create /tn Maintenance /tr C:\Windows\System32\cleanmgr.exe /sc daily",
        ]
        for cmd in negative_cmds:
            self.assertFalse(re.search(cmd_re, cmd), f"False positive pada scheduled task benign: {cmd}")


if __name__ == "__main__":
    unittest.main()
