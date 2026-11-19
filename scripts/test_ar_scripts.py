#!/usr/bin/env python3
"""Unit tests untuk Active Response scripts (quarantine-file, block-domain) dan custom-n8n.py."""

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parent.parent
QUARANTINE_SCRIPT = REPO_ROOT / "scripts" / "quarantine-file"
BLOCK_DOMAIN_SCRIPT = REPO_ROOT / "scripts" / "block-domain"
CUSTOM_N8N_PATH = REPO_ROOT / "scripts" / "custom-n8n.py"


def _load_custom_n8n():
    spec = importlib.util.spec_from_file_location("custom_n8n_mod", CUSTOM_N8N_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestQuarantineFileScript(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.qdir = self.base / "quarantine"
        self.log = self.base / "ar.log"
        self.env = {
            **os.environ,
            "SOAR_QUARANTINE_DIR": str(self.qdir),
            "SOAR_AR_LOG": str(self.log),
        }

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, command: str, target: str):
        payload = json.dumps({
            "version": 1,
            "origin": {"name": "wazuh", "module": "api"},
            "command": command,
            "parameters": {"extra_args": [target]},
        })
        return subprocess.run(
            ["bash", str(QUARANTINE_SCRIPT)],
            input=payload,
            text=True,
            capture_output=True,
            env=self.env,
            timeout=10,
        )

    def test_rejects_symlink_to_etc_passwd(self):
        link = self.base / "innocent.txt"
        os.symlink("/etc/passwd", link)
        res = self._run("add", str(link))
        self.assertNotEqual(res.returncode, 0)
        self.assertTrue(link.is_symlink())
        self.assertIn("DITOLAK", self.log.read_text())

    def test_rejects_path_traversal_to_protected_dir(self):
        traversal = f"{self.base}/../../../../etc/hosts"
        res = self._run("add", traversal)
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("DITOLAK", self.log.read_text())

    def test_quarantine_and_restore_cycle_with_manifest(self):
        sample = self.base / "malware sample.bin"
        sample.write_bytes(b"PAYLOAD")
        res = self._run("add", str(sample))
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertFalse(sample.exists())
        manifest = json.loads((self.qdir / "manifest.json").read_text())
        self.assertEqual(len(manifest), 1)
        qfile = Path(manifest[0]["quarantined"])
        self.assertTrue(qfile.exists())
        self.assertEqual(os.stat(qfile).st_mode & 0o777, 0)

        res_del = self._run("delete", str(sample))
        self.assertEqual(res_del.returncode, 0, res_del.stderr)
        self.assertTrue(sample.exists())
        self.assertEqual(sample.read_bytes(), b"PAYLOAD")
        self.assertFalse(qfile.exists())


class TestBlockDomainScript(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.base = Path(self.tmp.name)
        self.hosts = self.base / "hosts"
        self.hosts.write_text("127.0.0.1 localhost\n")
        self.backup = self.base / "backups"
        self.log = self.base / "ar.log"
        self.env = {
            **os.environ,
            "SOAR_HOSTS_FILE": str(self.hosts),
            "SOAR_BACKUP_DIR": str(self.backup),
            "SOAR_AR_LOG": str(self.log),
        }

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, command: str, target: str):
        payload = json.dumps({
            "version": 1,
            "command": command,
            "parameters": {"extra_args": [target]},
        })
        return subprocess.run(
            ["bash", str(BLOCK_DOMAIN_SCRIPT)],
            input=payload,
            text=True,
            capture_output=True,
            env=self.env,
            timeout=10,
        )

    def test_rejects_protected_domain(self):
        for dom in ("github.com", "api.virustotal.com", "sub.cloudflare.com", "localhost"):
            res = self._run("add", dom)
            self.assertNotEqual(res.returncode, 0, f"expected reject for {dom}")

    def test_literal_dot_matching_and_rollback(self):
        # Add evil-x-com.test and evil.x.com.test -> deleting evil.x.com.test must NOT delete evilaxacom.test
        r1 = self._run("add", "evilaxacom.test")
        r2 = self._run("add", "evil.x.com.test")
        self.assertEqual(r1.returncode, 0)
        self.assertEqual(r2.returncode, 0)
        r3 = self._run("delete", "evil.x.com.test")
        self.assertEqual(r3.returncode, 0)
        content = self.hosts.read_text()
        self.assertIn("0.0.0.0 evilaxacom.test # WAZUH-SOAR-SINKHOLE", content)
        self.assertNotIn("0.0.0.0 evil.x.com.test # WAZUH-SOAR-SINKHOLE", content)


class TestCustomN8n(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_custom_n8n()

    def test_iso_dmg_and_var_tmp_are_not_ignored(self):
        self.assertFalse(self.mod.is_noisy_path("/home/alice/Downloads/invoice.iso"))
        self.assertFalse(self.mod.is_noisy_path("/Users/bob/Downloads/dropper.dmg"))
        self.assertFalse(self.mod.is_noisy_path("/var/tmp/stage2.sh"))
        self.assertTrue(self.mod.is_noisy_path("/home/alice/Downloads/desktop.ini"))
        self.assertTrue(self.mod.is_noisy_path("/tmp/node-compile-cache/abc"))

    def test_build_payload_omits_stale_model_and_handles_string_level(self):
        alert = {
            "rule": {"id": "110039", "level": "12", "description": "Inhibit recovery"},
            "agent": {"id": "7", "name": "win-pc"},
            "timestamp": "2026-11-19T00:00:00Z",
            "data": {
                "win": {
                    "eventdata": {
                        "image": "C:\\Windows\\System32\\vssadmin.exe",
                        "parentImage": "C:\\Windows\\System32\\cmd.exe",
                        "commandLine": "vssadmin delete shadows /all /quiet",
                    }
                }
            },
        }
        payload = self.mod.build_webhook_payload(alert)
        self.assertIsNotNone(payload)
        self.assertNotIn("model", payload)
        self.assertEqual(payload["rule"]["level"], 12)
        self.assertEqual(payload["agent"]["id"], "007")
        self.assertEqual(payload["data"]["event_type"], "process_chain")
        self.assertIn("vssadmin.exe", payload["data"]["proc_image"])

    def test_send_with_retry_sends_secret_and_retries(self):
        attempts = []

        class _Resp:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *a): return False

        def fake_urlopen(req, timeout=10):
            attempts.append((req.get_header("X-soar-webhook-secret"), timeout))
            if len(attempts) < 2:
                raise OSError("transient")
            return _Resp()

        sleeps = []
        with mock.patch.object(self.mod.urllib.request, "urlopen", side_effect=fake_urlopen):
            self.mod.send_with_retry(
                "http://127.0.0.1:5678/webhook/test",
                {"hello": "world"},
                secret="topsecret",
                sleep_fn=sleeps.append,
            )
        self.assertEqual(len(attempts), 2)
        self.assertEqual(attempts[0][0], "topsecret")
        self.assertEqual(sleeps, [1])


if __name__ == "__main__":
    unittest.main()
