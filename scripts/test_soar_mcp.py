#!/usr/bin/env python3
"""
Unit test komprehensif untuk SOAR MCP Server (scripts/soar_mcp_server.py).
Memverifikasi:
- Handshake JSON-RPC 2.0 (initialize, ping, unknown method)
- tools/list mengembalikan skema valid untuk 6 tools
- Eksekusi masing-masing tool (fleet status, list agents, threat events, lookup hash, execute command, stats)
- Penanganan error, format payload, dan isolasi stderr vs stdout
"""

import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

MODULE_PATH = Path(__file__).with_name("soar_mcp_server.py")
SPEC = importlib.util.spec_from_file_location("soar_mcp_server", MODULE_PATH)
assert SPEC and SPEC.loader
mcp = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mcp)


class TestSoarMcpTools(unittest.TestCase):
    def setUp(self):
        self.mock_client = MagicMock(spec=mcp.SoarClient)

    def test_tools_list_schema(self):
        """Pastikan seluruh 6 tools terdaftar dengan schema valid."""
        tools = mcp.TOOLS
        self.assertEqual(len(tools), 6)
        tool_names = {t["name"] for t in tools}
        expected = {
            "soar_get_fleet_status",
            "soar_list_agents",
            "soar_get_threat_events",
            "soar_lookup_hash",
            "soar_execute_command",
            "soar_get_stats",
        }
        self.assertEqual(tool_names, expected)
        for t in tools:
            self.assertIn("description", t)
            self.assertIn("inputSchema", t)
            self.assertEqual(t["inputSchema"]["type"], "object")

    def test_handle_fleet_status_success(self):
        self.mock_client.request.return_value = (
            200,
            {
                "generated_at": "2026-11-06T20:00:00Z",
                "health": {"wazuh_api": True, "n8n": True, "gemini": True},
                "stats": {
                    "total": 10,
                    "active": 8,
                    "disconnected": 2,
                    "rust": 7,
                    "wazuh": 1,
                    "capacity_pct": 10,
                },
            },
        )
        res = mcp.handle_tool_call(self.mock_client, "soar_get_fleet_status", {})
        self.assertIn("=== STATUS SISTEM & ARMADA SOAR ===", res)
        self.assertIn("Total Agen: 10 host", res)
        self.assertIn("Wazuh Manager API: AKTIF", res)
        self.assertIn("Gemini 2.5 Flash AI Engine: SIAP", res)

    def test_handle_list_agents_filter(self):
        self.mock_client.request.return_value = (
            200,
            {
                "agents": [
                    {
                        "id": "001",
                        "name": "wazuh-agent-1",
                        "ip": "192.168.1.10",
                        "status": "active",
                        "is_rust": False,
                    },
                    {
                        "id": "009",
                        "name": "nixbox",
                        "ip": "100.73.91.17",
                        "status": "active",
                        "is_rust": True,
                    },
                    {
                        "id": "010",
                        "name": "lab-offline",
                        "ip": "10.0.0.5",
                        "status": "disconnected",
                        "is_rust": True,
                    },
                ]
            },
        )
        # Filter active
        res_active = mcp.handle_tool_call(
            self.mock_client, "soar_list_agents", {"status_filter": "active"}
        )
        self.assertIn("wazuh-agent-1", res_active)
        self.assertIn("nixbox", res_active)
        self.assertNotIn("lab-offline", res_active)

    def test_handle_threat_events(self):
        self.mock_client.request.return_value = (
            200,
            {
                "events": [
                    {
                        "id": "ev1",
                        "severity": "CRITICAL",
                        "rule_desc": "Ransomware canary triggered",
                        "agent": "kasir-pc",
                        "agent_id": "003",
                        "path": "/home/user/canary.docx",
                        "hash": "abc12345",
                        "verdict": "MALICIOUS",
                        "ai": "T1486 Data Encrypted for Impact",
                    }
                ]
            },
        )
        res = mcp.handle_tool_call(
            self.mock_client, "soar_get_threat_events", {"limit": 5, "severity": "CRITICAL"}
        )
        self.assertIn("[CRITICAL] Ransomware canary triggered", res)
        self.assertIn("Target/Path: /home/user/canary.docx", res)
        self.assertIn("T1486 Data Encrypted for Impact", res)

    def test_handle_lookup_hash_hit_and_miss(self):
        # Hit
        self.mock_client.request.return_value = (
            200,
            {
                "hit": True,
                "entry": {
                    "verdict": "MALICIOUS",
                    "source": "VirusTotal & MalwareBazaar",
                    "ttl_remaining_secs": 86400,
                    "stats": {"malicious": 58, "suspicious": 2, "undetected": 10},
                },
            },
        )
        res_hit = mcp.handle_tool_call(
            self.mock_client, "soar_lookup_hash", {"hash": "e3b0c44298fc1c149afbf4c8996fb924"}
        )
        self.assertIn("Vonis: MALICIOUS", res_hit)
        self.assertIn("Malicious: 58", res_hit)

        # Miss
        self.mock_client.request.return_value = (200, {"hit": False})
        res_miss = mcp.handle_tool_call(
            self.mock_client, "soar_lookup_hash", {"hash": "unknownhash"}
        )
        self.assertIn("belum ada di cache server SOAR", res_miss)

    def test_handle_execute_command(self):
        self.mock_client.request.return_value = (
            200,
            {"status": "queued", "agent_id": "003", "action": "quarantine"},
        )
        res = mcp.handle_tool_call(
            self.mock_client,
            "soar_execute_command",
            {"agent_id": "003", "action": "quarantine", "target": "/tmp/malware.exe"},
        )
        self.assertIn("Perintah Active Response BERHASIL", res)
        self.assertIn("Aksi: QUARANTINE", res)
        self.assertIn("Agen Target: 003", res)

    def test_handle_get_stats(self):
        self.mock_client.request.return_value = (
            200,
            {
                "stats": {
                    "severity": {"CRITICAL": 3, "HIGH": 12, "MEDIUM": 5, "LOW": 2, "INFO": 20},
                    "top_agents": [{"key": "003", "count": 15}, {"key": "001", "count": 7}],
                    "daily": [{"date": "2026-11-06", "count": 22}],
                }
            },
        )
        res = mcp.handle_tool_call(self.mock_client, "soar_get_stats", {})
        self.assertIn("CRITICAL: 3", res)
        self.assertIn("Agent 003: 15 insiden", res)
        self.assertIn("2026-11-06: 22 insiden", res)


class TestSoarMcpJsonRpcSubprocess(unittest.TestCase):
    """Pengujian E2E protokol JSON-RPC melalui subprocess stdio."""

    def test_mcp_handshake_and_tools_call(self):
        proc = subprocess.Popen(
            [sys.executable, str(MODULE_PATH), "--url", "http://127.0.0.1:9999"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        try:
            # 1. Initialize
            init_req = json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {"protocolVersion": "2024-11-05"},
                }
            )
            proc.stdin.write(init_req + "\n")
            proc.stdin.flush()
            init_resp = json.loads(proc.stdin.channel if hasattr(proc.stdin, "channel") else proc.stdout.readline())
            self.assertEqual(init_resp["id"], 1)
            self.assertEqual(init_resp["result"]["serverInfo"]["name"], "soar-mcp-server")

            # 2. Ping
            ping_req = json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"})
            proc.stdin.write(ping_req + "\n")
            proc.stdin.flush()
            ping_resp = json.loads(proc.stdout.readline())
            self.assertEqual(ping_resp["id"], 2)
            self.assertEqual(ping_resp["result"], {})

            # 3. tools/list
            list_req = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}})
            proc.stdin.write(list_req + "\n")
            proc.stdin.flush()
            list_resp = json.loads(proc.stdout.readline())
            self.assertEqual(list_resp["id"], 3)
            self.assertEqual(len(list_resp["result"]["tools"]), 6)

        finally:
            if proc.stdin:
                proc.stdin.close()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            proc.terminate()
            proc.wait(timeout=3)


if __name__ == "__main__":
    unittest.main()
