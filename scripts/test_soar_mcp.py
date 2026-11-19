#!/usr/bin/env python3
"""Unit tests untuk scripts/soar_mcp_server.py."""

import io
import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import soar_mcp_server as mcp


class FakeSoarClient(mcp.SoarClient):
    def __init__(self, routes):
        super().__init__(base_url="http://127.0.0.1:8080", api_key="test-key")
        self.routes = routes

    def request(self, path, method="GET", body=None):
        key = (method, path)
        if key in self.routes:
            return self.routes[key]
        return 404, {"error": f"not mocked: {key}"}


class TestSoarMcpServer(unittest.TestCase):
    def test_default_url_has_no_personal_tailscale_ip(self):
        self.assertNotIn("100.73.91.17", mcp.DEFAULT_SOAR_URL)

    def test_list_agents_handles_string_os_and_rust_type(self):
        client = FakeSoarClient({
            ("GET", "/api/fleet"): (
                200,
                {
                    "agents": [
                        {
                            "id": "003",
                            "name": "linux-ws",
                            "ip": "10.0.0.5",
                            "status": "active",
                            "os": "linux",
                            "type": "rust",
                            "regDate": "2026-10-01T00:00:00Z",
                            "lastKeepAlive": "2026-11-19T00:00:00Z",
                        },
                        {
                            "id": "001",
                            "name": "win-ws",
                            "ip": "10.0.0.6",
                            "status": "active",
                            "os": {"name": "Windows 11"},
                            "type": "wazuh",
                        },
                    ]
                },
            )
        })
        out = mcp.handle_tool_call(client, "soar_list_agents", {})
        self.assertIn("Rust soar-agent", out)
        self.assertIn("OS: linux", out)
        self.assertIn("Wazuh Agent", out)
        self.assertIn("OS: Windows 11", out)

    def test_lookup_hash_reads_flat_fleet_monitor_response(self):
        h = "a" * 64
        client = FakeSoarClient({
            ("POST", "/api/vt-cache/lookup"): (
                200,
                {
                    "hit": True,
                    "status": "malicious",
                    "mal": 58,
                    "susp": 2,
                    "undet": 10,
                    "mb_hit": True,
                    "mb_sig": "Ramnit",
                    "otx_pulses": 4,
                    "source": "vt+mb+otx",
                    "ttl_s": 7200,
                },
            )
        })
        out = mcp.handle_tool_call(client, "soar_lookup_hash", {"hash": h})
        self.assertIn("Vonis: MALICIOUS", out)
        self.assertIn("Malicious: 58", out)
        self.assertIn("Suspicious: 2", out)
        self.assertIn("Undetected/Clean: 10", out)
        self.assertIn("YA (Ramnit)", out)
        self.assertIn("OTX Pulses: 4", out)
        self.assertIn("2.0 jam tersisa", out)

    def test_get_fleet_status_computes_capacity_and_extra_health(self):
        client = FakeSoarClient({
            ("GET", "/api/fleet"): (
                200,
                {
                    "health": {
                        "wazuh_api": True,
                        "n8n": True,
                        "gemini": True,
                        "misp": True,
                        "alert_log": True,
                    },
                    "stats": {
                        "total": 12,
                        "active": 10,
                        "disconnected": 2,
                        "rust": 8,
                        "wazuh": 4,
                    },
                    "generated_at": "2026-11-19T00:00:00Z",
                },
            )
        })
        out = mcp.handle_tool_call(client, "soar_get_fleet_status", {})
        self.assertIn("12.0% dari 100 PC target", out)
        self.assertIn("MISP OSINT Feed: AKTIF", out)
        self.assertIn("Alert Log Registry: AKTIF", out)

    def test_stdio_server_rejects_non_object_json_without_crashing(self):
        stdin_buf = io.StringIO('[1, 2, 3]\n{"jsonrpc":"2.0","id":7,"method":"ping"}\n')
        stdout_buf = io.StringIO()
        client = FakeSoarClient({})
        with mock.patch.object(sys, "stdin", stdin_buf), mock.patch.object(sys, "stdout", stdout_buf):
            mcp.run_stdio_server(client)
        lines = [json.loads(line) for line in stdout_buf.getvalue().splitlines() if line.strip()]
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0]["error"]["code"], -32600)
        self.assertEqual(lines[1]["id"], 7)
        self.assertEqual(lines[1]["result"], {})


if __name__ == "__main__":
    unittest.main()
