import importlib.util
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime
from http.server import HTTPServer
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

# Heartbeat menulis roster ke STATE_FILE; arahkan ke temp agar test tidak
# mengotori scripts/.fleet-state.json.
os.environ.setdefault(
    "FLEET_STATE_FILE",
    os.path.join(tempfile.mkdtemp(prefix="fleet-test-"), "fleet-state.json"),
)
os.environ["FLEET_COMMAND_TOKEN"] = "command-" + "a" * 48
os.environ["FLEET_AGENT_POLL_TOKENS_JSON"] = json.dumps(
    {
        "009": "poll-" + "b" * 48,
        "010": "poll-" + "c" * 48,
    }
)

MODULE_PATH = Path(__file__).with_name("fleet-monitor.py")
SPEC = importlib.util.spec_from_file_location("fleet_monitor", MODULE_PATH)
assert SPEC and SPEC.loader
fleet_monitor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fleet_monitor)


class _ApiTestCase(unittest.TestCase):
    """Harness HTTP bersama: server di port acak + helper request()."""

    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), fleet_monitor.Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, method, path, body=None, token=None):
        headers = {"Accept": "application/json"}
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method
        )
        try:
            with urlopen(request, timeout=2) as response:
                return response.status, response.headers, json.loads(response.read())
        except HTTPError as error:
            body = error.read()
            error.close()
            return error.code, error.headers, json.loads(body)


class CommandApiTests(_ApiTestCase):
    def setUp(self):
        fleet_monitor.COMMANDS.clear()

    def test_runtime_rejects_equal_command_and_poll_tokens(self):
        original_command = fleet_monitor.FLEET_COMMAND_TOKEN
        original_poll = fleet_monitor.FLEET_AGENT_POLL_TOKENS
        fleet_monitor.FLEET_COMMAND_TOKEN = "same-" + "a" * 48
        fleet_monitor.FLEET_AGENT_POLL_TOKENS = {
            "009": fleet_monitor.FLEET_COMMAND_TOKEN
        }
        try:
            with self.assertRaises(RuntimeError):
                fleet_monitor._validate_runtime_secrets()
        finally:
            fleet_monitor.FLEET_COMMAND_TOKEN = original_command
            fleet_monitor.FLEET_AGENT_POLL_TOKENS = original_poll

    def test_empty_runtime_command_token_never_authorizes(self):
        original = fleet_monitor.FLEET_COMMAND_TOKEN
        fleet_monitor.FLEET_COMMAND_TOKEN = ""
        try:
            status, _, _ = self.request(
                "POST",
                "/api/commands",
                {"agent_id": "009", "action": "scan", "target": "/home/ravi/Downloads"},
                "",
            )
        finally:
            fleet_monitor.FLEET_COMMAND_TOKEN = original

        self.assertEqual(status, 401)

    def test_post_requires_command_token(self):
        status, headers, body = self.request(
            "POST",
            "/api/commands",
            {"agent_id": "009", "action": "scan", "target": "/home/ravi/Downloads"},
        )

        self.assertEqual(status, 401)
        self.assertEqual(headers["WWW-Authenticate"], "Bearer")
        self.assertEqual(body["error"], "unauthorized")

    def test_post_queues_valid_command_with_token(self):
        status, _, body = self.request(
            "POST",
            "/api/commands",
            {
                "agent_id": "009",
                "action": "quarantine",
                "target": "/home/ravi/Downloads/eicar.com",
                "by": "dashboard",
            },
            fleet_monitor.FLEET_COMMAND_TOKEN,
        )

        self.assertEqual(status, 200)
        self.assertEqual(
            body, {"status": "queued", "agent_id": "009", "action": "quarantine"}
        )
        self.assertEqual(fleet_monitor.COMMANDS["009"][0]["by"], "dashboard")

    def test_post_rejects_invalid_target(self):
        status, _, body = self.request(
            "POST",
            "/api/commands",
            {"agent_id": "009", "action": "scan", "target": "/home/ravi/../etc"},
            fleet_monitor.FLEET_COMMAND_TOKEN,
        )

        self.assertEqual(status, 400)
        self.assertIn("path absolut", body["error"])

    def test_get_requires_poll_token_and_drains_once(self):
        self.request(
            "POST",
            "/api/commands",
            {"agent_id": "009", "action": "sinkhole", "target": "evil.example"},
            fleet_monitor.FLEET_COMMAND_TOKEN,
        )
        status, _, _ = self.request("GET", "/api/commands?agent_id=009")
        self.assertEqual(status, 401)

        status, _, body = self.request(
            "GET",
            "/api/commands?agent_id=009",
            token=fleet_monitor.FLEET_AGENT_POLL_TOKENS["009"],
        )
        self.assertEqual(status, 200)
        self.assertEqual(len(body["commands"]), 1)
        self.assertEqual(fleet_monitor.COMMANDS, {})

    def test_webhook_events_receive_unique_ids(self):
        payload = {
            "agent": "009",
            "agent_id": "009",
            "path": "/home/ravi/Downloads/eicar.com",
            "hash": "a" * 64,
        }
        first = self.request("POST", "/webhook-log", payload)
        second = self.request("POST", "/webhook-log", payload)
        first_event = fleet_monitor.EVENTS[-2]
        second_event = fleet_monitor.EVENTS[-1]

        self.assertEqual(first[0], 200)
        self.assertEqual(second[0], 200)
        self.assertNotEqual(first_event["id"], second_event["id"])

    def test_post_rejects_unregistered_agent(self):
        status, _, _ = self.request(
            "POST",
            "/api/commands",
            {"agent_id": "011", "action": "scan", "target": "/home/ravi/Downloads"},
            fleet_monitor.FLEET_COMMAND_TOKEN,
        )

        self.assertEqual(status, 404)

    def test_agent_token_cannot_poll_another_agent(self):
        status, _, _ = self.request(
            "GET",
            "/api/commands?agent_id=010",
            token=fleet_monitor.FLEET_AGENT_POLL_TOKENS["009"],
        )

        self.assertEqual(status, 401)

    def test_sinkhole_rejects_ip_literal(self):
        status, _, _ = self.request(
            "POST",
            "/api/commands",
            {"agent_id": "009", "action": "sinkhole", "target": "127.0.0.1"},
            fleet_monitor.FLEET_COMMAND_TOKEN,
        )

        self.assertEqual(status, 400)

    def test_post_rejects_oversized_body(self):
        request = Request(
            f"{self.base_url}/api/commands",
            data=b"x" * (fleet_monitor.COMMAND_BODY_MAX + 1),
            headers={
                "Authorization": f"Bearer {fleet_monitor.FLEET_COMMAND_TOKEN}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        with self.assertRaises(HTTPError) as context:
            urlopen(request, timeout=2)

        self.assertEqual(context.exception.code, 413)
        context.exception.close()

    def test_command_response_does_not_allow_cross_origin(self):
        status, headers, _ = self.request(
            "POST",
            "/api/commands",
            {"agent_id": "009", "action": "scan", "target": "/home/ravi/Downloads"},
            fleet_monitor.FLEET_COMMAND_TOKEN,
        )

        self.assertEqual(status, 200)
        self.assertNotIn("Access-Control-Allow-Origin", headers)


class RegistrationDateTests(_ApiTestCase):
    """Heartbeat Rust -> "Registration date" (first_seen) gaya Wazuh."""

    def setUp(self):
        fleet_monitor.HEARTBEATS.clear()

    def test_heartbeat_sets_and_preserves_first_seen(self):
        payload = {"id": "009", "name": "agent-009", "os": "linux"}
        self.request("POST", "/api/heartbeat", payload)
        first = fleet_monitor.HEARTBEATS["009"]["first_seen"]

        self.request("POST", "/api/heartbeat", payload)
        entry = fleet_monitor.HEARTBEATS["009"]

        self.assertEqual(entry["first_seen"], first)
        self.assertGreaterEqual(entry["last_seen"], entry["first_seen"])

    def test_build_fleet_emits_regdate_from_first_seen(self):
        self.request(
            "POST", "/api/heartbeat", {"id": "009", "name": "agent-009", "os": "linux"}
        )

        original_fetch = fleet_monitor.fetch_wazuh_agents
        original_http = fleet_monitor.check_http
        fleet_monitor.fetch_wazuh_agents = lambda cfg: []
        fleet_monitor.check_http = lambda url: False
        try:
            data = fleet_monitor.build_fleet(
                {"gemini_key": "", "n8n_url": "http://127.0.0.1:1"}
            )
        finally:
            fleet_monitor.fetch_wazuh_agents = original_fetch
            fleet_monitor.check_http = original_http

        agent = next(a for a in data["agents"] if a["id"] == "009")
        expected = datetime.fromtimestamp(
            fleet_monitor.HEARTBEATS["009"]["first_seen"], fleet_monitor.WITA
        ).isoformat()
        self.assertNotEqual(agent["regDate"], "-")
        self.assertEqual(agent["regDate"], expected)


if __name__ == "__main__":
    unittest.main()
