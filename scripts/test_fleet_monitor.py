import importlib.util
import json
import os
import tempfile
import threading
import unittest
from datetime import datetime, timedelta
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
# Riwayat event (SQLite) juga ke temp agar test tidak mengotori scripts/.
os.environ.setdefault(
    "FLEET_EVENTS_DB",
    os.path.join(tempfile.mkdtemp(prefix="fleet-events-"), "events.db"),
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
fleet_monitor._event_store_init()


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


def _clear_events():
    conn = fleet_monitor._db()
    try:
        conn.execute("DELETE FROM events")
        conn.commit()
    finally:
        conn.close()


class EventStoreTests(_ApiTestCase):
    """Riwayat durable: insert/query rentang, retensi, cap baris (SQLite)."""

    def setUp(self):
        _clear_events()

    def test_insert_dan_query_rentang(self):
        now = datetime.now(fleet_monitor.WITA)
        fleet_monitor._event_store_insert(
            {"ts": (now - timedelta(days=40)).isoformat(), "agent_id": "009",
             "path": "/old", "severity": "HIGH"}
        )
        fleet_monitor._event_store_insert(
            {"ts": now.isoformat(), "agent_id": "009", "path": "/new",
             "severity": "CRITICAL"}
        )

        rows = fleet_monitor._event_store_query(
            since=(now - timedelta(days=1)).isoformat()
        )

        self.assertEqual([r["path"] for r in rows], ["/new"])
        self.assertEqual(rows[0]["source"], "soar")

    def test_normalisasi_ts_ke_utc(self):
        self.assertEqual(
            fleet_monitor._to_utc_iso("2026-09-30T10:00:00+08:00"),
            fleet_monitor._to_utc_iso("2026-09-30T02:00:00Z"),
        )
        self.assertTrue(fleet_monitor._to_utc_iso("2026-09-30T10:00:00+08:00").endswith("Z"))
        self.assertEqual(
            fleet_monitor._to_utc_iso("2026-05-16T20:08:00.000+0000"),
            fleet_monitor._to_utc_iso("2026-05-16T20:08:00.000Z"),
        )

    def test_prune_retensi(self):
        now = datetime.now(fleet_monitor.WITA)
        fleet_monitor._event_store_insert(
            {"ts": (now - timedelta(days=fleet_monitor.EVENTS_RETENTION_DAYS + 5)).isoformat(),
             "agent_id": "009", "path": "/stale"}
        )
        fleet_monitor._event_store_insert(
            {"ts": now.isoformat(), "agent_id": "009", "path": "/fresh"}
        )

        fleet_monitor._event_store_prune(now)

        rows = fleet_monitor._event_store_query()
        self.assertEqual([r["path"] for r in rows], ["/fresh"])

    def test_prune_cap_baris(self):
        original = fleet_monitor.EVENTS_MAX_ROWS
        fleet_monitor.EVENTS_MAX_ROWS = 3
        try:
            now = datetime.now(fleet_monitor.WITA)
            for i in range(6):
                fleet_monitor._event_store_insert(
                    {"ts": (now + timedelta(seconds=i)).isoformat(),
                     "agent_id": "009", "path": f"/f{i}"}
                )
            fleet_monitor._event_store_prune(now)
            rows = fleet_monitor._event_store_query()
        finally:
            fleet_monitor.EVENTS_MAX_ROWS = original

        self.assertEqual(len(rows), 3)
        self.assertEqual([r["path"] for r in rows], ["/f5", "/f4", "/f3"])


class IndexerMappingTests(unittest.TestCase):
    def test_map_alert_wazuh(self):
        hit = {"_id": "abc", "_source": {
            "@timestamp": "2026-09-30T03:17:59.883Z",
            "rule": {"id": "110002", "level": 10, "description": "cmd->powershell"},
            "agent": {"id": "007", "name": "bali-handmade"},
            "data": {"sha256": "f" * 64, "path": "C:/x"},
        }}

        event = fleet_monitor._indexer_map(hit)

        self.assertEqual(event["severity"], "HIGH")
        self.assertEqual(event["agent_id"], "007")
        self.assertEqual(event["rule_level"], 10)
        self.assertEqual(event["source"], "wazuh")
        self.assertEqual(event["hash"], "f" * 64)

    def test_level_ke_severity(self):
        cases = ((12, "CRITICAL"), (11, "HIGH"), (7, "HIGH"), (6, "MEDIUM"), (3, "INFO"))
        for level, expected in cases:
            hit = {"_source": {"rule": {"level": level}, "agent": {}}}
            self.assertEqual(fleet_monitor._indexer_map(hit)["severity"], expected)


class MergeTests(unittest.TestCase):
    def test_dedup_buang_wazuh_yang_sudah_dienrich(self):
        soar = [{"agent_id": "009", "hash": "A" * 64, "path": "/x", "source": "soar"}]
        wazuh = [
            {"agent_id": "009", "hash": "a" * 64, "path": "/x", "source": "wazuh"},
            {"agent_id": "009", "hash": "b" * 64, "path": "/y", "source": "wazuh"},
        ]

        merged = fleet_monitor._merge_history(soar, wazuh, dedup=True)

        self.assertEqual(len(merged), 2)
        self.assertEqual({e["source"] for e in merged}, {"soar", "wazuh"})

    def test_tanpa_dedup_semua_masuk(self):
        merged = fleet_monitor._merge_history(
            [{"agent_id": "009", "hash": "a" * 64, "source": "soar"}],
            [{"agent_id": "009", "hash": "a" * 64, "source": "wazuh"}],
            dedup=False,
        )
        self.assertEqual(len(merged), 2)


class HistoryEndpointTests(_ApiTestCase):
    def setUp(self):
        _clear_events()

    def test_endpoint_history_kembalikan_event_dan_stats(self):
        payload = {
            "agent": "agent-009", "agent_id": "009",
            "path": "/home/ravi/Downloads/eicar.com", "hash": "a" * 64,
            "severity": "CRITICAL",
            "ts": datetime.now(fleet_monitor.WITA).isoformat(),
        }
        self.request("POST", "/webhook-log", payload)

        status, _, body = self.request("GET", "/api/events/history?source=soar&limit=10")

        self.assertEqual(status, 200)
        self.assertEqual(body["total"], 1)
        self.assertEqual(body["events"][0]["path"], payload["path"])
        self.assertEqual(body["stats"]["severity"]["CRITICAL"], 1)
        self.assertEqual(body["sources"]["wazuh"], 0)

    def test_endpoint_history_filter_since_dan_severity(self):
        now = datetime.now(fleet_monitor.WITA)
        self.request("POST", "/webhook-log", {
            "agent_id": "009", "path": "/old", "severity": "HIGH",
            "ts": (now - timedelta(days=40)).isoformat(),
        })
        self.request("POST", "/webhook-log", {
            "agent_id": "009", "path": "/new", "severity": "CRITICAL",
            "ts": now.isoformat(),
        })

        status, _, body = self.request(
            "GET", "/api/events/history?since=" + (now - timedelta(days=1)).isoformat()
        )
        self.assertEqual(status, 200)
        self.assertEqual([e["path"] for e in body["events"]], ["/new"])

        _, _, body = self.request("GET", "/api/events/history?severity=CRITICAL")
        self.assertEqual([e["path"] for e in body["events"]], ["/new"])

    def test_endpoint_degradasi_tanpa_indexer(self):
        status, _, body = self.request("GET", "/api/events/history")
        self.assertEqual(status, 200)
        self.assertIsNone(body["indexer_ok"])


if __name__ == "__main__":
    unittest.main()
