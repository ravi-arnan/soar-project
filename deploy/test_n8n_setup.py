import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).with_name("n8n-setup.py")
SPEC = importlib.util.spec_from_file_location("n8n_setup", MODULE_PATH)
assert SPEC and SPEC.loader
n8n_setup = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(n8n_setup)


class WorkflowSetupTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        (self.root / "n8n-workflows").mkdir()
        self.original_repo = n8n_setup.REPO
        self.original_workflows = n8n_setup.WORKFLOWS
        self.original_api = n8n_setup.api
        n8n_setup.REPO = str(self.root)
        n8n_setup.WORKFLOWS = ["demo"]
        self.local = {
            "name": "Demo",
            "nodes": [
                {"name": "Webhook", "type": "n8n-nodes-base.webhook", "parameters": {}}
            ],
            "connections": {},
            "settings": {"executionOrder": "v1"},
            "active": True,
        }
        (self.root / "n8n-workflows" / "demo.json").write_text(json.dumps(self.local))

    def tearDown(self):
        n8n_setup.REPO = self.original_repo
        n8n_setup.WORKFLOWS = self.original_workflows
        n8n_setup.api = self.original_api
        self.temp_dir.cleanup()

    def test_fingerprint_ignores_position_and_credential_id(self):
        left = json.loads(json.dumps(self.local))
        right = json.loads(json.dumps(self.local))
        left["nodes"][0]["position"] = [1, 2]
        right["nodes"][0]["credentials"] = {
            "httpHeaderAuth": {"id": "old-id", "name": "API"}
        }
        left["nodes"][0]["credentials"] = {
            "httpHeaderAuth": {"id": "new-id", "name": "API"}
        }

        self.assertEqual(
            n8n_setup.workflow_fingerprint(left), n8n_setup.workflow_fingerprint(right)
        )

    def test_drift_stops_before_any_workflow_update(self):
        calls = []

        def fake_api(base, key, method, path, body=None):
            calls.append((method, path))
            if method == "GET" and path.endswith("/workflows?limit=250"):
                return {"data": [{"id": "live-1", "name": "Demo"}]}
            if method == "GET" and path.endswith("/workflows/live-1"):
                current = json.loads(json.dumps(self.local))
                current["nodes"].append(
                    {"name": "Newer", "type": "n8n-nodes-base.code"}
                )
                return current
            return {}

        n8n_setup.api = fake_api
        with self.assertRaises(SystemExit):
            n8n_setup.import_workflows("http://n8n", "key", {})

        self.assertEqual([method for method, _ in calls if method == "PUT"], [])

    def test_force_allows_explicit_replacement(self):
        calls = []

        def fake_api(base, key, method, path, body=None):
            calls.append((method, path))
            if method == "GET" and path.endswith("/workflows?limit=250"):
                return {"data": [{"id": "live-1", "name": "Demo"}]}
            if method == "GET" and path.endswith("/workflows/live-1"):
                current = json.loads(json.dumps(self.local))
                current["nodes"].append(
                    {"name": "Newer", "type": "n8n-nodes-base.code"}
                )
                return current
            if method == "PUT":
                return {"active": True}
            return {}

        n8n_setup.api = fake_api
        results = n8n_setup.import_workflows("http://n8n", "key", {}, force=True)

        self.assertEqual(results[0][1], "updated")
        self.assertIn(("PUT", "/api/v1/workflows/live-1"), calls)


if __name__ == "__main__":
    unittest.main()
