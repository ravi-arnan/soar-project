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

    def test_push_credentials_maps_otx_and_aliases(self):
        env = {
            "TELEGRAM_BOT_TOKEN": "bot123",
            "WAZUH_API_USER": "wuser",
            "WAZUH_API_PASS": "wpass",
            "GSB_API_KEY": "gsbkey",
            "URLSCAN_API_KEY": "urlkey",
            "MALWAREBAZAAR_API_KEY": "mbkey",
            "OTX_API_KEY": "otxkey123",
        }
        # Mode dry-run
        name_to_id = n8n_setup.push_credentials("http://n8n", "key", env, vt_key="vtkey123", dry=True)
        self.assertIn("OTX API Key", name_to_id)
        self.assertIn("OTX Header Auth", name_to_id)
        self.assertEqual(name_to_id["OTX API Key"], ("httpHeaderAuth", "DRY"))
        self.assertEqual(name_to_id["OTX Header Auth"], ("httpHeaderAuth", "DRY"))

    def test_build_data_includes_gsb_query_auth_value(self):
        gsb_cred = next(c for c in n8n_setup.CREDENTIALS if c["name"] == "GSB Query Auth")
        data = n8n_setup.build_data(gsb_cred, {"GSB_API_KEY": "real-gsb-key"}, None)
        self.assertEqual(data, {"name": "key", "value": "real-gsb-key"})

    def test_all_default_workflows_exist_and_parse(self):
        n8n_setup.REPO = self.original_repo
        n8n_setup.WORKFLOWS = self.original_workflows
        self.assertIn("sla-eskalasi-hitl", n8n_setup.WORKFLOWS)
        for wf in n8n_setup.WORKFLOWS:
            body, _, _ = n8n_setup.load_workflow_plan(wf, {})
            self.assertTrue(body["name"])
            self.assertIsInstance(body["nodes"], list)
            self.assertGreater(len(body["nodes"]), 0)

    def test_sla_workflow_skips_info_and_escalates_overdue_hitl_via_node(self):
        import subprocess
        n8n_setup.REPO = self.original_repo
        sla_path = Path(self.original_repo) / "n8n-workflows" / "sla-eskalasi-hitl.json"
        sla = json.loads(sla_path.read_text())
        check_node = next(n for n in sla["nodes"] if n["name"] == "Cek Keputusan Lewat SLA")
        tg_node = next(n for n in sla["nodes"] if n["name"] == "Kirim Eskalasi Telegram")
        self.assertFalse(tg_node["parameters"]["additionalFields"].get("appendAttribution", True))
        self.assertIn("overdue=1", check_node["parameters"]["jsCode"])

        malware_path = Path(self.original_repo) / "n8n-workflows" / "deteksi-malware.json"
        malware = json.loads(malware_path.read_text())
        reg_node = next(n for n in malware["nodes"] if n["name"] == "Catat Keputusan Tertunda")

        script = r"""
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
const SLA_CODE = __SLA__;
const REG_CODE = __REG__;
async function run(code, items, nodes) {
  const calls = [];
  const helpers = {
    httpRequest: async (opts) => {
      calls.push(opts);
      if (opts.method === 'GET' && opts.url.includes('/decision/pending')) {
        return { items };
      }
      return { ok: true };
    }
  };
  const $ = (name) => ({ first: () => ({ json: nodes[name] || {} }) });
  const $input = { first: () => ({ json: nodes.__input || {} }) };
  const fn = new AsyncFunction('$', '$input', '$env', SLA_CODE === code ? 'return await (async () => {' + code + '})()' : code);
  const res = await fn.call({ helpers }, $, $input, { ALERT_LOG_TOKEN: 'tok' });
  return { res, calls };
}
(async () => {
  // 1) Hanya INFO / hitl=false -> harus return [] (silence total)
  const infoOnly = await run(SLA_CODE, [
    { did: 'eb8f666a80b90000', severity: 'INFO', hitl: false, status: 'pending', filename: '.org.chromium.Chromium.ii4jt3' },
    { did: 'aaaa111122223333', severity: 'INFO', hitl: true, status: 'pending', filename: 'weird.txt' },
  ], {});
  // 2) Campur INFO + MEDIUM HITL pending -> hanya eskalasi yang MEDIUM HITL + panggil /decision/escalate
  const mixed = await run(SLA_CODE, [
    { did: 'eb8f666a80b90000', severity: 'INFO', hitl: false, status: 'pending', filename: '.org.chromium.Chromium.ii4jt3' },
    { did: 'bbbb111122223333', severity: 'MEDIUM', hitl: true, status: 'pending', filename: 'unknown.exe', agent_id: '009', agent_name: 'nixbox', age_secs: 1200 },
  ], {});
  // 3) Catat Keputusan Tertunda di deteksi-malware: INFO/observe dilewati, MEDIUM/hitl terdaftar
  const regFn = new AsyncFunction('$', '$input', '$env', REG_CODE);
  const regCallsInfo = [];
  const regInfo = await regFn.call(
    { helpers: { httpRequest: async (o) => { regCallsInfo.push(o); return { ok: true }; } } },
    (n) => ({ first: () => ({ json: { decision_key: 'a'.repeat(64), agent_id: '009', filepath: '/tmp/.org.chromium.Chromium.ii4jt3', severity: 'INFO', policy_tier: 'observe', needs_decision: false } }) }),
    { first: () => ({ json: { alert_title: 'TANPA INDIKASI MALWARE' } }) },
    {}
  );
  const regCallsHitl = [];
  const regHitl = await regFn.call(
    { helpers: { httpRequest: async (o) => { regCallsHitl.push(o); return { ok: true }; } } },
    (n) => ({ first: () => ({ json: { decision_key: 'b'.repeat(64), agent_id: '009', filepath: '/tmp/unknown.exe', severity: 'MEDIUM', policy_tier: 'hitl-review', needs_decision: true, hitl_deadline_secs: 900 } }) }),
    { first: () => ({ json: { alert_title: 'FILE PERLU REVIEW' } }) },
    {}
  );
  console.log(JSON.stringify({ infoOnly, mixed, regInfo: regInfo[0].json.decision_registry, regCallsInfo, regHitl: regHitl[0].json.decision_registry, regCallsHitl }));
})();
"""
        program = script.replace(
            "__SLA__", json.dumps(check_node["parameters"]["jsCode"])
        ).replace(
            "__REG__", json.dumps(reg_node["parameters"]["jsCode"])
        )
        proc = subprocess.run(["node", "-e", program], capture_output=True, text=True, timeout=30)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        out = json.loads(proc.stdout)
        self.assertEqual(out["infoOnly"]["res"], [])
        self.assertEqual(len(out["infoOnly"]["calls"]), 1)
        self.assertEqual(out["mixed"]["res"][0]["json"]["count"], 1)
        self.assertIn("unknown.exe", out["mixed"]["res"][0]["json"]["message"])
        self.assertNotIn("Chromium", out["mixed"]["res"][0]["json"]["message"])
        self.assertTrue(
            any("/decision/escalate" in c["url"] for c in out["mixed"]["calls"])
        )
        self.assertEqual(out["regInfo"]["result"], "skipped-info-observe")
        self.assertEqual(out["regCallsInfo"], [])
        self.assertTrue(out["regHitl"]["attempted"])
        self.assertEqual(len(out["regCallsHitl"]), 1)


if __name__ == "__main__":
    unittest.main()
