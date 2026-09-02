#!/usr/bin/env python3
"""Push updated Rangkum Hasil jsCode to n8n via MCP update_workflow."""
import json
import sys
import urllib.request

MCP_URL = "http://localhost:5678/mcp-server/http"
TOKEN = sys.argv[1] if len(sys.argv) > 1 else ""
WORKFLOW_ID = "76f8gAyctCAAu5f6"

# Read updated jsCode from local file
with open("n8n-workflows/deteksi-malware.json") as f:
    raw = json.load(f)
wf = raw[0] if isinstance(raw, list) else raw
for n in wf["nodes"]:
    if n["name"] == "Rangkum Hasil":
        js_code = n["parameters"]["jsCode"]
        break
else:
    print("ERROR: Rangkum Hasil node not found in local file")
    sys.exit(1)

# Also get Cek Cache VT code
for n in wf["nodes"]:
    if n["name"] == "Cek Cache VT":
        cache_code = n["parameters"]["jsCode"]
        break
else:
    cache_code = None

print(f"Rangkum Hasil jsCode: {len(js_code)} chars")
if cache_code:
    print(f"Cek Cache VT jsCode: {len(cache_code)} chars")

# Build MCP request
operations = [
    {
        "type": "setNodeParameter",
        "nodeName": "Rangkum Hasil",
        "path": "/parameters/jsCode",
        "value": js_code
    }
]
if cache_code:
    operations.append({
        "type": "setNodeParameter",
        "nodeName": "Cek Cache VT",
        "path": "/parameters/jsCode",
        "value": cache_code
    })

payload = {
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
        "name": "update_workflow",
        "arguments": {
            "workflowId": WORKFLOW_ID,
            "operations": operations
        }
    },
    "id": 20
}

data = json.dumps(payload).encode()
req = urllib.request.Request(
    MCP_URL,
    data=data,
    headers={
        "Authorization": f"Bearer {TOKEN}",
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream"
    }
)

try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw_text = resp.read().decode()
        for line in raw_text.split("\n"):
            if line.startswith("data: "):
                result = json.loads(line[6:])
                content = result.get("result", {}).get("content", [])
                for c in content:
                    if c.get("type") == "text":
                        print(c["text"])
                break
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
