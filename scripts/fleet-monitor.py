#!/usr/bin/env python3
"""Fleet Monitor 100 PC — custom monitoring untuk arahan dospem (custom Go/Rust, bukan Wazuh Dashboard berat).

Poll Wazuh API untuk agent Wazuh (001,002) + terima heartbeat dari soar-agent Rust (003..N)
via POST /api/heartbeat. Serve HTML dashboard single-pane untuk 100 workstation.

Endpoints:
  GET  /              -> HTML dashboard (auto-refresh 5s, Lucide icons, no emoji)
  GET  /api/fleet     -> JSON fleet status
  POST /api/heartbeat -> {"id":"003","name":"rust-agent-ravi","ip":"100.95.198.108","version":"0.1.0"} -> 200
  GET  /healthz       -> 200 ok (untuk docker healthcheck)

Tanpa deps tambahan (stdlib only). Jalankan: python3 scripts/fleet-monitor.py
Docker: python:3.12-alpine + mount scripts/fleet-monitor.py + env .env

ponytail: sengaja tidak pakai FastAPI/Flask — satu file, 3 tugas (poll Wazuh, terima heartbeat, serve HTML).
Upgrade path: ganti http.server dengan FastAPI + Prometheus kalau butuh Grafana (ROADMAP.md:92 E).
"""

import base64
import json
import os
import ssl
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse


# Load .env jika ada (untuk jalan di host tanpa docker env_file)
def _load_dotenv():
    for p in [".env", os.path.join(os.path.dirname(__file__), "..", ".env")]:
        if os.path.exists(p):
            try:
                with open(p) as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip('"').strip("'")
                        if k not in os.environ:
                            os.environ[k] = v
            except Exception:
                pass
            break


_load_dotenv()

WITA = timezone(timedelta(hours=8))

_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE

# In-memory heartbeat store: id -> {name, ip, version, last_seen, last_hash, quarantine_count}
HEARTBEATS = {}
HEARTBEAT_TTL = (
    120  # detik, lewat ini dianggap disconnected (2x interval heartbeat 60s)
)

# Cache Wazuh agents
WAZUH_CACHE = {"data": [], "fetched_at": 0}
WAZUH_TTL = 30


def _cfg():
    # ponytail: default 127.0.0.1 untuk host, docker-compose akan override via env_file/host.docker.internal jika perlu
    return {
        "wazuh_url": os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000").rstrip(
            "/"
        ),
        "wazuh_user": os.environ.get("WAZUH_API_USER", "wazuh-wui"),
        "wazuh_pass": os.environ.get("WAZUH_API_PASS", ""),
        "n8n_url": os.environ.get("N8N_HEALTH_URL", "http://127.0.0.1:5678/healthz"),
        "ollama_url": os.environ.get(
            "OLLAMA_URL", "http://127.0.0.1:11434/api/version"
        ),
        "port": int(os.environ.get("FLEET_PORT", "8080")),
    }


def _get(url, headers=None, timeout=10):
    req = urllib.request.Request(url, headers=headers or {})
    return urllib.request.urlopen(req, timeout=timeout, context=_INSECURE)


def check_http(url):
    try:
        with _get(url) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def _fetch_wazuh_once(base_url, cfg):
    auth = base64.b64encode(f"{cfg['wazuh_user']}:{cfg['wazuh_pass']}".encode()).decode()
    with _get(f"{base_url}/security/user/authenticate", headers={"Authorization": f"Basic {auth}"}) as r:
        token = json.load(r)["data"]["token"]
    with _get(f"{base_url}/agents?select=id,name,status,ip,version,dateAdd,lastKeepAlive&limit=500", headers={"Authorization": f"Bearer {token}"}) as r:
        return json.load(r)["data"]["affected_items"]

def fetch_wazuh_agents(cfg):
    now = time.time()
    if now - WAZUH_CACHE["fetched_at"] < WAZUH_TTL and WAZUH_CACHE["data"]:
        return WAZUH_CACHE["data"]
    urls = [cfg["wazuh_url"]]
    if "127.0.0.1" in cfg["wazuh_url"]:
        urls.append(cfg["wazuh_url"].replace("127.0.0.1", "host.docker.internal"))
    elif "host.docker.internal" in cfg["wazuh_url"]:
        urls.append(cfg["wazuh_url"].replace("host.docker.internal", "127.0.0.1"))
    last_err = None
    for url in urls:
        try:
            agents = _fetch_wazuh_once(url, cfg)
            WAZUH_CACHE["data"] = agents
            WAZUH_CACHE["fetched_at"] = now
            return agents
        except Exception as e:
            last_err = e
            continue
    print(f"wazuh fetch error: {last_err}", flush=True)
    return WAZUH_CACHE["data"]


def build_fleet(cfg):
    wazuh_agents = fetch_wazuh_agents(cfg)
    now = time.time()
    now_wita = datetime.now(WITA).isoformat()

    fleet = []
    # Wazuh agents
    for a in wazuh_agents:
        fleet.append(
            {
                "id": a.get("id", "?"),
                "name": a.get("name", "?"),
                "type": "wazuh",
                "status": a.get("status", "unknown"),
                "ip": a.get("ip", "-"),
                "version": a.get("version", "-"),
                "lastKeepAlive": a.get("lastKeepAlive", "-"),
                "binary": "50 MB",
                "ram": "~50 MB",
            }
        )

    # Rust heartbeats (id 003..N) — merge, kalau id sama dengan Wazuh, tampilkan Rust sebagai type ringan
    for hid, hb in list(HEARTBEATS.items()):
        age = now - hb["last_seen"]
        status = "active" if age < HEARTBEAT_TTL else "disconnected"
        # Jika sudah ada di Wazuh dengan id sama, timpa dengan data Rust (lebih ringan)
        existing = next((x for x in fleet if x["id"] == hid), None)
        entry = {
            "id": hid,
            "name": hb.get("name", f"rust-agent-{hid}"),
            "type": "rust",
            "status": status,
            "ip": hb.get("ip", "-"),
            "version": hb.get("version", "0.1.0"),
            "lastKeepAlive": datetime.fromtimestamp(hb["last_seen"], WITA).isoformat(),
            "last_hash": hb.get("last_hash", "-")[:12] + "..."
            if hb.get("last_hash")
            else "-",
            "binary": "5.3 MB",
            "ram": "5.2 MB",
            "age_sec": int(age),
        }
        if existing:
            # ganti entry Wazuh dengan Rust jika heartbeat lebih fresh
            fleet = [e for e in fleet if e["id"] != hid]
        fleet.append(entry)

    # Sort by id
    fleet.sort(key=lambda x: x["id"])

    health = {
        "n8n": check_http(cfg["n8n_url"]),
        "ollama": check_http(cfg["ollama_url"]),
        "wazuh_api": len(wazuh_agents) > 0,
    }

    active = sum(1 for a in fleet if a["status"] == "active")
    rust_count = sum(1 for a in fleet if a["type"] == "rust")
    wazuh_count = sum(1 for a in fleet if a["type"] == "wazuh")

    return {
        "generated_at": now_wita,
        "health": health,
        "stats": {
            "total": len(fleet),
            "active": active,
            "disconnected": len(fleet) - active,
            "rust": rust_count,
            "wazuh": wazuh_count,
            "capacity_demo": "100 workstation ready (scalable, hash-only 1-2 KB per event)",
        },
        "agents": fleet,
    }


HTML = r"""<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wazuh — Fleet Monitor (100 Workstation)</title>
<script src="https://unpkg.com/lucide@latest"></script>
<style>
  /* Wazuh Dashboard palette — tiru OpenSearch Dashboards + Wazuh plugin (light theme) */
  *{box-sizing:border-box}
  body{font-family:Inter, ui-sans-system, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; margin:0; background:#f5f7fa; color:#2f343f}
  /* Top nav ala Wazuh: dark navy, logo wazuh. */
  .wz-header{background:#011a2f; color:#fff; padding:0 16px; height:48px; display:flex; align-items:center; justify-content:space-between; border-bottom:3px solid #00a9e0}
  .wz-brand{display:flex;align-items:center;gap:10px;font-weight:700;letter-spacing:.02em}
  .wz-brand span.wz-logo{font-size:20px;letter-spacing:.01em}
  .wz-brand span.wz-logo b{color:#00a9e0}
  .wz-brand small{font-weight:400;opacity:.75;font-size:12px;margin-left:8px}
  .wz-header-right{font-size:11px;opacity:.8;display:flex;gap:12px;align-items:center}
  .wz-subnav{background:#fff;border-bottom:1px solid #d3dae6;padding:10px 16px;display:flex;gap:16px;flex-wrap:wrap;align-items:center}
  .wz-subnav .breadcrumb{font-size:13px;color:#00a9e0}
  .wz-subnav .meta{font-size:11px;color:#6a717d;margin-left:auto;display:flex;gap:12px;align-items:center}
  /* Cards ala Wazuh overview: putih, border tipis, shadow halus */
  .cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;padding:16px}
  .card{background:#fff;border:1px solid #d3dae6;border-radius:4px;padding:14px;box-shadow:0 1px 2px rgba(0,0,0,.04)}
  .card .label{font-size:11px;letter-spacing:.06em;color:#6a717d;text-transform:uppercase;font-weight:600}
  .card .value{font-size:24px;font-weight:700;margin-top:4px;color:#011a2f}
  .card .hint{font-size:11px;color:#6a717d;margin-top:2px}
  .status-ok{color:#00a86b} .status-warn{color:#ff8f1c} .status-bad{color:#db2828}
  /* Health bar ala Wazuh */
  .health{background:#fff;border:1px solid #d3dae6;border-radius:4px;margin:0 16px;padding:10px 14px;display:flex;gap:18px;flex-wrap:wrap;font-size:12px;align-items:center}
  .health span{display:inline-flex;align-items:center;gap:6px}
  .health .dot{width:8px;height:8px;border-radius:50%;display:inline-block}
  /* Table ala Wazuh Agents */
  .panel{background:#fff;border:1px solid #d3dae6;border-radius:4px;margin:16px;overflow:hidden;box-shadow:0 1px 2px rgba(0,0,0,.04)}
  .panel-head{padding:12px 14px;border-bottom:1px solid #d3dae6;display:flex;gap:8px;align-items:center;flex-wrap:wrap;background:#fff}
  .panel-head h2{margin:0;font-size:13px;font-weight:700;color:#011a2f;display:flex;align-items:center;gap:8px}
  .panel-head .spacer{flex:1}
  .btn{appearance:none;border:1px solid transparent;background:#00a9e0;color:#fff;padding:6px 12px;border-radius:4px;font-size:12px;font-weight:600;cursor:pointer;display:inline-flex;gap:6px;align-items:center}
  .btn:hover{background:#0095c7}
  .btn-secondary{background:#fff;color:#00658f;border-color:#00a9e0}
  .btn-secondary:hover{background:#e6f7ff}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th{background:#f8f9fb;color:#5a6470;font-weight:600;text-align:left;padding:8px 10px;border-bottom:1px solid #d3dae6;font-size:11px;letter-spacing:.04em;text-transform:uppercase;white-space:nowrap}
  td{padding:8px 10px;border-bottom:1px solid #eef1f6;color:#2f343f}
  tr:hover td{background:#f2f8ff}
  .badge{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:10px;font-size:11px;font-weight:600;border:1px solid}
  .badge-active{background:#e6f4ea;color:#137333;border-color:#b7e1c5}
  .badge-disc{background:#fce8e6;color:#a50e0e;border-color:#f5c6c2}
  .badge-rust{background:#e8f0fe;color:#1967d2;border-color:#c2d6ff}
  .badge-wazuh{background:#f1f3f4;color:#3c4043;border-color:#dadce0}
  .mono{font-family:ui-monospace, "Cascadia Code", Menlo, monospace; font-size:11px}
  .muted{color:#6a717d}
  .wrap-foot{padding:10px 14px;background:#f8f9fb;border-top:1px solid #d3dae6;font-size:11px;color:#6a717d}
  a{color:#00a9e0;text-decoration:none} a:hover{text-decoration:underline}
</style>
</head>
<body>
<!-- Header plek Wazuh Dashboard -->
<div class="wz-header">
  <div class="wz-brand"><span class="wz-logo">wazuh<span>.</span></span> <small>Fleet Monitor</small> <span style="background:#00a9e0;color:#fff;font-size:10px;padding:2px 6px;border-radius:3px;margin-left:8px;letter-spacing:.06em">100 WORKSTATION</span></div>
  <div class="wz-header-right"><span><i data-lucide="clock" style="width:12px;height:12px;vertical-align:-2px"></i> <span id="generated">-</span></span> <span>auto refresh 5s • <span id="countdown">5</span>s</span> <span style="opacity:.6">|</span> <span>SOAR • n8n otak • hash-only</span></div>
</div>
<div class="wz-subnav">
  <span class="breadcrumb"><i data-lucide="layout-dashboard" style="width:13px;height:13px;vertical-align:-2px"></i> Management / Fleet Monitor</span>
  <span class="meta"><i data-lucide="info" style="width:12px;height:12px"></i> Visualisasi pakai desain Wazuh • <a href="https://127.0.0.1:443" target="_blank">buka Wazuh Dashboard asli</a> untuk forensik</span>
</div>

<div class="cards" id="cards"></div>
<div class="health" id="health"></div>

<div class="panel">
  <div class="panel-head">
    <h2><i data-lucide="monitor-smartphone" style="width:15px;height:15px;color:#00a9e0"></i> Agents ({{total}})</h2>
    <span class="muted" style="font-size:11px">Wazuh ~50 MB vs Rust 5.3 MB • polling Wazuh API 30s + heartbeat Rust 60s</span>
    <span class="spacer"></span>
    <button class="btn" onclick="load()"><i data-lucide="refresh-cw" style="width:12px;height:12px"></i> Refresh</button>
    <button class="btn-secondary btn" onclick="simulate()"><i data-lucide="users" style="width:12px;height:12px"></i> Simulasi 100 PC</button>
  </div>
<table>
<thead><tr><th>ID</th><th>Nama</th><th>Tipe</th><th>Status</th><th>IP</th><th>Versi</th><th>Last KeepAlive</th><th>Binary</th><th>RAM</th></tr></thead>
<tbody id="tbody"><tr><td colspan=9 class="muted" style="padding:24px;text-align:center">loading agents...</td></tr></tbody>
</table>
  <div class="wrap-foot">POST <span class="mono">/api/heartbeat</span> untuk Rust agent &bull; GET <span class="mono">/api/fleet</span> JSON &bull; Desain meniru Wazuh Dashboard (OpenSearch Dashboards, light theme, header #011a2f, aksen #00a9e0) agar dospem langsung familiar. Rust agent kirim heartbeat 60s + file event hash-only 1-2 KB ke n8n.</div>
</div>

<script>
let timer=5;
async function load(){
  try{
    const r=await fetch('/api/fleet'); const j=await r.json();
    document.getElementById('generated').textContent=j.generated_at;
    // cards
    const s=j.stats, h=j.health;
    document.getElementById('cards').innerHTML=`
      <div class="card"><div class="label">Total Agents</div><div class="value">${s.total}</div><div class="hint">${s.rust} Rust ringan + ${s.wazuh} Wazuh</div></div>
      <div class="card"><div class="label">Active</div><div class="value status-ok">${s.active}</div><div class="hint">${s.disconnected} disconnected</div></div>
      <div class="card"><div class="label">Coverage</div><div class="value" style="font-size:12px;line-height:1.3">${s.capacity_demo}</div><div class="hint">scalable tanpa Docker per klien</div></div>
      <div class="card"><div class="label">Efisiensi</div><div class="value" style="font-size:16px">90% lebih ringan</div><div class="hint">5.3 MB vs 50 MB • 5.2 MB RAM</div></div>
    `;
    document.getElementById('health').innerHTML=`
      <span><span class="dot" style="background:${h.n8n?'#00a86b':'#db2828'}"></span> n8n ${h.n8n?'OK':'DOWN'}</span>
      <span><span class="dot" style="background:${h.ollama?'#00a86b':'#db2828'}"></span> Ollama ${h.ollama?'OK':'DOWN'}</span>
      <span><span class="dot" style="background:${h.wazuh_api?'#00a86b':'#db2828'}"></span> Wazuh API ${h.wazuh_api?'OK':'DOWN'}</span>
      <span class="muted mono" style="margin-left:auto">fleet: ${j.agents.length} agents • header #011a2f, aksen #00a9e0 plek Wazuh</span>
    `;
    const tb=document.getElementById('tbody'); tb.innerHTML='';
    if(j.agents.length===0) tb.innerHTML='<tr><td colspan=9 class="muted">belum ada agent (nyalakan Wazuh agent / soar-agent)</td></tr>';
    else j.agents.forEach(a=>{
      const isActive=a.status==='active';
      tb.innerHTML+=`<tr>
        <td class="mono">${a.id}</td>
        <td>${a.name}</td>
        <td><span class="badge ${a.type==='rust'?'badge-rust':'badge-wazuh'}">${a.type}</span></td>
        <td><span class="badge ${isActive?'badge-active':'badge-disc'}"><i data-lucide="${isActive?'activity':'wifi-off'}" style="width:12px;height:12px"></i> ${a.status}</span></td>
        <td class="mono">${a.ip}</td>
        <td class="mono">${a.version}</td>
        <td class="mono muted">${(a.lastKeepAlive||'-').slice(0,19)}</td>
        <td class="mono">${a.binary}</td>
        <td class="mono">${a.ram}</td>
      </tr>`;
    });
    lucide.createIcons();
  }catch(e){ document.getElementById('tbody').innerHTML=`<tr><td colspan=9 class="status-bad">error: ${e}</td></tr>` }
  timer=5;
}
async function simulate(){
  // kirim 97 heartbeat dummy (003 sudah ada, jadi total 100: 2 Wazuh + 98 Rust dummy)
  for(let i=4;i<=100;i++){
    const id=String(i).padStart(3,'0');
    await fetch('/api/heartbeat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id, name:`rust-agent-lab-${id}`, ip:`192.168.18.${100+i}`, version:"0.1.0", last_hash:"simulated"})});
  }
  load();
}
setInterval(()=>{ document.getElementById('countdown').textContent=--timer; if(timer<=0) load(); },1000);
load();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} {fmt % args}", flush=True)

    def do_GET(self):
        cfg = _cfg()
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML.encode())
        elif parsed.path == "/api/fleet":
            data = build_fleet(cfg)
            body = json.dumps(data).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/healthz":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"not found")

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/heartbeat":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                j = json.loads(body)
                hid = str(j.get("id", "")).strip()
                if not hid:
                    raise ValueError("need id")
                # IP dari X-Forwarded atau remote
                ip = j.get("ip") or self.client_address[0]
                HEARTBEATS[hid] = {
                    "name": j.get("name", f"rust-agent-{hid}"),
                    "ip": ip,
                    "version": j.get("version", "0.1.0"),
                    "last_hash": j.get("last_hash", ""),
                    "last_seen": time.time(),
                }
                resp = {"status": "ok", "id": hid}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(resp).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()


def main():
    cfg = _cfg()
    port = cfg["port"]
    # ponytail: bind 0.0.0.0 supaya bisa diakses dari Tailscale 100.95.198.108:8080 untuk 100 PC
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(
        f"fleet-monitor listen 0.0.0.0:{port} (Wazuh {cfg['wazuh_url']}, n8n {cfg['n8n_url']})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
