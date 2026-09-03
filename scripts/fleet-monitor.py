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

# Ring buffer event (max 200): alert file dari agent / n8n webhook-log
EVENTS = []
EVENTS_MAX = 200

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
        "gemini_key": os.environ.get("GEMINI_API_KEY", ""),
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
    auth = base64.b64encode(
        f"{cfg['wazuh_user']}:{cfg['wazuh_pass']}".encode()
    ).decode()
    with _get(
        f"{base_url}/security/user/authenticate",
        headers={"Authorization": f"Basic {auth}"},
    ) as r:
        token = json.load(r)["data"]["token"]
    with _get(
        f"{base_url}/agents?select=id,name,status,ip,version,dateAdd,lastKeepAlive&limit=500",
        headers={"Authorization": f"Bearer {token}"},
    ) as r:
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

    # Gemini API full — tidak cek Ollama lagi (hemat 4GB, 10-60s). Cek GEMINI_API_KEY ada atau coba endpoint Gemini (tanpa quota hit)
    has_gemini = bool(cfg.get("gemini_key"))
    health = {
        "n8n": check_http(cfg["n8n_url"]),
        "gemini": has_gemini,
        "wazuh_api": len(wazuh_agents) > 0,
    }

    # Severity summary untuk donut chart (dari EVENTS)
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "UNVERIFIED": 0, "INFO": 0}
    for ev in EVENTS:
        sev = ev.get("severity", "INFO")
        if sev in sev_counts:
            sev_counts[sev] += 1
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
            "events_total": len(EVENTS),
            "severity": sev_counts,
        },
        "agents": fleet,
    }


HTML = r"""<!doctype html>
<html lang="id">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Wazuh — Fleet Monitor</title>
<script>
/* Inline SVG icons (offline-proof, tanpa CDN). Path dari lucide (ISC license). */
const ICONS={
'clock':'<circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>',
'layout-dashboard':'<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>',
'monitor-smartphone':'<path d="M18 8h1a1 1 0 0 1 1 1v5a1 1 0 0 1-1 1h-1"/><path d="M4 16V4a1 1 0 0 1 1-1h10a1 1 0 0 1 1 1v12"/><path d="M2 19h10" /><path d="m5 22 3-3-3-3"/>',
'shield-alert':'<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="M12 8v4"/><path d="M12 16h.01"/>',
'activity':'<path d="M22 12h-2.48a2 2 0 0 0-1.93 1.46l-2.35 8.36a.25.25 0 0 1-.48 0L9.4 4.497a.25.25 0 0 0-.48 0l-2.35 8.36A2 2 0 0 1 4.64 12H2"/>',
'chevrons-right':'<path d="m6 17 5-5-5-5"/><path d="m13 17 5-5-5-5"/>',
'gauge':'<path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/>',
'newspaper':'<path d="M4 22h16a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2H8a2 2 0 0 0-2 2v16a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V5a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2Z"/><path d="M18 14h-8"/><path d="M15 18h-5"/><path d="M10 6h8v4h-8V6Z"/>',
'refresh-cw':'<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/>',
'users':'<path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>'
};
function ic(name,w){w=w||16;return `<svg viewBox="0 0 24 24" width="${w}" height="${w}" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex:none">${ICONS[name]||''}</svg>`}
</script>
<style>
  /* ===== Wazuh Dashboard asli (OpenSearch Dashboards light + Wazuh plugin) ===== */
  *{box-sizing:border-box}
  body{font-family:"Open Sans",Inter,system-ui,-apple-system,"Segoe UI",Roboto,Arial,sans-serif;margin:0;background:#fafbfd;color:#1a1c21;font-size:14px}
  a{color:#00a9e0;text-decoration:none} a:hover{text-decoration:underline}

  /* Top bar Wazuh: navy #011a2f, aksen biru #00a9e0 */
  .topbar{background:#011a2f;height:48px;display:flex;align-items:center;padding:0 18px;position:sticky;top:0;z-index:50}
  .topbar .logo{display:flex;align-items:center;gap:10px;color:#fff;font-size:19px;font-weight:700}
  .topbar .logo b{color:#00a9e0;font-weight:700}
  .topbar .logo .app{font-weight:400;font-size:13px;color:#8ea9c1;margin-left:2px}
  .topbar .badge100{background:#00a9e0;color:#fff;font-size:10px;letter-spacing:.08em;padding:2px 8px;border-radius:3px;font-weight:700}
  .topbar .right{margin-left:auto;display:flex;gap:16px;color:#8ea9c1;font-size:11.5px;align-items:center}
  .topbar .right .live{display:inline-flex;align-items:center;gap:5px;color:#7fd4a0}
  .topbar .right .live .pulse{width:7px;height:7px;border-radius:50%;background:#7fd4a0;animation:pl 1.5s infinite}
  @keyframes pl{0%{opacity:1}50%{opacity:.3}100%{opacity:1}}

  /* Sidebar kiri ala OpenSearch Dashboards: toggle statis, TIDAK overlay hover */
  .side{position:fixed;top:48px;left:0;bottom:0;width:64px;background:#011a2f;padding-top:12px;display:flex;flex-direction:column;gap:4px;z-index:40;transition:width .15s}
  body.x .side{width:200px}
  .side a.item{display:flex;align-items:center;gap:12px;color:#8ea9c1;padding:10px 20px;font-size:12.5px;white-space:nowrap;overflow:hidden;border-left:3px solid transparent}
  .side a.item:hover{color:#fff;background:#0d2b47}
  .side a.item.active{color:#fff;border-left-color:#00a9e0;background:#0d2b47}
  .side a.item i{width:16px;height:16px;flex:none}
  .side .lbl{opacity:0;transition:.15s}
  body.x .side .lbl{opacity:1}
  .side .tog{margin-top:auto;color:#8ea9c1;background:none;border:0;border-top:1px solid #0d2b47;padding:12px 24px;cursor:pointer;font-size:12px;display:flex;gap:12px;align-items:center;white-space:nowrap}
  .side .tog:hover{color:#fff}
  .side .tog i{width:16px;height:16px;flex:none}

  .main{margin-left:64px;padding:20px 24px 40px;transition:margin-left .15s}
  body.x .main{margin-left:200px}
  @media(max-width:900px){.side{width:64px}body.x .side{width:64px}body.x .side .lbl{opacity:0}.main{margin-left:64px}body.x .main{margin-left:64px}}
  .crumbs{font-size:12.5px;color:#69707d;margin-bottom:14px}
  .crumbs b{color:#00618a}

  h1.pv{font-size:20px;font-weight:600;margin:0 0 4px;color:#011a2f}
  .pvsub{font-size:12.5px;color:#69707d;margin-bottom:16px}

  /* KPI cards ala Wazuh overview */
  .kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-bottom:18px}
  .kpi{background:#fff;border:1px solid #d3dae6;border-radius:4px;padding:14px 16px;box-shadow:0 1px 2px rgba(0,26,47,.06)}
  .kpi .t{font-size:11px;letter-spacing:.07em;text-transform:uppercase;color:#69707d;font-weight:700}
  .kpi .v{font-size:26px;font-weight:700;color:#011a2f;margin-top:4px}
  .kpi .v.ok{color:#0b8a4b}.kpi .v.warn{color:#b26b00}.kpi .v.bad{color:#bd2719}
  .kpi .h{font-size:11px;color:#8b8f99;margin-top:3px}

  .row{display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:18px}
  @media(max-width:1100px){.row{grid-template-columns:1fr}}

  .panel{background:#fff;border:1px solid #d3dae6;border-radius:4px;box-shadow:0 1px 2px rgba(0,26,47,.06)}
  .panel .hd{padding:12px 16px;border-bottom:1px solid #d3dae6;display:flex;align-items:center;gap:8px}
  .panel .hd h2{margin:0;font-size:14px;font-weight:600;color:#011a2f;display:flex;gap:8px;align-items:center}
  .panel .hd .sub{font-size:11.5px;color:#69707d}
  .panel .bd{padding:14px 16px}

  /* Donut severity ala Wazuh (pure CSS conic-gradient) */
  .donut-wrap{display:flex;gap:18px;align-items:center;flex-wrap:wrap}
  .donut{width:150px;height:150px;border-radius:50%;position:relative;flex:none}
  .donut::after{content:attr(data-total);position:absolute;inset:26px;background:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#011a2f}
  .lg{display:flex;flex-direction:column;gap:6px;font-size:12.5px}
  .lg .li{display:flex;align-items:center;gap:8px}
  .lg .sw{width:10px;height:10px;border-radius:2px;flex:none}
  .lg .n{color:#4c525b;margin-left:auto;font-weight:600}

  /* Bar chart threat ala Wazuh */
  .bars{display:flex;flex-direction:column;gap:10px}
  .bar-row{display:grid;grid-template-columns:120px 1fr 46px;gap:10px;align-items:center;font-size:12.5px}
  .bar-track{background:#eef1f6;border-radius:3px;height:16px;overflow:hidden}
  .bar-fill{height:100%;border-radius:3px;transition:width .4s}

  table{width:100%;border-collapse:collapse;font-size:13px}
  th{background:#f5f7fa;color:#565d66;text-align:left;padding:9px 12px;border-bottom:1px solid #d3dae6;font-size:11px;letter-spacing:.05em;text-transform:uppercase;font-weight:700;white-space:nowrap}
  td{padding:9px 12px;border-bottom:1px solid #edf0f4;color:#26292e}
  tbody tr:hover td{background:#f2f9ff}
  .tbl-scroll{max-height:560px;overflow:auto}

  .chip{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:11px;font-size:11.5px;font-weight:600;border:1px solid}
  .c-ok{background:#e6f4ea;color:#0b8a4b;border-color:#b7e1c5}
  .c-no{background:#fce8e6;color:#a50e0e;border-color:#f5c6c2}
  .c-rust{background:#e8f0fe;color:#1a5dc8;border-color:#c2d6ff}
  .c-wz{background:#f1f3f4;color:#3c4043;border-color:#dadce0}
  .c-crit{background:#fce8e6;color:#a50e0e;border-color:#f5c6c2}
  .c-high{background:#fef3e2;color:#a65c00;border-color:#f8d9a8}
  .c-med{background:#fdf4d0;color:#8a6d00;border-color:#eee3a3}
  .c-unv{background:#ede7fe;color:#5b21b6;border-color:#d8ccf7}
  .c-info{background:#e8f0fe;color:#1a5dc8;border-color:#c2d6ff}

  .mono{font-family:ui-monospace,"Cascadia Code",Menlo,monospace;font-size:11.5px}
  .muted{color:#69707d}

  /* News feed ala Wazuh dashboard */
  .feed{display:flex;flex-direction:column;gap:0}
  .feed .fi{display:grid;grid-template-columns:64px 1fr auto;gap:10px;padding:10px 4px;border-bottom:1px solid #edf0f4;font-size:12.5px;align-items:start}
  .feed .fi:last-child{border-bottom:0}
  .feed .tm{color:#69707d;font-size:11px;white-space:nowrap}
  .feed .msg{color:#26292e}
  .feed .msg .f{color:#0b6b9e;font-weight:600}

  .btn{appearance:none;border:1px solid transparent;background:#00a9e0;color:#fff;padding:7px 13px;border-radius:4px;font-size:12.5px;font-weight:600;cursor:pointer;display:inline-flex;gap:7px;align-items:center}
  .btn:hover{background:#0294cb}
  .btn.sec{background:#fff;color:#00618a;border-color:#00a9e0}
  .btn.sec:hover{background:#e6f7ff}
  .toolbar{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:14px}
  .toolbar .sp{flex:1}

  /* Views */
  .view{display:none}
  .view.on{display:block}

  .legend-foot{font-size:11px;color:#8b8f99;margin-top:10px;border-top:1px solid #edf0f4;padding-top:8px}
</style>
</head>
<body>

<div class="topbar">
  <div class="logo"><span>wazuh<b>.</b></span><span class="app">Fleet Monitor</span></div>
  <span class="badge100">100 WORKSTATION</span>
  <div class="right">
    <span class="live"><span class="pulse"></span> live</span>
    <span><i data-lucide="clock" style="width:12px;height:12px;vertical-align:-2px"></i> <span id="generated">-</span></span>
    <span>refresh <span id="countdown">5</span>s</span>
  </div>
</div>

<nav class="side">
  <a class="item active" data-view="overview" href="#overview"><i data-lucide="layout-dashboard"></i><span class="lbl">Overview</span></a>
  <a class="item" data-view="agents" href="#agents"><i data-lucide="monitor-smartphone"></i><span class="lbl">Agents</span></a>
  <a class="item" data-view="threat" href="#threat"><i data-lucide="shield-alert"></i><span class="lbl">Threat Events</span></a>
  <a class="item" data-view="health" href="#health"><i data-lucide="activity"></i><span class="lbl">Health</span></a>
  <button class="tog" onclick="document.body.classList.toggle('x')" title="Buka/tutup menu"><i data-lucide="chevrons-right" id="togi"></i><span class="lbl">Buka menu</span></button>
</nav>

<div class="main">
  <div class="crumbs">Server management / <b id="crumb">Overview</b></div>

  <!-- ================= OVERVIEW ================= -->
  <section class="view on" id="v-overview">
    <h1 class="pv">Overview</h1>
    <div class="pvsub">Ringkasan fleet 100 workstation: agen ringan Rust hash-only ke n8n (otak), arahan dospem.</div>
    <div class="kpis" id="kpis"></div>

    <div class="row">
      <div class="panel">
        <div class="hd"><h2><i data-lucide="shield-alert" style="color:#00a9e0"></i> Threat severity</h2><span class="sub">dari event feed</span></div>
        <div class="bd">
          <div class="donut-wrap">
            <div class="donut" id="donut" data-total="0"></div>
            <div class="lg" id="lg"></div>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="hd"><h2><i data-lucide="gauge" style="color:#00a9e0"></i> Efisiensi agen</h2><span class="sub">Rust vs Wazuh</span></div>
        <div class="bd">
          <div class="bars" id="eff"></div>
          <div class="legend-foot">Wazuh Agent ~50 MB RAM + enroll 1514/1515 · soar-agent 5.3 MB binary, RSS 5.2 MB, hash-only 1-2 KB/event, scp + systemd tanpa enroll.</div>
        </div>
      </div>
    </div>

    <div class="panel">
      <div class="hd"><h2><i data-lucide="newspaper" style="color:#00a9e0"></i> Latest events</h2><span class="sub">news feed</span>
        <span style="margin-left:auto" class="sub">lihat semua di tab Threat Events</span></div>
      <div class="bd"><div class="feed" id="feed5"></div></div>
    </div>
  </section>

  <!-- ================= AGENTS ================= -->
  <section class="view" id="v-agents">
    <h1 class="pv">Agents</h1>
    <div class="pvsub">Polling Wazuh API 30s + heartbeat Rust 60s. Badge biru = agen ringan Rust, abu = Wazuh.</div>
    <div class="toolbar">
      <input id="q" placeholder="Cari nama / IP / ID..." oninput="renderAgents()" style="padding:7px 10px;border:1px solid #d3dae6;border-radius:4px;font-size:12.5px;width:220px">
      <button class="btn sec" onclick="load()"><i data-lucide="refresh-cw" style="width:12px;height:12px"></i> Refresh</button>
      <button class="btn" onclick="simulate()"><i data-lucide="users" style="width:12px;height:12px"></i> Simulasi 100 PC</button>
      <span class="sub muted" style="font-size:11.5px">POST /api/heartbeat untuk real agent</span>
    </div>
    <div class="panel">
      <div class="tbl-scroll">
      <table>
        <thead><tr><th>ID</th><th>Nama</th><th>Tipe</th><th>Status</th><th>IP</th><th>Versi</th><th>Last keep alive</th><th>Binary</th><th>RAM</th></tr></thead>
        <tbody id="tbody"></tbody>
      </table>
      </div>
    </div>
  </section>

  <!-- ================= THREAT EVENTS ================= -->
  <section class="view" id="v-threat">
    <h1 class="pv">Threat Events</h1>
    <div class="pvsub">Feed event file (hash) dari agen + pipeline n8n: VT ensemble + Gemini 2.5 + HITL Telegram.</div>
    <div class="toolbar">
      <select id="sevf" onchange="renderEvents()" style="padding:7px 10px;border:1px solid #d3dae6;border-radius:4px;font-size:12.5px">
        <option value="">Semua severity</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>UNVERIFIED</option><option>INFO</option>
      </select>
      <span class="sp"></span>
      <span class="muted" style="font-size:11.5px" id="evcount"></span>
    </div>
    <div class="panel">
      <div class="tbl-scroll">
      <table>
        <thead><tr><th>Waktu</th><th>Agent</th><th>File</th><th>Hash</th><th>Severity</th><th>Status</th></tr></thead>
        <tbody id="evbody"></tbody>
      </table>
      </div>
    </div>
  </section>

  <!-- ================= HEALTH ================= -->
  <section class="view" id="v-health">
    <h1 class="pv">Health</h1>
    <div class="pvsub">Self-aware monitoring (kategori F): n8n otak, Gemini API, Wazuh API.</div>
    <div class="kpis" id="hkpis"></div>
    <div class="panel">
      <div class="bd" style="display:flex;gap:22px;flex-wrap:wrap;font-size:13px" id="hlist"></div>
    </div>
  </section>
</div>

<script>
let DATA=null, timer=5;

const SEV_META={CRITICAL:['#bd2719','c-crit'],HIGH:['#d97706','c-high'],MEDIUM:['#eab308','c-med'],UNVERIFIED:['#7c3aed','c-unv'],INFO:['#00a9e0','c-info']};

async function load(){
  try{
    const [f,e]=await Promise.all([fetch('/api/fleet').then(r=>r.json()),fetch('/api/events').then(r=>r.json())]);
    DATA={...f,events:(e.events||[])};
    document.getElementById('generated').textContent=new Date(f.generated_at).toLocaleTimeString('id-ID');
    renderOverview();renderAgents();renderEvents();renderHealth();
    renderIcons();
  }catch(err){console.error(err)}
  timer=5;
}

function esc(s){return String(s??'').replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}

function renderIcons(){
  document.querySelectorAll('i[data-lucide]').forEach(el=>{
    const name=el.getAttribute('data-lucide');
    const w=parseInt(el.style.width)||16;
    const span=document.createElement('span');
    span.style.display='inline-flex';span.style.verticalAlign=el.style.verticalAlign||'middle';
    span.innerHTML=ic(name,w);
    el.replaceWith(span);
  });
}

function renderOverview(){
  const s=DATA.stats,h=DATA.health;
  document.getElementById('kpis').innerHTML=`
    <div class="kpi"><div class="t">Total agents</div><div class="v">${s.total}</div><div class="h">${s.rust} Rust ringan + ${s.wazuh} Wazuh</div></div>
    <div class="kpi"><div class="t">Active</div><div class="v ok">${s.active}</div><div class="h">${s.disconnected} disconnected</div></div>
    <div class="kpi"><div class="t">Events</div><div class="v">${s.events_total}</div><div class="h">file hash terdeteksi</div></div>
    <div class="kpi"><div class="t">Efisiensi</div><div class="v">90%</div><div class="h">5.3 MB vs 50 MB per agen</div></div>`;

  // Donut severity
  const sev=DATA.stats.severity||{};const keys=Object.keys(sev);
  let acc=0;const total=keys.reduce((a,k)=>a+sev[k],0);
  const parts=keys.map(k=>{const c=SEV_META[k][0];const v=sev[k];const st=acc;acc+=v;return `${c} ${st/total*360}deg ${(st+v)/total*360}deg`}).filter((x,i)=>sev[keys[i]]>0);
  const donut=document.getElementById('donut');
  donut.style.background=total>0?`conic-gradient(${parts.join(',')})`:'#eef1f6';
  donut.dataset.total=total;
  document.getElementById('lg').innerHTML=keys.map(k=>`<div class="li"><span class="sw" style="background:${SEV_META[k][0]}"></span>${k}<span class="n">${sev[k]}</span></div>`).join('');

  // Efisiensi bars
  document.getElementById('eff').innerHTML=`
    <div class="bar-row"><span>Wazuh Agent</span><div class="bar-track"><div class="bar-fill" style="width:100%;background:#bd2719"></div></div><span>50 MB</span></div>
    <div class="bar-row"><span>soar-agent</span><div class="bar-track"><div class="bar-fill" style="width:10.6%;background:#0b8a4b"></div></div><span>5.3 MB</span></div>
    <div class="bar-row"><span>RSS Rust</span><div class="bar-track"><div class="bar-fill" style="width:10.4%;background:#00a9e0"></div></div><span>5.2 MB</span></div>`;

  // Feed 5 terakhir
  const ev=DATA.events.slice(0,5);
  document.getElementById('feed5').innerHTML=ev.length?ev.map(e=>{
    const sm=SEV_META[e.severity||'INFO']||SEV_META.INFO;
    return `<div class="fi"><span class="tm">${new Date(e.ts).toLocaleTimeString('id-ID')}</span>
      <span class="msg"><span class="f">${esc(e.agent)}</span> · ${esc((e.path||'').split('/').pop()||'-')} <span class="mono muted">${esc((e.hash||'').slice(0,12))}...</span></span>
      <span class="chip ${sm[1]}">${esc(e.severity||'INFO')}</span></div>`}).join('')
    :'<div class="fi muted">Belum ada event. Drop file di ~/Downloads agen, atau lihat simulasi tombol Agents.</div>';
}

function renderAgents(){
  const q=(document.getElementById('q').value||'').toLowerCase();
  const tb=document.getElementById('tbody');
  const rows=DATA.agents.filter(a=>!q||[a.id,a.name,a.ip].join(' ').toLowerCase().includes(q));
  tb.innerHTML=rows.length?rows.map(a=>`<tr>
    <td class="mono">${esc(a.id)}</td><td>${esc(a.name)}</td>
    <td><span class="chip ${a.type==='rust'?'c-rust':'c-wz'}">${esc(a.type)}</span></td>
    <td><span class="chip ${a.status==='active'?'c-ok':'c-no'}">${esc(a.status)}</span></td>
    <td class="mono">${esc(a.ip)}</td><td class="mono">${esc(a.version)}</td>
    <td class="mono muted">${esc((a.lastKeepAlive||'-').slice(0,19))}</td>
    <td class="mono">${esc(a.binary)}</td><td class="mono">${esc(a.ram)}</td></tr>`).join('')
  :'<tr><td colspan="9" class="muted" style="text-align:center;padding:24px">tidak ada agent cocok</td></tr>';
}

function renderEvents(){
  const f=document.getElementById('sevf').value;
  const ev=DATA.events.filter(e=>!f||(e.severity||'INFO')===f);
  document.getElementById('evcount').textContent=`${ev.length} event terfilter dari ${DATA.events.length}`;
  document.getElementById('evbody').innerHTML=ev.length?ev.map(e=>{
    const sm=SEV_META[e.severity||'INFO']||SEV_META.INFO;
    return `<tr><td class="mono muted">${new Date(e.ts).toLocaleString('id-ID')}</td>
      <td>${esc(e.agent)}</td><td class="mono" title="${esc(e.path)}">${esc((e.path||'-').split('/').pop())}</td>
      <td class="mono muted" title="${esc(e.hash)}">${esc((e.hash||'-').slice(0,16))}...</td>
      <td><span class="chip ${sm[1]}">${esc(e.severity||'INFO')}</span></td>
      <td class="mono">${esc(e.status)}</td></tr>`}).join('')
  :'<tr><td colspan="6" class="muted" style="text-align:center;padding:24px">belum ada event — drop EICAR di ~/Downloads</td></tr>';
}

function renderHealth(){
  const h=DATA.health;
  document.getElementById('hkpis').innerHTML=`
    <div class="kpi"><div class="t">n8n (otak)</div><div class="v ${h.n8n?'ok':'bad'}">${h.n8n?'UP':'DOWN'}</div><div class="h">webhook wazuh-alert</div></div>
    <div class="kpi"><div class="t">Gemini 2.5</div><div class="v ${h.gemini?'ok':'warn'}">${h.gemini?'KEY OK':'NO KEY'}</div><div class="h">API analisis AI</div></div>
    <div class="kpi"><div class="t">Wazuh API</div><div class="v ${h.wazuh_api?'ok':'bad'}">${h.wazuh_api?'UP':'DOWN'}</div><div class="h">baseline agent 001/002</div></div>`;
  document.getElementById('hlist').innerHTML=`
    <span><span class="chip ${h.n8n?'c-ok':'c-no'}">n8n ${h.n8n?'OK':'DOWN'}</span></span>
    <span><span class="chip ${h.gemini?'c-ok':'c-no'}">Gemini ${h.gemini?'OK':'no key'}</span></span>
    <span><span class="chip ${h.wazuh_api?'c-ok':'c-no'}">Wazuh API ${h.wazuh_api?'OK':'DOWN'}</span></span>
    <span class="muted">Fleet bind 0.0.0.0:8080 · Tailscale 100.95.198.108:8080 untuk 100 PC · desain plek Wazuh Dashboard</span>`;
}

async function simulate(){
  for(let i=4;i<=100;i++){const id=String(i).padStart(3,'0');
    await fetch('/api/heartbeat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id,name:`rust-agent-lab-${id}`,ip:`192.168.18.${100+i}`,version:'0.1.0'})});}
  load();
}

// Sidebar nav multi-view
document.querySelectorAll('.side .item').forEach(a=>a.addEventListener('click',ev=>{
  ev.preventDefault();
  document.querySelectorAll('.side .item').forEach(x=>x.classList.remove('active'));
  a.classList.add('active');
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('on'));
  document.getElementById('v-'+a.dataset.view).classList.add('on');
  document.getElementById('crumb').textContent=a.querySelector('.lbl').textContent;
  location.hash=a.dataset.view;
}));
const hash=location.hash.slice(1);
if(['overview','agents','threat','health'].includes(hash)){document.querySelector(`.side .item[data-view="${hash}"]`).click();}

renderIcons(); // render statis saat DOM ready
setInterval(()=>{document.getElementById('countdown').textContent=--timer;if(timer<=0)load()},1000);
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
        elif parsed.path == "/api/events":
            body = json.dumps({"events": list(reversed(EVENTS))}).encode()
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
                # Event file dari agent (kalau dikirim bersama heartbeat)
                if j.get("last_hash") and j.get("last_path"):
                    EVENTS.append(
                        {
                            "ts": datetime.now(WITA).isoformat(),
                            "agent": j.get("name", hid),
                            "agent_id": hid,
                            "path": j.get("last_path", ""),
                            "hash": j.get("last_hash", ""),
                            "status": j.get("last_status", "sent"),
                        }
                    )
                    del EVENTS[:-EVENTS_MAX]
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
        elif parsed.path == "/webhook-log":
            # n8n / agent lain bisa POST alert log ke sini -> tampil di dashboard News feed
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length) if length else b"{}"
            try:
                j = json.loads(body)
                ev = {
                    "ts": j.get("ts") or datetime.now(WITA).isoformat(),
                    "agent": j.get("agent", "-"),
                    "agent_id": j.get("agent_id", "-"),
                    "path": j.get("path", "-"),
                    "hash": j.get("hash", ""),
                    "severity": j.get("severity", "INFO"),
                    "status": j.get("status", "alerted"),
                    "ai": j.get("ai", ""),
                }
                EVENTS.append(ev)
                del EVENTS[:-EVENTS_MAX]
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            except Exception as e:
                self.send_response(400)
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
