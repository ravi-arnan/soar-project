#!/usr/bin/env python3
"""Fleet Monitor 100 PC — custom monitoring untuk arahan dospem (custom Go/Rust, bukan Wazuh Dashboard berat).

Poll Wazuh API untuk agent Wazuh (001,002) + terima heartbeat dari soar-agent Rust (003..N)
via POST /api/heartbeat. Serve HTML dashboard single-pane untuk 100 workstation.

Endpoints:
  GET  /              -> HTML dashboard (auto-refresh 5s, Lucide icons, no emoji)
  GET  /api/fleet     -> JSON fleet status
  GET  /api/events/history?since=&until=&source=all -> riwayat event (SQLite + Wazuh Indexer)
  POST /api/heartbeat -> {"id":"003","name":"rust-agent-ravi","ip":"100.95.198.108","version":"0.1.0"} -> 200
  GET  /healthz       -> 200 ok (untuk docker healthcheck)

Tanpa deps tambahan (stdlib only). Jalankan: python3 scripts/fleet-monitor.py
Docker: python:3.12-alpine + mount scripts/fleet-monitor.py + env .env

ponytail: sengaja tidak pakai FastAPI/Flask — satu file, 3 tugas (poll Wazuh, terima heartbeat, serve HTML).
Upgrade path: ganti http.server dengan FastAPI + Prometheus kalau butuh Grafana (ROADMAP.md:92 E).
"""

import base64
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from contextlib import closing
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer, ThreadingHTTPServer
from pathlib import PurePosixPath, PureWindowsPath
from urllib.parse import parse_qs, urlparse

_SCRIPTS_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from fleet import installers as _fleet_installers  # noqa: E402
from fleet import locks as _fleet_locks  # noqa: E402
from fleet import security as _fleet_sec  # noqa: E402
from fleet import soc_ops as _fleet_soc  # noqa: E402

AI_CIRCUIT_BREAKER = _fleet_sec.AiCircuitBreaker()
_STATE_LAST_SAVE = 0.0
_STATE_SAVE_MIN_INTERVAL = 5.0
_API_KEY_LAST_TOUCH = {}
_LOGIN_ATTEMPTS = {}
_LOGIN_LOCK = threading.Lock()
_CF_SYNC_THREAD = None


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

FLEET_COMMAND_TOKEN = os.environ.get("FLEET_COMMAND_TOKEN", "").strip()
try:
    FLEET_AGENT_POLL_TOKENS = json.loads(
        os.environ.get("FLEET_AGENT_POLL_TOKENS_JSON", "{}")
    )
except json.JSONDecodeError:
    FLEET_AGENT_POLL_TOKENS = {}
MIN_RUNTIME_SECRET_LENGTH = 32
COMMAND_BODY_MAX = 8 * 1024
COMMAND_AGENT_MAX = 64
COMMAND_TARGET_MAX = 4096
COMMANDS_MAX_AGENTS = 1000

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

# Riwayat event durable (SQLite) untuk view "minggu/bulan/custom" dashboard.
# Ring EVENTS di atas hanya 200 & hilang saat restart; event pipeline SOAR
# (dari /webhook-log + heartbeat) disimpan ke SQLite supaya bisa dikueri per
# rentang waktu. ponytail: sqlite3 stdlib, satu file; tanpa ORM.
EVENTS_DB = os.environ.get(
    "FLEET_EVENTS_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fleet-events.db"),
)
EVENTS_RETENTION_DAYS = int(os.environ.get("FLEET_EVENTS_RETENTION_DAYS", "90") or 90)
EVENTS_MAX_ROWS = int(os.environ.get("FLEET_EVENTS_MAX_ROWS", "200000") or 200000)
EVENTS_PRUNE_EVERY = 100  # prune tiap N insert (hindari thread terpisah)
_events_insert_count = 0
_EVENT_STATS_CACHE = {
    "ts": 0,
    "total": 0,
    "all_time": 0,
    "severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "UNVERIFIED": 0, "INFO": 0},
}
_EVENT_STATS_TTL = 10  # detik (hindari SQLite scan tiap 5s poll)

# Wazuh Indexer (OpenSearch) untuk riwayat penuh alert Wazuh historis (semua
# rule, bukan cuma yang lewat pipeline). Kosong = source indexer nonaktif
# (endpoint tetap jalan, hanya SQLite). fleet-monitor host-net -> 127.0.0.1:9200.
INDEXER_URL = os.environ.get("WAZUH_INDEXER_URL", "https://127.0.0.1:9200").rstrip("/")
INDEXER_USER = os.environ.get("WAZUH_INDEXER_USER", "admin")
INDEXER_PASS = os.environ.get("WAZUH_INDEXER_PASS", "").strip()
INDEXER_INDEX = os.environ.get("WAZUH_INDEXER_INDEX", "wazuh-alerts-*")
INDEXER_SEARCH_MAX = 1000
HISTORY_DEFAULT_LIMIT = 100
HISTORY_MAX_LIMIT = 10000

# Command queue per agent (aksi dari dashboard, di-poll agent via GET):
# id -> [{action: quarantine|sinkhole|scan, target, ts, by}]
# ponytail: tanpa DB/antrean persisten; perintah hilang saat fleet-monitor
# restart. Upgrade path: persist ke sqlite/redis kalau butuh durability.
COMMANDS = {}
COMMANDS_MAX = 20

# History metrics per agent untuk grafik (ring buffer, 60 titik @60s = 1 jam).
# ponytail: in-memory saja; hilang saat restart. Upgrade: TSDB kalau perlu.
METRICS = {}
METRICS_MAX = 60

# Claim-check dedup untuk n8n lapis-2 (node Dedup Alert): key -> ts pertama
# terlihat. Single-threaded HTTPServer jadi check-and-set atomik alami.
# ponytail: in-memory saja (restart = lupa, wajar untuk window menit);
# entri tua dibersihkan tiap hit. Upgrade: redis SETNX kalau multi-replika.
SEEN = {}

# Scan on-demand: agent walk folder pilihan -> hash -> POST /api/scan-result.
# Laporan RINGKASAN per agent (bukan alert per-file) supaya Telegram & dedup
# n8n tidak kebanjiran. id -> {path, scanned, new_hashes, known_hashes, files[]}.
SCAN_RESULTS = {}
SCAN_HISTORY = []
SCAN_HISTORY_MAX = 50
SCAN_FILES_MAX = 2000
# Cache-first: memori hash yang sudah pernah terlihat (event/scan) -> hitung
# "baru" vs "sudah dikenal" tanpa re-analisis. In-memory; restart = lupa
# (pola SEEN/METRICS). Upgrade: persist/sqlite kalau butuh lintas-restart.
KNOWN_HASHES = {}
KNOWN_HASHES_MAX = 200000

# Cache verdict VirusTotal (dipakai node n8n "Cek Cache VT" lewat
# POST /api/vt-cache/lookup). Alasan: kuota VT free 4 req/menit, sedangkan burst
# 100 PC dengan hash SAMA = 100 panggilan VT kalau tiap alert memanggil sendiri
# (dedup /api/seen ber-key per-agent, jadi tidak menolong untuk kasus ini).
# Key = hash (bukan per-agent) -> hash sama cukup 1 panggilan VT.
# TTL diferensial (ROADMAP B): verdict berubah seiring waktu -> yang bersih /
# tidak-dikenal kadaluwarsa lebih cepat daripada yang confirmed malicious.
# ponytail: dict + file JSON (pola STATE_FILE), bukan redis; dipersist karena
# restart container (deploy) tidak perlu membuang cache yang masih berlaku.
VT_CACHE = {}
VT_CACHE_MAX = 20000
VT_TTL_MALICIOUS = 7 * 86400
VT_TTL_CLEAN = 86400
VT_TTL_UNKNOWN = 6 * 3600
VT_SAVE_MIN_INTERVAL = 30  # detik; hindari menulis 20k entri tiap store
VT_CACHE_STATS = {"lookups": 0, "hits": 0, "misses": 0, "stores": 0}
_vt_last_save = 0.0

# Cache Wazuh agents
WAZUH_CACHE = {"data": [], "fetched_at": 0}
WAZUH_TTL = 30

# Roster heartbeat di-persist ke disk: tanpa ini, restart fleet-monitor
# menghapus agent yang sedang OFFLINE dari daftar (padahal cuma disconnect,
# mesinnya mati sementara) -> "list agent berkurang" tiap habis restart.
# ponytail: JSON sederhana (bukan DB); cukup untuk roster <= ratusan agent.
STATE_FILE = os.environ.get(
    "FLEET_STATE_FILE",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), ".fleet-state.json"),
)
STATE_MAX_AGE = 30 * 86400  # buang entri lebih tua dari 30 hari

# File cache VT mengikuti direktori state (volume ./state di compose), jadi
# ikut persisten tanpa volume baru.
VT_CACHE_FILE = os.environ.get(
    "FLEET_VT_CACHE_FILE",
    os.path.join(os.path.dirname(STATE_FILE), ".fleet-vt-cache.json"),
)
CONTAINER_STATS_FILE = os.environ.get(
    "FLEET_CONTAINER_STATS_FILE",
    os.path.join(os.path.dirname(STATE_FILE) or ".", "container-stats.json"),
)
CONTAINER_STATS_MAX_AGE_SECS = int(os.environ.get("FLEET_CONTAINER_STATS_MAX_AGE_SECS", "180"))
CONTAINER_STATS_MAX_BYTES = 64 * 1024


def _read_container_stats():
    """Baca snapshot konsumsi memori container Docker yang ditulis collector host."""
    try:
        with open(CONTAINER_STATS_FILE, encoding="utf-8") as f:
            raw = f.read(CONTAINER_STATS_MAX_BYTES + 1)
    except FileNotFoundError:
        return None
    except OSError:
        return None
    if len(raw) > CONTAINER_STATS_MAX_BYTES:
        return None
    try:
        data = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    updated_raw = str(data.get("updated_at") or "").strip()
    if not updated_raw:
        return None
    try:
        ts_str = updated_raw[:-1] + "+00:00" if updated_raw.endswith("Z") else updated_raw
        updated_dt = datetime.fromisoformat(ts_str)
        if updated_dt.tzinfo is None:
            updated_dt = updated_dt.replace(tzinfo=timezone.utc)
        age = (datetime.now(timezone.utc) - updated_dt).total_seconds()
    except ValueError:
        return None
    if age > CONTAINER_STATS_MAX_AGE_SECS or age < -60:
        return None

    raw_containers = data.get("containers")
    if not isinstance(raw_containers, dict):
        return None
    containers = {}
    for name, item in list(raw_containers.items())[:64]:
        if not isinstance(name, str) or not isinstance(item, dict):
            continue
        clean_name = name.strip()[:128]
        if not clean_name:
            continue
        try:
            used_mb = round(float(item.get("mem_used_mb", 0) or 0), 1)
            limit_mb = round(float(item.get("mem_limit_mb", 0) or 0), 1)
            mem_pct = round(float(item.get("mem_pct", 0) or 0), 1)
            cpu_pct = round(float(item.get("cpu_pct", 0) or 0), 1)
        except (TypeError, ValueError):
            continue
        if used_mb < 0 or limit_mb < 0 or mem_pct < 0:
            continue
        containers[clean_name] = {
            "mem_used_mb": used_mb,
            "mem_limit_mb": limit_mb,
            "mem_pct": mem_pct,
            "cpu_pct": cpu_pct,
        }
    return {"updated_at": updated_raw, "containers": containers}


def _load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return
    except Exception as e:
        print(f"state file rusak, abaikan: {e}", flush=True)
        return
    cutoff = time.time() - STATE_MAX_AGE
    hbs = data.get("heartbeats", {})
    if isinstance(hbs, dict):
        with _fleet_locks.STATE_LOCK:
            for k, v in hbs.items():
                if isinstance(v, dict) and v.get("last_seen", 0) >= cutoff:
                    HEARTBEATS[str(k)] = v
    print(f"state dimuat: {len(HEARTBEATS)} heartbeat dari {STATE_FILE}", flush=True)


def _secret_is_valid(value):
    return len(value) >= MIN_RUNTIME_SECRET_LENGTH and not value.lower().startswith(
        ("your-", "isi-dengan", "replace-", "generate-")
    )


def _validate_runtime_secrets():
    missing = []
    if not _secret_is_valid(FLEET_COMMAND_TOKEN):
        missing.append("FLEET_COMMAND_TOKEN")
    if not isinstance(FLEET_AGENT_POLL_TOKENS, dict) or not FLEET_AGENT_POLL_TOKENS:
        missing.append("FLEET_AGENT_POLL_TOKENS_JSON")
    else:
        seen_tokens = set()
        for agent_id, token in FLEET_AGENT_POLL_TOKENS.items():
            if (
                not _valid_agent_id(str(agent_id))
                or not isinstance(token, str)
                or not _secret_is_valid(token)
            ):
                missing.append(f"token agent {agent_id}")
            if str(token) in seen_tokens:
                missing.append(f"token agent duplikat {agent_id}")
            seen_tokens.add(str(token))
            if _secret_is_valid(FLEET_COMMAND_TOKEN) and hmac.compare_digest(
                FLEET_COMMAND_TOKEN, str(token)
            ):
                missing.append(f"token agent {agent_id} sama dengan command token")
    if missing:
        raise RuntimeError("runtime secret belum valid: " + ", ".join(missing))


def _bearer_matches(headers, expected):
    if not _secret_is_valid(expected):
        return False
    value = headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return False
    try:
        return hmac.compare_digest(value[7:].strip(), expected)
    except (TypeError, UnicodeEncodeError):
        return False


def _valid_agent_id(value):
    return bool(re.fullmatch(rf"[A-Za-z0-9._-]{{1,{COMMAND_AGENT_MAX}}}", value))


def _valid_path_target(value):
    if not value or len(value) > COMMAND_TARGET_MAX:
        return False
    if any(ord(char) < 32 for char in value):
        return False
    if value.startswith(("//", "\\\\")):
        return False
    posix = PurePosixPath(value.replace("\\", "/"))
    windows = PureWindowsPath(value)
    if ".." in posix.parts or ".." in windows.parts:
        return False
    if not (value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value)):
        return False
    driveless = value[2:] if re.match(r"^[A-Za-z]:", value) else value
    return ":" not in driveless


def _valid_domain_target(value):
    domain = value.rstrip(".").lower()
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    labels = domain.split(".")
    return all(
        re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
    )


def _read_command_body(handler):
    try:
        length = int(handler.headers.get("Content-Length", "0"))
    except ValueError as exc:
        raise ValueError("Content-Length tidak valid") from exc
    if length < 0:
        raise ValueError("Content-Length tidak valid")
    if length > COMMAND_BODY_MAX:
        raise OverflowError("body command terlalu besar")
    raw = handler.rfile.read(length) if length else b"{}"
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise TypeError("body command harus object")
    return value


def _validate_command(value):
    agent_id = str(value.get("agent_id", "")).strip()
    action = str(value.get("action", "")).strip()
    target = str(value.get("target", "")).strip()
    actor = str(value.get("by", "dashboard")).strip() or "dashboard"
    if not _valid_agent_id(agent_id):
        raise ValueError("agent_id tidak valid")
    if action in ("quarantine", "scan", "restore"):
        if not _valid_path_target(target):
            raise ValueError(f"target {action} harus path absolut tanpa traversal")
        if action == "quarantine" and _fleet_sec.is_protected_path(target):
            raise ValueError("target quarantine tidak boleh menyentuh path sistem/agen")
    elif action in ("sinkhole", "unsinkhole"):
        if not _valid_domain_target(target):
            raise ValueError(f"target {action} harus domain valid")
        if action == "sinkhole" and _fleet_sec.is_protected_domain(target):
            raise ValueError("target sinkhole tidak boleh memblokir domain kritis/infrastruktur")
    else:
        raise ValueError("action harus quarantine|sinkhole|unsinkhole|scan|restore")
    if len(actor) > 64 or any(ord(char) < 32 for char in actor):
        raise ValueError("by tidak valid")
    return {"agent_id": agent_id, "action": action, "target": target, "by": actor}


def _save_state(force=False):
    global _STATE_LAST_SAVE
    now = time.time()
    with _fleet_locks.STATE_LOCK:
        if not force and (now - _STATE_LAST_SAVE < _STATE_SAVE_MIN_INTERVAL):
            return
        _STATE_LAST_SAVE = now
        snapshot = {"heartbeats": dict(HEARTBEATS)}
    try:
        _fleet_locks.atomic_write_json(STATE_FILE, snapshot)
    except Exception as e:
        print(f"gagal simpan state: {e}", flush=True)


def _is_hex_hash(h):
    """Hash VT yang sah: md5/sha1/sha256 (hex 32/40/64). Selain itu ditolak."""
    return len(h) in (32, 40, 64) and all(c in "0123456789abcdef" for c in h)


def _vt_ttl_secs(malicious, known):
    """TTL diferensial: bersih/tidak-dikenal lebih cepat kadaluwarsa (verdict
    berubah seiring waktu), confirmed malicious boleh lama."""
    if malicious >= 1:
        return VT_TTL_MALICIOUS
    return VT_TTL_CLEAN if known else VT_TTL_UNKNOWN


def _vt_cache_load():
    try:
        with open(VT_CACHE_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return
    except Exception as e:
        print(f"vt-cache rusak, abaikan: {e}", flush=True)
        return
    now = time.time()
    entries = data.get("entries", {})
    if isinstance(entries, dict):
        with _fleet_locks.VT_CACHE_LOCK:
            for h, v in entries.items():
                if isinstance(v, dict) and now - v.get("stored_at", 0) < v.get("ttl", 0):
                    VT_CACHE[str(h)] = v
    print(
        f"vt-cache dimuat: {len(VT_CACHE)} entri dari {VT_CACHE_FILE}",
        flush=True,
    )


def _vt_cache_save():
    """Persist cache (di-throttle) secara atomic dan thread-safe."""
    global _vt_last_save
    now = time.time()
    with _fleet_locks.VT_CACHE_LOCK:
        if now - _vt_last_save < VT_SAVE_MIN_INTERVAL:
            return
        _vt_last_save = now
        snapshot = {"entries": dict(VT_CACHE)}
    try:
        _fleet_locks.atomic_write_json(VT_CACHE_FILE, snapshot)
    except Exception as e:
        print(f"gagal simpan vt-cache: {e}", flush=True)


def _vt_cache_prune(now):
    with _fleet_locks.VT_CACHE_LOCK:
        for h in [
            h for h, v in list(VT_CACHE.items()) if now - v.get("stored_at", 0) >= v.get("ttl", 0)
        ]:
            VT_CACHE.pop(h, None)
        if len(VT_CACHE) > VT_CACHE_MAX:
            oldest = sorted(VT_CACHE.items(), key=lambda kv: kv[1].get("stored_at", 0))
            for h, _ in oldest[: len(VT_CACHE) - VT_CACHE_MAX]:
                VT_CACHE.pop(h, None)


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


_HEALTH_CACHE = {}
_HEALTH_CACHE_TTL = 15  # detik (hindari blocking HTTP connection tiap poll dashboard)


def check_http(url, timeout=3):
    now = time.time()
    cached = _HEALTH_CACHE.get(url)
    if cached and now - cached["ts"] < _HEALTH_CACHE_TTL:
        return cached["ok"]
    try:
        with _get(url, timeout=timeout) as r:
            ok = 200 <= r.status < 300
    except Exception:
        ok = False
    _HEALTH_CACHE[url] = {"ok": ok, "ts": now}
    return ok


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
        f"{base_url}/agents?select=id,name,status,ip,version,dateAdd,lastKeepAlive,os.name,os.version,os.platform&limit=500",
        headers={"Authorization": f"Bearer {token}"},
    ) as r:
        return json.load(r)["data"]["affected_items"]


def _short_os(a):
    """Ringkas objek os Wazuh API jadi 'windows 10 ...' / 'linux ...'."""
    osv = a.get("os") or {}
    if isinstance(osv, dict):
        plat = osv.get("platform", "") or ""
        name = osv.get("name", "") or ""
        ver = osv.get("version", "") or ""
        s = " ".join(x for x in (plat, name, ver) if x).strip()
        return s or "unknown"
    return str(osv) if osv else "unknown"


def fetch_wazuh_agents(cfg):
    now = time.time()
    with _fleet_locks.WAZUH_LOCK:
        if now - WAZUH_CACHE["fetched_at"] < WAZUH_TTL and WAZUH_CACHE["data"]:
            return list(WAZUH_CACHE["data"])
        cached_fallback = list(WAZUH_CACHE["data"])
    urls = [cfg["wazuh_url"]]
    if "127.0.0.1" in cfg["wazuh_url"]:
        urls.append(cfg["wazuh_url"].replace("127.0.0.1", "host.docker.internal"))
    elif "host.docker.internal" in cfg["wazuh_url"]:
        urls.append(cfg["wazuh_url"].replace("host.docker.internal", "127.0.0.1"))
    last_err = None
    for url in urls:
        try:
            agents = _fetch_wazuh_once(url, cfg)
            if not agents:
                print(
                    f"wazuh API {url} balik 0 agent, keep cache {len(cached_fallback)}",
                    flush=True,
                )
                continue
            with _fleet_locks.WAZUH_LOCK:
                WAZUH_CACHE["data"] = agents
                WAZUH_CACHE["fetched_at"] = now
            return list(agents)
        except Exception as e:
            last_err = e
            continue
    print(f"wazuh fetch error: {last_err}", flush=True)
    return cached_fallback


def build_fleet(cfg):
    wazuh_agents = fetch_wazuh_agents(cfg)
    now = time.time()
    now_wita = datetime.now(WITA).isoformat()

    fleet = []
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
                "regDate": a.get("dateAdd", "-"),
                "os": _short_os(a),
                "binary": "50 MB",
                "ram": "~50 MB",
            }
        )

    with _fleet_locks.STATE_LOCK:
        hb_items = list(HEARTBEATS.items())
    for hid, hb in hb_items:
        age = now - hb["last_seen"]
        status = "active" if age < HEARTBEAT_TTL else "disconnected"
        existing = next((x for x in fleet if x["id"] == hid), None)
        entry = {
            "id": hid,
            "name": hb.get("name", f"rust-agent-{hid}"),
            "type": "rust",
            "os": hb.get("os", "unknown"),
            "status": status,
            "ip": hb.get("ip", "-"),
            "version": hb.get("version", "0.1.0"),
            "lastKeepAlive": datetime.fromtimestamp(hb["last_seen"], WITA).isoformat(),
            "regDate": datetime.fromtimestamp(hb["first_seen"], WITA).isoformat()
            if hb.get("first_seen")
            else "-",
            "last_hash": hb.get("last_hash", "-")[:12] + "..."
            if hb.get("last_hash")
            else "-",
            "watch_paths": hb.get("watch_paths", []),
            "binary": "5.3 MB",
            "ram": "5.2 MB",
            "age_sec": int(age),
            "cpu_pct": hb.get("cpu_pct", 0),
            "ram_gb": hb.get("ram_gb", {}),
        }
        if existing:
            fleet = [e for e in fleet if e["id"] != hid]
        fleet.append(entry)

    fleet.sort(key=lambda x: x["id"])

    has_gemini = bool(cfg.get("gemini_key"))
    misp_url = os.environ.get("MISP_HEALTH_URL", "http://127.0.0.1:8090/healthz")
    alert_log_url = os.environ.get("ALERT_LOG_HEALTH_URL", "http://127.0.0.1:8091/healthz")
    health = {
        "n8n": check_http(cfg["n8n_url"]),
        "gemini": has_gemini,
        "wazuh_api": len(wazuh_agents) > 0,
        "misp": check_http(misp_url),
        "alert_log": check_http(alert_log_url),
        "ai_circuit_breaker": AI_CIRCUIT_BREAKER.snapshot(),
        "container_stats": _read_container_stats(),
    }

    # Severity summary dan total event 24 jam terakhir (selaras dengan status operasional realtime)
    now_ts = time.time()
    if now_ts - _EVENT_STATS_CACHE["ts"] < _EVENT_STATS_TTL:
        events_total = _EVENT_STATS_CACHE["total"]
        events_all = _EVENT_STATS_CACHE.get("all_time", events_total)
        sev_counts = dict(_EVENT_STATS_CACHE["severity"])
    else:
        since_24h = (
            (datetime.now(timezone.utc) - timedelta(hours=24))
            .isoformat()
            .replace("+00:00", "Z")
        )
        events_total = 0
        events_all = 0
        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "UNVERIFIED": 0, "INFO": 0}
        try:
            with closing(_db()) as conn:
                row_24h = conn.execute(
                    "SELECT count(*) FROM events WHERE source = 'soar' AND ts >= ?",
                    (since_24h,),
                ).fetchone()
                if row_24h and row_24h[0] is not None:
                    events_total = int(row_24h[0])
                cur = conn.execute(
                    "SELECT severity, count(*) FROM events WHERE source = 'soar' AND ts >= ? GROUP BY severity",
                    (since_24h,),
                )
                for r in cur.fetchall():
                    sev = (r[0] or "INFO").upper()
                    if sev in sev_counts:
                        sev_counts[sev] += r[1]
                row_all = conn.execute("SELECT count(*) FROM events WHERE source = 'soar'").fetchone()
                if row_all and row_all[0] is not None:
                    events_all = int(row_all[0])
                _EVENT_STATS_CACHE["total"] = events_total
                _EVENT_STATS_CACHE["all_time"] = events_all
                _EVENT_STATS_CACHE["severity"] = dict(sev_counts)
                _EVENT_STATS_CACHE["ts"] = now_ts
        except Exception:
            events_total = 0
            events_all = len(EVENTS)
            for ev in EVENTS:
                ev_ts = _to_utc_iso(ev.get("ts"))
                if ev_ts >= since_24h:
                    events_total += 1
                    sev = (ev.get("severity") or "INFO").upper()
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
            "events_total": events_total,
            "events_all_time": events_all,
            "severity": sev_counts,
        },
        "agents": fleet,
    }


HTML = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>SOAR Control Plane API</title></head>
<body style="font-family:system-ui,sans-serif;max-width:680px;margin:48px auto;padding:0 16px;color:#1a1c21;">
  <h1>SOAR Fleet Control Plane API</h1>
  <p>This service provides the authenticated backend API for the SOAR Dashboard and Endpoint Agents.</p>
  <p>Health endpoint: <code>GET /healthz</code>. Use the Next.js Dashboard UI for interactive SOC operations.</p>
</body>
</html>
"""

def _to_utc_iso(value):
    """Normalisasi ts apa pun (WITA +08:00, Z, Wazuh +0000, epoch) -> UTC 'Z'.

    Penting: kolom `ts` di SQLite dibandingkan sebagai string, jadi semua
    sumber harus format kanonik yang sama supaya urut & filter rentang benar.
    """
    if not value:
        return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    v = str(value).strip()
    if re.fullmatch(r"\d{10,13}", v):
        n = int(v)
        if n > 10**12:
            n /= 1000
        return (
            datetime.fromtimestamp(n, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z")
        )
    try:
        s = v.replace("Z", "+00:00")
        m = re.search(r"([+-]\d{2})(\d{2})$", s)  # Wazuh: +0000 tanpa colon
        if m and ":" not in s[-6:]:
            s = s[:-5] + m.group(1) + ":" + m.group(2)
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return v


def _event_row(ev):
    """Bentuk satu baris tabel events dari dict event (immutable, default aman)."""
    return (
        ev.get("id") or uuid.uuid4().hex,
        _to_utc_iso(ev.get("ts")),
        ev.get("agent", "-"),
        str(ev.get("agent_id", "-")),
        ev.get("path", "-"),
        ev.get("hash", ""),
        (ev.get("severity") or "INFO"),
        ev.get("status", "alerted"),
        ev.get("ai", ""),
        ev.get("url", ""),
        ev.get("verdict", ""),
        str(ev.get("rule_id", "")),
        ev.get("rule_level"),
        ev.get("rule_desc", ""),
        ev.get("source", "soar"),
        str(ev.get("size") or ""),
        str(ev.get("perm") or ""),
        str(ev.get("uname") or ""),
        str(ev.get("uid") or ""),
        str(ev.get("gname") or ""),
        str(ev.get("gid") or ""),
        str(ev.get("mtime") or ""),
        str(ev.get("inode") or ""),
        str(ev.get("md5") or ""),
        str(ev.get("sha1") or ""),
    )


def _db():
    conn = sqlite3.connect(EVENTS_DB, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def _event_store_init():
    # Fail-open: kalau path DB tak bisa ditulis (mis. /scripts read-only karena
    # FLEET_EVENTS_DB belum di-set), jangan sampai mematikan fleet-monitor.
    try:
        os.makedirs(os.path.dirname(EVENTS_DB) or ".", exist_ok=True)
        with closing(_db()) as conn, conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    agent TEXT, agent_id TEXT, path TEXT, hash TEXT,
                    severity TEXT, status TEXT, ai TEXT, url TEXT, verdict TEXT,
                    rule_id TEXT, rule_level INTEGER, rule_desc TEXT,
                    source TEXT NOT NULL DEFAULT 'soar',
                    size TEXT, perm TEXT, uname TEXT, uid TEXT,
                    gname TEXT, gid TEXT, mtime TEXT, inode TEXT,
                    md5 TEXT, sha1 TEXT
                )"""
            )
            for col in ("size", "perm", "uname", "uid", "gname", "gid", "mtime", "inode", "md5", "sha1"):
                try:
                    conn.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
                except Exception:
                    pass
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts)")
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_id, ts)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity, ts)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_source_ts ON events(source, ts)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_source_sev ON events(source, severity)"
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    key_hash TEXT NOT NULL UNIQUE,
                    prefix TEXT NOT NULL,
                    scopes TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_used_at TEXT,
                    revoked INTEGER NOT NULL DEFAULT 0
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash)"
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'viewer',
                    email TEXT,
                    name TEXT,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT,
                    active INTEGER NOT NULL DEFAULT 1
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)"
            )
            try:
                conn.execute(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique "
                    "ON users(LOWER(email)) WHERE email IS NOT NULL AND TRIM(email) != ''"
                )
            except Exception:
                pass
            _init_default_users(conn)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS agent_enrollment_requests (
                    id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    os TEXT NOT NULL,
                    arch TEXT,
                    ip TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    agent_id TEXT,
                    poll_token TEXT,
                    claim_secret_hash TEXT,
                    token_claimed_at TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    approved_by TEXT
                )"""
            )
            for col in ("claim_secret_hash", "token_claimed_at"):
                try:
                    conn.execute(f"ALTER TABLE agent_enrollment_requests ADD COLUMN {col} TEXT")
                except Exception:
                    pass
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enroll_status ON agent_enrollment_requests(status)"
            )
            conn.execute(
                """CREATE TABLE IF NOT EXISTS enrolled_agents (
                    agent_id TEXT PRIMARY KEY,
                    hostname TEXT NOT NULL,
                    name TEXT NOT NULL,
                    poll_token TEXT NOT NULL UNIQUE,
                    os TEXT,
                    ip TEXT,
                    enrolled_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active'
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_enrolled_poll_token ON enrolled_agents(poll_token)"
            )
            _load_enrolled_agents(conn)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS system_settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    updated_by TEXT
                )"""
            )
            _init_default_settings(conn)
            conn.execute(
                """CREATE TABLE IF NOT EXISTS agent_investigations (
                    id TEXT PRIMARY KEY,
                    ts TEXT NOT NULL,
                    title TEXT NOT NULL,
                    agent_source TEXT NOT NULL,
                    model TEXT,
                    verdict TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    analysis TEXT NOT NULL,
                    recommendations TEXT,
                    mitre_techniques TEXT,
                    target_agent_ids TEXT,
                    target_hashes TEXT,
                    target_paths TEXT,
                    created_by TEXT
                )"""
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_inv_ts ON agent_investigations(ts)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_agent_inv_verdict ON agent_investigations(verdict, ts)"
            )
            _fleet_soc.init_soc_tables(conn)
        print(f"event store siap: {EVENTS_DB}", flush=True)
        _event_store_load_recent()
        _command_store_load_queued()
    except Exception as e:
        print(f"event store init gagal (riwayat nonaktif): {e}", flush=True)


def _command_store_load_queued():
    """Muat antrean command berstatus 'queued' dari SQLite ke memory buffer COMMANDS."""
    loaded = _fleet_soc.load_queued_commands(_db)
    with _fleet_locks.COMMANDS_LOCK:
        for aid, items in loaded.items():
            COMMANDS[aid] = items[-COMMANDS_MAX:]


def _record_audit(action, target="", status="ok", detail="", actor="system", role="", ip=""):
    return _fleet_soc.append_audit_log(
        _db,
        action=action,
        target=target,
        status=status,
        detail=detail,
        actor=actor,
        role=role,
        ip=ip,
    )


def _event_store_load_recent():
    """Muat event terbaru dari SQLite ke memory buffer EVENTS saat startup."""
    global EVENTS
    try:
        with closing(_db()) as conn:
            cur = conn.execute(
                "SELECT * FROM events WHERE source = 'soar' ORDER BY ts DESC LIMIT ?",
                (EVENTS_MAX,),
            )
            rows = [dict(r) for r in cur.fetchall()]
            if rows:
                EVENTS = list(reversed(rows))
                print(f"event store: {len(EVENTS)} event dimuat ke ring buffer", flush=True)
    except Exception as e:
        print(f"event store load recent error: {e}", flush=True)


def _event_store_insert(ev):
    """Simpan event ke riwayat durable. Gagal DB tidak boleh mematikan ingest."""
    global _events_insert_count
    try:
        with closing(_db()) as conn, conn:
            conn.execute(
                """INSERT OR IGNORE INTO events
                (id, ts, agent, agent_id, path, hash, severity, status, ai, url,
                 verdict, rule_id, rule_level, rule_desc, source,
                 size, perm, uname, uid, gname, gid, mtime, inode, md5, sha1)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                _event_row(ev),
            )
        _events_insert_count += 1
        _EVENT_STATS_CACHE["ts"] = 0  # Invalidate agar /api/fleet langsung hitung ulang
        if _events_insert_count % EVENTS_PRUNE_EVERY == 0:
            _event_store_prune()
    except Exception as e:
        print(f"event store insert error: {e}", flush=True)


def _event_store_prune(now=None):
    """Buang event lebih tua dari retensi, lalu cap jumlah baris (terbaru menang)."""
    cutoff = _to_utc_iso(
        (now or datetime.now(WITA)) - timedelta(days=EVENTS_RETENTION_DAYS)
    )
    try:
        with closing(_db()) as conn, conn:
            conn.execute("DELETE FROM events WHERE ts < ?", (cutoff,))
            conn.execute(
                "DELETE FROM events WHERE id IN ("
                "SELECT id FROM events ORDER BY ts DESC LIMIT -1 OFFSET ?)",
                (EVENTS_MAX_ROWS,),
            )
    except Exception as e:
        print(f"event store prune error: {e}", flush=True)


def _event_store_query(since=None, until=None, severity=None, agent_id=None, q=None, limit=HISTORY_MAX_LIMIT):
    """Ambil event SOAR dalam rentang dengan batas atas aman."""
    where = ["source = 'soar'"]
    params = []
    if since:
        where.append("ts >= ?")
        params.append(_to_utc_iso(since))
    if until:
        where.append("ts <= ?")
        params.append(_to_utc_iso(until))
    if agent_id:
        where.append("agent_id = ?")
        params.append(str(agent_id))
    if severity:
        where.append("severity IN (%s)" % ",".join("?" * len(severity)))
        params.extend(severity)
    for token in q or []:
        like = f"%{token}%"
        where.append(
            "(path LIKE ? OR hash LIKE ? OR url LIKE ? OR agent LIKE ?"
            " OR ai LIKE ? OR rule_desc LIKE ?)"
        )
        params.extend([like] * 6)
    safe_limit = max(1, min(int(limit or HISTORY_MAX_LIMIT), HISTORY_MAX_LIMIT))
    sql = "SELECT * FROM events WHERE " + " AND ".join(where) + " ORDER BY ts DESC LIMIT ?"
    params.append(safe_limit)
    try:
        with closing(_db()) as conn:
            rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]
    except Exception as e:
        print(f"event store query error: {e}", flush=True)
        return []


def _hash_api_key(token):
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _api_key_create(name, scopes):
    clean_name = (name or "AI Agent").strip()[:100]
    valid_scopes = [
        s.strip()
        for s in (scopes or [])
        if s.strip() in ("read:fleet", "read:intel", "write:actions", "write:investigations", "*")
    ]
    if not valid_scopes:
        valid_scopes = ["read:fleet", "read:intel"]
    scopes_str = ",".join(valid_scopes)

    raw_token = f"soar_live_{secrets.token_hex(24)}"
    key_hash = _hash_api_key(raw_token)
    prefix = f"{raw_token[:16]}...{raw_token[-4:]}"
    key_id = f"key_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(WITA).isoformat()

    with closing(_db()) as conn, conn:
        conn.execute(
            """INSERT INTO api_keys
            (id, name, key_hash, prefix, scopes, created_at, last_used_at, revoked)
            VALUES (?, ?, ?, ?, ?, ?, NULL, 0)""",
            (key_id, clean_name, key_hash, prefix, scopes_str, created_at),
        )

    return {
        "id": key_id,
        "name": clean_name,
        "token": raw_token,
        "prefix": prefix,
        "scopes": valid_scopes,
        "created_at": created_at,
    }


def _api_key_list(include_revoked=False):
    try:
        where_clause = "" if include_revoked else "WHERE revoked = 0"
        with closing(_db()) as conn:
            rows = conn.execute(
                f"""SELECT id, name, prefix, scopes, created_at, last_used_at, revoked
                FROM api_keys {where_clause} ORDER BY created_at DESC"""
            ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "prefix": r["prefix"],
                "scopes": [s.strip() for s in r["scopes"].split(",") if s.strip()],
                "created_at": r["created_at"],
                "last_used_at": r["last_used_at"],
                "revoked": bool(r["revoked"]),
            }
            for r in rows
        ]
    except Exception as e:
        print(f"api_key_list error: {e}", flush=True)
        return []


def _api_key_revoke(key_id):
    try:
        with closing(_db()) as conn, conn:
            cur = conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (str(key_id),))
            return cur.rowcount > 0
    except Exception as e:
        print(f"api_key_revoke error: {e}", flush=True)
        return False


def _api_key_rotate(key_id):
    try:
        raw_token = f"soar_live_{secrets.token_hex(24)}"
        new_hash = _hash_api_key(raw_token)
        new_prefix = f"{raw_token[:16]}...{raw_token[-4:]}"
        new_id = f"key_{uuid.uuid4().hex[:12]}"
        created_at = datetime.now(WITA).isoformat()

        with closing(_db()) as conn, conn:
            row = conn.execute(
                "SELECT id, name, prefix, scopes, revoked FROM api_keys WHERE id = ?",
                (str(key_id),),
            ).fetchone()
            if not row or row["revoked"]:
                return None
            scopes_str = row["scopes"]
            scopes_list = [s.strip() for s in scopes_str.split(",") if s.strip()]
            conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (str(key_id),))
            conn.execute(
                """INSERT INTO api_keys
                (id, name, key_hash, prefix, scopes, created_at, last_used_at, revoked)
                VALUES (?, ?, ?, ?, ?, ?, NULL, 0)""",
                (new_id, row["name"], new_hash, new_prefix, scopes_str, created_at),
            )
            return {
                "id": new_id,
                "name": row["name"],
                "token": raw_token,
                "prefix": new_prefix,
                "scopes": scopes_list,
                "created_at": created_at,
                "rotated_from": str(key_id),
                "old_prefix": row["prefix"],
            }
    except Exception as e:
        print(f"api_key_rotate error: {e}", flush=True)
        return None


def _verify_api_key(headers, required_scope=""):
    auth = headers.get("Authorization", "").strip()
    x_api_key = headers.get("X-API-Key", "").strip()
    token = ""
    if auth.startswith("Bearer "):
        token = auth[7:].strip()
    elif x_api_key:
        token = x_api_key

    if not token or not token.startswith("soar_live_"):
        return False, None

    key_hash = _hash_api_key(token)
    try:
        with closing(_db()) as conn:
            row = conn.execute(
                "SELECT id, name, scopes, revoked FROM api_keys WHERE key_hash = ?",
                (key_hash,),
            ).fetchone()
        if not row or row["revoked"]:
            return False, None

        scopes = [s.strip() for s in row["scopes"].split(",") if s.strip()]
        if required_scope and ("*" not in scopes and required_scope not in scopes):
            return False, None

        now_ts = time.time()
        should_touch = False
        with _fleet_locks.API_KEY_TOUCH_LOCK:
            last_t = _API_KEY_LAST_TOUCH.get(row["id"], 0.0)
            if now_ts - last_t >= 60.0:
                _API_KEY_LAST_TOUCH[row["id"]] = now_ts
                should_touch = True
        if should_touch:
            now_iso = datetime.now(WITA).isoformat()
            with closing(_db()) as conn, conn:
                conn.execute(
                    "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
                    (now_iso, row["id"]),
                )

        return True, {"id": row["id"], "name": row["name"], "scopes": scopes}
    except Exception as e:
        print(f"verify_api_key error: {e}", flush=True)
        return False, None


INVESTIGATION_MAX_ROWS = 2000


def _clean_str_list(val, max_items=25):
    if isinstance(val, str):
        items = [x.strip() for x in val.split(",") if x.strip()]
    elif isinstance(val, list):
        items = [str(x).strip() for x in val if str(x).strip()]
    else:
        items = []
    seen = []
    for item in items:
        clean = item[:256]
        if clean and clean not in seen:
            seen.append(clean)
        if len(seen) >= max_items:
            break
    return seen


def _investigation_row_to_dict(row):
    d = dict(row)
    for field in ("mitre_techniques", "target_agent_ids", "target_hashes", "target_paths"):
        raw = d.get(field) or "[]"
        try:
            parsed = json.loads(raw)
            d[field] = parsed if isinstance(parsed, list) else []
        except Exception:
            d[field] = []
    return d


def _investigation_create(data, created_by="external-agent"):
    if not isinstance(data, dict):
        raise ValueError("Payload investigasi harus berupa JSON object")
    title = str(data.get("title", "")).strip()[:200]
    summary = str(data.get("summary", "")).strip()[:2000]
    analysis = str(data.get("analysis", "")).strip()[:12000] or summary
    if not title:
        raise ValueError("title wajib diisi")
    if not summary:
        raise ValueError("summary wajib diisi")

    verdict = str(data.get("verdict", "NEEDS_REVIEW")).strip().upper()
    if verdict not in ("MALICIOUS", "SUSPICIOUS", "BENIGN", "NEEDS_REVIEW"):
        verdict = "NEEDS_REVIEW"

    severity = str(data.get("severity", "MEDIUM")).strip().upper()
    if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        severity = "MEDIUM"

    agent_source = str(data.get("agent_source", "agy")).strip()[:80] or "agy"
    model = str(data.get("model", "")).strip()[:120]
    recommendations = str(data.get("recommendations", "")).strip()[:4000]

    mitre = _clean_str_list(data.get("mitre_techniques"))
    agent_ids = _clean_str_list(data.get("target_agent_ids"))
    hashes = _clean_str_list(data.get("target_hashes"))
    paths = _clean_str_list(data.get("target_paths"))

    inv_id = f"inv_{uuid.uuid4().hex[:12]}"
    ts = datetime.now(WITA).isoformat()
    actor = (str(data.get("created_by") or created_by or "external-agent")).strip()[:120]

    with closing(_db()) as conn, conn:
        conn.execute(
            """INSERT INTO agent_investigations
            (id, ts, title, agent_source, model, verdict, severity, summary, analysis,
             recommendations, mitre_techniques, target_agent_ids, target_hashes, target_paths, created_by)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                inv_id,
                ts,
                title,
                agent_source,
                model,
                verdict,
                severity,
                summary,
                analysis,
                recommendations,
                json.dumps(mitre),
                json.dumps(agent_ids),
                json.dumps(hashes),
                json.dumps(paths),
                actor,
            ),
        )
        conn.execute(
            "DELETE FROM agent_investigations WHERE id IN ("
            "SELECT id FROM agent_investigations ORDER BY ts DESC LIMIT -1 OFFSET ?)",
            (INVESTIGATION_MAX_ROWS,),
        )

    return {
        "id": inv_id,
        "ts": ts,
        "title": title,
        "agent_source": agent_source,
        "model": model,
        "verdict": verdict,
        "severity": severity,
        "summary": summary,
        "analysis": analysis,
        "recommendations": recommendations,
        "mitre_techniques": mitre,
        "target_agent_ids": agent_ids,
        "target_hashes": hashes,
        "target_paths": paths,
        "created_by": actor,
    }


def _investigation_list(limit=50, verdict=None, severity=None, q=None, agent_source=None):
    try:
        limit = max(1, min(int(limit), 200))
    except (TypeError, ValueError):
        limit = 50

    where = []
    params = []
    if verdict and verdict.upper() != "ALL":
        where.append("verdict = ?")
        params.append(verdict.upper())
    if severity and severity.upper() != "ALL":
        where.append("severity = ?")
        params.append(severity.upper())
    if agent_source and agent_source.lower() != "all":
        where.append("LOWER(agent_source) = ?")
        params.append(agent_source.lower())
    if q:
        like = f"%{q}%"
        where.append(
            "(title LIKE ? OR summary LIKE ? OR analysis LIKE ? OR recommendations LIKE ?"
            " OR agent_source LIKE ? OR model LIKE ? OR mitre_techniques LIKE ?"
            " OR target_agent_ids LIKE ? OR target_hashes LIKE ? OR target_paths LIKE ?)"
        )
        params.extend([like] * 10)

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    try:
        with closing(_db()) as conn:
            total = conn.execute(
                f"SELECT COUNT(*) FROM agent_investigations{clause}", params
            ).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM agent_investigations{clause} ORDER BY ts DESC LIMIT ?",
                [*params, limit],
            ).fetchall()
        return {"investigations": [_investigation_row_to_dict(r) for r in rows], "total": total}
    except Exception as e:
        print(f"investigation list error: {e}", flush=True)
        return {"investigations": [], "total": 0}


def _investigation_delete(inv_id):
    if not inv_id:
        return False
    try:
        with closing(_db()) as conn, conn:
            cur = conn.execute("DELETE FROM agent_investigations WHERE id = ?", (inv_id,))
            return cur.rowcount > 0
    except Exception as e:
        print(f"investigation delete error: {e}", flush=True)
        return False


def _hash_password(password, salt=None):
    return _fleet_sec.hash_password(password, salt=salt)


def _verify_password(password, stored_hash):
    return _fleet_sec.verify_password(password, stored_hash)


def _init_default_users(conn):
    try:
        cur = conn.execute("SELECT count(*) FROM users")
        count = cur.fetchone()[0]
        if count > 0:
            return
        admin_email = (
            os.environ.get("FLEET_BOOTSTRAP_ADMIN_EMAIL")
            or os.environ.get("ADMIN_EMAIL")
            or "admin@soar.local"
        ).strip().lower()
        init_pw = (
            os.environ.get("FLEET_BOOTSTRAP_ADMIN_PASSWORD")
            or os.environ.get("ADMIN_INITIAL_PASSWORD")
            or ""
        ).strip()
        generated = False
        if not init_pw:
            init_pw = secrets.token_urlsafe(18)
            generated = True
        now_iso = datetime.now(WITA).isoformat()
        conn.execute(
            """INSERT INTO users (id, username, password_hash, role, email, name, created_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
            ("usr_admin", "admin", _hash_password(init_pw), "admin", admin_email, "SOAR Administrator", now_iso),
        )
        if generated:
            print(
                f"BOOTSTRAP ADMIN GENERATED: username=admin email={admin_email} password={init_pw}",
                flush=True,
            )
        else:
            print(f"default admin initialized: username=admin email={admin_email}", flush=True)
    except Exception as e:
        print(f"init_default_users error: {e}", flush=True)


def _user_by_email(email):
    clean = (email or "").strip().lower()
    if not clean:
        return None
    try:
        with closing(_db()) as conn:
            row = conn.execute(
                """SELECT id, username, role, email, name, active
                FROM users WHERE LOWER(email) = ? AND active = 1""",
                (clean,),
            ).fetchone()
        if not row:
            return None
        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "email": row["email"],
            "name": row["name"],
            "active": bool(row["active"]),
        }
    except Exception as e:
        print(f"user_by_email error: {e}", flush=True)
        return None


def _user_list():
    try:
        with closing(_db()) as conn:
            rows = conn.execute(
                """SELECT id, username, role, email, name, created_at, last_login_at, active
                FROM users ORDER BY created_at ASC"""
            ).fetchall()
        return [
            {
                "id": r["id"],
                "username": r["username"],
                "role": r["role"],
                "email": r["email"] or "",
                "name": r["name"] or "",
                "created_at": r["created_at"],
                "last_login_at": r["last_login_at"],
                "active": bool(r["active"]),
            }
            for r in rows
        ]
    except Exception as e:
        print(f"user_list error: {e}", flush=True)
        return []


def _user_create(username, password, role="viewer", email="", name=""):
    clean_username = (username or "").strip().lower()
    if not re.fullmatch(r"^[a-zA-Z0-9_.-]{3,32}$", clean_username):
        raise ValueError("Username harus 3-32 karakter alfanumerik (._- diperbolehkan)")
    if role not in ("admin", "analyst", "viewer"):
        role = "viewer"
    if not password or len(password) < 8:
        raise ValueError("Password minimal 8 karakter")

    user_id = f"usr_{uuid.uuid4().hex[:12]}"
    created_at = datetime.now(WITA).isoformat()
    pass_hash = _hash_password(password)
    clean_email = (email or "").strip()[:120]
    clean_name = (name or clean_username).strip()[:100]

    with closing(_db()) as conn, conn:
        existing = conn.execute("SELECT id FROM users WHERE username = ?", (clean_username,)).fetchone()
        if existing:
            raise ValueError(f"Username '{clean_username}' sudah digunakan")
        conn.execute(
            """INSERT INTO users (id, username, password_hash, role, email, name, created_at, active)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
            (user_id, clean_username, pass_hash, role, clean_email, clean_name, created_at),
        )

    return {
        "id": user_id,
        "username": clean_username,
        "role": role,
        "email": clean_email,
        "name": clean_name,
        "created_at": created_at,
        "last_login_at": None,
        "active": True,
    }


def _user_update(user_id, updates):
    clean_id = str(user_id).strip()
    if not clean_id:
        raise ValueError("User ID diperlukan")

    with closing(_db()) as conn, conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (clean_id,)).fetchone()
        if not row:
            raise ValueError("User tidak ditemukan")

        # Guard: tidak boleh menonaktifkan atau demote admin terakhir
        new_role = updates.get("role", row["role"])
        new_active = int(updates.get("active", row["active"]))
        if row["role"] == "admin" and (new_role != "admin" or new_active == 0):
            admin_count = conn.execute(
                "SELECT count(*) FROM users WHERE role = 'admin' AND active = 1 AND id != ?",
                (clean_id,),
            ).fetchone()[0]
            if admin_count < 1:
                raise ValueError("Tidak dapat mengubah role atau menonaktifkan akun Admin aktif terakhir")

        set_clauses = []
        params = []
        if "role" in updates and updates["role"] in ("admin", "analyst", "viewer"):
            set_clauses.append("role = ?")
            params.append(updates["role"])
        if "active" in updates:
            set_clauses.append("active = ?")
            params.append(1 if updates["active"] else 0)
        if "email" in updates:
            set_clauses.append("email = ?")
            params.append(str(updates["email"]).strip()[:120])
        if "name" in updates:
            set_clauses.append("name = ?")
            params.append(str(updates["name"]).strip()[:100])
        if "password" in updates and updates["password"]:
            pwd = str(updates["password"])
            if len(pwd) < 8:
                raise ValueError("Password baru minimal 8 karakter")
            set_clauses.append("password_hash = ?")
            params.append(_hash_password(pwd))

        if not set_clauses:
            return {
                "id": row["id"],
                "username": row["username"],
                "role": row["role"],
                "email": row["email"] or "",
                "name": row["name"] or "",
                "created_at": row["created_at"],
                "last_login_at": row["last_login_at"],
                "active": bool(row["active"]),
            }

        params.append(clean_id)
        conn.execute(f"UPDATE users SET {', '.join(set_clauses)} WHERE id = ?", params)
        updated = conn.execute(
            "SELECT id, username, role, email, name, created_at, last_login_at, active FROM users WHERE id = ?",
            (clean_id,),
        ).fetchone()
        return {
            "id": updated["id"],
            "username": updated["username"],
            "role": updated["role"],
            "email": updated["email"] or "",
            "name": updated["name"] or "",
            "created_at": updated["created_at"],
            "last_login_at": updated["last_login_at"],
            "active": bool(updated["active"]),
        }


def _user_delete(user_id):
    clean_id = str(user_id).strip()
    with closing(_db()) as conn, conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (clean_id,)).fetchone()
        if not row:
            return False
        if row["role"] == "admin":
            admin_count = conn.execute(
                "SELECT count(*) FROM users WHERE role = 'admin' AND active = 1 AND id != ?",
                (clean_id,),
            ).fetchone()[0]
            if admin_count < 1:
                raise ValueError("Tidak dapat menghapus akun Admin aktif terakhir")
        conn.execute("DELETE FROM users WHERE id = ?", (clean_id,))
        return True


def _user_authenticate(username, password):
    clean_username = (username or "").strip().lower()
    if not clean_username or not password:
        return None
    try:
        with closing(_db()) as conn:
            row = conn.execute(
                "SELECT * FROM users WHERE username = ? AND active = 1",
                (clean_username,),
            ).fetchone()
        if not row:
            return None
        if not _verify_password(password, row["password_hash"]):
            return None

        now_iso = datetime.now(WITA).isoformat()
        with closing(_db()) as conn, conn:
            conn.execute("UPDATE users SET last_login_at = ? WHERE id = ?", (now_iso, row["id"]))

        return {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
            "email": row["email"] or "",
            "name": row["name"] or "",
        }
    except Exception as e:
        print(f"user_authenticate error: {e}", flush=True)
        return None


def _user_touch_login(username="", email=""):
    """Catat timestamp login terakhir untuk sesi SSO, 2FA OTP, atau token master."""
    clean_email = (email or "").strip().lower()
    clean_user = (username or "").strip().lower()
    if not clean_email and not clean_user:
        return False
    now_iso = datetime.now(WITA).isoformat()
    try:
        with closing(_db()) as conn, conn:
            if clean_email:
                cur = conn.execute(
                    "UPDATE users SET last_login_at = ? WHERE LOWER(email) = ? AND active = 1",
                    (now_iso, clean_email),
                )
                if cur.rowcount > 0:
                    return True
            if clean_user:
                cur = conn.execute(
                    "UPDATE users SET last_login_at = ? WHERE username = ? AND active = 1",
                    (now_iso, clean_user),
                )
                return cur.rowcount > 0
    except Exception as e:
        print(f"user_touch_login error: {e}", flush=True)
    return False


_CF_SYNC_STATE = {
    "last_synced_at": None,
    "last_status": "idle",
    "last_detail": "",
    "emails_count": 0,
    "policy_name": "",
}


def _cf_access_config():
    return {
        "token": os.environ.get("CLOUDFLARE_API_TOKEN", "").strip(),
        "account_id": os.environ.get("CLOUDFLARE_ACCOUNT_ID", "").strip(),
        "app_id": os.environ.get("CLOUDFLARE_ACCESS_APP_ID", "").strip(),
        "policy_id": os.environ.get("CLOUDFLARE_ACCESS_POLICY_ID", "").strip(),
        "api_base": os.environ.get("CLOUDFLARE_API_BASE_URL", "https://api.cloudflare.com/client/v4").strip().rstrip("/"),
    }


def _cf_active_user_emails():
    emails = set()
    try:
        with closing(_db()) as conn:
            rows = conn.execute(
                "SELECT email FROM users WHERE active = 1 AND email IS NOT NULL AND TRIM(email) != ''"
            ).fetchall()
        for r in rows:
            em = str(r["email"] or "").strip().lower()
            if _fleet_sec.is_valid_external_email(em):
                emails.add(em)
    except Exception as e:
        print(f"cf_active_user_emails error: {e}", flush=True)
    return sorted(emails)


def _cf_build_include_rules(existing_include, emails):
    preserved = []
    if isinstance(existing_include, list):
        for rule in existing_include:
            if isinstance(rule, dict) and "email" not in rule:
                preserved.append(rule)
    for em in emails:
        preserved.append({"email": {"email": em}})
    return preserved


def _cf_api_request(url, token, method="GET", payload=None, timeout=12):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _cf_sync_status_summary():
    cfg = _cf_access_config()
    configured = bool(cfg["token"] and cfg["account_id"] and cfg["policy_id"])
    emails = _cf_active_user_emails()
    return {
        "configured": configured,
        "account_id": cfg["account_id"],
        "app_id": cfg["app_id"],
        "policy_id": cfg["policy_id"],
        "active_emails_count": len(emails),
        "last_synced_at": _CF_SYNC_STATE.get("last_synced_at"),
        "last_status": _CF_SYNC_STATE.get("last_status", "idle"),
        "last_detail": _CF_SYNC_STATE.get("last_detail", ""),
        "policy_name": _CF_SYNC_STATE.get("policy_name", ""),
    }


def _sync_cloudflare_access_policy():
    """Sinkronkan daftar email user aktif ke Cloudflare Zero Trust Access Policy."""
    with _fleet_locks.CF_SYNC_LOCK:
        return _sync_cloudflare_access_policy_locked()


def _sync_cloudflare_access_policy_locked():
    cfg = _cf_access_config()
    emails = _cf_active_user_emails()
    if not (cfg["token"] and cfg["account_id"] and cfg["policy_id"]):
        detail = "Belum dikonfigurasi: isi CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, dan CLOUDFLARE_ACCESS_POLICY_ID"
        _CF_SYNC_STATE.update({
            "last_status": "unconfigured",
            "last_detail": detail,
            "emails_count": len(emails),
        })
        return {
            "configured": False,
            "synced": False,
            "status": "unconfigured",
            "detail": detail,
            "emails_count": len(emails),
            "emails": emails,
        }

    if not emails:
        detail = "Sinkronisasi dilewati: tidak ada email user aktif (proteksi anti-lockout)"
        _CF_SYNC_STATE.update({
            "last_status": "skipped",
            "last_detail": detail,
            "emails_count": 0,
        })
        return {
            "configured": True,
            "synced": False,
            "status": "skipped",
            "detail": detail,
            "emails_count": 0,
            "emails": [],
        }

    candidates = []
    if cfg["app_id"]:
        candidates.append(
            f"{cfg['api_base']}/accounts/{cfg['account_id']}/access/apps/{cfg['app_id']}/policies/{cfg['policy_id']}"
        )
    candidates.append(
        f"{cfg['api_base']}/accounts/{cfg['account_id']}/access/policies/{cfg['policy_id']}"
    )

    last_err = ""
    for target_url in candidates:
        try:
            get_resp = _cf_api_request(target_url, cfg["token"], method="GET")
            if not isinstance(get_resp, dict) or not get_resp.get("success"):
                errs = get_resp.get("errors", []) if isinstance(get_resp, dict) else []
                raise RuntimeError(f"Cloudflare GET policy gagal: {errs or get_resp}")

            policy_obj = get_resp.get("result") or {}
            # Preserve seluruh field policy yang ada dari GET, hanya ganti include/name/decision
            put_body = {
                k: v
                for k, v in policy_obj.items()
                if k not in ("id", "uid", "created_at", "updated_at", "reusable")
                and v is not None
            }
            put_body["name"] = policy_obj.get("name") or "SOAR Authorized Users"
            put_body["decision"] = policy_obj.get("decision") or "allow"
            put_body["include"] = _cf_build_include_rules(policy_obj.get("include"), emails)

            put_resp = _cf_api_request(target_url, cfg["token"], method="PUT", payload=put_body)
            if not isinstance(put_resp, dict) or not put_resp.get("success"):
                errs = put_resp.get("errors", []) if isinstance(put_resp, dict) else []
                raise RuntimeError(f"Cloudflare PUT policy gagal: {errs or put_resp}")

            synced_at = datetime.now(WITA).isoformat()
            policy_name = str(put_resp.get("result", {}).get("name") or put_body["name"])
            detail = f"Tersinkron ke policy '{policy_name}' ({len(emails)} email aktif)"
            _CF_SYNC_STATE.update({
                "last_synced_at": synced_at,
                "last_status": "synced",
                "last_detail": detail,
                "emails_count": len(emails),
                "policy_name": policy_name,
            })
            return {
                "configured": True,
                "synced": True,
                "status": "synced",
                "detail": detail,
                "policy_name": policy_name,
                "emails_count": len(emails),
                "emails": emails,
                "synced_at": synced_at,
            }
        except urllib.error.HTTPError as he:
            err_body = ""
            try:
                err_body = he.read().decode("utf-8", errors="replace")[:300]
            except Exception:
                pass
            last_err = f"HTTP {he.code}: {err_body or he.reason}"
            # Jika app-scoped URL mengembalikan 404 dan masih ada kandidat reusable policy, lanjut coba
            if he.code == 404 and target_url != candidates[-1]:
                continue
            break
        except Exception as e:
            last_err = str(e)
            break

    detail = f"Gagal sinkron Cloudflare Access: {last_err}"
    print(f"sync_cloudflare_access_policy error: {detail}", flush=True)
    _CF_SYNC_STATE.update({
        "last_status": "error",
        "last_detail": detail,
        "emails_count": len(emails),
    })
    return {
        "configured": True,
        "synced": False,
        "status": "error",
        "detail": detail,
        "emails_count": len(emails),
        "emails": emails,
    }


def _load_enrolled_agents(conn):
    try:
        cur = conn.execute("SELECT agent_id, poll_token FROM enrolled_agents WHERE status = 'active'")
        count = 0
        for row in cur.fetchall():
            aid = str(row[0]).strip()
            token = str(row[1]).strip()
            if _valid_agent_id(aid) and len(token) >= MIN_RUNTIME_SECRET_LENGTH:
                FLEET_AGENT_POLL_TOKENS[aid] = token
                count += 1
        if count > 0:
            print(f"enrolled agents dimuat dari database: {count} agent", flush=True)
    except Exception as e:
        print(f"gagal memuat enrolled agents dari database: {e}", flush=True)


def _enroll_request_create(hostname, os_name="linux", arch="x86_64", ip=""):
    clean_host = (hostname or "workstation").strip()[:64]
    clean_os = (os_name or "linux").strip().lower()[:32]
    clean_arch = (arch or "x86_64").strip()[:32]
    clean_ip = (ip or "").strip()[:64]
    req_id = f"req_{uuid.uuid4().hex[:12]}"
    claim_secret = secrets.token_hex(24)
    claim_secret_hash = _hash_api_key(claim_secret)
    created_at = datetime.now(WITA).isoformat()

    with closing(_db()) as conn, conn:
        conn.execute(
            """INSERT INTO agent_enrollment_requests
            (id, hostname, os, arch, ip, status, claim_secret_hash, created_at)
            VALUES (?, ?, ?, ?, ?, 'pending', ?, ?)""",
            (req_id, clean_host, clean_os, clean_arch, clean_ip, claim_secret_hash, created_at),
        )

    return {
        "request_id": req_id,
        "claim_secret": claim_secret,
        "hostname": clean_host,
        "os": clean_os,
        "arch": clean_arch,
        "ip": clean_ip,
        "status": "pending",
        "created_at": created_at,
    }


def _enroll_request_get(req_id):
    clean_id = str(req_id).strip()
    if not clean_id:
        return None
    try:
        with closing(_db()) as conn:
            row = conn.execute(
                """SELECT id, hostname, os, arch, ip, status, agent_id, poll_token,
                          claim_secret_hash, token_claimed_at, created_at, updated_at, approved_by
                FROM agent_enrollment_requests WHERE id = ?""",
                (clean_id,),
            ).fetchone()
            if not row:
                return None
            return {
                "id": row["id"],
                "hostname": row["hostname"],
                "os": row["os"],
                "arch": row["arch"],
                "ip": row["ip"],
                "status": row["status"],
                "agent_id": row["agent_id"],
                "poll_token": row["poll_token"],
                "claim_secret_hash": row["claim_secret_hash"],
                "token_claimed_at": row["token_claimed_at"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
                "approved_by": row["approved_by"],
            }
    except Exception as e:
        print(f"enroll_request_get error: {e}", flush=True)
        return None


def _enroll_claim_status(req_id, claim_secret=""):
    """Ambil status enrollment dengan one-time pickup poll_token (TTL 15 menit)."""
    req = _enroll_request_get(req_id)
    if not req:
        return None, 404, "request tidak ditemukan"
    expected_hash = (req.get("claim_secret_hash") or "").strip()
    if expected_hash:
        provided = str(claim_secret or "").strip()
        if not provided or not hmac.compare_digest(_hash_api_key(provided), expected_hash):
            return None, 403, "claim_secret tidak valid"
    poll_token = None
    if req["status"] == "approved" and req.get("poll_token") and not req.get("token_claimed_at"):
        # Cek TTL 15 menit sejak approval
        updated_epoch = _ts_epoch(req.get("updated_at") or req.get("created_at"))
        if not updated_epoch or (time.time() - updated_epoch <= 900):
            poll_token = req["poll_token"]
            now_iso = datetime.now(WITA).isoformat()
            with closing(_db()) as conn, conn:
                conn.execute(
                    "UPDATE agent_enrollment_requests SET poll_token = NULL, token_claimed_at = ? WHERE id = ?",
                    (now_iso, req["id"]),
                )
    return {
        "status": req["status"],
        "agent_id": req.get("agent_id"),
        "agent_name": f"agent-{req.get('hostname')}",
        "poll_token": poll_token,
    }, 200, None


def _enroll_requests_list(status_filter=None):
    try:
        with closing(_db()) as conn:
            if status_filter:
                rows = conn.execute(
                    """SELECT id, hostname, os, arch, ip, status, agent_id, poll_token, created_at, updated_at, approved_by
                    FROM agent_enrollment_requests WHERE status = ? ORDER BY created_at DESC LIMIT 100""",
                    (status_filter,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT id, hostname, os, arch, ip, status, agent_id, poll_token, created_at, updated_at, approved_by
                    FROM agent_enrollment_requests ORDER BY created_at DESC LIMIT 100"""
                ).fetchall()

            return [
                {
                    "id": r["id"],
                    "hostname": r["hostname"],
                    "os": r["os"],
                    "arch": r["arch"],
                    "ip": r["ip"],
                    "status": r["status"],
                    "agent_id": r["agent_id"],
                    "created_at": r["created_at"],
                    "updated_at": r["updated_at"],
                    "approved_by": r["approved_by"],
                }
                for r in rows
            ]
    except Exception as e:
        print(f"enroll_requests_list error: {e}", flush=True)
        return []


def _next_agent_id(conn):
    existing_ids = set()
    for k in FLEET_AGENT_POLL_TOKENS.keys():
        if str(k).isdigit():
            existing_ids.add(int(k))
    try:
        for row in conn.execute("SELECT agent_id FROM enrolled_agents").fetchall():
            aid = str(row[0]).strip()
            if aid.isdigit():
                existing_ids.add(int(aid))
    except Exception:
        pass

    if existing_ids:
        next_val = max(existing_ids) + 1
    else:
        next_val = 4
    return f"{next_val:03d}"


def _enroll_request_approve(req_id, custom_agent_id=None, custom_name=None, approved_by="admin"):
    clean_id = str(req_id).strip()
    conn = sqlite3.connect(EVENTS_DB, timeout=10, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=10000")
    try:
        conn.execute("BEGIN IMMEDIATE")
        row = conn.execute(
            "SELECT * FROM agent_enrollment_requests WHERE id = ?", (clean_id,)
        ).fetchone()
        if not row:
            conn.execute("ROLLBACK")
            raise ValueError("Permohonan enrollment tidak ditemukan")
        if row["status"] != "pending":
            conn.execute("ROLLBACK")
            raise ValueError(f"Permohonan sudah berstatus '{row['status']}'")

        if custom_agent_id and _valid_agent_id(str(custom_agent_id).strip()):
            agent_id = str(custom_agent_id).strip()
        else:
            agent_id = _next_agent_id(conn)

        agent_name = (custom_name or f"agent-{row['hostname']}").strip()[:64]
        poll_token = secrets.token_hex(24)
        now_iso = datetime.now(WITA).isoformat()

        conn.execute(
            """INSERT OR REPLACE INTO enrolled_agents
            (agent_id, hostname, name, poll_token, os, ip, enrolled_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, 'active')""",
            (agent_id, row["hostname"], agent_name, poll_token, row["os"], row["ip"], now_iso),
        )

        conn.execute(
            """UPDATE agent_enrollment_requests
            SET status = 'approved', agent_id = ?, poll_token = ?, updated_at = ?, approved_by = ?
            WHERE id = ?""",
            (agent_id, poll_token, now_iso, approved_by, clean_id),
        )
        conn.execute("COMMIT")
        with _fleet_locks.STATE_LOCK:
            FLEET_AGENT_POLL_TOKENS[agent_id] = poll_token
    except Exception:
        try:
            conn.execute("ROLLBACK")
        except Exception:
            pass
        raise
    finally:
        conn.close()

    return {
        "request_id": clean_id,
        "status": "approved",
        "agent_id": agent_id,
        "agent_name": agent_name,
        "poll_token": poll_token,
        "approved_at": now_iso,
        "approved_by": approved_by,
    }


def _enroll_request_reject(req_id, rejected_by="admin"):
    clean_id = str(req_id).strip()
    with closing(_db()) as conn, conn:
        row = conn.execute(
            "SELECT * FROM agent_enrollment_requests WHERE id = ?", (clean_id,)
        ).fetchone()
        if not row:
            raise ValueError("Permohonan enrollment tidak ditemukan")
        if row["status"] != "pending":
            raise ValueError(f"Permohonan sudah berstatus '{row['status']}'")

        now_iso = datetime.now(WITA).isoformat()
        conn.execute(
            """UPDATE agent_enrollment_requests
            SET status = 'rejected', updated_at = ?, approved_by = ?
            WHERE id = ?""",
            (now_iso, rejected_by, clean_id),
        )

    return {"request_id": clean_id, "status": "rejected", "updated_at": now_iso}


def _enroll_agent_revoke(agent_id, revoked_by="admin", reason="", remove_heartbeat=False):
    aid = str(agent_id or "").strip()
    if not _valid_agent_id(aid):
        raise ValueError("agent_id tidak valid")
    now_iso = datetime.now(WITA).isoformat()
    found = False
    with _fleet_locks.STATE_LOCK:
        if aid in FLEET_AGENT_POLL_TOKENS:
            FLEET_AGENT_POLL_TOKENS.pop(aid, None)
            found = True
        if aid in HEARTBEATS:
            found = True
            if remove_heartbeat:
                HEARTBEATS.pop(aid, None)
            else:
                HEARTBEATS[aid]["last_seen"] = 0
                HEARTBEATS[aid]["revoked"] = True
            _save_state(force=True)
    with _fleet_locks.COMMANDS_LOCK:
        COMMANDS.pop(aid, None)

    try:
        with closing(_db()) as conn, conn:
            cur = conn.execute(
                "UPDATE enrolled_agents SET status = 'revoked' WHERE agent_id = ?",
                (aid,),
            )
            if cur.rowcount > 0:
                found = True
            conn.execute(
                """UPDATE agent_enrollment_requests
                   SET status = 'revoked', updated_at = ?, approved_by = ?
                   WHERE agent_id = ? AND status = 'approved'""",
                (now_iso, revoked_by, aid),
            )
            conn.execute(
                """UPDATE commands
                   SET status = 'expired', completed_at = ?, output = 'Agent token revoked'
                   WHERE agent_id = ? AND status = 'queued'""",
                (now_iso, aid),
            )
    except Exception as e:
        print(f"enroll_agent_revoke db error: {e}", flush=True)

    if not found:
        raise ValueError(f"Agent '{aid}' tidak ditemukan")

    return {
        "agent_id": aid,
        "status": "revoked",
        "revoked_at": now_iso,
        "revoked_by": revoked_by,
        "reason": str(reason or "").strip()[:256],
        "removed_from_roster": bool(remove_heartbeat),
    }


def _enroll_agent_rotate_token(agent_id, rotated_by="admin"):
    aid = str(agent_id or "").strip()
    if not _valid_agent_id(aid):
        raise ValueError("agent_id tidak valid")
    with _fleet_locks.STATE_LOCK:
        hb = dict(HEARTBEATS.get(aid) or {})
        in_tokens = aid in FLEET_AGENT_POLL_TOKENS

    db_row = None
    try:
        with closing(_db()) as conn:
            db_row = conn.execute(
                "SELECT * FROM enrolled_agents WHERE agent_id = ?", (aid,)
            ).fetchone()
    except Exception:
        pass

    if not (in_tokens or hb or db_row):
        raise ValueError(f"Agent '{aid}' tidak ditemukan")

    new_token = secrets.token_hex(24)
    now_iso = datetime.now(WITA).isoformat()
    hostname = (db_row["hostname"] if db_row else None) or hb.get("name") or f"agent-{aid}"
    name = (db_row["name"] if db_row else None) or hb.get("name") or f"agent-{aid}"
    os_name = (db_row["os"] if db_row else None) or hb.get("os") or "linux"
    ip_addr = (db_row["ip"] if db_row else None) or hb.get("ip") or ""

    with closing(_db()) as conn, conn:
        conn.execute(
            """INSERT INTO enrolled_agents
               (agent_id, hostname, name, poll_token, os, ip, enrolled_at, status)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'active')
               ON CONFLICT(agent_id) DO UPDATE SET
                   poll_token = excluded.poll_token,
                   status = 'active'""",
            (aid, hostname, name, new_token, os_name, ip_addr, now_iso),
        )

    with _fleet_locks.STATE_LOCK:
        FLEET_AGENT_POLL_TOKENS[aid] = new_token
        if aid in HEARTBEATS:
            HEARTBEATS[aid].pop("revoked", None)

    return {
        "agent_id": aid,
        "agent_name": name,
        "poll_token": new_token,
        "token_prefix": f"{new_token[:8]}...{new_token[-4:]}",
        "rotated_at": now_iso,
        "rotated_by": rotated_by,
    }


def _generate_linux_installer_script(server_origin):
    return _fleet_installers.generate_linux_installer_script(server_origin)


def _generate_macos_installer_script(server_origin):
    return _fleet_installers.generate_macos_installer_script(server_origin)


def _generate_windows_installer_script(server_origin):
    return _fleet_installers.generate_windows_installer_script(server_origin)


def _generate_linux_update_script(server_origin):
    return _fleet_installers.generate_linux_update_script(server_origin)


def _generate_macos_update_script(server_origin):
    return _fleet_installers.generate_macos_update_script(server_origin)


def _generate_windows_update_script(server_origin):
    return _fleet_installers.generate_windows_update_script(server_origin)

DEFAULT_AI_CONFIG = {
    "enabled": True,
    "provider": "google",
    "model": "gemini-2.5-flash",
    "temperature": 0.3,
    "max_tokens": 1500,
    "system_instruction": "You are a senior SOC analyst. Respond in formal Bahasa Indonesia. Write 2-3 concise sentences. Focus on immediate containment and severity.",
    "api_key": "",
    "custom_base_url": "",
    "primary_saved_key_id": "",
    "fallback_enabled": True,
    "fallback_provider": "pollinations",
    "fallback_model": "deepseek/deepseek-v4-flash",
    "fallback_api_key": "",
    "fallback_base_url": "",
    "fallback_saved_key_id": "",
    "saved_api_keys": [],
}

PROVIDER_ENV_KEYS = {
    "google": "GEMINI_API_KEY",
    "pollinations": "POLLINATIONS_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "experiential": "EXPERIENTIAL_API_KEY",
}


def _merge_ai_defaults(raw):
    merged = dict(DEFAULT_AI_CONFIG)
    if isinstance(raw, dict):
        merged.update(raw)
    if not isinstance(merged.get("saved_api_keys"), list):
        merged["saved_api_keys"] = []
    return merged


def _resolve_provider_env_key(provider):
    env_name = PROVIDER_ENV_KEYS.get(str(provider or "").strip().lower(), "")
    return os.environ.get(env_name, "").strip() if env_name else ""


def _find_saved_key(saved_keys, key_id):
    kid = str(key_id or "").strip()
    if not kid or not isinstance(saved_keys, list):
        return None
    for item in saved_keys:
        if isinstance(item, dict) and str(item.get("id", "")).strip() == kid:
            return item
    return None


def _sanitize_discovered_models(raw_models):
    if not isinstance(raw_models, list):
        return []
    cleaned = []
    seen = set()
    for m in raw_models[:400]:
        if not isinstance(m, dict):
            continue
        mid = str(m.get("id", "")).strip()
        if not mid or mid in seen:
            continue
        seen.add(mid)
        entry = {
            "id": mid,
            "label": str(m.get("label") or mid).strip(),
            "free": bool(m.get("free", False)),
            "chat_supported": bool(m.get("chat_supported", True)),
        }
        if m.get("context_window") is not None:
            try:
                entry["context_window"] = int(m["context_window"])
            except (TypeError, ValueError):
                pass
        cleaned.append(entry)
    return cleaned


def _sanitize_saved_key_entry(item, existing_by_id):
    if not isinstance(item, dict):
        return None
    kid = str(item.get("id") or "").strip() or f"key_{uuid.uuid4().hex[:10]}"
    prev = existing_by_id.get(kid, {})
    raw_in = str(item.get("api_key") or "").strip()
    if item.get("clear_api_key"):
        final_key = ""
    elif raw_in and "•" not in raw_in:
        final_key = raw_in
    else:
        final_key = str(prev.get("api_key") or "").strip()

    models = (
        _sanitize_discovered_models(item.get("models"))
        if "models" in item
        else _sanitize_discovered_models(prev.get("models", []))
    )
    return {
        "id": kid,
        "name": str(item.get("name") or prev.get("name") or "Saved Key").strip()[:80],
        "provider": str(item.get("provider") or prev.get("provider") or "google").strip().lower(),
        "model": str(item.get("model") or prev.get("model") or "").strip(),
        "base_url": str(item.get("base_url") if "base_url" in item else prev.get("base_url") or "").strip(),
        "api_key": final_key,
        "models": models,
        "models_updated_at": str(
            item.get("models_updated_at") if "models_updated_at" in item else prev.get("models_updated_at") or ""
        ).strip(),
    }


def _resolve_ai_key(inline_key, saved_key_id, stored_ai, slot_key_field="api_key", provider=""):
    s = str(inline_key or "").strip()
    if s and "•" not in s:
        return s
    saved = _find_saved_key((stored_ai or {}).get("saved_api_keys"), saved_key_id)
    if saved and str(saved.get("api_key") or "").strip():
        return str(saved["api_key"]).strip()
    if slot_key_field and stored_ai:
        slot_val = str(stored_ai.get(slot_key_field) or "").strip()
        if slot_val:
            return slot_val
    return _resolve_provider_env_key(provider)

DEFAULT_THREAT_INTEL_CONFIG = {
    "consensus_mode": "ensemble",
    "sources": {
        "virustotal": {
            "enabled": True,
            "min_engines_high": 5,
            "min_engines_critical": 20,
            "api_key": "",
        },
        "malwarebazaar": {
            "enabled": True,
            "auto_escalate": True,
            "api_key": "",
        },
        "alienvault_otx": {
            "enabled": True,
            "min_pulses": 1,
            "api_key": "",
        },
        "misp": {
            "enabled": True,
            "sync_osint": True,
        },
    },
    "cache_ttl": {
        "malicious_days": 7,
        "clean_hours": 24,
        "unknown_hours": 6,
    },
}


def _mask_secret(val):
    if not val or not isinstance(val, str):
        return ""
    val = val.strip()
    if len(val) <= 8:
        return "••••••••"
    return f"{val[:4]}••••••••{val[-4:]}"


def _init_default_settings(conn):
    try:
        now_iso = datetime.now(WITA).isoformat()
        row_ai = conn.execute("SELECT key FROM system_settings WHERE key = 'ai_config'").fetchone()
        if not row_ai:
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                ("ai_config", json.dumps(DEFAULT_AI_CONFIG), now_iso, "system_init"),
            )
        row_ti = conn.execute("SELECT key FROM system_settings WHERE key = 'threat_intel_config'").fetchone()
        if not row_ti:
            conn.execute(
                "INSERT INTO system_settings (key, value, updated_at, updated_by) VALUES (?, ?, ?, ?)",
                ("threat_intel_config", json.dumps(DEFAULT_THREAT_INTEL_CONFIG), now_iso, "system_init"),
            )
    except Exception as e:
        print(f"init_default_settings error: {e}", flush=True)


def _transform_settings_secrets(key, value, fn):
    if not isinstance(value, dict):
        return value
    copied = json.loads(json.dumps(value))
    if key == "ai_config":
        for f in ("api_key", "fallback_api_key"):
            if copied.get(f):
                copied[f] = fn(copied[f])
        for item in copied.get("saved_api_keys") or []:
            if isinstance(item, dict) and item.get("api_key"):
                item["api_key"] = fn(item["api_key"])
    elif key == "threat_intel_config":
        sources = copied.get("sources")
        if isinstance(sources, dict):
            for sval in sources.values():
                if isinstance(sval, dict) and sval.get("api_key"):
                    sval["api_key"] = fn(sval["api_key"])
    return copied


def _get_system_setting(key, default=None):
    try:
        with closing(_db()) as conn:
            row = conn.execute("SELECT value FROM system_settings WHERE key = ?", (key,)).fetchone()
            if row:
                parsed = json.loads(row[0])
                return _transform_settings_secrets(key, parsed, _fleet_sec.decrypt_secret)
    except Exception as e:
        print(f"get_system_setting error ({key}): {e}", flush=True)
    return default


def _set_system_setting(key, value, updated_by="admin"):
    now_iso = datetime.now(WITA).isoformat()
    secured = _transform_settings_secrets(key, value, _fleet_sec.encrypt_secret)
    val_str = json.dumps(secured)
    with closing(_db()) as conn, conn:
        conn.execute(
            """INSERT INTO system_settings (key, value, updated_at, updated_by)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
            value = excluded.value,
            updated_at = excluded.updated_at,
            updated_by = excluded.updated_by""",
            (key, val_str, now_iso, updated_by),
        )
    return True


def _get_masked_settings():
    ai = _merge_ai_defaults(_get_system_setting("ai_config", DEFAULT_AI_CONFIG))
    ti = _get_system_setting("threat_intel_config", DEFAULT_THREAT_INTEL_CONFIG)

    ai_safe = dict(ai)
    primary_key = (ai_safe.get("api_key") or "").strip() or _resolve_provider_env_key(ai_safe.get("provider"))
    ai_safe["has_api_key"] = bool(primary_key)
    ai_safe["api_key_masked"] = _mask_secret(primary_key)
    ai_safe["api_key"] = ai_safe["api_key_masked"]

    fb_key = (ai_safe.get("fallback_api_key") or "").strip() or _resolve_provider_env_key(ai_safe.get("fallback_provider"))
    ai_safe["has_fallback_api_key"] = bool(fb_key)
    ai_safe["fallback_api_key_masked"] = _mask_secret(fb_key)
    ai_safe["fallback_api_key"] = ai_safe["fallback_api_key_masked"]

    masked_saved = []
    for item in ai_safe.get("saved_api_keys") or []:
        if not isinstance(item, dict):
            continue
        raw_k = str(item.get("api_key") or "").strip()
        masked_k = _mask_secret(raw_k)
        masked_saved.append(
            {
                "id": str(item.get("id") or ""),
                "name": str(item.get("name") or "Saved Key"),
                "provider": str(item.get("provider") or "google"),
                "model": str(item.get("model") or ""),
                "base_url": str(item.get("base_url") or ""),
                "has_api_key": bool(raw_k),
                "api_key_masked": masked_k,
                "api_key": masked_k,
                "models": _sanitize_discovered_models(item.get("models") or []),
                "models_updated_at": str(item.get("models_updated_at") or ""),
            }
        )
    ai_safe["saved_api_keys"] = masked_saved

    ti_safe = json.loads(json.dumps(ti))
    sources = ti_safe.get("sources", {})
    if "virustotal" in sources:
        vt_key = sources["virustotal"].get("api_key") or os.environ.get("VIRUSTOTAL_API_KEY") or ""
        sources["virustotal"]["has_api_key"] = bool(vt_key)
        sources["virustotal"]["api_key_masked"] = _mask_secret(vt_key)
        sources["virustotal"]["api_key"] = sources["virustotal"]["api_key_masked"]

    if "malwarebazaar" in sources:
        mb_key = sources["malwarebazaar"].get("api_key") or os.environ.get("MALWAREBAZAAR_API_KEY") or ""
        sources["malwarebazaar"]["has_api_key"] = bool(mb_key)
        sources["malwarebazaar"]["api_key_masked"] = _mask_secret(mb_key)
        sources["malwarebazaar"]["api_key"] = sources["malwarebazaar"]["api_key_masked"]

    if "alienvault_otx" in sources:
        otx_key = sources["alienvault_otx"].get("api_key") or os.environ.get("OTX_API_KEY") or ""
        sources["alienvault_otx"]["has_api_key"] = bool(otx_key)
        sources["alienvault_otx"]["api_key_masked"] = _mask_secret(otx_key)
        sources["alienvault_otx"]["api_key"] = sources["alienvault_otx"]["api_key_masked"]

    return {
        "ai_config": ai_safe,
        "threat_intel_config": ti_safe,
    }


def _update_system_settings(payload, updated_by="admin"):
    curr_ai = _merge_ai_defaults(_get_system_setting("ai_config", DEFAULT_AI_CONFIG))
    curr_ti = _get_system_setting("threat_intel_config", DEFAULT_THREAT_INTEL_CONFIG)

    if "ai_config" in payload and isinstance(payload["ai_config"], dict):
        new_ai = payload["ai_config"]
        existing_saved = {
            str(k.get("id") or ""): k
            for k in (curr_ai.get("saved_api_keys") or [])
            if isinstance(k, dict) and k.get("id")
        }
        if "saved_api_keys" in new_ai and isinstance(new_ai["saved_api_keys"], list):
            next_saved = []
            for raw_item in new_ai["saved_api_keys"][:30]:
                cleaned_item = _sanitize_saved_key_entry(raw_item, existing_saved)
                if cleaned_item:
                    next_saved.append(cleaned_item)
            curr_ai["saved_api_keys"] = next_saved

        for field in (
            "enabled",
            "provider",
            "model",
            "temperature",
            "max_tokens",
            "system_instruction",
            "custom_base_url",
            "primary_saved_key_id",
            "fallback_enabled",
            "fallback_provider",
            "fallback_model",
            "fallback_base_url",
            "fallback_saved_key_id",
        ):
            if field in new_ai:
                curr_ai[field] = new_ai[field]

        if new_ai.get("clear_api_key"):
            curr_ai["api_key"] = ""
        elif "api_key" in new_ai and new_ai["api_key"] and "•" not in str(new_ai["api_key"]):
            curr_ai["api_key"] = str(new_ai["api_key"]).strip()
        elif new_ai.get("primary_saved_key_id"):
            saved_p = _find_saved_key(curr_ai.get("saved_api_keys"), new_ai.get("primary_saved_key_id"))
            if saved_p and saved_p.get("api_key"):
                curr_ai["api_key"] = saved_p["api_key"]

        if new_ai.get("clear_fallback_api_key"):
            curr_ai["fallback_api_key"] = ""
        elif "fallback_api_key" in new_ai and new_ai["fallback_api_key"] and "•" not in str(new_ai["fallback_api_key"]):
            curr_ai["fallback_api_key"] = str(new_ai["fallback_api_key"]).strip()
        elif new_ai.get("fallback_saved_key_id"):
            saved_fb = _find_saved_key(curr_ai.get("saved_api_keys"), new_ai.get("fallback_saved_key_id"))
            if saved_fb and saved_fb.get("api_key"):
                curr_ai["fallback_api_key"] = saved_fb["api_key"]

        _set_system_setting("ai_config", curr_ai, updated_by)

    if "threat_intel_config" in payload and isinstance(payload["threat_intel_config"], dict):
        new_ti = payload["threat_intel_config"]
        if "consensus_mode" in new_ti:
            curr_ti["consensus_mode"] = str(new_ti["consensus_mode"]).strip()
        if "cache_ttl" in new_ti and isinstance(new_ti["cache_ttl"], dict):
            curr_ti["cache_ttl"].update(new_ti["cache_ttl"])
        if "sources" in new_ti and isinstance(new_ti["sources"], dict):
            for sname, sval in new_ti["sources"].items():
                if sname in curr_ti.get("sources", {}) and isinstance(sval, dict):
                    target = curr_ti["sources"][sname]
                    for k, v in sval.items():
                        if k == "api_key":
                            if v and "•" not in str(v):
                                target["api_key"] = str(v).strip()
                        else:
                            target[k] = v
        _set_system_setting("threat_intel_config", curr_ti, updated_by)

    return _get_masked_settings()


_OPENAI_COMPAT_BASES = {
    "openai": "https://api.openai.com/v1",
    "pollinations": "https://gen.pollinations.ai/v1",
    "experiential": "https://api.experientiallabs.ai/v1",
}

_OPENAI_COMPAT_DEFAULTS = {
    "openai": "gpt-4o-mini",
    "pollinations": "deepseek/deepseek-v4-flash",
    "experiential": "gpt-6-luna:free",
}

_NON_CHAT_EXPERIENTIAL_MODELS = {
    "clef",
    "clef:free",
    "clef-flash",
    "gemini-decision-1",
    "gpt-6-luna-decisions",
    "gpt-6-luna-decisions:free",
    "jev-latest",
    "jev-latest:free",
}


def _format_http_error(exc, effective_key=""):
    detail = ""
    if isinstance(exc, urllib.error.HTTPError):
        try:
            body = exc.read().decode("utf-8", errors="replace")[:240]
            detail = f"HTTP {exc.code}: {body or exc.reason}"
        except Exception:
            detail = f"HTTP {exc.code}: {exc.reason}"
    else:
        detail = str(exc)
    if effective_key and len(effective_key) > 6:
        detail = detail.replace(effective_key, "[REDACTED]")
    return detail


def _invoke_ai_provider(
    provider,
    model_name,
    prompt,
    api_key=None,
    base_url=None,
    temperature=0.3,
    max_tokens=300,
    system_instruction=None,
):
    start_t = time.time()
    prov = str(provider or "google").strip().lower()
    model_id = str(model_name or "").strip()
    clean_prompt = prompt or "Uji inferensi model untuk triage keamanan SOAR"
    effective_key = (api_key or "").strip()
    if "•" in effective_key:
        effective_key = ""
    if not effective_key:
        effective_key = _resolve_provider_env_key(prov)
    clean_base = str(base_url or "").strip().rstrip("/")
    try:
        temp = max(0.0, min(2.0, float(temperature) if temperature is not None else 0.3))
    except (TypeError, ValueError):
        temp = 0.3
    try:
        tok = max(1, min(8192, int(max_tokens) if max_tokens is not None else 300))
    except (TypeError, ValueError):
        tok = 300
    sys_inst = str(system_instruction or "").strip()

    if prov == "google":
        if not effective_key:
            return {"success": False, "provider": prov, "model": model_id or "gemini-2.5-flash", "error": "API Key Google Gemini belum dikonfigurasi"}
        model_id = model_id or "gemini-2.5-flash"
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent"
        try:
            _fleet_sec.validate_outbound_url(url)
        except ValueError as ve:
            return {"success": False, "provider": prov, "model": model_id, "error": str(ve)}
        body_data = {
            "contents": [{"parts": [{"text": clean_prompt}]}],
            "generationConfig": {"temperature": temp, "maxOutputTokens": tok},
        }
        if sys_inst:
            body_data["systemInstruction"] = {"parts": [{"text": sys_inst}]}
        req = urllib.request.Request(
            url,
            data=json.dumps(body_data).encode("utf-8"),
            headers={"Content-Type": "application/json", "x-goog-api-key": effective_key},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                parts = res_json.get("candidates", [{}])[0].get("content", {}).get("parts", [{}])
                text = "".join(str(p.get("text", "")) for p in parts if isinstance(p, dict))
                latency = int((time.time() - start_t) * 1000)
                if not text.strip():
                    AI_CIRCUIT_BREAKER.record_failure(prov, "empty response")
                    return {"success": False, "provider": prov, "model": model_id, "error": "Gemini mengembalikan respons kosong"}
                AI_CIRCUIT_BREAKER.record_success(prov)
                return {
                    "success": True,
                    "model": model_id,
                    "provider": "google",
                    "latency_ms": latency,
                    "response": text.strip(),
                }
        except Exception as e:
            err_msg = _format_http_error(e, effective_key)
            immediate = isinstance(e, urllib.error.HTTPError) and e.code in (401, 402, 403)
            AI_CIRCUIT_BREAKER.record_failure(prov, err_msg, immediate_open=immediate)
            return {"success": False, "provider": prov, "model": model_id, "error": f"Gemini error: {err_msg}"}

    if prov == "anthropic":
        if not effective_key:
            return {"success": False, "provider": prov, "model": model_id or "claude-3-5-sonnet-latest", "error": "API Key Anthropic Claude belum dikonfigurasi"}
        model_id = model_id or "claude-3-5-sonnet-latest"
        url = f"{clean_base}/messages" if clean_base else "https://api.anthropic.com/v1/messages"
        try:
            _fleet_sec.validate_outbound_url(url)
        except ValueError as ve:
            return {"success": False, "provider": prov, "model": model_id, "error": str(ve)}
        body_data = {
            "model": model_id,
            "max_tokens": tok,
            "temperature": temp,
            "messages": [{"role": "user", "content": clean_prompt}],
        }
        if sys_inst:
            body_data["system"] = sys_inst
        req = urllib.request.Request(
            url,
            data=json.dumps(body_data).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "x-api-key": effective_key,
                "anthropic-version": "2023-06-01",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                blocks = res_json.get("content", [])
                text = "".join(str(b.get("text", "")) for b in blocks if isinstance(b, dict) and b.get("type") == "text")
                latency = int((time.time() - start_t) * 1000)
                if not text.strip():
                    AI_CIRCUIT_BREAKER.record_failure(prov, "empty response")
                    return {"success": False, "provider": prov, "model": model_id, "error": "Anthropic mengembalikan respons kosong"}
                AI_CIRCUIT_BREAKER.record_success(prov)
                return {
                    "success": True,
                    "model": model_id,
                    "provider": "anthropic",
                    "latency_ms": latency,
                    "response": text.strip(),
                }
        except Exception as e:
            err_msg = _format_http_error(e, effective_key)
            immediate = isinstance(e, urllib.error.HTTPError) and e.code in (401, 402, 403)
            AI_CIRCUIT_BREAKER.record_failure(prov, err_msg, immediate_open=immediate)
            return {"success": False, "provider": prov, "model": model_id, "error": f"Anthropic error: {err_msg}"}

    if prov in _OPENAI_COMPAT_BASES or (prov == "custom" and clean_base):
        if prov in ("openai", "experiential") and not effective_key:
            label = "OpenAI" if prov == "openai" else "Experiential Labs"
            return {"success": False, "provider": prov, "model": model_id or _OPENAI_COMPAT_DEFAULTS[prov], "error": f"API Key {label} belum dikonfigurasi"}
        model_id = model_id or _OPENAI_COMPAT_DEFAULTS.get(prov, "default-model")
        endpoint_base = clean_base or _OPENAI_COMPAT_BASES.get(prov, "")
        url = endpoint_base if endpoint_base.endswith("/chat/completions") else f"{endpoint_base}/chat/completions"
        try:
            _fleet_sec.validate_outbound_url(url)
        except ValueError as ve:
            return {"success": False, "provider": prov, "model": model_id, "error": str(ve)}
        headers = {"Content-Type": "application/json", "User-Agent": "soar-fleet-monitor/1.0"}
        if effective_key:
            headers["Authorization"] = f"Bearer {effective_key}"
        messages = []
        if sys_inst:
            messages.append({"role": "system", "content": sys_inst})
        messages.append({"role": "user", "content": clean_prompt})
        body_data = {
            "model": model_id,
            "max_tokens": tok,
            "temperature": temp,
            "messages": messages,
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(body_data).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=25) as resp:
                res_json = json.loads(resp.read().decode("utf-8"))
                msg = res_json.get("choices", [{}])[0].get("message", {})
                text = (msg.get("content") if isinstance(msg, dict) else "") or ""
                latency = int((time.time() - start_t) * 1000)
                if not str(text).strip():
                    AI_CIRCUIT_BREAKER.record_failure(prov, "empty response")
                    return {"success": False, "provider": prov, "model": model_id, "error": f"{prov} mengembalikan respons kosong"}
                AI_CIRCUIT_BREAKER.record_success(prov)
                return {
                    "success": True,
                    "model": model_id,
                    "provider": prov,
                    "latency_ms": latency,
                    "response": str(text).strip(),
                }
        except Exception as e:
            err_msg = _format_http_error(e, effective_key)
            immediate = isinstance(e, urllib.error.HTTPError) and e.code in (401, 402, 403)
            AI_CIRCUIT_BREAKER.record_failure(prov, err_msg, immediate_open=immediate)
            return {"success": False, "provider": prov, "model": model_id, "error": f"{prov} error: {err_msg}"}

    # Custom tanpa base URL: mode simulasi lokal untuk pengujian offline
    return {
        "success": True,
        "model": model_id or "custom-local",
        "provider": prov,
        "latency_ms": 12,
        "response": f"Simulasi respons inferensi berhasil untuk model '{model_id}' (Provider: {prov}). Analisis kontekstual siap beroperasi.",
    }


def _fetch_provider_models(provider, api_key=None, base_url=None, saved_key_id=None, slot=None):
    prov = str(provider or "google").strip().lower()
    stored_ai = _merge_ai_defaults(_get_system_setting("ai_config", DEFAULT_AI_CONFIG))
    slot_field = ""
    if slot == "primary" and stored_ai.get("provider") == prov:
        slot_field = "api_key"
    elif slot == "fallback" and stored_ai.get("fallback_provider") == prov:
        slot_field = "fallback_api_key"
    clean_base = str(base_url or "").strip().rstrip("/")
    using_stored_secret = bool(saved_key_id or slot_field) and not (api_key and "•" not in str(api_key))
    if clean_base and using_stored_secret and not _fleet_sec.provider_host_allows_stored_key(prov, clean_base):
        return {
            "success": False,
            "provider": prov,
            "error": "Ditolak: stored API key tidak boleh dikirim ke custom base_url di luar host resmi provider",
        }
    effective_key = _resolve_ai_key(api_key, saved_key_id, stored_ai, slot_field, prov)

    if prov == "google":
        if not effective_key:
            return {"success": False, "provider": prov, "error": "API Key Google Gemini diperlukan untuk memuat daftar model"}
        url = "https://generativelanguage.googleapis.com/v1beta/models"
        try:
            _fleet_sec.validate_outbound_url(url)
        except ValueError as ve:
            return {"success": False, "provider": prov, "error": str(ve)}
        req = urllib.request.Request(
            url,
            headers={"Accept": "application/json", "x-goog-api-key": effective_key},
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            models = []
            for m in data.get("models", []):
                methods = m.get("supportedGenerationMethods") or []
                if "generateContent" not in methods:
                    continue
                raw_name = str(m.get("name", ""))
                mid = raw_name[7:] if raw_name.startswith("models/") else raw_name
                if not mid:
                    continue
                disp = str(m.get("displayName") or mid).strip()
                models.append(
                    {
                        "id": mid,
                        "label": f"{mid} ({disp})" if disp and disp != mid else mid,
                        "free": False,
                        "chat_supported": True,
                        "context_window": m.get("inputTokenLimit"),
                    }
                )
            models.sort(key=lambda x: x["id"])
            return {"success": True, "provider": prov, "models": models, "total": len(models), "free_count": 0}
        except Exception as e:
            return {"success": False, "provider": prov, "error": f"Gagal memuat model Google: {_format_http_error(e, effective_key)}"}

    if prov == "anthropic":
        if not effective_key:
            return {"success": False, "provider": prov, "error": "API Key Anthropic diperlukan untuk memuat daftar model"}
        base = clean_base or "https://api.anthropic.com/v1"
        url = f"{base}/models"
        try:
            _fleet_sec.validate_outbound_url(url)
        except ValueError as ve:
            return {"success": False, "provider": prov, "error": str(ve)}
        req = urllib.request.Request(
            url,
            headers={
                "Accept": "application/json",
                "x-api-key": effective_key,
                "anthropic-version": "2023-06-01",
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            models = []
            for m in data.get("data", []):
                mid = str(m.get("id", "")).strip()
                if not mid:
                    continue
                disp = str(m.get("display_name") or mid).strip()
                models.append(
                    {
                        "id": mid,
                        "label": f"{mid} ({disp})" if disp and disp != mid else mid,
                        "free": False,
                        "chat_supported": True,
                    }
                )
            models.sort(key=lambda x: x["id"])
            return {"success": True, "provider": prov, "models": models, "total": len(models), "free_count": 0}
        except Exception as e:
            return {"success": False, "provider": prov, "error": f"Gagal memuat model Anthropic: {_format_http_error(e, effective_key)}"}

    if prov in _OPENAI_COMPAT_BASES or (prov == "custom" and clean_base):
        if prov in ("openai", "experiential") and not effective_key:
            label = "OpenAI" if prov == "openai" else "Experiential Labs"
            return {"success": False, "provider": prov, "error": f"API Key {label} diperlukan untuk memuat daftar model"}
        endpoint_base = clean_base or _OPENAI_COMPAT_BASES.get(prov, "")
        if endpoint_base.endswith("/chat/completions"):
            endpoint_base = endpoint_base[: -len("/chat/completions")]
        url = endpoint_base if endpoint_base.endswith("/models") else f"{endpoint_base}/models"
        try:
            _fleet_sec.validate_outbound_url(url)
        except ValueError as ve:
            return {"success": False, "provider": prov, "error": str(ve)}
        headers = {"Accept": "application/json", "User-Agent": "soar-fleet-monitor/1.0"}
        if effective_key:
            headers["Authorization"] = f"Bearer {effective_key}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            raw_list = data.get("data") if isinstance(data, dict) else data
            if not isinstance(raw_list, list):
                raw_list = []
            models = []
            for m in raw_list:
                if not isinstance(m, dict):
                    continue
                mid = str(m.get("id") or m.get("name") or "").strip()
                if not mid:
                    continue
                pricing = m.get("pricing") if isinstance(m.get("pricing"), dict) else {}
                in_nano = pricing.get("input_nano_usd_per_million_tokens")
                out_nano = pricing.get("output_nano_usd_per_million_tokens")
                is_free = (
                    (in_nano == 0 and out_nano == 0)
                    or ":free" in mid.lower()
                    or bool(m.get("is_free"))
                )
                chat_ok = True
                if m.get("supports_completions") is False or (
                    prov == "experiential" and mid.lower() in _NON_CHAT_EXPERIENTIAL_MODELS
                ):
                    chat_ok = False
                ctx = m.get("context_window_tokens") or m.get("context_length")
                tag = ""
                if is_free and not chat_ok:
                    tag = " [Free - Non-Chat]"
                elif is_free:
                    tag = " [FREE]"
                elif not chat_ok:
                    tag = " [Non-Chat]"
                models.append(
                    {
                        "id": mid,
                        "label": f"{mid}{tag}",
                        "free": bool(is_free),
                        "chat_supported": chat_ok,
                        "context_window": ctx,
                    }
                )
            models.sort(key=lambda x: (not (x["free"] and x["chat_supported"]), not x["free"], not x["chat_supported"], x["id"]))
            free_count = sum(1 for x in models if x["free"])
            return {"success": True, "provider": prov, "models": models, "total": len(models), "free_count": free_count}
        except Exception as e:
            return {"success": False, "provider": prov, "error": f"Gagal memuat model {prov}: {_format_http_error(e, effective_key)}"}

    return {"success": False, "provider": prov, "error": "Isi Base URL Endpoint untuk memuat daftar model dari Custom Endpoint"}


def _test_ai_inference(
    provider,
    model_name,
    prompt="Tes analisis SOC",
    api_key=None,
    base_url=None,
    fallback_config=None,
    temperature=0.3,
    max_tokens=300,
    system_instruction=None,
    target="primary",
    saved_key_id=None,
):
    stored_ai = _merge_ai_defaults(_get_system_setting("ai_config", DEFAULT_AI_CONFIG))

    if target == "fallback":
        fb = fallback_config if isinstance(fallback_config, dict) else {}
        fb_prov = fb.get("provider") or stored_ai.get("fallback_provider") or "pollinations"
        fb_model = fb.get("model") or stored_ai.get("fallback_model") or "deepseek/deepseek-v4-flash"
        fb_slot = "fallback_api_key" if stored_ai.get("fallback_provider") == fb_prov else ""
        fb_base = fb.get("base_url") if fb.get("base_url") is not None else stored_ai.get("fallback_base_url")
        if fb_base and not (fb.get("api_key") and "•" not in str(fb.get("api_key"))) and not _fleet_sec.provider_host_allows_stored_key(fb_prov, fb_base):
            if fb_base != stored_ai.get("fallback_base_url"):
                return {"success": False, "provider": fb_prov, "model": fb_model, "error": "Ditolak: stored API key tidak boleh dikirim ke custom base_url asing"}
        fb_key = _resolve_ai_key(fb.get("api_key"), fb.get("saved_key_id"), stored_ai, fb_slot, fb_prov)
        return _invoke_ai_provider(
            fb_prov,
            fb_model,
            prompt,
            api_key=fb_key,
            base_url=fb_base,
            temperature=temperature,
            max_tokens=max_tokens,
            system_instruction=system_instruction,
        )

    p_slot = "api_key" if stored_ai.get("provider") == provider else ""
    eff_base = base_url if base_url is not None else stored_ai.get("custom_base_url")
    if base_url and not (api_key and "•" not in str(api_key)) and not _fleet_sec.provider_host_allows_stored_key(provider, base_url):
        if str(base_url).strip().rstrip("/") != str(stored_ai.get("custom_base_url") or "").strip().rstrip("/"):
            return {"success": False, "provider": provider, "model": model_name, "error": "Ditolak: stored API key tidak boleh dikirim ke custom base_url asing"}
    eff_key = _resolve_ai_key(api_key, saved_key_id, stored_ai, p_slot, provider)

    if target == "auto" and AI_CIRCUIT_BREAKER.is_open(provider):
        primary_res = {
            "success": False,
            "provider": provider,
            "model": model_name,
            "error": "Primary provider sedang dalam cooldown circuit breaker",
        }
    else:
        primary_res = _invoke_ai_provider(
            provider,
            model_name,
            prompt,
            api_key=eff_key,
            base_url=eff_base,
            temperature=temperature,
            max_tokens=max_tokens,
            system_instruction=system_instruction,
        )
    if primary_res.get("success") or target != "auto":
        return primary_res

    fb = fallback_config if isinstance(fallback_config, dict) else {}
    fb_enabled = fb.get("enabled") if "enabled" in fb else stored_ai.get("fallback_enabled", True)
    if not fb_enabled:
        return primary_res

    fb_prov = fb.get("provider") or stored_ai.get("fallback_provider") or "pollinations"
    fb_model = fb.get("model") or stored_ai.get("fallback_model") or "deepseek/deepseek-v4-flash"
    fb_slot = "fallback_api_key" if stored_ai.get("fallback_provider") == fb_prov else ""
    fb_key = _resolve_ai_key(fb.get("api_key"), fb.get("saved_key_id"), stored_ai, fb_slot, fb_prov)
    fb_base = fb.get("base_url") if fb.get("base_url") is not None else stored_ai.get("fallback_base_url")
    fb_res = _invoke_ai_provider(
        fb_prov,
        fb_model,
        prompt,
        api_key=fb_key,
        base_url=fb_base,
        temperature=temperature,
        max_tokens=max_tokens,
        system_instruction=system_instruction,
    )
    if fb_res.get("success"):
        fb_res["used_fallback"] = True
        fb_res["primary_error"] = primary_res.get("error")
        return fb_res
    return {
        "success": False,
        "provider": provider,
        "model": model_name,
        "error": f"Primary gagal ({primary_res.get('error')}) | Fallback gagal ({fb_res.get('error')})",
    }


def _indexer_enabled():
    return bool(INDEXER_PASS)


def _to_indexer_time(value):
    if not value:
        return None
    v = str(value).strip()
    if re.fullmatch(r"\d{10,13}", v):
        return _to_utc_iso(v)
    return v  # ISO; indexer paham


_INDEXER_Q_FIELDS = (
    "syscheck.path",
    "data.path",
    "data.sha256_after",
    "data.sha256",
    "data.url",
    "agent.name",
    "rule.description",
)


def _indexer_severity_clause(severity):
    """Filter severity di sisi indexer (level Wazuh), bukan setelah fetch."""
    ranges = []
    for s in {str(x).upper() for x in (severity or [])}:
        if s == "CRITICAL":
            ranges.append({"range": {"rule.level": {"gte": 12}}})
        elif s == "HIGH":
            ranges.append({"range": {"rule.level": {"gte": 7, "lt": 12}}})
        elif s == "MEDIUM":
            ranges.append({"range": {"rule.level": {"gte": 5, "lt": 7}}})
        elif s == "INFO":
            ranges.append({"range": {"rule.level": {"lt": 5}}})
    if not ranges:
        return {"match_none": {}}
    return {"bool": {"should": ranges, "minimum_should_match": 1}}


def _indexer_filter_clauses(since, until, agent_id=None, q=None):
    clauses = [
        {
            "range": {
                "@timestamp": {
                    "gte": since or "now-90d",
                    "lte": until or "now",
                }
            }
        }
    ]
    if agent_id:
        clauses.append({"term": {"agent.id": str(agent_id)}})
    for token in q or []:
        t = str(token).strip().replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")
        if not t:
            continue
        clauses.append(
            {
                "bool": {
                    "should": [
                        {
                            "wildcard": {
                                field: {
                                    "value": f"*{t}*",
                                    "case_insensitive": True,
                                }
                            }
                        }
                        for field in _INDEXER_Q_FIELDS
                    ],
                    "minimum_should_match": 1,
                }
            }
        )
    return clauses


def _indexer_search_body(since, until, size, severity=None, agent_id=None, q=None):
    must = [_indexer_severity_clause(severity)] if severity else []
    return {
        "size": max(1, min(size, INDEXER_SEARCH_MAX)),
        "track_total_hits": True,
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
        "query": {
            "bool": {
                "filter": _indexer_filter_clauses(since, until, agent_id, q),
                "must": must,
            }
        },
        "_source": [
            "@timestamp",
            "timestamp",
            "rule",
            "agent",
            "syscheck",
            "data",
            "location",
        ],
    }


def _indexer_stats_body(since, until, agent_id=None, q=None):
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {
            "bool": {"filter": _indexer_filter_clauses(since, until, agent_id, q)}
        },
        "aggs": {
            "severity": {
                "filters": {
                    "filters": {
                        "CRITICAL": {"range": {"rule.level": {"gte": 12}}},
                        "HIGH": {"range": {"rule.level": {"gte": 7, "lt": 12}}},
                        "MEDIUM": {"range": {"rule.level": {"gte": 5, "lt": 7}}},
                        "INFO": {"range": {"rule.level": {"lt": 5}}},
                    }
                }
            },
            "daily": {
                "date_histogram": {
                    "field": "@timestamp",
                    "calendar_interval": "day",
                    "time_zone": "+08:00",
                    "format": "yyyy-MM-dd",
                    "min_doc_count": 1,
                }
            },
            "top_agents": {"terms": {"field": "agent.name", "size": 5}},
            "top_paths": {"terms": {"field": "syscheck.path", "size": 5}},
        },
    }


def _indexer_post(body):
    auth = base64.b64encode(f"{INDEXER_USER}:{INDEXER_PASS}".encode()).decode()
    req = urllib.request.Request(
        f"{INDEXER_URL}/{INDEXER_INDEX}/_search",
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=15, context=_INSECURE) as r:
        return json.load(r)


def _indexer_search_full(since, until, size, severity=None, agent_id=None, q=None):
    """POST _search; kembalikan (hits, ok, total_cocok_di_indexer)."""
    try:
        resp = _indexer_post(
            _indexer_search_body(since, until, size, severity, agent_id, q)
        )
        hits = resp.get("hits", {})
        total = hits.get("total", 0)
        if isinstance(total, dict):
            total = total.get("value", 0)
        return hits.get("hits", []), True, int(total or 0)
    except Exception as e:
        print(f"indexer search error: {e}", flush=True)
        return [], False, None


def _indexer_search(since, until, size, severity=None, agent_id=None, q=None):
    """POST _search rentang @timestamp. Kembalikan (hits, ok). Gagal -> ([], False)."""
    hits, ok, _ = _indexer_search_full(
        since, until, size, severity, agent_id, q
    )
    return hits, ok


def _indexer_stats(since, until, agent_id=None, q=None):
    """Agregasi severity/harian/top dari indexer (akurat, tanpa batas 1000 dok)."""
    try:
        aggs = _indexer_post(_indexer_stats_body(since, until, agent_id, q)).get(
            "aggregations", {}
        )
        sev = aggs.get("severity", {}).get("buckets", {})
        severity = {
            name: int(sev.get(name, {}).get("doc_count", 0))
            for name in ("CRITICAL", "HIGH", "MEDIUM", "INFO")
        }
        severity["UNVERIFIED"] = 0
        daily = [
            {
                "date": (b.get("key_as_string") or "")[:10],
                "count": int(b.get("doc_count", 0)),
            }
            for b in aggs.get("daily", {}).get("buckets", [])
            if b.get("key_as_string")
        ]
        top_agents = [
            {"key": b.get("key"), "count": int(b.get("doc_count", 0))}
            for b in aggs.get("top_agents", {}).get("buckets", [])
        ]
        top_paths = [
            {"key": b.get("key"), "count": int(b.get("doc_count", 0))}
            for b in aggs.get("top_paths", {}).get("buckets", [])
        ]
        return {
            "severity": severity,
            "daily": daily,
            "top_agents": top_agents,
            "top_paths": top_paths,
        }, True
    except Exception as e:
        print(f"indexer stats error: {e}", flush=True)
        return None, False


def _indexer_map(hit):
    """Petakan dokumen alert Wazuh -> bentuk FleetEvent (dengan rule_*)."""
    s = hit.get("_source", {}) or {}
    rule = s.get("rule", {}) or {}
    agent = s.get("agent", {}) or {}
    syscheck = s.get("syscheck", {}) or {}
    data = s.get("data", {}) or {}
    try:
        level = int(rule.get("level", 0))
    except (TypeError, ValueError):
        level = 0
    severity = (
        "CRITICAL"
        if level >= 12
        else "HIGH"
        if level >= 7
        else "MEDIUM"
        if level >= 5
        else "INFO"
    )
    h = (
        syscheck.get("sha256_after")
        or syscheck.get("sha256_before")
        or data.get("sha256_after")
        or data.get("sha256")
        or syscheck.get("md5_after")
        or data.get("md5")
        or ""
    )
    return {
        "id": str(hit.get("_id") or uuid.uuid4().hex),
        "ts": _to_utc_iso(s.get("@timestamp") or s.get("timestamp") or ""),
        "agent": agent.get("name", "-"),
        "agent_id": str(agent.get("id", "-")),
        "path": syscheck.get("path") or data.get("path") or "-",
        "hash": h,
        "severity": severity,
        "status": syscheck.get("event") or rule.get("description", "-"),
        "ai": "",
        "url": data.get("url", ""),
        "verdict": "",
        "rule_id": str(rule.get("id", "")),
        "rule_level": level,
        "rule_desc": rule.get("description", ""),
        "source": "wazuh",
        "size": syscheck.get("size_after") or syscheck.get("size_before") or data.get("size") or "",
        "perm": syscheck.get("perm_after") or syscheck.get("perm_before") or data.get("perm") or "",
        "uname": syscheck.get("uname_after") or syscheck.get("uname_before") or data.get("uname") or "",
        "uid": str(syscheck.get("uid_after") if syscheck.get("uid_after") is not None else syscheck.get("uid_before") or data.get("uid") or ""),
        "gname": syscheck.get("gname_after") or syscheck.get("gname_before") or data.get("gname") or "",
        "gid": str(syscheck.get("gid_after") if syscheck.get("gid_after") is not None else syscheck.get("gid_before") or data.get("gid") or ""),
        "mtime": _to_utc_iso(syscheck.get("mtime_after") or syscheck.get("mtime_before") or data.get("mtime") or ""),
        "inode": str(syscheck.get("inode_after") if syscheck.get("inode_after") is not None else syscheck.get("inode_before") or data.get("inode") or ""),
        "md5": syscheck.get("md5_after") or syscheck.get("md5_before") or data.get("md5") or "",
        "sha1": syscheck.get("sha1_after") or syscheck.get("sha1_before") or data.get("sha1") or "",
    }


def _ts_epoch(value):
    """ISO/epoch -> epoch detik; None bila tidak bisa diparse."""
    v = str(value or "").strip()
    if not v:
        return None
    try:
        if re.fullmatch(r"\d{10,13}", v):
            n = int(v)
            return n / 1000 if n > 10**12 else float(n)
        s = v.replace("Z", "+00:00")
        m = re.search(r"([+-]\d{2})(\d{2})$", s)
        if m and ":" not in s[-6:]:
            s = s[:-5] + m.group(1) + ":" + m.group(2)
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return None


def _merge_history(soar_rows, wazuh_rows, dedup=True):
    """Gabung event SOAR + alert Wazuh, buang Wazuh yang sudah ter-enrich SOAR.

    Dedup path hanya untuk event dalam jarak 1 jam dari event SOAR. Sebelumnya
    satu event SOAR menghapus semua alert Wazuh dengan path sama sepanjang 90
    hari, sehingga riwayat FIM hilang.
    """
    if not dedup:
        return list(soar_rows) + list(wazuh_rows)
    hashes = set()
    path_times = {}
    for e in soar_rows:
        aid = e.get("agent_id")
        if e.get("hash"):
            hashes.add((aid, str(e["hash"]).lower()))
        p = e.get("path")
        if p and p not in ("", "-"):
            t = _ts_epoch(e.get("ts"))
            if t is not None:
                path_times.setdefault((aid, p), []).append(t)
    kept = []
    for e in wazuh_rows:
        if e.get("hash") and (e.get("agent_id"), str(e["hash"]).lower()) in hashes:
            continue
        p = e.get("path")
        if p and p not in ("", "-"):
            t = _ts_epoch(e.get("ts"))
            near = path_times.get((e.get("agent_id"), p), [])
            if t is not None and any(abs(t - s) <= 3600 for s in near):
                continue
        kept.append(e)
    return list(soar_rows) + kept


def _merge_stats(*stats_items):
    """Gabung beberapa HistoryStats (SOAR + Wazuh) tanpa kehilangan bucket."""
    severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "UNVERIFIED": 0, "INFO": 0}
    daily = {}
    agents = {}
    paths = {}
    for stats in stats_items:
        if not stats:
            continue
        for k, v in (stats.get("severity") or {}).items():
            if k in severity:
                severity[k] += int(v or 0)
        for d in stats.get("daily") or []:
            key = d.get("date")
            if key:
                daily[key] = daily.get(key, 0) + int(d.get("count") or 0)
        for a in stats.get("top_agents") or []:
            key = a.get("key") or "-"
            agents[key] = agents.get(key, 0) + int(a.get("count") or 0)
        for p in stats.get("top_paths") or []:
            key = p.get("key")
            if key and key != "-":
                paths[key] = paths.get(key, 0) + int(p.get("count") or 0)

    def top(counts):
        pairs = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        return [{"key": k, "count": n} for k, n in pairs]

    return {
        "severity": severity,
        "daily": [{"date": k, "count": daily[k]} for k in sorted(daily)],
        "top_agents": top(agents),
        "top_paths": top(paths),
    }


def _wita_day(value):
    """Tanggal WITA (UTC+8) untuk konsistensi dengan tampilan UI."""
    t = _ts_epoch(value)
    if t is None:
        return str(value or "")[:10]
    return datetime.fromtimestamp(t, tz=WITA).date().isoformat()


def _history_stats(events):
    severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "UNVERIFIED": 0, "INFO": 0}
    daily = {}
    agents = {}
    paths = {}
    for e in events:
        s = (e.get("severity") or "INFO").upper()
        severity[s if s in severity else "INFO"] += 1
        day = _wita_day(e.get("ts"))
        if day:
            daily[day] = daily.get(day, 0) + 1
        name = e.get("agent") or "-"
        agents[name] = agents.get(name, 0) + 1
        p = e.get("path")
        if p and p != "-":
            paths[p] = paths.get(p, 0) + 1

    def top(counts):
        pairs = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:5]
        return [{"key": k, "count": n} for k, n in pairs]

    return {
        "severity": severity,
        "daily": [{"date": k, "count": daily[k]} for k in sorted(daily)],
        "top_agents": top(agents),
        "top_paths": top(paths),
    }


def _parse_csv(value):
    return [v.strip().upper() for v in (value or "").split(",") if v.strip()]


def build_event_history(
    since=None,
    until=None,
    limit=None,
    offset=0,
    severity=None,
    agent_id=None,
    q=None,
    source="all",
    dedup=True,
):
    """Riwayat event gabungan (SOAR SQLite + Wazuh Indexer) untuk rentang waktu."""
    started = time.time()
    try:
        limit = int(limit) if limit else HISTORY_DEFAULT_LIMIT
    except (TypeError, ValueError):
        limit = HISTORY_DEFAULT_LIMIT
    limit = max(1, min(limit, HISTORY_MAX_LIMIT))
    try:
        offset = max(0, int(offset or 0))
    except (TypeError, ValueError):
        offset = 0
    source = source if source in ("all", "soar", "wazuh") else "all"

    # SOAR: ambil tanpa filter severity agar stats tetap menunjukkan semua level.
    soar_rows = []
    if source in ("all", "soar"):
        soar_rows = _event_store_query(since, until, None, agent_id, q)
    soar_stats = _history_stats(soar_rows)

    # Wazuh: search sudah difilter (severity/agent/q) supaya event lama yang
    # relevan tidak tertutup 1000 dokumen terbaru. Stats memakai agregasi.
    wazuh_rows = []
    wazuh_stats = None
    indexer_ok = None
    indexer_matched = None
    if source in ("all", "wazuh") and _indexer_enabled():
        wazuh_stats, stats_ok = _indexer_stats(
            _to_indexer_time(since), _to_indexer_time(until), agent_id, q
        )
        hits, indexer_ok, indexer_matched = _indexer_search_full(
            _to_indexer_time(since),
            _to_indexer_time(until),
            INDEXER_SEARCH_MAX,
            severity,
            agent_id,
            q,
        )
        wazuh_rows = [_indexer_map(h) for h in hits]
        # Post-filter tetap dipertahankan untuk kompatibilitas indexer lama.
        if agent_id:
            wazuh_rows = [e for e in wazuh_rows if e.get("agent_id") == str(agent_id)]
        tokens = [t.lower() for t in (q or [])]
        if tokens:
            wazuh_rows = [
                e
                for e in wazuh_rows
                if all(
                    t
                    in " ".join(
                        str(e.get(k, ""))
                        for k in ("path", "hash", "url", "agent", "rule_desc")
                    ).lower()
                    for t in tokens
                )
            ]
        if severity:
            sev_set = {s.upper() for s in severity}
            wazuh_rows = [
                e
                for e in wazuh_rows
                if (e.get("severity") or "INFO").upper() in sev_set
            ]
        if not stats_ok:
            fallback_hits, _ = _indexer_search(
                _to_indexer_time(since),
                _to_indexer_time(until),
                INDEXER_SEARCH_MAX,
                None,
                agent_id,
                q,
            )
            wazuh_stats = _history_stats([_indexer_map(h) for h in fallback_hits])

    merged_all = _merge_history(soar_rows, wazuh_rows, dedup)
    merged_all.sort(key=lambda e: e.get("ts") or "", reverse=True)

    # Stats gabungan: SOAR dihitung dari baris, Wazuh dari agregasi indexer.
    stats = _merge_stats(soar_stats, wazuh_stats)

    # Filter keparahan juga diterapkan ke daftar SOAR (pagination + total).
    if severity:
        sev_set = {s.upper() for s in severity}
        filtered = [
            e for e in merged_all if (e.get("severity") or "INFO").upper() in sev_set
        ]
    else:
        filtered = merged_all

    page_events = _fleet_soc.enrich_events_with_triage(_db, filtered[offset : offset + limit])
    return {
        "events": page_events,
        "total": len(filtered),
        "limit": limit,
        "offset": offset,
        "took_ms": int((time.time() - started) * 1000),
        "indexer_ok": indexer_ok,
        "indexer_matched": indexer_matched,
        "sources": {
            "soar": sum(1 for e in filtered if e.get("source") == "soar"),
            "wazuh": sum(1 for e in filtered if e.get("source") == "wazuh"),
        },
        "stats": stats,
    }


def _find_installer_binary(bin_name):
    here = os.path.dirname(__file__)
    search_paths = [
        f"/deploy/bundle/{bin_name}",
        f"/agent-rs/target/release/{bin_name}",
        os.path.join(here, "../deploy/bundle", bin_name),
        os.path.join(here, "../agent-rs/target/release", bin_name),
        os.path.join(here, bin_name),
    ]
    return next((p for p in search_paths if os.path.isfile(p)), None)


def _check_login_rate_limit(key):
    now = time.time()
    window = 900.0
    max_attempts = 10
    with _LOGIN_LOCK:
        attempts = [ts for ts in _LOGIN_ATTEMPTS.get(key, []) if now - ts < window]
        _LOGIN_ATTEMPTS[key] = attempts
        if len(attempts) >= max_attempts:
            return False
    return True


def _record_login_failure(key):
    now = time.time()
    with _LOGIN_LOCK:
        attempts = [ts for ts in _LOGIN_ATTEMPTS.get(key, []) if now - ts < 900.0]
        attempts.append(now)
        _LOGIN_ATTEMPTS[key] = attempts
        if len(_LOGIN_ATTEMPTS) > 5000:
            _LOGIN_ATTEMPTS.clear()


def _clear_login_failures(key):
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(key, None)


def _is_agent_or_command_authorized(headers, agent_id):
    if _bearer_matches(headers, FLEET_COMMAND_TOKEN):
        return True
    if not _valid_agent_id(agent_id):
        return False
    with _fleet_locks.STATE_LOCK:
        expected = str(FLEET_AGENT_POLL_TOKENS.get(agent_id, "") or "")
    return bool(expected) and _bearer_matches(headers, expected)


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        try:
            self.request.settimeout(15)
        except OSError:
            pass

    def log_message(self, fmt, *args):
        print(f"{self.client_address[0]} {fmt % args}", flush=True)

    def _json(self, code, obj, headers=None):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _unauthorized(self):
        self._json(401, {"error": "unauthorized"}, {"WWW-Authenticate": "Bearer"})

    def _read_json(self, max_bytes=65536, require_dict=True):
        try:
            return _fleet_sec.read_bounded_json_body(self, max_bytes=max_bytes, require_dict=require_dict), None
        except OverflowError:
            self._json(413, {"error": "payload terlalu besar"})
            return None, 413
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})
            return None, 400

    def _require_command_or_scope(self, scope):
        if _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
            return True, None
        valid_key, key_info = _verify_api_key(self.headers, scope)
        if valid_key:
            return True, key_info
        self._unauthorized()
        return False, None

    def do_GET(self):
        cfg = _cfg()
        parsed = urlparse(self.path)
        if parsed.path == "/":
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif parsed.path == "/healthz":
            self._json(200, {"status": "ok"})
        elif parsed.path == "/api/fleet":
            ok, _ = self._require_command_or_scope("read:fleet")
            if not ok:
                return
            self._json(200, build_fleet(cfg))
        elif parsed.path == "/api/events":
            ok, _ = self._require_command_or_scope("read:intel")
            if not ok:
                return
            with _fleet_locks.EVENTS_LOCK:
                ev_copy = list(reversed(EVENTS))
            self._json(200, {"events": _fleet_soc.enrich_events_with_triage(_db, ev_copy)})
        elif parsed.path == "/api/events/history":
            ok, _ = self._require_command_or_scope("read:intel")
            if not ok:
                return
            qs = parse_qs(parsed.query)

            def _one(key, default=""):
                return (qs.get(key, [default])[0] or "").strip()

            self._json(
                200,
                build_event_history(
                    since=_one("since") or None,
                    until=_one("until") or None,
                    limit=_one("limit", str(HISTORY_DEFAULT_LIMIT)) or None,
                    offset=_one("offset", "0") or 0,
                    severity=_parse_csv(_one("severity")) or None,
                    agent_id=_one("agent_id") or None,
                    q=[t for t in qs.get("q", []) if t.strip()] or None,
                    source=(_one("source", "all") or "all").lower(),
                    dedup=(_one("dedup", "true").lower() not in ("0", "false", "no")),
                ),
            )
        elif parsed.path == "/api/metrics":
            ok, _ = self._require_command_or_scope("read:fleet")
            if not ok:
                return
            qs = parse_qs(parsed.query)
            aid = (qs.get("agent_id", [""])[0] or "").strip()
            with _fleet_locks.METRICS_LOCK:
                pts = list(METRICS.get(aid, []))
            self._json(200, {"agent_id": aid, "points": pts})
        elif parsed.path == "/api/scan-results":
            ok, _ = self._require_command_or_scope("read:fleet")
            if not ok:
                return
            qs = parse_qs(parsed.query)
            aid = (qs.get("agent_id", [""])[0] or "").strip()
            with _fleet_locks.SCAN_LOCK:
                if aid:
                    scan_data = SCAN_RESULTS.get(aid)
                    self._json(200, {"agent_id": aid, "scan": scan_data})
                else:
                    scans = {
                        k: {kk: vv for kk, vv in v.items() if kk != "files"}
                        for k, v in SCAN_RESULTS.items()
                    }
                    self._json(200, {"scans": scans, "history": list(SCAN_HISTORY[-20:])})
        elif parsed.path == "/api/commands":
            qs = parse_qs(parsed.query)
            aid = (qs.get("agent_id", [""])[0] or "").strip()
            if not _valid_agent_id(aid):
                self._json(400, {"error": "agent_id tidak valid"})
                return
            with _fleet_locks.STATE_LOCK:
                expected_token = FLEET_AGENT_POLL_TOKENS.get(aid, "")
            if not expected_token:
                self._json(403, {"error": "agent tidak terdaftar"})
                return
            if not _bearer_matches(self.headers, str(expected_token)):
                self._unauthorized()
                return
            with _fleet_locks.COMMANDS_LOCK:
                cmds = COMMANDS.pop(aid, [])
            _fleet_soc.mark_commands_delivered(_db, aid, cmds)
            self._json(200, {"commands": cmds})
        elif parsed.path == "/api/commands/history":
            ok, _ = self._require_command_or_scope("read:fleet")
            if not ok:
                return
            qs = parse_qs(parsed.query)
            aid = (qs.get("agent_id", [""])[0] or "").strip() or None
            status_filter = (qs.get("status", [""])[0] or "").strip() or None
            limit_val = (qs.get("limit", ["100"])[0] or "100").strip()
            self._json(
                200,
                _fleet_soc.list_command_history(
                    _db, agent_id=aid, status=status_filter, limit=limit_val
                ),
            )
        elif parsed.path == "/api/audit":
            ok, _ = self._require_command_or_scope("read:fleet")
            if not ok:
                return
            qs = parse_qs(parsed.query)
            limit_val = (qs.get("limit", ["100"])[0] or "100").strip()
            action_filter = (qs.get("action", [""])[0] or "").strip() or None
            actor_filter = (qs.get("actor", [""])[0] or "").strip() or None
            status_filter = (qs.get("status", [""])[0] or "").strip() or None
            q_filter = (qs.get("q", [""])[0] or "").strip() or None
            verify_flag = (qs.get("verify", ["1"])[0] or "1").lower() not in ("0", "false", "no")
            self._json(
                200,
                _fleet_soc.query_audit_logs(
                    _db,
                    limit=limit_val,
                    action=action_filter,
                    actor=actor_filter,
                    status=status_filter,
                    q=q_filter,
                    verify=verify_flag,
                ),
            )
        elif parsed.path == "/api/triage":
            ok, _ = self._require_command_or_scope("read:intel")
            if not ok:
                return
            qs = parse_qs(parsed.query)
            status_filter = (qs.get("status", [""])[0] or "").strip() or None
            assignee_filter = (qs.get("assignee", [""])[0] or "").strip() or None
            limit_val = (qs.get("limit", ["500"])[0] or "500").strip()
            self._json(
                200,
                _fleet_soc.list_triage(
                    _db, status=status_filter, assignee=assignee_filter, limit=limit_val
                ),
            )
        elif parsed.path == "/api/hitl/decisions":
            ok, _ = self._require_command_or_scope("read:intel")
            if not ok:
                return
            qs = parse_qs(parsed.query)
            inc_all = (qs.get("all", ["0"])[0] or "0").lower() in ("1", "true", "yes")
            limit_val = (qs.get("limit", ["100"])[0] or "100").strip()
            self._json(
                200,
                _fleet_soc.fetch_hitl_decisions(include_all=inc_all, limit=limit_val),
            )
        elif parsed.path == "/api/vt-cache":
            ok, _ = self._require_command_or_scope("read:intel")
            if not ok:
                return
            qs = parse_qs(parsed.query)
            h = (qs.get("hash", [""])[0] or "").strip().lower()
            now = time.time()
            with _fleet_locks.VT_CACHE_LOCK:
                if h:
                    ent = VT_CACHE.get(h)
                    self._json(
                        200,
                        {
                            "hash": h,
                            "found": bool(ent),
                            "entry": ent,
                            "age_secs": int(now - ent["stored_at"]) if ent else None,
                        },
                    )
                else:
                    lookups = VT_CACHE_STATS["lookups"]
                    self._json(
                        200,
                        {
                            "size": len(VT_CACHE),
                            "max": VT_CACHE_MAX,
                            "ttl_secs": {
                                "malicious": VT_TTL_MALICIOUS,
                                "clean": VT_TTL_CLEAN,
                                "unknown": VT_TTL_UNKNOWN,
                            },
                            "stats": dict(VT_CACHE_STATS),
                            "hit_rate": (
                                round(VT_CACHE_STATS["hits"] / lookups, 4) if lookups else 0.0
                            ),
                        },
                    )
        elif parsed.path == "/api/investigations":
            ok, _ = self._require_command_or_scope("read:intel")
            if not ok:
                return
            qs = parse_qs(parsed.query)
            res = _investigation_list(
                limit=(qs.get("limit", ["50"])[0] or "50").strip(),
                verdict=(qs.get("verdict", [""])[0] or "").strip() or None,
                severity=(qs.get("severity", [""])[0] or "").strip() or None,
                q=(qs.get("q", [""])[0] or "").strip() or None,
                agent_source=(qs.get("agent_source", [""])[0] or "").strip() or None,
            )
            self._json(200, res)
        elif parsed.path == "/api/keys":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            qs = parse_qs(parsed.query)
            include_revoked = qs.get("include_revoked", ["0"])[0] in ("1", "true", "yes")
            self._json(200, {"keys": _api_key_list(include_revoked=include_revoked)})
        elif parsed.path == "/api/users":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            self._json(200, {"users": _user_list(), "cloudflare_sync": _cf_sync_status_summary()})
        elif parsed.path == "/api/users/lookup":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            qs = parse_qs(parsed.query)
            email = qs.get("email", [""])[0].strip()
            user = _user_by_email(email)
            self._json(200, {"user": user})
        elif parsed.path == "/api/enroll/status":
            qs = parse_qs(parsed.query)
            req_id = qs.get("request_id", [""])[0].strip()
            claim_secret = qs.get("claim_secret", [""])[0].strip()
            if not req_id:
                self._json(400, {"error": "request_id diperlukan"})
                return
            data, code, err = _enroll_claim_status(req_id, claim_secret=claim_secret)
            if err:
                self._json(code, {"error": err})
                return
            self._json(200, data)
        elif parsed.path == "/api/enroll/requests":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            qs = parse_qs(parsed.query)
            status_filter = qs.get("status", [""])[0].strip() or None
            self._json(200, {"requests": _enroll_requests_list(status_filter)})
        elif parsed.path in (
            "/api/enroll/script/linux",
            "/api/enroll/script/windows",
            "/api/enroll/script/macos",
            "/api/update/script/linux",
            "/api/update/script/windows",
            "/api/update/script/macos",
        ):
            origin = _fleet_sec.sanitize_public_origin(
                raw_host=self.headers.get("X-Forwarded-Host") or self.headers.get("Host", ""),
                x_proto=self.headers.get("X-Forwarded-Proto", ""),
            )
            qs = parse_qs(parsed.query)
            action = (qs.get("action", [""])[0].strip() or qs.get("mode", [""])[0].strip()).lower()
            is_update = action == "update" or parsed.path.startswith("/api/update/script")
            if is_update:
                script_map = {
                    "linux": _generate_linux_update_script,
                    "windows": _generate_windows_update_script,
                    "macos": _generate_macos_update_script,
                }
            else:
                script_map = {
                    "linux": _generate_linux_installer_script,
                    "windows": _generate_windows_installer_script,
                    "macos": _generate_macos_installer_script,
                }
            target_os = parsed.path.rsplit("/", 1)[-1]
            script = script_map[target_os](origin).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(script)))
            self.end_headers()
            self.wfile.write(script)
        elif parsed.path in (
            "/api/installer/download/soar-agent",
            "/api/installer/download/soar-agent.exe",
            "/api/installer/download/soar-agent-macos",
            "/api/installer/download/soar-agent-macos-arm64",
            "/api/installer/download/soar-agent-macos-x86_64",
        ):
            bin_name = parsed.path.rsplit("/", 1)[-1]
            found_path = _find_installer_binary(bin_name)
            if found_path:
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                self.send_header("Content-Length", str(os.path.getsize(found_path)))
                self.end_headers()
                with open(found_path, "rb") as bf:
                    while chunk := bf.read(65536):
                        self.wfile.write(chunk)
            else:
                self._json(404, {"error": f"Binary {bin_name} belum tersedia di server"})
        elif parsed.path in (
            "/api/installer/checksum/soar-agent",
            "/api/installer/checksum/soar-agent.exe",
            "/api/installer/checksum/soar-agent-macos",
            "/api/installer/checksum/soar-agent-macos-arm64",
            "/api/installer/checksum/soar-agent-macos-x86_64",
        ):
            bin_name = parsed.path.rsplit("/", 1)[-1]
            found_path = _find_installer_binary(bin_name)
            if not found_path:
                self._json(404, {"error": f"Binary {bin_name} belum tersedia di server"})
                return
            digest = hashlib.sha256()
            with open(found_path, "rb") as bf:
                while chunk := bf.read(65536):
                    digest.update(chunk)
            out = (digest.hexdigest() + "\n").encode("ascii")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)
        elif parsed.path == "/api/settings/threat-intel":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            self._json(200, _get_masked_settings())
        elif parsed.path == "/api/settings/runtime-config":
            # Hanya token internal control plane (n8n/dashboard), BUKAN API key eksternal read:intel
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            ai = _merge_ai_defaults(_get_system_setting("ai_config", DEFAULT_AI_CONFIG))
            if not (ai.get("api_key") or "").strip():
                ai["api_key"] = _resolve_ai_key("", ai.get("primary_saved_key_id"), ai, "", ai.get("provider"))
            if not (ai.get("fallback_api_key") or "").strip():
                ai["fallback_api_key"] = _resolve_ai_key("", ai.get("fallback_saved_key_id"), ai, "", ai.get("fallback_provider"))
            ai.pop("saved_api_keys", None)
            ti = _get_system_setting("threat_intel_config", DEFAULT_THREAT_INTEL_CONFIG)
            self._json(200, {"ai": ai, "threat_intel": ti})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/heartbeat":
            j, err = self._read_json(max_bytes=65536)
            if err:
                return
            try:
                hid = str(j.get("id", "")).strip()
                if not hid:
                    raise ValueError("need id")
                if not _is_agent_or_command_authorized(self.headers, hid):
                    legacy_compat = os.environ.get("FLEET_LEGACY_HEARTBEAT_COMPAT", "").strip().lower() in ("1", "true", "yes")
                    with _fleet_locks.STATE_LOCK:
                        enrolled = bool(FLEET_AGENT_POLL_TOKENS.get(hid)) or (hid in HEARTBEATS)
                    if not (legacy_compat and _valid_agent_id(hid) and enrolled):
                        self._unauthorized()
                        return
                    print(f"[compat] legacy unauthenticated heartbeat accepted for enrolled agent {hid} (upgrade soar-agent binary)", flush=True)
                _sent_ip = (j.get("ip") or "").strip()
                if _sent_ip in ("", "127.0.0.1", "0.0.0.0", "localhost", "::1"):
                    _sent_ip = ""
                ip = _sent_ip or self.client_address[0]
                _now = time.time()
                with _fleet_locks.STATE_LOCK:
                    _prev = HEARTBEATS.get(hid) or {}
                    HEARTBEATS[hid] = {
                        "name": j.get("name", f"rust-agent-{hid}"),
                        "ip": ip,
                        "version": j.get("version", "0.1.0"),
                        "os": j.get("os", "unknown"),
                        "last_hash": j.get("last_hash", ""),
                        "watch_paths": j.get("watch_paths", []),
                        "last_seen": _now,
                        "first_seen": _prev.get("first_seen") or _now,
                        "cpu_pct": j.get("cpu_pct", 0),
                        "ram_gb": j.get("ram_gb", {}),
                    }
                _save_state()
                try:
                    cpu = float(j.get("cpu_pct", 0) or 0)
                except (TypeError, ValueError):
                    cpu = 0
                ram = j.get("ram_gb") or {}
                if cpu > 0 or (isinstance(ram, dict) and ram.get("total")):
                    with _fleet_locks.METRICS_LOCK:
                        hist = METRICS.setdefault(hid, [])
                        hist.append(
                            {
                                "ts": datetime.now(WITA).isoformat(),
                                "cpu_pct": round(cpu, 2),
                                "ram_used": round(float(ram.get("used", 0) or 0), 2),
                                "ram_total": round(float(ram.get("total", 0) or 0), 2),
                            }
                        )
                        del hist[:-METRICS_MAX]
                if j.get("last_hash") and j.get("last_path"):
                    ev = {
                        "id": uuid.uuid4().hex,
                        "ts": datetime.now(WITA).isoformat(),
                        "agent": j.get("name", hid),
                        "agent_id": hid,
                        "path": j.get("last_path", ""),
                        "hash": j.get("last_hash", ""),
                        "status": j.get("last_status", "sent"),
                    }
                    with _fleet_locks.EVENTS_LOCK:
                        EVENTS.append(ev)
                        del EVENTS[:-EVENTS_MAX]
                    _event_store_insert(ev)
                self._json(200, {"status": "ok", "id": hid})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/webhook-log":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            j, err = self._read_json(max_bytes=131072)
            if err:
                return
            try:
                sc = j.get("syscheck") or {}
                ev = {
                    "id": uuid.uuid4().hex,
                    "ts": j.get("ts") or datetime.now(WITA).isoformat(),
                    "agent": j.get("agent", "-"),
                    "agent_id": j.get("agent_id", "-"),
                    "path": j.get("path") or sc.get("path") or "-",
                    "hash": j.get("hash") or sc.get("sha256_after") or sc.get("sha256") or "",
                    "severity": j.get("severity", "INFO"),
                    "status": j.get("status", "alerted"),
                    "ai": j.get("ai", ""),
                    "url": j.get("url", ""),
                    "verdict": j.get("verdict", ""),
                    "size": str(j.get("size") or sc.get("size_after") or sc.get("size") or ""),
                    "perm": str(j.get("perm") or sc.get("perm_after") or sc.get("perm") or ""),
                    "uname": str(j.get("uname") or sc.get("uname_after") or sc.get("uname") or ""),
                    "uid": str(j.get("uid") if j.get("uid") is not None else sc.get("uid_after") or sc.get("uid") or ""),
                    "gname": str(j.get("gname") or sc.get("gname_after") or sc.get("gname") or ""),
                    "gid": str(j.get("gid") if j.get("gid") is not None else sc.get("gid_after") or sc.get("gid") or ""),
                    "mtime": _to_utc_iso(j.get("mtime") or sc.get("mtime_after") or sc.get("mtime") or ""),
                    "inode": str(j.get("inode") if j.get("inode") is not None else sc.get("inode_after") or sc.get("inode") or ""),
                    "md5": str(j.get("md5") or sc.get("md5_after") or sc.get("md5") or ""),
                    "sha1": str(j.get("sha1") or sc.get("sha1_after") or sc.get("sha1") or ""),
                }
                with _fleet_locks.EVENTS_LOCK:
                    EVENTS.append(ev)
                    del EVENTS[:-EVENTS_MAX]
                _event_store_insert(ev)
                self._json(200, {"status": "ok"})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/seen":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            j, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                key = str(j.get("key", "")).strip()
                if not key:
                    raise ValueError("need key")
                if len(key) > 512:
                    raise ValueError("key terlalu panjang")
                try:
                    window = int(j.get("window_secs", 300))
                except (TypeError, ValueError):
                    window = 300
                window = max(10, min(window, 3600))
                now = time.time()
                with _fleet_locks.SEEN_LOCK:
                    for k in [k for k, ts in list(SEEN.items()) if now - ts > window]:
                        SEEN.pop(k, None)
                    if key in SEEN:
                        dup = True
                    else:
                        SEEN[key] = now
                        dup = False
                self._json(200, {"duplicate": dup})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/vt-cache/lookup":
            ok, _ = self._require_command_or_scope("read:intel")
            if not ok:
                return
            j, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                h = str(j.get("hash", "")).strip().lower()
                if not _is_hex_hash(h):
                    raise ValueError("hash harus hex 32/40/64")
                now = time.time()
                with _fleet_locks.VT_CACHE_LOCK:
                    VT_CACHE_STATS["lookups"] += 1
                    ent = VT_CACHE.get(h)
                    if ent and now - ent.get("stored_at", 0) < ent.get("ttl", 0):
                        VT_CACHE_STATS["hits"] += 1
                        resp_obj = {
                            "hit": True,
                            "hash": h,
                            "stats": ent.get("stats"),
                            "known": ent.get("known", False),
                            "malicious": ent.get("malicious", 0),
                            "age_secs": int(now - ent["stored_at"]),
                            "ttl_secs": ent.get("ttl"),
                        }
                    else:
                        VT_CACHE_STATS["misses"] += 1
                        VT_CACHE.pop(h, None)
                        resp_obj = {"hit": False, "hash": h}
                self._json(200, resp_obj)
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/vt-cache/store":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            j, err = self._read_json(max_bytes=16384)
            if err:
                return
            try:
                h = str(j.get("hash", "")).strip().lower()
                if not _is_hex_hash(h):
                    raise ValueError("hash harus hex 32/40/64")
                now = time.time()
                if j.get("not_found"):
                    ent = {
                        "stats": None,
                        "known": False,
                        "malicious": 0,
                        "stored_at": now,
                        "ttl": VT_TTL_UNKNOWN,
                    }
                else:
                    stats = j.get("stats")
                    if not isinstance(stats, dict):
                        raise TypeError("butuh stats (objek) atau not_found true")
                    slim = {
                        k: int(stats.get(k, 0) or 0)
                        for k in ("malicious", "suspicious", "undetected", "harmless", "timeout")
                    }
                    malicious = slim["malicious"]
                    ent = {
                        "stats": slim,
                        "known": True,
                        "malicious": malicious,
                        "stored_at": now,
                        "ttl": _vt_ttl_secs(malicious, True),
                    }
                with _fleet_locks.VT_CACHE_LOCK:
                    VT_CACHE[h] = ent
                    VT_CACHE_STATS["stores"] += 1
                    cache_size = len(VT_CACHE)
                _vt_cache_prune(now)
                _vt_cache_save()
                self._json(
                    200,
                    {"status": "ok", "hash": h, "ttl_secs": ent["ttl"], "cache_size": cache_size},
                )
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/scan-result":
            j, err = self._read_json(max_bytes=1048576)
            if err:
                return
            try:
                aid = str(j.get("agent_id", "")).strip()
                if not aid:
                    raise ValueError("need agent_id")
                if not _is_agent_or_command_authorized(self.headers, aid):
                    self._unauthorized()
                    return
                if not isinstance(j.get("files"), list):
                    raise TypeError("files harus list")
                now = time.time()
                files = []
                new_hashes = 0
                malicious_hashes = 0
                total_bytes = 0
                with _fleet_locks.SCAN_LOCK, _fleet_locks.VT_CACHE_LOCK:
                    for f in j["files"][:SCAN_FILES_MAX]:
                        if not isinstance(f, dict):
                            continue
                        h = str(f.get("sha256", "")).strip().lower()
                        if len(h) != 64:
                            continue
                        size = int(f.get("size", 0) or 0)
                        vt_ent = VT_CACHE.get(h)
                        vt_mal = int(vt_ent.get("malicious", 0)) if isinstance(vt_ent, dict) else 0
                        is_mal = vt_mal >= 1
                        if is_mal:
                            malicious_hashes += 1
                        is_new = h not in KNOWN_HASHES
                        files.append(
                            {
                                "path": str(f.get("path", "")),
                                "size": size,
                                "sha256": h,
                                "new": is_new,
                                "malicious": is_mal,
                                "vt_malicious": vt_mal,
                            }
                        )
                        if is_new:
                            new_hashes += 1
                        KNOWN_HASHES[h] = now
                        total_bytes += size
                    if len(KNOWN_HASHES) > KNOWN_HASHES_MAX:
                        oldest = sorted(KNOWN_HASHES.items(), key=lambda kv: kv[1])
                        for k, _ in oldest[: len(KNOWN_HASHES) - KNOWN_HASHES_MAX]:
                            KNOWN_HASHES.pop(k, None)
                    scanned = len(files)
                    result = {
                        "agent_id": aid,
                        "agent_name": str(j.get("agent_name", "")),
                        "path": str(j.get("path", "")),
                        "trigger": str(j.get("trigger", "on-demand")),
                        "started": j.get("started") or datetime.now(WITA).isoformat(),
                        "finished": datetime.now(WITA).isoformat(),
                        "elapsed_ms": int(j.get("elapsed_ms", 0) or 0),
                        "scanned": scanned,
                        "new_hashes": new_hashes,
                        "known_hashes": scanned - new_hashes,
                        "malicious_hashes": malicious_hashes,
                        "total_bytes": int(j.get("total_bytes", 0) or 0) or total_bytes,
                        "truncated": bool(j.get("truncated")),
                        "files": files,
                    }
                    SCAN_RESULTS[aid] = result
                    SCAN_HISTORY.append({k: v for k, v in result.items() if k != "files"})
                    del SCAN_HISTORY[:-SCAN_HISTORY_MAX]
                self._json(
                    200,
                    {"status": "ok", "scan": {k: v for k, v in result.items() if k != "files"}},
                )
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/keys":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=16384)
            if err:
                return
            try:
                name = str(data.get("name", "AI Agent")).strip()
                scopes = data.get("scopes", ["read:fleet", "read:intel"])
                if not isinstance(scopes, list):
                    scopes = ["read:fleet", "read:intel"]
                created = _api_key_create(name, scopes)
                _record_audit(
                    "apikey.create",
                    target=created["id"],
                    detail={"name": created["name"], "scopes": created["scopes"], "prefix": created["prefix"]},
                    actor=str(data.get("actor") or "admin"),
                    role="admin",
                    ip=self.client_address[0],
                )
                self._json(201, created)
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/keys/revoke":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                key_id = str(data.get("id", "")).strip()
                if not key_id:
                    self._json(400, {"error": "id key diperlukan"})
                    return
                ok = _api_key_revoke(key_id)
                _record_audit(
                    "apikey.revoke",
                    target=key_id,
                    status="ok" if ok else "error",
                    actor=str(data.get("actor") or "admin"),
                    role="admin",
                    ip=self.client_address[0],
                )
                self._json(200, {"revoked": ok, "id": key_id})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/keys/rotate":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                key_id = str(data.get("id", "")).strip()
                if not key_id:
                    self._json(400, {"error": "id key diperlukan"})
                    return
                rotated = _api_key_rotate(key_id)
                if not rotated:
                    _record_audit(
                        "apikey.rotate",
                        target=key_id,
                        status="error",
                        actor=str(data.get("actor") or "admin"),
                        role="admin",
                        ip=self.client_address[0],
                    )
                    self._json(404, {"error": "API key tidak ditemukan atau sudah dicabut"})
                    return
                old_prefix = rotated.pop("old_prefix", "")
                _record_audit(
                    "apikey.rotate",
                    target=key_id,
                    detail={
                        "new_id": rotated["id"],
                        "name": rotated["name"],
                        "scopes": rotated["scopes"],
                        "old_prefix": old_prefix,
                        "new_prefix": rotated["prefix"],
                    },
                    actor=str(data.get("actor") or "admin"),
                    role="admin",
                    ip=self.client_address[0],
                )
                self._json(200, rotated)
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/users":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=32768)
            if err:
                return
            try:
                action = data.get("action", "create")
                actor = str(data.get("actor") or "admin")
                if action == "create":
                    created = _user_create(
                        username=data.get("username", ""),
                        password=data.get("password", ""),
                        role=data.get("role", "viewer"),
                        email=data.get("email", ""),
                        name=data.get("name", ""),
                    )
                    cf_sync = _sync_cloudflare_access_policy()
                    _record_audit(
                        "user.create",
                        target=created["username"],
                        detail={"id": created["id"], "role": created["role"], "email": created.get("email", "")},
                        actor=actor,
                        role="admin",
                        ip=self.client_address[0],
                    )
                    self._json(201, {"success": True, "user": created, "cloudflare_sync": cf_sync})
                elif action == "update":
                    user_id = data.get("id") or data.get("user_id")
                    updated = _user_update(user_id, data)
                    cf_sync = _sync_cloudflare_access_policy()
                    _record_audit(
                        "user.update",
                        target=str(user_id),
                        detail={"username": updated.get("username"), "role": updated.get("role"), "active": updated.get("active")},
                        actor=actor,
                        role="admin",
                        ip=self.client_address[0],
                    )
                    self._json(200, {"success": True, "user": updated, "cloudflare_sync": cf_sync})
                elif action == "delete":
                    user_id = data.get("id") or data.get("user_id")
                    ok = _user_delete(user_id)
                    cf_sync = _sync_cloudflare_access_policy() if ok else _cf_sync_status_summary()
                    _record_audit(
                        "user.delete",
                        target=str(user_id),
                        status="ok" if ok else "error",
                        actor=actor,
                        role="admin",
                        ip=self.client_address[0],
                    )
                    self._json(200, {"success": ok, "id": user_id, "cloudflare_sync": cf_sync})
                elif action == "sync_cloudflare":
                    cf_sync = _sync_cloudflare_access_policy()
                    _record_audit(
                        "cloudflare.sync",
                        target=str(cf_sync.get("policy_name") or "access_policy"),
                        status="ok" if cf_sync.get("synced") else str(cf_sync.get("status") or "error"),
                        detail=cf_sync.get("detail", ""),
                        actor=actor,
                        role="admin",
                        ip=self.client_address[0],
                    )
                    if cf_sync.get("configured") and cf_sync.get("status") == "error":
                        self._json(502, {"success": False, "error": cf_sync.get("detail"), "cloudflare_sync": cf_sync})
                    else:
                        self._json(200, {"success": bool(cf_sync.get("synced")), "cloudflare_sync": cf_sync})
                elif action == "touch_login":
                    ok = _user_touch_login(
                        username=str(data.get("username", "")),
                        email=str(data.get("email", "")),
                    )
                    self._json(200, {"success": ok})
                else:
                    self._json(400, {"error": f"action '{action}' tidak dikenal"})
            except ValueError as ve:
                self._json(400, {"error": str(ve)})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif parsed.path == "/api/auth/login":
            data, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                username = str(data.get("username", "")).strip()
                password = str(data.get("password", ""))
                rl_key = f"{self.client_address[0]}:{username.lower()}"
                if not _check_login_rate_limit(rl_key):
                    _record_audit(
                        "auth.login.failed",
                        target=username,
                        status="denied",
                        detail="rate_limited",
                        actor=username or "anonymous",
                        ip=self.client_address[0],
                    )
                    self._json(429, {"error": "Terlalu banyak percobaan login gagal. Coba lagi nanti."})
                    return
                user = _user_authenticate(username, password)
                if not user:
                    _record_login_failure(rl_key)
                    _record_audit(
                        "auth.login.failed",
                        target=username,
                        status="denied",
                        detail="invalid_credentials",
                        actor=username or "anonymous",
                        ip=self.client_address[0],
                    )
                    self._json(401, {"error": "Username atau password salah atau akun nonaktif"})
                    return
                _clear_login_failures(rl_key)
                _record_audit(
                    "auth.login.success",
                    target=user.get("username", username),
                    status="ok",
                    actor=user.get("email") or user.get("username") or username,
                    role=user.get("role", ""),
                    ip=self.client_address[0],
                )
                self._json(200, {"success": True, "user": user})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/enroll/request":
            data, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                hostname = str(data.get("hostname", "")).strip()
                os_name = str(data.get("os", "linux")).strip()
                arch = str(data.get("arch", "x86_64")).strip()
                ip = self.client_address[0]
                req = _enroll_request_create(hostname, os_name, arch, ip)
                self._json(
                    201,
                    {
                        "success": True,
                        "request_id": req["request_id"],
                        "claim_secret": req["claim_secret"],
                        "status": "pending",
                    },
                )
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/enroll/approve":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=16384)
            if err:
                return
            try:
                req_id = str(data.get("request_id", "")).strip()
                custom_id = data.get("agent_id")
                custom_name = data.get("agent_name")
                approved_by = str(data.get("approved_by", "admin")).strip()
                res = _enroll_request_approve(req_id, custom_id, custom_name, approved_by)
                _record_audit(
                    "enroll.approve",
                    target=res["agent_id"],
                    detail={"request_id": req_id, "agent_name": res["agent_name"]},
                    actor=approved_by,
                    role="admin",
                    ip=self.client_address[0],
                )
                self._json(200, {"success": True, "agent": res})
            except ValueError as ve:
                self._json(400, {"error": str(ve)})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif parsed.path == "/api/enroll/reject":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                req_id = str(data.get("request_id", "")).strip()
                rejected_by = str(data.get("rejected_by", "admin")).strip()
                res = _enroll_request_reject(req_id, rejected_by)
                _record_audit(
                    "enroll.reject",
                    target=req_id,
                    actor=rejected_by,
                    role="admin",
                    ip=self.client_address[0],
                )
                self._json(200, {"success": True, "result": res})
            except ValueError as ve:
                self._json(400, {"error": str(ve)})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif parsed.path == "/api/enroll/revoke":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                aid = str(data.get("agent_id", "")).strip()
                revoked_by = str(data.get("revoked_by") or data.get("actor") or "admin").strip()
                reason = str(data.get("reason", "")).strip()
                remove_hb = bool(data.get("remove_heartbeat", False))
                res = _enroll_agent_revoke(
                    aid, revoked_by=revoked_by, reason=reason, remove_heartbeat=remove_hb
                )
                _record_audit(
                    "enroll.revoke",
                    target=aid,
                    detail={"reason": reason, "removed_from_roster": remove_hb},
                    actor=revoked_by,
                    role="admin",
                    ip=self.client_address[0],
                )
                self._json(200, {"success": True, "result": res})
            except ValueError as ve:
                self._json(400, {"error": str(ve)})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif parsed.path == "/api/enroll/rotate":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                aid = str(data.get("agent_id", "")).strip()
                rotated_by = str(data.get("rotated_by") or data.get("actor") or "admin").strip()
                res = _enroll_agent_rotate_token(aid, rotated_by=rotated_by)
                _record_audit(
                    "enroll.rotate",
                    target=aid,
                    detail={"agent_name": res["agent_name"], "token_prefix": res["token_prefix"]},
                    actor=rotated_by,
                    role="admin",
                    ip=self.client_address[0],
                )
                self._json(200, {"success": True, "result": res})
            except ValueError as ve:
                self._json(400, {"error": str(ve)})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif parsed.path == "/api/settings/threat-intel":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=65536)
            if err:
                return
            try:
                updated_by = str(data.get("updated_by", "admin")).strip()
                res = _update_system_settings(data, updated_by)
                _record_audit(
                    "settings.update",
                    target="ai_and_threat_intel",
                    detail={"sections": [k for k in ("ai", "threat_intel") if k in data]},
                    actor=updated_by,
                    role="admin",
                    ip=self.client_address[0],
                )
                self._json(200, {"success": True, "settings": res})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/settings/ai/test":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=65536)
            if err:
                return
            try:
                res = _test_ai_inference(
                    data.get("provider", "google"),
                    data.get("model", "gemini-2.5-flash"),
                    data.get("prompt", ""),
                    api_key=data.get("api_key"),
                    base_url=data.get("base_url"),
                    fallback_config=data.get("fallback"),
                    temperature=data.get("temperature", 0.3),
                    max_tokens=data.get("max_tokens", 300),
                    system_instruction=data.get("system_instruction"),
                    target=data.get("target", "primary"),
                    saved_key_id=data.get("saved_key_id"),
                )
                self._json(200, res)
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/settings/ai/models":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=16384)
            if err:
                return
            try:
                res = _fetch_provider_models(
                    data.get("provider", "google"),
                    api_key=data.get("api_key"),
                    base_url=data.get("base_url"),
                    saved_key_id=data.get("saved_key_id"),
                    slot=data.get("slot"),
                )
                self._json(200, res)
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/investigations":
            valid_key, key_info = _verify_api_key(self.headers, "write:investigations")
            if not valid_key:
                valid_key, key_info = _verify_api_key(self.headers, "write:actions")
            if not valid_key and not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=131072)
            if err:
                return
            try:
                actor = (
                    f"api_key:{key_info['name']}"
                    if valid_key and key_info
                    else str(data.get("created_by") or "dashboard-admin")
                )
                created = _investigation_create(data, created_by=actor)
                self._json(201, {"success": True, "investigation": created})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/investigations/delete":
            if not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=8192)
            if err:
                return
            try:
                inv_id = str(data.get("id", "")).strip()
                if not inv_id:
                    self._json(400, {"error": "id investigasi diperlukan"})
                    return
                ok = _investigation_delete(inv_id)
                self._json(200, {"deleted": ok, "id": inv_id})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/commands":
            valid_key, key_info = _verify_api_key(self.headers, "write:actions")
            if not valid_key and not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._json(415, {"error": "Content-Type harus application/json"})
                return
            try:
                value = _read_command_body(self)
            except OverflowError:
                self._json(413, {"error": "body command terlalu besar"})
                return
            except (TypeError, ValueError, json.JSONDecodeError) as exc:
                self._json(400, {"error": str(exc)})
                return
            try:
                command = _validate_command(value)
            except (TypeError, ValueError) as exc:
                self._json(400, {"error": str(exc)})
                return
            if valid_key and key_info:
                command["by"] = f"agent:{key_info['name']}"
            aid = command["agent_id"]
            with _fleet_locks.STATE_LOCK:
                registered = aid in FLEET_AGENT_POLL_TOKENS
            if not registered:
                self._json(404, {"error": "agent tidak terdaftar"})
                return
            now_iso = datetime.now(WITA).isoformat()
            with _fleet_locks.COMMANDS_LOCK:
                if aid not in COMMANDS and len(COMMANDS) >= COMMANDS_MAX_AGENTS:
                    self._json(429, {"error": "queue agent penuh"})
                    return
                persisted = _fleet_soc.persist_queued_command(
                    _db, {**command, "ts": now_iso}, now_iso=now_iso
                )
                q = COMMANDS.setdefault(aid, [])
                q.append(persisted)
                del q[:-COMMANDS_MAX]
            _record_audit(
                "command.queue",
                target=f"{aid}:{command['action']}",
                detail={"id": persisted["id"], "target": command["target"]},
                actor=command.get("by", "dashboard"),
                ip=self.client_address[0],
            )
            self._json(
                200,
                {"status": "queued", "agent_id": aid, "action": command["action"]},
            )
        elif parsed.path == "/api/commands/ack":
            data, err = self._read_json(max_bytes=16384)
            if err:
                return
            try:
                aid = str(data.get("agent_id", "")).strip()
                if not _valid_agent_id(aid):
                    self._json(400, {"error": "agent_id tidak valid"})
                    return
                if not _is_agent_or_command_authorized(self.headers, aid):
                    self._unauthorized()
                    return
                cmd_id = str(data.get("id") or data.get("command_id") or "").strip()
                status_val = data.get("status", "")
                ok_val = data.get("ok")
                output_val = data.get("output") or data.get("detail") or data.get("error") or ""
                with _fleet_locks.COMMANDS_LOCK:
                    updated, ack_err = _fleet_soc.ack_command(
                        _db,
                        agent_id=aid,
                        cmd_id=cmd_id,
                        status=status_val,
                        ok=ok_val,
                        output=output_val,
                        in_memory_commands=COMMANDS,
                    )
                if ack_err or not updated:
                    code = 404 if "tidak ditemukan" in str(ack_err) else 400
                    self._json(code, {"error": ack_err or "gagal ACK command"})
                    return
                _record_audit(
                    "command.ack",
                    target=f"{aid}:{updated.get('action', '')}",
                    status="ok" if updated.get("status") == "succeeded" else "error",
                    detail={"id": updated.get("id"), "status": updated.get("status"), "output": updated.get("output", "")[:240]},
                    actor=f"agent:{aid}",
                    role="agent",
                    ip=self.client_address[0],
                )
                self._json(200, {"ok": True, "command": updated})
            except Exception as e:
                self._json(400, {"error": str(e)})
        elif parsed.path == "/api/triage":
            valid_key, key_info = _verify_api_key(self.headers, "write:actions")
            if not valid_key:
                valid_key, key_info = _verify_api_key(self.headers, "write:investigations")
            if not valid_key and not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=32768)
            if err:
                return
            try:
                keys = data.get("event_keys") or data.get("event_key")
                status_val = data.get("status", "")
                assignee = data.get("assignee")
                note = data.get("note")
                actor = (
                    f"api_key:{key_info['name']}"
                    if valid_key and key_info
                    else str(data.get("updated_by") or data.get("actor") or "analyst")
                )
                res = _fleet_soc.upsert_triage(
                    _db,
                    event_keys=keys,
                    status=status_val,
                    assignee=assignee,
                    note=note,
                    updated_by=actor,
                )
                _record_audit(
                    "triage.update",
                    target=str(keys)[:120],
                    detail={"status": status_val, "updated": res["updated"], "assignee": assignee or ""},
                    actor=actor,
                    ip=self.client_address[0],
                )
                self._json(200, res)
            except ValueError as ve:
                self._json(400, {"error": str(ve)})
            except Exception as e:
                self._json(500, {"error": str(e)})
        elif parsed.path == "/api/hitl/resolve":
            valid_key, key_info = _verify_api_key(self.headers, "write:actions")
            if not valid_key and not _bearer_matches(self.headers, FLEET_COMMAND_TOKEN):
                self._unauthorized()
                return
            data, err = self._read_json(max_bytes=16384)
            if err:
                return
            try:
                actor = (
                    f"api_key:{key_info['name']}"
                    if valid_key and key_info
                    else str(data.get("by") or data.get("actor") or "dashboard-analyst")
                )
                payload = {
                    "did": str(data.get("did") or "").strip(),
                    "hash": str(data.get("hash") or "").strip(),
                    "agent_id": str(data.get("agent_id") or "").strip(),
                    "action": str(data.get("action") or "").strip().lower(),
                    "by": actor,
                    "note": str(data.get("note") or "").strip()[:512],
                    "dst": True,
                }
                code, resolved = _fleet_soc.resolve_hitl_decision(payload)
                ar_dispatched = None
                if code == 200 and isinstance(resolved, dict) and resolved.get("ok") and not resolved.get("duplicate"):
                    r_action = str(resolved.get("action") or payload["action"]).lower()
                    raw_aid = str(resolved.get("agent_id") or payload["agent_id"]).strip()
                    r_aid = raw_aid.zfill(3) if raw_aid.isdigit() else raw_aid
                    r_path = str(resolved.get("filepath") or "").strip()
                    r_hash = str(resolved.get("hash") or payload["hash"]).strip().lower()
                    if r_action == "quarantine" and r_aid and r_path:
                        with _fleet_locks.STATE_LOCK:
                            is_rust = r_aid in FLEET_AGENT_POLL_TOKENS
                        if is_rust:
                            try:
                                cmd_obj = _validate_command(
                                    {"agent_id": r_aid, "action": "quarantine", "target": r_path, "by": f"hitl:{actor}"}
                                )
                                now_iso = datetime.now(WITA).isoformat()
                                with _fleet_locks.COMMANDS_LOCK:
                                    persisted = _fleet_soc.persist_queued_command(
                                        _db, {**cmd_obj, "ts": now_iso}, now_iso=now_iso
                                    )
                                    q = COMMANDS.setdefault(r_aid, [])
                                    q.append(persisted)
                                    del q[:-COMMANDS_MAX]
                                ar_dispatched = {
                                    "channel": "rust_command_queue",
                                    "command_id": persisted["id"],
                                    "agent_id": r_aid,
                                    "action": "quarantine",
                                    "target": r_path,
                                }
                            except Exception as cmd_exc:
                                ar_dispatched = {"channel": "rust_command_queue", "error": str(cmd_exc)}
                    triage_st = (
                        "contained"
                        if r_action == "quarantine"
                        else "false_positive"
                        if r_action == "false_positive"
                        else "investigating"
                    )
                    t_keys = [k for k in (f"{r_aid}:{r_hash}" if (r_aid and r_hash) else "", r_hash) if k]
                    if t_keys:
                        try:
                            _fleet_soc.upsert_triage(
                                _db,
                                event_keys=t_keys,
                                status=triage_st,
                                assignee=actor,
                                note=payload["note"] or f"HITL resolved: {r_action}",
                                updated_by=actor,
                            )
                        except Exception:
                            pass
                    _record_audit(
                        "hitl.resolve",
                        target=f"{r_aid}:{r_hash[:16]}",
                        detail={"action": r_action, "filepath": r_path, "ar_dispatched": ar_dispatched},
                        actor=actor,
                        ip=self.client_address[0],
                    )
                self._json(code, {"ok": code == 200, "resolved": resolved, "ar_dispatched": ar_dispatched})
            except Exception as e:
                self._json(400, {"error": str(e)})
        else:
            self._json(404, {"error": "not found"})

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()


def main():
    _validate_runtime_secrets()
    cfg = _cfg()
    port = cfg["port"]
    bind = os.environ.get("FLEET_BIND", "0.0.0.0").strip() or "0.0.0.0"
    _load_state()
    _vt_cache_load()
    _event_store_init()
    _event_store_prune()
    server = ThreadingHTTPServer((bind, port), Handler)
    print(
        f"fleet-monitor listen {bind}:{port} (Wazuh {cfg['wazuh_url']}, n8n {cfg['n8n_url']})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
