#!/usr/bin/env python3
"""
SOAR Model Context Protocol (MCP) Server.
Menyediakan antarmuka terstandar (MCP JSON-RPC 2.0 stdio) bagi AI Agent
(Antigravity / agy cli, Claude Code, Codex, Freebuff, Cursor, OpenCode)
untuk berinteraksi langsung dengan sistem SOAR (fleet-monitor, Wazuh, n8n).

Fitur Tools:
1. soar_get_fleet_status: Cek kesehatan komponen (Wazuh, n8n, Gemini) & ringkasan armada.
2. soar_list_agents: Daftar endpoint agent aktif/offline, IP, OS, dan versi.
3. soar_get_threat_events: Riwayat insiden keamanan (malware, phishing, canary, persistence).
4. soar_lookup_hash: Pengecekan reputasi hash SHA-256/MD5 ke server cache VT & MalwareBazaar.
5. soar_execute_command: Eksekusi Active Response (quarantine, sinkhole, scan, restore).
6. soar_get_stats: Agregasi tren insiden harian & distribusi severity.

Kompatibilitas: Python 3.8+ Standard Library murni (tanpa dependensi eksternal).
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

SERVER_NAME = "soar-mcp-server"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2024-11-05"

DEFAULT_SOAR_URL = os.environ.get("SOAR_API_URL") or "http://127.0.0.1:8080"
DEFAULT_SOAR_KEY = os.environ.get("SOAR_API_KEY", "")
CF_CLIENT_ID = os.environ.get("CF_ACCESS_CLIENT_ID", "")
CF_CLIENT_SECRET = os.environ.get("CF_ACCESS_CLIENT_SECRET", "")


def _log(msg: str):
    """Log ke stderr agar tidak merusak komunikasi JSON-RPC di stdout."""
    print(f"[{SERVER_NAME}] {msg}", file=sys.stderr, flush=True)


class SoarClient:
    """HTTP Client terpadu untuk berkomunikasi dengan SOAR API."""

    def __init__(
        self,
        base_url: str = DEFAULT_SOAR_URL,
        api_key: str = DEFAULT_SOAR_KEY,
        cf_client_id: str = CF_CLIENT_ID,
        cf_client_secret: str = CF_CLIENT_SECRET,
        timeout: int = 15,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key.strip()
        self.cf_client_id = cf_client_id.strip()
        self.cf_client_secret = cf_client_secret.strip()
        self.timeout = timeout

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": f"{SERVER_NAME}/{SERVER_VERSION}",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        if self.cf_client_id and self.cf_client_secret:
            headers["CF-Access-Client-Id"] = self.cf_client_id
            headers["CF-Access-Client-Secret"] = self.cf_client_secret
        if extra:
            headers.update(extra)
        return headers

    def request(
        self, path: str, method: str = "GET", body: Optional[Dict[str, Any]] = None
    ) -> Tuple[int, Any]:
        url = f"{self.base_url}{path}"
        data = None
        headers = self._headers()
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = resp.status
                raw = resp.read().decode("utf-8")
                try:
                    return status, json.loads(raw)
                except json.JSONDecodeError:
                    return status, raw
        except urllib.error.HTTPError as e:
            raw_err = e.read().decode("utf-8", errors="replace")
            try:
                err_data = json.loads(raw_err)
            except Exception:
                err_data = {"error": f"HTTP {e.code}: {raw_err}"}
            return e.code, err_data
        except Exception as e:
            return 500, {"error": f"Connection error ke {url}: {str(e)}"}


# ==============================================================================
# TOOL DEFINITIONS & HANDLERS
# ==============================================================================

TOOLS = [
    {
        "name": "soar_get_fleet_status",
        "description": (
            "Mendapatkan status kesehatan sistem SOAR secara menyeluruh: "
            "status koneksi Wazuh API, n8n orchestrator, Gemini AI engine, "
            "serta statistik jumlah endpoint agent (aktif vs offline) dan kapasitas armada."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "soar_list_agents",
        "description": (
            "Melihat daftar seluruh endpoint agent (workstation/server) yang terdaftar di SOAR. "
            "Menampilkan agent ID, nama hostname, alamat IP, sistem operasi, status (active/disconnected), "
            "tipe agen (Wazuh vs Rust soar-agent), serta timestamp registrasi dan heartbeat terakhir."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status_filter": {
                    "type": "string",
                    "enum": ["all", "active", "disconnected"],
                    "description": "Filter status agent (default: 'all')",
                }
            },
            "required": [],
        },
    },
    {
        "name": "soar_get_threat_events",
        "description": (
            "Mengambil riwayat insiden dan event ancaman keamanan terbaru "
            "(malware, ransomware canary, persistensi autostart, phishing, atau modifikasi file sistem). "
            "Dapat difilter berdasarkan tingkat keparahan (severity) atau ID agen."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Jumlah maksimal event yang diambil (default: 10, maks: 100)",
                    "default": 10,
                },
                "severity": {
                    "type": "string",
                    "enum": ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    "description": "Filter tingkat keparahan ancaman (default: ALL)",
                },
                "agent_id": {
                    "type": "string",
                    "description": "Filter event untuk agent ID tertentu (contoh: '001', '009')",
                },
                "q": {
                    "type": "string",
                    "description": "Kata kunci pencarian bebas (nama file, hash, path, url)",
                },
            },
            "required": [],
        },
    },
    {
        "name": "soar_lookup_hash",
        "description": (
            "Memeriksa reputasi hash berkas (SHA-256, MD5, atau SHA-1) dari cache lokal SOAR "
            "yang menyatukan data intelijen VirusTotal dan MalwareBazaar. "
            "Pencarian ini cepat dan tidak menghabiskan kuota API publik."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash": {
                    "type": "string",
                    "description": "Hash berkas yang ingin diperiksa (hex MD5/SHA1/SHA256)",
                }
            },
            "required": ["hash"],
        },
    },
    {
        "name": "soar_execute_command",
        "description": (
            "Mengeksekusi tindakan mitigasi respon aktif (Active Response) secara terukur ke endpoint target. "
            "Aksi yang didukung: 'quarantine' (karantina berkas), 'restore' (kembalikan berkas dari karantina), "
            "'sinkhole' (blokir domain phishing), 'unsinkhole' (cabut blokir domain), atau 'scan' (pemicu pemindaian direktori). "
            "Membutuhkan scope write:actions pada API key."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "agent_id": {
                    "type": "string",
                    "description": "ID agent tujuan (contoh: '001', '003', '009')",
                },
                "action": {
                    "type": "string",
                    "enum": ["quarantine", "restore", "sinkhole", "unsinkhole", "scan"],
                    "description": "Jenis tindakan mitigasi keamanan",
                },
                "target": {
                    "type": "string",
                    "description": (
                        "Target aksi: path absolut berkas (untuk quarantine/restore/scan) "
                        "atau nama domain FQDN tanpa protokol (untuk sinkhole, misal: 'login-update-bca.com')"
                    ),
                },
            },
            "required": ["agent_id", "action", "target"],
        },
    },
    {
        "name": "soar_get_stats",
        "description": (
            "Mengambil statistik agregasi keamanan SOAR: tren jumlah insiden harian, "
            "distribusi insiden per level keparahan (CRITICAL, HIGH, MEDIUM, LOW), "
            "serta 5 agent dengan temuan insiden terbanyak."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
    {
        "name": "soar_save_investigation",
        "description": (
            "Menyimpan laporan hasil investigasi dan penalaran AI Agent eksternal (misal agy / Gemini 4 Hydrogen) "
            "ke database SOAR agar muncul terpisah dari AI pipeline otomatis di tab 'Investigasi AI Agent' "
            "pada halaman Threat Intelligence Dashboard."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Judul singkat temuan atau investigasi",
                },
                "summary": {
                    "type": "string",
                    "description": "Ringkasan eksekutif hasil investigasi (1-3 kalimat)",
                },
                "analysis": {
                    "type": "string",
                    "description": "Analisis mendalam, korelasi antar-event/agent, dan alasan kesimpulan",
                },
                "verdict": {
                    "type": "string",
                    "enum": ["MALICIOUS", "SUSPICIOUS", "BENIGN", "NEEDS_REVIEW"],
                    "description": "Kesimpulan verdict hasil investigasi agent",
                },
                "severity": {
                    "type": "string",
                    "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                    "description": "Tingkat keparahan insiden",
                },
                "agent_source": {
                    "type": "string",
                    "description": "Nama agent AI yang melakukan analisis (default: agy)",
                },
                "model": {
                    "type": "string",
                    "description": "Nama model yang digunakan (contoh: gemini-4-hydrogen)",
                },
                "recommendations": {
                    "type": "string",
                    "description": "Langkah tindak lanjut atau mitigasi yang direkomendasikan",
                },
                "mitre_techniques": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Daftar teknik MITRE ATT&CK terkait (contoh: ['T1059.001'])",
                },
                "target_agent_ids": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Daftar agent_id terdampak (contoh: ['001', '009'])",
                },
                "target_hashes": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Daftar hash SHA-256 artefak terkait",
                },
                "target_paths": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Daftar path berkas atau URL terkait",
                },
            },
            "required": ["title", "summary", "analysis", "verdict", "severity"],
        },
    },
    {
        "name": "soar_list_investigations",
        "description": (
            "Mengambil daftar laporan investigasi yang sudah disimpan oleh AI Agent eksternal (agy / MCP)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {
                    "type": "integer",
                    "description": "Jumlah maksimum laporan (default 20)",
                    "default": 20,
                },
                "verdict": {
                    "type": "string",
                    "enum": ["ALL", "MALICIOUS", "SUSPICIOUS", "BENIGN", "NEEDS_REVIEW"],
                    "description": "Filter verdict",
                },
                "q": {
                    "type": "string",
                    "description": "Kata kunci pencarian",
                },
            },
            "required": [],
        },
    },
]


def handle_tool_call(client: SoarClient, name: str, args: Dict[str, Any]) -> str:
    """Mengeksekusi pemanggilan tool dan mengembalikan teks format ramah analis."""

    if name == "soar_get_fleet_status":
        status, data = client.request("/api/fleet")
        if status != 200 or not isinstance(data, dict):
            return f"Gagal mengambil status armada SOAR (HTTP {status}): {json.dumps(data)}"

        health = data.get("health", {})
        stats = data.get("stats", {})
        total_agents = int(stats.get("total", 0) or 0)
        capacity_pct = stats.get("capacity_pct")
        if capacity_pct is None:
            capacity_pct = min(100.0, round((total_agents / 100.0) * 100.0, 1))

        health_lines = [
            f"- Wazuh Manager API: {'AKTIF' if health.get('wazuh_api') else 'TERGANGGU'}",
            f"- n8n Orchestrator: {'AKTIF' if health.get('n8n') else 'TERGANGGU'}",
            f"- AI Reasoning Engine: {'SIAP' if health.get('gemini') else 'TIDAK TERSEDIA'}",
            f"- MISP OSINT Feed: {'AKTIF' if health.get('misp') else 'NONAKTIF/TERGANGGU'}",
            f"- Alert Log Registry: {'AKTIF' if health.get('alert_log') else 'TERGANGGU'}",
        ]

        summary = (
            "=== STATUS SISTEM & ARMADA SOAR ===\n\n"
            "Kesehatan Komponen Inti:\n"
            + "\n".join(health_lines)
            + "\n\n"
            "Statistik Endpoint:\n"
            f"- Total Agen: {total_agents} host\n"
            f"- Agen Aktif: {stats.get('active', 0)} host\n"
            f"- Agen Terputus: {stats.get('disconnected', 0)} host\n"
            f"- Agen Ringan Rust (soar-agent): {stats.get('rust', 0)} host\n"
            f"- Agen Tradisional Wazuh: {stats.get('wazuh', 0)} host\n"
            f"- Kapasitas Armada: {capacity_pct}% dari 100 PC target\n"
            f"\nDiperbarui pada: {data.get('generated_at', '-')}"
        )
        return summary

    elif name == "soar_list_agents":
        status, data = client.request("/api/fleet")
        if status != 200 or not isinstance(data, dict):
            return f"Gagal mengambil daftar agent (HTTP {status}): {json.dumps(data)}"

        agents: List[Dict[str, Any]] = data.get("agents", [])
        status_filter = str(args.get("status_filter", "all")).lower()
        if status_filter in ("active", "disconnected"):
            agents = [a for a in agents if str(a.get("status", "")).lower() == status_filter]

        if not agents:
            return f"Tidak ada agen ditemukan dengan filter: {status_filter}."

        lines = [f"=== DAFTAR AGENT ENDPOINT ({len(agents)} Host) ==="]
        for a in agents:
            aid = a.get("id", "-")
            name_host = a.get("name", "Unknown")
            ip = a.get("ip", "-")
            st = str(a.get("status", "unknown")).upper()
            raw_os = a.get("os")
            if isinstance(raw_os, dict):
                os_name = a.get("os_short") or raw_os.get("name") or "Unknown"
            else:
                os_name = a.get("os_short") or (str(raw_os).strip() if raw_os else "") or "Unknown"
            is_rust = str(a.get("type", "")).lower() == "rust" or bool(a.get("is_rust"))
            agent_type = "Rust soar-agent" if is_rust else "Wazuh Agent"
            reg_date = a.get("regDate") or a.get("dateAdd") or "-"
            last_seen = a.get("lastKeepAlive") or "-"

            lines.append(
                f"[{aid}] {name_host} ({ip})\n"
                f"  Status: {st} | Tipe: {agent_type} | OS: {os_name}\n"
                f"  Registrasi: {reg_date} | Heartbeat Terakhir: {last_seen}"
            )

        return "\n\n".join(lines)

    elif name == "soar_get_threat_events":
        limit = min(int(args.get("limit", 10)), 100)
        params = {"limit": str(limit)}
        if args.get("severity") and args["severity"] != "ALL":
            params["severity"] = str(args["severity"]).upper()
        if args.get("agent_id"):
            params["agent_id"] = str(args["agent_id"]).strip()
        if args.get("q"):
            params["q"] = str(args["q"]).strip()

        qs = urllib.parse.urlencode(params)
        status, data = client.request(f"/api/events/history?{qs}")
        if status != 200 or not isinstance(data, dict):
            # Fallback ke /api/events jika /api/events/history gagal
            status, data = client.request("/api/events")
            if status != 200 or not isinstance(data, dict):
                return f"Gagal mengambil event ancaman (HTTP {status}): {json.dumps(data)}"

        events: List[Dict[str, Any]] = data.get("events", [])
        if not events:
            return "Tidak ditemukan event ancaman yang sesuai dengan filter kriteria."

        lines = [f"=== RIWAYAT ANCAMAN KEAMANAN TERAKHIR ({len(events)} Temuan) ==="]
        for idx, ev in enumerate(events[:limit], 1):
            sev = (ev.get("severity") or "INFO").upper()
            target_path = ev.get("path") or ev.get("url") or "-"
            hash_val = ev.get("hash") or "-"
            rule_desc = ev.get("rule_desc") or "-"
            agent_label = f"{ev.get('agent', 'Unknown')} (ID: {ev.get('agent_id', '-')})"
            ts = ev.get("ts") or "-"
            ai_notes = ev.get("ai") or "-"
            verdict = ev.get("verdict") or "-"

            lines.append(
                f"{idx}. [{sev}] {rule_desc}\n"
                f"   Waktu: {ts} | Agen: {agent_label}\n"
                f"   Target/Path: {target_path}\n"
                f"   Hash: {hash_val}\n"
                f"   Vonis/Verdict: {verdict}\n"
                f"   Analisis AI: {ai_notes}"
            )

        return "\n\n".join(lines)

    elif name == "soar_lookup_hash":
        target_hash = str(args.get("hash", "")).strip().lower()
        if not target_hash:
            return "Parameter hash wajib diisi."

        status, data = client.request(
            "/api/vt-cache/lookup", method="POST", body={"hash": target_hash}
        )
        if status != 200 or not isinstance(data, dict):
            return f"Lookup hash gagal (HTTP {status}): {json.dumps(data)}"

        hit = data.get("hit", False)
        if not hit:
            return (
                f"Hash {target_hash} belum ada di cache server SOAR.\n"
                "Artinya hash ini belum pernah diperiksa oleh workstation armada "
                "atau masa berlaku TTL cache telah berakhir."
            )

        # Support baik format flat dari fleet-monitor.py maupun format nested entry
        entry = data.get("entry") if isinstance(data.get("entry"), dict) else data
        stats = entry.get("stats") if isinstance(entry.get("stats"), dict) else {}
        mal = int(stats.get("malicious", entry.get("mal", 0)) or 0)
        susp = int(stats.get("suspicious", entry.get("susp", 0)) or 0)
        undet = int(stats.get("undetected", entry.get("undet", 0)) or 0)
        mb_hit = bool(entry.get("mb_hit", False))
        mb_sig = entry.get("mb_sig") or "-"
        otx_pulses = int(entry.get("otx_pulses", 0) or 0)
        verdict = str(entry.get("verdict") or entry.get("status") or "unknown").upper()
        source = entry.get("source") or "vt-cache"
        ttl_left = int(entry.get("ttl_remaining_secs", entry.get("ttl_s", 0)) or 0)
        hours_left = round(ttl_left / 3600, 1)

        summary = (
            f"=== HASIL INTELIJEN HASH (CACHE SOAR) ===\n"
            f"Hash: {target_hash}\n"
            f"Vonis: {verdict}\n"
            f"Sumber: {source}\n"
            f"Statistik Antivirus (VirusTotal / MalwareBazaar / OTX):\n"
            f"  - Malicious: {mal}\n"
            f"  - Suspicious: {susp}\n"
            f"  - Undetected/Clean: {undet}\n"
            f"  - MalwareBazaar Hit: {'YA (' + str(mb_sig) + ')' if mb_hit else 'TIDAK'}\n"
            f"  - AlienVault OTX Pulses: {otx_pulses}\n"
            f"Masa Berlaku Cache: {hours_left} jam tersisa ({ttl_left} detik)"
        )
        return summary

    elif name == "soar_execute_command":
        aid = str(args.get("agent_id", "")).strip()
        action = str(args.get("action", "")).strip().lower()
        target = str(args.get("target", "")).strip()

        if not aid or not action or not target:
            return "Parameter agent_id, action, dan target wajib diisi lengkap."

        payload = {
            "agent_id": aid,
            "action": action,
            "target": target,
            "by": "ai-agent-mcp",
        }

        status, data = client.request("/api/commands", method="POST", body=payload)
        if status in (200, 201, 202):
            return (
                f"Perintah Active Response BERHASIL dikirim ke SOAR!\n"
                f"- Aksi: {action.upper()}\n"
                f"- Agen Target: {aid}\n"
                f"- Entitas Target: {target}\n"
                f"- Status Antrean: Berhasil dijadwalkan ke poller agen ({json.dumps(data)})"
            )
        elif status == 401:
            return (
                "Gagal mengeksekusi aksi: Unauthorized (401). "
                "Pastikan SOAR_API_KEY memiliki scope 'write:actions'."
            )
        else:
            return f"Gagal mengeksekusi aksi mitigasi (HTTP {status}): {json.dumps(data)}"

    elif name == "soar_get_stats":
        status, data = client.request("/api/events/history?limit=1")
        stats_data = {}
        if status == 200 and isinstance(data, dict):
            stats_data = data.get("stats", {})
        else:
            status, data = client.request("/api/fleet")
            if status == 200 and isinstance(data, dict):
                stats_data = data.get("stats", {})

        severity_counts = stats_data.get("severity", {})
        top_agents = stats_data.get("top_agents", [])
        daily_trends = stats_data.get("daily", [])

        lines = [
            "=== METRIK AGREGASI KEAMANAN SOAR ===",
            "\nDistribusi Keparahan Insiden:",
            f"- CRITICAL: {severity_counts.get('CRITICAL', 0)}",
            f"- HIGH: {severity_counts.get('HIGH', 0)}",
            f"- MEDIUM: {severity_counts.get('MEDIUM', 0)}",
            f"- LOW: {severity_counts.get('LOW', 0)}",
            f"- INFO: {severity_counts.get('INFO', 0)}",
        ]

        if top_agents:
            lines.append("\nTop 5 Agen Paling Terdampak:")
            for a in top_agents[:5]:
                lines.append(f"- Agent {a.get('key')}: {a.get('count')} insiden")

        if daily_trends:
            lines.append("\nTren Insiden Harian Terbaru:")
            for d in daily_trends[-7:]:
                lines.append(f"- {d.get('date')}: {d.get('count')} insiden")

        return "\n".join(lines)

    elif name == "soar_save_investigation":
        payload = {
            "title": str(args.get("title", "")).strip(),
            "summary": str(args.get("summary", "")).strip(),
            "analysis": str(args.get("analysis", "")).strip(),
            "verdict": str(args.get("verdict", "NEEDS_REVIEW")).strip().upper(),
            "severity": str(args.get("severity", "MEDIUM")).strip().upper(),
            "agent_source": str(args.get("agent_source") or "agy").strip(),
            "model": str(args.get("model") or "").strip(),
            "recommendations": str(args.get("recommendations") or "").strip(),
            "mitre_techniques": args.get("mitre_techniques") or [],
            "target_agent_ids": args.get("target_agent_ids") or [],
            "target_hashes": args.get("target_hashes") or [],
            "target_paths": args.get("target_paths") or [],
        }
        status, data = client.request("/api/investigations", method="POST", body=payload)
        if status in (200, 201) and isinstance(data, dict) and data.get("investigation"):
            inv = data["investigation"]
            return (
                f"Investigasi AI Agent berhasil disimpan ke Dashboard SOAR!\n"
                f"- ID: {inv.get('id')}\n"
                f"- Judul: {inv.get('title')}\n"
                f"- Agent/Model: {inv.get('agent_source')} ({inv.get('model') or '-'})\n"
                f"- Verdict/Severity: {inv.get('verdict')} / {inv.get('severity')}\n"
                f"- Lokasi UI: Threat Intelligence -> Tab 'Investigasi AI Agent'"
            )
        return f"Gagal menyimpan investigasi (HTTP {status}): {json.dumps(data)}"

    elif name == "soar_list_investigations":
        params = {"limit": str(min(int(args.get("limit", 20)), 100))}
        if args.get("verdict") and args["verdict"] != "ALL":
            params["verdict"] = str(args["verdict"]).upper()
        if args.get("q"):
            params["q"] = str(args["q"]).strip()
        qs = urllib.parse.urlencode(params)
        status, data = client.request(f"/api/investigations?{qs}")
        if status != 200 or not isinstance(data, dict):
            return f"Gagal mengambil daftar investigasi (HTTP {status}): {json.dumps(data)}"
        invs = data.get("investigations", [])
        if not invs:
            return "Belum ada laporan investigasi AI Agent yang tersimpan."
        lines = [f"=== DAFTAR INVESTIGASI AI AGENT ({len(invs)} dari {data.get('total', len(invs))}) ==="]
        for idx, inv in enumerate(invs, 1):
            lines.append(
                f"{idx}. [{inv.get('verdict')} / {inv.get('severity')}] {inv.get('title')}\n"
                f"   ID: {inv.get('id')} | Waktu: {inv.get('ts')} | Agent: {inv.get('agent_source')} ({inv.get('model') or '-'})\n"
                f"   Ringkasan: {inv.get('summary')}"
            )
        return "\n\n".join(lines)

    return f"Tool '{name}' tidak dikenali."


# ==============================================================================
# PROTOKOL JSON-RPC 2.0 (MCP STDIO DISPATCHER)
# ==============================================================================


def send_response(response: Dict[str, Any]):
    """Kirimkan pesan JSON-RPC ke stdout diikuti newline."""
    raw = json.dumps(response)
    sys.stdout.write(raw + "\n")
    sys.stdout.flush()


def run_stdio_server(client: SoarClient):
    """Loop utama pembaca protokol MCP dari stdin."""
    _log(f"MCP Server berjalan (URL: {client.base_url}, Protocol: {PROTOCOL_VERSION})")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        try:
            req = json.loads(line)
        except json.JSONDecodeError as e:
            send_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32700, "message": f"Parse error: {str(e)}"},
                }
            )
            continue

        if not isinstance(req, dict):
            send_response(
                {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32600, "message": "Invalid Request: payload harus JSON object"},
                }
            )
            continue

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") if isinstance(req.get("params"), dict) else {}

        # 1. Inisialisasi Handshake
        if method == "initialize":
            send_response(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "protocolVersion": PROTOCOL_VERSION,
                        "capabilities": {
                            "tools": {},
                        },
                        "serverInfo": {
                            "name": SERVER_NAME,
                            "version": SERVER_VERSION,
                        },
                    },
                }
            )

        # 2. Notifikasi Initialized (tanpa respons)
        elif method == "notifications/initialized":
            _log("Koneksi client AI Agent berhasil diinisialisasi.")
            continue

        # 3. Ping Liveness
        elif method == "ping":
            send_response({"jsonrpc": "2.0", "id": req_id, "result": {}})

        # 4. Daftar Tools
        elif method == "tools/list":
            send_response(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "tools": TOOLS,
                    },
                }
            )

        # 5. Eksekusi Tool
        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments") or {}

            try:
                output_text = handle_tool_call(client, tool_name, tool_args)
                send_response(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [{"type": "text", "text": output_text}],
                            "isError": False,
                        },
                    }
                )
            except Exception as e:
                _log(f"Error mengeksekusi tool {tool_name}: {str(e)}")
                send_response(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": f"Terjadi kesalahan saat memproses tool {tool_name}: {str(e)}",
                                }
                            ],
                            "isError": True,
                        },
                    }
                )

        # 6. Method tidak didukung
        else:
            if req_id is not None:
                send_response(
                    {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {
                            "code": -32601,
                            "message": f"Method '{method}' tidak didukung oleh {SERVER_NAME}.",
                        },
                    }
                )


def main():
    parser = argparse.ArgumentParser(description="SOAR Model Context Protocol (MCP) Server")
    parser.add_argument(
        "--url",
        default=DEFAULT_SOAR_URL,
        help=f"URL SOAR API backend (default: {DEFAULT_SOAR_URL})",
    )
    parser.add_argument(
        "--key",
        default=DEFAULT_SOAR_KEY,
        help="API Key Bearer token (soar_live_...)",
    )
    parser.add_argument(
        "--cf-client-id",
        default=CF_CLIENT_ID,
        help="Cloudflare Access Client ID (jika lewat domain publik)",
    )
    parser.add_argument(
        "--cf-client-secret",
        default=CF_CLIENT_SECRET,
        help="Cloudflare Access Client Secret (jika lewat domain publik)",
    )

    args = parser.parse_args()
    client = SoarClient(
        base_url=args.url,
        api_key=args.key,
        cf_client_id=args.cf_client_id,
        cf_client_secret=args.cf_client_secret,
    )
    run_stdio_server(client)


if __name__ == "__main__":
    main()
