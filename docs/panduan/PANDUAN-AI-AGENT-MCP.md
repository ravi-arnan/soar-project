# Panduan Integrasi AI Agent SOAR via Model Context Protocol (MCP)

Dokumen ini menjelaskan cara menghubungkan berbagai Agen AI pengembang (Antigravity CLI `agy`, Claude Code, Codex, Freebuff, Cursor, Windsurf, OpenCode) ke sistem SOAR `soar.raviarnan.dev` melalui standar industri **Model Context Protocol (MCP)**.

---

## 1. Arsitektur Komunikasi

Agen AI berkomunikasi dengan SOAR menggunakan protokol JSON-RPC 2.0 melalui STDIN/STDOUT (`stdio`), ditenagai oleh skrip mandiri Python Standard Library (`scripts/soar_mcp_server.py`).

```
+-------------------------------------------------------------+
|               AI AGENT HARNESS (Client)                     |
|    Antigravity (agy) / Claude Code / Codex / Cursor / dll   |
+-------------------------------------------------------------+
                              |
                     STDIO (JSON-RPC 2.0)
                              |
                              v
+-------------------------------------------------------------+
|             SOAR MCP Server (scripts/soar_mcp_server.py)    |
|   - soar_get_fleet_status                                   |
|   - soar_list_agents                                        |
|   - soar_get_threat_events                                  |
|   - soar_lookup_hash                                        |
|   - soar_execute_command                                    |
|   - soar_get_stats                                          |
+-------------------------------------------------------------+
                              |
               REST API (Bearer Token M2M Scope)
                              |
                              v
+-------------------------------------------------------------+
|              SOAR Backend (fleet-monitor & Wazuh)           |
|      http://100.73.91.17:8080 / https://soar.raviarnan.dev  |
+-------------------------------------------------------------+
```

---

## 2. Tools yang Tersedia untuk AI Agent

| Nama Tool | Deskripsi & Kegunaan | Parameter |
|---|---|---|
| `soar_get_fleet_status` | Memeriksa status kesehatan inti (Wazuh API, n8n, Gemini AI), kapasitas 100 PC, dan rasio agen aktif vs offline. | *(tanpa parameter)* |
| `soar_list_agents` | Menampilkan daftar seluruh endpoint (Wazuh agent & Rust `soar-agent`), alamat IP, OS, versi, dan heartbeat. | `status_filter`: `'all'`, `'active'`, atau `'disconnected'` |
| `soar_get_threat_events` | Mengambil insiden keamanan terbaru (malware, canary ransomware, autostart persistence, phishing, sistem file). | `limit` (int), `severity` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`), `agent_id`, `q` (query pencarian) |
| `soar_lookup_hash` | Memeriksa reputasi hash (MD5/SHA1/SHA256) pada cache server lokal (gabungan VirusTotal & MalwareBazaar) tanpa buang kuota. | `hash`: string hash |
| `soar_execute_command` | Memicu mitigasi Active Response ke endpoint target (`quarantine`, `sinkhole`, `scan`, `restore`). Butuh scope `write:actions`. | `agent_id`, `action`, `target` (path berkas atau domain) |
| `soar_get_stats` | Mengambil metrik agregasi: tren harian insiden, distribusi tingkat keparahan, dan top 5 agen terdampak. | *(tanpa parameter)* |

---

## 3. Konfigurasi Client AI Agent

### A. Antigravity CLI (`agy`)
Konfigurasi tersimpan pada file `~/.gemini/config/mcp_config.json`:
```json
{
  "mcpServers": {
    "soar": {
      "command": "python3",
      "args": [
        "/home/ravi/Projects/soar-project/scripts/soar_mcp_server.py"
      ],
      "env": {
        "SOAR_API_URL": "http://100.73.91.17:8080",
        "SOAR_API_KEY": "soar_live_e60d3a8e786fb5b4c1c049023e7c3ebd463b983d2579eae6"
      },
      "description": "SOAR Threat Intelligence, Incident Telemetry, and Active Response System"
    }
  }
}
```

### B. Claude Code
Claude Code membaca file `.mcp.json` di root proyek secara otomatis:
```json
{
  "mcpServers": {
    "soar": {
      "command": "python3",
      "args": ["scripts/soar_mcp_server.py"],
      "env": {
        "SOAR_API_URL": "http://100.73.91.17:8080",
        "SOAR_API_KEY": "soar_live_e60d3a8e786fb5b4c1c049023e7c3ebd463b983d2579eae6"
      }
    }
  }
}
```

### C. Cursor / Windsurf / Codex / Freebuff
Tambahkan pada konfigurasi MCP di settings aplikasi masing-masing:
* **Command:** `python3`
* **Args:** `/home/ravi/Projects/soar-project/scripts/soar_mcp_server.py`
* **Environment Variables:**
  * `SOAR_API_URL`: `http://100.73.91.17:8080` (Tailscale) atau `https://soar.raviarnan.dev`
  * `SOAR_API_KEY`: token Bearer `soar_live_...`

---

## 4. Contoh Interaksi Pengembang dengan AI Agent

Pengembang cukup mengetik perintah alami ke agen AI:

1. **Memeriksa Status:**
   > *"Cek kesehatan sistem SOAR dan ada berapa agent yang aktif sekarang?"*
   *Agen memanggil tool:* `soar_get_fleet_status`

2. **Memeriksa Ancaman Terkini:**
   > *"Ada insiden keamanan apa saja dengan tingkat keparahan CRITICAL atau HIGH?"*
   *Agen memanggil tool:* `soar_get_threat_events` dengan parameter `{"severity": "HIGH"}`

3. **Cek Reputasi File Mencurigakan:**
   > *"Tolong cek apakah hash berkas 553330973113264ceb8cd54ddad3777ae9774cce32560c489701abb69a0c4e91 sudah dikenal di SOAR?"*
   *Agen memanggil tool:* `soar_lookup_hash` dengan parameter hash terkait.

4. **Eksekusi Mitigasi:**
   > *"Karantina file /tmp/malware.sh pada agent 009 sekarang."*
   *Agen memanggil tool:* `soar_execute_command` dengan parameter:
   `{"agent_id": "009", "action": "quarantine", "target": "/tmp/malware.sh"}`
