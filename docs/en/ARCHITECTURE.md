# Architecture Overview

Technical architecture of the **Agentic-Driven Open-Source SOAR** platform (`v1.1.0+`).

## 1. High-Level Layers

The platform separates endpoint telemetry, workflow orchestration, control-plane state, and analyst governance into four decoupled layers:

1. **Endpoint Fleet (`agent-rs` + Wazuh Agent)**
   - **`soar-agent` (Rust)**: Lightweight cross-platform binary (Linux static musl, Windows, macOS) watching `~/Downloads`, `~/Desktop`, and removable USB media. Computes streaming SHA-256 hashes (metadata only; file bytes never leave the host), filters benign exported chat media, monitors ransomware decoy canary files (`EventKind::Modify` and `EventKind::Remove`), and executes local Active Response (`quarantine`, `restore`, `sinkhole`, `unsinkhole`, `scan`) via authenticated HTTP/command polling.
   - **Wazuh Agent**: Handles OS-level log collection, Windows Sysmon Event ID 1 process-chain telemetry (rules `110001-110044`), and SIEM correlation.
2. **Agentic Orchestration & AI (`n8n` + `soar_mcp_server.py`)**
   - **`n8n` (`2.42.5`)**: Executes declarative playbooks in [`n8n-workflows/`](../../n8n-workflows/) for malware detection, phishing analysis, proactive URLhaus feeds, Telegram callback resolution, and SLA HITL escalation.
   - **Multi-Provider AI Engine**: Runtime-configurable primary and fallback LLM routing (`Google Gemini`, `OpenAI GPT`, `Anthropic Claude`, `Pollinations`, `Experiential Labs`, or custom OpenAI-compatible endpoints such as `Ollama`, `Groq`, or `vLLM`) via Dashboard Settings without restarting containers.
   - **External AI Agent MCP Server ([`scripts/soar_mcp_server.py`](../../scripts/soar_mcp_server.py))**: Pure Python stdlib JSON-RPC 2.0 server over stdio exposing fleet health, IoC reputation, and gated Active Response actions to external AI coding/SOC agents using least-privilege scoped API keys (`read:fleet`, `read:intel`, `write:actions`).
3. **Control Plane & Threat Intelligence (`fleet-monitor` + `misp-index` + `alert-log`)**
   - **`fleet-monitor` (`scripts/fleet-monitor.py`)**: Pure Python stdlib HTTP control plane backed by SQLite WAL (`state/events.db`). Owns differential-TTL verdict caching (malicious 7d, clean 24h, unknown 6h), persistent Active Response command queue with execution ACKs, alert triage lifecycle (`new`, `investigating`, `contained`, `false_positive`, `resolved`), RBAC users, scoped M2M API keys, encrypted AI/TI settings, and a SHA-256 hash-chained `audit_logs` table.
   - **`misp-index` (`scripts/misp-feed-sync.py`)**: Syncs CIRCL OSINT MISP feeds every 12h into local SQLite (`state/misp.db`) for zero-key IoC lookups.
   - **`alert-log` (`scripts/alert-log.py`)**: Tracks outbound Telegram delivery observability and stores pending/resolved HITL analyst decisions with SLA escalation support.
   - **External OSINT Sources**: VirusTotal, MalwareBazaar, AlienVault OTX, Google Safe Browsing, and URLScan.io.
4. **Dashboard & HITL Interfaces (`dashboard/` + Telegram + TUI)**
   - **Next.js 16 Web UI (`dashboard/`)**: Wazuh/OUI-styled SOC console with Overview Hub, Security Events, Threat Intel, Integrity Monitoring (FIM), Agents Management, Deploy Portal (`/install`), MITRE ATT&CK Matrix, Network Map, Web HITL Approval Queue, RBAC Users, and Settings.
   - **Telegram HITL (`tg-callback-poller.py`)**: Long-polling bot bridge (`getUpdates` -> n8n webhook) allowing analysts to approve or dismiss medium/high-confidence detections directly from Telegram inline buttons without exposing n8n webhooks publicly.
   - **Terminal UI (`scripts/fleet-tui.py`)**: SSH-friendly Python `curses` TUI reading the same `/api/fleet` and `/api/events` endpoints.

## 2. Confidence-Based Tiered Response Model

Instead of binary blocking or noisy rule-only alerting, every incident is evaluated through multi-source consensus and routed to one of three operational tiers:

| Tier | Trigger Criteria | Automated Action | Analyst Interaction |
|------|------------------|------------------|---------------------|
| **CRITICAL (Autonomous Containment)** | High-confidence consensus (e.g., VirusTotal >= 20 detections or confirmed GSB/URLhaus phishing) | Immediate `quarantine` or domain `sinkhole` | Real-time notification sent to Telegram and logged in Dashboard |
| **HIGH / AMBIGUOUS (HITL Gated)** | Moderate detections (`1-19` VT), MalwareBazaar/MISP hit with low VT, suspicious LOLBin/process chains, or unverified executables | Context synthesis + MITRE mapping prepared; no destructive OS action taken automatically | Analyst approves (`Quarantine` / `Block`) or marks `False Positive` via Telegram inline buttons or Dashboard HITL Queue; SLA auto-escalates overdue items |
| **INFO / BENIGN (Noise Suppression)** | Benign chat-export media, `0`-byte/temporary download files, or verified clean baseline files | Suppressed from Telegram and HITL queues | Recorded silently in `fleet-monitor` for audit and baseline visibility |

## 3. Security & Tamper-Evident Controls

- **Zero-Trust Ingress**: Cloudflare Access JWT (`cf-access-jwt-assertion`) verified cryptographically via RS256 JWKS (`CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`), paired with signed HMAC session cookies, PBKDF2-HMAC-SHA256 (600,000 iterations), CSRF Origin validation, and strict HTTP security headers.
- **Active Response Safety**: Symlink rejection, canonicalized OS path denylists, protected infrastructure domain denylists (`localhost`, gateway/API domains), manifest-only file restoration, and Windows cross-drive + `icacls` ACL hardening.
- **Tamper-Evident Audit Chain**: Sensitive control-plane mutations append to `audit_logs` with `prev_hash` + `entry_hash` (SHA-256) and automatic secret redaction, verifiable live via `GET /api/audit?verify=1`.
- **Container Hardening**: Services in [`docker-compose.yml`](../../docker-compose.yml) run with `no-new-privileges:true`, dropped capabilities (`cap_drop: [ALL]`), bounded memory limits, log rotation, and local loopback bindings (`127.0.0.1`) for internal services.
