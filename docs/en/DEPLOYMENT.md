# Deployment & Verification Guide

Quick-start guide for deploying the **Agentic-Driven Open-Source SOAR** stack (`v1.1.0+`).

## 1. Prerequisites

### Server Host (Linux / VPS)
- **OS**: Linux (Debian 12+, Ubuntu 22.04+, Rocky 9+, Fedora, or NixOS 25.05+)
- **Runtime**: Docker Engine >= 20.10 with Docker Compose v2, `git`, `openssl`, `curl`, and `python3`
- **Hardware**: Minimum 12 GB RAM (16 GB recommended when running the full Wazuh Indexer + n8n stack) and 80 GB disk

### External Credentials
- **VirusTotal API Key** (free tier works; protected by differential TTL verdict cache)
- **Telegram Bot Token** (`@BotFather`) and **Chat ID** (`@get_id_bot`) for HITL alerts
- **Optional OSINT & AI Keys**: Google Safe Browsing, URLScan.io, MalwareBazaar, AlienVault OTX, and at least one LLM provider (`GEMINI_API_KEY`, OpenAI, Anthropic, or a custom OpenAI-compatible endpoint)

## 2. Server Bootstrap

1. **Configure `.env`** from the template and populate required tokens (minimum 32 random characters for auth secrets):
   ```bash
   cp .env.example .env
   ```
   Key variables to set in `.env`:
   - `PUBLIC_SOAR_URL`, `PUBLIC_ENROLL_URL`, `WAZUH_MANAGER_HOST`, `DASHBOARD_ALLOWED_ORIGINS`
   - `FLEET_COMMAND_TOKEN`, `FLEET_AGENT_POLL_TOKENS_JSON`, `DASHBOARD_LOGIN_TOKEN`, `SOAR_SETTINGS_ENCRYPTION_KEY`, `N8N_WEBHOOK_SECRET`
   - `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `TELEGRAM_ALLOWED_CHAT_IDS`
   - `WAZUH_API_USER`, `WAZUH_API_PASS`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASS`

2. **Run the idempotent server setup script**:
   ```bash
   bash deploy/setup-server.sh
   ```
   This checks Docker prerequisites, generates missing certs/keys, launches the Wazuh (`v4.14.8`) and core SOAR Compose stacks, and syncs n8n workflows via [`deploy/n8n-setup.py`](../../deploy/n8n-setup.py).

   > **Note for NixOS hosts**: Add `networking.firewall.trustedInterfaces = [ "docker0" "br-+" ];` in `/etc/nixos/configuration.nix` so Docker containers can communicate across compose bridges.

3. **Verify Live Services**:
   - `n8n`: `http://127.0.0.1:5678/healthz`
   - `fleet-monitor`: `http://127.0.0.1:8080/healthz`
   - `misp-index`: `http://127.0.0.1:8090/healthz`
   - `alert-log`: `http://127.0.0.1:8091/healthz`
   - `dashboard`: `http://127.0.0.1:3000`

## 3. Endpoint Enrollment (`soar-agent`)

Endpoints can enroll through the Dashboard (**Deploy agent**) or the public installer portal (`/install`):

- **Linux**:
  ```bash
  curl -sSL https://soar-agent.example.com/api/enroll/script?os=linux | sudo bash
  ```
  Alternatively, build/install the `.deb` package (`agent-rs/build-deb.sh`), use the NixOS module in [`deploy/nixos/`](../../deploy/nixos/), or roll out across hosts with [`deploy/ansible/`](../../deploy/ansible/).
- **Windows**: Use the generated PowerShell command from `/install` or [`deploy/install-agent-windows.ps1`](../../deploy/install-agent-windows.ps1).
- **macOS**: Use the Darwin enrollment script served from `/install`.

Newly enrolled agents appear under **Pending Approvals** in the dashboard and receive an authenticated `poll_token` upon admin approval.

## 4. Local Test Suites

Run all unit tests across the three runtimes before deploying changes:

```bash
# 1. Python Backend, SOC Ops, MCP, AR & Setup (210+ tests)
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 -m unittest discover -s deploy -p 'test_*.py'

# 2. Next.js Dashboard (28 unit tests, ESLint, TypeScript, production build)
npm --prefix dashboard run check

# 3. Rust soar-agent workspace
cargo test --manifest-path agent-rs/Cargo.toml
```

## 5. E2E Pipeline Smoke Check

To verify the live n8n workflows, Telegram HITL delivery, and `fleet-monitor` event persistence:

```bash
python3 scripts/e2e-soar-check.py
```

For full quantitative benchmarking (`--mode mttr-malware`, `mttr-phishing`, `load`, `vt-cold`, `mttr-fleet`, `mttr-hitl`), see [`scripts/benchmark-soar.py`](../../scripts/benchmark-soar.py).
