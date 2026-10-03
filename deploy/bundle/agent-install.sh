#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_ID="${AGENT_ID:-}"
AGENT_NAME="${AGENT_NAME:-rust-agent-$(hostname | tr 'A-Z' 'a-z' | cut -c1-20)}"
SERVER="${SERVER:-100.73.91.17}"
WATCH="${WATCH:-}"
POLL_TOKEN="${FLEET_AGENT_POLL_TOKEN:-}"
BIN_SRC="$SCRIPT_DIR/soar-agent"

[ "$(id -u)" = 0 ] || { echo "[x] jalankan sebagai root (sudo)" >&2; exit 1; }
[ -n "$AGENT_ID" ] || { echo "[x] AGENT_ID wajib" >&2; exit 1; }
[ "${#POLL_TOKEN}" -ge 32 ] || { echo "[x] FLEET_AGENT_POLL_TOKEN minimal 32 karakter" >&2; exit 1; }
[ -f "$BIN_SRC" ] || { echo "[x] binary bundle tidak ditemukan: $BIN_SRC" >&2; exit 1; }

install -m 755 "$BIN_SRC" /usr/local/bin/soar-agent
install -d -m 750 /var/ossec/quarantine
install -d -m 700 /etc/soar-agent
umask 077
printf '%s\n' "$POLL_TOKEN" > /etc/soar-agent/fleet.token
printf 'SOAR_FLEET_POLL_TOKEN_FILE=/etc/soar-agent/fleet.token\n' > /etc/soar-agent/fleet.env
chmod 600 /etc/soar-agent/fleet.token /etc/soar-agent/fleet.env

ARGS="--webhook http://${SERVER}:5678/webhook/wazuh-alert"
ARGS+=" --agent-id ${AGENT_ID} --agent-name ${AGENT_NAME}"
ARGS+=" --fleet-url http://${SERVER}:8080/api/heartbeat"
[ -n "$WATCH" ] && ARGS+=" --watch ${WATCH}"
cat > /etc/systemd/system/soar-agent.service <<UNIT
[Unit]
Description=SOAR Agen Ringan Rust
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/soar-agent ${ARGS}
Restart=always
RestartSec=5
Environment=RUST_LOG=info
EnvironmentFile=/etc/soar-agent/fleet.env

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now soar-agent
systemctl is-active --quiet soar-agent
