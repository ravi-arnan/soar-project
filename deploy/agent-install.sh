#!/usr/bin/env bash
# =============================================================================
# agent-install.sh — pasang soar-agent Rust di 1 workstation (tanpa Docker)
#
# Pemakaian di workstation target (butuh binary soar-agent, cara dapat di bawah):
#   sudo AGENT_ID=004 AGENT_NAME=laptop-budi SERVER=soar.example.com FLEET_AGENT_POLL_TOKEN=... bash agent-install.sh
#
# Cara dapat binary (pilih satu):
#   a) build di mesin ini:      agent-rs/build-deb.sh  (butuh rustc/cargo)
#   b) scp dari mesin build:    scp agent-rs/target/x86_64-unknown-linux-musl/release/soar-agent target:/tmp/
#      -> script ini otomatis pakai /tmp/soar-agent kalau ada
#   c) .deb via package manager: sudo apt install ./soar-agent_0.3.0_amd64.deb
#      -> tidak butuh script ini sama sekali (systemd unit sudah dibawa .deb)
#
# Env yang dipahami:
#   AGENT_ID    id unik agent (004..100+)            [wajib untuk fleet rapi]
#   AGENT_NAME  nama tampil di dashboard             [default: rust-agent-$HOSTNAME]
#   SERVER      IP/host server SOAR (Tailscale/LAN)  [wajib]
#   WATCH       path dipantau, dipisah koma          [default: ~/Downloads,~/Desktop,/run/media]
#   FLEET_AGENT_POLL_TOKEN  token polling dari server [wajib]
#   BIN_URL     URL HTTPS binary jika tidak ada lokal [opsional]
#   BIN_SHA256  SHA-256 hex binary (wajib bila pakai BIN_URL) [opsional]
#
# satu binary musl statis + satu unit systemd, tanpa enroll/key/manager.
# =============================================================================
set -euo pipefail

AGENT_ID="${AGENT_ID:-}"
AGENT_NAME="${AGENT_NAME:-rust-agent-$(hostname | tr 'A-Z' 'a-z' | cut -c1-20)}"
SERVER="${SERVER:-}"
WATCH="${WATCH:-}"
POLL_TOKEN="${FLEET_AGENT_POLL_TOKEN:-}"
BIN_SRC="${BIN_SRC:-/tmp/soar-agent}"
BIN_URL="${BIN_URL:-}"
BIN_SHA256="${BIN_SHA256:-}"
REPO_HINT="(clone repo SOAR, lihat agent-rs/README.md)"

[ "$(id -u)" = 0 ] || { echo "[x] jalankan sebagai root (sudo)"; exit 1; }
[ -n "$AGENT_ID" ] || { echo "[x] AGENT_ID wajib. Contoh: sudo AGENT_ID=004 SERVER=192.0.2.10 FLEET_AGENT_POLL_TOKEN=... bash agent-install.sh"; exit 1; }
[ -n "$SERVER" ] || { echo "[x] SERVER wajib diisi (IP/hostname server SOAR)"; exit 1; }
[ "${#POLL_TOKEN}" -ge 32 ] || { echo "[x] FLEET_AGENT_POLL_TOKEN wajib diisi (minimal 32 karakter)"; exit 1; }
[[ "$POLL_TOKEN" != *[[:space:]]* ]] || { echo "[x] FLEET_AGENT_POLL_TOKEN tidak boleh berisi whitespace"; exit 1; }

echo "[1/5] cari binary soar-agent"
if [ ! -f "$BIN_SRC" ]; then
  for c in agent-rs/target/x86_64-unknown-linux-musl/release/soar-agent \
           agent-rs/target/release/soar-agent; do
    [ -f "$c" ] && BIN_SRC="$c" && break
  done
fi
# Kalau binary belum ada, hanya download dari URL HTTPS yang ditentukan operator.
if [ ! -f "$BIN_SRC" ] && [ -n "$BIN_URL" ] && command -v curl >/dev/null 2>&1; then
  case "$BIN_URL" in
    https://*) ;;
    *) echo "[x] BIN_URL wajib memakai HTTPS."; exit 1 ;;
  esac
  TMP_BIN="$(mktemp /tmp/soar-agent.XXXXXX)"
  trap 'rm -f "$TMP_BIN"' EXIT
  echo "      tidak ada di lokal, download dari BIN_URL..."
  curl -fSL -o "$TMP_BIN" "$BIN_URL"
  if [ -n "$BIN_SHA256" ]; then
    echo "${BIN_SHA256}  ${TMP_BIN}" | sha256sum -c - || { echo "[x] Verifikasi SHA-256 binary gagal"; exit 1; }
  fi
  BIN_SRC="$TMP_BIN"
fi
if [ ! -f "$BIN_SRC" ]; then
  echo "[x] binary tidak ditemukan ($BIN_SRC). Dapatkan dulu: build $REPO_HINT, atau scp, atau pakai .deb."
  exit 1
fi
echo "      pakai: $BIN_SRC ($(du -h "$BIN_SRC" | cut -f1))"

echo "[2/5] install binary + buat direktori karantina"
install -m 755 "$BIN_SRC" /usr/local/bin/soar-agent
mkdir -p /var/ossec/quarantine
chmod 750 /var/ossec/quarantine

echo "[3/5] tulis systemd unit (agent-id=$AGENT_ID name=$AGENT_NAME server=$SERVER)"
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
Description=SOAR Agen Ringan Rust (alternatif Wazuh Agent)
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

echo "[4/5] enable + start service"
systemctl daemon-reload
systemctl enable --now soar-agent

echo "[5/5] verifikasi"
sleep 2
if systemctl is-active --quiet soar-agent; then
  echo "      service aktif ✓"
else
  echo "      [!] service belum aktif — cek: journalctl -u soar-agent -n 20"
fi
if curl -fsS -m 5 "http://${SERVER}:8080/healthz" >/dev/null 2>&1; then
  echo "      fleet-monitor terjangkau ✓ (agent akan muncul hijau di dashboard, id ${AGENT_ID})"
else
  echo "      [!] fleet-monitor http://${SERVER}:8080 belum terjangkau (firewall/network?) — agent tetap jalan"
fi

cat <<EOF

Selesai. Test:  printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > ~/Downloads/eicar.com
Lihat:          journalctl -u soar-agent -f
Uninstall:      systemctl disable --now soar-agent && rm -f /etc/systemd/system/soar-agent.service /usr/local/bin/soar-agent /etc/soar-agent/fleet.env /etc/soar-agent/fleet.token
EOF
