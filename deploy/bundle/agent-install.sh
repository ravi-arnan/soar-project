#!/usr/bin/env bash
# =============================================================================
# agent-install.sh — pasang soar-agent Rust di 1 workstation (tanpa Docker)
#
# Pemakaian di workstation target (butuh binary soar-agent, cara dapat di bawah):
#   sudo AGENT_ID=004 AGENT_NAME=laptop-budi SERVER=100.95.198.108 bash agent-install.sh
#
# Cara dapat binary (pilih satu):
#   a) build di mesin ini:      agent-rs/build-deb.sh  (butuh rustc/cargo)
#   b) scp dari mesin build:    scp agent-rs/target/x86_64-unknown-linux-musl/release/soar-agent target:/tmp/
#      -> script ini otomatis pakai /tmp/soar-agent kalau ada
#   c) .deb via package manager: sudo apt install ./soar-agent_0.1.0_amd64.deb
#      -> tidak butuh script ini sama sekali (systemd unit sudah dibawa .deb)
#
# Env yang dipahami:
#   AGENT_ID    id unik agent (004..100+)            [wajib untuk fleet rapi]
#   AGENT_NAME  nama tampil di dashboard             [default: rust-agent-$HOSTNAME]
#   SERVER      IP server SOAR (Tailscale/LAN)       [default: 100.95.198.108]
#   WATCH       path dipantau, dipisah koma          [default: ~/Downloads,~/Desktop,/run/media]
#
# ponytail: satu binary musl statis + satu unit systemd, tanpa enroll/key/manager —
# inilah klaim "setup lintas-device dipermudah" untuk 100 workstation.
# =============================================================================
set -euo pipefail

AGENT_ID="${AGENT_ID:-}"
AGENT_NAME="${AGENT_NAME:-rust-agent-$(hostname | tr 'A-Z' 'a-z' | cut -c1-20)}"
SERVER="${SERVER:-100.73.91.17}"
WATCH="${WATCH:-}"
BIN_SRC="${BIN_SRC:-/tmp/soar-agent}"
REPO_HINT="(clone repo SOAR, lihat agent-rs/README.md)"

[ "$(id -u)" = 0 ] || { echo "[x] jalankan sebagai root (sudo)"; exit 1; }
[ -n "$AGENT_ID" ] || { echo "[x] AGENT_ID wajib. Contoh: sudo AGENT_ID=004 SERVER=100.95.198.108 bash agent-install.sh"; exit 1; }

echo "[1/5] cari binary soar-agent"
if [ ! -f "$BIN_SRC" ]; then
  for c in agent-rs/target/x86_64-unknown-linux-musl/release/soar-agent \
           agent-rs/target/release/soar-agent; do
    [ -f "$c" ] && BIN_SRC="$c" && break
  done
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
Uninstall:      systemctl disable --now soar-agent && rm -f /etc/systemd/system/soar-agent.service /usr/local/bin/soar-agent
EOF
