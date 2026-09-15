#!/usr/bin/env bash
# =============================================================================
# build-deb.sh — build soar-agent musl statis + bungkus .deb (package manager)
#
# Hasil: agent-rs/dist/soar-agent_<versi>_amd64.deb
# Pasang di workstation:   sudo apt install ./soar-agent_0.1.0_amd64.deb
# Uninstall:               sudo apt remove soar-agent
# Upgrade = pasang .deb versi lebih tinggi (systemd unit ikut terganti).
#
# Isi .deb:
#   /usr/local/bin/soar-agent                    binary musl statis (~5 MB)
#   /etc/systemd/system/soar-agent.service       unit (disabled default; config
#                                                per-host via env /etc/default/soar-agent)
#   /etc/default/soar-agent                      AGENT_ID/AGENT_NAME/SERVER/WATCH diisi admin
#   /var/ossec/quarantine/                       direktori karantina
#
# Konfigurasi per-host setelah install: edit /etc/default/soar-agent lalu
#   sudo systemctl enable --now soar-agent
#
# ponytail: unit di .deb pakai EnvironmentFile — binary sama untuk 100 PC,
# yang beda cuma 4 baris config per host (AGENT_ID/NAME/SERVER/WATCH).
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")"
VERSION="$(grep -m1 '^version' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')"
ARCH="amd64"
DIST="dist"
DEBROOT="$DIST/soar-agent_${VERSION}_${ARCH}"
# ponytail: default musl statis; override BIN=... untuk toolchain tanpa std
# musl (mis. cargo distro): BIN=target/release/soar-agent ./build-deb.sh
BIN="${BIN:-target/x86_64-unknown-linux-musl/release/soar-agent}"

echo "[1/4] build musl statis"
rustup target add x86_64-unknown-linux-musl 2>/dev/null || true
if command -v cross >/dev/null 2>&1; then
  cross build --release --target x86_64-unknown-linux-musl
else
  cargo build --release --target x86_64-unknown-linux-musl
fi
[ -f "$BIN" ] || { echo "[x] binary tidak ditemukan: $BIN"; exit 1; }
strip "$BIN" 2>/dev/null || true

echo "[2/4] susun tree .deb ($DEBROOT)"
mkdir -p "$DIST"
rm -rf "$DEBROOT"
install -Dm755 "$BIN"                     "$DEBROOT/usr/local/bin/soar-agent"
install -Dm644 dist/soar-agent.service    "$DEBROOT/etc/systemd/system/soar-agent.service"
install -Dm644 dist/soar-agent.default    "$DEBROOT/etc/default/soar-agent"
install -dm750                            "$DEBROOT/var/ossec/quarantine"

echo "[3/4] tulis control"
mkdir -p "$DEBROOT/DEBIAN"
cat > "$DEBROOT/DEBIAN/control" <<EOF
Package: soar-agent
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Ravi Arnan <raviarnankeren@gmail.com>
Description: Agen ringan SOAR (Rust) - pantau file, hitung sha256, POST JSON ke n8n
 Alternatif ringan Wazuh Agent: binary statis ~5 MB, RSS ~5 MB, tanpa
 enroll/manager. Bagian dari TA SOAR n8n (HITL Telegram).
Homepage: https://github.com/raviarnan/soar-project
License: GPL-2.0
EOF

cat > "$DEBROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
mkdir -p /var/ossec/quarantine && chmod 750 /var/ossec/quarantine
systemctl daemon-reload || true
echo "soar-agent terpasang. Konfigurasi: /etc/default/soar-agent"
echo "lalu: sudo systemctl enable --now soar-agent"
EOF

cat > "$DEBROOT/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
systemctl stop soar-agent 2>/dev/null || true
systemctl disable soar-agent 2>/dev/null || true
EOF

chmod 755 "$DEBROOT/DEBIAN/postinst" "$DEBROOT/DEBIAN/prerm"

echo "[4/4] dpkg-deb"
mkdir -p "$DIST"
dpkg-deb --build --root-owner-group "$DEBROOT"
echo "selesai: $DIST/soar-agent_${VERSION}_${ARCH}.deb"
echo
echo "Distribusi ke 100 PC (pilih salah satu):"
echo "  scp + apt : scp $DIST/soar-agent_${VERSION}_${ARCH}.deb user@pc:/tmp/ && ssh user@pc sudo apt install /tmp/soar-agent_${VERSION}_${ARCH}.deb"
echo "  ansible   : lihat deploy/ansible/deploy-agents.yml"
echo "  apt repo  : mini-dinstall/reprepro — future work"
