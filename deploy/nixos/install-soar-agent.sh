#!/usr/bin/env bash
# Pasang soar-agent sebagai layanan NixOS di nixbox (idempoten, aman di-rerun).
#
#   sudo bash deploy/nixos/install-soar-agent.sh
#
# Yang dilakukan:
#   1. backup /etc/nixos/configuration.nix
#   2. tulis /etc/nixos/soar-agent.nix (import modul + setelan host)
#   3. tambahkan ./soar-agent.nix ke imports di configuration.nix (sekali saja)
#   4. nixos-rebuild switch
#
# Batal: hapus baris ./soar-agent.nix dari configuration.nix lalu rebuild lagi
# (atau `git -C /etc/nixos diff` kalau dikelola git), service langsung hilang.

set -euo pipefail

NIXOS_DIR=/etc/nixos
CONF="$NIXOS_DIR/configuration.nix"
MODULE_SRC="/home/ravi/Projects/soar-project/deploy/nixos/soar-agent.nix"
AGENT_SRC="/home/ravi/Projects/soar-project/agent-rs"
LOCAL="$NIXOS_DIR/soar-agent.nix"

AGENT_ID="${AGENT_ID:-002}"
AGENT_NAME="${AGENT_NAME:-nixbox}"
AGENT_USER="${AGENT_USER:-ravi}"
SERVER="${SERVER:-192.168.1.47}"
FLAKE_ATTR="${FLAKE_ATTR:-nixbox}"
POLL_TOKEN="${FLEET_AGENT_POLL_TOKEN:-}"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: jalankan dengan sudo (butuh tulis /etc/nixos + nixos-rebuild)" >&2
  exit 1
fi
if [[ ${#POLL_TOKEN} -lt 32 ]]; then
  echo "ERROR: FLEET_AGENT_POLL_TOKEN minimal 32 karakter" >&2
  exit 1
fi

for f in "$CONF" "$MODULE_SRC" "$AGENT_SRC/Cargo.lock"; do
  [[ -e $f ]] || { echo "ERROR: tidak ada $f" >&2; exit 1; }
done

# --- 1. backup ---------------------------------------------------------------
STAMP=$(date +%Y%m%d-%H%M%S)
if [[ ! -e "$CONF.bak-soar-agent" ]]; then
  cp -a "$CONF" "$CONF.bak-soar-agent"
  echo "[i] backup pertama: $CONF.bak-soar-agent"
fi
cp -a "$CONF" "$CONF.bak-$STAMP"
echo "[i] backup: $CONF.bak-$STAMP"

# --- 2. tulis modul lokal ----------------------------------------------------
cat >"$LOCAL" <<EOF
# Di-generate oleh deploy/nixos/install-soar-agent.sh — jangan diedit manual.
# Setelan per-host ada di sini; modulnya ada di repo soar-project.
{ ... }:

{
  imports = [ $MODULE_SRC ];

  services.soar-agent = {
    enable = true;
     agentId = "$AGENT_ID";
     agentName = "$AGENT_NAME";
     user = "$AGENT_USER";
     server = "$SERVER";

    packageSource = $AGENT_SRC;
  };
}
EOF
echo "[i] ditulis: $LOCAL"

# --- 3. sisipkan import (sekali saja) ---------------------------------------
if grep -q '\./soar-agent\.nix' "$CONF"; then
  echo "[=] imports sudah memuat ./soar-agent.nix"
else
  python3 - "$CONF" <<'PY'
import re, sys
p = sys.argv[1]
src = open(p).read()
# Sisipkan setelah entri hardware-configuration.nix di dalam blok imports.
pat = re.compile(r'(\n\s*\./hardware-configuration\.nix\s*\n)')
m = pat.search(src)
if not m:
    sys.exit("ERROR: tidak menemukan './hardware-configuration.nix' di imports")
src = src[:m.end()] + "    ./soar-agent.nix\n" + src[m.end():]
open(p, "w").write(src)
print("[+] ./soar-agent.nix ditambahkan ke imports")
PY
fi

install -d -m 700 -o "$AGENT_USER" -g "$(id -gn "$AGENT_USER")" /etc/soar-agent
printf '%s\n' "$POLL_TOKEN" > /etc/soar-agent/fleet.token
chown "$AGENT_USER:$(id -gn "$AGENT_USER")" /etc/soar-agent/fleet.token
chmod 600 /etc/soar-agent/fleet.token

# --- 4. rebuild --------------------------------------------------------------
echo "[i] nixos-rebuild switch --flake $NIXOS_DIR#$FLAKE_ATTR"
nixos-rebuild switch --impure --flake "$NIXOS_DIR#$FLAKE_ATTR"

echo
echo "[i] status:"
systemctl --no-pager --lines=15 status soar-agent || true
