#!/bin/bash
# Deploy custom Active Response "block-domain" (sinkhole domain phishing).
#   1. Copy script block-domain ke agent bin (/var/ossec/active-response/bin)
#   2. Register <command> + <active-response> block di manager ossec.conf
#   3. Restart wazuh-manager (container) + wazuh-agent (host)
#
# Usage: sudo bash scripts/deploy-block-domain.sh

set -e

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: jalankan dengan sudo"
  exit 1
fi

SCRIPT_DIR="/home/ravi/Projects/soar-project/scripts"
SRC="$SCRIPT_DIR/block-domain"
DST="/var/ossec/active-response/bin/block-domain"
CONTAINER="single-node-wazuh.manager-1"
MANAGER_CONF="/var/ossec/etc/ossec.conf"
TS=$(date +%Y%m%d-%H%M%S)

echo "=== STEP 1: Deploy script ke agent bin ==="
install -o root -g wazuh -m 750 "$SRC" "$DST"
echo "  OK: $DST (root:wazuh 750)"

echo ""
echo "=== STEP 2: Register command block-domain di MANAGER ==="
if docker exec "$CONTAINER" grep -q '<name>block-domain</name>' "$MANAGER_CONF" 2>/dev/null; then
  echo "  command block-domain sudah terdaftar — skip"
else
  docker exec "$CONTAINER" cp "$MANAGER_CONF" "${MANAGER_CONF}.bak-${TS}"
  echo "  backup manager config: ${MANAGER_CONF}.bak-${TS} (di container)"
  docker exec -i "$CONTAINER" python3 - <<'PY'
conf="/var/ossec/etc/ossec.conf"
s=open(conf).read()
block="""
  <command>
    <name>block-domain</name>
    <executable>block-domain</executable>
    <timeout_allowed>no</timeout_allowed>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>block-domain</command>
    <location>local</location>
    <rules_id>999998</rules_id>
  </active-response>
"""
# sisipkan sebelum </ossec_config> pertama
i=s.find("</ossec_config>")
if i==-1:
    raise SystemExit("ERROR: </ossec_config> tidak ditemukan")
s=s[:i]+block+"\n"+s[i:]
open(conf,"w").write(s)
print("  OK: command + active-response block disisipkan")
PY
fi

echo ""
echo "=== STEP 3: Restart wazuh-manager (load command baru) ==="
docker exec "$CONTAINER" /var/ossec/bin/wazuh-control restart 2>&1 | tail -3

echo ""
echo "=== STEP 4: Restart wazuh-agent (host) — ambil ar.conf baru ==="
systemctl restart wazuh-agent
sleep 4

echo ""
echo "=== Verify ==="
echo "ar.conf agent (harus memuat block-domain):"
grep -i 'block-domain' /var/ossec/etc/shared/ar.conf 2>/dev/null || echo "  (belum muncul — tunggu beberapa detik lalu cek lagi)"
echo ""
echo "Script terpasang:"
ls -l "$DST"

echo ""
echo "DONE. Test (sebagai user biasa, hati-hati: ini mengubah /etc/hosts Anda):"
echo "  Picu lewat webhook phishing dgn URL ber-deteksi VT, lalu klik tombol Blokir di Telegram."
echo ""
echo "Rollback command dari manager:"
echo "  docker exec $CONTAINER cp ${MANAGER_CONF}.bak-${TS} $MANAGER_CONF && docker exec $CONTAINER /var/ossec/bin/wazuh-control restart"
