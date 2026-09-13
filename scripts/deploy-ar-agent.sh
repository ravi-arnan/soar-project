#!/bin/bash
# Diagnose + deploy quarantine-file Active Response ke agent lokal (agent 001).
# Jalankan dengan sudo:  sudo bash scripts/deploy-ar-agent.sh
set -u

SRC="/home/ravi/Projects/soar-project/scripts/quarantine-file"
DST="/var/ossec/active-response/bin/quarantine-file"
ARLOG="/var/ossec/logs/active-responses.log"

echo "===== DIAGNOSA SEBELUM ====="
echo "[1] Script AR terpasang di agent?"
ls -la "$DST" 2>&1 || echo "  -> BELUM ADA (ini kemungkinan penyebabnya)"

echo
echo "[2] Registrasi di ar.conf (push dari manager)?"
grep -i quarantine /var/ossec/etc/shared/ar.conf 2>&1 || echo "  -> tidak ada entri quarantine di ar.conf"

echo
echo "[3] 15 baris terakhir active-responses.log:"
tail -15 "$ARLOG" 2>&1 || echo "  -> log tak terbaca"

echo
echo "===== DEPLOY ====="
if [ ! -f "$SRC" ]; then
  echo "FATAL: sumber $SRC tidak ditemukan"; exit 1
fi
install -o root -g wazuh -m 750 "$SRC" "$DST" && \
  echo "OK: $DST terpasang (root:wazuh 750)" || { echo "GAGAL install"; exit 1; }
ls -la "$DST"

echo
echo "===== RESTART AGENT ====="
systemctl restart wazuh-agent && echo "wazuh-agent restarted" || \
  /var/ossec/bin/wazuh-control restart

echo
echo "[4] Status agent:"
systemctl is-active wazuh-agent 2>/dev/null || /var/ossec/bin/wazuh-control status | grep -i agentd

echo
echo "Selesai. Sekarang tap lagi tombol Isolasi di alert baru untuk verifikasi."
