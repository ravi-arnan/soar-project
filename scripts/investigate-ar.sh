#!/bin/bash
# READ-ONLY: investigasi kenapa Active Response quarantine-file tidak memindahkan
# file di agent 001. Tidak mengubah apa pun. Jalankan: sudo bash scripts/investigate-ar.sh
echo "===== [1] Binary AR di agent (SMOKING GUN) ====="
echo "Isi /var/ossec/active-response/bin/:"
ls -la /var/ossec/active-response/bin/ 2>&1
echo
if [ -f /var/ossec/active-response/bin/quarantine-file ]; then
  echo ">> quarantine-file ADA. Cek izin/owner (harus root:wazuh, 750) di atas."
else
  echo ">> quarantine-file TIDAK ADA -> ini penyebabnya (execd tak punya script untuk dijalankan)."
fi

echo
echo "===== [2] ar.conf yang diterima agent ====="
cat /var/ossec/etc/shared/ar.conf 2>&1

echo
echo "===== [3] active-responses.log agent (30 baris terakhir) ====="
echo "Cari baris sekitar waktu tap tombol (mis. error 'Cannot ...' / 'No such file'),"
echo "atau pesan dari script kita 'quarantine-file: QUARANTINED/GAGAL/tidak ditemukan'."
tail -30 /var/ossec/logs/active-responses.log 2>&1

echo
echo "===== [4] Error execd/AR di ossec.log agent ====="
grep -iE "quarantine|active.?response|execd|Cannot exec|No such" /var/ossec/logs/ossec.log 2>&1 | tail -20

echo
echo "===== [5] Versi & status agent ====="
/var/ossec/bin/wazuh-control info 2>&1 | head -3
/var/ossec/bin/wazuh-control status 2>&1 | grep -iE "execd|agentd"
echo
echo "Selesai (read-only)."
