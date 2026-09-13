#!/bin/bash
# Sinkron config Wazuh manager SOAR-critical (ter-version di repo) ke lokasi
# bind-mount di dalam wazuh-docker/ (repo upstream, di-gitignore), lalu recreate
# manager agar entrypoint memuat ulang ossec.conf dari template.
#
# Kenapa perlu: wazuh-docker/ di-gitignore, jadi edit config di dalamnya TIDAK
# ter-version-control. Sumber kebenaran = config/wazuh/wazuh_manager.conf di repo.
# Isi penting yang harus persist: integrasi custom-n8n + Active Response
# quarantine-file (999999) & block-domain (999998).
#
# Usage: bash scripts/sync-wazuh-config.sh

set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/config/wazuh/wazuh_manager.conf"
DST="$REPO_ROOT/wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf"

if [[ ! -f "$SRC" ]]; then echo "ERROR: sumber tidak ada: $SRC"; exit 1; fi
if [[ ! -d "$(dirname "$DST")" ]]; then echo "ERROR: folder tujuan tidak ada (wazuh-docker belum di-clone?): $(dirname "$DST")"; exit 1; fi

cp "$SRC" "$DST"
echo "OK: config disalin -> $DST"
echo ""
echo "Verifikasi Active Response yang harus terdaftar:"
grep -E '<name>(quarantine-file|block-domain)</name>' "$DST" || echo "  (PERINGATAN: block/quarantine tidak ditemukan)"
echo ""
echo "Terapkan (recreate manager agar template ter-load):"
echo "  cd $REPO_ROOT/wazuh-docker/single-node && docker compose up -d --force-recreate wazuh.manager"
echo ""
echo "Setelah manager up (~40s), cek:"
echo "  docker exec single-node-wazuh.manager-1 grep -E 'block-domain|quarantine' /var/ossec/etc/shared/ar.conf"
