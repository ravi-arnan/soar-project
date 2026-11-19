#!/bin/bash
# backup-soar.sh - Backup konsisten SQLite + state JSONL + volume n8n SOAR.
#
# Pemakaian:
#   ./scripts/backup-soar.sh                      # simpan ke ./backups/soar-backup-YYYYMMDD-HHMMSS
#   BACKUP_ROOT=/mnt/backup ./scripts/backup-soar.sh
#
# Restore (contoh):
#   1. Hentikan stack: docker compose down
#   2. Salin state/*.db & state/*.jsonl kembali ke ./state/
#   3. Restore volume n8n (jika ada n8n_data.tar.gz):
#      docker run --rm -v soar-project_n8n_data:/target -v "$BACKUP_DIR":/src alpine \
#        sh -c 'rm -rf /target/* && tar -xzf /src/n8n_data.tar.gz -C /target'
#   4. Jalankan ulang: docker compose up -d

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STATE_DIR="${SOAR_STATE_DIR:-$REPO_ROOT/state}"
BACKUP_ROOT="${BACKUP_ROOT:-$REPO_ROOT/backups/scheduled}"
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-14}"
N8N_VOLUME="${SOAR_N8N_VOLUME:-soar-project_n8n_data}"

STAMP="$(date +%Y%m%d-%H%M%S)"
DEST="$BACKUP_ROOT/soar-backup-$STAMP"
mkdir -p "$DEST/state"

echo "[1/4] Backup SQLite databases secara konsisten (.backup)"
for db in "$STATE_DIR"/*.db; do
  [ -f "$db" ] || continue
  base="$(basename "$db")"
  if command -v sqlite3 >/dev/null 2>&1; then
    sqlite3 "$db" ".backup '$DEST/state/$base'"
  else
    python3 - "$db" "$DEST/state/$base" <<'PY'
import sqlite3, sys
src = sqlite3.connect(sys.argv[1])
dst = sqlite3.connect(sys.argv[2])
with dst:
    src.backup(dst)
dst.close()
src.close()
PY
  fi
  echo "  - $base OK"
done

echo "[2/4] Salin file state JSON/JSONL"
for f in "$STATE_DIR"/*.json "$STATE_DIR"/*.jsonl; do
  [ -f "$f" ] || continue
  cp -p "$f" "$DEST/state/"
  echo "  - $(basename "$f") OK"
done

echo "[3/4] Backup Docker volume n8n ($N8N_VOLUME) jika tersedia"
if command -v docker >/dev/null 2>&1 && docker volume inspect "$N8N_VOLUME" >/dev/null 2>&1; then
  docker run --rm \
    -v "${N8N_VOLUME}:/source:ro" \
    -v "$DEST:/backup" \
    alpine:3.20 tar -czf /backup/n8n_data.tar.gz -C /source .
  echo "  - n8n_data.tar.gz OK"
else
  echo "  - skip (Docker/volume $N8N_VOLUME tidak ditemukan)"
fi

echo "[4/4] Hapus backup lama (> ${RETENTION_DAYS} hari)"
find "$BACKUP_ROOT" -maxdepth 1 -type d -name 'soar-backup-*' -mtime "+$RETENTION_DAYS" -exec rm -rf {} +

echo "Backup selesai: $DEST"
