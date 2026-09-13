#!/usr/bin/env bash
# =============================================================================
# setup-server.sh — bootstrap 1-perintah server SOAR (Wazuh + n8n + monitors)
#
# Jawaban untuk arahan dospem: "kebayangnya script yang menjalankan/menginstall
# semua service yang diperlukan, lalu pertama minta api key dari virus total,
# dll ke orangnya."
#
# Yang dilakukan (idempoten — aman dijalankan ulang):
#   1. Cek prerequisites (docker, docker compose plugin, git, openssl, curl)
#   2. Generate .env interaktif — INTANYA yang ditanya ke manusia:
#      Telegram bot token + chat id, GSB/URLScan, Gemini, password Wazuh API.
#      Sisanya (encryption key, hash Caddy) digenerate otomatis.
#      VirusTotal key TIDAK lewat .env — diambil di Step 7 oleh n8n-setup.py
#      (dari VT_API_KEY env / prompt) langsung jadi credential n8n.
#   3. Clone wazuh-docker v4.9.2 + generate sertifikat indexer (kalau belum ada)
#   4. docker compose up Wazuh stack (manager/indexer/dashboard) + tunggu sehat
#   5. docker compose up stack inti (n8n + tg-callback-poller + health-monitor + fleet-monitor)
#   6. Deploy integrasi ke Wazuh manager via Ansible (kalau ada) — kalau tidak,
#      cetak perintah manual penggantinya
#   7. Sinkron credentials n8n dari .env (+ VT key via VT_API_KEY/prompt) dan
#      import 4 workflow dengan remap credential-ID via deploy/n8n-setup.py
#      (kalau N8N_OWNER_API_KEY diberikan; kalau tidak, cetak caranya)
#   8. Cetak checklist: yang TETAP harus manual (buat bot, isi credential n8n,
#      ganti password default) + tabel URL + cara test EICAR
#
# Pemakaian:
#   bash deploy/setup-server.sh              # interaktif
#   bash deploy/setup-server.sh --yes        # non-interaktif (pakai nilai .env yang sudah ada)
#   bash deploy/setup-server.sh --skip-wazuh # stack Wazuh sudah jalan, hanya stack inti
#   N8N_OWNER_API_KEY=xxx bash deploy/setup-server.sh --skip-wazuh
#
# ponytail: semua langkah idempoten — script bisa dijalankan ulang tanpa merusak
# state. Yang mahal (clone, certs, image pull) di-skip kalau sudah ada.
# =============================================================================
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

WAZUH_DIR="$REPO_ROOT/wazuh-docker"
WAZUH_VERSION="v4.9.2"
ENV_FILE="$REPO_ROOT/.env"
ASSUME_YES=0
SKIP_WAZUH=0

for arg in "$@"; do
  case "$arg" in
    --yes) ASSUME_YES=1 ;;
    --skip-wazuh) SKIP_WAZUH=1 ;;
    -h|--help) sed -n '2,40p' "$0"; exit 0 ;;
    *) echo "arg tidak dikenal: $arg"; exit 1 ;;
  esac
done

log()  { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!\033[0m] %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# ----------------------------------------------------------------- 1. prereqs
need() { command -v "$1" >/dev/null 2>&1 || die "butuh '$1' — install dulu (lihat docs/DEPLOYMENT.md Prerequisites)"; }
log "Step 1/7 — cek prerequisites"
need docker; need git; need openssl; need curl
docker compose version >/dev/null 2>&1 || die "docker compose plugin v2 belum ada (sudo apt install docker-compose-plugin)"
docker info >/dev/null 2>&1 || die "docker daemon tidak berjalan atau user belum di grup docker (logout/login setelah usermod)"

# --------------------------------------------------------- 2. .env interaktif
ask() { # ask VAR "pertanyaan" "default" [rahasia]
  local var="$1" q="$2" def="${3:-}" secret="${4:-}" cur="" ans=""
  cur="$(grep -E "^${var}=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  [ -n "$cur" ] && def="$cur"
  if [ "$ASSUME_YES" = 1 ]; then
    ans="$def"
  else
    if [ "$secret" = "1" ]; then
      printf '\033[1;36m?\033[0m %s%s: ' "$q" "${def:+ [sudah diisi, Enter=keep]}"
      read -r -s ans || true; printf '\n'
      [ -z "$ans" ] && ans="$def"
    else
      printf '\033[1;36m?\033[0m %s%s: ' "$q" "${def:+ [$def]}"
      read -r ans || true
      [ -z "$ans" ] && ans="$def"
    fi
  fi
  printf '%s=%s\n' "$var" "$ans" >> "$ENV_FILE.tmp"
}

if [ ! -f "$ENV_FILE" ] && [ -f "$ENV_FILE.example" ]; then
  cp "$ENV_FILE.example" "$ENV_FILE"
  log "Step 2/7 — .env belum ada: di-generate dari .env.example (jawab pertanyaannya)"
else
  log "Step 2/7 — .env ada: pertanyaan dilewati kecuali nilai masih kosong/placeholder"
fi

: > "$ENV_FILE.tmp"
grep -vE '^(TELEGRAM_BOT_TOKEN|TELEGRAM_CHAT_ID|GSB_API_KEY|URLSCAN_API_KEY|GEMINI_API_KEY|WAZUH_API_PASS|N8N_ENCRYPTION_KEY|CADDY_BASIC_AUTH_USER|CADDY_BASIC_AUTH_HASH)=' "$ENV_FILE" >> "$ENV_FILE.tmp" 2>/dev/null || true

ask TELEGRAM_BOT_TOKEN "Token bot Telegram (dari @BotFather, format 123456:ABC-...)" ""
ask TELEGRAM_CHAT_ID   "Chat ID tujuan alert (dari @get_id_bot; grup = -100...)" ""
ask GSB_API_KEY        "Google Safe Browsing API key (untuk phishing) [kosong=skip dulu]" ""
ask URLSCAN_API_KEY    "urlscan.io API key [kosong=skip dulu]" ""
ask GEMINI_API_KEY     "Gemini API key (aistudio.google.com/app/apikey, gratis 60 req/menit)" ""
CUR_WAZUH_PASS="$(grep -E '^WAZUH_API_PASS=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
if [ -z "$CUR_WAZUH_PASS" ] || [ "$CUR_WAZUH_PASS" = "change-me" ] || [ "$CUR_WAZUH_PASS" = "MyS3cr37P450r.*-" ]; then
  ask WAZUH_API_PASS "Password BARU Wazuh API user wazuh-wui [Enter=generate acak]" "$(openssl rand -base64 18 | tr -d '/+=' | cut -c1-20)" 1
else
  printf 'WAZUH_API_PASS=%s\n' "$CUR_WAZUH_PASS" >> "$ENV_FILE.tmp"
fi
CUR_ENC="$(grep -E '^N8N_ENCRYPTION_KEY=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
if [ -z "$CUR_ENC" ] || [[ "$CUR_ENC" == generate-with-* ]]; then
  log "N8N_ENCRYPTION_KEY digenerate otomatis (openssl rand -hex 24)"
  printf 'N8N_ENCRYPTION_KEY=%s\n' "$(openssl rand -hex 24)" >> "$ENV_FILE.tmp"
else
  printf 'N8N_ENCRYPTION_KEY=%s\n' "$CUR_ENC" >> "$ENV_FILE.tmp"
fi
CUR_CADDY_HASH="$(grep -E '^CADDY_BASIC_AUTH_HASH=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
if [ -z "$CUR_CADDY_HASH" ] || [[ "$CUR_CADDY_HASH" == *replace-with-caddy-hash* ]]; then
  CADDY_USER="$(grep -E '^CADDY_BASIC_AUTH_USER=' "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  CADDY_USER="${CADDY_USER:-admin}"
  printf 'CADDY_BASIC_AUTH_USER=%s\n' "$CADDY_USER" >> "$ENV_FILE.tmp"
  printf 'CADDY_BASIC_AUTH_HASH=%s\n' "$(docker run --rm caddy:2-alpine caddy hash-password --plaintext "$(openssl rand -base64 12 | tr -d '/+=')" 2>/dev/null | tail -1)" >> "$ENV_FILE.tmp"
  warn "Hash basic-auth Caddy digenerate acak — kalau mau pilih password sendiri: docker run --rm caddy:2-alpine caddy hash-password --plaintext 'passwordmu' lalu tempel ke CADDY_BASIC_AUTH_HASH di .env"
else
  printf 'CADDY_BASIC_AUTH_HASH=%s\n' "$CUR_CADDY_HASH" >> "$ENV_FILE.tmp"
fi
mv "$ENV_FILE.tmp" "$ENV_FILE"
chmod 600 "$ENV_FILE"
log ".env siap (mode 600, gitignored)"

# ------------------------------------------------------- 3. Wazuh + sertifikat
if [ "$SKIP_WAZUH" = 0 ]; then
  log "Step 3/7 — Wazuh $WAZUH_VERSION + sertifikat indexer"
  if [ ! -d "$WAZUH_DIR/.git" ]; then
    git clone https://github.com/wazuh/wazuh-docker.git "$WAZUH_DIR"
  fi
  git -C "$WAZUH_DIR" checkout -q "$WAZUH_VERSION"
  if [ ! -f "$WAZUH_DIR/single-node/config/wazuh_indexer/wazuh.indexer.ssl.key" ]; then
    (cd "$WAZUH_DIR/single-node" && docker compose -f generate-indexer-certs.yml run --rm generator)
  fi
  log "Step 4/7 — start Wazuh stack (pull image bisa lama, sekali saja)"
  (cd "$WAZUH_DIR/single-node" && docker compose up -d)
  log "tunggu indexer sehat (max 3 menit)..."
  for _ in $(seq 1 36); do
    if curl -sk -u "admin:$(grep -E '^INDEXER_PASS' "$WAZUH_DIR/single-node/config/wazuh_indexer/wazuh1.internal_users.yml" 2>/dev/null | head -1 | grep -oE '"[^"]+"' | tr -d '"' || echo admin)" https://127.0.0.1:9200 >/dev/null 2>&1 \
       || curl -sk https://127.0.0.1:9200 >/dev/null 2>&1; then
      log "indexer merespon"; break
    fi
    sleep 5
  done
else
  log "Step 3-4/7 — dilewati (--skip-wazuh), asumsi Wazuh stack sudah jalan"
fi

# ----------------------------------------------------------- 5. stack inti SOAR
log "Step 5/7 — start stack inti (n8n + tg-callback-poller + health-monitor + fleet-monitor)"
REPO_DIR_NAME="$(basename "$REPO_ROOT")"
if [ "$REPO_DIR_NAME" != "soar-project" ]; then
  warn "docker-compose.yml memakai bind-mount /home/ravi/Projects/soar-project/scripts."
  warn "Repo kamu ada di: $REPO_ROOT — sesuaikan volume compose atau symlink:"
  warn "  sudo mkdir -p /home/ravi/Projects && sudo ln -s \"$REPO_ROOT\" /home/ravi/Projects/soar-project"
  warn "(jangan di-sed — file compose ter-track git)"
fi
docker compose up -d

# ------------------------------------------------ 6. integrasi Wazuh (Ansible)
log "Step 6/7 — deploy integrasi SOAR ke Wazuh manager"
if command -v ansible-playbook >/dev/null 2>&1; then
  if [ ! -f deploy/ansible/inventory.ini ]; then
    cp deploy/ansible/inventory.ini.example deploy/ansible/inventory.ini
  fi
  GW="$(docker network inspect single-node_default -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || echo 172.20.0.1)"
  ansible-playbook -i deploy/ansible/inventory.ini deploy/ansible/deploy-integration.yml -e "n8n_gw=${GW}:5678" \
    && log "integrasi terpasang (custom-n8n + AR scripts + <integration> block)" \
    || warn "ansible-playbook gagal — jalankan manual, lihat deploy/README.md"
else
  warn "ansible tidak terpasang — deploy integrasi manual:"
  warn "  nix-shell -p ansible --run 'ansible-playbook -i deploy/ansible/inventory.ini deploy/ansible/deploy-integration.yml'"
  warn "  atau ikuti docs/DEPLOYMENT.md Step 2 (docker cp + ossec.conf + restart)"
fi

# ------------------------------------------------- 7. credentials + workflows
N8N_BASE="${N8N_URL:-http://127.0.0.1:5678}"
if [ -n "${N8N_OWNER_API_KEY:-}" ]; then
  log "Step 7/7 — sinkron credentials + import workflow (deploy/n8n-setup.py)"
  VT_ARG=""
  [ -n "${VT_API_KEY:-}" ] && VT_ARG="--vt-key ${VT_API_KEY}"
  if python3 "$REPO_ROOT/deploy/n8n-setup.py" --url "$N8N_BASE" --all $VT_ARG; then
    log "  credentials (Telegram/Wazuh/GSB/urlscan/VT) + 4 workflow tersinkron,"
    log "  credential ID di-remap by name -> node tidak merah, tanpa setup UI."
  else
    warn "  n8n-setup gagal — cek N8N_OWNER_API_KEY, lalu jalankan ulang:"
    warn "    N8N_OWNER_API_KEY=xxx python3 deploy/n8n-setup.py --all"
  fi
else
  log "Step 7/7 — sinkronisasi n8n dilewati (butuh N8N_OWNER_API_KEY)"
  warn "  Buat API key: n8n UI → Settings → n8n API → Create API key, lalu:"
  warn "    N8N_OWNER_API_KEY=xxx python3 deploy/n8n-setup.py --all   # VT key ditanya/dari $VT_API_KEY"
  warn "  Alternatif manual: n8n UI → Import from File (node akan MERAH — credential ID tidak di-remap)"
fi

# ------------------------------------------------------------------- ringkasan
cat <<'EOF'

============================================================
 SOAR server siap. Yang OTOMATIS tadi: docker stack (Wazuh
 manager/indexer/dashboard, n8n, tg-callback-poller, health
 monitor, fleet monitor) + integrasi Wazuh<->n8n + .env.

 Yang TETAP MANUAL (butuh akun browser kamu):
  1. Buat bot: Telegram @BotFather -> /newbot -> token sudah
     ditanya di atas. Kalau belum, isi TELEGRAM_BOT_TOKEN di .env.
  2. Chat ID: DM @get_id_bot -> isi TELEGRAM_CHAT_ID di .env.
  3. VirusTotal API key (free): https://www.virustotal.com/gui/my-apikey
     -> SUDAH OTOMATIS kalau tadi set VT_API_KEY=xxx saat menjalankan script
        (credential n8n "VirusTotal API Key" dibuat + di-remap ke node).
        Belum? Jalankan: N8N_OWNER_API_KEY=xxx VT_API_KEY=yyy \
          python3 deploy/n8n-setup.py --push-credentials --import-workflows
        (VT key tidak pernah disimpan ke .env.)
  4. Gemini key sudah kamu isi; kalau kosong, workflows AI akan error.
  5. GANTI password default Wazuh (dashboard + wazuh-wui) sebelum dipakai
     beneran — pass acak untuk wazuh-wui sudah di .env, sinkronkan ke
     wazuh-docker/single-node/config/wazuh_indexer/wazuh1.internal_users.yml
     lalu `docker compose restart wazuh.indexer wazuh.dashboard`.
  6. Firewall: allow 1514/1515 hanya dari subnet endpoint (docs/DEPLOYMENT.md 7.1).

 URL (di server / via Tailscale IP):
  - n8n (otak):        http://127.0.0.1:5678
  - Fleet Monitor GUI: http://127.0.0.1:8080   (browser)
  - Fleet Monitor TUI: python3 scripts/fleet-tui.py --url http://127.0.0.1:8080
  - Wazuh Dashboard:   https://127.0.0.1:5601  (self-signed)

 Test end-to-end (EICAR):
  printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.com
  -> Telegram: alert CRITICAL + tombol Isolasi/Abaikan + alasan AI.
============================================================
EOF
log "selesai. Re-run script ini kapan saja — semua langkah idempoten."
