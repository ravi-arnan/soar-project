# deploy/ — Hardening & IaC (kategori D)

Menutup gap **D (keamanan platform)** + reproducibility di `ROADMAP.md`.

## Quickstart — setup 1-perintah (arahan dospem 2026-09-11: "permudahkan setup lintas-device")

### Server (1 mesin, semua service)

```bash
bash deploy/setup-server.sh          # interaktif: tanya Telegram/VT/Gemini key sekali,
                                     # sisanya (encryption key, password acak, certs,
                                     # compose up, integrasi Wazuh, import workflow) otomatis
```

Script idempoten — jalankan ulang aman. Yang tersisa manual cuma yang butuh
akun browser kamu: buat bot @BotFather, buat API key n8n (Settings → n8n API),
ganti password default Wazuh dashboard.

### Sinkron credentials + workflow n8n (tanpa setup UI)

```bash
# Buat API key dulu: n8n UI → Settings → n8n API → Create API key
N8N_OWNER_API_KEY=xxx VT_API_KEY=yyy python3 deploy/n8n-setup.py --all
# atau tanpa VT_API_KEY (ditanya interaktif, tidak disimpan ke .env):
N8N_OWNER_API_KEY=xxx python3 deploy/n8n-setup.py --all
```

Yang dilakukan: buat/reuse 5 credentials dari `.env` (Telegram, Wazuh basic-auth,
GSB query-auth, urlscan header-auth, VirusTotal `x-apikey`) lalu import 4
workflow dengan **remap credential ID by name** — kelemahan import-from-file UI
(file bawa ID dari mesin lama → node merah) otomatis teratasi. Idempoten:
credential/workflow dengan nama sama di-update, bukan diduplikat.
`--dry-run` untuk lihat rencana tanpa API key.

### Workstation (100 PC, 3 jalur — pilih sesuai selera)

| Jalur | Perintah | Cocok untuk |
|-------|----------|-------------|
| **.deb / apt** | `agent-rs/build-deb.sh` lalu `sudo apt install ./soar-agent_0.1.0_amd64.deb` | admin yang terbiasa package manager |
| **1 host manual** | `sudo AGENT_ID=004 SERVER=<ip> bash deploy/agent-install.sh` | 1-2 mesin / percobaan |
| **fleet via Ansible** | isi `deploy/ansible/inventory-agents.ini` lalu `ansible-playbook -i inventory-agents.ini deploy-agents.yml -e server_ip=<ip>` | rollout massal + update binary sekali jalan |

Konfigurasi per-host cuma 4 baris di `/etc/default/soar-agent` (AGENT_ID,
AGENT_NAME, SERVER, WATCH) — binary sama untuk semua PC.

### Dashboard: GUI atau TUI, data sama

```bash
python3 scripts/fleet-monitor.py                  # GUI web  http://0.0.0.0:8080
python3 scripts/fleet-tui.py --url http://127.0.0.1:8080   # TUI (SSH-friendly)
```

TUI (`scripts/fleet-tui.py`, stdlib curses) membaca `/api/fleet` + `/api/events`
yang sama dengan GUI — 4 view (overview/agents/threat/health), cari agent (`/`),
saring severity (`e`), simulasi 100 PC (`s`).

## `hardened/` — deploy produksi (reverse-proxy + TLS + auth + segmentasi)

Beda dari compose demo di root repo:

| Aspek | Demo (root) | Hardened |
|-------|-------------|----------|
| Editor n8n | HTTP `localhost:5678` telanjang | di balik Caddy: **TLS + basic-auth** |
| Port n8n | publish ke host | **tidak** publish; hanya via Caddy/internal |
| Jaringan | 1 network | segmentasi **edge** vs **backend** |
| Secret n8n | default | `N8N_ENCRYPTION_KEY` dari `.env`, secure cookie |
| Webhook Wazuh | — | tetap jalur internal (tak lewat Caddy) |

```bash
cp .env.example .env         # isi N8N_ENCRYPTION_KEY, N8N_HOSTNAME, CADDY_*
docker run --rm caddy:2-alpine caddy hash-password --plaintext 'passwordmu'
#   -> tempel hasil ke CADDY_BASIC_AUTH_HASH di .env
openssl rand -hex 24         # -> N8N_ENCRYPTION_KEY
docker compose -f deploy/hardened/docker-compose.yml up -d
```

Akses editor: `https://<N8N_HOSTNAME>` (Caddy internal CA untuk `*.local` → trust
manual di browser, atau pakai domain publik untuk ACME otomatis).

Sisa hardening di luar compose: **firewall** (allow 1514/1515 hanya dari subnet
endpoint — lihat DEPLOYMENT Step 7.1) dan **ganti password default Wazuh**.

## `ansible/` — IaC deploy integrasi

Otomatiskan langkah manual `docker cp`/`docker exec` (DEPLOYMENT Step 2 + AR
scripts) jadi playbook idempoten:

```bash
cd deploy/ansible
cp inventory.ini.example inventory.ini
ansible-playbook -i inventory.ini deploy-integration.yml
```

Yang di-deploy: `custom-n8n.py` (integration bridge), AR scripts
`quarantine-file` + `block-domain`, blok `<integration>` di `ossec.conf`
(disisipkan sekali via marker), lalu restart + verifikasi `integratord`.
Butuh Docker CLI di target; nol dependency Ansible eksternal.

Dua hal yang harus diperiksa sebelum menjalankannya:

1. **`n8n_gw` di-hardcode `172.20.0.1:5678`.** Subnet bridge dialokasikan Docker
   per-host, jadi di mesin lain bisa berbeda (terverifikasi `172.19.0.1` di host
   NixOS). Override saat run:

   ```bash
   GW=$(docker network inspect single-node_default \
         -f '{{range .IPAM.Config}}{{.Gateway}}{{end}}')
   ansible-playbook -i inventory.ini deploy-integration.yml -e "n8n_gw=$GW:5678"
   ```

2. **Marker idempotensi hanya mengenali blok yang ditulis playbook ini.**
   Manager yang `<integration>`-nya pernah dipasang manual (mis. mengikuti
   DEPLOYMENT.md Step 2.2) tidak punya marker `SOAR-N8N-INTEGRATION`, sehingga
   playbook menyisipkan pasangan kedua dan blok lama yang basi tetap tinggal.
   Hapus blok manualnya lebih dulu, atau jalankan playbook hanya di manager yang
   masih bersih.

Di host tanpa Ansible (mis. NixOS), jalankan tanpa memasang apa pun:
`nix-shell -p ansible --run 'ansible-playbook -i inventory.ini deploy-integration.yml'`.
