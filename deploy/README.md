# deploy/ — Hardening & IaC (kategori D)

Menutup gap **D (keamanan platform)** + reproducibility di `ROADMAP.md`.

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
