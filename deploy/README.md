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
