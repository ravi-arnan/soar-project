# Runbook Upgrade Versi — Oktober 2026

Panduan upgrade **n8n** dan **Wazuh** untuk menutup CVE / mengejar versi stable.
Dasar: riset [`docs/ilmiah/RELEVANSI-2026.md`](RELEVANSI-2026.md) (2026-10-08).

**Status repo:** pin n8n **sudah** dipatch ke `2.42.5`. Wazuh **belum** dinaikkan —
menunggu jendela eksekusi (server `ravi-debian` offline saat runbook ini ditulis).
Verifikasi terakhir: `docker ps`, `curl localhost:5678/healthz`, `docker compose config`.

**Status eksekusi (2026-10-08):** §A n8n **SUDAH dijalankan & terverifikasi** di ravi-debian —
`n8n --version` = 2.42.5, healthz ok, 5 workflow active, migrasi DB "Finished", **E2E hijau**
(FIM 21 node, chain 8 node, 0 error). Backup compose: `docker-compose.yml.bak-20261008-183407`.

§B Wazuh **SUDAH dijalankan & terverifikasi** — `4.10.5 → 4.14.8`. Urut indexer→manager→dashboard.
Bukti: indexer cluster **GREEN** (data & cluster_uuid terjaga), manager `v4.14.8` + `analysisd -t` rc=0,
rule kustom selamat, agent 001/002 **Active**, integratord aktifkan 3 integrasi kustom,
**manager→n8n `healthz=200`**, fleet `wazuh_api: True`. Cert **tidak** diregenerasi (kompatibel 4.x).
Backup: `~/wazuh-backup-20261008-184204`, `docker-compose.yml.bak-20261008-184154`.

---

## A. n8n `2.40.0 → 2.42.5` (PRIORITAS — menutup CVE)

**Alasan:** batch CVE Okt 2026 menambal "2.40.0 before 2.40.1" — termasuk 2 **Critical 9.0**
(CVE-2026-103255, CVE-2026-103248) + beberapa High. `2.42.5` = stable terbaru (2026-10-08),
di atas semua versi patch. Alternatif minimal: `2.40.1` (tetap rentan ke patch setelahnya).

**Lokasi pin (repo, sudah diubah):** `docker-compose.yml:3`, `deploy/hardened/docker-compose.yml:29`, `README.md`.

### A.1 Pre-flight

```bash
cd ~/Projects/soar-project
docker compose ps                       # konfirmasi stack hidup
docker exec n8n n8n --version           # harus 2.40.0
# backup workflow live (kalau perlu): gunakan API key n8n + GET /api/v1/workflows
curl -fsS localhost:5678/healthz        # harapkan {"status":"ok"}
```

### A.2 Deploy

```bash
cd ~/Projects/soar-project
docker compose pull n8n
docker compose up -d n8n
docker exec n8n n8n --version           # harapkan 2.42.5
```

> **Gotcha DB:** n8n menjalankan migrasi skema SQLite saat start. **Downgrade tidak selalu
> aman** — jangan buru-buru balik ke 2.40.0 bila ada masalah; snapshot `n8n_data` dulu.

### A.3 Verifikasi

- `curl -fsS localhost:5678/healthz` → `ok`.
- Editor n8n: **5 workflow tetap `Active`** (Deteksi Malware, Deteksi Phishing, Proaktif Phishing, Telegram Callback, +1).
- E2E 1 alert sintetis ke `/webhook/wazuh-alert` → jalur `Build Payload → AI Generate → Send Telegram`
  tanpa error (perhatikan gotcha lama: output **FALSE** IF via API tidak mengeksekusi downstream — desain lama sudah pakai TRUE/fan-out).
- Dashboard & fleet tidak terpengaruh (backend terpisah).

---

## B. Wazuh `4.10.5 → 4.14.8` (modernisasi, bukan darurat CVE)

**Alasan:** 4.10.5 tertinggal; stable terbaru **4.14.8** (23 Sep 2026). **Tidak mendesak**
(tak ada CVE yang dikejar) → eksekusi di jendela terjadwal, bukan di tengah demo.

**Aturan penting:**
- **Manager harus ≥ versi agent.** Server 4.14.8 **bisa** mengelola agent 4.10.x/4.9.x tanpa
  upgrade agent lebih dulu. Urutan upgrade komponen: **Indexer → Manager → Dashboard**.
- **Preserve kustomisasi** (JANGAN timpa): `config/wazuh/wazuh_manager.conf` + blok `<integration>`,
  `block-domain` AR (rules_id 999998), rule chain `process-chain-rules.xml` (110001–110020),
  dan `config/` yang ter-version-control.
- Dari 4.10.5, langkah migrasi path (<4.8) **tidak** berlaku.

### B.1 Pre-flight / backup

```bash
cd ~/Projects/soar-project/wazuh-docker/single-node
docker compose ps
# backup konfigurasi kustom (di host):
cp -a config /tmp/wazuh-config-backup-$(date +%F)
# backup config live di container (kalau pernah diedit runtime):
docker exec single-node-wazuh.manager-1 cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak$(date +%F)
# catat versi
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control info
```
Snapshot volume indexer (opsional tapi disarankan) sebelum ubah versi.

### B.2 Ubah tag image (strategi: pertahankan compose kustom)

Edit `wazuh-docker/single-node/docker-compose.yml`:

```yaml
wazuh.manager:
  image: wazuh/wazuh-manager:4.14.8
wazuh.indexer:
  image: wazuh/wazuh-indexer:4.14.8
wazuh.dashboard:
  image: wazuh/wazuh-dashboard:4.14.8
```

Samakan `.env` (`WAZUH_VERSION=4.14.8`, `WAZUH_IMAGE_VERSION=4.14.8`, `FILEBEAT_TEMPLATE_BRANCH=4.14.8`).

### B.3 Regenerasi sertifikat (direkomendasikan oleh dok upgrade)

`single-node/generate-indexer-certs.yml`: pastikan generator `wazuh/wazuh-certs-generator:0.0.4`
+ tambah `CERT_TOOL_VERSION=4.14`, lalu:

```bash
cd ~/Projects/soar-project/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```

### B.4 Deploy (urutan indexer → manager → dashboard)

```bash
docker compose pull
docker compose up -d wazuh.indexer && sleep 30   # tunggu cluster GREEN
docker compose up -d wazuh.manager
docker compose up -d wazuh.dashboard
docker compose ps
```

> Alternatif resmi "default compose": `git fetch --all --tags && git checkout v4.14.8` —
> **hindari** bila kustomisasi kita belum di-rebase, karena menimpa `wazuh_manager.conf`.

### B.5 Verifikasi

- `docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control info` → `v4.14.8`.
- `wazuh-analysisd -t` → rc=0 (validasi rule kustom).
- Indexer cluster **GREEN**; `curl -k https://127.0.0.1:55000` API hidup (401 = normal).
- fleet health `wazuh_api: true`.
- E2E FIM: drop EICAR → agent → manager → n8n → Telegram.
- Agent 4.10.x tetap `Active` (manager ≥ agent). **Rekomendasi lanjutan:** upgrade agent ke 4.14.x
  saat sempat (feature parity; tidak wajib untuk kompatibilitas).

### B.6 Rollback

Kembalikan tag image ke `4.10.5` + `docker compose up -d` (sertifikat & data di volume persist).
Bila cert sudah diganti 4.14, regenerasi ulang dengan `CERT_TOOL_VERSION=4.10` sebelum rollback.

---

## C. Catatan

- **Wazuh 5.0** (Beta 5) **jangan** dikejar sekarang: bukan in-place, ada ubah format (XML→Sigma),
  field (`rule.level`→`wazuh.rule.level`), severity jadi label, dan data historis tak dimigrasi. Pasca-TA.
- Setelah semua upgrade hijau, samakan badge/versi di `README.md` dengan yang benar-benar ter-deploy.
