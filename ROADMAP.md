# ROADMAP — SOAR Open-Source (Wazuh + n8n + HITL + AI Lokal)

Konsolidasi **gap (kesenjangan/masalah)** dan **solusi** untuk proyek:
*Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop* — Ravi Arnan Irianto (2305551076).

Kategori: (A) Bug keandalan, (B) Keandalan threat-intel, (C) Bukti ilmiah, (D) Keamanan platform, (E) Arsitektur, (F) Kontribusi terhadap masalah industri, (G) Perluasan cakupan deteksi (penguatan TA), (H) Pemeliharaan & modernisasi stack.

---

## Status ringkas (per 2026-09-02)

### ✅ SUDAH dikerjakan
- **A#1** `block-domain` persist (permanen di template + config ter-version-control).
- **A#3** notifikasi ganda diperbaiki (abaikan event FIM `deleted` akibat karantina).
- **Reproducibility** config Wazuh manager ter-track (`config/` + `scripts/sync-wazuh-config.sh`).
- **C** metrik kuantitatif terukur (MTTR malware 1,68 dtk · phishing 2,13 dtk · FP suppression 100%).
- **B#1** hybrid: file eksekutabel tak-dikenal VT → tombol review (tutup celah zero-day utama).
- **F (explainable)** notifikasi malware **&** phishing memuat `🧠 Alasan keputusan`; **F (self-aware inline)** tandai `⚠️ Deteksi TERDEGRADASI` saat sumber rate-limit/error; **F (audit-trail)** keputusan analis dicatat `oleh <analis> pada <waktu WITA>` + riwayat eksekusi n8n.
- **F (self-aware health monitor, 2026-07-06)** `scripts/health-monitor.py` — poll komponen inti (agent putus via Wazuh API, n8n, Ollama), alert Telegram HANYA saat status berubah (anti-spam), state persist. Service `health-monitor` di compose.
- **D (hardening + IaC, 2026-07-06)** `deploy/hardened/` (Caddy reverse-proxy + TLS + basic-auth + segmentasi edge/backend, n8n tak publish port, `N8N_ENCRYPTION_KEY`) · **secret mgmt** `.env.example` · **IaC** `deploy/ansible/deploy-integration.yml` (idempoten).
- **H (pemeliharaan stack, 2026-09-02)** n8n di-update `2.35.7 → 2.36.9` — berada di atas semua versi patch CVE 2026 (Ni8mare/CVE-2026-21858 fixed di 1.121.0, CVE-2026-21877 di 1.121.3, CVE-2026-27495 di 1.123.22/2.x). Image python:3.12-alpine, caddy:2-alpine, Wazuh 4.9.2 di-pull ulang; seluruh container di-recreate & sehat (indexer cluster GREEN, 3 workflow n8n aktif).
- **C (bukti ilmiah, 2026-09-02)** Script benchmark (`scripts/benchmark-soar.py`) dibuat — 5 mode pengukuran (mttr-malware, mttr-phishing, load, vt-cold, fn-rate). Pemetaan MITRE ATT&CK (`docs/MITRE-ATTACK-MAPPING.md`: 10 teknik). Justifikasi n8n vs Shuffle (`docs/N8N-VS-SHUFFLE.md`: n8n 3.8/5 vs Shuffle 2.5/5). Evaluasi-metrik diperbarui.
- **B (multi-sumber + re-scan, 2026-09-02)** Script MalwareBazaar (`scripts/apply-b-malwarebazaar.py`): tambah node HTTP ke `mb-api.abuse.ch`, ensemble VT+MB (VT atau MB mendeteksi → THREAT), severity MB-aware, output fields MB. Script TTL diferensial (`scripts/apply-b-ttl-rescan.py`): malicious 7 hari, clean 24 jam, unknown 6 jam. Seluruh script perlu dijalankan di environment live + buat credential MalwareBazaar di n8n.

### ⬜ BELUM dikerjakan (sisa)
| Prioritas | Item | Kategori | Berat |
|-----------|------|----------|-------|
| — | **A#2** event pertama terlewat pasca-restart agent | A | dimitigasi (fix sejati = buffer/queue di E) |
| Menengah | **Jalankan** benchmark N≥30 + load test + VT cold-vs-cache (script: `scripts/benchmark-soar.py`) | C | sedang |
| Menengah | **Jalankan** apply-b-malwarebazaar + apply-b-ttl-rescan + buat credential MB di n8n | B | sedang |
| Lanjutan | **LLM-fallback** advisory + **RAG** anti-halusinasi; **trusted autonomy** (timeout/SLA) | F | berat |
| **#6** | **Arsitektur**: n8n queue-mode (Redis+worker) + PostgreSQL, HA, message-queue, observability | E | berat/berisiko ke live |
| Ditunda pasca-TA | **Upgrade Wazuh 4.9.2 → 4.14.7** terjadwal (agent ikut) | H3 | berat |

**Sisa hardening D di luar kode** (operasional, bukan artefak repo): firewall allow 1514/1515 dari subnet endpoint saja + **ganti password default Wazuh**.

**Rekomendasi lanjut berikutnya:** **Jalankan script B** (MalwareBazaar + TTL re-scan) di environment live, lalu **jalankan benchmark N≥30** untuk data numerik.

---

## A. Gap keandalan sistem (bug teramati saat pengujian) — prioritas #1

| Status | Gap | Akar masalah | Solusi yang diterapkan |
|--------|-----|--------------|------------------------|
| ✅ **SELESAI** (2026-07-02) | AR `block-domain` **hilang tiap container restart** | Manager sync `ossec.conf` dari template bind-mount tiap start; `block-domain` dulu hanya diedit runtime → tertimpa | Blok `block-domain` (command + active-response rules_id 999998) ditambahkan **permanen** ke template `wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf`. Terverifikasi via `--force-recreate`: block-domain0 tetap di ar.conf tanpa deploy script |
| ✅ **SELESAI** (2026-07-02) | **≥2 notifikasi untuk 1 file** | Karantina memindahkan file → FIM memicu event **`deleted`** → alert & eksekusi kedua (loop umpan balik) | Node `Ekstrak Alert` kini **mengabaikan event `deleted`** (`fimEvent === 'deleted' → return []`). Terverifikasi: EICAR → hanya **1** baris AR & 1 notifikasi (eksekusi event deleted berhenti di Ekstrak Alert). Tersimpan ke repo `n8n-workflows/deteksi-malware.json` |
| 🟡 **Dimitigasi / ditunda** | **Event phishing pertama terlewat** pasca-restart agent | Timing **logcollector** saat agent restart (seek ke EOF; `client_buffer` sudah aktif jadi bukan drop-disconnect). Tak ada toggle config yang menjamin fix | **Mitigasi operasional:** picu 1 event "pemanasan" setelah restart (sudah jadi praktik pra-demo). **Fix sejati (arsitektural, kategori E):** buffer/queue antara sumber log ↔ Wazuh. Di produksi dampak minim (gateway kirim banyak event); ini mayoritas artefak demo (injeksi manual tunggal) |

## B. Gap keandalan Threat Intelligence (VirusTotal/GSB/URLScan)

VT andal sebagai **sinyal pendukung** (ancaman dikenal), **bukan ground truth**.

| Status | Gap | Dampak | Solusi |
|--------|-----|--------|--------|
| ✅ **SELESAI** (2026-07-02) | **Zero-day / file baru → 0/70** | ⚠️ **False-negative** (jahat dianggap bersih → disuppress diam-diam) | Node `Rangkum Hasil` kini: file **eksekutabel/berisiko** (ekstensi .sh/.exe/.ps1/… ) yang **tak dikenal VT** → `review_unknown=true` → **THREAT jalur tombol (HITL)**, bukan silent/auto. File jinak non-eksekutabel tetap sunyi. **Terverifikasi:** `.sh` unknown → Telegram Alert (tombol); `.txt` unknown → sunyi. **Batas:** file eksekutabel **tanpa ekstensi** (ELF) belum tertangkap → lanjutan: deteksi magic-byte/exec-bit |
| ⬜ Lanjutan | Hanya melihat **hash dikenal** (ganti 1 byte → hash baru) | Reputasi hash mudah dielakkan | **Deteksi perilaku** (rule Wazuh, sandbox lokal spt CAPEv2) |
| ✅ Script siap (2026-09-02) | *Detection lag* (verdict berubah seiring waktu) | Cache bisa menyajikan verdict basi | **TTL diferensial** (`scripts/apply-b-ttl-rescan.py`): malicious 7 hari, clean 24 jam, unknown 6 jam. Verdict bersih di-cache lebih singkat → re-scan lebih cepat → turunkan FN rate |
| ✅ Script siap (2026-09-02) | Ketergantungan 1 sumber | Single point of intel-failure | **MalwareBazaar** sebagai sumber kedua (`scripts/apply-b-malwarebazaar.py`): ensemble VT+MB (VT atau MB mendeteksi → THREAT). Perlu buat credential MB di n8n + jalankan script |
| ✅ Sudah ada | Rate limit / downtime | Analisis gagal | Ditangani `vt_unverified` (jangan dianggap bersih) |

**Prinsip:** perlakukan VT/GSB/URLScan sebagai **corroboration multi-sinyal**, bukan otoritas tunggal.

## C. Gap bukti ilmiah (paling menaikkan nilai) — prioritas #2

| Status | Gap | Solusi / hasil |
|--------|-----|----------------|
| 🟢 **Terukur** (2026-07-02) | Klaim "unggul" belum terukur | **Data nyata (`docs/EVALUASI-METRIK.pdf`):** MTTR malware auto-isolate **1,68 dtk** (N=15, cache hangat); MTTR phishing auto-block **2,13 dtk** (N=5, jalur GSB); **reduksi false-positive 100%** (N=8: 8 alert FIM baseline → 0 notifikasi SOAR). **Lanjutan:** MTTR HITL & jalur URLScan, VT cold vs cache, uji beban, false-negative zero-day, ulangi N≥30 |
| ✅ **Selesai** (2026-09-02) | Justifikasi empiris **n8n vs Shuffle** | **`docs/N8N-VS-SHUFFLE.md`:** perbandingan 6 aspek (code execution, state, integrasi, observability, deployment, HITL). n8n 3.8/5 vs Shuffle 2.5/5. Bukti dalam kode (staticData cache, Code node HTTP, SQLite)
| ✅ **Selesai** (2026-09-02) | Pemetaan **MITRE ATT&CK** | **`docs/MITRE-ATTACK-MAPPING.md`:** 10 teknik unik (T1566.002, T1189, T1204.002, T1027, T1036, T1484, T1005, T1059, T1070.004, T1499). Visual matrix coverage + gap analysis
| ✅ **Selesai** (2026-09-02) | Script benchmark (uji beban + N≥30) | **`scripts/benchmark-soar.py`:** 5 mode (mttr-malware, mttr-phishing, load, vt-cold, fn-rate). Output JSON + tabel. Tinggal jalankan dengan N≥30
| ⬜ Belum dijalankan | **Jalankan benchmark N≥30** | Perlu environment live (VT API key, Wazuh running). Output ke `docs/EVALUASI-METRIK.pdf`

## D. Gap keamanan platform SOAR itu sendiri — prioritas #3 🟢 SEBAGIAN (2026-07-06)

| Status | Gap | Solusi |
|--------|-----|--------|
| ✅ **SELESAI** | n8n rentan (CVE-2026-21858 "Ni8mare", CVSS 10.0; penyalahgunaan webhook) | Webhook **tidak diekspos publik** (poller keluar-saja di balik NAT — sudah) + `deploy/hardened/`: **Caddy reverse-proxy + TLS + basic-auth** di depan editor, n8n **tak publish port** (hanya internal/Caddy), **segmentasi jaringan** edge/backend, **secret mgmt** (`.env.example` + `N8N_ENCRYPTION_KEY`, tanpa kredensial hardcode) |
| ✅ **SELESAI** | Reproducibility | **IaC** `deploy/ansible/deploy-integration.yml` — playbook idempoten ganti langkah manual `docker cp`/`docker exec` (integration script, AR scripts, blok `<integration>` ossec.conf, restart+verif) |
| ⬜ Operasional | Firewall + password default | Allow 1514/1515 dari subnet endpoint saja (DEPLOYMENT Step 7.1); **ganti password default Wazuh** sebelum produksi |

## E. Gap arsitektur (jangka menengah–panjang) ⬜ BELUM

| Gap | Solusi |
|-----|--------|
| **SPOF**: Wazuh single-node + n8n 1 container | **High-Availability**: manager/indexer redundan + load balancer + failover (selaras Springer CCIS 2026) |
| n8n single-process (SQLite, tanpa queue) → bottleneck saat lonjakan | **n8n queue mode** (Redis + worker) + **PostgreSQL** |
| State tidak terbagi/persist (cache VT di `staticData`) | Pindah cache ke **Redis** (survive restart, dibagi lintas-worker) |
| Kopling Wazuh↔n8n langsung (tanpa buffer) | **Message queue** (Redis/RabbitMQ) → buffering & replay |
| Tak ada observability pipeline | **Prometheus + Grafana** (sekaligus sumber data metrik bab evaluasi) |
| Ollama bersaing resource | AI sebagai **microservice inferensi** terpisah; opsi **RAG** atas playbook/threat-intel |

## F. Kontribusi terhadap masalah INDUSTRI (arah kebaruan) 🟢 SEBAGIAN

Masalah industri 2025–2026: playbook rapuh/statis, *playbook rot* (silent-failure), alert fatigue (67% alert diabaikan), black-box → analis tak percaya, risiko LLM (halusinasi/kebocoran).

| Status | Gap industri | Kontribusi (dari fondasi proyek ini) |
|--------|--------------|--------------------------------------|
| ✅ **SELESAI** (2026-07-06) | Automasi **gagal diam-diam** & tak sadar cakupan turun | **Self-aware (inline):** notifikasi menandai **`⚠️ Deteksi TERDEGRADASI`** saat VT rate-limit/error (`degraded`). **Self-aware (health monitor):** `scripts/health-monitor.py` poll agent (putus = blind spot), n8n, Ollama, Wazuh-API → Telegram alert HANYA saat status berubah (anti-spam), state persist lintas-restart |
| ✅ **SELESAI** (explainable+audit, 2026-07-02) | **Black-box** merusak kepercayaan analis | Setiap notifikasi (malware **&** phishing) memuat **`🧠 Alasan`** (skor VT/GSB + keyakinan + jalur). **Audit-trail:** callback handler mencatat keputusan analis **`oleh <analis> pada <waktu WITA>`** di pesan Telegram + riwayat eksekusi n8n (action/agent/target/analis). Catatan: log file dari Code node tak tersedia (fs sandbox n8n) → audit via Telegram+execution-history |
| ⬜ Lanjutan | Alert yang **tak cocok playbook** → diam/dilempar | **LLM-fallback** (Ollama) advisory + **RAG** anti-halusinasi + AI tak pernah eksekusi AR sendiri |
| ✅ **Terukur** (di C) | **Alert fatigue** | Reduksi FP VT-gated **100%** (lihat `docs/EVALUASI-METRIK.pdf`) |
| ⬜ Lanjutan | HITL = bottleneck vs otonomi berisiko | **Trusted autonomy**: timeout/SLA + otonomi adaptif per tingkat keyakinan |

## G. Perluasan cakupan deteksi (penguatan TA, selaras milestone M2–M3)

Scope sekarang (per batasan masalah 1.5): **malware via FIM + reputasi hash** dan **phishing via log akses URL**. Belum mencakup vektor lain — bukan kelemahan, tapi pilihan desain. Prioritas perluasan diurutkan nilai/effort. (Item multi-sumber/re-scan/sandbox sudah tercakup di bagian B — tidak diduplikasi di sini.)

| Prioritas | Item | Status sekarang | Aksi | Berat |
|-----------|------|-----------------|------|-------|
| 1 | **G1 — Phishing proaktif** (url/domain *belum* sempat diklik) | Reaktif: baru mendeteksi URL yang muncul di log akses | ✅ **SELESAI (2026-09-02):** workflow n8n `Proaktif Phishing (URLhaus)` — Schedule tiap jam → feed URLhaus CSV (`csv_recent/`, publik) → parse/filter `malware_download` (max 15/siklus) → verifikasi **GSB** per URL → **auto-`!block-domain`** ke agent 001 (via Wazuh API inline) untuk threat GSB; yang GSB `unavailable` → masuk **review** (tidak diklaim aman); bersih → silent. Cache 24 jam (staticData) anti-rescan. 1 notifikasi ringkasan Telegram per siklus (anti-spam). Teruji: feed→parse→GSB→review/block→notif. | sedang |
| 2 | **G2 — Magic-byte untuk file tanpa ekstensi** | B#1 baru menangkap file berekstensi (.sh/.exe/.ps1/…); ELF/MZ **tanpa ekstensi** lolos & disenyapkan | ✅ **SELESAI (2026-09-02):** deteksi **execute-bit via `perm_after`** dari alert FIM (check_all) — node `Ekstrak Alert` ekstrak `perm_after`/`no_ext`/`is_exec`; `Rangkum Hasil` perluas `review_unknown`: file **tanpa ekstensi + executable + VT unknown** → `risky_exec` → jalur tombol HITL, bukan sunyi. Teruji: file exec tanpa ekstensi + VT unknown → **REVIEW (tombol)**; file non-exec tanpa ekstensi → **sunyi** (tanpa FP) | sedang |
| 3 (opsional) | **G3 — Phishing email** (lampiran + tautan body) | Belum ada | Aturan Wazuh atas log mail/proxy; lampiran dialihkan ke pipeline malware (hash VT); tautan ke pipeline phishing | berat |
| 4 (opsional) | **G4 — Deteksi perilaku ringan** (auditd) sbg pemicu kedua | Hanya FIM (file jatuh ke disk) | Rule eksekusi mencurigakan (execve via auditd) → enrichment VT + HITL. Menangkap malware yang *berjalan*, bukan cuma *tersimpan* | berat |

## H. Pemeliharaan & modernisasi stack

| Status | Item | Catatan |
|--------|------|---------|
| ✅ **SELESAI** (2026-09-02) | **H1 — Update image & recreate** | n8n `2.35.7 → 2.36.9` (di atas semua versi patch CVE 2026); python/caddy/Wazuh di-pull; container di-recreate & sehat (indexer GREEN) |
| ✅ **SELESAI** (2026-09-02) | **H2 — Pin versi n8n** | `image: n8nio/n8n` → `n8nio/n8n:2.36.9` di `docker-compose.yml` root & `deploy/hardened/docker-compose.yml`. Digest tag = digest image berjalan (`a9e2e3c8…`), container di-recreate & sehat (healthz 200) |
| ⬜ Ditunda pasca-TA | **H3 — Upgrade Wazuh 4.9.2 → 4.14.7** | Stable terbaru jalur 4.x (30 Jul 2026). Ikuti panduan resmi `upgrading-wazuh-docker` (path cert dashboard/indexer berubah, update image + `wazuh_manager.conf`). **Agent wajib di-upgrade bareng** (kompatibilitas versi — risiko seperti insiden 4.14.5 dulu). Uji di lingkungan terpisah dulu |
| ⬜ Jangan dikejar | **H4 — Wazuh 5.0** | Masih **beta** (beta5, 1 Sep 2026) & breaking besar: engine sendiri, hapus Filebeat, path `/var/wazuh-manager`, hapus agent ID 000 → berdampak integratord + AR path lama. Evaluasi pasca-TA |
| Catatan | **H5 — Alternatif "lebih ringan"** | Tidak ada pengganti Wazuh setara yang lebih ringan: osquery/Falco/Velociraptor = fungsi lebih sedikit; Elastic/Graylog/Security Onion = selevel/lebih berat (Graylog SSPL). Resource sekarang sehat (~2,7 GB: indexer 1,5 GB, manager 0,5 GB, dashboard 0,2 GB, n8n 0,37 GB) |

---

## Prioritas eksekusi (sepadan-usaha)

1. ✅ **Perbaiki 3 bug keandalan (A)** — selesai (2026-07-02).
2. ✅ **Tambah metrik kuantitatif (C)** — dasar selesai (2026-07-02), lanjutan selesai (2026-09-02: script benchmark + MITRE mapping + n8n vs Shuffle).
3. **Jalankan benchmark N≥30** — script sudah ada, tinggal eksekusi di environment live.
4. ✅ **Deteksi hybrid/multi-sinyal (B)** — script MalwareBazaar + TTL re-scan selesai (2026-09-02). Tinggal jalankan di environment live.
5. ✅ **Housekeeping versi (H1–H2)** — selesai (2026-09-02).
6. ✅ **Perluasan cakupan (G1 + G2)** — selesai (2026-09-02).
7. ✅ **Hardening keamanan + IaC (D)** — sebagian selesai (2026-07-06).
8. ✅ **Kontribusi self-aware + explainable (F)** — sebagian selesai (2026-07-06).
9. **Arsitektur queue-mode + HA (E)** — jangka menengah.
10. **Modernisasi stack (H3/H4, pasca-TA)** — upgrade Wazuh 4.14.7 terjadwal; evaluasi 5.0 setelah stabil.

## Prinsip arah tesis
> SOAR open-source yang **confidence-based, transparan, dan sadar-degradasi** untuk menekan alert fatigue tanpa silent-failure — dengan human-in-the-loop yang dapat dipertanggungjawabkan.

*(Referensi lengkap ada di `docs/PERBANDINGAN-PENELITIAN.pdf`.)*
