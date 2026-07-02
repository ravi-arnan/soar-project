# ROADMAP — SOAR Open-Source (Wazuh + n8n + HITL + AI Lokal)

Konsolidasi **gap (kesenjangan/masalah)** dan **solusi** untuk proyek:
*Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop* — Ravi Arnan Irianto (2305551076).

Kategori: (A) Bug keandalan, (B) Keandalan threat-intel, (C) Bukti ilmiah, (D) Keamanan platform, (E) Arsitektur, (F) Kontribusi terhadap masalah industri.

---

## Status ringkas (per 2026-07-02)

### ✅ SUDAH dikerjakan
- **A#1** `block-domain` persist (permanen di template + config ter-version-control).
- **A#3** notifikasi ganda diperbaiki (abaikan event FIM `deleted` akibat karantina).
- **Reproducibility** config Wazuh manager ter-track (`config/` + `scripts/sync-wazuh-config.sh`).
- **C** metrik kuantitatif terukur (MTTR malware 1,68 dtk · phishing 2,13 dtk · FP suppression 100%).
- **B#1** hybrid: file eksekutabel tak-dikenal VT → tombol review (tutup celah zero-day utama).
- **F (explainable)** setiap notifikasi memuat `🧠 Alasan keputusan`; **F (self-aware inline)** tandai `⚠️ Deteksi TERDEGRADASI` saat VT rate-limit/error.

### ⬜ BELUM dikerjakan (sisa)
| Prioritas | Item | Kategori | Berat |
|-----------|------|----------|-------|
| — | **A#2** event pertama terlewat pasca-restart agent | A | dimitigasi (fix sejati = buffer/queue di E) |
| Menengah | MTTR HITL & URLScan, VT cold-vs-cache, **uji beban**, false-negative rate, ulangi N≥30 | C | sedang |
| Menengah | Justifikasi empiris **n8n vs Shuffle** + pemetaan **MITRE ATT&CK** | C | sedang |
| Menengah | **Deteksi perilaku** (sandbox/exec-bit), **multi-sumber** (MISP/MalwareBazaar), re-scan, TTL cache | B | berat |
| **#3** | **Hardening keamanan** (reverse-proxy+TLS, auth, segmentasi, secret mgmt) + **IaC** (Ansible) | D | sedang |
| — | **F sisa**: pemantau kesehatan/coverage penuh + **audit-trail** analis (explainable & degradasi inline SUDAH) | F | sedang |
| Lanjutan | **LLM-fallback** advisory + **RAG** anti-halusinasi; **trusted autonomy** (timeout/SLA) | F | berat |
| **#6** | **Arsitektur**: n8n queue-mode (Redis+worker) + PostgreSQL, HA, message-queue, observability | E | berat/berisiko ke live |

**Rekomendasi lanjut berikutnya:** **F** (self-aware + explainable) — orisinal, menjawab keluhan industri teratas, tanpa mengubah arsitektur berisiko. Alternatif: **D** (keamanan).

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
| ⬜ Lanjutan | *Detection lag* (verdict berubah seiring waktu) | Cache bisa menyajikan verdict basi | **Re-scan terjadwal** + turunkan TTL cache verdict "bersih" |
| ⬜ Lanjutan | Ketergantungan 1 sumber | Single point of intel-failure | **Multi-sinyal/ensemble**: MalwareBazaar, Hybrid Analysis, **MISP** |
| ✅ Sudah ada | Rate limit / downtime | Analisis gagal | Ditangani `vt_unverified` (jangan dianggap bersih) |

**Prinsip:** perlakukan VT/GSB/URLScan sebagai **corroboration multi-sinyal**, bukan otoritas tunggal.

## C. Gap bukti ilmiah (paling menaikkan nilai) — prioritas #2

| Status | Gap | Solusi / hasil |
|--------|-----|----------------|
| 🟢 **Terukur** (2026-07-02) | Klaim "unggul" belum terukur | **Data nyata (`docs/EVALUASI-METRIK.pdf`):** MTTR malware auto-isolate **1,68 dtk** (N=15, cache hangat); MTTR phishing auto-block **2,13 dtk** (N=5, jalur GSB); **reduksi false-positive 100%** (N=8: 8 alert FIM baseline → 0 notifikasi SOAR). **Lanjutan:** MTTR HITL & jalur URLScan, VT cold vs cache, uji beban, false-negative zero-day, ulangi N≥30 |
| "Kenapa n8n bukan Shuffle?" | Bandingkan **empiris** n8n vs Shuffle (fleksibilitas, latensi, biaya, maintenance) |
| Cakupan deteksi | Pemetaan **MITRE ATT&CK** per playbook; uji **false-negative** |

## D. Gap keamanan platform SOAR itu sendiri — prioritas #3 ⬜ BELUM

| Gap | Solusi |
|-----|--------|
| n8n rentan (CVE-2026-21858 "Ni8mare", CVSS 10.0; penyalahgunaan webhook) | Webhook **tidak diekspos publik** (poller keluar-saja di balik NAT — sudah), **reverse-proxy + TLS**, autentikasi, **segmentasi jaringan**, manajemen secret, versi ter-patch |
| Reproducibility | **IaC** (Ansible / docker-compose lengkap) — bukan Coolify; validasi/uji workflow otomatis |

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
| 🟢 **Sebagian** (2026-07-02) | Automasi **gagal diam-diam** & tak sadar cakupan turun | **Self-aware (inline):** notifikasi menandai **`⚠️ Deteksi TERDEGRADASI`** saat VT rate-limit/error (`degraded`) → tak diam-diam. **Lanjutan:** pemantau kesehatan/coverage penuh (agent putus/webhook gagal) |
| ✅ **SELESAI** (explainable, 2026-07-02) | **Black-box** merusak kepercayaan analis | Setiap notifikasi memuat **`🧠 Alasan keputusan`** (skor VT + tingkat keyakinan + jalur). Terverifikasi: auto-isolate → "VirusTotal 65/67 (≥20) → keyakinan tinggi, isolasi otomatis". **Lanjutan:** **audit-trail** keputusan analis (siapa/kapan) |
| ⬜ Lanjutan | Alert yang **tak cocok playbook** → diam/dilempar | **LLM-fallback** (Ollama) advisory + **RAG** anti-halusinasi + AI tak pernah eksekusi AR sendiri |
| ✅ **Terukur** (di C) | **Alert fatigue** | Reduksi FP VT-gated **100%** (lihat `docs/EVALUASI-METRIK.pdf`) |
| ⬜ Lanjutan | HITL = bottleneck vs otonomi berisiko | **Trusted autonomy**: timeout/SLA + otonomi adaptif per tingkat keyakinan |

---

## Prioritas eksekusi (sepadan-usaha)

1. **Perbaiki 3 bug keandalan (A)** — kredibel, berbasis bukti, cepat.
2. **Tambah metrik kuantitatif (C)** — membuktikan klaim "unggul".
3. **Deteksi hybrid/multi-sinyal (B)** — tutup celah false-negative zero-day.
4. **Hardening keamanan + IaC (D)** — kematangan & reproducibility.
5. **Kontribusi self-aware + explainable (F)** — kebaruan menjawab keluhan teratas industri.
6. **Arsitektur queue-mode + HA (E)** — jangka menengah.

## Prinsip arah tesis
> SOAR open-source yang **confidence-based, transparan, dan sadar-degradasi** untuk menekan alert fatigue tanpa silent-failure — dengan human-in-the-loop yang dapat dipertanggungjawabkan.

*(Referensi lengkap ada di `docs/PERBANDINGAN-PENELITIAN.pdf`.)*
