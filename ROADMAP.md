# ROADMAP — SOAR Open-Source (Wazuh + n8n + HITL + AI Lokal)

Konsolidasi **gap (kesenjangan/masalah)** dan **solusi** untuk proyek:
*Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop* — Ravi Arnan Irianto (2305551076).

Kategori: (A) Bug keandalan, (B) Keandalan threat-intel, (C) Bukti ilmiah, (D) Keamanan platform, (E) Arsitektur, (F) Kontribusi terhadap masalah industri.

---

## A. Gap keandalan sistem (bug teramati saat pengujian) — prioritas #1

| Status | Gap | Akar masalah | Solusi yang diterapkan |
|--------|-----|--------------|------------------------|
| ✅ **SELESAI** (2026-07-02) | AR `block-domain` **hilang tiap container restart** | Manager sync `ossec.conf` dari template bind-mount tiap start; `block-domain` dulu hanya diedit runtime → tertimpa | Blok `block-domain` (command + active-response rules_id 999998) ditambahkan **permanen** ke template `wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf`. Terverifikasi via `--force-recreate`: block-domain0 tetap di ar.conf tanpa deploy script |
| ✅ **SELESAI** (2026-07-02) | **≥2 notifikasi untuk 1 file** | Karantina memindahkan file → FIM memicu event **`deleted`** → alert & eksekusi kedua (loop umpan balik) | Node `Ekstrak Alert` kini **mengabaikan event `deleted`** (`fimEvent === 'deleted' → return []`). Terverifikasi: EICAR → hanya **1** baris AR & 1 notifikasi (eksekusi event deleted berhenti di Ekstrak Alert). Tersimpan ke repo `n8n-workflows/deteksi-malware.json` |
| 🟡 **Dimitigasi / ditunda** | **Event phishing pertama terlewat** pasca-restart agent | Timing **logcollector** saat agent restart (seek ke EOF; `client_buffer` sudah aktif jadi bukan drop-disconnect). Tak ada toggle config yang menjamin fix | **Mitigasi operasional:** picu 1 event "pemanasan" setelah restart (sudah jadi praktik pra-demo). **Fix sejati (arsitektural, kategori E):** buffer/queue antara sumber log ↔ Wazuh. Di produksi dampak minim (gateway kirim banyak event); ini mayoritas artefak demo (injeksi manual tunggal) |

## B. Gap keandalan Threat Intelligence (VirusTotal/GSB/URLScan)

VT andal sebagai **sinyal pendukung** (ancaman dikenal), **bukan ground truth**.

| Gap | Dampak | Solusi |
|-----|--------|--------|
| **Zero-day / file baru → 0/70** | ⚠️ **False-negative** (jahat dianggap bersih → disuppress diam-diam) | Jangan bisukan file eksekutabel **tak-dikenal** di folder sensitif → arahkan ke **HITL (tombol)** |
| Hanya melihat **hash dikenal** (ganti 1 byte → hash baru) | Reputasi hash mudah dielakkan | **Deteksi perilaku** (rule Wazuh, sandbox lokal spt CAPEv2) |
| *Detection lag* (verdict berubah seiring waktu) | Cache bisa menyajikan verdict basi | **Re-scan terjadwal** + turunkan TTL cache verdict "bersih" |
| Ketergantungan 1 sumber | Single point of intel-failure | **Multi-sinyal/ensemble**: MalwareBazaar, Hybrid Analysis, **MISP** |
| Rate limit / downtime | Analisis gagal | ✅ Sudah ditangani `vt_unverified` (jangan dianggap bersih) |

**Prinsip:** perlakukan VT/GSB/URLScan sebagai **corroboration multi-sinyal**, bukan otoritas tunggal.

## C. Gap bukti ilmiah (paling menaikkan nilai) — prioritas #2

| Gap | Solusi |
|-----|--------|
| Klaim "unggul" belum terukur | **Metrik kuantitatif**: MTTR (deteksi→respons), **% reduksi false-positive** dari VT-gating (sebelum vs sesudah), *detection rate* atas korpus uji (EICAR/malware nyata + PhishTank/OpenPhish), uji beban (N alert serentak), latensi Ollama |
| "Kenapa n8n bukan Shuffle?" | Bandingkan **empiris** n8n vs Shuffle (fleksibilitas, latensi, biaya, maintenance) |
| Cakupan deteksi | Pemetaan **MITRE ATT&CK** per playbook; uji **false-negative** |

## D. Gap keamanan platform SOAR itu sendiri — prioritas #3

| Gap | Solusi |
|-----|--------|
| n8n rentan (CVE-2026-21858 "Ni8mare", CVSS 10.0; penyalahgunaan webhook) | Webhook **tidak diekspos publik** (poller keluar-saja di balik NAT — sudah), **reverse-proxy + TLS**, autentikasi, **segmentasi jaringan**, manajemen secret, versi ter-patch |
| Reproducibility | **IaC** (Ansible / docker-compose lengkap) — bukan Coolify; validasi/uji workflow otomatis |

## E. Gap arsitektur (jangka menengah–panjang)

| Gap | Solusi |
|-----|--------|
| **SPOF**: Wazuh single-node + n8n 1 container | **High-Availability**: manager/indexer redundan + load balancer + failover (selaras Springer CCIS 2026) |
| n8n single-process (SQLite, tanpa queue) → bottleneck saat lonjakan | **n8n queue mode** (Redis + worker) + **PostgreSQL** |
| State tidak terbagi/persist (cache VT di `staticData`) | Pindah cache ke **Redis** (survive restart, dibagi lintas-worker) |
| Kopling Wazuh↔n8n langsung (tanpa buffer) | **Message queue** (Redis/RabbitMQ) → buffering & replay |
| Tak ada observability pipeline | **Prometheus + Grafana** (sekaligus sumber data metrik bab evaluasi) |
| Ollama bersaing resource | AI sebagai **microservice inferensi** terpisah; opsi **RAG** atas playbook/threat-intel |

## F. Kontribusi terhadap masalah INDUSTRI (arah kebaruan)

Masalah industri 2025–2026: playbook rapuh/statis, *playbook rot* (silent-failure), alert fatigue (67% alert diabaikan), black-box → analis tak percaya, risiko LLM (halusinasi/kebocoran).

| Gap industri | Kontribusi yang diusulkan (dari fondasi proyek ini) |
|--------------|------------------------------------------------------|
| Automasi **gagal diam-diam** & tak sadar cakupan turun | **"Self-aware SOAR"**: kembangkan `vt_unverified` jadi **pemantau kesehatan/coverage** — laporkan saat intel down/webhook gagal/agent putus, alih-alih diam |
| **Black-box** merusak kepercayaan analis | Keputusan **explainable & auditable**: setiap aksi auto/tombol menjelaskan alasan (skor VT, verdict GSB, rule, keyakinan) + **audit-trail** keputusan analis |
| Alert yang **tak cocok playbook** → diam/dilempar | **LLM-fallback** (Ollama lokal) untuk alert tanpa aturan cocok → *advisory* ke analis (bukan auto-aksi) + **RAG** anti-halusinasi + AI tak pernah eksekusi AR sendiri |
| **Alert fatigue** | Formalkan & **ukur** reduksi FP dari respons berjenjang VT-gated (angka konkret) |
| HITL = bottleneck vs otonomi berisiko | **Trusted autonomy**: timeout/SLA + otonomi adaptif per tingkat keyakinan + umpan balik keputusan analis menyetel ambang |

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
