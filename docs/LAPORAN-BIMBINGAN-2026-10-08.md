# Laporan Bimbingan Tugas Akhir — Update & Perbandingan Milestone

| | |
|---|---|
| **NIM** | 2305551076 |
| **Nama** | Ravi Arnan Irianto |
| **Bidang Keahlian** | Network and Cloud Computing |
| **Mata Kuliah** | Proyek 1 — Semester Ganjil 2026/2027 (Semester 7) |
| **Judul** | Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop (Studi Kasus: CV Bali Handmade) |
| **Pembimbing 1** | Ir. I Nyoman Piarsa, ST., MT., IPM. |
| **Pembimbing 2** | A.A. Kt Agung Cahyawan Wiranatha, S.T., M.T. |
| **Tanggal laporan** | 8 Oktober 2026 |

---

## 1. Ringkasan

Laporan ini melampirkan **bukti pelaksanaan bimbingan**: (a) tindak lanjut atas catatan
bimbingan 3 September 2026, (b) update terbaru pekerjaan Tugas Akhir, dan (c) perbandingan
capaian dengan **7 milestone** Semester 7.

**Posisi saat ini: seluruh milestone yang jatuh tempo (M1–M2) selesai, dan M3–M6 sudah
berjalan lebih cepat dari jadwal (rata-rata capaian ≈ 81%).** Sistem berjalan **live** dan
telah diuji end-to-end.

---

## 2. Tindak lanjut catatan bimbingan 3 September 2026

| Arahan dospem (3 Sep) | Status | Bukti |
|---|---|---|
| Revisi diagram: n8n sebagai **otak orkestrasi**, alur eksplisit | ✅ Selesai | `docs/ARCHITECTURE.md`, `docs/FLOW.md`, `docs/diagrams/arsitektur-soar.png` |
| Format pertukaran data **JSON** (skema disepakati) didokumentasikan | ✅ Selesai | `docs/ARCHITECTURE.md` (skema payload) |
| Scope diperluas: **USB flashdisk** + perpindahan file | ✅ Selesai | Agen Rust: watch `~/Downloads`, `~/Desktop`, `/run/media/<user>` (recursive, auto-unwatch) |
| **Agen ringan** (dospem sarankan Go) — POC minggu itu | ✅ Selesai | `agent-rs/` (Rust, ~5,3 MB, RSS ~5,2 MB vs Wazuh agent ~50 MB). Alasan memilih Rust (bukan Go) di `docs/AGENT-RINGAN.md` |
| Skenario laporan gaya awam (100 workstation + HITL) | ✅ Selesai | `docs/diagrams/fig-karyawan-*`, narasi bab 1 laporan |
| Cek typo & kejelasan laporan per paragraf (pakai AI) | 🔄 Berjalan | `docs/Laporan-SOAR.md` (revisi berkelanjutan) |
| Progres mingguan + demo (1 server + beberapa klien) | ✅ Berjalan | Sistem live: 100-workstation ready, dashboard + TUI, fleet 7 endpoint |

---

## 3. Update terbaru (sejak bimbingan 3 September 2026)

**Keandalan & keamanan stack (LIVE, 8 Okt 2026)**
- **n8n `2.40.0 → 2.42.5`** — menutup batch CVE Okt 2026 (termasuk 2 Critical 9.0: CVE-2026-103255/103248). Deploy live, healthz ok, 5 workflow active, migrasi DB bersih, E2E hijau.
- **Wazuh `4.10.5 → 4.14.8`** — indexer cluster GREEN (data & `cluster_uuid` terjaga), manager `analysisd -t` rc=0, rule kustom selamat, agent 001/002 Active, integrasi kustom aktif, manager→n8n 200.

**Threat intelligence (memperkuat klaim multi-sumber)**
- **Cache verdict VT (TTL diferensial) + ensemble MalwareBazaar** — LIVE.
- **MISP (feed OSINT komunitas) sebagai sumber intel ke-4** — LIVE. Feed CIRCL OSINT (tanpa API key) di-index ke SQLite; node `MISP Lookup` di workflow, `misp_threat` menaikkan severity. **E2E: hash yang hanya dikenal MISP (VT 0, MB false) → severity HIGH** (celah false-negative tertutup).

**Bukti kuantitatif baru (menjawab permintaan bukti, bukan asumsi)**
- **MTTR jalur human-in-the-loop**: notifikasi siap **21,05 dtk** (N=5; ~18 dtk di antaranya biaya ringkasan LLM), eksekusi Active Response **0,07 dtk**.
- **VT cold vs cache**: tidak ada percepatan end-to-end (latensi didominasi MalwareBazaar + LLM) → **manfaat cache = penghematan kuota VT** (hits 10 / stores 14). Dilaporkan jujur; lihat `docs/EVALUASI-METRIK.md §11–§12`.

**Explainability & observability**
- Notifikasi memuat **alasan keputusan** + jejak audit; penandaan **deteksi terdegradasi**; **RAG anti-halusinasi** (playbook lokal); **trusted autonomy** (timeout/SLA).
- **Baru:** pencatat **alert Telegram keluar** (`alert-log`) — menutup celah Bot API (tidak ada histori keluar); tiap alert terkirim tercatat (severity, agent, hash, message_id).

**Perbaikan false-positive (kualitas keputusan)**
- File konfigurasi sistem (`hosts`) tidak lagi "MALWARE HIGH"; FP `rundll32` System32; verifikasi berbasis indikator threat-intel (bukan level rule FIM semata).

**Kajian relevansi & kebaruan (8 Okt 2026)**
- Sweep 2026 (versi komponen, CVE, tren industri, literatur) → `docs/RELEVANSI-2026.md`. Arah tesis (confidence-based, transparan, sadar-degradasi, HITL) **divalidasi literatur 2025–2026**; kontribusi diposisikan pada matriks confidence→otonomi + metrik terukur + audit-trail di konteks UKM.

---

## 4. Perbandingan dengan Milestone

Target jadwal: M1 Agu · M2 Sep · M3/M4 Okt · M5 Nov · M6 Nov–Des · M7 Des–Jan.

| M | Milestone | Target | Capaian | Status / Bukti |
|---|---|---|---|---|
| M1 | Konsolidasi purwarupa & lingkungan uji | Agu 2026 | **100%** | Selesai. A#1/A#3 tuntas, config ter-version-control, prosedur uji baku |
| M2 | Verifikasi ancaman **multi-sumber** | Sep 2026 | **100%** | **Selesai.** MalwareBazaar + magic-byte + TTL re-scan + **MISP** LIVE |
| M3 | Respons berjenjang berbasis keyakinan | Okt 2026 | **85%** | HITL 2-arah + SLA berjalan; sisa: **dokumen matriks confidence→otonomi** |
| M4 | Integrasi LLM & explainability | Okt 2026 | **80%** | LLM API + explainable + audit + AI tak eksekusi AR; sisa: **uji konsistensi keluaran LLM** |
| M5 | Pengerasan keamanan & reproduksibilitas | Nov 2026 | **60%** | IaC Ansible + bootstrap idempoten + dok. deploy; sisa: firewall 1514/1515 + ganti password default Wazuh |
| M6 | Pengujian & evaluasi kuantitatif | Nov–Des 2026 | **90%** | N≥30, load test, FN rate, MITRE mapping, n8n vs Shuffle, **MTTR HITL & VT cache** selesai |
| M7 | Laporan & seminar Proyek 1 | Des 2026–Jan 2027 | **50%** | Draf laporan berjalan; seminar akhir belum |

**Total capaian ≈ 81%** (rata-rata sederhana 565/7). **Lebih cepat dari jadwal** — pada 8 Okt
idealnya baru menuntaskan M1–M2 dan mengerjakan M3–M4; faktanya M5–M6 sudah berjalan.

Catatan: bobot 7 milestone diasumsikan setara; angka adalah penilaian berbasis bukti artefak
(ROADMAP, uji, E2E, benchmark), bukan klaim.

---

## 5. Hasil pengukuran (kumulatif)

| Metrik | Hasil | Keterangan |
|---|---|---|
| MTTR malware auto-isolate | **1,68 dtk** (N=15) | end-to-end, VT cache hangat |
| MTTR end-to-end via fleet-log | **3,00 dtk** (N=30) | injeksi → verdict tercatat |
| MTTR HITL — notifikasi | **21,05 dtk** (N=5) | injeksi → Telegram bertombol (≈18 dtk = LLM) |
| MTTR HITL — AR dispatch | **0,07 dtk** (N=5) | setelah keputusan → perintah AR |
| Throughput | **34 alert/detik** (N=20) | load test webhook |
| False-negative rate | **0,0%** (N=15) | semua file berisiko terdeteksi |
| FP suppression | **100%** (N=8) | 8 alert baseline → 0 notifikasi |
| MISP E2E | **HIGH** | hash hanya-dikenal-MISP menaikkan severity |

---

## 6. Rencana & item berikutnya

1. **M3** — susun dokumen **matriks confidence → aksi** (formalisasi respons berjenjang).
2. **M4** — **uji konsistensi keluaran LLM** (variasi output pada alert identik).
3. **M5** — pengerasan operasional: firewall 1514/1515 + ganti password default + rotasi kredensial.
4. **M7** — bukti laporan (screenshot dashboard + Telegram), kolom "Agen Ringan" di dokumen pembanding, draf bab hasil.
5. **Pasca-TA** — Wazuh 5.0, n8n queue-mode + HA (Redis/PostgreSQL), observability Prometheus/Grafana.

---

## 7. Lampiran — daftar artefak bukti

- **Kode & service**: `agent-rs/` (agen ringan), `scripts/misp-feed-sync.py`, `scripts/alert-log.py`, `scripts/benchmark-soar.py`, `scripts/patch-n8n-*.py`.
- **Uji**: `scripts/test_misp_feed.py` (18/18), `scripts/test_patch_n8n_misp.py` (14/14), `scripts/test_alert_log.py` (9/9), `scripts/e2e-misp-check.py`, `scripts/e2e-soar-check.py`.
- **Hasil pengukuran**: `docs/bench-*.json`, `docs/EVALUASI-METRIK.md`.
- **Dokumen**: `docs/RELEVANSI-2026.md`, `docs/ARCHITECTURE.md`, `docs/FLOW.md`, `docs/MITRE-ATTACK-MAPPING.md`, `docs/N8N-VS-SHUFFLE.md`, `docs/PERBANDINGAN-PENELITIAN.md`, `docs/AGENT-RINGAN.md`.
- **Roadmap & status**: `ROADMAP.md`, `HANDOFF.md`, `milestone/milestone.html`.
