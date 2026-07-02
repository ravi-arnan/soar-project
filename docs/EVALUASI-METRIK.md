# Evaluasi Kuantitatif Sistem SOAR

Pengukuran **data nyata** dari sistem live untuk membuktikan klaim efektivitas — bukan estimasi.
Proyek: *Implementasi Sistem SOAR Open-Source Berbasis n8n…* — Ravi Arnan Irianto (2305551076).

## 1. Tujuan & metrik

| Metrik | Definisi | Menjawab masalah |
|--------|----------|-------------------|
| **MTTR (Mean Time To Respond)** | Waktu dari ancaman muncul → tindakan mitigasi selesai (containment) | Kecepatan respons otomatis |
| **FP suppression rate** | % alert berkas "jinak" yang **tidak** memunculkan notifikasi/AR (dibanding baseline rule-only) | *Alert fatigue* / false positive |

## 2. Lingkungan & metodologi

- **Host uji:** agent `ravi-zorin` (Ubuntu/Zorin), FIM realtime `~/Downloads`. Agent `rocky-server` (Rocky 9) diverifikasi fungsional terpisah.
- **Stack:** Wazuh 4.9.2 (Docker) + n8n + Ollama `llama3.2:3b` + VirusTotal (malware) + Google Safe Browsing/URLScan (phishing). VT cache hangat.
- **E1 — MTTR malware (N=15):** drop file EICAR, ukur selisih epoch milidetik `drop → hilang (terkarantina)` via polling 0,2 dtk. Jeda 12 dtk antar-run.
- **E3 — MTTR phishing auto-block (N=5):** bersihkan `/etc/hosts`, injeksi event URL ber-deteksi GSB, ukur `injeksi → domain ter-sinkhole di /etc/hosts`. Jeda antar-run; 1 event pemanasan tidak dihitung.
- **E2 — FP suppression (N=8):** drop berkas jinak beragam tipe (.jpg/.txt/.md/.csv/.yaml/.png/.json/.docx), jeda 20 dtk (hormati rate-limit VT free ≤4/mnt). Bandingkan Active Response yang terpicu dengan jumlah alert FIM yang Wazuh hasilkan (baseline rule-only).
- **Tanggal:** 2026-07-02.

## 3. Hasil E1 — MTTR malware auto-isolate (N=15)

Sampel (detik): 1,62 · 2,22 · 1,21 · 1,21 · 1,21 · 2,42 · 1,21 · 1,21 · 1,42 · 2,02 · 2,22 · 1,42 · 2,22 · 2,22 · 1,42

| Statistik | Nilai |
|-----------|-------|
| **Rata-rata** | **1,68 dtk** |
| Median | 1,42 dtk |
| Min – Maks | 1,21 – 2,42 dtk |
| Std. deviasi | ± 0,46 dtk |

**Interpretasi:** dari malware muncul hingga terisolasi **≈1,7 detik** (VT cache hangat) — MTTR containment mendekati nol untuk ancaman keyakinan tinggi. Pembanding: respons manual analis SOC lazimnya menit–jam.

## 4. Hasil E3 — MTTR phishing auto-block (N=5)

Sampel (detik): 1,83 · 2,44 · 2,13 · 1,83 · 2,43 — **5/5 berhasil** (tidak ada timeout).

| Statistik | Nilai |
|-----------|-------|
| **Rata-rata** | **2,13 dtk** |
| Median | 2,13 dtk |
| Min – Maks | 1,83 – 2,44 dtk |
| Std. deviasi | ± 0,27 dtk |

**Interpretasi:** dari URL phishing terdeteksi hingga domain ter-**sinkhole** ≈2,1 detik lewat jalur cepat Google Safe Browsing (tanpa menunggu URLScan). Konsisten (sd rendah).

## 5. Hasil E2 — FP suppression (anti alert-fatigue, N=8)

Kedelapan berkas jinak → **AR terpicu = 0** (semua disuppress).

| Ukuran | Baseline (rule-only Wazuh) | SOAR (VT-gated) |
|--------|-----------------------------|------------------|
| Alert FIM dihasilkan | **8** (rule 553/554) | 8 |
| **Notifikasi / Active Response** | **8** (setiap berkas baru = 1 alert) | **0** |
| **Reduksi false-positive** | — | **100% (8/8)** |

**Interpretasi:** Wazuh **tetap mendeteksi** kedelapan berkas (baseline rule-only akan memunculkan 8 notifikasi), tetapi lapisan VT-gating **menekan 100%**-nya karena VirusTotal bersih → analis tidak dibanjiri alert palsu. Ini mekanisme konkret penekan *alert fatigue*.

## 6. Ringkasan hasil

| Metrik | Hasil (data nyata) |
|--------|--------------------|
| MTTR malware auto-isolate (N=15) | **1,68 dtk** (median 1,42; ±0,46) |
| MTTR phishing auto-block (N=5) | **2,13 dtk** (±0,27) |
| Reduksi false-positive (N=8) | **100%** (8 alert baseline → 0 notifikasi) |

Ketiga angka mendukung klaim keunggulan pada tabel perbandingan (respons berjenjang berbasis keyakinan) dengan **bukti terukur**, bukan asumsi: respons otomatis ~1,7–2,1 dtk dan penekanan false-positive total pada berkas jinak.

## 7. Keterbatasan (jujur)

- **N moderat** (15/5/8) — indikatif kuat, namun laporan akhir sebaiknya N ≥ 30 untuk uji signifikansi.
- **MTTR diukur dengan VT cache hangat** dan jalur GSB cepat; panggilan dingin / rate-limit / jalur URLScan (±35 dtk) akan lebih lambat (perlu diukur terpisah).
- **FP diukur untuk berkas jinak (true-negative)**; **false-negative** (malware/URL tak-dikenal/zero-day) belum diuji — keterbatasan reputasi (roadmap kategori B).
- Rate-limit VT free (≤4/mnt) membatasi **throughput** — perlu uji beban banyak-alert-serentak.

## 8. Pengukuran lanjutan (untuk bab evaluasi penuh)

1. MTTR jalur **human-in-the-loop** (termasuk waktu keputusan analis) & jalur phishing **URLScan** (bukan hanya GSB).
2. MTTR VT **cold** vs **cache** (kuantifikasi manfaat cache).
3. **Uji beban**: N alert serentak → throughput, antrean, latensi Ollama.
4. **False-negative rate** atas korpus malware nyata + zero-day.
5. Ulangi seluruh eksperimen dengan **N ≥ 30**.
