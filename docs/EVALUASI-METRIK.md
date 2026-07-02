# Evaluasi Kuantitatif Sistem SOAR

Pengukuran **data nyata** dari sistem live untuk membuktikan klaim efektivitas — bukan estimasi.
Proyek: *Implementasi Sistem SOAR Open-Source Berbasis n8n…* — Ravi Arnan Irianto (2305551076).

## 1. Tujuan & metrik

| Metrik | Definisi | Menjawab masalah |
|--------|----------|-------------------|
| **MTTR (Mean Time To Respond)** | Waktu dari file malware muncul → file terkarantina (containment) | Kecepatan respons otomatis |
| **FP suppression rate** | % alert file "jinak" yang **tidak** memunculkan notifikasi/AR (dibanding baseline rule-only) | *Alert fatigue* / false positive |

## 2. Lingkungan & metodologi

- **Host uji:** agent `ravi-zorin` (Ubuntu/Zorin), FIM realtime `~/Downloads`.
- **Stack:** Wazuh 4.9.2 (Docker) + n8n + Ollama `llama3.2:3b` + VirusTotal (cache hangat).
- **E1 (MTTR):** 5× drop file EICAR, ukur selisih epoch milidetik `drop → hilang (terkarantina)` via polling 0,3 dtk. Jeda 12 dtk antar-run.
- **E2 (FP):** 5× drop file bersih beragam tipe (.jpg/.txt/.md/.csv/.yaml), jeda 20 dtk (hormati rate-limit VT free ≤4/mnt). Hitung Active Response yang terpicu; bandingkan dengan jumlah alert FIM yang Wazuh hasilkan (baseline rule-only).
- **Tanggal:** 2026-07-02.

## 3. Hasil E1 — MTTR malware auto-isolate

| Run | MTTR (detik) |
|-----|--------------|
| 1 | 1,81 |
| 2 | 1,51 |
| 3 | 2,12 |
| 4 | 1,21 |
| 5 | 1,21 |

| Statistik | Nilai |
|-----------|-------|
| **Rata-rata** | **1,57 dtk** |
| Median | 1,51 dtk |
| Min – Maks | 1,21 – 2,12 dtk |
| Std. deviasi | ± 0,35 dtk |

**Interpretasi:** dari malware muncul hingga terisolasi **≈1,5 detik** (VT cache hangat) — MTTR mendekati nol untuk ancaman keyakinan tinggi. Sebagai pembanding, respons manual analis SOC lazimnya menit–jam.

## 4. Hasil E2 — FP suppression (anti alert-fatigue)

| Run | File bersih | AR terpicu | Hasil |
|-----|-------------|-----------|-------|
| 1 | foto-liburan.jpg | 0 | disuppress |
| 2 | laporan.txt | 0 | disuppress |
| 3 | catatan.md | 0 | disuppress |
| 4 | data.csv | 0 | disuppress |
| 5 | config.yaml | 0 | disuppress |

| Ukuran | Baseline (rule-only Wazuh) | SOAR (VT-gated) |
|--------|-----------------------------|------------------|
| Alert FIM dihasilkan | **5** (rule 553/554) | 5 |
| **Notifikasi / Active Response** | **5** (setiap file baru = 1 alert) | **0** |
| **Reduksi false-positive** | — | **100% (5/5)** |

**Interpretasi:** Wazuh **tetap mendeteksi** kelima file (baseline rule-only akan memunculkan 5 notifikasi), tetapi lapisan VT-gating **menekan 100%**-nya karena VirusTotal bersih → analis tidak dibanjiri alert palsu. Inilah mekanisme konkret penekan *alert fatigue*.

## 5. Kesimpulan

- **MTTR containment ≈1,57 dtk** — respons otomatis nyaris seketika untuk ancaman keyakinan tinggi.
- **Reduksi false-positive 100%** pada berkas jinak — sistem hanya "bersuara" saat intelijen benar-benar mendeteksi, bukan sekadar "ada file baru".

Kedua angka ini mendukung klaim keunggulan pada tabel perbandingan (respons berjenjang berbasis keyakinan) dengan bukti terukur, bukan asumsi.

## 6. Keterbatasan (jujur)

- **N kecil** (5 per eksperimen) — indikatif, bukan signifikansi statistik penuh; perlu ulangan lebih banyak untuk laporan akhir.
- **MTTR diukur dengan VT cache hangat**; panggilan VT dingin/rate-limit akan lebih lambat (perlu diukur terpisah).
- **FP diukur untuk berkas jinak (true-negative)**, belum menguji **false-negative** (malware tak-dikenal/zero-day) — keterbatasan reputasi VT (lihat roadmap kategori B).
- Rate-limit VT free (≤4/mnt) membatasi **throughput** — perlu uji beban banyak-alert-serentak.
- Uji pada 1 host; agent `rocky-server` sudah diverifikasi fungsional terpisah.

## 7. Pengukuran lanjutan (untuk bab evaluasi penuh)

1. MTTR jalur **phishing** (deteksi → sinkhole) dan jalur **human-in-the-loop** (termasuk waktu keputusan analis).
2. MTTR VT **cold** vs **cache** (kuantifikasi manfaat cache).
3. **Uji beban**: N alert serentak → throughput, antrean, latensi Ollama.
4. **False-negative rate** atas korpus malware nyata + zero-day (uji keterbatasan reputasi).
5. Ulangi E1/E2 dengan N ≥ 30 untuk statistik yang kuat.
