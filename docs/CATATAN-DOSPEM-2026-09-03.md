# Catatan Bimbingan Dospem - 2026-09-03

Dosen: I Nyoman Piarsa
Mahasiswa: Ravi Arnan Irianto (2305551076) + Ezza Putra Wibawa + Chalimus Candra
Judul: Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop

## 1. Ringkasan alur yang disepakati (versi bahasa awam)

Dospem minta bisa menjelaskan tanpa bahasa teknis. Skenario yang dia validasi:

> Saya admin IT punya 100 workstation. Tidak mungkin cek satu per satu. Jadi saya bangun 1 server pusat dan agen kecil di tiap laptop. Karyawan A tidak sengaja download file dari link aneh -> agen di laptop A deteksi ada file baru -> agen hitung ciri file (hash/signature) -> kirim JSON ke server pusat (n8n) -> server cek ke VirusTotal dan AI lokal -> server kirim notifikasi Telegram ke admin dengan tombol -> admin klik Isolasi atau Abaikan -> agen eksekusi.

Kalau bisa cerita itu ke orang awam dan orangnya paham, berarti kita paham sistem sendiri.

## 2. Apa yang sudah benar di implementasi sekarang

- Agen hitung hash lalu kirim JSON, bukan kirim file utuh. Ini efisien untuk file besar (1 GB tidak dikirim). `scripts/custom-n8n.py` sudah memisahkan payload malware vs phishing.
- n8n sebagai otak orkestrasi. Wazuh agent hanya deteksi, semua keputusan di n8n (cek VT, cek AI, tentukan severity, kirim Telegram).
- Human-in-the-loop: Telegram bot kirim inline keyboard `iso:<agentId>` / `ign:<agentId>`, eksekusi `quarantine-file` baru jalan setelah admin klik Isolasi. Model ini sudah disepakati dospem.

Referensi: `docs/ARCHITECTURE.md:40` diagram utama, `docs/FLOW.md:6` sequence lengkap.

## 3. Feedback koreksi arsitektur

1. **Diagram harus direvisi.** n8n harus digambar sebagai mesin orkestrasi pusat, bukan kotak biasa. Alur harus eksplisit: `Agent -> hash JSON -> n8n -> VirusTotal/AI -> Telegram -> callback -> Wazuh API -> agent action`.
2. **Format pertukaran data adalah JSON** dengan skema yang disepakati n8n. Perlu didokumentasikan di `docs/ARCHITECTURE.md:349`.
3. **Agen berat.** Dospem menangkap Wazuh butuh Docker di tiap klien jadi berat. Faktanya Wazuh agent native hanya ~50 MB (`docs/ARCHITECTURE.md:82`), yang pakai Docker itu manager di server (`wazuh-docker/single-node/docker-compose.yml:6`). Tapi persepsi tetap valid untuk 50-100 endpoint harus seringan mungkin.
4. **Scope diperluas.** Jangan hanya `~/Downloads`. USB flashdisk (`/media/*`) dan perpindahan file antar folder juga perlu dipantau. Tambahkan ke `docs/ARCHITECTURE.md:313` FIM strategy.

## 4. Arahan agen ringan (minta dicoba minggu ini)

Dospem menyarankan dua opsi, preferensi: bikin sendiri pakai Golang dengan bantuan AI.

**Opsi A - Agen ringan greenfield (rekomendasi untuk POC minggu ini):**
- Tugas minimal: pantau file baru (inotify), hitung sha256, kirim JSON ke webhook n8n.
- Tidak bawa Docker. Satu binary Go, jalan sebagai service background.
- Semua logika berat tetap di n8n.

**Opsi B - Diet Wazuh open-source:**
- Wazuh itu open source (GPLv2), bisa di-fork dan di-trim. Matikan modul yang tidak dipakai (rootcheck, logcollector verbose, wodles tertentu), sisakan `wazuh-syscheckd` + `wazuh-execd`.
- Lihat detail kelayakan di `docs/AGENT-RINGAN.md:3` (analisis fork vs agen baru).

Dospem mencontohkan dia sendiri sudah pakai agen Go untuk monitor health 50 PC kantor (cek hardisk, RAM, suhu) dan work well.

## 5. Cara kerja yang diminta dospem

- Diskusi dulu dengan AI partner sebelum coding. Hasil diskusi jadi catatan `.md`, baru implement. Jangan langsung minta "buatkan aplikasi".
- Laporan: pakai AI untuk cek typo dan cek per paragraf ("apa maksud paragraf ini?"). Kalau AI menjawab melenceng, berarti tulisan kita belum jelas.
- Progres mingguan wajib ada. Minggu ini harus ada demo simulasi (1 server + 1-2 klien) + laporan barengan, tidak menunggu sistem jadi baru nulis.

## 6. To-do minggu ini

- [ ] Revisi diagram `docs/ARCHITECTURE.md` dan `docs/FLOW.md` (tunjukkan n8n sebagai otak + hash-only + USB path)
- [ ] Buat spec agen ringan `docs/AGENT-RINGAN.md` (JSON schema kompatibel dengan `POST /webhook/wazuh-alert`)
- [ ] POC agen ringan (Go atau Python dulu) tanpa Docker, kirim event ke n8n, tombol Telegram tetap jalan
- [ ] Update skenario laporan: analogi 100 workstation admin IT + human-in-the-loop
- [ ] Cek typo laporan per paragraf pakai AI

## 7. Catatan ponytail

> ponytail: Wazuh tetap jadi baseline thesis. Agen ringan adalah jalur alternatif untuk menjawab kritik "berat untuk 100 endpoint", bukan pengganti total minggu ini. Satu guard di fungsi bersama lebih baik dari guard di tiap pemanggil, dan diet di agent lebih berdampak dari optimasi di manager.

## 8. Transkrip asli

Transkrip meeting mentah disimpan terpisah (jangan commit verbatim panjang). Inti sudah dirangkum di atas sesuai arahan dospem untuk memahami sistem secara detail dan sederhana dulu sebelum masuk teknis.
