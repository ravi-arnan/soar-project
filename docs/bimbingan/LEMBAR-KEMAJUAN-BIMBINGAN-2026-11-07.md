# Lembar Kemajuan Bimbingan Tugas Akhir
**Tanggal Bimbingan:** Sabtu, 7 November 2026  
**Dosen Pembimbing 1:** I Nyoman Piarsa, S.T., M.T.  
**Mahasiswa:** Ravi Arnan Irianto (NIM: 2305551076)  
**Judul Tugas Akhir:** Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop (Studi Kasus: CV Bali Handmade)

---

### 1. Elevator Pitch & Cerita Bahasa Awam (Analogi 30 Detik)

> "Pak Nyoman, sistem yang saya kembangkan ini menyelesaikan masalah klasik UKM seperti CV Bali Handmade: staf toko dan kasir sering tidak sengaja mengunduh berkas berbahaya atau mengklik link phishing, sementara komputer kasir berspesifikasi rendah dan admin IT tidak mungkin memeriksa puluhan komputer satu per satu.
>
> Sistem SOAR ini bertindak sebagai **Pusat Komando Keamanan Terpadu**:
> 1. Agen mandiri berukuran sangat kecil (~7 MB RAM) memantau aktivitas berkas dan flashdisk karyawan.
> 2. Begitu ada berkas atau tautan baru, agen hanya mengirimkan sidik jari (hash SHA-256) ke server pusat n8n, tanpa membebani bandwidth jaringan.
> 3. Server menguji reputasi ke puluhan database keamanan global (VirusTotal, MalwareBazaar, MISP).
> 4. Jika ancaman kritis, sistem langsung mengisolasi berkas dalam 0,04 detik. Jika mencurigakan/ambigu, sistem mengirimkan notifikasi interaktif ke Telegram admin dengan tombol **[Karantina]** dan **[Abaikan]**, sehingga operasional toko terlindungi tanpa risiko salah hapus dokumen kerja sah."

---

### 2. Progres Kemajuan Baru yang Dilaporkan Minggu Ini

#### A. Penguatan Deteksi Pre-Encryption Ransomware & Autostart Persistence (Adaptasi Azure Sentinel & SigmaHQ)
Menjawab antisipasi serangan ransomware sebelum enkripsi berkas dimulai:
* **MITRE T1490 (Inhibit System Recovery)**: Menambahkan aturan deteksi level 12 (CRITICAL) pada `scripts/process-chain-rules.xml` (Rule 110039 & 110040) untuk mendeteksi upaya malware melumpuhkan backup Windows (`vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit recoveryenabled no`, dan `wbadmin delete catalog`).
* **MITRE T1547.001 & T1053.005 (Persistence via Run Keys & Scheduled Tasks)**: Menambahkan aturan deteksi level 9 (HIGH) pada Rule 110041-110044 saat perintah `reg.exe add ...\Run` atau `schtasks.exe /create` diarahkan ke folder user (`Temp`, `AppData`, `Downloads`, `Users\Public`).
* **Hasil Verifikasi**: Seluruh rule lolos validasi XML dan pengujian regex (5/5 unit test baru PASS, total 130 tests suite PASS).

#### B. Studi Komparasi Empiris Head-to-Head: n8n vs Shuffle SOAR di Localhost
Melakukan pengujian langsung di lingkungan lokal terhadap platform SOAR open-source terpopuler di dunia (Shuffle SOAR):
* **Beban Memori**: Shuffle membutuhkan klaster multi-kontainer berat (OpenSearch berbasis Java Heap 3-4 GB, Backend Go, Frontend React, Orborus worker) dengan total konsumsi RAM ~4,5 GB, sedangkan arsitektur n8n kita hanya memakan ~400 MB RAM (hemat >90% memori).
* **Mekanisme Eksekusi**: Shuffle men-spawn kontainer Docker baru untuk setiap pemanggilan fungsi (Docker-in-Docker overhead), sedangkan n8n mengeksekusi logika secara instan di dalam process workflow.
* **Justifikasi Ilmiah**: Membuktikan bahwa n8n jauh lebih layak, murah, dan realistis untuk diaplikasikan pada infrastruktur server UKM dengan biaya operasional Rp 0.

#### C. Garansi Pengiriman Transmisi Callback Telegram (Hardening Keandalan)
* Menambahkan mekanisme *Offset Protection* pada poller Telegram (`scripts/tg-callback-poller.py`): jika server n8n mengalami restart atau kendala jaringan sesaat, status klik tombol analis tidak akan hilang diam-diam, melainkan di-retry otomatis hingga sukses dikonfirmasi (HTTP 2xx).
* Menyelaraskan kontainer monitor kesehatan (`health-monitor`) pada host network untuk mengeliminasi false alarm status API Wazuh.

---

### 3. Matriks Hasil Pengujian Empiris Terukur (Data Kuantitatif)

| Parameter Pengujian | Hasil Pengukuran Riil | Standar / Pembanding | Keterangan |
|---|---|---|---|
| **MTTR Karantina Malware (Agen Rust)** | **0,04 detik** (median 0,03 dtk) | Standar industri: < 10 detik | Diukur pada 30 kali pengujian (N=30) dengan cache hangat |
| **MTTR Karantina Malware (Wazuh Stack)**| **1,68 detik** (median 1,42 dtk) | Standar manual: ~15 menit | Diukur pada 15 kali pengujian (N=15) |
| **MTTR Auto-Sinkhole Phishing** | **2,13 detik** | Manual DNS: jam/hari | 5/5 pengujian sukses sinkhole domain ke 0.0.0.0 |
| **Throughput Uji Beban (Load Test)** | **29,49 alert/detik** | Kapasitas 100 endpoint | Latensi rata-rata 164,84 ms pada concurrency=5 |
| **False Positive Suppression Rate** | **100% (8/8 file ditekan)** | Rule FIM murni: 100% false alarm | File kerja jinak (.mp4, .pdf) tidak memicu alarm palsu |
| **Jejak Memori Agen Endpoint** | **~7 - 10 MB RAM** | Wazuh agent: ~80-150 MB | Binary mandiri Rust 5,4 MB (tanpa dependensi runtime) |
| **Kepatuhan Guardrail LLM DeepSeek** | **100% lolos (30/30 tes)** | Suhu 0.3, N=5 per skenario | Nol rekomendasi salah hapus file sistem Windows/Linux |

---

### 4. Skenario Demo Singkat (Jika Diminta Ditunjukkan Langsung)

1. **Alur Deteksi Berkas & Tombol Telegram**:
   * Tunjukkan pesan alert di bot Telegram: menampilkan detail endpoint, skor reputasi VirusTotal/MalwareBazaar, alasan AI, dan tombol interaktif `[Karantina File]` serta `[Abaikan]`.
   * Klik tombol `[Karantina File]` -> tunjukkan respons instan pesan berubah menjadi *"Dikonfirmasi Karantina oleh Analis Ravi"* lengkap dengan timestamp audit trail.
2. **Dashboard Visual Fleet Monitor**:
   * Buka browser ke antarmuka web Fleet Monitor: tunjukkan donut chart tingkat keparahan, grafik tren insiden per hari, serta daftar endpoint yang sedang aktif terpantau.
3. **Efisiensi Agen Rust**:
   * Tunjukkan output `htop` atau `tasklist` di terminal klien: proses `soar-agent` hanya mengonsumsi ~7 MB RAM dan 0% CPU saat idle.

---

### 5. Antisipasi Pertanyaan Pak Nyoman Piarsa

* **Q: "Kenapa agennya dibuat pakai Rust, bukan Go seperti yang saya contohkan?"**
  * *Jawaban:* "Rust menghasilkan binary statis native tanpa overhead garbage collection runtime, sehingga konsumsi memorinya bisa ditekan hingga hanya ~7 MB (dibanding Go yang umumnya ~15-25 MB). Ini memastikan agen sama sekali tidak mengganggu kinerja komputer kasir tua di toko CV Bali Handmade."
* **Q: "Apakah sistem ini aman dari risiko salah hapus berkas kasir?"**
  * *Jawaban:* "Sangat aman, Pak. Sistem menerapkan *Human-in-the-Loop*. Berkas yang skor kecurigaannya berada di zona abu-abu (skor 1-19) tidak pernah dihapus otomatis, melainkan meminta persetujuan admin lewat Telegram. Selain itu, ada filter proteksi jalur yang melarang keras karantina terhadap berkas sistem operasi."
* **Q: "Apa target berikutnya sebelum ujian sidang?"**
  * *Jawaban:* "Infrastruktur aplikasi, agen, dan data evaluasi kuantitatif sudah lengkap 100%. Target selanjutnya adalah menyelesaikan penulisan naskah Bab I hingga Bab V secara komprehensif mengacu pada data empiris yang sudah terkumpul."
