# Panduan Alur Kerja Workflow n8n: Deteksi Malware & Deteksi Phishing
## Materi Persiapan Bimbingan Tugas Akhir & Presentasi Teknis
**Mahasiswa:** Ravi Arnan Irianto (NIM: 2305551076)  
**Dosen Pembimbing:** I Nyoman Piarsa  

---

## 1. Workflow Deteksi Malware (28 Nodes)

Workflow ini bertugas menginvestigasi berkas baru di area kerja workstation endpoint CV Bali Handmade (`~/Downloads`, `Desktop`, `USB Flashdisk`). Menerapkan prinsip *confidence-based response* agar mitigasi akurat dan tidak menyebabkan salah hapus dokumen kantor.

### Alur Eksekusi Visual:
```
[Endpoint] → Webhook → Filter → Ekstrak → Dedup → Cek Cache VT → Cache Hit?
  ├─ (Hit) ──────────────────────────────────────────────────────────┐
  └─ (Miss) → Scan VirusTotal → Simpan Cache → VT OK? ┬─ (OK) ────────┼→ MalwareBazaar → MISP → Rangkum Hasil
                                                     └─ (Fail) → OTX ─┘
[Decision Hub] Rangkum Hasil (+ Process Chain) → Tentukan Otonomi ┬→ Log ke Fleet (Monitoring)
                                                                 └→ Cek Ancaman (AR?)
  ├─ (True: Kritis) → Get Wazuh Token → Trigger Active Response → Fleet Quarantine ┐
  └─ (False: Ambigu/Review) ──────────────────────────────────────────────────────┴→ Build Payload →
      Perlu Notif? → Catat Keputusan Tertunda → AI Generate (Gemini) → Send Telegram (HITL) → Log Alert
```

### Penjelasan per Tahapan:

1. **Tahap 1: Ingestion, Normalisasi, & Anti-Duplikasi**
   - Node: `Webhook`, `Filter Alert Malware`, `Ekstrak Alert`, `Dedup Alert`.
   - Menerima event JSON dari agen Rust (`soar-agent`) atau Wazuh.
   - Menyaring noise sistem (seperti file swap atau direktori `/tmp/`).
   - Mengekstrak metadata inti (hash SHA-256, path berkas, nama workstation, ukuran, status executable bit).
   - Menghindari duplikasi notifikasi jika file dimodifikasi berkali-kali dalam jeda waktu singkat.

2. **Tahap 2: Hierarki Intelijen Multi-Sumber (Cache-First & Fallback)**
   - Node: `Cek Cache VT`, `Scan VirusTotal`, `Simpan Cache VT`, `VT OK?`, `OTX Lookup`, `MalwareBazaar Lookup`, `MISP Lookup`.
   - **Cache Lokal Dulu**: Jika hash pernah diperiksa sebelumnya (*cache hit*), query internet langsung dilewati (menghemat kuota API free VT).
   - **VirusTotal (70+ AV Engine)**: Jika *cache miss*, hash dikirim ke API VirusTotal v3.
   - **Fallback OTX**: Jika kuota API VT habis (error 429), sistem otomatis beralih ke AlienVault OTX.
   - **Feed Komunitas**: Hash selalu diverifikasi silang ke feed aktif MalwareBazaar (abuse.ch) dan feed CIRCL OSINT MISP lokal.

3. **Tahap 3: Jalur Paralel Rantai Proses (Process Chain)**
   - Node: `Cabang Chain?`, `Ekstrak Chain`, `Rangkum Chain`.
   - Memantau anomali eksekusi proses (misal file nota Word/Excel yang tiba-tiba memicu `powershell.exe` atau `cmd.exe`).
   - Mengalir di jalur bawah sejajar dengan FIM, lalu disatukan ke engine keputusan.

4. **Tahap 4: Engine Keputusan & Dual Mitigasi (Active Response)**
   - Node: `Tentukan Otonomi`, `Cek Ancaman`, `Get Wazuh Token`, `Trigger Active Response`, `Fleet Quarantine`.
   - Klasifikasi Severity:
     - **Kritis (skor >= 20)**: Memicu Active Response otomatis ganda (panggil API Wazuh dan API agen Rust `/quarantine`).
     - **Tinggi / Ambigu (skor 1-19)**: Masuk ke peninjauan manusia (Human-in-the-Loop).
     - **Bersih (skor 0)**: Ditekan (tanpa notifikasi).

5. **Tahap 5: Ringkasan AI & Human-in-the-Loop 2-Arah**
   - Node: `Build Payload`, `Perlu Notifikasi?`, `Catat Keputusan Tertunda`, `AI Generate`, `Send Telegram Alert`, `Log Telegram Alert`.
   - Menggunakan LLM (Gemini Flash) untuk merangkum hasil investigasi teknis menjadi bahasa Indonesia yang mudah dipahami admin non-teknis.
   - Mengirim notifikasi Telegram dengan inline keyboard `[Isolasi]` / `[Abaikan]`.

---

## 2. Workflow Deteksi Phishing (25 Nodes)

Workflow ini bertugas melindungi seluruh workstation dari serangan tautan palsu (phishing) dengan memutus akses domain jahat di seluruh jaringan secara real-time.

### Alur Eksekusi Visual:
```
[Endpoint Log] → Webhook Phishing → Filter → Ekstrak URL → Cek Cache URL → Cache Hit?
  ├─ (Hit) ────────────────────────────────────────────────────────────────────────┐
  └─ (Miss) → GSB Lookup (Google Safe Browsing) → GSB Threat?                      │
                ├─ (True: Bahaya) ─────────────────────────────────────────────────┼→ Rangkum Phishing
                └─ (False: Cek Lanjut) → URLScan.io Submit → Tunggu → URLScan Result ┘
[Mitigasi & AI] Rangkum Phishing ┬→ Log ke Fleet (Monitoring)
                                 └→ Cek Ancaman
  ├─ (Bahaya) → Auto Block? ┬─ (True) → Get Wazuh Token → Active Response (Sinkhole Hosts) ┐
  │                         └─ (False) ────────────────────────────────────────────────────┴→ Build Payload →
  │                                                                 Gemini Generate → Tipe Notif? ┬→ Send Telegram Alert
  └─ (Aman) → Build Payload Aman ──────────────────────────────────────────────────────────────────┴→ Send Telegram Info
```

### Penjelasan per Tahapan:

1. **Tahap 1: Ingestion & Cache Reputasi URL**
   - Node: `Webhook Phishing`, `Filter Alert Phishing`, `Ekstrak Alert Phishing`, `Cek Cache URL`, `Cache Hit URL?`.
   - Menangkap log akses URL dari browser atau aplikasi chatting di endpoint.
   - Mengecek database cache URL lokal. Jika domain pernah dipindai, langsung dilempar ke rangkuman tanpa query API.

2. **Tahap 2: Dual Threat Intel (Jalur Kilat GSB vs. Deep Scan URLScan)**
   - Node: `GSB Lookup`, `GSB Threat?`, `URLScan.io Submit`, `Tunggu Scan`, `URLScan Result`.
   - **Jalur Kilat Google Safe Browsing (GSB)**: Jika terdaftar sebagai phishing, sistem langsung merespons dalam waktu **~2,13 detik**.
   - **Deep Scan URLScan.io**: Jika GSB belum mencatatnya, URL dikirim ke sandbox URLScan untuk diuji perilaku redirect dan tangkapan layarnya.

3. **Tahap 3: Mitigasi Aktif Domain Sinkhole di Level Jaringan**
   - Node: `Rangkum Phishing`, `Log ke Fleet`, `Cek Ancaman`, `Auto Block?`, `Get Wazuh Token`, `Trigger Active Response`.
   - Jika terbukti phishing, sistem mengeksekusi Active Response `block-domain` di endpoint.
   - Script memetakan domain berbahaya ke `0.0.0.0` pada `/etc/hosts` atau DNS lokal, sehingga seluruh workstation lain di kantor terproteksi seketika.

4. **Tahap 4: Ringkasan AI & Notifikasi Dua Arah**
   - Node: `Build Payload`, `Build Payload Aman`, `Gemini Generate`, `Tipe Notif?`, `Send Telegram Alert`, `Send Telegram Info`, `Log Telegram Alert`.
   - Merangkum domain, tipe rekayasa sosial, dan status blokir domain via Gemini.
   - Mengirim alert real-time ke Telegram admin.

---

## 3. Rangkuman Perbedaan Strategi: Malware vs. Phishing

| Aspek Operasional | Workflow Deteksi Malware | Workflow Deteksi Phishing |
|---|---|---|
| **Vektor Ancaman** | Berkas di storage (`~/Downloads`, `Desktop`, `USB`) | Tautan URL di web browser, email, dan WhatsApp Web |
| **Sumber Threat Intel** | VirusTotal (70+ AV), MalwareBazaar, MISP, OTX | Google Safe Browsing v4 (kilat) dan URLScan.io (sandbox) |
| **Bentuk Active Response** | Isolasi berkas lokal (karantina via Rust / Wazuh) | Domain sinkhole (`0.0.0.0` di hosts/DNS jaringan) |
| **Kecepatan Respons (MTTR)**| 0,04 detik (Agen Rust) / 1,68 detik (Wazuh AR) | 2,13 detik (Jalur cepat Google Safe Browsing) |
| **Model Human-in-the-Loop** | Auto-karantina (skor >= 20); Tombol persetujuan (skor 1-19) | Auto-sinkhole seketika, disusul laporan AI ke Telegram |

---

## 4. Kunci Jawaban & Elevator Pitch Saat Dosen Bertanya

> **Dosen:** *"Kenapa alur workflow di n8n ini dibuat berlapis-lapis dan tidak langsung trigger saja?"*
>
> **Mahasiswa:** *"Pak, arsitektur ini menerapkan prinsip **Defense-in-Depth** dan **Efficiency-First**:
> 1. **Lapisan Cache**: Menghindari pemborosan kuota API VirusTotal/GSB dan membuat waktu respons mendekati instan (MTTR 0,04 detik).
> 2. **Multi-Source Intel**: Menggabungkan 70+ vendor antivirus dan feed komunitas OSINT agar keputusan tidak bias pada satu vendor saja.
> 3. **Mitigasi Terukur (Confidence-Based)**: Kasus yang sangat yakin (&ge;20 deteksi) ditangani otomatis oleh sistem, sedangkan kasus abu-abu/meragukan diserahkan ke persetujuan admin lewat tombol Telegram (Human-in-the-Loop) agar tidak terjadi salah hapus file penting kantor."*
