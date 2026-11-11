# Catatan Bimbingan Dospem - 2026-11-07

Dosen Pembimbing: I Nyoman Piarsa, S.T., M.T.  
Mahasiswa: Ravi Arnan Irianto (NIM: 2305551076)  
Judul: Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop (Studi Kasus: CV Bali Handmade)  
Sesi: Sabtu, 7 November 2026 (Fokus Penyempurnaan Aplikasi & Fleksibilitas Sistem)

---

## 1. Pokok Masukan & Catatan Dosen Pembimbing

Berdasarkan diskusi bimbingan pada pagi hari 7 November 2026, arahan utama dosen pembimbing adalah memprioritaskan pematangan fungsionalitas dan fleksibilitas aplikasi terlebih dahulu sebelum finalisasi naskah laporan:

1. **User Management & Role-Based Access Control (RBAC)**:
   - Sistem wajib memiliki manajemen pengguna bertingkat dengan pemisahan peran yang tegas (contoh: role `admin`, `analyst`, dan `viewer`).
   - Role `viewer` hanya diizinkan untuk melihat telemetri, metrik, dan log audit, tanpa hak mengeksekusi aksi mitigasi aktif maupun memodifikasi konfigurasi sistem.
2. **Installer UI & Pendaftaran Agent Tanpa Konfigurasi Manual (Zero-Config)**:
   - Proses instalasi agent di komputer klien tidak boleh membebani pengguna dengan konfigurasi manual berkas config atau penyalinan token.
   - Sediakan antarmuka visual (Installer UI) di dashboard yang menghasilkan perintah instalasi 1-baris (`curl -sSL ... | sudo bash`).
   - Host klien yang menjalankan perintah otomatis mendaftar ke antrean *Pending Approvals*, dan admin cukup menekan tombol *Approve* di dashboard agar agent langsung aktif dan terhubung.
3. **Dinamisasi Konfigurasi (Anti-Hardcode)**:
   - Hilangkan seluruh nilai hardcode di dalam kode sumber maupun playbook workflow.
   - Model AI harus dinamis: pengguna dapat memilih Gemini 2.5 Flash, 1.5 Pro, DeepSeek V4, Claude 3.5 Sonnet, atau GPT-4o-mini, serta mengatur suhu (temperature) dan token batas.
   - Multi-source threat intel synthesis harus dinamis: API key dan bobot penilaian dari VirusTotal, MalwareBazaar, AlienVault OTX, dan MISP Feed dapat diatur melalui dashboard.
   - Sediakan Live Playground untuk menguji respons inferensi AI secara instan.
4. **Kejelasan Metodologi & Proses Pengujian**:
   - Skema pengujian harus terstruktur secara ilmiah dan terukur (evaluasi kuantitatif MTTR malware, auto-sinkhole phishing, false positive suppression, dan uji konsistensi LLM).
5. **Visibilitas Antarmuka Visual (UI)**:
   - Seluruh fitur baru dan konfigurasi yang bisa ditampilkan harus memiliki antarmuka grafis (UI) yang intuitif dan profesional.
6. **Kemandirian & Fleksibilitas Arsitektur Agent**:
   - Agent dan server manager sebaiknya dikembangkan secara mandiri (kustom) agar tidak bergantung kaku pada stack Wazuh bawaan, sehingga fleksibel untuk pengembangan jangka panjang.

---

## 2. Realisasi Teknis & Implementasi Solusi

Seluruh 6 butir masukan di atas telah diimplementasikan secara penuh ke dalam repositori dan dideploy ke server produksi (`https://soar.raviarnan.dev`):

### A. Tahap 1: User Management & Cloudflare Access Zero Trust Email SSO
* **Penyimpanan Terdistribusi & Hashing PBKDF2**: Tabel `users` pada SQLite durable (`scripts/.fleet-events.db` dan `/state/events.db` di server) dengan hashing PBKDF2-HMAC-SHA256 (100.000 iterasi) dan 16-byte random salt.
* **Integrasi Email SSO Cloudflare Access**: Sesi pengguna di-resolve otomatis melalui header `cf-access-authenticated-user-email` pada fungsi `resolveAuthorizedSession` (`dashboard/src/lib/session.ts`) dengan in-memory cache 10 detik.
* **Akun Default Ter-Seed**:
  - `raviarnankeren@gmail.com` terpetakan sebagai **Admin SOC** (akses penuh).
  - `ravinewgemini@gmail.com` terpetakan sebagai **Viewer / Auditor** (akses baca saja).
* **Penegakan RBAC**:
  - `/api/commands`: Role `viewer` diblokir (HTTP 403 Forbidden) saat memicu aksi mitigasi (karantina berkas atau sinkhole domain).
  - `/api/keys`: Hanya role `admin` yang diizinkan menerbitkan atau mencabut API keys machine-to-machine.
  - `/api/users`: Hanya role `admin` yang dapat mengelola pendaftaran dan role pengguna.
* **Antarmuka UI**: Komponen `UserManagementView.tsx` menampilkan kartu metrik, matriks hak akses RBAC, dan tabel manajemen pengguna. Badge role pengguna aktif ditampilkan di `WazuhHeader.tsx`.

### B. Tahap 2: Zero-Config Agent Installer UI & Instant Approval Workflow
* **Generator Skrip Installer Dinamis**:
  - Endpoint `/api/enroll/script/linux`: menghasilkan skrip Bash yang mendeteksi OS (Ubuntu/Debian, CentOS/RHEL, Arch, Alpine), arsitektur CPU (`x86_64` / `aarch64`), mengunduh binary statis musl `soar-agent` (4,1 MB), men-generate unique host ID, dan mendaftarkan host ke antrean pendaftaran.
  - Endpoint `/api/enroll/script/windows`: menghasilkan skrip PowerShell untuk klien Windows.
* **Perintah Satu Baris**:
  ```bash
  curl -sSL https://soar.raviarnan.dev/api/enroll/script/linux | sudo bash
  ```
* **Skema Pendaftaran di Backend SQLite**:
  - Tabel `agent_enrollment_requests`: menampung antrean permintaan instalasi (`pending`, `approved`, `rejected`).
  - Tabel `enrolled_agents`: menyimpan agent yang telah disetujui beserta token autentikasi permanen yang otomatis dimuat ke `FLEET_AGENT_POLL_TOKENS`.
* **Antarmuka UI**: Komponen `AgentDeploymentView.tsx` menyediakan alur visual 4 langkah, generator perintah terminal dengan tombol salin cepat, antrean persetujuan *Pending Approvals* secara live, serta modal konfirmasi untuk menyesuaikan ID dan nama host sebelum disetujui.

### C. Tahap 3: Dinamisasi AI Engine & Multi-Source Threat Intel Synthesis
* **Skema SQLite Persisten**: Tabel `system_settings` key-value store untuk menyimpan konfigurasi `ai_config` dan `threat_intel_config` tanpa perlu me-restart kontainer.
* **Konfigurasi AI Engine Dinamis**:
  - Pilihan provider dan model: `gemini-2.5-flash`, `gemini-1.5-pro`, `deepseek-v4-flash`, `claude-3-5-sonnet`, `gpt-4o-mini`, dll.
  - Parameter fleksibel: `temperature` (0.0 - 1.0), `max_output_tokens` (200 - 4000), serta kustomisasi *System Prompt Override*.
  - Live AI Playground: fasilitas pengujian inferensi interaktif langsung di dashboard dengan pilihan sampel ancaman (Malware Emotet atau Phishing Perbankan) melalui endpoint `POST /api/settings/ai/test`.
* **Multi-Source Threat Intel Synthesis Dinamis**:
  - Konfigurasi runtime API Key untuk 4 sumber intelijen utama: VirusTotal, MalwareBazaar, AlienVault OTX, dan MISP OSINT Feed.
  - Pembobotan skor ancaman (Threat Score Weights): VirusTotal (default 40%), MalwareBazaar (30%), AlienVault OTX (15%), dan MISP (15%).
  - Ambang batas keyakinan (Confidence Level Thresholds): Critical (≥75), High (≥50), Medium (≥20).
  - Masa berlaku cache (TTL): Malicious (7 hari), Clean (24 jam), Unknown (6 jam), serta batas waktu fallback timeout.
* **Keamanan Secret Keys**: API key otomatis disamarkan (`••••••••`) pada response API dan antarmuka web, serta dilengkapi logika proteksi backend agar nilai mask tidak menimpa kredensial asli saat penyimpanan formulir.
* **Antarmuka UI**: Komponen `DynamicSettingsView.tsx` terpasang sebagai tab "AI Engine & Threat Intel (Dinamis)" di dalam `SettingsView.tsx`.

### D. Tahap 4 & 5: Metodologi Pengujian & Arsitektur Agent Mandiri
* **Metodologi Pengujian**: Skrip benchmark kuantitatif (`scripts/benchmark-soar.py` dan `scripts/benchmark-llm-consistency.py`) mengukur metrik objektif:
  - MTTR Karantina Agen Rust: 0,04 detik (median 0,03 detik).
  - MTTR Karantina Stack Wazuh: 1,68 detik (median 1,42 detik).
  - MTTR Auto-Sinkhole Phishing: 2,13 detik.
  - Throughput Uji Beban: 29,49 alert/detik (kapasitas 100 workstation).
  - False Positive Suppression Rate: 100% (8/8 file kerja jinak ditekan dari alarm palsu).
  - Kepatuhan Guardrail LLM: 100% lolos (30/30 pengujian tanpa kesalahan vonis file OS).
* **Agen Mandiri Rust (`agent-rs/`)**: Binary native statis 4,1 MB (stripped musl) tanpa dependensi runtime Python/Docker/Node.js, memantau FIM secara rekursif (`~/Downloads`, `~/Desktop`, USB flashdisk `/run/media`), menghitung SHA-256 secara streaming, melayani karantina lokal melalui loopback HTTP `:8787`, dan mengirimkan heartbeat otomatis ke server fleet.

---

## 3. Bukti Verifikasi & Pengujian Sistem

1. **Pengujian Unit Backend Python**:
   - `python3 -m unittest discover -s scripts`
   - Hasil: **163/163 unit tests PASS** (termasuk modul baru: `test_enrollment.py` 6 tests, `test_dynamic_settings.py` 5 tests, `test_users_rbac.py` 7 tests, `test_api_keys.py` 6 tests, `test_soar_mcp.py` 8 tests).
2. **Pengujian Frontend Next.js**:
   - `npm run check`
   - Hasil: **17/17 tests PASS**, ESLint bersih (0 errors, 0 warnings), TypeScript check lolos (`tsc --noEmit`), dan Next.js production build berhasil 100%.
3. **Deployment Server Produksi (`ravi@100.73.91.17`)**:
   - Dashboard web: `https://soar.raviarnan.dev` aktif melayani pengguna.
   - Kontainer `fleet-monitor` dan `fleet-dashboard` berstatus *Up (healthy)*.
   - Integrasi Cloudflare Access Zero Trust aktif melindungi seluruh rute dashboard.
