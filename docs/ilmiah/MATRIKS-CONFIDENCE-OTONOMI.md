# Matriks Confidence → Otonomi & Playbook Respons Berjenjang

**Milestone M3 — Penyempurnaan Respons Berjenjang Berbasis Keyakinan**
Sistem: SOAR open-source (Wazuh + n8n + LLM + Telegram) · Studi kasus CV Bali Handmade
Status: **LIVE & terverifikasi** di `ravi-debian` (2026-10-14)
Berkas terkait: `scripts/patch-n8n-hitl-matrix.py`, `scripts/alert-log.py`,
`scripts/e2e-hitl-matrix.py`, `scripts/test_patch_n8n_hitl_matrix.py`,
`scripts/test_alert_log.py`

---

## 1. Tujuan dan prinsip

Milestone M3 memformalkan **aturan pemetaan tingkat keyakinan ancaman terhadap tingkat
otonomi tindakan**. Sebelumnya kebijakan respons tersebar di beberapa node JavaScript dan
sebagian tidak konsisten dengan kenyataan di lapangan:

| Temuan audit 2026-10-14 (live) | Akibat |
|---|---|
| `should_active_response` dihitung di `Rangkum Hasil`, sedangkan judul/notifikasi di `Build Payload` | kebijakan tersebar, rawan divergen |
| Notifikasi malware **tidak lagi punya tombol inline**, padahal workflow `Telegram Callback Handler` masih menunggu aksi `iso:`/`ign:` | jalur HITL Telegram untuk malware **mati**; mitigasi aktif hanya bisa dari dashboard |
| Tidak ada node `Wait`/SLA di kelima workflow | item menunggu keputusan **bisa hilang tanpa jejak** |
| Keputusan analis hanya mengubah teks pesan Telegram | tidak ada audit trail; tidak terukur |

Prinsip yang dipakai (selaras arah tesis):

1. **Confidence-based** — tindakan otomatis hanya untuk keyakinan tinggi; keyakinan sedang
   diserahkan ke analis.
2. **Transparan** — setiap notifikasi menyebut *bukti* yang mendasari keputusan
   (`TANPA INDIKASI MALWARE`, `FILE PERLU REVIEW`, `INDIKASI MALWARE`), bukan vonis buta.
3. **Sadar-degradasi** — kegagalan verifikasi (rate-limit/5xx/timeout) tidak disenyapkan;
   ditandai sebagai belum terverifikasi.
4. **HITL yang dapat dipertanggungjawabkan** — setiap keputusan analis tercatat (siapa,
   kapan, aksi apa, berapa lama respons) dan item yang tak direspons **dieskalasi**.

---

## 2. Sumber bukti (evidence) dan tingkat keyakinan

| Sumber | Yang dibaca | Sifat |
|---|---|---|
| VirusTotal (via cache TTL server) | `last_analysis_stats` (malicious/suspicious/undetected) | kuat bila ≥ 5 deteksi |
| MalwareBazaar | `signature`, `tags` | kuat bila hash terdaftar malware |
| OTX (fallback saat VT gagal) | `pulse_info.count` | kuat bila ada pulse |
| MISP (feed OSINT) | `matches[].to_ids`, `event_info` | kuat bila hash ada di event |
| Rule chain Wazuh (110001–110018) | `sysmon.commandLine`, `win.eventdata.commandLine`, parent | indikatif (LOLBin bisa sah) |
| Rule FIM Wazuh (550/554) | perubahan checksum/file | **bukan** indikator malware |
| Penanda file sistem | path `hosts`, `drivers\etc\`, `resolv.conf` | perubahan administratif |
| Metadata file | ekstensi berisiko, bit eksekusi, tanpa ekstensi | sinyal lemah (perlu review) |

Tingkat keyakinan yang dipakai: **tinggi**, **sedang**, **rendah**, **tidak ada**.

---

## 3. Matriks confidence → otonomi (kebijakan resmi)

Tabel ini adalah **kontrak kebijakan**. Implementasinya tunggal, di node
`Tentukan Otonomi` (workflow `Deteksi Malware`), sehingga `should_active_response`
diturunkan dari otonomi — bukan dihitung ulang di tempat lain.

| Tingkat keyakinan | Bukti pemicu | Tier kebijakan | Otonomi | Tindakan otomatis | Notifikasi | Tenggat keputusan |
|---|---|---|---|---|---|---|
| **Tinggi** | `malicious ≥ 20`, atau MalwareBazaar signature + `malicious ≥ 5` | `auto-critical` | **Otonom** | AR otomatis (karantina file) **+** notifikasi | Ya, dengan bukti + alasan LLM + tombol `Tandai FP` | — (sudah ditangani) |
| **Tinggi** | `malicious ≥ 5`, atau MB/OTX/MISP hit, rule chain level ≥ 12 | `auto-critical` / `auto-high` | **Otonom** | AR otomatis **+** notifikasi | Ya | — |
| **Sedang** | indikator lemah (`malicious 1–4`), atau VT belum terverifikasi (429/5xx/timeout), atau eksekutabel/ekstensi berisiko dengan hash tak dikenal | `hitl-review` | **HITL** | **Tidak ada** AR otomatis | Ya (`FILE PERLU REVIEW`), tombol `Karantina file` + `Tandai FP` | **900 dtk (15 mnt)** → eskalasi |
| **Sedang** | rantai proses mencurigakan (LOLBin, rule 110001–110018) | `hitl-chain` | **HITL** | **Tidak ada** AR (binary sistem bisa sah) | Ya, tombol `Sudah ditinjau` + `Tandai FP` | **900 dtk** → eskalasi |
| **Tidak ada** | file konfigurasi sistem berubah (rule 550/554 pada `hosts` dsb.) | `manual-config` | **Tahan (notify-hold)** | **Tidak ada** AR (file OS tak boleh dikarantina) | Ya, maksimum severity **MEDIUM** | — |
| **Rendah** | tidak ada satu pun indikator threat intel | `observe` | **Pantau** | Tidak ada | Hanya bila bukan media/dokumen jinak; media jinak disenyapkan (`notify=false`) | — |

Catatan penting:

- **Rule FIM tidak lagi menaikkan severity** jalur file; severity jalur file murni dari
  threat intel (patch `patch:noindicator:v1`, live 2026-10-09).
- **Kegagalan verifikasi bukan "bersih"**: VT error non-404 → `MEDIUM` belum terverifikasi,
  tetap diberitakan (sadar-degradasi, tanpa silent-failure).
- **Hash tak dikenal + eksekutabel** tidak dianggap aman; masuk HITL `FILE PERLU REVIEW`
  (menutup celah zero-day).

---

## 4. Playbook respons berjenjang

### Tier `auto-critical` / `auto-high` — otonom

1. Deteksi masuk (webhook Wazuh → `Filter Alert Malware` → `Dedup Alert`).
2. Verifikasi berlapis: cache VT → VT (atau OTX bila VT gagal) → MalwareBazaar → MISP.
3. `Tentukan Otonomi` menetapkan `confidence=high`, `autonomy=auto`, `should_active_response=true`.
4. **Active Response otomatis**, berlapis (lihat §5): Wazuh AR `!quarantine-file` → bila
   gagal, perintah karantina dimasukkan ke antrean agen Rust (`POST :8080/api/commands`
   di fleet-monitor, di-poll agen ≤ 60 detik).
5. Deteksi tetap **didaftarkan** di registry keputusan (audit trail, tanpa tenggat).
6. Notifikasi Telegram berisi judul berbasis bukti + hasil deteksi + `🤖 Analisis AI` +
   tombol **`Tandai FP`** (umpan balik false-positive tercatat, bukan hilang).

### Tier `hitl-review` / `hitl-chain` — human-in-the-loop

1. Deteksi diverifikasi seperti biasa; `Tentukan Otonomi` menetapkan `autonomy=hitl`,
   `should_active_response=false` (AR otomatis **dimatikan**).
2. **Registry keputusan** mencatat item: hash (atau kunci sintetis `chain:<rule>:<agent>`),
   agen, path target, severity, tier, tenggat 900 dtk, `did` = 16 karakter pertama kunci.
3. Notifikasi Telegram dikirim dengan tombol inline:
   - `hitl-review`: **`Karantina file`** (`q:`) dan **`Tandai FP`** (`f:`);
   - `hitl-chain`: **`Sudah ditinjau`** (`a:`) dan **`Tandai FP`** (`f:`).
4. Analis menekan tombol → `Telegram Callback Handler`:
   `Parse Keputusan` (baca `did`) → `Catat Keputusan` (**klaim** keputusan di registry →
   audit trail + target aksi diambil dari registry, bukan parsing teks pesan) →
   `Answer Callback` → `Get Wazuh Token` → `Jalankan AR` (hanya `q:`/`pblk:` yang
   mengeksekusi AR) → `Edit Pesan Hasil` (satu pesan hasil dinamis).
5. Keputusan juga dicatat ke fleet (`POST /webhook-log`) sehingga **tampil di dashboard**
   (`status: analyst-quarantine` / `analyst-fp` / `analyst-ack`).
6. **Bila tidak ada keputusan dalam 15 menit** → workflow `SLA Eskalasi HITL`
   (Schedule 1 menit) membaca registry `GET /decision/pending?overdue=1`, mengirim
   **eskalasi Telegram** `⏰ BELUM DITANGANI (SLA terlampaui)`, lalu menandai item
   (`POST /decision/escalate`) agar **tidak spam**; item tetap terlihat lewat `?all=1`
   sampai keputusan datang atau kedaluwarsa (TTL 6 jam).

### Tier `manual-config` — perubahan file konfigurasi sistem

Dilaporkan dengan judul `PERUBAHAN FILE KONFIGURASI SISTEM`, severity maksimum MEDIUM,
VirusTotal ditandai **N/A**, AR otomatis **dimatikan**, dan prompt LLM diberi konteks bahwa
SOAR ini sendiri menulis entri `# soar-sinkhole` ke `hosts` (mencegah over-eskalasi).

### Tier `observe` — tanpa indikator

Dicatat ke fleet (dashboard) dan **tidak** mengganggu analis kecuali berkasnya bukan
media/dokumen jinak. Tidak ada AR, tidak ada tenggat.

---

## 5. Implementasi live

| Bagian | Artefak | Keadaan |
|---|---|---|
| Sumber kebijakan tunggal | node `Tentukan Otonomi` (Code) di `Deteksi Malware` — dipasang untuk jalur file **dan** jalur rantai proses | LIVE (28 node) |
| Pendaftaran keputusan | node `Catat Keputusan Tertunda` → `POST :8091/decision/pending` (sebelum notifikasi, fail-open) | LIVE |
| Notifikasi HITL | `Send Telegram Alert` + inline keyboard dinamis (`q:`/`a:` + `f:`) | LIVE |
| Audit trail notifikasi | `Log Telegram Alert` kini membawa `hash`, `agent_id`, `path`, `tier`, `hitl`, `decision_did` | LIVE |
| Registry + audit + SLA | service `alert-log` (`scripts/alert-log.py`): `/decision/pending`, `/decision/resolve`, `/decision/escalate`, `/decision/audit`, `/stats`; state `state/decisions.json` + `state/decisions-audit.jsonl` | LIVE |
| Eskalasi SLA | workflow baru `SLA Eskalasi HITL` (5 node, Schedule 1 menit) | LIVE (aktif) |
| Jalur HITL phishing | tetap seperti semula (tombol `pblk:`/`pign:` → `!block-domain`); target URL dari teks pesan | LIVE |
| HITL dari dashboard | workflow `Dashboard AR` (secret + `!quarantine-file` / `!block-domain`) | LIVE |

**Active Response berlapis** (jalur file):

```
Tentukan Otonomi (autonomy=auto)
   └─ Cek Ancaman ─→ Get Wazuh Token ─→ Trigger Active Response (!quarantine-file)
                                             └─ gagal? → Fleet Quarantine
                                                          └─ POST :8080/api/commands
                                                             (di-poll agen Rust ≤ 60 dtk)
```

Agen Rust bukan agen Wazuh, sehingga Wazuh AR kerap menjawab `1701 agent does not exist`;
karena itu lapis kedua (antrean perintah fleet) adalah jalur eksekusi nyata untuk endpoint
Rust — dan inilah yang dieksekusi oleh keputusan `q:` dari analis maupun AR otomatis.

---

## 6. Jaminan keselamatan (guardrail)

1. **File konfigurasi sistem tidak pernah dikarantina** — dikecualikan di node kebijakan dan
   dijaga ulang di `Fleet Quarantine` (`skipped-system-file`).
2. **Rantai proses tidak pernah auto-AR** — meski severity HIGH, otonomi tetap `hitl`
   (binary sistem seperti `powershell.exe` tidak boleh dibunuh otomatis).
3. **AR hanya dari tier otonom** — keputusan `f:`/`a:` tidak mengeksekusi AR
   (`status: tanpa-ar`), diverifikasi E2E.
4. **Registry fail-open** — registry mati tidak mematikan deteksi; deteksi tetap
   diverifikasi, dinotifikasi, dan dicatat di fleet.
5. **Target aksi dari registry** — tombol membawa `did` (≤ 64 byte, batas `callback_data`
   Telegram), bukan path; path diambil dari registry sehingga tidak rusak oleh escape
   Markdown maupun pemotongan pesan (fallback legacy tetap didukung: `iso:`, `ign:`, `pblk:`, `pign:`).
6. **Eskalasi tidak berulang** — item yang sudah dieskalasi keluar dari daftar overdue.

---

## 7. Audit trail dan metrik

Endpoint registry (`alert-log :8091`):

| Endpoint | Isi |
|---|---|
| `GET /decision/pending?overdue=1&all=1&limit=` | item menunggu / lewat tenggat / seluruh riwayat |
| `GET /decision/audit?limit=&hash=` | keputusan & eskalasi (JSONL, tahan restart) |
| `GET /stats` | `decisions.total/by_status/by_action/by_tier`, `hitl`, `auto`, `mean_response_secs`, `min/max`, `hitl_response_secs` |

Data nyata setelah sesi verifikasi 2026-10-14 (termasuk 3 run E2E):

```
total=7 · resolved=3 · pending=2 (tier otomatis, memang tanpa keputusan) · escalated=2
hitl=5 · auto=2 · mean_response_secs=5.3 · max=8
by_action: quarantine=2 · acknowledged=1
by_tier: hitl-review=5 · auto-critical=2
```

Ini adalah **angka pertama untuk metrik keputusan HITL** (waktu respons analis sampai
tombol ditekan, dalam lingkungan uji) yang sebelumnya hanya bisa diklaim kualitatif.

---

## 8. Bukti uji

| Lapis | Perintah | Hasil |
|---|---|---|
| Unit registry & SLA | `python3 scripts/test_alert_log.py` | **58/58 lulus** |
| Unit patch + perilaku JS (via `node`) | `python3 scripts/test_patch_n8n_hitl_matrix.py` | **26/26 lulus** (matriks per tier, payload pendaftaran, parsing tombol, pemilihan AR, sweeper SLA, gagal-keras bila pola live berubah) |
| E2E live | `python3 scripts/e2e-hitl-matrix.py --n8n-url http://100.73.91.17:5678 --api-key-file /tmp/n8n_api_key.txt` | **36/36 lulus** |
| Idempotensi | patch dijalankan 2× | pass kedua = 0 perubahan |

Cakupan E2E live: (A) jalur HITL menetapkan `hitl-review` + tenggat 900 dtk + **tanpa** AR,
(B) simulasi klik `Karantina` → registry resolved + audit + tercatat di fleet + AR dijalankan,
(C) jalur otomatis `auto-critical` → AR + fallback antrean fleet + `hitl=false` tanpa tenggat,
(D) eskalasi SLA menandai item lewat tenggat dan tercatat di alert-log.

Bukti mentah: `backups/n8n-malware-hitl-matrix-*.json` &
`backups/n8n-callback-hitl-matrix-*.json` (snapshot pra-patch, otomatis).

---

## 9. Batasan dan kerja lanjutan

1. **Jalur phishing belum memakai registry** — tombol phishing masih legacy (`pblk:`/`pign:`)
   dengan target dari teks pesan; menyamakan ke registry adalah langkah berikutnya yang murah.
2. **Registri AR otomatis hanya menyediakan umpan balik "Tandai FP"** — belum ada aksi
   "batalkan karantina" (butuh dukungan `restore` di agen).
3. **`ALERT_LOG_TOKEN` opsional & belum diaktifkan** — service `alert-log` masih menerima
   penulisan keputusan tanpa autentikasi di jaringan host (kandidat item M5).
4. **Deadline & TTL bersifat tetap** (900 dtk / 6 jam) — dapat dibuat per-tier bila data
   waktu respons sudah cukup.
5. **Angka `mean_response_secs` masih dari uji sintetis** (N kecil); untuk bab evaluasi perlu
   N ≥ 30 dengan skenario nyata (`docs/evaluasi/EVALUASI-METRIK.md`).
