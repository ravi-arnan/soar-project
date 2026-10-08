# ROADMAP — SOAR Open-Source (Wazuh + n8n + HITL)

Konsolidasi **gap (kesenjangan/masalah)** dan **solusi** untuk proyek:
*Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop (Studi Kasus: CV Bali Handmade)* — Ravi Arnan Irianto (2305551076).

Kategori: (A) Bug keandalan, (B) Keandalan threat-intel, (C) Bukti ilmiah, (D) Keamanan platform, (E) Arsitektur, (F) Kontribusi terhadap masalah industri, (G) Perluasan cakupan deteksi (penguatan TA), (H) Pemeliharaan & modernisasi stack, (I) Agen Ringan.

## Relevansi & Lanskap 2026 (riset 2026-10-08)

Sweep penuh (versi komponen + CVE + tren industri + jurnal) → **`docs/ilmiah/RELEVANSI-2026.md`**.
Ringkas: proyek **masih relevan**, arah tesis (confidence-based, transparan, sadar-degradasi,
HITL) **divalidasi literatur 2025–2026**, tapi ada 2 aksi konkret + tekanan kebaruan:

- **n8n 2.40.0 rentan** — batch CVE Okt 2026 (termasuk 2 Critical 9.0: CVE-2026-103255/103248)
  menambal "2.40.0 before 2.40.1" → **wajib upgrade ke ≥ 2.40.1**. **Repo sudah dipatch ke 2.42.5**
  (stable terbaru 2026-10-08); deploy live menunggu server online.
- **Wazuh 4.10.5 tertinggal** — stable terbaru **4.14.6** (Jul 2026); **5.0 sudah Beta 5**
  (bukan in-place upgrade: XML→Sigma, field/severity berubah, data tak dimigrasi).
- **Tren industri**: pergeseran SOAR playbook → **agentic SOC** (Microsoft ISOC, Wazuh AI Assistant);
  adopsi masih ~14%; risiko prompt injection → OWASP Top 10 Agentic Apps 2026.
- **Tekanan kebaruan**: kombinasi Wazuh+n8n+LLM sudah jadi pola umum 2026 → posisikan kontribusi
  pada **matriks confidence→otonomi + metrik terukur + audit-trail di konteks UKM**.

---

## Status ringkas (per 2026-09-28)

### ✅ SUDAH dikerjakan
- **Gemini full (2026-09-04)** Migrasi Ollama llama3.2:3b (4 GB) -> **Gemini 2.5 Flash API** di `deteksi-malware.json` + `deteksi-phishing.json` (node `Gemini Generate`, `maxOutputTokens 800` + `thinkingBudget 0`, `GEMINI_API_KEY` env, `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`). Server ~11 GB -> ~5-6 GB light. Hemat 5 GB.
- **RAG anti-halusinasi (F, 2026-09-04)** `docs/playbooks/` (critical/high/unverified) + node `RAG Retrieve` inject konteks playbook lokal ke prompt Gemini (keyword severity, tanpa vector DB).
- **Trusted autonomy SLA (F, 2026-09-04)** `Wait SLA 15m -> SLA Auto Escalate (CRITICAL/HIGH) -> Send Telegram Auto SLA` setelah Telegram alert; analis tidak klik 15 menit -> auto-eskalasi.
- **VT rate limit (B, 2026-09-04)** `VT Rate Limiter 15s` (4 req/menit free) + `VT 429? -> Wait 60s -> MalwareBazaar` + TTL diferensial aktif (7d/24h/6h) — aman untuk burst 100 workstation, hash sama cache-hit.
- **Fleet Monitor 100 PC (I, 2026-09-04)** `scripts/fleet-monitor.py` — custom monitoring arahan dospem, UI plek Wazuh Dashboard multi-view (Overview donut severity, Agents, Threat Events, Health), poll Wazuh API 30s + heartbeat Rust 60s, `POST /webhook-log` feed events, simulasi 101 agents, container `fleet-monitor` port 8080 (Tailscale `100.95.198.108:8080`).
- **USB dynamic scanner (I, 2026-09-04)** saran dospem deteksi malware dari flashdisk: agent scan `/run/media/<user>` tiap 2s, mount baru auto-watch RECURSIVE (subfolder ikut), unwatch saat cabut. Verified EICAR root + subfolder -> POST 200. Limitasi race mount-detik-pertama (upgrade: udev).
- **Agen ringan Rust (I, 2026-09-06..09)** `agent-rs/` crate `soar-agent` v0.1.0 (GPL-2.0, musl static target) — watch `~/Downloads`/`~/Desktop` + USB `/run/media/<user>` (poll 2s, recursive, unwatch saat cabut), sha256 streaming, POST JSON kompatibel `scripts/custom-n8n.py:170`, quarantine HTTP `127.0.0.1:8787`, heartbeat fleet-monitor, unit systemd. Binary 5,3 MB stripped · RSS 5,2 MB (vs Wazuh agent ~50 MB). Bukti: `docs/evaluasi/bench-rust-mttr-malware.json`, `docs/evaluasi/bench-rust-load.json`, EICAR -> n8n 200 + quarantine. Catatan: dospem menyarankan Go, implementasi dipilih **Rust** (alasan: `docs/agen-ringan/AGENT-RINGAN.md:45`).
- **Setup lintas-device + dashboard GUI/TUI + n8n otomatis (I/D, 2026-09-11)** Arahan dospem 2026-09-11 ("permudahkan setup SOAR lintas device" + "dashboard GUI dan TUI bebas pilih"): `deploy/setup-server.sh` (bootstrap server 1-perintah idempoten: .env interaktif → Wazuh certs → compose up 2 stack → integrasi Ansible → sinkron n8n → checklist manual) · `deploy/n8n-setup.py` (credentials dari .env + VT key via prompt **tidak ke .env**; import 4 workflow dengan **remap credential-ID by name** — 15 ref, tanpa node merah; idempoten + --dry-run) · 3 jalur workstation: `.deb` (`agent-rs/build-deb.sh`, config per-host 4 baris di `/etc/default/soar-agent`), `deploy/agent-install.sh` (1 host), `deploy/ansible/deploy-agents.yml` (fleet N host + verifikasi heartbeat) · `scripts/fleet-tui.py` (TUI kembaran GUI web, stdlib curses, sumber data sama `/api/fleet`+`/api/events`, 4 view + cari/saring/simulasi, adaptive terminal sempit) · `docs/arsitektur/VS-ANTIVIRUS.md` (jawaban dospem "beda dengan antivirus?") · diagram `docs/diagrams/fig-karyawan-flow` + `fig-karyawan-setup-vs-harian` (perspektif karyawan: tidak menjalankan apa pun). Bukti: py_compile/ruff/bash -n clean, TUI smoke-test pty lawan fleet-monitor asli (4 view + siklus filter + error banner), remap unit-test idempoten. Sisa: live-test setup + n8n-setup di server (butuh N8N_OWNER_API_KEY).
- **A#1** `block-domain` persist (permanen di template + config ter-version-control).
- **A#3** notifikasi ganda diperbaiki (abaikan event FIM `deleted` akibat karantina).
- **Reproducibility** config Wazuh manager ter-track (`config/` + `scripts/sync-wazuh-config.sh`).
- **C** metrik kuantitatif terukur (MTTR malware 1,68 dtk · phishing 2,13 dtk · FP suppression 100%).
- **B#1** hybrid: file eksekutabel tak-dikenal VT → tombol review (tutup celah zero-day utama).
- **F (explainable)** notifikasi malware **&** phishing memuat `🧠 Alasan keputusan`; **F (self-aware inline)** tandai `⚠️ Deteksi TERDEGRADASI` saat sumber rate-limit/error; **F (audit-trail)** keputusan analis dicatat `oleh <analis> pada <waktu WITA>` + riwayat eksekusi n8n.
- **F (self-aware health monitor, 2026-07-06, update Gemini 2026-09-04)** `scripts/health-monitor.py` — poll komponen inti (agent putus via Wazuh API, n8n, Gemini key), alert Telegram HANYA saat status berubah (anti-spam), state persist. Service `health-monitor` di compose.
- **D (hardening + IaC, 2026-07-06)** `deploy/hardened/` (Caddy reverse-proxy + TLS + basic-auth + segmentasi edge/backend, n8n tak publish port, `N8N_ENCRYPTION_KEY`) · **secret mgmt** `.env.example` · **IaC** `deploy/ansible/deploy-integration.yml` (idempoten).
- **H (pemeliharaan stack, 2026-09-02)** n8n di-update `2.35.7 → 2.36.9` — berada di atas semua versi patch CVE 2026 (Ni8mare/CVE-2026-21858 fixed di 1.121.0, CVE-2026-21877 di 1.121.3, CVE-2026-27495 di 1.123.22/2.x). Image python:3.12-alpine, caddy:2-alpine, Wazuh 4.9.2 di-pull ulang; seluruh container di-recreate & sehat (indexer cluster GREEN, 3 workflow n8n aktif).
- **C (bukti ilmiah, 2026-09-02)** Script benchmark (`scripts/benchmark-soar.py`) dibuat — 5 mode pengukuran (mttr-malware, mttr-phishing, load, vt-cold, fn-rate). Pemetaan MITRE ATT&CK (`docs/ilmiah/MITRE-ATTACK-MAPPING.md`: 10 teknik). Justifikasi n8n vs Shuffle (`docs/ilmiah/N8N-VS-SHUFFLE.md`: n8n 3.8/5 vs Shuffle 2.5/5). Evaluasi-metrik diperbarui.
- **B (multi-sumber + re-scan, 2026-09-02)** Script MalwareBazaar (`scripts/apply-b-malwarebazaar.py`): tambah node HTTP ke `mb-api.abuse.ch`, ensemble VT+MB (VT atau MB mendeteksi → THREAT), severity MB-aware, output fields MB. Script TTL diferensial (`scripts/apply-b-ttl-rescan.py`): malicious 7 hari, clean 24 jam, unknown 6 jam. **Status: LIVE 2026-09-20** lewat `scripts/patch-n8n-vt-cache-mb.py` (lihat entri "Cache verdict VT + ensemble MalwareBazaar" di bawah). Dua script `apply-b-*` lama **hanya mengedit file repo `n8n-workflows/deteksi-malware.json` yang sudah menyimpang dari live** — jangan diimport ke live (sudah ditandai SUPERSEDED di docstring-nya).
- **F (LLM-fallback advisory, 2026-09-02)** Flag `needs_advisory` di Rangkum Hasil (VT unverified, borderline 1-4 malicious, review_unknown non-exec). Build Payload generate advisory prompt → Ollama → Telegram. AI hanya advisory, tidak eksekusi AR. Push ke n8n via MCP.
- **Cache verdict VT + ensemble MalwareBazaar (B, 2026-09-20)** Sisa kategori B dijalankan **di workflow LIVE** (bukan import file repo yang sudah menyimpang). Temuan: live tidak punya cache sama sekali (`staticData` tidak persist di n8n 2.40) → TTL diferensial tak punya target. Solusi: cache verdict **server-side di `fleet-monitor`** (`POST /api/vt-cache/lookup|store`, key = **hash** bukan per-agent → burst 100 PC dengan hash sama = 1 panggilan VT; TTL diferensial malicious 7h/clean 24j/unknown 6j; persist ke `state/.fleet-vt-cache.json`) + 3 node n8n (`Cek Cache VT`, `Cache Hit?`, `Simpan Cache VT`) dan **`MalwareBazaar Lookup`** sebagai sumber intel kedua (credential `MalwareBazaar Auth`, `MALWAREBAZAAR_API_KEY`). `Rangkum Hasil` jadi sadar cache + MB (`mb_threat` menaikkan severity). Patch live: `scripts/patch-n8n-vt-cache-mb.py` (idempoten, backup, dry-run, bisa upgrade dari versi sebelumnya). Bukti: 24 uji unit endpoint cache (TTL/validasi/persist/expiry/burst) · 42 uji mock-API patch script (2 skenario: workflow asli + upgrade) · **E2E live 23 pass** (miss→store TTL 6 jam→hit; run 2 melewati VT & `Simpan Cache VT`, source `vt-cache`) · **E2E live 11 pass** (verdict cache "VT bersih 0/70" + MB signature `Mirai` → severity **HIGH** + alert, tanpa MB akan MEDIUM/senyap = celah FN tertutup).
- **Observability alert Telegram keluar (F, 2026-10-08, LIVE)** Bot API Telegram **tidak** menyediakan histori pesan keluar, jadi tiap alert yang benar-benar terkirim dicatat sendiri: service `alert-log` (:8091, JSONL `state/telegram-alerts.jsonl`, endpoint `/log` + `/stats`) + node **`Log Telegram Alert`** (fail-open) di workflow `Deteksi Malware` & `Deteksi Phishing` (dipasang setelah node kirim). Patch: `scripts/patch-n8n-telegram-log.py` (idempoten, backup, dry-run, multi-workflow). Bukti: **9/9 unit test** service · **E2E live**: 1 alert CRITICAL terkirim → tercatat `{telegram_ok:true, message_id, chat_id, severity}`.
- **Adopsi diagram-design (visual, 2026-10-08)** Ganti Mermaid → **HTML+SVG editorial** (skill `diagram-design`): token `paper/ink/muted/accent`, Instrument Serif + Geist/Geist Mono, tanpa shadow, konektor orthogonal, 1 aksen. Sumber di `docs/diagrams/src/`, PNG via `scripts/render-diagram.py`. Panduan: `docs/panduan/DIAGRAM-DESIGN.md`. **Selesai 3**: `fig-3.5-sequence-ar`, `overview-bernomor`, `arsitektur-soar` (semua `self_check` OK + `verify-geometry` 0 temuan). Sisa 12 diagram (beberapa sumber >9 simpul → merge/split).
- **MISP feed OSINT sebagai sumber intel ke-4 (B/M2, 2026-10-08, LIVE)** Menutup sisa milestone M2 (multi-sumber). **Feed CIRCL OSINT** (format MISP, ~1681 event, **tanpa API key**) dikonsumsi `scripts/misp-feed-sync.py`: tarik manifest + event JSON → ekstrak atribut IOC (hash/domain/ip/url) → index SQLite (`state/misp.db`, incremental). Service `misp-index` (:8090, `--serve`) menyajikan `GET /lookup?value=<hash|domain|ip|url>` + `/stats`; sync berkala 12 jam. Workflow LIVE `Deteksi Malware` ditambah node **`MISP Lookup`** antara `MalwareBazaar Lookup` → `Rangkum Hasil` (fail-open), `Rangkum Hasil` v3 sadar `misp_threat` (menaikkan HIGH). Patch: `scripts/patch-n8n-misp.py` (idempoten, backup, dry-run, v2→v3). Bukti: **18/18 unit test** feed consumer (parse/lookup/idempotensi/HTTP) · **14/14 unit test** patch · **E2E live HIJAU**: hash yang **hanya** dikenal MISP (VT 0, MB `false`, rule level 5 < ambang 7) → `misp_hit=true` + severity **HIGH**.
- **Scan on-demand (I/G, 2026-09-20)** Menutup blind spot file yang **sudah ada di disk sebelum agent dipasang** (agent reaktif hanya lihat create/modify → file lama tak pernah terlihat). Fondasi command queue (`/api/commands`, sudah quarantine/sinkhole) ditambah aksi **`scan`** + path. Agent Rust `collect_scan_targets()` walk folder pilihan (**bukan full disk** — VT 4 req/menit jebol), tanpa follow symlink, skip noise/0-byte, batas 2000 file (flag `truncated`); hash → **satu laporan ringkasan** `POST /api/scan-result` (**bukan alert per-file** → Telegram & dedup n8n aman). Fleet klasifikasi **cache-first** (`KNOWN_HASHES`: hash dikenal vs baru) + `GET /api/scan-results`. Dashboard `AgentDetailView`: kartu "On-demand scan" (tombol scan folder + ringkasan + link VT, hanya agent Rust). Bukti: `cargo test` 6 passed, E2E agent+fleet (scan 3 file → `new=3`; ulang → `new=0 known=3`), dashboard typecheck+build hijau.

- **Fix FP rundll32 System32 di rule chain (A/B, 2026-09-28, LIVE)** `scripts/process-chain-rules.xml` `110007`/`110017` memakai `<match>` yang diuji ke SELURUH log, sehingga alternatif `.dll.*\s*-` menelan `ParentCommandLine` → rundll32 maintenance Windows (StateRepository) naik **level 10 HIGH**. Fix: `<field ...commandLine>` + regex diketatkan (`.dll[,\s]+-\w`) + allowlist level 0 `110019`/`110020`. Bukti: `full_log` alert asli dari arsip manager, `wazuh-analysisd -t` rc=0. Live di manager v4.10.5.
- **File konfigurasi sistem (`hosts`) bukan lagi "MALWARE HIGH" (A, 2026-09-28, LIVE)** Rule 550 (FIM checksum berubah, level 7) dipetakan HIGH + judul keras `MALWARE TERDETEKSI`, dan Active Response otomatis **mencoba karantina file OS**. Fix `scripts/patch-n8n-systemfile.py` (4 node): `is_system_file` → severity maks MEDIUM (tetap diberitakan), `should_active_response=false`, judul "PERUBAHAN FILE KONFIGURASI SISTEM", VT N/A, prompt AI sadar `soar-sinkhole`, + pengaman `Fleet Quarantine`. Test 8/8; E2E exec 1234 hijau.
- **FP media jinak "MALWARE TERDETEKSI" (A, 2026-10-06)** `.mp4` di `~/Downloads/Telegram Desktop/` naik MEDIUM "MALWARE TERDETEKSI" padahal VirusTotal 404 + MalwareBazaar/OTX kosong; satu-satunya pemicu rule FIM 554 level 5. Akar: di `Rangkum Hasil`, `MEDIUM` adalah cabang `else` → setiap file tanpa indikator divonis malware. Fix `scripts/patch-n8n-noindicator.py` (Ekstrak/Rangkum/Build + gate "Perlu Notifikasi?"): severity jalur file murni dari threat intel (**rule FIM 550/554 tidak lagi menaikkan**), tanpa indikator → **INFO**; media/dokumen jinak (mp4/jpg/pdf/docx/...) tidak dikirim ke Telegram; eksekutabel hash tak dikenal (ekstensi berisiko / bit exec) → **MEDIUM "FILE PERLU REVIEW"**; VT error non-404 (429/5xx) → MEDIUM tak terverifikasi (bukan INFO); AR otomatis hanya CRITICAL/HIGH nyata. Test 13/13 (`scripts/test_patch_n8n_noindicator.py`).

### ⬜ BELUM dikerjakan (sisa)
| Prioritas | Item | Kategori | Berat |
|-----------|------|----------|-------|
| — | **A#2** event pertama terlewat pasca-restart agent | A | dimitigasi (fix sejati = buffer/queue di E) |
| ✅ **LIVE (2026-10-08)** | **Jalankan** benchmark N≥30 + load test + **MTTR HITL** + **VT cold-vs-cache** — mode baru `mttr-hitl` & `vt-cold` diperbaiki (end-to-end; versi lama salah). Hasil: `docs/evaluasi/EVALUASI-METRIK.md §11–§12`, JSON `docs/evaluasi/bench-mttr-hitl-20261008.json`, `docs/evaluasi/bench-vt-cold-vs-cache-20261008.json` | C | sedang |
| ✅ Sebagian (2026-09-11) | **Setup lintas-device (arahan dospem)**: `deploy/setup-server.sh` (bootstrap server 1-perintah interaktif: .env + Wazuh certs + compose up + integrasi Ansible) · `deploy/n8n-setup.py` (sinkron credentials dari .env + VT key via prompt, import 4 workflow dengan remap credential-ID by name → tanpa setup UI merah) · jalur workstation: `.deb` (`agent-rs/build-deb.sh` + `apt install`), `deploy/agent-install.sh` (1 host), `deploy/ansible/deploy-agents.yml` (fleet N host) | I/D | sedang |
| ✅ Sebagian (2026-09-11) | **Dashboard TUI** `scripts/fleet-tui.py` — kembaran terminal fleet-monitor (GUI), sumber data sama `/api/fleet` + `/api/events`, 4 view parity, cari/saring/simulasi, stdlib curses | I | kecil |
| ✅ **LIVE (2026-09-20)** | **Jalankan** apply-b (MalwareBazaar + TTL re-scan) + credential MB di n8n | B | sedang |
| ✅ Sebagian (2026-09-02) | **LLM-fallback** advisory (sudah selesai); **RAG** anti-halusinasi + **trusted autonomy** (timeout/SLA) | F | berat |
| Kecil (sisa bukti) | **I — Agen Ringan**: kode **sudah jalan** (Rust `agent-rs`, lihat bagian ✅ di atas); sisa hanya bukti laporan: bench JSON, kolom "Agen Ringan" di `docs/ilmiah/PERBANDINGAN-PENELITIAN.md`, sub-bab arsitektur | I | kecil |
| **#6** | **Arsitektur**: n8n queue-mode (Redis+worker) + PostgreSQL, HA, message-queue, observability | E | berat/berisiko ke live |
| Ditunda pasca-TA | **Upgrade Wazuh 4.9.2 → 4.14.7** terjadwal (agent ikut) | H3 | berat |
| Ditunda pasca-TA | **I-future — Fork Wazuh diet** (branch diet-syscheck-only, build .deb minimal) | I | berat |
| Menengah | **Registration date agent Rust (`first_seen`)** — kode **SIAP di repo, BELUM deploy** (lihat HANDOFF 2026-09-28): fleet-monitor simpan `first_seen` + emit `regDate`; `AgentDetailView` sudah di-wire. Tests 14/14 | I | kecil |
| Tinggi (drift) | **`fleet-monitor` server = versi lama** (tanpa command API & `_validate_runtime_secrets`), sedangkan repo lebih baru — dan `.env` server **tak punya** `FLEET_COMMAND_TOKEN` / `FLEET_AGENT_POLL_TOKENS_JSON`. Deploy versi repo tanpa mengisi token → crash-loop. Isi 2 token dulu sebelum naikkan versi | D | kecil |
| Menengah | **Rapikan logika Active Response** (temuan 2026-09-28): `Fleet Quarantine` selalu jalan + `!firewall-drop` srcip `0.0.0.0` untuk alert file. Pengaman file-sistem sudah live, jalur lain belum | A | sedang |
| ✅ **LIVE (2026-10-08)** | **Patch n8n `2.40.0 → 2.42.5`** (riset 2026-10-08): batch CVE Okt 2026 menambal "2.40.0 before 2.40.1" — 2 Critical 9.0 (CVE-2026-103255/103248 Supabase) + beberapa High. Deploy nyata di ravi-debian: `pull` + `up -d n8n`, healthz ok, **5 workflow active**, migrasi DB bersih, **E2E hijau** (FIM 21 node, chain 8 node, 0 error). Backup: `docker-compose.yml.bak-20261008-183407` | D | kecil |
| ✅ **LIVE (2026-10-08)** | **Upgrade Wazuh `4.10.5 → 4.14.8`** — urut **indexer→manager→dashboard** (outage ~5 mnt). Bukti: indexer cluster **GREEN** + data terjaga (cluster_uuid sama), manager `v4.14.8` `analysisd -t` rc=0, rule kustom (`process-chain-rules.xml`, `local_rules.xml`) selamat, agent 001/002 **Active**, integratord aktifkan 3 integrasi kustom, **manager→n8n `healthz=200`**, fleet `wazuh_api: True`. Backup: `~/wazuh-backup-20261008-184204` + `docker-compose.yml.bak-20261008-184154`. **5.0 ditunda pasca-TA** (bukan in-place: XML→Sigma, field/severity berubah, data tak dimigrasi) | H | sedang |

**Sisa hardening D di luar kode** (operasional, bukan artefak repo): firewall allow 1514/1515 dari subnet endpoint saja + **ganti password default Wazuh**.

**Rekomendasi lanjut berikutnya:** **lanjutkan 12 diagram diagram-design** (`docs/panduan/DIAGRAM-DESIGN.md`), lalu **M3** (matriks confidence→otonomi), **M4** (uji konsistensi LLM), **M5** (firewall + ganti password default Wazuh + OTX key → credential), dan **bukti laporan** (screenshot dashboard/Telegram, kolom "Agen Ringan"). ~~benchmark VT cold-vs-cache~~ ✅ **2026-10-08** (`§12`). ~~integrasi MISP (M2)~~ ✅ **2026-10-08** (feed CIRCL OSINT + node `MISP Lookup`). ~~observability Telegram~~ ✅ **2026-10-08** (`alert-log`). Lihat penutupan sesi di `HANDOFF.md`.

---

## A. Gap keandalan sistem (bug teramati saat pengujian) — prioritas #1

| Status | Gap | Akar masalah | Solusi yang diterapkan |
|--------|-----|--------------|------------------------|
| ✅ **SELESAI** (2026-07-02) | AR `block-domain` **hilang tiap container restart** | Manager sync `ossec.conf` dari template bind-mount tiap start; `block-domain` dulu hanya diedit runtime → tertimpa | Blok `block-domain` (command + active-response rules_id 999998) ditambahkan **permanen** ke template `wazuh-docker/single-node/config/wazuh_cluster/wazuh_manager.conf`. Terverifikasi via `--force-recreate`: block-domain0 tetap di ar.conf tanpa deploy script |
| ✅ **SELESAI** (2026-07-02) | **≥2 notifikasi untuk 1 file** | Karantina memindahkan file → FIM memicu event **`deleted`** → alert & eksekusi kedua (loop umpan balik) | Node `Ekstrak Alert` kini **mengabaikan event `deleted`** (`fimEvent === 'deleted' → return []`). Terverifikasi: EICAR → hanya **1** baris AR & 1 notifikasi (eksekusi event deleted berhenti di Ekstrak Alert). Tersimpan ke repo `n8n-workflows/deteksi-malware.json` |
| 🟡 **Dimitigasi / ditunda** | **Event phishing pertama terlewat** pasca-restart agent | Timing **logcollector** saat agent restart (seek ke EOF; `client_buffer` sudah aktif jadi bukan drop-disconnect). Tak ada toggle config yang menjamin fix | **Mitigasi operasional:** picu 1 event "pemanasan" setelah restart (sudah jadi praktik pra-demo). **Fix sejati (arsitektural, kategori E):** buffer/queue antara sumber log ↔ Wazuh. Di produksi dampak minim (gateway kirim banyak event); ini mayoritas artefak demo (injeksi manual tunggal) |
| 🟡 **Dipulihkan** (temuan 2026-09-28) | `fleet-monitor` **crash-loop** saat deploy versi repo (outage singkat) | Container menjalankan skrip **LAMA** (tanpa validasi); repo menambah `_validate_runtime_secrets()` yang mewajibkan `FLEET_COMMAND_TOKEN` + `FLEET_AGENT_POLL_TOKENS_JSON`, padahal `.env` server tak punya keduanya | **Dipulihkan** ke skrip lama (healthz 200). Jalur aman: patch minimal ke skrip lama, atau isi 2 token dulu lalu `docker compose up -d fleet-monitor` |
| ✅ **SELESAI** (2026-09-28, live) | Perubahan file FIM apa pun (mis. `hosts`) naik jadi **"MALWARE TERDETEKSI" HIGH** | Rule **550 level 7** dipetakan `ruleLevel>=7 → HIGH` + judul di-hardcode; hash `hosts` spesifik-mesin → VT tak relevan; AR otomatis (`Fleet Quarantine`) **mencoba karantina file OS** (exec 1231, gagal 400 hanya karena validasi menolak path Windows) | `scripts/patch-n8n-systemfile.py`: `is_system_file` (path) → severity maks **MEDIUM** (tetap diberitakan), `should_active_response=false`, judul "PERUBAHAN FILE KONFIGURASI SISTEM", VT N/A, prompt AI sadar `soar-sinkhole`, + pengaman `Fleet Quarantine` tak pernah karantina file sistem. Test 8/8, E2E exec 1234 hijau |
| ⬜ **BARU** (temuan 2026-09-28) | Logika AR belum rapi: `Fleet Quarantine` selalu jalan (`ar.status !== 'isolated'` **selalu true**), dan `Trigger Active Response` kirim `!firewall-drop` srcip `0.0.0.0` untuk alert **file** (bukan IP) | Pengaman file-sistem sudah ada, tapi jalur AR lain masih bisa salah sasaran | Rapikan: ganti kondisi sukses AR yang benar, pisahkan AR IP vs file, dan batasi karantina ke direktori user-writable |

## B. Gap keandalan Threat Intelligence (VirusTotal/GSB/URLScan)

VT andal sebagai **sinyal pendukung** (ancaman dikenal), **bukan ground truth**.

| Status | Gap | Dampak | Solusi |
|--------|-----|--------|--------|
| ✅ **SELESAI** (2026-07-02) | **Zero-day / file baru → 0/70** | ⚠️ **False-negative** (jahat dianggap bersih → disuppress diam-diam) | Node `Rangkum Hasil` kini: file **eksekutabel/berisiko** (ekstensi .sh/.exe/.ps1/… ) yang **tak dikenal VT** → `review_unknown=true` → **THREAT jalur tombol (HITL)**, bukan silent/auto. File jinak non-eksekutabel tetap sunyi. **Terverifikasi:** `.sh` unknown → Telegram Alert (tombol); `.txt` unknown → sunyi. **Batas:** file eksekutabel **tanpa ekstensi** (ELF) belum tertangkap → lanjutan: deteksi magic-byte/exec-bit |
| ⬜ Lanjutan | Hanya melihat **hash dikenal** (ganti 1 byte → hash baru) | Reputasi hash mudah dielakkan | **Deteksi perilaku** (rule Wazuh, sandbox lokal spt CAPEv2) |
| ✅ Script siap (2026-09-02) | *Detection lag* (verdict berubah seiring waktu) | Cache bisa menyajikan verdict basi | ✅ **LIVE (2026-09-20):** **TTL diferensial** aktif di cache server-side (`fleet-monitor` `POST /api/vt-cache/store`, key = hash): malicious 7 hari, clean 24 jam, unknown 6 jam. Verdict bersih/tidak-dikenal kadaluwarsa lebih singkat → re-scan lebih cepat → turunkan FN rate. (Cache di dalam n8n tidak dipakai: `staticData` tidak persist di n8n 2.40.) |
| ✅ **LIVE** (2026-09-20) | Ketergantungan 1 sumber | Single point of intel-failure | ✅ **MalwareBazaar aktif di workflow live** (`scripts/patch-n8n-vt-cache-mb.py`, node `MalwareBazaar Lookup` + credential `MalwareBazaar Auth`): ensemble VT atau MB mendeteksi → THREAT. MB dijalankan di **kedua** jalur (cache hit & miss) — verdict bersih dari cache tetap diadu MB, jadi hash yang dikenal MB tapi belum dikenal VT tidak lolos senyap. **OTX AlienVault** tetap fallback saat VT rate-limit/error (`scripts/patch-n8n-otx.py`). |
| ✅ Sudah ada (2026-09-15) | Rate limit / downtime | Analisis gagal | **OTX fallback** dipicu saat VT 429 — verdict dari OTX menggantikan. Idempoten patch script. |

**Prinsip:** perlakukan VT/GSB/URLScan sebagai **corroboration multi-sinyal**, bukan otoritas tunggal.

## C. Gap bukti ilmiah (paling menaikkan nilai) — prioritas #2

| Status | Gap | Solusi / hasil |
|--------|-----|----------------|
| 🟢 **Terukur** (2026-07-02) | Klaim "unggul" belum terukur | **Data nyata (`docs/evaluasi/EVALUASI-METRIK.pdf`):** MTTR malware auto-isolate **1,68 dtk** (N=15, cache hangat); MTTR phishing auto-block **2,13 dtk** (N=5, jalur GSB); **reduksi false-positive 100%** (N=8: 8 alert FIM baseline → 0 notifikasi SOAR). **Lanjutan:** MTTR HITL & jalur URLScan, VT cold vs cache, uji beban, false-negative zero-day, ulangi N≥30 |
| ✅ **Selesai** (2026-09-02) | Justifikasi empiris **n8n vs Shuffle** | **`docs/ilmiah/N8N-VS-SHUFFLE.md`:** perbandingan 6 aspek (code execution, state, integrasi, observability, deployment, HITL). n8n 3.8/5 vs Shuffle 2.5/5. Bukti dalam kode (staticData cache, Code node HTTP, SQLite)
| ✅ **Selesai** (2026-09-02) | Pemetaan **MITRE ATT&CK** | **`docs/ilmiah/MITRE-ATTACK-MAPPING.md`:** 10 teknik unik (T1566.002, T1189, T1204.002, T1027, T1036, T1484, T1005, T1059, T1070.004, T1499). Visual matrix coverage + gap analysis
| ✅ **Selesai** (2026-09-02, **update 2026-10-08**) | Script benchmark (uji beban + N≥30) | **`scripts/benchmark-soar.py`:** 7 mode (mttr-malware, mttr-fleet, mttr-phishing, **mttr-hitl**, load, **vt-cold** [end-to-end, diperbaiki], fn-rate). Output JSON + tabel. **§11–§12 dijalankan 2026-10-08.**
| ✅ **Selesai** (2026-09-02) | **Jalankan benchmark** | MTTR malware 0,03s webhook (N=30), MTTR phishing 0,03s (N=10), Load test 34,11 alert/detik (N=20), FN rate 0% (N=15). Detail di `docs/evaluasi/bench-*.json` + `docs/evaluasi/EVALUASI-METRIK.md §9`

## D. Gap keamanan platform SOAR itu sendiri — prioritas #3 🟢 SEBAGIAN (2026-07-06)

| Status | Gap | Solusi |
|--------|-----|--------|
| ✅ **SELESAI** | n8n rentan (CVE-2026-21858 "Ni8mare", CVSS 10.0; penyalahgunaan webhook) | Webhook **tidak diekspos publik** (poller keluar-saja di balik NAT — sudah) + `deploy/hardened/`: **Caddy reverse-proxy + TLS + basic-auth** di depan editor, n8n **tak publish port** (hanya internal/Caddy), **segmentasi jaringan** edge/backend, **secret mgmt** (`.env.example` + `N8N_ENCRYPTION_KEY`, tanpa kredensial hardcode) |
| ✅ **SELESAI** | Reproducibility | **IaC** `deploy/ansible/deploy-integration.yml` — playbook idempoten ganti langkah manual `docker cp`/`docker exec` (integration script, AR scripts, blok `<integration>` ossec.conf, restart+verif) |
| ⬜ Operasional | Firewall + password default | Allow 1514/1515 dari subnet endpoint saja (DEPLOYMENT Step 7.1); **ganti password default Wazuh** sebelum produksi |
| ⬜ **BARU** (temuan 2026-09-20) | **Key OTX tertulis inline** di node `OTX Lookup` (bukan credential) → ikut ter-return `GET /api/v1/workflows/{id}` dan tersalin ke setiap file di `backups/` | Pindahkan ke credential `OTX API Key` (httpHeaderAuth) seperti `MalwareBazaar Auth`/`VirusTotal API Key`, lalu **rotasi key**. Perlu 1 patch kecil + verifikasi |

## E. Gap arsitektur (jangka menengah–panjang) ⬜ BELUM

| Gap | Solusi |
|-----|--------|
| **SPOF**: Wazuh single-node + n8n 1 container | **High-Availability**: manager/indexer redundan + load balancer + failover (selaras Springer CCIS 2026) |
| n8n single-process (SQLite, tanpa queue) → bottleneck saat lonjakan | **n8n queue mode** (Redis + worker) + **PostgreSQL** |
| State tidak terbagi/persist (cache VT di `staticData`) | Pindah cache ke **Redis** (survive restart, dibagi lintas-worker) |
| Kopling Wazuh↔n8n langsung (tanpa buffer) | **Message queue** (Redis/RabbitMQ) → buffering & replay |
| Tak ada observability pipeline | **Prometheus + Grafana** (sekaligus sumber data metrik bab evaluasi) |
| Inferensi AI bersaing resource | AI sebagai **microservice inferensi** terpisah; opsi **RAG** atas playbook/threat-intel |

## F. Kontribusi terhadap masalah INDUSTRI (arah kebaruan) 🟢 SEBAGIAN

Masalah industri 2025–2026: playbook rapuh/statis, *playbook rot* (silent-failure), alert fatigue (67% alert diabaikan), black-box → analis tak percaya, risiko LLM (halusinasi/kebocoran).

| Status | Gap industri | Kontribusi (dari fondasi proyek ini) |
|--------|--------------|--------------------------------------|
| ✅ **SELESAI** (2026-07-06) | Automasi **gagal diam-diam** & tak sadar cakupan turun | **Self-aware (inline):** notifikasi menandai **`⚠️ Deteksi TERDEGRADASI`** saat VT rate-limit/error (`degraded`). **Self-aware (health monitor):** `scripts/health-monitor.py` poll agent (putus = blind spot), n8n, LLM API, Wazuh-API → Telegram alert HANYA saat status berubah (anti-spam), state persist lintas-restart |
| ✅ **SELESAI** (explainable+audit, 2026-07-02) | **Black-box** merusak kepercayaan analis | Setiap notifikasi (malware **&** phishing) memuat **`🧠 Alasan`** (skor VT/GSB + keyakinan + jalur). **Audit-trail:** callback handler mencatat keputusan analis **`oleh <analis> pada <waktu WITA>`** di pesan Telegram + riwayat eksekusi n8n (action/agent/target/analis). Catatan: log file dari Code node tak tersedia (fs sandbox n8n) → audit via Telegram+execution-history |
| ✅ **Selesai** (2026-09-02) | Alert yang **tak cocok playbook** → diam/dilempar | **LLM-fallback advisory** (LLM API): flag `needs_advisory` di Rangkum Hasil (VT unverified, borderline 1-4 malicious, review_unknown non-exec). Build Payload generate prompt advisory → Ollama → Telegram. AI hanya **advisory**, tak pernah eksekusi AR sendiri. |
| ✅ **Terukur** (di C) | **Alert fatigue** | Reduksi FP VT-gated **100%** (lihat `docs/evaluasi/EVALUASI-METRIK.pdf`) |
| ⬜ Lanjutan | HITL = bottleneck vs otonomi berisiko | **Trusted autonomy**: timeout/SLA + otonomi adaptif per tingkat keyakinan |

## G. Perluasan cakupan deteksi (penguatan TA, selaras milestone M2–M3)

Scope sekarang (per batasan masalah 1.5): **malware via FIM + reputasi hash** dan **phishing via log akses URL**. Belum mencakup vektor lain — bukan kelemahan, tapi pilihan desain. Prioritas perluasan diurutkan nilai/effort. (Item multi-sumber/re-scan/sandbox sudah tercakup di bagian B — tidak diduplikasi di sini.)

| Prioritas | Item | Status sekarang | Aksi | Berat |
|-----------|------|-----------------|------|-------|
| 1 | **G1 — Phishing proaktif** (url/domain *belum* sempat diklik) | Reaktif: baru mendeteksi URL yang muncul di log akses | ✅ **SELESAI (2026-09-02):** workflow n8n `Proaktif Phishing (URLhaus)` — Schedule tiap jam → feed URLhaus CSV (`csv_recent/`, publik) → parse/filter `malware_download` (max 15/siklus) → verifikasi **GSB** per URL → **auto-`!block-domain`** ke agent 001 (via Wazuh API inline) untuk threat GSB; yang GSB `unavailable` → masuk **review** (tidak diklaim aman); bersih → silent. Cache 24 jam (staticData) anti-rescan. 1 notifikasi ringkasan Telegram per siklus (anti-spam). Teruji: feed→parse→GSB→review/block→notif. | sedang |
| 2 | **G2 — Magic-byte untuk file tanpa ekstensi** | B#1 baru menangkap file berekstensi (.sh/.exe/.ps1/…); ELF/MZ **tanpa ekstensi** lolos & disenyapkan | ✅ **SELESAI (2026-09-02):** deteksi **execute-bit via `perm_after`** dari alert FIM (check_all) — node `Ekstrak Alert` ekstrak `perm_after`/`no_ext`/`is_exec`; `Rangkum Hasil` perluas `review_unknown`: file **tanpa ekstensi + executable + VT unknown** → `risky_exec` → jalur tombol HITL, bukan sunyi. Teruji: file exec tanpa ekstensi + VT unknown → **REVIEW (tombol)**; file non-exec tanpa ekstensi → **sunyi** (tanpa FP) | sedang |
| 3 (opsional) | **G3 — Phishing email** (lampiran + tautan body) | Belum ada | Aturan Wazuh atas log mail/proxy; lampiran dialihkan ke pipeline malware (hash VT); tautan ke pipeline phishing | berat |
| 4 (opsional) | **G4 — Deteksi perilaku ringan** (auditd) sbg pemicu kedua | Hanya FIM (file jatuh ke disk) | Rule eksekusi mencurigakan (execve via auditd) → enrichment VT + HITL. Menangkap malware yang *berjalan*, bukan cuma *tersimpan* | berat |

## H. Pemeliharaan & modernisasi stack

| Status | Item | Catatan |
|--------|------|---------|
| ✅ **SELESAI** (2026-07-06, update 2026-09-02, 2026-09-16, **2026-10-08 LIVE**) | **H1 — Update n8n & recreate** | `2.35.7 → 2.36.9` (2026-09-02) → `2.40.0` (2026-09-16) → **`2.42.5`** (2026-10-08, menutup batch CVE Okt 2026). Deploy live di ravi-debian: healthz 200, **5 workflow active**, E2E hijau. |
| ✅ **SELESAI** (2026-09-02, **2026-10-08 LIVE**) | **H2 — Pin versi n8n** | `image: n8nio/n8n` → `2.36.9` → `2.40.0` → **`2.42.5`** di `docker-compose.yml` + `deploy/hardened/docker-compose.yml` (server + repo). |
| ✅ **SELESAI** (2026-09-16, update **2026-10-08**) | **H3 — Upgrade Wazuh** | `4.9.2 → 4.10.5` (2026-09-16) → **`4.14.8`** (2026-10-08, stable terbaru 23 Sep 2026). Cara: pertahankan compose kustom, bump tag manager/indexer/dashboard, `pull` + `up -d` urut indexer→manager→dashboard. Data & cert persist (volume), rule/decoder/integration kustom di named volume selamat. Catatan: cert **tidak** diregenerasi (masih kompatibel 4.x); agent 4.10.x tetap connect (manager ≥ agent). |
| ⬜ Jangan dikejar | **H4 — Wazuh 5.0** | Masih **beta** (beta5, 1 Sep 2026) & breaking besar: engine sendiri, hapus Filebeat, path `/var/wazuh-manager`, hapus agent ID 000 → berdampak integratord + AR path lama. Evaluasi pasca-TA |
| Catatan | **H5 — Alternatif "lebih ringan"** | Tidak ada pengganti Wazuh setara yang lebih ringan: osquery/Falco/Velociraptor = fungsi lebih sedikit; Elastic/Graylog/Security Onion = selevel/lebih berat (Graylog SSPL). Resource sekarang sehat (~2,7 GB: indexer 1,5 GB, manager 0,5 GB, dashboard 0,2 GB, n8n 0,37 GB) |

---

## Prioritas eksekusi (sepadan-usaha)

1. ✅ **Perbaiki 3 bug keandalan (A)** — selesai (2026-07-02).
2. ✅ **Tambah metrik kuantitatif (C)** — dasar selesai (2026-07-02), lanjutan selesai (2026-09-02: script benchmark + MITRE mapping + n8n vs Shuffle).
3. ✅ **LLM-fallback advisory (F)** — selesai (2026-09-02): needs_advisory flag + advisory prompt + push ke n8n.
4. ✅ **Deteksi hybrid/multi-sinyal (B)** — script selesai (2026-09-02), **LIVE 2026-09-20**: cache verdict VT di fleet-monitor (TTL diferensial) + node `Cek Cache VT`/`Cache Hit?`/`Simpan Cache VT` + `MalwareBazaar Lookup` (ensemble VT+MB) + credential `MalwareBazaar Auth`. Patch: `scripts/patch-n8n-vt-cache-mb.py`.
5. ✅ **Housekeeping versi (H1–H2)** — selesai (2026-09-02).
6. ✅ **Perluasan cakupan (G1 + G2)** — selesai (2026-09-02).
7. ✅ **Hardening keamanan + IaC (D)** — sebagian selesai (2026-07-06).
8. ✅ **Jalankan benchmark** — selesai (2026-09-02): MTTR, load test, FN rate. Throughput 34 alert/detik, FN 0%.
9. 🟢 **I — Agen Ringan** — diagram + Rust 5.3 MB + EICAR E2E + USB recursive scanner + fleet monitor DONE (2026-09-04). Setup lintas-device + TUI dashboard (2026-09-11). Sisa Fase 3: benchmark final + laporan (`docs/agen-ringan/ROADMAP-AGEN-RINGAN.md:126`).
10. ✅ **RAG anti-halusinasi + Trusted autonomy (F)** — selesai (2026-09-04): playbook lokal inject + SLA 15m auto-eskalasi.
11. **Arsitektur queue-mode + HA (E)** — SKIP untuk TA (berisiko ke live); VT limiter + cache staticData cukup untuk demo 100 PC. Future work pasca-sidang.
12. ✅ **Modernisasi stack (H3, 2026-09-16)** — Upgrade Wazuh `4.9.2 → 4.10.5` selesai. Ditunda: **4.14.7** pasca-TA (breaking path cert/agent).
13. **I-future — Fork Wazuh diet** — pasca sidang, hanya jika perlu klaim optimasi.
14. ⬜ **Selesai-kan sisa dashboard (2026-09-16 scan)** — Live-kan MITRE ATT&CK module, visualisasi severity, webhook-log phishing, link hash → VT/OTX. Detail di tabel "Scan aplikasi" di atas.
15. ✅ **Fitur dashboard fase 2 (2026-09-16)** — Metrics CPU/RAM per agent via heartbeat (agent Rust `sysinfo` v0.2.0 → fleet `/api/fleet` + history `/api/metrics` → strip metadata + grafik garis di agent detail) · Tombol Karantina/Blokir di tabel events → command queue `POST /api/commands` di-poll agent (quarantine `do_quarantine` + sinkhole hosts `do_sinkhole`, validasi ketat, keluar-saja aman NAT) · Network map hub-and-spoke (SVG native, klik node → detail) · Tombol SSH per agent (salin perintah, Opsi A tanpa RCE).
16. ✅ **Scan on-demand (2026-09-20)** — aksi `scan` di command queue + agent Rust walk/hash folder pilihan (cache-first, laporan ringkasan) + kartu dashboard di `AgentDetailView`. Bukti E2E hijau. **LIVE di ravi-debian (010) + nixbox (009)**: dashboard di-rebuild, binary agent terpasang, uji scan sungguhan 010 (`new=3`) & 009 (`scanned=2000 truncated`). Bonus fix: roster heartbeat di-persist (`state/`) supaya restart tak menghapus agent offline dari daftar. Sisa device lain: 002/005/006/007 (+008 macbook saat online).
17. ✅ **Riwayat event per periode (2026-10-04)** — dashboard bisa lihat alert/event per **24j/7h/30h/90h + rentang custom**, di semua view event (Security events, FIM, Threat Intel, Agent detail). Backend: event pipeline SOAR dipersist ke **SQLite** (`state/events.db`, retensi 90 hari) + endpoint `GET /api/events/history?since&until&source=all` yang **menggabung+dedup** dengan alert Wazuh historis dari **Wazuh Indexer** (`wazuh-alerts-*`). Komponen bersama `PeriodFilter`/`Pagination`; hook `useEventHistory`; `formatWazuhTime` dipin ke WITA. Verifikasi: 25 unit fleet-monitor + 7 unit FE hijau, `npm run check` hijau, E2E durable lintas-restart. **LIVE di ravi-debian (2026-10-04)** via bedah file (tree server divergen): fleet-monitor `event store siap: /state/events.db`, dashboard rebuild, `/api/events/history` mengembalikan alert Wazuh Indexer nyata + event SOAR.

## Scan aplikasi 2026-09-16 — sisa yang belum live di dashboard/fleet

Hasil tes end-to-end 16 Sep: semua workflow n8n (Deteksi Malware, Deteksi Phishing, Proaktif Phishing, Telegram Callback) + agent Rust + fleet API + dashboard **100% jalan**. Duplikat workflow dibersihkan (ZSAV8 Proaktif + D2ApFC Telegram). Binary agent 003 di-update ke versi dengan sensor phishing. Sisa gap yang baru ditemukan saat scan:

| Prioritas | Item | Kategori | Berat | Aksi |
|-----------|------|----------|-------|------|
| Tertinggi | **M — MITRE ATT&CK module `soon`** di dashboard (`ModulesHub.tsx`) — label "Segera", tidak bisa diklik, mapping rule Wazuh → teknik MITRE sudah ada di `docs/ilmiah/MITRE-ATTACK-MAPPING.md` | I/G | sedang | ✅ **SELESAI (2026-09-16)** — komponen `MitreAttackView.tsx` baru, 6 playbook + 10 teknik unik, label "Segera" dihapus, view bisa diklik. Deployed |
| Tinggi | **Benchmark MTTR resmi N≥30** (`scripts/benchmark-soar.py`) | C | sedang | ✅ **SELESAI (2026-09-16; ralat 2026-09-28)** — hasil nyata: `docs/evaluasi/bench-mttr-malware.json` (n=30, mean **0.03s**, VT-cache hangat) + `docs/evaluasi/bench-mttr-fleet-20260915-N30.json` (n=30, mean **3.00s** injeksi→fleet-log). **Klaim lama salah** (`result/bench-mttr-malware-n30.json`, mean 9.04s): folder `result/` tidak ada & di-ignore `.gitignore`, dan angkanya tak cocok artefak |
| Menengah | **Event severity belum divisualisasi** — fleet-monitor kirim `severity`, dashboard belum tampilkan pie/bar breakdown per severity, hanya angka total | I | kecil | ✅ **SELESAI (2026-09-16)** — donut severity live (CRITICAL/HIGH/MEDIUM/UNVERIFIED) ganti chart statis |
| Menengah | **`/webhook-log` hanya dari Deteksi Malware** — Deteksi Phishing & Proaktif belum nge-log ke fleet, dashboard tidak melihat event phishing | B/I | kecil | ✅ **SELESAI (2026-09-16)** — node `Log ke Fleet` ditambahkan ke `Deteksi Phishing`, event phishing tampil di fleet (exec success) |
| Kecil | **Hash event tidak link ke VT/OTX** — tiap event punya `hash`, dashboard belum buat tautan `https://virustotal.com/gui/file/<hash>` | I | 1 baris | ✅ **SELESAI (2026-09-16)** — kolom "Hash (VT)" link ke VirusTotal di SecurityEventsDashboard |
| Rendah (berat) | **SCA module `soon`** (`ModulesHub.tsx`) — butuh polling Wazuh SCA endpoint, tapi soar-agent bukan Wazuh agent (tak ada isi SCA) | I/G | sedang | ⬜ Arsipkan; SCA relevan kalau ada agent Wazuh sungguhan |

## Prinsip arah tesis
> SOAR open-source yang **confidence-based, transparan, dan sadar-degradasi** untuk menekan alert fatigue tanpa silent-failure — dengan human-in-the-loop yang dapat dipertanggungjawabkan.

*(Referensi lengkap ada di `docs/ilmiah/PERBANDINGAN-PENELITIAN.pdf`.)*
