# Handoff SOAR - 2026-09-14 (lanjutan)

## 0. Fix dashboard 500 + kolom IP/OS (sesi nixbox, 14 Sep sore)

**Dashboard `/api/fleet` + `/api/events` 500** — akar: `rewrites()` di
`next.config.ts` dievaluasi SEKALI saat `next build` lalu destination
di-serialize ke `.next/routes-manifest.json` (bukan per-request). Image lama
ke-bake `http://127.0.0.1:8080` yang dari dalam container = dirinya sendiri
→ `ECONNREFUSED` → 500. Env runtime `FLEET_API_URL` tidak ngaruh.

- Diubah: `dashboard/Dockerfile` — ARG default → `host.docker.internal:8080`,
  deps/builder → `node:24-slim` (layer cache alpine corrupt:
  `lightningcss.linux-x64-musl.node` hilang, `--no-cache` gagal build).
- Diubah: `dashboard/next.config.ts` — komentar diluruskan (build-time baking)
  + fallback default → `host.docker.internal:8080`.
- Live: rebuild `soar-fleet-dashboard:latest`
  (`--build-arg FLEET_API_URL=http://host.docker.internal:8080`), container
  restart dengan `--add-host host.docker.internal:host-gateway`.
  Verifikasi: `:3000/api/fleet` + `/api/events` + `/healthz` 200, log bersih
  dari ECONNREFUSED.

**Kolom IP semua `127.0.0.1`** — akar: agent kirim `"ip":"127.0.0.1"` hardcoded
di heartbeat (`agent-rs/src/main.rs`), server (`fleet-monitor.py`) percaya saja.

- Diubah: agent kirim `"ip":""` + `os` lowercase (`linux|windows|macos`,
  cocok dengan `osType()` dashboard).
- Diubah: server petakan `"" / 127.0.0.1 / 0.0.0.0 / localhost / ::1` →
  `self.client_address[0]` (IP TCP asli). Ini JUGA menyembuhkan binary lama
  yang belum rebuild. File tersync ke ravi-debian, `fleet-monitor` di-restart.
- Verifikasi live: `002 nixbox 192.168.1.26`, `003 ravi-debian 100.73.91.17`,
  `006 ideapc 100.124.118.45`. `000 wazuh.manager 127.0.0.1` = benar by design
  (manager Wazuh selalu self-loopback).

**Kolom OS cuma nixbox** — binary lama (003/005/006) belum punya field `os`
sama sekali → dashboard tampilkan `-`. Butuh binary baru:

- Baru: `deploy/rebuild-agent-binaries.sh` (jalan DI ravi-debian, butuh sudo):
  `cargo build --release` (registry 284M sudah cache) → install + restart 003;
  `--windows` cross-compile `.exe` via rustup+mingw (linker sudah ada);
  `--deb` bungkus `.deb` dari binary gnu.
- Diubah: `agent-rs/build-deb.sh` — `BIN` bisa di-override
  (`BIN=target/release/soar-agent ./build-deb.sh`), default tetap musl.
- Binary nixbox sudah diverifikasi kirim `{"ip":"","os":"linux"}` (dummy server).
- `002 nixbox`: modul NixOS build dari source lokal → ikut fix saat rebuild.

**Update 14 Sep malam (password sudo dipakai via stdin, tidak disimpan):**

- ✅ `002 nixbox`: `sudo nixos-rebuild switch --impure` sukses (pure mode menolak
  import absolute path). Binary baru verified live: `002 nixbox 192.168.1.26 linux`.
- ✅ Server-side IP fix verified live sebelum server down (002/003/006 IP asli).
- ⚠️ `003 ravi-debian`: binary nixbox TIDAK bisa dipakai (glibc 2.42 +
  interpreter /nix/store → 203/EXEC). Restore binary lama dari .deb (active).
  Binary gnu Debian-native SUDAH dibuild di server
  (`agent-rs/target/release/soar-agent`, 5.5MB, interpreter /lib64) — tinggal
  install + restart.
- ✅ `soar-agent.exe` BARU berhasil di-cross-compile DI NIXBOX (7.9MB, PE32+,
  ada di `deploy/bundle/soar-agent.exe`): rustup stable 1.98.1 + target
  `x86_64-pc-windows-gnu` + linker mingw nixpkgs + `-L` pthreads
  (`pkgsCross.mingwW64.windows.pthreads`, mingw-w64 ≥ 12 tidak bundle pthread).
- 🔴 **ravi-debian DOWN** sejak ~18:00 (ping/SSH No route, ARP FAILED; tunnel
  hanya sajikan halaman Access). Kemungkinan mati listrik/tidur (baterai X260).
  **Update 20:30: server NYALA lagi.** Lanjutan dikerjakan:
  1. ✅ exe + ps1 baru diantar ke server; file server :8000 ternyata root-nya
     `/home/ravi/public` (bukan deploy/bundle) → copy ke sana, verified
     `200 7928320` (byte pas = binary baru).
  2. ✅ `003 ravi-debian`: binary gnu Debian-native (5.5MB) terpasang +
     restart, verified live `003 ravi-debian 100.73.91.17 linux`.
  3. ✅ `fleet-dashboard` container Up healthy, `:3000/api/fleet` 200.
  4. ⏳ SISA: 005/006 reinstall via ps1 (manual di PC Windows, butuh admin):
     `Stop-Service soar-agent; sc.exe delete soar-agent` lalu
     `$env:AGENT_ID="005" $env:AGENT_NAME="toshiba-bapak" powershell -File install-agent-windows.ps1`
     (006: ID 006 / ideapc). 005 belum heartbeat sejak outage (mungkin PC mati).
- `deploy/rebuild-agent-binaries.sh` disesuaikan: linux pakai rustup stable
  (cargo distro 1.85 terlalu tua), catat pelajaran glibc/nix.

**TINGGAL RAVI (butuh sudo / akses mesin):**

1. ravi-debian: `cd ~/Projects/soar-project && ./deploy/rebuild-agent-binaries.sh --windows`
2. nixbox (sini): `sudo nixos-rebuild switch`
3. 005/006: jalankan ulang `install-agent-windows.ps1` dengan exe baru di `deploy/bundle/`

## 1. Dashboard fleet diganti UI Wazuh (`dashboard/`)

Permintaan: "existing dashboard fleet ganti dengan milik wazuh-dashboard-clone karena UI-nya sudah proper, dan UI-nya harus sama persis".

**Keputusan arsitektur**: `scripts/fleet-monitor.py` **TETAP** dipakai, tapi turun peran jadi **backend data (headless)** — dia titik masuk data (`POST /api/heartbeat` dari soar-agent, `POST /webhook-log` dari n8n, poll Wazuh API). Kalau `.py` dihapus, 100 agent + workflow n8n harus diarahkan ulang. Yang diganti hanya lapisan tampilan.

UI diambil **apa adanya** dari `wazuh-dashboard-clone` (komponen Next.js utuh → dijamin identik, tidak diport ke vanilla JS yang berisiko drift).

- **Baru**: `dashboard/` — Next.js 16 standalone. Hanya deps yang dipakai komponen (`react`, `next`, `lucide-react`, `tailwindcss`, `tw-animate-css`, `shadcn`). Dep berat clone (`three`, `gsap`, `lenis`) dibuang.
- **Baru**: `dashboard/src/lib/fleet.ts` — types + `useFleet()` (poll `/api/fleet` + `/api/events` tiap 5s, error non-fatal → data terakhir tetap tampil).
- **Baru**: `dashboard/next.config.ts` — `rewrites` `/api/*` → `FLEET_API_URL` (default `http://127.0.0.1:8080`), + `turbopack.root` (wajib: parent `/home/ravi/Projects` punya lockfile lain yang bikin resolusi CSS gagal).
- **Diubah**: `docker-compose.yml` + `dashboard/Dockerfile` — service `dashboard` di :3000, `FLEET_API_URL=http://host.docker.internal:8080` (fleet-monitor `network_mode: host`, sudah dites: `127.0.0.1:8080` dari dalam container = container sendiri).

**Data live yang sudah diwire**:
| View | Sumber |
|------|--------|
| Modules KPI + badge sidebar | `stats.total/active/disconnected` |
| Agents table + donut status + coverage | `agents[]` |
| Agent detail header + FIM recent events | agent terpilih + event `agent_id` |
| Security events table + KPI + Top 5 agents donut | `events[]` + `stats.severity` |
| FIM daftar file + SHA256 + hits | path & hash unik dari `events[]` |
| Health n8n/AI/Wazuh | footer sidebar, dot `API` di header |

**Masih statis (tidak ada sumbernya di API)**: chart evolusi, MITRE ATT&CK, Compliance PCI DSS, SCA CIS, seluruh halaman Vulnerabilities. Mapping KPI: `Level 12+`=CRITICAL, `Authentication failure`=HIGH, `Authentication success`=MEDIUM.

Verifikasi: `npm run check` (lint 0 error / 16 warning warisan clone, typecheck, build) ✅.

## 2. n8n "Deteksi Malware": node `Log ke Fleet` ✅

Workflow **live** (id `1MVcpL7ZKfBhR2tc`, 12 node) ternyata sudah **menyimpang** dari file repo `n8n-workflows/deteksi-malware.json` (23 node, id beda) — live sudah pakai Ollama, repo masih Gemini/RAG/SLA. **Jangan import file repo**, nanti menimpa yang jalan.

- Ditambah lewat **n8n public API** (`PUT /api/v1/workflows/...`), bukan UI.
- Node `Log ke Fleet` (HTTP Request v4.4) → `POST http://host.docker.internal:8080/webhook-log`, `onError: continueRegularOutput` (dashboard mati tidak mematikan deteksi).
- Wiring: `Rangkum Hasil` → `[Cek Ancaman, Log ke Fleet]` — **cabang paralel**, alur AR/Telegram tidak disentuh.
- Script idempoten: `scripts/patch-n8n-log-fleet.py`. Backup: `backups/deteksi-malware-live-*.json`.
- Dites: `POST /webhook-log` → muncul di `/api/events` ✅.

## 3. Nixbox agent via NixOS — **tinggal jalankan**

NixOS tidak punya dpkg, dan binary di `agent-rs/target/release/` ter-link ke glibc `/nix/store` (bukan musl) → bisa rusak kena GC. Jadi dibuat derivasi Nix yang build dari source.

- **Baru**: `deploy/nixos/soar-agent.nix` — modul NixOS (`buildRustPackage` + systemd unit, deklaratif, tanpa `/etc/default`).
- **Baru**: `deploy/nixos/install-soar-agent.sh` — idempoten: backup `configuration.nix`, tulis `/etc/nixos/soar-agent.nix`, sisip 1 baris import, `nixos-rebuild switch`.
- Sudah diverifikasi: modul lolos eval NixOS asli (ExecStart benar) **dan paketnya sudah berhasil di-build** dari source.
- Setelan: `agentId=002`, `agentName=nixbox`, `server=192.168.1.47`.

> `server` sengaja LAN, bukan Tailscale: dari nixbox `100.73.91.17:8080` **tidak routable** (000) padahal `tailscale ping` ke ravi-debian pong; `192.168.1.47:8080` → 200.

Apply: `sudo bash deploy/nixos/install-soar-agent.sh`

# Handoff SOAR - 2026-09-14 autopilot (selagi Ravi tidur)

**Apa yang sudah dikerjakan otomatis:**
1. **Cloudflare Tunnel** — restart tunnel, paksa edge-ip-version=4 (IPv4), sekarang konek semua. Tapi DNS `soar.raviarnan.dev` CNAME ke tunnel yang hanya punya IPv6 (AAAA), jadi dari IPv4-only network tidak bisa akses.
   - **Solusi**: pindahkan nameserver raviarnan.dev dari **Name.com** ke **Cloudflare**. Login Name.com → Nameservers → ganti ke 2 nameserver yang diberikan Cloudflare (ada di dashboard Cloudflare). Setelah itu, Cloudflare jadi authoritative DNS dan bisa proxy CNAME dengan IPv4.
   - Sementara pakai Tailscale MagicDNS: `http://ravi-debian.tailab358b.ts.net:8080`
2. **Pipeline verified**: EICAR → agent → n8n → VT → Telegram **success**
3. **Duplikat workflow n8n dibersihkan** (2 duplikat dihapus)
4. **Fleet dashboard** masih butuh webhook-log dari n8n agar Threat Events terisi — edit workflow di UI n8n, tambah HTTP Request node ke `http://127.0.0.1:8080/webhook-log`

# Handoff SOAR - 2026-09-14 dini hari

- **Tanggal & Waktu**: 2026-09-13 14:00 ~ 2026-09-14 04:00 WITA (sesi: migrasi Rocky→Debian, SOAR stack, agent Windows, dashboard detail)
- **Commit**: bukan, push ke GitHub release v0.2.0 untuk binary agent
- **Live server**: ravi-debian (100.73.91.17, Debian 13 Trixie, ThinkPad X260)
- **SOAR stack**: n8n + fleet-monitor + health-monitor + tg-callback-poller + Wazuh v4.9.2 (semua Up)
- **Dashboard**: fleet-monitor di `http://ravi-debian.tailab358b.ts.net:8080`

## Ringkasan sesi

1. **Migrasi Rocky Linux → Debian 13 Trixie**: ravi-debian setup ulang (Docker, Wazuh v4.9.2, compose stack, integrasi custom-n8n.py + AR scripts)
2. **n8n credentials + workflows**: 5 creds (VirusTotal, urlscan, GSB, Wazuh, Telegram) + 4 workflow aktif. Fix PATCH update, Wait node `afterTimeElapsed`
3. **soar-agent cross-platform**: build Linux musl (5.4 MB) + Windows (12 MB). Agent terinstal di: ravi-debian (003), toshiba-bapak (005), ideapc (006). Nixbox (002) belum karena config NixOS.
4. **Dashboard fleet**: modal detail agent (klik baris), kolom OS, filter status dropdown, export CSV
5. **Pipeline verified**: EICAR → soar-agent → n8n → VirusTotal → Telegram (success, excluding AI layer)
6. **Cloudflare Tunnel**: tunnel `soar-fleet` terbuat, DNS `soar.raviarnan.dev` → CNAME `806a7239-e77c-4c0f-b260-be6ccf3b5514.cfargotunnel.com`. SSL Flexible. DNS propagate global tapi akses dari ravi-debian/nixbox terhambat resolver lokal.

## Status fleet (4 agent)

| ID | Nama | OS | Status | Catatan |
|----|------|------|--------|---------|
| 000 | wazuh.manager | Linux | active | Wazuh v4.9.2 |
| 003 | ravi-debian | Linux | active | Debian 13, Rust agent |
| 005 | toshiba-bapak | Windows | active | Windows Rust agent |
| 006 | ideapc | Windows | disconnected | heartbeat TTL? |

## File berubah / baru

| File | Isi |
|------|-----|
| `docs/VS-ANTIVIRUS.md` | Jawaban dospem: beda SOAR vs antivirus (elevator pitch + tabel + paragraf siap laporan) |
| `deploy/setup-server.sh` | Bootstrap server 1-perintah idempoten: cek prereq → .env interaktif (tanya Telegram/GSB/URLScan/Gemini/Wazuh pass; generate encryption key + hash Caddy) → clone Wazuh v4.9.2 + certs → compose up 2 stack → integrasi Ansible (auto-detect docker gateway) → sinkron n8n (Step 7) → checklist manual. Flag: `--yes`, `--skip-wazuh`; `N8N_OWNER_API_KEY`/`VT_API_KEY` via env |
| `deploy/n8n-setup.py` | Sinkron n8n via public API v1: buat/reuse 5 credentials dari .env (Telegram, Wazuh basic, GSB query, urlscan header, VT `x-apikey`) + **VT key via prompt/env, TIDAK ke .env** + import 4 workflow dengan **remap credential-ID by name** (15 ref — kelemahan import-UI: node merah di mesin baru → solved) + aktivasi. Idempoten (update bukan duplikat). `--dry-run` jalan tanpa API key |
| `deploy/agent-install.sh` | Pasang soar-agent di 1 workstation: cari binary (/tmp atau repo) → install → systemd unit dengan `AGENT_ID/AGENT_NAME/SERVER/WATCH` → verifikasi fleet reachable |
| `agent-rs/build-deb.sh` | Build musl statis + bungkus `.deb` (bin, unit, `/etc/default/soar-agent`, quarantine dir, postinst/prerm). Install: `sudo apt install ./soar-agent_0.1.0_amd64.deb` |
| `agent-rs/dist/soar-agent.service` + `soar-agent.default` | Unit untuk .deb: `EnvironmentFile=/etc/default/soar-agent` — binary sama 100 PC, config per-host 4 baris. CATATAN: `$WATCH_ARGS` tanpa kurung kurawal (systemd split whitespace, kosong = nol argumen) |
| `deploy/ansible/deploy-agents.yml` + `inventory-agents.ini.example` + `soar-agent.service.j2` | Rollout fleet: copy binary + render unit per-host (agent_id dari inventory) + tunggu heartbeat muncul di fleet-monitor |
| `scripts/fleet-tui.py` | **TUI dashboard** kembaran fleet-monitor GUI — sumber data SAMA (`/api/fleet` + `/api/events`), stdlib curses. 4 view (overview/agents/events/health) + cari `/` + saring severity `e` + simulasi 100 PC `s` + `q`. Adaptive terminal sempit (80 kolom SSH), path left-truncate (basename tetap terlihat), error banner saat server mati (bukan layar kosong) |
| `docs/diagrams/fig-karyawan-flow.mmd` + `.png` | Sequence harian perspektif karyawan: Sinta tidak menjalankan apa pun → hash JSON → verdict → Telegram admin → isolasi; else silent. Render mmdc + chrome lokal |
| `docs/diagrams/fig-karyawan-setup-vs-harian.mmd` + `.png` | Flowchart 3 kotak: SEKALI SAJA (admin) / HARIAN (otomatis) / PANTAUAN (GUI+TUI) |

## File diubah

- `deploy/README.md` — quickstart setup 1-perintah + tabel 3 jalur workstation + bagian n8n-setup + GUI/TUI
- `agent-rs/README.md` — bagian install via .deb di atas bagian Build
- `ROADMAP.md` — 2 baris ✅ Sebagian baru (setup lintas-device, TUI) di tabel status + entri sesi di ✅ dikerjakan + baris prioritas #9
- `docs/ROADMAP-AGEN-RINGAN.md` — checklist 11 Sep (malam) ✅

## Keputusan desain sesi ini

- **VT key tidak pernah ke .env** — via `VT_API_KEY` env / `--vt-key` / prompt interaktif, langsung jadi credential n8n. Alasan: .env disalin ke banyak compose, sedangkan VT key hanya dipakai node HTTP via credential store.
- **Remap credential by name+type**, bukan by ID — file workflow repo membawa ID dari mesin lama (`4XbvXfmuxwJcgXcc` dst). Import-UI tidak meremap → node merah. n8n-setup match `credentials.<type>.name` dengan nama credential yang dibuat, tulis ulang ID-nya.
- **TUI read-only kecuali simulasi** — keputusan respons tetap Telegram HITL; TUI cuma pemantauan (sejalan dengan prinsip trusted autonomy).
- **`.deb` pakai EnvironmentFile** — binary identik 100 PC, per-host hanya `/etc/default/soar-agent`. Upgrade = pasang .deb versi lebih tinggi.
- **setup-server.sh idempoten penuh** — semua langkah skip kalau sudah ada (clone, certs, .env nilai terisi). Re-run aman.

## Test yang sudah dilakukan (semuanya hijau)

- `py_compile` + `ruff check` fleet-tui.py & n8n-setup.py; `bash -n` 3 script shell
- TUI smoke-test **pty asli** (python `pty.fork`, bukan `script` yang ribet partial-update) lawan fleet-monitor hidup: 4 view render, agent row + event CRITICAL + hash tampil, siklus `e` CRITICAL→HIGH→MEDIUM (SESUAI urutan SEV_ORDER), simulasi `s` → 98 agent, `q` exit, server mati → error banner
- remap_credentials unit-test: match by name+type, type-mismatch tidak tersentuh, unknown dibiarkan, idempoten (pass kedua = 0)
- n8n-setup dry-run: 5 credentials (VT skip tanpa key, ikut dengan `VT_API_KEY`) + 4 workflow (remap 4/4/4/3 ref)
- Cleanup: fleet-monitor test instance mati, /tmp bersih

## Next Action

- [ ] Nixbox: install soar-agent via NixOS config permanen (ada di `/etc/nixos/configuration.nix`, perlu rebuild)
- [ ] Debug pipeline: Gemini 429 rate limit → disable; Ollama node (ECONNREFUSED) → disable keduanya, workflow sukses
- [ ] Dashboard akses: Cloudflare Tunnel SSL cert belum aktif — cek lagi nanti. Alternatif: akses via MagicDNS di tailnet sudah jalan (`http://ravi-debian.tailab358b.ts.net:8080`)
- [ ] fleet-monitor: tambah webhook-log POST dari n8n ke fleet biar Threat Events muncul
- [ ] Update binary agent di GitHub release v0.2.0 dengan build terbaru (sudah include os field)
- [ ] Screenshot dashboard + Telegram untuk laporan
- [ ] `docs/PERBANDINGAN-PENELITIAN.md` kolom Agen Ringan

## Catatan penting

- **SSH via Tailscale tidak jalan** — ravi-debian SSH hanya via LAN `192.168.1.47` karena Tailscale SSH disabled
- **RAVI-DEBIAN BATERAI** — ThinkPad X260 baterai ~65% health. Kalau mati listrik/mati, SOAR stack ikut mati. Pertimbangkan host stack di nixbox atau VPS.
- **Binary agent Windows ada di GitHub Release** `v0.2.0` — install via PowerShell 1 baris
- **Noise filter**: `.iso`, `.ds_store`, `.dmg` sudah ditambahkan di custom-n8n.py dan soar-agent main.rs

## Update 14 Sep 21:20 — FP noise STOP (verified live)

- `should_ignore()` + test `ignore_fp_noise_14sep` (cargo test ok).
- Deploy: 002 nixos-rebuild, 003 gnu md5-match + restart, exe baru di `~/public/`
  (byte pas). Fleet 21:17 semua heartbeat segar, noise nixbox berhenti total.
- SISA MANUAL: (a) 005/006 ps1 reinstall; (b) patch `Filter Alert Malware` —
  SELESAI 22:30an: `scripts/patch-n8n-fp-guard.py` (notRegex native +
  escape Telegram). Debugging berlapis, pelajaran penting:
  1. ekspresi n8n di JSON workflow WAJIB prefix `=` (`={{...}}`, bukan
     `{{...}}`) — tanpanya dianggap literal (exec 721 lolos, 719/720 error);
  2. IF node TIDAK support regex literal/`.test`/`.includes` di kiri
     (hanya konstruk dasar); op string native: contains/notContains/
     startsWith/endsWith/regex/notRegex (baca dari filter-parameter.js);
  3. `notRegex` nilai kanan = literal regex "/pola/flags" (parseRegexLiteral).
  Verifikasi: T1 noise → drop di Filter (exec 727, 2 node, sunyi); T2 bersih +
  filename `[_]()` → full run + Telegram terkirim (msg 1229, tanpa parse error).
  Workflow probe sementara sudah dihapus.

## Sesi berakhir 14 Sep ~23:45 — lanjut besok

Yang sudah hijau malam ini: dashboard 500 sembuh, IP/OS 002+003 akurat,
FP noise berhenti (agent + Filter lapis-2 + Telegram escape, T1/T2 hijau).
MD yang diupdate: `agent-rs/README.md` (Noise filter + catatan toolchain),
`docs/DEPLOYMENT.md` (troubleshooting Telegram + FP + gotcha n8n).

Resume besok (satu-satunya sisa): ps1 reinstall di 005/006
(exe baru sudah di `http://100.73.91.17:8000/soar-agent.exe`, byte 7928320).
Lalu: screenshot dashboard + Telegram untuk laporan (TODO lama).

# Handoff SOAR - 2026-09-16/17 (nixbox, Atria + auto-karantina)

## 1. AI Generate pindah Experiential -> Atria (kredit habis)

- Key Atria (`atr_...`, 36 char) di `~/.config/opencode/secrets/atria.key`.
  API OpenAI-compatible `https://api.atria-asi.ai/v1`, model `Atria-Dawn-Preview`
  (text-only, reasoning; `/v1/models` terverifikasi hidup).
- Repo: `scripts/patch-n8n-ai-generate.py` (jsCode Atria + Bearer),
  `docker-compose.yml` (`ATRIA_API_KEY`), `.env.example`.
- Server: `.env` + compose diupdate via ssh, `docker compose up -d n8n`
  (env kebaca: `docker exec n8n env` ada ATRIA_API_KEY).
- n8n API key lama 401 -> pulihkan dari sqlite manager
  (`docker cp n8n:.../database.sqlite`, tabel `user_api_keys` label
  soar-project). Patch live OK, read-back: active, ada atria, tanpa experiential.
- Gotcha: max_tokens 300 habis di reasoning -> `content: null`
  (test EICAR-1 ai_response = dump JSON). Fix: max_tokens 1500 +
  temperature 0.3 + fallback statis. Test EICAR-2: AI Indonesia benar
  ("66 dari 68 AV...", CRITICAL).

## 2. Auto-karantina ternyata tidak pernah jalan -> diperbaiki

- Akar: alert dari agen Rust (003) diformat mirip Wazuh; Trigger AR panggil
  Wazuh API untuk 003, manager cuma kenal 000 -> 1701 Agent does not exist.
- Fix: node baru **Fleet Quarantine**
  (Trigger AR -> Fleet Quarantine -> Build Payload, onError continue).
  Kalau AR != isolated, POST `http://host.docker.internal:8080/api/commands`
  `{agent_id, quarantine, target}`; agen eksekusi lokal via do_quarantine
  (pindah + chmod 000, latensi <= heartbeat 60 dtk).
  Script: `scripts/patch-n8n-fleet-quarantine.py` (idempoten + backup).
- Test EICAR-3 (exec 949): `fleet_quarantine: queued` -> file hilang dari
  Downloads -> `/var/ossec/quarantine` (dibuat agent, root-owned).
  Template Telegram live netral ("MALWARE TERDETEKSI", tanpa klaim isolasi).

## File berubah (belum commit)

M: `.env.example`, `docker-compose.yml`,
`scripts/patch-n8n-ai-generate.py`, `scripts/patch-n8n-fleet-quarantine.py` (baru),
`HANDOFF.md`. WIP lama tak tersentuh: process-chain rules/decoder,
`agent-rs/src/main.rs`, `custom-n8n.py`, MITRE doc.

## Sisa / next

- Screenshot dashboard + Telegram untuk laporan (TODO lama).
- WIP process-chain (LOLBin/Sysmon) belum selesai: 1 error XML di
  `scripts/process-chain-rules.xml:69` belum dibetulkan.
- Token sementara sudah di-shred kedua sisi; backup patch di `backups/`.

# Handoff SOAR - 2026-09-18 (nixbox, fix FP Security Events)

## 1. Akar FP (data 005: puluhan MEDIUM — png, xlsx, zip, e3b0c44...)

- Agent hash tiap chunk download (settle 300ms + debounce 2 dtk) → 1 file
  jadi 4-5 event, hash parsial beda-beda (`.zip.part` 4x, xlsx 5 hash beda
  dalam 1 detik).
- File kosong ikut di-hash → `e3b0c442...` (hash file kosong) muncul 6x.
- File parsial browser (`*.zip.part`) ikut dipindai.

## 2. Fix di `agent-rs/src/main.rs` (cargo test 5 passed)

- `wait_settled()`: hash hanya kalau size stabil 2x poll 500ms (maks ~8 dtk).
- File 0-byte di-skip (event modify saat isi datang retrigger).
- `NOISY_EXT` + `.part/.crdownload/.download/.opdownload/.filepart/.partial`
  (rename ke nama final = event Create baru, tetap lolos).
- Debounce per path 2 dtk → 60 dtk (`DEBOUNCE_SECS`).
- Test baru: `ignore_partial_download_18sep`, `wait_settled_stabil_dan_hilang`.

## 3. Build/deploy (TERHALANG jaringan, butuh Ravi)

- ✅ `soar-agent.exe` baru dibuild di nixbox: 7.990.272 bytes, PE32+ x86-64,
  ada di `deploy/bundle/soar-agent.exe` (belum commit, biar Ravi cek dulu).
- 🔴 Server tak terjangkau (nixbox di WiFi 192.168.131.x, 192.168.1.47
  timeout; Tailscale nixbox logged out). Belum: antar exe ke `~/public`,
  rebuild gnu + restart 003, nixos-rebuild 002 (butuh sudo).
- Langkah Ravi tertulis di board #19. Koordinasi lanjut via
  ai-board-azure.vercel.app (#18 + #19).
- Sampai binary baru terpasang, FP masih muncul (binary lama masih jalan).

# Handoff SOAR - 2026-09-20 (tutup sesi nixbox 19-20 Sep, fleet clear tanpa dobel)

## Status akhir sesi

- Fleet tanpa dobel: Wazuh 000/001/002/003 + Rust 005-010; merge per host
  (001 ideapc, 002 bali, 003 toshiba) setelah samakan ID Rust ke ID Wazuh.
  008 macbook (Rust, macOS), 009 nixbox, 010 ravi-debian.
- Pipeline FIM + chain LOLBin end-to-end HIJAU sampai Telegram di ketiga
  Windows (005/006/007). E2E check `scripts/e2e-soar-check.py` hijau.
- Gotcha n8n 2.40: output FALSE IF via API tidak eksekusi downstream
  (pakai TRUE/fan-out saja). Gotcha manager: edit ossec.conf langsung
  hilang tiap restart (edit file mount); <name> integration harus unik;
  select API `os` tidak valid (pakai os.name/version/platform).
- SSH: 006 user microsoft, 008 user macbook (peta di dashboard).
- Board terakhir #83. Sisa: commit laporan + screenshot (Ravi).

# Handoff SOAR - 2026-09-19 (nixbox, E2E 007 HIJAU)

## End-to-end 007 HIJAU (alert asli -> Telegram)

- 007 (002 bali-handmade) chain 16:15 fire 110011 (2x) + 110012 di manager.
- 2 bug pengiriman diperbaiki: integrator live ketinggalan (exit 0 tanpa
  POST) -> deploy custom-n8n.py baru (teruskan seluruh data + proc_*) ke
  /var/ossec/integrations/; Cabang n8n <=110011 -> <=110018.
- Replay 110012 asli -> chain full run tanpa error -> Telegram terkirim.
- Board: #50 TODO 005+007, #51 DONE 007, #52-54 MacBook, #55 verifikasi.
- Menunggu: 006 re-chain, 005 install, push/commit (kata Ravi), pubkey
  MacBook (kata Ravi).

# Handoff SOAR - 2026-09-19 (nixbox, E2E check + SSH 006)

## E2E check otomatis (TODO #41 DONE) + SSH 006

- `scripts/e2e-soar-check.py`: POST FIM + chain sintetis, verifikasi node
  lengkap tanpa error. Hijau: FIM 17 node, chain 8 node. Gotcha skrip:
  filter startedAt>t0 (exec lama menipu), stamp unik per run (dedup 5 mnt).
  Tiap run = 2 pesan Telegram asli, manual saja.
- SSH 006: `ssh microsoft@100.124.118.45` terverifikasi tanpa password.
  Dashboard SSH_USER_BY_AGENT 006=microsoft (live).
- Board: #44 INFO sesi, #46 verifikasi SSH, #49 minta re-chain 006,
  #50 TODO 005+007 Wazuh/Sysmon.

# Handoff SOAR - 2026-09-19 (nixbox, chain JSON + config permanen)

## Rule kembar JSON 110011-110018 + config mount permanen

- Event 006 sampai manager tapi hanya fire rules bawaan: agent Windows
  modern kirim JSON -> field `win.eventdata.*`, rules 110001-110008 hanya
  baca `sysmon.*`. Tambah 8 kembar JSON 110011-110018 (pola sama).
- GOTCHA: edit /var/ossec/etc/ossec.conf langsung HILANG tiap restart
  (entrypoint salin dari wazuh-docker/.../wazuh_cluster/wazuh_manager.conf).
  Sumber permanen = file mount itu (hook 172.18.0.1 + blok chain; 2 blok
  lama ikut dibetulkan). `config/wazuh/wazuh_manager.conf` disamakan identik.
- Status: -t lolos, restart OK. Menunggu 006 jalankan chain lagi untuk
  verifikasi 110012 + Telegram (pesan board #49).

# Handoff SOAR - 2026-09-19 (nixbox, cabang chain n8n DONE)

## Cabang process-chain di workflow Deteksi Malware (nomor 1 DONE)

- Alert Sysmon 110001-110011 tak punya hash: mati di Filter + tak cocok
  Scan VT / karantina file. Cabang baru via `scripts/patch-n8n-chain.py`:
  Webhook fan-out ke Filter (FIM utuh) + Cabang Chain? (true saja).
  Ekstrak Chain (dedup inline /api/seen) -> Rangkum Chain (severity dari
  rule_level, AR=false SELALU: LOLBin = binary sah) -> Build Payload +
  Log Fleet (dipakai bersama, prompt LOLBin chain-aware). Telegram $json
  semua + judul dinamis + baris Command kondisional.
- GOTCHA n8n 2.40: output FALSE IF yang dibuat via API tidak mengeksekusi
  downstream (reproduksi terisolasi, bukan typeVersion/typeValidation/IIFE).
  Solusi: desain hanya pakai output TRUE + fan-out. Jangan pakai false-branch
  untuk node baru sampai diverifikasi di versi lain.
- Uji: chain sintetis full run (RANTAI PROSES MENCURIGAKAN, HIGH, tanpa
  error); FIM regresi full run 17 node tanpa error; template Telegram baru
  terkirim 1 pesan uji (cek Telegram Ravi). Script: patch-n8n-chain.py.

# Handoff SOAR - 2026-09-19 (nixbox, process-chain LIVE di manager)

## Process-chain LOLBin live di manager (110001-110011)

- `scripts/process-chain-rules.xml` → `/var/ossec/etc/rules/` manager + restart.
  Backup live conf: `/var/ossec/etc/ossec.conf.bak-20260919` (di container).
- Akar masalah "rule tak pernah fire": `type="osmatch"` tidak mendukung pola
  regex `(?i) \\ (¦)?$`. Diganti semua (12x) ke `type="pcre2"` mengikuti
  ruleset bawaan (contoh 0810-sysmon_id_3.xml). Uji logtest: log LOLBin
  sintetis (cmd -> powershell Hidden) fire **110002 level 10**. Catatan:
  field match Wazuh case-insensitive, jadi "Hidden" kapital tetap fire.
- "Error XML baris 69" resmi basi: file valid + `-t` lolos sejak awal.
- Integration manager->n8n: manager beda docker network dgn n8n
  (single-node_default vs soar-project_default). 172.20.0.1 tak terjangkau,
  gateway single-node **172.18.0.1:5678 OK**. Blok integration ketiga
  terpasang live + `config/wazuh/wazuh_manager.conf` repo dibetulkan.
- SISA end-to-end (butuh tangan di Windows, tak bisa dari nixbox):
  1. Install Wazuh agent di salah satu Windows (005/006/007 saat ini
     soar-agent Rust, bukan Wazuh agent) + enroll ke manager.
  2. Install Sysmon + apply `deploy/sysmon-minimal.xml`.
  3. Tambahkan isi `config/wazuh/agent-windows-process-chain.conf`
     ke ossec.conf agent + restart wazuh-svc.
  4. Uji: jalankan chain cmd->powershell hidden, alert 110002 masuk
     n8n -> Telegram + dashboard.

# Handoff SOAR - 2026-09-19 (nixbox, dedup lapis-2 n8n DONE)

## Lapis-2 dedup n8n SELESAI (janji #18 lunas)

- Rencana awal (staticData workflow, window 5 mnt) GAGAL: uji 3x POST
  identik lolos semua (exec 1017/1018/1019 full run), `staticData: null`
  setelah eksekusi sukses = tidak persist di versi n8n ini. Bukan race
  (POST ketiga setelah jeda tetap lolos).
- Pivot ke claim-check atomik di server: `POST /api/seen`
  (`scripts/fleet-monitor.py`, store in-memory `SEEN`, check-and-set
  atomik karena HTTPServer single-threaded; validasi key<=512,
  window clamp 10-3600 dtk, default 300).
- Deploy: scp + `docker restart fleet-monitor` (volume mount, tanpa rebuild).
  Uji endpoint: hit-1 `{"duplicate": false}`, hit-2 `{"duplicate": true}`.
- Node `Dedup Alert` (Ekstrak Alert -> Dedup -> Scan VT) panggil /api/seen
  via httpRequest helper, fail-open (fleet down/error = item diteruskan,
  deteksi tidak mati). Script: `scripts/patch-n8n-dedup.py` (idempoten).
- Uji double-POST (jeda 2 dtk): exec 1020 full run sampai Telegram,
  exec 1021 berhenti di Dedup (tanpa Scan VT / Telegram ganda). HIJAU.

## Sisa

- Screenshot dashboard + Telegram untuk laporan (TODO lama).
- WIP process-chain (LOLBin/Sysmon): 1 error XML di
  `scripts/process-chain-rules.xml:69` belum dibetulkan.
- `.opencode/` tetap tak ikut commit.

# Handoff SOAR - 2026-09-18/19 malam (nixbox, tutup #18 + 007 + metrics)

## 1. Deploy fix FP selesai di semua device (board #18-#25)

- Nixbox balik ke LAN 192.168.1.26, server reachable lagi (hambatan #19 hilang).
- 003: `main.rs` baru di-scp, `cargo build --release` + `cargo test` 5 passed
  DI server, install + restart via sudo (password sekali via stdin, tak disimpan).
  Backup: `/tmp/main.rs.bak-18sep`, `/tmp/soar-agent.bak-18sep`.
- Exe 7990272 (sha 47701718) live di `~/public` + `:8000` (200).
- 005/006 reinstall OK (v0.2.0). 002 sudah OK sebelumnya.
- Post #22 + tutup #25. `events_total` stagnan 28 = FP berhenti.
- Gotcha: `pgrep -f cargo build` match string ssh-nya sendiri (false BUILDING);
  cek log/target binary langsung. `strings|grep` tak temukan literal
  NOISY_EXT di binary Linux (artefak codegen), tapi `.partial` ada di binary
  baru + `cargo test ignore_partial_download_18sep` lolos = fix live.
  Jangan verifikasi binary via grep literal.

## 2. Onboarding 007 bali-handmade (board #26-#31)

- Panduan dipost #26 (ID 007, Windows ps1 + timpa exe :8000 / Linux 1-baris).
- 007 DONE #27 (ASUS Win10 Home, tanpa Tailscale, SERVER=LAN).
  Catatan: exe GitHub release v0.2.0 = 7954432 bytes PRE-FIX, jangan dipakai;
  selalu timpa dari `:8000`.
- Tailscale 007 dipost #29, DONE #30 (100.126.10.58 via winget). Tutup #31.
- Fleet 6/6 active. EICAR tak dijalankan di 007 (diblokir Defender = wajar).

## 3. Tailscale nixbox (bukan logout biasa)

- `tailscaled`: tiap boot sejak >=14 Sep `nodeKeyExpired=false,
  machineAuthorized=false` -> NeedsLogin. Key valid, mesin tak terotorisasi
  di tailnet (kemungkinan terhapus/belum approve di admin).
- Ravi login ulang OK, nixbox = 100.75.103.60. Dicatat board #32.

## 4. Fix metrics Windows (Resource usage kosong)

- Akar: `cpu_pct`/`ram_gb` di `main.rs` dikunci `#[cfg(target_os = "linux")]`
  -> exe kirim 0 -> server tak simpan titik. 002/003 selalu normal (60 titik).
- Fix: gate cfg dicabut (sysinfo 0.30 cross-platform), `cargo test` 5 passed,
  exe baru 9888768 bytes (sha a956e46b, sysinfo Windows ikut ke-link)
  live di `:8000`. Post #33, DONE 005/006/007 (#35/#37/#39, sha match),
  metrics mengalir. 002/003 tak perlu update.
- SSH Windows (#34): 007 klaim DONE tapi port 22 timeout dari nixbox;
  005/006 handshake OK tapi pubkey ditolak walau key cocok (curiga username
  bukan akun lokal / ACL authorized_keys). Detail cek per device di #40.
- Batasan sensor (diskusi): ping/ICMP tak memicu apa pun (sensor file-based).
  Sengaja bukan alert (noise); kalau mau visibilitas, log INFO + alert hanya
  pola lanjutan (scan/bruteforce) = butuh NIDS, di luar scope. Tulis eksplisit
  di dokumen keterbatasan.

## Sisa

- Commit ini: `main.rs` (metrics) + exe 9888768. `.opencode/` tetap tak ikut.

# Handoff SOAR - 2026-09-20 (nixbox, fitur Scan on-demand)

## Scan on-demand (tutup blind spot file lama)

Latar: agent reaktif (FIM create/modify) — file jahat yang **sudah ada di disk
sebelum agent dipasang** tak pernah memicu event, jadi tak terlihat selamanya.
Scan on-demand menutup celah itu, dengan batasan sengaja: folder pilihan (**bukan
full disk** -> VT 4 req/menit jebol), **cache-first**, dan hasil = **satu laporan
ringkasan** (**bukan alert per-file** -> Telegram & dedup n8n tak kebanjiran).

Fondasi yang dipakai: command queue `/api/commands` (sudah quarantine/sinkhole) —
tinggal tambah aksi `scan` + path; agent walk + hash + lapor ke endpoint baru.

- **Agent** (`agent-rs/src/main.rs`): aksi `scan` di command loop; scan dijalankan
  di **task terpisah** supaya heartbeat tetap tepat waktu (TTL 120 dtk). Helper
  `collect_scan_targets()` walk rekursif TANPA follow symlink, skip `should_ignore`
  + file 0-byte, batas `MAX_SCAN_FILES=2000` (flag `truncated`). `do_scan()` hash
  semua file lalu POST satu laporan ke `/api/scan-result`. Test baru
  `collect_scan_targets_skip_noise_dan_batas`.
- **Fleet** (`scripts/fleet-monitor.py`): `POST /api/scan-result` (hitung
  **new vs known** via `KNOWN_HASHES`, LRU cap 200k) + `GET /api/scan-results`
  (`?agent_id=` -> termasuk daftar file) + `/api/commands` terima `action=scan`
  (validasi target = path absolut tanpa `..`). Helper `Handler._json()`.
- **Dashboard** (`AgentDetailView.tsx` + `lib/fleet.ts`): kartu "On-demand scan" —
  tombol "Scan folder…" (prompt path -> antre command) + ringkasan (file, hash
  baru, dikenal, total byte) + tabel 20 file teratas, hash baru = link VirusTotal.
  Aktif hanya untuk agent Rust.

## Bukti uji (semua hijau)

- `cargo test --release`: **6 passed** (termasuk test walker baru).
- `cargo build --release`: binary gnu `target/release/soar-agent` = 7.953.928 byte.
- `py_compile` + `ruff`: bersih (delta hanya +1 BLE001, mengikuti pola existing).
- Dashboard: `eslint` file baru bersih, `tsc --noEmit` bersih, `next build` sukses.
  (3 error lint **existing** di `SecurityEventsDashboard.tsx` — sudah ada di HEAD,
  bukan dari fitur ini.)
- **E2E nyata** (agent baru + fleet-monitor di port uji 18080): scan
  `~/soar-scan-test` (5 file: 2 normal, 1 `.log` noise, 1 kosong, 1 di subfolder)
  -> `scanned=3` (noise + 0-byte di-skip, subfolder ikut), `new=3`. Scan **ulang**
  -> `new=0, known=3` (cache-first terbukti). Agent 099 heartbeat `active`.
  Test server/agent dimatikan, folder uji + port dibersihkan.

## Deploy Scan on-demand (2026-09-20) — ravi-debian + nixbox LIVE

Dikerjakan nixbox via SSH (`192.168.1.47`) + docker group; install agent pakai sudo
(password via stdin, tidak disimpan).

- ✅ 4 file sinkron ke `~/Projects/soar-project` ravi-debian (main.rs, fleet-monitor.py,
  fleet.ts, AgentDetailView.tsx) + `docker-compose.yml` + `.gitignore`.
- ✅ Image `soar-fleet-dashboard` di-rebuild + container di-recreate → `:3000` sehat,
  kartu "On-demand scan" tampil di detail agent.
- ✅ Binary agent ravi-debian dibuild + **di-install** (`/usr/local/bin`, sudo) +
  `systemctl restart soar-agent` (md5 cocok, service active).
- ✅ **009 nixbox**: `sudo nixos-rebuild switch --flake /etc/nixos#nixbox --impure`
  (build dari source lokal → ikut fitur scan), service active.
- ✅ **Uji scan SUNGGUHAN live**: 010 ravi-debian `~/Downloads` → `scanned=14 new=3`;
  009 nixbox `~/Downloads` → `scanned=2000 new=1880` **truncated=true** (cap 2000 file
  kena, 13,8 GB). Log agent: "scan on-demand terkirim ... perintah dashboard OK
  action=scan". Fitur terbukti end-to-end dari tombol dashboard.

### Fix regresi "list agent berkurang" (bukan fitur scan)

- Akar: `HEARTBEATS` fleet-monitor **in-memory** → tiap restart container, agent yang
  sedang **offline** (008 macbook 100.114.170.66, 002 bali 100.126.10.58 — dua-duanya
  unreachable/ping mati) **hilang dari daftar**, bukan sekadar "disconnected".
  Bukan bug fitur scan; restart deploy yang mengekspos kerapuhan lama.
- Fix: roster heartbeat **di-persist** ke `state/fleet-state.json` (volume compose
  `./state:/state:rw`, `FLEET_STATE_FILE=/state/fleet-state.json`; `/scripts` memang
  read-only). Load saat start, save tiap heartbeat; entri >30 hari dibuang.
  Uji: agent tetap ada setelah restart (status `disconnected`).
- Backfill 1x: roster diisi ulang `008 macbook` (identitas dari board) agar tampil
  `disconnected` seperti sebelumnya — sembuh sendiri begitu macbook online.
- Fleet kembali **7**: 000 manager, 001 ideapc, 002 bali (disconnected), 003 toshiba,
  008 macbook (disconnected), 009 nixbox, 010 ravi-debian.

## Sisa (device lain)

- **002** (Linux) + **005/006/007** (Windows): binary baru via
  `./deploy/rebuild-agent-binaries.sh --windows --deb` lalu sebar (`:8000` / ps1).
  (008 macbook menyusul saat perangkatnya online.)

## File berubah

M: `agent-rs/src/main.rs`, `scripts/fleet-monitor.py`, `docker-compose.yml`,
`.gitignore`, `dashboard/src/lib/fleet.ts`,
`dashboard/src/components/wazuh/AgentDetailView.tsx`, `ROADMAP.md`, `HANDOFF.md`.
`.opencode/` tetap tak ikut commit.

# Handoff SOAR - 2026-09-20 (nixbox, sisa B: cache VT + ensemble MalwareBazaar LIVE)

## 0. Temuan pembuka: live TIDAK punya cache VT

`apply-b-malwarebazaar.py` + `apply-b-ttl-rescan.py` (script lama) hanya mengedit
`n8n-workflows/deteksi-malware.json` — dan file itu sudah menyimpang dari workflow
live (live 21 node; tidak ada `Cek Cache VT` / `Cache Hit?` / `vtCache`). Jadi:

- Script lama **tidak bisa dipakai** (import file repo = menimpa workflow live).
  Keduanya sudah ditandai **SUPERSEDED** di docstring-nya.
- TTL diferensial **tak punya target**: cache di dalam n8n dibuang karena
  `staticData` tidak persist di 2.40 (pelajaran dedup 19 Sep).
- Dedup `/api/seen` ber-key `agent_id|rule_id|hash|filepath` → 100 PC kena malware
  **sama** = 100 key = **100 panggilan VT** (kuota 4/menit jebol). Cache ber-key
  **hash** yang menutup celah ini.

Keputusan (pilihan Ravi): cache dibangun **server-side di fleet-monitor**, bukan
dikembalikan ke n8n.

## 1. Cache verdict VT di `scripts/fleet-monitor.py`

- `POST /api/vt-cache/lookup` `{hash}` → `{hit, stats, known, malicious, age_secs,
  ttl_secs}` (miss → `{hit:false}`). `POST /api/vt-cache/store` `{hash, stats}`
  atau `{hash, not_found:true}`. `GET /api/vt-cache[?hash=]` = ringkasan
  (size, stats, hit_rate) untuk bukti laporan.
- **TTL diferensial**: malicious 7 hari · bersih 24 jam · tidak dikenal 6 jam
  (`_vt_ttl_secs`). Key = hash, LRU cap 20k, validasi hash hex 32/40/64.
- **Persist** ke `state/.fleet-vt-cache.json` (ikut volume `/state`, tulis
  di-throttle 30 dtk) → restart container/deploy tidak membuang verdict.
- Hanya verdict sah yang disimpan dari sisi n8n: data VT, atau 404
  `NotFoundError`. **429/5xx/timeout tidak disimpan** supaya error transien tidak
  membekukan verdict jadi "tidak dikenal" selama 6 jam.

## 2. Patch workflow live `scripts/patch-n8n-vt-cache-mb.py` (baru, idempoten)

Alur jadi: `Dedup → Cek Cache VT → Cache Hit?`
- **hit** → `MalwareBazaar Lookup` → `Rangkum Hasil` (VT dilewati)
- **miss** → `Scan VirusTotal` → `Simpan Cache VT` → `VT OK?` → true: MB ·
  false: `OTX Lookup` → MB → `Rangkum Hasil`

+ credential `MalwareBazaar Auth` (HTTP Header Auth `Auth-Key`) dibuat lewat API,
+ `Rangkum Hasil` sadar cache (`cache_hit`, `cached_stats`) dan MB
  (`mb_known/mb_signature/mb_tags/mb_threat`; `mb_threat` menaikkan severity,
  dual-source +malicious≥5 → CRITICAL).

### Bug yang ketangkap saat uji (penting)

Versi 1 menaruh MB **hanya di jalur cache miss**. Uji E2E membuktikan akibatnya:
hash yang ada di cache (verdict "bersih") **tidak pernah diadu dengan MB** →
`mb_known:false`, celah FN tetap terbuka selama TTL. Versi 2 memindahkan MB ke
**kedua jalur** (input `Rangkum Hasil` selalu respons MB; status cache dibaca dari
`$('Cek Cache VT')`). Script bisa **upgrade** dari v1 (fixture uji dari live
disimpan; marker `patch:cache-mb:v2`).

## 3. Bukti uji (semua hijau)

- **24 pass** uji endpoint cache (kelas TTL 7h/24j/6j, stats utuh, validasi hash,
  burst 100 lookup = 100 hit, restart masih ada, entri kadaluwarsa dibuang).
- **42 pass** uji patch script lawan mock n8n API, 2 skenario: workflow asli (21
  node) dan **upgrade dari v1** (25 node) → 25 node, tanpa duplikat, idempoten.
- **E2E live A: 23 pass** `e2e-vt-cache.py` (hash acak → dijamin miss): run 1
  VT 404 (`0/0`, MEDIUM) → cache disimpan kelas **unknown 6 jam**; run 2 **melewati
  `Scan VirusTotal` + `Simpan Cache VT`**, `source: vt-cache`, MB tetap
  dikonsultasi. Cache: lookups 2, hits 1, misses 1.
- **E2E live B: 11 pass** `e2e-mb-only.py`: cache di-seed verdict "VT bersih 0/70"
  (fixture), rule level 3 → **MB signature `Mirai` menaikkan severity ke HIGH +
  `silent:false` + Telegram terkirim**. Tanpa MB = MEDIUM/senyap → **celah
  false-negative terbukti tertutup**. Fixture dikembalikan ke verdict asli 33/64.
- Catatan: 3 pesan Telegram asli terkirim saat uji (2 di A, 1 di B).

## 4. Lain-lain

- `deploy/n8n-setup.py`: credential `MalwareBazaar Auth` ditambahkan (dry-run →
  6 credential; `build_data` httpHeaderAuth jadi data-driven pakai `extra.name`).
- `.env.example`: `MALWAREBAZAAR_API_KEY` didokumentasikan.
- `.gitignore`: `scripts/.fleet-vt-cache.json*`.
- 🔴 **Server ravi-debian REBOOT (10:46) di tengah uji** — pola lama (baterai X260 /
  listrik). Semua container pulih otomatis; **cache selamat** (`state/.fleet-vt-cache.json`
  ada isinya) = bukti persist jalan. `/tmp` server terhapus → API key dipulihkan
  ulang dari sqlite n8n.
- ⚠️ **Temuan keamanan (kategori D, belum diperbaiki):** key **OTX tertulis inline**
  di node `OTX Lookup` (bukan credential) — ikut ter-return `GET /api/v1/workflows/{id}`
  dan tersalin ke tiap file di `backups/`. Sama polanya dengan VT/urlscan/GSB yang
  sudah pakai credential → sebaiknya dipindah ke credential `OTX API Key`
  (httpHeaderAuth) seperti `MalwareBazaar Auth`. Perlu 1 patch kecil + rotasi key.

## 5. Sisa

- **Commit** (nanti saja — sudah ditandai Ravi): fitur scan on-demand + cache/MB ini.
- Deploy binary agent baru ke **002/005/006/007/008** (kebanyakan offline).
- Bukti laporan: screenshot dashboard + Telegram; kolom "Agen Ringan" di
  `docs/PERBANDINGAN-PENELITIAN.md`.
- Benchmark **VT cold-vs-cache** — sekarang bisa diukur (hit_rate sudah tersedia
  di `GET /api/vt-cache`).

## File berubah sesi ini

M: `scripts/fleet-monitor.py`, `deploy/n8n-setup.py`, `.env.example`, `.gitignore`,
`ROADMAP.md`, `HANDOFF.md`, `scripts/apply-b-malwarebazaar.py`,
`scripts/apply-b-ttl-rescan.py` (ditandai SUPERSEDED).
Baru: `scripts/patch-n8n-vt-cache-mb.py`.

---

# Handoff SOAR - 2026-09-20 (lanjutan: README + diagram arsitektur minimal)

## 1. README.md ditulis ulang

Sebab: README masih menyebut Wazuh 4.9.2, Ollama sebagai AI utama, agent Wazuh
saja, dan daftar host lama (ravi-zorin/rocky-server) yang sudah tidak ada di fleet.

Isi baru (semua diverifikasi ke sistem live): versi stack (Wazuh 4.10.5,
n8n 2.40.0), agen Rust, ensemble VT+MB+OTX, cache verdict TTL diferensial,
dedup claim-check, scan on-demand, monitoring (dashboard `:3000` / API `:8080` /
TUI), tabel fleet 7 endpoint, quick start (`deploy/setup-server.sh` + 4 jalur
agent), struktur repo, catatan bahwa `n8n-workflows/` hanyalah **snapshot**
(sumber kebenaran = workflow live, patch lewat `scripts/patch-n8n-*.py`).

## 2. Diagram arsitektur baru (gaya minimal)

- **Baru**: `docs/diagrams/arsitektur-soar.mmd` + `.png` (1568x480) — gaya
  minimal: abu-abu/putih, tanpa emoji, garis tipis, sans-serif. Isi: endpoint
  (soar-agent Rust) → n8n → intel (VT/MB/OTX + GSB/URLScan) + LLM → Telegram →
  analis → Active Response; plus fleet-monitor (dashboard/TUI) dan heartbeat.
- **Baru**: `docs/diagrams/mermaid-minimal.json` (tema + wrapping) supaya render
  bisa diulang; perintah render ditulis sebagai komentar `%%` di file `.mmd`.
  Catatan: `docs/diagrams/puppeteer-config.json` menunjuk `/usr/bin/google-chrome`
  (tidak ada di nixbox) — sesuaikan `executablePath` bila render di mesin lain.
- README sekarang memakai diagram ini (sebelumnya `fig-3.3-arsitektur.png`).
- Diagram lain **tidak disentuh** (sesuai keputusan Ravi): `fig-3.1`–`fig-3.6`,
  `workflow-*`, `overview-bernomor`, `demo-hybrid-flow`, `fig-karyawan-*`.

## 3. Perbaikan laporan: Gambar 3.3 tertarik

`docs/Laporan-SOAR.md` adalah XML Word (openxml) yang menempel PNG pada
**extent tetap**. Gambar 3.3 dipasang `cx=5486400 cy=4489704` (rasio 1,22)
padahal PNG-nya 1584x902 (rasio 1,76) → gambar tampil **tertarik vertikal**.
Diperbaiki: `cy` → **3124200** (rasio 1,76, dua kemunculan: `<wp:extent>` dan
`<a:ext>`). Figur lain sudah cocok (3.1/3.2/3.4/3.5/3.6 selisih < 1%).

## 4. ⚠️ Temuan yang butuh keputusan Ravi: "AI lokal" tidak lagi akurat

Audit live (5 workflow aktif) menunjukkan:

- **Tidak ada Ollama** di server: port `11434` mati, tidak ada container Ollama.
- Node `Preload Model` dan `Ollama Generate` di `Deteksi Malware` **orphan** —
  tidak ada koneksi masuk ke `Preload Model`, jadi jalur Ollama tidak pernah
  dijalankan (itulah sebabnya eksekusi E2E tetap tanpa error).
- Jalur AI yang benar-benar jalan: **Atria** (OpenAI-compatible) untuk malware,
  **Gemini** untuk phishing. `Submit URL VirusTotal` + `Get URL Report` di
  workflow phishing juga orphan (eskalasi manual lama).

README sudah ditulis netral ("LLM — ringkasan dan rekomendasi, provider dapat
ditukar"). **Narasi laporan perlu diputuskan**: kalau tetap menyebut "AI lokal
(Ollama)", hidupkan kembali Ollama atau ubah klaimnya.

## Sisa sesi ini

- Keputusan narasi AI di laporan (hidupkan Ollama atau ubah teks).
- Opsional: tambahkan baris diagram baru di `docs/PANDUAN-DIAGRAM.md`.
- Belum di-commit (menunggu aba-aba Ravi), termasuk perubahan B sebelumnya.
