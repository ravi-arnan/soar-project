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
