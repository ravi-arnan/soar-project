# Handoff SOAR - 2026-09-11 malam

- **Tanggal & Waktu**: 2026-09-11 ~23:30-00:45 WITA (sesi: VS-antivirus + setup lintas-device + TUI + n8n otomatis + diagram)
- **Branch**: main, commit bersih siap commit (lihat daftar file baru di bawah)
- **Runtime**: n8n & fleet-monitor TIDAK jalan di laptop saat sesi ini (semua test dilakukan dengan instance sementara yang sudah di-cleanup)

## Konteks sesi: dua arahan dospem 2026-09-11

1. **"Apa bedanya dengan antivirus?"** → dijawab + didokumentasikan `docs/VS-ANTIVIRUS.md` (elevator pitch, tabel 9 dimensi, paragraf laporan, angka benchmark, poin "komplementer bukan kompetitor").
2. **"Permudahkan setup SOAR lintas device" + kebayangan "script yang install semua service lalu minta API key"** → dibangun penuh, lihat di bawah. Bonus permintaan lanjutan: **dashboard TUI** kembaran GUI web, **automasi n8n** (credentials + workflow + remap), dan **diagram perspektif karyawan**.

## File baru (semua tested, belum di-commit)

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

## Belum dites live (lakukan di server)

- [ ] `bash deploy/setup-server.sh` end-to-end di mesin/server bersih (perbaiki bind-mount compose kalau repo bukan di `~/Projects/soar-project` — script sudah mencetak peringatan)
- [ ] `N8N_OWNER_API_KEY=xxx python3 deploy/n8n-setup.py --all` lawan n8n hidup — perhatikan bentuk respons public API v1 (terutama PUT aktivasi workflow)
- [ ] `agent-rs/build-deb.sh` butuh rustup target musl (script sudah `rustup target add`)
- [ ] ansible deploy-agents ke ≥1 workstation nyata

## Next Action

- [ ] Commit sesi ini (10 file baru + 4 update, lihat tabel di atas)
- [ ] Live-test setup-server + n8n-setup di server (checklist di atas)
- [ ] Sisa Fase 3 agen ringan: `docs/PERBANDINGAN-PENELITIAN.md` kolom Agen Ringan + screenshot Telegram/fleet/TUI untuk laporan
- [ ] Tanya dospem: apakah `docs/VS-ANTIVIRUS.md` cukup atau mau dimasukkan ke bab laporan (sub-bab "posisi terhadap antivirus")
- [ ] Push commit yang masih lokal kalau ada

## Catatan penting

- `agent-rs/target/` dan `.env` tetap gitignored. `docs/.~lock.*.pdf#` jangan di-commit (tutup dulu dokumennya di LibreOffice).
- Diagram baru dirender pakai `npx -y @mermaid-js/mermaid-cli` + chrome lokal (`/etc/profiles/per-user/ravi/bin/google-chrome`), config puppeteer inline — path chrome beda antar mesin.
- fleet-monitor di laptop sering di-reap (nohup tidak cukup) — kalau mau test lokal pakai `setsid nohup ... &` lalu `curl :8080/healthz` dulu.
