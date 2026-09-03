# Handoff SOAR - 2026-09-03 malam

- **Tanggal & Waktu**: 2026-09-03 21:48 WITA (lanjutan roadmap I — Agen Ringan)
- **Branch**: main (dirty, siap commit)
- **Agent**: rust-agent-ravi (003) pid 25064 (release 5.3 MB stripped, RSS 5.2 MB), n8n 2.36.9 aktif, Wazuh 4.9.2 GREEN

## Status Terakhir

- Meeting dospem Piarsa dirangkum ke `docs/CATATAN-DOSPEM-2026-09-03.md` (alur 100 workstation hash-only JSON ke n8n, HITL Telegram, scope USB).
- Analisis fork vs greenfield di `docs/AGENT-RINGAN.md` (Wazuh GPLv2 bisa fork tapi POC Rust lebih ringan, Go alternatif).
- Roadmap agen ringan `docs/ROADMAP-AGEN-RINGAN.md` — Fase 0 done, **Fase 1-2 done malam ini**.
- Scaffold `agent-rs/` Rust (notify 6.1, sha2, reqwest rustls, tokio) — watch Downloads/Desktop + USB non-recursive `/run/media/ravi`, POST ke `http://127.0.0.1:5678/webhook/wazuh-alert` kompatibel `scripts/custom-n8n.py:170` dan `docs/FLOW.md:198`, quarantine `127.0.0.1:8787` fallback `~/.soar-quarantine` + copy fallback cross-device.
- **Revisi diagram 2026-09-03 malam**: `docs/ARCHITECTURE.md:6` (dual jalur Wazuh + Rust ke n8n otak, hash-only 1-2KB, USB path) + `docs/FLOW.md:6` (sequence par Jalur A/B, payload identik) + `docs/FLOW.md:472` (Multi-Agent Flow dengan 003 hijau) + `docs/ARCHITECTURE.md:431` (tabel footprint 5.3 MB vs 50 MB).
- **Build release**: `cargo build --release` (strip) = **5.3 MB** (dari 87 MB debug), RSS **5.2 MB** (6588 KB), `file` = ELF GNU stripped. Musl static 1-3 MB butuh `musl-gcc` + target rustup (tertunda, GNU 5.3 MB sudah <10 MB & 90% lebih ringan dari Wazuh 50 MB, cukup untuk sidang).
- **Fix workflow** `n8n-workflows/deteksi-malware.json` (hapus credential placeholder `mb_auth_credential_id` header MalwareBazaar invalid) + reimport.
- **E2E verified malam ini**: EICAR `printf` tanpa newline -> hash `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` -> agent `file event -> POST ke n8n 40-43 ms -> 200 OK` (log `/tmp/soar-agent.log`), quarantine `POST /quarantine` -> `~/.soar-quarantine/eicar-003-final.com.1788443309.quarantined` + `chmod 000`. Benchmark Rust existing: `bench-rust-mttr-malware.json` N=30 mean 0.04s (Wazuh 0.03s), `bench-rust-load.json` thr 29.49 vs 34.11 — proof tidak lambat.
- **USB**: watcher non-recursive `/run/media/ravi` aktif (log confirm), tapi file di subdir butuh dynamic watcher — dicatat sebagai future fix (poll/re-watch saat mount).

## Berkas Yang Diubah / Dibuat

- `docs/CATATAN-DOSPEM-2026-09-03.md` (baru)
- `docs/AGENT-RINGAN.md` (baru)
- `docs/ROADMAP-AGEN-RINGAN.md` (update checklist 04 Sep done)
- `ROADMAP.md` (tambah kategori I + prioritas 9)
- `docs/ARCHITECTURE.md` (revisi diagram otak + tabel footprint Rust)
- `docs/FLOW.md` (revisi sequence dual jalur + multi-agent)
- `n8n-workflows/deteksi-malware.json` (hapus credentials MB)
- `agent-rs/Cargo.toml`, `agent-rs/src/main.rs`, `agent-rs/README.md`, `agent-rs/soar-agent.service`, `agent-rs/shell.nix` (scaffold) + `agent-rs/target/release/soar-agent` 5.3 MB (gitignored, jangan commit binary)
- `docs/bench-rust-mttr-malware.json`, `docs/bench-rust-load.json` (baru)
- `HANDOFF.md` (ini)

## Next Action

- Update `docs/PERBANDINGAN-PENELITIAN.md` tambah kolom "Agen Ringan" (RAM 5.2 MB, binary 5.3 MB, MTTR 0.04s) + screenshot Telegram EICAR 003.
- Uji tombol Telegram Isolasi end-to-end via `~/.soar-quarantine` (callback handler panggil `http://<tailscale>:8787/quarantine` sebagai alternatif `PUT /active-response`).
- USB real colok + file EICAR di flashdisk -> verifikasi trigger (butuh dynamic watcher fix jika subdir tidak ke-detect).
- Commit: `git add docs/CATATAN-DOSPEM-2026-09-03.md docs/AGENT-RINGAN.md docs/ROADMAP-AGEN-RINGAN.md ROADMAP.md docs/ARCHITECTURE.md docs/FLOW.md n8n-workflows/deteksi-malware.json agent-rs/Cargo.toml agent-rs/src/main.rs agent-rs/README.md agent-rs/soar-agent.service agent-rs/shell.nix docs/bench-rust*.json HANDOFF.md` lalu `git commit -m "feat: agen ringan Rust + diagram otak + release 5.3MB + E2E EICAR"` (jangan auto-push, jangan commit `target/`).
- Stop agent dev: `pkill -9 soar-agent` (pid 25064) atau `systemctl stop soar-agent` kalau sudah pakai service. Bersihkan EICAR quarantine di `~/.soar-quarantine/` jika perlu.
