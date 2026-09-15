# soar-agent (Rust)

Agen ringan SOAR alternatif Wazuh Agent. 1 binary **5.3 MB** (stripped, GNU) RSS 5.2 MB, watch file, hitung hash, POST ke n8n. Untuk 100 workstation: scp + systemd, tanpa enroll/key/manager.

## Install via package manager (.deb)

```bash
./build-deb.sh                                # build musl + bungkus .deb
sudo apt install ./dist/soar-agent_0.1.0_amd64.deb   # di tiap workstation
sudo nano /etc/default/soar-agent             # isi AGENT_ID, AGENT_NAME, SERVER
sudo systemctl enable --now soar-agent
```

Uninstall: `sudo apt remove soar-agent`. Upgrade: pasang .deb versi lebih tinggi.
Rollout massal: `deploy/ansible/deploy-agents.yml` (1 perintah untuk N host).
Setup 1 host tanpa .deb: `deploy/agent-install.sh`.

## Build

Butuh Rust 1.70+. Di nixbox:

```bash
nix-shell -p rustc cargo pkg-config openssl
# atau via fenix / rustup

cargo build --release
# musl static untuk 100 workstation tanpa deps
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
ls -lh target/x86_64-unknown-linux-musl/release/soar-agent
```

Catatan toolchain (kejadian 14 Sep, jangan diulang):
- Binary nixbox (glibc 2.42, interpreter `/nix/store/...`) TIDAK jalan di
  Debian (glibc 2.41) → `status=203/EXEC`. Build 003 HARUS di ravi-debian
  (rustup stable; cargo distro 1.85 terlalu tua untuk Cargo.lock).
- Cross `.exe` Windows hanya bisa via rustup stable + target
  `x86_64-pc-windows-gnu` + linker mingw (`...-w64-mingw32-gcc`) +
  `RUSTFLAGS="-L <nixpkgs pkgsCross.mingwW64.windows.pthreads>/lib"`
  (mingw-w64 ≥ 12 tidak bundle `libpthread.a`, rust butuh `-l:libpthread.a`).
- Lihat `deploy/rebuild-agent-binaries.sh` (urutan build + deploy lengkap).

## Jalankan

```bash
# default watch ~/Downloads + ~/Desktop + USB /run/media/<user> (dynamic scan 2s, recursive), webhook Tailscale plan.md:5
RUST_LOG=info ./target/release/soar-agent --webhook http://100.73.91.17:5678/webhook/wazuh-alert --agent-id 003 --agent-name rust-agent-ravi \
  --fleet-url http://100.73.91.17:8080/api/heartbeat --heartbeat-secs 60

# custom watch
./target/release/soar-agent --watch /home/ravi/Downloads,/media --webhook http://100.73.91.17:5678/webhook/wazuh-alert
```

## USB dynamic scanner

Saran dospem (deteksi malware dipindah dari flashdisk): scan `/run/media/<user>` tiap 2 detik. Flashdisk colok kapan pun auto-watch **recursive** (subfolder ikut), dicabut auto-unwatch. File yang dibuat saat mount belum ter-watch (race 2 detik pertama) bisa terlewat — upgrade path: udev mount event.

## Noise filter (`should_ignore`)

File yang di-skip (tidak di-hash, tidak di-POST, hemat kuota VT + anti spam Telegram): prefix `/tmp/`, `/var/cache|log|tmp`, `/tmp/.vscode-`, `/tmp/org.chromium|com.brave|mozilla-`, dsb; pola bebas di mana saja `/dosdevices/` (mirror Wine!), `/.git/`, `/node_modules/`, `/__pycache__/`, `/cache/`; ekstensi `.iso .dmg .db-wal .db-shm .db-journal .tmp .log .swp .ds_store .thumbs.db` + akhiran `~`. Mirror ke lapis-2: kondisi `cond-not-noise` (op `notRegex`) di node Filter workflow Deteksi Malware. Test: `cargo test ignore_fp_noise_14sep`.

## Heartbeat Fleet Monitor

Agent kirim heartbeat tiap `--heartbeat-secs` (default 60) ke Fleet Monitor (`scripts/fleet-monitor.py`, port 8080) supaya muncul hijau di dashboard 100 PC. Best-effort, tidak crash kalau fleet down.

## Test EICAR

```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.com
# harus muncul di n8n executions + Telegram dengan tombol (verdict VT cache 275a021)

## Quarantine

Agent listen `127.0.0.1:8787/quarantine` (alternatif Wazuh Active Response `docs/FLOW.md:299`):

```bash
curl -X POST http://127.0.0.1:8787/quarantine -H 'Content-Type: application/json' -d '{"path":"/home/ravi/Downloads/eicar.com"}'
```

n8n callback handler bisa panggil endpoint ini sebagai alternatif `PUT /active-response`.

## Systemd

Lihat `soar-agent.service` di repo.

```bash
sudo cp target/release/soar-agent /usr/local/bin/soar-agent
sudo cp soar-agent.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soar-agent
journalctl -u soar-agent -f
```

## Payload

Kompatibel dengan `scripts/custom-n8n.py:170` dan lolos `docs/FLOW.md:198`. Lihat `src/main.rs:build_payload`.
