# soar-agent (Rust)

Agen ringan SOAR alternatif Wazuh Agent. 1 binary **5.3 MB** (stripped, GNU) RSS 5.2 MB, watch file, hitung hash, POST ke n8n. Untuk 100 workstation: scp + systemd, tanpa enroll/key/manager.

## Install via package manager (.deb)

```bash
./build-deb.sh                                # build musl + bungkus .deb
sudo apt install ./dist/soar-agent_0.3.0_amd64.deb   # di tiap workstation
sudo nano /etc/default/soar-agent             # isi AGENT_ID, AGENT_NAME, SERVER
sudo install -d -m 700 /etc/soar-agent
sudo bash -c 'umask 077; read -rsp "Poll token: " t; printf "%s\\n" "$t" > /etc/soar-agent/fleet.token'
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
# default watch ~/Downloads + ~/Desktop + USB /run/media/<user> (dynamic scan 2s, recursive), webhook Tailscale docs/panduan/TAILSCALE-SETUP.md:5
printf '%s' 'token-min-32-karakter' > /tmp/soar-fleet-token && chmod 600 /tmp/soar-fleet-token
SOAR_FLEET_POLL_TOKEN_FILE=/tmp/soar-fleet-token RUST_LOG=info ./target/release/soar-agent --webhook http://<SOAR_SERVER_IP>:5678/webhook/wazuh-alert --agent-id 003 --agent-name workstation-01 \
  --fleet-url http://<SOAR_SERVER_IP>:8080/api/heartbeat --heartbeat-secs 60

# custom watch
./target/release/soar-agent --watch /home/<user>/Downloads,/media --webhook http://<SOAR_SERVER_IP>:5678/webhook/wazuh-alert
```

## USB dynamic scanner

Saran dospem (deteksi malware dipindah dari flashdisk): scan `/run/media/<user>` tiap 2 detik. Flashdisk colok kapan pun auto-watch **recursive** (subfolder ikut), dicabut auto-unwatch. File yang dibuat saat mount belum ter-watch (race 2 detik pertama) bisa terlewat — upgrade path: udev mount event.

## Noise filter (`should_ignore`)

File yang di-skip (tidak di-hash, tidak di-POST, hemat kuota VT + anti spam Telegram): prefix `/tmp/`, `/var/cache|log|tmp`, `/tmp/.vscode-`, `/tmp/org.chromium|com.brave|mozilla-`, dsb; pola bebas di mana saja `/dosdevices/` (mirror Wine!), `/.git/`, `/node_modules/`, `/__pycache__/`, `/cache/`; ekstensi `.iso .dmg .db-wal .db-shm .db-journal .tmp .log .swp .ds_store .thumbs.db` + akhiran `~`. Mirror ke lapis-2: kondisi `cond-not-noise` (op `notRegex`) di node Filter workflow Deteksi Malware. Test: `cargo test ignore_fp_noise_14sep`.

## Settle + skip kosong + debounce (18 Sep, FP download bertahap)

Browser/Telegram menulis file bertahap (chunk per detik): tanpa settle, tiap
chunk jadi 1 POST (hash parsial beda-beda, duplikat 4-5x per file). Sekarang:
tunggu ukuran stabil 2x poll 500ms (`wait_settled`, maks ~8 dtk, lewat itu
skip dan event modify berikutnya retrigger); file 0-byte di-skip (hash-nya
selalu `e3b0c44...`, VT tak bisa menilai); download parsial
`.part .crdownload .download .opdownload .filepart .partial` di-ignore
(rename ke nama final = event Create baru, tetap lolos); debounce per path
2 dtk → 60 dtk (`DEBOUNCE_SECS`). Test: `cargo test ignore_partial_download_18sep wait_settled_stabil_dan_hilang`.

## Heartbeat, Command Queue & Execution ACK (v1.1)

- Agent mengirim heartbeat tiap `--heartbeat-secs` (default 60) ke Fleet Monitor (`POST /api/heartbeat`) dan laporan on-demand scan (`POST /api/scan-result`) lengkap dengan header `Authorization: Bearer <poll_token>`.
- Saat mem-poll `GET /api/commands?agent_id=<id>`, agent mengeksekusi aksi (`quarantine`, `restore`/`unquarantine`, `sinkhole`, `unsinkhole`, `scan`) lalu otomatis mengirim laporan hasil eksekusi (`succeeded` / `failed` + detail output) ke `POST /api/commands/ack`.
- **Parity Lintas-OS & Keamanan**:
  - Auto-discovery direktori `Downloads` dan `Desktop` lintas user (`/home/*`, `/Users/*`, `C:\Users\*`) saat berjalan sebagai service `root`/`SYSTEM`, dengan fallback `/var/tmp` pada server Linux headless.
  - Penanganan pindah lintas-partisi/drive pada Linux (`EXDEV=18`) dan Windows (`ERROR_NOT_SAME_DEVICE=17`), serta pembatasan ACL `icacls` saat karantina di Windows.
  - Deteksi `EventKind::Modify` dan `EventKind::Remove` pada berkas umpan canary ransomware (`.soar-canary.docx`, Rule `100004` Level 12) dengan worker pemrosesan konkuren terbatas (`Semaphore(4)`).
  - Pemulihan berkas (`restore`) hanya diizinkan untuk berkas yang tercatat resmi di `manifest.json` dalam direktori karantina (menolak symlink), serta `sinkhole`/`unsinkhole` dilengkapi denylist domain infrastruktur kritis.

## Test EICAR

```bash
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.com
# harus muncul di n8n executions + Telegram dengan tombol (verdict VT cache 275a021)

## Quarantine

Agent listen `127.0.0.1:8787/quarantine` (alternatif Wazuh Active Response `docs/arsitektur/FLOW.md:299`):

```bash
curl -X POST http://127.0.0.1:8787/quarantine -H "Authorization: Bearer $(cat /etc/soar-agent/fleet.token)" -H 'Content-Type: application/json' -d '{"path":"/home/ravi/Downloads/eicar.com"}'
```

n8n callback handler bisa panggil endpoint ini sebagai alternatif `PUT /active-response`.

## Systemd

`SOAR_FLEET_POLL_TOKEN_FILE` wajib menunjuk file token mode 0600. Isi file
harus cocok dengan entry agent_id di `FLEET_AGENT_POLL_TOKENS_JSON` server.
Installer Linux, Ansible, NixOS, dan Windows sudah menyediakan jalur ini.

Lihat `soar-agent.service` di repo.

```bash
sudo cp target/release/soar-agent /usr/local/bin/soar-agent
sudo cp soar-agent.service /etc/systemd/system/
sudo cp dist/soar-agent.default /etc/default/soar-agent
sudo install -d -m 700 /etc/soar-agent
sudo bash -c 'umask 077; read -rsp "Poll token: " t; printf "%s\\n" "$t" > /etc/soar-agent/fleet.token'
sudo systemctl daemon-reload
sudo systemctl enable --now soar-agent
journalctl -u soar-agent -f
```

## Payload

Kompatibel dengan `scripts/custom-n8n.py:170` dan lolos `docs/arsitektur/FLOW.md:198`. Lihat `src/main.rs:build_payload`.
