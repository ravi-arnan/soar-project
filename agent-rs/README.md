# soar-agent (Rust)

Agen ringan SOAR alternatif Wazuh Agent. 1 binary 1-3 MB, watch file, hitung hash, POST ke n8n.

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

## Jalankan

```bash
# default watch ~/Downloads + /media + ~/Desktop, webhook Tailscale plan.md:5
RUST_LOG=info cargo run -- --webhook http://100.95.198.108:5678/webhook/wazuh-alert --agent-id 003 --agent-name rust-agent-ravi

# custom watch
cargo run -- --watch /home/ravi/Downloads,/media --webhook http://100.95.198.108:5678/webhook/wazuh-alert
```

Test EICAR:

```bash
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/eicar.com
# harus muncul di n8n executions + Telegram CRITICAL dengan tombol
```

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
