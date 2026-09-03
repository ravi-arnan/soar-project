# Agen Ringan vs Fork Wazuh - Analisis Kelayakan

> Jawaban untuk pertanyaan: bisa tidak kita fork Wazuh untuk bikin agen custom yang lebih ringan?

## 1. Jawaban singkat

**Bisa, Wazuh itu GPLv2, boleh di-fork.** Tapi untuk TA ini, fork full Wazuh bukan jalur paling murah. Rekomendasi: **POC agen ringan greenfield Rust yang kirim JSON kompatibel ke n8n** (dipilih karena nilai teknis tertinggi, murni footprint dan security, bukan learning curve), sambil jadikan fork Wazuh sebagai opsi jangka panjang. Dua jalur ini tidak saling mengecualikan. Dospem sarankan Go (`docs/CATATAN-DOSPEM-2026-09-03.md:22`), tapi Rust unggul untuk klaim ultra ringan di sidang.

## 2. Opsi B - Fork Wazuh (diet)

### Apa yang di-fork

Repo: `wazuh/wazuh` (C, bukan `wazuh-docker` yang hanya compose). Docker yang kamu pakai di `wazuh-docker/single-node/docker-compose.yml:6` hanya packaging. Logic agent ada di `src/` (syscheckd, logcollector, execd, dll).

Lisensi GPLv2: boleh fork, modifikasi, distribusi, tapi turunan harus tetap GPLv2 dan source harus dipublish kalau didistribusikan. Untuk TA internal kampus ini aman, cukup cantumkan lisensi dan link fork.

### Apa yang bisa di-trim

Agent Wazuh default bawa banyak modul. Yang kita pakai cuma:

- `wazuh-syscheckd` (FIM inotify untuk `~/Downloads`, `/media/*`, `/etc/cron*`, `/etc/systemd/system`, `~/.ssh`)
- `wazuh-execd` (eksekusi `quarantine-file` dari `wazuh-active-response` volume `wazuh-docker/single-node/docker-compose.yml:38`)

Yang bisa dimatikan via `ossec.conf` atau dihapus dari build:

- `wazuh-logcollector` verbose (kecuali untuk phishing URL log)
- `rootcheck`, `wodle` (open-scap, cis-cat, syscollector) yang tidak dipakai
- `wazuh-agentd` keep-alive tetap perlu, tapi bisa kurangi interval

Hasil: binary lebih kecil, RAM target <20 MB, tanpa dependensi Docker di klien (agent Wazuh native tidak butuh Docker, yang butuh Docker itu manager).

### Estimasi effort fork

- Build dari source butuh toolchain C + cmake, bukan `apt install wazuh-agent`. Harus maintain branch sendiri, rebase tiap rilis upstream (kamu sekarang pin di `4.9.2`, lihat `ROADMAP.md:123` H3).
- Risiko: salah trim = FIM tidak trigger atau Active Response tidak jalan. Butuh test matriks.

### Kapan fork masuk akal

Kalau butuh tetap kompatibel protokol Wazuh (TCP 1514 + enroll 1515 + API 55000) untuk 100 endpoint yang sudah terlanjur pakai manager. Cocok untuk skripsi yang mau klaim "optimasi Wazuh".

## 3. Opsi A - Agen ringan greenfield Rust (rekomendasi POC minggu ini, dipilih)

### Kenapa Rust, bukan Go (keputusan 2026-09-03)

Dospem bilang bikin agen sendiri pakai Golang. Polanya sama seperti agen health 50 PC yang dia bikin: baca sensor, kirim JSON, server yang mikir. Untuk TA ini kita pilih **Rust** karena nilai teknis murni lebih tinggi (footprint 1-3 MB vs Go 5-10 MB, no GC, deterministik, lebih aman untuk proses root), bukan karena learning curve. `n8n` di `docs/FLOW.md:198` tidak peduli bahasa, yang penting JSON kompatibel.

### Spec minimal (kompatibel dengan pipeline kamu sekarang)

```
binary: soar-agent (Rust, 1-3 MB musl static)
monitor:
  - ~/Downloads/**  (inotify via crate notify)
  - /media/**       (USB flashdisk)
  - ~/Desktop/**    (opsional)
action:
  - hitung sha256_after (streaming via sha2 crate, tidak load full file ke RAM)
  - baca size, perm_after (untuk magic-byte / exec-bit seperti di `docs/ROADMAP.md:112` G2)
  - POST JSON ke n8n webhook yang sama dengan Wazuh:
    POST http://<manager-tailnet-ip>:5678/webhook/wazuh-alert
payload: reuse struktur `scripts/custom-n8n.py:build payload` (rule.id=554, level=5, syscheck.path, syscheck.sha256_after, agent.id/name)
active-response:
  - HTTP lokal 127.0.0.1:8787/quarantine terima {"path": "..."} lalu mv -> /var/ossec/quarantine + chmod 000 (copy logic scripts/quarantine-file)
  - n8n callback handler panggil endpoint ini sebagai alternatif PUT /active-response di docs/FLOW.md:299
```

Contoh payload JSON (harus lolos filter `docs/FLOW.md:198`):

```json
{
  "rule": {"id": "554", "level": 5, "description": "File added to the system."},
  "agent": {"id": "003", "name": "rust-agent-ravi"},
  "timestamp": "2026-09-03T10:00:00+08:00",
  "data": {"sha256_after": "abc...", "path": "/home/user/Downloads/malware.exe"},
  "syscheck": {"path": "/home/user/Downloads/malware.exe", "sha256_after": "abc...", "event": "added", "perm_after": "755"}
}
```

### Keuntungan Rust

- Tidak depend ke Wazuh manager sama sekali, bisa langsung tembak n8n. Pipeline n8n kamu (`Filter Alert Malware`, `Ekstrak Alert`, `Rangkum Hasil`) tidak perlu diubah.
- Build paling ringan (1-3 MB musl), idle RAM 2-5 MB, no GC, cocok untuk 100 workstation.
- Cross-compile `cargo build --release --target x86_64-unknown-linux-musl`, install sebagai `systemd` service, update via scp.
- Mudah tambah fitur USB, magic-byte, tanpa recompile C, plus klaim novelty systems programming di sidang.

### Kekurangan

- Kehilangan fitur Wazuh lain (logcollector, rootcheck) kalau suatu saat butuh. Tapi untuk scope malware/phishing via file drop, itu tidak perlu.
- Perlu implementasi Active Response sendiri (pindah file ke quarantine + chmod 000). Bisa copy logic `scripts/quarantine-file`.
- Compile lebih lambat (20-60 detik) dibanding Go.

## 4. Rekomendasi strategi untuk TA

**Minggu ini (kejar progres dospem):**
1. Tetap pertahankan Wazuh sebagai baseline (2 agent aktif `ravi-zorin` + `rocky-server` di `docs/ARCHITECTURE.md:440`). Jangan bongkar yang sudah jalan.
2. Bikin POC Rust agent di satu endpoint baru (id 003) yang kirim ke webhook yang sama. Demo: download EICAR di folder pantauan -> Telegram muncul dengan tombol -> Isolasi work.
3. Dokumentasikan hasil di `docs/CATATAN-DOSPEM-2026-09-03.md:6`.

**Pasca sidang / future work:**
- Fork `wazuh/wazuh` branch `diet-syscheck-only`, build `.deb` custom, benchmark RAM/CPU vs Rust agent. Tulis di bab perbandingan.

Kedua jalur bisa diklaim di laporan: "sistem mendukung dua jenis agen: Wazuh agent untuk kompatibilitas enterprise, dan agen ringan Rust untuk deployment massal workstation". Go tetap bisa dicantumkan sebagai alternatif yang disarankan dospem.

## 5. Checklist POC Rust agent

- [ ] inotify watch `~/Downloads` + `/media/*` (crate notify)
- [ ] sha256 streaming + stat perm (sha2 + std::fs::metadata)
- [ ] POST JSON kompatibel ke `http://100.95.198.108:5678/webhook/wazuh-alert` (Tailscale IP dari `plan.md:5`)
- [ ] systemd unit `soar-agent.service` (restart unless-stopped)
- [ ] handler quarantine `POST /quarantine` lokal (dipanggil n8n callback handler sebagai alternatif `PUT /active-response`)
- [ ] test: EICAR `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` harus muncul CRITICAL dengan tombol

## 6. Referensi

- Wazuh agent source: https://github.com/wazuh/wazuh (GPLv2, `wazuh-docker/LICENSE`)
- Agent footprint sekarang: ~50 MB RAM `docs/ARCHITECTURE.md:82`, bukan Docker per klien
- Manager Docker: `wazuh-docker/single-node/docker-compose.yml:6`
- Roadmap diet vs queue-mode: `ROADMAP.md:5` kategori E dan H
