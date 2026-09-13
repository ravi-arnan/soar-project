# 🎴 KARTU CONTEKAN DEMO SOAR — 1 HALAMAN

> Aturan emas: **1 skenario per kali**, tunggu hasil muncul sebelum lanjut. Layar: n8n (tab Executions) + Telegram di HP.

---

## ⏱️ PREFLIGHT (5 mnt sebelum tampil)
```bash
cd ~/Projects/soar-project && docker compose start
cd wazuh-docker/single-node && docker compose start && cd ../..
ollama run llama3.2:3b "test" >/dev/null
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l       # 2 agent Active?
docker exec single-node-wazuh.manager-1 grep block-domain /var/ossec/etc/shared/ar.conf  # ada?
```
Pemanasan: picu 1 EICAR lalu hapus. (block-domain hilang? → `sudo bash scripts/deploy-block-domain.sh`)

---

## 1️⃣ MALWARE — AUTO-ISOLATE (keyakinan tinggi)
```bash
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > ~/Downloads/malware-demo.com
```
→ ~15–30 dtk → Telegram **"OTOMATIS DIISOLASI"** (tanpa tombol). Bukti: `ls ~/Downloads/malware-demo.com` → **HILANG**.
🗣️ *"VT yakin (≈59/70). Tunggu manusia = nambah risiko → karantina otomatis, MTTR ≈ 0."*

## 2️⃣ MALWARE — TOMBOL (ambigu, human-in-the-loop)
```bash
echo "dokumen kerja yang sah" > ~/Downloads/demoreview-laporan-rapat.txt
```
→ Telegram **[Isolasi File] [Abaikan]** → **TAP "Isolasi File"** → jadi "DIISOLASI", file terkarantina.
🗣️ *"Deteksi ambigu → keputusan ke analis lewat 1 klik. Hindari isolasi buta (masukan pembimbing)."*

## 3️⃣ FILE BERSIH — ANTI FALSE-POSITIVE ⭐
```bash
echo "foto liburan biasa" > ~/Downloads/foto-liburan.jpg
```
→ Telegram **TETAP SUNYI** (VT bersih).
🗣️ *"Dulu tiap unduhan dianggap malware = alert fatigue. Sekarang hanya bersuara saat VT benar menemukan sesuatu."*

## 4️⃣ PHISHING — AUTO-BLOCK
```bash
bash scripts/test-phishing.sh "http://testsafebrowsing.appspot.com/s/phishing.html"
```
→ ~40 dtk (URLScan) → Telegram info + sinkhole. Bukti: `grep testsafebrowsing /etc/hosts` → `0.0.0.0 ...`.
🗣️ *"GSB tandai phishing → domain di-sinkhole otomatis, korban tak bisa akses."*

## 5️⃣ PHISHING — TOMBOL BLOKIR
```bash
bash scripts/test-phishing.sh "http://demoreview-phish-test.example.org/login"
```
→ Telegram **[Blokir] [Abaikan]** → **TAP "Blokir"** → sinkhole di `/etc/hosts`.
🗣️ *"Sama seperti malware — phishing ambigu juga bisa diserahkan ke analis."*

---

## 🔎 BUKTI (saat ditanya)
```bash
docker exec single-node-wazuh.manager-1 grep malware-demo /var/ossec/logs/alerts/alerts.json | tail -1
sudo tail -5 /var/ossec/logs/active-responses.log
```

## 🆘 TROUBLESHOOTING CEPAT
| Gejala | Tindakan |
|--------|----------|
| Telegram lama (>1 mnt) | Ollama dingin / VT lambat — wajar, jelaskan |
| Notifikasi tak muncul | Cek workflow Active di n8n; `docker logs n8n --tail 20` |
| Tombol diklik tak ada efek | `docker logs tg-callback-poller --tail 10` (harus "forwarded callback_query") |
| Agent tak Active | `sudo systemctl restart wazuh-agent` |
| **FIM rewel** → picu via webhook | lihat `docs/KARTU-DEMO.md` §6 |

## 🧹 BERSIH-BERSIH SETELAH DEMO
```bash
sudo sed -i '/WAZUH-SOAR-SINKHOLE/d' /etc/hosts
rm -f ~/Downloads/malware-demo.com ~/Downloads/demoreview-*.txt ~/Downloads/foto-liburan.jpg
```

---
**Komponen:** Wazuh (SIEM/HIDS+AR) · n8n (orkestrasi) · VirusTotal/GSB/URLScan (intel) · Ollama llama3.2:3b (AI lokal) · Telegram (notif+keputusan) · Tailscale (mesh). **2 agent:** ravi-zorin (Ubuntu) + rocky-server (Rocky 9).
