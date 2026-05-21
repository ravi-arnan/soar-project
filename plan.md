# Plan: Akses Remote rocky-server via Tailscale

## STATUS (selesai 2026-05-22)
- Tailscale aktif di kedua mesin (akun ravi-arnan@github, tailnet free):
  - laptop utama / manager (ravi-zorin): **100.95.198.108**
  - rocky-server (agent): **100.79.21.46**
- Wazuh agent rocky sudah di-repoint ke `100.95.198.108` (dari `192.168.18.45`),
  backup di `/var/ossec/etc/ossec.conf.bak`. Agent connect ke manager lewat
  Tailscale, status **Active**. Pipeline jalan walau beda jaringan.
- SSH lewat Tailscale: `ssh ravi@100.79.21.46` (rocky), `ssh ravi@100.95.198.108`
  (laptop utama).

### Sisa to-do (belum dikerjakan)
1. Tambah `restart: unless-stopped` di compose Wazuh + n8n supaya stack auto-hidup
   sesudah reboot (sekarang mati tiap laptop reboot/shutdown).
2. Downgrade agent host ravi-zorin 4.14.5 -> 4.9.2 + `apt-mark hold` (lihat
   bagian "Known issue" di bawah).
3. (Opsional) Fix SELinux supaya Tailscale SSH (`--ssh`) jalan di rocky. Sementara
   SSH biasa via IP Tailscale tetap jalan.

---


## Masalah
SSH ke rocky-server saat ini pakai IP privat LAN (`192.168.18.13`), jadi hanya
bisa kalau laptop dan rocky-server berada di router/jaringan yang sama. Begitu
salah satu pindah WiFi, IP privat tidak ter-route dan koneksi putus.

Ini juga berdampak ke pipeline SOAR: Wazuh agent di rocky-server menembak ke
manager di `192.168.18.45`. Kalau rocky pindah jaringan, agent ikut putus dari
manager.

Solusi: Tailscale (mesh VPN). Setelah aktif, tiap mesin dapat IP stabil
`100.x.x.x` yang reachable dari jaringan mana pun, tanpa port forwarding.

## Kendala saat ini (chicken-and-egg)
Untuk memasang Tailscale di rocky-server butuh akses ke mesinnya, tapi sekarang
kita di luar jaringannya dan belum ada jalur remote. Jadi rocky-server tidak
bisa disentuh sampai:
- kembali satu jaringan dengannya (di rumah / router yang sama), atau
- ada di depan mesinnya langsung.

Ini setup sekali saja. Setelah Tailscale hidup di rocky, masalah beda-WiFi
hilang permanen.

## Saat balik nanti (urutan)
1. Cek rocky-server hidup. Baterai terakhir 20% dan discharging tanpa charger,
   kemungkinan sudah mati. Colok charger, nyalakan.
2. SSH seperti biasa (saat itu sudah satu LAN lagi): `ssh ravi@192.168.18.13`.
3. Install Tailscale di rocky-server:
   ```bash
   curl -fsSL https://tailscale.com/install.sh | sh
   sudo systemctl enable --now tailscaled
   sudo tailscale up --ssh
   ```
   Langkah `up` menampilkan URL login. Karena rocky CLI-only, copy URL itu dan
   buka di HP/laptop berbrowser untuk autentikasi.
4. Ambil IP Tailscale rocky:
   ```bash
   tailscale ip -4    # 100.x.x.x, dipakai SSH dari mana saja
   ```

## Bisa dikerjakan sekarang (tanpa rocky-server)
- Buat akun di tailscale.com (login Google/GitHub) supaya autentikasi nanti
  tinggal approve.
- Install Tailscale di laptop utama (SOAR server, `192.168.18.45`) dan device
  yang dipakai sekarang.

## Langkah lanjutan setelah Tailscale hidup di kedua mesin
- Repoint Wazuh agent rocky ke IP Tailscale manager (`100.x.x.x`) di
  `/var/ossec/etc/ossec.conf` (blok `<address>`), lalu restart agent:
  ```bash
  sudo systemctl restart wazuh-agent
  ```
  Tujuannya agar pipeline SOAR tetap jalan walau rocky pindah jaringan.
- (Opsional) Disable sleep/suspend di rocky supaya tidak drop dari network:
  ```bash
  sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
  ```

## SELESAI: Active Response Interaktif (human-in-the-loop) - saran dosen
Tujuan: untuk alert KRITIS, analis memutuskan via tombol Telegram apakah file
diisolasi (Active Response) atau dibiarkan (false positive). Bukan auto-AR buta.

Status: TERVERIFIKASI end-to-end di rocky lewat Tailscale (2026-05-22). Tombol
"Isolasi File" -> file dikarantina + pesan ter-update; "Abaikan" -> file
dibiarkan + pesan ditandai false positive. SELinux rocky tidak memblokir.

Komponen:
1. Workflow "Deteksi Malware" (id 76f8gAyctCAAu5f6): auto-AR DIHAPUS. Alert
   CRITICAL/HIGH (should_active_response=true) dikirim dengan inline keyboard
   2 tombol; MEDIUM tetap polos. callback_data = "iso:<agentId>" / "ign:<agentId>".
2. Poller (scripts/tg-callback-poller.py, container `tg-callback-poller`):
   n8n Telegram Trigger berbasis webhook (butuh URL publik) -> tak bisa di balik
   NAT. Jadi poller long-poll getUpdates (keluar saja) dan teruskan klik tombol
   ke n8n Webhook lokal `/webhook/tg-callback`. Token dari .env (gitignored).
   Poller jalankan deleteWebhook saat start (jangan pasang Telegram Trigger node
   lain di bot yang sama -> konflik getUpdates).
3. Workflow "Telegram Callback Handler" (id kGzPH0MPHjKvailW): Webhook -> Parse
   (action+agentId dari callback_data; path/hash dari teks pesan) -> answerQuery
   -> IF iso? -> [iso] Get Wazuh Token + PUT /active-response !quarantine-file
   arguments [path] -> editMessageText "DIISOLASI"; [ign] editMessageText
   "FALSE POSITIVE".
4. AR script scripts/quarantine-file -> agent /var/ossec/active-response/bin/
   (root:wazuh 750). Pindahkan file ke /var/ossec/quarantine + chmod 000.
5. Manager config: command `quarantine-file` + active-response block dummy
   rules_id 999999 (terdaftar di ar.conf agent, tidak auto-fire; hanya via API).

Definisi workflow disimpan di n8n-workflows/ (BACKUP.json = versi asli sebelum
diubah, gitignored). Kredensial (Telegram/VT/Wazuh) TETAP utuh lewat CLI import
(beda dengan SDK update yang dulu menghapusnya) - tidak perlu re-link.

Deploy quarantine-file ke agent baru: salin script ke
/var/ossec/active-response/bin/quarantine-file, chown root:wazuh, chmod 750,
restart wazuh-agent.

## Known issue: agent host (ravi-zorin) version mismatch
Saat start service (2026-05-21), agent host `ravi-zorin` gagal connect ke
manager. Log manager: `wazuh-authd: ERROR: Incompatible version for new agent`.
Penyebab: agent host ke-upgrade ke `4.14.5` (apt upgrade, tanpa hold) sedangkan
manager `4.9.2`. Enrollment ditolak, agent tidak pernah connect.

Fix (butuh sudo, lakukan setelah presentasi):
```bash
sudo systemctl stop wazuh-agent
sudo apt-get install --allow-downgrades -y wazuh-agent=4.9.2-1
sudo apt-mark hold wazuh-agent          # cegah auto-upgrade lagi
sudo systemctl start wazuh-agent
```
Lakukan hal sama di rocky-server kalau ter-upgrade lagi (`apt-mark hold` /
`dnf versionlock` supaya tidak naik melebihi versi manager).

Catatan: demo pipeline tetap bisa tanpa agent live, lewat trigger webhook n8n
langsung (lihat README / curl ke `http://localhost:5678/webhook/wazuh-alert`).
