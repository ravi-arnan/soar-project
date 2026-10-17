# Setup & Update Agent SOAR - toshiba-bapak (Agent 003)

Panduan instalasi dan pembaruan SOAR Agent (Rust) serta Wazuh Agent pada laptop Toshiba Bapak (`toshiba-bapak`, IP LAN `192.168.1.15`, Tailscale `100.124.254.89`).

## Cara Cepat (1-Liner PowerShell Administrator)

Buka **PowerShell sebagai Administrator** (tekan `Win + X`, pilih `Windows PowerShell (Admin)`), lalu salin dan jalankan satu baris perintah berikut:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; (New-Object Net.WebClient).DownloadFile("http://192.168.1.50:8000/install-toshiba.ps1", "$env:TEMP\install-toshiba.ps1"); powershell -ExecutionPolicy Bypass -File "$env:TEMP\install-toshiba.ps1"
```

## Apa yang Dikerjakan Skrip Ini

1. **Auto-Detect Server**: Mendeteksi koneksi ke server SOAR (`192.168.1.50` untuk jaringan lokal Wi-Fi atau `100.73.91.17` jika Tailscale aktif).
2. **Download Binary**: Mengunduh binary terbaru `soar-agent.exe` yang sudah diperbaiki (tidak memindai drive fixed `D:\`, hanya removable/flashdisk).
3. **Token Keamanan**: Mendaftarkan token polling resmi untuk Agent 003 ke `C:\ProgramData\soar-agent\fleet.token` dengan proteksi hak akses sistem.
4. **Scheduled Task**: Memasang scheduled task `SOAR Agent` (berjalan sebagai akun `SYSTEM` saat komputer menyala dan saat pengguna login, dengan fitur auto-restart bila gagal).
5. **Wazuh Agent**: Memeriksa `ossec.conf`, mengarahkan server ke IP aktif, mendaftarkan key Agent 003 jika diperlukan, dan merestart `WazuhSvc`.
6. **Remote Management**: Mengaktifkan OpenSSH Server di port 22 agar pemeliharaan berikutnya dapat dilakukan otomatis dari jarak jauh.

## Verifikasi Hasil

Setelah skrip selesai, verifikasi status agent melalui terminal server atau browser:

```bash
curl -s http://192.168.1.50:8080/api/fleet | grep -o '"id": "003"[^}]*'
```

Di dashboard Fleet (`http://192.168.1.50:8080` atau `http://localhost:3000`), Agent 003 `toshiba-bapak` akan berstatus `active` dengan OS `windows`.