# Update Agent SOAR - toshiba-bapak

## Masalah

Dashboard fleet menampilkan OS toshiba-bapak sebagai `unknown` karena binary masih versi lama (belum kirim field `os`).

## Solusi

Reinstall agent dengan binary terbaru dari GitHub release.

### Jalankan di PowerShell (Admin)

```powershell
# 1. Hapus service lama
Stop-Service soar-agent -ErrorAction SilentlyContinue
sc.exe delete soar-agent

# 2. Download binary baru
$url = "https://github.com/ravi-arnan/soar-project/releases/download/v0.2.0/soar-agent.exe"
$out = "$env:TEMP\soar-agent.exe"
Invoke-WebRequest -Uri $url -OutFile $out

# 3. Install ulang dengan ID yang benar
$env:AGENT_ID = "005"
$env:AGENT_NAME = "toshiba-bapak"
$env:SERVER = "http://192.168.1.47:8080"
$env:WATCH = "C:\Users\$env:USERNAME\Downloads;C:\Users\$env:USERNAME\Desktop"
powershell -File install-agent-windows.ps1
```

### Verifikasi

Cek di dashboard `http://soar.raviarnan.dev:3000` atau fleet API:
```
curl http://192.168.1.47:8080/api/fleet
```

Kolom OS seharusnya sudah muncul sebagai `windows`.