# Update Agent SOAR - ideapc

## Masalah

Dashboard fleet menampilkan OS ideapc sebagai `unknown` karena binary masih versi lama (belum kirim field `os`).

## Solusi

Reinstall agent dengan binary terbaru dari GitHub release.

### Jalankan di PowerShell (Admin)

```powershell
# 1. Hapus service lama
Stop-Service soar-agent -ErrorAction SilentlyContinue
sc.exe delete soar-agent

# 2. Set binary HTTPS yang sudah diverifikasi dan token polling agent 006
$env:BINARY_URL = "<URL_HTTPS_BINARY_TERVERIFIKASI>"
$env:SOAR_FLEET_POLL_TOKEN = "<TOKEN_POLLING_AGENT_006>"

# 3. Install ulang dengan ID yang benar
$env:AGENT_ID = "006"
$env:AGENT_NAME = "ideapc"
$env:SERVER = "100.73.91.17"
powershell -File install-agent-windows.ps1
```

### Verifikasi

Cek di dashboard `http://soar.raviarnan.dev:3000` atau fleet API:
```
curl http://192.168.1.47:8080/api/fleet
```

Kolom OS seharusnya sudah muncul sebagai `windows`.