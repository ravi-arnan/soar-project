Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  Setup SOAR Agent - Toshiba Bapak (003)  " -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan

$AGENT_ID = if ($env:AGENT_ID) { $env:AGENT_ID } else { "003" }
$AGENT_NAME = if ($env:AGENT_NAME) { $env:AGENT_NAME } else { "toshiba-bapak" }
$POLL_TOKEN = if ($env:SOAR_FLEET_POLL_TOKEN) { $env:SOAR_FLEET_POLL_TOKEN } else { "89adbd12281c78a103fe5971ce28183b8260270bb1f9a355" }
$WAZUH_KEY = "MDAzIHRvc2hpYmEtYmFwYWsgYW55IDRhOWJjYWJlZTBkZTFhY2E3ZWY3YWEyYjFiMTU4Mzc2ZTA4MGI5OGU4NzgxZjU4OGFhOTU2NjY2ZjYyYzBmNWY="

# 1. Deteksi SERVER reachable (prioritas LAN 192.168.1.50 atau Tailscale 100.73.91.17)
$SERVER = if ($env:SERVER) {
    $env:SERVER
} else {
    $candidates = @("192.168.1.50", "100.73.91.17")
    $chosen = $null
    foreach ($cand in $candidates) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $iar = $tcp.BeginConnect($cand, 8080, $null, $null)
            $wait = $iar.AsyncWaitHandle.WaitOne(1500, $false)
            if ($wait -and $tcp.Connected) {
                $tcp.EndConnect($iar)
                $tcp.Close()
                $chosen = $cand
                break
            }
            $tcp.Close()
        } catch {}
    }
    if ($chosen) { $chosen } else { "192.168.1.50" }
}

Write-Host "[+] Menggunakan Server SOAR: $SERVER" -ForegroundColor Green

$BINARY_URL = "http://${SERVER}:8000/soar-agent.exe"
$LOCAL_DIR = "$env:ProgramFiles\soar-agent"
$LOCAL_PATH = "$LOCAL_DIR\soar-agent.exe"
$TOKEN_DIR = "$env:ProgramData\soar-agent"
$TOKEN_FILE = "$TOKEN_DIR\fleet.token"
$TASK_NAME = "SOAR Agent"
$WATCH = if ($env:SOAR_WATCH) { $env:SOAR_WATCH } else { "$env:USERPROFILE\Downloads,$env:USERPROFILE\Desktop,$env:USERPROFILE\Documents" }
$SCAN_INTERVAL = if ($env:SOAR_SCAN_INTERVAL_SECS) { $env:SOAR_SCAN_INTERVAL_SECS } else { "21600" }

# 2. Direktori & Unduh Binary SOAR Agent
Write-Host "[1/6] Menyiapkan direktori $LOCAL_DIR"
New-Item -ItemType Directory -Force -Path $LOCAL_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $TOKEN_DIR | Out-Null

# Bersihkan service lama & hentikan proses yang mungkin berjalan
Stop-Service soar-agent -ErrorAction SilentlyContinue
sc.exe delete soar-agent | Out-Null
Stop-Process -Name soar-agent -Force -ErrorAction SilentlyContinue
Start-Sleep 1

Write-Host "[2/6] Mengunduh binary agent terbaru dari $BINARY_URL"
Invoke-WebRequest -Uri $BINARY_URL -OutFile $LOCAL_PATH -UseBasicParsing

# 3. Tulis Token Fleet & Set Permissions
Write-Host "[3/6] Menyetel token fleet otorisasi"
Remove-Item $TOKEN_FILE -Force -ErrorAction SilentlyContinue
[System.IO.File]::WriteAllText($TOKEN_FILE, $POLL_TOKEN)
icacls $TOKEN_FILE /inheritance:r /grant:r "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" | Out-Null
[Environment]::SetEnvironmentVariable("SOAR_FLEET_POLL_TOKEN_FILE", $TOKEN_FILE, "Machine")
[Environment]::SetEnvironmentVariable("SOAR_FLEET_POLL_TOKEN", $null, "Machine")

# 4. Daftarkan Scheduled Task
Write-Host "[4/6] Mendaftarkan Scheduled Task $TASK_NAME (SYSTEM)"
Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
$TASK_ARGS = "--webhook http://${SERVER}:5678/webhook/wazuh-alert --agent-id $AGENT_ID --agent-name `"$AGENT_NAME`" --fleet-url http://${SERVER}:8080/api/heartbeat --fleet-poll-token-file `"$TOKEN_FILE`" --watch `"$WATCH`" --scan-interval-secs $SCAN_INTERVAL"
$action = New-ScheduledTaskAction -Execute $LOCAL_PATH -Argument $TASK_ARGS
$triggerStartup = New-ScheduledTaskTrigger -AtStartup
$triggerLogon = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName $TASK_NAME -Action $action -Trigger @($triggerStartup, $triggerLogon) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TASK_NAME

# 5. Konfigurasi Wazuh Agent jika terpasang
Write-Host "[5/6] Memeriksa instalasi Wazuh Agent"
$ossecDir = "${env:ProgramFiles(x86)}\ossec-agent"
if (Test-Path "$ossecDir\ossec.conf") {
    try {
        [xml]$xml = Get-Content "$ossecDir\ossec.conf"
        $addrNode = $xml.ossec_config.client.server.address
        if ($addrNode -ne $SERVER) {
            $xml.ossec_config.client.server.address = $SERVER
            $xml.Save("$ossecDir\ossec.conf")
            Write-Host "      Wazuh server address diarahkan ke $SERVER" -ForegroundColor Yellow
        }
        $keysFile = "$ossecDir\client.keys"
        if (-not (Test-Path $keysFile) -or (Get-Item $keysFile).Length -lt 20) {
            & "$ossecDir\manage_agents.exe" -i $WAZUH_KEY
        }
        Restart-Service WazuhSvc -ErrorAction SilentlyContinue
        Write-Host "      WazuhSvc berhasil direstart" -ForegroundColor Green
    } catch {
        Write-Host "      Wazuh config update: $_" -ForegroundColor DarkGray
    }
}

# 6. Pasang OpenSSH Server agar bisa remote management di kemudian hari
Write-Host "[6/6] Memastikan OpenSSH Server aktif untuk remote management"
try {
    $sshCap = Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH.Server*'
    if ($sshCap -and $sshCap.State -ne 'Installed') {
        Add-WindowsCapability -Online -Name $sshCap.Name | Out-Null
    }
    Start-Service sshd -ErrorAction SilentlyContinue
    Set-Service -Name sshd -StartupType 'Automatic' -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH SSH Server' -Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 -ErrorAction SilentlyContinue | Out-Null
    Write-Host "      OpenSSH Server aktif di port 22" -ForegroundColor Green
} catch {
    Write-Host "      OpenSSH capability check selesai" -ForegroundColor DarkGray
}

try {
    Start-Service Tailscale -ErrorAction SilentlyContinue
} catch {}

Start-Sleep 3
Write-Host "`n=== Verifikasi Status ===" -ForegroundColor Cyan
Get-ScheduledTask -TaskName $TASK_NAME | Format-Table State, TaskName
Get-Process soar-agent -ErrorAction SilentlyContinue | Format-Table Id, ProcessName, WorkingSet
Get-Service -Name WazuhSvc, sshd, Tailscale -ErrorAction SilentlyContinue | Format-Table Status, Name, DisplayName

Write-Host "Setup selesai. Agent terdaftar sebagai ID $AGENT_ID ($AGENT_NAME)." -ForegroundColor Green
