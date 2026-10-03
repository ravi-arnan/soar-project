Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AGENT_ID = $env:AGENT_ID
$AGENT_NAME = $env:AGENT_NAME
# Hormati $env:SERVER (bare IP/host, tanpa scheme/port). Default: Tailscale ravi-debian.
$SERVER = if ($env:SERVER) { $env:SERVER } else { "100.73.91.17" }
$BINARY_URL = $env:BINARY_URL
$POLL_TOKEN = $env:SOAR_FLEET_POLL_TOKEN
$LOCAL_PATH = "$env:ProgramFiles\soar-agent\soar-agent.exe"
$TOKEN_DIR = "$env:ProgramData\soar-agent"
$TOKEN_FILE = "$TOKEN_DIR\fleet.token"
$TASK_NAME = "SOAR Agent"

if (-not $AGENT_ID) {
    Write-Host "Gunakan: `$env:AGENT_ID=`"005`" `$env:AGENT_NAME=`"laptop-bapak`" powershell -File install-agent-windows.ps1"
    exit 1
}
if (-not $AGENT_NAME) {
    $AGENT_NAME = "windows-$($env:COMPUTERNAME.ToLower())"
}
if (-not $POLL_TOKEN -or $POLL_TOKEN.Length -lt 32) {
    Write-Host 'Gunakan: $env:SOAR_FLEET_POLL_TOKEN="token-min-32-karakter" sebelum menjalankan installer.'
    exit 1
}
if (-not $BINARY_URL) {
    Write-Host 'Set BINARY_URL ke URL HTTPS binary yang sudah diverifikasi.'
    exit 1
}
$BINARY_URI = [Uri]$BINARY_URL
if (-not $BINARY_URI.IsAbsoluteUri -or $BINARY_URI.Scheme -ne "https") {
    Write-Host 'BINARY_URL wajib memakai HTTPS.'
    exit 1
}

Write-Host "[1/5] Buat direktori $env:ProgramFiles\soar-agent"
New-Item -ItemType Directory -Force -Path "$env:ProgramFiles\soar-agent" | Out-Null

Write-Host "[2/5] Download binary dari $BINARY_URL"
Invoke-WebRequest -Uri $BINARY_URL -OutFile $LOCAL_PATH -UseBasicParsing

# NOTE: binary Rust ini console app tanpa windows-service handler, jadi
# New-Service gagal start (error 1053). Pakai Scheduled Task (SYSTEM) yang terbukti jalan.
Write-Host "[3/5] Bersihkan service/task lama"
Stop-Service soar-agent -ErrorAction SilentlyContinue
sc.exe delete soar-agent | Out-Null
Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
New-Item -ItemType Directory -Force -Path $TOKEN_DIR | Out-Null
[System.IO.File]::WriteAllText($TOKEN_FILE, $POLL_TOKEN)
icacls $TOKEN_FILE /inheritance:r /grant:r "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" | Out-Null
[Environment]::SetEnvironmentVariable("SOAR_FLEET_POLL_TOKEN_FILE", $TOKEN_FILE, "Machine")
[Environment]::SetEnvironmentVariable("SOAR_FLEET_POLL_TOKEN", $null, "Machine")

Write-Host "[4/5] Buat Scheduled Task $TASK_NAME (SYSTEM, AtStartup+AtLogOn)"
$ARGS = "--webhook http://${SERVER}:5678/webhook/wazuh-alert --agent-id $AGENT_ID --agent-name `"$AGENT_NAME`" --fleet-url http://${SERVER}:8080/api/heartbeat --fleet-poll-token-file `"$TOKEN_FILE`" --watch `"$env:USERPROFILE\Downloads,$env:USERPROFILE\Desktop`""
$action = New-ScheduledTaskAction -Execute $LOCAL_PATH -Argument $ARGS
$triggerStartup = New-ScheduledTaskTrigger -AtStartup
$triggerLogon = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName $TASK_NAME -Action $action -Trigger @($triggerStartup, $triggerLogon) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TASK_NAME

Write-Host "[5/5] Verifikasi"
Start-Sleep 3
Get-ScheduledTask -TaskName $TASK_NAME | Format-Table State, TaskName
Get-Process soar-agent -ErrorAction SilentlyContinue | Format-Table Id, WorkingSet

Write-Host "Selesai. Test: buat file di Downloads, cek n8n execution."
Write-Host "Uninstall: Unregister-ScheduledTask -TaskName '$TASK_NAME' -Confirm:`$false"
