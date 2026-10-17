Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AGENT_ID = $env:AGENT_ID
$AGENT_NAME = $env:AGENT_NAME
$SERVER = if ($env:SERVER) { $env:SERVER } else { "100.73.91.17" }
$POLL_TOKEN = $env:SOAR_FLEET_POLL_TOKEN
$BINARY_SOURCE = Join-Path $PSScriptRoot "soar-agent.exe"
$LOCAL_PATH = "$env:ProgramFiles\soar-agent\soar-agent.exe"
$TOKEN_DIR = "$env:ProgramData\soar-agent"
$TOKEN_FILE = "$TOKEN_DIR\fleet.token"
$TASK_NAME = "SOAR Agent"

# Cakupan pantau default (profile installer). Tambah folder via $env:SOAR_WATCH
# (dipisah koma). Drive non-system (USB/HDD eksternal) di-watch otomatis oleh
# agent, tidak perlu didaftarkan di sini.
$WATCH = if ($env:SOAR_WATCH) { $env:SOAR_WATCH } else { "$env:USERPROFILE\Downloads,$env:USERPROFILE\Desktop,$env:USERPROFILE\Documents" }
# Scan terjadwal (detik, 0=mati): menangkap file lama / file masuk saat agent
# mati yang tidak terlihat oleh FIM. Default 6 jam.
$SCAN_INTERVAL = if ($env:SOAR_SCAN_INTERVAL_SECS) { $env:SOAR_SCAN_INTERVAL_SECS } else { "21600" }

if (-not $AGENT_ID) { throw "AGENT_ID wajib diisi" }
if (-not $POLL_TOKEN -or $POLL_TOKEN.Length -lt 32) { throw "SOAR_FLEET_POLL_TOKEN minimal 32 karakter" }
if (-not (Test-Path $BINARY_SOURCE)) { throw "Binary bundle tidak ditemukan: $BINARY_SOURCE" }
if (-not $AGENT_NAME) { $AGENT_NAME = "windows-$($env:COMPUTERNAME.ToLower())" }

New-Item -ItemType Directory -Force -Path "$env:ProgramFiles\soar-agent" | Out-Null
Copy-Item $BINARY_SOURCE $LOCAL_PATH -Force
New-Item -ItemType Directory -Force -Path $TOKEN_DIR | Out-Null
# Token lama bisa terkunci ACL (SYSTEM+Administrators read-only) -> hapus dulu
# supaya reinstall tidak gagal "Access denied".
Remove-Item $TOKEN_FILE -Force -ErrorAction SilentlyContinue
[System.IO.File]::WriteAllText($TOKEN_FILE, $POLL_TOKEN)
icacls $TOKEN_FILE /inheritance:r /grant:r "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" | Out-Null

Stop-Service soar-agent -ErrorAction SilentlyContinue
sc.exe delete soar-agent | Out-Null
Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
$ARGS = "--webhook http://${SERVER}:5678/webhook/wazuh-alert --agent-id $AGENT_ID --agent-name `"$AGENT_NAME`" --fleet-url http://${SERVER}:8080/api/heartbeat --fleet-poll-token-file `"$TOKEN_FILE`" --watch `"$WATCH`" --scan-interval-secs $SCAN_INTERVAL"
$action = New-ScheduledTaskAction -Execute $LOCAL_PATH -Argument $ARGS
$triggerStartup = New-ScheduledTaskTrigger -AtStartup
$triggerLogon = New-ScheduledTaskTrigger -AtLogon
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName $TASK_NAME -Action $action -Trigger @($triggerStartup, $triggerLogon) -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $TASK_NAME
Start-Sleep 3
Get-ScheduledTask -TaskName $TASK_NAME | Format-Table State, TaskName
Get-Process soar-agent -ErrorAction SilentlyContinue | Format-Table Id, WorkingSet
