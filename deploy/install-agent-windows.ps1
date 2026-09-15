Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AGENT_ID = $env:AGENT_ID
$AGENT_NAME = $env:AGENT_NAME
# Hormati $env:SERVER (bare IP/host, tanpa scheme/port). Default: Tailscale ravi-debian.
$SERVER = if ($env:SERVER) { $env:SERVER } else { "100.73.91.17" }
$BINARY_URL = "https://github.com/ravi-arnan/soar-project/releases/download/v0.2.0/soar-agent.exe"
$LOCAL_PATH = "$env:ProgramFiles\soar-agent\soar-agent.exe"
$TASK_NAME = "SOAR Agent"

if (-not $AGENT_ID) {
    Write-Host "Gunakan: `$env:AGENT_ID=`"005`" `$env:AGENT_NAME=`"laptop-bapak`" powershell -File install-agent-windows.ps1"
    exit 1
}
if (-not $AGENT_NAME) {
    $AGENT_NAME = "windows-$($env:COMPUTERNAME.ToLower())"
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

Write-Host "[4/5] Buat Scheduled Task $TASK_NAME (SYSTEM, AtStartup+AtLogOn)"
$ARGS = "--webhook http://${SERVER}:5678/webhook/wazuh-alert --agent-id $AGENT_ID --agent-name `"$AGENT_NAME`" --fleet-url http://${SERVER}:8080/api/heartbeat --watch `"$env:USERPROFILE\Downloads,$env:USERPROFILE\Desktop`""
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
