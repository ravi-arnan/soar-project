Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$AGENT_ID = $env:AGENT_ID
$AGENT_NAME = $env:AGENT_NAME
$SERVER = "100.73.91.17"
$BINARY_URL = "https://github.com/ravi-arnan/soar-project/releases/download/v0.2.0/soar-agent.exe"
$LOCAL_PATH = "$env:ProgramFiles\soar-agent\soar-agent.exe"

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

Write-Host "[3/5] Buat service soar-agent"
$ARGS = "--webhook http://${SERVER}:5678/webhook/wazuh-alert --agent-id $AGENT_ID --agent-name `"$AGENT_NAME`" --fleet-url http://${SERVER}:8080/api/heartbeat --watch `"$env:USERPROFILE\Downloads,$env:USERPROFILE\Desktop`""
New-Service -Name "soar-agent" -BinaryPathName "`"$LOCAL_PATH`" $ARGS" -DisplayName "SOAR Agent Rust" -StartupType Automatic

Write-Host "[4/5] Start service"
Start-Service -Name "soar-agent"

Write-Host "[5/5] Verifikasi"
Start-Sleep 2
Get-Service -Name "soar-agent" | Format-Table Status, Name, DisplayName

Write-Host "Selesai. Test: buat file di Downloads, cek n8n execution."
Write-Host "Uninstall: Stop-Service soar-agent; sc.exe delete soar-agent"