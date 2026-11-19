"""Hardened zero-config agent installer templates (Linux, macOS, Windows)."""
from urllib.parse import urlparse


def _safe_host_from_origin(server_origin):
    parsed = urlparse(server_origin)
    return parsed.hostname or "127.0.0.1"


def generate_linux_installer_script(server_origin):
    host = _safe_host_from_origin(server_origin)
    return f"""#!/usr/bin/env bash
set -euo pipefail

# SOAR Agent Automated One-Line Installer (Linux)
SERVER_URL="{server_origin}"
SERVER_HOST="{host}"
AGENT_DIR="/opt/soar-agent"
TOKEN_DIR="/etc/soar-agent"
BINARY_PATH="/usr/local/bin/soar-agent"

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Jalankan installer dengan sudo: curl -sSL ${{SERVER_URL}}/api/enroll/script/linux | sudo bash"
  exit 1
fi

echo "============================================================"
echo "  SOAR Endpoint Agent Installer (Linux)"
echo "  Control Plane: ${{SERVER_URL}}"
echo "============================================================"

HOSTNAME_VAL="$(hostname | tr -cd 'a-zA-Z0-9._-' | cut -c1-48)"
ARCH_VAL="$(uname -m)"

echo "[1/5] Mengajukan permohonan enrollment ke server SOAR..."
ENROLL_RESP="$(curl -fsSL -X POST "${{SERVER_URL}}/api/enroll/request" \\
  -H "Content-Type: application/json" \\
  -d "{{\\"hostname\\":\\"${{HOSTNAME_VAL}}\\",\\"os\\":\\"linux\\",\\"arch\\":\\"${{ARCH_VAL}}\\"}}")"

REQ_ID="$(printf '%s' "$ENROLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('request_id',''))")"
CLAIM_SECRET="$(printf '%s' "$ENROLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('claim_secret',''))")"
if [ -z "$REQ_ID" ]; then
  echo "[x] Gagal mendaftar ke server SOAR. Response: $ENROLL_RESP"
  exit 1
fi

echo "[+] Permohonan terdaftar (Request ID: ${{REQ_ID}})."
echo "[!] Buka Dashboard SOAR -> Deploy Agent -> Pending Approvals dan klik Approve."
echo "[2/5] Menunggu persetujuan Admin..."

AGENT_ID=""
POLL_TOKEN=""
AGENT_NAME=""
for _ in $(seq 1 180); do
  STATUS_RESP="$(curl -fsSL "${{SERVER_URL}}/api/enroll/status?request_id=${{REQ_ID}}&claim_secret=${{CLAIM_SECRET}}" 2>/dev/null || true)"
  STATUS="$(printf '%s' "$STATUS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','pending'))" 2>/dev/null || echo pending)"
  if [ "$STATUS" = "approved" ]; then
    AGENT_ID="$(printf '%s' "$STATUS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))")"
    POLL_TOKEN="$(printf '%s' "$STATUS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('poll_token',''))")"
    AGENT_NAME="$(printf '%s' "$STATUS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_name',''))")"
    break
  elif [ "$STATUS" = "rejected" ]; then
    echo "[x] Permohonan enrollment DITOLAK oleh Admin."
    exit 1
  fi
  sleep 3
done

if [ -z "$AGENT_ID" ] || [ -z "$POLL_TOKEN" ]; then
  echo "[x] Timeout menunggu persetujuan Admin atau token gagal diambil."
  exit 1
fi

echo "[3/5] Mengunduh & memverifikasi binary soar-agent..."
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fsSL -o "${{TMP_DIR}}/soar-agent" "${{SERVER_URL}}/api/installer/download/soar-agent"
EXPECTED_SHA="$(curl -fsSL "${{SERVER_URL}}/api/installer/checksum/soar-agent" 2>/dev/null | tr -d '[:space:]' || true)"
if [ -n "$EXPECTED_SHA" ] && [ "${{#EXPECTED_SHA}}" -eq 64 ]; then
  echo "${{EXPECTED_SHA}}  ${{TMP_DIR}}/soar-agent" | sha256sum -c -
fi
install -m 0755 "${{TMP_DIR}}/soar-agent" "$BINARY_PATH"

echo "[4/5] Menulis konfigurasi & service systemd..."
install -d -m 0700 "$TOKEN_DIR" "$AGENT_DIR"
install -d -m 0700 /var/ossec/quarantine
umask 077
printf '%s\\n' "$POLL_TOKEN" > "${{TOKEN_DIR}}/fleet.token"
printf 'SOAR_FLEET_POLL_TOKEN_FILE=%s/fleet.token\\n' "$TOKEN_DIR" > "${{TOKEN_DIR}}/fleet.env"
chmod 0600 "${{TOKEN_DIR}}/fleet.token" "${{TOKEN_DIR}}/fleet.env"

cat > /etc/systemd/system/soar-agent.service <<UNIT
[Unit]
Description=SOAR Lightweight Endpoint Agent (Rust)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${{BINARY_PATH}} --webhook http://${{SERVER_HOST}}:5678/webhook/wazuh-alert --phishing-webhook http://${{SERVER_HOST}}:5678/webhook/wazuh-phishing --agent-id ${{AGENT_ID}} --agent-name ${{AGENT_NAME}} --fleet-url ${{SERVER_URL}}/api/heartbeat
Restart=always
RestartSec=5
Environment=RUST_LOG=info
EnvironmentFile=${{TOKEN_DIR}}/fleet.env

[Install]
WantedBy=multi-user.target
UNIT

echo "[5/5] Mengaktifkan service soar-agent..."
systemctl daemon-reload
systemctl enable --now soar-agent
echo "[+] Instalasi selesai. Agent ID: ${{AGENT_ID}} (${{AGENT_NAME}})."
"""


def generate_macos_installer_script(server_origin):
    host = _safe_host_from_origin(server_origin)
    return f"""#!/usr/bin/env bash
set -euo pipefail

# SOAR Agent Automated One-Line Installer (macOS)
SERVER_URL="{server_origin}"
SERVER_HOST="{host}"
TOKEN_DIR="/etc/soar-agent"
BINARY_PATH="/usr/local/bin/soar-agent"
PLIST_PATH="/Library/LaunchDaemons/io.soar.agent.plist"

if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Jalankan installer dengan sudo: curl -sSL ${{SERVER_URL}}/api/enroll/script/macos | sudo bash"
  exit 1
fi

HOSTNAME_VAL="$(scutil --get LocalHostName 2>/dev/null || hostname | tr -cd 'a-zA-Z0-9._-' | cut -c1-48)"
ARCH_VAL="$(uname -m)"
BIN_ASSET="soar-agent-macos-arm64"
if [ "$ARCH_VAL" = "x86_64" ]; then
  BIN_ASSET="soar-agent-macos-x86_64"
fi

echo "[1/5] Mengajukan permohonan enrollment macOS (${{ARCH_VAL}})..."
ENROLL_RESP="$(curl -fsSL -X POST "${{SERVER_URL}}/api/enroll/request" \\
  -H "Content-Type: application/json" \\
  -d "{{\\"hostname\\":\\"${{HOSTNAME_VAL}}\\",\\"os\\":\\"macos\\",\\"arch\\":\\"${{ARCH_VAL}}\\"}}")"

REQ_ID="$(printf '%s' "$ENROLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('request_id',''))")"
CLAIM_SECRET="$(printf '%s' "$ENROLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('claim_secret',''))")"
if [ -z "$REQ_ID" ]; then
  echo "[x] Gagal mendaftar ke server SOAR."
  exit 1
fi

echo "[2/5] Menunggu persetujuan Admin (Request ID: ${{REQ_ID}})..."
AGENT_ID=""
POLL_TOKEN=""
AGENT_NAME=""
for _ in $(seq 1 180); do
  STATUS_RESP="$(curl -fsSL "${{SERVER_URL}}/api/enroll/status?request_id=${{REQ_ID}}&claim_secret=${{CLAIM_SECRET}}" 2>/dev/null || true)"
  STATUS="$(printf '%s' "$STATUS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','pending'))" 2>/dev/null || echo pending)"
  if [ "$STATUS" = "approved" ]; then
    AGENT_ID="$(printf '%s' "$STATUS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_id',''))")"
    POLL_TOKEN="$(printf '%s' "$STATUS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('poll_token',''))")"
    AGENT_NAME="$(printf '%s' "$STATUS_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('agent_name',''))")"
    break
  elif [ "$STATUS" = "rejected" ]; then
    echo "[x] Permohonan enrollment DITOLAK oleh Admin."
    exit 1
  fi
  sleep 3
done

if [ -z "$AGENT_ID" ] || [ -z "$POLL_TOKEN" ]; then
  echo "[x] Timeout menunggu persetujuan Admin."
  exit 1
fi

echo "[3/5] Mengunduh & memverifikasi binary ${{BIN_ASSET}}..."
TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
curl -fsSL -o "${{TMP_DIR}}/soar-agent" "${{SERVER_URL}}/api/installer/download/${{BIN_ASSET}}"
EXPECTED_SHA="$(curl -fsSL "${{SERVER_URL}}/api/installer/checksum/${{BIN_ASSET}}" 2>/dev/null | tr -d '[:space:]' || true)"
if [ -n "$EXPECTED_SHA" ] && [ "${{#EXPECTED_SHA}}" -eq 64 ]; then
  echo "${{EXPECTED_SHA}}  ${{TMP_DIR}}/soar-agent" | shasum -a 256 -c -
fi
install -d -m 0755 /usr/local/bin
install -m 0755 "${{TMP_DIR}}/soar-agent" "$BINARY_PATH"

echo "[4/5] Menulis token & LaunchDaemon..."
install -d -m 0700 "$TOKEN_DIR" /var/ossec/quarantine
umask 077
printf '%s\\n' "$POLL_TOKEN" > "${{TOKEN_DIR}}/fleet.token"
chmod 0600 "${{TOKEN_DIR}}/fleet.token"

cat > "$PLIST_PATH" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>io.soar.agent</string>
  <key>ProgramArguments</key>
  <array>
    <string>${{BINARY_PATH}}</string>
    <string>--webhook</string><string>http://${{SERVER_HOST}}:5678/webhook/wazuh-alert</string>
    <string>--phishing-webhook</string><string>http://${{SERVER_HOST}}:5678/webhook/wazuh-phishing</string>
    <string>--agent-id</string><string>${{AGENT_ID}}</string>
    <string>--agent-name</string><string>${{AGENT_NAME}}</string>
    <string>--fleet-url</string><string>${{SERVER_URL}}/api/heartbeat</string>
    <string>--fleet-poll-token-file</string><string>${{TOKEN_DIR}}/fleet.token</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
PLIST

echo "[5/5] Memuat LaunchDaemon..."
launchctl unload "$PLIST_PATH" 2>/dev/null || true
launchctl load -w "$PLIST_PATH"
echo "[+] Instalasi macOS selesai. Agent ID: ${{AGENT_ID}}."
"""


def generate_windows_installer_script(server_origin):
    host = _safe_host_from_origin(server_origin)
    return f"""# SOAR Agent Automated One-Line Installer (Windows PowerShell)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ServerUrl = "{server_origin}"
$ServerHost = "{host}"
$InstallDir = "$env:ProgramFiles\\soar-agent"
$BinPath = "$InstallDir\\soar-agent.exe"
$TokenDir = "$env:ProgramData\\soar-agent"
$TokenFile = "$TokenDir\\fleet.token"
$TaskName = "SOAR Agent"

$HostName = $env:COMPUTERNAME
$Arch = $env:PROCESSOR_ARCHITECTURE

Write-Host "[1/5] Mengajukan permohonan enrollment ke $ServerUrl ..."
$Body = @{{ hostname = $HostName; os = "windows"; arch = $Arch }} | ConvertTo-Json
$Enroll = Invoke-RestMethod -Uri "$ServerUrl/api/enroll/request" -Method Post -ContentType "application/json" -Body $Body
$ReqId = $Enroll.request_id
$ClaimSecret = $Enroll.claim_secret
if (-not $ReqId) {{ throw "Gagal mendaftar ke server SOAR." }}

Write-Host "[2/5] Menunggu persetujuan Admin (Request ID: $ReqId)..."
$AgentId = $null
$PollToken = $null
$AgentName = $null
for ($i = 0; $i -lt 180; $i++) {{
    try {{
        $St = Invoke-RestMethod -Uri "$ServerUrl/api/enroll/status?request_id=$ReqId&claim_secret=$ClaimSecret" -Method Get
        if ($St.status -eq "approved") {{
            $AgentId = $St.agent_id
            $PollToken = $St.poll_token
            $AgentName = $St.agent_name
            break
        }} elseif ($St.status -eq "rejected") {{
            throw "Permohonan enrollment DITOLAK oleh Admin."
        }}
    }} catch {{}}
    Start-Sleep -Seconds 3
}}
if (-not $AgentId -or -not $PollToken) {{ throw "Timeout menunggu persetujuan Admin." }}

Write-Host "[3/5] Mengunduh & memverifikasi soar-agent.exe ..."
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $TokenDir | Out-Null
Invoke-WebRequest -Uri "$ServerUrl/api/installer/download/soar-agent.exe" -OutFile $BinPath -UseBasicParsing
try {{
    $ExpectedSha = (Invoke-WebRequest -Uri "$ServerUrl/api/installer/checksum/soar-agent.exe" -UseBasicParsing).Content.Trim().ToLower()
    if ($ExpectedSha.Length -eq 64) {{
        $ActualSha = (Get-FileHash -Path $BinPath -Algorithm SHA256).Hash.ToLower()
        if ($ActualSha -ne $ExpectedSha) {{
            Remove-Item $BinPath -Force -ErrorAction SilentlyContinue
            throw "Verifikasi SHA-256 binary gagal!"
        }}
    }}
}} catch {{
    if ($_.Exception.Message -like "*SHA-256*") {{ throw }}
}}

Write-Host "[4/5] Menyimpan token dengan NTFS ACL ketat..."
Remove-Item $TokenFile -Force -ErrorAction SilentlyContinue
[System.IO.File]::WriteAllText($TokenFile, $PollToken)
icacls $TokenFile /inheritance:r /grant:r "*S-1-5-18:(R)" "*S-1-5-32-544:(R)" | Out-Null

Write-Host "[5/5] Mendaftarkan Scheduled Task $TaskName ..."
$Watch = "$env:USERPROFILE\\Downloads,$env:USERPROFILE\\Desktop,$env:USERPROFILE\\Documents"
$ArgsStr = "--webhook http://${{ServerHost}}:5678/webhook/wazuh-alert --phishing-webhook http://${{ServerHost}}:5678/webhook/wazuh-phishing --agent-id $AgentId --agent-name `"$AgentName`" --fleet-url $ServerUrl/api/heartbeat --fleet-poll-token-file `"$TokenFile`" --watch `"$Watch`""
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
$Action = New-ScheduledTaskAction -Execute $BinPath -Argument $ArgsStr
$Trigger1 = New-ScheduledTaskTrigger -AtStartup
$Trigger2 = New-ScheduledTaskTrigger -AtLogOn
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger @($Trigger1, $Trigger2) -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Write-Host "[+] Instalasi Windows selesai. Agent ID: $AgentId ($AgentName)."
"""
