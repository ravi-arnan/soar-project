# Deployment Guide

Panduan setup SOAR project dari nol — untuk reproducibility (thesis bab Implementasi).

## Prerequisites

### Server Side (laptop utama / VPS)

- **Linux** (Ubuntu 22.04 LTS / Debian 12 / Rocky 9 / Fedora Server)
- **Docker Engine** ≥ 20.10 + Docker Compose v2
- **RAM** minimum 12 GB (rekomendasi 16 GB)
- **Disk** minimum 80 GB SSD
- **Network**: static IP atau hostname resolvable dari endpoint

### Endpoint Side

- **OS supported**: Linux (Ubuntu, Debian, RHEL, Rocky, Alma, Fedora, SUSE), Windows 10/11/Server, macOS
- **RAM** minimum 512 MB (agent ~50 MB)
- **Network access** ke server port 1514 (TCP)

### External Services

- **VirusTotal API key** — free tier (`https://www.virustotal.com/gui/my-apikey`)
- **Telegram Bot Token** — via BotFather (`https://core.telegram.org/bots#botfather`)
- **Telegram Chat ID** — ambil via `@get_id_bot`

## Step 1 — Setup Server Stack

### 1.1 Install Docker

```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
# logout/login

# Rocky/RHEL
sudo dnf install -y dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/rhel/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER
```

### 1.2 Clone Wazuh Docker

```bash
mkdir -p ~/Projects/soar-project
cd ~/Projects/soar-project
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker
git checkout v4.9.2  # match dengan agent version target
```

### 1.3 Generate SSL Certificates

```bash
cd ~/Projects/soar-project/wazuh-docker/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```

### 1.4 Start Wazuh Stack

```bash
cd ~/Projects/soar-project/wazuh-docker/single-node
docker compose up -d

# Wait ~2 menit untuk indexer ready
docker compose logs -f wazuh.indexer
# Ctrl+C setelah "Cluster state recovered"
```

### 1.5 Setup n8n

Create `docker-compose.yml` di `~/Projects/soar-project/`:

```yaml
services:
  n8n:
    image: docker.n8n.io/n8nio/n8n:latest
    container_name: n8n
    restart: "no"
    ports:
      - "5678:5678"
    environment:
      - N8N_HOST=localhost
      - N8N_PORT=5678
      - N8N_PROTOCOL=http
      - NODE_TLS_REJECT_UNAUTHORIZED=0
      - N8N_SECURE_COOKIE=false
    volumes:
      - n8n_data:/home/node/.n8n

volumes:
  n8n_data:
```

Start:
```bash
cd ~/Projects/soar-project
docker compose up -d
```

### 1.6 Setup Ollama (host service)

```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull model
ollama pull llama3.2:3b

# Verify
ollama list
```

Ollama otomatis listen di `http://172.17.0.1:11434` (host docker0 interface), accessible dari container.

## Step 2 — Setup Wazuh Integration

### 2.1 Deploy Custom Integration Script

```bash
# Copy script ke Wazuh manager container
docker cp ~/Projects/soar-project/scripts/custom-n8n.py \
  single-node-wazuh.manager-1:/var/ossec/integrations/custom-n8n
docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/integrations/custom-n8n
docker exec single-node-wazuh.manager-1 chmod 750 /var/ossec/integrations/custom-n8n
```

### 2.2 Add Integration Config ke ossec.conf

Edit `ossec.conf` di Wazuh manager container, tambah `<integration>` blocks sebelum `</ossec_config>`:

```xml
<!-- N8N SOAR Integration -->
<integration>
  <name>custom-n8n</name>
  <hook_url>http://172.20.0.1:5678/webhook/wazuh-alert</hook_url>
  <rule_id>554,550,553,552,551</rule_id>
  <alert_format>json</alert_format>
</integration>

<integration>
  <name>custom-n8n</name>
  <hook_url>http://172.20.0.1:5678/webhook/wazuh-phishing</hook_url>
  <rule_id>87105,87106,100002</rule_id>
  <alert_format>json</alert_format>
</integration>
```

> Catatan: IP `172.20.0.1` adalah gateway docker network `single-node_default`. Sesuaikan kalau network setup berbeda.

Restart manager:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

Verify integratord running:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control status | grep integratord
# Expected: wazuh-integratord is running...
```

## Step 3 — Setup n8n Workflows

### 3.1 Akses n8n editor

Browser: `http://localhost:5678`

Pertama kali akan minta create owner account (admin).

### 3.2 Create Credentials

| Credential Type | Name | Value |
|-----------------|------|-------|
| Header Auth | VirusTotal API Key | Name: `x-apikey`, Value: `<VT_API_KEY>` |
| Basic Auth | Wazuh Basic Auth | Username: `wazuh-wui`, Password: `MyS3cr37P450r.*-` |
| Telegram | Telegram Bot | Access Token: `<BOT_TOKEN>` |

### 3.3 Import Workflow

Workflows tersimpan di JSON. Untuk import (lewat n8n UI):
- Workflows → Import from File → pilih JSON dari `backups/`

Atau create manually mengikuti diagram di `ARCHITECTURE.md`.

### 3.4 Update workflow dengan credentials

- Buka workflow "Deteksi Malware"
- Klik node Scan VirusTotal → pilih credential "VirusTotal API Key"
- Klik node Get Wazuh Token → pilih credential "Wazuh Basic Auth"
- Klik node Send Telegram Alert → pilih credential "Telegram Bot", chat ID di parameter `chatId`
- Save → Active

Repeat untuk workflow "Deteksi Phishing".

## Step 4 — Setup Wazuh Agent (di Endpoint)

### 4.1 Linux (Debian/Ubuntu)

```bash
LAPTOP_IP="192.168.18.45"  # IP server

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

# Install pin version match manager
sudo WAZUH_MANAGER="$LAPTOP_IP" \
     WAZUH_REGISTRATION_SERVER="$LAPTOP_IP" \
     WAZUH_AGENT_NAME="$(hostname)" \
     apt install -y wazuh-agent=4.9.2-1

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

### 4.2 Linux (RHEL/Rocky/AlmaLinux/Fedora)

```bash
LAPTOP_IP="192.168.18.45"

sudo rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
sudo tee /etc/yum.repos.d/wazuh.repo > /dev/null << 'EOF'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
EOF

sudo WAZUH_MANAGER="$LAPTOP_IP" \
     WAZUH_REGISTRATION_SERVER="$LAPTOP_IP" \
     WAZUH_AGENT_NAME="$(hostname)" \
     dnf install -y wazuh-agent-4.9.2

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

### 4.3 Windows

PowerShell as Admin:
```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi `
  -OutFile $env:tmp\wazuh-agent.msi
msiexec.exe /i $env:tmp\wazuh-agent.msi /q `
  WAZUH_MANAGER='192.168.18.45' `
  WAZUH_REGISTRATION_SERVER='192.168.18.45' `
  WAZUH_AGENT_NAME="$env:COMPUTERNAME"
NET START WazuhSvc
```

### 4.4 Verify Agent Enrolled

Dari server:
```bash
docker exec single-node-wazuh.manager-1 /var/ossec/bin/agent_control -l
# Expected output:
# ID: 002, Name: <agent-name>, IP: any, Active
```

## Step 5 — Apply FIM Configuration

Apply syscheck config ke agent (untuk monitor high-value paths):

### Linux

```bash
sudo bash ~/Projects/soar-project/scripts/apply-syscheck.sh
```

Script akan backup, replace `<syscheck>` block di `ossec.conf`, restart agent.

> Adjust paths di `scripts/syscheck-recommended.xml` sesuai username (default: `/home/ravi/*`).

### Verify FIM Active

```bash
sudo grep "directories" /var/ossec/etc/ossec.conf | head -5

# Cek realtime FIM started
sudo grep -i "realtime" /var/ossec/logs/ossec.log | tail -5
```

## Step 6 — End-to-End Test

### Test pipeline dengan EICAR

```bash
mkdir -p ~/Downloads
printf '%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > ~/Downloads/eicar-test.com

sha256sum ~/Downloads/eicar-test.com
# Expected: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f

# Wait 30-60 detik untuk full pipeline
echo "Check Telegram..."
sleep 60
```

### Verify dari Server

```bash
# 1. Wazuh detected file
docker exec single-node-wazuh.manager-1 \
  grep "eicar-test" /var/ossec/logs/alerts/alerts.log | tail -5

# 2. Integratord call script
docker exec single-node-wazuh.manager-1 \
  tail -5 /var/ossec/logs/integrations.log  # should be empty (no error)

# 3. n8n workflow executed
# Open http://localhost:5678 → Executions tab → recent execution

# 4. Active Response fired
docker exec single-node-wazuh.manager-1 \
  grep "active-response" /var/ossec/logs/api.log | tail -3

# 5. Telegram message delivered
# Check Telegram chat manually
```

## Step 7 — Production Hardening (Optional)

### 7.1 Firewall rules

Allow only specific source IPs ke port Wazuh agent:
```bash
sudo ufw allow from 192.168.18.0/24 proto tcp to any port 1514
sudo ufw allow from 192.168.18.0/24 proto tcp to any port 1515
```

### 7.2 Webhook authentication

Wrap n8n webhook dengan Nginx auth atau HMAC signature di custom-n8n.py:
```python
import hmac
secret = "your-shared-secret"
signature = hmac.new(secret.encode(), payload_bytes, "sha256").hexdigest()
req.add_header("X-Signature", signature)
```

### 7.3 Disable auto-start (untuk lab)

```bash
# Container restart policy
docker update --restart=no n8n single-node-wazuh.manager-1 \
  single-node-wazuh.indexer-1 single-node-wazuh.dashboard-1

# Agent service
sudo systemctl disable wazuh-agent
```

### 7.4 Backup workflow + integration script

```bash
mkdir -p ~/Projects/soar-project/backups
cd ~/Projects/soar-project/backups

# Export n8n workflow (manual via UI: Workflow → Settings → Download)

# Backup integration script (already in scripts/)
git init
git add scripts/ docker-compose.yml docs/
git commit -m "Initial SOAR setup"
```

## Step 8 — Stop Services (akhir hari)

```bash
# Stop containers (won't auto-start kalau restart policy = "no")
docker stop n8n single-node-wazuh.dashboard-1 \
  single-node-wazuh.manager-1 single-node-wazuh.indexer-1

# Stop wazuh agent
sudo systemctl stop wazuh-agent
```

## Troubleshooting Common Issues

### Issue: integratord not running

```bash
# Cek log
docker exec single-node-wazuh.manager-1 \
  grep -i "integrator" /var/ossec/logs/ossec.log | tail -10

# Common cause: <integration> tidak ada di ossec.conf
# Fix: re-add config seperti Step 2.2 + restart manager
```

### Issue: Agent "Incompatible version"

```
ERROR: Incompatible version for new agent from: <ip>
```

Cause: agent version > manager version. Fix: pin agent version match manager (4.9.2).

### Issue: webhook Connection refused

Cause: n8n container down atau workflow inactive.

Fix:
```bash
docker ps | grep n8n  # ensure running
curl -X POST http://localhost:5678/webhook/wazuh-alert -d '{}'  # test
# Open n8n UI, activate workflow if inactive
```

### Issue: Telegram parse error "Can't find end of entity"

Cause: AI response contains unbalanced markdown chars.

Fix: ensure Ollama Generate code has sanitization:
```javascript
.replace(/[*_`\[\]()]/g, '')
```

### Issue: False positive flood dari /tmp atau /var paths

Fix: add path prefix ke `NOISY_PATH_PREFIXES` di `scripts/custom-n8n.py`, redeploy:
```bash
docker cp scripts/custom-n8n.py single-node-wazuh.manager-1:/var/ossec/integrations/custom-n8n
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

## Reference Materials

- Wazuh documentation: https://documentation.wazuh.com/4.9/
- n8n documentation: https://docs.n8n.io/
- Ollama API: https://github.com/ollama/ollama/blob/main/docs/api.md
- VirusTotal API v3: https://docs.virustotal.com/reference/overview
- Telegram Bot API: https://core.telegram.org/bots/api
- MITRE ATT&CK Framework: https://attack.mitre.org/
