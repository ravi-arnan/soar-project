# SOAR Open-Source — n8n + Wazuh + AI Lokal

Implementasi Security Orchestration, Automation, and Response (SOAR) menggunakan stack open-source untuk deteksi malware dan phishing dengan **Active Response human-in-the-loop** (isolasi file disetujui analis lewat tombol Telegram) dan AI analysis lokal.

## Komponen Utama

| Component | Role | Version |
|-----------|------|---------|
| **Wazuh Manager** | SIEM + alert correlation + integratord | 4.9.2 |
| **Wazuh Indexer** | OpenSearch — log storage & search | 4.9.2 |
| **Wazuh Dashboard** | Kibana-like UI (optional) | 4.9.2 |
| **Wazuh Agent** | FIM + endpoint monitoring | 4.9.2 |
| **n8n** | Workflow orchestration engine | 2.15.0 |
| **Ollama** | Local LLM inference (llama3.2:3b) | latest |
| **Telegram Bot** | Notification delivery channel | — |
| **VirusTotal API** | External threat enrichment | v3 |

## Arsitektur

Lihat [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) untuk arsitektur lengkap dengan diagram.

Lihat [`docs/FLOW.md`](docs/FLOW.md) untuk alur kerja step-by-step.

## Struktur Folder

```
soar-project/
├── README.md                       # File ini
├── plan.md                         # Catatan remote access (Tailscale) + to-do
├── docker-compose.yml              # n8n + tg-callback-poller stack
├── wazuh-docker/single-node/       # Wazuh stack (manager/indexer/dashboard)
├── scripts/
│   ├── custom-n8n.py              # Integration bridge Wazuh → n8n
│   ├── quarantine-file            # Custom AR: isolasi file (human-approved)
│   ├── tg-callback-poller.py      # Long-poll Telegram → webhook n8n (anti-NAT)
│   ├── syscheck-recommended.xml    # FIM config Wazuh agent
│   └── apply-syscheck.sh          # Auto-deploy syscheck config
├── n8n-workflows/                  # Definisi workflow (deteksi-malware, callback handler)
├── backups/                        # Workflow JSON backups
└── docs/
    ├── ARCHITECTURE.md             # System architecture (lihat Section 4b)
    ├── FLOW.md                     # End-to-end workflow + sequence human-in-the-loop
    └── DEPLOYMENT.md               # Setup steps
```

## Quick Start

```bash
# Start server (laptop utama)
cd /home/ravi/Projects/soar-project
docker compose up -d                          # n8n
cd wazuh-docker/single-node && docker compose up -d  # Wazuh stack

# Start agent (host atau endpoint terpisah)
sudo systemctl start wazuh-agent

# Test pipeline
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  > ~/Downloads/eicar-test.com
# Wait 30-60s → Telegram notification
```

## Endpoints

| Service | URL |
|---------|-----|
| n8n editor | http://localhost:5678 |
| n8n webhook malware | http://localhost:5678/webhook/wazuh-alert |
| n8n webhook phishing | http://localhost:5678/webhook/wazuh-phishing |
| Wazuh Dashboard | https://localhost:443 |
| Wazuh API | https://localhost:55000 |
| Wazuh Indexer | https://localhost:9200 |
| Wazuh Agent listener | 0.0.0.0:1514 (tcp) |
| Wazuh Agent enrollment | 0.0.0.0:1515 (tcp) |

## Status Multi-Agent

```
ID: 000, wazuh.manager (server)
ID: 001, ravi-zorin (Ubuntu/Debian laptop utama)
ID: 002, rocky-server (Rocky Linux 9 ThinkPad X260)
```

## Lisensi

Open-source — komponen menggunakan lisensi masing-masing (Wazuh: GPLv2, n8n: Sustainable Use License, Ollama: MIT).
