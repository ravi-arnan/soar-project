#!/bin/bash
# Demo trigger phishing detection.
# Inject JSON event ke /var/log/phishing-events.log → Wazuh detect → forward ke n8n.
#
# Usage:
#   bash test-phishing.sh                                    # Default URL test (AMTSO phishing test page)
#   bash test-phishing.sh "http://example.com/fake-login"    # Custom URL
#   bash test-phishing.sh "URL" "192.168.1.50"               # Custom URL + srcip

PHISHING_LOG="/var/log/phishing-events.log"

URL="${1:-https://www.amtso.org/check-desktop-phishing-page/}"
SRCIP="${2:-192.168.1.50}"
SOURCE="${3:-manual_test}"

if [[ ! -w "$PHISHING_LOG" ]]; then
  echo "ERROR: $PHISHING_LOG tidak writable. Run apply-phishing.sh dulu (sudo)."
  exit 1
fi

# Build JSON event (single line untuk Wazuh JSON decoder)
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
JSON="{\"event_type\":\"phishing_url\",\"url\":\"$URL\",\"srcip\":\"$SRCIP\",\"source\":\"$SOURCE\",\"timestamp\":\"$TIMESTAMP\"}"

echo "=== Inject phishing event ==="
echo "URL:    $URL"
echo "SrcIP:  $SRCIP"
echo "Source: $SOURCE"
echo ""
echo "JSON: $JSON"
echo "$JSON" >> "$PHISHING_LOG"
echo ""
echo "✅ Event written ke $PHISHING_LOG"
echo ""
echo "Pipeline:"
echo "  1. Wazuh agent logcollector tail file (instant)"
echo "  2. Forward ke manager → match rule 100002 (level 10)"
echo "  3. Integratord call custom-n8n script → POST ke webhook /wazuh-phishing"
echo "  4. n8n workflow: Filter → Ekstrak → Submit URL VT → Tunggu 15s → Get URL Report"
echo "     → URLScan.io → Cek Ancaman → (TRUE: Wazuh AR) → Build Payload → Ollama → Telegram"
echo ""
echo "Tunggu ~30-60 detik untuk Telegram notification."
echo ""
echo "Cek alert log Wazuh manager kalau perlu debug:"
echo "    docker exec single-node-wazuh.manager-1 grep \"$URL\" /var/ossec/logs/alerts/alerts.log | tail -5"
