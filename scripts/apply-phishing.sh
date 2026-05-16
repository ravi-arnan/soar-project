#!/bin/bash
# Apply phishing detection setup:
#   1. Add custom rule 100002 ke Wazuh manager local_rules.xml
#   2. Create /var/log/phishing-events.log (writable by all users)
#   3. Add localfile block ke agent ossec.conf untuk monitor log file
#   4. Restart wazuh-manager (container) + wazuh-agent (host)
#
# Usage: sudo bash apply-phishing.sh

set -e

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run with sudo"
  exit 1
fi

SCRIPT_DIR="/home/ravi/Projects/soar-project/scripts"
RULE_SOURCE="$SCRIPT_DIR/phishing-rule.xml"
LOCALFILE_SOURCE="$SCRIPT_DIR/phishing-monitor.xml"
PHISHING_LOG="/var/log/phishing-events.log"

AGENT_OSSEC_CONF="/var/ossec/etc/ossec.conf"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
AGENT_BACKUP="${AGENT_OSSEC_CONF}.bak-${TIMESTAMP}"

CONTAINER="single-node-wazuh.manager-1"
MANAGER_RULES="/var/ossec/etc/rules/local_rules.xml"

echo "=== STEP 1: Add custom rule 100002 ke Wazuh MANAGER ==="

# Cek apakah rule 100002 sudah ada
if docker exec "$CONTAINER" grep -q 'id="100002"' "$MANAGER_RULES" 2>/dev/null; then
  echo "Rule 100002 sudah ada di $MANAGER_RULES — skip"
else
  # Backup local_rules.xml di manager
  docker exec "$CONTAINER" cp "$MANAGER_RULES" "${MANAGER_RULES}.bak-${TIMESTAMP}"
  echo "Backup manager rules: ${MANAGER_RULES}.bak-${TIMESTAMP}"

  # Append rule
  docker cp "$RULE_SOURCE" "$CONTAINER:/tmp/phishing-rule.xml"
  docker exec "$CONTAINER" sh -c "cat /tmp/phishing-rule.xml >> $MANAGER_RULES"
  docker exec "$CONTAINER" rm /tmp/phishing-rule.xml
  echo "Rule 100002 + 100003 appended ke $MANAGER_RULES"
fi

echo ""
echo "=== STEP 2: Create log file (world-writable supaya semua user bisa append) ==="

if [[ ! -f "$PHISHING_LOG" ]]; then
  touch "$PHISHING_LOG"
  chmod 666 "$PHISHING_LOG"
  echo "Created $PHISHING_LOG (mode 666)"
else
  echo "$PHISHING_LOG sudah ada — skip"
fi

echo ""
echo "=== STEP 3: Add localfile block ke AGENT ossec.conf ==="

# Cek apakah localfile sudah ada
if grep -q "/var/log/phishing-events.log" "$AGENT_OSSEC_CONF"; then
  echo "Localfile phishing-events.log sudah di agent ossec.conf — skip"
else
  cp "$AGENT_OSSEC_CONF" "$AGENT_BACKUP"
  echo "Backup agent config: $AGENT_BACKUP"

  # Insert localfile block sebelum </ossec_config> terakhir
  python3 <<EOF
import re

with open("$AGENT_OSSEC_CONF") as f:
    content = f.read()

with open("$LOCALFILE_SOURCE") as f:
    localfile_block = f.read()

# Strip XML comment dari source
localfile_clean = re.sub(r'<!--.*?-->', '', localfile_block, flags=re.DOTALL).strip()

# Insert sebelum </ossec_config> terakhir
new_content = content.rstrip()
if new_content.endswith('</ossec_config>'):
    # Insert dengan indentation
    new_content = new_content[:-len('</ossec_config>')] + '\n  ' + localfile_clean + '\n\n</ossec_config>\n'
    with open("$AGENT_OSSEC_CONF", "w") as f:
        f.write(new_content)
    print("OK: Localfile block inserted")
else:
    print("WARN: Format ossec.conf tidak ekspektasi — manual review needed")
EOF
fi

echo ""
echo "=== STEP 4: Restart wazuh-manager (container) untuk load rule baru ==="
docker exec "$CONTAINER" /var/ossec/bin/wazuh-control restart 2>&1 | tail -3

echo ""
echo "=== STEP 5: Restart wazuh-agent (host) untuk load localfile baru ==="
systemctl restart wazuh-agent
sleep 3
systemctl status wazuh-agent --no-pager | head -5

echo ""
echo "=== Verify ==="
echo "Manager loaded rule 100002:"
docker exec "$CONTAINER" grep "100002" "$MANAGER_RULES" | head -3
echo ""
echo "Agent monitoring log:"
grep "phishing-events.log" "$AGENT_OSSEC_CONF" || echo "(check failed)"

echo ""
echo "✅ DONE."
echo ""
echo "TEST trigger phishing event:"
echo "    bash $SCRIPT_DIR/test-phishing.sh \"http://malicious.example.com/login\""
echo ""
echo "Backup files:"
echo "    Agent config: $AGENT_BACKUP"
echo "    Manager rules: ${MANAGER_RULES}.bak-${TIMESTAMP} (di container)"
echo ""
echo "Rollback agent config:"
echo "    sudo cp $AGENT_BACKUP $AGENT_OSSEC_CONF && sudo systemctl restart wazuh-agent"
