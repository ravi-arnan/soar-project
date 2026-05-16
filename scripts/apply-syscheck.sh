#!/bin/bash
# Apply recommended syscheck config to Wazuh agent.
# Run with sudo: sudo bash apply-syscheck.sh

set -e

OSSEC_CONF="/var/ossec/etc/ossec.conf"
RECOMMENDED="/home/ravi/Projects/soar-project/scripts/syscheck-recommended.xml"
BACKUP="/var/ossec/etc/ossec.conf.bak-$(date +%Y%m%d-%H%M%S)"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: Run with sudo"
  exit 1
fi

if [[ ! -f "$RECOMMENDED" ]]; then
  echo "ERROR: $RECOMMENDED not found"
  exit 1
fi

echo "=== Backup existing ossec.conf ==="
cp "$OSSEC_CONF" "$BACKUP"
echo "Backup: $BACKUP"

echo ""
echo "=== Show CURRENT syscheck block (untuk reference) ==="
sed -n '/<syscheck>/,/<\/syscheck>/p' "$OSSEC_CONF" | head -50

echo ""
echo "=== Replace syscheck block dengan recommended config ==="
# Use Python to safely replace XML block
python3 <<EOF
import re

with open("$OSSEC_CONF") as f:
    content = f.read()

with open("$RECOMMENDED") as f:
    new_syscheck = f.read()

# Strip XML comments di file recommended (cuma untuk dokumentasi, tidak perlu masuk ke ossec.conf)
new_syscheck_clean = re.sub(r'<!--.*?-->', '', new_syscheck, flags=re.DOTALL).strip()

# Replace existing syscheck block
new_content = re.sub(
    r'<syscheck>.*?</syscheck>',
    new_syscheck_clean,
    content,
    count=1,
    flags=re.DOTALL,
)

if new_content == content:
    print("WARN: Tidak ada <syscheck> block ditemukan untuk di-replace")
else:
    with open("$OSSEC_CONF", "w") as f:
        f.write(new_content)
    print("OK: Replaced syscheck block")
EOF

echo ""
echo "=== Verify NEW syscheck block ==="
sed -n '/<syscheck>/,/<\/syscheck>/p' "$OSSEC_CONF" | head -40

echo ""
echo "=== Restart wazuh-agent ==="
systemctl restart wazuh-agent

echo ""
echo "=== Check status ==="
systemctl status wazuh-agent --no-pager | head -10

echo ""
echo "✅ DONE. Test dengan:"
echo "    echo 'X5O!P%@AP[4\\PZX54(P^)7CC)7}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*' > ~/Downloads/eicar-demo.com"
echo ""
echo "Backup ada di: $BACKUP"
echo "Untuk rollback: sudo cp $BACKUP $OSSEC_CONF && sudo systemctl restart wazuh-agent"
