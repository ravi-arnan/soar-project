#!/var/ossec/framework/python/bin/python3
"""
Wazuh -> n8n SOAR integration (custom-n8n).

Forward Wazuh alerts ke n8n webhook dengan format nested yang sesuai struktur
yang diharapkan workflow. Webhook URL diambil dari argv[3] (di-pass oleh Wazuh
integratord dari <hook_url> di ossec.conf), jadi satu script handle multiple
integration block (malware + phishing).

Filter noise: skip path yang umumnya legitimate temp file / system activity.
"""
import sys
import json
import urllib.request


# Path prefix yang dianggap noise (tidak forward ke n8n).
# Tambahkan di sini kalau ada false positive baru.
NOISY_PATH_PREFIXES = (
    # Container runtime
    "/tmp/runc-process",
    "/tmp/runc.",
    # Editor / IDE / Claude / staging
    "/tmp/claude-",
    "/tmp/.vscode-",
    "/tmp/custom-",             # staging files untuk integration script
    # Window manager / desktop
    "/tmp/.X",
    "/tmp/.font-unix/",
    "/tmp/.ICE-unix/",
    "/tmp/.Test-unix/",
    "/tmp/.XIM-unix/",
    "/tmp/.com.google.",
    "/tmp/.org.chromium.",
    "/tmp/com.google.",         # Google software temp (non-dot prefix)
    "/tmp/org.chromium.",       # Chromium/Brave/Edge temp (non-dot prefix)
    "/tmp/com.brave.",
    "/tmp/com.microsoft.",
    "/tmp/mozilla-",            # Firefox temp
    "/tmp/snap.",
    "/tmp/systemd-private",
    "/tmp/dbus-",
    "/tmp/ssh-",
    # Dev runtime / build cache
    "/tmp/node-compile-cache",  # Node.js v8 bytecode cache
    "/tmp/v8-compile-cache",
    "/tmp/.bun/",               # Bun runtime cache
    "/tmp/yarn--",
    "/tmp/npm-",
    "/tmp/pip-",
    "/tmp/go-build",            # Go compiler temp
    "/tmp/cargo-",              # Rust cargo temp
    # System / persistent temp
    "/var/cache/",
    "/var/log/",
    "/var/tmp/",
)


def is_noisy_path(file_path):
    """Return True kalau path masuk noise list (skip dari forwarding)."""
    if not file_path:
        return False
    return file_path.startswith(NOISY_PATH_PREFIXES)


def extract_hash(alert):
    """Cari sha256/md5 hash dari berbagai possible path di Wazuh alert."""
    syscheck = alert.get("syscheck", {}) or {}
    data = alert.get("data", {}) or {}
    return (
        syscheck.get("sha256_after")
        or syscheck.get("sha256_before")
        or data.get("sha256_after")
        or data.get("sha256")
        or syscheck.get("md5_after")
        or data.get("md5")
        or ""
    )


def extract_path(alert):
    """Cari file path dari berbagai possible path."""
    syscheck = alert.get("syscheck", {}) or {}
    data = alert.get("data", {}) or {}
    return syscheck.get("path") or data.get("path") or ""


def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    alert_file = sys.argv[1]
    hook_url = sys.argv[3] if len(sys.argv) > 3 else ""

    if not hook_url:
        with open("/var/ossec/logs/integrations.log", "a") as log:
            log.write("[custom-n8n] ERROR: hook_url tidak di-pass (argv[3])\n")
        sys.exit(1)

    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except Exception as e:
        with open("/var/ossec/logs/integrations.log", "a") as log:
            log.write(f"[custom-n8n] ERROR baca alert {alert_file}: {e}\n")
        sys.exit(1)

    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", ""))
    rule_level = rule.get("level", 0)

    # Threshold rendah; workflow severity classifier yang decide silent vs alert
    if rule_level < 5:
        sys.exit(0)

    agent = alert.get("agent", {}) or {}
    agent_id = str(agent.get("id", "000")).zfill(3)
    agent_name = agent.get("name", "unknown")
    srcip = (alert.get("data", {}) or {}).get("srcip", "0.0.0.0")
    timestamp = alert.get("timestamp", "")

    payload = {
        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": rule.get("description", ""),
        },
        "agent": {
            "id": agent_id,
            "name": agent_name,
        },
        "timestamp": timestamp,
        "model": "llama3.2:3b",
    }

    url_value = (alert.get("data", {}) or {}).get("url", "")
    hash_value = extract_hash(alert)
    file_path = extract_path(alert)

    if url_value:
        # Phishing: URL-based event (tidak ada noise filter karena URL events jarang)
        payload["data"] = {"url": url_value, "srcip": srcip}
    elif hash_value or file_path:
        # Malware/FIM: filter noisy paths dulu sebelum forward
        if is_noisy_path(file_path):
            sys.exit(0)
        payload["data"] = {
            "sha256_after": hash_value,
            "path": file_path,
            "srcip": srcip,
        }
        if alert.get("syscheck"):
            payload["syscheck"] = alert["syscheck"]
    else:
        sys.exit(0)

    try:
        data_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            hook_url,
            data=data_bytes,
            headers={"Content-Type": "application/json"},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception as e:
        with open("/var/ossec/logs/integrations.log", "a") as log:
            log.write(
                f"[custom-n8n] ERROR send rule={rule_id} url={hook_url}: {e}\n"
            )
        sys.exit(1)


if __name__ == "__main__":
    main()
