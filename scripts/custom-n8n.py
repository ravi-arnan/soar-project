#!/var/ossec/framework/python/bin/python3
"""
Wazuh -> n8n SOAR integration (custom-n8n).

Forward Wazuh alerts ke n8n webhook dengan format nested yang sesuai struktur
yang diharapkan workflow. Webhook URL diambil dari argv[3] (di-pass oleh Wazuh
integratord dari <hook_url> di ossec.conf), jadi satu script handle multiple
integration block (malware + phishing + process chain).

Filter noise: skip path yang umumnya legitimate temp file / system activity.
"""

import json
import os
import sys
import time
import urllib.request


LOG_PATH = os.environ.get("SOAR_INTEGRATION_LOG", "/var/ossec/logs/integrations.log")
WEBHOOK_SECRET_FILE = os.environ.get(
    "N8N_WEBHOOK_SECRET_FILE", "/var/ossec/etc/soar-webhook.secret"
)
MAX_RETRIES = 3

# Path prefix yang dianggap noise (tidak forward ke n8n).
# Catatan: /var/tmp/ SENGAJA tidak diabaikan karena sering dipakai untuk staging malware Linux.
NOISY_PATH_PREFIXES = (
    # Container runtime
    "/tmp/runc-process",
    "/tmp/runc.",
    # Editor / IDE / staging
    "/tmp/claude-",
    "/tmp/.vscode-",
    "/tmp/custom-",
    # Window manager / desktop
    "/tmp/.X",
    "/tmp/.font-unix/",
    "/tmp/.ICE-unix/",
    "/tmp/.Test-unix/",
    "/tmp/.XIM-unix/",
    "/tmp/.com.google.",
    "/tmp/.org.chromium.",
    "/tmp/com.google.",
    "/tmp/org.chromium.",
    "/tmp/com.brave.",
    "/tmp/com.microsoft.",
    "/tmp/mozilla-",
    "/tmp/snap.",
    "/tmp/systemd-private",
    "/tmp/dbus-",
    "/tmp/ssh-",
    # Dev runtime / build cache
    "/tmp/node-compile-cache",
    "/tmp/v8-compile-cache",
    "/tmp/.bun/",
    "/tmp/yarn--",
    "/tmp/npm-",
    "/tmp/pip-",
    "/tmp/go-build",
    "/tmp/cargo-",
    # System cache / logs
    "/var/cache/",
    "/var/log/",
)


def _log(msg: str) -> None:
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as log:
            log.write(f"[custom-n8n] {msg}\n")
    except Exception:
        pass


def load_webhook_secret() -> str:
    env_val = os.environ.get("N8N_WEBHOOK_SECRET", "").strip()
    if env_val:
        return env_val
    try:
        if os.path.isfile(WEBHOOK_SECRET_FILE):
            with open(WEBHOOK_SECRET_FILE, "r", encoding="utf-8") as fh:
                return fh.read().strip()
    except Exception:
        pass
    return ""


def is_noisy_path(file_path: str) -> bool:
    """Return True kalau path masuk noise list (skip dari forwarding).

    Ekstensi container berbahaya (.iso, .dmg, .img) TIDAK diabaikan karena
    merupakan vektor Mark-of-the-Web bypass (T1553.005).
    """
    if not file_path:
        return False
    norm = file_path.replace("\\", "/").lower()
    if norm.startswith(NOISY_PATH_PREFIXES):
        return True
    if any(p in norm for p in ("/$recycle.bin/", "/system volume information/")):
        return True
    if norm.endswith(("/desktop.ini", "/thumbs.db", ".thumbs.db", ".ds_store")):
        return True
    return False


def extract_hash(alert: dict) -> str:
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


def extract_path(alert: dict) -> str:
    """Cari file path dari berbagai possible path."""
    syscheck = alert.get("syscheck", {}) or {}
    data = alert.get("data", {}) or {}
    return syscheck.get("path") or data.get("path") or ""


def extract_process_fields(alert: dict) -> dict:
    """Extract process chain fields dari Sysmon/4688 event."""
    data = alert.get("data", {}) or {}
    nested = data.get("data", {}) or {}
    sysmon = data.get("sysmon", {}) or {}
    win = data.get("win", {}) or {}
    eventdata = win.get("eventdata", {}) if isinstance(win, dict) else {}

    def _get(*names):
        for src in (sysmon, eventdata, nested, win, data):
            if not isinstance(src, dict):
                continue
            for n in names:
                v = src.get(n)
                if v:
                    return str(v)
        return ""

    parent_img = _get("parentImage", "ParentImage", "proc_parent_image")
    parent_name = parent_img.replace("\\", "/").rsplit("/", 1)[-1] if parent_img else ""

    return {
        "proc_image": _get("image", "Image", "proc_image"),
        "proc_parent_image": parent_img,
        "proc_cmdline": _get("commandLine", "CommandLine", "proc_cmdline"),
        "parent_name": parent_name,
    }


def build_webhook_payload(alert: dict) -> dict | None:
    """Bangun payload JSON untuk n8n, atau return None jika alert harus di-skip."""
    rule = alert.get("rule", {}) or {}
    rule_id = str(rule.get("id", ""))
    try:
        rule_level = int(rule.get("level", 0) or 0)
    except (ValueError, TypeError):
        rule_level = 0

    # Threshold rendah; workflow severity classifier yang memutuskan silent vs alert
    if rule_level < 5:
        return None

    agent = alert.get("agent", {}) or {}
    agent_id = str(agent.get("id", "000")).zfill(3)
    agent_name = agent.get("name", "unknown")
    srcip = (alert.get("data", {}) or {}).get("srcip", "0.0.0.0")
    timestamp = alert.get("timestamp", "")
    proc = extract_process_fields(alert)

    payload = {
        "rule": {
            "id": rule_id,
            "level": rule_level,
            "description": rule.get("description", ""),
        },
        "agent": {"id": agent_id, "name": agent_name},
        "timestamp": timestamp,
    }

    url_value = (alert.get("data", {}) or {}).get("url", "")
    hash_value = extract_hash(alert)
    file_path = extract_path(alert)

    if rule_id.startswith("1100") and rule_id.isdigit():
        raw = alert.get("data", {}) or {}
        payload["data"] = dict(raw) if isinstance(raw, dict) else {}
        payload["data"]["event_type"] = "process_chain"
        payload["data"]["proc_image"] = proc["proc_image"]
        payload["data"]["proc_parent_image"] = proc["proc_parent_image"]
        payload["data"]["proc_cmdline"] = proc["proc_cmdline"]
    elif url_value:
        payload["data"] = {"url": url_value, "srcip": srcip}
    elif hash_value or file_path:
        if is_noisy_path(file_path):
            return None
        payload["data"] = {
            "sha256_after": hash_value,
            "path": file_path,
            "srcip": srcip,
        }
        if alert.get("syscheck"):
            payload["syscheck"] = alert["syscheck"]
    else:
        return None

    return payload


def send_with_retry(hook_url: str, payload: dict, secret: str = "", sleep_fn=time.sleep) -> None:
    """Kirim payload JSON ke webhook n8n dengan retry backoff (3x)."""
    data_bytes = json.dumps(payload).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-SOAR-Webhook-Secret"] = secret

    last_err = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            req = urllib.request.Request(hook_url, data=data_bytes, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status < 400:
                    return
                last_err = RuntimeError(f"HTTP {resp.status}")
        except Exception as exc:
            last_err = exc
        if attempt < MAX_RETRIES:
            sleep_fn(2 ** (attempt - 1))
    raise last_err


def main():
    if len(sys.argv) < 2:
        sys.exit(1)

    alert_file = sys.argv[1]
    hook_url = sys.argv[3] if len(sys.argv) > 3 else ""

    if not hook_url:
        _log("ERROR: hook_url tidak di-pass (argv[3])")
        sys.exit(1)

    try:
        with open(alert_file, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        _log(f"ERROR baca alert {alert_file}: {e}")
        sys.exit(1)

    payload = build_webhook_payload(alert)
    if payload is None:
        sys.exit(0)

    rule_id = payload["rule"]["id"]
    try:
        send_with_retry(hook_url, payload, secret=load_webhook_secret())
    except Exception as e:
        _log(f"ERROR send rule={rule_id} url={hook_url} after {MAX_RETRIES}x: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
