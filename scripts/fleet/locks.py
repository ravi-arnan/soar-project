"""Thread-safety locks and atomic file persistence helpers for fleet-monitor."""
import json
import os
import tempfile
import threading

STATE_LOCK = threading.RLock()
VT_CACHE_LOCK = threading.RLock()
SEEN_LOCK = threading.RLock()
COMMANDS_LOCK = threading.RLock()
METRICS_LOCK = threading.RLock()
SCAN_LOCK = threading.RLock()
WAZUH_LOCK = threading.RLock()
CF_SYNC_LOCK = threading.RLock()
API_KEY_TOUCH_LOCK = threading.RLock()
EVENTS_LOCK = threading.RLock()


def atomic_write_json(path, payload):
    """Tulis JSON ke file secara atomic dengan temp file unik per panggilan."""
    parent = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".fleet-tmp-", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
