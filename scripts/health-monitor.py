#!/usr/bin/env python3
"""SOAR self-aware health monitor (sadar-degradasi).

Poll seluruh komponen inti SOAR secara berkala dan hanya mengirim notifikasi
Telegram saat status komponen berubah secara terkonfirmasi (hysteresis 2x untuk
down transition agar tidak spam saat transient flap).

Komponen yang dipantau:
  - n8n                 (/healthz)
  - wazuh_api + agents  (Wazuh Manager API)
  - fleet_monitor       (/healthz) + Rust agents (/api/fleet dengan Bearer token)
  - dashboard           (/api/config/public)
  - misp_index          (/healthz)
  - alert_log           (/healthz)
  - llm_key             (GEMINI_API_KEY / POLLINATIONS_API_KEY / HCNSEC_API_KEY)
"""

import base64
import json
import os
import ssl
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

WITA = timezone(timedelta(hours=8))
_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


def _cfg():
    return {
        "token": os.environ["TELEGRAM_BOT_TOKEN"],
        "chat_id": os.environ["TELEGRAM_CHAT_ID"],
        "wazuh_url": os.environ.get("WAZUH_API_URL", "https://127.0.0.1:55000").rstrip("/"),
        "wazuh_user": os.environ.get("WAZUH_API_USER", "wazuh-wui"),
        "wazuh_pass": os.environ.get("WAZUH_API_PASS", ""),
        "n8n_url": os.environ.get("N8N_HEALTH_URL", "http://127.0.0.1:5678/healthz"),
        "fleet_url": os.environ.get("FLEET_URL", "http://127.0.0.1:8080").rstrip("/"),
        "fleet_token": os.environ.get("FLEET_COMMAND_TOKEN", ""),
        "dashboard_url": os.environ.get("DASHBOARD_URL", "http://127.0.0.1:3000").rstrip("/"),
        "misp_url": os.environ.get("MISP_URL", "http://127.0.0.1:8090").rstrip("/"),
        "alert_log_url": os.environ.get("ALERT_LOG_URL", "http://127.0.0.1:8091").rstrip("/"),
        "gemini_key": os.environ.get("GEMINI_API_KEY", ""),
        "pollinations_key": os.environ.get("POLLINATIONS_API_KEY", ""),
        "hcnsec_key": os.environ.get("HCNSEC_API_KEY", ""),
        "interval": int(os.environ.get("HEALTH_INTERVAL", "60")),
        "fail_threshold": max(1, int(os.environ.get("HEALTH_FAIL_THRESHOLD", "2"))),
        "state_file": os.environ.get("HEALTH_STATE_FILE", "/state/health.json"),
        "ping_url": os.environ.get("HEALTHCHECK_PING_URL", "").strip(),
    }


def _get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    return urllib.request.urlopen(req, timeout=timeout, context=_INSECURE)


def check_http(url, headers=None):
    """Return True jika endpoint mengembalikan HTTP 2xx."""
    try:
        with _get(url, headers=headers) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def check_wazuh_agents(cfg):
    """Kembalikan {agent_label: ok_bool}. Key '_wazuh_api' menandai API reachable."""
    try:
        auth = base64.b64encode(
            f"{cfg['wazuh_user']}:{cfg['wazuh_pass']}".encode()
        ).decode()
        with _get(
            f"{cfg['wazuh_url']}/security/user/authenticate",
            headers={"Authorization": f"Basic {auth}"},
        ) as r:
            token = json.load(r)["data"]["token"]
        with _get(
            f"{cfg['wazuh_url']}/agents?select=id,name,status&limit=500",
            headers={"Authorization": f"Bearer {token}"},
        ) as r:
            agents = json.load(r)["data"]["affected_items"]
    except Exception:
        return {"_wazuh_api": False}

    out = {"_wazuh_api": True}
    for a in agents:
        label = f"agent {a.get('id', '???')} ({a.get('name', '?')})"
        out[label] = a.get("status") == "active"
    return out


def check_fleet_and_rust_agents(cfg):
    """Probe fleet-monitor /healthz serta status Rust agents via /api/fleet."""
    fleet_base = cfg.get("fleet_url", "").rstrip("/")
    if not fleet_base:
        return {}
    out = {"fleet_monitor": check_http(f"{fleet_base}/healthz")}
    if not out["fleet_monitor"]:
        return out
    token = (cfg.get("fleet_token") or "").strip()
    if not token:
        return out
    try:
        with _get(
            f"{fleet_base}/api/fleet",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        ) as r:
            data = json.load(r)
        for a in data.get("agents", []):
            if a.get("type") == "rust":
                label = f"rust-agent {a.get('id', '???')} ({a.get('name', '?')})"
                out[label] = str(a.get("status", "")).lower() == "active"
    except Exception:
        pass
    return out


def collect(cfg, prev=None):
    """Snapshot kesehatan seluruh komponen -> {component: ok_bool}."""
    has_llm = bool(
        cfg.get("gemini_key") or cfg.get("pollinations_key") or cfg.get("hcnsec_key")
    )
    status = {
        "n8n": check_http(cfg["n8n_url"]),
        "llm_key": has_llm,
    }
    if cfg.get("dashboard_url"):
        status["dashboard"] = check_http(f"{cfg['dashboard_url']}/api/config/public")
    if cfg.get("misp_url"):
        status["misp_index"] = check_http(f"{cfg['misp_url']}/healthz")
    if cfg.get("alert_log_url"):
        status["alert_log"] = check_http(f"{cfg['alert_log_url']}/healthz")

    fleet_status = check_fleet_and_rust_agents(cfg)
    if not fleet_status.get("fleet_monitor", True) and prev:
        for k, v in prev.items():
            if k.startswith("rust-agent "):
                fleet_status[k] = v
    status.update(fleet_status)

    wazuh_status = check_wazuh_agents(cfg)
    if not wazuh_status.get("_wazuh_api", False) and prev:
        for k, v in prev.items():
            if k.startswith("agent "):
                wazuh_status[k] = v
    status.update(wazuh_status)
    return status


def apply_hysteresis(prev, raw_curr, fail_streaks, fail_threshold=2):
    """Terapkan hysteresis untuk status down (membutuhkan fail_threshold kali gagal beruntun).

    Mengembalikan (effective_curr, updated_streaks).
    Pemulihan (up) langsung diteruskan tanpa penundaan.
    """
    effective = {}
    new_streaks = {}
    for comp, ok in raw_curr.items():
        if ok:
            effective[comp] = True
            new_streaks[comp] = 0
        else:
            streak = int(fail_streaks.get(comp, 0)) + 1
            new_streaks[comp] = streak
            if streak >= fail_threshold or prev.get(comp) is False:
                effective[comp] = False
            else:
                # Belum memenuhi ambang batas down; pertahankan status sehat sebelumnya
                effective[comp] = prev.get(comp, True)
    return effective, new_streaks


def compute_transitions(prev, curr):
    """Bandingkan dua snapshot -> daftar (component, kind, ok)."""
    transitions = []
    first_run = not prev
    for comp, ok in curr.items():
        was = prev.get(comp)
        if first_run:
            if not ok:
                transitions.append((comp, "down", ok))
        elif was is True and ok is False:
            transitions.append((comp, "down", ok))
        elif was is False and ok is True:
            transitions.append((comp, "up", ok))
        elif was is None and ok is False:
            transitions.append((comp, "down", ok))
    return transitions


def _fmt(transitions):
    now = datetime.now(WITA).strftime("%Y-%m-%d %H:%M:%S WITA")
    down = [c for c, k, _ in transitions if k == "down"]
    up = [c for c, k, _ in transitions if k == "up"]
    lines = []
    if down:
        lines.append("[ALERT] SOAR TERDEGRADASI (komponen berhenti sehat):")
        lines += [f"- {c}" for c in down]
    if up:
        if lines:
            lines.append("")
        lines.append("[OK] SOAR PULIH (komponen kembali sehat):")
        lines += [f"- {c}" for c in up]
    lines.append(f"\nWaktu: {now}")
    return "\n".join(lines)


def send_telegram(cfg, text):
    """Kirim pesan plain text ke Telegram. Return True jika sukses (ok=true)."""
    body = json.dumps(
        {
            "chat_id": cfg["chat_id"],
            "text": text,
            "disable_notification": False,
        }
    ).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{cfg['token']}/sendMessage",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            raw = r.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw else {}
            if 200 <= r.status < 300 and data.get("ok", True):
                return True
            print(f"telegram non-ok response: HTTP {r.status}", flush=True)
            return False
    except Exception as e:
        msg = str(e).replace(cfg.get("token", ""), "***")
        print(f"telegram error: {msg}", flush=True)
        return False


def ping_deadman(cfg):
    """Ping URL dead-man's switch eksternal (mis. healthchecks.io) bila dikonfigurasi."""
    ping_url = cfg.get("ping_url", "")
    if not ping_url:
        return
    try:
        with urllib.request.urlopen(urllib.request.Request(ping_url), timeout=10) as r:
            r.read(64)
    except Exception as e:
        print(f"deadman ping error: {e}", flush=True)


def _load_state(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, dict) and "status" in data and isinstance(data["status"], dict):
                return data["status"], data.get("streaks", {})
            if isinstance(data, dict):
                return data, {}
    except Exception:
        pass
    return {}, {}


def _save_state(path, state, streaks=None):
    try:
        parent = os.path.dirname(path) or "."
        os.makedirs(parent, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=parent, prefix=".health.")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump({"status": state, "streaks": streaks or {}}, f)
        os.replace(tmp, path)
    except Exception as e:
        print(f"state save error: {e}", flush=True)


def run_tick(cfg, prev, streaks):
    """Jalankan satu siklus probe -> hysteresis -> transisi -> kirim Telegram -> update state."""
    raw_curr = collect(cfg, prev=prev)
    curr, new_streaks = apply_hysteresis(
        prev, raw_curr, streaks, fail_threshold=cfg.get("fail_threshold", 2)
    )
    transitions = compute_transitions(prev, curr)
    if transitions:
        msg = _fmt(transitions)
        sent = send_telegram(cfg, msg)
        if not sent:
            # Jangan timpa prev saat Telegram gagal agar alert dicoba ulang pada siklus berikutnya
            return prev, new_streaks, False
        print(f"transitions: {[(c, k) for c, k, _ in transitions]}", flush=True)
    _save_state(cfg["state_file"], curr, new_streaks)
    if all(curr.values()):
        ping_deadman(cfg)
    return curr, new_streaks, True


def main():
    cfg = _cfg()
    prev, streaks = _load_state(cfg["state_file"])
    print(f"health-monitor start (interval={cfg['interval']}s, threshold={cfg['fail_threshold']})", flush=True)
    while True:
        prev, streaks, _ = run_tick(cfg, prev, streaks)
        time.sleep(cfg["interval"])


def _selftest():
    t = compute_transitions({}, {"n8n": True, "misp_index": False})
    assert t == [("misp_index", "down", False)], t
    t = compute_transitions({"n8n": True, "misp_index": False}, {"n8n": False, "misp_index": True})
    assert ("n8n", "down", False) in t and ("misp_index", "up", True) in t, t
    assert compute_transitions({"n8n": True}, {"n8n": True}) == []
    eff1, s1 = apply_hysteresis({"n8n": True}, {"n8n": False}, {}, fail_threshold=2)
    assert eff1["n8n"] is True and s1["n8n"] == 1
    eff2, s2 = apply_hysteresis(eff1, {"n8n": False}, s1, fail_threshold=2)
    assert eff2["n8n"] is False and s2["n8n"] == 2
    fmt_msg = _fmt([("n8n", "down", False), ("misp_index", "up", True)])
    assert "\u2014" not in fmt_msg and "\u2013" not in fmt_msg, fmt_msg
    print("selftest OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        main()
