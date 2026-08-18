#!/usr/bin/env python3
"""SOAR self-aware health monitor (kategori F — sadar-degradasi).

Menutup keluhan industri teratas: automasi yang GAGAL DIAM-DIAM. Pipeline SOAR
bisa "hidup" tapi buta — agent putus (cakupan deteksi hilang), n8n mati (alert
tak terproses), atau Ollama/Wazuh-API tak reachable. Tanpa pemantau, tak ada
yang tahu sampai insiden lolos.

Monitor ini poll komponen inti tiap interval dan HANYA kirim Telegram saat
STATUS BERUBAH (sehat->degradasi atau pulih), jadi tidak spam. State disimpan ke
disk supaya transisi tidak dikirim ulang tiap restart.

Cek:
  - Wazuh Manager API   -> tiap agent: active? (disconnected = blind spot)
  - n8n                 -> /healthz reachable
  - Ollama              -> /api/version reachable

Env (lihat .env.example):
  TELEGRAM_BOT_TOKEN   token bot (wajib)
  TELEGRAM_CHAT_ID     chat tujuan alert kesehatan (wajib)
  WAZUH_API_URL        default https://host.docker.internal:55000
  WAZUH_API_USER       default wazuh-wui
  WAZUH_API_PASS       password API (wajib untuk cek agent)
  N8N_HEALTH_URL       default http://n8n:5678/healthz
  OLLAMA_URL           default http://host.docker.internal:11434/api/version
  HEALTH_INTERVAL      detik antar-poll (default 60)
  HEALTH_STATE_FILE    default /state/health.json
"""
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

WITA = timezone(timedelta(hours=8))  # Asia/Makassar, tanpa DST
# ponytail: Wazuh API self-signed -> verifikasi TLS dimatikan. Upgrade path:
# mount CA Wazuh & pakai ssl.create_default_context(cafile=...) kalau perlu.
_INSECURE = ssl.create_default_context()
_INSECURE.check_hostname = False
_INSECURE.verify_mode = ssl.CERT_NONE


def _cfg():
    return {
        "token": os.environ["TELEGRAM_BOT_TOKEN"],
        "chat_id": os.environ["TELEGRAM_CHAT_ID"],
        "wazuh_url": os.environ.get("WAZUH_API_URL", "https://host.docker.internal:55000").rstrip("/"),
        "wazuh_user": os.environ.get("WAZUH_API_USER", "wazuh-wui"),
        "wazuh_pass": os.environ.get("WAZUH_API_PASS", ""),
        "n8n_url": os.environ.get("N8N_HEALTH_URL", "http://n8n:5678/healthz"),
        "ollama_url": os.environ.get("OLLAMA_URL", "http://host.docker.internal:11434/api/version"),
        "interval": int(os.environ.get("HEALTH_INTERVAL", "60")),
        "state_file": os.environ.get("HEALTH_STATE_FILE", "/state/health.json"),
    }


def _get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers=headers or {})
    return urllib.request.urlopen(req, timeout=timeout, context=_INSECURE)


def check_http(url):
    """True kalau endpoint balas 2xx."""
    try:
        with _get(url) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def check_wazuh_agents(cfg):
    """Kembalikan {agent_label: ok_bool}. Key khusus '_wazuh_api' menandai API itu
    sendiri reachable. Kalau API down, agent tak bisa dinilai (dilewati)."""
    try:
        auth = base64.b64encode(f"{cfg['wazuh_user']}:{cfg['wazuh_pass']}".encode()).decode()
        with _get(f"{cfg['wazuh_url']}/security/user/authenticate",
                  headers={"Authorization": f"Basic {auth}"}) as r:
            token = json.load(r)["data"]["token"]
        with _get(f"{cfg['wazuh_url']}/agents?select=id,name,status&limit=500",
                  headers={"Authorization": f"Bearer {token}"}) as r:
            agents = json.load(r)["data"]["affected_items"]
    except Exception:
        return {"_wazuh_api": False}

    out = {"_wazuh_api": True}
    for a in agents:
        # agent 000 = manager itu sendiri, selalu "active"; tetap dilaporkan.
        label = f"agent {a.get('id', '???')} ({a.get('name', '?')})"
        out[label] = a.get("status") == "active"
    return out


def collect(cfg):
    """Snapshot kesehatan seluruh komponen -> {component: ok_bool}."""
    status = {
        "n8n": check_http(cfg["n8n_url"]),
        "ollama": check_http(cfg["ollama_url"]),
    }
    status.update(check_wazuh_agents(cfg))
    return status


def compute_transitions(prev, curr):
    """Bandingkan dua snapshot -> daftar (component, kind, ok).

    kind: 'down' (ok->gagal / muncul-baru-gagal) atau 'up' (gagal->ok).
    Komponen yang hilang dari curr diabaikan (mis. agent dihapus). Snapshot
    pertama (prev kosong): hanya laporkan yang GAGAL, jangan banjiri yang sehat.
    """
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
        lines.append("⚠️ SOAR TERDEGRADASI — komponen berhenti sehat:")
        lines += [f"• {c}" for c in down]
    if up:
        if lines:
            lines.append("")
        lines.append("✅ SOAR PULIH — komponen kembali sehat:")
        lines += [f"• {c}" for c in up]
    lines.append(f"\n\U0001f550 {now}")
    return "\n".join(lines)


def send_telegram(cfg, text):
    # Plain text (tanpa parse_mode) — alert kesehatan tak boleh gagal terkirim
    # gara-gara hostname memuat char markdown (lihat DEPLOYMENT: parse error).
    body = json.dumps({
        "chat_id": cfg["chat_id"],
        "text": text,
        "disable_notification": False,
    }).encode()
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{cfg['token']}/sendMessage",
        data=body, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=15).read()
    except Exception as e:
        print(f"telegram error: {e}", flush=True)


def _load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(path, state):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"state save error: {e}", flush=True)


def main():
    cfg = _cfg()
    prev = _load_state(cfg["state_file"])
    print(f"health-monitor start (interval={cfg['interval']}s)", flush=True)
    while True:
        curr = collect(cfg)
        transitions = compute_transitions(prev, curr)
        if transitions:
            msg = _fmt(transitions)
            send_telegram(cfg, msg)
            print(f"transitions: {[(c, k) for c, k, _ in transitions]}", flush=True)
        prev = curr
        _save_state(cfg["state_file"], curr)
        time.sleep(cfg["interval"])


def _selftest():
    # snapshot pertama: hanya yang gagal dilaporkan, yang sehat diam
    t = compute_transitions({}, {"n8n": True, "ollama": False})
    assert t == [("ollama", "down", False)], t
    # sehat -> gagal = down; gagal -> sehat = up
    t = compute_transitions({"n8n": True, "ollama": False},
                            {"n8n": False, "ollama": True})
    assert ("n8n", "down", False) in t and ("ollama", "up", True) in t, t
    # tidak ada perubahan = tidak ada alert (anti-spam)
    assert compute_transitions({"n8n": True}, {"n8n": True}) == []
    # agent baru muncul dalam keadaan disconnected = down
    t = compute_transitions({}, {"agent 003 (x)": False})
    assert t == [("agent 003 (x)", "down", False)], t
    # komponen hilang dari snapshot diabaikan
    assert compute_transitions({"gone": False}, {"n8n": True}) == []
    print("selftest OK")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    else:
        main()
