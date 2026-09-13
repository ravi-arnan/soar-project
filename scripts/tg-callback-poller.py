#!/usr/bin/env python3
"""Telegram callback poller - jembatan SOAR human-in-the-loop.

n8n Telegram Trigger berbasis webhook (butuh URL publik). SOAR ini jalan di
balik NAT/Tailscale, jadi alih-alih webhook, kita long-poll getUpdates di sini
(koneksi keluar saja) dan teruskan HANYA update callback_query (klik tombol)
ke n8n Webhook node lokal. Tidak ada port n8n yang diekspos ke publik.

Env:
  TELEGRAM_BOT_TOKEN  token bot (wajib)
  N8N_WEBHOOK         URL webhook n8n (default http://n8n:5678/webhook/tg-callback)
"""
import os
import json
import time
import urllib.parse
import urllib.request
import urllib.error

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
N8N_WEBHOOK = os.environ.get("N8N_WEBHOOK", "http://n8n:5678/webhook/tg-callback")
API = f"https://api.telegram.org/bot{TOKEN}"


def api_get(method, params):
    url = f"{API}/{method}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=70) as r:
        return json.load(r)


def forward(update):
    data = json.dumps(update).encode()
    req = urllib.request.Request(
        N8N_WEBHOOK, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        urllib.request.urlopen(req, timeout=30).read()
        print(f"forwarded callback_query {update.get('update_id')}", flush=True)
    except Exception as e:
        print(f"forward error: {e}", flush=True)


def main():
    # Pastikan tidak ada webhook aktif di bot (kalau ada, getUpdates ditolak 409).
    try:
        api_get("deleteWebhook", {})
    except Exception:
        pass

    offset = 0
    print(f"poller start -> {N8N_WEBHOOK}", flush=True)
    while True:
        try:
            resp = api_get(
                "getUpdates",
                {
                    "offset": offset,
                    "timeout": 50,
                    "allowed_updates": json.dumps(["callback_query"]),
                },
            )
            for upd in resp.get("result", []):
                offset = upd["update_id"] + 1
                if "callback_query" in upd:
                    forward(upd)
        except urllib.error.URLError as e:
            print(f"poll error: {e}", flush=True)
            time.sleep(5)
        except Exception as e:
            print(f"err: {e}", flush=True)
            time.sleep(5)


if __name__ == "__main__":
    main()
