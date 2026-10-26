#!/usr/bin/env python3
"""Telegram callback poller - jembatan SOAR human-in-the-loop.

n8n Telegram Trigger berbasis webhook (butuh URL publik). SOAR ini jalan di
balik NAT/Tailscale, jadi alih-alih webhook, kita long-poll getUpdates di sini
(koneksi keluar saja) dan teruskan HANYA update callback_query (klik tombol)
ke n8n Webhook node lokal. Tidak ada port n8n yang diekspos ke publik.

Env:
  TELEGRAM_BOT_TOKEN  token bot (wajib)
  N8N_WEBHOOK         URL webhook n8n (default http://127.0.0.1:5678/webhook/tg-callback)
"""
import os
import json
import time
import urllib.parse
import urllib.request
import urllib.error

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
N8N_WEBHOOK = os.environ.get("N8N_WEBHOOK", "http://127.0.0.1:5678/webhook/tg-callback")
API = f"https://api.telegram.org/bot{TOKEN}"


def api_get(method, params, timeout=70):
    url = f"{API}/{method}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def forward(update, webhook_url=None):
    """Kirim update callback_query ke n8n.
    Kembalikan True jika n8n membalas HTTP 2xx, False bila gagal/error.
    """
    target = webhook_url or N8N_WEBHOOK
    data = json.dumps(update).encode()
    req = urllib.request.Request(
        target, data=data, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status = getattr(r, "status", 200)
            if 200 <= status < 300:
                print(f"forwarded callback_query {update.get('update_id')}", flush=True)
                return True
            print(f"forward error: status {status}", flush=True)
            return False
    except Exception as e:
        print(f"forward error: {e}", flush=True)
        return False


def process_updates(updates, webhook_url=None):
    """Proses daftar update dari getUpdates.
    Kembalikan (new_offset, success_count, pending_failure).
    Jika forward gagal untuk suatu update, proses berhenti di update tersebut
    dan offset TIDAK dinaikkan melewati update yang gagal agar bisa diulang.
    """
    processed = 0
    for upd in updates:
        uid = upd.get("update_id")
        if uid is None:
            continue
        if "callback_query" in upd:
            if not forward(upd, webhook_url=webhook_url):
                print(
                    f"forward gagal untuk update_id={uid}, offset ditahan untuk retry",
                    flush=True,
                )
                return uid, processed, True
        processed += 1
    if updates:
        return updates[-1]["update_id"] + 1, processed, False
    return None, 0, False


def main():
    if not TOKEN:
        raise SystemExit("TELEGRAM_BOT_TOKEN wajib diisi")

    # Pastikan tidak ada webhook aktif di bot (kalau ada, getUpdates ditolak 409).
    try:
        api_get("deleteWebhook", {}, timeout=15)
    except Exception:
        pass

    offset = 0
    backoff = 2
    print(f"poller start -> {N8N_WEBHOOK}", flush=True)
    while True:
        try:
            params = {
                "offset": offset,
                "timeout": 50,
                "allowed_updates": json.dumps(["callback_query"]),
            }
            resp = api_get("getUpdates", params, timeout=70)
            backoff = 2  # reset backoff bila berhasil terhubung
            updates = resp.get("result", [])
            new_offset, count, failed = process_updates(updates)
            if new_offset is not None:
                offset = new_offset
            if failed:
                time.sleep(3)
        except urllib.error.URLError as e:
            print(f"poll error: {e} (retry dalam {backoff}s)", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
        except Exception as e:
            print(f"err: {e} (retry dalam {backoff}s)", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)


if __name__ == "__main__":
    main()
