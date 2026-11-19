#!/usr/bin/env python3
"""Telegram callback poller - jembatan SOAR human-in-the-loop.

Env:
  TELEGRAM_BOT_TOKEN          token bot (wajib)
  N8N_WEBHOOK                 URL webhook n8n (default http://127.0.0.1:5678/webhook/tg-callback)
  N8N_WEBHOOK_SECRET          opsional; dikirim di header X-SOAR-Webhook-Secret
  TELEGRAM_ALLOWED_CHAT_IDS   opsional; daftar chat ID yang diizinkan (dipisah koma)
  TELEGRAM_ALLOWED_USER_IDS   opsional; daftar user ID yang diizinkan (dipisah koma)
  TG_POLLER_OFFSET_FILE       opsional; path file persist offset getUpdates
"""
import json
import os
import re
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
N8N_WEBHOOK = os.environ.get("N8N_WEBHOOK", "http://127.0.0.1:5678/webhook/tg-callback")
WEBHOOK_SECRET = os.environ.get("N8N_WEBHOOK_SECRET", "").strip()
OFFSET_FILE = os.environ.get("TG_POLLER_OFFSET_FILE", "").strip()
MAX_FAILURES_PER_UPDATE = int(os.environ.get("TG_POLLER_MAX_RETRIES", "3"))


def _parse_id_set(raw):
    out = set()
    for part in (raw or "").split(","):
        p = part.strip()
        if p:
            out.add(p)
    return out


ALLOWED_CHAT_IDS = _parse_id_set(os.environ.get("TELEGRAM_ALLOWED_CHAT_IDS", ""))
ALLOWED_USER_IDS = _parse_id_set(os.environ.get("TELEGRAM_ALLOWED_USER_IDS", ""))
_FAILURE_COUNTS = {}


def _sanitize_error(err):
    msg = str(err)
    if TOKEN:
        msg = msg.replace(TOKEN, "[REDACTED]")
    return re.sub(r"bot[0-9]+:[A-Za-z0-9_-]+", "bot[REDACTED]", msg)


def _load_offset(path=None):
    p = path or OFFSET_FILE
    if not p or not os.path.exists(p):
        return 0
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        return max(0, int(data.get("offset", 0)))
    except (OSError, ValueError, TypeError):
        return 0


def _save_offset(offset, path=None):
    p = path or OFFSET_FILE
    if not p:
        return
    try:
        parent = os.path.dirname(os.path.abspath(p)) or "."
        os.makedirs(parent, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".tg-off-", suffix=".json", dir=parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"offset": int(offset), "saved_at": time.time()}, f)
            os.replace(tmp, p)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except OSError:
        pass


def api_get(method, params, timeout=70):
    api_base = f"https://api.telegram.org/bot{TOKEN}"
    url = f"{api_base}/{method}?" + urllib.parse.urlencode(params)
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.load(r)


def is_sender_allowed(update, allowed_chats=None, allowed_users=None):
    chats = ALLOWED_CHAT_IDS if allowed_chats is None else allowed_chats
    users = ALLOWED_USER_IDS if allowed_users is None else allowed_users
    if not chats and not users:
        return True
    cq = update.get("callback_query") or {}
    chat_id = str(((cq.get("message") or {}).get("chat") or {}).get("id", "")).strip()
    user_id = str((cq.get("from") or {}).get("id", "")).strip()
    if chats and chat_id not in chats:
        return False
    if users and user_id not in users:
        return False
    return True


def forward(update, webhook_url=None, webhook_secret=None):
    """Kirim update callback_query ke n8n.
    Kembalikan True jika n8n membalas HTTP 2xx, False bila gagal/error.
    """
    target = webhook_url or N8N_WEBHOOK
    secret = WEBHOOK_SECRET if webhook_secret is None else webhook_secret
    data = json.dumps(update).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if secret:
        headers["X-SOAR-Webhook-Secret"] = secret
    req = urllib.request.Request(target, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            status = getattr(r, "status", 200)
            if 200 <= status < 300:
                print(f"forwarded callback_query {update.get('update_id')}", flush=True)
                return True
            print(f"forward error: status {status}", flush=True)
            return False
    except Exception as e:
        print(f"forward error: {_sanitize_error(e)}", flush=True)
        return False


def process_updates(
    updates,
    webhook_url=None,
    failure_counts=None,
    max_retries=MAX_FAILURES_PER_UPDATE,
    allowed_chats=None,
    allowed_users=None,
):
    """Proses daftar update dari getUpdates.
    Kembalikan (new_offset, success_count, pending_failure).
    Jika forward gagal untuk suatu update, offset ditahan hingga max_retries
    lalu di-dead-letter agar 1 callback rusak tidak memblokir seluruh antrean.
    """
    counts = _FAILURE_COUNTS if failure_counts is None else failure_counts
    processed = 0
    for upd in updates:
        uid = upd.get("update_id")
        if uid is None:
            continue
        if "callback_query" in upd:
            if not is_sender_allowed(upd, allowed_chats=allowed_chats, allowed_users=allowed_users):
                print(f"rejected unauthorized callback_query update_id={uid}", flush=True)
                counts.pop(uid, None)
                processed += 1
                continue
            if not forward(upd, webhook_url=webhook_url):
                tries = counts.get(uid, 0) + 1
                counts[uid] = tries
                if tries >= max(1, max_retries):
                    print(
                        f"dead-letter update_id={uid} setelah {tries} kegagalan, lanjut ke update berikutnya",
                        flush=True,
                    )
                    counts.pop(uid, None)
                    processed += 1
                    continue
                print(
                    f"forward gagal untuk update_id={uid} (percobaan {tries}/{max_retries}), offset ditahan",
                    flush=True,
                )
                return uid, processed, True
            counts.pop(uid, None)
        processed += 1
    if updates:
        return updates[-1]["update_id"] + 1, processed, False
    return None, 0, False


def main():
    if not TOKEN:
        raise SystemExit("TELEGRAM_BOT_TOKEN wajib diisi")

    try:
        api_get("deleteWebhook", {}, timeout=15)
    except Exception:
        pass

    offset = _load_offset()
    backoff = 2
    print(f"poller start -> {N8N_WEBHOOK} (offset={offset})", flush=True)
    while True:
        try:
            params = {
                "offset": offset,
                "timeout": 50,
                "allowed_updates": json.dumps(["callback_query"]),
            }
            resp = api_get("getUpdates", params, timeout=70)
            if not isinstance(resp, dict) or not resp.get("ok"):
                print(f"getUpdates non-ok response: {resp}", flush=True)
                time.sleep(backoff)
                backoff = min(backoff * 2, 30)
                continue
            backoff = 2
            updates = resp.get("result", [])
            new_offset, _count, failed = process_updates(updates)
            if new_offset is not None:
                offset = new_offset
                _save_offset(offset)
            if failed:
                time.sleep(3)
        except urllib.error.URLError as e:
            print(f"poll error: {_sanitize_error(e)} (retry dalam {backoff}s)", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)
        except Exception as e:
            print(f"err: {_sanitize_error(e)} (retry dalam {backoff}s)", flush=True)
            time.sleep(backoff)
            backoff = min(backoff * 2, 30)


if __name__ == "__main__":
    main()
