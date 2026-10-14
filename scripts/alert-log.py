#!/usr/bin/env python3
"""Pencatat alert Telegram keluar + registry keputusan analis (SOAR).

Dua peran, satu service:

1. **Observability alert keluar** (peran asli). n8n mem-POST setiap alert
   Telegram yang benar-benar terkirim ke sini; service menyimpannya sebagai
   JSONL (durable) di `state/telegram-alerts.jsonl`. Bot API Telegram TIDAK
   menyediakan histori pesan keluar, jadi kita catat sendiri di titik kirim.

2. **Registry keputusan analis (HITL)** — inti matriks confidence -> otonomi
   (milestone M3). Saat sebuah deteksi masuk jalur HITL, n8n mendaftarkan
   deteksi tertunda (per **hash**) di sini SEBELUM mengirim notifikasi, dan
   tombol inline di Telegram membawa hash (bukan path) supaya aksinya
   tepat-sasaran meski teks pesan di-escape Markdown. Registry menyediakan:
   - sumber kebenaran target aksi (path/agent) saat analis menekan tombol;
   - **batas waktu (deadline)** agar item HITL yang tak direspons bisa
     dieskalasi, bukan hilang diam-diam;
   - **audit trail** keputusan (siapa, kapan, aksi apa, berapa lama respons)
     yang bertahan lintas restart -> bukti bab evaluasi.

Tier non-HITL (otomatis/observasi) juga didaftarkan supaya setiap aksi analis
tercatat di audit trail, tetapi `hitl=false` sehingga tanpa tenggat eskalaasi.

Env:
  ALERT_LOG_FILE              default /state/telegram-alerts.jsonl
  ALERT_LOG_PORT              default 8091
  ALERT_DECISION_FILE         default <dir ALERT_LOG_FILE>/decisions.json
  ALERT_DECISION_AUDIT_FILE   default <dir>/decisions-audit.jsonl
  ALERT_DECISION_TTL_SECS     default 21600 (6 jam) -> pending kedaluwarsa
  ALERT_LOG_TOKEN             opsional; bila diisi, endpoint tulis keputusan
                              wajib header `Authorization: Bearer <token>`

Endpoint:
  POST /log   {..} atau [{..}]        -> {"ok":true,"stored":N}
  GET  /log?limit=50                  -> {"count":N,"items":[...]}
  GET  /stats                         -> total, by_severity/by_workflow, decisions
  POST /decision/pending  {hash,agent_id,filepath,severity,hitl,deadline_secs?}
  POST /decision/resolve  {hash|did,action,by,note?}
                                  -> {ok,found,filepath,agent_id,severity,dst}
  POST /decision/escalate {hash}      -> tandai sudah dieskalasi (anti-spam SLA)
  GET  /decision/pending?overdue=1&all=1&limit=
  GET  /decision/audit?limit=&hash=
  GET  /healthz
"""
import hmac
import json
import os
import re
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOG_FILE = os.getenv("ALERT_LOG_FILE", "state/telegram-alerts.jsonl")
PORT = int(os.getenv("ALERT_LOG_PORT", "8091"))
DECISION_FILE = os.getenv("ALERT_DECISION_FILE", "")
DECISION_AUDIT_FILE = os.getenv("ALERT_DECISION_AUDIT_FILE", "")
DECISION_TTL_SECS = int(os.getenv("ALERT_DECISION_TTL_SECS", "21600"))
LOG_TOKEN = os.getenv("ALERT_LOG_TOKEN", "").strip()

DEFAULT_DEADLINE_SECS = 900  # 15 menit (matriks M3)
DECISION_ID_LEN = 16  # id pendek untuk callback_data Telegram (<=64 byte)
MIN_DEADLINE_SECS = 30
MAX_DEADLINE_SECS = 86400
MAX_HASH_LEN = 128
MAX_STR = 4096
DECISION_ACTIONS = ("quarantine", "false_positive", "acknowledged")
_lock = threading.Lock()
DECISIONS = {}


def _state_dir():
    d = os.path.dirname(os.path.abspath(LOG_FILE))
    return d or "."


def decision_file():
    return DECISION_FILE or os.path.join(_state_dir(), "decisions.json")


def decision_audit_file():
    return DECISION_AUDIT_FILE or os.path.join(_state_dir(), "decisions-audit.jsonl")


def _ensure_dir(path=None):
    d = os.path.dirname(os.path.abspath(path or LOG_FILE))
    if d:
        os.makedirs(d, exist_ok=True)


# --------------------------------------------------------------------------
# Peran 1: pencatat alert keluar
# --------------------------------------------------------------------------
def append_records(records, path=None):
    path = path or LOG_FILE
    _ensure_dir(path)
    with _lock:
        with open(path, "a") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(records)


def read_records(limit=50, path=None):
    path = path or LOG_FILE
    if not os.path.exists(path):
        return []
    with _lock:
        with open(path) as f:
            lines = f.readlines()
    out = []
    for ln in lines[-max(1, limit):]:
        try:
            out.append(json.loads(ln))
        except ValueError:
            continue
    return out


def _iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


# --------------------------------------------------------------------------
# Peran 2: registry keputusan analis (HITL)
# --------------------------------------------------------------------------
def _load_decisions():
    path = decision_file()
    if not os.path.exists(path):
        return {}
    try:
        with open(path) as f:
            data = json.load(f)
    except (ValueError, OSError):
        return {}
    items = data.get("decisions") if isinstance(data, dict) else None
    if not isinstance(items, dict):
        return {}
    now = time.time()
    out = {}
    for k, v in items.items():
        if not isinstance(v, dict):
            continue
        if now - float(v.get("created_ts", 0)) > DECISION_TTL_SECS * 4:
            continue  # sangat lama: buang dari state
        out[str(k)] = v
    return out


def _save_decisions_locked():
    path = decision_file()
    _ensure_dir(path)
    tmp = path + ".tmp"
    payload = {"saved_at": time.time(), "decisions": DECISIONS}
    with open(tmp, "w") as f:
        json.dump(payload, f, ensure_ascii=False)
    os.replace(tmp, path)


def _clean_str(value, max_len=MAX_STR):
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_len]


def _valid_hash(value):
    return bool(value) and len(value) <= MAX_HASH_LEN and re.fullmatch(
        r"[A-Za-z0-9._:-]+", value
    ) is not None


def register_pending(payload):
    """Daftarkan deteksi HITL sebagai keputusan tertunda (key = hash)."""
    h = _clean_str(payload.get("hash"), MAX_HASH_LEN).lower()
    if not _valid_hash(h):
        return None, "hash tidak valid"
    agent_id = _clean_str(payload.get("agent_id"), 64)
    if not agent_id or re.fullmatch(r"[A-Za-z0-9._-]+", agent_id) is None:
        return None, "agent_id tidak valid"
    filepath = _clean_str(payload.get("filepath"), MAX_STR)
    if not filepath:
        return None, "filepath wajib (sumber target aksi HITL)"
    severity = _clean_str(payload.get("severity"), 32).upper()
    hitl = bool(payload.get("hitl"))
    try:
        deadline_secs = int(payload.get("deadline_secs") or 0)
    except (TypeError, ValueError):
        deadline_secs = 0
    if hitl:
        deadline_secs = max(MIN_DEADLINE_SECS,
                            min(MAX_DEADLINE_SECS, deadline_secs or DEFAULT_DEADLINE_SECS))
    else:
        # Tier otomatis/observasi: tetap dicatat untuk audit trail, tapi tanpa
        # tenggat -> tidak pernah masuk daftar eskalaasi SLA.
        deadline_secs = 0
    now = time.time()
    with _lock:
        prev = DECISIONS.get(h) or {}

        def _pick(field, max_len=MAX_STR, default=""):
            """Nilai baru bila dikirim; kalau kosong pertahankan nilai sebelumnya
            (pendaftaran ulang tanpa field opsional tidak boleh menghapus info)."""
            val = _clean_str(payload.get(field), max_len)
            return val or prev.get(field, default)

        same = (
            prev.get("filepath") == filepath
            and str(prev.get("agent_id")) == agent_id
            and prev.get("status") == "pending"
        )
        # Deteksi sama yang diulang (mis. retry n8n): jangan reset tenggat
        created = prev.get("created_ts", now) if same else now
        rec = {
            "hash": h,
            "did": h[:DECISION_ID_LEN],
            "hitl": hitl,
            "agent_id": agent_id,
            "agent_name": _pick("agent_name", 128),
            "filepath": filepath,
            "filename": _pick("filename", 512),
            "severity": severity or prev.get("severity", ""),
            "tier": _pick("tier", 32),
            "action_kind": _pick("action_kind", 32),
            "title": _pick("title", 256),
            "workflow": _pick("workflow", 64),
            "created_ts": created,
            "created_at": prev.get("created_at", _iso(created)) if same else _iso(now),
            "deadline_ts": (created + deadline_secs) if deadline_secs else None,
            "deadline_secs": deadline_secs,
            "status": "pending",
            "escalated_ts": None,
            "resolved_ts": None,
        }
        DECISIONS[h] = rec
        _save_decisions_locked()
    return rec, None


def _append_audit(rec):
    path = decision_audit_file()
    _ensure_dir(path)
    with open(path, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def _lookup_locked(key):
    """Cari entri keputusan: cocok persis, atau unik sebagai awalan (did pendek).

    Tombol Telegram hanya boleh membawa <=64 byte, jadi callback membawa id
    pendek (`did` = 16 karakter pertama hash/kunci). Bila awalan ambigu
    (teoretis), keputusan ditolak supaya aksi tidak salah sasaran.
    """
    rec = DECISIONS.get(key)
    if rec is not None:
        return rec, None
    matches = [r for k, r in DECISIONS.items() if k.startswith(key)]
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, "id keputusan ambigu"
    return None, "hash tidak terdaftar"


def resolve_decision(payload):
    """Catat keputusan analis; kembalikan target aksi dari registry."""
    key = _clean_str(payload.get("hash"), MAX_HASH_LEN).lower()
    action = _clean_str(payload.get("action"), 32).lower()
    by = _clean_str(payload.get("by"), 128) or "analis"
    if not _valid_hash(key) or action not in DECISION_ACTIONS:
        return None, "hash/action tidak valid"
    now = time.time()
    with _lock:
        rec, err = _lookup_locked(key)
        if rec is None:
            return None, err
        if rec.get("status") == "resolved":
            return {
                "ok": True,
                "found": True,
                "duplicate": True,
                "filepath": rec.get("filepath"),
                "agent_id": rec.get("agent_id"),
                "severity": rec.get("severity"),
            }, None
        rec["status"] = "resolved"
        rec["action"] = action
        rec["by"] = by
        rec["note"] = _clean_str(payload.get("note"), 512)
        rec["resolved_ts"] = now
        rec["resolved_at"] = _iso(now)
        rec["response_secs"] = int(now - float(rec.get("created_ts", now)))
        rec["dst"] = bool(payload.get("dst"))
        _save_decisions_locked()
        _append_audit(dict(rec))
        out = {
            "ok": True,
            "found": True,
            "duplicate": False,
            "hash": rec.get("hash"),
            "filepath": rec.get("filepath"),
            "agent_id": rec.get("agent_id"),
            "severity": rec.get("severity"),
            "tier": rec.get("tier"),
            "action": action,
            "by": by,
            "response_secs": rec["response_secs"],
        }
    return out, None


def mark_escalated(key):
    now = time.time()
    with _lock:
        rec, _err = _lookup_locked(key)
        if rec is None or rec.get("status") != "pending":
            return None
        if rec.get("escalated_ts"):
            return dict(rec)
        rec["escalated_ts"] = now
        rec["escalated_at"] = _iso(now)
        rec["status"] = "escalated"
        _save_decisions_locked()
        _append_audit(dict(rec))
        return dict(rec)


def pending_decisions(overdue_only=False, include_all=False, limit=100):
    now = time.time()
    with _lock:
        items = [dict(v) for v in DECISIONS.values()]
    out = []
    for rec in items:
        age = now - float(rec.get("created_ts", now))
        if age > DECISION_TTL_SECS and rec.get("status") in ("pending", "escalated"):
            rec["status"] = "expired"
        if not include_all and rec.get("status") not in ("pending", "escalated"):
            continue
        if overdue_only and rec.get("status") != "pending":
            # sudah dieskalasi -> jangan dieskalasi berulang oleh sweeper SLA;
            # pakai ?all=1 kalau mau melihat item yang tetap belum ditangani.
            continue
        if overdue_only and (not rec.get("hitl") or not rec.get("deadline_ts")):
            # tier otomatis/observasi: dicatat untuk audit, tanpa tenggat.
            continue
        if overdue_only and float(rec.get("deadline_ts") or 0) > now:
            continue
        rec["age_secs"] = int(age)
        rec["overdue_secs"] = int(max(0, now - float(rec.get("deadline_ts") or now)))
        out.append(rec)
    out.sort(key=lambda r: r.get("created_ts", 0))
    return out[: max(1, limit)]


def decision_stats():
    with _lock:
        items = [dict(v) for v in DECISIONS.values()]
    resolved = [r for r in items if r.get("status") == "resolved"]
    responses = [r["response_secs"] for r in resolved if r.get("response_secs") is not None]
    return {
        "total": len(items),
        "by_status": dict(Counter(r.get("status") for r in items)),
        "by_action": dict(Counter(r.get("action") for r in resolved if r.get("action"))),
        "by_tier": dict(Counter(r.get("tier") for r in items if r.get("tier"))),
        "hitl": sum(1 for r in items if r.get("hitl")),
        "auto": sum(1 for r in items if not r.get("hitl")),
        "mean_response_secs": round(sum(responses) / len(responses), 1) if responses else None,
        "min_response_secs": min(responses) if responses else None,
        "max_response_secs": max(responses) if responses else None,
        "hitl_response_secs": (
            round(
                sum(r["response_secs"] for r in resolved
                    if r.get("hitl") and r.get("response_secs") is not None)
                / max(1, len([r for r in resolved
                              if r.get("hitl") and r.get("response_secs") is not None])),
                1,
            )
            if [r for r in resolved if r.get("hitl") and r.get("response_secs") is not None]
            else None
        ),
        "deadline_secs_default": DEFAULT_DEADLINE_SECS,
        "ttl_secs": DECISION_TTL_SECS,
        "file": decision_file(),
        "audit_file": decision_audit_file(),
    }


def stats():
    items = read_records(limit=100000)
    last_ts = next((i.get("ts") for i in reversed(items) if i.get("ts")), None)
    return {
        "total": len(items),
        "by_severity": dict(Counter(i.get("severity") for i in items if i.get("severity"))),
        "by_workflow": dict(Counter(i.get("workflow") for i in items if i.get("workflow"))),
        "last_ts": last_ts,
        "file": LOG_FILE,
        "decisions": decision_stats(),
    }


def _authorized(headers):
    if not LOG_TOKEN:
        return True
    value = headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return False
    try:
        return hmac.compare_digest(value[7:].strip(), LOG_TOKEN)
    except (TypeError, UnicodeEncodeError):
        return False


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n).decode() or "{}")
        except (ValueError, UnicodeDecodeError):
            return None

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/healthz", "/"):
            return self._json({"status": "ok", "file": LOG_FILE,
                               "decisions_pending": len(pending_decisions(include_all=False))})
        if u.path == "/log":
            lim = int((q.get("limit") or ["50"])[0])
            items = read_records(limit=lim)
            return self._json({"count": len(items), "items": items})
        if u.path == "/stats":
            return self._json(stats())
        if u.path == "/decision/pending":
            overdue = (q.get("overdue") or ["0"])[0] in ("1", "true", "yes")
            include_all = (q.get("all") or ["0"])[0] in ("1", "true", "yes")
            lim = int((q.get("limit") or ["100"])[0])
            items = pending_decisions(overdue_only=overdue, include_all=include_all, limit=lim)
            return self._json({
                "count": len(items),
                "overdue": overdue,
                "server_ts": time.time(),
                "items": items,
            })
        if u.path == "/decision/audit":
            lim = int((q.get("limit") or ["100"])[0])
            h = (q.get("hash") or [""])[0].strip().lower()
            items = read_records(limit=lim, path=decision_audit_file())
            if h:
                items = [i for i in items if i.get("hash") == h]
            return self._json({"count": len(items), "items": items})
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        body = self._body()
        if body is None:
            return self._json({"error": "bad json"}, 400)
        if u.path == "/log":
            recs = body if isinstance(body, list) else [body]
            stored = append_records(recs)
            return self._json({"ok": True, "stored": stored})
        if u.path.startswith("/decision/"):
            if not _authorized(self.headers):
                return self._json({"error": "unauthorized"}, 401,
                                  {"WWW-Authenticate": "Bearer"})
            if u.path == "/decision/pending":
                rec, err = register_pending(body)
                if err:
                    return self._json({"ok": False, "error": err}, 400)
                return self._json({"ok": True, "hash": rec["hash"],
                                   "status": rec["status"],
                                   "deadline_ts": rec["deadline_ts"],
                                   "deadline_secs": rec["deadline_secs"]})
            if u.path == "/decision/resolve":
                out, err = resolve_decision(body)
                if err == "hash tidak terdaftar":
                    # fail-open: jangan gagalkan callback analis hanya karena
                    # registry restart/kedaluwarsa. n8n tetap boleh edit pesan.
                    return self._json({"ok": False, "found": False, "error": err}, 200)
                if err:
                    return self._json({"ok": False, "error": err}, 400)
                return self._json(out)
            if u.path == "/decision/escalate":
                h = _clean_str(body.get("hash"), MAX_HASH_LEN).lower()
                rec = mark_escalated(h)
                if rec is None:
                    return self._json({"ok": False, "error": "tidak ada pending"}, 404)
                return self._json({"ok": True, "hash": h,
                                   "escalated_at": rec.get("escalated_at")})
        return self._json({"error": "not found"}, 404)


def serve(port=PORT):
    _ensure_dir()
    _ensure_dir(decision_file())
    _ensure_dir(decision_audit_file())
    global DECISIONS
    DECISIONS = _load_decisions()
    srv = ThreadingHTTPServer(("0.0.0.0", port), Handler)
    print(f"[serve] alert-log di :{port}, file={LOG_FILE}, "
          f"keputusan={decision_file()} ({len(DECISIONS)} entri)", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--decisions", action="store_true")
    ap.add_argument("--log", type=int, default=0, metavar="N")
    a = ap.parse_args()
    if a.stats:
        print(json.dumps(stats(), indent=2, ensure_ascii=False))
    elif a.decisions:
        print(json.dumps({"pending": pending_decisions(include_all=True),
                          "stats": decision_stats()}, indent=2, ensure_ascii=False))
    elif a.log:
        print(json.dumps(read_records(a.log), indent=2, ensure_ascii=False))
    else:
        serve(a.port)
