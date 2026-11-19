#!/usr/bin/env python3
"""Pencatat alert Telegram keluar + registry keputusan analis (SOAR).

Env:
  ALERT_LOG_FILE              default state/telegram-alerts.jsonl
  ALERT_LOG_BIND              default 127.0.0.1
  ALERT_LOG_PORT              default 8091
  ALERT_DECISION_FILE         default <dir ALERT_LOG_FILE>/decisions.json
  ALERT_DECISION_AUDIT_FILE   default <dir>/decisions-audit.jsonl
  ALERT_DECISION_TTL_SECS     default 21600 (6 jam) -> pending kedaluwarsa
  ALERT_LOG_TOKEN             wajib di produksi (fail-closed)
  ALERT_LOG_DEV_INSECURE      set 1 hanya untuk dev/test lokal tanpa token
"""
import collections
import hashlib
import hmac
import json
import os
import re
import tempfile
import threading
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

LOG_FILE = os.getenv("ALERT_LOG_FILE", "state/telegram-alerts.jsonl")
BIND = os.getenv("ALERT_LOG_BIND", "127.0.0.1")
PORT = int(os.getenv("ALERT_LOG_PORT", "8091"))
DECISION_FILE = os.getenv("ALERT_DECISION_FILE", "")
DECISION_AUDIT_FILE = os.getenv("ALERT_DECISION_AUDIT_FILE", "")
DECISION_TTL_SECS = int(os.getenv("ALERT_DECISION_TTL_SECS", "21600"))
LOG_TOKEN = os.getenv("ALERT_LOG_TOKEN", "").strip()
DEV_INSECURE = os.getenv("ALERT_LOG_DEV_INSECURE", "").strip().lower() in ("1", "true", "yes")

DEFAULT_DEADLINE_SECS = 900  # 15 menit (matriks M3)
DECISION_ID_LEN = 16
MIN_PREFIX_LEN = 8
MIN_DEADLINE_SECS = 30
MAX_DEADLINE_SECS = 86400
MAX_HASH_LEN = 128
MAX_STR = 4096
MAX_BODY_BYTES = 262144
MAX_LIMIT = 1000
MAX_LOG_BYTES = 10 * 1024 * 1024
MAX_LOG_BACKUPS = 5
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


def _rotate_if_needed_locked(path):
    try:
        if not os.path.exists(path) or os.path.getsize(path) < MAX_LOG_BYTES:
            return
        for idx in range(MAX_LOG_BACKUPS - 1, 0, -1):
            src = f"{path}.{idx}"
            dst = f"{path}.{idx + 1}"
            if os.path.exists(src):
                os.replace(src, dst)
        os.replace(path, f"{path}.1")
    except OSError:
        pass


def _atomic_write_json(path, payload):
    _ensure_dir(path)
    parent = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --------------------------------------------------------------------------
# Peran 1: pencatat alert keluar
# --------------------------------------------------------------------------
def append_records(records, path=None):
    path = path or LOG_FILE
    _ensure_dir(path)
    with _lock:
        _rotate_if_needed_locked(path)
        with open(path, "a", encoding="utf-8") as f:
            for r in records:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
    return len(records)


def read_records(limit=50, path=None):
    path = path or LOG_FILE
    if not os.path.exists(path):
        return []
    safe_limit = max(1, min(int(limit or 50), 100000))
    with _lock:
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                tail = collections.deque(f, maxlen=safe_limit)
        except OSError:
            return []
    out = []
    for ln in tail:
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
def _decision_key(agent_id, h):
    return f"{agent_id}:{h}"


def _decision_did(agent_id, h):
    # Untuk kompatibilitas, gunakan 16 char hash unik per (agent_id, hash)
    # namun _lookup_locked juga tetap menerima prefix hash bila tidak ambigu.
    return hashlib.sha256(f"{agent_id}:{h}".encode("utf-8")).hexdigest()[:DECISION_ID_LEN]


def _load_decisions():
    path = decision_file()
    if not os.path.exists(path):
        return {}
    try:
        with open(path, encoding="utf-8") as f:
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
            continue
        out[str(k)] = v
    return out


def _save_decisions_locked():
    payload = {"saved_at": time.time(), "decisions": DECISIONS}
    _atomic_write_json(decision_file(), payload)


def _prune_and_expire_locked(now=None):
    now = time.time() if now is None else now
    changed = False
    to_drop = []
    for k, rec in DECISIONS.items():
        age = now - float(rec.get("created_ts", now))
        if age > DECISION_TTL_SECS * 4:
            to_drop.append(k)
            changed = True
            continue
        if age > DECISION_TTL_SECS and rec.get("status") in ("pending", "escalated"):
            rec["status"] = "expired"
            rec["expired_ts"] = now
            rec["expired_at"] = _iso(now)
            _append_audit_locked(dict(rec))
            changed = True
    for k in to_drop:
        DECISIONS.pop(k, None)
    if changed:
        _save_decisions_locked()


def _clean_str(value, max_len=MAX_STR):
    if not isinstance(value, str):
        return ""
    return value.strip()[:max_len]


def _valid_hash(value):
    return bool(value) and len(value) <= MAX_HASH_LEN and re.fullmatch(
        r"[A-Za-z0-9._:-]+", value
    ) is not None


def _append_audit_locked(rec):
    path = decision_audit_file()
    _ensure_dir(path)
    _rotate_if_needed_locked(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def register_pending(payload):
    """Daftarkan deteksi HITL sebagai keputusan tertunda (key = agent_id:hash)."""
    if not isinstance(payload, dict):
        return None, "payload harus objek JSON"
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
    # Event INFO tidak pernah membutuhkan eskalasi atau persetujuan HITL analis.
    hitl = bool(payload.get("hitl")) and severity != "INFO"
    try:
        deadline_secs = int(payload.get("deadline_secs") or 0)
    except (TypeError, ValueError):
        deadline_secs = 0
    if hitl:
        deadline_secs = max(
            MIN_DEADLINE_SECS,
            min(MAX_DEADLINE_SECS, deadline_secs or DEFAULT_DEADLINE_SECS),
        )
    else:
        deadline_secs = 0
    now = time.time()
    dkey = _decision_key(agent_id, h)
    with _lock:
        _prune_and_expire_locked(now)
        prev = DECISIONS.get(dkey) or {}

        def _pick(field, max_len=MAX_STR, default=""):
            val = _clean_str(payload.get(field), max_len)
            return val or prev.get(field, default)

        same = (
            prev.get("filepath") == filepath
            and str(prev.get("agent_id")) == agent_id
            and prev.get("status") == "pending"
        )
        created = prev.get("created_ts", now) if same else now
        did = _decision_did(agent_id, h)
        rec = {
            "key": dkey,
            "hash": h,
            "did": did,
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
            "status": "pending" if hitl else "observed",
            "escalated_ts": None,
            "resolved_ts": None,
        }
        DECISIONS[dkey] = rec
        _save_decisions_locked()
    return rec, None


def _lookup_locked(key, agent_id=""):
    """Cari entri keputusan: exact key / did / hash (atau prefix >= 8 char unik)."""
    if agent_id:
        composite = _decision_key(agent_id, key)
        if composite in DECISIONS:
            return DECISIONS[composite], None
    if key in DECISIONS:
        return DECISIONS[key], None
    exact_did = [r for r in DECISIONS.values() if r.get("did") == key]
    if len(exact_did) == 1:
        return exact_did[0], None
    if len(exact_did) > 1:
        return None, "id keputusan ambigu"
    exact_hash = [r for r in DECISIONS.values() if r.get("hash") == key]
    if len(exact_hash) == 1:
        return exact_hash[0], None
    if len(exact_hash) > 1:
        return None, "id keputusan ambigu"
    if len(key) < MIN_PREFIX_LEN:
        return None, "hash tidak terdaftar"
    matches = [
        r
        for k, r in DECISIONS.items()
        if k.startswith(key)
        or str(r.get("hash", "")).startswith(key)
        or str(r.get("did", "")).startswith(key)
    ]
    if len(matches) == 1:
        return matches[0], None
    if len(matches) > 1:
        return None, "id keputusan ambigu"
    return None, "hash tidak terdaftar"


def resolve_decision(payload):
    """Catat keputusan analis; kembalikan target aksi dari registry."""
    if not isinstance(payload, dict):
        return None, "payload harus objek JSON"
    key = _clean_str(payload.get("hash") or payload.get("did"), MAX_HASH_LEN).lower()
    agent_id = _clean_str(payload.get("agent_id"), 64)
    action = _clean_str(payload.get("action"), 32).lower()
    by = _clean_str(payload.get("by"), 128) or "analis"
    if not _valid_hash(key) or action not in DECISION_ACTIONS:
        return None, "hash/action tidak valid"
    now = time.time()
    with _lock:
        _prune_and_expire_locked(now)
        rec, err = _lookup_locked(key, agent_id=agent_id)
        if rec is None:
            return None, err
        if rec.get("status") == "expired":
            return None, "keputusan sudah kedaluwarsa"
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
        _append_audit_locked(dict(rec))
        out = {
            "ok": True,
            "found": True,
            "duplicate": False,
            "hash": rec.get("hash"),
            "did": rec.get("did"),
            "filepath": rec.get("filepath"),
            "agent_id": rec.get("agent_id"),
            "severity": rec.get("severity"),
            "tier": rec.get("tier"),
            "action": action,
            "by": by,
            "response_secs": rec["response_secs"],
        }
    return out, None


def mark_escalated(key, agent_id=""):
    now = time.time()
    with _lock:
        _prune_and_expire_locked(now)
        rec, _err = _lookup_locked(key, agent_id=agent_id)
        if rec is None or rec.get("status") != "pending":
            return None
        if rec.get("escalated_ts"):
            return dict(rec)
        rec["escalated_ts"] = now
        rec["escalated_at"] = _iso(now)
        rec["status"] = "escalated"
        _save_decisions_locked()
        _append_audit_locked(dict(rec))
        return dict(rec)


def pending_decisions(overdue_only=False, include_all=False, limit=100):
    now = time.time()
    with _lock:
        _prune_and_expire_locked(now)
        items = [dict(v) for v in DECISIONS.values()]
    out = []
    for rec in items:
        age = now - float(rec.get("created_ts", now))
        is_hitl = bool(rec.get("hitl")) and str(rec.get("severity") or "").upper() != "INFO"
        if not include_all:
            if not is_hitl or rec.get("status") not in ("pending", "escalated"):
                continue
        if overdue_only and rec.get("status") != "pending":
            continue
        if overdue_only and (not is_hitl or not rec.get("deadline_ts")):
            continue
        if overdue_only and float(rec.get("deadline_ts") or 0) > now:
            continue
        rec["age_secs"] = int(age)
        rec["overdue_secs"] = int(max(0, now - float(rec.get("deadline_ts") or now)))
        out.append(rec)
    out.sort(key=lambda r: r.get("created_ts", 0))
    return out[: max(1, min(int(limit or 100), MAX_LIMIT))]


def decision_stats():
    now = time.time()
    with _lock:
        _prune_and_expire_locked(now)
        items = [dict(v) for v in DECISIONS.values()]
    resolved = [r for r in items if r.get("status") == "resolved"]
    responses = [r["response_secs"] for r in resolved if r.get("response_secs") is not None]
    hitl_responses = [
        r["response_secs"] for r in resolved if r.get("hitl") and r.get("response_secs") is not None
    ]
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
            round(sum(hitl_responses) / len(hitl_responses), 1) if hitl_responses else None
        ),
        "deadline_secs_default": DEFAULT_DEADLINE_SECS,
        "ttl_secs": DECISION_TTL_SECS,
        "file": decision_file(),
        "audit_file": decision_audit_file(),
    }


def stats():
    items = read_records(limit=10000)
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
        return DEV_INSECURE
    value = headers.get("Authorization", "")
    if not value.startswith("Bearer "):
        return False
    try:
        return hmac.compare_digest(value[7:].strip(), LOG_TOKEN)
    except (TypeError, UnicodeEncodeError):
        return False


def _parse_limit(q, default=50):
    raw = (q.get("limit") or [str(default)])[0]
    try:
        val = int(raw)
    except (TypeError, ValueError):
        return default
    return max(1, min(val, MAX_LIMIT))


class Handler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        try:
            self.request.settimeout(15)
        except OSError:
            pass

    def log_message(self, *a):
        pass

    def _json(self, obj, code=200, extra_headers=None):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        raw_len = self.headers.get("Content-Length", "0")
        try:
            n = int(raw_len)
        except (TypeError, ValueError):
            return None, 400
        if n < 0 or n > MAX_BODY_BYTES:
            return None, 413 if n > MAX_BODY_BYTES else 400
        try:
            raw = self.rfile.read(n).decode("utf-8") if n else ""
            return json.loads(raw or "{}"), 200
        except (ValueError, UnicodeDecodeError):
            return None, 400

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        if u.path in ("/healthz", "/"):
            return self._json({"status": "ok"})
        if not _authorized(self.headers):
            return self._json({"error": "unauthorized"}, 401, {"WWW-Authenticate": "Bearer"})
        if u.path == "/log":
            lim = _parse_limit(q, default=50)
            items = read_records(limit=lim)
            return self._json({"count": len(items), "items": items})
        if u.path == "/stats":
            return self._json(stats())
        if u.path == "/decision/pending":
            overdue = (q.get("overdue") or q.get("overdue_only") or ["0"])[0] in ("1", "true", "yes")
            include_all = (q.get("all") or ["0"])[0] in ("1", "true", "yes")
            lim = _parse_limit(q, default=100)
            items = pending_decisions(overdue_only=overdue, include_all=include_all, limit=lim)
            return self._json({
                "count": len(items),
                "overdue": overdue,
                "server_ts": time.time(),
                "items": items,
            })
        if u.path == "/decision/audit":
            lim = _parse_limit(q, default=100)
            h = (q.get("hash") or [""])[0].strip().lower()
            items = read_records(limit=lim, path=decision_audit_file())
            if h:
                items = [i for i in items if i.get("hash") == h]
            return self._json({"count": len(items), "items": items})
        self._json({"error": "not found"}, 404)

    def do_POST(self):
        u = urlparse(self.path)
        if not _authorized(self.headers):
            return self._json({"error": "unauthorized"}, 401, {"WWW-Authenticate": "Bearer"})
        body, status = self._body()
        if status == 413:
            return self._json({"error": "payload too large"}, 413)
        if body is None:
            return self._json({"error": "bad json"}, 400)
        if u.path == "/log":
            recs = body if isinstance(body, list) else [body]
            stored = append_records(recs)
            return self._json({"ok": True, "stored": stored})
        if u.path == "/decision/pending":
            rec, err = register_pending(body)
            if err:
                return self._json({"ok": False, "error": err}, 400)
            return self._json({
                "ok": True,
                "hash": rec["hash"],
                "did": rec["did"],
                "status": rec["status"],
                "deadline_ts": rec["deadline_ts"],
                "deadline_secs": rec["deadline_secs"],
            })
        if u.path == "/decision/resolve":
            out, err = resolve_decision(body)
            if err == "hash tidak terdaftar":
                return self._json({"ok": False, "found": False, "error": err}, 200)
            if err:
                return self._json({"ok": False, "error": err}, 400)
            return self._json(out)
        if u.path == "/decision/escalate":
            h = _clean_str(body.get("hash") or body.get("did"), MAX_HASH_LEN).lower()
            aid = _clean_str(body.get("agent_id"), 64)
            rec = mark_escalated(h, agent_id=aid)
            if rec is None:
                return self._json({"ok": False, "error": "tidak ada pending"}, 404)
            return self._json({
                "ok": True,
                "hash": rec.get("hash", h),
                "did": rec.get("did"),
                "escalated_at": rec.get("escalated_at"),
            })
        return self._json({"error": "not found"}, 404)


def serve(port=PORT, bind=BIND):
    if not LOG_TOKEN and not DEV_INSECURE:
        raise SystemExit(
            "FATAL: ALERT_LOG_TOKEN wajib diisi (atau set ALERT_LOG_DEV_INSECURE=1 untuk dev lokal)."
        )
    _ensure_dir()
    _ensure_dir(decision_file())
    _ensure_dir(decision_audit_file())
    global DECISIONS
    DECISIONS = _load_decisions()
    srv = ThreadingHTTPServer((bind, port), Handler)
    print(
        f"[serve] alert-log di {bind}:{port}, file={LOG_FILE}, "
        f"keputusan={decision_file()} ({len(DECISIONS)} entri)",
        flush=True,
    )
    srv.serve_forever()


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--serve", action="store_true")
    ap.add_argument("--bind", default=BIND)
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--stats", action="store_true")
    ap.add_argument("--decisions", action="store_true")
    ap.add_argument("--log", type=int, default=0, metavar="N")
    a = ap.parse_args()
    if a.stats:
        print(json.dumps(stats(), indent=2, ensure_ascii=False))
    elif a.decisions:
        print(
            json.dumps(
                {"pending": pending_decisions(include_all=True), "stats": decision_stats()},
                indent=2,
                ensure_ascii=False,
            )
        )
    elif a.log:
        print(json.dumps(read_records(a.log), indent=2, ensure_ascii=False))
    else:
        serve(a.port, a.bind)
