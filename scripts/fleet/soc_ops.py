"""SOC Operational Completeness (v1.1 / Workstream 6) helpers for fleet-monitor.

Includes:
1. Persistent Active Response Command Queue & Execution History (`commands` SQLite table + ACK)
2. Centralized Tamper-Evident Audit Trail (`audit_logs` SQLite table with SHA-256 hash chain)
3. Alert Triage Lifecycle (`alert_triage` SQLite table + event enrichment)
4. Dashboard HITL Decision Queue integration with `alert-log` service (:8091)
"""
from contextlib import closing
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
import uuid

WITA = timezone(timedelta(hours=8))

COMMAND_STATUSES = ("queued", "delivered", "succeeded", "failed", "expired")
COMMAND_TTL_DEFAULT = 900
COMMAND_MAX_ROWS = 5000

AUDIT_MAX_ROWS = 10000
AUDIT_LOCK = threading.RLock()

TRIAGE_STATUSES = ("new", "investigating", "contained", "false_positive", "resolved")
TRIAGE_LOCK = threading.RLock()

_SECRET_REDACT_RE = re.compile(
    r"(soar_live_[A-Za-z0-9]+|Bearer\s+[A-Za-z0-9._\-]+|eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+)",
    re.IGNORECASE,
)


def _now_wita_iso():
    return datetime.now(WITA).isoformat()


def _redact_text(val, max_len=1000):
    text = str(val or "").strip()
    if not text:
        return ""
    text = _SECRET_REDACT_RE.sub("[REDACTED]", text)
    return text[:max_len]


def init_soc_tables(conn):
    """Inisialisasi tabel SQLite untuk command queue, audit trail, dan alert triage."""
    conn.execute(
        """CREATE TABLE IF NOT EXISTS commands (
            id TEXT PRIMARY KEY,
            agent_id TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'queued',
            requested_by TEXT NOT NULL DEFAULT 'dashboard',
            created_at TEXT NOT NULL,
            created_epoch REAL NOT NULL,
            delivered_at TEXT NOT NULL DEFAULT '',
            completed_at TEXT NOT NULL DEFAULT '',
            output TEXT NOT NULL DEFAULT '',
            ttl_secs INTEGER NOT NULL DEFAULT 900
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_commands_agent_status ON commands(agent_id, status, created_epoch)"
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_commands_created ON commands(created_epoch DESC)"
    )

    conn.execute(
        """CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT '',
            action TEXT NOT NULL,
            target TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'ok',
            ip TEXT NOT NULL DEFAULT '',
            detail TEXT NOT NULL DEFAULT '',
            prev_hash TEXT NOT NULL,
            entry_hash TEXT NOT NULL
        )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_logs(ts DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_logs(action, ts DESC)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_logs(actor, ts DESC)")

    conn.execute(
        """CREATE TABLE IF NOT EXISTS alert_triage (
            event_key TEXT PRIMARY KEY,
            status TEXT NOT NULL DEFAULT 'new',
            assignee TEXT NOT NULL DEFAULT '',
            note TEXT NOT NULL DEFAULT '',
            updated_by TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        )"""
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_triage_status ON alert_triage(status, updated_at DESC)"
    )


# ---------------------------------------------------------------------------
# 1. Persistent Command Queue & Execution History (ACK)
# ---------------------------------------------------------------------------
def expire_stale_commands_conn(conn, now_epoch=None, now_iso=None):
    now_epoch = time.time() if now_epoch is None else float(now_epoch)
    now_iso = now_iso or _now_wita_iso()
    conn.execute(
        """UPDATE commands
           SET status = 'expired',
               completed_at = ?,
               output = CASE WHEN output = '' THEN 'Command TTL expired before agent poll' ELSE output END
           WHERE status = 'queued' AND (created_epoch + ttl_secs) < ?""",
        (now_iso, now_epoch),
    )


def load_queued_commands(db_fn, now_epoch=None, now_iso=None):
    """Muat antrean command berstatus 'queued' yang belum expired dari SQLite saat startup."""
    now_epoch = time.time() if now_epoch is None else float(now_epoch)
    now_iso = now_iso or _now_wita_iso()
    out = {}
    try:
        with closing(db_fn()) as conn, conn:
            expire_stale_commands_conn(conn, now_epoch=now_epoch, now_iso=now_iso)
            rows = conn.execute(
                """SELECT id, agent_id, action, target, requested_by, created_at
                   FROM commands
                   WHERE status = 'queued'
                   ORDER BY created_epoch ASC"""
            ).fetchall()
            for r in rows:
                aid = str(r["agent_id"])
                out.setdefault(aid, []).append(
                    {
                        "id": r["id"],
                        "agent_id": aid,
                        "action": r["action"],
                        "target": r["target"],
                        "by": r["requested_by"],
                        "ts": r["created_at"],
                    }
                )
    except Exception as exc:
        print(f"load_queued_commands error: {exc}", flush=True)
    return out


def persist_queued_command(db_fn, command, ttl_secs=COMMAND_TTL_DEFAULT, now_epoch=None, now_iso=None):
    """Simpan command baru ke tabel SQLite `commands` dan kembalikan dict command lengkap."""
    now_epoch = time.time() if now_epoch is None else float(now_epoch)
    now_iso = now_iso or command.get("ts") or _now_wita_iso()
    cmd_id = str(command.get("id") or f"cmd_{uuid.uuid4().hex[:12]}").strip()
    aid = str(command["agent_id"]).strip()
    action = str(command["action"]).strip()
    target = str(command["target"]).strip()
    by = str(command.get("by") or "dashboard").strip()[:120]
    try:
        ttl = max(30, min(int(ttl_secs or COMMAND_TTL_DEFAULT), 86400))
    except (TypeError, ValueError):
        ttl = COMMAND_TTL_DEFAULT

    entry = {
        **command,
        "id": cmd_id,
        "agent_id": aid,
        "action": action,
        "target": target,
        "by": by,
        "ts": now_iso,
    }
    try:
        with closing(db_fn()) as conn, conn:
            expire_stale_commands_conn(conn, now_epoch=now_epoch, now_iso=now_iso)
            conn.execute(
                """INSERT OR REPLACE INTO commands
                   (id, agent_id, action, target, status, requested_by, created_at, created_epoch,
                    delivered_at, completed_at, output, ttl_secs)
                   VALUES (?, ?, ?, ?, 'queued', ?, ?, ?, '', '', '', ?)""",
                (cmd_id, aid, action, target, by, now_iso, now_epoch, ttl),
            )
            conn.execute(
                "DELETE FROM commands WHERE id IN ("
                "SELECT id FROM commands ORDER BY created_epoch DESC LIMIT -1 OFFSET ?)",
                (COMMAND_MAX_ROWS,),
            )
    except Exception as exc:
        print(f"persist_queued_command error: {exc}", flush=True)
    return entry


def mark_commands_delivered(db_fn, agent_id, drained_cmds, now_epoch=None, now_iso=None):
    """Tandai command yang di-drain oleh agent sebagai 'delivered' di SQLite."""
    now_epoch = time.time() if now_epoch is None else float(now_epoch)
    now_iso = now_iso or _now_wita_iso()
    delivered_ids = [str(c.get("id")) for c in (drained_cmds or []) if c.get("id")]
    try:
        with closing(db_fn()) as conn, conn:
            expire_stale_commands_conn(conn, now_epoch=now_epoch, now_iso=now_iso)
            for cid in delivered_ids:
                conn.execute(
                    """UPDATE commands
                       SET status = 'delivered', delivered_at = ?
                       WHERE id = ? AND agent_id = ?""",
                    (now_iso, cid, str(agent_id)),
                )
            # Sinkronkan baris 'queued' yatim (misal jika in-memory COMMANDS di-clear saat test)
            if delivered_ids:
                placeholders = ",".join("?" * len(delivered_ids))
                conn.execute(
                    f"""UPDATE commands
                        SET status = 'expired', completed_at = ?
                        WHERE agent_id = ? AND status = 'queued' AND id NOT IN ({placeholders})""",
                    [now_iso, str(agent_id), *delivered_ids],
                )
            else:
                conn.execute(
                    """UPDATE commands
                       SET status = 'expired', completed_at = ?
                       WHERE agent_id = ? AND status = 'queued'""",
                    (now_iso, str(agent_id)),
                )
    except Exception as exc:
        print(f"mark_commands_delivered error: {exc}", flush=True)


def ack_command(db_fn, agent_id, cmd_id="", status="", ok=None, output="", in_memory_commands=None, now_iso=None):
    """Catat hasil eksekusi command (ACK) dari soar-agent."""
    now_iso = now_iso or _now_wita_iso()
    aid = str(agent_id or "").strip()
    if not aid:
        return None, "agent_id wajib diisi"
    norm_status = str(status or "").strip().lower()
    if not norm_status and ok is not None:
        norm_status = "succeeded" if bool(ok) else "failed"
    if norm_status in ("ok", "success", "completed", "done"):
        norm_status = "succeeded"
    elif norm_status in ("error", "err", "fail"):
        norm_status = "failed"
    if norm_status not in ("succeeded", "failed"):
        return None, "status ACK harus 'succeeded' atau 'failed'"

    clean_out = _redact_text(output, max_len=2000)
    clean_id = str(cmd_id or "").strip()

    try:
        with closing(db_fn()) as conn, conn:
            if clean_id:
                row = conn.execute(
                    "SELECT * FROM commands WHERE id = ? AND agent_id = ?",
                    (clean_id, aid),
                ).fetchone()
            else:
                row = conn.execute(
                    """SELECT * FROM commands
                       WHERE agent_id = ? AND status IN ('delivered', 'queued')
                       ORDER BY created_epoch DESC LIMIT 1""",
                    (aid,),
                ).fetchone()
            if not row:
                return None, "command tidak ditemukan untuk agent ini"

            target_id = row["id"]
            delivered_at = row["delivered_at"] or now_iso
            conn.execute(
                """UPDATE commands
                   SET status = ?, delivered_at = ?, completed_at = ?, output = ?
                   WHERE id = ?""",
                (norm_status, delivered_at, now_iso, clean_out, target_id),
            )
            updated = conn.execute(
                "SELECT * FROM commands WHERE id = ?", (target_id,)
            ).fetchone()
            if isinstance(in_memory_commands, dict) and aid in in_memory_commands:
                in_memory_commands[aid] = [
                    c for c in in_memory_commands.get(aid, []) if c.get("id") != target_id
                ]
                if not in_memory_commands[aid]:
                    in_memory_commands.pop(aid, None)
            return dict(updated), None
    except Exception as exc:
        return None, str(exc)


def list_command_history(db_fn, agent_id=None, status=None, limit=100):
    """Daftar riwayat command beserta ringkasan status."""
    try:
        safe_limit = max(1, min(int(limit or 100), 500))
    except (TypeError, ValueError):
        safe_limit = 100

    where = []
    params = []
    if agent_id and str(agent_id).strip().lower() not in ("", "all"):
        where.append("agent_id = ?")
        params.append(str(agent_id).strip())
    if status and str(status).strip().lower() not in ("", "all"):
        where.append("status = ?")
        params.append(str(status).strip().lower())
    clause = (" WHERE " + " AND ".join(where)) if where else ""

    counts = {s: 0 for s in COMMAND_STATUSES}
    rows = []
    try:
        with closing(db_fn()) as conn, conn:
            expire_stale_commands_conn(conn)
            for r in conn.execute(
                "SELECT status, COUNT(*) AS cnt FROM commands GROUP BY status"
            ).fetchall():
                st = str(r["status"] or "")
                if st in counts:
                    counts[st] = int(r["cnt"] or 0)
            cur = conn.execute(
                f"SELECT * FROM commands{clause} ORDER BY created_epoch DESC LIMIT ?",
                [*params, safe_limit],
            )
            rows = [dict(r) for r in cur.fetchall()]
    except Exception as exc:
        print(f"list_command_history error: {exc}", flush=True)

    return {
        "commands": rows,
        "counts": counts,
        "total": sum(counts.values()),
    }


# ---------------------------------------------------------------------------
# 2. Centralized Tamper-Evident Audit Trail (SHA-256 Hash Chain)
# ---------------------------------------------------------------------------
def compute_audit_hash(prev_hash, ts, actor, role, action, target, status, ip, detail):
    raw = f"{prev_hash}|{ts}|{actor}|{role}|{action}|{target}|{status}|{ip}|{detail}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def append_audit_log(
    db_fn,
    action,
    target="",
    status="ok",
    detail="",
    actor="system",
    role="",
    ip="",
    now_iso=None,
):
    """Tambahkan 1 entri audit trail dengan hash-chain SHA-256."""
    ts = now_iso or _now_wita_iso()
    clean_actor = _redact_text(actor or "system", max_len=120) or "system"
    clean_role = _redact_text(role, max_len=40)
    clean_action = _redact_text(action, max_len=80) or "unknown"
    clean_target = _redact_text(target, max_len=256)
    clean_status = _redact_text(status or "ok", max_len=32) or "ok"
    clean_ip = _redact_text(ip, max_len=64)
    if isinstance(detail, (dict, list)):
        clean_detail = _redact_text(json.dumps(detail, ensure_ascii=False), max_len=1500)
    else:
        clean_detail = _redact_text(detail, max_len=1500)

    with AUDIT_LOCK:
        try:
            with closing(db_fn()) as conn, conn:
                last_row = conn.execute(
                    "SELECT entry_hash FROM audit_logs ORDER BY id DESC LIMIT 1"
                ).fetchone()
                prev_hash = str(last_row["entry_hash"]) if last_row else "GENESIS"
                entry_hash = compute_audit_hash(
                    prev_hash,
                    ts,
                    clean_actor,
                    clean_role,
                    clean_action,
                    clean_target,
                    clean_status,
                    clean_ip,
                    clean_detail,
                )
                cur = conn.execute(
                    """INSERT INTO audit_logs
                       (ts, actor, role, action, target, status, ip, detail, prev_hash, entry_hash)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        ts,
                        clean_actor,
                        clean_role,
                        clean_action,
                        clean_target,
                        clean_status,
                        clean_ip,
                        clean_detail,
                        prev_hash,
                        entry_hash,
                    ),
                )
                row_id = cur.lastrowid
                conn.execute(
                    "DELETE FROM audit_logs WHERE id IN ("
                    "SELECT id FROM audit_logs ORDER BY id DESC LIMIT -1 OFFSET ?)",
                    (AUDIT_MAX_ROWS,),
                )
                return {
                    "id": row_id,
                    "ts": ts,
                    "actor": clean_actor,
                    "role": clean_role,
                    "action": clean_action,
                    "target": clean_target,
                    "status": clean_status,
                    "ip": clean_ip,
                    "detail": clean_detail,
                    "prev_hash": prev_hash,
                    "entry_hash": entry_hash,
                }
        except Exception as exc:
            print(f"append_audit_log error: {exc}", flush=True)
            return None


def verify_audit_chain(db_fn, max_verify=5000):
    """Verifikasi integritas rantai SHA-256 pada tabel `audit_logs`."""
    with AUDIT_LOCK:
        try:
            with closing(db_fn()) as conn:
                rows = conn.execute(
                    "SELECT * FROM audit_logs ORDER BY id ASC LIMIT ?",
                    (max_verify,),
                ).fetchall()
            if not rows:
                return {"chain_valid": True, "verified_count": 0, "broken_at_id": None}
            prev_expected = None
            for idx, r in enumerate(rows):
                if idx == 0:
                    prev_expected = r["prev_hash"]
                elif r["prev_hash"] != prev_expected:
                    return {
                        "chain_valid": False,
                        "verified_count": idx,
                        "broken_at_id": r["id"],
                    }
                computed = compute_audit_hash(
                    r["prev_hash"],
                    r["ts"],
                    r["actor"],
                    r["role"],
                    r["action"],
                    r["target"],
                    r["status"],
                    r["ip"],
                    r["detail"],
                )
                if computed != r["entry_hash"]:
                    return {
                        "chain_valid": False,
                        "verified_count": idx,
                        "broken_at_id": r["id"],
                    }
                prev_expected = r["entry_hash"]
            return {
                "chain_valid": True,
                "verified_count": len(rows),
                "broken_at_id": None,
            }
        except Exception as exc:
            print(f"verify_audit_chain error: {exc}", flush=True)
            return {"chain_valid": False, "verified_count": 0, "broken_at_id": -1}


def query_audit_logs(db_fn, limit=100, action=None, actor=None, status=None, q=None, verify=True):
    try:
        safe_limit = max(1, min(int(limit or 100), 500))
    except (TypeError, ValueError):
        safe_limit = 100

    where = []
    params = []
    if action and str(action).strip().lower() not in ("", "all"):
        where.append("action = ?")
        params.append(str(action).strip())
    if actor and str(actor).strip().lower() not in ("", "all"):
        where.append("LOWER(actor) LIKE ?")
        params.append(f"%{str(actor).strip().lower()}%")
    if status and str(status).strip().lower() not in ("", "all"):
        where.append("status = ?")
        params.append(str(status).strip().lower())
    if q and str(q).strip():
        like = f"%{str(q).strip()}%"
        where.append("(action LIKE ? OR actor LIKE ? OR target LIKE ? OR detail LIKE ? OR ip LIKE ?)")
        params.extend([like] * 5)

    clause = (" WHERE " + " AND ".join(where)) if where else ""
    logs = []
    total = 0
    actions_summary = []
    try:
        with closing(db_fn()) as conn:
            total = conn.execute(f"SELECT COUNT(*) FROM audit_logs{clause}", params).fetchone()[0]
            rows = conn.execute(
                f"SELECT * FROM audit_logs{clause} ORDER BY id DESC LIMIT ?",
                [*params, safe_limit],
            ).fetchall()
            logs = [dict(r) for r in rows]
            act_rows = conn.execute(
                "SELECT action, COUNT(*) AS cnt FROM audit_logs GROUP BY action ORDER BY cnt DESC LIMIT 30"
            ).fetchall()
            actions_summary = [{"action": r["action"], "count": r["cnt"]} for r in act_rows]
    except Exception as exc:
        print(f"query_audit_logs error: {exc}", flush=True)

    chain_info = verify_audit_chain(db_fn) if verify else {"chain_valid": True, "verified_count": 0, "broken_at_id": None}
    return {
        "logs": logs,
        "total": total,
        "actions": actions_summary,
        **chain_info,
    }


# ---------------------------------------------------------------------------
# 3. Alert Triage Lifecycle
# ---------------------------------------------------------------------------
def upsert_triage(db_fn, event_keys, status, assignee="", note="", updated_by="analyst", now_iso=None):
    norm_status = str(status or "").strip().lower()
    if norm_status not in TRIAGE_STATUSES:
        raise ValueError(f"status triage harus salah satu dari: {', '.join(TRIAGE_STATUSES)}")

    if isinstance(event_keys, str):
        raw_keys = [event_keys]
    elif isinstance(event_keys, list):
        raw_keys = event_keys
    else:
        raise ValueError("event_key atau event_keys wajib diisi")

    keys = []
    for k in raw_keys[:200]:
        ck = str(k or "").strip()[:256]
        if ck and ck not in keys:
            keys.append(ck)
    if not keys:
        raise ValueError("event_key tidak boleh kosong")

    clean_assignee = _redact_text(assignee, max_len=120)
    clean_note = _redact_text(note, max_len=1000)
    clean_by = _redact_text(updated_by or "analyst", max_len=120)
    ts = now_iso or _now_wita_iso()

    updated_items = []
    with TRIAGE_LOCK:
        with closing(db_fn()) as conn, conn:
            for ek in keys:
                prev = conn.execute(
                    "SELECT assignee, note FROM alert_triage WHERE event_key = ?", (ek,)
                ).fetchone()
                final_assignee = clean_assignee if assignee is not None and str(assignee) != "" else (prev["assignee"] if prev else "")
                final_note = clean_note if note is not None and str(note) != "" else (prev["note"] if prev else "")
                conn.execute(
                    """INSERT INTO alert_triage (event_key, status, assignee, note, updated_by, updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(event_key) DO UPDATE SET
                           status = excluded.status,
                           assignee = excluded.assignee,
                           note = excluded.note,
                           updated_by = excluded.updated_by,
                           updated_at = excluded.updated_at""",
                    (ek, norm_status, final_assignee, final_note, clean_by, ts),
                )
                updated_items.append(
                    {
                        "event_key": ek,
                        "status": norm_status,
                        "assignee": final_assignee,
                        "note": final_note,
                        "updated_by": clean_by,
                        "updated_at": ts,
                    }
                )
    return {"ok": True, "updated": len(updated_items), "items": updated_items}


def list_triage(db_fn, status=None, assignee=None, limit=500):
    try:
        safe_limit = max(1, min(int(limit or 500), 2000))
    except (TypeError, ValueError):
        safe_limit = 500
    where = []
    params = []
    if status and str(status).strip().lower() not in ("", "all"):
        where.append("status = ?")
        params.append(str(status).strip().lower())
    if assignee and str(assignee).strip():
        where.append("LOWER(assignee) = ?")
        params.append(str(assignee).strip().lower())
    clause = (" WHERE " + " AND ".join(where)) if where else ""

    counts = {s: 0 for s in TRIAGE_STATUSES}
    items = []
    try:
        with closing(db_fn()) as conn:
            for r in conn.execute("SELECT status, COUNT(*) AS cnt FROM alert_triage GROUP BY status").fetchall():
                st = str(r["status"] or "")
                if st in counts:
                    counts[st] = int(r["cnt"] or 0)
            rows = conn.execute(
                f"SELECT * FROM alert_triage{clause} ORDER BY updated_at DESC LIMIT ?",
                [*params, safe_limit],
            ).fetchall()
            items = [dict(r) for r in rows]
    except Exception as exc:
        print(f"list_triage error: {exc}", flush=True)
    return {"items": items, "counts": counts}


def enrich_events_with_triage(db_fn, events):
    """Perkaya list event dict dengan kolom `triage_status`, `triage_assignee`, `triage_note`."""
    if not events:
        return events
    triage_map = {}
    try:
        with closing(db_fn()) as conn:
            for r in conn.execute("SELECT * FROM alert_triage").fetchall():
                triage_map[str(r["event_key"])] = dict(r)
    except Exception:
        pass

    out = []
    for ev in events:
        if not isinstance(ev, dict):
            continue
        item = dict(ev)
        ev_id = str(item.get("id") or "").strip()
        aid = str(item.get("agent_id") or "").strip()
        h = str(item.get("hash") or "").strip().lower()
        comp_key = f"{aid}:{h}" if (aid and h) else ""
        t_rec = (
            triage_map.get(ev_id)
            or (triage_map.get(comp_key) if comp_key else None)
            or (triage_map.get(h) if h else None)
        )
        if t_rec:
            item["triage_status"] = t_rec["status"]
            item["triage_assignee"] = t_rec.get("assignee", "")
            item["triage_note"] = t_rec.get("note", "")
            item["triage_updated_by"] = t_rec.get("updated_by", "")
            item["triage_updated_at"] = t_rec.get("updated_at", "")
        else:
            item.setdefault("triage_status", "new")
            item.setdefault("triage_assignee", "")
            item.setdefault("triage_note", "")
        out.append(item)
    return out


# ---------------------------------------------------------------------------
# 4. Dashboard HITL Decision Queue Integration (`alert-log` :8091)
# ---------------------------------------------------------------------------
def _alert_log_base_url():
    raw = os.environ.get("ALERT_LOG_URL", "").strip()
    if raw:
        return raw.rstrip("/")
    health_url = os.environ.get("ALERT_LOG_HEALTH_URL", "http://127.0.0.1:8091/healthz").strip()
    if health_url.endswith("/healthz"):
        return health_url[: -len("/healthz")].rstrip("/")
    return "http://127.0.0.1:8091"


def _alert_log_request(path, method="GET", payload=None, timeout=8):
    base = _alert_log_base_url()
    token = os.environ.get("ALERT_LOG_TOKEN", "").strip()
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(f"{base}{path}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.status, json.loads(resp.read().decode("utf-8"))


def fetch_hitl_decisions(include_all=False, limit=100):
    q = f"?limit={max(1, min(int(limit or 100), 500))}"
    if include_all:
        q += "&all=1"
    try:
        _code, data = _alert_log_request(f"/decision/pending{q}", method="GET")
        items = (data.get("items") or data.get("decisions") or []) if isinstance(data, dict) else []
        pending_cnt = sum(1 for d in items if isinstance(d, dict) and d.get("status") in ("pending", "escalated"))
        return {
            "ok": True,
            "decisions": items,
            "pending_count": pending_cnt,
            "total": len(items),
        }
    except urllib.error.HTTPError as he:
        body = ""
        try:
            body = he.read().decode("utf-8", errors="replace")[:300]
        except Exception:
            pass
        return {"ok": False, "decisions": [], "pending_count": 0, "error": f"alert-log HTTP {he.code}: {body}"}
    except Exception as exc:
        return {"ok": False, "decisions": [], "pending_count": 0, "error": str(exc)}


def resolve_hitl_decision(payload):
    """Kirim penyelesaian keputusan HITL ke `alert-log` (:8091/decision/resolve)."""
    try:
        code, data = _alert_log_request("/decision/resolve", method="POST", payload=payload)
        return code, data
    except urllib.error.HTTPError as he:
        try:
            err_obj = json.loads(he.read().decode("utf-8", errors="replace"))
        except Exception:
            err_obj = {"ok": False, "error": f"alert-log HTTP {he.code}"}
        return he.code, err_obj
    except Exception as exc:
        return 502, {"ok": False, "error": f"Gagal menghubungi alert-log: {exc}"}
