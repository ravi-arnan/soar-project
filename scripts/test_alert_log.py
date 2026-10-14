#!/usr/bin/env python3
"""Unit test alert-log service (offline). Jalankan: python3 scripts/test_alert_log.py

Mencakup peran 1 (pencatat alert keluar) dan peran 2 (registry keputusan HITL /
matriks confidence -> otonomi M3): validasi, deadline, eskalasi, audit trail,
persist lintas-restart, TTL, dan token opsional.
"""
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
passed = failed = 0


def check(name, cond):
    global passed, failed
    if cond:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        print(f"  FAIL  {name}")


def load():
    spec = importlib.util.spec_from_file_location("alog", os.path.join(HERE, "alert-log.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def post(url, obj, headers=None):
    h = {"Content-Type": "application/json"}
    h.update(headers or {})
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=5) as r:
        return json.load(r)


def post_expect_error(url, obj, headers=None):
    try:
        post(url, obj, headers)
    except urllib.error.HTTPError as e:
        return e.code, json.load(e)
    return None, None


def main():
    M = load()
    tmp = tempfile.mkdtemp()
    M.LOG_FILE = os.path.join(tmp, "tg.jsonl")
    M.DECISION_FILE = os.path.join(tmp, "decisions.json")
    M.DECISION_AUDIT_FILE = os.path.join(tmp, "decisions-audit.jsonl")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), M.Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    time.sleep(0.3)
    base = f"http://127.0.0.1:{port}"
    try:
        # --- peran 1: pencatat alert keluar (perilaku lama tidak berubah) ----
        check("healthz ok", get(base + "/healthz").get("status") == "ok")
        r = post(base + "/log", {"ts": "2026-10-08T22:00:00Z", "workflow": "Deteksi Malware",
                                 "node": "Send Telegram Alert", "severity": "HIGH",
                                 "telegram_ok": True, "message_id": 111})
        check("POST /log stored=1", r.get("stored") == 1)
        post(base + "/log", [{"workflow": "Deteksi Phishing", "severity": "CRITICAL"},
                             {"workflow": "Deteksi Malware", "severity": "CRITICAL"}])
        lg = get(base + "/log?limit=10")
        check("GET /log mengembalikan 3 item", lg.get("count") == 3)
        check("urutan terbaru di akhir", lg["items"][-1].get("severity") == "CRITICAL")
        st = get(base + "/stats")
        check("stats total=3", st.get("total") == 3)
        check("stats by_severity", st["by_severity"].get("CRITICAL") == 2)
        check("stats by_workflow", st["by_workflow"].get("Deteksi Malware") == 2)
        check("stats last_ts ada", bool(st.get("last_ts")))
        check("GET /log?limit=1 -> 1 item", get(base + "/log?limit=1").get("count") == 1)

        # --- peran 2: registry keputusan HITL ---------------------------------
        HASH = "a" * 64
        OK = post(base + "/decision/pending", {
            "hash": HASH, "agent_id": "010", "agent_name": "ravi-debian",
            "filepath": "/home/ravi/Downloads/setup-installer.exe",
            "filename": "setup-installer.exe", "severity": "MEDIUM", "tier": "hitl-review",
            "hitl": True, "action_kind": "quarantine", "title": "FILE PERLU REVIEW",
            "workflow": "Deteksi Malware", "deadline_secs": 900})
        check("POST /decision/pending ok", OK.get("ok") is True and OK.get("status") == "pending")
        check("pending mengembalikan deadline", OK.get("deadline_secs") == 900)
        check("pending mengembalikan did pendek (<=64 byte callback)", len(OK.get("hash") or "") == 64)
        pend = get(base + "/decision/pending")
        check("GET /decision/pending -> 1 item", pend.get("count") == 1)
        rec = pend["items"][0]
        check("path/agent tersimpan (sumber target aksi)", rec["filepath"] == "/home/ravi/Downloads/setup-installer.exe"
              and rec["agent_id"] == "010")
        check("status awal pending", rec.get("status") == "pending")
        check("did = 16 karakter pertama hash", rec.get("did") == HASH[:16])
        check("hitl ditandai", rec.get("hitl") is True)

        # dedup deteksi sama: tenggat tidak di-reset
        first_deadline = rec["deadline_ts"]
        post(base + "/decision/pending", {"hash": HASH, "agent_id": "010",
                                         "filepath": "/home/ravi/Downloads/setup-installer.exe",
                                         "severity": "MEDIUM", "hitl": True})
        check("pendaftaran ulang tidak reset tenggat",
              get(base + "/decision/pending")["items"][0]["deadline_ts"] == first_deadline)

        # validasi input
        code, _ = post_expect_error(base + "/decision/pending", {"hash": "bad hash!", "agent_id": "010",
                                                                 "filepath": "/tmp/x"})
        check("hash tidak valid -> 400", code == 400)
        code, _ = post_expect_error(base + "/decision/pending", {"hash": "b" * 64, "agent_id": "010"})
        check("filepath kosong -> 400", code == 400)
        code, _ = post_expect_error(base + "/decision/pending", {"hash": "b" * 64, "agent_id": "a b",
                                                                 "filepath": "/tmp/x"})
        check("agent_id tidak valid -> 400", code == 400)

        # resolve -> target aksi diambil dari registry (bukan dari teks pesan)
        res = post(base + "/decision/resolve", {"hash": HASH[:16], "action": "quarantine",
                                                "by": "Ravi", "dst": True})
        check("resolve ok + found", res.get("ok") is True and res.get("found") is True)
        check("resolve via did pendek (callback Telegram) -> entri tepat",
              res.get("hash") == HASH)
        check("resolve mengembalikan filepath registry",
              res.get("filepath") == "/home/ravi/Downloads/setup-installer.exe")
        check("resolve mengembalikan agent", res.get("agent_id") == "010")
        check("response_secs terisi", isinstance(res.get("response_secs"), int))
        dup = post(base + "/decision/resolve", {"hash": HASH, "action": "quarantine", "by": "Ravi"})
        check("resolve ulang -> duplicate", dup.get("duplicate") is True)
        audit = get(base + "/decision/audit")
        check("audit berisi 1 catatan (tanpa dobel)", audit.get("count") == 1)
        check("audit memuat pelaku & aksi", audit["items"][0].get("by") == "Ravi"
              and audit["items"][0].get("action") == "quarantine")
        check("audit terfilter by hash", get(base + "/decision/audit?hash=" + HASH).get("count") == 1)
        check("audit hash lain -> 0", get(base + "/decision/audit?hash=" + "c" * 64).get("count") == 0)
        check("resolve tidak mengembalikan lagi sebagai pending",
              get(base + "/decision/pending").get("count") == 0)

        # hash tak terdaftar -> fail-open (200, found=false), callback tetap lanjut
        nf = post(base + "/decision/resolve", {"hash": "d" * 64, "action": "acknowledged", "by": "Ravi"})
        check("hash tak dikenal fail-open", nf.get("ok") is False and nf.get("found") is False)
        code, _ = post_expect_error(base + "/decision/resolve", {"hash": "d" * 64, "action": "hack"})
        check("action tak dikenal -> 400", code == 400)

        # jalur HITL kedua: rantai proses (AR dimatikan) + eskalasi lewat tenggat
        H2 = "e" * 64
        post(base + "/decision/pending", {"hash": H2, "agent_id": "005", "filepath": "C:\\Users\\ravi\\x.exe",
                                          "severity": "MEDIUM", "tier": "hitl-chain", "hitl": True,
                                          "action_kind": "acknowledge", "deadline_secs": 900})
        # tier otomatis: dicatat untuk audit, tapi TIDAK pernah masuk eskalaasi
        post(base + "/decision/pending", {"hash": "9" * 64, "agent_id": "010",
                                          "filepath": "/home/ravi/Downloads/x.exe",
                                          "severity": "CRITICAL", "tier": "auto-critical",
                                          "hitl": False, "action_kind": "fp_only"})
        check("tier otomatis tanpa tenggat",
              get(base + "/decision/pending")["items"][-1].get("deadline_ts") is None)
        check("item kedua belum overdue", get(base + "/decision/pending?overdue=1").get("count") == 0)
        M.DECISIONS[H2]["deadline_ts"] = time.time() - 5
        M.DECISIONS[H2]["created_ts"] = time.time() - 905
        od = get(base + "/decision/pending?overdue=1")
        check("item lewat tenggat -> overdue=1", od.get("count") == 1 and od["items"][0]["hash"] == H2)
        check("tier otomatis tak ikut terlambat walau lama",
              all(i.get("hash") != "9" * 64 for i in od["items"]))
        check("overdue_secs dihitung", od["items"][0]["overdue_secs"] >= 5)
        esc = post(base + "/decision/escalate", {"hash": H2})
        check("eskalasi tercatat", esc.get("ok") is True and bool(esc.get("escalated_at")))
        check("setelah dieskalasi tidak masuk overdue lagi (anti-spam)",
              get(base + "/decision/pending?overdue=1").get("count") == 0)
        check("masih terlihat via ?all=1", any(
            i.get("hash") == H2 and i.get("status") == "escalated"
            for i in get(base + "/decision/pending?all=1")["items"]))
        code, _ = post_expect_error(base + "/decision/escalate", {"hash": H2})
        check("eskalasi ulang -> 404", code == 404)

        # stats keputusan (bukti metrik M3)
        dst = get(base + "/stats")["decisions"]
        check("stats decisions total=3", dst.get("total") == 3)
        check("stats by_action quarantine=1", dst["by_action"].get("quarantine") == 1)
        check("stats memisahkan hitl vs otomatis", dst.get("hitl") == 2 and dst.get("auto") == 1)
        check("stats by_tier terisi", dst["by_tier"].get("hitl-review") == 1)
        check("mean_response_secs terisi", isinstance(dst.get("mean_response_secs"), (int, float)))
        check("stats deadline default 900", dst.get("deadline_secs_default") == 900)

        # persist lintas-restart (file state + audit JSONL)
        check("state file keputusan ditulis", os.path.exists(M.DECISION_FILE))
        reloaded = M._load_decisions()
        check("muat ulang state -> 3 entri", len(reloaded) == 3)
        check("entri resolved tetap resolved", reloaded[HASH]["status"] == "resolved")
        check("audit JSONL ditulis", os.path.exists(M.DECISION_AUDIT_FILE))

        # TTL: entri sangat lama tidak lagi dipakai
        M.DECISIONS["f" * 64] = {"hash": "f" * 64, "did": "f" * 16, "hitl": True,
                                 "agent_id": "010", "filepath": "/tmp/old",
                                 "created_ts": time.time() - M.DECISION_TTL_SECS - 10,
                                 "deadline_ts": time.time() - 1000, "status": "pending"}
        check("entri kadaluwarsa ditandai expired",
              any(i.get("hash") == "f" * 64 and i.get("status") == "expired"
                  for i in get(base + "/decision/pending?all=1")["items"]))

        # token opsional untuk endpoint tulis keputusan
        M.LOG_TOKEN = "token-rahasia-panjang"
        r = post(base + "/log", {"workflow": "x"})
        check("/log tetap tanpa token", r.get("ok") is True)
        code, _ = post_expect_error(base + "/decision/pending", {"hash": "1" * 64, "agent_id": "010",
                                                                 "filepath": "/tmp/x"})
        check("decision/pending tanpa token -> 401", code == 401)
        ok = post(base + "/decision/pending", {"hash": "1" * 64, "agent_id": "010", "filepath": "/tmp/x"},
                  {"Authorization": "Bearer token-rahasia-panjang"})
        check("decision/pending dengan token -> ok", ok.get("ok") is True)
        M.LOG_TOKEN = ""
        check("healthz melaporkan jumlah pending", isinstance(get(base + "/healthz").get("decisions_pending"), int))
    finally:
        srv.shutdown()

    print(f"\n{passed}/{passed + failed} lulus")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
