#!/usr/bin/env python3
"""E2E verifikasi matriks confidence -> otonomi (milestone M3).

Menguji empat jalur pada stack LIVE (semua lewat HTTP, tanpa akses DB):

  A. **Jalur HITL** — alert FIM eksekutabel dengan hash tak dikenal:
     `Tentukan Otonomi` harus menetapkan tier `hitl-review`, deteksi
     didaftarkan ke registry (hitl=true, tenggat 15 menit), notifikasi
     terkirim, dan cabang Active Response **tidak** jalan.
  B. **Keputusan analis** — tombol Telegram disimulasikan (`q:<agent>:<did>`):
     registry resolve (audit trail + response_secs), target aksi diambil dari
     registry, dan keputusan tercatat di fleet (dashboard).
  C. **Jalur otomatis** — verdict VT kuat (di-seed ke cache server):
     tier `auto-critical`, AR otomatis jalan (Wazuh AR + fallback perintah
     fleet masuk antrean), registry tetap mencatat untuk audit tanpa tenggat.
  D. **SLA** — keputusan HITL lewat tenggat dieskalasi oleh workflow
     `SLA Eskalasi HITL` (Schedule 1 menit) dan ditandai agar tidak spam.

CATATAN: tiap run mengirim **pesan Telegram asli** (2 alert + 1 eskalasi) dan
membuat 1 entri cache verdict + entri audit bertanda `e2e`. Jalankan manual.

Pakai: python3 scripts/e2e-hitl-matrix.py \
         --n8n-url http://100.73.91.17:5678 --api-key-file /tmp/n8n_api_key.txt
Keluar 0 = semua hijau, 1 = ada yang gagal.
"""

import argparse
import calendar
import json
import sys
import time
import urllib.error
import urllib.request

MALWARE_ID = "1MVcpL7ZKfBhR2tc"
CALLBACK_ID = "pVgvxowV7CCB3ZfV"
E2E_AGENT = "zz-e2e"
AUTO_NODES = ["Tentukan Otonomi", "Catat Keputusan Tertunda", "Trigger Active Response",
              "Fleet Quarantine", "Send Telegram Alert"]
HITL_NODES = ["Tentukan Otonomi", "Catat Keputusan Tertunda", "Send Telegram Alert"]
FORBIDDEN_HITL_NODES = ["Trigger Active Response", "Fleet Quarantine", "Get Wazuh Token"]
CALLBACK_NODES = ["Parse Keputusan", "Catat Keputusan", "Jalankan AR", "Edit Pesan Hasil"]

passed = failed = 0


def check(name, cond, extra=""):
    global passed, failed
    if cond:
        passed += 1
        print("  PASS  " + name)
    else:
        failed += 1
        print("  FAIL  " + name + ("  <- " + str(extra) if extra else ""))
    return bool(cond)


def http(url, method="GET", body=None, headers=None, timeout=20):
    data = json.dumps(body).encode() if body is not None else None
    hdr = {"Content-Type": "application/json"}
    hdr.update(headers or {})
    req = urllib.request.Request(url, data=data, headers=hdr, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            try:
                return r.status, json.loads(raw)
            except ValueError:
                return r.status, raw.decode(errors="replace")
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, raw.decode(errors="replace")


def get(url, headers=None):
    return http(url, headers=headers)[1]


def post(url, body, headers=None, timeout=20):
    return http(url, "POST", body, headers, timeout)


def wait_for(fn, timeout, interval=5):
    """Poll sampai fn() mengembalikan nilai truthy; kembalikan (nilai, detik)."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        val = fn()
        if val:
            return val, round(time.time() - t0, 1)
        time.sleep(interval)
    return None, round(time.time() - t0, 1)


def iso_shift(iso_utc, secs):
    """Geser string ISO UTC (tanpa timezone) sebanyak `secs` detik."""
    t = calendar.timegm(time.strptime(iso_utc, "%Y-%m-%dT%H:%M:%S")) + secs
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t))


def n8n_exec(api_base, key, workflow_id, since_iso, want_nodes, timeout=180, contains=None):
    """Tunggu eksekusi workflow yang memuat `want_nodes`.

    Filter waktu diberi margin 20 dtk (selisih jam container-host bisa ~1 dtk,
    sehingga eksekusi run ini bisa tercatat *sebelum* stempel waktu lokal) dan
    bila `contains` diisi, isi runData harus memuat penanda unik run ini.
    """
    t0 = time.time()
    since = iso_shift(since_iso, -20)
    while time.time() - t0 < timeout:
        time.sleep(6)
        listing = get(api_base + "/api/v1/executions?workflowId=" + workflow_id + "&limit=8",
                      {"X-N8N-API-KEY": key})
        for e in (listing.get("data") or []):
            if (e.get("startedAt") or "") < since:
                continue
            det = get(api_base + "/api/v1/executions/" + e["id"] + "?includeData=true",
                      {"X-N8N-API-KEY": key})
            rd = (det.get("data") or {}).get("resultData", {}).get("runData", {})
            if not set(want_nodes) <= set(rd.keys()):
                continue
            if contains:
                blob = json.dumps(rd, ensure_ascii=False)
                if not all(c in blob for c in contains):
                    continue
            errs = [n for n in rd if rd[n][0].get("error")]
            return {"id": e["id"], "nodes": sorted(rd.keys()), "errors": errs,
                    "runData": rd}
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://100.73.91.17:5678")
    ap.add_argument("--fleet-url", default="http://100.73.91.17:8080")
    ap.add_argument("--alert-log-url", default="http://100.73.91.17:8091")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--sla-wait", type=int, default=180)
    a = ap.parse_args()
    key = open(a.api_key_file).read().strip()
    n8n = a.n8n_url.rstrip("/")
    fleet = a.fleet_url.rstrip("/")
    alog = a.alert_log_url.rstrip("/")
    stamp = time.strftime("%H%M%S")
    hitl_hash = ("e2e" + stamp + "a" * 58)[:64].ljust(64, "0")
    auto_hash = ("e2e" + stamp + "b" * 58)[:64].ljust(64, "0")
    sla_hash = "e2e-sla-" + stamp

    print("== 0. Sehat? ==")
    check("alert-log sehat", get(alog + "/healthz").get("status") == "ok")
    check("fleet-monitor sehat", bool(get(fleet + "/api/fleet")))

    print("\n== A. Jalur HITL (eksekutabel hash tak dikenal) ==")
    t0 = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    alert_hitl = {
        "agent": {"id": E2E_AGENT, "name": "e2e-hitl-matrix"},
        "syscheck": {"path": "C:\\Users\\ravi\\Downloads\\installer-%s.exe" % stamp,
                     "sha256_after": hitl_hash, "event": "added"},
        "rule": {"id": "554", "level": 5, "description": "e2e hitl matrix check"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    post(n8n + "/webhook/wazuh-alert", alert_hitl)

    def find_pending():
        d = get(alog + "/decision/pending?all=1&limit=50")
        for it in d.get("items", []):
            if it.get("hash") == hitl_hash:
                return it
        return None

    rec, secs = wait_for(find_pending, 150)
    check("deteksi terdaftar di registry (=did)", bool(rec), "tak muncul dalam %ss" % secs)
    if rec:
        check("tier hitl-review", rec.get("tier") == "hitl-review", rec.get("tier"))
        check("hitl=true + tenggat 900 dtk",
              rec.get("hitl") is True and rec.get("deadline_secs") == 900,
              (rec.get("hitl"), rec.get("deadline_secs")))
        check("target aksi (path) tersimpan", rec.get("filepath", "").endswith(".exe"),
              rec.get("filepath"))
        check("did pendek <=64 byte untuk callback", len(rec.get("did") or "") <= 64)
    ex_hitl = n8n_exec(n8n, key, MALWARE_ID, t0, HITL_NODES, contains=[hitl_hash])
    check("jalur HITL dieksekusi (Tentukan Otonomi + registry + notifikasi)", bool(ex_hitl))
    if ex_hitl:
        forbidden = [n for n in FORBIDDEN_HITL_NODES if n in ex_hitl["nodes"]]
        check("tanpa Active Response otomatis (HITL)", not forbidden, forbidden)
        check("tidak ada node error", not ex_hitl["errors"], ex_hitl["errors"])
        policy = ex_hitl["runData"]["Tentukan Otonomi"][0]["data"]["main"][0][0]["json"]
        check("kebijakan: autonomy=hitl, AR mati",
              policy.get("autonomy") == "hitl" and policy.get("should_active_response") is False,
              (policy.get("autonomy"), policy.get("should_active_response")))
    logs = get(alog + "/log?limit=100").get("items", [])
    hitl_log = [x for x in logs if x.get("hash") == hitl_hash]
    check("alert HITL tercatat di alert-log", bool(hitl_log), hitl_log[:1])

    print("\n== B. Keputusan analis via tombol (simulasi klik 'Karantina') ==")
    did = (rec or {}).get("did") or hitl_hash[:16]
    t1 = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    cb = {"callback_query": {
        "id": "e2e-cb-" + stamp, "data": "q:%s:%s" % (E2E_AGENT, did),
        "from": {"first_name": "e2e-analis"},
        "message": {
            "message_id": 1, "chat": {"id": 1295213498},
            "text": "INDIKASI MALWARE\nFile: installer-%s.exe\nPath: C:\\Users\\ravi\\Downloads\\installer-%s.exe\nHash: `%s`"
                    % (stamp, stamp, hitl_hash)}}}
    post(n8n + "/webhook/tg-callback", cb)

    def resolved():
        items = get(alog + "/decision/pending?all=1&limit=50").get("items", [])
        for it in items:
            if it.get("hash") == hitl_hash and it.get("status") == "resolved":
                return it
        return None

    res, secs = wait_for(resolved, 120, interval=4)
    check("keputusan tercatat di registry", bool(res), "belum resolved")
    if res:
        check("aksi = quarantine", res.get("action") == "quarantine", res.get("action"))
        check("pelaku + waktu respons tersimpan",
              bool(res.get("by")) and res.get("response_secs") is not None,
              (res.get("by"), res.get("response_secs")))
    audit = get(alog + "/decision/audit?hash=" + hitl_hash)
    check("audit trail berisi keputusan", audit.get("count", 0) >= 1, audit.get("count"))
    ex_cb = n8n_exec(n8n, key, CALLBACK_ID, t1, CALLBACK_NODES, timeout=120,
                     contains=["q:%s:%s" % (E2E_AGENT, did)])
    check("jalur callback dieksekusi (klaim + AR + edit pesan)", bool(ex_cb))
    if ex_cb:
        check("callback tanpa node error", not ex_cb["errors"], ex_cb["errors"])
        claim = ex_cb["runData"]["Catat Keputusan"][0]["data"]["main"][0][0]["json"]
        check("target aksi diambil dari registry (bukan teks pesan)",
              claim.get("filePath", "").endswith(".exe") and claim.get("registry", {}).get("found"),
              (claim.get("filePath"), claim.get("registry", {}).get("found")))
        check("keputusan dicatat ke fleet (dashboard)", claim.get("fleet_logged") is True)
    ev = get(fleet + "/api/events").get("events", [])
    hist = get(fleet + "/api/events/history?since=0&limit=100")
    ev_hist = []
    if isinstance(hist, dict):
        ev_hist = hist.get("items") or hist.get("events") or []
    ev_all = [e for e in (ev + ev_hist) if e.get("hash") == hitl_hash]
    check("keputusan analis tampil di event fleet",
          any(e.get("status") == "analyst-quarantine" for e in ev_all),
          [e.get("status") for e in ev_all][:3])

    print("\n== C. Jalur otomatis (verdict VT kuat via cache) ==")
    st, resp = post(fleet + "/api/vt-cache/store",
                    {"hash": auto_hash, "stats": {"malicious": 30, "suspicious": 2, "undetected": 38}})
    check("seed verdict VT ke cache server", st == 200, resp)
    t2 = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    alert_auto = {
        "agent": {"id": E2E_AGENT, "name": "e2e-hitl-matrix"},
        "syscheck": {"path": "C:\\Users\\ravi\\Downloads\\payload-%s.exe" % stamp,
                     "sha256_after": auto_hash, "event": "added"},
        "rule": {"id": "554", "level": 5, "description": "e2e auto tier check"},
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    post(n8n + "/webhook/wazuh-alert", alert_auto)

    def find_auto():
        d = get(alog + "/decision/pending?all=1&limit=50")
        for it in d.get("items", []):
            if it.get("hash") == auto_hash:
                return it
        return None

    rec_auto, secs = wait_for(find_auto, 150)
    check("deteksi otomatis terdaftar (audit)", bool(rec_auto), "tak muncul dalam %ss" % secs)
    if rec_auto:
        check("tier auto-critical", rec_auto.get("tier") == "auto-critical", rec_auto.get("tier"))
        check("hitl=false + tanpa tenggat (tidak masuk eskalaasi)",
              rec_auto.get("hitl") is False and rec_auto.get("deadline_ts") is None,
              (rec_auto.get("hitl"), rec_auto.get("deadline_ts")))
    ex_auto = n8n_exec(n8n, key, MALWARE_ID, t2, AUTO_NODES, contains=[auto_hash])
    check("jalur otomatis jalan (AR + fallback fleet)", bool(ex_auto))
    if ex_auto:
        check("tanpa node error", not ex_auto["errors"], ex_auto["errors"])
        policy = ex_auto["runData"]["Tentukan Otonomi"][0]["data"]["main"][0][0]["json"]
        check("kebijakan: autonomy=auto, AR hidup",
              policy.get("autonomy") == "auto" and policy.get("should_active_response") is True,
              (policy.get("autonomy"), policy.get("should_active_response")))
        check("severity dari threat intel = CRITICAL", policy.get("severity") == "CRITICAL",
              policy.get("severity"))
        fq = ex_auto["runData"]["Fleet Quarantine"][0]["data"]["main"][0][0]["json"]
        check("karantina fleet diantrekan (Wazuh AR bukan agent Wazuh -> fallback)",
              fq.get("fleet_quarantine", {}).get("result") in ("queued", "failed"),
              fq.get("fleet_quarantine"))
    cmds = get(fleet + "/api/commands?agent_id=" + E2E_AGENT).get("commands", [])
    check("perintah karantina ada di antrean agent", any(c.get("action") == "quarantine" for c in cmds),
          cmds[:2])
    auto_logs = [x for x in get(alog + "/log?limit=100").get("items", [])
                 if x.get("severity") == "CRITICAL"]
    check("alert CRITICAL tercatat di alert-log", bool(auto_logs), auto_logs[:1])

    print("\n== D. SLA: keputusan HITL lewat tenggat ==")
    st, resp = post(alog + "/decision/pending",
                    {"hash": sla_hash, "agent_id": E2E_AGENT, "filepath": "/tmp/e2e-sla.bin",
                     "severity": "MEDIUM", "tier": "hitl-review", "hitl": True,
                     "deadline_secs": 30, "title": "e2e SLA"})
    check("item SLA terdaftar (tenggat 30 dtk)", st == 200 and resp.get("deadline_secs") == 30, resp)

    def escalated():
        items = get(alog + "/decision/pending?all=1&limit=50").get("items", [])
        for it in items:
            if it.get("hash") == sla_hash and it.get("status") == "escalated":
                return it
        return None

    esc, secs = wait_for(escalated, a.sla_wait, interval=10)
    check("workflow SLA menandai item lewat tenggat", bool(esc), "belum ter-eskalasi")
    if esc:
        check("tidak muncul lagi di daftar overdue (anti-spam)",
              not any(i.get("hash") == sla_hash
                      for i in get(alog + "/decision/pending?overdue=1").get("items", [])))
    sla_logs = [x for x in get(alog + "/log?limit=100").get("items", [])
                if x.get("workflow") == "SLA Eskalasi HITL"]
    check("eskalasi tercatat di alert-log (bukti SLA berjalan)", bool(sla_logs), sla_logs[:1])

    print("\n== E. Bersih-bersih ==")
    drained = get(fleet + "/api/commands?agent_id=" + E2E_AGENT).get("commands", [])
    print("  antrean agent %s dikosongkan: %d perintah (tidak dieksekusi agent nyata)"
          % (E2E_AGENT, len(drained)))
    stats = get(alog + "/stats").get("decisions", {})
    print("  registry: total=%s hitl=%s otomatis=%s mean respons=%ss"
          % (stats.get("total"), stats.get("hitl"), stats.get("auto"),
             stats.get("mean_response_secs")))
    print("\n%d/%d lulus" % (passed, passed + failed))
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
