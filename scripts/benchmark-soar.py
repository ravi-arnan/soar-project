#!/usr/bin/env python3
"""Benchmark & load-test untuk Sistem SOAR (Wazuh + n8n).

Ukur MTTR (Mean Time To Respond) untuk:
  1. Malware auto-isolate  (VT cache hangat vs dingin)
  2. Phishing auto-block   (GSB cepat vs URLScan)
  3. Load test             (N alert serentak → throughput, antrean, latensi)
  4. False-negative rate   (zero-day / file tak-dikenal)

Metodologi selaras dengan docs/evaluasi/EVALUASI-METRIK.md.

Usage:
    python3 benchmark-soar.py --mode mttr-malware  --n 30 --delay 2
    python3 benchmark-soar.py --mode mttr-fleet    --n 30 --delay 16
    (mttr-fleet: ukur injeksi -> event fleet-log; jujur untuk webhook onReceived)
    python3 benchmark-soar.py --mode mttr-phishing --n 10 --delay 5
    python3 benchmark-soar.py --mode mttr-hitl     --n 10 --delay 3
    python3 benchmark-soar.py --mode load          --n 20 --concurrency 5
    python3 benchmark-soar.py --mode vt-cold       --n 6 --delay 16
    python3 benchmark-soar.py --mode fn-rate       --n 15
    python3 benchmark-soar.py --mode all           --n 30

Mode baru:
    mttr-hitl : latensi notifikasi HITL + latensi dispatch Active Response
                (komponen otomatis; waktu berpikir analis di luar otomasi).
    vt-cold   : cold vs cache END-TO-END (injeksi -> fleet-log), hash sama /
                path beda agar cache-hit jujur. Butuh N8N_API_KEY_FILE
                (/tmp/n8n_api_key.txt) + fleet :8080 + Wazuh API :55000.

Output: JSON ke stdout + ringkasan tabel ke stderr.
"""

import argparse
import base64
import hashlib
import json
import os
import random
import ssl
import statistics
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ─── Konfigurasi ────────────────────────────────────────────────────────
N8N_WEBHOOK_MALWARE = os.getenv(
    "N8N_WEBHOOK_MALWARE", "http://localhost:5678/webhook/wazuh-alert"
)
N8N_WEBHOOK_PHISHING = os.getenv(
    "N8N_WEBHOOK_PHISHING", "http://localhost:5678/webhook/wazuh-phishing"
)
FLEET_EVENTS_URL = os.getenv("FLEET_EVENTS_URL", "http://localhost:8080/api/events")
WAZUH_API = os.getenv("WAZUH_API", "https://172.17.0.1:55000")
AGENT_ID = os.getenv("AGENT_ID", "001")
AGENT_NAME = os.getenv("AGENT_NAME", "ravi-zorin")
TIMEOUT = int(os.getenv("BENCH_TIMEOUT", "120"))  # detik per alert

# Endpoint tambahan untuk mode HITL & VT cold-vs-cache (end-to-end)
N8N_API = os.getenv("N8N_API", "http://localhost:5678")
N8N_API_KEY_FILE = os.getenv("N8N_API_KEY_FILE", "/tmp/n8n_api_key.txt")
MALWARE_WORKFLOW_ID = os.getenv("MALWARE_WORKFLOW_ID", "1MVcpL7ZKfBhR2tc")
VT_CACHE_URL = os.getenv("VT_CACHE_URL", "http://localhost:8080/api/vt-cache")
WAZUH_API_BASE = os.getenv("WAZUH_API_BASE", "https://127.0.0.1:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASS = os.getenv("WAZUH_API_PASS", "MyS3cr37P450r.*-")
HITL_AGENT_ID = os.getenv("HITL_AGENT_ID", "001")  # agent Wazuh untuk uji AR aman

# EICAR test file (dikenal VT → isolasi otomatis)
EICAR_HASH = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"

# Phishing test URLs (AMTSO + beberapa known-phishing untuk GSB)
PHISHING_URLS_SAFE = [
    "https://www.amtso.org/check-desktop-phishing-page/",
    "https://www.amtso.org/check-desktop-phishing-sample/",
]
PHISHING_URLS_MALICIOUS = [
    # Contoh URL yang terdaftar di GSB (update sesuai kebutuhan)
    "http://malware.testcategory.com/",
]

# ─── Helpers ────────────────────────────────────────────────────────────


def ts_now():
    return datetime.now(timezone.utc).isoformat()


def http_post(url, payload, timeout=TIMEOUT):
    """POST JSON, return (response_json, elapsed_ms)."""
    data = json.dumps(payload).encode()
    req = Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    t0 = time.monotonic()
    try:
        with urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode()
            elapsed = (time.monotonic() - t0) * 1000
            return json.loads(body) if body else {}, elapsed
    except HTTPError as e:
        elapsed = (time.monotonic() - t0) * 1000
        return {"error": str(e), "code": e.code}, elapsed
    except (URLError, OSError) as e:
        elapsed = (time.monotonic() - t0) * 1000
        return {"error": str(e)}, elapsed


def http_get(url, timeout=10):
    """GET JSON, return dict ({} jika gagal)."""
    try:
        with urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except (URLError, OSError, ValueError):
        return {}


_SSL_CTX = ssl.create_default_context()
_SSL_CTX.check_hostname = False
_SSL_CTX.verify_mode = ssl.CERT_NONE


def http_json(url, method="GET", payload=None, headers=None, timeout=30, insecure=False):
    """Request JSON generik, return (dict, elapsed_ms). Tak melempar (error → {})."""
    data = json.dumps(payload).encode() if payload is not None else None
    req = Request(url, data=data, method=method, headers=headers or {})
    t0 = time.monotonic()
    try:
        with urlopen(req, timeout=timeout, context=_SSL_CTX if insecure else None) as r:
            body = r.read().decode()
        return (json.loads(body) if body else {}), (time.monotonic() - t0) * 1000
    except (HTTPError, URLError, OSError, ValueError) as e:
        return {"error": str(e)}, (time.monotonic() - t0) * 1000


def n8n_api_key():
    key = os.getenv("N8N_API_KEY")
    if key:
        return key.strip()
    try:
        return open(N8N_API_KEY_FILE).read().strip()
    except OSError:
        return ""


def n8n_exec_duration(workflow_id, since_dt, key, timeout=120, poll=2):
    """Durasi (detik) eksekusi n8n pertama (mulai >= since_dt) untuk workflow_id.

    Dipakai sebagai latensi pipeline end-to-end (injeksi -> selesai, termasuk
    node Telegram/Send Alert). Return (durasi_detik, exec_id) atau (None, None).
    """
    deadline = time.monotonic() + timeout
    hdr = {"X-N8N-API-KEY": key}
    while time.monotonic() < deadline:
        try:
            with urlopen(
                Request(
                    f"{N8N_API}/api/v1/executions?workflowId={workflow_id}&limit=20",
                    headers=hdr,
                ),
                timeout=15,
            ) as r:
                data = json.loads(r.read().decode())
        except (HTTPError, URLError, OSError, ValueError):
            data = {}
        cands = []
        for e in data.get("data", []):
            sa, st = e.get("startedAt"), e.get("stoppedAt")
            if not sa or not st:
                continue
            try:
                sad = datetime.fromisoformat(sa.replace("Z", "+00:00"))
                std = datetime.fromisoformat(st.replace("Z", "+00:00"))
            except ValueError:
                continue
            if sad >= since_dt:
                cands.append((sad, (std - sad).total_seconds(), e.get("id")))
        if cands:
            cands.sort(key=lambda x: x[0])
            return round(cands[0][1], 2), cands[0][2]
        time.sleep(poll)
    return None, None


def wazuh_token(timeout=15):
    auth = "Basic " + base64.b64encode(
        f"{WAZUH_API_USER}:{WAZUH_API_PASS}".encode()
    ).decode()
    d, _ = http_json(
        f"{WAZUH_API_BASE}/security/user/authenticate",
        method="POST",
        headers={"Authorization": auth},
        timeout=timeout,
        insecure=True,
    )
    return (d.get("data") or {}).get("token") if isinstance(d, dict) else None


def random_hash():
    """Generate random SHA256 (tidak dikenal VT → zero-day path)."""
    return hashlib.sha256(os.urandom(32)).hexdigest()


def fake_fim_alert(filename, filepath, sha256, rule_level=10, agent_id=AGENT_ID):
    """Bangun payload FIM alert yang meniru Wazuh."""
    return {
        "rule": {
            "id": "553",
            "level": rule_level,
            "description": "File added to the system.",
        },
        "syscheck": {
            "path": filepath,
            "sha256_after": sha256,
            "event": "added",
            "perm_after": "rw-r--r--",
        },
        "agent": {"id": agent_id, "name": AGENT_NAME, "ip": "192.168.1.10"},
        "timestamp": ts_now(),
    }


def fake_phishing_alert(url, srcip="192.168.1.50", agent_id=AGENT_ID):
    """Bangun payload phishing alert yang meniru Wazuh."""
    return {
        "rule": {"id": "100002", "level": 10, "description": "Phishing URL detected."},
        "data": {"url": url, "srcip": srcip, "event_type": "phishing_url"},
        "agent": {"id": agent_id, "name": AGENT_NAME},
        "timestamp": ts_now(),
    }


def stats_summary(samples, label=""):
    """Hitung statistik dari list float (ms atau detik)."""
    if not samples:
        return {}
    s = sorted(samples)
    n = len(s)
    return {
        "label": label,
        "n": n,
        "mean": round(statistics.mean(s), 2),
        "median": round(statistics.median(s), 2),
        "min": round(min(s), 2),
        "max": round(max(s), 2),
        "stdev": round(statistics.stdev(s), 2) if n > 1 else 0,
        "p95": round(s[int(n * 0.95)] if n > 1 else s[0], 2),
        "p99": round(s[int(n * 0.99)] if n > 1 else s[0], 2),
        "samples": s,
    }


def print_table(stats, unit="ms"):
    """Cetak tabel ringkasan ke stderr."""
    print(f"\n{'=' * 60}", file=sys.stderr)
    print(f"  {stats.get('label', 'Results')}  (N={stats['n']})", file=sys.stderr)
    print(f"{'=' * 60}", file=sys.stderr)
    print(f"  Rata-rata : {stats['mean']:.2f} {unit}", file=sys.stderr)
    print(f"  Median    : {stats['median']:.2f} {unit}", file=sys.stderr)
    print(
        f"  Min – Max : {stats['min']:.2f} – {stats['max']:.2f} {unit}", file=sys.stderr
    )
    print(f"  Std dev   : ±{stats['stdev']:.2f} {unit}", file=sys.stderr)
    print(f"  P95       : {stats['p95']:.2f} {unit}", file=sys.stderr)
    print(f"  P99       : {stats['p99']:.2f} {unit}", file=sys.stderr)
    print(f"{'=' * 60}\n", file=sys.stderr)


# ─── Mode: MTTR Malware ────────────────────────────────────────────────


def bench_mttr_malware(n, delay):
    """Ukur waktu dari alert injection hingga n8n selesai proses.
    Catatan: MTTR di sini = waktu HTTP response n8n (seluruh pipeline).
    Untuk isolasi sebenarnya perlu cek / Downloads terkarantina.
    """
    print(f"[mttr-malware] N={n}, delay={delay}s antar-run", file=sys.stderr)
    samples_sec = []
    results = []

    for i in range(n):
        h = EICAR_HASH  # hangat: VT sudah punya verdict
        fname = f"bench-malware-{i:03d}.com"
        fpath = f"/home/{AGENT_NAME}/Downloads/{fname}"
        payload = fake_fim_alert(fname, fpath, h, rule_level=12)

        t0 = time.monotonic()
        resp, elapsed_ms = http_post(N8N_WEBHOOK_MALWARE, payload)
        elapsed_sec = elapsed_ms / 1000
        samples_sec.append(elapsed_sec)

        results.append(
            {
                "run": i + 1,
                "hash": h,
                "filename": fname,
                "elapsed_ms": round(elapsed_ms, 2),
                "elapsed_sec": round(elapsed_sec, 4),
                "response": resp,
                "timestamp": ts_now(),
            }
        )
        print(f"  [{i + 1:3d}/{n}] {elapsed_sec:.2f}s  hash={h[:12]}…", file=sys.stderr)

        if i < n - 1:
            time.sleep(delay)

    st = stats_summary(samples_sec, "MTTR Malware (VT cache hangat)")
    st["unit"] = "detik"
    print_table(st, "detik")
    return {"mode": "mttr_malware", "stats": st, "runs": results}


# ─── Mode: MTTR Malware via Fleet Log ────────────────────────────────


def bench_mttr_fleet(n, delay, timeout=120):
    """Ukur MTTR end-to-end yang jujur: injeksi alert -> event verdict muncul
    di fleet-monitor /api/events (node Log ke Fleet, tepat setelah Rangkum
    Hasil). Dipakai karena webhook live ber-responseMode onReceived sehingga
    waktu HTTP response BUKAN waktu pipeline.
    """
    print(f"[mttr-fleet] N={n}, delay={delay}s antar-run", file=sys.stderr)
    samples_sec = []
    results = []
    tag = "mf" + "".join(random.choices(string.ascii_lowercase + string.digits, k=4))

    for i in range(n):
        fname = f"bench-{tag}-{i:03d}.com"
        fpath = f"/home/{AGENT_NAME}/Downloads/{fname}"
        payload = fake_fim_alert(fname, fpath, EICAR_HASH, rule_level=12)

        t0 = time.monotonic()
        http_post(N8N_WEBHOOK_MALWARE, payload)
        elapsed = None
        deadline = t0 + timeout
        while time.monotonic() < deadline:
            time.sleep(1)
            data = http_get(FLEET_EVENTS_URL)
            evs = data.get("events", data) if isinstance(data, dict) else data
            if isinstance(evs, list) and any(
                isinstance(e, dict) and e.get("path") == fpath for e in evs
            ):
                elapsed = time.monotonic() - t0
                break
        if elapsed is None:
            elapsed = timeout
            status = "timeout"
        else:
            status = "logged"
            samples_sec.append(elapsed)

        results.append(
            {
                "run": i + 1,
                "filename": fname,
                "path": fpath,
                "elapsed_sec": round(elapsed, 2),
                "status": status,
                "timestamp": ts_now(),
            }
        )
        print(f"  [{i + 1:3d}/{n}] {elapsed:.2f}s  {status}  {fname}", file=sys.stderr)

        if i < n - 1:
            time.sleep(delay)

    st = stats_summary(samples_sec, "MTTR Malware (injeksi -> fleet-log)")
    st["unit"] = "detik"
    st["timeouts"] = n - len(samples_sec)
    print_table(st, "detik")
    return {"mode": "mttr_fleet", "stats": st, "runs": results}


# ─── Mode: MTTR Phishing ───────────────────────────────────────────────


def bench_mttr_phishing(n, delay):
    """Ukur MTTR phishing: URL → n8n selesai proses (GSB + URLScan)."""
    print(f"[mttr-phishing] N={n}, delay={delay}s antar-run", file=sys.stderr)
    samples_sec = []
    results = []

    for i in range(n):
        url = PHISHING_URLS_SAFE[i % len(PHISHING_URLS_SAFE)]
        payload = fake_phishing_alert(url, srcip=f"10.0.{i // 256}.{i % 256}")

        t0 = time.monotonic()
        resp, elapsed_ms = http_post(N8N_WEBHOOK_PHISHING, payload)
        elapsed_sec = elapsed_ms / 1000
        samples_sec.append(elapsed_sec)

        results.append(
            {
                "run": i + 1,
                "url": url,
                "elapsed_ms": round(elapsed_ms, 2),
                "elapsed_sec": round(elapsed_sec, 4),
                "response": resp,
                "timestamp": ts_now(),
            }
        )
        print(f"  [{i + 1:3d}/{n}] {elapsed_sec:.2f}s  url={url[:50]}", file=sys.stderr)

        if i < n - 1:
            time.sleep(delay)

    st = stats_summary(samples_sec, "MTTR Phishing (GSB + URLScan)")
    st["unit"] = "detik"
    print_table(st, "detik")
    return {"mode": "mttr_phishing", "stats": st, "runs": results}


# ─── Mode: Load Test ───────────────────────────────────────────────────


def bench_load(n, concurrency):
    """Kirim N alert secara bersamaan (concurrency threads).
    Ukur throughput total dan latensi per alert.
    """
    print(f"[load] N={n}, concurrency={concurrency}", file=sys.stderr)

    def send_one(i):
        h = random_hash()  # semua unik → VT cold
        fname = f"bench-load-{i:03d}.bin"
        fpath = f"/home/{AGENT_NAME}/Downloads/{fname}"
        payload = fake_fim_alert(fname, fpath, h, rule_level=10)
        t0 = time.monotonic()
        resp, elapsed_ms = http_post(N8N_WEBHOOK_MALWARE, payload)
        return {
            "run": i + 1,
            "hash": h,
            "elapsed_ms": round(elapsed_ms, 2),
            "response": resp,
        }

    wall_start = time.monotonic()
    results = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {pool.submit(send_one, i): i for i in range(n)}
        for fut in as_completed(futures):
            r = fut.result()
            results.append(r)
            print(
                f"  [{r['run']:3d}/{n}] {r['elapsed_ms']:.0f}ms  hash={r['hash'][:12]}…",
                file=sys.stderr,
            )

    wall_total = (time.monotonic() - wall_start) * 1000
    latencies = [r["elapsed_ms"] for r in results]
    st = stats_summary(latencies, f"Load Test (concurrency={concurrency})")
    st["unit"] = "ms"
    st["wall_total_ms"] = round(wall_total, 2)
    st["throughput_per_sec"] = (
        round(n / (wall_total / 1000), 2) if wall_total > 0 else 0
    )
    print_table(st, "ms")
    print(f"  Wall time total: {wall_total / 1000:.1f}s", file=sys.stderr)
    print(
        f"  Throughput: {st['throughput_per_sec']:.2f} alert/detik\n", file=sys.stderr
    )
    return {"mode": "load", "stats": st, "runs": results}


# ─── Mode: VT Cold vs Cache ───────────────────────────────────────────


def _inject_and_wait(pairs, delay, phase):
    """Injeksi tiap (filename, hash) lalu tunggu path-nya muncul di fleet-log.

    Return (samples_detik_hanya_sukses, runs). Timeout tidak dihitung di sampel.
    """
    samples, runs = [], []
    n = len(pairs)
    for i, (fname, h) in enumerate(pairs):
        fpath = f"/home/{AGENT_NAME}/Downloads/{fname}"
        payload = fake_fim_alert(fname, fpath, h, rule_level=10)
        t0 = time.monotonic()
        http_post(N8N_WEBHOOK_MALWARE, payload)
        elapsed, status = None, "timeout"
        deadline = t0 + TIMEOUT
        while time.monotonic() < deadline:
            time.sleep(1)
            data = http_get(FLEET_EVENTS_URL)
            evs = data.get("events", data) if isinstance(data, dict) else data
            if isinstance(evs, list) and any(
                isinstance(e, dict) and e.get("path") == fpath for e in evs
            ):
                elapsed = time.monotonic() - t0
                status = "logged"
                break
        if elapsed is not None:
            samples.append(elapsed)
        val = elapsed if elapsed is not None else TIMEOUT
        runs.append(
            {
                "run": i + 1,
                "phase": phase,
                "hash": h,
                "path": fpath,
                "elapsed_sec": round(val, 2),
                "status": status,
            }
        )
        print(
            f"  {phase:4s} [{i + 1:3d}/{n}] {val:5.2f}s  {status}  {h[:12]}…",
            file=sys.stderr,
        )
        if i < n - 1:
            time.sleep(delay)
    return samples, runs


def bench_vt_cold(n, delay=16):
    """VT cold vs cache — END-TO-END (injeksi alert → event di fleet-log).

    - cold: N hash acak (belum dikenal) → n8n memanggil VirusTotal (+MB).
    - hot : hash SAMA diinjeksi ulang dengan **path BARU**. Dedup claim-check
      ber-key `agent|rule|hash|path`, jadi path baru LOLOS dedup sementara
      hash sama tetap kena **cache verdict** (TTL) → VT dilewati. Ini cache-hit
      yang jujur (versi lama salah: hash hot di-generate baru = selalu cold).
    """
    print(f"[vt-cold] N={n} cold + N={n} cache-hit (end-to-end)", file=sys.stderr)
    tag = "vc" + "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    cold_pairs = [(f"bench-{tag}-{i:03d}.bin", random_hash()) for i in range(n)]
    print(f"\n[vt-cold] fase COLD (hash baru → panggil VT)", file=sys.stderr)
    cold_samples, cold_runs = _inject_and_wait(cold_pairs, delay, "cold")

    hot_pairs = [
        (f"bench-{tag}-hot-{i:03d}.bin", h) for i, (_, h) in enumerate(cold_pairs)
    ]
    print(f"\n[vt-cold] fase HOT (hash sama, path beda → cache hit)", file=sys.stderr)
    hot_samples, hot_runs = _inject_and_wait(hot_pairs, 2, "hot")

    cold_st = stats_summary(cold_samples, "VT Cold (hash baru, panggil VT)")
    cold_st["unit"] = "detik"
    cold_st["timeouts"] = len(cold_runs) - len(cold_samples)
    hot_st = stats_summary(hot_samples, "VT Cache Hit (hash sama, path beda)")
    hot_st["unit"] = "detik"
    hot_st["timeouts"] = len(hot_runs) - len(hot_samples)

    for st in (cold_st, hot_st):
        if st:
            print_table(st, "detik")

    speedup = 0
    if cold_st and hot_st and cold_st.get("mean") and hot_st.get("mean"):
        speedup = cold_st["mean"] / hot_st["mean"]
        print(f"  Cache speedup: {speedup:.1f}x lebih cepat\n", file=sys.stderr)

    cache_stats = http_get(VT_CACHE_URL)
    return {
        "mode": "vt_cold_vs_cache",
        "cold": cold_st,
        "hot": hot_st,
        "speedup": round(speedup, 2),
        "vt_cache": cache_stats,
        "runs": {"cold": cold_runs, "hot": hot_runs},
    }


# ─── Mode: MTTR Human-in-the-Loop ──────────────────────────────────────


def bench_mttr_hitl(n, delay=3):
    """MTTR jalur human-in-the-loop — komponen OTOMATIS (tanpa waktu berpikir analis).

    Yang bisa diotomasi & aman:
      1) notif_latency : injeksi alert CRITICAL → eksekusi n8n selesai
         (termasuk pengiriman pesan Telegram bertombol = serah-terima ke analis).
      2) ar_latency    : "setelah klik" → Active Response ter-*dispatch* ke agent
         (PUT /active-response?wait_for_complete=true). AR **no-op & aman**:
         path sengaja tidak ada, jadi tidak ada berkas nyata yang dikarantina.

    Waktu berpikir analis TIDAK termasuk — itu manual / di luar otomasi.
    """
    print(f"[mttr-hitl] N={n} notif + N={n} AR-dispatch", file=sys.stderr)
    key = n8n_api_key()
    tag = "hitl" + "".join(random.choices(string.ascii_lowercase + string.digits, k=4))
    notif_samples, notif_runs = [], []
    for i in range(n):
        fname = f"bench-{tag}-{i:03d}.bin"
        fpath = f"/home/{AGENT_NAME}/Downloads/{fname}"
        payload = fake_fim_alert(fname, fpath, EICAR_HASH, rule_level=12)
        since = datetime.now(timezone.utc)
        http_post(N8N_WEBHOOK_MALWARE, payload)
        dur, eid = n8n_exec_duration(MALWARE_WORKFLOW_ID, since, key, timeout=TIMEOUT)
        if dur is not None:
            notif_samples.append(dur)
            notif_runs.append({"run": i + 1, "latency_sec": dur, "exec_id": eid, "path": fpath})
            print(f"  notif [{i + 1:3d}/{n}] {dur:5.2f}s  exec={eid}", file=sys.stderr)
        else:
            notif_runs.append({"run": i + 1, "latency_sec": None, "exec_id": None,
                               "path": fpath, "status": "timeout"})
            print(f"  notif [{i + 1:3d}/{n}] TIMEOUT", file=sys.stderr)
        if i < n - 1:
            time.sleep(delay)

    ar_samples, ar_runs = [], []
    tok = wazuh_token()
    if not tok:
        print("  (AR dilewati: token Wazuh gagal diperoleh)", file=sys.stderr)
    else:
        for i in range(n):
            body = {
                "command": "!quarantine-file",
                "arguments": [f"/tmp/bench-hitl-nonexistent-{tag}-{i:03d}.bin"],
            }
            d, ms = http_json(
                f"{WAZUH_API_BASE}/active-response?agents_list={HITL_AGENT_ID}"
                "&wait_for_complete=true",
                method="PUT",
                payload=body,
                headers={"Authorization": "Bearer " + tok, "Content-Type": "application/json"},
                timeout=30,
                insecure=True,
            )
            ok = isinstance(d, dict) and d.get("error") == 0
            ar_samples.append(ms / 1000)
            ar_runs.append({"run": i + 1, "elapsed_sec": round(ms / 1000, 4), "ok": ok})
            print(f"  ar    [{i + 1:3d}/{n}] {ms:6.1f}ms  ok={ok}", file=sys.stderr)

    notif_st = stats_summary(notif_samples, "MTTR HITL — notifikasi (injeksi→Telegram)")
    if notif_st:
        notif_st["unit"] = "detik"
        notif_st["timeouts"] = len(notif_runs) - len(notif_samples)
        print_table(notif_st, "detik")
    ar_st = stats_summary(ar_samples, "MTTR HITL — AR dispatch (keputusan→perintah)")
    if ar_st:
        ar_st["unit"] = "detik"
        print_table(ar_st, "detik")

    return {
        "mode": "mttr_hitl",
        "notif": notif_st,
        "ar_dispatch": ar_st,
        "note": "Komponen otomatis saja. Waktu berpikir analis TIDAK termasuk (manual).",
        "runs": {"notif": notif_runs, "ar": ar_runs},
    }


# ─── Mode: False-Negative Rate ────────────────────────────────────────


def bench_fn_rate(n):
    """Ukur false-negative rate: kirim file yang SEHARUSNYA terdeteksi
    (hash random = zero-day / unknown) dengan ekstensi berisiko.
    Nanti = berapa yang jatuh ke review (benar) vs sunyi (salah).
    """
    print(f"[fn-rate] N={n} risky-extension + unknown hash", file=sys.stderr)
    risky_exts = ["sh", "exe", "ps1", "bat", "py", "elf"]
    results = []
    silent_count = 0
    review_count = 0
    threat_count = 0

    for i in range(n):
        ext = random.choice(risky_exts)
        h = random_hash()
        fname = f"bench-fn-{i:03d}.{ext}"
        fpath = f"/home/{AGENT_NAME}/Downloads/{fname}"
        payload = fake_fim_alert(fname, fpath, h, rule_level=10)

        resp, elapsed_ms = http_post(N8N_WEBHOOK_MALWARE, payload)

        # Interpretasi: response kosong = bersih (sunyi) → false negative!
        is_silent = not resp or resp == [] or resp == {} or resp.get("error")
        # Cek apakah ada tombol review (review_unknown path)
        has_review = False
        if isinstance(resp, dict):
            has_review = resp.get("review_unknown", False)
        elif isinstance(resp, list) and resp:
            has_review = (
                resp[0].get("review_unknown", False)
                if isinstance(resp[0], dict)
                else False
            )

        status = "silent" if is_silent else ("review" if has_review else "threat")
        if status == "silent":
            silent_count += 1
        elif status == "review":
            review_count += 1
        else:
            threat_count += 1

        results.append(
            {
                "run": i + 1,
                "hash": h,
                "filename": fname,
                "ext": ext,
                "status": status,
                "elapsed_ms": round(elapsed_ms, 2),
            }
        )
        print(
            f"  [{i + 1:3d}/{n}] {status:8s}  {fname}  hash={h[:12]}…", file=sys.stderr
        )
        time.sleep(2)

    total = len(results)
    fn_rate = round(silent_count / total * 100, 2) if total > 0 else 0

    summary = {
        "mode": "fn_rate",
        "n": total,
        "silent_count": silent_count,
        "review_count": review_count,
        "threat_count": threat_count,
        "false_negative_rate_pct": fn_rate,
        "true_positive_rate_pct": round((review_count + threat_count) / total * 100, 2)
        if total > 0
        else 0,
    }
    print(f"\n  Total: {total}", file=sys.stderr)
    print(f"  Silent (FN): {silent_count} ({fn_rate}%)", file=sys.stderr)
    print(f"  Review (HITL): {review_count}", file=sys.stderr)
    print(f"  Threat (auto): {threat_count}", file=sys.stderr)
    print(
        f"  True-positive rate: {summary['true_positive_rate_pct']}%\n", file=sys.stderr
    )
    return summary


# ─── Mode: All ─────────────────────────────────────────────────────────


def bench_all(n, delay=2, concurrency=5):
    """Jalankan semua mode secara berurutan."""
    results = {}
    print("\n" + "=" * 60, file=sys.stderr)
    print("  FULL BENCHMARK — SOAR Open-Source", file=sys.stderr)
    print(f"  {ts_now()}", file=sys.stderr)
    print("=" * 60 + "\n", file=sys.stderr)

    results["mttr_malware"] = bench_mttr_malware(n, delay)
    results["mttr_phishing"] = bench_mttr_phishing(min(n, 10), delay)
    results["load"] = bench_load(n, concurrency)
    results["mttr_hitl"] = bench_mttr_hitl(min(n, 10), delay)
    results["vt_cold_vs_cache"] = bench_vt_cold(min(n, 10), delay)
    results["fn_rate"] = bench_fn_rate(min(n, 15))

    return results


# ─── Main ───────────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description="Benchmark & load-test SOAR")
    parser.add_argument(
        "--mode",
        choices=[
            "mttr-malware",
            "mttr-fleet",
            "mttr-phishing",
            "mttr-hitl",
            "load",
            "vt-cold",
            "fn-rate",
            "all",
        ],
        default="all",
        help="Mode benchmark",
    )
    parser.add_argument("--n", type=int, default=30, help="Jumlah sampel (N)")
    parser.add_argument("--delay", type=float, default=2, help="Jeda antar-run (detik)")
    parser.add_argument(
        "--concurrency", type=int, default=5, help="Thread parallel (load test)"
    )
    parser.add_argument(
        "--output", type=str, default=None, help="Output file JSON (default: stdout)"
    )
    args = parser.parse_args()

    print(f"Benchmark SOAR — mode={args.mode}, N={args.n}", file=sys.stderr)
    print(f"Webhook malware : {N8N_WEBHOOK_MALWARE}", file=sys.stderr)
    print(f"Webhook phishing: {N8N_WEBHOOK_PHISHING}", file=sys.stderr)
    print(f"Agent           : {AGENT_NAME} (id={AGENT_ID})\n", file=sys.stderr)

    if args.mode == "mttr-malware":
        result = bench_mttr_malware(args.n, args.delay)
    elif args.mode == "mttr-fleet":
        result = bench_mttr_fleet(args.n, args.delay)
    elif args.mode == "mttr-phishing":
        result = bench_mttr_phishing(args.n, args.delay)
    elif args.mode == "mttr-hitl":
        result = bench_mttr_hitl(args.n, args.delay)
    elif args.mode == "load":
        result = bench_load(args.n, args.concurrency)
    elif args.mode == "vt-cold":
        result = bench_vt_cold(args.n, args.delay)
    elif args.mode == "fn-rate":
        result = bench_fn_rate(args.n)
    else:
        result = bench_all(args.n, args.delay, args.concurrency)

    # Tambah metadata
    result["metadata"] = {
        "timestamp": ts_now(),
        "mode": args.mode,
        "n": args.n,
        "agent": AGENT_NAME,
        "n8n_webhook_malware": N8N_WEBHOOK_MALWARE,
        "n8n_webhook_phishing": N8N_WEBHOOK_PHISHING,
    }

    output = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        with open(args.output, "w") as f:
            f.write(output)
        print(f"\nHasil disimpan ke {args.output}", file=sys.stderr)
    else:
        print(output)

    print("\n✅ Benchmark selesai.", file=sys.stderr)


if __name__ == "__main__":
    main()
