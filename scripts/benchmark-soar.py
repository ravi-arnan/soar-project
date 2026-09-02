#!/usr/bin/env python3
"""Benchmark & load-test untuk Sistem SOAR (Wazuh + n8n).

Ukur MTTR (Mean Time To Respond) untuk:
  1. Malware auto-isolate  (VT cache hangat vs dingin)
  2. Phishing auto-block   (GSB cepat vs URLScan)
  3. Load test             (N alert serentak → throughput, antrean, latensi)
  4. False-negative rate   (zero-day / file tak-dikenal)

Metodologi selaras dengan docs/EVALUASI-METRIK.md.

Usage:
    python3 benchmark-soar.py --mode mttr-malware  --n 30 --delay 2
    python3 benchmark-soar.py --mode mttr-phishing --n 10 --delay 5
    python3 benchmark-soar.py --mode load          --n 20 --concurrency 5
    python3 benchmark-soar.py --mode vt-cold       --n 10
    python3 benchmark-soar.py --mode fn-rate       --n 15
    python3 benchmark-soar.py --mode all           --n 30

Output: JSON ke stdout + ringkasan tabel ke stderr.
"""

import argparse
import hashlib
import json
import os
import random
import statistics
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ─── Konfigurasi ────────────────────────────────────────────────────────
N8N_WEBHOOK_MALWARE = os.getenv("N8N_WEBHOOK_MALWARE", "http://localhost:5678/webhook/wazuh-alert")
N8N_WEBHOOK_PHISHING = os.getenv("N8N_WEBHOOK_PHISHING", "http://localhost:5678/webhook/wazuh-phishing")
WAZUH_API = os.getenv("WAZUH_API", "https://172.17.0.1:55000")
AGENT_ID = os.getenv("AGENT_ID", "001")
AGENT_NAME = os.getenv("AGENT_NAME", "ravi-zorin")
TIMEOUT = int(os.getenv("BENCH_TIMEOUT", "120"))  # detik per alert

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
    req = Request(url, data=data, headers={"Content-Type": "application/json"}, method="POST")
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


def random_hash():
    """Generate random SHA256 (tidak dikenal VT → zero-day path)."""
    return hashlib.sha256(os.urandom(32)).hexdigest()


def fake_fim_alert(filename, filepath, sha256, rule_level=10, agent_id=AGENT_ID):
    """Bangun payload FIM alert yang meniru Wazuh."""
    return {
        "rule": {"id": "553", "level": rule_level, "description": "File added to the system."},
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
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"  {stats.get('label', 'Results')}  (N={stats['n']})", file=sys.stderr)
    print(f"{'='*60}", file=sys.stderr)
    print(f"  Rata-rata : {stats['mean']:.2f} {unit}", file=sys.stderr)
    print(f"  Median    : {stats['median']:.2f} {unit}", file=sys.stderr)
    print(f"  Min – Max : {stats['min']:.2f} – {stats['max']:.2f} {unit}", file=sys.stderr)
    print(f"  Std dev   : ±{stats['stdev']:.2f} {unit}", file=sys.stderr)
    print(f"  P95       : {stats['p95']:.2f} {unit}", file=sys.stderr)
    print(f"  P99       : {stats['p99']:.2f} {unit}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)


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

        results.append({
            "run": i + 1,
            "hash": h,
            "filename": fname,
            "elapsed_ms": round(elapsed_ms, 2),
            "elapsed_sec": round(elapsed_sec, 4),
            "response": resp,
            "timestamp": ts_now(),
        })
        print(f"  [{i+1:3d}/{n}] {elapsed_sec:.2f}s  hash={h[:12]}…", file=sys.stderr)

        if i < n - 1:
            time.sleep(delay)

    st = stats_summary(samples_sec, "MTTR Malware (VT cache hangat)")
    st["unit"] = "detik"
    print_table(st, "detik")
    return {"mode": "mttr_malware", "stats": st, "runs": results}


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

        results.append({
            "run": i + 1,
            "url": url,
            "elapsed_ms": round(elapsed_ms, 2),
            "elapsed_sec": round(elapsed_sec, 4),
            "response": resp,
            "timestamp": ts_now(),
        })
        print(f"  [{i+1:3d}/{n}] {elapsed_sec:.2f}s  url={url[:50]}", file=sys.stderr)

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
            print(f"  [{r['run']:3d}/{n}] {r['elapsed_ms']:.0f}ms  hash={r['hash'][:12]}…", file=sys.stderr)

    wall_total = (time.monotonic() - wall_start) * 1000
    latencies = [r["elapsed_ms"] for r in results]
    st = stats_summary(latencies, f"Load Test (concurrency={concurrency})")
    st["unit"] = "ms"
    st["wall_total_ms"] = round(wall_total, 2)
    st["throughput_per_sec"] = round(n / (wall_total / 1000), 2) if wall_total > 0 else 0
    print_table(st, "ms")
    print(f"  Wall time total: {wall_total/1000:.1f}s", file=sys.stderr)
    print(f"  Throughput: {st['throughput_per_sec']:.2f} alert/detik\n", file=sys.stderr)
    return {"mode": "load", "stats": st, "runs": results}


# ─── Mode: VT Cold vs Cache ───────────────────────────────────────────

def bench_vt_cold(n):
    """Bandingkan VT response time untuk hash yang belum dikenal (cold)
    vs hash yang sudah di-cache oleh n8n (hangat).
    """
    print(f"[vt-cold] N={n} cold queries", file=sys.stderr)
    cold_samples = []

    for i in range(n):
        h = random_hash()
        fname = f"bench-cold-{i:03d}.bin"
        fpath = f"/home/{AGENT_NAME}/Downloads/{fname}"
        payload = fake_fim_alert(fname, fpath, h, rule_level=10)

        t0 = time.monotonic()
        resp, elapsed_ms = http_post(N8N_WEBHOOK_MALWARE, payload)
        cold_samples.append(elapsed_ms / 1000)
        print(f"  cold [{i+1:3d}/{n}] {elapsed_ms/1000:.2f}s  hash={h[:12]}…", file=sys.stderr)
        time.sleep(16)  # hormati rate-limit VT free (≤4/mnt)

    # Sekarang kirim hash yang sama lagi → harus cache hit
    print(f"\n[vt-cold] N={n} cache-hit queries (hash yang sama)", file=sys.stderr)
    hot_samples = []
    for i in range(n):
        h = random_hash()
        fname = f"bench-cold-{i:03d}.bin"  # nama sama → n8n cache lookup
        fpath = f"/home/{AGENT_NAME}/Downloads/{fname}"
        payload = fake_fim_alert(fname, fpath, h, rule_level=10)

        t0 = time.monotonic()
        resp, elapsed_ms = http_post(N8N_WEBHOOK_MALWARE, payload)
        hot_samples.append(elapsed_ms / 1000)
        print(f"  hot  [{i+1:3d}/{n}] {elapsed_ms/1000:.2f}s  hash={h[:12]}…", file=sys.stderr)
        time.sleep(2)

    cold_st = stats_summary(cold_samples, "VT Cold (hash baru)")
    cold_st["unit"] = "detik"
    hot_st = stats_summary(hot_samples, "VT Cache Hit (hash sama)")
    hot_st["unit"] = "detik"

    print_table(cold_st, "detik")
    print_table(hot_st, "detik")

    if cold_st["mean"] > 0 and hot_st["mean"] > 0:
        speedup = cold_st["mean"] / hot_st["mean"]
        print(f"  Cache speedup: {speedup:.1f}x lebih cepat\n", file=sys.stderr)
    else:
        speedup = 0

    return {
        "mode": "vt_cold_vs_cache",
        "cold": cold_st,
        "hot": hot_st,
        "speedup": round(speedup, 2),
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
            has_review = resp[0].get("review_unknown", False) if isinstance(resp[0], dict) else False

        status = "silent" if is_silent else ("review" if has_review else "threat")
        if status == "silent":
            silent_count += 1
        elif status == "review":
            review_count += 1
        else:
            threat_count += 1

        results.append({
            "run": i + 1,
            "hash": h,
            "filename": fname,
            "ext": ext,
            "status": status,
            "elapsed_ms": round(elapsed_ms, 2),
        })
        print(f"  [{i+1:3d}/{n}] {status:8s}  {fname}  hash={h[:12]}…", file=sys.stderr)
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
        "true_positive_rate_pct": round((review_count + threat_count) / total * 100, 2) if total > 0 else 0,
    }
    print(f"\n  Total: {total}", file=sys.stderr)
    print(f"  Silent (FN): {silent_count} ({fn_rate}%)", file=sys.stderr)
    print(f"  Review (HITL): {review_count}", file=sys.stderr)
    print(f"  Threat (auto): {threat_count}", file=sys.stderr)
    print(f"  True-positive rate: {summary['true_positive_rate_pct']}%\n", file=sys.stderr)
    return summary


# ─── Mode: All ─────────────────────────────────────────────────────────

def bench_all(n, delay=2, concurrency=5):
    """Jalankan semua mode secara berurutan."""
    results = {}
    print("\n" + "="*60, file=sys.stderr)
    print("  FULL BENCHMARK — SOAR Open-Source", file=sys.stderr)
    print(f"  {ts_now()}", file=sys.stderr)
    print("="*60 + "\n", file=sys.stderr)

    results["mttr_malware"] = bench_mttr_malware(n, delay)
    results["mttr_phishing"] = bench_mttr_phishing(min(n, 10), delay)
    results["load"] = bench_load(n, concurrency)
    results["vt_cold_vs_cache"] = bench_vt_cold(min(n, 10))
    results["fn_rate"] = bench_fn_rate(min(n, 15))

    return results


# ─── Main ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Benchmark & load-test SOAR")
    parser.add_argument("--mode", choices=["mttr-malware", "mttr-phishing", "load",
                                           "vt-cold", "fn-rate", "all"],
                        default="all", help="Mode benchmark")
    parser.add_argument("--n", type=int, default=30, help="Jumlah sampel (N)")
    parser.add_argument("--delay", type=float, default=2, help="Jeda antar-run (detik)")
    parser.add_argument("--concurrency", type=int, default=5, help="Thread parallel (load test)")
    parser.add_argument("--output", type=str, default=None, help="Output file JSON (default: stdout)")
    args = parser.parse_args()

    print(f"Benchmark SOAR — mode={args.mode}, N={args.n}", file=sys.stderr)
    print(f"Webhook malware : {N8N_WEBHOOK_MALWARE}", file=sys.stderr)
    print(f"Webhook phishing: {N8N_WEBHOOK_PHISHING}", file=sys.stderr)
    print(f"Agent           : {AGENT_NAME} (id={AGENT_ID})\n", file=sys.stderr)

    if args.mode == "mttr-malware":
        result = bench_mttr_malware(args.n, args.delay)
    elif args.mode == "mttr-phishing":
        result = bench_mttr_phishing(args.n, args.delay)
    elif args.mode == "load":
        result = bench_load(args.n, args.concurrency)
    elif args.mode == "vt-cold":
        result = bench_vt_cold(args.n)
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
