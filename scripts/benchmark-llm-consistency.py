#!/usr/bin/env python3
"""Benchmark Konsistensi & Ketahanan Inferensi LLM (DeepSeek-V4-Flash) untuk SOAR.

Milestone M4: Menguji konsistensi inferensi, stabilitas leksikal/semantik,
kepatuhan batasan instruksi (guardrail constraints), dan distribusi latensi
pada skenario alert keamanan identik (repeatability testing).

Metodologi selaras dengan docs/evaluasi/EVALUASI-METRIK.md.

Usage:
    python3 scripts/benchmark-llm-consistency.py --n 10 --delay 1.0
    python3 scripts/benchmark-llm-consistency.py --scenarios malware_critical,system_file_hosts --n 5
    python3 scripts/benchmark-llm-consistency.py --mock --n 3 (offline mock testing)
"""

import argparse
import itertools
import json
import os
import re
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

DEFAULT_ENDPOINT = "https://api.hcnsec.cn/v1/chat/completions"
DEFAULT_MODEL = "DeepSeek-V4-Flash"
DEFAULT_TEMPERATURE = 0.3
DEFAULT_MAX_TOKENS = 1500
DEFAULT_TIMEOUT = 30
DEFAULT_OUTPUT = "docs/evaluasi/bench-llm-consistency-20261022.json"

STOPWORDS_ID = {
    "dan", "di", "ke", "dari", "ini", "itu", "yang", "untuk", "pada", "adalah",
    "sebagai", "dengan", "oleh", "dalam", "atau", "juga", "karena", "maka",
    "akan", "bisa", "dapat", "harus", "sudah", "tidak", "bukan", "hanya",
    "tersebut", "ada", "jika", "bila", "serta", "secara", "lebih", "atas",
}


def load_env_file(filepath=".env"):
    """Muat variabel lingkungan dari file .env tanpa dependensi pihak ketiga."""
    env_path = Path(filepath)
    if not env_path.is_file():
        # Coba root repo jika dipanggil dari subfolder
        env_path = Path(__file__).resolve().parent.parent / ".env"
    if env_path.is_file():
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip("'\"")
                if k not in os.environ:
                    os.environ[k] = v


# ─── Definisi Skenario Uji Alert ─────────────────────────────────────────────

SCENARIOS = {
    "malware_critical": {
        "id": "malware_critical",
        "title": "Malware Kritis (EICAR / Ransomware)",
        "severity": "CRITICAL",
        "rule": "100201 level 12: High-confidence malware detected by multi-engine",
        "prompt": (
            "You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. "
            "Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter "
            "markdown seperti asterisk underscore backtick atau bracket.\n\n"
            "Severity: CRITICAL Wazuh level 12, malicious 62 dari 70\n"
            "File: eicar.com\n"
            "Hash: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n"
            "VirusTotal: 62 dari 70 antivirus mendeteksi file ini sebagai malware.\n\n"
            "Konteks: ancaman KRITIS. Berikan rekomendasi immediate response, isolasi sistem, dan eradikasi.\n"
            "Jelaskan tingkat bahaya file ini dan berikan rekomendasi tindakan yang harus diambil."
        ),
        "expected_positive_terms": ["kritis", "bahaya", "isolasi", "karantina", "eradikasi", "segera"],
        "disallowed_terms": ["bukan ancaman", "aman", "abaikan"],
        "check_constraint": lambda text: any(t in text.lower() for t in ["isolasi", "karantina", "eradikasi", "tindakan segera", "segera"]) and not any(t in text.lower() for t in ["bukan ancaman", "file aman"]),
    },
    "malware_high": {
        "id": "malware_high",
        "title": "Malware Tingkat Tinggi (Trojan / MalwareBazaar Hit)",
        "severity": "HIGH",
        "rule": "100202 level 10: Known Trojan signature matched in MalwareBazaar",
        "prompt": (
            "You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. "
            "Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter "
            "markdown seperti asterisk underscore backtick atau bracket.\n\n"
            "Severity: HIGH Wazuh level 10, malicious 5 dari 70\n"
            "File: invoice_macro.docm\n"
            "Hash: c1f2e3d4b5a67890123456789abcdef0123456789abcdef0123456789abcdef0\n"
            "VirusTotal: 5 dari 70 antivirus mendeteksi file ini sebagai malware. Terdeteksi di MalwareBazaar sebagai Emotet.\n\n"
            "Konteks: ancaman TINGGI. Berikan rekomendasi tindakan dalam 24 jam, verifikasi dan kontainmen.\n"
            "Jelaskan tingkat bahaya file ini dan berikan rekomendasi tindakan yang harus diambil."
        ),
        "expected_positive_terms": ["tinggi", "bahaya", "kontainmen", "verifikasi", "karantina", "tindakan"],
        "disallowed_terms": ["bukan ancaman", "file aman"],
        "check_constraint": lambda text: any(t in text.lower() for t in ["kontainmen", "karantina", "isolasi", "verifikasi", "24 jam", "waspada"]) and not any(t in text.lower() for t in ["bukan ancaman", "file aman"]),
    },
    "system_file_hosts": {
        "id": "system_file_hosts",
        "title": "Perubahan File Konfigurasi Sistem (hosts / FIM)",
        "severity": "MEDIUM",
        "rule": "550 level 7: Integrity checksum changed for system configuration file",
        "prompt": (
            "You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. "
            "Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter "
            "markdown seperti asterisk underscore backtick atau bracket.\n\n"
            "Jenis: perubahan file konfigurasi sistem. Wazuh rule 550 level 7: Integrity checksum changed.\n"
            "File: hosts\n"
            "Hash: a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90\n\n"
            "Konteks penting: sistem SOAR ini SENDIRI menulis ke file hosts untuk memblokir domain phishing "
            "(entri ditandai komentar soar-sinkhole); selain itu perubahan bisa merupakan konfigurasi jaringan administratif. "
            "JANGAN sebut file ini malware. Sarankan verifikasi apakah perubahan berasal dari automasi SOAR atau admin, "
            "dan JANGAN menyarankan karantina atau penghapusan file hosts."
        ),
        "expected_positive_terms": ["verifikasi", "administratif", "sinkhole", "soar", "konfigurasi"],
        "disallowed_terms": ["karantina file hosts", "hapus file hosts", "file ini adalah malware"],
        "check_constraint": lambda text: (
            not any(t in text.lower() for t in ["karantina file hosts", "hapus file hosts", "file ini adalah malware"])
            and any(t in text.lower() for t in ["verifikasi", "administratif", "sinkhole", "soar", "konfigurasi"])
        ),
    },
    "unknown_executable": {
        "id": "unknown_executable",
        "title": "Eksekutabel Baru / Hash Tak Dikenal (Perlu Review)",
        "severity": "MEDIUM",
        "rule": "554 level 7: File added to monitored desktop with executable extension",
        "prompt": (
            "You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. "
            "Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter "
            "markdown seperti asterisk underscore backtick atau bracket.\n\n"
            "File: update_patch.exe\n"
            "Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n"
            "VirusTotal: hash file belum pernah dikenali NotFound, tidak ada data deteksi.\n\n"
            "File ini berekstensi/ber-flag eksekutabel tetapi hash-nya belum dikenal threat intel "
            "sehingga belum bisa dipastikan. Nyatakan bahwa file PERLU REVIEW manual (cek asal, "
            "tanda tangan, izin eksekusi), BUKAN vonis malware. JANGAN menyarankan isolasi host otomatis."
        ),
        "expected_positive_terms": ["review", "manual", "verifikasi", "tanda tangan", "asal", "belum dipastikan"],
        "disallowed_terms": ["isolasi host otomatis", "vonis malware", "pasti malware"],
        "check_constraint": lambda text: (
            not any(t in text.lower() for t in ["isolasi host otomatis", "vonis malware", "pasti malware"])
            and any(t in text.lower() for t in ["review", "manual", "verifikasi", "periksa", "tanda tangan"])
        ),
    },
    "lolbin_powershell": {
        "id": "lolbin_powershell",
        "title": "Rantai Proses Mencurigakan / LOLBin (PowerShell Obfuscated)",
        "severity": "HIGH",
        "rule": "110010 level 10: Suspicious PowerShell execution with encoded command",
        "prompt": (
            "You are a cybersecurity analyst. Respond ONLY in formal Bahasa Indonesia. "
            "Write exactly 2-3 sentences. No extra explanation. JANGAN gunakan karakter "
            "markdown seperti asterisk underscore backtick atau bracket.\n\n"
            "Severity: HIGH Wazuh rule 110010 level 10: Suspicious PowerShell execution with encoded command\n"
            "Proses: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\n"
            "Command line: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA...\n"
            "Parent: C:\\Windows\\System32\\cmd.exe cmd.exe /c start\n"
            "Agent: 003-ravi-pc\n\n"
            "Konteks: ancaman TINGGI. Berikan rekomendasi tindakan dalam 24 jam, verifikasi dan kontainmen.\n"
            "Nilai apakah rantai proses ini indikasi LOLBin atau malware (JANGAN sarankan menghapus binary sistem Windows), "
            "dan rekomendasi verifikasi berikutnya."
        ),
        "expected_positive_terms": ["lolbin", "mencurigakan", "proses", "investigasi", "verifikasi", "skrip"],
        "disallowed_terms": ["hapus powershell.exe", "karantina powershell.exe", "hapus binary sistem"],
        "check_constraint": lambda text: (
            not any(t in text.lower() for t in ["hapus powershell.exe", "karantina powershell.exe", "hapus binary sistem"])
            and any(t in text.lower() for t in ["lolbin", "mencurigakan", "proses", "periksa", "analisis", "investigasi", "encoded"])
        ),
    },
    "phishing_credential": {
        "id": "phishing_credential",
        "title": "Indikasi Phishing Kredensial (GSB / URLScan Hit)",
        "severity": "HIGH",
        "rule": "100301 level 10: Malicious phishing URL detected via Google Safe Browsing",
        "prompt": (
            "Anda adalah analis keamanan siber. Respon HANYA dalam Bahasa Indonesia formal, 2-3 kalimat, tanpa karakter markdown (asterisk underscore backtick bracket).\n\n"
            "URL dicurigai: http://login-verifikasi-bca-security.com/update.html\n"
            "IP sumber: 198.51.100.42\n"
            "Status: TINGGI\n"
            "Google Safe Browsing: Dikenali sebagai situs phishing / rekayasa sosial berbahaya\n"
            "URLScan.io: Nilai risiko berbahaya, targeting portal perbankan\n\n"
            "Jelaskan tingkat bahaya URL ini dan rekomendasi tindakan yang harus diambil."
        ),
        "expected_positive_terms": ["phishing", "bahaya", "blokir", "sinkhole", "kredensial", "peringatan"],
        "disallowed_terms": ["bukan ancaman", "situs aman"],
        "check_constraint": lambda text: (
            not any(t in text.lower() for t in ["bukan ancaman", "situs aman"])
            and any(t in text.lower() for t in ["phishing", "blokir", "sinkhole", "akses", "waspada", "kredensial"])
        ),
    },
}


# ─── Utilitas Pemrosesan Teks & Sanitasi ──────────────────────────────────────

def clean_llm_response(raw_text):
    """Sanitasi respons model persis seperti implementasi n8n node AI Generate."""
    if not raw_text:
        return ""
    # Hapus tag <think>...</think> (penalaran internal DeepSeek)
    cleaned = re.sub(r"<think>[\s\S]*?</think>", "", raw_text)
    # Hapus karakter markdown (* _ ` [ ] ( ))
    cleaned = re.sub(r"[*_`\[\]()]", "", cleaned)
    # Normalisasi spasi/baris baru ganda
    cleaned = re.sub(r"\n\n+", "\n", cleaned)
    return cleaned.strip()


def count_sentences(text):
    """Hitung jumlah kalimat berdasarkan tanda baca titik, tanda seru, tanda tanya."""
    if not text:
        return 0
    chunks = re.split(r"[.!?]+(?:\s+|$)", text.strip())
    sentences = [c.strip() for c in chunks if len(c.strip()) > 3]
    return len(sentences)


def tokenize_words(text):
    """Ekstrak kumpulan token kata unik (non-stopword, panjang > 2)."""
    words = re.findall(r"\b[a-zA-Z0-9-]{3,}\b", text.lower())
    return {w for w in words if w not in STOPWORDS_ID}


def calculate_jaccard_similarity(set_a, set_b):
    """Hitung indeks Jaccard similarity antar dua set token."""
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a.intersection(set_b))
    union = len(set_a.union(set_b))
    return intersection / union if union > 0 else 0.0


def check_markdown_violations(text):
    """Deteksi apakah teks mengandung karakter markdown yang dilarang."""
    forbidden = ["*", "_", "`", "[", "]", "(", ")"]
    return [char for char in forbidden if char in text]


# ─── Pemanggilan API LLM ─────────────────────────────────────────────────────

def call_hcnsec_api(prompt, api_key, model=DEFAULT_MODEL, endpoint=DEFAULT_ENDPOINT,
                    temperature=DEFAULT_TEMPERATURE, max_tokens=DEFAULT_MAX_TOKENS,
                    timeout=DEFAULT_TIMEOUT):
    """Panggil OpenAI-compatible endpoint HCNSEC secara sinkron."""
    body = {
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature,
        "messages": [{"role": "user", "content": prompt}],
    }
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "SOAR-Benchmark-M4/1.0",
        },
    )

    start_time = time.perf_counter()
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        duration_ms = (time.perf_counter() - start_time) * 1000.0
        status_code = resp.status
        resp_json = json.loads(resp.read().decode("utf-8"))

    content = resp_json.get("choices", [{}])[0].get("message", {}).get("content", "")
    usage = resp_json.get("usage", {})

    return {
        "status_code": status_code,
        "latency_ms": round(duration_ms, 2),
        "raw_content": content,
        "usage": usage,
    }


def call_mock_generator(scenario_id, prompt):
    """Generator tiruan untuk pengujian unit / offline verification."""
    time.sleep(0.05)
    mock_responses = {
        "malware_critical": "File eicar.com merupakan ancaman malware dengan tingkat bahaya sangat kritis yang terdeteksi oleh mayoritas mesin antivirus. Sistem yang terdampak harus segera diisolasi dari jaringan dan file harus dikarantina untuk mencegah eskalasi. Lakukan investigasi menyeluruh pada direktori terkait untuk memastikan tidak ada payload sekunder yang tertinggal.",
        "malware_high": "File invoice_macro.docm teridentifikasi sebagai varian Trojan Emotet dengan tingkat risiko tinggi yang memerlukan penanganan dalam kurun waktu 24 jam. Langkah kontainmen dan karantina file harus segera diterapkan pada workstation terkait. Lakukan analisis jejak eksekusi makro serta periksa komunikasi jaringan yang mencurigakan.",
        "system_file_hosts": "Perubahan pada file hosts ini bukan merupakan indikasi malware melainkan modifikasi konfigurasi sistem yang sah dari automasi SOAR sinkhole atau tugas administratif. Disarankan untuk memverifikasi riwayat perubahan terhadap catatan tiket perubahan dan konfigurasi jaringan internal. Jangan melakukan karantina atau penghapusan terhadap file hosts sistem operasi ini.",
        "unknown_executable": "File update_patch.exe belum dikenali oleh basis data threat intelligence sehingga belum dapat divonis sebagai malware. Diperlukan review manual untuk memverifikasi asal file, tanda tangan digital, serta izin eksekusi sebelum file diizinkan berjalan. Hindari isolasi host otomatis dan prioritaskan pengecekan kontekstual terlebih dahulu.",
        "lolbin_powershell": "Aktivitas eksekusi PowerShell dengan argumen terenkripsi ini menunjukkan indikasi kuat teknik LOLBin untuk mengunduh muatan mencurigakan. Analis harus segera memeriksa proses induk, riwayat koneksi jaringan keluar, serta mendekripsi perintah tersebut tanpa menghapus binary powershell.exe bawaan Windows. Lakukan isolasi proses mencurigakan dan tinjau log aktivitas akun pengguna terkait.",
        "phishing_credential": "Tautan ini tergolong ancaman phishing tingkat tinggi yang dirancang untuk mencuri kredensial perbankan pengguna. Segera lakukan pemblokiran domain melalui sinkhole DNS lokal dan putuskan akses ke alamat IP terkait. Lakukan sosialisasi peringatan keamanan kepada seluruh karyawan agar tidak memasukkan informasi rahasia pada halaman tersebut.",
    }
    content = mock_responses.get(scenario_id, "Tingkat bahaya terdeteksi pada sistem. Lakukan verifikasi dan monitoring.")
    return {
        "status_code": 200,
        "latency_ms": 50.0,
        "raw_content": content,
        "usage": {"prompt_tokens": 120, "completion_tokens": 65, "total_tokens": 185},
    }


# ─── Mesin Pengujian Konsistensi ─────────────────────────────────────────────

def run_scenario_benchmark(scenario_key, scenario_data, n_runs, api_key,
                           delay_sec=1.0, mock=False, model=DEFAULT_MODEL,
                           endpoint=DEFAULT_ENDPOINT, temperature=DEFAULT_TEMPERATURE):
    """Jalankan N iterasi pengujian untuk satu skenario identik."""
    results = []
    tokens_list = []

    for i in range(1, n_runs + 1):
        try:
            if mock:
                api_result = call_mock_generator(scenario_key, scenario_data["prompt"])
            else:
                api_result = call_hcnsec_api(
                    scenario_data["prompt"],
                    api_key=api_key,
                    model=model,
                    endpoint=endpoint,
                    temperature=temperature,
                )

            raw = api_result["raw_content"]
            clean = clean_llm_response(raw)
            has_think = "<think>" in raw
            raw_markdown = check_markdown_violations(raw)
            clean_markdown = check_markdown_violations(clean)
            sentences = count_sentences(clean)
            words = clean.split()
            word_count = len(words)
            tokens = tokenize_words(clean)
            tokens_list.append(tokens)

            # Validasi aturan batasan instruksi
            constraint_passed = bool(scenario_data["check_constraint"](clean))
            sentence_passed = 2 <= sentences <= 3

            results.append({
                "run_index": i,
                "status": "SUCCESS",
                "latency_ms": api_result["latency_ms"],
                "has_think_tag": has_think,
                "raw_markdown_violations": raw_markdown,
                "clean_markdown_violations": clean_markdown,
                "sentence_count": sentences,
                "sentence_passed": sentence_passed,
                "word_count": word_count,
                "constraint_passed": constraint_passed,
                "clean_text": clean,
                "tokens_count": len(tokens),
                "api_usage": api_result.get("usage", {}),
            })
        except Exception as exc:
            results.append({
                "run_index": i,
                "status": "ERROR",
                "error_message": str(exc),
                "latency_ms": 0.0,
                "constraint_passed": False,
                "sentence_passed": False,
                "clean_text": "",
            })

        if i < n_runs and delay_sec > 0:
            time.sleep(delay_sec)

    # ─── Agregasi Statistik Skenario ───
    successful = [r for r in results if r["status"] == "SUCCESS"]
    success_count = len(successful)
    total_runs = len(results)

    if successful:
        latencies = [r["latency_ms"] for r in successful]
        mean_latency = statistics.mean(latencies)
        median_latency = statistics.median(latencies)
        min_latency = min(latencies)
        max_latency = max(latencies)
        stdev_latency = statistics.stdev(latencies) if len(latencies) > 1 else 0.0

        constraint_passed_count = sum(1 for r in successful if r["constraint_passed"])
        constraint_rate = (constraint_passed_count / success_count) * 100.0

        sentence_passed_count = sum(1 for r in successful if r["sentence_passed"])
        sentence_rate = (sentence_passed_count / success_count) * 100.0

        raw_clean_no_markdown_count = sum(1 for r in successful if not r["raw_markdown_violations"])
        raw_markdown_compliance_rate = (raw_clean_no_markdown_count / success_count) * 100.0

        post_clean_no_markdown_count = sum(1 for r in successful if not r["clean_markdown_violations"])
        post_clean_compliance_rate = (post_clean_no_markdown_count / success_count) * 100.0

        # Pairwise Jaccard Lexical Consistency
        jaccard_scores = []
        if len(tokens_list) > 1:
            for pair in itertools.combinations(tokens_list, 2):
                jaccard_scores.append(calculate_jaccard_similarity(pair[0], pair[1]))
            avg_jaccard = statistics.mean(jaccard_scores)
        else:
            avg_jaccard = 1.0

        word_counts = [r["word_count"] for r in successful]
        mean_word_count = statistics.mean(word_counts)
        stdev_word_count = statistics.stdev(word_counts) if len(word_counts) > 1 else 0.0
    else:
        mean_latency = median_latency = min_latency = max_latency = stdev_latency = 0.0
        constraint_rate = sentence_rate = raw_markdown_compliance_rate = post_clean_compliance_rate = 0.0
        avg_jaccard = 0.0
        mean_word_count = stdev_word_count = 0.0

    return {
        "scenario_id": scenario_key,
        "title": scenario_data["title"],
        "severity": scenario_data["severity"],
        "total_runs": total_runs,
        "success_count": success_count,
        "error_count": total_runs - success_count,
        "latency_stats": {
            "mean_ms": round(mean_latency, 2),
            "median_ms": round(median_latency, 2),
            "min_ms": round(min_latency, 2),
            "max_ms": round(max_latency, 2),
            "stdev_ms": round(stdev_latency, 2),
        },
        "metrics": {
            "constraint_adherence_pct": round(constraint_rate, 2),
            "sentence_length_adherence_pct": round(sentence_rate, 2),
            "raw_no_markdown_pct": round(raw_markdown_compliance_rate, 2),
            "sanitized_no_markdown_pct": round(post_clean_compliance_rate, 2),
            "avg_jaccard_lexical_similarity": round(avg_jaccard, 4),
            "word_count_mean": round(mean_word_count, 1),
            "word_count_stdev": round(stdev_word_count, 1),
        },
        "runs": results,
    }


def run_full_benchmark(scenarios_to_run, n_runs=10, delay_sec=1.0, mock=False,
                       api_key=None, model=DEFAULT_MODEL, endpoint=DEFAULT_ENDPOINT,
                       temperature=DEFAULT_TEMPERATURE):
    """Eksekusi keseluruhan suite pengujian konsistensi LLM."""
    all_scenario_summaries = {}
    total_start = time.perf_counter()

    for s_key in scenarios_to_run:
        s_data = SCENARIOS[s_key]
        print(f"[*] Menjalankan skenario '{s_data['title']}' (N={n_runs})...", file=sys.stderr)
        summary = run_scenario_benchmark(
            s_key,
            s_data,
            n_runs=n_runs,
            api_key=api_key,
            delay_sec=delay_sec,
            mock=mock,
            model=model,
            endpoint=endpoint,
            temperature=temperature,
        )
        all_scenario_summaries[s_key] = summary

    total_duration_sec = time.perf_counter() - total_start

    # Agregasi Global
    all_latencies = []
    all_constraints = []
    all_jaccards = []
    total_calls = 0
    total_successes = 0

    for s in all_scenario_summaries.values():
        total_calls += s["total_runs"]
        total_successes += s["success_count"]
        all_constraints.append(s["metrics"]["constraint_adherence_pct"])
        all_jaccards.append(s["metrics"]["avg_jaccard_lexical_similarity"])
        for r in s["runs"]:
            if r["status"] == "SUCCESS":
                all_latencies.append(r["latency_ms"])

    global_stats = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "total_duration_sec": round(total_duration_sec, 2),
        "total_calls": total_calls,
        "total_successes": total_successes,
        "success_rate_pct": round((total_successes / total_calls * 100.0) if total_calls else 0.0, 2),
        "overall_constraint_adherence_pct": round(statistics.mean(all_constraints) if all_constraints else 0.0, 2),
        "overall_jaccard_lexical_similarity": round(statistics.mean(all_jaccards) if all_jaccards else 0.0, 4),
        "overall_latency_ms": {
            "mean": round(statistics.mean(all_latencies), 2) if all_latencies else 0.0,
            "median": round(statistics.median(all_latencies), 2) if all_latencies else 0.0,
            "min": round(min(all_latencies), 2) if all_latencies else 0.0,
            "max": round(max(all_latencies), 2) if all_latencies else 0.0,
            "stdev": round(statistics.stdev(all_latencies), 2) if len(all_latencies) > 1 else 0.0,
        },
    }

    return {
        "meta": {
            "model": model,
            "endpoint": endpoint,
            "temperature": temperature,
            "n_per_scenario": n_runs,
            "is_mock": mock,
        },
        "global_summary": global_stats,
        "scenarios": all_scenario_summaries,
    }


def print_text_report(benchmark_data):
    """Cetak ringkasan tabel hasil benchmark ke stdout."""
    g = benchmark_data["global_summary"]
    m = benchmark_data["meta"]

    print("\n" + "=" * 90)
    print(f"  LAPORAN EVALUASI KONSISTENSI & KETAHANAN INFERENSI LLM (MILESTONE M4)")
    print(f"  Model: {m['model']} | Temp: {m['temperature']} | N per skenario: {m['n_per_scenario']} | Mock: {m['is_mock']}")
    print("=" * 90)
    print(f"Total Pemanggilan : {g['total_calls']} (Sukses: {g['total_successes']} / {g['success_rate_pct']}%)")
    print(f"Durasi Total      : {g['total_duration_sec']} detik")
    print(f"Latensi Rata-rata : {g['overall_latency_ms']['mean']} ms (median: {g['overall_latency_ms']['median']} ms, ±{g['overall_latency_ms']['stdev']} ms)")
    print(f"Kepatuhan Aturan  : {g['overall_constraint_adherence_pct']}% (adherence to guardrails & context)")
    print(f"Indeks Jaccard    : {g['overall_jaccard_lexical_similarity']} (stabilitas kesamaan leksikal semantik)")
    print("-" * 90)
    print(f"{'Skenario Uji':<36} | {'N':<3} | {'Mean Latency':<12} | {'Adherence':<9} | {'Jaccard':<7} | {'PostClean'}")
    print("-" * 90)

    for s_key, s_data in benchmark_data["scenarios"].items():
        name = s_data["title"][:35]
        n_val = s_data["success_count"]
        lat = f"{s_data['latency_stats']['mean_ms']} ms"
        adh = f"{s_data['metrics']['constraint_adherence_pct']}%"
        jac = f"{s_data['metrics']['avg_jaccard_lexical_similarity']:.3f}"
        clean_pct = f"{s_data['metrics']['sanitized_no_markdown_pct']}%"
        print(f"{name:<36} | {n_val:<3} | {lat:<12} | {adh:<9} | {jac:<7} | {clean_pct}")

    print("=" * 90 + "\n")


# ─── Entry Point ─────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Benchmark Konsistensi & Ketahanan Inferensi LLM untuk Sistem SOAR"
    )
    parser.add_argument("--n", type=int, default=10, help="Jumlah repetisi per skenario (default: 10)")
    parser.add_argument("--delay", type=float, default=1.0, help="Jeda antar pemanggilan dalam detik (default: 1.0)")
    parser.add_argument("--scenarios", type=str, default="all", help="Daftar skenario koma-terpisah atau 'all'")
    parser.add_argument("--api-key", type=str, default=None, help="API key override (default: baca dari .env)")
    parser.add_argument("--model", type=str, default=DEFAULT_MODEL, help="Nama model LLM (default: DeepSeek-V4-Flash)")
    parser.add_argument("--endpoint", type=str, default=DEFAULT_ENDPOINT, help="URL API endpoint")
    parser.add_argument("--temperature", type=float, default=DEFAULT_TEMPERATURE, help="Suhu inferensi (default: 0.3)")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT, help="Path output file JSON")
    parser.add_argument("--mock", action="store_true", help="Gunakan mock responses offline untuk pengujian")
    args = parser.parse_args()

    load_env_file()
    api_key = args.api_key or os.getenv("HCNSEC_API_KEY")

    if not args.mock and not api_key:
        print("ERROR: HCNSEC_API_KEY tidak ditemukan di .env atau argumen --api-key.", file=sys.stderr)
        print("Gunakan flag --mock bila ingin menguji secara offline.", file=sys.stderr)
        sys.exit(1)

    if args.scenarios == "all":
        selected_scenarios = list(SCENARIOS.keys())
    else:
        selected_scenarios = [s.strip() for s in args.scenarios.split(",") if s.strip() in SCENARIOS]
        if not selected_scenarios:
            print(f"ERROR: Tidak ada skenario valid yang cocok. Pilihan: {list(SCENARIOS.keys())}", file=sys.stderr)
            sys.exit(1)

    print(f"Memulai Benchmark LLM (Model: {args.model}, N={args.n}, Skenario={len(selected_scenarios)})...")
    result = run_full_benchmark(
        scenarios_to_run=selected_scenarios,
        n_runs=args.n,
        delay_sec=args.delay,
        mock=args.mock,
        api_key=api_key,
        model=args.model,
        endpoint=args.endpoint,
        temperature=args.temperature,
    )

    print_text_report(result)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"Hasil lengkap disimpan ke: {out_path}")


if __name__ == "__main__":
    main()
