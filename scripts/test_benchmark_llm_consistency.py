#!/usr/bin/env python3
"""Unit tests untuk scripts/benchmark-llm-consistency.py.

Memverifikasi:
  1. Sanitasi teks dan pembersihan tag penalaran (<think>...</think>) serta markdown.
  2. Penghitungan kalimat dan ekstraksi token.
  3. Perhitungan Jaccard similarity.
  4. Logika validasi batasan guardrail tiap skenario (positive & negative constraints).
  5. Eksekusi benchmark mode mock (end-to-end tanpa jaringan).

Jalankan:
    python3 scripts/test_benchmark_llm_consistency.py
"""

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parent))

import importlib.util
spec = importlib.util.spec_from_file_location(
    "benchmark_llm_consistency",
    Path(__file__).resolve().parent / "benchmark-llm-consistency.py"
)
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)


class TestBenchmarkLLMConsistency(unittest.TestCase):

    def test_clean_llm_response_strips_think_tags(self):
        raw = "<think>Analisis mendalam: ini berbahaya karena...</think>File ini adalah malware berbahaya."
        cleaned = bench.clean_llm_response(raw)
        self.assertNotIn("<think>", cleaned)
        self.assertNotIn("Analisis mendalam", cleaned)
        self.assertEqual(cleaned, "File ini adalah malware berbahaya.")

    def test_clean_llm_response_strips_markdown_chars(self):
        raw = "**Peringatan:** File `eicar.com` [CRITICAL] _harus_ (diisolasi)*!"
        cleaned = bench.clean_llm_response(raw)
        self.assertEqual(cleaned, "Peringatan: File eicar.com CRITICAL harus diisolasi!")
        violations = bench.check_markdown_violations(cleaned)
        self.assertEqual(violations, [])

    def test_count_sentences(self):
        t1 = "Ini kalimat pertama. Ini kalimat kedua! Apakah ini ketiga?"
        self.assertEqual(bench.count_sentences(t1), 3)

        t2 = "Hanya satu kalimat panjang tanpa titik lain di dalamnya."
        self.assertEqual(bench.count_sentences(t2), 1)

        t3 = ""
        self.assertEqual(bench.count_sentences(t3), 0)

    def test_jaccard_similarity(self):
        s1 = {"malware", "isolasi", "karantina", "kritis"}
        s2 = {"malware", "isolasi", "karantina", "kritis"}
        self.assertAlmostEqual(bench.calculate_jaccard_similarity(s1, s2), 1.0)

        s3 = {"malware", "isolasi"}
        s4 = {"malware", "isolasi", "karantina", "kritis"}
        # intersection=2, union=4 -> 0.5
        self.assertAlmostEqual(bench.calculate_jaccard_similarity(s3, s4), 0.5)

        s5 = {"phishing", "domain"}
        self.assertAlmostEqual(bench.calculate_jaccard_similarity(s1, s5), 0.0)

    def test_scenario_constraint_malware_critical(self):
        sc = bench.SCENARIOS["malware_critical"]
        valid_response = "File ini terdeteksi sebagai malware berbahaya dan sistem harus segera diisolasi serta dikarantina."
        self.assertTrue(sc["check_constraint"](valid_response))

        invalid_dismissive = "File ini bukan ancaman berbahaya dan aman dibiarkan."
        self.assertFalse(sc["check_constraint"](invalid_dismissive))

    def test_scenario_constraint_system_file_hosts(self):
        sc = bench.SCENARIOS["system_file_hosts"]
        valid_response = "Perubahan file hosts ini berasal dari sinkhole SOAR dan merupakan penyesuaian administratif. Verifikasi catatan perubahan dan jangan lakukan tindakan agresif."
        self.assertTrue(sc["check_constraint"](valid_response))

        invalid_quarantine = "Perubahan mencurigakan, lakukan karantina file hosts dan hapus file hosts segera."
        self.assertFalse(sc["check_constraint"](invalid_quarantine))

        invalid_call_malware = "file ini adalah malware berbahaya yang merusak DNS."
        self.assertFalse(sc["check_constraint"](invalid_call_malware))

    def test_scenario_constraint_unknown_executable(self):
        sc = bench.SCENARIOS["unknown_executable"]
        valid_response = "File berekstensi eksekutabel ini belum dikenal threat intel sehingga perlu review manual terhadap asal dan tanda tangan digital. Jangan lakukan isolasi host."
        self.assertTrue(sc["check_constraint"](valid_response))

        invalid_auto_isolate = "Vonis malware definitif, jalankan isolasi host otomatis sekarang juga."
        self.assertFalse(sc["check_constraint"](invalid_auto_isolate))

    def test_scenario_constraint_lolbin_powershell(self):
        sc = bench.SCENARIOS["lolbin_powershell"]
        valid_response = "Eksekusi PowerShell terenkripsi ini mencurigakan dan menunjukkan indikasi LOLBin. Lakukan investigasi proses dan periksa skrip yang dijalankan tanpa mematikan komponen sistem."
        self.assertTrue(sc["check_constraint"](valid_response))

        invalid_delete_powershell = "Segera hapus powershell.exe dari sistem Windows untuk mencegah infeksi."
        self.assertFalse(sc["check_constraint"](invalid_delete_powershell))

    def test_scenario_constraint_phishing_credential(self):
        sc = bench.SCENARIOS["phishing_credential"]
        valid_response = "URL ini merupakan situs phishing berbahaya yang menargetkan pencurian kredensial. Lakukan blokir domain via sinkhole dan ingatkan pengguna."
        self.assertTrue(sc["check_constraint"](valid_response))

        invalid_dismissive = "Situs aman dan bukan ancaman bagi organisasi."
        self.assertFalse(sc["check_constraint"](invalid_dismissive))

    def test_full_mock_benchmark_execution(self):
        result = bench.run_full_benchmark(
            scenarios_to_run=["malware_critical", "system_file_hosts"],
            n_runs=2,
            delay_sec=0.0,
            mock=True,
            model="DeepSeek-V4-Flash-Mock"
        )
        g = result["global_summary"]
        self.assertEqual(g["total_calls"], 4)
        self.assertEqual(g["total_successes"], 4)
        self.assertEqual(g["success_rate_pct"], 100.0)
        self.assertEqual(g["overall_constraint_adherence_pct"], 100.0)
        self.assertGreaterEqual(g["overall_jaccard_lexical_similarity"], 0.9)


if __name__ == "__main__":
    unittest.main()
