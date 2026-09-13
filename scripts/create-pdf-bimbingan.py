#!/usr/bin/env python3
"""Buat PDF bimbingan TA — mirip PPT tapi sebagai PDF."""
import sys
sys.path.insert(0, "/tmp/pptx-env/lib/python3.13/site-packages")

from fpdf import FPDF

class SOAR_PDF(FPDF):
    def header(self):
        pass
    
    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Ravi Arnan Irianto | 2305551076 | Halaman {self.page_no()}/{{nb}}", align="C")

    def add_title(self, text, size=28):
        self.set_font("Helvetica", "B", size)
        self.set_text_color(26, 86, 142)
        self.cell(0, 12, text, new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(26, 86, 142)
        self.line(20, self.get_y(), 80, self.get_y())
        self.ln(5)

    def add_subtitle(self, text, size=14):
        self.set_font("Helvetica", "", size)
        self.set_text_color(100, 100, 100)
        self.cell(0, 8, text, new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def add_body(self, text, size=11, bold=False):
        style = "B" if bold else ""
        self.set_font("Helvetica", style, size)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 6, text)
        self.ln(1)

    def add_bullet(self, text, indent=10, size=11):
        self.set_font("Helvetica", "", size)
        self.set_text_color(50, 50, 50)
        x = self.l_margin + indent
        self.set_x(x)
        self.multi_cell(0, 6, "- " + text)

    def add_table(self, headers, rows, col_widths=None):
        if col_widths is None:
            col_widths = [170 / len(headers)] * len(headers)
        
        # Header
        self.set_font("Helvetica", "B", 9)
        self.set_fill_color(26, 86, 142)
        self.set_text_color(255, 255, 255)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 7, h, border=1, fill=True, align="C")
        self.ln()
        
        # Rows
        self.set_font("Helvetica", "", 9)
        self.set_text_color(50, 50, 50)
        for r_idx, row in enumerate(rows):
            if r_idx % 2 == 0:
                self.set_fill_color(240, 240, 240)
            else:
                self.set_fill_color(255, 255, 255)
            
            row_height = 7
            
            # Check if we need a new page
            if self.get_y() + row_height > 280:
                self.add_page()
            
            for i, cell_text in enumerate(row):
                self.cell(col_widths[i], row_height, cell_text, border=1, fill=True)
            self.ln()


pdf = SOAR_PDF(orientation="L", unit="mm", format="A4")
pdf.alias_nb_pages()
pdf.set_auto_page_break(auto=True, margin=20)

# ═══════════════════════════════════════════════════════════════
# PAGE 1: Cover
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.ln(50)
pdf.set_font("Helvetica", "B", 32)
pdf.set_text_color(26, 86, 142)
pdf.cell(0, 15, "Implementasi Sistem SOAR Open-Source", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)
pdf.set_font("Helvetica", "", 18)
pdf.set_text_color(80, 80, 80)
pdf.cell(0, 10, "Berbasis n8n untuk Deteksi dan Respons Ancaman", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.cell(0, 10, "Malware dan Phishing", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(3)
pdf.set_font("Helvetica", "I", 14)
pdf.cell(0, 10, "dengan Mitigasi Aktif Human-in-the-Loop", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(20)
pdf.set_draw_color(26, 86, 142)
pdf.line(80, pdf.get_y(), 210, pdf.get_y())
pdf.ln(10)
pdf.set_font("Helvetica", "B", 16)
pdf.set_text_color(50, 50, 50)
pdf.cell(0, 10, "Ravi Arnan Irianto  |  2305551076", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(5)
pdf.set_font("Helvetica", "", 12)
pdf.set_text_color(120, 120, 120)
pdf.cell(0, 8, "Bimbingan Tugas Akhir  -  September 2026", align="C", new_x="LMARGIN", new_y="NEXT")

# ═══════════════════════════════════════════════════════════════
# PAGE 2: Latar Belakang
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.add_title("Latar Belakang")

pdf.add_body("Masalah utama di SOC (Security Operations Center):", bold=True)
for item in [
    "Alert fatigue: 67% alert diabaikan karena terlalu banyak false positive",
    "Response manual: analis butuh menit-jam untuk tangani 1 alert",
    "SOAR komersial mahal (Splunk SOAR, Palo Alto XSOAM)",
    "SOAR open-source (Shuffle, Cortex) masih punya keterbatasan",
]:
    pdf.add_bullet(item)

pdf.ln(5)
pdf.add_body("Yang ditawarkan tugas akhir ini:", bold=True)
for item in [
    "SOAR open-source berbasis n8n (gratis, fleksibel)",
    "Confidence-based: keputusan berdasarkan keyakinan, bukan tebakan",
    "Explainable: setiap notifikasi ada alasan kenapa dianggap berbahaya",
    "Self-aware: tahu kapan deteksinya sedang tidak akurat",
]:
    pdf.add_bullet(item)

# ═══════════════════════════════════════════════════════════════
# PAGE 3: Perbandingan
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.add_title("Perbandingan dengan Pendekatan Lain")

pdf.add_table(
    ["Aspek", "SOC Manual", "SOAR Komersial", "Shuffle/Cortex", "Sistem Ini (n8n)"],
    [
        ["Biaya", "Gaji analis tinggi", "License mahal", "Gratis", "Gratis"],
        ["Kecepatan", "Menit - jam", "Detik - menit", "Detik - menit", "1,68 detik"],
        ["Transparensi", "Tergantung analis", "Black-box", "Black-box", "Alasan di notif"],
        ["Self-aware", "Tergantung analis", "Tidak ada", "Tidak ada", "Degrade otomatis"],
        ["Audit trail", "Manual", "Ada (bayar)", "Terbatas", "Gratis"],
        ["Phishing", "Tidak ada", "Tergantung playbook", "Tidak ada", "URLhaus auto-block"],
        ["AI advisory", "Tergantung analis", "Tergantung vendor", "Tidak ada", "Ollama lokal"],
        ["Multi-sumber", "Manual", "Tergantung integrasi", "Beberapa", "VT + MB"],
        ["Setup", "Tidak ada", "Kompleks", "Sedang", "Docker + Ansible"],
    ],
    [30, 35, 35, 35, 35]
)

pdf.ln(3)
pdf.set_font("Helvetica", "I", 9)
pdf.set_text_color(120, 120, 120)
pdf.cell(0, 5, "* Semua fitur berjalan di 1 VPS dengan RAM ~3 GB", new_x="LMARGIN", new_y="NEXT")

# ═══════════════════════════════════════════════════════════════
# PAGE 4: Arsitektur (text-based)
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.add_title("Arsitektur Sistem")

pdf.add_body("Stack:", bold=True)
for item in [
    "Wazuh 4.9.2 (SIEM + FIM + Active Response)",
    "n8n 2.36.9 (workflow automation)",
    "Ollama llama3.2:3b (AI lokal)",
    "VirusTotal API (hash reputation)",
    "Google Safe Browsing (URL reputation)",
    "MalwareBazaar (malware intel)",
]:
    pdf.add_bullet(item)

pdf.ln(3)
pdf.add_body("Container (6 total):", bold=True)
for item in [
    "wazuh.manager - log analysis + active response",
    "wazuh.indexer - log storage (Elasticsearch)",
    "wazuh.dashboard - web UI",
    "n8n - workflow engine + webhook",
    "tg-callback-poller - Telegram HITL bridge",
    "health-monitor - uptime monitoring",
]:
    pdf.add_bullet(item)

pdf.ln(3)
pdf.add_body("Alur:", bold=True)
pdf.set_font("Courier", "", 10)
pdf.set_text_color(50, 50, 50)
pdf.cell(0, 6, "Endpoint -> Wazuh -> n8n Webhook -> VT+MB -> Ollama -> Telegram", new_x="LMARGIN", new_y="NEXT")

# ═══════════════════════════════════════════════════════════════
# PAGE 5: Alur Keputusan
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.add_title("Alur Keputusan")

pdf.add_body("5 jalur keputusan berdasarkan keyakinan:", bold=True)
pdf.ln(2)

pdf.add_table(
    ["Kondisi", "Tindakan", "Keterangan"],
    [
        ["VT >= 20 malicious", "Auto isolate", "Keyakinan tinggi, langsung karantina file"],
        ["VT 5-19 / MB match", "HITL Telegram", "Analis pilih: Isolasi atau Abaikan"],
        ["VT 1-4 / risky unknown", "HITL + LLM advisory", "Saran AI ditambahkan ke notifikasi"],
        ["VT error / rate-limit", "Degrade + advisory", "Sistem jujur: tidak bisa verifikasi"],
        ["VT bersih + MB bersih", "Silent", "Tidak ganggu analis"],
    ],
    [45, 40, 85]
)

# ═══════════════════════════════════════════════════════════════
# PAGE 6: Hasil Pengukuran
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.add_title("Hasil Pengukuran")

pdf.add_subtitle("Uji coba dijalankan langsung di sistem live (bukan simulasi)")
pdf.ln(2)

pdf.add_table(
    ["Metrik", "Hasil", "Keterangan"],
    [
        ["MTTR malware (N=30)", "1,68 detik", "dari alert masuk sampai file terisolasi"],
        ["MTTR phishing (N=10)", "2,13 detik", "dari URL terdeteksi sampai domain diblokir"],
        ["Throughput (N=20)", "34 alert/detik", "load test 5 thread paralel"],
        ["FN rate (N=15)", "0%", "semua file risky berhasil terdeteksi"],
        ["FP suppression (N=8)", "100%", "8 alert baseline -> 0 notifikasi"],
    ],
    [45, 35, 90]
)

pdf.ln(5)
pdf.add_body("Catatan:", bold=True)
for item in [
    "MTTR 1,68 detik itu waktu end-to-end (VT cache hangat). Kalau VT cold, tambah ~3-5 detik.",
    "Phishing lebih lama sedikit karena ada pengecekan URLScan, tapi GSB langsung.",
    "Load test 34 alert/detik itu kapasitas webhook n8n. Pipeline backend jalan async.",
    "FN rate 0% artinya tidak ada file berisiko yang lolos dari deteksi.",
]:
    pdf.add_bullet(item, size=10)

# ═══════════════════════════════════════════════════════════════
# PAGE 7: Roadmap
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.add_title("Roadmap Pengerjaan")

pdf.add_table(
    ["Kategori", "Item", "Status", "Tanggal"],
    [
        ["A - Bug fix", "block-domain persist", "Selesai", "2026-07-02"],
        ["A - Bug fix", "Notifikasi ganda diperbaiki", "Selesai", "2026-07-02"],
        ["B - Threat intel", "Hybrid: risky ext -> HITL", "Selesai", "2026-07-02"],
        ["B - Threat intel", "MalwareBazaar ensemble", "Selesai", "2026-09-02"],
        ["B - Threat intel", "TTL diferensial cache", "Selesai", "2026-09-02"],
        ["C - Evaluasi", "MTTR & FP suppression", "Selesai", "2026-07-02"],
        ["C - Evaluasi", "Benchmark N>=30", "Selesai", "2026-09-02"],
        ["C - Evaluasi", "MITRE ATT&CK mapping", "Selesai", "2026-09-02"],
        ["D - Hardening", "Caddy + TLS + Ansible", "Selesai", "2026-07-06"],
        ["F - Explainable", "Self-aware + audit trail", "Selesai", "2026-07-06"],
        ["F - Explainable", "LLM-fallback advisory", "Selesai", "2026-09-02"],
        ["G - Perluasan", "Phishing proaktif", "Selesai", "2026-09-02"],
        ["G - Perluasan", "Magic-byte detection", "Selesai", "2026-09-02"],
        ["H - Maintenance", "n8n update + pin versi", "Selesai", "2026-09-02"],
        ["F - Lanjutan", "Trusted autonomy", "Belum", "-"],
        ["F - Lanjutan", "RAG anti-halusinasi", "Belum", "-"],
        ["E - Arsitektur", "HA: queue-mode + Redis", "Belum", "-"],
        ["H - Maintenance", "Upgrade Wazuh 4.14.7", "Belum", "PascTA"],
    ],
    [35, 65, 25, 30]
)

# ═══════════════════════════════════════════════════════════════
# PAGE 8: Rencana ke Depan
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.add_title("Rencana ke Depan")

items = [
    ("Trusted Autonomy",
     "Sekarang: semua keputusan butuh konfirmasi analis (HITL).\n"
     "Rencana: kalau keyakinan sangat tinggi, boleh auto tanpa tunggu analis, tapi ada timeout & SLA."),
    ("RAG (Retrieval-Augmented Generation)",
     "Masalah: LLM kadang mengarang rekomendasi (halusinasi).\n"
     "Rencana: kasih LLM akses ke playbook & threat-intel supaya jawabannya berbasis data."),
    ("Arsitektur HA",
     "Sekarang: 1 container n8n + SQLite (single point of failure).\n"
     "Rencana: n8n queue-mode + Redis + PostgreSQL + Prometheus/Grafana."),
    ("Upgrade Wazuh",
     "4.9.2 -> 4.14.7. Deferred pasca-TA karena agent juga harus di-upgrade bareng."),
]

for title, desc in items:
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(26, 86, 142)
    pdf.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(50, 50, 50)
    pdf.multi_cell(0, 6, desc)
    pdf.ln(5)

# ═══════════════════════════════════════════════════════════════
# PAGE 9: Penutup
# ═══════════════════════════════════════════════════════════════
pdf.add_page()
pdf.ln(60)
pdf.set_font("Helvetica", "B", 32)
pdf.set_text_color(26, 86, 142)
pdf.cell(0, 15, "Terima Kasih", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(10)
pdf.set_draw_color(26, 86, 142)
pdf.line(80, pdf.get_y(), 210, pdf.get_y())
pdf.ln(10)
pdf.set_font("Helvetica", "I", 13)
pdf.set_text_color(80, 80, 80)
pdf.multi_cell(0, 7, "Sistem ini dibangun dengan prinsip:\nbukan menggantikan analis, tapi membantu analis\nambil keputusan lebih cepat dengan informasi yang cukup.", align="C")
pdf.ln(20)
pdf.set_font("Helvetica", "B", 14)
pdf.set_text_color(50, 50, 50)
pdf.cell(0, 8, "Ravi Arnan Irianto  |  2305551076", align="C", new_x="LMARGIN", new_y="NEXT")
pdf.ln(3)
pdf.set_font("Helvetica", "", 11)
pdf.set_text_color(120, 120, 120)
pdf.cell(0, 8, "raviarnankeren@gmail.com", align="C", new_x="LMARGIN", new_y="NEXT")

# ─── Simpan ───
output_path = "docs/BIMBINGAN-TA-SOAR.pdf"
pdf.output(output_path)
print(f"PDF disimpan ke {output_path}")
print(f"Total halaman: {pdf.pages_count}")
