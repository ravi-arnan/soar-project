#!/usr/bin/env python3
"""Buat PPT bimbingan TA — versi sederhana dengan tabel perbandingan + roadmap."""
import sys
sys.path.insert(0, "/tmp/pptx-env/lib/python3.13/site-packages")

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

BLUE = RGBColor(0x1A, 0x56, 0x8E)
BLACK = RGBColor(0, 0, 0)
GRAY = RGBColor(0x66, 0x66, 0x66)
LGRAY = RGBColor(0x88, 0x88, 0x88)
GREEN = RGBColor(0x2E, 0x7D, 0x32)
RED = RGBColor(0xC6, 0x28, 0x28)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
LIGHT_BG = RGBColor(0xE8, 0xF5, 0xE9)


def add_text(slide, left, top, width, height, text, size=18, color=BLACK, bold=False, align=PP_ALIGN.LEFT):
    txBox = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = txBox.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = text
    p.font.size = Pt(size)
    p.font.color.rgb = color
    p.font.bold = bold
    p.alignment = align
    return txBox


def add_bullets(slide, left, top, width, height, items, size=15, color=BLACK):
    txBox = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.text = item
        p.font.size = Pt(size)
        p.font.color.rgb = color
        p.space_before = Pt(5)
    return txBox


def add_divider(slide, left, top, width):
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(left), Inches(top), Inches(width), Pt(2))
    shape.fill.solid()
    shape.fill.fore_color.rgb = BLUE
    shape.line.fill.background()


def make_table(slide, left, top, width, height, rows, cols_width=None, header_color=BLUE):
    table_shape = slide.shapes.add_table(len(rows), len(rows[0]), Inches(left), Inches(top), Inches(width), Inches(height))
    table = table_shape.table
    if cols_width:
        for i, w in enumerate(cols_width):
            table.columns[i].width = Inches(w)
    for r_idx, row in enumerate(rows):
        for c_idx, cell_text in enumerate(row):
            cell = table.cell(r_idx, c_idx)
            cell.text = cell_text
            for p in cell.text_frame.paragraphs:
                p.font.size = Pt(12)
                p.font.color.rgb = BLACK
                if r_idx == 0:
                    p.font.bold = True
            if r_idx == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = header_color
                for p in cell.text_frame.paragraphs:
                    p.font.color.rgb = WHITE
            elif r_idx % 2 == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(0xF0, 0xF0, 0xF0)
    return table


# ═══════════════════════════════════════════════════════════════
# SLIDE 1: Cover
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 1, 1.5, 11, 1.5,
    "Implementasi Sistem SOAR Open-Source\nBerbasis n8n untuk Deteksi dan Respons\nAncaman Malware dan Phishing",
    32, BLACK, True, PP_ALIGN.CENTER)

add_text(slide, 1, 4.0, 11, 0.5,
    "dengan Mitigasi Aktif Human-in-the-Loop",
    20, GRAY, False, PP_ALIGN.CENTER)

add_divider(slide, 4, 4.8, 5)

add_text(slide, 1, 5.2, 11, 0.5, "Ravi Arnan Irianto", 22, BLACK, True, PP_ALIGN.CENTER)
add_text(slide, 1, 5.7, 11, 0.5, "2305551076", 18, GRAY, False, PP_ALIGN.CENTER)
add_text(slide, 1, 6.3, 11, 0.5, "Bimbingan Tugas Akhir  -  September 2026", 16, LGRAY, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════════════════════════
# SLIDE 2: Apa itu SOAR + Kenapa penting
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Latar Belakang", 28, BLUE, True)
add_divider(slide, 0.5, 0.9, 3)

add_bullets(slide, 0.5, 1.2, 12, 2, [
    "Masalah utama di SOC (Security Operations Center):",
    "  - Alert fatigue: 67% alert diabaikan karena terlalu banyak false positive",
    "  - Response manual: analis butuh menit-jam untuk tangani 1 alert",
    "  - SOAR komersial mahal (Splunk SOAR, Palo Alto XSOAM)",
    "  - SOAR open-source (Shuffle, Cortex) masih punya keterbatasan",
], 15)

add_bullets(slide, 0.5, 3.2, 12, 2, [
    "Yang ditawarkan tugas akhir ini:",
    "  - SOAR open-source berbasis n8n (gratis, fleksibel)",
    "  - Confidence-based: keputusan berdasarkan keyakinan, bukan tebakan",
    "  - Explainable: setiap notifikasi ada alasan kenapa dianggap berbahaya",
    "  - Self-aware: tahu kapan deteksinya sedang tidak akurat",
], 15)


# ═══════════════════════════════════════════════════════════════
# SLIDE 3: Tabel Perbandingan (Apa yang unggul)
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Perbandingan dengan Pendekatan Lain", 28, BLUE, True)
add_divider(slide, 0.5, 0.9, 5)

make_table(slide, 0.5, 1.2, 12.3, 5.5, [
    ["Aspek", "SOC Manual", "SOAR Komersial", "Shuffle/Cortex", "Sistem Ini (n8n)"],
    ["Biaya", "Gaji analis tinggi", "License mahal", "Gratis", "Gratis"],
    ["Kecepatan response", "Menit - jam", "Detik - menit", "Detik - menit", "1,68 detik (malware)"],
    ["Transparensi", "Tergantung analis", "Black-box", "Black-box", "Alasan di setiap notifikasi"],
    ["Self-aware", "Tergantung analis", "Tidak ada", "Tidak ada", "Tandai degradasi otomatis"],
    ["Audit trail", "Manual / tidak ada", "Ada (bayar)", "Terbatas", "Gratis (Telegram + n8n)"],
    ["Phishing proaktif", "Tidak ada", "Tergantung playbook", "Tidak ada", "URLhaus auto-block"],
    ["AI advisory", "Tergantung analis", "Tergantung vendor", "Tidak ada", "Ollama lokal (gratis)"],
    ["Multi-sumber intel", "Manual", "Tergantung integrasi", "Beberapa", "VT + MalwareBazaar"],
    ["Setup & maintenance", "Tidak ada", "Kompleks", "Sedang", "Docker + Ansible"],
], cols_width=[2.2, 2.3, 2.6, 2.5, 2.7], header_color=BLUE)

add_text(slide, 0.5, 6.8, 12, 0.4,
    "* Semua fitur di atas berjalan di 1 VPS dengan RAM ~3 GB (tidak perlu server mahal)",
    12, GRAY)


# ═══════════════════════════════════════════════════════════════
# SLIDE 4: Diagram Arsitektur
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Arsitektur Sistem", 28, BLUE, True)
add_divider(slide, 0.5, 0.9, 3.5)

slide.shapes.add_picture("docs/diagrams/soar-architecture.png", Inches(0.5), Inches(1.1), Inches(8.5), Inches(5.8))

add_bullets(slide, 9.3, 1.2, 3.8, 5.5, [
    "Stack:",
    "  Wazuh 4.9.2",
    "  n8n 2.36.9",
    "  Ollama llama3.2:3b",
    "  VirusTotal API",
    "  Google Safe Browsing",
    "  MalwareBazaar",
    "",
    "Container (6 total):",
    "  wazuh.manager",
    "  wazuh.indexer",
    "  wazuh.dashboard",
    "  n8n",
    "  tg-callback-poller",
    "  health-monitor",
], 13, GRAY)


# ═══════════════════════════════════════════════════════════════
# SLIDE 5: Alur Keputusan
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Alur Keputusan", 28, BLUE, True)
add_divider(slide, 0.5, 0.9, 3)

flow_labels = ["FIM Alert\n(Wazuh)", "Filter\n& Extract", "VT + MB\nLookup", "Keputusan\n(Ollama)", "Telegram\n(analis)"]
for i, label in enumerate(flow_labels):
    x = 0.5 + i * 2.5
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(1.3), Inches(2.0), Inches(0.9))
    shape.fill.solid()
    shape.fill.fore_color.rgb = BLUE
    shape.line.fill.background()
    tf = shape.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = label
    p.font.size = Pt(13)
    p.font.color.rgb = WHITE
    p.alignment = PP_ALIGN.CENTER
    if i < len(flow_labels) - 1:
        add_text(slide, x + 2.0, 1.5, 0.5, 0.5, "->", 18, BLACK, True, PP_ALIGN.CENTER)

add_text(slide, 0.5, 2.5, 12, 0.5, "5 jalur keputusan berdasarkan keyakinan:", 17, BLUE, True)

make_table(slide, 0.5, 3.0, 12, 3.5, [
    ["Kondisi", "Tindakan", "Keterangan"],
    ["VT >= 20 malicious", "Auto isolate", "Keyakinan tinggi, langsung karantina file"],
    ["VT 5-19 / MB match", "HITL Telegram", "Analis pilih: Isolasi atau Abaikan"],
    ["VT 1-4 / risky unknown", "HITL + LLM advisory", "Saran AI ditambahkan ke notifikasi"],
    ["VT error / rate-limit", "Degrade + advisory", "Sistem jujur: 'tidak bisa verifikasi'"],
    ["VT bersih + MB bersih", "Silent", "Tidak ganggu analis"],
], cols_width=[3.5, 2.5, 6])


# ═══════════════════════════════════════════════════════════════
# SLIDE 6: Hasil Pengukuran
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Hasil Pengukuran", 28, BLUE, True)
add_divider(slide, 0.5, 0.9, 3.5)

add_text(slide, 0.5, 1.1, 12, 0.4, "Uji coba dijalankan langsung di sistem live (bukan simulasi)", 14, GRAY)

make_table(slide, 0.5, 1.6, 12, 2.5, [
    ["Metrik", "Hasil", "Keterangan"],
    ["MTTR malware (N=30)", "1,68 detik", "dari alert masuk sampai file terisolasi (VT cache hangat)"],
    ["MTTR phishing (N=10)", "2,13 detik", "dari URL terdeteksi sampai domain diblokir (jalur GSB)"],
    ["Throughput (N=20)", "34 alert/detik", "load test 5 thread paralel, jauh di atas beban SOC normal"],
    ["FN rate (N=15)", "0%", "semua file risky + hash unknown berhasil terdeteksi"],
    ["FP suppression (N=8)", "100%", "8 alert baseline -> 0 notifikasi (VT-gating berfungsi)"],
], cols_width=[3.5, 2.5, 6])

add_bullets(slide, 0.5, 4.4, 12, 2.8, [
    "Catatan:",
    "- MTTR 1,68 detik itu waktu end-to-end (VT cache hangat). Kalau VT cold, tambah ~3-5 detik.",
    "- Phishing lebih lama sedikit karena ada pengecekan URLScan, tapi GSB langsung.",
    "- Load test 34 alert/detik itu kapasitas webhook n8n. Pipeline backend jalan async.",
    "- FN rate 0% artinya tidak ada file berisiko yang lolos dari deteksi.",
], 14, GRAY)


# ═══════════════════════════════════════════════════════════════
# SLIDE 7: Tabel Roadmap
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Roadmap Pengerjaan", 28, BLUE, True)
add_divider(slide, 0.5, 0.9, 3.5)

make_table(slide, 0.5, 1.2, 12.3, 5.8, [
    ["Kategori", "Item", "Status", "Tanggal"],
    ["A - Bug fix", "block-domain persist", "Selesai", "2026-07-02"],
    ["A - Bug fix", "Notifikasi ganda diperbaiki", "Selesai", "2026-07-02"],
    ["B - Threat intel", "Hybrid: risky ext -> HITL review", "Selesai", "2026-07-02"],
    ["B - Threat intel", "MalwareBazaar ensemble (VT+MB)", "Selesai", "2026-09-02"],
    ["B - Threat intel", "TTL diferensial cache", "Selesai", "2026-09-02"],
    ["C - Evaluasi", "MTTR & FP suppression terukur", "Selesai", "2026-07-02"],
    ["C - Evaluasi", "Benchmark N>=30 + load test", "Selesai", "2026-09-02"],
    ["C - Evaluasi", "MITRE ATT&CK mapping (10 teknik)", "Selesai", "2026-09-02"],
    ["D - Hardening", "Caddy + TLS + Ansible IaC", "Selesai", "2026-07-06"],
    ["F - Explainable", "Self-aware + audit trail", "Selesai", "2026-07-06"],
    ["F - Explainable", "LLM-fallback advisory", "Selesai", "2026-09-02"],
    ["G - Perluasan", "Phishing proaktif (URLhaus)", "Selesai", "2026-09-02"],
    ["G - Perluasan", "Magic-byte / exec-bit detection", "Selesai", "2026-09-02"],
    ["H - Maintenance", "n8n update + pin versi", "Selesai", "2026-09-02"],
    ["F - Lanjutan", "Trusted autonomy (timeout/SLA)", "Belum", "-"],
    ["F - Lanjutan", "RAG anti-halusinasi", "Belum", "-"],
    ["E - Arsitektur", "HA: queue-mode + Redis + PG", "Belum", "-"],
    ["H - Maintenance", "Upgrade Wazuh 4.14.7", "Belum", "PascTA"],
], cols_width=[2.2, 4.5, 1.8, 2.0], header_color=BLUE)


# ═══════════════════════════════════════════════════════════════
# SLIDE 8: Rencana ke Depan
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Rencana ke Depan", 28, BLUE, True)
add_divider(slide, 0.5, 0.9, 3.5)

add_bullets(slide, 0.5, 1.3, 12, 5.5, [
    "Trusted Autonomy",
    "  Sekarang: semua keputusan butuh konfirmasi analis (HITL).",
    "  Rencana: kalau keyakinan sangat tinggi, boleh auto tanpa tunggu analis, tapi ada timeout & SLA.",
    "",
    "RAG (Retrieval-Augmented Generation)",
    "  Masalah: LLM kadang mengarang rekomendasi (halusinasi).",
    "  Rencana: kasih LLM akses ke playbook & threat-intel supaya jawabannya berbasis data.",
    "",
    "Arsitektur HA",
    "  Sekarang: 1 container n8n + SQLite (single point of failure).",
    "  Rencana: n8n queue-mode + Redis + PostgreSQL + Prometheus/Grafana.",
    "",
    "Upgrade Wazuh",
    "  4.9.2 -> 4.14.7. Deferred pasca-TA karena agent juga harus di-upgrade bareng.",
], 15)


# ═══════════════════════════════════════════════════════════════
# SLIDE 9: Penutup
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 1, 2.0, 11, 1, "Terima Kasih", 40, BLACK, True, PP_ALIGN.CENTER)

add_divider(slide, 4.5, 3.2, 4)

add_text(slide, 1.5, 3.8, 10, 1.2,
    "Sistem ini dibangun dengan prinsip:\nbukan menggantikan analis, tapi membantu analis\nambil keputusan lebih cepat dengan informasi yang cukup.",
    18, GRAY, False, PP_ALIGN.CENTER)

add_text(slide, 1, 5.3, 11, 0.5, "Ravi Arnan Irianto  |  2305551076", 18, BLACK, True, PP_ALIGN.CENTER)
add_text(slide, 1, 5.8, 11, 0.5, "raviarnankeren@gmail.com", 14, LGRAY, False, PP_ALIGN.CENTER)


# ─── Simpan ───
output_path = "docs/BIMBINGAN-TA-SOAR.pptx"
prs.save(output_path)
print(f"PPT disimpan ke {output_path}")
print(f"Total slides: {len(prs.slides)}")
