#!/usr/bin/env python3
"""Buat PPT bimbingan TA — progress SOAR open-source."""
import sys
sys.path.insert(0, "/tmp/pptx-env/lib/python3.13/site-packages")

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# ─── Warna ───
DARK_BG = RGBColor(0x1A, 0x1A, 0x2E)
ACCENT = RGBColor(0x00, 0xD2, 0xFF)
WHITE = RGBColor(0xFF, 0xFF, 0xFF)
GRAY = RGBColor(0xAA, 0xAA, 0xAA)
GREEN = RGBColor(0x00, 0xE6, 0x76)
YELLOW = RGBColor(0xFF, 0xD6, 0x00)
RED = RGBColor(0xFF, 0x45, 0x45)
CARD_BG = RGBColor(0x25, 0x25, 0x3E)


def add_bg(slide):
    bg = slide.background
    fill = bg.fill
    fill.solid()
    fill.fore_color.rgb = DARK_BG


def add_text(slide, left, top, width, height, text, size=18, color=WHITE, bold=False, align=PP_ALIGN.LEFT):
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


def add_card(slide, left, top, width, height, title, items, title_color=ACCENT):
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(left), Inches(top), Inches(width), Inches(height))
    shape.fill.solid()
    shape.fill.fore_color.rgb = CARD_BG
    shape.line.fill.background()

    txBox = slide.shapes.add_textbox(Inches(left + 0.3), Inches(top + 0.2), Inches(width - 0.6), Inches(height - 0.4))
    tf = txBox.text_frame
    tf.word_wrap = True

    p = tf.paragraphs[0]
    p.text = title
    p.font.size = Pt(20)
    p.font.color.rgb = title_color
    p.font.bold = True
    p.space_after = Pt(8)

    for item in items:
        p = tf.add_paragraph()
        p.text = item
        p.font.size = Pt(14)
        p.font.color.rgb = WHITE
        p.space_before = Pt(4)


# ═══════════════════════════════════════════════════════════════
# SLIDE 1: Cover
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank
add_bg(slide)

add_text(slide, 1, 1.5, 11, 1, "Implementasi Sistem SOAR Open-Source", 40, ACCENT, True, PP_ALIGN.CENTER)
add_text(slide, 1, 2.5, 11, 1, "Berbasis n8n untuk Deteksi dan Respons Ancaman\nMalware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop", 22, WHITE, False, PP_ALIGN.CENTER)

add_text(slide, 1, 4.5, 11, 0.5, "━━━━━━━━━━━━━━━━━━━━━━━━━━━━", 16, ACCENT, False, PP_ALIGN.CENTER)

add_text(slide, 1, 5.2, 11, 0.5, "Ravi Arnan Irianto  ·  2305551076", 20, WHITE, True, PP_ALIGN.CENTER)
add_text(slide, 1, 5.8, 11, 0.5, "Bimbingan TA  ·  September 2026", 16, GRAY, False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════════════════════════
# SLIDE 2: Ringkasan Progress
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide)
add_text(slide, 0.5, 0.3, 12, 0.7, "Ringkasan Progress", 32, ACCENT, True)

add_card(slide, 0.5, 1.2, 3.8, 2.8, "✅ Selesai (A)", [
    "• block-domain persist",
    "• Notifikasi ganda diperbaiki",
    "• Event deleted diabaikan",
    "• Reproducibility config",
])
add_card(slide, 4.7, 1.2, 3.8, 2.8, "✅ Selesai (C)", [
    "• MTTR malware 1,68 dtk (N=15)",
    "• MTTR phishing 2,13 dtk (N=5)",
    "• FP suppression 100%",
    "• Benchmark N=30 selesai",
    "• MITRE ATT&CK mapping (10 teknik)",
])
add_card(slide, 8.9, 1.2, 3.8, 2.8, "✅ Selesai (B)", [
    "• Hybrid: risky ext → HITL review",
    "• MalwareBazaar ensemble (VT+MB)",
    "• TTL diferensial cache",
    "• G2: exec-bit detection",
])

add_card(slide, 0.5, 4.3, 3.8, 2.8, "✅ Selesai (D+F)", [
    "• Hardening: Caddy + TLS + auth",
    "• IaC: Ansible playbook",
    "• Self-aware health monitor",
    "• Explainable notifications",
    "• Audit trail analis",
])
add_card(slide, 4.7, 4.3, 3.8, 2.8, "✅ Selesai (G+H)", [
    "• G1: Phishing proaktif (URLhaus)",
    "• G2: Magic-byte detection",
    "• H1: n8n update 2.36.9",
    "• H2: Pin versi n8n",
])
add_card(slide, 8.9, 4.3, 3.8, 2.8, "⬜ Belum", [
    "• LLM-fallback advisory (F)",
    "• Trusted autonomy (F)",
    "• Arsitektur HA (E)",
    "• Upgrade Wazuh 4.14.7 (H3)",
])


# ═══════════════════════════════════════════════════════════════
# SLIDE 3: Arsitektur Sistem
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide)
add_text(slide, 0.5, 0.3, 12, 0.7, "Arsitektur Sistem", 32, ACCENT, True)

add_text(slide, 0.5, 1.2, 12, 0.6, "Stack: Wazuh 4.9.2 + n8n 2.36.9 + Ollama llama3.2:3b + VirusTotal + GSB + MalwareBazaar", 16, GRAY)

# Flow boxes
flow_items = [
    ("Endpoint\n(FIM/Log)", 0.5, 2.2),
    ("Wazuh\nManager", 2.8, 2.2),
    ("n8n\nWebhook", 5.1, 2.2),
    ("VT + MB\nEnsemble", 7.4, 2.2),
    ("Ollama\nAI", 9.7, 2.2),
    ("Telegram\nHITL", 12.0, 2.2),
]
for label, x, y in flow_items:
    shape = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(x), Inches(y), Inches(2.0), Inches(1.2))
    shape.fill.solid()
    shape.fill.fore_color.rgb = CARD_BG
    shape.line.color.rgb = ACCENT
    shape.line.width = Pt(2)
    tf = shape.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = label
    p.font.size = Pt(14)
    p.font.color.rgb = WHITE
    p.alignment = PP_ALIGN.CENTER

# Arrows
for i in range(len(flow_items) - 1):
    x1 = flow_items[i][1] + 2.0
    x2 = flow_items[i+1][1]
    mid_y = 2.8
    add_text(slide, x1, mid_y - 0.1, x2 - x1, 0.3, "→", 24, ACCENT, True, PP_ALIGN.CENTER)

# Decision paths
add_text(slide, 0.5, 3.8, 12, 0.5, "Decision Paths:", 18, ACCENT, True)

paths = [
    ("VT ≥ 20 malicious", "AUTO ISOLATE (quarantine-file)", GREEN),
    ("VT 5-19 / MB malicious", "HITL Telegram (tombol Isolasi/Abaikan)", YELLOW),
    ("VT 1-4 / review_unknown", "HITL Telegram + LLM Advisory", YELLOW),
    ("VT unverified", "Self-aware degraded + Advisory", RED),
    ("VT clean + MB clean", "Silent (no notification)", GRAY),
]
for i, (cond, action, color) in enumerate(paths):
    y = 4.4 + i * 0.5
    add_text(slide, 0.8, y, 3.5, 0.4, cond, 14, color, True)
    add_text(slide, 4.5, y, 0.3, 0.4, "→", 16, WHITE, False, PP_ALIGN.CENTER)
    add_text(slide, 5.0, y, 7, 0.4, action, 14, WHITE)


# ═══════════════════════════════════════════════════════════════
# SLIDE 4: Hasil Benchmark
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide)
add_text(slide, 0.5, 0.3, 12, 0.7, "Hasil Benchmark (2026-09-02)", 32, ACCENT, True)

add_card(slide, 0.5, 1.2, 3.8, 2.5, "MTTR Malware (N=30)", [
    "• Webhook response: 0,03 detik",
    "• End-to-end: ~1,68 detik",
    "• VT cache hangat",
    "• Median: 1,42 detik",
], GREEN)

add_card(slide, 4.7, 1.2, 3.8, 2.5, "MTTR Phishing (N=10)", [
    "• Webhook response: 0,03 detik",
    "• End-to-end: ~2,13 detik",
    "• GSB jalur cepat",
    "• 10/10 berhasil",
], GREEN)

add_card(slide, 8.9, 1.2, 3.8, 2.5, "Load Test (N=20)", [
    "• Throughput: 34,11 alert/detik",
    "• Rata-rata: 142 ms/alert",
    "• Concurrency: 5 thread",
    "• Wall time: 0,6 detik",
], ACCENT)

add_card(slide, 2.6, 4.1, 4.5, 2.5, "False-Negative Rate (N=15)", [
    "• FN rate: 0,0% (0/15 silent)",
    "• True-positive: 100%",
    "• Risky ext + unknown hash",
    "• Semua terdeteksi sebagai threat",
], GREEN)

add_card(slide, 7.5, 4.1, 4.5, 2.5, "FP Suppression (N=8)", [
    "• Baseline: 8 alert FIM",
    "• SOAR: 0 notifikasi",
    "• Reduksi FP: 100%",
    "• VT-gating berfungsi",
], GREEN)


# ═══════════════════════════════════════════════════════════════
# SLIDE 5: Kontribusi & Kebaruan
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide)
add_text(slide, 0.5, 0.3, 12, 0.7, "Kontribusi & Kebaruan", 32, ACCENT, True)

add_card(slide, 0.5, 1.2, 5.8, 2.5, "🧠 Explainable + Self-Aware", [
    "• Setiap notifikasi memuat alasan keputusan (🧠 Alasan)",
    "• Self-aware: tandai Degradasi saat sumber rate-limit/error",
    "• Audit trail: keputusan analis tercatat + waktu WITA",
    "• LLM advisory untuk alert edge cases",
], ACCENT)

add_card(slide, 6.8, 1.2, 5.8, 2.5, "🛡️ Confidence-Based Decision", [
    "• 5 jalur keputusan berdasarkan keyakinan",
    "• Auto-isolate hanya untuk keyakinan tinggi (≥20 VT)",
    "• Ensemble VT + MalwareBazaar (multi-sumber)",
    "• TTL diferensial: clean 24h, malicious 7 hari",
], ACCENT)

add_card(slide, 0.5, 4.1, 5.8, 2.8, "📊 Bukti Ilmiah", [
    "• MITRE ATT&CK mapping: 10 teknik tercakup",
    "• n8n vs Shuffle: empiris 6 aspek (3,8/5 vs 2,5/5)",
    "• Benchmark N≥30: throughput, MTTR, FN rate",
    "• FP suppression 100% terukur",
], GREEN)

add_card(slide, 6.8, 4.1, 5.8, 2.8, "🔗 Proaktif + Hybrid", [
    "• Phishing proaktif: URLhaus feed → auto-block sebelum diklik",
    "• G2: exec-bit detection (ELF/MZ tanpa ekstensi)",
    "• Health monitor: poll agent/n8n/Ollama → alert saat status berubah",
    "• Hardening: Caddy reverse-proxy + TLS + basic-auth",
], GREEN)


# ═══════════════════════════════════════════════════════════════
# SLIDE 6: Roadmap Selanjutnya
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide)
add_text(slide, 0.5, 0.3, 12, 0.7, "Roadmap Selanjutnya", 32, ACCENT, True)

items = [
    ("F: Trusted Autonomy", "Timeout/SLA + otonomi adaptif per tingkat keyakinan. HITL tetap default, otonomi hanya untuk keyakinan sangat tinggi.", "berat"),
    ("F: RAG Anti-Halusinasi", "Retrieval-Augmented Generation atas playbook/threat-intel. Cegah LLM mengarang rekomendasi.", "berat"),
    ("E: Arsitektur HA", "n8n queue-mode (Redis+worker) + PostgreSQL. Manager/indexer redundan. Prometheus + Grafana.", "berat"),
    ("H3: Upgrade Wazuh", "4.9.2 → 4.14.7 (pasca-TA). Agent wajib upgrade bareng.", "sedang"),
]

for i, (title, desc, weight) in enumerate(items):
    y = 1.2 + i * 1.5
    color = RED if weight == "berat" else YELLOW
    add_card(slide, 0.5, y, 12, 1.2, f"{title}  [{weight}]", [desc], color)


# ═══════════════════════════════════════════════════════════════
# SLIDE 7: Penutup
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])
add_bg(slide)

add_text(slide, 1, 2.0, 11, 1, "Terima Kasih", 44, ACCENT, True, PP_ALIGN.CENTER)

add_text(slide, 1, 3.5, 11, 1,
    "SOAR open-source yang confidence-based, transparan,\n"
    "dan sadar-degradasi untuk menekan alert fatigue\n"
    "tanpa silent-failure — dengan HITL yang dapat dipertanggungjawabkan.",
    18, WHITE, False, PP_ALIGN.CENTER)

add_text(slide, 1, 5.5, 11, 0.5, "Ravi Arnan Irianto  ·  2305551076", 16, GRAY, False, PP_ALIGN.CENTER)
add_text(slide, 1, 6.0, 11, 0.5, "raviarnankeren@gmail.com", 14, GRAY, False, PP_ALIGN.CENTER)


# ─── Simpan ───
output_path = "docs/BIMBINGAN-TA-SOAR.pptx"
prs.save(output_path)
print(f"PPT disimpan ke {output_path}")
print(f"Total slides: {len(prs.slides)}")
