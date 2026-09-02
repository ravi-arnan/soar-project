#!/usr/bin/env python3
"""Buat PPT bimbingan TA — versi sederhana seperti buatan mahasiswa."""
import sys
sys.path.insert(0, "/tmp/pptx-env/lib/python3.13/site-packages")

from pptx import Presentation
from pptx.util import Inches, Pt, Emu
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)


def add_text(slide, left, top, width, height, text, size=18, color=RGBColor(0,0,0), bold=False, align=PP_ALIGN.LEFT):
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


def add_bullets(slide, left, top, width, height, items, size=16, color=RGBColor(0,0,0), bold_first=False):
    txBox = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = txBox.text_frame
    tf.word_wrap = True
    for i, item in enumerate(items):
        if i == 0:
            p = tf.paragraphs[0]
        else:
            p = tf.add_paragraph()
        p.text = item
        p.font.size = Pt(size)
        p.font.color.rgb = color
        p.space_before = Pt(6)
        if bold_first and i == 0:
            p.font.bold = True
    return txBox


def make_table(slide, left, top, width, height, rows, cols_width=None):
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
                p.font.size = Pt(13)
                p.font.color.rgb = RGBColor(0, 0, 0)
                if r_idx == 0:
                    p.font.bold = True
            if r_idx == 0:
                cell.fill.solid()
                cell.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
                for p in cell.text_frame.paragraphs:
                    p.font.color.rgb = RGBColor(255, 255, 255)
    return table


# ═══════════════════════════════════════════════════════════════
# SLIDE 1: Cover
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 1, 1.5, 11, 1.5,
    "Implementasi Sistem SOAR Open-Source\nBerbasis n8n untuk Deteksi dan Respons\nAncaman Malware dan Phishing",
    32, RGBColor(0, 0, 0), True, PP_ALIGN.CENTER)

add_text(slide, 1, 4.0, 11, 0.5,
    "dengan Mitigasi Aktif Human-in-the-Loop",
    20, RGBColor(0x55, 0x55, 0x55), False, PP_ALIGN.CENTER)

# garis
shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(4), Inches(4.8), Inches(5), Pt(2))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
shape.line.fill.background()

add_text(slide, 1, 5.2, 11, 0.5, "Ravi Arnan Irianto", 22, RGBColor(0, 0, 0), True, PP_ALIGN.CENTER)
add_text(slide, 1, 5.7, 11, 0.5, "2305551076", 18, RGBColor(0x55, 0x55, 0x55), False, PP_ALIGN.CENTER)
add_text(slide, 1, 6.3, 11, 0.5, "Bimbingan Tugas Akhir  -  September 2026", 16, RGBColor(0x88, 0x88, 0x88), False, PP_ALIGN.CENTER)


# ═══════════════════════════════════════════════════════════════
# SLIDE 2: Progress Pengerjaan
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Progress Pengerjaan", 28, RGBColor(0x1A, 0x56, 0x8E), True)

# Garis bawah judul
shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.5), Inches(0.9), Inches(4), Pt(2))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
shape.line.fill.background()

add_bullets(slide, 0.5, 1.2, 5.8, 5.5, [
    "Bug fix & deteksi:",
    "  - block-domain sekarang persist, tidak hilang saat restart",
    "  - notifikasi ganda untuk 1 file sudah diperbaiki",
    "  - file berekstensi berisiko (.sh/.exe) yang tak dikenal VT minta review",
    "  - file tanpa ekstensi tapi ada execute bit juga tertangkap",
    "",
    "Threat intelligence:",
    "  - sekarang pakai 2 sumber: VirusTotal + MalwareBazaar",
    "  - cache VT TTL diferensial (bersih 24 jam, berbahaya 7 hari)",
    "  - phishing proaktif: fetch URLhaus tiap jam, block sebelum user klik",
    "  - kalau VT error, sistem tetap jalan dan kasih tahu analis",
], 15)

add_bullets(slide, 6.8, 1.2, 5.8, 5.5, [
    "Infrastruktur:",
    "  - n8n di-update ke 2.36.9 (di atas semua CVE 2026)",
    "  - hardening: Caddy reverse-proxy + TLS + basic auth",
    "  - IaC pakai Ansible playbook (idempoten)",
    "  - health monitor: cek agent/n8n/Ollama, alert saat status berubah",
    "",
    "Pengukuran:",
    "  - benchmark udah jalan: throughput 34 alert/detik",
    "  - FN rate 0% (15/15 file berisiko ketangkep)",
    "  - FP suppression 100% (8 alert baseline -> 0 notifikasi)",
    "  - mapping ke MITRE ATT&CK: 10 teknik tercakup",
], 15)


# ═══════════════════════════════════════════════════════════════
# SLIDE 3: Arsitektur / Cara Kerja
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Cara Kerja Sistem", 28, RGBColor(0x1A, 0x56, 0x8E), True)

shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.5), Inches(0.9), Inches(3.5), Pt(2))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
shape.line.fill.background()

add_text(slide, 0.5, 1.2, 12, 0.5,
    "Stack: Wazuh 4.9.2 + n8n 2.36.9 + Ollama llama3.2:3b + VirusTotal + GSB + MalwareBazaar",
    14, RGBColor(0x66, 0x66, 0x66))

# Flow sederhana pakai kotak biasa
flow_labels = ["Endpoint\n(FIM/Log)", "Wazuh\nManager", "n8n\nWorkflow", "VT + MB\nEnsemble", "Ollama\n(AI lokal)", "Telegram\n(analis)"]
for i, label in enumerate(flow_labels):
    x = 0.3 + i * 2.15
    shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(x), Inches(1.9), Inches(1.8), Inches(0.9))
    shape.fill.solid()
    shape.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
    shape.line.fill.background()
    tf = shape.text_frame
    tf.word_wrap = True
    p = tf.paragraphs[0]
    p.text = label
    p.font.size = Pt(12)
    p.font.color.rgb = RGBColor(255, 255, 255)
    p.alignment = PP_ALIGN.CENTER

    if i < len(flow_labels) - 1:
        add_text(slide, x + 1.8, 2.1, 0.35, 0.5, "->", 18, RGBColor(0, 0, 0), True, PP_ALIGN.CENTER)

# Tabel decision
add_text(slide, 0.5, 3.2, 12, 0.5, "Keputusan berdasarkan keyakinan:", 17, RGBColor(0x1A, 0x56, 0x8E), True)

make_table(slide, 0.5, 3.7, 12, 3.2, [
    ["Situasi", "Yang dilakukan"],
    ["VT deteksi >= 20", "Langsung isolasi file otomatis"],
    ["VT deteksi 5-19 atau MB match", "Kirim ke Telegram, analis pilih tombol"],
    ["VT deteksi 1-4 atau file risky unknown", "Kirim notifikasi + minta saran AI"],
    ["VT error / rate-limit", "Tandai degradasi, minta verifikasi manual"],
    ["VT bersih + MB bersih", "Diam saja (tidak ganggu analis)"],
], cols_width=[5, 7])


# ═══════════════════════════════════════════════════════════════
# SLIDE 4: Hasil Pengukuran
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Hasil Pengukuran", 28, RGBColor(0x1A, 0x56, 0x8E), True)

shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.5), Inches(0.9), Inches(3.5), Pt(2))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
shape.line.fill.background()

add_text(slide, 0.5, 1.1, 12, 0.4, "Uji coba dijalankan langsung di sistem live (bukan simulasi)", 14, RGBColor(0x66, 0x66, 0x66))

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
    "- Load test 34 alert/detik itu kapasitas webhook n8n. Pipeline backend (VT/MB/Ollama) jalan async.",
    "- FN rate 0% artinya tidak ada file berisiko yang lolos dari deteksi.",
], 14, RGBColor(0x55, 0x55, 0x55))


# ═══════════════════════════════════════════════════════════════
# SLIDE 5: Kontribusi / Kebaruan
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Kontribusi & Kebaruan", 28, RGBColor(0x1A, 0x56, 0x8E), True)

shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.5), Inches(0.9), Inches(4), Pt(2))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
shape.line.fill.background()

add_bullets(slide, 0.5, 1.2, 5.8, 5.5, [
    "Kenapa ini berbeda dari SOAR lain:",
    "  - SOAR lain (Shuffle, Cortex) itu black-box",
    "    analis tidak tahu kenapa keputusan diambil",
    "  - Sistem ini kasih alasan di setiap notifikasi:",
    "    kenapa file ini dianggap berbahaya",
    "  - Kalau sumber intel error, sistem jujur bilang",
    "    'saya tidak bisa verifikasi' bukan diam saja",
    "  - Auto-isolate cuma untuk keyakinan tinggi,",
    "    sisanya serahin ke analis",
], 15)

add_bullets(slide, 6.8, 1.2, 5.8, 5.5, [
    "Yang belum ada di SOAR lain:",
    "  - LLM advisory lokal (Ollama) untuk alert ambigu",
    "    tanpa kirim data ke cloud",
    "  - Phishing proaktif: blok URL dari feed publik",
    "    sebelum user sempat klik",
    "  - Health monitor yang sadar diri: tahu kapan",
    "    ia sedang tidak bisa bekerja dengan baik",
    "  - Cache VT dengan TTL diferensial:",
    "    file bersih di-scan ulang lebih cepat",
], 15)

add_bullets(slide, 0.5, 4.6, 12, 2.5, [
    "Bukti pendukung:",
    "  - Mapping MITRE ATT&CK: 10 teknik tercakup dalam playbook",
    "  - Perbandingan empiris n8n vs Shuffle: 6 aspek dinilai (n8n menang 3,8 vs 2,5)",
    "  - Benchmark N>=30 dengan data nyata, bukan simulasi",
    "  - Semua konfigurasi di-version-control (Ansible + Docker Compose)",
], 14, RGBColor(0x55, 0x55, 0x55))


# ═══════════════════════════════════════════════════════════════
# SLIDE 6: Rencana ke Depan
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 0.5, 0.3, 12, 0.6, "Rencana ke Depan", 28, RGBColor(0x1A, 0x56, 0x8E), True)

shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(0.5), Inches(0.9), Inches(3.5), Pt(2))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
shape.line.fill.background()

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
# SLIDE 7: Penutup
# ═══════════════════════════════════════════════════════════════
slide = prs.slides.add_slide(prs.slide_layouts[6])

add_text(slide, 1, 2.0, 11, 1, "Terima Kasih", 40, RGBColor(0, 0, 0), True, PP_ALIGN.CENTER)

shape = slide.shapes.add_shape(MSO_SHAPE.RECTANGLE, Inches(4.5), Inches(3.2), Inches(4), Pt(2))
shape.fill.solid()
shape.fill.fore_color.rgb = RGBColor(0x1A, 0x56, 0x8E)
shape.line.fill.background()

add_text(slide, 1.5, 3.8, 10, 1.2,
    "Sistem ini dibangun dengan prinsip:\nbukan menggantikan analis, tapi membantu analis\nambil keputusan lebih cepat dengan informasi yang cukup.",
    18, RGBColor(0x55, 0x55, 0x55), False, PP_ALIGN.CENTER)

add_text(slide, 1, 5.3, 11, 0.5, "Ravi Arnan Irianto  |  2305551076", 18, RGBColor(0, 0, 0), True, PP_ALIGN.CENTER)
add_text(slide, 1, 5.8, 11, 0.5, "raviarnankeren@gmail.com", 14, RGBColor(0x88, 0x88, 0x88), False, PP_ALIGN.CENTER)


# ─── Simpan ───
output_path = "docs/BIMBINGAN-TA-SOAR.pptx"
prs.save(output_path)
print(f"PPT disimpan ke {output_path}")
print(f"Total slides: {len(prs.slides)}")
