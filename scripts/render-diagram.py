#!/usr/bin/env python3
"""Render diagram Design HTML -> PNG (diagram-only) via Chrome headless.

Ekstrak elemen <svg> pertama dari file HTML (design system diagram-design),
bungkus minimal (background paper + Google Fonts), lalu raster dengan Chrome.

Pakai:
  python3 scripts/render-diagram.py docs/diagrams/src/foo.html -o docs/diagrams/foo.png --scale 2
"""
import argparse
import os
import re
import subprocess
import tempfile

FONTS = ("https://fonts.googleapis.com/css2?"
         "family=Instrument+Serif:ital@0;1&family=Geist:wght@400;500;600&"
         "family=Geist+Mono:wght@400;500;600&display=swap")
PAPER = "#f5f5f5"


def extract_svg(html):
    m = re.search(r"<svg\b.*?</svg>", html, re.DOTALL)
    if not m:
        raise SystemExit("tidak menemukan <svg> di HTML")
    svg = m.group(0)
    vb = re.search(r'viewBox="([\d.\s-]+)"', svg)
    if not vb:
        raise SystemExit("svg tanpa viewBox")
    _, _, w, h = [float(x) for x in vb.group(1).split()]
    return svg, int(w), int(h)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("-o", "--output", required=True)
    ap.add_argument("--scale", type=int, default=2)
    ap.add_argument("--svg-only", action="store_true")
    ap.add_argument("--chrome", default="google-chrome")
    a = ap.parse_args()

    html = open(a.input, encoding="utf-8").read()
    svg, w, h = extract_svg(html)
    W, H = w * a.scale, h * a.scale
    svg = re.sub(r'\swidth="[^"]*"', "", svg, count=1)
    svg = re.sub(r'\sheight="[^"]*"', "", svg, count=1)
    svg = svg.replace("<svg ", f'<svg width="{W}" height="{H}" ', 1)

    out = os.path.abspath(a.output)
    os.makedirs(os.path.dirname(out), exist_ok=True)

    if a.svg_only:
        open(out, "w").write(svg)
        print(f"SVG -> {out} ({w}x{h})")
        return

    page = (f'<!doctype html><html><head><meta charset="utf-8">'
            f'<link href="{FONTS}" rel="stylesheet"></head>'
            f'<body style="margin:0;background:{PAPER}">{svg}</body></html>')
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False) as f:
        f.write(page)
        tmp = f.name
    prof = tempfile.mkdtemp(prefix="chrome-render-")
    try:
        subprocess.run(
            [a.chrome, "--headless=new", "--no-sandbox", "--disable-gpu",
             "--hide-scrollbars", f"--user-data-dir={prof}",
             f"--window-size={W},{H}", f"--screenshot={out}",
             "--virtual-time-budget=8000", f"file://{tmp}"],
            check=True, capture_output=True, timeout=120,
        )
    finally:
        os.unlink(tmp)
    print(f"PNG -> {out} ({W}x{H}, dari viewBox {w}x{h})")


if __name__ == "__main__":
    main()
