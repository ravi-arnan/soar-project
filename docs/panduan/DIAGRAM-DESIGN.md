# Diagram Design — alur kerja diagram proyek

Proyek ini memakai **[diagram-design](https://github.com/cathrynlavery/diagram-design)**
(Agent Skill, MIT) untuk membuat diagram: **HTML + SVG mandiri**, gaya editorial,
menggantikan Mermaid.

## Struktur
- **Sumber**: `docs/diagrams/src/<nama>.html` — satu file HTML mandiri per diagram.
- **Hasil**: `docs/diagrams/<nama>.png` — diekspor dari sumber, dipakai di dokumen/laporan.
- **Mermaid lama** (`.mmd`, `.drawio`): tinggal sebagai arsip; digantikan bertahap.

Skema penamaan slug: samakan `slug` di `aria-labelledby`/`<title>`/`<desc>` dengan nama file.

## Aturan inti (dari skill)
- Token semantik, bukan hex langsung: `paper #f5f5f5`, `ink #2d3142`, `muted #4f5d75`,
  `soft #7a8399`, `accent #eb6c36`. **Aksen hanya 1–2 elemen.**
- Font: **Instrument Serif** (judul), **Geist** sans (nama simpul), **Geist Mono** (sublabel teknis).
- **Tanpa shadow.** Hairline 1px, radius simpul 6px, grid 4px.
- Konektor **hanya ortogonal** (siku `r=8`), label panah selalu punya mask + celah 6–10px.
- Anggaran: **maks 9 simpul**, **12 panah**, **2 elemen aksen**, **2 anotasi**.
- SVG aksesibel: `role="img"`, `<title>` anak pertama, id `<slug>-title`/`<slug>-desc`.

## Render
```bash
python3 scripts/render-diagram.py docs/diagrams/src/<nama>.html -o docs/diagrams/<nama>.png --scale 2
```

## Validasi (opsional, dari checkout skill)
```bash
# clone sekali: git clone https://github.com/cathrynlavery/diagram-design ~/code/diagram-design
python3 ~/code/diagram-design/skills/diagram-design/scripts/self_check.py <sumber.html>
python3 ~/code/diagram-design/scripts/verify-geometry.py <sumber.html>
```

## Status migrasi
| Diagram | Tipe | Status |
|---|---|---|
| `fig-3.5-sequence-ar` | Sequence | ✅ selesai (pilot) |
| `overview-bernomor` | Flowchart (bernomor) | ✅ selesai |
| `arsitektur-soar` | Architecture | ⬜ |
| `fig-3.3-arsitektur` | Architecture | ⬜ |
| `fig-3.4-pipeline` | Data flow | ⬜ |
| `fig-3.6-telegram` | Sequence | ⬜ |
| `fig-karyawan-flow` | Sequence | ⬜ |
| `fig-karyawan-setup-vs-harian` | Flowchart | ⬜ |
| `demo-hybrid-flow` | Flowchart | ⬜ |
| `workflow-malware` | Flowchart | ⬜ |
| `workflow-phishing` | Flowchart | ⬜ |
| `workflow-callback` | Flowchart | ⬜ |
| `fig-3.1-tahapan` | Timeline | ⬜ |
| `fig-3.2-waterfall` | Gantt | ⬜ |

Catatan: `overview-bernomor` (diagram "ikuti nomornya" untuk orang awam) tetap dipertahankan
konsep bernomornya, tetapi digambar dengan tipe Architecture + nomor sebagai anotasi.
