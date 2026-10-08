# Indeks Dokumentasi (`docs/`)

Semua dokumen proyek, dikelompokkan per kategori. **Sumber utama = Markdown (`.md`)**;
PDF/DOCX/PPTX adalah hasil ekspor untuk dibaca/dibagikan. Aset gambar ada di subfolder.

```
docs/
  arsitektur/    arsitektur, alur, konsep mitigasi, perbandingan dgn antivirus
  evaluasi/      metrik & data mentah benchmark
  ilmiah/        perbandingan penelitian, n8n vs shuffle, MITRE, relevansi 2026
  laporan/       draf & ekspor laporan TA
  bimbingan/     laporan bimbingan, catatan dospem, materi        (+ lampiran/)
  demo/          kartu demo & contekan
  panduan/       panduan diagram, deployment, runbook upgrade
  agen-ringan/   spesifikasi & roadmap agen Rust
  diagrams/      sumber & hasil diagram
  screenshots/   tangkapan layar
  playbooks/     playbook RAG (anti-halusinasi)
```

## arsitektur/
| Dokumen | Isi |
|---|---|
| `ARCHITECTURE.md` | Arsitektur & komponen, skema payload |
| `FLOW.md` | Alur (sequence) deteksi → respons |
| `KONSEP-MITIGASI.md` | Konsep mitigasi / Active Response |
| `VS-ANTIVIRUS.md` | Bedanya SOAR ini vs antivirus |

## evaluasi/
| Dokumen | Isi |
|---|---|
| `EVALUASI-METRIK.md` | Metrik kuantitatif (MTTR, FP/FN, throughput, HITL, VT cache) |
| `bench-*.json` | Data mentah hasil benchmark |

## ilmiah/
| Dokumen | Isi |
|---|---|
| `PERBANDINGAN-PENELITIAN.md` | Tabel perbandingan + referensi |
| `N8N-VS-SHUFFLE.md` | Justifikasi n8n vs Shuffle |
| `MITRE-ATTACK-MAPPING.md` | Pemetaan teknik MITRE ATT&CK |
| `RELEVANSI-2026.md` | Kajian relevansi & lanskap 2026 |

## laporan/
| Dokumen | Isi |
|---|---|
| `Laporan-SOAR.md` / `.docx` | Draf laporan TA |
| `Laporan TA - SOAR.pdf` | Ekspor laporan TA |
| `Laporan TA - Topik Khusus Network.pdf` | Laporan mata kuliah terkait (arsip) |

## bimbingan/
| Dokumen | Isi |
|---|---|
| `CATATAN-DOSPEM-2026-09-03.md` | Catatan bimbingan 3 Sep 2026 |
| `LAPORAN-BIMBINGAN-2026-10-08.html` / `.pdf` | Laporan update + perbandingan milestone |
| `BIMBINGAN-TA-SOAR.pptx` / `.pdf` | Materi bimbingan |
| `lampiran/` | Gambar lampiran laporan bimbingan |

## demo/
| Dokumen | Isi |
|---|---|
| `KARTU-DEMO.md` / `.docx` / `.pdf`, `KARTU-CONTEKAN-*` | Skrip & contekan demo |

## panduan/
| Dokumen | Isi |
|---|---|
| `PANDUAN-DIAGRAM.md` / `.docx` / `.pdf` | Cara membaca diagram (versi awam) |
| `DIAGRAM-DESIGN.md` | Alur kerja diagram (diagram-design: sumber HTML+SVG, render PNG) |
| `DEPLOYMENT.md` | Panduan penggelaran |
| `UPGRADE-VERSI-2026-10.md` | Runbook upgrade n8n/Wazuh |
| `TAILSCALE-SETUP.md` | Setup akses remote via Tailscale (arsip rencana) |

## agen-ringan/
| Dokumen | Isi |
|---|---|
| `AGENT-RINGAN.md`, `ROADMAP-AGEN-RINGAN.md` | Spesifikasi & roadmap agen ringan |

> Status pekerjaan menonjol: `../ROADMAP.md`. Jejak sesi: `../HANDOFF.md`.
