# Indeks Dokumentasi (`docs/`)

Semua dokumen proyek, dikelompokkan per kategori. **Sumber utama = Markdown (`.md`)**;
PDF/DOCX/PPTX adalah hasil ekspor untuk dibaca/dibagikan. Aset gambar ada di subfolder.

```
docs/
  arsitektur/    arsitektur, alur, konsep mitigasi, perbandingan dgn antivirus
  evaluasi/      metrik & data mentah benchmark (termasuk 7 skenario LLM v1.1)
  ilmiah/        perbandingan penelitian, n8n vs shuffle, MITRE, relevansi 2026
  demo/          kartu demo & contekan
  panduan/       panduan diagram, deployment, MCP AI agent, runbook upgrade
  agen-ringan/   spesifikasi & roadmap agen Rust (soar-agent v0.3.0 / SOAR v1.1)
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
| `EVALUASI-METRIK.md` / `.pdf` | Metrik kuantitatif (MTTR, FP/FN, throughput, HITL, VT cache, konsistensi & ketahanan prompt injection LLM 7 skenario N=35) |
| `bench-*.json` | Data mentah hasil benchmark |

## ilmiah/
| Dokumen | Isi |
|---|---|
| `PERBANDINGAN-PENELITIAN.md` | Tabel perbandingan + referensi |
| `N8N-VS-SHUFFLE.md` | Justifikasi n8n vs Shuffle |
| `MITRE-ATTACK-MAPPING.md` | Pemetaan teknik MITRE ATT&CK |
| `RELEVANSI-2026.md` | Kajian relevansi & lanskap 2026 |
| `MATRIKS-CONFIDENCE-OTONOMI.md` | Matriks keyakinan → otonomi + playbook respons berjenjang (M3) |

> Catatan: Naskah akademik pribadi (`proposal/`, `milestone/`, `referensi/`, `docs/laporan/`, `docs/bimbingan/`) dipisahkan dari repositori publik ini.

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
