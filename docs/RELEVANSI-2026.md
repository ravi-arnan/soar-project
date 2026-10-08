# Relevansi & Lanskap 2026 — Verifikasi Proyek SOAR

Dokumen ini menjawab: **apakah proyek masih relevan, adakah teknologi terbaru yang
menggantikan, dan apa kata literatur 2025–2026** — beserta daftar **pro/kontra**nya.
Hasil *full research sweep* 2026-10-08 (versi komponen, CVE, tren industri, jurnal).

Proyek: *Implementasi Sistem SOAR Open-Source Berbasis n8n… (Studi Kasus: CV Bali Handmade)*
— Ravi Arnan Irianto (2305551076).

---

## 0. Verdict singkat

| Pertanyaan | Jawaban |
|---|---|
| Masih relevan? | **Ya**, masalahnya makin mendesak (alert fatigue, kekurangan analis, risiko agentic AI). |
| Ada teknologi yang menggantikan? | **Sebagian** — arah industri bergeser dari SOAR playbook statis → **agentic SOC**. Tapi adopsi masih dini; pendekatan hybrid/HITL tetap sah dan justru direkomendasikan literatur. |
| Ada yang ketinggalan? | **Ya, dua hal konkret:** (1) n8n 2.40.0 punya CVE terbuka → wajib ≥2.40.1; (2) Wazuh 4.10.5 tertinggal 4 minor (stable terbaru **4.14.8**) + 5.0 sudah beta. |
| Arah tesis (confidence-based, transparan, sadar-degradasi, HITL) | **Divalidasi kuat** oleh riset 2025–2026. Ini kekuatan utama. |
| Tekanan kebaruan | **Ada** — kombinasi Wazuh+n8n+LLM sudah jadi pola umum 2026; klaim kebaruan harus bertumpu pada metodologi & pertanggungjawaban, bukan pada pemilihan stack. |

---

## 1. Status versi komponen (per 2026-10-08)

### 1.1 n8n — proyek memakai `2.40.0`

> **Aksi 2026-10-08:** pin dinaikkan ke **`2.42.5`** (repo) **dan sudah LIVE** di ravi-debian —
> healthz ok, 5 workflow active, migrasi DB bersih, E2E hijau (FIM 21 node / chain 8 node, 0 error).

Batch CVE dipublikasikan **1–6 Okt 2026**, semuanya menambal **"2.40.0 before 2.40.1"**
(dan "sebelum 2.39.6"). Artinya versi yang dipakai sekarang **rentan**.

| CVE | Skor | Inti |
|-----|------|------|
| CVE-2026-103255 | **9.0 Critical** | Path traversal node Supabase (bypass RLS, akses/ubah data) |
| CVE-2026-103248 | **9.0 Critical** | Filter injection node Supabase (baca/ubah/hapus seluruh tabel) |
| CVE-2026-103253 | 8.7 | SQL injection node Oracle |
| CVE-2026-103247 | 8.5 | Tamper credential via node-ID duplikat |
| CVE-2026-103250 | 8.1 | NoSQL injection node MongoDB Chat Memory |
| CVE-2026-103246/103252/103259/103251/103256/103257/103249/103245 | 5.3–7.7 | Kebocoran secret credential, path traversal node n8n, XSS tersimpan, dll. |

**Tidak berlaku ke 2.40.0** (sudah dipatch sebelum versi ini): CVE-2026-1470 (sandbox escape, 9.9, fixed ≤2.5.1),
CVE-2025-68613 (expression-injection RCE, 9.9, masuk **KEV**, fixed 1.121.x/1.122.0),
CVE-2026-0863, CVE-2026-92587/92588, CVE-2026-72762/72764/72767.

→ **Aksi: upgrade ke n8n ≥ 2.40.1** (idealnya rilis stabil terbaru).

### 1.2 Wazuh — proyek memakai `4.10.5`

> **Aksi 2026-10-08:** **sudah LIVE di ravi-debian** — `4.10.5 → 4.14.8`
> (indexer→manager→dashboard). Indexer GREEN, agent Active, integrasi kustom aktif,
> manager→n8n 200. Cert tidak diregenerasi (kompatibel 4.x).

| Rilis | Status | Catatan |
|-------|--------|---------|
| **4.14.8** | **Stable terbaru** (23 Sep 2026) | Target upgrade. 4.14.7 (29 Jul 2026), 4.14.6 (1 Jul 2026) menyusul di bawahnya. |
| **5.0** | **Beta 5** (Sept 2026) | Bukan upgrade biasa — lihat batasan di bawah. |

Aturan kompatibilitas: **manager harus ≥ versi agent** (server 4.14.x bisa mengelola agent 4.9+),
urutan upgrade **Indexer → Manager → Dashboard**.

Wazuh 5.0 membawa **Case Management, Sigma rules, Content Manager (Draft→Test→Custom),
AI Assistant, Active Response di dashboard, WCS**. **Tetapi tidak bisa in-place upgrade**:
data historis tidak dimigrasi, XML rules/decoders → YAML/Sigma, `rule.level` → `wazuh.rule.level`,
severity jadi label (`low/medium/high`) bukan angka, Filebeat diganti `indexer-connector`,
path `/var/ossec` → `/var/wazuh-manager`. **Konsekuensi untuk proyek ini:** rule chain XML kustom,
`alerts.json`, dan logika n8n yang membaca `rule_level >= 7` **harus ditulis ulang** saat pindah 5.0.

---

## 2. Tren industri 2026 — pergeseran ke "agentic SOC"

- **Dari SOAR playbook → agentic AI.** Banyak vendor 2026 menyebut SOAR klasik sebagai
  *maintenance treadmill* (playbook rapuh, integration debt) dan mengusung **agentic SOC** /
  **AI SOC agents** yang menyelidiki & menyusun containment secara otonom.
- **Vendor besar ikut bergerak:** Microsoft "agentic SOC" (Apr 2026), **ISOC di Defender** (Sep 2026),
  Security Copilot agents (GA/preview). Ini sekaligus **validasi arah** (AI masuk ke SOC) dan
  **kompetisi** (fitur jadi bawaan platform).
- **Adopsi masih dini:** satu sumber industri menyebut **hanya ~14%** organisasi keamanan sudah
  memakai agentic (awal 2026) — jendela untuk pendekatan hybrid masih terbuka.
- **Risiko agentic:** **OWASP Top 10 for Agentic Applications 2026** (Des 2025) menyoroti
  prompt injection, privilege abuse, dll. Google Cybersecurity Forecast 2026 menyebut
  **prompt injection jadi mainstream** (73% deployment AI enterprise terpapar; injeksi langsung
  sukses >79%). Riset 2026 soal multi-agent AI SOC menyoroti **prompt injection, token-depletion
  deadlock, dan eksekusi otomatis yang salah** — persis alasan mengapa **HITL + AI advisory**
  (bukan AI eksekutor) adalah pilihan defensif yang tepat.

---

## 3. Literatur 2025–2026 dan implikasinya ke proyek

| Karya | Temuan kunci | Implikasi ke proyek |
|-------|--------------|---------------------|
| Singh dkk., *LLMs in the SOC* (arXiv 2508.18947, 2025) — 3.090 kueri, 45 analis, 10 bln | Analis pakai LLM sebagai **alat bantu kognitif on-demand, bukan pengambil keputusan**; hanya **4%** minta rekomendasi biner; 93% selaras NICE | **Membenarkan** desain AI-advisory + HITL + "evidence over recommendation" |
| *Unified Framework for Human-AI Collaboration in SOC with Trusted Autonomy* (arXiv 2505.23397) | Formalisasi autonomy + trust calibration + HITL | Istilah "trusted autonomy" proyek selaras kerangka ini (sitasi wajib) |
| Chhetri dkk. (ACM TOIT 2024), Tariq dkk. *Alert fatigue in SOC* (ACM CSUR 2025) | Kerangka human-AI teaming untuk menekan alert fatigue | Landasan teori reduksi FP & HITL |
| *AI-Augmented SOC: Survey of LLMs & Agents* (MDPI 2026) | LLM otonom sering **halusinasi/omit**; kolaborasi human-AI lebih baik | Validasi RAG anti-halusinasi + degradasi-sadar |
| SLR SOAR (ICCWS 2026, 29 studi) | SOAR menurunkan waktu respons & menaikkan akurasi deteksi | Dasar klaim manfaat SOAR |
| SOAR4BC (Springer 2026) | SOAR berbasis digital-twin + AI | Arah future work arsitektur |
| *Hybrid SIEM + SOAR Ecosystem* (ResearchGate 2026) | Wazuh + n8n + **multi-agent LLM** + auto-response | **Kompetitor terdekat** — pertajam diferensiasi |
| IJARSCT 2026 | SOAR n8n + Groq AI + threat intel | Pola serupa; kebaruan bukan di stack |
| SLR LLM di phishing (ScienceDirect 2026); *Quantized LLMs vs classical* (arXiv 2507.07406); eval lintas-model (Frontiers 2026) | LLM berperan ganda (menyerang & mendeteksi); ada trade-off akurasi/efisiensi | Pembanding metrik jalur phishing |

---

## 4. PRO (kenapa tetap layak)

- **Masalah belum selesai** — alert fatigue, kekurangan analis, dan kini **risiko agentic AI**
  justru memperkuat urgensi "human oversight yang dapat dipertanggungjawabkan".
- **Desain = konsensus riset 2026**: HITL, explainability (`🧠 Alasan`), audit-trail,
  degradasi-sadar, evidence-over-recommendation.
- **Stack open-source tetap sah**: n8n termasuk 5 SOAR open-source teratas (AIMultiple) dan
  tool incident-response automation 2026; Wazuh SIEM/EDR matang.
- **Biaya & reproduksibilitas**: cocok untuk studi kasus UKM — pembeda vs agentic SOC komersial (SaaS, mahal).
- **Angka terukur** (MTTR, FP suppression, FN rate) masih jarang di karya serupa.
- **Sejalan arus**: Wazuh 5.0 & Microsoft membawa AI ke dalam platform → arah proyek tidak menyimpang.

## 5. KONTRA (risiko & gap)

- **Utang keamanan versi**: n8n 2.40.0 punya CVE terbuka (kritis + high) → wajib patch ≥2.40.1.
  Ironis untuk produk keamanan; auditor bisa menyorot.
- **Satu generasi di belakang tren orkestrasi**: model playbook statis sedang dikritik sebagai rapuh
  (walau arah tesis memitigasi).
- **Beban migrasi Wazuh 5.0** besar (XML→Sigma, ubah field & severity, data tak pindah).
- **Risiko LLM/agentic**: prompt injection (log/CTI masuk ke prompt), halusinasi, biaya, egress data.
  Mitigasi saat ini belum berpedoman **OWASP Agentic Top 10**.
- **Tekanan kebaruan**: karya Wazuh+n8n+LLM sudah banyak → klaim kebaruan harus spesifik.
- **Skala/HA**: single-node, tanpa queue-mode (sengaja di-skip) → batasi klaim produksi.

---

## 6. Rekomendasi / aksi (prioritas)

| # | Aksi | Kategori | Berat |
|---|------|----------|-------|
| 1 | **Patch n8n → `2.42.5`** (tutup CVE Okt 2026) — **SELESAI & LIVE (2026-10-08)** | D | kecil |
| 2 | **Upgrade Wazuh → 4.14.8** — **SELESAI & LIVE (2026-10-08)** | H | sedang |
| 3 | **Pertajam klaim kebaruan**: posisikan kontribusi pada matriks confidence→otonomi + metrik + audit-trail di konteks UKM | C/F | kecil |
| 4 | **Sitasi literatur 2025–2026** (Singh, Chhetri, Tariq, MDPI, OWASP Agentic) di bab landasan teori | C | kecil |
| 5 | **Tambah seksi batasan**: prompt injection ke jalur LLM; sketsa migrasi Wazuh 5.0 sebagai future work | F | kecil |
| 6 | **Isi gap milestone**: MTTR HITL + VT cold-vs-cache (M6), MISP (M2), uji konsistensi LLM (M4) | C/B/G | sedang |
| 7 | **Jadwalkan Wazuh 5.0** pasca-sidang (bukan sekarang) | H | berat |

---

## Referensi

1. Wazuh, *4.14.6 Release notes* (1 Jul 2026) — https://documentation.wazuh.com/current/release-notes/release-4-14-6.html
2. initMAX, *Wazuh 5.0 is almost here!* (Beta 5) — https://www.initmax.com/wazuh-5-0/
3. Wazuh, *Release timeframe of Wazuh 5.0* (GitHub Discussion #34029) — https://github.com/wazuh/wazuh/discussions/34029
4. OpenCVE, *n8n CVEs and Security Vulnerabilities* — https://app.opencve.io/cve/?vendor=n8n
5. Orca Security, *CVE-2026-1470: Critical n8n RCE & Sandbox Escape* — https://orca.security/resources/blog/cve-2026-1470-n8n-rce-sandbox-escape/
6. Canadian Centre for Cyber Security, *n8n security advisory AV26-985* (1 Okt 2026) — https://www.cyber.gc.ca/en/alerts-advisories/n8n-security-advisory-av26-985
7. UnderDefense, *AI Security Orchestration: Replacing SOAR* — https://underdefense.com/blog/ai-security-orchestration/
8. SecurityBoulevard, *Best SOAR Alternatives in 2026* — https://securityboulevard.com/2026/07/best-soar-alternatives-in-2026-the-agentic-platforms-replacing-legacy-soar/
9. AIMultiple, *Top 5 Open Source SOAR Tools* — https://aimultiple.com/open-source-soar
10. Microsoft Security, *The agentic SOC* (Apr 2026) — https://www.microsoft.com/en-us/security/blog/2026/04/09/the-agentic-soc-rethinking-secops-for-the-next-decade/
11. Microsoft Learn, *Security Copilot agents overview* — https://learn.microsoft.com/en-us/copilot/security/agents-overview
12. OWASP, *Top 10 for Agentic Applications 2026* — https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/
13. Bregg, *Google Cybersecurity Forecast 2026 (ringkasan)* — https://www.bregg.com/blog/google-cybersecurity-forecast-2026-ai-agents-prompt-injection-agentic-soc
14. Axis Intelligence, *Prompt Injection Statistics 2026* — https://axis-intelligence.com/prompt-injection-statistics/
15. Singh dkk., *LLMs in the SOC: An Empirical Study of Human-AI Collaboration* (arXiv 2508.18947) — https://arxiv.org/abs/2508.18947
16. *A Unified Framework for Human-AI Collaboration in SOC with Trusted Autonomy* (arXiv 2505.23397) — https://arxiv.org/abs/2505.23397
17. *AI-Augmented SOC: A Survey of LLMs and Agents* (MDPI 2026) — https://www.mdpi.com/2624-800X/5/4/95
18. *Secure autonomous cyber defense with LLM agents* (ScienceDirect 2026) — https://www.sciencedirect.com/science/article/pii/S0045790626002569
19. *AI-driven digital twin-based SOAR (SOAR4BC)* (Springer 2026) — https://link.springer.com/article/10.1007/s10515-026-00612-1
20. *Systematic Literature Review: Adoption of SOAR Technology* (ICCWS 2026) — https://papers.academic-conferences.org/index.php/iccws/article/view/4422
21. *Hybrid SIEM + SOAR Ecosystem* (Wazuh + n8n + multi-agent LLM, ResearchGate 2026) — https://www.researchgate.net/publication/414511878_Hybrid_SIEM_SOAR_Ecosystem_Technical_Implementation_and_Documentation
22. *SOAR Automation Platform for Cybersecurity Incident Response* (IJARSCT 2026) — https://www.ijarsct.co.in/Paper37895.pdf
23. *A systematic literature review of LLMs in phishing* (ScienceDirect 2026) — https://www.sciencedirect.com/science/article/pii/S2590005626000986
24. *Phishing Detection in the Gen-AI Era: Quantized LLMs vs Classical Models* (arXiv 2507.07406) — https://arxiv.org/html/2507.07406v1
25. *Cross-model evaluation of phishing detectors against LLM* (Frontiers 2026) — https://www.frontiersin.org/journals/big-data/articles/10.3389/fdata.2026.1883452/full
26. CyberSense, *The Autonomous SOC and Its Attack Surface* (2026) — https://cybersense.solutions/articles/2026/Jul/20260710-AutonomousSOC.html
