# Tabel Perbandingan dengan Penelitian / Karya Sejenis

**Karya ini:** *Implementasi Sistem SOAR Open-Source Berbasis n8n untuk Deteksi dan Respons Ancaman Malware dan Phishing dengan Mitigasi Aktif Human-in-the-Loop* — Ravi Arnan Irianto (2305551076).

> Legenda: ✔ = ada · ✘ = tidak ada · **1-arah** = notifikasi saja (bukan interaktif) · – = tidak disebutkan pada sumber publik.
> Catatan: detail pada baris pembanding didasarkan pada deskripsi publik (jurnal/blog/repo) dan dapat berbeda dari implementasi aktual.

## Tabel 1 — Perbandingan fitur

| # | Karya / Sumber (jenis) | Orkestrasi (SOAR) | SIEM | Ancaman ditangani | Sumber intel/reputasi | Human-in-the-loop 2-arah | Active Response otomatis | Respons berjenjang berbasis keyakinan | AI analisis | Multi-agent lintas-OS |
|---|------------------------|-------------------|------|-------------------|-----------------------|--------------------------|--------------------------|----------------------------------------|-------------|------------------------|
| **0** | **Karya ini (2026)** | **n8n** | **Wazuh** | **Malware + Phishing** | **VirusTotal + Google Safe Browsing + URLScan.io** | **✔ (tombol Telegram → AR)** | **✔ quarantine-file + sinkhole domain** | **✔ (VT-gated: auto / tombol / sunyi)** | **✔ lokal (Ollama llama3.2:3b)** | **✔ (Ubuntu + Rocky 9)** |
| 1 | Wazuh + Shuffle, serangan app-layer Windows — *jurnal IJESTE, 2025* | Shuffle | Wazuh | Serangan application-layer | – | ✘ (otomatis) | ✔ | ✘ | ✘ | – |
| 2 | Wazuh + Active Response + Telegram, brute force — *jurnal, 2024* | Native Wazuh AR | Wazuh | Brute force | ✘ | **1-arah** (notif) | ✔ (blok IP) | ✘ | ✘ | ✘ |
| 3 | Wazuh + n8n + VirusTotal + Gmail — *blog (Medium)* | n8n | Wazuh | Malware (file) | VirusTotal | **1-arah** (email) | ✘ (enrichment saja) | ✘ | ✘ | – |
| 4 | AI-Powered SOC: Wazuh + n8n + Claude + MCP — *blog (Medium)* | n8n | Wazuh | Umum | – | – | ✔ (sebagian) | ✘ | ✔ **cloud** (Claude API) | – |
| 5 | AI_SOC: Wazuh + TheHive + LLM lokal + RAG — *proyek (GitHub)* | Multi-agent kustom | Wazuh | Umum (triage) | – | ✘ (triage) | – | ✘ | ✔ lokal (Ollama/Foundation-Sec) | – |
| 6 | Template resmi n8n: Wazuh → VirusTotal → Slack | n8n | Wazuh | Malware (file) | VirusTotal | **1-arah** (Slack) | ✘ | ✘ | ✘ | ✘ |
| 7 | Kerangka Human–AI Collaboration in SOC — *arXiv, 2025 (konseptual)* | Konseptual | – | Umum | – | ✔ (konsep approval) | ✔ (konsep) | ✔ (level otonomi) | ✔ (konsep) | – |
| 8 | Wazuh terdistribusi *high-availability* — *Springer CCIS, 2026* | ✘ (fokus deteksi/HA) | Wazuh | Deteksi umum | – | ✘ | – (fokus deteksi) | ✘ | ✘ | ✔ (terdistribusi/HA) |
| 9 | Wazuh + Shuffle SOAR — *IJERT/ACSCON, 2026* | Shuffle | Wazuh | Umum | – | ✘ (otomatis) | ✔ | ✘ | ✘ | – |

> **Catatan kolom "Sumber intel/reputasi":** tanda **–** berarti karya tersebut **tidak memakai feed reputasi/threat-intelligence eksternal** (mis. VirusTotal/GSB/URLScan) — **bukan** berarti tidak mendeteksi. Deteksinya tetap berjalan, umumnya lewat **rule/korelasi bawaan Wazuh** (dan sebagian menambah triase LLM atau model IDS). Kolom ini khusus melacak **pengayaan reputasi eksternal** yang dipakai untuk memutuskan tingkat keyakinan respons — yang menjadi salah satu pembeda karya ini (Wazuh mendeteksi → diverifikasi ke reputasi multi-sumber sebelum merespons). Konsekuensinya, pembanding yang murni rule-based lebih rentan *false-positive*, sedangkan pendekatan berbasis reputasi menambah keterbatasan tersendiri (lihat sub-bagian *Keandalan sumber Threat Intelligence*).

## Tabel 2 — Ringkasan diferensiator karya ini

| Diferensiator | Penjelasan | Pembanding yang belum punya |
|---------------|-----------|------------------------------|
| **Respons berjenjang berbasis keyakinan (VT-gated)** | Otoritas keputusan = konsensus VirusTotal/GSB, bukan noise FIM. Auto-isolasi (≥20) / tombol (1–19) / **sunyi** (bersih) → menekan *alert fatigue* & false positive | 1, 2, 3, 5, 6, 8, 9 |
| **Human-in-the-loop interaktif 2-arah** | Tombol Telegram [Isolasi]/[Blokir]/[Abaikan] langsung memicu Active Response — bukan sekadar notifikasi | 1, 2 (1-arah), 3, 6 (1-arah), 8, 9 |
| **Dua kelas ancaman + dua AR berbeda** | Malware → `quarantine-file`; Phishing → **sinkhole domain** (`/etc/hosts`) | Mayoritas hanya 1 ancaman / 1 AR |
| **AI analisis lokal (kedaulatan data, biaya nol)** | Ollama on-premise → data tidak keluar infrastruktur, tanpa biaya API | 2, 3, 6, 8, 9 (tanpa AI); 4 (AI cloud) |
| **n8n sebagai mesin SOAR (akademik)** | Jurnal sejenis umumnya Shuffle/TheHive (termasuk 2026); n8n masih jarang di ranah akademik | 1, 5, 9 |
| **Multi-agent lintas distribusi + open-source penuh** | Ubuntu + Rocky 9 lapor ke 1 manager; seluruh stack open-source, biaya nol | Jarang disebut eksplisit (kec. 8 yang fokus HA) |

## Catatan untuk sidang
- Kebaruan bersifat **integratif** (kombinasi + desain), bukan fundamental — sampaikan jujur.
- Perkuat klaim "unggul" dengan **metrik kuantitatif** (MTTR, % reduksi false-positive dari VT-gating, throughput/latensi) — belum dimiliki mayoritas pembanding level blog.
- **Posisi 2026:** riset Wazuh terbaru (2026) masih (a) berbasis **Shuffle** (IJERT/ACSCON), atau (b) fokus **infrastruktur/high-availability** (Springer CCIS) — belum ada yang menggabungkan n8n + malware & phishing + HITL 2-arah + AI lokal + respons berjenjang VT-gated. Diferensiator karya ini tetap valid.
- **Pertimbangan keamanan platform (WAJIB diantisipasi):** riset 2026 menyorot penyalahgunaan n8n & kerentanan kritis **CVE-2026-21858 ("Ni8mare", CVSS 10.0)** — RCE/arbitrary file read via webhook. Mitigasi pada sistem ini: webhook n8n **tidak diekspos publik** (poller keluar-saja di balik NAT), n8n versi ter-patch, dan akses dibatasi lokal. Bahas di bab keterbatasan/keamanan sebagai bentuk kesadaran risiko.

## Pengembangan Lanjutan & Penguatan Proyek

### Tabel 3 — Penguatan keandalan (berdasarkan masalah teramati saat pengujian)

| Masalah teramati | Dampak | Penguatan yang diusulkan |
|------------------|--------|--------------------------|
| Registrasi AR `block-domain` **hilang setiap container restart** | Tombol Blokir phishing gagal setelah reboot | Persist registrasi AR di volume ter-mount / custom image / IaC |
| **Event phishing pertama terlewat** pasca-restart agent | Deteksi pertama tidak jalan (harus inject 2×) | Investigasi sinkronisasi logcollector; buffering/queue antara Wazuh ↔ n8n agar event tidak hilang |
| **1 file → 2 notifikasi** (FIM "added" + "modified") | Duplikasi alert | Deduplikasi berbasis hash+waktu di node `Ekstrak Alert` (window ±30 dtk) |

### Arah penguatan (dikelompokkan)

1. **Keandalan (prioritas #1):** perbaiki 3 masalah pada Tabel 3 → sistem dari "jalan di demo" menjadi "andal & production-aware".
2. **Bukti ilmiah (paling menaikkan nilai):** metrik terukur — **MTTR**, **% reduksi false-positive** dari VT-gating (sebelum vs sesudah), *detection rate* atas korpus uji (EICAR/malware nyata + PhishTank/OpenPhish), dan uji beban (N alert serentak).
3. **Kualitas deteksi:** tuning aturan & filter noise, pemetaan **MITRE ATT&CK** per playbook, uji false-negative (mis. hash tak dikenal VT).
4. **Keamanan SOAR itu sendiri:** hardening n8n (CVE-2026-21858 "Ni8mare") — reverse-proxy + TLS, autentikasi, segmentasi jaringan, manajemen secret, versi ter-patch.
5. **Reproducibility:** Infrastructure-as-Code (Ansible/compose lengkap) agar seluruh stack dibangun ulang satu perintah; validasi/uji workflow otomatis.
6. **Human-in-the-loop lanjutan:** **timeout/SLA** (auto-eskalasi bila analis tak merespons dalam X menit) + **audit-trail** keputusan analis.
7. **Keandalan threat intelligence (deteksi hybrid/multi-sinyal):** kurangi ketergantungan pada satu sumber (lihat sub-bagian di bawah).

### Keandalan sumber Threat Intelligence & deteksi multi-sinyal

VirusTotal andal sebagai **sinyal pendukung** (konsensus 70+ engine untuk ancaman yang sudah dikenal), tetapi **bukan ground truth**. Keterbatasan yang perlu diakui:

| Keterbatasan VT | Dampak pada sistem |
|-----------------|--------------------|
| Bukan kebenaran mutlak (agregasi verdict AV yang juga punya FP/FN) | Deteksi 1/70 bisa jadi false-positive |
| **Zero-day / file baru → 0/70 atau "not found"** | ⚠️ **False-negative**: file jahat baru bisa dianggap bersih → disuppress diam-diam |
| Hanya melihat **hash yang dikenal** (ganti 1 byte → hash baru) | Reputasi hash mudah dielakkan |
| *Detection lag* (verdict berubah seiring waktu) | Cache 6 jam bisa menyajikan verdict "bersih" yang basi |
| Rate limit / downtime (free: 4/mnt, 500/hari) | Sudah ditangani via `vt_unverified` (jangan dianggap bersih) |
| Hash/URL dikirim ke pihak ketiga (cloud) | Nuansa klaim kedaulatan data: hanya AI (Ollama) yang lokal; VT/GSB tetap cloud |

**Titik lemah utama:** false-negative pada file tak-dikenal (zero-day). Penguatan yang diusulkan:

1. **Jangan membisukan file eksekutabel tak-dikenal** di folder sensitif → arahkan ke **HITL (tombol)** alih-alih sunyi.
2. **Tambah deteksi perilaku** (aturan Wazuh, sandbox lokal mis. CAPEv2) untuk menangkap zero-day yang lolos reputasi hash.
3. **Sumber intel tambahan** (MalwareBazaar, Hybrid Analysis, MISP) + **re-scan terjadwal** untuk melawan *detection lag*.
4. **Turunkan TTL cache** untuk verdict "bersih" guna mengurangi risiko verdict basi.

Prinsip: perlakukan VT/GSB/URLScan sebagai **corroboration multi-sinyal**, bukan otoritas tunggal — selaras temuan industri bahwa strategi deteksi *ensemble* menurunkan false positive sekaligus menutup celah false negative.

### Arah pengembangan arsitektur (jangka menengah–panjang)

- **Kinerja & skala:** n8n **queue mode** (Redis + worker) + **PostgreSQL** menggantikan SQLite → tahan lonjakan alert.
- **State terbagi:** cache VT/GSB dari `staticData` → **Redis** (survive restart, dibagi lintas-worker).
- **Decoupling:** message queue (Redis/RabbitMQ) antara Wazuh `integratord` ↔ n8n → buffering & replay.
- **High-Availability:** manager/indexer redundan + load balancer + failover (selaras Springer CCIS 2026).
- **Observability:** Prometheus + Grafana untuk metrik SOAR (sumber data bab evaluasi).
- **AI:** Ollama sebagai microservice inferensi terpisah; opsi RAG atas playbook/threat-intel (selaras pendekatan SERC, MDPI 2025).

### Prioritas sepadan-usaha (rekomendasi)

1. Perbaiki **3 bug keandalan** (Tabel 3) — kredibel & berbasis bukti.
2. Tambah **metrik kuantitatif** — membuktikan klaim "unggul".
3. **Hardening keamanan + IaC** — kematangan & reproducibility.

## Referensi / Sumber Pembanding

1. *Automated Defense Against Application-Layer Attacks on Windows Systems Using Wazuh and Shuffle*, International Journal of Education, Science, Technology, and Engineering (IJESTE), Vol. 8 No. 1, hlm. 45–57, Juni 2025 — https://lamintang.org/journal/index.php/ijeste/article/view/842
2. *Implementation of SIEM Wazuh with Active Response and Telegram Notification for Mitigating Brute Force Attacks on the GT-I2TI USAKTI Information System* (jurnal, Maret 2024) — https://www.researchgate.net/publication/378672896
3. Bappe Sarker, *SOC Automation: Wazuh SIEM integration with n8n, VirusTotal, Gmail for Malicious File detection* (Medium) — https://medium.com/@bappesarker2010/soc-automation-forwazuh-siem-integration-with-n8n-virustotal-gmail-03f3ee7ef684
4. Bashar Raed, *A Complete AI-Powered SOC: From Detection to Automated Response with Wazuh, n8n, Claude AI, and MCP* (Medium) — https://medium.com/@basharraed/a-complete-ai-powered-soc-from-detection-to-automated-response-with-wazuh-n8n-claude-ai-and-mcp-78e7fa80d986
5. *AI_SOC — Open-source AI-augmented SOC (LLM + Multi-Agent, Ollama, Wazuh, TheHive, RAG)* (GitHub) — https://github.com/zhadyz/AI_SOC
6. n8n, *Malicious file detection & response: Wazuh to VirusTotal with Slack alerts* (template resmi) — https://n8n.io/workflows/5997-malicious-file-detection-and-response-wazuh-to-virustotal-with-slack-alerts/
7. *A Unified Framework for Human–AI Collaboration in Security Operations Centers with Trusted Autonomy* (arXiv, 2025) — https://arxiv.org/html/2505.23397v2
8. *Large Language Models for Security Operations Centers: A Comprehensive Survey* (arXiv, 2025) — https://arxiv.org/abs/2509.10858
9. Wazuh, *Wazuh and Shuffle Announce Technology Partnership* (Sept 2025) — https://wazuh.com/blog/wazuh-and-shuffle-announce-technology-partnership-to-deliver-integrated-security-automation/
10. *SOC Alert Fatigue: How Threat Intelligence Reduces False Positives Without Hiding Real Attacks* (isMalicious) — https://ismalicious.com/posts/soc-alert-fatigue-threat-intelligence-false-positives
11. D. P. Alves, J. Loureiro, T. Pedrosa, *Wazuh for Incident Detection: Design and Implementation*, Advanced Research in Technologies, Information, Innovation and Sustainability (ARTIIS 2025), Communications in Computer and Information Science, Vol. 2791, Springer, 2026 — https://doi.org/10.1007/978-3-032-16848-1_35
12. *Enhancing Wazuh SIEM Capabilities through SOAR* (Wazuh + Shuffle), IJERT — Proc. ACSCON, Vol. 14 No. 06, 2026 — https://www.ijert.org/research/IJERTCONV14IS060090.pdf
13. Cisco Talos, *The n8n n8mare: How threat actors are misusing AI workflow automation* (2026) + CVE-2026-21858 "Ni8mare" (CVSS 10.0) — https://blog.talosintelligence.com/the-n8n-n8mare/
14. *Incident Response Planning Using a Lightweight Large Language Model with Reduced Hallucination* (arXiv, 2025) — https://arxiv.org/pdf/2508.05188
