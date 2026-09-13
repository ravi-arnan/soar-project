# Pemetaan MITRE ATT&CK — SOAR Open-Source

Pemetaan **teknik MITRE ATT&CK** ke playbook/workflow n8n dalam sistem SOAR ini.
Bertujuan untuk membuktikan cakupan deteksi & respons secara terstruktur (bukan klaim informal).

**Referensi:** [attack.mitre.org](https://attack.mitre.org/) — Enterprise Matrix v15.1 (2026-09-02)

---

## 1. Ringkasan Cakupan

| Playbook | Fase ATT&CK | Teknik yang Dipetakan | Status |
|----------|-------------|----------------------|--------|
| **Deteksi Malware** (FIM + VT) | TA0002 Execution, TA0005 Defense Evasion, TA0001 Initial Access | T1204.002, T1059, T1027, T1036 | ✅ Aktif |
| **Deteksi Phishing** (URL + GSB/URLScan) | TA0001 Initial Access | T1566.002, T1189 | ✅ Aktif |
| **Proaktif Phishing** (URLhaus feed) | TA0001 Initial Access (preventif) | T1566.002 | ✅ Aktif |
| **Active Response — Quarantine** | TA0005 Defense Evasion → TA0040 Impact | T1070.004 (remedi), AR manual | ✅ Aktif |
| **Active Response — Block Domain** | TA0001 Initial Access → TA0040 Impact | T1189 (remedi), AR manual | ✅ Aktif |
| **Health Monitor** | TA0040 Impact (availability) | T1499 (availability monitoring) | ✅ Aktif |

---

## 2. Pemetaan Detail per Playbook

### 2.1 Deteksi Malware (`deteksi-malware.json`)

| Komponen | Teknik MITRE | Keterangan |
|----------|-------------|------------|
| **FIM (File Integrity Monitoring)** | **T1005** — Data from Local System | Wazuh syscheck memantau file baru/berubah di direktori kritis |
| | **T1204.002** — User Execution: Malicious File | FIM mendeteksi file jatuh ke disk (Downloads/) → pemicu pipeline |
| | **T1059** — Command and Scripting Interpreter | Ekstensi .sh/.ps1/.bat/.py terdeteksi sebagai risky → jalur review |
| **VT Hash Lookup** | **T1027** — Obfuscated Files or Information | Hash VT mencocokkan pola malware yang dikenal (meski diobfuskasi) |
| | **T1036** — Masquerading | File tanpa ekstensi tapi executable (G2 magic-byte) tertangkap |
| **Auto-Isolate (CRITICAL)** | **T1484** — Domain Policy Modification | AR `!quarantine-file` mengkarantina file → mencegah eksekusi lebih lanjut |
| **HITL Review (HIGH/MEDIUM)** | — | Tombol Isolasi/Abaikan di Telegram → keputusan analis tercatat (F: audit-trail) |
| **G2: Exec-bit Detection** | **T1036.005** — Masquerading: Match Legitimate Name or Location | File tanpa ekstensi + execute bit →dideteksi sebagai risky |

**Jalur eksekusi:**
```
FIM alert (Wazuh) → Filter noise → Ekstrak hash → Cek cache VT
  ├─ [cache hit] → Rangkum Hasil → Cek Ancaman → AR/Notif
  └─ [cache miss] → Scan VirusTotal API → Rangkum Hasil → ...
```

### 2.2 Deteksi Phishing (`deteksi-phishing.json`)

| Komponen | Teknik MITRE | Keterangan |
|----------|-------------|------------|
| **URL Detection (log akses)** | **T1566.002** — Phishing: Spearphishing Link | Wazuh logcollector mendeteksi URL berbahaya di log akses |
| **GSB Lookup** | **T1189** — Drive-by Compromise | Google Safe Browsing verifikasi URL sebagai phishing/malware |
| **URLScan.io** | **T1189** — Drive-by Compromise | Screenshot + verdict untuk URL tidak dikenal GSB |
| **Auto-Block Domain** | **T1484** — Domain Policy Modification | AR `!block-domain` → sinkhole domain ke 0.0.0.0 di /etc/hosts |
| **HITL (suspicious/unverified)** | — | Tombol Blokir/Abaikan di Telegram → keputusan analis |

**Jalur eksekusi:**
```
URL alert (Wazuh) → Filter URL → Ekstrak → Cek cache URL
  ├─ [cache hit] → Rangkum → Cek Ancaman → AR/Notif
  └─ [cache miss] → GSB Lookup ──┐
                                  ├─ Rangkum → ...
               URLScan Submit ────┘
```

### 2.3 Proaktif Phishing (`proaktif-phishing.json`)

| Komponen | Teknik MITRE | Keterangan |
|----------|-------------|------------|
| **URLhaus Feed** | **T1566.002** — Phishing: Spearphishing Link | Feed publik URLhaus CSV → deteksi URL belum sempat diklik |
| **GSB Verification** | **T1189** — Drive-by Compromise | Verifikasi URL terhadap GSB sebelum blokir |
| **Auto-Block** | **T1484** — Domain Policy Modification | `!block-domain` ke agent via Wazuh API |

---

## 3. Matrix Coverage (visual)

```
                        MITRE ATT&CK Enterprise — Coverage Map
                        
INITIAL ACCESS          EXECUTION               DEFENSE EVASION        IMPACT
─────────────           ─────────               ───────────────        ──────
T1566.002 ●●●           T1204.002 ●●            T1027 ●                T1499 ●
(Phishing Link)         (Malicious File)        (Obfuscation)          (DoS - health)
T1189 ●●                T1059 ●                 T1036 ●●               T1484 ●●●
(Drive-by)              (Scripting)             (Masquerading)          (Domain Policy)
                         T1005 ●                 T1070.004 ●
                         (Local Data)            (File Deletion→remed)
```

**Legend:** ● = 1 playbook, ●● = 2 playbook, ●●● = 3+ playbook

---

## 4. Gap Coverage (belum tercakup)

Teknik ATT&CK yang **belum** ditangani oleh sistem ini (bukan kelemahan desain — batasan scope TA):

| Teknik | Fase | Alasan belum dicakup |
|--------|------|---------------------|
| T1566.001 (Spearphishing Attachment) | Initial Access | Belum ada deteksi email proxy/log mail (G3) |
| T1059.001 (PowerShell) | Execution | Hanya FIM, belum ada monitoring proses runtime (G4: auditd) |
| T1053 (Scheduled Task) | Persistence | Tidak ada monitoring scheduled task |
| T1071 (Application Layer Protocol) | Command & Control | Tidak ada network traffic analysis |
| T1486 (Data Encrypted for Impact) | Impact | Tidak ada behavioral detection enkripsi massal (ransomware) |
| T1490 (Inhibit System Recovery) | Impact | Tidak ada backup monitoring |

**Catatan:** Gap di atas masuk kategori **G4 (Deteksi perilaku ringan/auditd)** dalam roadmap, yang merupakan perluasan cakupan pasca-TA.

---

## 5. Konsistensi dengan SPR/Sicherheitstechnik

| Aspek | SOAR ini | Pembanding ( Shuffle / Demisto ) |
|-------|----------|----------------------------------|
| **Fase tercakup** | IA, Execution, Defense Evasion, Impact | Sama (tergantung playbook) |
| **Jumlah teknik** | 10 teknik unik | Tergantung integrasi |
| **Automated vs Manual** | Auto-isolate (≥20 malicious) + HITL | Auto/manual tergantung playbook |
| **Explainability** | ✅ Alasan keputusan + self-aware | ❌ Black-box (kebanyakan) |
| **Audit trail** | ✅ Callback handler catat keputusan analis | Tergantung config |

---

## 6. Cara Memperluas Coverage

1. **G3 — Phishing Email:** Tambah Wazuh rule untuk log mail/proxy → extract attachment hash → pipeline malware. Cakup: T1566.001, T1204.001.
2. **G4 — Deteksi Perilaku (auditd):** Rule auditd untuk execve mencurigakan → enrich VT → HITL. Cakup: T1059, T1053, T1204.002.
3. **Multi-sinyal (B):** Tambah MalwareBazaar/MISP sebagai sinyal kedua. Perkuat keyakinan tanpa menambah teknik baru.

---

*Pemetaan ini bersifat **snapshot** — perlu diupdate setiap kali playbook berubah atau teknik ATT&CK baru ditambahkan.*
*Referensi lengkap: `docs/PERBANDINGAN-PENELITIAN.pdf`*
