# Sistem Ini vs Antivirus pada Umumnya

> Jawaban untuk pertanyaan dospem: **"Apa bedanya ini dengan antivirus pada umumnya? Apa yang membuat project ini beda?"**
> Pertanyaan ini hampir pasti muncul lagi di sidang — jawabannya perlu dipahami, bukan dihafal.

## Jawaban singkat (versi elevator pitch)

> Antivirus menjawab **"apakah file ini berbahaya?"** di satu mesin, dengan pencocokan signature lokal, lalu bertindak atas keputusannya sendiri. Project ini menjawab **"apa yang terjadi di 100 workstation, apa yang harus dilakukan, siapa yang memutuskan, dan bisakah dibuktikan?"** — ini sistem orkestrasi dan respons, bukan produk deteksi.

## Perbedaan konkret

| Dimensi | Antivirus biasa | Project ini (SOAR) |
|---|---|---|
| **Unit perlindungan** | Satu endpoint, berdiri sendiri | Fleet (100 workstation) + 1 otak pusat (n8n) |
| **Deteksi** | Engine signature/heuristik lokal yang dibundel di produk | Agen tipis hanya mendeteksi *event* (FIM file-drop, USB, log URL) lalu mengirim **hash + metadata sebagai JSON** — file itu sendiri tidak pernah keluar dari mesin (file 1 GB biayanya sama dengan 1 KB) |
| **Sumber verdict** | Engine vendor (black-box) | **Ensemble multi-sumber**: VirusTotal + MalwareBazaar, plus AI (Gemini) dengan konteks playbook lokal via RAG — verdict selalu *dikoreborasi*, tidak pernah sumber tunggal |
| **File unknown (zero-day)** | Umumnya diam-diam diizinkan atau flag generik | Jalur ketiga eksplisit: file eksekutabel unknown → **tidak dianggap bersih**, masuk review manusia (desain anti-false-negative, ROADMAP B#1/G2) |
| **Keputusan respons** | Otomatis, opak | **Human-in-the-loop**: alert Telegram dengan tombol Isolasi/Abaikan, admin memutuskan, agen mengeksekusi karantina / block-domain |
| **Akuntabilitas** | Tidak ada — "AV yang melakukannya" | Explainable (`🧠 Alasan keputusan` di setiap notifikasi), audit-trail (`oleh <analis> pada <waktu WITA>`), **SLA 15 menit auto-eskalasi** jika analis tidak merespons |
| **Kepercayaan pada diri sendiri** | Gagal diam-diam (silent failure) | **Sadar-degradasi**: menandai `⚠️ Deteksi TERDEGRADASI` saat VT rate-limit; health-monitor meng-alert hanya saat status berubah |
| **Cakupan** | Malware saja | Malware **+ phishing** (reaktif via log URL + *proaktif* URLhaus→GSB blokir domain sebelum diklik) + vektor USB |
| **Footprint per endpoint** | Produk penuh (ratusan MB) | Agen Rust: **binary 5,3 MB, RSS 5,2 MB** (vs Wazuh agent ~50 MB) — semua logika berat ada di server |

## Versi satu paragraf (untuk dospem/laporan)

Antivirus adalah sebuah **produk**: engine deteksi, verdict, dan respons semuanya dilebur dalam satu binary tertutup di tiap PC, dan pengguna tidak pernah tahu alasannya serta tidak diberi ruang memutuskan. Project ini sengaja **memisahkan tiga lapisan itu**: agen ringan (Rust) hanya *merasakan* dan melaporkan; orkestrator pusat (n8n) yang *berpikir* — mengkoreborasi VirusTotal, MalwareBazaar, dan AI dengan playbook lokal; dan *keputusan* untuk merespons tetap di tangan analis manusia lewat Telegram, dengan eskalasi berbasis SLA agar human-in-the-loop tidak menjadi bottleneck. Jadi kontribusinya bukan "deteksi lebih baik dari antivirus", melainkan **orkestrasi respons terukur, akuntabel, dan fleet-wide** di atas komponen open-source: MTTR ~1,7 detik untuk malware, throughput 34 alert/detik, supresi false-positive 100%, dan nol silent-failure.

## Poin jujur yang perlu disebutkan (justru memperkuat)

Keduanya **komplementer, bukan kompetitor**. Sistem ini mengonsumsi threat intel reputasi (hash/URL), bukan membangkitkan engine pemindai file sendiri. Di produksi, antivirus justru bisa hidup berdampingan sebagai **satu sinyal tambahan** di antara banyak sinyal yang dinilai orkestrator. Mengatakan ini lebih dulu terdengar lebih kuat daripada ditanya balik oleh penguji.

## Angka pendukung (dari benchmark repo)

- MTTR malware auto-isolate: **1,68 dtk** (N=15, cache hangat) — `docs/EVALUASI-METRIK.md`
- Throughput load test: **34,11 alert/detik** — `docs/bench-load.json`
- False-negative rate: **0%** (N=15) — `docs/bench-fn-rate.json`
- Agen Rust: **5,3 MB binary / 5,2 MB RSS** vs Wazuh agent ~50 MB — `docs/bench-rust-*.json`
- Reduksi false-positive: **100%** (N=8) — `docs/EVALUASI-METRIK.md`

## Referensi silang

- `ROADMAP.md` — prinsip arah tesis: confidence-based, transparan, sadar-degradasi
- `docs/ARCHITECTURE.md` — diagram pemisahan lapisan deteksi/orkestrasi/respons
- `docs/N8N-VS-SHUFFLE.md` — contoh pola argumentasi serupa (justifikasi pemilihan tool)
- `docs/PERBANDINGAN-PENELITIAN.md` — posisi terhadap penelitian sejenis
