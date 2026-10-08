# Playbook NO-INDICATOR (RAG source)

Status: tidak ada satu pun indikator malware dari threat intel
(VirusTotal 0 deteksi / hash belum dikenal 404, MalwareBazaar & OTX kosong) dan
tidak ada rule deteksi yang menaikkan severity.

Tindakan:
1. Ini BUKAN vonis malware. Jangan tulis "terinfeksi", "malware", atau
   rekomendasikan isolasi/karantina host.
2. Media/dokumen jinak (mp4, mp3, jpg, png, pdf, docx, zip, ...) -> cukup
   catat sebagai informasional; tidak perlu tindakan.
3. Tipe lain (mis. arsip/format tak dikenal) -> sarankan verifikasi manual bila
   pengguna ragu (cek asal, hash ulang, unggah ke VirusTotal bila perlu).
4. Eksekutabel dengan hash belum dikenal ditangani terpisah oleh playbook
   UNVERIFIED / jalur "PERLU REVIEW" (bukan no-indicator).

Grounding untuk LLM: nyatakan file tidak menunjukkan indikasi berbahaya dan
jangan menyarankan isolasi.
