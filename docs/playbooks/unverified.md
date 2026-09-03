# Playbook UNVERIFIED (RAG source)

Status: VirusTotal rate-limit / error, atau hash unknown untuk file non-eksekutabel.
Tindakan:
1. Jangan anggap aman — perlakukan sebagai perlu verifikasi.
2. Verifikasi manual: cek file di sandbox terisolasi, cek magic-byte, cek exec-bit (G2), cek sumber URL.
3. Jika file eksekutabel tanpa ekstensi + exec-bit -> jalur review (tombol HITL), bukan silent.
4. SLA: jika analis tidak respons 15 menit, auto-notif ulang + pertahankan status unverified, jangan auto-block kecuali CRITICAL.

Grounding untuk Gemini: selalu sarankan verifikasi manual, jangan klaim bersih.
