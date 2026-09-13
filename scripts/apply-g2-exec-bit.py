#!/usr/bin/env python3
"""G2: tambah deteksi file eksekutabel tanpa ekstensi via perm_after (execute bit).

Edit pada n8n-workflows/deteksi-malware.json:
1. Node 'Ekstrak Alert': ekstrak perm_after/mode dari body.syscheck, hitung no_ext & is_exec.
2. Node 'Rangkum Hasil': perluas review_unknown — file TANPA ekstensi tapi executable
   (perm_after mengandung 'x') dan tak dikenal VT -> HITL, bukan sunyi.
"""
import json
import sys

PATH = "n8n-workflows/deteksi-malware.json"
with open(PATH) as f:
    raw = json.load(f)
# File repo berupa array berisi SATU workflow (format n8n export), bukan objek.
wf = raw[0] if isinstance(raw, list) else raw
NODES = wf["nodes"] if isinstance(wf, dict) and "nodes" in wf else raw

def get_node(name):
    for n in NODES:
        if n.get("name") == name:
            return n
    raise SystemExit(f"Node {name} tidak ditemukan")

# ---------- 1. Ekstrak Alert ----------
node = get_node("Ekstrak Alert")
js = node["parameters"]["jsCode"]

old_ret = """return [{
  json: {
    rule_id:          body?.rule?.id || body?.rule_id || 'unknown',"""

new_perm = """// ===== G2: deteksi file eksekutabel tanpa ekstensi (via perm_after) =====
// Alert FIM Wazuh (check_all) menyertakan perm_after, mis. 'rwxr-xr-x'. File
// tanpa ekstensi yang executable (ELF/MZ/script) tak tertangkap RISKY_EXT di
// Rangkum Hasil -> di sini diekstrak & ditandai agar tak disenyapkan saat VT unknown.
const perm_after = body?.syscheck?.perm_after
                || body?.syscheck?.perm
                || body?.data?.perm_after
                || body?.perm_after
                || '';
const no_ext = (filename || '').indexOf('.') === -1;   // tanpa titik = tanpa ekstensi
const is_exec = no_ext && /x/.test(perm_after);        // ada execute bit utk user/group/other
const is_script_shebang = no_ext && /^#!/.test(String(body?.data?.file_head || '').slice(0,2)); // cadangan bila head tersedia

return [{
  json: {
    rule_id:          body?.rule?.id || body?.rule_id || 'unknown',"""

assert old_ret in js, "pola return Ekstrak Alert tidak ditemukan"
js = js.replace(old_ret, new_perm)

old_fields = """    hash:             hash,
    hash_available:   hash !== null && hash !== undefined && hash !== '',"""
new_fields = """    hash:             hash,
    hash_available:   hash !== null && hash !== undefined && hash !== '',
    perm_after:       perm_after,
    no_ext:           no_ext,
    is_exec:          is_exec,
    is_script_shebang: is_script_shebang,"""
assert old_fields in js, "pola fields Ekstrak Alert tidak ditemukan"
js = js.replace(old_fields, new_fields)
node["parameters"]["jsCode"] = js
print("Ekstrak Alert: OK")

# ---------- 2. Rangkum Hasil ----------
node = get_node("Rangkum Hasil")
js = node["parameters"]["jsCode"]

old_risky = """const RISKY_EXT = ['exe','dll','scr','com','bat','cmd','ps1','vbs','vbe','js','jse','jar','msi','apk','sh','bash','bin','run','elf','deb','rpm','py','pl','php','wsf','lnk','iso','img','dmg','app','desktop','hta','cpl'];
const _ext = (alertData.filename || '').split('.').pop().toLowerCase();
const risky_ext = RISKY_EXT.includes(_ext);
const review_unknown = !vt_known && !vt_unverified && risky_ext && (malicious < 1);"""

new_risky = """const RISKY_EXT = ['exe','dll','scr','com','bat','cmd','ps1','vbs','vbe','js','jse','jar','msi','apk','sh','bash','bin','run','elf','deb','rpm','py','pl','php','wsf','lnk','iso','img','dmg','app','desktop','hta','cpl'];
const _ext = (alertData.filename || '').split('.').pop().toLowerCase();
const risky_ext = RISKY_EXT.includes(_ext);
// G2: file TANPA ekstensi tapi executable (execute bit di perm_after) dianggap
// berisiko setara ekstensi berbahaya -> jangan disenyapkan saat VT tidak mengenal.
const risky_exec = !risky_ext && (alertData.is_exec === true);
const review_unknown = !vt_known && !vt_unverified && (risky_ext || risky_exec) && (malicious < 1);"""

assert old_risky in js, "pola RISKY_EXT Rangkum Hasil tidak ditemukan"
js = js.replace(old_risky, new_risky)

# update decision_reason utk kasus risky_exec (tanpa ekstensi)
old_reason = """else if (review_unknown) decision_reason = 'File eksekutabel (.' + _ext + ') TIDAK dikenal VirusTotal -> potensi zero-day, minta review analis';"""
new_reason = """else if (review_unknown) decision_reason = risky_exec
  ? 'File eksekutabel TANPA ekstensi (execute bit) TIDAK dikenal VirusTotal -> potensi zero-day, minta review analis'
  : 'File eksekutabel (.' + _ext + ') TIDAK dikenal VirusTotal -> potensi zero-day, minta review analis';"""
assert old_reason in js, "pola decision_reason tidak ditemukan"
js = js.replace(old_reason, new_reason)

# tambahkan risky_exec ke output json
old_out = """  vt_known, vt_status, vt_unverified, review_unknown, risky_ext,"""
new_out = """  vt_known, vt_status, vt_unverified, review_unknown, risky_ext, risky_exec,"""
assert old_out in js, "pola output Rangkum Hasil tidak ditemukan"
js = js.replace(old_out, new_out)
node["parameters"]["jsCode"] = js
print("Rangkum Hasil: OK")

with open(PATH, "w") as f:
    json.dump(raw, f, ensure_ascii=False, separators=(",", ":"))
print("deteksi-malware.json ditulis ulang (single-line).")
