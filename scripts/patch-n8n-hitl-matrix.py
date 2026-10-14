#!/usr/bin/env python3
"""Formalisasi matriks confidence -> otonomi + jalur HITL (milestone M3).

Latar (audit live 2026-10-14): kebijakan respons tersebar di beberapa node JS,
notifikasi malware **tidak lagi punya tombol HITL** (workflow `Telegram Callback
Handler` masih menunggu callback `iso:`/`ign:` yang tak pernah dikirim), tidak
ada batas waktu/eskalasi, dan keputusan analis tidak tersimpan (hanya mengedit
teks pesan Telegram).

Patch ini (marker `patch:hitl-matrix:v1`) melakukan empat hal:

1. **Satu sumber kebijakan** — node baru `Tentukan Otonomi` menetapkan tingkat
   keyakinan (`confidence`) dan tingkat otonomi (`autonomy`) dari bukti yang
   sudah dikumpulkan node hulu, lalu **menentukan** `should_active_response`
   (sebelumnya logika terpisah). Dipasang untuk jalur file maupun jalur rantai
   proses.
   Matriks: CRITICAL/HIGH -> `auto` (AR otomatis); MEDIUM berindikator lemah /
   VT tak terverifikasi / eksekutabel belum dikenal -> `hitl` (tunggu analis);
   rantai proses -> `hitl` (AR selalu mati); file konfigurasi sistem ->
   `notify-hold`; tanpa indikator -> `observe`.
2. **Registry keputusan** — node baru `Catat Keputusan Tertunda` mendaftarkan
   deteksi (per hash, + `did` 16 karakter) ke service `alert-log` (:8091)
   SEBELUM notifikasi dikirim, supaya tombol membawa id pendek dan aksi analis
   tepat sasaran + tercatat (audit trail).
3. **Tombol HITL di notifikasi malware** — `Send Telegram Alert` diberi
   inline keyboard dinamis sesuai tingkat otonomi (`Karantina file` /
   `Sudah ditinjau` + `Tandai FP`) -> menutup HITL Telegram yang mati.
4. **Batas waktu & eskalasi** — workflow baru `SLA Eskalasi HITL` (Schedule
   tiap 1 menit) membaca keputusan HITL yang lewat tenggat di alert-log,
   mengirim eskalasi Telegram, dan menandainya agar tidak spam.

Juga memperbaiki jalur callback: `Parse Keputusan` mengenali aksi baru
(`q:`/`f:`/`a:`), `Catat Keputusan` mengklaim keputusan + mengambil target aksi
dari registry (bukan parsing teks pesan yang di-escape Markdown), dan jalur
callback dibuat **linear** (tanpa cabang FALSE IF — lihat gotcha n8n 2.40:
output FALSE yang dibuat via API tidak mengeksekusi downstream).

Cara pakai (dari nixbox, n8n via Tailscale):
  python3 scripts/patch-n8n-hitl-matrix.py \
    --n8n-url http://100.73.91.17:5678 --api-key-file /tmp/n8n_api_key.txt
  # tambahkan --dry-run untuk pratinjau, --skip-sla untuk tanpa workflow SLA

Idempoten: node yang sudah bermarker tidak dipatch ulang. Backup ke backups/.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "..", "backups")
WORKFLOW_ID_DEFAULT = "1MVcpL7ZKfBhR2tc"  # Deteksi Malware
CALLBACK_ID_DEFAULT = "pVgvxowV7CCB3ZfV"  # Telegram Callback Handler
SLA_NAME = "SLA Eskalasi HITL"
MARKER = "patch:hitl-matrix:v1"
ALERT_LOG_URL = "http://host.docker.internal:8091"
FLEET_URL = "http://host.docker.internal:8080"

# ---------------------------------------------------------------------------
# JS: kebijakan confidence -> otonomi (satu-satunya tempat kebijakan)
# ---------------------------------------------------------------------------
POLICY_JS = """// patch:hitl-matrix:v1
// MATRIKS CONFIDENCE -> OTONOMI (milestone M3). Satu-satunya tempat kebijakan
// respons ditetapkan: node hulu hanya menyediakan BUKTI (severity dari threat
// intel, penanda file sistem, jenis rantai proses), di sini bukti dipetakan ke
// tingkat keyakinan + tingkat otonomi tindakan.
//   keyakinan tinggi  -> otonom      : Active Response otomatis + notifikasi
//   keyakinan sedang  -> HITL        : notifikasi bertombol, tunggu keputusan
//   file konfigurasi  -> tahan       : dilaporkan (maks MEDIUM) tanpa AR
//   tanpa indikator   -> pantau      : dicatat; media jinak tak diberitakan
const i = $input.first().json;
const severity = String(i.severity || 'INFO').toUpperCase();
const isChain = !!i.chain;
const isSystemFile = !!i.is_system_file;
const hasIndicator = !!i.has_indicator;
const agentId = String(i.agent_id || '000');
// Target aksi HITL harus konkret: jalur file pakai path file, jalur rantai
// proses pakai image proses (LOLBin tidak punya hash file).
const filepath = i.filepath
  || (i.chain && (i.chain.image || i.chain.parentImage)) || '';
// Kunci keputusan (audit + tombol): hash sha256 untuk jalur file; kunci
// sintetis untuk rantai proses yang tidak membawa hash.
const hashKey = (i.hash && String(i.hash).length)
  ? String(i.hash).toLowerCase()
  : ('chain:' + String(i.rule_id || 'rule') + ':' + agentId);

let tier, confidence, autonomy, needsDecision, actionKind, deadlineSecs, reason;
if (isSystemFile) {
  tier = 'manual-config'; confidence = 'none'; autonomy = 'notify-hold';
  needsDecision = false; actionKind = 'fp_only'; deadlineSecs = 0;
  reason = 'perubahan file konfigurasi sistem: bukan vonis malware, AR dimatikan';
} else if (isChain) {
  tier = severity === 'CRITICAL' ? 'hitl-chain-critical' : 'hitl-chain';
  confidence = 'medium'; autonomy = 'hitl';
  needsDecision = true; actionKind = 'acknowledge'; deadlineSecs = 900;
  reason = 'rantai proses mencurigakan: binary bisa sah -> keputusan analis';
} else if (severity === 'CRITICAL' || severity === 'HIGH') {
  tier = severity === 'CRITICAL' ? 'auto-critical' : 'auto-high';
  confidence = 'high'; autonomy = 'auto';
  needsDecision = false; actionKind = 'fp_only'; deadlineSecs = 0;
  reason = 'indikator threat intel kuat -> karantina otomatis + notifikasi';
} else if (severity === 'MEDIUM' && (hasIndicator || i.unknown_exec_review || i.vt_unverified)) {
  tier = 'hitl-review'; confidence = 'medium'; autonomy = 'hitl';
  needsDecision = true; actionKind = 'quarantine'; deadlineSecs = 900;
  reason = 'indikator lemah / belum terverifikasi -> keputusan analis';
} else {
  tier = 'observe'; confidence = 'low'; autonomy = 'observe';
  needsDecision = false; actionKind = 'fp_only'; deadlineSecs = 0;
  reason = 'tanpa indikator malware: dicatat untuk observasi';
}

// Otonomi MENENTUKAN Active Response (bukan sebaliknya): hanya tier otomatis
// yang mengeksekusi AR tanpa persetujuan analis. File konfigurasi sistem
// selalu dikecualikan.
return [{ json: { ...i,
  policy_tier: tier,
  confidence: confidence,
  autonomy: autonomy,
  needs_decision: needsDecision,
  action_kind: actionKind,
  hitl_deadline_secs: deadlineSecs,
  decision_key: hashKey,
  did: hashKey.slice(0, 16),
  policy_reason: reason,
  filepath: filepath,
  agent_id: agentId,
  should_active_response: autonomy === 'auto',
} }];
// patch:hitl-matrix:v1"""

# ---------------------------------------------------------------------------
# JS: daftarkan keputusan tertunda ke alert-log (sebelum notifikasi)
# ---------------------------------------------------------------------------
REGISTER_JS = """// patch:hitl-matrix:v1
// Daftarkan deteksi ke registry keputusan (alert-log :8091) SEBELUM notifikasi
// dikirim, supaya: (a) tombol Telegram cukup membawa id pendek (did <=64 byte),
// (b) target aksi diambil dari registry (bukan parse teks pesan), (c) keputusan
// analis tercatat di audit trail. Fail-open: registry mati != deteksi mati.
// Field kebijakan dibaca dari node 'Tentukan Otonomi' — Build Payload di hilir
// tidak lagi membawa hash/agent_id, jadi membaca $input saja akan membuat
// pendaftaran dilewati (bug yang ketangkap E2E 2026-10-14).
const src = $('Tentukan Otonomi').first().json;
const bp = $input.first().json;
const rec = {
  hash: src.decision_key,
  agent_id: src.agent_id,
  agent_name: src.agent_name || '',
  filepath: src.filepath || '',
  filename: src.filename || '',
  severity: src.severity || '',
  tier: src.policy_tier || '',
  action_kind: src.action_kind || '',
  hitl: !!src.needs_decision,
  deadline_secs: src.hitl_deadline_secs || 0,
  title: bp.alert_title || src.alert_title || '',
  workflow: 'Deteksi Malware',
};
let regist = { attempted: false, result: 'skipped-tanpa-target' };
if (rec.hash && rec.filepath) {
  try {
    regist = { attempted: true, result: await this.helpers.httpRequest({
      method: 'POST',
      url: '%s/decision/pending',
      headers: { 'Content-Type': 'application/json' },
      body: rec, timeout: 5000 }) };
  } catch (e) {
    regist = { attempted: true, result: 'failed',
      error: String((e && e.message) || e).slice(0, 200) };
  }
}
return [{ json: { ...bp, decision_registry: regist } }];
// patch:hitl-matrix:v1""" % ALERT_LOG_URL

# ---------------------------------------------------------------------------
# JS: klaim keputusan di callback handler (audit + target aksi)
# ---------------------------------------------------------------------------
CLAIM_JS = """// patch:hitl-matrix:v1
// Analis menekan tombol: klaim keputusan di registry (audit trail + sumber
// target aksi yang benar). Path dari registry lebih dipercaya daripada teks
// pesan Telegram (yang di-escape Markdown dan bisa terpotong).
const p = $('Parse Keputusan').first().json;
let reg = { ok: false, found: false };
if (p.did) {
  try {
    reg = await this.helpers.httpRequest({
      method: 'POST',
      url: '%s/decision/resolve',
      headers: { 'Content-Type': 'application/json' },
      body: { hash: p.did, action: p.registryAction, by: p.analyst },
      timeout: 5000 });
  } catch (e) {
    reg = { ok: false, found: false, error: String((e && e.message) || e).slice(0, 200) };
  }
}
const filePath = (reg && reg.filepath) || p.filePath || '';
const agentId = (reg && reg.agent_id) || p.agentId || '000';
// Keputusan analis juga dicatat ke fleet-monitor -> tampil di dashboard
// (audit trail yang bisa dilihat, bukan cuma edit teks pesan Telegram).
let logged = false;
try {
  await this.helpers.httpRequest({
    method: 'POST',
    url: '%s/webhook-log',
    headers: { 'Content-Type': 'application/json' },
    body: {
      agent_id: agentId, agent: (reg && reg.agent_name) || '',
      path: filePath, hash: (reg && reg.hash) || '',
      severity: (reg && reg.severity) || 'INFO',
      status: p.logStatus, by: p.analyst, action: p.registryAction,
      ai: 'keputusan analis via Telegram (' + p.analyst + ')',
    },
    timeout: 5000,
  });
  logged = true;
} catch (e) { /* fail-open */ }
return [{ json: { ...p, filePath: filePath, agentId: agentId,
  registry: reg, decision_action: p.registryAction, fleet_logged: logged } }];
// patch:hitl-matrix:v1""" % (ALERT_LOG_URL, FLEET_URL)

# ---------------------------------------------------------------------------
# JS: Parse Keputusan (callback_data baru + fallback legacy)
# ---------------------------------------------------------------------------
PARSE_JS = r"""// patch:hitl-matrix:v1
// Aksi tombol (callback_data):
//   q:<agent_id>:<did>  -> karantina file (HITL disetujui analis)
//   f:<agent_id>:<did>  -> tandai false positive (audit saja, tanpa AR)
//   a:<agent_id>:<did>  -> tandai sudah ditinjau (tanpa AR; rantai proses)
//   iso:/ign:           -> legacy malware (kompatibilitas tombol lama)
//   pblk:/pign:         -> phishing (block-domain / abaikan)
const body = $input.first().json.body || $input.first().json;
const cq = body.callback_query || {};
const data = String(cq.data || '');
const parts = data.split(':');
const action = parts[0] || '';
const did = parts[2] || '';
const text = (cq.message && cq.message.text) || '';

// Fallback legacy: tombol lama tidak membawa did, jadi target dibaca dari teks
// pesan. Backslash escape Markdown dibersihkan supaya path utuh.
const unesc = (s) => String(s || '')
  .replace(/\\([_*\[\]()~`>#+\-=|{}.!])/g, '$1')
  .replace(/^[*`\s]+|[*`\s]+$/g, '')
  .trim();
const pathMatch = text.match(/Path:\s*(.+)/);
const fileMatch = text.match(/File:\s*(.+)/);
const hashMatch = text.match(/([a-f0-9]{64})/i);
const urlMatch = text.match(/URL:\*?\s*(\S+)/i);
const urlClean = urlMatch ? unesc(urlMatch[1]) : '';

const isPhishing = (action === 'pblk' || action === 'pign');
const doBlock = (action === 'q' || action === 'iso' || action === 'pblk');
const registryAction = (action === 'q' || action === 'iso') ? 'quarantine'
  : (doBlock ? 'acknowledged' : (action === 'a' ? 'acknowledged' : 'false_positive'));
const logStatus = doBlock ? 'analyst-quarantine'
  : (action === 'a' ? 'analyst-ack' : 'analyst-fp');

const decidedAt = new Date().toLocaleString('sv-SE', { timeZone: 'Asia/Makassar' });

return [{ json: {
  decidedAt,
  action, doBlock, isPhishing, registryAction, logStatus, did,
  agentId: parts[1] || '000',
  filePath: pathMatch ? unesc(pathMatch[1]) : '',
  fileName: fileMatch ? unesc(fileMatch[1]) : '',
  hash: hashMatch ? hashMatch[1] : '',
  url: urlClean,
  chatId: cq.message ? cq.message.chat.id : '',
  messageId: cq.message ? cq.message.message_id : '',
  callbackQueryId: cq.id || '',
  analyst: (cq.from && (cq.from.first_name || cq.from.username)) || 'analis',
  origText: text
}}];
// patch:hitl-matrix:v1"""

# ---------------------------------------------------------------------------
# JS: Jalankan AR (pakai target dari registry; tanpa AR untuk f:/a:)
# ---------------------------------------------------------------------------
AR_JS = """// patch:hitl-matrix:v1
// Aksi lanjutan analis. Karantina file & blokir domain butuh Active Response;
// 'tandai FP' dan 'sudah ditinjau' hanya audit (tanpa AR) -> jalur tetap linear
// (tanpa cabang FALSE IF, lihat gotcha n8n 2.40).
const p = $('Catat Keputusan').first().json;
let command = null, arg = null;
if (p.action === 'pblk') { command = '!block-domain'; arg = p.url; }
else if (p.decision_action === 'quarantine' && !p.isPhishing) {
  command = '!quarantine-file'; arg = p.filePath;
}
if (!command || !arg) {
  return [{ json: { status: 'tanpa-ar', command: null, arg: null,
    agentId: p.agentId, decision_action: p.decision_action,
    detail: 'tidak ada tindakan aktif untuk aksi ini' } }];
}
const token = $('Get Wazuh Token').first().json.data.token;
let response;
try {
  response = await this.helpers.httpRequest({
    method: 'PUT',
    url: 'https://172.17.0.1:55000/active-response?agents_list=' + p.agentId + '&wait_for_complete=true',
    headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' },
    body: JSON.stringify({ command: command, arguments: [arg] }),
    rejectUnauthorized: false, timeout: 30000
  });
} catch (e) {
  response = { error: 'exception', detail: String((e && e.message) || e).slice(0, 200) };
}
const ok = response && (response.error === 0
  || (response.error === undefined && (!response.failed_items || response.failed_items.length === 0)));
return [{ json: { status: ok ? 'terkirim' : 'gagal', command, arg,
  agentId: p.agentId, decision_action: p.decision_action, ar_response: response } }];
// patch:hitl-matrix:v1"""

EDIT_JS_TEXT = (
    "={{ (() => { const c = $('Catat Keputusan').first().json;"
    " const a = $('Jalankan AR').first().json;"
    " const r = c.registry || {};"
    " const esc = (s) => String(s ?? '').replace(/([_*\\[\\]()~`>#+\\-=|{}.!\\\\])/g, '\\\\$1');"
    " const head = c.decision_action === 'quarantine'"
    "   ? '\\u2705 *KEPUTUSAN ANALIS: KARANTINA FILE*'"
    "   : (c.decision_action === 'acknowledged'"
    "     ? '\\ud83e\\uddfe *SUDAH DITINJAU (tanpa aksi otomatis)*'"
    "     : '\\ud83d\\udeab *DITANDAI FALSE POSITIVE*');"
    " const tgt = c.isPhishing ? c.url : c.filePath;"
    " return head + '\\n\\n' + '\\ud83c\\udfaf Target: ' + esc(tgt || '-')"
    "   + '\\n\\ud83d\\udda5\\ufe0f Agent: ' + esc(c.agentId)"
    "   + (c.decision_action === 'quarantine'"
    "      ? '\\n\\ud83d\\udee1\\ufe0f Status AR: ' + esc(a.status || '-') : '')"
    "   + '\\n\\ud83e\\udd16 Sumber target: ' + (c.filePath && r.found ? 'registry keputusan' : 'teks pesan')"
    "   + '\\n\\ud83d\\udc64 Oleh: ' + esc(c.analyst)"
    "   + '\\n\\ud83d\\udd50 ' + esc(c.decidedAt); })() }}"
)

TGLOG_OLD = """for (const nm of ['Build Payload', 'Rangkum Hasil', 'Rangkum Chain']) {
  try {
    const p = $(nm).first().json;
    rec.severity = rec.severity || p.severity || p.severityLabel;
    rec.agent = rec.agent || p.agent || p.agentName;
    rec.hash = rec.hash || p.hash;
    rec.path = rec.path || p.filePath || p.path;
    rec.title = rec.title || p.title || p.subject;
    break;
  } catch (e) {}
}"""

TGLOG_NEW = """// patch:hitl-matrix:v1 — field audit diambil dari node kebijakan (Tentukan
// Otonomi); Build Payload tidak membawa hash/agent_id sehingga log lama
// kehilangan korelasi ke deteksi.
const src = $('Tentukan Otonomi').first().json;
const bp = (() => { try { return $('Build Payload').first().json; } catch (e) { return {}; } })();
rec.severity = rec.severity || src.severity || null;
rec.agent = rec.agent || src.agent_name || bp.agent_name || null;
rec.agent_id = src.agent_id || null;
rec.hash = src.hash || null;
rec.path = src.filepath || bp.filepath || null;
rec.title = bp.alert_title || src.alert_title || null;
rec.tier = src.policy_tier || null;
rec.hitl = src.needs_decision === true;
rec.decision_did = src.did || null;"""

SLA_TRIGGER = "Tiap Menit"
SLA_FETCH = "Ambil Keputusan Tertunda"
SLA_BUILD = "Bangun Eskalasi"
SLA_SEND = "Kirim Eskalasi SLA"
SLA_LOG = "Catat Eskalasi"

SLA_BUILD_JS = """// patch:hitl-matrix:v1
// Sweeper SLA: keputusan HITL yang lewat tenggat (default 15 menit) dieskalasi
// ke analis, lalu ditandai di registry supaya tidak spam tiap menit.
// Tanpa cabang FALSE IF: daftar kosong -> return [] -> node Telegram tidak jalan.
const items = Array.isArray($json.items) ? $json.items : [];
if (!items.length) return [];
const lines = [];
let i = 1;
for (const it of items) {
  const mins = Math.floor((it.age_secs || 0) / 60);
  lines.push(i++ + '. *' + (it.severity || '-') + '* ' + (it.title || it.tier || 'deteksi')
    + ' \\u2014 ' + (it.filename || it.filepath || '-')
    + ' (agent ' + (it.agent_id || '-') + ') \\u2014 ' + mins + ' mnt');
  try {
    await this.helpers.httpRequest({
      method: 'POST',
      url: '%s/decision/escalate',
      headers: { 'Content-Type': 'application/json' },
      body: { hash: it.did || it.hash },
      timeout: 5000,
    });
  } catch (e) { /* fail-open */ }
}
const text = '\\u23f0 *BELUM DITANGANI (SLA terlampaui)*\\n\\n'
  + items.length + ' deteksi menunggu keputusan analis:\\n' + lines.join('\\n')
  + '\\n\\nBuka dashboard :3000 atau tekan tombol pada pesan alert.';
return [{ json: { text: text, count: items.length } }];
// patch:hitl-matrix:v1""" % ALERT_LOG_URL

SLA_LOG_JS = """// patch:hitl-matrix:v1
// Catat eskalasi ke alert-log (observability + bukti evaluasi SLA).
const inp = $('Bangun Eskalasi').first().json;
let ok = false;
try {
  await this.helpers.httpRequest({
    method: 'POST',
    url: '%s/log',
    headers: { 'Content-Type': 'application/json' },
    body: { ts: new Date().toISOString(), workflow: '%s',
      node: '%s', severity: 'HIGH', title: 'Eskalasi SLA HITL',
      count: inp.count, escalated: true, telegram_ok: false },
    timeout: 5000,
  });
  ok = true;
} catch (e) { /* fail-open */ }
return [{ json: { logged: ok, count: inp.count } }];
// patch:hitl-matrix:v1""" % (ALERT_LOG_URL, SLA_NAME, SLA_SEND)

# Tombol inline: teks & callback dinamis dari tingkat otonomi
BTN_PRIMARY_TEXT = (
    "={{ $('Tentukan Otonomi').first().json.action_kind === 'quarantine'"
    " ? 'Karantina file' : 'Sudah ditinjau' }}"
)
BTN_PRIMARY_DATA = (
    "={{ ($('Tentukan Otonomi').first().json.action_kind === 'quarantine' ? 'q:' : 'a:')"
    " + $('Tentukan Otonomi').first().json.agent_id + ':'"
    " + $('Tentukan Otonomi').first().json.did }}"
)
BTN_FP_TEXT = "Tandai FP"
BTN_FP_DATA = (
    "={{ 'f:' + $('Tentukan Otonomi').first().json.agent_id + ':'"
    " + $('Tentukan Otonomi').first().json.did }}"
)


def read_file(p):
    with open(p) as f:
        return f.read().strip()


def api(url, key, method="GET", body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("X-N8N-API-KEY", key)
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        print("HTTP " + str(e.code) + " " + url + " -> " + e.read().decode()[:300])
        raise SystemExit(1)


def get_node(nodes, name):
    for n in nodes:
        if n.get("name") == name:
            return n
    return None


def node_pos(nodes, name, fallback=(0, 0)):
    n = get_node(nodes, name)
    return list(n.get("position", fallback)) if n else list(fallback)


def ensure_code_node(nodes, name, js, pos, marker=MARKER, extra=None):
    """Tambah/samakan node Code dengan isi yang diinginkan. True bila berubah.

    Perbandingan berbasis ISI (bukan sekadar marker), supaya perbaikan bug di
    node yang sudah pernah dipatch tetap ikut tersinkron, sementara idempotensi
    tetap terjaga (pass kedua: isi identik -> tanpa perubahan).
    """
    node = get_node(nodes, name)
    if node is not None and node.get("parameters", {}).get("jsCode", "") == js:
        return False
    if node is None:
        nodes.append({
            "parameters": {"mode": "runOnceForAllItems", "jsCode": js},
            "id": name.lower().replace(" ", "-")[:36],
            "name": name,
            "type": "n8n-nodes-base.code",
            "typeVersion": 2,
            "position": pos,
        })
        if extra:
            get_node(nodes, name).update(extra)
        return True
    node["parameters"]["jsCode"] = js
    return True


def set_outputs(conns, name, outputs):
    conns[name] = {"main": outputs}


def out(*names):
    return [{"node": n, "type": "main", "index": 0} for n in names]


def patch_malware(wf, dry):
    nodes = wf["nodes"]
    conns = wf["connections"]
    changes = []

    if ensure_code_node(nodes, "Tentukan Otonomi", POLICY_JS,
                        [node_pos(nodes, "Rangkum Hasil", [0, 0])[0] + 260,
                         node_pos(nodes, "Rangkum Hasil", [0, 0])[1]]):
        changes.append("+ node Tentukan Otonomi (matriks confidence → otonomi)")

    if ensure_code_node(nodes, "Catat Keputusan Tertunda", REGISTER_JS,
                        [node_pos(nodes, "Perlu Notifikasi?", [0, 0])[0] + 260,
                         node_pos(nodes, "Perlu Notifikasi?", [0, 0])[1]]):
        changes.append("+ node Catat Keputusan Tertunda (registry HITL)")

    # Rewire: kebijakan lewat Tentukan Otonomi (satu sumber)
    if conns.get("Rangkum Hasil", {}).get("main", [[]])[0] != out("Tentukan Otonomi"):
        set_outputs(conns, "Rangkum Hasil", [out("Tentukan Otonomi")])
        changes.append("~ Rangkum Hasil → Tentukan Otonomi")
    if conns.get("Rangkum Chain", {}).get("main", [[]])[0] != out("Tentukan Otonomi"):
        set_outputs(conns, "Rangkum Chain", [out("Tentukan Otonomi")])
        changes.append("~ Rangkum Chain → Tentukan Otonomi")
    if conns.get("Tentukan Otonomi", {}).get("main", [[]])[0] != out("Cek Ancaman", "Log ke Fleet"):
        set_outputs(conns, "Tentukan Otonomi", [out("Cek Ancaman", "Log ke Fleet")])
        changes.append("~ Tentukan Otonomi → Cek Ancaman + Log ke Fleet")

    # Gate notifikasi -> registry -> AI
    main = conns.get("Perlu Notifikasi?", {}).get("main", [[], []])
    while len(main) < 2:
        main.append([])
    if main[0] != out("Catat Keputusan Tertunda"):
        main[0] = out("Catat Keputusan Tertunda")
        conns["Perlu Notifikasi?"] = {"main": main}
        changes.append("~ Perlu Notifikasi? (true) → Catat Keputusan Tertunda")
    if conns.get("Catat Keputusan Tertunda", {}).get("main", [[]])[0] != out("AI Generate"):
        set_outputs(conns, "Catat Keputusan Tertunda", [out("AI Generate")])
        changes.append("~ Catat Keputusan Tertunda → AI Generate")

    # Log Telegram Alert: lengkapi field audit (hash/agent/path/tier) dari node
    # kebijakan — sebelumnya hanya terisi sebagian (Build Payload tak punya hash).
    tlog = get_node(nodes, "Log Telegram Alert")
    if tlog is not None:
        js = tlog["parameters"].get("jsCode", "")
        if TGLOG_NEW not in js:
            if TGLOG_OLD not in js:
                raise SystemExit("[x] pola blok pengambilan field 'Log Telegram Alert' "
                                 "tidak cocok dengan live")
            tlog["parameters"]["jsCode"] = js.replace(TGLOG_OLD, TGLOG_NEW)
            changes.append("~ Log Telegram Alert: field audit dari Tentukan Otonomi")

    # Tombol HITL pada notifikasi malware
    tg = get_node(nodes, "Send Telegram Alert")
    if tg is None:
        raise SystemExit("[x] node 'Send Telegram Alert' tidak ditemukan")
    want_rows = [{"row": {"buttons": [
        {"text": BTN_PRIMARY_TEXT, "additionalFields": {"callback_data": BTN_PRIMARY_DATA}},
        {"text": BTN_FP_TEXT, "additionalFields": {"callback_data": BTN_FP_DATA}},
    ]}}]
    if tg["parameters"].get("inlineKeyboard", {}).get("rows") != want_rows:
        tg["parameters"]["replyMarkup"] = "inlineKeyboard"
        tg["parameters"]["inlineKeyboard"] = {"rows": want_rows}
        changes.append("~ Send Telegram Alert: tombol HITL (karantina/tinjau + tandai FP)")

    if dry:
        return changes
    if not changes:
        return [], None
    return changes, {
        "name": wf.get("name"),
        "nodes": nodes,
        "connections": conns,
        "settings": wf.get("settings", {}),
        "staticData": wf.get("staticData"),
    }


def patch_callback(wf, dry):
    nodes = wf["nodes"]
    conns = wf["connections"]
    changes = []

    parse = get_node(nodes, "Parse Keputusan")
    if parse is None:
        raise SystemExit("[x] node 'Parse Keputusan' tidak ditemukan")
    if parse.get("parameters", {}).get("jsCode", "") != PARSE_JS:
        parse["parameters"]["jsCode"] = PARSE_JS
        changes.append("~ Parse Keputusan: aksi q/f/a (did dari registry) + fallback legacy")

    tg_creds = telegram_credentials(nodes)
    if ensure_code_node(nodes, "Catat Keputusan", CLAIM_JS,
                        [node_pos(nodes, "Parse Keputusan", [0, 0])[0] + 260,
                         node_pos(nodes, "Parse Keputusan", [0, 0])[1]]):
        changes.append("+ node Catat Keputusan (klaim + audit trail + target dari registry)")

    ar = get_node(nodes, "Jalankan AR")
    if ar is None:
        raise SystemExit("[x] node 'Jalankan AR' tidak ditemukan")
    if ar.get("parameters", {}).get("jsCode", "") != AR_JS:
        ar["parameters"]["jsCode"] = AR_JS
        ar["onError"] = "continueRegularOutput"
        changes.append("~ Jalankan AR: target dari registry, tanpa AR untuk f:/a:")

    # Output tunggal dinamis: hapus ketergantungan cabang FALSE IF
    edit = get_node(nodes, "Edit Pesan Hasil")
    if edit is None:
        nodes.append({
            "parameters": {
                "resource": "message", "operation": "editMessageText",
                "chatId": "={{ $('Parse Keputusan').first().json.chatId }}",
                "messageId": "={{ $('Parse Keputusan').first().json.messageId }}",
                "text": EDIT_JS_TEXT,
                "additionalFields": {"parse_mode": "Markdown", "appendAttribution": False},
            },
            "id": "edit-pesan-hasil",
            "name": "Edit Pesan Hasil",
            "type": "n8n-nodes-base.telegram",
            "typeVersion": 1.2,
            "position": [node_pos(nodes, "Edit Pesan Isolasi", [0, 0])[0],
                         node_pos(nodes, "Edit Pesan Isolasi", [0, 0])[1]],
            "onError": "continueRegularOutput",
            **({"credentials": tg_creds} if tg_creds else {}),
        })
        changes.append("+ node Edit Pesan Hasil (satu output dinamis)")
    elif edit["parameters"].get("text") != EDIT_JS_TEXT:
        edit["parameters"]["text"] = EDIT_JS_TEXT
        changes.append("~ Edit Pesan Hasil: teks dinamis per aksi")

    # Node Telegram tanpa credential ditolak n8n saat publish (dan gagal saat
    # jalan) -> salin credential telegramApi dari node Telegram lain.
    edit = get_node(nodes, "Edit Pesan Hasil")
    if edit is not None and tg_creds and not edit.get("credentials"):
        edit["credentials"] = json.loads(json.dumps(tg_creds))
        changes.append("~ Edit Pesan Hasil: credential Telegram disalin dari node lain")

    # Answer Callback tetap tapi toleran (callback kedaluwarsa tidak mematikan jalur)
    ans = get_node(nodes, "Answer Callback")
    if ans is not None and ans.get("onError") != "continueRegularOutput":
        ans["onError"] = "continueRegularOutput"
        changes.append("~ Answer Callback: toleran terhadap callback kedaluwarsa")

    # Jalur linear: Parse → Catat → Answer → Token → AR → Edit
    wanted = {
        "Parse Keputusan": [out("Catat Keputusan")],
        "Catat Keputusan": [out("Answer Callback")],
        "Answer Callback": [out("Get Wazuh Token")],
        "Get Wazuh Token": [out("Jalankan AR")],
        "Jalankan AR": [out("Edit Pesan Hasil")],
    }
    for name, outs in wanted.items():
        if conns.get(name, {}).get("main") != outs:
            set_outputs(conns, name, outs)
            changes.append("~ jalur callback linear: " + name + " → " + outs[0][0]["node"])

    # Node lama tak terpakai (cabang FALSE yang tak reliabel via API)
    for dead in ("Perlu Tindakan?", "Edit Pesan Isolasi", "Edit Pesan Abaikan"):
        if get_node(nodes, dead) is not None:
            nodes.remove(get_node(nodes, dead))
            conns.pop(dead, None)
            changes.append("- node " + dead + " (digantikan jalur linear)")

    if dry:
        return changes
    if not changes:
        return [], None
    return changes, {
        "name": wf.get("name"),
        "nodes": nodes,
        "connections": conns,
        "settings": wf.get("settings", {}),
        "staticData": wf.get("staticData"),
    }


def telegram_credentials(nodes):
    """Ambil credential Telegram dari node yang sudah ada (dipakai node baru;
    n8n menolak publish node Telegram tanpa credential telegramApi)."""
    for n in nodes:
        if n.get("type") == "n8n-nodes-base.telegram" and n.get("credentials"):
            return json.loads(json.dumps(n["credentials"]))
    return None


def build_sla_workflow(chat_id, creds=None):
    return {
        "name": SLA_NAME,
        "nodes": [
            {
                "parameters": {"rule": {"interval": [{"field": "minutes", "minutesInterval": 1}]}},
                "id": "sla-tiap-menit",
                "name": SLA_TRIGGER,
                "type": "n8n-nodes-base.scheduleTrigger",
                "typeVersion": 1.2,
                "position": [0, 0],
            },
            {
                "parameters": {
                    "url": ALERT_LOG_URL + "/decision/pending?overdue=1&limit=20",
                    "options": {"timeout": 5000},
                },
                "id": "sla-ambil",
                "name": SLA_FETCH,
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4.4,
                "position": [220, 0],
                "onError": "continueRegularOutput",
            },
            {
                "parameters": {"mode": "runOnceForAllItems", "jsCode": SLA_BUILD_JS},
                "id": "sla-bangun",
                "name": SLA_BUILD,
                "type": "n8n-nodes-base.code",
                "typeVersion": 2,
                "position": [440, 0],
            },
            {
                "parameters": {
                    "resource": "message", "operation": "sendMessage",
                    "chatId": str(chat_id),
                    "text": "={{ $json.text }}",
                    "additionalFields": {"parse_mode": "Markdown", "appendAttribution": False},
                },
                "id": "sla-kirim",
                "name": SLA_SEND,
                "type": "n8n-nodes-base.telegram",
                "typeVersion": 1.2,
                "position": [660, 0],
                **({"credentials": creds} if creds else {}),
            },
            {
                "parameters": {"mode": "runOnceForAllItems", "jsCode": SLA_LOG_JS},
                "id": "sla-catat",
                "name": SLA_LOG,
                "type": "n8n-nodes-base.code",
                "typeVersion": 2,
                "position": [880, 0],
                "onError": "continueRegularOutput",
            },
        ],
        "connections": {
            SLA_TRIGGER: {"main": [out(SLA_FETCH)]},
            SLA_FETCH: {"main": [out(SLA_BUILD)]},
            SLA_BUILD: {"main": [out(SLA_SEND)]},
            SLA_SEND: {"main": [out(SLA_LOG)]},
        },
        "settings": {"executionOrder": "v1"},
    }


def ensure_sla(base, key, chat_id, dry, creds=None):
    listing = api(base + "/api/v1/workflows?limit=250", key)
    existing = next((w for w in listing.get("data", []) if w.get("name") == SLA_NAME), None)
    body = build_sla_workflow(chat_id, creds)
    # n8n menolak field `id`/`active` di body PUT (read-only) -> aktivasi lewat
    # endpoint khusus POST /workflows/{id}/activate.
    if existing:
        cur = api(base + "/api/v1/workflows/" + existing["id"], key)
        if MARKER in json.dumps(cur.get("nodes", [])) and cur.get("active"):
            return None, existing["id"]
        if dry:
            return "update", existing["id"]
        api(base + "/api/v1/workflows/" + existing["id"], key, "PUT", body)
        wid = existing["id"]
        action = "update"
    else:
        if dry:
            return "create", None
        created = api(base + "/api/v1/workflows", key, "POST", body)
        wid = created.get("id")
        action = "create"
    if not dry and wid and not api(base + "/api/v1/workflows/" + wid, key).get("active"):
        try:
            api(base + "/api/v1/workflows/" + wid + "/activate", key, "POST", {})
        except SystemExit:
            print("  [peringatan] aktivasi endpoint gagal untuk " + str(wid))
        if not api(base + "/api/v1/workflows/" + wid, key).get("active"):
            print("  [peringatan] workflow " + str(wid) + " masih belum aktif")
    return action, wid


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://100.73.91.17:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--workflow-id", default=WORKFLOW_ID_DEFAULT)
    ap.add_argument("--callback-workflow-id", default=CALLBACK_ID_DEFAULT)
    ap.add_argument("--chat-id", default="1295213498")
    ap.add_argument("--skip-sla", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    if not os.path.exists(a.api_key_file):
        sys.exit("API key file tidak ada: " + a.api_key_file)
    key = read_file(a.api_key_file)
    base = a.n8n_url.rstrip("/")
    os.makedirs(BACKUP_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")

    for label, wid, fn in (
        ("malware", a.workflow_id, patch_malware),
        ("callback", a.callback_workflow_id, patch_callback),
    ):
        url = base + "/api/v1/workflows/" + wid
        wf = api(url, key)
        print("[" + label + "] " + wf.get("name") + " (" + wid + ") node=" + str(len(wf["nodes"])))
        result = fn(wf, a.dry_run)
        if a.dry_run:
            changes = result
            payload = None
        else:
            changes, payload = result
        if not changes:
            print("  tidak ada perubahan (sudah idempoten)")
            continue
        bk = os.path.join(BACKUP_DIR, "n8n-" + label + "-hitl-matrix-" + stamp + ".json")
        with open(bk, "w") as f:
            json.dump(wf, f, indent=2)
        print("  backup: " + bk)
        for c in changes:
            print("  " + c)
        if a.dry_run:
            continue
        res = api(url, key, "PUT", payload)
        print("  PUT ok -> active=" + str(res.get("active")) + " node=" + str(len(res.get("nodes", []))))

    if not a.skip_sla:
        creds = None
        for wid_probe in (a.callback_workflow_id, a.workflow_id):
            try:
                creds = telegram_credentials(api(base + "/api/v1/workflows/" + wid_probe, key)["nodes"])
            except SystemExit:
                creds = None
            if creds:
                break
        action, wid = ensure_sla(base, key, a.chat_id, a.dry_run, creds)
        if action is None:
            print("[sla] " + SLA_NAME + " sudah ada & aktif (idempoten)")
        elif a.dry_run:
            print("[sla] akan " + action + " workflow " + SLA_NAME)
        else:
            print("[sla] " + action + " + aktifkan: " + SLA_NAME + " (" + str(wid) + ")")

    print("selesai" + (" (DRY-RUN)" if a.dry_run else ""))


if __name__ == "__main__":
    main()
