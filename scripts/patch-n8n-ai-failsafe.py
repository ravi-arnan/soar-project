#!/usr/bin/env python3
"""Bikin node AI (dan notifikasi Telegram) gagal-aman di workflow live
'Deteksi Malware' (n8n).

Latar (temuan 2026-10-04): kadang notifikasi Telegram keluar dengan semua
field `undefined`:

    undefined undefined - undefined
    📁 undefined:
    📂 Path:
    🔍 Hash: undefined
    ...

Penyebab: rantai live `Build Payload -> AI Generate -> Send Telegram Alert`.
Node 'AI Generate' (Code, panggil API LLM) memakai
`onError: continueRegularOutput`. Saat panggilan AI gagal (timeout 60s,
5xx/429, `HCNSEC_API_KEY` kosong, atau respons tanpa
`choices[0].message.content`), n8n TIDAK meneruskan `$json` dari Build
Payload -- outputnya jadi item error. 'Send Telegram Alert' membaca SEMUA
field dari `$json` -> semuanya undefined. Itu sebabnya muncul 'kadang' saja
(hanya saat AI gagal).

Patch ini dua lapis:

  1. 'AI Generate' -> provider utama Pollinations (deepseek/deepseek-v4-flash,
     max_tokens 1500), fallback Gemini flash, dibungkus try/catch; SELALU
     `return [{ json: { ...$json, ai_response, llm_error, llm_model } }]`. Gagal
     AI hanya membuat bagian analisis jadi teks fallback, field lain tetap utuh.
  2. 'Send Telegram Alert' -> field terstruktur (file/path/severity/hash/agent/
     waktu/dll) diambil dari node sumber `$('Build Payload')`, bukan `$json`,
     plus fallback `?? ''`, plus baris `⚠️ Error AI: <llm_error>` saat gagal.
     Jadi walau `$json` rusak, pesan tetap utuh.

Cara pakai (jalankan di ravi-debian, n8n terjangkau):
  python3 scripts/patch-n8n-ai-failsafe.py \
    --n8n-url http://127.0.0.1:5678 \
    --api-key-file /tmp/n8n_api_key.txt [--dry-run]

Idempoten (marker `patch:aifailsafe:v4` di kode AI + penanda `*Error AI:*`
di template Telegram). Backup otomatis ke backups/.
"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.request

BACKUP_DIR = os.path.join(os.path.dirname(__file__), "..", "backups")
WORKFLOW_ID_DEFAULT = "1MVcpL7ZKfBhR2tc"
MARKER = "patch:aifailsafe:v7"

AI_NAME = "AI Generate"
TG_NAME = "Send Telegram Alert"

# Marker struktural di template Telegram (bukti lapis 2 sudah diterapkan).
TG_MARKER = "*Error AI:*"

# Lapis 1: node AI Generate dinamis + gagal-aman.
# Membaca konfigurasi primary & fallback dari fleet-monitor (/api/settings/runtime-config)
# bila FLEET_COMMAND_TOKEN tersedia; fail-open ke env ($env.POLLINATIONS_API_KEY /
# $env.GEMINI_API_KEY) bila fleet-monitor tak terjangkau.
AI_JSCODE = """const FALLBACK = 'Analisis AI tidak tersedia saat ini karena layanan AI gagal atau tidak dikonfigurasi.';
const prompt = ($json.prompt || '') + '\\nJANGAN gunakan tanda pisah em dash (\\u2014) atau en dash (\\u2013); gunakan koma, titik, atau tanda kurung.';

const cleanText = (t) => String(t || '')
  .replace(/<think>[\\s\\S]*?<\\/think>/g, '')
  .replace(/[*_`\\[\\]()]/g, '')
  .replace(/\\s*[\\u2014\\u2013]\\s*/g, ', ')
  .replace(/\\n\\n+/g, '\\n')
  .trim();

const envKeyFor = (prov) => {
  const p = String(prov || '').toLowerCase();
  if (p === 'google') return $env.GEMINI_API_KEY || '';
  if (p === 'openai') return $env.OPENAI_API_KEY || '';
  if (p === 'anthropic') return $env.ANTHROPIC_API_KEY || '';
  if (p === 'pollinations') return $env.POLLINATIONS_API_KEY || '';
  if (p === 'experiential') return $env.EXPERIENTIAL_API_KEY || '';
  return '';
};

const envMissingMsg = (prov) => {
  const p = String(prov || '').toLowerCase();
  if (p === 'pollinations') return 'POLLINATIONS_API_KEY belum di-set';
  if (p === 'google') return 'GEMINI_API_KEY belum di-set';
  if (p === 'openai') return 'OPENAI_API_KEY belum di-set';
  if (p === 'anthropic') return 'ANTHROPIC_API_KEY belum di-set';
  if (p === 'experiential') return 'EXPERIENTIAL_API_KEY belum di-set';
  return 'API key ' + p + ' belum di-set';
};

let runtimeAi = null;
const fleetToken = $env.FLEET_COMMAND_TOKEN || '';
if (fleetToken) {
  try {
    const fleetBase = String($env.FLEET_API_URL || 'http://host.docker.internal:8080').replace(/\\/+$/, '');
    const cfg = await this.helpers.httpRequest({
      method: 'GET',
      url: fleetBase + '/api/settings/runtime-config',
      headers: { 'Authorization': 'Bearer ' + fleetToken, 'Accept': 'application/json' },
      timeout: 3000,
    });
    if (cfg && cfg.ai) runtimeAi = cfg.ai;
  } catch (e) {
    // Fail-open ke konfigurasi env default
  }
}

if (runtimeAi && runtimeAi.enabled === false) {
  return [{ json: { ...$json, ai_response: 'Enrichment AI dinonaktifkan oleh konfigurasi dashboard.', llm_error: null, llm_model: 'disabled' } }];
}

const temperature = Number(runtimeAi?.temperature ?? 0.3);
const maxTokens = Number(runtimeAi?.max_tokens ?? 1500);
const sysInst = String(runtimeAi?.system_instruction || '').trim();

const attempts = runtimeAi ? [
  {
    provider: String(runtimeAi.provider || 'google').toLowerCase(),
    model: String(runtimeAi.model || 'gemini-2.5-flash'),
    apiKey: String(runtimeAi.api_key || '').trim() || envKeyFor(runtimeAi.provider),
    baseUrl: String(runtimeAi.custom_base_url || '').trim(),
  },
  ...(runtimeAi.fallback_enabled !== false && runtimeAi.fallback_provider ? [{
    provider: String(runtimeAi.fallback_provider).toLowerCase(),
    model: String(runtimeAi.fallback_model || ''),
    apiKey: String(runtimeAi.fallback_api_key || '').trim() || envKeyFor(runtimeAi.fallback_provider),
    baseUrl: String(runtimeAi.fallback_base_url || '').trim(),
  }] : []),
] : [
  { provider: 'pollinations', model: 'deepseek/deepseek-v4-flash', apiKey: envKeyFor('pollinations'), baseUrl: '' },
  { provider: 'google', model: 'gemini-2.5-flash', apiKey: envKeyFor('google'), baseUrl: '' },
];

const callProvider = async (cfg) => {
  const prov = cfg.provider;
  const key = cfg.apiKey;
  const base = cfg.baseUrl.replace(/\\/+$/, '');
  if (!key && prov !== 'custom') {
    throw new Error(envMissingMsg(prov));
  }
  if (prov === 'google') {
    const model = cfg.model || 'gemini-2.5-flash';
    const body = {
      contents: [{ parts: [{ text: prompt }] }],
      generationConfig: { temperature, maxOutputTokens: maxTokens },
    };
    if (sysInst) body.systemInstruction = { parts: [{ text: sysInst }] };
    const resp = await this.helpers.httpRequest({
      method: 'POST',
      url: 'https://generativelanguage.googleapis.com/v1beta/models/' + model + ':generateContent?key=' + key,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      timeout: 30000,
    });
    const text = (resp?.candidates?.[0]?.content?.parts || []).map((p) => p.text || '').join('');
    return { text: cleanText(text), usedModel: 'gemini:' + model.replace(/^gemini-/, '') };
  }
  if (prov === 'anthropic') {
    const model = cfg.model || 'claude-3-5-sonnet-latest';
    const url = base ? (base.endsWith('/messages') ? base : base + '/messages') : 'https://api.anthropic.com/v1/messages';
    const body = { model, max_tokens: maxTokens, temperature, messages: [{ role: 'user', content: prompt }] };
    if (sysInst) body.system = sysInst;
    const resp = await this.helpers.httpRequest({
      method: 'POST',
      url,
      headers: { 'Content-Type': 'application/json', 'x-api-key': key, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify(body),
      timeout: 35000,
    });
    const text = (resp?.content || []).filter((b) => b && b.type === 'text').map((b) => b.text || '').join('');
    return { text: cleanText(text), usedModel: 'anthropic:' + model };
  }
  const defaultBase = prov === 'openai'
    ? 'https://api.openai.com/v1'
    : prov === 'experiential'
      ? 'https://api.experientiallabs.ai/v1'
      : 'https://gen.pollinations.ai/v1';
  const ep = base || defaultBase;
  const url = ep.endsWith('/chat/completions') ? ep : ep + '/chat/completions';
  const model = cfg.model || (prov === 'openai' ? 'gpt-4o-mini' : prov === 'experiential' ? 'gpt-6-luna:free' : 'deepseek/deepseek-v4-flash');
  const headers = { 'Content-Type': 'application/json' };
  if (key) headers['Authorization'] = 'Bearer ' + key;
  const messages = sysInst ? [{ role: 'system', content: sysInst }, { role: 'user', content: prompt }] : [{ role: 'user', content: prompt }];
  const body = { model, temperature, messages };
  if (prov === 'openai') {
    body.max_completion_tokens = maxTokens;
  } else {
    body.max_tokens = maxTokens;
  }
  let resp = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      resp = await this.helpers.httpRequest({
        method: 'POST',
        url,
        headers,
        body: JSON.stringify(body),
        timeout: 35000,
      });
      break;
    } catch (err) {
      const msgLower = String((err && err.message) || err).toLowerCase();
      let adjusted = false;
      if ('max_tokens' in body && msgLower.includes('max_tokens') && msgLower.includes('max_completion_tokens')) {
        body.max_completion_tokens = body.max_tokens;
        delete body.max_tokens;
        adjusted = true;
      } else if ('max_completion_tokens' in body && msgLower.includes('max_completion_tokens') && (msgLower.includes('unsupported') || msgLower.includes('not supported'))) {
        body.max_tokens = body.max_completion_tokens;
        delete body.max_completion_tokens;
        adjusted = true;
      }
      if ('temperature' in body && msgLower.includes('temperature') && (msgLower.includes('unsupported') || msgLower.includes('not supported') || msgLower.includes('does not support'))) {
        delete body.temperature;
        adjusted = true;
      }
      if (!adjusted || attempt === 2) throw err;
    }
  }
  return { text: cleanText(resp?.choices?.[0]?.message?.content), usedModel: prov + ':' + model };
};

let clean = '';
let errMsg = null;
let usedModel = null;

for (const cfg of attempts) {
  if (!cfg.apiKey && cfg.provider !== 'custom') {
    if (!errMsg) errMsg = envMissingMsg(cfg.provider);
    continue;
  }
  if (cfg.provider === 'custom' && !cfg.baseUrl) {
    continue;
  }
  try {
    const res = await callProvider(cfg);
    if (res.text) {
      clean = res.text;
      usedModel = res.usedModel;
      errMsg = null;
      break;
    }
    errMsg = (errMsg ? errMsg + ' | ' : '') + cfg.provider + ': respons kosong';
  } catch (e) {
    errMsg = (errMsg ? errMsg + ' | ' : '') + cfg.provider + ': ' + String((e && e.message) || e).slice(0, 160);
  }
}

return [{ json: { ...$json, ai_response: clean || FALLBACK, llm_error: clean ? null : errMsg, llm_model: usedModel || 'gagal' } }];
// patch:aifailsafe:v7"""

# Lapis 2: template Telegram ambil field terstruktur dari 'Build Payload'
# (bukan $json), plus fallback `?? ''`. Field AI tetap dari $json output
# 'AI Generate'. Pada parse_mode: "Markdown" (legacy v1), hanya karakter
# entitas Markdown v1 ([_*`\[]) yang boleh di-escape agar tidak bocor
# backslash literal (\., \-, \\) di pesan Telegram.
TG_TEXT = """={{ $('Build Payload').first().json.severityIcon + " *" + $('Build Payload').first().json.severityLabel + " - " + $('Build Payload').first().json.alert_title + "*\\n\\n📁 " + $('Build Payload').first().json.target_label + ": " + ((($('Build Payload').first().json.filename ?? '') + '').replace(/([_*`\\[])/g, '\\\\$1')) + "\\n📂 Path: " + ((($('Build Payload').first().json.filepath ?? '') + '').replace(/\\\\\\\\/g, '\\\\').replace(/([_*`\\[])/g, '\\\\$1')) + ($('Build Payload').first().json.chain_cmd ? ("\\n💻 Command: " + ((($('Build Payload').first().json.chain_cmd ?? '') + '').replace(/\\\\\\\\/g, '\\\\').replace(/\\\\"/g, '"').replace(/([_*`\\[])/g, '\\\\$1'))) : "") + "\\n🔍 Hash: `" + ($('Build Payload').first().json.hash_display ?? 'Tidak tersedia') + "`" + "\\n🛡️ Severity: " + ($('Build Payload').first().json.severity ?? '') + " level " + ($('Build Payload').first().json.rule_level ?? '') + "\\n📊 Deteksi: " + ($('Build Payload').first().json.detection_text ?? '') + "\\n🖥️ Agent: " + ((($('Build Payload').first().json.agent_name ?? '') + '').replace(/([_*`\\[])/g, '\\\\$1')) + "\\n🕐 Waktu: " + ($('Build Payload').first().json.timestamp ?? '') + "\\n\\n🤖 *Analisis AI:*\\n" + (($json.ai_response ?? 'Analisis AI tidak tersedia.') + '').replace(/\\s*[\\u2014\\u2013]\\s*/g, ', ').replace(/([_*`\\[])/g, '\\\\$1') + "\\n\\n" + ($('Build Payload').first().json.vt_footer ?? '') + (($json.llm_error) ? ("\\n⚠️ *Error AI:* " + (($json.llm_error + '').replace(/([_*`\\[])/g, '\\\\$1'))) : "") }}"""


def read_file(p):
    with open(p) as f:
        return f.read().strip()


def api_get(url, api_key):
    req = urllib.request.Request(url, headers={"X-N8N-API-KEY": api_key})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def api_put(url, api_key, payload):
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=body,
        method="PUT",
        headers={"X-N8N-API-KEY": api_key, "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read())


def get_node(nodes, name):
    for n in nodes:
        if n.get("name") == name:
            return n
    return None


def patch_node(nodes, name, js, marker):
    n = get_node(nodes, name)
    if n is None:
        raise SystemExit("Node '" + name + "' tidak ditemukan.")
    cur = n.get("parameters", {}).get("jsCode", "")
    if marker in cur:
        return False
    n["parameters"]["jsCode"] = js
    return True


def patch_telegram(nodes, name, text, marker):
    n = get_node(nodes, name)
    if n is None:
        raise SystemExit("Node '" + name + "' tidak ditemukan.")
    cur = n.get("parameters", {}).get("text", "")
    if cur == text or (marker in cur and "~`>#" not in cur):
        return False
    n["parameters"]["text"] = text
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n8n-url", default="http://127.0.0.1:5678")
    ap.add_argument("--api-key-file", default="/tmp/n8n_api_key.txt")
    ap.add_argument("--workflow-id", default=WORKFLOW_ID_DEFAULT)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not os.path.exists(args.api_key_file):
        sys.exit("API key file tidak ada: " + args.api_key_file)
    api_key = read_file(args.api_key_file)
    base = args.n8n_url.rstrip("/")
    wf_url = base + "/api/v1/workflows/" + args.workflow_id

    print("Mengambil workflow " + args.workflow_id + " ...")
    wf = api_get(wf_url, api_key)
    nodes = wf.get("nodes", [])
    print("  Node saat ini: " + str(len(nodes)))

    os.makedirs(BACKUP_DIR, exist_ok=True)
    backup_path = os.path.join(
        BACKUP_DIR,
        "deteksi-malware-live-ai-failsafe-" + time.strftime("%Y%m%d-%H%M%S") + ".json",
    )
    with open(backup_path, "w") as f:
        json.dump(wf, f, indent=2)
    print("  Backup: " + backup_path)

    changed = []
    if patch_node(nodes, AI_NAME, AI_JSCODE, MARKER):
        changed.append(AI_NAME)
    if patch_telegram(nodes, TG_NAME, TG_TEXT, TG_MARKER):
        changed.append(TG_NAME)

    if args.dry_run:
        print("[DRY-RUN] Node akan dipatch: " + str(changed))
        return

    if not changed:
        print("Tidak ada perubahan.")
        return

    payload = {
        "name": wf.get("name"),
        "nodes": nodes,
        "connections": wf.get("connections", {}),
        "settings": wf.get("settings", {}),
        "staticData": wf.get("staticData"),
    }
    print("Menulis ke n8n ...")
    try:
        result = api_put(wf_url, api_key, payload)
        print("Selesai. Aktif: " + str(result.get("active")))
    except urllib.error.HTTPError as e:
        print("GAGAL PUT: " + str(e.code) + " " + e.read().decode()[:300])
        sys.exit(1)


if __name__ == "__main__":
    main()
