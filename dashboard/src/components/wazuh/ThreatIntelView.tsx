'use client';

import React, { useEffect, useMemo, useState } from 'react';
import { WuiIcon } from '../wui/WuiIcon';
import { formatWazuhTime, useEventHistory, periodToWindow } from '@/lib/fleet';
import { postCommand } from '@/lib/commands';
import {
  DEFAULT_AI_CONFIG,
  DEFAULT_THREAT_INTEL_CONFIG,
  getProviderMeta,
  type AiConfig,
  type ThreatIntelConfig,
} from '@/lib/aiConfig';
import { PeriodFilter } from './PeriodFilter';
import { WuiBadge, WuiCallOut, WuiHealth, WuiPageHeader, WuiPanel, type WuiTone } from '../wui/WuiPrimitives';
import type { FleetEvent, PeriodValue } from '@/lib/fleet';

const DEFAULT_PERIOD: PeriodValue = { preset: '7d', since: null, until: null };

interface ThreatAnalysis {
  model: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN';
  verdictLabel: string;
  reasoning: string;
  mitreTechnique: string;
  actionRecommendation: string;
}

/**
 * Helper ekstraksi nama file dari path.
 * Menangani path Linux (/path/to/file) maupun Windows (C:\path\to\file).
 */
function extractFilename(path?: string, hash?: string): string {
  if (!path || path === '-' || path === 'unknown') {
    return hash ? `sample-${hash.slice(0, 8)}.bin` : 'unknown-artifact';
  }
  const cleanPath = path.replace(/\\/g, '/');
  const name = cleanPath.split('/').pop();
  return name && name.trim().length > 0 ? name : `artifact-${hash?.slice(0, 8) || 'file'}`;
}

/**
 * Generate analisis agentic terpadu per ancaman.
 * Menggunakan teks asli pipeline bila ada di e.ai, atau menghasilkan
 * sintesis penalaran deterministik berbasis konteks artefak dan IoC.
 */
function generateThreatAnalysis(event: FleetEvent, activeAi: AiConfig): ThreatAnalysis {
  const filename = extractFilename(event.path, event.hash).toLowerCase();
  const severity = (event.severity || 'INFO').toUpperCase();
  const ruleDesc = (event.rule_desc || '').toLowerCase();
  const hash = event.hash || '';

  // 1. Tentukan Model / Mesin Analisis
  let modelName = `${activeAi.model} (${getProviderMeta(activeAi.provider).shortLabel})`;
  const hasRealAi = Boolean(event.ai && event.ai.trim().length > 10);

  if (hasRealAi) {
    const aiText = (event.ai || '').toLowerCase();
    if (aiText.includes('deepseek')) {
      modelName = 'DeepSeek V4 Flash (SOC Triage)';
    } else if (aiText.includes('claude')) {
      modelName = 'Anthropic Claude (SOC Triage)';
    } else if (aiText.includes('gpt')) {
      modelName = 'OpenAI GPT (SOC Triage)';
    } else {
      modelName = `${activeAi.model} (${getProviderMeta(activeAi.provider).shortLabel})`;
    }
  } else {
    modelName = 'Wazuh Syscheck & Rule Heuristic';
  }

  // 2. Evaluasi Verdict & MITRE ATT&CK
  let verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' = 'BENIGN';
  let verdictLabel = 'Benign (Verified Safe)';
  let mitreTechnique = 'T1565.001 (Data Manipulation / FIM Baseline)';
  let actionRecommendation =
    'Tidak ada indikasi aktivitas jahat. Pertahankan dalam daftar pantau normal.';

  const isRansomwareRelated =
    filename.includes('canary') ||
    filename.includes('ransom') ||
    filename.includes('crypt') ||
    ruleDesc.includes('ransomware') ||
    ruleDesc.includes('canary');

  const isShadowCopyTarget =
    ruleDesc.includes('shadow') ||
    ruleDesc.includes('vssadmin') ||
    ruleDesc.includes('recovery');

  const isPersistence =
    ruleDesc.includes('autostart') ||
    ruleDesc.includes('run key') ||
    ruleDesc.includes('scheduled task') ||
    filename.includes('startup');

  const isExecOrScript =
    filename.endsWith('.exe') ||
    filename.endsWith('.dll') ||
    filename.endsWith('.vbs') ||
    filename.endsWith('.ps1') ||
    filename.endsWith('.bat') ||
    filename.endsWith('.sh');

  if (severity === 'CRITICAL' || isRansomwareRelated || isShadowCopyTarget) {
    verdict = 'MALICIOUS';
    verdictLabel = 'Malicious (Critical Threat)';
    mitreTechnique = isShadowCopyTarget
      ? 'T1490 (Inhibit System Recovery)'
      : 'T1486 (Data Encrypted for Impact)';
    actionRecommendation =
      'Isolasi host segera dari jaringan lokal dan picu tindakan Karantina File otomatis via Active Response.';
  } else if (severity === 'HIGH' || isPersistence) {
    verdict = 'MALICIOUS';
    verdictLabel = 'Malicious (High Risk)';
    mitreTechnique = isPersistence
      ? 'T1547.001 (Registry Run Keys / Startup Folder)'
      : 'T1059.001 (Command and Scripting Interpreter)';
    actionRecommendation =
      'Pindahkan file ke direktori karantina terisolasi dan periksa histori proses induk (PPID).';
  } else if (severity === 'MEDIUM' || (isExecOrScript && severity !== 'INFO')) {
    verdict = 'SUSPICIOUS';
    verdictLabel = 'Suspicious (Perlu Tinjauan)';
    mitreTechnique = 'T1036.007 (Double Extension / Masquerading)';
    actionRecommendation =
      'Lakukan peninjauan mendalam pada koneksi keluar dan verifikasi reputasi hash di sandbox.';
  } else {
    verdict = 'BENIGN';
    verdictLabel = 'Benign / Clean';
    mitreTechnique = 'T1565.001 (Integrity Monitoring)';
    actionRecommendation =
      'File konsisten dengan pola operasi rutin sistem. Tidak diperlukan eskalasi isolasi.';
  }

  // 3. Bangun Narasi Penalaran (Reasoning)
  let reasoning = '';
  if (hasRealAi) {
    reasoning = (event.ai || '').trim();
  } else {
    if (verdict === 'MALICIOUS') {
      reasoning = `Telemetri mendeteksi anomali kritis pada artefak ${filename} (hash: ${hash ? hash.slice(0, 16) + '...' : '-'}). Karakteristik FIM dan pola ekstensi sesuai taktik ${mitreTechnique}. Direkomendasikan segera memicu Active Response karantina.`;
    } else if (verdict === 'SUSPICIOUS') {
      reasoning = `Indikator mencurigakan terdeteksi pada ${filename} di agent ${event.agent || 'endpoint'}. Modifikasi atau eksekusi memerlukan tinjauan lebih lanjut terhadap reputasi IoC eksternal.`;
    } else {
      reasoning = `Artefak ${filename} berada dalam batas toleransi baseline FIM normal tanpa indikasi anomali aktif.`;
    }
  }

  return {
    model: modelName,
    verdict,
    verdictLabel,
    reasoning,
    mitreTechnique,
    actionRecommendation,
  };
}

interface ThreatIntelViewProps {
  onOpenAiSettings?: () => void;
}

interface AgentInvestigation {
  id: string;
  ts: string;
  title: string;
  agent_source: string;
  model?: string;
  verdict: 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN' | 'NEEDS_REVIEW';
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';
  summary: string;
  analysis: string;
  recommendations?: string;
  mitre_techniques: string[];
  target_agent_ids: string[];
  target_hashes: string[];
  target_paths: string[];
  created_by?: string;
}

export function ThreatIntelView({ onOpenAiSettings }: ThreatIntelViewProps) {
  const [activeTab, setActiveTab] = useState<'pipeline' | 'agent'>('pipeline');
  const [period, setPeriod] = useState<PeriodValue>(DEFAULT_PERIOD);
  const [filterSeverity, setFilterSeverity] = useState<'ALL' | 'MALICIOUS' | 'SUSPICIOUS' | 'BENIGN'>('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);
  const [quarantineStatus, setQuarantineStatus] = useState<Record<string, string>>({});
  const [isQuarantining, setIsQuarantining] = useState<string | null>(null);
  const [aiConfig, setAiConfig] = useState<AiConfig>(DEFAULT_AI_CONFIG);
  const [tiConfig, setTiConfig] = useState<ThreatIntelConfig>(DEFAULT_THREAT_INTEL_CONFIG);

  const [investigations, setInvestigations] = useState<AgentInvestigation[]>([]);
  const [invLoading, setInvLoading] = useState(false);
  const [invError, setInvError] = useState<string | null>(null);
  const [invVerdictFilter, setInvVerdictFilter] = useState<'ALL' | 'MALICIOUS' | 'SUSPICIOUS' | 'NEEDS_REVIEW' | 'BENIGN'>('ALL');
  const [invSearch, setInvSearch] = useState('');
  const [deletingInvId, setDeletingInvId] = useState<string | null>(null);

  const loadInvestigations = React.useCallback(async () => {
    try {
      setInvLoading(true);
      const res = await fetch('/api/investigations?limit=100', { cache: 'no-store' });
      const data = await res.json().catch(() => null);
      if (!res.ok) {
        setInvError((data && data.error) || `HTTP ${res.status}`);
        return;
      }
      setInvestigations(Array.isArray(data?.investigations) ? data.investigations : []);
      setInvError(null);
    } catch (err: unknown) {
      setInvError(err instanceof Error ? err.message : String(err));
    } finally {
      setInvLoading(false);
    }
  }, []);

  useEffect(() => {
    let ignore = false;
    async function loadSettings() {
      try {
        const res = await fetch('/api/settings/threat-intel', { cache: 'no-store' });
        if (!res.ok || ignore) return;
        const data = await res.json();
        if (ignore) return;
        if (data.ai_config) setAiConfig({ ...DEFAULT_AI_CONFIG, ...data.ai_config });
        if (data.threat_intel_config) setTiConfig(data.threat_intel_config);
      } catch {
        // Pertahankan default jika endpoint settings belum tersedia
      }
    }
    async function initInvestigations() {
      try {
        const res = await fetch('/api/investigations?limit=100', { cache: 'no-store' });
        const data = await res.json().catch(() => null);
        if (ignore) return;
        if (!res.ok) {
          setInvError((data && data.error) || `HTTP ${res.status}`);
          return;
        }
        setInvestigations(Array.isArray(data?.investigations) ? data.investigations : []);
        setInvError(null);
      } catch (err: unknown) {
        if (!ignore) setInvError(err instanceof Error ? err.message : String(err));
      }
    }
    loadSettings();
    initInvestigations();
    return () => {
      ignore = true;
    };
  }, []);

  const timeWindow = useMemo(() => periodToWindow(period), [period]);
  const { events, loading, refresh } = useEventHistory(
    { since: timeWindow.since, until: timeWindow.until, source: 'all', limit: 500 },
    30000
  );

  const intel = useMemo(() => {
    const withHash = events.filter((e) => e.hash && e.hash.trim().length > 0);
    const crit = withHash.filter((e) => (e.severity || '').toUpperCase() === 'CRITICAL').length;
    const high = withHash.filter((e) => (e.severity || '').toUpperCase() === 'HIGH').length;
    const med = withHash.filter((e) => (e.severity || '').toUpperCase() === 'MEDIUM').length;
    const uniq = new Set(withHash.map((e) => e.hash)).size;

    const analyzedList = withHash.map((e) => ({
      event: e,
      analysis: generateThreatAnalysis(e, aiConfig),
    }));

    return {
      total: withHash.length,
      crit,
      high,
      med,
      uniq,
      items: analyzedList,
    };
  }, [events, aiConfig]);

  const filteredItems = useMemo(() => {
    return intel.items.filter(({ event, analysis }) => {
      // Filter kategori verdict
      if (filterSeverity === 'MALICIOUS' && analysis.verdict !== 'MALICIOUS') return false;
      if (filterSeverity === 'SUSPICIOUS' && analysis.verdict !== 'SUSPICIOUS') return false;
      if (filterSeverity === 'BENIGN' && analysis.verdict !== 'BENIGN') return false;

      // Filter pencarian query
      if (searchQuery.trim().length > 0) {
        const q = searchQuery.toLowerCase();
        const fname = extractFilename(event.path, event.hash).toLowerCase();
        const p = (event.path || '').toLowerCase();
        const h = (event.hash || '').toLowerCase();
        const ag = (event.agent || '').toLowerCase();
        const r = analysis.reasoning.toLowerCase();
        const m = analysis.model.toLowerCase();
        return (
          fname.includes(q) ||
          p.includes(q) ||
          h.includes(q) ||
          ag.includes(q) ||
          r.includes(q) ||
          m.includes(q)
        );
      }

      return true;
    });
  }, [intel.items, filterSeverity, searchQuery]);

  const handleCopyHash = (hash: string) => {
    if (!navigator?.clipboard) return;
    navigator.clipboard.writeText(hash).then(() => {
      setCopiedHash(hash);
      setTimeout(() => setCopiedHash(null), 2000);
    });
  };

  const handleQuarantine = async (event: FleetEvent) => {
    const path = event.path;
    const agentId = event.agent_id || '001';
    const key = `${agentId}-${path}`;

    if (!path || path === '-' || path === 'unknown') {
      setQuarantineStatus((prev) => ({
        ...prev,
        [key]: 'Gagal: Path artefak tidak valid untuk karantina langsung.',
      }));
      return;
    }

    try {
      setIsQuarantining(key);
      const res = await postCommand({
        agent_id: agentId,
        action: 'quarantine',
        target: path,
      });

      if (res.ok) {
        setQuarantineStatus((prev) => ({
          ...prev,
          [key]: 'Sukses: Perintah karantina berhasil dikirim ke agen.',
        }));
      } else {
        const errText = await res.text().catch(() => 'Status error');
        setQuarantineStatus((prev) => ({
          ...prev,
          [key]: `Gagal (${res.status}): ${errText}`,
        }));
      }
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      setQuarantineStatus((prev) => ({
        ...prev,
        [key]: `Error koneksi: ${msg}`,
      }));
    } finally {
      setIsQuarantining(null);
    }
  };

  const handleDeleteInvestigation = async (invId: string) => {
    try {
      setDeletingInvId(invId);
      const res = await fetch('/api/investigations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'delete', id: invId }),
      });
      if (res.ok) {
        setInvestigations((prev) => prev.filter((item) => item.id !== invId));
      } else {
        const data = await res.json().catch(() => null);
        setInvError((data && data.error) || `Gagal menghapus (HTTP ${res.status})`);
      }
    } catch (err: unknown) {
      setInvError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeletingInvId(null);
    }
  };

  const invStats = useMemo(() => {
    let mal = 0;
    let susp = 0;
    let review = 0;
    let benign = 0;
    for (const inv of investigations) {
      if (inv.verdict === 'MALICIOUS') mal += 1;
      else if (inv.verdict === 'SUSPICIOUS') susp += 1;
      else if (inv.verdict === 'BENIGN') benign += 1;
      else review += 1;
    }
    return { total: investigations.length, mal, susp, review, benign };
  }, [investigations]);

  const filteredInvestigations = useMemo(() => {
    const q = invSearch.trim().toLowerCase();
    return investigations.filter((inv) => {
      if (invVerdictFilter !== 'ALL' && inv.verdict !== invVerdictFilter) return false;
      if (!q) return true;
      return (
        inv.title.toLowerCase().includes(q) ||
        inv.summary.toLowerCase().includes(q) ||
        inv.analysis.toLowerCase().includes(q) ||
        (inv.recommendations || '').toLowerCase().includes(q) ||
        inv.agent_source.toLowerCase().includes(q) ||
        (inv.model || '').toLowerCase().includes(q) ||
        inv.mitre_techniques.some((m) => m.toLowerCase().includes(q)) ||
        inv.target_agent_ids.some((a) => a.toLowerCase().includes(q)) ||
        inv.target_paths.some((p) => p.toLowerCase().includes(q)) ||
        inv.target_hashes.some((h) => h.toLowerCase().includes(q))
      );
    });
  }, [investigations, invVerdictFilter, invSearch]);

  const subtabCls = (active: boolean) =>
    `pb-2.5 -mb-[9px] text-[13px] font-medium transition-colors flex items-center gap-1.5 cursor-pointer ${
      active
        ? 'border-b-2 border-[#006BB4] text-[#006BB4]'
        : 'text-[#5A626F] hover:text-[#1A1C21]'
    }`;

  return (
    <div className="space-y-4">
      <WuiPageHeader
        title="Threat Intelligence"
        description="Memisahkan analisis otomatis pipeline (n8n + LLM) dengan laporan investigasi AI Agent eksternal (agy / MCP)."
        actions={
          <>
            <button
              type="button"
              onClick={() => (activeTab === 'pipeline' ? refresh() : loadInvestigations())}
              disabled={activeTab === 'pipeline' ? loading : invLoading}
              className="h-8 px-3 text-[12px] font-medium text-[#1A1C21] bg-white border border-[#D3DAE6] rounded-[4px] hover:bg-[#FAFBFD] flex items-center gap-1.5 transition disabled:opacity-50 cursor-pointer"
              title="Muat ulang data"
            >
              <WuiIcon
                type="refresh"
                size="s"
                className={(activeTab === 'pipeline' ? loading : invLoading) ? 'animate-spin' : ''}
              />
              <span>Refresh</span>
            </button>
            {activeTab === 'pipeline' && <PeriodFilter value={period} onChange={setPeriod} />}
          </>
        }
      />

      {/* Sub-tab pemisah Pipeline AI Otomatis vs Investigasi AI Agent (agy/MCP) */}
      <div className="flex flex-wrap items-center gap-6 border-b border-[#D3DAE6] pb-2">
        <button
          type="button"
          onClick={() => setActiveTab('pipeline')}
          className={subtabCls(activeTab === 'pipeline')}
        >
          <span>Pipeline AI Otomatis (n8n &amp; LLM)</span>
          <WuiBadge tone={activeTab === 'pipeline' ? 'primary' : 'default'}>{intel.items.length}</WuiBadge>
        </button>
        <button
          type="button"
          onClick={() => setActiveTab('agent')}
          className={subtabCls(activeTab === 'agent')}
        >
          <span>Investigasi AI Agent (agy / MCP)</span>
          <WuiBadge tone={activeTab === 'agent' ? 'primary' : 'default'}>{investigations.length}</WuiBadge>
        </button>
      </div>

      {activeTab === 'pipeline' && (
        <>

      {/* Panel Status Agent & Model AI (Dinamis dari /api/settings/threat-intel) */}
      <WuiPanel
        title="Status sistem orkestrasi AI agent"
        right={
          <div className="flex items-center gap-3">
            {onOpenAiSettings && (
              <button
                type="button"
                onClick={onOpenAiSettings}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-[4px] text-[12px] font-medium bg-white border border-[#D3DAE6] text-[#1A1C21] hover:border-[#006BB4] hover:text-[#006BB4] transition cursor-pointer"
              >
                <WuiIcon type="controlsHorizontal" size="s" className="text-[#535966]" />
                <span>Atur Model &amp; Fallback</span>
              </button>
            )}
            <WuiHealth tone={aiConfig.enabled ? 'success' : 'default'}>
              {aiConfig.enabled ? 'Engine online' : 'Enrichment nonaktif'}
            </WuiHealth>
          </div>
        }
        bodyClassName="p-0"
      >
        <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-[#E9EDF3] text-[12px]">
          <div className="px-4 py-3">
            <div className="text-[#535966] text-[11.5px] font-medium">
              Model penalaran utama
            </div>
            <div className="font-semibold text-[#1A1C21] mt-1 flex flex-wrap items-baseline gap-1.5">
              <span className="font-mono text-[12.5px]">{aiConfig.model || 'gemini-2.5-flash'}</span>
              <span className="text-[11.5px] text-[#535966] font-normal">
                ({getProviderMeta(aiConfig.provider).shortLabel})
              </span>
            </div>
            <div className="text-[11.5px] text-[#69707D] mt-1">
              {aiConfig.fallback_enabled
                ? `Fallback: ${aiConfig.fallback_model} (${getProviderMeta(aiConfig.fallback_provider).shortLabel})`
                : 'Fallback: Nonaktif'}
            </div>
          </div>

          <div className="px-4 py-3">
            <div className="text-[#535966] text-[11.5px] font-medium">
              Enrichment OSINT feeds
            </div>
            <div className="font-semibold text-[#1A1C21] mt-1">
              {tiConfig.consensus_mode === 'majority'
                ? 'Majority Vote (Min. 2 Sumber)'
                : tiConfig.consensus_mode === 'vt_first'
                  ? 'Primary VT with Fallback'
                  : 'Multi-Source Synthesis'}
            </div>
            <div className="text-[11.5px] text-[#69707D] mt-1">
              {[
                tiConfig.sources?.virustotal?.enabled !== false ? 'VirusTotal' : null,
                tiConfig.sources?.malwarebazaar?.enabled !== false ? 'MalwareBazaar' : null,
                tiConfig.sources?.alienvault_otx?.enabled !== false ? 'AlienVault OTX' : null,
                tiConfig.sources?.misp?.enabled !== false ? 'MISP OSINT' : null,
                'Wazuh FIM',
              ]
                .filter(Boolean)
                .join(', ')}
            </div>
          </div>

          <div className="px-4 py-3">
            <div className="text-[#535966] text-[11.5px] font-medium">
              Kebijakan respons mitigasi
            </div>
            <div className="font-semibold text-[#1A1C21] mt-1">
              Autonomous AR &amp; SLA 15 Menit
            </div>
            <div className="text-[11.5px] text-[#69707D] mt-1 font-mono tabular-nums">
              VT Critical &ge;{tiConfig.sources?.virustotal?.min_engines_critical ?? 20}, High &ge;
              {tiConfig.sources?.virustotal?.min_engines_high ?? 5} · TTL{' '}
              {tiConfig.cache_ttl?.malicious_days ?? 7}h/{tiConfig.cache_ttl?.clean_hours ?? 24}j/
              {tiConfig.cache_ttl?.unknown_hours ?? 6}j
            </div>
          </div>
        </div>
      </WuiPanel>

      {/* Ringkasan Metrik Intelijen (WUI Unified Stat Bar) */}
      <div className="grid grid-cols-2 lg:grid-cols-4 bg-white border border-[#D3DAE6] rounded-[4px] divide-y lg:divide-y-0 lg:divide-x divide-[#E9EDF3] text-center">
        <div className="p-3.5">
          <div className="text-[12px] text-[#535966] font-medium">Total Artefak Dianalisis</div>
          <div className="text-[26px] font-semibold text-[#006BB4] font-mono tabular-nums leading-tight mt-1">{intel.total}</div>
          <div className="text-[11px] text-[#69707D] font-mono tabular-nums mt-0.5">{intel.uniq} hash unik</div>
        </div>
        <div className="p-3.5">
          <div className="text-[12px] text-[#535966] font-medium">Malicious (Critical)</div>
          <div className="text-[26px] font-semibold text-[#BD271E] font-mono tabular-nums leading-tight mt-1">{intel.crit}</div>
          <div className="text-[11px] text-[#BD271E] mt-0.5">Perlu isolasi segera</div>
        </div>
        <div className="p-3.5">
          <div className="text-[12px] text-[#535966] font-medium">Malicious (High)</div>
          <div className="text-[26px] font-semibold text-[#8A5300] font-mono tabular-nums leading-tight mt-1">{intel.high}</div>
          <div className="text-[11px] text-[#8A5300] mt-0.5">Persistensi / Scripting</div>
        </div>
        <div className="p-3.5">
          <div className="text-[12px] text-[#535966] font-medium">Suspicious / Review</div>
          <div className="text-[26px] font-semibold text-[#535966] font-mono tabular-nums leading-tight mt-1">{intel.med}</div>
          <div className="text-[11px] text-[#69707D] mt-0.5">Tinjau aktivitas proses</div>
        </div>
      </div>

      {/* Bar Pencarian & Filter Kategori */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2 bg-white border border-[#D3DAE6] rounded-[4px] p-2.5">
        <div className="relative flex-1">
          <WuiIcon type="search" size="m" className="text-[#69707D] absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Cari nama file, path, hash, agent, model AI, atau reasoning..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full h-8 pl-9 pr-3 text-[12px] bg-white border border-[#D3DAE6] rounded-[4px] focus:outline-none focus:border-[#006BB4] transition"
          />
        </div>

        <div className="flex items-center gap-1 overflow-x-auto text-[11px]">
          <button
            type="button"
            onClick={() => setFilterSeverity('ALL')}
            className={`px-2.5 py-1.5 rounded-[4px] font-medium transition whitespace-nowrap cursor-pointer ${
              filterSeverity === 'ALL'
                ? 'bg-[#006BB4] text-white'
                : 'bg-[#FAFBFD] border border-[#D3DAE6] text-[#535966] hover:text-[#1A1C21]'
            }`}
          >
            Semua ({intel.items.length})
          </button>
          <button
            type="button"
            onClick={() => setFilterSeverity('MALICIOUS')}
            className={`px-2.5 py-1.5 rounded-[4px] font-medium transition whitespace-nowrap cursor-pointer ${
              filterSeverity === 'MALICIOUS'
                ? 'bg-[#BD271E] text-white'
                : 'bg-[#FBECEB] border border-[#F3C5C3] text-[#BD271E]'
            }`}
          >
            Malicious ({intel.crit + intel.high})
          </button>
          <button
            type="button"
            onClick={() => setFilterSeverity('SUSPICIOUS')}
            className={`px-2.5 py-1.5 rounded-[4px] font-medium transition whitespace-nowrap cursor-pointer ${
              filterSeverity === 'SUSPICIOUS'
                ? 'bg-[#8A5300] text-white'
                : 'bg-[#FFF8E5] border border-[#F6DF98] text-[#8A5300]'
            }`}
          >
            Suspicious ({intel.med})
          </button>
          <button
            type="button"
            onClick={() => setFilterSeverity('BENIGN')}
            className={`px-2.5 py-1.5 rounded-[4px] font-medium transition whitespace-nowrap cursor-pointer ${
              filterSeverity === 'BENIGN'
                ? 'bg-[#017D73] text-white'
                : 'bg-[#E6F4F3] border border-[#BBDEDB] text-[#017D73]'
            }`}
          >
            Benign ({Math.max(0, intel.items.length - (intel.crit + intel.high + intel.med))})
          </button>
        </div>
      </div>

      {/* Konten Daftar Ancaman */}
      <div className="space-y-3">
        {filteredItems.length === 0 ? (
          <WuiPanel>
            <div className="py-6 text-center">
              <WuiIcon type="securityAnalyticsApp" size={28} className="ouiIcon--mono text-[#69707D] mx-auto mb-2" />
              <div className="text-[13px] font-semibold text-[#1A1C21]">
                Tidak ada ancaman yang cocok
              </div>
              <p className="text-[12px] text-[#535966] mt-1 max-w-md mx-auto">
                Tidak ditemukan data intelijen dengan filter atau kata kunci yang dipilih.
              </p>
            </div>
          </WuiPanel>
        ) : (
          filteredItems.map(({ event, analysis }, idx) => {
            const filename = extractFilename(event.path, event.hash);
            const actionKey = `${event.agent_id || '001'}-${event.path}`;
            const actionMessage = quarantineStatus[actionKey];
            const isBusy = isQuarantining === actionKey;
            const severityLabel = (event.severity || 'INFO').toUpperCase();
            const verdictTone: WuiTone =
              analysis.verdict === 'MALICIOUS'
                ? 'danger'
                : analysis.verdict === 'SUSPICIOUS'
                  ? 'warning'
                  : 'success';
            const severityTone: WuiTone =
              severityLabel === 'CRITICAL' || severityLabel === 'HIGH'
                ? 'danger'
                : severityLabel === 'MEDIUM'
                  ? 'warning'
                  : 'default';

            return (
              <div
                key={`${event.hash}-${event.ts}-${idx}`}
                className="bg-white border border-[#D3DAE6] rounded-[4px] overflow-hidden"
              >
                {/* Header Artefak (WUI Panel Header) */}
                <div className="px-4 py-2.5 bg-[#FAFBFD] border-b border-[#E9EDF3] flex flex-col md:flex-row md:items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[13px] font-semibold text-[#1A1C21] font-mono break-all">
                        {filename}
                      </span>
                      {analysis.verdict === 'BENIGN' ? (
                        <span
                          title="Benign / Aman"
                          aria-label="Benign / Aman"
                          className="inline-flex items-center text-[#017D73]"
                        >
                          <WuiIcon type="checkInCircleFilled" size="s" />
                        </span>
                      ) : (
                        <WuiHealth tone={verdictTone} className="text-[11.5px]">
                          {analysis.verdictLabel}
                        </WuiHealth>
                      )}
                      <span className="text-[#D3DAE6]" aria-hidden="true">|</span>
                      <span className="text-[11.5px] text-[#535966]">
                        Agent: <span className="font-medium text-[#1A1C21]">{event.agent || 'unknown'}</span>
                      </span>
                    </div>
                    <div className="mt-1 text-[11px] text-[#69707D] font-mono break-all">
                      {event.path && event.path !== '-' ? event.path : '(Path tidak terekam dalam alert)'}
                    </div>
                  </div>

                  <div className="flex items-center gap-2.5 shrink-0 pt-1.5 md:pt-0 border-t md:border-0 border-[#E9EDF3]">
                    <WuiBadge tone={severityTone}>{severityLabel}</WuiBadge>
                    <span className="text-[11px] font-mono tabular-nums text-[#535966]">
                      {formatWazuhTime(event.ts)}
                    </span>
                  </div>
                </div>

                {/* Body Analisis AI Agent */}
                <div className="px-4 py-3 space-y-2.5">
                  <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
                    <span className="font-semibold uppercase tracking-wide text-[#535966]">
                      Analisis AI Agent
                    </span>
                    <span className="text-[#69707D] font-mono">
                      Engine: {analysis.model}
                    </span>
                  </div>

                  <p className="text-[12px] text-[#1A1C21] leading-relaxed">
                    {analysis.reasoning}
                  </p>

                  <div className="pt-2 border-t border-[#F0F2F6] grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-1 text-[11.5px]">
                    <div>
                      <span className="text-[#535966]">MITRE ATT&amp;CK: </span>
                      <span className="font-mono font-medium text-[#006BB4]">{analysis.mitreTechnique}</span>
                    </div>
                    <div>
                      <span className="text-[#535966]">Rekomendasi: </span>
                      <span className="font-medium text-[#1A1C21]">{analysis.actionRecommendation}</span>
                    </div>
                  </div>

                  {actionMessage && (
                    <WuiCallOut tone={actionMessage.startsWith('Sukses') ? 'success' : 'danger'}>
                      {actionMessage}
                    </WuiCallOut>
                  )}
                </div>

                {/* IoC Bar & Controls */}
                <div className="px-4 py-2 bg-[#FAFBFD] border-t border-[#E9EDF3] flex flex-col lg:flex-row lg:items-center justify-between gap-2 text-[11.5px]">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-medium text-[#535966]">SHA-256:</span>
                    <code
                      className="bg-white border border-[#D3DAE6] px-1.5 py-0.5 rounded-[4px] font-mono text-[11px] text-[#1A1C21] select-all"
                      title={event.hash}
                    >
                      {event.hash ? `${event.hash.slice(0, 20)}...${event.hash.slice(-8)}` : 'Tidak ada hash'}
                    </code>
                    {event.hash && (
                      <button
                        type="button"
                        onClick={() => handleCopyHash(event.hash)}
                        className="inline-flex items-center gap-1 text-[11px] font-medium text-[#006BB4] hover:underline transition cursor-pointer"
                        title="Salin hash lengkap ke clipboard"
                      >
                        <WuiIcon type="copy" size="xs" />
                        <span>{copiedHash === event.hash ? 'Tersalin' : 'Salin'}</span>
                      </button>
                    )}
                  </div>

                  {analysis.verdict !== 'BENIGN' && severityLabel !== 'INFO' && (
                    <div className="flex items-center gap-2.5 flex-wrap">
                      {event.hash && (
                        <div className="flex items-center gap-1.5 text-[11px]">
                          <span className="text-[#69707D] font-medium">OSINT:</span>
                          <a
                            href={`https://www.virustotal.com/gui/file/${event.hash}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#006BB4] hover:underline inline-flex items-center gap-0.5 font-medium"
                          >
                            VT
                            <WuiIcon type="popout" size="xs" />
                          </a>
                          <span className="text-[#D3DAE6]">|</span>
                          <a
                            href={`https://bazaar.abuse.ch/sample/${event.hash}/`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#006BB4] hover:underline inline-flex items-center gap-0.5 font-medium"
                          >
                            MB
                            <WuiIcon type="popout" size="xs" />
                          </a>
                          <span className="text-[#D3DAE6]">|</span>
                          <a
                            href={`https://otx.alienvault.com/indicator/file/${event.hash}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-[#006BB4] hover:underline inline-flex items-center gap-0.5 font-medium"
                          >
                            OTX
                            <WuiIcon type="popout" size="xs" />
                          </a>
                        </div>
                      )}

                      {event.path && event.path !== '-' && (
                        <button
                          type="button"
                          onClick={() => handleQuarantine(event)}
                          disabled={isBusy}
                          className={`flex items-center gap-1.5 px-3 py-1 rounded-[4px] font-medium text-[11px] transition cursor-pointer ${
                            analysis.verdict === 'MALICIOUS'
                              ? 'bg-[#BD271E] hover:bg-[#9E1F18] text-white'
                              : 'bg-white border border-[#D3DAE6] text-[#1A1C21] hover:bg-[#F5F7FA]'
                          } disabled:opacity-50`}
                        >
                          <WuiIcon type="console" size="xs" />
                          <span>{isBusy ? 'Memproses...' : 'Karantina File'}</span>
                        </button>
                      )}
                    </div>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>

          {/* Footer Penjelas Pipeline */}
          <div className="px-4 py-2.5 text-[11.5px] text-[#535966] bg-white border border-[#D3DAE6] rounded-[4px] flex items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <WuiIcon type="appCode" size="m" className="ouiIcon--mono text-[#006BB4]" />
              <span>
                Pipeline deteksi aktif menghubungkan Wazuh Manager, orkestrasi n8n, AI Reasoning Engine dinamis, dan Active Response.
              </span>
            </div>
            <span className="text-[11px] text-[#69707D] hidden sm:inline font-mono">
              WITA (UTC+8)
            </span>
          </div>
        </>
      )}

      {activeTab === 'agent' && (
        <div className="space-y-4">
          {invError && <WuiCallOut tone="danger">{invError}</WuiCallOut>}

          <div className="grid grid-cols-2 lg:grid-cols-4 bg-white border border-[#D3DAE6] rounded-[4px] divide-y lg:divide-y-0 lg:divide-x divide-[#E9EDF3] text-center">
            <div className="p-3.5">
              <div className="text-[12px] text-[#535966] font-medium">Total Laporan Agent</div>
              <div className="text-[26px] font-semibold text-[#006BB4] font-mono tabular-nums leading-tight mt-1">
                {invStats.total}
              </div>
              <div className="text-[11px] text-[#69707D] mt-0.5">Tersimpan di SQLite</div>
            </div>
            <div className="p-3.5">
              <div className="text-[12px] text-[#535966] font-medium">Malicious</div>
              <div className="text-[26px] font-semibold text-[#BD271E] font-mono tabular-nums leading-tight mt-1">
                {invStats.mal}
              </div>
              <div className="text-[11px] text-[#BD271E] mt-0.5">Perlu isolasi / eskalasi</div>
            </div>
            <div className="p-3.5">
              <div className="text-[12px] text-[#535966] font-medium">Suspicious / Review</div>
              <div className="text-[26px] font-semibold text-[#8A5300] font-mono tabular-nums leading-tight mt-1">
                {invStats.susp + invStats.review}
              </div>
              <div className="text-[11px] text-[#8A5300] mt-0.5">Tindak lanjut analis</div>
            </div>
            <div className="p-3.5">
              <div className="text-[12px] text-[#535966] font-medium">Benign</div>
              <div className="text-[26px] font-semibold text-[#017D73] font-mono tabular-nums leading-tight mt-1">
                {invStats.benign}
              </div>
              <div className="text-[11px] text-[#017D73] mt-0.5">False positive / aman</div>
            </div>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-2 bg-white border border-[#D3DAE6] rounded-[4px] p-2.5">
            <div className="relative flex-1">
              <WuiIcon type="search" size="m" className="text-[#69707D] absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                placeholder="Cari judul, ringkasan, model, teknik MITRE, agent_id, path, atau hash..."
                value={invSearch}
                onChange={(e) => setInvSearch(e.target.value)}
                className="w-full h-8 pl-9 pr-3 text-[12px] bg-white border border-[#D3DAE6] rounded-[4px] focus:outline-none focus:border-[#006BB4] transition"
              />
            </div>

            <div className="flex items-center gap-1 overflow-x-auto text-[11px]">
              {(
                [
                  { id: 'ALL', label: `Semua (${invStats.total})` },
                  { id: 'MALICIOUS', label: `Malicious (${invStats.mal})` },
                  { id: 'SUSPICIOUS', label: `Suspicious (${invStats.susp})` },
                  { id: 'NEEDS_REVIEW', label: `Review (${invStats.review})` },
                  { id: 'BENIGN', label: `Benign (${invStats.benign})` },
                ] as const
              ).map((chip) => (
                <button
                  key={chip.id}
                  type="button"
                  onClick={() => setInvVerdictFilter(chip.id)}
                  className={`px-2.5 py-1.5 rounded-[4px] font-medium transition whitespace-nowrap cursor-pointer ${
                    invVerdictFilter === chip.id
                      ? 'bg-[#006BB4] text-white'
                      : 'bg-[#FAFBFD] border border-[#D3DAE6] text-[#535966] hover:text-[#1A1C21]'
                  }`}
                >
                  {chip.label}
                </button>
              ))}
            </div>
          </div>

          {filteredInvestigations.length === 0 ? (
            <WuiPanel>
              <div className="py-6 text-center space-y-2">
                <WuiIcon type="machineLearningApp" size={28} className="ouiIcon--mono text-[#69707D] mx-auto" />
                <div className="text-[13px] font-semibold text-[#1A1C21]">
                  Belum ada laporan investigasi AI Agent eksternal
                </div>
                <p className="text-[12px] text-[#535966] max-w-xl mx-auto leading-relaxed">
                  Hasil investigasi interaktif dari <code className="font-mono text-[#1A1C21]">agy</code> (atau client MCP/API lainnya) akan tersimpan di sini dan terpisah dari analisis pipeline n8n otomatis. Gunakan tool MCP <code className="font-mono text-[#006BB4]">soar_save_investigation</code> atau endpoint <code className="font-mono text-[#006BB4]">POST /api/investigations</code>.
                </p>
              </div>
            </WuiPanel>
          ) : (
            <div className="space-y-3">
              {filteredInvestigations.map((inv) => {
                const vTone: WuiTone =
                  inv.verdict === 'MALICIOUS'
                    ? 'danger'
                    : inv.verdict === 'SUSPICIOUS' || inv.verdict === 'NEEDS_REVIEW'
                      ? 'warning'
                      : 'success';
                const sTone: WuiTone =
                  inv.severity === 'CRITICAL' || inv.severity === 'HIGH'
                    ? 'danger'
                    : inv.severity === 'MEDIUM'
                      ? 'warning'
                      : 'default';

                return (
                  <div
                    key={inv.id}
                    className="bg-white border border-[#D3DAE6] rounded-[4px] overflow-hidden"
                  >
                    <div className="px-4 py-2.5 bg-[#FAFBFD] border-b border-[#E9EDF3] flex flex-col md:flex-row md:items-center justify-between gap-2">
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-[13px] font-semibold text-[#1A1C21]">
                            {inv.title}
                          </span>
                          {inv.verdict === 'BENIGN' ? (
                            <span
                              title="Benign / Aman"
                              aria-label="Benign / Aman"
                              className="inline-flex items-center text-[#017D73]"
                            >
                              <WuiIcon type="checkInCircleFilled" size="s" />
                            </span>
                          ) : (
                            <WuiHealth tone={vTone} className="text-[11.5px]">
                              {inv.verdict}
                            </WuiHealth>
                          )}
                          <WuiBadge tone="primary">
                            {inv.agent_source}
                            {inv.model ? ` · ${inv.model}` : ''}
                          </WuiBadge>
                        </div>
                        <p className="mt-1 text-[12px] text-[#535966]">{inv.summary}</p>
                      </div>

                      <div className="flex items-center gap-2.5 shrink-0 pt-1.5 md:pt-0 border-t md:border-0 border-[#E9EDF3]">
                        <WuiBadge tone={sTone}>{inv.severity}</WuiBadge>
                        <span className="text-[11px] font-mono tabular-nums text-[#535966]">
                          {formatWazuhTime(inv.ts)}
                        </span>
                      </div>
                    </div>

                    <div className="px-4 py-3 space-y-2.5">
                      <div className="text-[11px] font-semibold uppercase tracking-wide text-[#535966]">
                        Analisis &amp; Korelasi AI Agent
                      </div>
                      <p className="text-[12px] text-[#1A1C21] leading-relaxed whitespace-pre-line">
                        {inv.analysis}
                      </p>

                      {(inv.recommendations ||
                        inv.mitre_techniques.length > 0 ||
                        inv.target_agent_ids.length > 0 ||
                        inv.target_paths.length > 0 ||
                        inv.target_hashes.length > 0) && (
                        <div className="pt-2 border-t border-[#F0F2F6] space-y-1.5 text-[11.5px]">
                          {inv.recommendations && (
                            <div>
                              <span className="text-[#535966]">Rekomendasi: </span>
                              <span className="font-medium text-[#1A1C21]">{inv.recommendations}</span>
                            </div>
                          )}
                          <div className="flex flex-wrap items-center gap-2">
                            {inv.mitre_techniques.map((m) => (
                              <WuiBadge key={m} tone="primary" className="font-mono">
                                {m}
                              </WuiBadge>
                            ))}
                            {inv.target_agent_ids.map((aid) => (
                              <WuiBadge key={aid} tone="default" className="font-mono">
                                Agent: {aid}
                              </WuiBadge>
                            ))}
                            {inv.target_paths.map((p) => (
                              <WuiBadge key={p} tone="default" className="font-mono max-w-md truncate">
                                {p}
                              </WuiBadge>
                            ))}
                            {inv.target_hashes.map((h) => (
                              <WuiBadge key={h} tone="default" className="font-mono">
                                {h.slice(0, 16)}...
                              </WuiBadge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>

                    <div className="px-4 py-2 bg-[#FAFBFD] border-t border-[#E9EDF3] flex items-center justify-between gap-2 text-[11px] text-[#535966]">
                      <div className="font-mono">
                        ID: {inv.id} · Dicatat oleh: {inv.created_by || inv.agent_source}
                      </div>
                      <button
                        type="button"
                        onClick={() => handleDeleteInvestigation(inv.id)}
                        disabled={deletingInvId === inv.id}
                        className="inline-flex items-center gap-1 text-[#BD271E] hover:underline disabled:opacity-50 cursor-pointer"
                      >
                        <WuiIcon type="trash" size="xs" />
                        <span>{deletingInvId === inv.id ? 'Menghapus...' : 'Hapus'}</span>
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
